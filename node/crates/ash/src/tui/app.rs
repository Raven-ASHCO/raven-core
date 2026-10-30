//! The app's state and its one transition, [`App::update`].
//!
//! `update` is pure: it turns a [`Msg`] (a key, a paste, a resize, a tick of
//! the clock, a job's result, what the poller found, a signal) into new state
//! plus the [`Cmd`]s the UI thread carries out, and never does I/O. The time
//! comes in with every message, so tests drive the clock. There is the
//! first-run wizard (WZ-1 to WZ-6), ERR-ID, Home (the friends, the open
//! conversation and the composer), Add a friend, VF, AF-3, CI, NET, MEET,
//! SET, the header's node and security chips, the SMALL screen, toasts, and
//! the HELP, QUIT, RX, KC, PASSFILE, FW, MSG, LOCK, ERASE, SEC and confirm
//! overlays.
//!
//! Home's conversations come from the chat history only, reloaded when the
//! file changes, its rows in the order the history wrote them. Rows already
//! there at the first load are marked as such: they never count as new
//! contact (presence.rs). Unread counts the friend's messages after the last
//! one read on this computer; the read markers are saved 2 s after they
//! change, and nothing is ever sent about them.
//!
//! The wizard writes nothing into the profile until the identity exists: the
//! name and the receive answer wait in the App, and are saved after creation.
//! Creation runs on the store worker behind a spinner, or, on a passphrase-
//! vault profile, on the UI thread with the screen suspended
//! ([`Cmd::Suspend`]), since the vault asks for its passphrase on the terminal.
//!
//! Enter in the composer sends ([`SendJob`]): the message shows at once with
//! its tick, and delivery.rs follows it from the send's answer, the history
//! and raven-node's outbox. R, C and S act on one message as its state
//! allows; C and S ask first.
//!
//! Under the open friend's name Home says how long a message written to
//! them now could wait, or that they have to meet first. The poller asks
//! for that every minute and the store worker reads it
//! ([`StoreJob::LoadHorizons`]), never a draw; once the poller has asked, a
//! send's end, a change to the friends or the history reads it again sooner.
//!
//! The background program starts by itself only as OD-3 says
//! ([`App::auto_start`]): the identity exists, receiving is on (RX asks once
//! when it was never answered), a vault profile has its passphrase file, and
//! Raven knows where its own program is. Then at launch with at least one
//! friend saved, otherwise when the user opens Add a friend.
//!
//! Add a friend (A) is AF-1, then AF-2 or NAME-CLASH. AF-1 shares my invite,
//! with this computer's address only once a node listens on the network
//! (OD-5), and takes the friend's by paste. A paste is only ever text: it
//! parses where it lands and never goes on by itself, and Enter means
//! nothing for 300 ms after it. COPY shows my invite alone on the plain
//! terminal ([`Cmd::Peek`]) until any key.
//!
//! VF compares the security words out loud (Ctrl+O: the old code), then
//! AF-3 says the friend is added. A friend is saved verified only after the
//! words (or code) typed as they read them matched theirs and the fresh
//! confirmation code was typed; saved as not verified (Tab, 'Later') only
//! after the confirmation code. The friend's words and code are never on
//! screen before they matched, words get no mark against theirs, and after 3
//! entries that were not theirs VF stops checking. CI is one saved friend's
//! page: rename, their address, verify, remove (after typing 'remove'),
//! unblock.
//!
//! NET (N on the friend list) says what the background program is doing and
//! what this build lets on, read once at startup ([`GatesView`]): On,
//! Preview or Lab, and never a switch. From there S starts it, X stops it as
//! OD-16 allows (after a yes), R asks again after it stopped answering, and
//! L shows its service log's last lines. FW explains the firewall prompt
//! once per profile, after this app started a node that listens on the
//! network (Windows and macOS).
//!
//! MEET (G on the friend list and on NET) guides a meeting without the
//! internet: who makes a hotspot and how, then this computer's address and
//! the friend's, typed and saved as CI's E saves it, with one retry of the
//! messages waiting for them. It says you are connected once a message from
//! them arrived, or one of yours was delivered, after G. It changes no
//! system setting and runs no command.
//!
//! SET (S on the friend list) changes the settings one value at a time, each
//! change saved at once through a store job. Motion, colours and symbols
//! apply at once ([`LookEnv`]); receiving on applies at once unless this
//! session's node would listen on this computer only, off applies at the
//! next start (and offers to stop a node this app started); 'Always open the
//! classic menu' is read by the gate at the next start. 'Switch to the
//! classic menu now' leaves the screen ([`Cmd::SwitchToClassic`]) unless a
//! save or a send is in flight.
//!
//! QUIT says what keeps running ([`App::quit_view`]): Enter quits as 'When
//! I quit' says (OD-2), S stops the background program first and K keeps
//! it, where the stop rules allow (OD-16). A quit chosen while a message is
//! being sent waits for it (Q quits anyway), and while the identity or a
//! change to the friends is being saved QUIT only waits. Once the app asked
//! to end or to leave for the classic menu it asks for nothing more. While
//! messages the background program keeps trying haven't gone yet, QUIT says
//! so first (UXF.8): Enter stays and waits, Q quits anyway.
//!
//! Two toasts on Home follow a meeting (UXF.8): a friend's messages that
//! waited were all delivered, and a burst of messages from a friend came
//! after an hour of none. Each shows at most once a minute for one friend.
//!
//! UNLOCK (review E-harness-docs-ci-3): when the app opens on a profile
//! `raven lock` locked, nothing starts the background program until the
//! user answers. Enter starts Raven again (the lock goes, and the start
//! the app would have made follows); Esc keeps it stopped for this session
//! (NET's S asks again, and a send says Raven is locked). The app's own
//! Lock is cleared when the app opens, as before.
//!
//! LOCK (Lock now v1, UXF.7; SET's 'Lock now' and QUIT's L) asks first, in
//! the words of a passphrase-vault profile (locked) or a keychain one (only
//! stopped). Enter waits for a send or a save in flight, then asks for the
//! same stop as X on NET; once nothing of this profile answers any more the
//! app ends with the terminal cleared and one line ([`ExitPlan::locked`]).
//! A stop that left it running (a login service, the stop rules, a failure)
//! keeps the app open and LOCK says why.
//!
//! A letter or digit key typed with a Persian keyboard layout on is the
//! shortcut on that key (keys_fa.rs), except where a field takes the text:
//! there it stays the character typed.
//!
//! The honest notes (UXF.9) show once per profile, each remembered in
//! tui_state.json as soon as it shows: NOTE, what people on the network can
//! see, the first time Raven receives there with receiving on (on Home, NET
//! or SET, once no other box is open and no field has the keys); MEET's
//! step 2a, what whoever runs a hotspot can see; AF-2's hint to use a
//! nickname; the laptop note under the exit line, the first time the user
//! quits with receiving on; and COPY's note to clear the invite from the
//! terminal afterwards.
//!
//! The privacy pack's parts (PP.21) all need the privacy read
//! ([`StoreJob::LoadPrivacy`]): before it answers, and when it says this
//! profile can't use them, every one is hidden. SET's 'Keep chats for'
//! opens KEEP, a chooser whose change is saved through one store job. CI's
//! C asks before the chat with the friend is deleted on this computer
//! (DEL: 'delete' typed, also on a Persian keyboard; a paste clears the
//! word, and Enter means nothing for 300 ms after one), and F before their
//! saved address is forgotten (FORGET: Enter). Home shows the sealing
//! notice and the retention notice once each (NOTICE), marked shown once
//! the user said OK. The header chip says 'Locked out of your friends list'
//! while raven-node can't open it.
//!
//! Home's live feel (UXF.10, live.rs) follows only what Raven did: each
//! Status the background program answered is a heartbeat; a message of
//! yours coming to Delivered (its receipt) or Sent, a friend's message
//! arriving and raven-node's outbox listing another attempt are the
//! ticker's events; how the last delivery to a friend went is what its own
//! send answered (carrier and address) or what the outbox recorded
//! (carrier and p2p path). Nothing here runs on a timer of its own: anim.rs
//! wakes the UI thread when the picture changes.
//!
//! SET's last row, 'Erase Raven from this computer' (PP.22, also only once
//! the privacy read answered), opens ERASE over the whole screen: the
//! question, what goes in plain words, and 'erase' to type (as DEL's word;
//! no shortcut). Enter with it waits until no job is in flight, stops the
//! background program this app started, then runs `raven erase`'s erase as
//! one store job; from the moment the erase can't be taken back the
//! controller refuses every job and saves nothing. The app then ends on a
//! cleared terminal with the result list ([`ExitPlan::erased`]); an erase
//! that changed nothing (Raven still runs) says why and the app goes on.
//!
//! Security notices (Phase 6b design A, P6.31) come from the store worker
//! ([`StoreJob::LoadSecurity`]: on the poller's minute word, when raven-node's
//! security counts change, and after a change): the header chip, a friend's
//! badge and the open friend's banner, SEC (W; D on a friend; R resolves, V
//! compares words), NET's Security group and CI's Security row. VF for a
//! verified friend checks again ([`StoreJob::Recheck`]: a match resolves
//! their notices, and while the older method may be accepted VF asks for
//! 'accept'). P pauses or resumes sending to a friend (`node_policy`
//! `send_hold`, read by raven-node's outbox worker), only while a notice
//! about them is open or it is paused, and never by itself; while paused,
//! nothing is sent to them from here either.
//!
//! Groups (lab only, app/groups.rs): while this build lets them on, the
//! friend list has a GROUPS section, a group's chat opens in the
//! conversation pane, and C, M and E open NEW GROUP and MEMBERS. While it
//! does not, none of it shows and no key or job of theirs exists.

use std::collections::{HashMap, HashSet, VecDeque};
use std::mem::{self, Discriminant};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::style::Style;
use ratatui::text::Span;
use raven_core::arrivals::ArrivedVia;
use raven_core::ipc::OutboxItem;

#[cfg(test)]
use super::anim;
use super::bridge::{
    self, AtRestStateView, ChatKeepView, ContactView, DeleteChatOutcome, EraseEnd, ErasePlanView,
    FriendPreview, LoginItemView, MeView, NotAvailable, Notice, Resolved, SecNotice, SecurityView,
};
use super::controller::{
    self, Conversations, GroupChange, GroupDone, GroupsRead, Horizons, NameCheck, NoCardLan,
    PasteProblem, PrivacyRead, RowView, SendOutcome, SendResult, Share, Verify,
};
use super::delivery::{
    self, Actions, JobState, Outcome, PendingSend, Sources, Tick, Unmet, Waiting, WriteEvidence,
};
use super::display;
use super::errors::{self, IdentityProblem, NodeStartProblem, Plain};
use super::keys_fa;
use super::live::{self, Event, Live};
use super::node::{
    self, BindFailure, Ensured, GatesView, LoginItemKnown, Managed, NodeFolder, NodeState,
    NodeView, Probe, Program, StopOutcome, StopPlan, Stopped, Vault,
};
use super::read_marks::{self, ReadMark, ReadMarks};
use super::state_file::{
    self, ColorChoice, MotionSetting, OnQuit, Receive, SymbolSetting, TuiState,
};
#[cfg(test)]
use super::testkit;
use super::theme::{self, Glyphs, Motion, TermEnv, Theme};
use super::ui::widgets::Chip;
use super::ui::{add_friend, home, meet, network, overlays, wizard};
use super::workers::{
    self, FileStamp, KeychainWait, OsSignal, PollCtl, PollHints, PollUpdate, Watched,
};

// Lock now v2 (Phase 6 P6.40): LOCKED, the idle lock, SET's lock rows and
// PASS.
mod lock_v2;
use lock_v2::LockWhy;
mod updates;
// Groups (lab, docs/design/2026-10-groups.md): the list's GROUPS section, a
// group's chat, NEW GROUP, MEMBERS and WHO HAS IT.
mod groups;
pub(super) use groups::{
    text_problem as group_text_problem, GroupItem, GroupOverlay, GroupsState, MemberAsk,
    MembersState, PickFor, PickState,
};
#[cfg(test)]
pub(super) use groups::{
    GROUP_WAITS, NAME_EMPTY as GROUP_NAME_EMPTY, PICK_NONE as GROUP_PICK_NONE,
};
pub(super) use lock_v2::{
    typed_of, LockSettingsView, LockV2State, LockedView, Masked, PassState, PassStep,
};
pub(super) use updates::{UpdState, UpdStep};

/// How to stop a background program by hand on Windows, in NET after
/// 'To stop it yourself: ' (the app's own stop is [X]).
pub(super) const WINDOWS_STOP: &str = "end raven-node.exe in Task Manager (Details tab).";

/// What the exit prints when the input or signal thread has died: the app
/// can no longer be used or stopped safely.
pub(super) const PART_FAILED: &str =
    "Raven stopped because part of it failed. Nothing was lost. Open Raven again.";
/// After N on the receive question (WZ-3's copy).
pub(super) const RECEIVE_OFF_TOAST: &str =
    "OK. Friends can't send you messages until you turn receiving on in Settings.";
/// WZ-4: the identity was made, but not its first prekey or device
/// certificate (the menu prints a `prekey:` line for it). Raven goes on.
pub(super) const PREKEY_TOAST: &str = "Raven set up your identity, but could not prepare one \
                                       part for receiving first messages. It will retry when you \
                                       send.";
/// The most terminal cells the user's own name takes (WZ-2).
pub(super) const NAME_CELLS: usize = 32;
/// A settings save that failed: the setting holds until Raven closes.
const SETTINGS_NOT_SAVED: &str =
    "Raven couldn't save this setting, so it holds only until you close Raven.";
/// KEEP's save failed (PP.21): the setting stays as it was saved.
const KEEP_NOT_SAVED: &str = "Raven couldn't save how long chats are kept. Nothing was changed.";
/// The erase job itself failed (PP.22): what went is not known.
const ERASE_FAILED: &str =
    "Raven couldn't finish erasing this profile. Run `raven erase` to finish.";
/// How long Enter means nothing after a paste: a pasted line break must not
/// answer a question.
const PASTE_GUARD: Duration = Duration::from_millis(300);

/// QUIT's line for the plain terminal when the background program keeps
/// running after the app.
pub(super) fn still_running_line(pid: u32) -> String {
    format!(
        "Raven is still running in the background (process {pid}), so friends can reach you \
         while this computer is on. Open it again with: raven"
    )
}

/// QUIT's line for the plain terminal after it stopped the background
/// program.
pub(super) const STOPPED_LINE: &str = "Raven's background program was stopped.";

/// The plain terminal's last line the first time the user quits with
/// receiving on (UXF.9).
pub(super) const EXIT_NOTE: &str = "If someone gets this laptop while you're logged in, they can \
                                    read your Raven chats. Lock Raven or your screen when you \
                                    step away.";

/// LOCK's line on the cleared terminal (UXF.7): a passphrase-vault profile
/// is locked; any other is only stopped, its keys still in the keychain.
pub(super) const LOCKED_LINE: &str = "Raven is locked.";
pub(super) const LOCK_STOPPED_LINE: &str = "Raven is stopped.";
/// The same when LOCK unloaded Raven's own login item for this login
/// session (PP.23): it starts Raven again at the next login.
pub(super) const LOCK_UNTIL_LOGIN_LINE: &str = "Raven is stopped until you log in again.";

/// The smallest terminal the screens are laid out for; below it, SMALL.
pub(super) const MIN_COLS: u16 = 60;
pub(super) const MIN_ROWS: u16 = 16;

/// What a friend with no draft has in the composer.
static EMPTY_COMPOSER: Composer = Composer {
    text: String::new(),
    cursor: 0,
};

/// How long a toast shows, counted from when it is first shown.
const TOAST_TIME: Duration = Duration::from_secs(4);
/// Toasts kept at once: the one shown and those waiting their turn. A new one
/// past this replaces the oldest waiting one.
const MAX_TOASTS: usize = 3;
/// The meeting toasts (UXF.8): each of the two shows at most once a minute
/// for one friend, and one due sooner is dropped.
const MEETING_TOAST_EVERY: Duration = Duration::from_secs(60);
/// A burst after a meeting: this many messages or more from one friend,
/// arrived within [`BURST_WITHIN`], after none for [`BURST_AFTER_MS`].
const BURST_MIN: usize = 3;
const BURST_WITHIN: Duration = Duration::from_secs(60);
const BURST_AFTER_MS: u64 = 60 * 60_000;
/// How long QUIT takes no key that ends the app after its warning about
/// waiting messages (UXF.8) appeared or went: Q opens QUIT and also answers
/// that warning, and a key held down repeats.
pub(super) const QUIT_SETTLE: Duration = Duration::from_secs(1);

/// Ctrl+Z: raw mode turns it into a key, and suspending the app would leave
/// the terminal in raw mode under the shell.
const PAUSE_TOAST: &str = "Pausing is not supported here. Press Q to quit.";
/// UNLOCK's Esc (review E-harness-docs-ci-3): how to start it later.
pub(super) const UNLOCK_KEPT_TOAST: &str =
    "Raven stays stopped. To start it, press N, then S, or run `raven unlock`.";
/// UNLOCK's Enter, when the lock could not be cleared.
pub(super) const UNLOCK_FAILED_TOAST: &str =
    "Raven is still locked: the lock couldn't be cleared. Run `raven unlock` in a terminal.";
/// The classic menu was asked for while a save or a send runs: leaving now
/// could lose it.
const FINISHING_TOAST: &str =
    "Raven is still finishing (saving, or sending a message). Try again in a moment.";
/// A paste on the friend list: a card goes into Add a friend, never here.
pub(super) const LIST_PASTE_TOAST: &str = "To add a friend, press A and paste there.";
/// R on a waiting message, as raven-node answered it.
pub(super) const RETRYING_TOAST: &str = "Raven is trying to send it again now.";
pub(super) const NOT_RETRIED_TOAST: &str = "Raven's background program isn't retrying messages \
                                            now. This one goes out with your next message.";
pub(super) const NOT_WAITING_TOAST: &str = "That message isn't waiting to be sent any more.";
pub(super) const RETRY_FAILED_TOAST: &str = "Raven couldn't try it again now.";
/// C on a waiting message, confirmed.
pub(super) const STOPPED_TOAST: &str = "Raven stopped trying to send it.";
pub(super) const DELIVERED_FIRST_TOAST: &str = "It was delivered before Raven could stop it.";
pub(super) const STOP_FAILED_TOAST: &str = "Raven couldn't stop trying it.";
/// ext.rs's words for a message no longer waiting, an outbox no background
/// program runs, and a cancel that came too late (testkit checks ext.rs
/// still says them).
pub(super) const EXT_NOT_WAITING: &str = "is not waiting to be delivered";
pub(super) const EXT_NO_OUTBOX: &str = "outbox is not running here";
pub(super) const EXT_DELIVERED_FIRST: &str = "before it could be cancelled";
/// The composer's refusals, shown over it: no send while one holds.
pub(super) const CONTROL_REFUSED: &str =
    "This message has control characters Raven can't send. Remove them and try again.";
pub(super) const RESERVED_REFUSED: &str = "Messages can't start with RVNAPP/ or RVNGRP/.";
/// AF-1's share box, when no background program can receive for a reason
/// of its own (the copy adds '. [S] Show my invite anyway').
pub(super) const NO_PROGRAM_PATH: &str =
    "Raven can't tell where its own program is, so it can't start its background program";
pub(super) const NOT_RUNNING: &str = "Raven's background program isn't running";
pub(super) const NOT_LISTENING: &str =
    "Raven's background program is running, but it isn't listening for messages";
pub(super) const NOT_ANSWERING: &str = "Raven's background program isn't answering";
pub(super) const NO_CARD_ADDRESS: &str =
    "Raven couldn't put this computer's network address in your invite";
/// X on NET, as the stop went (a stop that worked shows as 'Not running').
pub(super) const STILL_RUNNING_TOAST: &str =
    "Raven asked its background program to stop, but it is still running.";
pub(super) const MANAGED_STOP_TOAST: &str = "Raven's background program is set to start when you \
                                             log in, so Raven doesn't stop it.";
pub(super) const NODE_STOP_FAILED_TOAST: &str = "Raven couldn't stop its background program.";
/// The most the paste box keeps: far more than any invite or card.
const PASTE_TEXT_MAX: usize = 16 * 1024;
/// The most characters a confirmation code's field takes ([U], VF).
const CODE_FIELD_MAX: usize = 8;
/// The most letters and digits VF's field takes of a friend's security code
/// (one has 12 at most).
const SECURITY_CODE_MAX: usize = 16;
/// The most characters VF's words field takes: 10 of the longest Raven
/// words with spaces are 89.
const WORDS_FIELD_MAX: usize = 120;
/// After this many well-formed entries that were not the friend's, VF stops
/// offering the check (`RAVEN_SECURITY_WORDS_V1.md` section 8, rule 4).
pub(super) const MAX_MISMATCHES: u8 = 3;
/// The most characters CI's address and 'remove' fields take.
const LINE_FIELD_MAX: usize = 64;
/// What CI's remove question wants typed.
const REMOVE_WORD: &str = "remove";
/// The word DEL asks for before a chat is deleted (PP.21).
const DELETE_WORD: &str = "delete";
/// The word ERASE asks for before this profile is erased (PP.22).
const ERASE_WORD: &str = "erase";
/// The word VF's older-method question asks for (design A R9, P6.31), as
/// `raven contact verify` does.
const ACCEPT_WORD: &str = "accept";
/// Resolving a security notice failed (P6.31).
const NOT_RESOLVED: &str = "Raven couldn't change its security notices right now.";
/// The name DEL's toasts give a friend who is not saved any more.
const NO_NAME: &str = "your friend";
/// How long changed read markers wait before they are saved: reading a
/// conversation as it grows writes the file once, not on every message.
const MARKS_SAVE_AFTER: Duration = Duration::from_secs(2);

/// How every screen looks: chosen at startup from Settings and the terminal
/// (theme.rs), and again as Settings change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Look {
    pub(super) glyphs: Glyphs,
    pub(super) theme: Theme,
    pub(super) motion: Motion,
    /// Time between spinner frames: 83 ms, or 166 ms over SSH.
    pub(super) spinner_interval: Duration,
}

impl Look {
    /// The look `settings` ask for in a terminal like `env`.
    pub(super) fn of(settings: &TuiState, env: &LookEnv) -> Look {
        Look {
            glyphs: env.glyphs(settings.symbols),
            theme: Theme::for_setting(settings.colors, settings.palette, &env.term),
            motion: env.motion(settings.motion),
            spinner_interval: theme::spinner_interval(&env.term),
        }
    }
}

/// What the look follows besides Settings, read once at startup: the
/// terminal's environment, the Windows output code page, and whether a
/// screen reader runs. Settings' changes apply with it at once.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct LookEnv {
    pub(super) term: TermEnv,
    pub(super) code_page: Option<u32>,
    pub(super) screen_reader: bool,
}

impl LookEnv {
    fn glyphs(&self, setting: SymbolSetting) -> Glyphs {
        Glyphs::of(theme::glyph_set(setting, &self.term, self.code_page))
    }

    fn motion(&self, setting: MotionSetting) -> Motion {
        theme::motion(setting, &self.term, self.screen_reader)
    }
}

/// The screen under the overlays. A window below [`MIN_COLS`] by
/// [`MIN_ROWS`] shows SMALL instead, without forgetting the screen: it is
/// back as it was once the window grows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Screen {
    /// WZ-1 to WZ-6: the first run, for a profile with no identity yet.
    Wizard(WizardStep),
    /// ERR-ID: the identity store can't be read, or raven-core refused to
    /// make a new identity over the files already there. It never offers to
    /// create one.
    IdentityError(Failure),
    /// HOME: the friend list, the open conversation and the composer.
    Home,
    /// AF-1, then AF-2: a friend from their invite or card, and a name.
    AddFriend(Box<AddFriendState>),
    /// NAME-CLASH: the name typed is a verified friend's, and the key is not.
    /// Nothing is saved from here.
    NameClash(Box<ClashState>),
    /// VF: the security words compared out loud, for a friend from AF-2 or a
    /// saved one.
    Verify(Box<VerifyState>),
    /// AF-3: the friend from VF is saved.
    Added(AddedState),
    /// CI: one saved friend's page.
    FriendPage(Box<PageState>),
    /// NET: the background program and this build's ways to reach friends.
    Network(Box<NetState>),
    /// MEET: meeting a friend without the internet, step by step (G).
    Meet(Box<MeetState>),
    /// SET: the app's settings, each saved as it changes.
    Settings(SettingsState),
}

/// SET's rows, top to bottom.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SetRow {
    /// The user's own name (Enter edits it).
    Name,
    Motion,
    Colors,
    Symbols,
    /// When I quit (OD-2).
    OnQuit,
    Receive,
    /// Share my network address in my invite.
    ShareAddress,
    /// Show technical details.
    Details,
    /// Keep chats for (PP.21): Enter opens KEEP. Shown once the privacy read
    /// answered.
    KeepChats,
    /// Start Raven when I log in: shown only (OD-11).
    LoginStart,
    /// Switch to the classic menu now: an action.
    ClassicNow,
    /// Always open the classic menu: read by the gate at the next start.
    AlwaysClassic,
    /// Lock now: an action, LOCK (UXF.7).
    LockNow,
    /// Lock v2 (P6.40), shown once the lock settings were read: 'Lock Raven
    /// when the computer sleeps' (raven-node's policy).
    SleepLock,
    /// 'Lock Raven when this app is idle' (this app's settings).
    IdleLock,
    /// 'Raven passphrase': Enter opens PASS.
    Passphrase,
    /// Erase Raven from this computer: an action, ERASE (PP.22). Shown once
    /// the privacy read answered.
    Erase,
}

impl SetRow {
    pub(super) const ALL: [SetRow; 17] = [
        SetRow::Name,
        SetRow::Motion,
        SetRow::Colors,
        SetRow::Symbols,
        SetRow::OnQuit,
        SetRow::Receive,
        SetRow::ShareAddress,
        SetRow::Details,
        SetRow::KeepChats,
        SetRow::LoginStart,
        SetRow::ClassicNow,
        SetRow::AlwaysClassic,
        SetRow::LockNow,
        SetRow::SleepLock,
        SetRow::IdleLock,
        SetRow::Passphrase,
        SetRow::Erase,
    ];
}

/// SET: the chosen row, the name while it is typed, and the stop question
/// after receiving was turned off.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SettingsState {
    pub(super) row: SetRow,
    /// Enter on 'Your name': the field as typed, at most [`NAME_CELLS`]
    /// cells, until Enter saves it or Esc leaves it.
    pub(super) name: Option<String>,
    /// Typing went past [`NAME_CELLS`] and stopped: the field says why.
    pub(super) name_full: bool,
    /// Receiving was turned off while a background program this app started
    /// runs: Y stops it, N keeps it.
    pub(super) asking_stop: bool,
}

impl SettingsState {
    fn new() -> SettingsState {
        SettingsState {
            row: SetRow::Name,
            name: None,
            name_full: false,
            asking_stop: false,
        }
    }
}

/// NET: the panel or its service log, and the stop question.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct NetState {
    /// Rows of the panel scrolled off its top.
    pub(super) scroll: u16,
    /// X: the stop question is up (Y stops, N keeps it running).
    pub(super) asking_stop: bool,
    /// L: the service log in place of the panel.
    pub(super) log: Option<LogView>,
}

/// What NET's keys can do now, besides L (the log) and Esc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct NetKeys {
    /// S: start the background program.
    pub(super) start: bool,
    /// X: stop it, after a yes.
    pub(super) stop: bool,
    /// R: ask it again after it stopped answering.
    pub(super) check_again: bool,
}

/// NET's log view: the service log's last lines, read on the node worker,
/// read again while it is open and the log grows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct LogView {
    /// Raw lines, oldest first, or why they can't be read; None until the
    /// first read answers.
    pub(super) lines: Option<Result<Vec<String>, String>>,
    /// A read is out: a change to the log waits for it.
    reading: bool,
    /// Lines scrolled up from the newest, which is at the bottom.
    pub(super) scroll: u16,
}

/// MEET: the guide for meeting a friend without the internet (UXF.6). It
/// explains and waits: it never changes Wi-Fi, firewall or system settings,
/// and runs no command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct MeetState {
    pub(super) step: MeetStep,
    /// Where G was pressed: Esc goes back there.
    pub(super) from: MeetFrom,
    /// The friend met (their key): Home's highlighted friend at G, another
    /// one chosen on step 3 with Up and Down. None with no friend saved.
    pub(super) friend: Option<String>,
    /// One of you makes a hotspot (1 or 2 on step 1): step 4 says to turn it
    /// off.
    pub(super) hotspot: bool,
    /// Step 2a says what whoever runs the hotspot can see: the first time
    /// this profile reached it (UXF.9), for the rest of this visit.
    pub(super) hotspot_note: bool,
    /// When G was pressed: a message from the friend that arrives after it,
    /// or one of yours delivered after it, shows you are connected.
    pub(super) opened: Instant,
    /// The friend's messages that were waiting then (ids, lower case): how
    /// many of them went, and were delivered, is counted from these.
    pub(super) waiting: Vec<String>,
    /// The retry step 3 asked for after a save (the message id): its answer
    /// is the guide's, and no toast.
    retry: Option<String>,
}

/// Where the guide is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum MeetStep {
    /// 1: what you need, and who makes the hotspot.
    Start,
    /// 2a: this computer makes it, in its own system's words.
    MakeHotspot,
    /// 2b: the friend makes it, and this computer joins.
    JoinHotspot,
    /// 3: this computer's address, and the friend's as typed.
    Find(FindState),
    /// 4: a message from the friend arrived, or one of yours was delivered,
    /// since G.
    Connected,
}

/// Step 3's field.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct FindState {
    /// The friend's address as typed, Persian and Arabic-Indic digits as 0-9.
    pub(super) text: String,
    /// Enter found it is not an address Raven can use.
    pub(super) bad: bool,
    /// The store worker saves it: the keys wait.
    pub(super) saving: bool,
    /// It was saved as it is typed now.
    pub(super) saved: bool,
}

impl MeetState {
    /// Step 3's address is being saved: the keys wait.
    pub(super) fn saving(&self) -> bool {
        matches!(&self.step, MeetStep::Find(find) if find.saving)
    }
}

/// Where G opened the guide.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MeetFrom {
    Home,
    Network,
}

/// Which of AF-1's boxes takes the keys. A paste goes into the paste box
/// whichever has them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AddFocus {
    /// My invite: L, C (and Ctrl+C) and S.
    Share,
    /// Their invite: typing is text there until it parses.
    Paste,
}

/// Add a friend: AF-1 (share mine, paste theirs), then AF-2 (who is it?).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AddFriendState {
    /// On AF-2: the paste parsed and Enter went on.
    pub(super) naming: bool,
    pub(super) focus: AddFocus,
    /// The paste box as pasted and typed, raw: no control character but
    /// line breaks, at most [`PASTE_TEXT_MAX`] bytes.
    pub(super) text: String,
    /// What the text is (`controller::parse_friend_paste`); None while it is
    /// empty.
    pub(super) parsed: Option<Result<FriendPreview, PasteProblem>>,
    /// When it came to parse as this friend: the summary fades from bold.
    pub(super) parsed_at: Option<Instant>,
    /// When text last came into the paste box: what follows within the paste
    /// guard is the rest of it, never a key.
    last_input: Option<Instant>,
    /// When AF-1 opened: the share box's spinner turns from then while
    /// nothing is known yet.
    pub(super) opened: Instant,
    /// S: my invite without an address is on show.
    pub(super) share_anyway: bool,
    /// [U]'s question for a friend already saved: their new addresses need
    /// its confirmation code.
    pub(super) update: Option<ConfirmCode>,
    /// The [U] save is running.
    pub(super) updating: bool,
    /// Why the last [U] save failed, in plain words.
    pub(super) update_error: Option<String>,
    /// AF-2's field: the friend's name as typed, at most [`NAME_CELLS`]
    /// cells.
    pub(super) name: String,
    pub(super) name_full: bool,
    /// What Enter on AF-2 found wrong with the name.
    pub(super) name_problem: Option<NameProblem>,
    /// AF-2's hint says to use a nickname: the first time this profile
    /// reached AF-2 (UXF.9), for the rest of this visit.
    pub(super) names_note: bool,
}

impl AddFriendState {
    fn new(now: Instant) -> AddFriendState {
        AddFriendState {
            naming: false,
            focus: AddFocus::Paste,
            text: String::new(),
            parsed: None,
            parsed_at: None,
            last_input: None,
            opened: now,
            share_anyway: false,
            update: None,
            updating: false,
            update_error: None,
            name: String::new(),
            name_full: false,
            name_problem: None,
            names_note: false,
        }
    }

    /// The friend the paste parsed to.
    pub(super) fn friend(&self) -> Option<&FriendPreview> {
        self.parsed.as_ref().and_then(|parsed| parsed.as_ref().ok())
    }

    /// Text that came within the paste guard of the last: the rest of a
    /// paste, or fast typing.
    fn follows_input(&self, now: Instant) -> bool {
        self.last_input
            .is_some_and(|at| now.saturating_duration_since(at) < PASTE_GUARD)
    }

    /// `raw` into the paste box as text: after what is there, or in its
    /// place when that parsed already and this is not the rest of it.
    fn input(&mut self, raw: &str, me_pub_hex: &str, now: Instant) {
        let add = display::field_input(raw, true);
        if self.friend().is_some() && !self.follows_input(now) {
            self.text.clear();
        }
        let room = PASTE_TEXT_MAX.saturating_sub(self.text.len());
        let mut cut = add.len().min(room);
        while !add.is_char_boundary(cut) {
            cut -= 1;
        }
        self.text.push_str(&add[..cut]);
        self.last_input = Some(now);
        self.focus = AddFocus::Paste;
        self.reparse(me_pub_hex, now);
    }

    /// The paste box emptied (Ctrl+U), or its last grapheme gone.
    fn erase(&mut self, all: bool, me_pub_hex: &str, now: Instant) {
        if all || self.friend().is_some() {
            self.text.clear();
        } else if let Some(&start) = grapheme_bounds(&self.text)
            .iter()
            .rev()
            .find(|&&at| at < self.text.len())
        {
            self.text.truncate(start);
        }
        self.reparse(me_pub_hex, now);
    }

    /// Parses the paste box again: pure, no file and no key store. A [U]
    /// question or its failure belonged to the text before.
    fn reparse(&mut self, me_pub_hex: &str, now: Instant) {
        let before = self.friend().map(|friend| friend.pub_hex.clone());
        self.parsed = (!self.text.trim().is_empty())
            .then(|| controller::parse_friend_paste(&self.text, me_pub_hex));
        self.parsed_at = match self.friend() {
            Some(friend) if before.as_deref() == Some(friend.pub_hex.as_str()) => self.parsed_at,
            Some(_) => Some(now),
            None => None,
        };
        self.update = None;
        self.update_error = None;
    }
}

/// Why AF-2 did not go on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum NameProblem {
    Empty,
    /// The friend `pub_hex` (not verified) has this name.
    Taken(String),
}

/// A fresh confirmation code for one save ([U] on AF-1, VF), and what is
/// typed of it. It is drawn when the question appears, so no pasted card can
/// hold it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ConfirmCode {
    pub(super) code: String,
    pub(super) typed: String,
    /// The code typed last was wrong: this one is new.
    pub(super) wrong: bool,
    /// Enter found letters of another alphabet in what is typed: the
    /// keyboard is not on Latin letters. The code and what is typed stay.
    pub(super) keyboard: bool,
}

impl ConfirmCode {
    fn new(wrong: bool) -> ConfirmCode {
        ConfirmCode {
            code: bridge::new_confirm_code(&mut rand::thread_rng()),
            typed: String::new(),
            wrong,
            keyboard: false,
        }
    }

    /// `raw` typed into its field, as one line with Persian and
    /// Arabic-Indic digits as 0-9, up to [`CODE_FIELD_MAX`] characters.
    fn type_text(&mut self, raw: &str) {
        for c in bridge::fold_code_digits(&display::field_input(raw, false)).chars() {
            if self.typed.chars().count() >= CODE_FIELD_MAX {
                break;
            }
            self.typed.push(c);
        }
    }
}

/// NAME-CLASH: AF-2 as it was (Esc goes back to it), and the verified friend
/// whose name was typed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ClashState {
    pub(super) back: AddFriendState,
    pub(super) verified: String,
}

/// VF: whose security words (or old code) are compared, how far, and what
/// is typed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct VerifyState {
    pub(super) who: VerifyWho,
    /// The group of my own code the read-aloud helper spells (Left, Right),
    /// in code mode.
    pub(super) helper: usize,
    /// What is typed of the friend's words, or of their old code.
    pub(super) entry: Entry,
    /// The last group of the code typed to get its mark, and when: it draws
    /// in. Code mode only.
    pub(super) marked: Option<(usize, Instant)>,
    /// Well-formed entries that were not theirs (words or code): after
    /// [`MAX_MISMATCHES`] Enter checks no more.
    pub(super) mismatches: u8,
    pub(super) step: VerifyStep,
}

impl VerifyState {
    /// Enough entries were not theirs: VF stops offering the check.
    pub(super) fn stopped(&self) -> bool {
        self.mismatches >= MAX_MISMATCHES
    }
}

/// VF's field: the friend's security words as they read them (the default),
/// or their old code (for a friend with an older Raven).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(super) struct Entry {
    pub(super) mode: EntryMode,
    /// The words typed so far, as list indexes: only a Raven word becomes a
    /// chip.
    pub(super) chips: Vec<u8>,
    /// What is typed after the last chip: the word being typed, lower case
    /// a-z (after a pasted word that is not a Raven word, the rest of the
    /// paste too, a space between its words).
    pub(super) current: String,
    /// What is typed of the old code: letters and digits only (the
    /// separators are drawn; Persian and Arabic-Indic digits as 0-9), at
    /// most [`SECURITY_CODE_MAX`].
    pub(super) code: String,
}

/// What VF's field takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) enum EntryMode {
    #[default]
    Words,
    Code,
}

impl Entry {
    /// What the comparator reads: the words (the chips, then what is typed
    /// after them), or the code.
    pub(super) fn text(&self) -> String {
        match self.mode {
            EntryMode::Code => self.code.clone(),
            EntryMode::Words => {
                let mut words: Vec<&str> =
                    self.chips.iter().map(|&i| bridge::list_word(i)).collect();
                if !self.current.trim().is_empty() {
                    words.push(self.current.trim());
                }
                words.join(" ")
            }
        }
    }

    /// The word being typed, when it stands for exactly one Raven word: a
    /// Raven word, its plural, 3 letters of one, or the start of only one.
    fn pick(&self) -> Option<u8> {
        if self.current.is_empty() || self.current.contains(' ') {
            return None;
        }
        match bridge::word_suggestions(&self.current)[..] {
            [index] => Some(index),
            _ => None,
        }
    }

    /// The word being typed made a chip, if it can be one ([`Entry::pick`]).
    fn chip(&mut self) -> bool {
        let Some(index) = self.pick() else {
            return false;
        };
        self.chips.push(index);
        self.current.clear();
        true
    }

    /// Why what is typed after the chips is not a Raven word: the first word
    /// of it that is not one, by its place in the set (word `chips + 1`
    /// onwards). None when it is one (or nothing is typed).
    fn word_problem(&self) -> Option<bridge::ParseError> {
        use bridge::{ParseError, TokenError};
        if self.pick().is_some() {
            return None;
        }
        let first = self.chips.len() + 1;
        bridge::word_tokens(&self.current)
            .iter()
            .enumerate()
            .find_map(|(n, word)| {
                let position = first + n;
                match bridge::resolve_word(word) {
                    Ok(_) => None,
                    Err(TokenError::Ambiguous) => Some(ParseError::Ambiguous { position }),
                    Err(TokenError::Unknown) => Some(ParseError::Unknown { position }),
                    Err(TokenError::NonLatin) => Some(ParseError::NonLatin { position }),
                }
            })
    }

    /// `text` typed (or pasted) into the words field. Letters go into the
    /// word being typed (lower case; full-width ones as a-z); a space or
    /// other separator makes it a chip when it is a Raven word ([`chip`]).
    /// Digits are position numbers ("1. turtle"), and invisible characters
    /// go. A word that is not a Raven word stays typed: what is typed then
    /// says why, and in a paste the rest follows it after a space, so no
    /// two words run together. Other characters are not kept: true when
    /// one came (the keyboard is not on English letters).
    ///
    /// [`chip`]: Entry::chip
    fn type_words(&mut self, text: &str, pasted: bool) -> (bool, Option<bridge::ParseError>) {
        let mut other = false;
        let mut problem = None;
        for c in text.chars() {
            match word_char(c) {
                WordChar::Letter(letter) => {
                    if self.text().chars().count() < WORDS_FIELD_MAX {
                        self.current.push(letter);
                    }
                }
                WordChar::Gap => {
                    if self.current.is_empty() || self.current.ends_with(' ') {
                        continue;
                    }
                    if self.current.contains(' ') || !self.chip() {
                        problem = problem.or_else(|| self.word_problem());
                        if (pasted || self.current.contains(' '))
                            && self.text().chars().count() < WORDS_FIELD_MAX
                        {
                            self.current.push(' ');
                        }
                    }
                }
                WordChar::Skip => {}
                WordChar::Other => other = true,
            }
        }
        (other, problem)
    }

    /// Backspace: a letter of what is typed; with nothing typed after the
    /// chips, the last chip, whole (it is typed again as it was read). In
    /// code mode, a letter of the code.
    fn erase(&mut self) {
        match self.mode {
            EntryMode::Code => {
                self.code.pop();
            }
            EntryMode::Words => {
                if self.current.pop().is_none() {
                    self.chips.pop();
                }
            }
        }
    }
}

/// One character typed into VF's words field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WordChar {
    /// An English letter, as a-z.
    Letter(char),
    /// A space, dash or punctuation between words (raven-core's), or a
    /// digit: a position number ("1. turtle").
    Gap,
    /// An invisible character (a zero-width space, a direction mark).
    Skip,
    /// Any other character: another alphabet, an accented letter.
    Other,
}

/// How VF's words field reads `c`. Separators and invisible characters are
/// raven-core's (`split_tokens`), so the field and the comparator agree.
fn word_char(c: char) -> WordChar {
    match c {
        'a'..='z' => WordChar::Letter(c),
        'A'..='Z' => WordChar::Letter(c.to_ascii_lowercase()),
        '\u{FF21}'..='\u{FF3A}' | '\u{FF41}'..='\u{FF5A}' => {
            let first = if c <= '\u{FF3A}' { 0xFF21 } else { 0xFF41 };
            let offset = u8::try_from(u32::from(c) - first).unwrap_or(0);
            WordChar::Letter(char::from(b'a' + offset))
        }
        _ if bridge::fold_code_digits(&c.to_string())
            .chars()
            .all(|d| d.is_ascii_digit())
            || matches!(c, '\u{FF10}'..='\u{FF19}') =>
        {
            WordChar::Gap
        }
        _ => match &bridge::word_tokens(&format!("a{c}a"))[..] {
            [_, _] => WordChar::Gap,
            [one] if one == "aa" => WordChar::Skip,
            _ => WordChar::Other,
        },
    }
}

/// Whose security code VF checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum VerifyWho {
    /// A friend from AF-2, not saved yet: AF-2 as it was (the paste and the
    /// name), for Esc and for the save.
    New(Box<AddFriendState>),
    /// A saved friend, by key; Esc goes back to `back`.
    Saved { pub_hex: String, back: Back },
}

/// Where Esc on VF goes for a saved friend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Back {
    Home,
    FriendPage,
}

/// How far VF is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum VerifyStep {
    /// The friend's code is being typed, and what the last Enter found (or,
    /// for letters of another alphabet, what was typed).
    Comparing(Option<CodeProblem>),
    /// It matched at `at` (both columns stand out for a moment): the code
    /// shows, and the confirmation code is asked for.
    Matched { at: Instant, confirm: ConfirmCode },
    /// Tab: saved as not verified, after the confirmation code.
    Later(ConfirmCode),
    /// The save runs; `verified`: with the pin.
    Saving { verified: bool },
    /// The save failed, in plain words; D shows the technical text.
    Failed(Failure),
    /// The friend is verified already: both codes, and Enter checks again
    /// (P6.31): a match resolves their security notices.
    AlreadyVerified,
    /// After "Check again" matched with the security words, while the
    /// friend's Raven offers an older security method than before (design A
    /// R9): 'accept' typed accepts it, anything else keeps the newer one.
    OlderMethod { typed: String },
}

/// Why what was typed did not match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CodeProblem {
    /// The same letters, but upper and lower case differ somewhere (code
    /// mode).
    CaseOnly,
    /// Well-formed words, or a code, that are not the friend's.
    Mismatch,
    /// Letters of another alphabet were typed (the field keeps none): the
    /// keyboard is not on Latin letters. It stays until a Latin letter is
    /// typed, and Enter keeps it: never the mismatch's warning.
    Keyboard,
    /// What is typed is not 10 valid words (raven-core's parse status, with
    /// the place of the word): it depends only on the typed text.
    Words(bridge::ParseError),
}

/// What VF draws, worked out by the App: the friend's words and code
/// themselves only once they matched, so a frame before that can't hold
/// them. Everything else depends only on what was typed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct VerifyView<'a> {
    pub(super) state: &'a VerifyState,
    /// The friend's name, shaped.
    pub(super) name: String,
    /// Not saved yet: Later saves them as not verified.
    pub(super) new: bool,
    /// My own security code in groups of 4.
    pub(super) mine: Vec<String>,
    /// My own security words.
    pub(super) mine_words: Vec<String>,
    /// What is typed of their code in groups of 4, each with its mark once
    /// it is complete: right (true) or wrong. Code mode only: words get no
    /// mark against theirs.
    pub(super) typed: Vec<(String, Option<bool>)>,
    /// The words typed so far (the chips), as the list has them.
    pub(super) chips: Vec<&'static str>,
    /// The Raven words the word being typed can become, from the whole list
    /// in list order; empty while nothing is typed after the chips.
    pub(super) suggestions: Vec<&'static str>,
    /// Their code in groups, once it matched (or for a friend verified
    /// already); None before.
    pub(super) theirs: Option<Vec<String>>,
    /// Their security words, once they matched (or for a friend verified
    /// already); None before.
    pub(super) theirs_words: Option<Vec<String>>,
}

/// AF-3: who was saved, and whether verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AddedState {
    /// Lower case, as contacts.json keeps it.
    pub(super) pub_hex: String,
    /// The name typed on AF-2, raw.
    pub(super) name: String,
    pub(super) verified: bool,
    /// When it opened: the check mark draws in.
    pub(super) at: Instant,
}

/// CI: the friend `pub_hex`, the field open on the page, and how the last
/// change went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PageState {
    pub(super) pub_hex: String,
    pub(super) edit: Option<PageEdit>,
    /// A change is being saved: the keys wait for it.
    pub(super) saving: bool,
    /// Why the last change failed.
    pub(super) failure: Option<Failure>,
}

/// A field open on CI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum PageEdit {
    /// R: the new name as typed, at most [`NAME_CELLS`] cells, and what Enter
    /// found wrong with it.
    Rename {
        name: String,
        full: bool,
        problem: Option<NameProblem>,
    },
    /// E: the local-network address as typed (Persian and Arabic-Indic
    /// digits as 0-9); `bad`: Enter found it is not one Raven can use.
    Address { text: String, bad: bool },
    /// X: what is typed of 'remove'.
    Remove { typed: String },
}

/// A change to one friend, each written by the store worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FriendChange {
    /// A new friend from VF.
    Add,
    /// A saved friend, verified on VF.
    Verify,
    Rename,
    Address,
    Remove,
    Unblock,
    /// F on CI (PP.21): the saved addresses forgotten.
    ForgetAddress,
}

/// What AF-1's share box says about my invite (OD-5): this computer's
/// address only from a node that listens on the network; otherwise why not,
/// with S for the invite without one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ShareState {
    /// Raven is starting, or making the card: a spinner from `since`.
    Starting {
        since: Instant,
    },
    /// A friend can reach the listener at `lan`.
    Ready {
        lan: String,
    },
    /// The listener is on this computer only, at `ip`.
    LocalOnly {
        ip: String,
    },
    ReceiveOff,
    NeedsSetup,
    /// Why nothing receives, in plain words (without a final full stop).
    Failed(String),
    /// Listening on every address, and this computer's own can't be told.
    NoAddress,
}

/// The share box: its state, and the line on show, if any (the card with my
/// address, or without one after S or with L off).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ShareView {
    pub(super) state: ShareState,
    pub(super) line: Option<String>,
    pub(super) with_address: bool,
}

impl ShareView {
    /// S shows the invite without an address: in every state that can't
    /// share one, and not while Raven starts.
    pub(super) fn offers_anyway(&self) -> bool {
        !matches!(
            self.state,
            ShareState::Starting { .. } | ShareState::Ready { .. }
        )
    }
}

/// Where the first run is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum WizardStep {
    /// WZ-1, its letters appearing one by one from `since`; None when they
    /// are all there already (back from WZ-2).
    Welcome { since: Option<Instant> },
    /// WZ-2: the user's own name, typed into [`App::name`].
    Name,
    /// WZ-3: may Raven receive on this computer? `yes`: Yes is highlighted
    /// (it is at first).
    Receive { yes: bool },
    /// WZ-4.
    Creating(Creating),
    /// WZ-5: the user's own security words, appearing one by one from
    /// `since`, and the old-style code.
    Words { since: Instant },
    /// WZ-6.
    Ready,
}

/// WZ-4's two states.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Creating {
    /// The vault check, then the identity being made, since `since`: a
    /// spinner, and no key but Ctrl+C.
    Working { since: Instant },
    /// It failed: [R] tries again. A refusal over files already in the
    /// profile goes to ERR-ID instead.
    Failed(Failure),
}

/// A failure on a screen of its own, in plain words, with its technical text
/// shown or not ([D]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Failure {
    pub(super) plain: Plain,
    pub(super) details: bool,
}

impl Failure {
    /// Its technical text shown at once when Settings ask for technical
    /// details (`details`).
    fn new(plain: Plain, details: bool) -> Failure {
        Failure { plain, details }
    }
}

/// Boxes drawn over the screen; the last one gets the keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Overlay {
    /// Keys and the meaning of every mark, scrolled by `scroll` rows.
    Help {
        scroll: u16,
    },
    Quit,
    /// RX: may Raven receive on this computer? Asked once, before the first
    /// start, for a profile that never answered.
    Receive(RxState),
    /// UNLOCK (review E-harness-docs-ci-3): the app opened on a profile
    /// `raven lock` locked. Start Raven again, or keep it stopped?
    Unlock,
    /// KC: a Keychain dialog holds Raven up ([`App::keychain`] says what).
    Keychain,
    /// PASSFILE: raven-node needs the vault passphrase in a file.
    PassFile,
    /// MSG: one message of yours, its state and what can be done.
    Message(MessageView),
    /// A yes-or-no question before a message is stopped or sent again.
    Confirm(ConfirmState),
    /// FW: the firewall may ask about raven-node (Windows or macOS).
    Firewall,
    /// NOTE (UXF.9), once per profile: what people on this network can see
    /// now that Raven receives on it.
    NetworkNote,
    /// LOCK (UXF.7): this profile's background program stops, the terminal
    /// is cleared and the app ends. From SET's 'Lock now' and QUIT's [L].
    Lock(LockStep),
    /// KEEP (PP.21): SET's 'Keep chats for' chooser, on `choice`; Enter
    /// saves it.
    KeepChats {
        choice: ChatKeepView,
    },
    /// DEL (PP.21): 'Delete chat with {name}' for the friend `peer` (lower
    /// case); Enter deletes once `typed` is 'delete'.
    DeleteChat {
        peer: String,
        typed: String,
    },
    /// FORGET (PP.21): 'Forget {name}'s address' for the friend `peer`
    /// (lower case); Enter forgets.
    ForgetAddress {
        peer: String,
    },
    /// NOTICE (PP.21): one of the privacy pack's notices, once, on Home.
    PrivacyNotice(Notice),
    /// ERASE (PP.22): SET's 'Erase Raven from this computer', over the
    /// whole screen.
    Erase(EraseState),
    /// SEC (P6.31): the open security alerts and warnings, from W (Home,
    /// CI, NET) and D on a friend with one.
    Security(SecState),
    /// LOCKED (Lock v2, P6.40): this profile's raven-node runs locked; under
    /// every other overlay, over the whole screen.
    Locked(LockedView),
    /// PASS (P6.40): SET's 'Raven passphrase'.
    Passphrase(PassState),
    /// UPDATES (P6.47): what waits to be installed, and its install after
    /// the word is typed (U on Home and NET).
    Updates(UpdState),
    /// The groups' boxes (lab): NEW GROUP's name and the friend picker,
    /// MEMBERS, WHO HAS IT (app/groups.rs).
    Group(GroupOverlay),
}

/// SEC: which notice is chosen (by its place in the list) and whether its
/// details show.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct SecState {
    pub(super) chosen: usize,
    pub(super) details: bool,
}

impl Overlay {
    /// It needs the privacy read: it goes when that says not available.
    /// ERASE stays once its erase began.
    fn needs_privacy(&self) -> bool {
        match self {
            Overlay::KeepChats { .. }
            | Overlay::DeleteChat { .. }
            | Overlay::ForgetAddress { .. }
            | Overlay::PrivacyNotice(_) => true,
            Overlay::Erase(erase) => !erase.erasing(),
            _ => false,
        }
    }
}

/// Where ERASE is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum EraseState {
    /// What erasing would delete is being read (`bridge::erase_plan`).
    Reading,
    /// Erase refuses this profile, or the read failed: why (raw). Nothing
    /// was changed.
    Refused(String),
    /// The question with what goes in plain words, and the word as typed:
    /// Enter (not right after a paste) erases once it is 'erase'.
    Asking { plan: ErasePlanView, typed: String },
    /// 'erase' was typed and Enter pressed at `since`; `stage` says how far
    /// it is. Only the erase's answer ends this.
    Erasing { since: Instant, stage: EraseStage },
    /// The erase changed nothing (Raven still runs, or the folder is
    /// refused): why (raw), in the CLI's words. The app goes on.
    NotErased(String),
}

impl EraseState {
    /// Enter was pressed with 'erase' typed.
    pub(super) fn erasing(&self) -> bool {
        matches!(self, EraseState::Erasing { .. })
    }
}

/// How far ERASE's erase is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EraseStage {
    /// Every job in flight finishes first (a send, a save, a read): then no
    /// worker holds the profile open. Esc still cancels.
    Waiting,
    /// The background program this app started is being stopped (on
    /// Windows only this app may stop it).
    Stopping,
    /// The erase job runs (it stops Raven itself, as `raven erase` does,
    /// when it still runs).
    Running,
}

/// Where LOCK is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum LockStep {
    /// The question: Enter locks (a keychain profile: stops), Esc cancels.
    Asking,
    /// Enter was pressed at `since`. A message still being sent, or a change
    /// to the friends being saved, goes first (Esc still cancels); then the
    /// stop is asked for (`stopping`), and only its answer ends this.
    Locking { since: Instant, stopping: bool },
    /// The stop answered, and the background program may still run: why
    /// (never Stopped or NotRunning).
    NotStopped(StopOutcome),
}

/// MSG: which message, in whose conversation, and whether its technical
/// details show (D).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct MessageView {
    /// The friend's key, lower case.
    pub(super) peer: String,
    pub(super) key: BubbleKey,
    pub(super) details: bool,
}

/// What Y does in a confirm box, for the friend `peer` (lower case).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ConfirmState {
    pub(super) peer: String,
    pub(super) action: ConfirmAction,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ConfirmAction {
    /// raven-node stops trying message `mid`.
    StopTrying { mid: String },
    /// `body` goes again as a new message, though the friend may have it.
    SendAgain { body: String },
}

/// One message of a conversation: a history row by its id (lower case; for
/// a legacy row without one, its direction, time and length), or a send of
/// this session no row is bound to yet.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) enum BubbleKey {
    Mid(String),
    Local(u64),
}

/// One message of a conversation as Home draws it.
#[derive(Debug, Clone, Copy)]
pub(super) enum Bubble<'a> {
    Row(&'a Row),
    /// Sent in this session, with no history row bound to it yet.
    Pending(&'a PendingSend),
}

impl Bubble<'_> {
    pub(super) fn outgoing(&self) -> bool {
        match self {
            Bubble::Row(row) => row.view.outgoing,
            Bubble::Pending(_) => true,
        }
    }

    /// The friend later sent different text under this message's id (the
    /// body shown is the first).
    pub(super) fn id_conflict(&self) -> bool {
        match self {
            Bubble::Row(row) => row.view.id_conflict,
            Bubble::Pending(_) => false,
        }
    }

    /// Raw: shaped by display.rs when drawn.
    pub(super) fn body(&self) -> &str {
        match self {
            Bubble::Row(row) => &row.view.body,
            Bubble::Pending(send) => &send.body,
        }
    }

    /// When the sender's computer made it (for a send of this session, this
    /// one's clock at Enter).
    pub(super) fn created_at_ms(&self) -> u64 {
        match self {
            Bubble::Row(row) => row.view.created_at_ms,
            Bubble::Pending(send) => send.sent_ms,
        }
    }

    /// Its message id (hex), once known.
    pub(super) fn mid(&self) -> Option<&str> {
        match self {
            Bubble::Row(row) if !row.view.id.is_empty() => Some(&row.view.id),
            _ => None,
        }
    }

    pub(super) fn key(&self) -> BubbleKey {
        match self {
            Bubble::Row(row) if row.view.id.is_empty() => BubbleKey::Mid(format!(
                "legacy:{}:{}:{}",
                row.view.outgoing,
                row.view.created_at_ms,
                row.view.body.len()
            )),
            Bubble::Row(row) => BubbleKey::Mid(row.view.id.to_ascii_lowercase()),
            Bubble::Pending(send) => BubbleKey::Local(send.local_id),
        }
    }
}

/// Where one message of yours stands, for its tick, label and MSG.
#[derive(Debug, Clone)]
pub(super) struct TickView<'a> {
    pub(super) tick: Tick,
    pub(super) evidence: WriteEvidence,
    /// Its send in this session, if it was one.
    pub(super) pending: Option<&'a PendingSend>,
    /// raven-node's outbox item for it, as last listed.
    pub(super) outbox: Option<&'a OutboxItem>,
    /// Its message id, once known.
    pub(super) mid: Option<&'a str>,
    /// When it came to this state, if this app saw it change (None: as it
    /// was when first seen, which nothing animates).
    pub(super) since: Option<Instant>,
    /// What R, C and S may do now (R and C need the message id).
    pub(super) actions: Actions,
    /// A delivered history row: when it was written, and when this app saw
    /// it delivered (None when it was so at the start), for the time a late
    /// delivery came (E1).
    pub(super) delivered: Option<(u64, Option<u64>)>,
}

impl TickView<'_> {
    /// How its send job ended, if it was one of this session's.
    pub(super) fn outcome(&self) -> Option<&Outcome> {
        self.pending.and_then(|send| send.outcome.as_ref())
    }
}

/// The receive question: what asked it, and which answer Enter gives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RxState {
    pub(super) trigger: AutoStart,
    /// Yes is highlighted (it is at first).
    pub(super) yes: bool,
}

/// Why the background program would start by itself (OD-3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AutoStart {
    /// The app opened with at least one friend saved.
    Launch,
    /// Add a friend opened: the friend needs this computer's address.
    AddFriend,
}

/// A start or a send refused because `raven lock` locked the profile
/// (ext.rs's `LOCKED_TEXT`).
fn is_locked_text(why: &str) -> bool {
    why.trim() == raven_core::privacy::LOCKED_TEXT
}

/// A start that waits for UNLOCK's Enter (review E-harness-docs-ci-3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AfterUnlock {
    /// One the app would have made by itself.
    Auto(AutoStart),
    /// NET's S.
    Net,
}

/// Whether the profile has its identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum IdentityStatus {
    /// Before [`App::start`].
    Pending,
    Ready,
    /// None yet: nothing touches the profile until the wizard makes one.
    Missing,
    /// The identity store can't be read (raven-core's reason).
    Unavailable(String),
}

/// What the plain terminal found before the screen opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum IdentityStart {
    Ready(MeView),
    Missing,
    Unavailable(String),
}

/// Who chose the listen address of a node this app starts
/// (`RAVEN_SERVICE_LAN_LISTEN`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ListenOverride {
    /// Nobody: ext.rs's default, every address on port 7420 (OD-4).
    None,
    /// The user set it: the app leaves it alone.
    User,
    /// This app set it to this computer only, because receiving is off.
    Loopback,
}

/// The session the App starts with ([`App::start`]).
#[derive(Debug, Clone)]
pub(super) struct Session {
    pub(super) identity: IdentityStart,
    /// The profile's folder, as WZ-1 and ERR-ID name it.
    pub(super) data_dir: PathBuf,
    pub(super) settings: TuiState,
    pub(super) program: Program,
    pub(super) listen: ListenOverride,
    /// SSH_CONNECTION or SSH_TTY is set: no Keychain dialog can appear here.
    pub(super) over_ssh: bool,
    /// What this build lets on, read before the app's threads start.
    pub(super) gates: GatesView,
    /// The terminal the look follows besides Settings.
    pub(super) look_env: LookEnv,
    /// `raven lock` locked the profile, and the lock is still on (review
    /// E-harness-docs-ci-3): UNLOCK asks before anything starts Raven.
    pub(super) locked: bool,
}

/// A Keychain wait on show (or hidden with Esc), since `since`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct KeychainView {
    pub(super) wait: KeychainWait,
    pub(super) since: Instant,
}

/// Work for the store worker. Every write to contacts.json is one of these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum StoreJob {
    LoadContacts,
    /// Every conversation, from the chat history.
    LoadHistory,
    /// How long a message written now could wait for each of `peers` (the
    /// friends, by key): read from the profile, nothing is written.
    LoadHorizons {
        peers: Vec<String>,
    },
    /// tui_state.json, once the identity exists.
    SaveSettings(TuiState),
    /// tui_state.json for its read markers or a note shown once: skipped
    /// while the file is there but can't be read (the user did not ask for
    /// this save).
    SaveReadMarks(TuiState),
    /// The read markers as saved: the desktop app's reads come in so
    /// (read_marks.rs).
    LoadReadMarks,
    /// Whether making the identity will ask for a passphrase on the terminal
    /// (a passphrase-vault profile). Records nothing in the profile.
    CheckVault,
    /// Makes the identity behind WZ-4's spinner: no prompt needs the
    /// terminal.
    CreateIdentity,
    /// A send reached the friend `pub_hex` at the address it learned for
    /// them: saved as theirs, as `raven send` keeps it.
    SaveLearnedDial {
        pub_hex: String,
        dial: String,
    },
    /// My invite for AF-1: the cards for a node listening at `listen` (its
    /// Status's listener, only while it listens on the network), or with no
    /// address.
    ShareCard {
        listen: Option<String>,
    },
    /// [U] on AF-1, after the confirmation code: a saved friend's routes from
    /// their new invite. Their name and pin stay.
    UpdateAddresses(FriendPreview),
    /// VF, after both checks (or the confirmation code alone for Later): a
    /// new friend with the name typed on AF-2 and the paste's routes.
    SaveFriend {
        friend: FriendPreview,
        name: String,
        verify: Verify,
    },
    /// VF for a saved friend, after both checks: pinned with the code as
    /// typed. Their name and routes stay.
    VerifyExisting {
        pub_hex: String,
        typed_fp: String,
    },
    /// R on CI: the name checked against the others' already.
    RenameFriend {
        pub_hex: String,
        name: String,
    },
    /// E on CI: the local-network address as typed (checked already).
    SetFriendAddress {
        pub_hex: String,
        address: String,
    },
    /// X on CI, after 'remove' was typed.
    RemoveFriend {
        pub_hex: String,
    },
    /// U on CI.
    UnblockFriend {
        pub_hex: String,
    },
    /// The privacy pack's read (PP.21): 'Keep chats for', the one-time
    /// notices due, the free disk space sealing waits for. Nothing is
    /// written.
    LoadPrivacy,
    /// KEEP's choice, saved as `raven chats keep` saves it.
    SetChatKeep(ChatKeepView),
    /// A one-time notice was shown and answered OK: the CLI doesn't say it
    /// again.
    MarkNoticeShown(Notice),
    /// C on CI, after 'delete' was typed: the chat with the friend goes
    /// from this computer.
    DeleteChat {
        pub_hex: String,
    },
    /// ERASE's list: what erasing this profile deletes, or why erase
    /// refuses it. Nothing is written.
    ErasePlan,
    /// ERASE, after 'erase' was typed and nothing else ran: this profile is
    /// erased as `raven erase` erases it.
    Erase,
    /// F on CI, after Enter: the friend's saved addresses are forgotten.
    ForgetAddress {
        pub_hex: String,
    },
    /// The security notices and the friends sending is paused to (P6.31):
    /// read, nothing is written (the ledger is never created by it).
    LoadSecurity,
    /// R on SEC: the notice with the ledger's `id` is resolved.
    ResolveNotice {
        id: i64,
    },
    /// P: sending to the friend `pub_hex` paused (`on`) or resumed.
    SetSendHold {
        pub_hex: String,
        on: bool,
    },
    /// "Check again" (VF for a verified friend) matched with `typed`: their
    /// open security notices are resolved.
    Recheck {
        pub_hex: String,
        typed: String,
    },
    /// 'accept' typed after "Check again" matched with the words `typed`:
    /// the friend's older security method is accepted.
    AcceptOlderMethod {
        pub_hex: String,
        typed: String,
    },
    /// Every group and the chat of `open` (lab); with `refresh`, after the
    /// copies' delivery and the waiting work (`group::run_pending`).
    LoadGroups {
        open: Option<raven_core::group::GroupId>,
        refresh: bool,
    },
    /// The group's chat is on screen: its messages are read here.
    MarkGroupRead {
        group: raven_core::group::GroupId,
    },
}

impl StoreJob {
    pub(super) fn name(&self) -> JobName {
        match self {
            StoreJob::LoadContacts => JobName::LoadContacts,
            StoreJob::LoadHistory => JobName::LoadHistory,
            StoreJob::LoadHorizons { .. } => JobName::LoadHorizons,
            StoreJob::SaveSettings(_) => JobName::SaveSettings,
            StoreJob::SaveReadMarks(_) => JobName::SaveReadMarks,
            StoreJob::LoadReadMarks => JobName::LoadReadMarks,
            StoreJob::CheckVault => JobName::CheckVault,
            StoreJob::CreateIdentity => JobName::CreateIdentity,
            StoreJob::SaveLearnedDial { .. } => JobName::SaveLearnedDial,
            StoreJob::ShareCard { .. } => JobName::ShareCard,
            StoreJob::UpdateAddresses(_) => JobName::UpdateAddresses,
            StoreJob::SaveFriend { .. } => JobName::ChangeFriend(FriendChange::Add),
            StoreJob::VerifyExisting { .. } => JobName::ChangeFriend(FriendChange::Verify),
            StoreJob::RenameFriend { .. } => JobName::ChangeFriend(FriendChange::Rename),
            StoreJob::SetFriendAddress { .. } => JobName::ChangeFriend(FriendChange::Address),
            StoreJob::RemoveFriend { .. } => JobName::ChangeFriend(FriendChange::Remove),
            StoreJob::UnblockFriend { .. } => JobName::ChangeFriend(FriendChange::Unblock),
            StoreJob::LoadPrivacy => JobName::LoadPrivacy,
            StoreJob::SetChatKeep(_) => JobName::SetChatKeep,
            StoreJob::MarkNoticeShown(_) => JobName::MarkNotice,
            StoreJob::DeleteChat { .. } => JobName::DeleteChat,
            StoreJob::ForgetAddress { .. } => JobName::ChangeFriend(FriendChange::ForgetAddress),
            StoreJob::ErasePlan => JobName::ErasePlan,
            StoreJob::Erase => JobName::Erase,
            StoreJob::LoadSecurity => JobName::LoadSecurity,
            StoreJob::ResolveNotice { .. } => JobName::ResolveNotice,
            StoreJob::SetSendHold { .. } => JobName::SetSendHold,
            StoreJob::Recheck { .. } => JobName::Recheck,
            StoreJob::AcceptOlderMethod { .. } => JobName::AcceptOlderMethod,
            StoreJob::LoadGroups { .. } => JobName::LoadGroups,
            StoreJob::MarkGroupRead { .. } => JobName::MarkGroupRead,
        }
    }
}

/// Work for the send worker, first in first out. `peer` and `pub_hex` are
/// the friend's key in lower case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum SendJob {
    /// The send of message `local_id`.
    Send {
        local_id: u64,
        pub_hex: String,
        text: String,
    },
    /// `raven outbox retry`: raven-node tries message `mid` now.
    Retry { mid: String, peer: String },
    /// `raven outbox cancel --yes`: raven-node stops trying it (the user
    /// confirmed).
    Cancel { mid: String, peer: String },
    /// `raven group send` of message `local_id` to the group (lab).
    GroupSend {
        local_id: u64,
        group: raven_core::group::GroupId,
        text: String,
    },
    /// `raven group create|add|remove|leave` (lab; the user asked, and for
    /// a remove or a leave said yes).
    GroupChange(GroupChange),
}

impl SendJob {
    pub(super) fn name(&self) -> JobName {
        match self {
            SendJob::Send { .. } => JobName::Send,
            SendJob::Retry { .. } => JobName::Retry,
            SendJob::Cancel { .. } => JobName::Cancel,
            SendJob::GroupSend { .. } => JobName::GroupSend,
            SendJob::GroupChange(_) => JobName::GroupChange,
        }
    }
}

/// Work the UI thread does itself, with the screen suspended for a prompt on
/// the plain terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SuspendJob {
    /// Makes the identity of a passphrase-vault profile: the vault asks for
    /// the new passphrase twice, on the terminal.
    CreateIdentity,
}

impl SuspendJob {
    pub(super) fn name(self) -> JobName {
        match self {
            SuspendJob::CreateIdentity => JobName::CreateIdentity,
        }
    }
}

/// Work for the node worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum NodeJob {
    Probe,
    /// Start it unless one answers (under the node gate).
    Ensure,
    /// Stop it, as the stop rules allow; the user confirmed.
    Stop {
        started_by_app: Option<u32>,
        managed: bool,
    },
    /// LOCK's stop once the login item read answered (PP.23): the lock is
    /// recorded first (a send then starts no Raven), Raven's own login
    /// item is unloaded for this login session (`own_item`), then the stop
    /// as the stop rules allow (`managed`: where this build reads no login
    /// items, UXF.7's check found a login service, which is left alone;
    /// review D-lock-tui-6); the lock is taken back when Raven still runs.
    /// Its answer is a stop's.
    Lock {
        started_by_app: Option<u32>,
        own_item: bool,
        managed: bool,
    },
    /// Is it a login service? Raven's own login item for this profile
    /// (PP.23), or where this build reads none, UXF.7's check.
    DetectManaged,
    /// Is this a vault profile without a passphrase file?
    VaultCheck,
    /// UNLOCK's Enter: the lock `raven lock` set goes (review
    /// E-harness-docs-ci-3).
    Unlock,
    /// Every address of this computer a friend could dial, hotspot first,
    /// for MEET's step 3 and NET (nothing is sent).
    LanAddresses,
    /// The service log's last lines, for NET's log view.
    ServiceLog,
    /// Lock v2 (P6.40): IPC `Lock` (LOCK's Enter, the idle lock).
    LockV2,
    /// LOCKED's Enter: IPC `Unlock` with what was typed (None: a keychain
    /// profile's resume).
    UnlockV2(Option<Masked>),
    /// PASS's change, with raven-node held locked meanwhile.
    Passphrase {
        op: bridge::PassOp,
        current: Option<Masked>,
        new: Option<Masked>,
    },
    /// The lock settings: the passphrase on offer and the sleep lock.
    LockSettings,
    /// 'Lock Raven when the computer sleeps' saved.
    SetSleepLock(bool),
    /// UPDATES and NET's row (P6.47): what waits to be installed (a read;
    /// `full` for UPDATES, which shows what installing it shows).
    LoadUpdates {
        full: bool,
    },
    /// UPDATES' install of the build `serial`, after the word was typed:
    /// this profile's node stops around the swap and starts again.
    InstallUpdate {
        serial: u64,
        started_by_app: Option<u32>,
    },
    /// UPDATES' Y on a friend's offer (P6.49): the download approved; the
    /// view read again.
    ApproveDownload {
        digest: [u8; 32],
    },
}

impl NodeJob {
    pub(super) fn name(&self) -> JobName {
        match self {
            NodeJob::Probe => JobName::NodeProbe,
            NodeJob::Ensure => JobName::NodeEnsure,
            NodeJob::Stop { .. } | NodeJob::Lock { .. } => JobName::NodeStop,
            NodeJob::DetectManaged => JobName::NodeManaged,
            NodeJob::VaultCheck => JobName::NodeVault,
            NodeJob::Unlock => JobName::NodeUnlock,
            NodeJob::LanAddresses => JobName::NodeLanAddresses,
            NodeJob::ServiceLog => JobName::NodeLog,
            NodeJob::LockV2 => JobName::NodeLockV2,
            NodeJob::UnlockV2(_) => JobName::NodeUnlockV2,
            NodeJob::Passphrase { .. } => JobName::NodePassphrase,
            NodeJob::LockSettings => JobName::NodeLockSettings,
            NodeJob::LoadUpdates { .. } | NodeJob::ApproveDownload { .. } => JobName::NodeUpdates,
            NodeJob::InstallUpdate { .. } => JobName::NodeInstall,
            NodeJob::SetSleepLock(_) => JobName::NodeSleepLock,
        }
    }
}

/// Which job a result answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum JobName {
    LoadContacts,
    LoadHistory,
    LoadHorizons,
    SaveSettings,
    SaveReadMarks,
    LoadReadMarks,
    CheckVault,
    CreateIdentity,
    SaveLearnedDial,
    ShareCard,
    UpdateAddresses,
    ChangeFriend(FriendChange),
    LoadPrivacy,
    SetChatKeep,
    MarkNotice,
    DeleteChat,
    ErasePlan,
    Erase,
    LoadSecurity,
    ResolveNotice,
    SetSendHold,
    Recheck,
    AcceptOlderMethod,
    Send,
    Retry,
    Cancel,
    LoadGroups,
    MarkGroupRead,
    GroupSend,
    GroupChange,
    NodeProbe,
    NodeEnsure,
    NodeStop,
    NodeManaged,
    NodeVault,
    NodeUnlock,
    NodeLanAddresses,
    NodeLog,
    NodeLockV2,
    NodeUnlockV2,
    NodePassphrase,
    /// A read only: nothing waits for it ([`JobName::tracked`]).
    NodeLockSettings,
    NodeSleepLock,
    /// A read only, like the lock settings (P6.47).
    NodeUpdates,
    NodeInstall,
}

impl JobName {
    /// Counted in flight: everything but the lock settings' read (P6.40),
    /// which writes nothing, so ERASE, the loopback switch and the classic
    /// menu never wait for it.
    pub(super) fn tracked(self) -> bool {
        !matches!(self, JobName::NodeLockSettings | JobName::NodeUpdates)
    }

    pub(super) fn kind(self) -> JobKind {
        match self {
            JobName::CreateIdentity
            | JobName::SaveLearnedDial
            | JobName::UpdateAddresses
            | JobName::ChangeFriend(_)
            | JobName::DeleteChat
            | JobName::Erase
            | JobName::SetSendHold
            | JobName::AcceptOlderMethod => JobKind::Critical,
            JobName::Send
            | JobName::Retry
            | JobName::Cancel
            | JobName::GroupSend
            | JobName::GroupChange => JobKind::Send,
            JobName::LoadContacts
            | JobName::LoadHistory
            | JobName::LoadHorizons
            | JobName::SaveSettings
            | JobName::SaveReadMarks
            | JobName::LoadReadMarks
            | JobName::CheckVault
            | JobName::ShareCard
            | JobName::LoadPrivacy
            | JobName::SetChatKeep
            | JobName::MarkNotice
            | JobName::ErasePlan
            | JobName::LoadSecurity
            | JobName::ResolveNotice
            | JobName::Recheck
            | JobName::LoadGroups
            | JobName::MarkGroupRead => JobKind::Store,
            JobName::NodeProbe
            | JobName::NodeEnsure
            | JobName::NodeStop
            | JobName::NodeManaged
            | JobName::NodeVault
            | JobName::NodeUnlock
            | JobName::NodeLanAddresses
            | JobName::NodeLog
            | JobName::NodeLockV2
            | JobName::NodeUnlockV2
            | JobName::NodePassphrase
            | JobName::NodeLockSettings
            | JobName::NodeSleepLock
            | JobName::NodeUpdates
            | JobName::NodeInstall => JobKind::Node,
        }
    }
}

/// A new identity's public half, for the App. Settings are saved through a
/// store job, whose controller holds the identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct NewIdentity {
    pub(super) me: MeView,
    /// Its first prekey or device certificate could not be made: a toast,
    /// and no failure.
    pub(super) prekey_warning: Option<String>,
}

/// A job's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum JobResult {
    /// The friends, with contacts.json's size and time from just before the
    /// read.
    Contacts {
        contacts: Result<Vec<ContactView>, String>,
        stamp: FileStamp,
    },
    /// Every conversation, with the history file's size and time from just
    /// before the read.
    History {
        history: Result<Conversations, String>,
        stamp: FileStamp,
    },
    /// How long a message could wait for each friend asked about whose
    /// answer is known.
    Horizons(Horizons),
    SettingsSaved(Result<(), String>),
    /// The read markers: saved (true), or left because tui_state.json can't
    /// be read (false).
    ReadMarksSaved(Result<bool, String>),
    /// The read markers as saved (none when they can't be read).
    ReadMarks(ReadMarks),
    /// Making the identity will ask for a passphrase on the terminal.
    VaultChecked {
        prompts: bool,
    },
    /// The identity made, or raven-core's reason it was not; and what the
    /// job printed meanwhile (for Details).
    Created {
        result: Result<NewIdentity, String>,
        captured: String,
    },
    Probed(Probe),
    Ensured(Ensured),
    Stopped(Stopped),
    /// A login service runs it (UXF.7's check, where this build reads no
    /// login items).
    Managed(Option<Managed>),
    /// Raven's own login item for this profile, or none (PP.23).
    LoginItem(Option<LoginItemView>),
    Vault(Vault),
    /// UNLOCK's job: the lock went, or why it couldn't.
    Unlocked(Result<(), String>),
    /// Every address of this computer a friend could dial, hotspot first;
    /// None when the interfaces can't be read.
    LanAddresses(Option<Vec<IpAddr>>),
    /// The service log's last lines, or why they can't be read.
    ServiceLog(Result<Vec<String>, String>),
    /// Message `local_id`'s send ended.
    Sent {
        local_id: u64,
        outcome: SendOutcome,
    },
    /// A retry of message `mid` (to the friend `peer`) was asked, or why not;
    /// and what it printed.
    Retried {
        mid: String,
        peer: String,
        result: Result<(), String>,
        captured: String,
    },
    /// A cancel of message `mid`, as for a retry. What it printed says
    /// whether the friend may have it anyway.
    Cancelled {
        mid: String,
        peer: String,
        result: Result<(), String>,
        captured: String,
    },
    /// The address a send learned, saved (or why not).
    LearnedDialSaved(Result<(), String>),
    /// My cards, made for the listener `listen`.
    Shared {
        listen: Option<String>,
        share: Share,
    },
    /// The friend `pub_hex`'s new routes saved, or why not (security codes
    /// already taken out).
    AddressesUpdated {
        pub_hex: String,
        result: Result<(), String>,
    },
    /// A change to the friend `pub_hex` saved, or why not (security codes of
    /// friends not verified already taken out). `notes`: what a saved change
    /// could not do in full, raw, one each (ForgetAddress: what Raven
    /// learned about reaching them that it could not forget).
    FriendChanged {
        change: FriendChange,
        pub_hex: String,
        result: Result<(), String>,
        notes: Vec<String>,
    },
    /// The privacy pack's read, or that this profile can't use it (PP.21).
    Privacy(Result<PrivacyRead, NotAvailable>),
    /// KEEP's choice saved, or why not.
    ChatKeepSaved {
        keep: ChatKeepView,
        result: Result<(), String>,
    },
    /// A one-time notice marked shown.
    NoticeMarked(Notice),
    /// The chat with the friend `pub_hex` deleted on this computer (counts
    /// only), or why not.
    ChatDeleted {
        pub_hex: String,
        result: Result<DeleteChatOutcome, String>,
    },
    /// What erasing this profile deletes, or why erase refuses it (raw).
    ErasePlan(Result<ErasePlanView, String>),
    /// How the erase ended.
    Erased(EraseEnd),
    /// The security notices and the paused friends, or that they can't be
    /// read before the identity exists (P6.31).
    Security(Result<SecurityView, NotAvailable>),
    /// R on SEC: resolved (`Ok(false)`: it was not open any more), or why
    /// not.
    NoticeResolved(Result<bool, String>),
    /// P: whether sending to `pub_hex` is paused now, or why it could not
    /// change (`on`: what was asked).
    SendHoldSet {
        pub_hex: String,
        on: bool,
        result: Result<bool, String>,
    },
    /// "Check again": what the match resolved, or why not.
    Rechecked {
        pub_hex: String,
        result: Result<Resolved, String>,
    },
    /// The older method accepted (`Ok(false)`: the friend had no floor), or
    /// why not.
    OlderMethodAccepted {
        pub_hex: String,
        result: Result<bool, String>,
    },
    /// Lock v2's lock (P6.40): `Ok(true)` locked, `Ok(false)` the node does
    /// not serve Lock v2, or why not.
    LockedV2(Result<bool, String>),
    /// LOCKED's unlock answered.
    UnlockedV2(bridge::UnlockAnswer),
    /// PASS's change: the lines to say, or why not.
    PassphraseChanged(Result<Vec<String>, String>),
    /// The lock settings, as read.
    LockSettings(LockSettingsView),
    /// 'Lock Raven when the computer sleeps' saved, or why not.
    SleepLockSaved(Result<(), String>),
    /// What waits to be installed (P6.47).
    Updates(bridge::UpdateView),
    /// UPDATES' install ended: its lines, or why not; the Status after; and
    /// the node it started from this app (review lock-updates-local-7).
    UpdateInstalled {
        result: Result<Vec<String>, String>,
        after: Probe,
        started: Option<u32>,
    },
    /// The groups and the open one's chat, as read (lab).
    Groups(GroupsRead),
    /// The group's messages marked read, or why not.
    GroupMarked {
        group: raven_core::group::GroupId,
        result: Result<(), String>,
    },
    /// Group message `local_id`'s send ended.
    GroupSent {
        local_id: u64,
        done: GroupDone<[u8; 16]>,
    },
    /// A change to a group ended.
    GroupChanged {
        change: GroupChange,
        done: GroupDone<raven_core::group::GroupId>,
    },
    /// The job panicked.
    Failed {
        job: JobName,
        plain: Plain,
    },
}

impl JobResult {
    pub(super) fn name(&self) -> JobName {
        match self {
            JobResult::Contacts { .. } => JobName::LoadContacts,
            JobResult::History { .. } => JobName::LoadHistory,
            JobResult::Horizons(_) => JobName::LoadHorizons,
            JobResult::SettingsSaved(_) => JobName::SaveSettings,
            JobResult::ReadMarksSaved(_) => JobName::SaveReadMarks,
            JobResult::ReadMarks(_) => JobName::LoadReadMarks,
            JobResult::VaultChecked { .. } => JobName::CheckVault,
            JobResult::Created { .. } => JobName::CreateIdentity,
            JobResult::Probed(_) => JobName::NodeProbe,
            JobResult::Ensured(_) => JobName::NodeEnsure,
            JobResult::Stopped(_) => JobName::NodeStop,
            JobResult::Managed(_) | JobResult::LoginItem(_) => JobName::NodeManaged,
            JobResult::Vault(_) => JobName::NodeVault,
            JobResult::Unlocked(_) => JobName::NodeUnlock,
            JobResult::LanAddresses(_) => JobName::NodeLanAddresses,
            JobResult::ServiceLog(_) => JobName::NodeLog,
            JobResult::Sent { .. } => JobName::Send,
            JobResult::Retried { .. } => JobName::Retry,
            JobResult::Cancelled { .. } => JobName::Cancel,
            JobResult::LearnedDialSaved(_) => JobName::SaveLearnedDial,
            JobResult::Shared { .. } => JobName::ShareCard,
            JobResult::AddressesUpdated { .. } => JobName::UpdateAddresses,
            JobResult::FriendChanged { change, .. } => JobName::ChangeFriend(*change),
            JobResult::Privacy(_) => JobName::LoadPrivacy,
            JobResult::ChatKeepSaved { .. } => JobName::SetChatKeep,
            JobResult::NoticeMarked(_) => JobName::MarkNotice,
            JobResult::ChatDeleted { .. } => JobName::DeleteChat,
            JobResult::ErasePlan(_) => JobName::ErasePlan,
            JobResult::Erased(_) => JobName::Erase,
            JobResult::Security(_) => JobName::LoadSecurity,
            JobResult::NoticeResolved(_) => JobName::ResolveNotice,
            JobResult::SendHoldSet { .. } => JobName::SetSendHold,
            JobResult::Rechecked { .. } => JobName::Recheck,
            JobResult::OlderMethodAccepted { .. } => JobName::AcceptOlderMethod,
            JobResult::LockedV2(_) => JobName::NodeLockV2,
            JobResult::UnlockedV2(_) => JobName::NodeUnlockV2,
            JobResult::PassphraseChanged(_) => JobName::NodePassphrase,
            JobResult::LockSettings(_) => JobName::NodeLockSettings,
            JobResult::SleepLockSaved(_) => JobName::NodeSleepLock,
            JobResult::Updates(_) => JobName::NodeUpdates,
            JobResult::UpdateInstalled { .. } => JobName::NodeInstall,
            JobResult::Groups(_) => JobName::LoadGroups,
            JobResult::GroupMarked { .. } => JobName::MarkGroupRead,
            JobResult::GroupSent { .. } => JobName::GroupSend,
            JobResult::GroupChanged { .. } => JobName::GroupChange,
            JobResult::Failed { job, .. } => *job,
        }
    }
}

/// Which part of Home takes the keys. Tab goes Friends, Composer, Messages
/// and round again; Composer and Messages only while a conversation is open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Focus {
    /// The friend list: Up and Down move the highlight only.
    Friends,
    /// The line that writes to the open friend: typing is text there.
    Composer,
    /// The open conversation: Up and Down choose a message.
    Messages,
}

impl Focus {
    fn next(self) -> Focus {
        match self {
            Focus::Friends => Focus::Composer,
            Focus::Composer => Focus::Messages,
            Focus::Messages => Focus::Friends,
        }
    }

    fn previous(self) -> Focus {
        match self {
            Focus::Friends => Focus::Messages,
            Focus::Composer => Focus::Friends,
            Focus::Messages => Focus::Composer,
        }
    }
}

/// What a job handed to a worker holds up until it is answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum JobKind {
    /// A store job that writes the identity or contacts.json. The process
    /// must not end under it: QUIT and the classic menu wait for it.
    Critical,
    /// Any other store job: loads, settings.
    Store,
    /// A send, retry or cancel: QUIT waits for it, or quits anyway.
    Send,
    /// Starting, checking or stopping the background program.
    Node,
}

/// Jobs handed to the workers and not answered yet, by kind.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct JobCounts {
    critical: u32,
    store: u32,
    send: u32,
    node: u32,
}

impl JobCounts {
    pub(super) fn start(&mut self, kind: JobKind) {
        let count = self.count(kind);
        *count = count.saturating_add(1);
    }

    pub(super) fn finish(&mut self, kind: JobKind) {
        let count = self.count(kind);
        *count = count.saturating_sub(1);
    }

    /// No job in flight: the environment may be changed
    /// (`Cmd::ApplyListenLoopback`, once there are workers).
    pub(super) fn idle(&self) -> bool {
        *self == JobCounts::default()
    }

    /// A save or a send is in flight: leaving for the classic menu now could
    /// lose it.
    pub(super) fn holds_classic(&self) -> bool {
        self.critical > 0 || self.send > 0
    }

    fn count(&mut self, kind: JobKind) -> &mut u32 {
        match kind {
            JobKind::Critical => &mut self.critical,
            JobKind::Store => &mut self.store,
            JobKind::Send => &mut self.send,
            JobKind::Node => &mut self.node,
        }
    }
}

/// One message of a conversation, as Home keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Row {
    /// As the history has it; the body raw.
    pub(super) view: RowView,
    /// It was there at the session's first history load: it is not new, and
    /// says nothing about contact now.
    pub(super) seen_at_start: bool,
    /// When this app saw the friend's message arrive, or one of yours
    /// delivered (presence.rs's 'in touch'); None for a row seen at the start
    /// as it is.
    pub(super) touched: Option<Touch>,
}

/// A moment this app saw, on both clocks: monotonic for how long ago, the
/// wall clock for the words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Touch {
    pub(super) at: Instant,
    pub(super) at_ms: u64,
}

impl Row {
    /// Delivered to the friend: their Raven confirmed it.
    fn delivered(view: &RowView) -> bool {
        view.outgoing && matches!(view.delivery.as_str(), "delivered" | "read")
    }

    /// A key that finds this row again in the next load: the id and
    /// direction, with the time and length for legacy rows without an id.
    fn key(view: &RowView) -> (bool, String, u64, usize) {
        (
            view.outgoing,
            view.id.to_ascii_lowercase(),
            view.created_at_ms,
            view.body.len(),
        )
    }
}

/// The conversations of a new history load, each row matched with what the
/// last load had: rows of the session's first load (`first`) are seen at
/// the start, a row that appears later is touched at `now` when it is the
/// friend's or delivered, and a row of yours seen delivered for the first
/// time is touched then.
fn merge_history(
    old: &HashMap<String, Vec<Row>>,
    new: Conversations,
    first: bool,
    now: Touch,
) -> HashMap<String, Vec<Row>> {
    let mut merged = HashMap::with_capacity(new.len());
    for (key, views) in new {
        let before: HashMap<_, &Row> = old
            .get(&key)
            .map(|rows| rows.iter().map(|row| (Row::key(&row.view), row)).collect())
            .unwrap_or_default();
        let rows = views
            .into_iter()
            .map(|view| match before.get(&Row::key(&view)) {
                Some(prev) => Row {
                    seen_at_start: prev.seen_at_start,
                    touched: prev.touched.or_else(|| {
                        (Row::delivered(&view) && !Row::delivered(&prev.view)).then_some(now)
                    }),
                    view,
                },
                None if first => Row {
                    view,
                    seen_at_start: true,
                    touched: None,
                },
                None => Row {
                    touched: (!view.outgoing || Row::delivered(&view)).then_some(now),
                    view,
                    seen_at_start: false,
                },
            })
            .collect();
        merged.insert(key, rows);
    }
    merged
}

/// Where the message `id` is in the conversation `key` (the history's
/// order), for [`read_marks::later`].
fn place_in(convo: &HashMap<String, Vec<Row>>, key: &str, id: &str) -> Option<usize> {
    convo
        .get(key)?
        .iter()
        .rposition(|row| row.view.id.eq_ignore_ascii_case(id))
}

/// The key a friend's conversation, draft and read marker go by: their
/// public key in lower case, as the history writes it.
fn convo_key(pub_hex: &str) -> String {
    pub_hex.to_ascii_lowercase()
}

/// An outbox item raven-node still has to send: `queued`, or parked until
/// its deadline (`waiting`, Phase 5a), which only raven-node pairs and
/// seals again (review cross-5).
fn waits_for_the_node(item: &OutboxItem) -> bool {
    matches!(item.state.as_str(), "queued" | "waiting")
}

/// How many messages from a friend arrived within the last
/// [`BURST_WITHIN`], when that is [`BURST_MIN`] or more and none had come
/// for [`BURST_AFTER_MS`] before the first of them (UXF.8): what they wrote
/// while the two of you were apart, arriving as you meet. `rows` is their
/// conversation at `now` (`now_ms` on the wall clock). A row of the first
/// history load counts as arrived when it was written, and one written
/// ahead of this clock as arrived now.
fn burst_after_silence(rows: &[Row], now: Instant, now_ms: u64) -> Option<usize> {
    let recent = |row: &Row| {
        row.touched
            .is_some_and(|touch| now.saturating_duration_since(touch.at) < BURST_WITHIN)
    };
    let theirs = || rows.iter().filter(|row| !row.view.outgoing);
    let burst: Vec<u64> = theirs()
        .filter(|row| recent(row))
        .filter_map(|row| row.touched.map(|touch| touch.at_ms))
        .collect();
    if burst.len() < BURST_MIN {
        return None;
    }
    let first_ms = burst.iter().copied().min()?;
    let quiet_before = theirs().filter(|row| !recent(row)).all(|row| {
        let arrived_ms = row
            .touched
            .map_or(row.view.created_at_ms.min(now_ms), |touch| touch.at_ms);
        first_ms.saturating_sub(arrived_ms) >= BURST_AFTER_MS
    });
    quiet_before.then_some(burst.len())
}

/// The meeting toast when a friend's waiting messages were all delivered.
fn delivered_toast(n: usize, name: &str) -> String {
    let messages = if n == 1 { "message" } else { "messages" };
    format!("Delivered {n} {messages} to {name}.")
}

/// The meeting toast for a burst of messages from a friend.
fn burst_toast(n: usize, name: &str) -> String {
    format!("{n} new messages from {name} (written while you were apart).")
}

/// What the user writes to one friend. Typed and pasted text alike holds no
/// control character but line breaks, and at most
/// `bridge::MAX_LAN_ENDPOINT_TEXT` bytes: what goes past the limit is
/// dropped (near it, the composer counts).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct Composer {
    text: String,
    /// The cursor, a byte offset at a grapheme boundary.
    cursor: usize,
}

impl Composer {
    /// Raw: shaped by display.rs when drawn.
    pub(super) fn text(&self) -> &str {
        &self.text
    }

    pub(super) fn cursor(&self) -> usize {
        self.cursor
    }

    pub(super) fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    /// Why this text can't be sent as it is, in the composer's words: a
    /// control character (cli.rs's own check, a backstop: none can be
    /// typed), or the prefix raven-core keeps for app frames.
    pub(super) fn problem(&self) -> Option<&'static str> {
        if bridge::tty_message_problem(&self.text).is_some() {
            Some(CONTROL_REFUSED)
        } else if !bridge::chat_text_allowed(&self.text) {
            Some(RESERVED_REFUSED)
        } else {
            None
        }
    }

    /// Adds `raw` at the cursor, as text: control characters dropped (line
    /// breaks kept), and cut where the message would pass the size limit.
    fn insert(&mut self, raw: &str) -> bool {
        let mut add = display::field_input(raw, true);
        let room = bridge::MAX_LAN_ENDPOINT_TEXT.saturating_sub(self.text.len());
        if add.len() > room {
            let mut cut = room;
            while !add.is_char_boundary(cut) {
                cut -= 1;
            }
            add.truncate(cut);
        }
        if add.is_empty() {
            return false;
        }
        self.text.insert_str(self.cursor, &add);
        self.cursor += add.len();
        true
    }

    /// Backspace: the grapheme before the cursor goes.
    fn backspace(&mut self) -> bool {
        let Some(start) = self.before() else {
            return false;
        };
        self.text.replace_range(start..self.cursor, "");
        self.cursor = start;
        true
    }

    /// Delete: the grapheme after the cursor goes.
    fn delete(&mut self) -> bool {
        let Some(end) = self.after() else {
            return false;
        };
        self.text.replace_range(self.cursor..end, "");
        true
    }

    fn left(&mut self) -> bool {
        self.move_to(self.before())
    }

    fn right(&mut self) -> bool {
        self.move_to(self.after())
    }

    /// Home: the start of the cursor's line.
    fn line_start(&mut self) -> bool {
        let start = self.text[..self.cursor].rfind('\n').map_or(0, |at| at + 1);
        self.move_to(Some(start))
    }

    /// End: the end of the cursor's line.
    fn line_end(&mut self) -> bool {
        let end = self.text[self.cursor..]
            .find('\n')
            .map_or(self.text.len(), |at| self.cursor + at);
        self.move_to(Some(end))
    }

    fn move_to(&mut self, at: Option<usize>) -> bool {
        match at {
            Some(at) if at != self.cursor => {
                self.cursor = at;
                true
            }
            _ => false,
        }
    }

    /// The grapheme boundary before the cursor, if any.
    fn before(&self) -> Option<usize> {
        grapheme_bounds(&self.text)
            .into_iter()
            .rev()
            .find(|&at| at < self.cursor)
    }

    /// The grapheme boundary after the cursor, if any.
    fn after(&self) -> Option<usize> {
        grapheme_bounds(&self.text)
            .into_iter()
            .find(|&at| at > self.cursor)
    }
}

/// Every grapheme boundary of `text` as a byte offset, its start and end
/// included: a line break is a grapheme of its own.
fn grapheme_bounds(text: &str) -> Vec<usize> {
    let base = text.as_ptr() as usize;
    let mut bounds = vec![0, text.len()];
    for line in text.split('\n') {
        let start = line.as_ptr() as usize - base;
        bounds.extend([start, start + line.len()]);
        let span = Span::raw(line);
        bounds.extend(
            span.styled_graphemes(Style::default())
                .map(|g| g.symbol.as_ptr() as usize - base),
        );
    }
    bounds.sort_unstable();
    bounds.dedup();
    bounds
}

/// A short note on the bottom row that goes away by itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Toast {
    /// Raw: drawn through display.rs like any other text.
    pub(super) text: String,
    /// When it goes away: set once it is the one shown, so a toast that
    /// waited its turn still gets its full time.
    until: Option<Instant>,
}

impl Toast {
    pub(super) fn until(&self) -> Option<Instant> {
        self.until
    }
}

/// One key from the input thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Key {
    /// A key as crossterm reports it. The input thread passes on presses only
    /// (Windows Alt+numpad codes become presses there), but releases are
    /// ignored here too.
    Event(KeyEvent),
    /// An Enter that came within 30 ms of another text key with more text
    /// right after it: part of a paste, so it is text and never confirms or
    /// sends. One with nothing after it is the user's Enter (workers.rs).
    PastedEnter,
}

/// Where a paste came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PasteVia {
    /// The terminal's bracketed paste: one event.
    Bracketed,
    /// A burst of keystrokes the input thread joined up (Windows, and
    /// terminals without bracketed paste).
    Keystrokes,
}

/// Everything the UI thread hears, from the input, stderr and signal threads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Msg {
    Key(Key),
    Paste {
        text: String,
        via: PasteVia,
    },
    /// The terminal's size now, in cells.
    Resize {
        cols: u16,
        rows: u16,
    },
    /// No message came before the time anim.rs asked to wake at: timers may
    /// have run out.
    Tick,
    /// A line written to stderr while the screen is up (it is in the ring too).
    Stderr(String),
    /// A worker finished a job.
    Job(JobResult),
    /// What the poller found.
    Poll(PollUpdate),
    /// SIGTERM or SIGHUP (Windows: the console closing, Ctrl+Break).
    OsSignal(OsSignal),
    /// A thread that should run as long as the app has ended (workers.rs's
    /// thread names).
    ThreadDied(&'static str),
}

/// What `update` asks the UI thread to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Cmd {
    /// Draw every cell again at the next draw (Ctrl+L).
    Redraw,
    Store(StoreJob),
    Send(SendJob),
    Node(NodeJob),
    /// A job the UI thread runs itself on the plain terminal: it pauses the
    /// keyboard, suspends the screen (SCREEN_ACTIVE off, stderr through to
    /// the terminal), holds signals, runs the job, comes back and hands the
    /// result to `update`.
    Suspend(SuspendJob),
    /// A word for the poller.
    Poll(PollCtl),
    /// Receiving is off: a node started from now on listens on this
    /// computer only (`RAVEN_SERVICE_LAN_LISTEN=127.0.0.1:0`, unless the user
    /// set it). `update` asks only while no job is in flight, since the
    /// environment is the whole process's, and before any job queued
    /// meanwhile.
    ApplyListenLoopback,
    /// Leave the screen for the classic line menu in this terminal. `update`
    /// asks only while no save or send is in flight.
    SwitchToClassic,
    /// COPY: leave the alternate screen (raw mode stays, the keys keep
    /// coming) and print these lines on the plain terminal, where the
    /// terminal itself can select them. Nothing is drawn until
    /// [`Cmd::Unpeek`].
    Peek(Vec<String>),
    /// Back from COPY: the screen again, every cell drawn anew.
    Unpeek,
    /// Leave the screen and end the process.
    Exit(ExitPlan),
}

/// How the app ends, carried out by tui/mod.rs once the screen is gone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ExitPlan {
    /// The process exit code.
    pub(super) code: i32,
    /// One line for the plain terminal: stdout for code 0, stderr otherwise.
    pub(super) line: Option<String>,
    /// Print and ask nothing: the terminal has hung up, or stopped taking
    /// output.
    pub(super) quiet: bool,
    /// LOCK and ERASE: the plain terminal is cleared, its scrollback too
    /// where the terminal can, before the line.
    pub(super) clear: bool,
    /// tui_state.json to save on the UI thread before the screen goes: the
    /// line carries a note shown once (UXF.9), remembered as shown. No
    /// worker would finish a save once the app ends.
    pub(super) save: Option<TuiState>,
}

impl Cmd {
    /// It ends the screen: the app ends, or leaves for the classic menu.
    fn leaves(&self) -> bool {
        matches!(self, Cmd::Exit(_) | Cmd::SwitchToClassic)
    }

    /// The kind of job this hands to a worker; None for the UI thread's own.
    fn job_kind(&self) -> Option<JobKind> {
        match self {
            Cmd::Store(job) => Some(job.name().kind()),
            Cmd::Send(job) => Some(job.name().kind()),
            Cmd::Node(job) => Some(job.name())
                .filter(|name| name.tracked())
                .map(JobName::kind),
            Cmd::Suspend(job) => Some(job.name().kind()),
            _ => None,
        }
    }
}

impl ExitPlan {
    /// The user quit. A background program left running (`running_pid`) is
    /// named on the plain terminal.
    pub(super) fn quit(running_pid: Option<u32>) -> ExitPlan {
        ExitPlan {
            code: 0,
            line: running_pid.map(still_running_line),
            quiet: false,
            clear: false,
            save: None,
        }
    }

    /// The user quit, and the background program was stopped first.
    pub(super) fn quit_stopped() -> ExitPlan {
        ExitPlan {
            code: 0,
            line: Some(STOPPED_LINE.to_owned()),
            quiet: false,
            clear: false,
            save: None,
        }
    }

    /// LOCK stopped this profile's background program: the terminal is
    /// cleared, then one line says it is locked (a passphrase-vault
    /// profile, `vault`) or only stopped (its keys stay in the keychain).
    pub(super) fn locked(vault: bool) -> ExitPlan {
        let line = if vault {
            LOCKED_LINE
        } else {
            LOCK_STOPPED_LINE
        };
        ExitPlan {
            code: 0,
            line: Some(line.to_owned()),
            quiet: false,
            clear: true,
            save: None,
        }
    }

    /// LOCK stopped this profile's background program after it unloaded
    /// Raven's own login item for this login session (PP.23): as
    /// [`ExitPlan::locked`], and the line says Raven starts again at the
    /// next login (on every profile, as `raven lock` says it).
    pub(super) fn locked_until_login() -> ExitPlan {
        ExitPlan {
            line: Some(LOCK_UNTIL_LOGIN_LINE.to_owned()),
            ..ExitPlan::locked(false)
        }
    }

    /// ERASE's erase ran (PP.22): the terminal is cleared, its scrollback
    /// too where the terminal can, then the result list (the UX copy) on
    /// stdout; when something is left (`finished` false), exactly what, on
    /// stderr, with code 1. Nothing is saved.
    pub(super) fn erased(finished: bool, lines: &[String]) -> ExitPlan {
        let lines: Vec<String> = lines
            .iter()
            .map(|line| display::one_line(line, u16::MAX, ""))
            .collect();
        ExitPlan {
            code: if finished { 0 } else { 1 },
            line: Some(lines.join("\n")),
            quiet: false,
            clear: true,
            save: None,
        }
    }

    /// Ended by `signal`: 128 + its number (Windows: 1), and silent once the
    /// terminal has gone.
    pub(super) fn signal(signal: OsSignal) -> ExitPlan {
        ExitPlan {
            code: signal.exit_code(),
            line: None,
            quiet: signal.hung_up(),
            clear: false,
            save: None,
        }
    }

    /// The input or signal thread died.
    pub(super) fn part_failed() -> ExitPlan {
        ExitPlan {
            code: 1,
            line: Some(PART_FAILED.to_owned()),
            quiet: false,
            clear: false,
            save: None,
        }
    }

    /// A draw after the first one failed: the terminal is gone or broken
    /// (EIO after a hang-up). Silent, with 129 after SIGHUP and 1 otherwise.
    pub(super) fn draw_failed(received: Option<OsSignal>) -> ExitPlan {
        ExitPlan {
            code: received
                .filter(|signal| signal.hung_up())
                .map_or(1, OsSignal::exit_code),
            line: None,
            quiet: true,
            clear: false,
            save: None,
        }
    }
}

/// What quitting does with the background program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum QuitChoice {
    /// It keeps running (OD-2's default).
    Keep,
    /// It is stopped first, as the stop rules allow (OD-16).
    Stop,
}

/// A quit under way: QUIT waits for something before the app ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Quitting {
    /// The quit was chosen while a message was being sent, since `since`:
    /// the app ends once no send (nor contacts save) is in flight, or at
    /// once with Q.
    AfterSends { choice: QuitChoice, since: Instant },
    /// The background program is being stopped, since `since`; the app
    /// ends once that is done.
    Stopping { since: Instant },
}

/// What QUIT says and offers now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum QuitView {
    /// The identity is being made: Esc only.
    SettingUp,
    /// A change to the friends is being saved: Esc only.
    Saving,
    /// [`Quitting::AfterSends`] while a send is in flight.
    Sending { since: Instant },
    /// [`Quitting::Stopping`].
    Stopping { since: Instant },
    /// The question, with nothing to say about a background program: no
    /// identity yet, or its state not known yet.
    Plain,
    /// The question: no background program runs.
    NotRunning,
    /// The question: one runs (or is starting).
    Running(RunningQuit),
    /// Before the question (UXF.8): messages of yours that the background
    /// program keeps trying haven't left this computer. Enter stays, Q quits
    /// anyway.
    Waiting(WaitingQuit),
}

/// QUIT's question while a background program runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RunningQuit {
    /// A login service runs it: QUIT says so, and never stops it.
    pub(super) managed: bool,
    /// The stop rules allow stopping it from here.
    pub(super) can_stop: bool,
    /// What Enter does, from 'When I quit' (OD-2): None under 'Ask me',
    /// where K or S is chosen each time.
    pub(super) enter: Option<QuitChoice>,
}

/// QUIT's warning while messages wait (UXF.8). It names the friend whose
/// waiting message runs out first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct WaitingQuit {
    /// That friend's key, lower case.
    pub(super) peer: String,
    /// Their messages that haven't gone yet.
    pub(super) count: usize,
    /// The other friends' messages that haven't gone yet.
    pub(super) more: usize,
    /// When the first of them runs out, on the wall clock; None when
    /// raven-node didn't say.
    pub(super) until_ms: Option<u64>,
    /// The question behind the warning: Q quits as its Enter would, or,
    /// under 'Ask me', QUIT asks it.
    pub(super) question: RunningQuit,
}

/// What the meeting toasts (UXF.8) follow for one friend.
#[derive(Debug, Clone, Default)]
struct MeetingNotes {
    /// Messages of yours to them (ids, lower case) seen waiting or held in
    /// this session, and not delivered or ended yet.
    waiting: HashSet<String>,
    /// How many of those were delivered since the last toast about them.
    delivered: usize,
    /// A burst of this many messages from them, not toasted yet.
    burst: Option<usize>,
    /// When each toast last showed for them.
    delivered_at: Option<Instant>,
    burst_at: Option<Instant>,
}

impl MeetingNotes {
    /// A toast is due: a burst, or every message that waited is delivered
    /// or ended and one at least was delivered.
    fn due(&self) -> bool {
        self.burst.is_some() || (self.waiting.is_empty() && self.delivered > 0)
    }
}

/// Whether a terminal of `cols` by `rows` cells is below the smallest the
/// screens are laid out for.
pub(super) fn too_small(cols: u16, rows: u16) -> bool {
    cols < MIN_COLS || rows < MIN_ROWS
}

/// The whole state of the screen.
#[derive(Debug, Clone)]
pub(super) struct App {
    screen: Screen,
    overlays: Vec<Overlay>,
    look: Look,
    /// The terminal's size in cells, as the last [`Msg::Resize`] said.
    size: (u16, u16),
    /// The friend list, top to bottom, by public key (hex). Empty until the
    /// contacts are loaded.
    friends: Vec<String>,
    /// The friend-list cursor. Up and Down move it in Friends focus only.
    highlight: usize,
    /// The friend whose conversation is shown and whom the composer writes
    /// to. Only Enter on the list changes it, never Up or Down.
    open_friend: Option<String>,
    focus: Focus,
    jobs_in_flight: JobCounts,
    /// The first one is shown; the others wait their turn.
    toasts: VecDeque<Toast>,
    /// The time of the last update, monotonic and wall-clock (milliseconds
    /// since the Unix epoch, for the age of a message).
    now: Instant,
    now_ms: u64,
    /// When the last frame was drawn: anim.rs draws a frame only when
    /// something moved on since.
    drawn_at: Option<Instant>,
    /// Something visible changed since the last draw.
    dirty: bool,

    identity: IdentityStatus,
    /// The identity's public half; its secrets stay in the controller.
    me: Option<MeView>,
    /// The profile's folder (raw: drawn through display.rs).
    folder: PathBuf,
    /// WZ-2's field: the user's own name as typed, at most [`NAME_CELLS`]
    /// cells. It goes into the settings on Enter.
    name: String,
    /// Typing went past [`NAME_CELLS`] and stopped: WZ-2 says why.
    name_full: bool,
    /// macOS: WZ-4 says what to do when the Mac asks for the password.
    mac: bool,
    settings: TuiState,
    /// The saved friends as the last load found them; raw strings.
    contacts: Vec<ContactView>,
    /// A load has succeeded once.
    contacts_loaded: bool,
    contacts_loading: bool,
    /// Why the last load failed (the list stays as it was).
    contacts_error: Option<String>,
    /// contacts.json as the last load and the poller last saw it.
    contacts_stamp: Option<FileStamp>,
    contacts_seen: Option<FileStamp>,
    node: NodeView,
    /// Reads of Raven's own login item ([`NodeJob::DetectManaged`]) not
    /// answered yet: LOCK waits for them (review D-lock-tui-6).
    login_item_reads: u32,
    /// The vault check has answered: before it, nothing starts by itself.
    vault_checked: bool,
    /// What it found; nothing (no vault) until it answers.
    vault: Vault,
    /// A start waiting for the vault check.
    auto_pending: Option<AutoStart>,
    /// The lock `raven lock` set is still on (review E-harness-docs-ci-3):
    /// nothing starts Raven until UNLOCK's Enter cleared it.
    cli_locked: bool,
    /// Lock now v2 (P6.40): the lock settings, a lock that is out, the idle
    /// clock.
    lock_v2: LockV2State,
    /// The start that waits for UNLOCK's Enter: one by itself, or NET's S.
    after_unlock: Option<AfterUnlock>,
    /// The port a background program this app starts listens on (RX and
    /// FW name it while none listens): `bridge::service_port`.
    service_port: u16,
    /// PASSFILE was shown for a start that was skipped.
    passfile_shown: bool,
    listen: ListenOverride,
    /// The loopback listen address is to be set once no job runs; jobs
    /// asked for meanwhile wait in `held`.
    loopback_wanted: bool,
    held: Vec<Cmd>,
    /// Jobs and words for the poller this update hands out.
    cmds: Vec<Cmd>,
    keychain: Option<KeychainView>,
    /// The poller was started (the identity exists), and the hints it last
    /// got.
    poller_on: bool,
    hints_sent: Option<PollHints>,
    /// The outbox's last list had a message waiting, held or sent.
    outbox_live: bool,
    over_ssh: bool,
    /// Windows: NET's per-account note and its stop rule (OD-16).
    windows: bool,
    gates: GatesView,
    /// Every address of this computer a friend could dial, as MEET's step 3
    /// or NET last read them: None until a read answers, then None inside
    /// when they can't be told.
    lan_addresses: Option<Option<Vec<IpAddr>>>,
    /// Whether this computer has an address other than loopback, as the
    /// poller last read it: None until known, or when it can't be told.
    on_any_network: Option<bool>,
    /// X's stop is running.
    stopping: bool,
    /// How to stop the background program by hand, after a stop the rules
    /// did not allow, with the pid it was for.
    stop_advice: Option<(Option<u32>, String)>,
    last_paste: Option<Instant>,

    /// Every friend's conversation by [`convo_key`], as the last history
    /// load found it.
    convo: HashMap<String, Vec<Row>>,
    /// A history load has succeeded once.
    history_loaded: bool,
    history_loading: bool,
    /// Why the last load failed (the conversations stay as they were), and
    /// whether its technical text is shown (D).
    history_error: Option<String>,
    history_details: bool,
    /// The history file as the last load and the poller last saw it.
    history_stamp: Option<FileStamp>,
    history_seen: Option<FileStamp>,
    /// desktop_hidden.json as the poller last saw it: a change after the
    /// first look (the desktop app deleted a message) loads the history again.
    hidden_seen: Option<FileStamp>,
    /// How long a message written now could wait for each friend, as the
    /// last read found it; a friend not in it is not known (no line).
    horizons: Horizons,
    /// The poller asked for the horizons once: from then on a send's end, a
    /// change to the friends or the history reads them again too.
    horizons_on: bool,
    horizons_loading: bool,
    /// A read is wanted once the friends are loaded and none runs.
    horizons_due: bool,
    /// What is typed to each friend, by [`convo_key`]: the composer shows
    /// the open friend's, so a draft never goes to another friend.
    drafts: HashMap<String, Composer>,
    /// Rows of the open conversation below the window: 0 shows the newest.
    scroll: usize,
    /// The read markers changed: they are saved then.
    marks_due: Option<Instant>,
    /// The saved read markers are being read (another app may have read a
    /// chat), and whether they changed again meanwhile.
    marks_loading: bool,
    marks_again: bool,
    /// The wall-clock minute Home's ages were last drawn for.
    age_minute: u64,
    /// The message chosen in Messages focus, counted from the newest (0).
    chosen: Option<usize>,
    /// Messages whose whole body shows (Enter on a clipped one).
    expanded: HashSet<BubbleKey>,

    /// This session's sends, oldest first.
    pending: Vec<PendingSend>,
    /// The next send's number.
    next_send: u64,
    /// The send worker's jobs not answered yet, in its order: a send's
    /// number, or None for a retry or a cancel. The first one runs.
    send_queue: VecDeque<Option<u64>>,
    /// raven-node's outbox items by message id (lower case), as last listed.
    outbox: HashMap<String, OutboxItem>,
    /// How messages came and went, by message id (lower case), as
    /// raven-node said this session (it remembers since it started).
    paths: node::Paths,
    /// Message ids seen written once: listed as sent, or cancelled with a
    /// note that the friend may have it.
    written: HashSet<String>,
    /// Each message's tick as last worked out, and when this app saw it come
    /// to it (None: as first seen).
    tick_seen: HashMap<BubbleKey, (Discriminant<Tick>, Option<Instant>)>,
    /// Something a tick reads changed: worked out again at the end of the
    /// update.
    ticks_stale: bool,

    /// AF-1's cards, with the listener they were made for.
    share: Option<(Option<String>, Share)>,
    /// The listener the last card job was asked for (it may still run).
    share_asked: Option<Option<String>>,
    /// COPY is on the plain terminal: nothing is drawn, and any key comes
    /// back.
    peeking: bool,

    /// The terminal the look follows besides Settings.
    look_env: LookEnv,
    /// QUIT waits for a send or a stop before the app ends.
    quitting: Option<Quitting>,
    /// Whether QUIT showed its warning about waiting messages at the end of
    /// the last update; None while QUIT is closed.
    quit_warned: Option<bool>,
    /// When that warning last appeared or went: until [`QUIT_SETTLE`] has
    /// passed, no key in QUIT ends the app.
    quit_settle: Option<Instant>,
    /// Q answered the warning under 'Ask me': QUIT asks its question.
    quit_anyway: bool,
    /// What the meeting toasts follow, by friend ([`convo_key`]).
    meeting: HashMap<String, MeetingNotes>,
    /// The app asked to end or to leave for the classic menu: it asks for
    /// nothing more.
    leaving: bool,
    /// The privacy pack's read as it last answered (PP.21): None before it
    /// answers, and when this profile can't use it. Then SET's 'Keep chats
    /// for', CI's C and F and Home's one-time notices are all hidden.
    privacy: Option<PrivacyRead>,
    /// A read runs; `privacy_due`: another is wanted once it ends.
    privacy_loading: bool,
    privacy_due: bool,
    /// Home's one-time notices answered OK in this session: never shown
    /// here again, whatever a read in flight still says.
    notices_shown: Vec<Notice>,
    /// The security notices and the paused friends as the store worker last
    /// read them (P6.31): None before the first read answered (nothing of it
    /// shows), and before the identity exists.
    security: Option<SecurityView>,
    /// A read runs; `security_due`: another is wanted once it ends.
    security_loading: bool,
    security_due: bool,
    /// What waits to be installed, as the node worker last read it (P6.47):
    /// None before the first read (and while the gate is shut).
    updates: Option<bridge::UpdateView>,
    /// What Home's live feel follows (UXF.10): the heartbeat, how the last
    /// delivery to each friend went, the retry rings, the ticker's event.
    live: Live,
    /// The groups (lab): nothing of them shows while they are not live.
    groups: GroupsState,
}

impl App {
    pub(super) fn new(look: Look, size: (u16, u16), now: Instant, now_ms: u64) -> App {
        // Until the session says what this build lets on, nothing is.
        let closed = bridge::Gate {
            production: false,
            live: false,
        };
        App {
            screen: Screen::Home,
            overlays: Vec::new(),
            look,
            size,
            friends: Vec::new(),
            highlight: 0,
            open_friend: None,
            focus: Focus::Friends,
            jobs_in_flight: JobCounts::default(),
            toasts: VecDeque::new(),
            now,
            now_ms,
            drawn_at: None,
            dirty: true,
            identity: IdentityStatus::Pending,
            me: None,
            folder: PathBuf::new(),
            name: String::new(),
            name_full: false,
            mac: cfg!(target_os = "macos"),
            settings: TuiState::default(),
            contacts: Vec::new(),
            contacts_loaded: false,
            contacts_loading: false,
            contacts_error: None,
            contacts_stamp: None,
            contacts_seen: None,
            node: NodeView::new(Program {
                binary: Default::default(),
                exe_known: false,
            }),
            login_item_reads: 0,
            vault_checked: false,
            vault: Vault::default(),
            auto_pending: None,
            cli_locked: false,
            lock_v2: LockV2State::default(),
            after_unlock: None,
            service_port: raven_core::paths::DEFAULT_LAN_PORT,
            passfile_shown: false,
            listen: ListenOverride::None,
            loopback_wanted: false,
            held: Vec::new(),
            cmds: Vec::new(),
            keychain: None,
            poller_on: false,
            hints_sent: None,
            outbox_live: false,
            over_ssh: false,
            windows: cfg!(windows),
            gates: GatesView::of(
                bridge::Gates {
                    lan: closed,
                    internet: closed,
                    p2p: closed,
                    custody: closed,
                    nearby: closed,
                },
                false,
            ),
            lan_addresses: None,
            on_any_network: None,
            stopping: false,
            stop_advice: None,
            last_paste: None,
            convo: HashMap::new(),
            history_loaded: false,
            history_loading: false,
            history_error: None,
            history_details: false,
            history_stamp: None,
            history_seen: None,
            hidden_seen: None,
            horizons: Horizons::new(),
            horizons_on: false,
            horizons_loading: false,
            horizons_due: false,
            drafts: HashMap::new(),
            scroll: 0,
            marks_due: None,
            marks_loading: false,
            marks_again: false,
            age_minute: now_ms / 60_000,
            chosen: None,
            expanded: HashSet::new(),
            pending: Vec::new(),
            next_send: 1,
            send_queue: VecDeque::new(),
            outbox: HashMap::new(),
            paths: node::Paths::default(),
            written: HashSet::new(),
            tick_seen: HashMap::new(),
            ticks_stale: false,
            share: None,
            share_asked: None,
            peeking: false,
            look_env: LookEnv::default(),
            quitting: None,
            quit_warned: None,
            quit_settle: None,
            quit_anyway: false,
            meeting: HashMap::new(),
            leaving: false,
            privacy: None,
            privacy_loading: false,
            privacy_due: false,
            notices_shown: Vec::new(),
            security: None,
            security_loading: false,
            security_due: false,
            updates: None,
            live: Live::default(),
            groups: GroupsState::default(),
        }
    }

    /// The session begins with what the plain terminal found and this
    /// process's facts. With an identity, its first jobs go out: the
    /// friends, the background program's state, and the poller. Without one
    /// nothing touches the profile: the wizard opens, or ERR-ID when the
    /// identity store can't be read (never an offer to create one over it).
    pub(super) fn start(&mut self, session: Session) -> Vec<Cmd> {
        self.settings = session.settings;
        self.service_port = bridge::service_port(&session.data_dir);
        self.folder = session.data_dir;
        self.node = NodeView::new(session.program);
        self.listen = session.listen;
        self.over_ssh = session.over_ssh;
        self.gates = session.gates;
        self.look_env = session.look_env;
        match session.identity {
            IdentityStart::Ready(me) => {
                self.identity = IdentityStatus::Ready;
                self.me = Some(me);
                self.screen = Screen::Home;
                self.begin_ready();
                if session.locked {
                    self.cli_locked = true;
                    self.open_overlay(Overlay::Unlock);
                }
            }
            IdentityStart::Missing => {
                self.identity = IdentityStatus::Missing;
                self.screen = Screen::Wizard(WizardStep::Welcome {
                    since: Some(self.now),
                });
            }
            IdentityStart::Unavailable(why) => {
                let (_, plain) = errors::explain_identity(&why);
                let failure = Failure::new(plain, self.settings.show_details);
                self.screen = Screen::IdentityError(failure);
                self.identity = IdentityStatus::Unavailable(why);
            }
        }
        self.dirty = true;
        self.take_cmds()
    }

    /// The identity exists: the poller starts and the first jobs go out.
    /// The vault check comes first on the node worker, so no start it would
    /// forbid can come before it.
    fn begin_ready(&mut self) {
        self.poller_on = true;
        self.cmds.push(Cmd::Poll(PollCtl::Start));
        self.load_contacts();
        self.load_history();
        self.load_privacy();
        for job in [NodeJob::VaultCheck, NodeJob::Probe] {
            self.job(Cmd::Node(job));
        }
        self.read_login_item();
        self.groups_begin();
    }

    /// Asks the node worker about Raven's own login item for this profile
    /// ([`NodeJob::DetectManaged`]); LOCK waits for the answer.
    fn read_login_item(&mut self) {
        self.login_item_reads = self.login_item_reads.saturating_add(1);
        self.job(Cmd::Node(NodeJob::DetectManaged));
    }

    /// A read of Raven's own login item answered (or failed).
    fn login_item_read(&mut self) {
        self.login_item_reads = self.login_item_reads.saturating_sub(1);
        self.dirty = true;
    }

    /// Where the identity stands, for tests.
    #[cfg(test)]
    pub(super) fn identity(&self) -> &IdentityStatus {
        &self.identity
    }

    pub(super) fn me(&self) -> Option<&MeView> {
        self.me.as_ref()
    }

    /// The profile's folder, raw.
    pub(super) fn folder(&self) -> &Path {
        &self.folder
    }

    /// WZ-2's field, raw (it holds no control character).
    pub(super) fn name(&self) -> &str {
        &self.name
    }

    /// Typing in WZ-2's field stopped at the limit.
    pub(super) fn name_full(&self) -> bool {
        self.name_full
    }

    /// The app runs on macOS.
    pub(super) fn on_mac(&self) -> bool {
        self.mac
    }

    /// Render tests draw the macOS copy on any system, and the others on
    /// macOS.
    #[cfg(test)]
    pub(super) fn set_mac_for_tests(&mut self, mac: bool) {
        self.mac = mac;
    }

    /// The identity is being made (WZ-4's spinner): the app must not end,
    /// nor leave for the classic menu, until it is done.
    pub(super) fn finishing_setup(&self) -> bool {
        matches!(
            self.screen,
            Screen::Wizard(WizardStep::Creating(Creating::Working { .. }))
        )
    }

    pub(super) fn settings(&self) -> &TuiState {
        &self.settings
    }

    /// NO_COLOR is set: no colours, whatever Settings say.
    pub(super) fn no_color_env(&self) -> bool {
        self.look_env.term.no_color
    }

    pub(super) fn node(&self) -> &NodeView {
        &self.node
    }

    /// The Keychain wait on show or hidden; None when nothing waits.
    pub(super) fn keychain(&self) -> Option<&KeychainView> {
        self.keychain.as_ref()
    }

    pub(super) fn over_ssh(&self) -> bool {
        self.over_ssh
    }

    /// The app runs on Windows.
    pub(super) fn on_windows(&self) -> bool {
        self.windows
    }

    /// Render tests draw the Windows copy on any system, and the others on
    /// Windows.
    #[cfg(test)]
    pub(super) fn set_windows_for_tests(&mut self, windows: bool) {
        self.windows = windows;
    }

    /// The e2e test draws one app's state in another glyph set too, and the
    /// render tests draw in each look (on every system: review
    /// E-harness-docs-ci-2, the Windows test build needs it too).
    #[cfg(test)]
    pub(super) fn set_look_for_tests(&mut self, look: Look) {
        self.look = look;
    }

    /// What this build lets on (NET's labels).
    pub(super) fn gates(&self) -> &GatesView {
        &self.gates
    }

    /// Every address of this computer a friend could dial, hotspot first, as
    /// last read: None until a read answers, `Some(None)` when they can't be
    /// told, and an empty list on no network.
    pub(super) fn lan_addresses(&self) -> Option<Option<&[IpAddr]>> {
        self.lan_addresses.as_ref().map(Option::as_deref)
    }

    /// This computer is on no network at all, as the poller last read it:
    /// no address but loopback. Never when that can't be told.
    pub(super) fn not_on_any_network(&self) -> bool {
        self.on_any_network == Some(false)
    }

    /// X's stop is running.
    pub(super) fn stopping(&self) -> bool {
        self.stopping
    }

    /// How the stop rules (OD-16) treat the background program now: on
    /// Unix the pid this profile's Status reports, on Windows only a pid this
    /// app started, never a login service.
    pub(super) fn stop_plan(&self) -> StopPlan {
        super::node::stop_plan(
            self.windows,
            self.node.managed.is_some(),
            self.node.running(),
            self.node.pid,
            self.node.ours(),
        )
    }

    /// How to stop it by hand, when NET can't (ext.rs's
    /// `profile_stop_advice`): a node the rules leave alone, or one a stop
    /// left running. Raw: drawn through display.rs.
    pub(super) fn stop_advice(&self) -> Option<String> {
        let advice = match (self.stop_plan(), &self.stop_advice) {
            (StopPlan::Advise(pid), _) => bridge::profile_stop_advice(&self.folder, pid),
            // For the process it was given for, while that one runs.
            (_, Some((pid, advice))) if self.node.running() && self.node.pid == *pid => {
                advice.clone()
            }
            _ => return None,
        };
        if !self.windows {
            return Some(advice);
        }
        // Windows: words, never `taskkill /F` to type (E1); none for another
        // folder's program, nor before its folder is read.
        match self.node.folder() {
            Some(NodeFolder::This | NodeFolder::Unknown) => Some(WINDOWS_STOP.to_owned()),
            Some(NodeFolder::Other(_)) | None => None,
        }
    }

    /// Messages of yours raven-node's outbox lists as waiting to be sent:
    /// queued, or parked until their deadline (`waiting`, Phase 5a), which
    /// only raven-node sends again (review cross-5).
    pub(super) fn waiting_count(&self) -> usize {
        self.outbox
            .values()
            .filter(|item| waits_for_the_node(item))
            .count()
    }

    /// The keys NET offers now, besides L and Esc.
    pub(super) fn net_keys(&self) -> NetKeys {
        NetKeys {
            start: self.can_start(),
            stop: !self.stopping
                && matches!(
                    self.stop_plan(),
                    StopPlan::Terminate(_) | StopPlan::TaskKill(_)
                ),
            check_again: self.node.state == NodeState::NotAnswering || self.node.polling_stopped,
        }
    }

    /// S on NET: only while none runs or the last start failed, with the
    /// identity there, receiving on, the vault check answered, and Raven's
    /// own program known (else ext.rs would look raven-node up on PATH).
    fn can_start(&self) -> bool {
        self.identity == IdentityStatus::Ready
            && self.settings.receive == Receive::On
            && self.vault_checked
            && self.node.program.exe_known
            && !self.stopping
            && matches!(
                self.node.state,
                NodeState::NotRunning | NodeState::StartFailed(_)
            )
    }

    /// The port FW names: the one the node this app started listens on, or
    /// the one it listens on unless the user chose another (ext.rs's default,
    /// every address on port 7420: OD-4).
    pub(super) fn firewall_port(&self) -> u16 {
        match self.node.state {
            NodeState::Listening { port: Some(port) } => port,
            _ => self.service_port,
        }
    }

    /// The port RX names: where this folder's background program listens,
    /// else where one this app starts would (the profile's own port, E1).
    pub(super) fn receive_port(&self) -> u16 {
        self.node
            .listen
            .as_deref()
            .and_then(|listen| listen.rsplit_once(':'))
            .and_then(|(_, port)| port.parse().ok())
            .unwrap_or_else(|| self.firewall_port())
    }

    #[cfg(test)]
    pub(super) fn set_service_port_for_tests(&mut self, port: u16) {
        self.service_port = port;
    }

    /// When KC's icon started to pulse, while KC is on screen.
    pub(super) fn keychain_pulse(&self) -> Option<Instant> {
        self.keychain
            .filter(|_| self.overlays.contains(&Overlay::Keychain))
            .map(|kc| kc.since)
    }

    /// The header's node chip: what this computer's background program
    /// does, in the words HOME gives each state. None before it is known.
    pub(super) fn chip(&self) -> Option<Chip> {
        if self.identity != IdentityStatus::Ready {
            return None;
        }
        if self.keychain.is_some() {
            return Some(Chip::WaitingForPermission);
        }
        // raven-node can't open the friends list (PP.21): nobody can connect
        // and nothing is sent until it can, whatever else it does.
        if self.node.at_rest.is_some_and(AtRestStateView::locked_out) {
            return Some(Chip::LockedOut);
        }
        Some(match self.node.state {
            NodeState::Unknown => return None,
            NodeState::NeedsPassphraseFile => Chip::NeedsSetup,
            NodeState::Starting { since } => Chip::Starting { since },
            NodeState::NotAnswering => Chip::NotResponding,
            // Nothing reaches a friend from here, whatever the program does.
            _ if self.not_on_any_network() => Chip::NotOnAnyNetwork,
            NodeState::Listening { port } => Chip::Listening { port },
            NodeState::ReceivingLocalOnly => Chip::LocalOnly,
            NodeState::SendOnly => match self.node.bind_failure() {
                Some(BindFailure::AddrNotHere { .. }) => Chip::AddressNotHere,
                _ => Chip::SendOnly,
            },
            NodeState::NotRunning | NodeState::StartFailed(_) => match self.settings.receive {
                Receive::Off => Chip::ReceiveOff,
                _ if self.contacts_loaded && self.friends.is_empty() => Chip::StartsWithFirstFriend,
                _ => Chip::NotRunning,
            },
        })
    }

    pub(super) fn screen(&self) -> &Screen {
        &self.screen
    }

    /// Bottom first: each one is drawn over the ones before it.
    pub(super) fn overlays(&self) -> &[Overlay] {
        &self.overlays
    }

    pub(super) fn look(&self) -> &Look {
        &self.look
    }

    pub(super) fn size(&self) -> (u16, u16) {
        self.size
    }

    /// The window is below the smallest size: SMALL takes the keys.
    pub(super) fn too_small(&self) -> bool {
        too_small(self.size.0, self.size.1)
    }

    pub(super) fn focus(&self) -> Focus {
        self.focus
    }

    pub(super) fn highlight(&self) -> usize {
        self.highlight
    }

    pub(super) fn open_friend(&self) -> Option<&str> {
        self.open_friend.as_deref()
    }

    /// The saved friends, in the list's order; raw strings.
    pub(super) fn contacts(&self) -> &[ContactView] {
        &self.contacts
    }

    /// The saved friend with key `pub_hex`.
    pub(super) fn friend(&self, pub_hex: &str) -> Option<&ContactView> {
        self.contacts
            .iter()
            .find(|c| c.pub_hex.eq_ignore_ascii_case(pub_hex))
    }

    /// What a message written now to the friend `pub_hex` could do, as the
    /// last read found it ([`Horizons`]); None not known.
    pub(super) fn horizon(&self, pub_hex: &str) -> Option<bridge::QueueReach> {
        self.horizons.get(&convo_key(pub_hex)).copied()
    }

    /// The friends were loaded once at least.
    pub(super) fn contacts_ready(&self) -> bool {
        self.contacts_loaded
    }

    /// Why the last load of the friends failed.
    pub(super) fn contacts_error(&self) -> Option<&str> {
        self.contacts_error.as_deref()
    }

    /// The conversation with `pub_hex`, oldest first: empty with none.
    pub(super) fn rows(&self, pub_hex: &str) -> &[Row] {
        self.convo
            .get(&convo_key(pub_hex))
            .map_or(&[], Vec::as_slice)
    }

    /// The history was loaded once at least.
    pub(super) fn history_ready(&self) -> bool {
        self.history_loaded
    }

    /// Why the last history load failed, and whether D shows it.
    pub(super) fn history_error(&self) -> Option<&str> {
        self.history_error.as_deref()
    }

    pub(super) fn history_details(&self) -> bool {
        self.history_details
    }

    /// The open friend's draft; None with no friend open.
    pub(super) fn composer(&self) -> Option<&Composer> {
        let key = convo_key(self.open_friend.as_deref()?);
        Some(self.drafts.get(&key).unwrap_or(&EMPTY_COMPOSER))
    }

    /// Rows of the open conversation below the window.
    pub(super) fn scroll(&self) -> usize {
        self.scroll
    }

    /// The conversation with `pub_hex` as Home draws it, oldest first: the
    /// history's rows, then this session's sends no row is bound to yet.
    pub(super) fn bubbles(&self, pub_hex: &str) -> Vec<Bubble<'_>> {
        let key = convo_key(pub_hex);
        let mut bubbles: Vec<Bubble<'_>> = self.rows(pub_hex).iter().map(Bubble::Row).collect();
        bubbles.extend(
            self.pending
                .iter()
                .filter(|send| send.peer == key && send.bound_mid.is_none())
                .map(Bubble::Pending),
        );
        bubbles
    }

    /// The message chosen in Messages focus, counted from the newest (0).
    pub(super) fn chosen(&self) -> Option<usize> {
        self.chosen.filter(|_| self.focus == Focus::Messages)
    }

    /// Whether the message's whole body shows, however long.
    pub(super) fn expanded(&self, key: &BubbleKey) -> bool {
        self.expanded.contains(key)
    }

    /// This session's sends, oldest first.
    #[cfg(test)]
    pub(super) fn sends(&self) -> &[PendingSend] {
        &self.pending
    }

    /// Where a message of yours stands; None for the friend's, and for an
    /// old row of yours with no state to show.
    /// How the message `mid` (hex) came, when raven-node said it this
    /// session.
    pub(super) fn received_path(&self, mid: &str) -> Option<ArrivedVia> {
        self.paths.received.get(&mid.to_ascii_lowercase()).copied()
    }

    /// How a message of yours went, by id, when raven-node said it this
    /// session (it delivered it, or your send did through it).
    pub(super) fn delivered_path(&self, mid: &str) -> Option<ArrivedVia> {
        self.paths.delivered.get(&mid.to_ascii_lowercase()).copied()
    }

    pub(super) fn tick_view<'a>(&'a self, bubble: Bubble<'a>) -> Option<TickView<'a>> {
        if !bubble.outgoing() {
            return None;
        }
        let (pending, history, mid, delivered) = match bubble {
            Bubble::Row(row) => {
                let mid = Some(row.view.id.as_str()).filter(|id| !id.is_empty());
                let pending = mid.and_then(|mid| {
                    self.pending.iter().find(|send| {
                        send.bound_mid
                            .as_deref()
                            .is_some_and(|bound| bound.eq_ignore_ascii_case(mid))
                    })
                });
                let delivered = Row::delivered(&row.view)
                    .then(|| (row.view.created_at_ms, row.touched.map(|touch| touch.at_ms)));
                (pending, Some(row.view.delivery.as_str()), mid, delivered)
            }
            Bubble::Pending(send) => (Some(send), None, None, None),
        };
        let lower = mid.map(str::to_ascii_lowercase);
        let outbox = lower.as_ref().and_then(|mid| self.outbox.get(mid));
        let outcome = pending.and_then(|send| send.outcome.as_ref());
        let tick = delivery::tick(&Sources {
            history,
            outbox,
            outcome,
            job: self.job_state(pending),
            node_running: self.node.running(),
        })?;
        let written = lower.as_ref().is_some_and(|mid| self.written.contains(mid));
        let evidence = delivery::evidence(outcome, written);
        let mut actions = delivery::actions(&tick, evidence);
        if mid.is_none() {
            // raven-node knows a message by its id only.
            actions.try_now = false;
            actions.stop = false;
        }
        Some(TickView {
            since: self
                .tick_seen
                .get(&bubble.key())
                .and_then(|(_, since)| *since),
            tick,
            evidence,
            pending,
            outbox,
            mid,
            actions,
            delivered,
        })
    }

    /// Where the send job of `pending` is: the send worker's first job runs.
    fn job_state(&self, pending: Option<&PendingSend>) -> JobState {
        match pending {
            Some(send) if send.outcome.is_none() => {
                let mine = Some(send.local_id);
                if self.send_queue.front() == Some(&mine) {
                    JobState::Running
                } else if self.send_queue.contains(&mine) {
                    JobState::Queued
                } else {
                    JobState::Done
                }
            }
            _ => JobState::Done,
        }
    }

    /// The message `key` in the conversation with `peer`.
    pub(super) fn find_bubble(&self, peer: &str, key: &BubbleKey) -> Option<Bubble<'_>> {
        self.bubbles(peer)
            .into_iter()
            .find(|bubble| bubble.key() == *key)
    }

    /// A friend's name as the screens draw it: shaped, at most 24 cells.
    pub(super) fn shown_name(&self, pub_hex: &str) -> String {
        self.friend(pub_hex).map_or_else(String::new, |friend| {
            display::one_line(&friend.label, home::NAME_CELLS, self.look.glyphs.ellipsis)
        })
    }

    /// The friend's messages after the last one read on this computer, in
    /// this app or the desktop app (every one of theirs before any is read;
    /// read_marks.rs).
    pub(super) fn unread(&self, pub_hex: &str) -> usize {
        let rows = self.rows(pub_hex).iter().map(|row| read_marks::Row {
            id: &row.view.id,
            outgoing: row.view.outgoing,
            at_ms: row.view.created_at_ms,
        });
        let mark = self.settings.read_mark(&convo_key(pub_hex));
        read_marks::unread(rows, mark.as_ref())
    }

    /// The first other friend, in the list's order, with unread messages:
    /// one pane's conversation header says so.
    pub(super) fn unread_elsewhere(&self) -> Option<(usize, &ContactView)> {
        self.contacts
            .iter()
            .filter(|c| {
                self.open_friend
                    .as_deref()
                    .is_none_or(|open| !c.pub_hex.eq_ignore_ascii_case(open))
            })
            .find_map(|c| Some((self.unread(&c.pub_hex), c)).filter(|(n, _)| *n > 0))
    }

    /// The open conversation is on screen: Home in a window big enough,
    /// beside the list or, in one pane, in its place.
    pub(super) fn conversation_visible(&self) -> bool {
        self.screen == Screen::Home
            && !self.too_small()
            && self.open_friend.is_some()
            && (home::two_panes(self.size) || self.focus != Focus::Friends)
    }

    /// When the changed read markers are saved: the UI thread wakes for it.
    pub(super) fn marks_due(&self) -> Option<Instant> {
        self.marks_due
    }

    /// The jobs in flight, for tests.
    #[cfg(test)]
    pub(super) fn jobs_in_flight(&self) -> &JobCounts {
        &self.jobs_in_flight
    }

    /// COPY is on the plain terminal: the UI thread draws nothing until a
    /// key brings the screen back.
    pub(super) fn peeking(&self) -> bool {
        self.peeking
    }

    /// AF-1's share box; None on any other screen.
    pub(super) fn share_view(&self) -> Option<ShareView> {
        let Screen::AddFriend(add) = &self.screen else {
            return None;
        };
        let state = self.share_state(add.opened);
        let share = self.current_share();
        // Without a card yet (or none can be made), the invite line: it
        // parses as well, with no address.
        let plain = || {
            share
                .and_then(|share| share.plain.clone().ok())
                .or_else(|| self.me.as_ref().map(|me| me.invite.clone()))
        };
        let (line, with_address) = match &state {
            ShareState::Ready { .. } if self.settings.include_lan_in_card => {
                (share.and_then(|share| share.with_lan.clone()?.ok()), true)
            }
            ShareState::Ready { .. } => (plain(), false),
            ShareState::Starting { .. } => (None, false),
            _ if add.share_anyway => (plain(), false),
            _ => (None, false),
        };
        Some(ShareView {
            state,
            line,
            with_address,
        })
    }

    /// The share box's state, from the background program, the receive
    /// setting and the cards made for its listener. `opened`: when AF-1
    /// opened, for a spinner while nothing is known yet.
    fn share_state(&self, opened: Instant) -> ShareState {
        let local_ip = || super::node::local_host(self.node.listen.as_deref());
        match &self.node.state {
            NodeState::Starting { since } => ShareState::Starting { since: *since },
            NodeState::Listening { .. } => {
                let Some(share) = self.current_share() else {
                    return ShareState::Starting { since: opened };
                };
                match (&share.lan, &share.with_lan) {
                    (Some(Ok(lan)), Some(Ok(_))) => ShareState::Ready { lan: lan.clone() },
                    (Some(Ok(_)), _) => ShareState::Failed(NO_CARD_ADDRESS.to_owned()),
                    (Some(Err(NoCardLan::LocalOnly)), _) => {
                        ShareState::LocalOnly { ip: local_ip() }
                    }
                    (Some(Err(_)) | None, _) => ShareState::NoAddress,
                }
            }
            _ if self.settings.receive != Receive::On => ShareState::ReceiveOff,
            NodeState::ReceivingLocalOnly => ShareState::LocalOnly { ip: local_ip() },
            NodeState::NeedsPassphraseFile => ShareState::NeedsSetup,
            NodeState::StartFailed(plain) => {
                ShareState::Failed(plain.headline.trim_end_matches('.').to_owned())
            }
            // Not asked yet, or a start waits for the vault check.
            NodeState::Unknown => ShareState::Starting { since: opened },
            _ if self.auto_pending.is_some() => ShareState::Starting { since: opened },
            NodeState::NotRunning if !self.node.program.exe_known => {
                ShareState::Failed(NO_PROGRAM_PATH.to_owned())
            }
            NodeState::NotRunning => ShareState::Failed(NOT_RUNNING.to_owned()),
            NodeState::SendOnly => ShareState::Failed(NOT_LISTENING.to_owned()),
            NodeState::NotAnswering => ShareState::Failed(NOT_ANSWERING.to_owned()),
        }
    }

    /// The listener my card shares: the node's, while it listens on the
    /// network; else none.
    fn card_listen(&self) -> Option<String> {
        matches!(self.node.state, NodeState::Listening { .. })
            .then(|| self.node.listen.clone())
            .flatten()
    }

    /// The cards made for the listener there is now.
    fn current_share(&self) -> Option<&Share> {
        self.share
            .as_ref()
            .filter(|(listen, _)| *listen == self.card_listen())
            .map(|(_, share)| share)
    }

    /// [U]'s code on show, for tests that type it.
    #[cfg(test)]
    pub(super) fn update_code_for_tests(&self) -> Option<&str> {
        match &self.screen {
            Screen::AddFriend(add) => add.update.as_ref().map(|u| u.code.as_str()),
            _ => None,
        }
    }

    /// VF's confirmation code on show, for tests that type it.
    #[cfg(test)]
    pub(super) fn verify_code_for_tests(&self) -> Option<&str> {
        match &self.screen {
            Screen::Verify(vf) => match &vf.step {
                VerifyStep::Matched { confirm, .. } | VerifyStep::Later(confirm) => {
                    Some(confirm.code.as_str())
                }
                _ => None,
            },
            _ => None,
        }
    }

    /// What VF draws; None on any other screen. The friend's code is in it
    /// only once the code typed matched (or they are verified already).
    pub(super) fn verify_view(&self) -> Option<VerifyView<'_>> {
        let Screen::Verify(vf) = &self.screen else {
            return None;
        };
        let (name, new) = match &vf.who {
            VerifyWho::New(add) => (
                display::one_line(add.name.trim(), home::NAME_CELLS, self.look.glyphs.ellipsis),
                true,
            ),
            VerifyWho::Saved { pub_hex, .. } => (self.shown_name(pub_hex), false),
        };
        let shown = matches!(
            vf.step,
            VerifyStep::Matched { .. }
                | VerifyStep::AlreadyVerified
                | VerifyStep::Saving { verified: true }
                | VerifyStep::OlderMethod { .. }
        );
        // Marks against their code, in code mode only: words are never
        // marked against theirs (that would give them away one by one).
        let typed = match vf.entry.mode {
            EntryMode::Code => {
                code_marks(&vf.entry.code, &self.expected_code(vf).unwrap_or_default())
            }
            EntryMode::Words => Vec::new(),
        };
        let suggestions = if vf.entry.current.is_empty() || vf.entry.current.contains(' ') {
            Vec::new()
        } else {
            bridge::word_suggestions(&vf.entry.current)
                .into_iter()
                .map(bridge::list_word)
                .collect()
        };
        Some(VerifyView {
            state: vf,
            name,
            new,
            mine: self
                .me
                .as_ref()
                .map(|me| wizard::code_groups(&me.fingerprint))
                .unwrap_or_default(),
            mine_words: self
                .me
                .as_ref()
                .map(|me| me.words.to_vec())
                .unwrap_or_default(),
            typed,
            chips: vf
                .entry
                .chips
                .iter()
                .map(|&i| bridge::list_word(i))
                .collect(),
            suggestions,
            theirs: shown.then(|| wizard::code_groups(&self.expected_code(vf).unwrap_or_default())),
            theirs_words: shown
                .then(|| self.expected_words(vf))
                .flatten()
                .map(|words| words.to_vec()),
        })
    }

    /// A saved friend's security words, only while they are verified (CI
    /// draws them then): None for a friend not verified, or not saved.
    pub(super) fn verified_words(&self, pub_hex: &str) -> Option<Box<[String; bridge::WORDS]>> {
        self.friend(pub_hex)
            .filter(|friend| friend.pinned)
            .and_then(|friend| bridge::words_of(&friend.pub_hex))
    }

    /// The security code VF checks: the pasted friend's, from their key, or
    /// the saved friend's.
    fn expected_code(&self, vf: &VerifyState) -> Option<String> {
        match &vf.who {
            VerifyWho::New(add) => add.friend().map(|friend| friend.fingerprint.clone()),
            VerifyWho::Saved { pub_hex, .. } => self
                .friend(pub_hex)
                .map(|friend| friend.fingerprint.clone()),
        }
    }

    /// The security words VF checks, from the friend's key: drawn only once
    /// they matched.
    fn expected_words(&self, vf: &VerifyState) -> Option<Box<[String; bridge::WORDS]>> {
        match &vf.who {
            VerifyWho::New(add) => add.friend().map(|friend| friend.words.clone()),
            VerifyWho::Saved { pub_hex, .. } => bridge::words_of(pub_hex),
        }
    }

    /// The key VF compares what is typed with: the pasted friend's, or the
    /// saved friend's.
    fn expected_key(&self, vf: &VerifyState) -> Option<String> {
        match &vf.who {
            VerifyWho::New(add) => add.friend().map(|friend| friend.pub_hex.clone()),
            VerifyWho::Saved { pub_hex, .. } => {
                self.friend(pub_hex).map(|friend| friend.pub_hex.clone())
            }
        }
    }

    /// Every toast, the one on show first.
    #[cfg(test)]
    pub(super) fn toasts_for_tests(&self) -> Vec<&str> {
        self.toasts.iter().map(|t| t.text.as_str()).collect()
    }

    /// The toast on show, if any.
    pub(super) fn toast(&self) -> Option<&Toast> {
        self.toasts.front()
    }

    /// The time of the last update.
    pub(super) fn now(&self) -> Instant {
        self.now
    }

    pub(super) fn now_ms(&self) -> u64 {
        self.now_ms
    }

    /// The wall clock at `now` (a frame drawn after the last update): the
    /// last update's, moved on by the time since.
    pub(super) fn wall_ms(&self, now: Instant) -> u64 {
        let since = now.saturating_duration_since(self.now).as_millis();
        self.now_ms
            .saturating_add(u64::try_from(since).unwrap_or(u64::MAX))
    }

    /// The identity is open: Home shows its live header, route line and
    /// footer (UXF.10).
    pub(super) fn ready(&self) -> bool {
        self.identity == IdentityStatus::Ready
    }

    /// What Home's live feel follows (UXF.10).
    pub(super) fn live(&self) -> &Live {
        &self.live
    }

    /// When each message of every conversation was sent or arrived, on the
    /// wall clock, for the activity line (UXF.10): yours when written, theirs
    /// when this app saw them arrive (else when written).
    pub(super) fn message_times(&self) -> impl Iterator<Item = u64> + '_ {
        self.convo.values().flatten().map(|row| match row.touched {
            Some(touch) if !row.view.outgoing => touch.at_ms,
            _ => row.view.created_at_ms,
        })
    }

    /// The friend (a key, lower case) whose send the send worker runs now.
    pub(super) fn sending_to(&self) -> Option<&str> {
        let running = (*self.send_queue.front()?)?;
        self.pending
            .iter()
            .find(|send| send.local_id == running && send.outcome.is_none())
            .map(|send| send.peer.as_str())
    }

    pub(super) fn drawn_at(&self) -> Option<Instant> {
        self.drawn_at
    }

    /// Whether the screen needs drawing, and from now on that it does not.
    pub(super) fn take_dirty(&mut self) -> bool {
        mem::take(&mut self.dirty)
    }

    /// The UI thread drew a frame at `now`.
    pub(super) fn mark_drawn(&mut self, now: Instant) {
        self.drawn_at = Some(now);
    }

    /// The new state after `msg` arrived at `now` (`now_ms` on the wall
    /// clock), and what the UI thread must do about it.
    pub(super) fn update(&mut self, msg: Msg, now: Instant, now_ms: u64) -> Vec<Cmd> {
        self.now = now;
        self.now_ms = now_ms;
        self.expire_toasts();
        if matches!(
            msg,
            Msg::Key(Key::Event(_) | Key::PastedEnter) | Msg::Paste { .. }
        ) {
            self.lock_v2_input();
        }
        let mut out = match msg {
            Msg::Key(Key::Event(key)) if key.kind == KeyEventKind::Press => self.on_key(key),
            // Part of a paste: a line break in the composer or AF-1's paste
            // box, and never a send or an answer anywhere. In DEL and ERASE
            // it clears the word: what came before it was pasted too.
            Msg::Key(Key::PastedEnter) => {
                self.last_paste = Some(now);
                if !self.clear_typed_word() {
                    if self.composer_takes_text() {
                        self.compose(|composer| composer.insert("\n"));
                    } else if self.paste_box_takes_text() {
                        self.paste_box_input("\n");
                    }
                }
                Vec::new()
            }
            // Releases.
            Msg::Key(_) => Vec::new(),
            Msg::Paste { text, .. } => {
                self.last_paste = Some(now);
                self.on_paste(&text);
                Vec::new()
            }
            Msg::Resize { cols, rows } => {
                self.size = (cols, rows);
                self.clamp_help_scroll();
                self.scroll = home::clamp_scroll(self, self.scroll);
                self.clamp_net_scroll();
                self.dirty = true;
                Vec::new()
            }
            // Toasts were expired above; nothing else runs on a timer yet.
            Msg::Tick => Vec::new(),
            // Kept in the ring for Details; a Keychain wait opens KC.
            Msg::Stderr(line) => {
                if let Some(wait) = workers::keychain_wait(&line) {
                    self.keychain_waiting(wait);
                }
                Vec::new()
            }
            Msg::Job(result) => {
                self.on_job(result);
                Vec::new()
            }
            Msg::Poll(update) => {
                self.on_poll(update);
                Vec::new()
            }
            Msg::OsSignal(signal) => vec![Cmd::Exit(ExitPlan::signal(signal))],
            // Without the input thread no key arrives, and without the signal
            // thread nothing restores the terminal on SIGTERM: stop now.
            Msg::ThreadDied(name)
                if name == workers::INPUT_THREAD || name == workers::SIGNAL_THREAD =>
            {
                vec![Cmd::Exit(ExitPlan::part_failed())]
            }
            Msg::ThreadDied(_) => Vec::new(),
        };
        self.home_upkeep();
        self.groups_upkeep();
        self.meeting_upkeep();
        self.share_upkeep();
        self.meet_upkeep();
        self.network_note_upkeep();
        self.firewall_upkeep();
        self.privacy_notice_upkeep();
        self.lock_upkeep();
        self.lock_v2_upkeep();
        self.erase_upkeep();
        self.quit_upkeep();
        out.extend(self.take_cmds());
        // Once the app asked to end or to leave for the classic menu, the UI
        // thread carries out that alone: no job and no word to the poller
        // goes out any more.
        if out.iter().any(Cmd::leaves) {
            self.leaving = true;
        }
        if self.leaving {
            out.retain(Cmd::leaves);
            out.truncate(1);
        }
        out
    }

    /// AF-1 asks for my cards again whenever the listener it would share
    /// changed: the card with an address follows the node, never a setting.
    fn share_upkeep(&mut self) {
        if !matches!(self.screen, Screen::AddFriend(_)) || self.identity != IdentityStatus::Ready {
            return;
        }
        let wanted = self.card_listen();
        if self.share_asked.as_ref() != Some(&wanted) {
            self.share_asked = Some(wanted.clone());
            self.job(Cmd::Store(StoreJob::ShareCard { listen: wanted }));
        }
    }

    /// The meeting toasts (UXF.8), shown on Home only (one noted on another
    /// screen waits for Home): a friend's messages that waited were all
    /// delivered, or a burst of messages from a friend came after an hour of
    /// none. Each shows at most once a minute for one friend; one due sooner
    /// is dropped.
    fn meeting_upkeep(&mut self) {
        if self.screen != Screen::Home || !self.meeting.values().any(MeetingNotes::due) {
            return;
        }
        let now = self.now;
        let may_show = |last: Option<Instant>| {
            last.is_none_or(|at| now.saturating_duration_since(at) >= MEETING_TOAST_EVERY)
        };
        let friends: Vec<(String, String)> = self
            .contacts
            .iter()
            .map(|friend| (convo_key(&friend.pub_hex), self.shown_name(&friend.pub_hex)))
            .collect();
        let mut toasts = Vec::new();
        for (key, name) in friends {
            let Some(notes) = self.meeting.get_mut(&key).filter(|notes| notes.due()) else {
                continue;
            };
            if notes.waiting.is_empty() && notes.delivered > 0 {
                let n = mem::take(&mut notes.delivered);
                if may_show(notes.delivered_at) {
                    notes.delivered_at = Some(now);
                    toasts.push(delivered_toast(n, &name));
                }
            }
            if let Some(n) = notes.burst.take() {
                if may_show(notes.burst_at) {
                    notes.burst_at = Some(now);
                    toasts.push(burst_toast(n, &name));
                }
            }
        }
        for text in toasts {
            self.push_toast(&text);
        }
    }

    /// What follows on Home from any message: the ages are drawn again each
    /// minute, the open conversation is read up to its newest message, and
    /// changed read markers are saved once due.
    fn home_upkeep(&mut self) {
        if mem::take(&mut self.ticks_stale) {
            self.refresh_ticks();
        }
        if self.screen == Screen::Home && !self.friends.is_empty() {
            let minute = self.now_ms / 60_000;
            if minute != self.age_minute {
                self.age_minute = minute;
                self.dirty = true;
            }
        }
        self.mark_open_read();
        if self.marks_due.is_some_and(|due| due <= self.now) && !self.erasing() {
            self.marks_due = None;
            self.job(Cmd::Store(StoreJob::SaveReadMarks(self.settings.clone())));
        }
    }

    /// The open conversation is on screen: its newest message is read. The
    /// marker is saved [`MARKS_SAVE_AFTER`] after the first change since the
    /// last save. It never leaves this computer.
    fn mark_open_read(&mut self) {
        if self.identity != IdentityStatus::Ready || !self.conversation_visible() {
            return;
        }
        let Some(key) = self.open_friend.as_deref().map(convo_key) else {
            return;
        };
        let Some(newest) = self
            .convo
            .get(&key)
            .and_then(|rows| rows.iter().rev().find(|row| !row.view.id.is_empty()))
        else {
            return;
        };
        let mark = ReadMark {
            id: newest.view.id.clone(),
            at_ms: Some(newest.view.created_at_ms),
        };
        // Never back: the desktop app may have read a newer message this
        // app has not loaded yet.
        let place = |id: &str| place_in(&self.convo, &key, id);
        if self
            .settings
            .read_mark(&key)
            .is_some_and(|current| !read_marks::later(&mark, &current, &place))
        {
            return;
        }
        self.settings.set_read_mark(&key, mark);
        self.marks_due.get_or_insert(self.now + MARKS_SAVE_AFTER);
        self.dirty = true;
    }

    /// The saved read markers changed (the poller saw tui_state.json or
    /// tui_private.rms change): read them again, once at a time.
    fn load_read_marks(&mut self) {
        if self.identity != IdentityStatus::Ready {
            return;
        }
        if self.marks_loading {
            self.marks_again = true;
            return;
        }
        self.marks_loading = true;
        self.job(Cmd::Store(StoreJob::LoadReadMarks));
    }

    /// The saved markers came: each one later than this app's (the desktop
    /// app read that chat) is taken, and the counts follow.
    fn read_marks_loaded(&mut self, marks: &ReadMarks) {
        self.marks_loading = false;
        let convo = &self.convo;
        if self
            .settings
            .take_later(marks, &|key, id| place_in(convo, key, id))
        {
            self.dirty = true;
        }
        if std::mem::take(&mut self.marks_again) {
            self.load_read_marks();
        }
    }

    /// A marker saved by an older app has no time (read_marks.rs): it gets
    /// its message's from the history, saved with the next marker save.
    fn time_old_marks(&mut self) {
        let mut timed = Vec::new();
        for (key, mark) in self.settings.read_marks() {
            if mark.at_ms.is_some() {
                continue;
            }
            let found = self.convo.get(&key).and_then(|rows| {
                rows.iter()
                    .rfind(|row| row.view.id.eq_ignore_ascii_case(&mark.id))
            });
            if let Some(row) = found {
                let at_ms = Some(row.view.created_at_ms);
                timed.push((key, ReadMark { at_ms, ..mark }));
            }
        }
        if timed.is_empty() {
            return;
        }
        for (key, mark) in timed {
            self.settings.set_read_mark(&key, mark);
        }
        self.marks_due.get_or_insert(self.now + MARKS_SAVE_AFTER);
    }

    /// A paste is text where text is typed (WZ-2's name, as one line, and the
    /// composer); on the friend list a toast says where a card goes. It never
    /// confirms, sends or saves anything.
    fn on_paste(&mut self, text: &str) {
        if self.too_small() || self.peeking {
            return;
        }
        // LOCKED's and PASS's passphrase fields take one line (P6.40).
        if self.lock_v2_paste(text) {
            return;
        }
        // NEW GROUP's name takes it as one line (groups, lab).
        if !self.too_small() && self.group_paste(text) {
            return;
        }
        // DEL's and ERASE's words must be typed: a paste into one clears it.
        if self.clear_typed_word() || !self.overlays.is_empty() {
            return;
        }
        match (&self.screen, self.focus) {
            (Screen::Wizard(WizardStep::Name), _) => self.type_name(text),
            (Screen::Home, Focus::Composer) if self.open_group().is_some() => {
                self.group_insert(text)
            }
            (Screen::Home, Focus::Composer) => self.compose(|composer| composer.insert(text)),
            (Screen::Home, Focus::Friends) => self.push_toast(LIST_PASTE_TOAST),
            // AF-2's name field takes it as one line.
            (Screen::AddFriend(add), _) if add.naming => self.type_friend_name(text),
            // Into the paste box, whichever box has the keys; never into
            // [U]'s code, which a paste must not be able to answer.
            (Screen::AddFriend(add), _) if add.update.is_none() => self.paste_box_input(text),
            // VF's field and CI's take it as text; Enter waits out the
            // paste guard, so it answers nothing.
            (Screen::Verify(_), _) => self.verify_input(text, true),
            (Screen::FriendPage(page), _) if page.edit.is_some() && !page.saving => {
                self.page_input(text)
            }
            // SET's name field takes it as one line.
            (Screen::Settings(set), _) if set.name.is_some() => self.settings_name_input(text),
            // MEET's address field, as CI's.
            (Screen::Meet(meet), _) if self.meet_field_open() && !meet.saving() => {
                self.meet_input(text)
            }
            _ => {}
        }
    }

    /// Hands a job out at the end of this update, counted until it answers.
    /// While the listen address is about to change, every new job waits
    /// behind that change.
    fn job(&mut self, cmd: Cmd) {
        if self.loopback_wanted {
            self.held.push(cmd);
            return;
        }
        if let Some(kind) = cmd.job_kind() {
            self.jobs_in_flight.start(kind);
        }
        self.cmds.push(cmd);
    }

    /// What this update hands the UI thread, once the rest has settled:
    ///
    /// - a Keychain wait is over once no job is left that it could hold up;
    /// - the loopback listen address is set once no job runs, before the
    ///   jobs that waited for it;
    /// - the poller hears when what it should look at changed.
    fn take_cmds(&mut self) -> Vec<Cmd> {
        if self.keychain.is_some() && self.jobs_in_flight.idle() {
            self.end_keychain_wait();
        }
        let mut out = Vec::new();
        if self.loopback_wanted && self.jobs_in_flight.idle() {
            self.loopback_wanted = false;
            self.listen = ListenOverride::Loopback;
            out.push(Cmd::ApplyListenLoopback);
            for cmd in mem::take(&mut self.held) {
                self.job(cmd);
            }
        }
        out.append(&mut self.cmds);
        if self.poller_on {
            let hints = self.poll_hints();
            if self.hints_sent != Some(hints) {
                self.hints_sent = Some(hints);
                out.push(Cmd::Poll(PollCtl::Hints(hints)));
            }
        }
        out
    }

    /// What the poller should look at: Status every second while starting,
    /// the outbox often while a message is live, and the service log while
    /// a start or KC may need it, NET shows it, or a node that runs isn't
    /// receiving (the lines written from then on say why; an older run's
    /// never count, and a login service's node writes elsewhere).
    fn poll_hints(&self) -> PollHints {
        let starting = matches!(self.node.state, NodeState::Starting { .. });
        let log_open = matches!(&self.screen, Screen::Network(net) if net.log.is_some());
        let send_only = self.node.state == NodeState::SendOnly;
        PollHints {
            starting,
            live: self.outbox_live || self.live_messages(),
            read_log: starting
                || self.overlays.contains(&Overlay::Keychain)
                || log_open
                || send_only,
        }
    }

    /// A message of yours is waiting, held or sent and not confirmed.
    fn live_messages(&self) -> bool {
        let live = [
            mem::discriminant(&Tick::Waiting(Waiting::NotRetried)),
            mem::discriminant(&Tick::OnHold {
                code: String::new(),
            }),
            mem::discriminant(&Tick::Sent),
        ];
        self.tick_seen
            .values()
            .any(|(class, _)| live.contains(class))
    }

    fn on_job(&mut self, result: JobResult) {
        let kind = result.name().kind();
        if result.name().tracked() {
            self.jobs_in_flight.finish(kind);
        }
        // The send worker answers in its order: this is its first job's.
        let send = if kind == JobKind::Send {
            self.send_queue.pop_front().flatten()
        } else {
            None
        };
        self.ticks_stale = true;
        let before = self.node.clone();
        match result {
            JobResult::Contacts { contacts, stamp } => self.contacts_loaded(contacts, stamp),
            JobResult::History { history, stamp } => self.history_loaded(history, stamp),
            JobResult::Horizons(found) => self.horizons_loaded(found),
            // A marker not saved is read again next time: nothing to say.
            JobResult::ReadMarksSaved(_) => {}
            JobResult::ReadMarks(marks) => self.read_marks_loaded(&marks),
            JobResult::SettingsSaved(Ok(())) => {}
            JobResult::SettingsSaved(Err(_)) => self.push_toast(SETTINGS_NOT_SAVED),
            JobResult::VaultChecked { prompts } => self.vault_checked_for_create(prompts),
            JobResult::Created { result, captured } => match result {
                Ok(new) => self.identity_created(new),
                Err(why) => self.create_failed(&why, &captured),
            },
            JobResult::Probed(probe) => self.apply_probe(&probe),
            JobResult::Ensured(ensured) => self.start_ended(ensured),
            JobResult::Stopped(stopped) => self.stop_ended(stopped),
            // This build reads no login items: UXF.7's check.
            JobResult::Managed(managed) => {
                self.node.login_item = LoginItemKnown::NotAvailable;
                self.node.managed = managed;
                self.login_item_read();
            }
            JobResult::LoginItem(item) => {
                self.node.login_item = LoginItemKnown::of(item);
                self.node.managed = item.map(|item| item.managed);
                self.login_item_read();
            }
            JobResult::LanAddresses(addresses) => {
                self.lan_addresses = Some(addresses);
                self.dirty = true;
            }
            JobResult::ServiceLog(lines) => self.log_read(lines),
            JobResult::Unlocked(result) => self.unlock_ended(result),
            JobResult::Vault(vault) => {
                self.vault_checked = true;
                self.vault = vault;
                if self.vault.needs_passphrase_file && !self.node.running() {
                    self.node.state = NodeState::NeedsPassphraseFile;
                }
                self.try_auto_start();
            }
            JobResult::Sent { local_id, outcome } => self.send_ended(local_id, outcome),
            JobResult::Retried {
                mid, peer, result, ..
            } if self.meet_asked_retry(&mid) => {
                self.meet_retry_ended(&peer, result.is_ok());
            }
            JobResult::Retried { peer, result, .. } => self.retry_ended(&peer, result),
            JobResult::Cancelled {
                mid,
                peer,
                result,
                captured,
            } => self.cancel_ended(&mid, &peer, result, &captured),
            // The send worked; the address is learned again next time.
            JobResult::LearnedDialSaved(_) => {}
            JobResult::Shared { listen, share } => {
                // Only the latest ask counts: an older listener's cards are
                // not this one's.
                if self.share_asked.as_ref() == Some(&listen) {
                    self.share = Some((listen, share));
                    self.dirty = true;
                }
            }
            JobResult::AddressesUpdated { pub_hex, result } => {
                self.addresses_updated(&pub_hex, result);
            }
            JobResult::FriendChanged {
                change,
                pub_hex,
                result,
                notes,
            } => self.friend_changed(change, &pub_hex, result, notes),
            JobResult::Privacy(read) => self.privacy_read(read),
            JobResult::ChatKeepSaved { keep, result } => self.chat_keep_saved(keep, result),
            // Marked, or left for the CLI to say: nothing to show.
            JobResult::NoticeMarked(_) => {}
            JobResult::ChatDeleted { pub_hex, result } => self.chat_deleted(&pub_hex, result),
            JobResult::ErasePlan(plan) => self.erase_plan_read(plan),
            JobResult::Erased(end) => self.erase_ended(end),
            JobResult::Security(read) => self.security_read(read),
            JobResult::NoticeResolved(result) => self.notice_resolved(result),
            JobResult::SendHoldSet {
                pub_hex,
                on,
                result,
            } => self.send_hold_set(&pub_hex, on, result),
            JobResult::Rechecked { pub_hex, result } => self.rechecked(&pub_hex, result),
            JobResult::OlderMethodAccepted { pub_hex, result } => {
                self.older_method_accepted(&pub_hex, result);
            }
            JobResult::LockedV2(result) => self.locked_v2(result),
            JobResult::UnlockedV2(answer) => self.unlocked_v2(answer),
            JobResult::PassphraseChanged(result) => self.passphrase_changed(result),
            JobResult::LockSettings(view) => self.lock_settings_read(view),
            JobResult::SleepLockSaved(result) => self.sleep_lock_saved(result),
            JobResult::Updates(view) => self.updates_read(view),
            JobResult::UpdateInstalled {
                result,
                after,
                started,
            } => self.update_installed(result, after, started),
            JobResult::Groups(read) => self.groups_loaded(read),
            JobResult::GroupMarked { result, .. } => self.group_marked(result),
            JobResult::GroupSent { local_id, done } => self.group_sent(local_id, done),
            JobResult::GroupChanged { change, done } => self.group_changed(change, done),
            JobResult::Failed { job, plain } => self.job_failed(job, plain, send),
        }
        self.node_changed(&before);
    }

    fn on_poll(&mut self, update: PollUpdate) {
        // ERASE's erase began: nothing more is read from the profile (the
        // next update after it, should it change nothing, reads again).
        if self.erasing() {
            return;
        }
        self.ticks_stale = true;
        let before = self.node.clone();
        match update {
            PollUpdate::Status(probe) => self.apply_probe(&probe),
            PollUpdate::StatusStopped => self.node.polling_stopped = true,
            PollUpdate::Outbox { peer, items } => {
                let live = items
                    .iter()
                    .any(|item| matches!(item.state.as_str(), "queued" | "held" | "sent"));
                // One friend's list says nothing about the others.
                self.outbox_live = live || (peer.is_some() && self.outbox_live);
                self.merge_outbox(peer.as_deref(), items);
            }
            PollUpdate::File {
                watched: Watched::Contacts,
                stamp,
            } => {
                self.contacts_seen = Some(stamp);
                if self.contacts_stamp != Some(stamp) {
                    self.load_contacts();
                }
            }
            PollUpdate::File {
                watched: Watched::History,
                stamp,
            } => {
                self.history_seen = Some(stamp);
                if self.history_stamp != Some(stamp) {
                    self.load_history();
                }
            }
            // This app's own saves come back here too: reading them again
            // takes nothing that isn't later.
            PollUpdate::File {
                watched: Watched::ReadMarks,
                ..
            } => self.load_read_marks(),
            // The desktop app deleted a message: the chats leave it out
            // (hidden.rs). The first look only notes the file, which the
            // first history load reads anyway.
            PollUpdate::File {
                watched: Watched::Hidden,
                stamp,
            } => {
                if self
                    .hidden_seen
                    .replace(stamp)
                    .is_some_and(|seen| seen != stamp)
                {
                    self.load_history();
                }
            }
            // groups.json (lab, only watched while groups are live).
            PollUpdate::File {
                watched: Watched::Groups,
                stamp,
            } => self.groups_file_seen(stamp),
            PollUpdate::HorizonsDue => {
                self.horizons_on = true;
                self.load_horizons();
                // The security notices, once a minute (P6.31).
                self.load_security();
                // The groups' copies and waiting work, once a minute.
                self.load_groups(true);
            }
            PollUpdate::Network(on_any) => {
                self.on_any_network = on_any;
                self.dirty = true;
            }
            PollUpdate::NodeFolder { pid, folder } => self.node.folder = Some((pid, folder)),
            PollUpdate::Paths(paths) => {
                let before = (self.paths.received.len(), self.paths.delivered.len());
                self.paths.received.extend(paths.received);
                self.paths.delivered.extend(paths.delivered);
                if before != (self.paths.received.len(), self.paths.delivered.len()) {
                    self.dirty = true;
                }
            }
            PollUpdate::ServiceLog(log) => {
                // Why a node that runs isn't receiving, when its Status
                // doesn't say (an older node).
                self.node.read_log(&log);
                if let (Some(item), NodeState::Starting { .. }) =
                    (bridge::service_keychain_wait(&log), &self.node.state)
                {
                    self.keychain_waiting(KeychainWait {
                        item,
                        service: true,
                    });
                }
                // The log grew while NET shows it: read its end again, once
                // the read before has answered.
                let reread = self
                    .log_view_mut()
                    .is_some_and(|view| !mem::replace(&mut view.reading, true));
                if reread {
                    self.job(Cmd::Node(NodeJob::ServiceLog));
                }
            }
        }
        self.node_changed(&before);
    }

    /// The background program's own word (its Status) applied; one that
    /// answered is a heartbeat (UXF.10), drawn at once.
    fn apply_probe(&mut self, probe: &Probe) {
        self.node.apply(probe);
        if probe.running() && !probe.timed_out {
            self.live.beat = Some(Touch {
                at: self.now,
                at_ms: self.now_ms,
            });
            self.dirty = true;
        }
    }

    /// The background program's view changed from `before`: drawn again,
    /// and when the profile's at-rest state moved (sealed now, the key
    /// back, ...) the privacy read runs again, so the notices and NET follow.
    fn node_changed(&mut self, before: &NodeView) {
        if self.node != *before {
            self.dirty = true;
        }
        // RX waited for this word, or this folder's background program
        // receives now while receiving was never answered.
        if self.node.state != NodeState::Unknown {
            self.adopt_receiving();
            self.try_auto_start();
        }
        // Lock v2 (P6.40): LOCKED follows the node's lock.
        if self.node.locked != before.locked
            || (self.node.locked == Some(true)
                && !self
                    .overlays
                    .iter()
                    .any(|overlay| matches!(overlay, Overlay::Locked(_))))
        {
            self.lock_v2_follow(before.locked);
        }
        if self.node.at_rest != before.at_rest {
            self.load_privacy();
        }
        // raven-node noted something new (its open alerts or what it
        // refused changed): the notices are read again.
        if self.node.security != before.security && self.security.is_some() {
            self.load_security();
        }
        // `raven lock`'s lock while Raven runs anyway (a login item the lock
        // left on started it at login): there is nothing to start, so UNLOCK
        // closes; the lock stays, and a later start asks again.
        if self.cli_locked && self.node.running() && self.overlays.last() == Some(&Overlay::Unlock)
        {
            self.close_overlay();
            self.after_unlock = None;
        }
    }

    /// Loads the friends, unless a load is running: that one's end looks at
    /// the file again.
    fn load_contacts(&mut self) {
        if !self.contacts_loading {
            self.contacts_loading = true;
            self.job(Cmd::Store(StoreJob::LoadContacts));
        }
    }

    fn contacts_loaded(&mut self, contacts: Result<Vec<ContactView>, String>, stamp: FileStamp) {
        self.contacts_loading = false;
        self.contacts_stamp = Some(stamp);
        match contacts {
            Ok(contacts) => {
                let first = !self.contacts_loaded;
                self.contacts_loaded = true;
                self.contacts_error = None;
                let friends: Vec<String> = contacts.iter().map(|c| c.pub_hex.clone()).collect();
                let changed = friends != self.friends;
                self.set_friends(friends);
                self.contacts = contacts;
                if first && !self.friends.is_empty() {
                    self.request_auto_start(AutoStart::Launch);
                }
                if self.horizons_due || (changed && self.horizons_on) {
                    self.load_horizons();
                }
                // A group shows its members by the friends' names.
                self.load_groups(false);
            }
            Err(why) => {
                self.contacts_error = Some(why);
                self.dirty = true;
            }
        }
        // Changed again while it was read.
        if self
            .contacts_seen
            .is_some_and(|seen| Some(seen) != self.contacts_stamp)
        {
            self.load_contacts();
        }
    }

    /// Reads how long a message written now could wait for each friend, on
    /// the store worker; once the friends are loaded and no read runs, else
    /// as soon as that is so.
    fn load_horizons(&mut self) {
        if self.identity != IdentityStatus::Ready || !self.contacts_loaded || self.horizons_loading
        {
            self.horizons_due = true;
            return;
        }
        self.horizons_due = false;
        if self.friends.is_empty() {
            self.horizons.clear();
            return;
        }
        self.horizons_loading = true;
        self.job(Cmd::Store(StoreJob::LoadHorizons {
            peers: self.friends.clone(),
        }));
    }

    /// A horizon read's answer: it replaces the last one whole (a friend it
    /// does not know about has no line).
    fn horizons_loaded(&mut self, found: Horizons) {
        self.horizons_loading = false;
        if self.horizons != found {
            self.horizons = found;
            self.dirty = true;
        }
        if self.horizons_due {
            self.load_horizons();
        }
    }

    /// Loads every conversation, unless a load is running: that one's end
    /// looks at the file again.
    fn load_history(&mut self) {
        if !self.history_loading {
            self.history_loading = true;
            self.job(Cmd::Store(StoreJob::LoadHistory));
        }
    }

    /// A history load's answer. The rows of the session's first load are
    /// seen at the start; later ones are new (presence.rs). A failure keeps
    /// the conversations as they were, and says so.
    fn history_loaded(&mut self, history: Result<Conversations, String>, stamp: FileStamp) {
        self.history_loading = false;
        self.history_stamp = Some(stamp);
        match history {
            Ok(conversations) => {
                let now = Touch {
                    at: self.now,
                    at_ms: self.now_ms,
                };
                self.convo = merge_history(&self.convo, conversations, !self.history_loaded, now);
                self.note_bursts(now);
                self.note_arrivals(now);
                self.time_old_marks();
                self.history_loaded = true;
                self.history_error = None;
                self.scroll = home::clamp_scroll(self, self.scroll);
                // A friend's message may have come over a new connection.
                if self.horizons_on {
                    self.load_horizons();
                }
                // A group copy's row may have changed (its receipt).
                self.load_groups(true);
            }
            Err(why) => self.history_error = Some(why),
        }
        self.dirty = true;
        // Changed again while it was read.
        if self
            .history_seen
            .is_some_and(|seen| Some(seen) != self.history_stamp)
        {
            self.load_history();
        }
    }

    /// A history load brought messages from friends (rows that arrived at
    /// `now`): a saved friend's burst after an hour of none is noted for its
    /// toast (UXF.8).
    fn note_bursts(&mut self, now: Touch) {
        let mut bursts = Vec::new();
        for (key, rows) in &self.convo {
            let arrived = rows
                .iter()
                .any(|row| !row.view.outgoing && row.touched == Some(now));
            if !arrived || self.friend(key).is_none() {
                continue;
            }
            if let Some(n) = burst_after_silence(rows, self.now, self.now_ms) {
                bursts.push((key.clone(), n));
            }
        }
        for (key, n) in bursts {
            self.meeting.entry(key).or_default().burst = Some(n);
        }
    }

    /// A history load brought messages from saved friends (rows that
    /// arrived at `now`): the ticker names the friend with the most of them
    /// (UXF.10).
    fn note_arrivals(&mut self, now: Touch) {
        let arrived = self
            .convo
            .iter()
            .filter(|(key, _)| self.friend(key).is_some())
            .map(|(key, rows)| {
                let count = rows
                    .iter()
                    .filter(|row| !row.view.outgoing && row.touched == Some(now))
                    .count();
                (count, key)
            })
            .filter(|(count, _)| *count > 0)
            .max_by(|a, b| a.0.cmp(&b.0).then_with(|| b.1.cmp(a.1)));
        if let Some((count, key)) = arrived {
            let event = Event::Received {
                peer: key.clone(),
                count,
            };
            self.live.event = Some((event, self.now));
        }
    }

    /// Follows the messages of yours that waited, from every message's tick
    /// (`ticks`: each friend's by message id), for the toast that says they
    /// were all delivered (UXF.8). One seen waiting or held joins its
    /// friend's notes; one delivered since counts; one that ended, or that
    /// the history no longer has, leaves. Only saved friends are followed.
    fn follow_waiting(&mut self, ticks: &HashMap<String, HashMap<String, Tick>>) {
        let saved: HashSet<String> = self
            .contacts
            .iter()
            .map(|friend| convo_key(&friend.pub_hex))
            .collect();
        self.meeting.retain(|key, _| saved.contains(key));
        let none = HashMap::new();
        for key in saved {
            let theirs = ticks.get(&key).unwrap_or(&none);
            let joining: Vec<&String> = theirs
                .iter()
                .filter(|(_, tick)| matches!(tick, Tick::Waiting(_) | Tick::OnHold { .. }))
                .map(|(mid, _)| mid)
                .collect();
            if joining.is_empty() && !self.meeting.contains_key(&key) {
                continue;
            }
            let notes = self.meeting.entry(key).or_default();
            notes.waiting.extend(joining.into_iter().cloned());
            let mut delivered = 0;
            notes.waiting.retain(|mid| match theirs.get(mid) {
                Some(Tick::Delivered) => {
                    delivered += 1;
                    false
                }
                Some(tick) => !tick.failed(),
                None => false,
            });
            notes.delivered += delivered;
        }
    }

    /// A start's answer: the node's state after it, and whether this app
    /// started the one running. A failure stays on show while none runs.
    fn start_ended(&mut self, ensured: Ensured) {
        // Out of Starting, so the Status after it decides.
        self.node.state = NodeState::Unknown;
        self.apply_probe(&ensured.after);
        match ensured.result {
            Ok(()) => self.node.started_by_app = ensured.started_by_app,
            // Another start won the race: one answers anyway.
            Err(_) if ensured.after.running() => {}
            Err(why) => match errors::explain_node_start(&why) {
                // `raven lock` locked it meanwhile (review
                // E-harness-docs-ci-3): NET's S asks first now.
                NodeStartProblem::Failed(plain) if is_locked_text(&why) => {
                    self.cli_locked = true;
                    self.node.state = NodeState::StartFailed(plain);
                }
                NodeStartProblem::NeedsPassphraseFile => {
                    self.node.state = NodeState::NeedsPassphraseFile;
                    self.show_passfile_once();
                }
                NodeStartProblem::Failed(plain) => self.node.state = NodeState::StartFailed(plain),
            },
        }
    }

    /// A job panicked: what waited for it stops waiting, and a toast says so.
    /// `send`: the send it was, for the send worker's.
    fn job_failed(&mut self, job: JobName, plain: Plain, send: Option<u64>) {
        self.push_toast(&plain.headline);
        if let Some(pending) =
            send.and_then(|id| self.pending.iter_mut().find(|p| p.local_id == id))
        {
            pending.outcome = Some(Outcome::NotSent {
                unmet: Unmet::No,
                plain: plain.clone(),
            });
        }
        match job {
            JobName::LoadContacts => {
                self.contacts_loading = false;
                self.contacts_error = Some(plain.technical);
            }
            JobName::LoadHistory => {
                self.history_loading = false;
                self.history_error = Some(plain.technical);
                self.dirty = true;
            }
            // Not known now: no line until a read answers.
            JobName::LoadHorizons => self.horizons_loaded(Horizons::new()),
            JobName::NodeEnsure => self.node.state = NodeState::StartFailed(plain),
            JobName::NodeStop => {
                self.stopping = false;
                self.dirty = true;
                if self.erase_waits_for_stop() {
                    // The erase stops Raven itself, or says why it can't.
                    self.run_erase();
                } else if self.lock_waits_for_stop() {
                    self.lock_not_stopped(StopOutcome::Failed(plain.technical));
                }
            }
            JobName::NodeLanAddresses => self.lan_addresses = Some(None),
            JobName::NodeLog => self.log_read(Err(plain.technical)),
            JobName::NodeVault => {
                self.vault_checked = true;
                self.try_auto_start();
            }
            JobName::NodeUnlock => self.unlock_ended(Err(plain.technical)),
            JobName::NodeLockV2
            | JobName::NodeUnlockV2
            | JobName::NodePassphrase
            | JobName::NodeLockSettings
            | JobName::NodeSleepLock => self.lock_v2_job_failed(job),
            // Not known now: what was read before stays.
            JobName::NodeUpdates => {}
            JobName::NodeInstall => self.update_install_failed(plain.headline.clone()),
            // WZ-4 says so, with [R] to try again.
            JobName::CheckVault | JobName::CreateIdentity => {
                if self.finishing_setup() {
                    let failure = Failure::new(plain, self.settings.show_details);
                    self.set_step(WizardStep::Creating(Creating::Failed(failure)));
                }
            }
            // No card: the share box says the address can't be told, and S
            // still shows the invite line.
            JobName::ShareCard => {
                self.share = self.share_asked.clone().map(|listen| {
                    let share = Share {
                        lan: None,
                        with_lan: None,
                        plain: Err(plain.technical),
                    };
                    (listen, share)
                });
            }
            JobName::UpdateAddresses => {
                if let Screen::AddFriend(add) = &mut self.screen {
                    add.updating = false;
                    add.update_error = Some(plain.headline);
                }
            }
            JobName::ChangeFriend(_)
            | JobName::DeleteChat
            | JobName::Recheck
            | JobName::AcceptOlderMethod => self.change_failed(plain),
            JobName::LoadSecurity => self.security_read(Err(NotAvailable)),
            // The toast said so; what is open is read again.
            JobName::ResolveNotice | JobName::SetSendHold => self.load_security(),
            // Not known now: hidden until a read answers.
            JobName::LoadPrivacy => self.privacy_read(Err(NotAvailable)),
            JobName::ErasePlan => self.erase_plan_read(Err(plain.technical)),
            // Whether anything went is not known: the app ends and says to
            // finish with `raven erase` (nothing is saved).
            JobName::Erase => self.erase_ended(EraseEnd::Ran {
                finished: false,
                lines: vec![ERASE_FAILED.to_owned()],
            }),
            // The toast said so; the setting is shown as it is saved.
            JobName::SetChatKeep => self.load_privacy(),
            // Not known: LOCK no longer waits for it, and stops as where
            // this build reads no login items (review D-lock-tui-6).
            JobName::NodeManaged => {
                if self.node.login_item == LoginItemKnown::Unknown {
                    self.node.login_item = LoginItemKnown::NotAvailable;
                }
                self.login_item_read();
            }
            // Read again at the next change.
            JobName::LoadReadMarks => self.marks_loading = false,
            JobName::LoadGroups => self.groups_load_failed(plain.technical),
            JobName::MarkGroupRead => self.group_mark_failed(),
            JobName::GroupSend => self.group_send_failed(),
            JobName::GroupChange => self.group_change_failed(),
            JobName::MarkNotice
            | JobName::SaveSettings
            | JobName::SaveReadMarks
            | JobName::SaveLearnedDial
            | JobName::Send
            | JobName::Retry
            | JobName::Cancel
            | JobName::NodeProbe => {}
        }
    }

    // ── Sending ─────────────────────────────────────────────────────────────

    /// Sends `body` to the friend `peer` as a new message: it shows at once,
    /// at the bottom of their conversation, and its job goes to the send
    /// worker behind any before it. The ids of the friend's rows of yours
    /// now are its snapshot: none of them is its own. Nothing while sending
    /// to them is paused (P6.31): a toast says how to resume.
    fn start_send(&mut self, peer: &str, body: String) {
        if self.paused(peer) {
            let name = self.shown_name(peer);
            self.push_toast(&format!(
                "You paused sending to {name}. To send, resume it: P on the friend list."
            ));
            return;
        }
        let key = convo_key(peer);
        let snapshot = self
            .rows(&key)
            .iter()
            .filter(|row| row.view.outgoing)
            .map(|row| row.view.id.to_ascii_lowercase())
            .collect();
        let local_id = self.next_send;
        self.next_send += 1;
        self.pending.push(PendingSend::new(
            local_id,
            &key,
            body.clone(),
            snapshot,
            self.now,
            self.now_ms,
        ));
        self.send_queue.push_back(Some(local_id));
        self.scroll = 0;
        if self.chosen.is_some() {
            self.chosen = Some(0);
        }
        self.ticks_stale = true;
        self.dirty = true;
        self.job(Cmd::Send(SendJob::Send {
            local_id,
            pub_hex: key,
            text: body,
        }));
    }

    /// A send's answer, in errors.rs's words. One that waits or was sent has
    /// the poller list that friend's outbox soon (twice); an address it
    /// learned is saved for the friend.
    fn send_ended(&mut self, local_id: u64, outcome: SendOutcome) {
        let Some(peer) = self
            .pending
            .iter()
            .find(|send| send.local_id == local_id)
            .map(|send| send.peer.clone())
        else {
            return;
        };
        if matches!(&outcome.result, SendResult::NodeUnavailable(why) if is_locked_text(why)) {
            // `raven lock` locked it meanwhile: NET's S asks first now.
            self.cli_locked = true;
        }
        let read = Outcome::of(&outcome.result, &self.shown_name(&peer));
        if matches!(read, Outcome::Waiting { .. } | Outcome::Sent(_)) {
            self.cmds
                .push(Cmd::Poll(PollCtl::Burst { peer: peer.clone() }));
        }
        if let Some(send) = self
            .pending
            .iter_mut()
            .find(|send| send.local_id == local_id)
        {
            send.outcome = Some(read);
            send.captured = outcome.captured;
            if let SendResult::Delivered(route) = outcome.result {
                send.route = Some(route);
            }
        }
        if let Some(dial) = outcome.learned_dial_used {
            self.job(Cmd::Store(StoreJob::SaveLearnedDial {
                pub_hex: peer,
                dial,
            }));
        }
        // A send may have set up a new secure connection with them.
        if self.horizons_on {
            self.load_horizons();
        }
        self.dirty = true;
    }

    /// R on a waiting message, answered.
    fn retry_ended(&mut self, peer: &str, result: Result<(), String>) {
        match result {
            Ok(()) => {
                self.push_toast(RETRYING_TOAST);
                self.cmds.push(Cmd::Poll(PollCtl::Burst {
                    peer: peer.to_owned(),
                }));
            }
            Err(why) if why.contains(EXT_NOT_WAITING) => self.push_toast(NOT_WAITING_TOAST),
            Err(why) if why.contains(EXT_NO_OUTBOX) => self.push_toast(NOT_RETRIED_TOAST),
            Err(_) => self.push_toast(RETRY_FAILED_TOAST),
        }
    }

    /// C on a waiting message, confirmed and answered. A cancel that says
    /// the friend may have it anyway makes it written once.
    fn cancel_ended(&mut self, mid: &str, peer: &str, result: Result<(), String>, captured: &str) {
        match result {
            Ok(()) if captured.contains(EXT_DELIVERED_FIRST) => {
                self.push_toast(DELIVERED_FIRST_TOAST);
            }
            Ok(()) => {
                if captured.contains(delivery::MAY_HAVE_IT) {
                    self.written.insert(mid.to_ascii_lowercase());
                }
                self.push_toast(STOPPED_TOAST);
            }
            Err(why) if why.contains(EXT_NOT_WAITING) => self.push_toast(NOT_WAITING_TOAST),
            Err(_) => self.push_toast(STOP_FAILED_TOAST),
        }
        self.cmds.push(Cmd::Poll(PollCtl::Burst {
            peer: peer.to_owned(),
        }));
    }

    /// raven-node's outbox as just listed: every friend's (`peer` None), or
    /// one friend's. What it shows written once is kept.
    fn merge_outbox(&mut self, peer: Option<&str>, items: Vec<OutboxItem>) {
        let before = self.outbox.clone();
        match peer {
            None => self.outbox.clear(),
            Some(peer) => self
                .outbox
                .retain(|_, item| !item.peer_pub_hex.eq_ignore_ascii_case(peer)),
        }
        for item in items
            .into_iter()
            .filter(|item| matches!(item.kind.as_str(), "message" | ""))
        {
            let mid = item.message_id_hex.to_ascii_lowercase();
            if delivery::outbox_wrote(&item) {
                self.written.insert(mid.clone());
            }
            let tried_again = before
                .get(&mid)
                .is_some_and(|was| item.attempts > was.attempts);
            if tried_again {
                self.tried_again(&item);
            }
            self.outbox.insert(mid, item);
        }
        if self.outbox != before {
            self.dirty = true;
        }
    }

    /// raven-node tried a message of yours again (its outbox lists more
    /// attempts than before): while it still waits, the friend's mark rings
    /// and the ticker says so (UXF.10). One delivered or ended is the
    /// tick's news, not this.
    fn tried_again(&mut self, item: &OutboxItem) {
        let key = convo_key(&item.peer_pub_hex);
        if !matches!(item.state.as_str(), "queued" | "held" | "sent" | "waiting")
            || self.friend(&key).is_none()
        {
            return;
        }
        self.live.rings.insert(key.clone(), self.now);
        let event = Event::TriedAgain {
            peer: key,
            unreachable: item.last_error_code == "NOT_REACHABLE",
            until_ms: item.expires_at_ms,
        };
        self.live.event = Some((event, self.now));
    }

    /// Binds this session's sends to their history rows, then works out
    /// every message's tick again: one that changed since the last time is
    /// marked with now (its draw-in or blink starts), one seen for the first
    /// time is not. The meeting toasts follow the waiting ones.
    fn refresh_ticks(&mut self) {
        for (local_id, mid) in delivery::bind(&mut self.pending, &self.convo) {
            if let Some(seen) = self.tick_seen.remove(&BubbleKey::Local(local_id)) {
                self.tick_seen.entry(BubbleKey::Mid(mid)).or_insert(seen);
            }
            self.expanded.remove(&BubbleKey::Local(local_id));
        }
        let mut peers: Vec<&str> = self.convo.keys().map(String::as_str).collect();
        peers.extend(self.pending.iter().map(|send| send.peer.as_str()));
        peers.sort_unstable();
        peers.dedup();
        let mut seen = HashMap::new();
        let mut events = Vec::new();
        // Each friend's messages by id, for the meeting toasts.
        let mut ticks: HashMap<String, HashMap<String, Tick>> = HashMap::new();
        for peer in peers {
            for bubble in self.bubbles(peer) {
                let Some(view) = self.tick_view(bubble) else {
                    continue;
                };
                if let Some(mid) = view.mid {
                    ticks
                        .entry(peer.to_owned())
                        .or_default()
                        .insert(mid.to_ascii_lowercase(), view.tick.clone());
                }
                let key = bubble.key();
                let class = mem::discriminant(&view.tick);
                let since = match self.tick_seen.get(&key) {
                    Some((before, since)) if *before == class => *since,
                    Some(_) => {
                        events.push(self.tick_news(peer, &view));
                        Some(self.now)
                    }
                    None => None,
                };
                seen.insert(key, (class, since));
            }
        }
        if seen != self.tick_seen {
            self.tick_seen = seen;
            self.dirty = true;
        }
        for (event, route) in events.into_iter().flatten() {
            if let Some(route) = route {
                self.live.routes.insert(event.peer().to_owned(), route);
            }
            self.live.event = Some((event, self.now));
        }
        self.follow_waiting(&ticks);
    }

    /// What a message of yours coming to `view`'s tick just now tells the
    /// ticker (UXF.10), with how it went when that is known: delivered (the
    /// receipt came: its own send's route and time, else the outbox's
    /// carrier and path), or written and not confirmed yet.
    fn tick_news(&self, peer: &str, view: &TickView) -> Option<(Event, Option<live::Route>)> {
        let peer = peer.to_owned();
        match view.tick {
            Tick::Delivered => {
                let inline = view.pending.and_then(|send| {
                    send.route
                        .clone()
                        .map(|route| (route, self.now.saturating_duration_since(send.sent_at)))
                });
                let (route, took) = match inline {
                    Some((route, took)) => (Some(route), Some(took)),
                    None => (
                        view.outbox.and_then(|item| {
                            Some(live::Route {
                                carrier: live::Carrier::of_label(&item.carrier)?,
                                dial: None,
                                path: item.path.clone(),
                            })
                        }),
                        None,
                    ),
                };
                let event = Event::Delivered {
                    peer,
                    route: route.clone(),
                    took,
                };
                Some((event, route))
            }
            Tick::Sent => Some((Event::Sent { peer }, None)),
            _ => None,
        }
    }

    /// R on a message of yours: raven-node tries it now, or the same text
    /// goes again as a new message, as its state allows. True when it did.
    fn press_r(&mut self, peer: &str, key: &BubbleKey) -> bool {
        let Some((actions, mid, body)) = self.facts(peer, key) else {
            return false;
        };
        match mid {
            Some(mid) if actions.try_now => {
                self.queue_send_job(SendJob::Retry {
                    mid,
                    peer: peer.to_owned(),
                });
                true
            }
            _ if actions.send_again => {
                // A send of this session that wrote nothing goes: the new one
                // takes its place.
                if let BubbleKey::Local(local_id) = key {
                    self.pending.retain(|send| send.local_id != *local_id);
                    self.tick_seen.remove(key);
                }
                self.start_send(peer, body);
                true
            }
            _ => false,
        }
    }

    /// C on a message of yours: the question before raven-node stops trying
    /// it, when it is waiting or held.
    fn ask_stop(&mut self, peer: &str, key: &BubbleKey) {
        if let Some((actions, Some(mid), _)) = self.facts(peer, key) {
            if actions.stop {
                self.open_overlay(Overlay::Confirm(ConfirmState {
                    peer: peer.to_owned(),
                    action: ConfirmAction::StopTrying { mid },
                }));
            }
        }
    }

    /// S in MSG: the warning before a message that may have arrived goes
    /// again.
    fn ask_send_again(&mut self, peer: &str, key: &BubbleKey) {
        if let Some((actions, _, body)) = self.facts(peer, key) {
            if actions.send_again_anyway {
                self.open_overlay(Overlay::Confirm(ConfirmState {
                    peer: peer.to_owned(),
                    action: ConfirmAction::SendAgain { body },
                }));
            }
        }
    }

    /// What may be done to message `key` of the conversation with `peer`, its
    /// id and its text.
    fn facts(&self, peer: &str, key: &BubbleKey) -> Option<(Actions, Option<String>, String)> {
        let bubble = self.find_bubble(peer, key)?;
        let view = self.tick_view(bubble)?;
        Some((
            view.actions,
            view.mid.map(str::to_ascii_lowercase),
            bubble.body().to_owned(),
        ))
    }

    /// A retry or a cancel for the send worker, behind the jobs before it.
    fn queue_send_job(&mut self, job: SendJob) {
        self.send_queue.push_back(None);
        self.job(Cmd::Send(job));
    }

    /// Asks for a start by itself (OD-3), once the vault check has answered.
    fn request_auto_start(&mut self, trigger: AutoStart) {
        self.auto_pending.get_or_insert(trigger);
        self.try_auto_start();
    }

    fn try_auto_start(&mut self) {
        if self.vault_checked {
            if let Some(trigger) = self.auto_pending.take() {
                self.auto_start(trigger);
            }
        }
    }

    /// Starts the background program by itself, only when everything OD-3
    /// asks holds: the identity exists; receiving is on (the receive question
    /// comes first while it was never answered); a vault profile has its
    /// passphrase file (else PASSFILE, once); Raven knows its own program's
    /// path (else ext.rs would look raven-node up on PATH); and none runs or
    /// is being started. Never while LOCK is stopping it, nor once ERASE's
    /// erase began.
    fn auto_start(&mut self, trigger: AutoStart) {
        if self.identity != IdentityStatus::Ready || self.locking() || self.erasing() {
            return;
        }
        // `raven lock`'s lock is on: the start waits for UNLOCK's Enter.
        if self.cli_locked {
            self.after_unlock.get_or_insert(AfterUnlock::Auto(trigger));
            return;
        }
        // RX waits for the background program's first word: one of this
        // folder that receives already answers it (E1).
        if self.settings.receive == Receive::Unset {
            if self.node.state == NodeState::Unknown
                || (self.node.receiving() && !self.folder_known())
            {
                self.auto_pending.get_or_insert(trigger);
                return;
            }
            self.adopt_receiving();
        }
        match self.settings.receive {
            Receive::Unset => {
                if !self
                    .overlays
                    .iter()
                    .any(|o| matches!(o, Overlay::Receive(_)))
                {
                    self.open_overlay(Overlay::Receive(RxState { trigger, yes: true }));
                }
                return;
            }
            Receive::Off => return,
            Receive::On => {}
        }
        if self.node.state == NodeState::NeedsPassphraseFile {
            self.show_passfile_once();
            return;
        }
        let starting = matches!(self.node.state, NodeState::Starting { .. });
        if !self.node.program.exe_known || starting || self.node.running() {
            return;
        }
        self.node.state = NodeState::Starting { since: self.now };
        self.dirty = true;
        self.job(Cmd::Node(NodeJob::Ensure));
    }

    /// Add a friend opened (AF-1, or [A] on WZ-6): the friend will need this
    /// computer's address, so the background program starts.
    fn add_friend_opened(&mut self) {
        self.request_auto_start(AutoStart::AddFriend);
    }

    fn show_passfile_once(&mut self) {
        if !self.passfile_shown {
            self.passfile_shown = true;
            self.open_overlay(Overlay::PassFile);
        }
    }

    fn save_settings(&mut self) {
        if self.identity == IdentityStatus::Ready {
            self.job(Cmd::Store(StoreJob::SaveSettings(self.settings.clone())));
        }
    }

    /// The answer to RX (Y, N, or Enter on the highlighted one). Yes: receive
    /// on, saved, and the start it was asked for. No: receive off, saved,
    /// and a node started from now on listens on this computer only.
    fn answer_receive(&mut self, trigger: AutoStart, yes: bool) {
        self.close_overlay();
        if yes {
            self.settings.receive = Receive::On;
            self.save_settings();
            self.auto_start(trigger);
        } else {
            // Before the save, so the save waits behind it too.
            self.receive_off();
            self.save_settings();
        }
    }

    /// Receiving was never answered, and this folder's background program
    /// receives already (started by a login item, a script or another
    /// Raven app): that is the answer, saved, and RX closes if it is open.
    /// Not for a Windows program another Raven folder runs.
    fn adopt_receiving(&mut self) -> bool {
        let adopt = self.settings.receive == Receive::Unset
            && self.identity == IdentityStatus::Ready
            && self.node.receiving()
            && self.folder_known()
            && !matches!(self.node.folder(), Some(NodeFolder::Other(_)));
        if adopt {
            self.settings.receive = Receive::On;
            self.save_settings();
            if let Some(at) = self
                .overlays
                .iter()
                .position(|o| matches!(o, Overlay::Receive(_)))
            {
                self.overlays.remove(at);
            }
            self.dirty = true;
        }
        adopt
    }

    /// Whose folder the running background program serves is read, or
    /// needs no read: on Unix its endpoint is this profile's own; on Windows
    /// the poller reads its command line ([`NodeFolder`]).
    fn folder_known(&self) -> bool {
        !self.windows || !self.node.running() || self.node.folder().is_some()
    }

    /// No to the receive question (RX or WZ-3): receiving off, and a node
    /// started from now on listens on this computer only, unless the user
    /// chose its address.
    fn receive_off(&mut self) {
        self.settings.receive = Receive::Off;
        if self.listen == ListenOverride::None {
            self.loopback_wanted = true;
        }
        self.push_toast(RECEIVE_OFF_TOAST);
    }

    // ── The first run ───────────────────────────────────────────────────────

    fn set_screen(&mut self, screen: Screen) {
        self.screen = screen;
        self.dirty = true;
    }

    fn set_step(&mut self, step: WizardStep) {
        self.set_screen(Screen::Wizard(step));
    }

    /// WZ-4 begins with the vault check: its answer decides where the
    /// identity is made.
    fn create_identity(&mut self) {
        self.set_step(WizardStep::Creating(Creating::Working { since: self.now }));
        self.job(Cmd::Store(StoreJob::CheckVault));
    }

    /// The vault check answered: a vault profile's identity is made on the
    /// plain terminal, where the vault asks for the new passphrase; any
    /// other by the store worker, behind the spinner.
    fn vault_checked_for_create(&mut self, prompts: bool) {
        if !self.finishing_setup() {
            return;
        }
        self.job(if prompts {
            Cmd::Suspend(SuspendJob::CreateIdentity)
        } else {
            Cmd::Store(StoreJob::CreateIdentity)
        });
    }

    /// The identity exists. Now the name and the receive answer are saved,
    /// and the first jobs go out as for a profile that had one: the poller,
    /// the friends and the background program's state. WZ-5 shows the words.
    fn identity_created(&mut self, new: NewIdentity) {
        self.identity = IdentityStatus::Ready;
        self.me = Some(new.me);
        if new.prekey_warning.is_some() {
            self.push_toast(PREKEY_TOAST);
        }
        self.set_step(WizardStep::Words { since: self.now });
        self.save_settings();
        self.begin_ready();
    }

    /// Making the identity failed. A refusal over the files already in the
    /// profile is ERR-ID, which never offers to make one over them; anything
    /// else stays on WZ-4, with [R].
    fn create_failed(&mut self, why: &str, captured: &str) {
        let (problem, mut plain) = errors::explain_identity(why);
        if !captured.trim().is_empty() {
            plain.technical.push('\n');
            plain.technical.push_str(captured.trim_end());
        }
        let failure = Failure::new(plain, self.settings.show_details);
        self.set_screen(if problem == IdentityProblem::Continuity {
            Screen::IdentityError(failure)
        } else {
            Screen::Wizard(WizardStep::Creating(Creating::Failed(failure)))
        });
    }

    /// Enter, not right after a paste: it answers or goes on.
    fn confirms(&self, key: KeyEvent) -> bool {
        key.code == KeyCode::Enter && !has_ctrl_or_alt(key) && !self.just_pasted()
    }

    /// The wizard's keys, step by step; Ctrl+C opens QUIT on each.
    fn on_wizard_key(&mut self, key: KeyEvent, step: WizardStep) -> Vec<Cmd> {
        if is_ctrl(key, 'c') {
            self.open_overlay(Overlay::Quit);
            return Vec::new();
        }
        match step {
            WizardStep::Welcome { .. } => return self.on_welcome_key(key),
            WizardStep::Name => self.on_name_key(key),
            WizardStep::Receive { yes } => self.on_wizard_receive_key(key, yes),
            // Only Ctrl+C while the identity is made.
            WizardStep::Creating(Creating::Working { .. }) => {}
            WizardStep::Creating(Creating::Failed(_)) => return self.on_create_failed_key(key),
            // No way back: the identity exists.
            WizardStep::Words { .. } => {
                if self.confirms(key) {
                    self.set_step(WizardStep::Ready);
                }
            }
            // [A] goes to Add a friend (AF-1), which starts the background
            // program (OD-3); Esc there goes on to Home.
            WizardStep::Ready => match plain_char(key) {
                Some('a' | 'A') => self.open_add_friend(),
                _ if self.confirms(key) => self.set_screen(Screen::Home),
                _ => {}
            },
        }
        Vec::new()
    }

    /// WZ-1: Enter starts, C opens the classic menu, Q or Esc quits at once
    /// (nothing runs yet that QUIT would explain), ? opens HELP.
    fn on_welcome_key(&mut self, key: KeyEvent) -> Vec<Cmd> {
        match (key.code, plain_char(key)) {
            (_, Some('c' | 'C')) => return self.switch_to_classic(),
            (KeyCode::Esc, _) | (_, Some('q' | 'Q')) => return vec![Cmd::Exit(self.quit_plan())],
            (_, Some('?')) => self.open_overlay(Overlay::Help { scroll: 0 }),
            _ if self.confirms(key) => self.set_step(WizardStep::Name),
            _ => {}
        }
        Vec::new()
    }

    /// WZ-2: every letter is text (no shortcut), Backspace edits, Enter goes
    /// on with the name (trimmed; empty is fine), Esc goes back keeping it.
    fn on_name_key(&mut self, key: KeyEvent) {
        match (key.code, plain_char(key)) {
            (KeyCode::Esc, _) => self.set_step(WizardStep::Welcome { since: None }),
            (KeyCode::Backspace, _) if !has_ctrl_or_alt(key) => {
                if self.name.pop().is_some() || self.name_full {
                    self.name_full = false;
                    self.dirty = true;
                }
            }
            (_, Some(c)) => self.type_name(c.encode_utf8(&mut [0; 4])),
            _ if self.confirms(key) => {
                self.settings.display_name = self.name.trim().to_owned();
                self.set_step(WizardStep::Receive { yes: true });
            }
            _ => {}
        }
    }

    /// Adds `text` to WZ-2's field as one line without control characters,
    /// until the name fills [`NAME_CELLS`] cells: the rest is dropped, and
    /// the field says why.
    fn type_name(&mut self, text: &str) {
        for c in display::field_input(text, false).chars() {
            self.name.push(c);
            if display::width(&self.name) > NAME_CELLS {
                self.name.pop();
                self.name_full = true;
                break;
            }
        }
        self.dirty = true;
    }

    /// WZ-3: Y or N answers, Enter gives the highlighted answer (not right
    /// after a paste), the arrows and Tab move the highlight, Esc goes back.
    fn on_wizard_receive_key(&mut self, key: KeyEvent, yes: bool) {
        match (key.code, plain_char(key)) {
            (_, Some('y' | 'Y')) => self.answer_wizard_receive(true),
            (_, Some('n' | 'N')) => self.answer_wizard_receive(false),
            (KeyCode::Esc, _) => self.set_step(WizardStep::Name),
            (
                KeyCode::Up
                | KeyCode::Down
                | KeyCode::Left
                | KeyCode::Right
                | KeyCode::Tab
                | KeyCode::BackTab,
                _,
            ) => self.set_step(WizardStep::Receive { yes: !yes }),
            _ if self.confirms(key) => self.answer_wizard_receive(yes),
            _ => {}
        }
    }

    /// WZ-3's answer, kept in the App until the identity exists (no save
    /// before). Then WZ-4.
    fn answer_wizard_receive(&mut self, yes: bool) {
        if yes {
            self.settings.receive = Receive::On;
        } else {
            self.receive_off();
        }
        self.create_identity();
    }

    /// WZ-4 after a failure: R tries again, D shows or hides the technical
    /// text, Q quits.
    fn on_create_failed_key(&mut self, key: KeyEvent) -> Vec<Cmd> {
        match plain_char(key) {
            Some('r' | 'R') => self.create_identity(),
            Some('d' | 'D') => self.toggle_details(),
            Some('q' | 'Q') => return vec![Cmd::Exit(self.quit_plan())],
            _ => {}
        }
        Vec::new()
    }

    /// ERR-ID: D shows or hides the technical text, C opens the classic
    /// menu, Q or Esc quits; Ctrl+C opens QUIT.
    fn on_identity_error_key(&mut self, key: KeyEvent) -> Vec<Cmd> {
        if is_ctrl(key, 'c') {
            self.open_overlay(Overlay::Quit);
            return Vec::new();
        }
        match (key.code, plain_char(key)) {
            (_, Some('d' | 'D')) => self.toggle_details(),
            (_, Some('c' | 'C')) => return self.switch_to_classic(),
            (KeyCode::Esc, _) | (_, Some('q' | 'Q')) => return vec![Cmd::Exit(self.quit_plan())],
            _ => {}
        }
        Vec::new()
    }

    /// [D] on ERR-ID and on a failed WZ-4.
    fn toggle_details(&mut self) {
        if let Screen::IdentityError(failure)
        | Screen::Wizard(WizardStep::Creating(Creating::Failed(failure))) = &mut self.screen
        {
            failure.details = !failure.details;
            self.dirty = true;
        }
    }

    /// A Keychain wait seen on stderr or in the service log: KC opens, unless
    /// it shows this wait already (or was hidden from it). Only a running
    /// job can be waiting.
    fn keychain_waiting(&mut self, wait: KeychainWait) {
        if self.jobs_in_flight.idle() || self.keychain.is_some_and(|kc| kc.wait == wait) {
            return;
        }
        self.keychain = Some(KeychainView {
            wait,
            since: self.now,
        });
        if !self.overlays.contains(&Overlay::Keychain) {
            self.overlays.push(Overlay::Keychain);
        }
        self.dirty = true;
    }

    fn end_keychain_wait(&mut self) {
        self.keychain = None;
        self.overlays
            .retain(|overlay| *overlay != Overlay::Keychain);
        self.dirty = true;
    }

    /// Enter came this soon after a paste: part of it.
    fn just_pasted(&self) -> bool {
        self.last_paste
            .is_some_and(|at| self.now.saturating_duration_since(at) < PASTE_GUARD)
    }

    fn on_key(&mut self, key: KeyEvent) -> Vec<Cmd> {
        // COPY: any key at all brings the screen back, before anything else
        // sees it (the screen it would act on is not there).
        if self.peeking {
            self.peeking = false;
            self.dirty = true;
            return vec![Cmd::Unpeek];
        }
        // A letter or digit key typed with a Persian layout on is the
        // shortcut on that key, unless a field takes it as text (UXF.4).
        let key = if self.field_takes_text() {
            key
        } else {
            keys_fa::shortcut(key)
        };
        if is_ctrl(key, 'l') {
            self.dirty = true;
            return vec![Cmd::Redraw];
        }
        if is_ctrl(key, 'z') {
            self.push_toast(PAUSE_TOAST);
            return Vec::new();
        }
        // SMALL covers everything, overlays too: it takes the keys (none
        // once ERASE's erase began: the app ends with its result).
        if self.too_small() {
            if self.erasing() {
                return Vec::new();
            }
            return self.on_small_key(key);
        }
        match self.overlays.last() {
            Some(Overlay::Quit) => return self.on_quit_key(key),
            Some(Overlay::Help { .. }) => self.on_help_key(key),
            Some(Overlay::Receive(rx)) => {
                let rx = *rx;
                self.on_receive_key(key, rx);
            }
            Some(Overlay::Unlock) => self.on_unlock_key(key),
            Some(Overlay::Keychain | Overlay::PassFile) => self.on_note_key(key),
            Some(Overlay::Firewall | Overlay::NetworkNote) => self.on_firewall_key(key),
            Some(Overlay::Message(view)) => {
                let view = view.clone();
                self.on_message_key(key, &view);
            }
            Some(Overlay::Confirm(confirm)) => {
                let confirm = confirm.clone();
                self.on_confirm_key(key, confirm);
            }
            Some(Overlay::Lock(step)) => {
                let step = step.clone();
                self.on_lock_key(key, &step);
            }
            Some(Overlay::KeepChats { choice }) => {
                let choice = *choice;
                self.on_keep_key(key, choice);
            }
            Some(Overlay::DeleteChat { peer, typed }) => {
                let (peer, typed) = (peer.clone(), typed.clone());
                self.on_delete_chat_key(key, &peer, &typed);
            }
            Some(Overlay::ForgetAddress { peer }) => {
                let peer = peer.clone();
                self.on_forget_key(key, &peer);
            }
            Some(Overlay::PrivacyNotice(notice)) => {
                let notice = *notice;
                self.on_notice_key(key, notice);
            }
            Some(Overlay::Erase(erase)) => {
                let erase = erase.clone();
                self.on_erase_key(key, &erase);
            }
            Some(Overlay::Security(sec)) => {
                let sec = *sec;
                self.on_security_key(key, sec);
            }
            Some(Overlay::Locked(_)) => self.on_locked_key(key),
            Some(Overlay::Passphrase(_)) => self.on_passphrase_key(key),
            Some(Overlay::Updates(upd)) => {
                let upd = upd.clone();
                self.on_updates_key(key, &upd);
            }
            Some(Overlay::Group(group)) => {
                let group = group.clone();
                self.on_group_overlay_key(key, group);
            }
            None => match &self.screen {
                Screen::Home => self.on_home_key(key),
                Screen::Wizard(step) => {
                    let step = step.clone();
                    return self.on_wizard_key(key, step);
                }
                Screen::IdentityError(_) => return self.on_identity_error_key(key),
                Screen::AddFriend(_) => self.on_add_friend_key(key),
                Screen::NameClash(_) => self.on_clash_key(key),
                Screen::Verify(_) => self.on_verify_key(key),
                Screen::Added(_) => self.on_added_key(key),
                Screen::FriendPage(_) => self.on_page_key(key),
                Screen::Network(_) => self.on_network_key(key),
                Screen::Meet(_) => self.on_meet_key(key),
                Screen::Settings(_) => return self.on_settings_key(key),
            },
        }
        Vec::new()
    }

    /// A field has the keys: what is typed goes into it as text. WZ-2's
    /// name, the composer, AF-1's paste box until it parses (and the rest of
    /// a paste in either box), [U]'s code, AF-2's name, VF's codes, CI's
    /// open field, SET's name and MEET's address on step 3. SMALL or an
    /// overlay over it has the keys itself, and takes no text.
    fn field_takes_text(&self) -> bool {
        // LOCKED's and PASS's passphrase fields (P6.40).
        if matches!(
            self.overlays.last(),
            Some(Overlay::Locked(_) | Overlay::Passphrase(_))
        ) && !self.too_small()
        {
            return true;
        }
        // NEW GROUP's name field (groups, lab).
        if matches!(self.overlays.last(), Some(Overlay::Group(group)) if group.takes_text())
            && !self.too_small()
        {
            return true;
        }
        if !self.overlays.is_empty() || self.too_small() {
            return false;
        }
        match &self.screen {
            Screen::Wizard(step) => matches!(step, WizardStep::Name),
            // A group that takes no messages from here has no composer.
            Screen::Home => {
                self.focus == Focus::Composer
                    && (self.open_group().is_none() || self.group_takes_text())
            }
            Screen::AddFriend(add) => {
                let paste_box = add.focus == AddFocus::Paste;
                add.naming
                    || match add.update {
                        Some(_) => paste_box,
                        None => {
                            add.follows_input(self.now) || (paste_box && add.friend().is_none())
                        }
                    }
            }
            Screen::Verify(vf) => matches!(
                vf.step,
                VerifyStep::Comparing(_)
                    | VerifyStep::Matched { .. }
                    | VerifyStep::Later(_)
                    | VerifyStep::OlderMethod { .. }
            ),
            Screen::FriendPage(page) => page.edit.is_some(),
            Screen::Settings(set) => set.name.is_some(),
            Screen::Meet(_) => self.meet_field_open(),
            Screen::IdentityError(_)
            | Screen::NameClash(_)
            | Screen::Added(_)
            | Screen::Network(_) => false,
        }
    }

    /// RX: Y or N answers, Enter gives the highlighted answer (not right
    /// after a paste), the arrows and Tab move the highlight, Esc answers
    /// Not now.
    fn on_receive_key(&mut self, key: KeyEvent, rx: RxState) {
        if is_ctrl(key, 'c') {
            self.open_overlay(Overlay::Quit);
            return;
        }
        match (key.code, plain_char(key)) {
            (_, Some('y' | 'Y')) => self.answer_receive(rx.trigger, true),
            (_, Some('n' | 'N')) => self.answer_receive(rx.trigger, false),
            (KeyCode::Enter, _) if !has_ctrl_or_alt(key) && !self.just_pasted() => {
                self.answer_receive(rx.trigger, rx.yes);
            }
            // Esc is Not now, kept like N (E1: asked again at every start).
            (KeyCode::Esc, _) => self.answer_receive(rx.trigger, false),
            (
                KeyCode::Up
                | KeyCode::Down
                | KeyCode::Left
                | KeyCode::Right
                | KeyCode::Tab
                | KeyCode::BackTab,
                _,
            ) => {
                if let Some(Overlay::Receive(open)) = self.overlays.last_mut() {
                    open.yes = !open.yes;
                    self.dirty = true;
                }
            }
            _ => {}
        }
    }

    /// UNLOCK (review E-harness-docs-ci-3): Enter (not right after a paste)
    /// clears `raven lock`'s lock, and the start it held follows once it is
    /// gone ([`App::unlock_ended`]); Esc keeps Raven stopped for this
    /// session, and a toast says how to start it later. Ctrl+C opens QUIT
    /// over it.
    fn on_unlock_key(&mut self, key: KeyEvent) {
        if is_ctrl(key, 'c') {
            self.open_overlay(Overlay::Quit);
        } else if self.confirms(key) {
            self.close_overlay();
            self.job(Cmd::Node(NodeJob::Unlock));
        } else if key.code == KeyCode::Esc {
            self.close_overlay();
            self.after_unlock = None;
            self.push_toast(UNLOCK_KEPT_TOAST);
        }
    }

    /// UNLOCK's job answered: once the lock is gone, the start it held (by
    /// itself, or NET's S) goes ahead, and the privacy read is asked again
    /// (it says whether Raven's login item stays off). Otherwise the lock
    /// stays, and a toast says how to clear it.
    fn unlock_ended(&mut self, result: Result<(), String>) {
        match result {
            Ok(()) => {
                self.cli_locked = false;
                self.load_privacy();
                match self.after_unlock.take() {
                    Some(AfterUnlock::Auto(trigger)) => self.request_auto_start(trigger),
                    Some(AfterUnlock::Net) => self.start_from_net(),
                    None => {}
                }
            }
            Err(_) => {
                self.after_unlock = None;
                self.push_toast(UNLOCK_FAILED_TOAST);
            }
        }
        self.dirty = true;
    }

    /// `raven lock`'s lock is still on (review E-harness-docs-ci-3).
    #[cfg(test)]
    pub(super) fn cli_locked(&self) -> bool {
        self.cli_locked
    }

    /// KC and PASSFILE: Esc closes (KC hides: Raven keeps waiting, and the
    /// chip still says so); Ctrl+C opens QUIT over them.
    fn on_note_key(&mut self, key: KeyEvent) {
        if is_ctrl(key, 'c') {
            self.open_overlay(Overlay::Quit);
        } else if key.code == KeyCode::Esc {
            self.close_overlay();
        }
    }

    /// FW and NOTE: Enter (not right after a paste) or Esc closes it; Ctrl+C
    /// opens QUIT over it.
    fn on_firewall_key(&mut self, key: KeyEvent) {
        if is_ctrl(key, 'c') {
            self.open_overlay(Overlay::Quit);
        } else if key.code == KeyCode::Esc || self.confirms(key) {
            self.close_overlay();
        }
    }

    /// SMALL: C for the classic menu, Q to quit. Its own copy says so, and
    /// nothing else fits in the window.
    fn on_small_key(&mut self, key: KeyEvent) -> Vec<Cmd> {
        match plain_char(key) {
            Some('c' | 'C') => self.switch_to_classic(),
            Some('q' | 'Q') => vec![Cmd::Exit(self.quit_plan())],
            _ => Vec::new(),
        }
    }

    /// Quitting: a background program that keeps running is named after
    /// the screen has gone.
    fn quit_plan(&self) -> ExitPlan {
        self.with_exit_note(ExitPlan::quit(self.node.running_pid()))
    }

    /// `plan` for a quit the user chose, with the laptop note under its line
    /// the first time they quit with receiving on (UXF.9), and the settings
    /// that remember it, saved on the way out. Before the identity exists
    /// nothing can be saved, so nothing is said.
    fn with_exit_note(&self, mut plan: ExitPlan) -> ExitPlan {
        if self.identity != IdentityStatus::Ready
            || self.settings.receive != Receive::On
            || self.settings.exit_note_shown
        {
            return plan;
        }
        plan.line = Some(match plan.line.take() {
            Some(line) => format!("{line}\n{EXIT_NOTE}"),
            None => EXIT_NOTE.to_owned(),
        });
        plan.save = Some(TuiState {
            exit_note_shown: true,
            ..self.settings.clone()
        });
        plan
    }

    /// What QUIT says and offers now: a wait while the identity or a change
    /// to the friends is saved, or while a chosen quit waits for a send or a
    /// stop; otherwise the question, by the background program's state and
    /// 'When I quit'. While the background program runs and messages it keeps
    /// trying haven't gone, a warning comes before the question (UXF.8).
    pub(super) fn quit_view(&self) -> QuitView {
        match self.quitting {
            Some(Quitting::Stopping { since }) => return QuitView::Stopping { since },
            Some(Quitting::AfterSends { since, .. }) if self.jobs_in_flight.send > 0 => {
                return QuitView::Sending { since };
            }
            _ => {}
        }
        if self.finishing_setup() {
            return QuitView::SettingUp;
        }
        if self.jobs_in_flight.critical > 0 {
            return QuitView::Saving;
        }
        if self.identity != IdentityStatus::Ready || self.node.state == NodeState::Unknown {
            return QuitView::Plain;
        }
        let starting = matches!(self.node.state, NodeState::Starting { .. });
        if !self.node.running() && !starting {
            return QuitView::NotRunning;
        }
        let can_stop = self.net_keys().stop;
        let started_here = self.node.started_by_app.is_some()
            && self.node.started_by_app == self.node.running_pid();
        let enter = match self.settings.on_quit {
            OnQuit::Ask if can_stop => None,
            OnQuit::StopIfStarted if can_stop && started_here => Some(QuitChoice::Stop),
            _ => Some(QuitChoice::Keep),
        };
        let question = RunningQuit {
            managed: self.node.managed.is_some(),
            can_stop,
            enter,
        };
        match self.waiting_quit(question) {
            Some(waiting) if !self.quit_anyway => QuitView::Waiting(waiting),
            _ => QuitView::Running(question),
        }
    }

    /// QUIT's warning (UXF.8), while raven-node runs and lists messages to
    /// saved friends as waiting (`queued`, or parked until their deadline:
    /// `waiting`) that nothing else known of them says left this computer,
    /// ended, or wait for a send rather than for raven-node. It names the
    /// friend whose waiting message runs out first (one with no known time
    /// comes after; then the list's order).
    fn waiting_quit(&self, question: RunningQuit) -> Option<WaitingQuit> {
        if !self.node.running() {
            return None;
        }
        // Per friend, by place in the list: how many, and the first expiry.
        let mut waiting: Vec<(usize, usize, Option<u64>)> = Vec::new();
        for item in self.outbox.values().filter(|item| waits_for_the_node(item)) {
            let Some(at) = self
                .contacts
                .iter()
                .position(|c| c.pub_hex.eq_ignore_ascii_case(&item.peer_pub_hex))
            else {
                continue;
            };
            let key = BubbleKey::Mid(item.message_id_hex.to_ascii_lowercase());
            let retried = self
                .find_bubble(&item.peer_pub_hex, &key)
                .and_then(|bubble| self.tick_view(bubble))
                .is_none_or(|view| matches!(view.tick, Tick::Waiting(Waiting::Retried { .. })));
            if !retried {
                continue;
            }
            let expires = Some(item.expires_at_ms).filter(|&ms| ms > 0);
            match waiting.iter_mut().find(|(friend, ..)| *friend == at) {
                Some((_, count, first)) => {
                    *count += 1;
                    *first = match (*first, expires) {
                        (Some(a), Some(b)) => Some(a.min(b)),
                        (a, b) => a.or(b),
                    };
                }
                None => waiting.push((at, 1, expires)),
            }
        }
        let total: usize = waiting.iter().map(|(_, count, _)| count).sum();
        let (at, count, until_ms) = waiting
            .into_iter()
            .min_by_key(|&(at, _, first)| (first.is_none(), first, at))?;
        Some(WaitingQuit {
            peer: convo_key(&self.contacts[at].pub_hex),
            count,
            more: total - count,
            until_ms,
            question,
        })
    }

    /// QUIT. Enter quits as 'When I quit' says, S quits and stops the
    /// background program and K quits and keeps it (where offered), L puts
    /// LOCK in QUIT's place (wherever QUIT knows the program's state), Esc
    /// stays. While a chosen quit waits for a send, Q quits anyway. While the
    /// identity or a change to the friends is saved, or the background
    /// program is being stopped, there is only waiting (and Esc, before a
    /// stop). Ctrl+C does nothing more here: it is how many people copy, so
    /// a second one must not quit.
    ///
    /// The warning about waiting messages (UXF.8): Enter or Esc stays, Q
    /// quits anyway, as the question's Enter would (under 'Ask me' QUIT then
    /// asks it). For [`QUIT_SETTLE`] after that warning appeared or went, no
    /// key ends the app: a press meant for what was there before must not.
    fn on_quit_key(&mut self, key: KeyEvent) -> Vec<Cmd> {
        let enter = key.code == KeyCode::Enter && !has_ctrl_or_alt(key);
        let letter = plain_char(key).map(|c| c.to_ascii_lowercase());
        let settled = !self.quit_settling();
        let choice = match self.quit_view() {
            QuitView::Stopping { .. } => return Vec::new(),
            QuitView::SettingUp | QuitView::Saving => None,
            QuitView::Sending { .. } => match (letter, self.quitting) {
                (Some('q'), Some(Quitting::AfterSends { choice, .. })) if settled => {
                    return self.carry_out_quit(choice);
                }
                _ => None,
            },
            QuitView::Waiting(_) if enter => {
                self.quitting = None;
                self.close_overlay();
                return Vec::new();
            }
            QuitView::Waiting(waiting) => match (letter, waiting.question.enter) {
                (Some('q'), Some(choice)) if settled => Some(choice),
                (Some('q'), None) if settled => {
                    self.quit_anyway = true;
                    // The question follows from Q itself: its keys need no
                    // settling.
                    self.quit_warned = Some(false);
                    self.dirty = true;
                    return Vec::new();
                }
                _ => None,
            },
            QuitView::NotRunning | QuitView::Running(_) if letter == Some('l') => {
                self.close_overlay();
                self.open_lock();
                return Vec::new();
            }
            _ if !settled => None,
            QuitView::Plain | QuitView::NotRunning => enter.then_some(QuitChoice::Keep),
            QuitView::Running(running) => match letter {
                _ if enter => running.enter,
                Some('s') if running.can_stop && running.enter != Some(QuitChoice::Stop) => {
                    Some(QuitChoice::Stop)
                }
                Some('k') if running.can_stop && running.enter != Some(QuitChoice::Keep) => {
                    Some(QuitChoice::Keep)
                }
                _ => None,
            },
        };
        if let Some(choice) = choice {
            return self.choose_quit(choice);
        }
        if key.code == KeyCode::Esc {
            self.quitting = None;
            self.close_overlay();
        }
        Vec::new()
    }

    /// A quit chosen on QUIT: a message being sent goes out first (QUIT says
    /// so, and Q quits anyway).
    fn choose_quit(&mut self, choice: QuitChoice) -> Vec<Cmd> {
        if self.jobs_in_flight.send > 0 {
            self.quitting = Some(Quitting::AfterSends {
                choice,
                since: self.now,
            });
            self.dirty = true;
            return Vec::new();
        }
        self.carry_out_quit(choice)
    }

    /// Quits now, keeping the background program; or stops it first, the
    /// app ending once the stop has answered.
    fn carry_out_quit(&mut self, choice: QuitChoice) -> Vec<Cmd> {
        match choice {
            QuitChoice::Keep => vec![Cmd::Exit(self.quit_plan())],
            QuitChoice::Stop => {
                self.quitting = Some(Quitting::Stopping { since: self.now });
                self.dirty = true;
                // A stop asked on NET or SET may already be running: its
                // answer ends the app too.
                if !self.stopping {
                    self.ask_node_to_stop();
                }
                Vec::new()
            }
        }
    }

    /// QUIT's warning about waiting messages appeared or went less than
    /// [`QUIT_SETTLE`] ago.
    fn quit_settling(&self) -> bool {
        self.quit_settle
            .is_some_and(|at| self.now.saturating_duration_since(at) < QUIT_SETTLE)
    }

    /// A chosen quit goes on once what it waits for is done: the sends (and
    /// a change to the friends one of them saved), or the stop. After a stop
    /// the plain terminal says whether the background program still runs.
    ///
    /// It also notes when QUIT's warning about waiting messages appears or
    /// goes (it opened with it, or the messages went while it showed), for
    /// [`QUIT_SETTLE`]; closed, QUIT forgets it.
    fn quit_upkeep(&mut self) {
        if self.overlays.contains(&Overlay::Quit) {
            let warned = matches!(self.quit_view(), QuitView::Waiting(_));
            if self.quit_warned.map_or(warned, |before| before != warned) {
                self.quit_settle = Some(self.now);
            }
            self.quit_warned = Some(warned);
        } else {
            self.quit_warned = None;
            self.quit_settle = None;
            self.quit_anyway = false;
        }
        match self.quitting {
            Some(Quitting::AfterSends { choice, .. })
                if self.jobs_in_flight.send == 0 && self.jobs_in_flight.critical == 0 =>
            {
                let out = self.carry_out_quit(choice);
                self.cmds.extend(out);
            }
            Some(Quitting::Stopping { .. }) if !self.stopping => {
                let plan = match self.node.running_pid() {
                    Some(pid) => ExitPlan::quit(Some(pid)),
                    None if self.node.running() => ExitPlan::quit(None),
                    None => ExitPlan::quit_stopped(),
                };
                let plan = self.with_exit_note(plan);
                self.cmds.push(Cmd::Exit(plan));
            }
            _ => {}
        }
    }

    // ── Lock now ────────────────────────────────────────────────────────────

    /// LOCK (UXF.7, Lock now v1), from SET's 'Lock now', QUIT's L (in
    /// QUIT's place) or L on Home (PP.23): its question, over the screen.
    fn open_lock(&mut self) {
        self.open_overlay(Overlay::Lock(LockStep::Asking));
    }

    /// LOCK's step, wherever it is among the overlays.
    fn lock_mut(&mut self) -> Option<&mut LockStep> {
        self.overlays
            .iter_mut()
            .rev()
            .find_map(|overlay| match overlay {
                Overlay::Lock(step) => Some(step),
                _ => None,
            })
    }

    /// Enter was pressed on LOCK: until it ends, nothing starts the
    /// background program by itself.
    fn locking(&self) -> bool {
        self.overlays
            .iter()
            .any(|overlay| matches!(overlay, Overlay::Lock(LockStep::Locking { .. })))
    }

    /// LOCK asked for the stop (or took over one already running) and waits
    /// for its answer.
    fn lock_waits_for_stop(&self) -> bool {
        self.overlays.iter().any(|overlay| {
            matches!(
                overlay,
                Overlay::Lock(LockStep::Locking { stopping: true, .. })
            )
        })
    }

    /// LOCK: Enter (not right after a paste) locks, Esc cancels. Once Enter
    /// was pressed, Esc still cancels while a send or a save goes first;
    /// after that only the stop's answer ends it. When it did not stop the
    /// program, Esc closes. Ctrl+C does nothing here.
    fn on_lock_key(&mut self, key: KeyEvent, step: &LockStep) {
        let esc = key.code == KeyCode::Esc;
        match step {
            // Lock v2 (P6.40): a node that serves it keeps running, locked.
            LockStep::Asking if self.confirms(key) && self.lock_v2_offered() => {
                self.close_overlay();
                self.lock_v2_now(LockWhy::User);
            }
            LockStep::Asking if self.confirms(key) => self.lock_now(),
            LockStep::Asking
            | LockStep::Locking {
                stopping: false, ..
            }
            | LockStep::NotStopped(_)
                if esc =>
            {
                self.close_overlay();
            }
            _ => {}
        }
    }

    /// Enter on LOCK's question: the stop goes out from [`App::lock_upkeep`]
    /// once no send nor change to the friends is in flight (a send could
    /// start the background program again).
    fn lock_now(&mut self) {
        let since = self.now;
        if let Some(step) = self.lock_mut() {
            *step = LockStep::Locking {
                since,
                stopping: false,
            };
        }
        self.dirty = true;
    }

    /// LOCK's job ([`NodeJob::Lock`], PP.23) goes out once nothing it must
    /// wait for is in flight: a send or a change to the friends, the read
    /// of Raven's own login item (review D-lock-tui-6: a LOCK confirmed
    /// before the read answered stopped Raven without recording the lock or
    /// unloading the item, and launchd started it again), and any stop
    /// already running. Where this build reads no login items it stops as
    /// UXF.7 did (a login service is left alone), with the lock recorded
    /// around the stop all the same.
    fn lock_upkeep(&mut self) {
        if self.jobs_in_flight.send > 0 || self.jobs_in_flight.critical > 0 {
            return;
        }
        let asked = matches!(
            self.lock_mut(),
            Some(LockStep::Locking {
                stopping: false,
                ..
            })
        );
        if !asked || self.stopping || self.login_item_reads > 0 {
            return;
        }
        let login_item = self.node.login_item;
        if login_item == LoginItemKnown::Unknown {
            // Not asked yet: LOCK waits for the answer.
            self.read_login_item();
            return;
        }
        if let Some(LockStep::Locking { stopping, .. }) = self.lock_mut() {
            *stopping = true;
        }
        self.dirty = true;
        self.stopping = true;
        self.stop_advice = None;
        self.job(Cmd::Node(NodeJob::Lock {
            started_by_app: self.node.ours(),
            own_item: matches!(login_item, LoginItemKnown::Own(_)),
            managed: login_item == LoginItemKnown::NotAvailable && self.node.managed.is_some(),
        }));
    }

    /// Raven's own login item runs this profile, as the read answered
    /// (PP.23): LOCK says it starts Raven again at the next login, and
    /// unloads it for this login session only.
    pub(super) fn own_login_item(&self) -> bool {
        matches!(self.node.login_item, LoginItemKnown::Own(_))
    }

    /// Raven's own login item runs this profile, and a `raven lock` turned
    /// it off (review D-lock-tui-7): it starts nothing at the next login, so
    /// LOCK says it stays off and ends with the plain line.
    pub(super) fn own_login_item_off(&self) -> bool {
        matches!(self.node.login_item, LoginItemKnown::Own(item) if item.stays_off)
    }

    /// The stop LOCK waits for answered. Once this profile's background
    /// program no longer answers at all, the app ends: the terminal cleared
    /// and one line ([`ExitPlan::locked`], or [`ExitPlan::locked_until_login`]
    /// after Raven's own login item was unloaded, unless a `raven lock`
    /// turned it off: review D-lock-tui-7). Otherwise LOCK says why, in
    /// place of NET's toast, and the app stays.
    fn lock_stop_ended(&mut self, stopped: Stopped) {
        self.dirty = true;
        if stopped.gone() {
            let plan = if self.own_login_item() && !self.own_login_item_off() {
                ExitPlan::locked_until_login()
            } else {
                ExitPlan::locked(self.vault.profile)
            };
            self.cmds.push(Cmd::Exit(plan));
            return;
        }
        let outcome = match stopped.outcome {
            // Its Status still answers, or did not answer in time: it may
            // still run.
            StopOutcome::Stopped | StopOutcome::NotRunning => StopOutcome::StillRunning,
            StopOutcome::Advice(advice) => {
                self.stop_advice = Some((stopped.after.pid, advice.clone()));
                StopOutcome::Advice(advice)
            }
            outcome => outcome,
        };
        self.lock_not_stopped(outcome);
    }

    /// LOCK did not stop the background program: it says why.
    fn lock_not_stopped(&mut self, outcome: StopOutcome) {
        if let Some(step) = self.lock_mut() {
            *step = LockStep::NotStopped(outcome);
        }
        self.dirty = true;
    }

    /// Whether a message is being sent now (LOCK waits for it).
    pub(super) fn sending(&self) -> bool {
        self.jobs_in_flight.send > 0
    }

    /// The vault check found a passphrase-vault profile: LOCK locks it, and
    /// says so. Until the check answers, LOCK speaks as for a keychain.
    pub(super) fn vault_profile(&self) -> bool {
        self.vault.profile
    }

    /// The file PASSFILE says to save the passphrase in is there: PASSFILE
    /// says what that means.
    pub(super) fn passphrase_saved(&self) -> bool {
        self.vault.passphrase_saved
    }

    /// A vault profile's passphrase is saved in this file (review
    /// D-lock-tui-2): LOCK says that anyone who can read it can unlock
    /// Raven, as `raven lock` does.
    pub(super) fn lock_passphrase_file(&self) -> Option<&Path> {
        self.vault
            .passphrase_file
            .as_deref()
            .filter(|_| self.vault.profile)
    }

    // ── Erase Raven from this computer ──────────────────────────────────────

    /// ERASE (PP.22), from SET's last row: over the whole screen, first
    /// what erasing would delete, read on the store worker.
    fn open_erase(&mut self) {
        if self.privacy.is_none() {
            return;
        }
        self.open_overlay(Overlay::Erase(EraseState::Reading));
        self.job(Cmd::Store(StoreJob::ErasePlan));
    }

    /// ERASE's state, wherever it is among the overlays.
    fn erase_mut(&mut self) -> Option<&mut EraseState> {
        self.overlays
            .iter_mut()
            .rev()
            .find_map(|overlay| match overlay {
                Overlay::Erase(erase) => Some(erase),
                _ => None,
            })
    }

    /// 'erase' was typed and Enter pressed: until the app ends (or the
    /// erase changed nothing), nothing starts the background program by
    /// itself, nothing is read from the profile and no read marker is
    /// saved.
    pub(super) fn erasing(&self) -> bool {
        self.overlays
            .iter()
            .any(|overlay| matches!(overlay, Overlay::Erase(erase) if erase.erasing()))
    }

    /// ERASE asked for the stop of the background program this app started
    /// and waits for its answer.
    fn erase_waits_for_stop(&self) -> bool {
        self.overlays.iter().any(|overlay| {
            matches!(
                overlay,
                Overlay::Erase(EraseState::Erasing {
                    stage: EraseStage::Stopping,
                    ..
                })
            )
        })
    }

    /// ERASE's list answered: the question, or why erase refuses this
    /// profile. An answer for a box closed meanwhile is dropped.
    fn erase_plan_read(&mut self, plan: Result<ErasePlanView, String>) {
        let Some(erase) = self.erase_mut() else {
            return;
        };
        if *erase != EraseState::Reading {
            return;
        }
        *erase = match plan {
            Ok(plan) => EraseState::Asking {
                plan,
                typed: String::new(),
            },
            Err(why) => EraseState::Refused(why),
        };
        self.dirty = true;
    }

    /// ERASE: what is typed goes into the word (a Persian keyboard's letter
    /// keys arrive as the Latin letters on them, as in every box);
    /// Backspace edits; Enter (not right after a paste) erases once the
    /// word is 'erase', and means nothing before; Esc cancels, also while
    /// the erase waits for a job in flight. Once it runs no key does
    /// anything, Ctrl+C neither. A refusal closes on Esc or Enter.
    fn on_erase_key(&mut self, key: KeyEvent, erase: &EraseState) {
        let esc = key.code == KeyCode::Esc;
        match erase {
            EraseState::Erasing {
                stage: EraseStage::Waiting,
                ..
            } if esc => self.close_overlay(),
            EraseState::Erasing { .. } => {}
            _ if is_ctrl(key, 'c') => self.open_overlay(Overlay::Quit),
            EraseState::Asking { typed, .. } => match (key.code, plain_char(key)) {
                (KeyCode::Esc, _) => self.close_overlay(),
                (_, Some(c)) => {
                    if let Some(EraseState::Asking { typed, .. }) = self.erase_mut() {
                        if typed.chars().count() < LINE_FIELD_MAX && !c.is_control() {
                            typed.push(c);
                        }
                    }
                    self.dirty = true;
                }
                (KeyCode::Backspace, _) if !has_ctrl_or_alt(key) => {
                    if let Some(EraseState::Asking { typed, .. }) = self.erase_mut() {
                        typed.pop();
                    }
                    self.dirty = true;
                }
                _ if self.confirms(key) && typed_word_is(typed, ERASE_WORD) => self.erase_now(),
                _ => {}
            },
            EraseState::Reading if esc => self.close_overlay(),
            EraseState::Refused(_) | EraseState::NotErased(_) if esc || self.confirms(key) => {
                self.close_overlay();
            }
            EraseState::Reading | EraseState::Refused(_) | EraseState::NotErased(_) => {}
        }
    }

    /// Enter on ERASE with 'erase' typed: the erase goes out from
    /// [`App::erase_upkeep`] once no job is in flight.
    fn erase_now(&mut self) {
        let since = self.now;
        if let Some(erase) = self.erase_mut() {
            *erase = EraseState::Erasing {
                since,
                stage: EraseStage::Waiting,
            };
        }
        self.dirty = true;
    }

    /// ERASE's erase goes out once every job in flight answered, so no
    /// worker holds the profile open (the store worker then runs nothing
    /// else): first the stop of the background program this app started
    /// (on Windows only this app may stop it), then the erase job, which
    /// stops any other itself, as `raven erase` does.
    fn erase_upkeep(&mut self) {
        let waiting = matches!(
            self.erase_mut(),
            Some(EraseState::Erasing {
                stage: EraseStage::Waiting,
                ..
            })
        );
        if !waiting || !self.jobs_in_flight.idle() {
            return;
        }
        let started_here = self.node.started_by_app.is_some()
            && self.node.started_by_app == self.node.running_pid();
        if !started_here {
            return self.run_erase();
        }
        if let Some(EraseState::Erasing { stage, .. }) = self.erase_mut() {
            *stage = EraseStage::Stopping;
        }
        self.dirty = true;
        // The node is this app's own child, not a login service's, even
        // where Raven's own login item is set up (review D-lock-tui-5: on
        // Windows, a stop that counted the task left the app's node
        // running, and the erase job may not end a node it did not start).
        self.send_stop(false);
    }

    /// The erase job, exactly once: from the wait, or once the stop
    /// answered.
    fn run_erase(&mut self) {
        let Some(EraseState::Erasing { stage, .. }) = self.erase_mut() else {
            return;
        };
        if *stage == EraseStage::Running {
            return;
        }
        *stage = EraseStage::Running;
        self.dirty = true;
        self.job(Cmd::Store(StoreJob::Erase));
    }

    /// The erase answered. It ran: the app ends, saving nothing, and the
    /// plain terminal, cleared, gets the result list (or what is left).
    /// Nothing was erased: ERASE says why, and the app goes on.
    fn erase_ended(&mut self, end: EraseEnd) {
        self.dirty = true;
        match end {
            EraseEnd::Ran { finished, lines } => {
                self.cmds
                    .push(Cmd::Exit(ExitPlan::erased(finished, &lines)));
            }
            EraseEnd::NotErased(why) => {
                if let Some(erase) = self.erase_mut() {
                    *erase = EraseState::NotErased(why);
                }
            }
        }
    }

    /// HELP: ? or Esc closes, Up and Down scroll; Ctrl+C opens QUIT over it.
    fn on_help_key(&mut self, key: KeyEvent) {
        if is_ctrl(key, 'c') {
            self.open_overlay(Overlay::Quit);
            return;
        }
        let max = overlays::help_max_scroll(
            &self.look,
            &self.screen,
            (self.privacy.is_some(), self.groups_live()),
            self.size,
        );
        let Some(Overlay::Help { scroll }) = self.overlays.last_mut() else {
            return;
        };
        let new = match (key.code, plain_char(key)) {
            (KeyCode::Esc, _) | (_, Some('?')) => {
                self.close_overlay();
                return;
            }
            (KeyCode::Up, _) => scroll.saturating_sub(1),
            (KeyCode::Down, _) => scroll.saturating_add(1).min(max),
            _ => return,
        };
        if new != *scroll {
            *scroll = new;
            self.dirty = true;
        }
    }

    /// Home: Ctrl+C opens QUIT and Tab moves the focus anywhere; the rest
    /// depends on the focus.
    fn on_home_key(&mut self, key: KeyEvent) {
        if is_ctrl(key, 'c') {
            self.open_overlay(Overlay::Quit);
            return;
        }
        match key.code {
            KeyCode::Tab if !has_ctrl_or_alt(key) => self.move_focus(Focus::next),
            KeyCode::BackTab => self.move_focus(Focus::previous),
            _ => match self.focus {
                Focus::Friends => self.on_friends_key(key),
                // A group's chat (lab): its own composer and messages.
                Focus::Composer if self.open_group().is_some() => self.on_group_composer_key(key),
                Focus::Messages if self.open_group().is_some() => self.on_group_messages_key(key),
                Focus::Composer => self.on_composer_key(key),
                Focus::Messages => self.on_messages_key(key),
            },
        }
    }

    /// The friend list: Up and Down (or k and j) move the highlight, Enter
    /// opens that friend's conversation and goes to the composer; V verifies
    /// the highlighted friend (VF), E or I opens their page (CI), G opens
    /// MEET for them, N opens NET and S opens SET; ? and Q open HELP and
    /// QUIT, and L opens LOCK (PP.23).
    fn on_friends_key(&mut self, key: KeyEvent) {
        let highlighted = self.friends.get(self.highlight).cloned();
        match (key.code, plain_char(key)) {
            (KeyCode::Up, _) | (_, Some('k')) => self.move_highlight(-1),
            (KeyCode::Down, _) | (_, Some('j')) => self.move_highlight(1),
            (KeyCode::Enter, _) if !has_ctrl_or_alt(key) => self.open_highlighted(),
            (_, Some('a' | 'A')) => self.open_add_friend(),
            (_, Some('v' | 'V')) => {
                if let Some(pub_hex) = highlighted {
                    self.open_verify(VerifyWho::Saved {
                        pub_hex,
                        back: Back::Home,
                    });
                }
            }
            (_, Some('e' | 'E' | 'i' | 'I')) => {
                if let Some(pub_hex) = highlighted {
                    self.open_friend_page(&pub_hex);
                } else {
                    // On a group (lab): its members.
                    self.group_page_from_list();
                }
            }
            // A new group (lab, while groups are live).
            (_, Some('c' | 'C')) => self.open_new_group(),
            (_, Some('g' | 'G')) => self.open_meet(MeetFrom::Home),
            (_, Some('n' | 'N')) => self.open_network(),
            (_, Some('s' | 'S')) => self.open_settings(),
            (_, Some('?')) => self.open_overlay(Overlay::Help { scroll: 0 }),
            (_, Some('q' | 'Q')) => self.open_overlay(Overlay::Quit),
            (_, Some('l' | 'L')) => self.open_lock(),
            // The security notices (P6.31): all of them, those about the
            // highlighted friend, and pausing sending to them.
            (_, Some('w' | 'W')) => self.open_security(None),
            // Raven updates (P6.47), while the gate is live.
            (_, Some('u' | 'U')) => self.open_updates(),
            (_, Some('d' | 'D')) => {
                if let Some(pub_hex) =
                    highlighted.filter(|key| self.notices_about(key).next().is_some())
                {
                    self.open_security(Some(&pub_hex));
                }
            }
            (_, Some('p' | 'P')) => {
                if let Some(pub_hex) = highlighted {
                    self.toggle_pause(&pub_hex);
                }
            }
            _ => {}
        }
    }

    /// The composer: typing is text, so no letter is a shortcut; Ctrl+J is a
    /// new line, and Backspace, Delete, Left, Right, Home and End edit. Up,
    /// Down, PgUp and PgDn scroll the conversation and never change the
    /// friend. Esc goes back to the list; ? on an empty composer opens HELP.
    /// Enter sends, also right after a paste: a paste's own line breaks are
    /// text (a bracketed paste's, and `Key::PastedEnter`), so an Enter key
    /// is the user's (field test E3: Enter right after fast text did not
    /// send). Questions keep [`PASTE_GUARD`].
    fn on_composer_key(&mut self, key: KeyEvent) {
        if is_ctrl(key, 'j') {
            self.compose(|composer| composer.insert("\n"));
            return;
        }
        let empty = self.composer().is_none_or(Composer::is_empty);
        match (key.code, plain_char(key)) {
            (KeyCode::Esc, _) => self.set_focus(Focus::Friends),
            (_, Some('?')) if empty => self.open_overlay(Overlay::Help { scroll: 0 }),
            (_, Some(c)) => self.compose(|composer| composer.insert(c.encode_utf8(&mut [0; 4]))),
            (KeyCode::Enter, _) if !has_ctrl_or_alt(key) => self.composer_enter(),
            (KeyCode::Backspace, _) if !has_ctrl_or_alt(key) => self.compose(Composer::backspace),
            (KeyCode::Delete, _) => self.compose(Composer::delete),
            (KeyCode::Left, _) => self.compose(Composer::left),
            (KeyCode::Right, _) => self.compose(Composer::right),
            (KeyCode::Home, _) => self.compose(Composer::line_start),
            (KeyCode::End, _) => self.compose(Composer::line_end),
            _ => self.scroll_key(key),
        }
    }

    /// Enter in the composer: the draft goes to the open friend, and the
    /// composer is empty again. Nothing for an empty draft, or one the
    /// composer refuses (its hint says why).
    fn composer_enter(&mut self) {
        let (Some(friend), Some(composer)) = (self.open_friend.clone(), self.composer()) else {
            return;
        };
        if composer.text().trim().is_empty() || composer.problem().is_some() {
            return;
        }
        // Sending to them is paused (P6.31): the draft stays, the hint says
        // how to resume.
        if self.paused(&friend) {
            return;
        }
        let text = composer.text().to_owned();
        self.drafts.remove(&convo_key(&friend));
        self.start_send(&friend, text);
    }

    /// The conversation: Up and Down choose a message (scrolling to it),
    /// PgUp and PgDn scroll, and neither changes the friend. Enter shows a
    /// clipped body whole, else opens MSG for a message of yours; R and C act
    /// on it as its state allows; D shows its details (or why the history
    /// can't be read). Esc goes back to the composer; ? and Q open HELP and
    /// QUIT, and L opens LOCK (PP.23).
    fn on_messages_key(&mut self, key: KeyEvent) {
        let peer = self.open_friend.as_deref().map(convo_key);
        let chosen = self.chosen_bubble().map(|b| (b.key(), b.outgoing()));
        match (key.code, plain_char(key)) {
            (KeyCode::Esc, _) => self.set_focus(Focus::Composer),
            (_, Some('?')) => self.open_overlay(Overlay::Help { scroll: 0 }),
            (_, Some('q' | 'Q')) => self.open_overlay(Overlay::Quit),
            (_, Some('l' | 'L')) => self.open_lock(),
            (_, Some('w' | 'W')) => self.open_security(None),
            (_, Some('d' | 'D')) if self.history_error.is_some() => {
                self.history_details = !self.history_details;
                self.dirty = true;
            }
            (KeyCode::Up, _) => self.choose(1),
            (KeyCode::Down, _) => self.choose(-1),
            _ => {
                let (Some(peer), Some((key_of, outgoing))) = (peer, chosen) else {
                    self.scroll_key(key);
                    return;
                };
                match (key.code, plain_char(key)) {
                    (_, Some('d' | 'D')) if outgoing => self.open_message(&peer, key_of, true),
                    (_, Some('r' | 'R')) if outgoing => {
                        self.press_r(&peer, &key_of);
                    }
                    (_, Some('c' | 'C')) if outgoing => self.ask_stop(&peer, &key_of),
                    _ if self.confirms(key) => self.enter_on_message(&peer, key_of, outgoing),
                    _ => self.scroll_key(key),
                }
            }
        }
    }

    /// The message chosen in Messages focus.
    fn chosen_bubble(&self) -> Option<Bubble<'_>> {
        let bubbles = self.bubbles(self.open_friend.as_deref()?);
        let at = self.chosen?;
        bubbles
            .len()
            .checked_sub(at + 1)
            .map(|index| bubbles[index])
    }

    /// Up (`by` 1: older) or Down: another message, and the window scrolled
    /// as little as it takes to show it.
    fn choose(&mut self, by: isize) {
        let Some(open) = self.open_friend.clone() else {
            return;
        };
        let count = self.bubbles(&open).len();
        if count == 0 {
            return;
        }
        let at = self.chosen.unwrap_or(0).min(count - 1);
        let new = at.saturating_add_signed(by).min(count - 1);
        if self.chosen != Some(new) {
            self.chosen = Some(new);
            self.dirty = true;
        }
        let scroll = home::scroll_to_message(self, new);
        if scroll != self.scroll {
            self.scroll = scroll;
            self.dirty = true;
        }
    }

    /// Enter on a message: a clipped body shows whole first; then MSG, for
    /// one of yours.
    fn enter_on_message(&mut self, peer: &str, key: BubbleKey, outgoing: bool) {
        let clipped = self
            .find_bubble(peer, &key)
            .is_some_and(|bubble| display::body_lines(bubble.body(), false).more_chars > 0);
        if clipped && !self.expanded.contains(&key) {
            self.expanded.insert(key);
            self.dirty = true;
        } else if outgoing {
            self.open_message(peer, key, false);
        }
    }

    /// MSG for message `key` of the conversation with `peer`; its details
    /// shown at once with D, or when Settings ask for technical details.
    fn open_message(&mut self, peer: &str, key: BubbleKey, details: bool) {
        self.open_overlay(Overlay::Message(MessageView {
            peer: peer.to_owned(),
            key,
            details: details || self.settings.show_details,
        }));
    }

    /// MSG: R and C as in the conversation (R closes it when the text goes
    /// again as a new message), S sends again after the warning, D shows or
    /// hides the details, Esc closes; Ctrl+C opens QUIT.
    fn on_message_key(&mut self, key: KeyEvent, view: &MessageView) {
        if is_ctrl(key, 'c') {
            self.open_overlay(Overlay::Quit);
            return;
        }
        match (key.code, plain_char(key)) {
            (KeyCode::Esc, _) => self.close_overlay(),
            (_, Some('d' | 'D')) => {
                if let Some(Overlay::Message(open)) = self.overlays.last_mut() {
                    open.details = !open.details;
                    self.dirty = true;
                }
            }
            (_, Some('r' | 'R')) => {
                let again = self
                    .facts(&view.peer, &view.key)
                    .is_some_and(|(actions, mid, _)| !(actions.try_now && mid.is_some()));
                if self.press_r(&view.peer, &view.key) && again {
                    self.close_overlay();
                }
            }
            (_, Some('c' | 'C')) => self.ask_stop(&view.peer, &view.key),
            (_, Some('s' | 'S')) => self.ask_send_again(&view.peer, &view.key),
            _ => {}
        }
    }

    /// A confirm box: Y does it, N or Esc keeps things as they are; Ctrl+C
    /// opens QUIT. Sending again closes MSG under it: the new message shows
    /// in the conversation.
    fn on_confirm_key(&mut self, key: KeyEvent, confirm: ConfirmState) {
        if is_ctrl(key, 'c') {
            self.open_overlay(Overlay::Quit);
            return;
        }
        match (key.code, plain_char(key)) {
            (_, Some('y' | 'Y')) => {
                self.close_overlay();
                match confirm.action {
                    ConfirmAction::StopTrying { mid } => self.queue_send_job(SendJob::Cancel {
                        mid,
                        peer: confirm.peer,
                    }),
                    ConfirmAction::SendAgain { body } => {
                        if matches!(self.overlays.last(), Some(Overlay::Message(_))) {
                            self.close_overlay();
                        }
                        self.start_send(&confirm.peer, body);
                    }
                }
            }
            (KeyCode::Esc, _) | (_, Some('n' | 'N')) => self.close_overlay(),
            _ => {}
        }
    }

    /// Up and Down by a row, PgUp and PgDn by a window, within the open
    /// conversation.
    fn scroll_key(&mut self, key: KeyEvent) {
        let page = isize::try_from(home::page_rows(self)).unwrap_or(isize::MAX);
        let by = match key.code {
            KeyCode::Up => 1,
            KeyCode::Down => -1,
            KeyCode::PageUp => page,
            KeyCode::PageDown => -page,
            _ => return,
        };
        let new = home::clamp_scroll(self, self.scroll.saturating_add_signed(by));
        if new != self.scroll {
            self.scroll = new;
            self.dirty = true;
        }
    }

    /// The composer has the keys: Home, the composer focused, a friend open,
    /// nothing over it.
    fn composer_takes_text(&self) -> bool {
        self.screen == Screen::Home
            && self.focus == Focus::Composer
            && (self.open_friend.is_some() || self.group_takes_text())
            && self.overlays.is_empty()
            && !self.too_small()
    }

    /// Edits the open friend's draft (or the open group's); a change is
    /// drawn.
    fn compose(&mut self, edit: impl FnOnce(&mut Composer) -> bool) {
        if self.open_group().is_some() {
            self.group_compose(edit);
            return;
        }
        let Some(key) = self.open_friend.as_deref().map(convo_key) else {
            return;
        };
        if edit(self.drafts.entry(key).or_default()) {
            self.dirty = true;
        }
    }

    // ── Network and status ──────────────────────────────────────────────────

    /// NET, from the friend list. The address is read again; a vault profile
    /// without its passphrase file gets PASSFILE over it.
    fn open_network(&mut self) {
        self.set_screen(Screen::Network(Box::default()));
        self.job(Cmd::Node(NodeJob::LanAddresses));
        self.load_updates();
        if self.node.state == NodeState::NeedsPassphraseFile {
            self.open_overlay(Overlay::PassFile);
        }
    }

    fn net_mut(&mut self) -> Option<&mut NetState> {
        match &mut self.screen {
            Screen::Network(net) => Some(net),
            _ => None,
        }
    }

    /// NET's log view, while it is open.
    fn log_view_mut(&mut self) -> Option<&mut LogView> {
        self.net_mut().and_then(|net| net.log.as_mut())
    }

    /// NET: Esc goes back to Home, L opens the log, G opens MEET, and S, X
    /// (after a yes) and R as [`App::net_keys`] allows; Up, Down, PgUp and
    /// PgDn scroll; ? and Q open HELP and QUIT, and Ctrl+C QUIT.
    fn on_network_key(&mut self, key: KeyEvent) {
        if is_ctrl(key, 'c') {
            self.open_overlay(Overlay::Quit);
            return;
        }
        let Screen::Network(net) = &self.screen else {
            return;
        };
        if net.log.is_some() {
            self.on_log_key(key);
            return;
        }
        if net.asking_stop {
            self.on_stop_question_key(key);
            return;
        }
        let keys = self.net_keys();
        match (key.code, plain_char(key)) {
            (KeyCode::Esc, _) => self.set_screen(Screen::Home),
            (_, Some('?')) => self.open_overlay(Overlay::Help { scroll: 0 }),
            (_, Some('q' | 'Q')) => self.open_overlay(Overlay::Quit),
            (_, Some('l' | 'L')) => self.open_log(),
            (_, Some('w' | 'W')) => self.open_security(None),
            (_, Some('u' | 'U')) => self.open_updates(),
            (_, Some('g' | 'G')) => self.open_meet(MeetFrom::Network),
            (_, Some('s' | 'S')) if keys.start => self.start_from_net(),
            (_, Some('x' | 'X')) if keys.stop => {
                if let Some(net) = self.net_mut() {
                    net.asking_stop = true;
                }
                self.dirty = true;
            }
            (_, Some('r' | 'R')) if keys.check_again => self.check_again(),
            _ => self.scroll_net(key),
        }
    }

    /// X's question: Y stops it, N or Esc keeps it running.
    fn on_stop_question_key(&mut self, key: KeyEvent) {
        match (key.code, plain_char(key)) {
            (_, Some('y' | 'Y')) => self.stop_node(),
            (KeyCode::Esc, _) | (_, Some('n' | 'N')) => {
                if let Some(net) = self.net_mut() {
                    net.asking_stop = false;
                }
                self.dirty = true;
            }
            _ => {}
        }
    }

    /// S: the background program starts now, as a start by itself would;
    /// while `raven lock`'s lock is on, UNLOCK asks first.
    fn start_from_net(&mut self) {
        if self.cli_locked {
            self.after_unlock = Some(AfterUnlock::Net);
            self.open_overlay(Overlay::Unlock);
            return;
        }
        self.stop_advice = None;
        self.node.state = NodeState::Starting { since: self.now };
        self.dirty = true;
        self.job(Cmd::Node(NodeJob::Ensure));
    }

    /// Y to X's question. The node worker takes a Status of its own just
    /// before it stops anything, and the same rules decide again there.
    fn stop_node(&mut self) {
        if let Some(net) = self.net_mut() {
            net.asking_stop = false;
        }
        self.dirty = true;
        if self.net_keys().stop {
            self.ask_node_to_stop();
        }
    }

    /// The stop job, after a yes (NET, SET) or on QUIT. The node worker
    /// takes a Status of its own just before it stops anything, and the stop
    /// rules decide again there.
    fn ask_node_to_stop(&mut self) {
        self.send_stop(self.node.managed.is_some());
    }

    /// The stop job: `managed` says a login service runs the node, which
    /// the stop rules then leave alone.
    fn send_stop(&mut self, managed: bool) {
        self.stopping = true;
        self.stop_advice = None;
        self.job(Cmd::Node(NodeJob::Stop {
            started_by_app: self.node.ours(),
            managed,
        }));
    }

    /// A stop's answer: the Status after it, and a word where the panel
    /// can't say it. A stop the rules did not allow leaves its advice in NET.
    /// ERASE and LOCK, when one waits for this stop, take the answer
    /// themselves.
    fn stop_ended(&mut self, stopped: Stopped) {
        self.stopping = false;
        self.apply_probe(&stopped.after);
        if self.erase_waits_for_stop() {
            // Whatever it says: the erase stops Raven itself, or says why
            // it can't.
            self.run_erase();
            return;
        }
        if self.lock_waits_for_stop() {
            self.lock_stop_ended(stopped);
            return;
        }
        match stopped.outcome {
            // NET says so: 'Not running'.
            StopOutcome::Stopped | StopOutcome::NotRunning => {}
            StopOutcome::StillRunning => self.push_toast(STILL_RUNNING_TOAST),
            StopOutcome::Advice(advice) => self.stop_advice = Some((stopped.after.pid, advice)),
            StopOutcome::Managed => self.push_toast(MANAGED_STOP_TOAST),
            StopOutcome::Failed(_) => self.push_toast(NODE_STOP_FAILED_TOAST),
        }
        self.dirty = true;
    }

    /// R, after the background program stopped answering: the poller asks
    /// again (on Windows it had stopped asking), and so does the node worker,
    /// now.
    fn check_again(&mut self) {
        self.cmds.push(Cmd::Poll(PollCtl::CheckAgain));
        self.job(Cmd::Node(NodeJob::Probe));
    }

    /// L: the log view, read at once on the node worker.
    fn open_log(&mut self) {
        if let Some(net) = self.net_mut() {
            net.log = Some(LogView {
                reading: true,
                ..LogView::default()
            });
        }
        self.dirty = true;
        self.job(Cmd::Node(NodeJob::ServiceLog));
    }

    /// A read of the service log answered: into the log view, if it is
    /// still open.
    fn log_read(&mut self, lines: Result<Vec<String>, String>) {
        let Some(view) = self.log_view_mut() else {
            return;
        };
        view.reading = false;
        view.lines = Some(lines);
        self.clamp_net_scroll();
        self.dirty = true;
    }

    /// The log view: Esc goes back to the panel, ? opens HELP, and the
    /// arrows and PgUp and PgDn scroll.
    fn on_log_key(&mut self, key: KeyEvent) {
        match (key.code, plain_char(key)) {
            (KeyCode::Esc, _) => {
                if let Some(net) = self.net_mut() {
                    net.log = None;
                }
                self.dirty = true;
            }
            (_, Some('?')) => self.open_overlay(Overlay::Help { scroll: 0 }),
            _ => self.scroll_net(key),
        }
    }

    /// Up and Down by a row, PgUp and PgDn by a window: the panel from its
    /// top, or the log view from its newest line (Up goes back in it).
    fn scroll_net(&mut self, key: KeyEvent) {
        let page = i32::from(network::page_rows(self).max(1));
        let down = match key.code {
            KeyCode::Up => -1,
            KeyCode::Down => 1,
            KeyCode::PageUp => -page,
            KeyCode::PageDown => page,
            _ => return,
        };
        let max = i32::from(network::max_scroll(self));
        let Some(net) = self.net_mut() else {
            return;
        };
        let (scroll, by) = match &mut net.log {
            Some(log) => (&mut log.scroll, -down),
            None => (&mut net.scroll, down),
        };
        let new = u16::try_from((i32::from(*scroll) + by).clamp(0, max)).unwrap_or(0);
        if new != *scroll {
            *scroll = new;
            self.dirty = true;
        }
    }

    /// After a resize or a new read NET may hold fewer rows: keep its scroll
    /// in range.
    fn clamp_net_scroll(&mut self) {
        let max = network::max_scroll(self);
        if let Some(net) = self.net_mut() {
            match &mut net.log {
                Some(log) => log.scroll = log.scroll.min(max),
                None => net.scroll = net.scroll.min(max),
            }
        }
    }

    /// FW, once per profile: on Windows and macOS, once a node this app
    /// started listens on the network, which is when the system may ask
    /// whether raven-node may accept connections.
    fn firewall_upkeep(&mut self) {
        if (self.windows || self.mac)
            && !self.settings.firewall_note_shown
            && self.node.started_by_app.is_some()
            && matches!(self.node.state, NodeState::Listening { .. })
        {
            self.settings.firewall_note_shown = true;
            self.open_overlay(Overlay::Firewall);
            self.save_settings();
        }
    }

    /// NOTE, once per profile (UXF.9): the first time Raven receives on the
    /// network with receiving on. It waits for Home, NET or SET with no
    /// other box open and no field that has the keys, so it never takes a
    /// key meant for something else (Enter on AF-1, a step of a guide); FW,
    /// due at the same moment, goes over it.
    fn network_note_upkeep(&mut self) {
        if self.identity == IdentityStatus::Ready
            && self.settings.receive == Receive::On
            && !self.settings.network_note_shown
            && matches!(self.node.state, NodeState::Listening { .. })
            && !self.not_on_any_network()
            && matches!(
                self.screen,
                Screen::Home | Screen::Network(_) | Screen::Settings(_)
            )
            && self.overlays.is_empty()
            && !self.field_takes_text()
        {
            self.settings.network_note_shown = true;
            self.open_overlay(Overlay::NetworkNote);
            self.save_notes();
        }
    }

    /// Saves that a note shown once (UXF.9) was shown: a save the user did
    /// not ask for, so a tui_state.json that can't be read is left as it is.
    fn save_notes(&mut self) {
        if self.identity == IdentityStatus::Ready {
            self.job(Cmd::Store(StoreJob::SaveReadMarks(self.settings.clone())));
        }
    }

    // ── Meet without the internet ───────────────────────────────────────────

    /// G on the friend list or NET: MEET on its first step, for Home's
    /// highlighted friend. It only explains and waits (UXF.6).
    fn open_meet(&mut self, from: MeetFrom) {
        let friend = self.friends.get(self.highlight).cloned();
        let waiting = friend
            .as_deref()
            .map(|friend| self.waiting_ids(friend))
            .unwrap_or_default();
        self.set_screen(Screen::Meet(Box::new(MeetState {
            step: MeetStep::Start,
            from,
            friend,
            hotspot: false,
            hotspot_note: false,
            opened: self.now,
            waiting,
            retry: None,
        })));
    }

    fn meet_mut(&mut self) -> Option<&mut MeetState> {
        match &mut self.screen {
            Screen::Meet(meet) => Some(meet),
            _ => None,
        }
    }

    /// Step 3's field, while MEET is on step 3.
    fn find_mut(&mut self) -> Option<&mut FindState> {
        match &mut self.meet_mut()?.step {
            MeetStep::Find(find) => Some(find),
            _ => None,
        }
    }

    /// The ids of the messages of yours to `peer` that wait or are held:
    /// none of them has left this computer.
    fn waiting_ids(&self, peer: &str) -> Vec<String> {
        self.bubbles(peer)
            .into_iter()
            .filter_map(|bubble| self.tick_view(bubble))
            .filter(|view| matches!(view.tick, Tick::Waiting(_) | Tick::OnHold { .. }))
            .filter_map(|view| view.mid.map(str::to_ascii_lowercase))
            .collect()
    }

    /// MEET's address field has the keys: on step 3, for a saved friend.
    fn meet_field_open(&self) -> bool {
        match &self.screen {
            Screen::Meet(meet) => {
                matches!(meet.step, MeetStep::Find(_))
                    && meet
                        .friend
                        .as_deref()
                        .is_some_and(|friend| self.friend(friend).is_some())
            }
            _ => false,
        }
    }

    /// MEET's keys: Esc goes back to where G was pressed, ? and Q open HELP
    /// and QUIT, Ctrl+C QUIT. Step 1: 1, 2 or 3 says who makes the hotspot,
    /// A adds a friend. Step 2: Enter goes on (not within the paste guard),
    /// C shows the Linux command alone to copy. Step 3: the field (or, with
    /// no friend saved, A). Step 4: Enter opens the chat. While step 3's
    /// address is saved only Ctrl+C works.
    fn on_meet_key(&mut self, key: KeyEvent) {
        if is_ctrl(key, 'c') {
            self.open_overlay(Overlay::Quit);
            return;
        }
        let Screen::Meet(guide) = &self.screen else {
            return;
        };
        if guide.saving() {
            return;
        }
        if self.meet_field_open() {
            self.on_meet_field_key(key);
            return;
        }
        let (step, friend) = (guide.step.clone(), guide.friend.clone());
        match (key.code, plain_char(key)) {
            (KeyCode::Esc, _) => return self.leave_meet(),
            (_, Some('?')) => return self.open_overlay(Overlay::Help { scroll: 0 }),
            (_, Some('q' | 'Q')) => return self.open_overlay(Overlay::Quit),
            _ => {}
        }
        match step {
            MeetStep::Start => match plain_char(key) {
                Some('1') => self.meet_step(MeetStep::MakeHotspot, true),
                Some('2') => self.meet_step(MeetStep::JoinHotspot, true),
                Some('3') => self.meet_find(),
                Some('a' | 'A') => self.open_add_friend(),
                _ => {}
            },
            MeetStep::MakeHotspot | MeetStep::JoinHotspot => match plain_char(key) {
                Some('c' | 'C')
                    if step == MeetStep::MakeHotspot
                        && meet::system(self) == meet::System::Linux =>
                {
                    self.open_meet_copy();
                }
                _ if self.confirms(key) => self.meet_find(),
                _ => {}
            },
            // No saved friend to type an address for.
            MeetStep::Find(_) => match (key.code, plain_char(key)) {
                (_, Some('a' | 'A')) => self.open_add_friend(),
                (KeyCode::Up, _) => self.meet_choose(-1),
                (KeyCode::Down, _) => self.meet_choose(1),
                _ => {}
            },
            MeetStep::Connected => {
                if let Some(friend) = friend.filter(|_| self.confirms(key)) {
                    self.open_chat(&friend);
                }
            }
        }
    }

    /// Step 3's field: typing is text, Backspace edits, Enter saves (not
    /// within the paste guard), Up and Down choose another friend, Esc goes
    /// back.
    fn on_meet_field_key(&mut self, key: KeyEvent) {
        match (key.code, plain_char(key)) {
            (KeyCode::Esc, _) => self.leave_meet(),
            (KeyCode::Up, _) => self.meet_choose(-1),
            (KeyCode::Down, _) => self.meet_choose(1),
            (_, Some(c)) => self.meet_input(c.encode_utf8(&mut [0; 4])),
            (KeyCode::Backspace, _) if !has_ctrl_or_alt(key) => self.meet_erase(),
            _ if self.confirms(key) => self.meet_save(),
            _ => {}
        }
    }

    /// Step 2a or 2b; `hotspot`: one of you makes one. The first time this
    /// profile makes one (2a), the hotspot note shows (UXF.9).
    fn meet_step(&mut self, step: MeetStep, hotspot: bool) {
        let note = step == MeetStep::MakeHotspot && !self.settings.hotspot_note_shown;
        if let Some(meet) = self.meet_mut() {
            meet.step = step;
            meet.hotspot = hotspot;
            meet.hotspot_note |= note;
        }
        if note {
            self.settings.hotspot_note_shown = true;
            self.save_notes();
        }
        self.dirty = true;
    }

    /// Step 3, with this computer's addresses read again: joining a
    /// hotspot changes them.
    fn meet_find(&mut self) {
        if let Some(meet) = self.meet_mut() {
            meet.step = MeetStep::Find(FindState::default());
        }
        self.dirty = true;
        self.job(Cmd::Node(NodeJob::LanAddresses));
    }

    /// Esc: back to where G was pressed.
    fn leave_meet(&mut self) {
        let Screen::Meet(meet) = &self.screen else {
            return;
        };
        let back = match meet.from {
            MeetFrom::Home => Screen::Home,
            MeetFrom::Network => Screen::Network(Box::default()),
        };
        self.set_screen(back);
    }

    /// C on step 2a (Linux): the hotspot command alone on the plain
    /// terminal, until any key.
    fn open_meet_copy(&mut self) {
        self.peeking = true;
        self.cmds.push(Cmd::Peek(meet::copy_lines()));
    }

    /// Up or Down on step 3: the friend before or after in the list, with an
    /// empty field. Their messages waiting now are the ones counted.
    fn meet_choose(&mut self, by: isize) {
        let Screen::Meet(meet) = &self.screen else {
            return;
        };
        let at = meet.friend.as_deref().and_then(|friend| {
            self.friends
                .iter()
                .position(|f| f.eq_ignore_ascii_case(friend))
        });
        let last = self.friends.len().saturating_sub(1);
        let new = at.map_or(0, |at| at.saturating_add_signed(by).min(last));
        let Some(friend) = self.friends.get(new).cloned().filter(|_| at != Some(new)) else {
            return;
        };
        let waiting = self.waiting_ids(&friend);
        if let Some(meet) = self.meet_mut() {
            meet.friend = Some(friend);
            meet.waiting = waiting;
            meet.step = MeetStep::Find(FindState::default());
        }
        self.dirty = true;
    }

    /// Text into step 3's field, as one line of at most [`LINE_FIELD_MAX`]
    /// characters, Persian and Arabic-Indic digits as 0-9 (as CI's).
    fn meet_input(&mut self, text: &str) {
        let add = bridge::fold_code_digits(&display::field_input(text, false));
        if let Some(find) = self.find_mut() {
            for c in add.chars() {
                if find.text.chars().count() >= LINE_FIELD_MAX {
                    break;
                }
                find.text.push(c);
            }
            find.bad = false;
            find.saved = false;
        }
        self.dirty = true;
    }

    /// Backspace in step 3's field.
    fn meet_erase(&mut self) {
        if let Some(find) = self.find_mut() {
            find.text.pop();
            find.bad = false;
            find.saved = false;
        }
        self.dirty = true;
    }

    /// Enter on step 3: the address is checked as `contact set-dial` checks
    /// it, then the store worker saves it for the friend, as CI's E does.
    fn meet_save(&mut self) {
        let Screen::Meet(meet) = &self.screen else {
            return;
        };
        let (Some(pub_hex), MeetStep::Find(find)) = (meet.friend.clone(), &meet.step) else {
            return;
        };
        let parsed = bridge::parse_lan_dial(&find.text);
        let Some(find) = self.find_mut() else {
            return;
        };
        match parsed {
            Ok(address) => {
                find.saving = true;
                self.job(Cmd::Store(StoreJob::SetFriendAddress { pub_hex, address }));
            }
            Err(_) => find.bad = true,
        }
        self.dirty = true;
    }

    /// Step 3's address is saved for the friend `pub_hex`: their messages
    /// waiting here are tried at it now, by one `raven outbox retry` (it has
    /// raven-node try every message waiting for the friend).
    fn meet_saved(&mut self, pub_hex: &str) {
        let Some(find) = self.find_mut().filter(|find| find.saving) else {
            return;
        };
        find.saving = false;
        find.saved = true;
        let text = find.text.trim().to_owned();
        self.edit_contact(pub_hex, |c| c.lan_dial = text);
        let waiting = self
            .outbox
            .values()
            .filter(|item| {
                item.peer_pub_hex.eq_ignore_ascii_case(pub_hex)
                    && matches!(item.state.as_str(), "queued" | "held")
            })
            .map(|item| item.message_id_hex.to_ascii_lowercase())
            .min();
        if let Some(mid) = waiting {
            if let Some(meet) = self.meet_mut() {
                meet.retry = Some(mid.clone());
            }
            self.queue_send_job(SendJob::Retry {
                mid,
                peer: convo_key(pub_hex),
            });
        }
    }

    /// The retry for message `mid` is MEET's own.
    fn meet_asked_retry(&self, mid: &str) -> bool {
        matches!(&self.screen, Screen::Meet(meet) if meet.retry.as_deref() == Some(mid))
    }

    /// MEET's retry answered: step 3 shows how the waiting messages go, so
    /// no toast. While raven-node tries them (`tried`), the poller looks
    /// often.
    fn meet_retry_ended(&mut self, peer: &str, tried: bool) {
        if let Some(meet) = self.meet_mut() {
            meet.retry = None;
        }
        if tried {
            self.cmds.push(Cmd::Poll(PollCtl::Burst {
                peer: peer.to_owned(),
            }));
        }
    }

    /// Step 3 turns into step 4 once a message from the friend arrived, or
    /// one of yours was delivered, after G: what 'in touch' means.
    fn meet_upkeep(&mut self) {
        let Screen::Meet(meet) = &self.screen else {
            return;
        };
        let (MeetStep::Find(_), Some(friend)) = (&meet.step, meet.friend.as_deref()) else {
            return;
        };
        let since = meet.opened;
        let touched = self
            .rows(friend)
            .iter()
            .filter_map(|row| row.touched)
            .any(|touch| touch.at >= since);
        if touched {
            if let Some(meet) = self.meet_mut() {
                meet.step = MeetStep::Connected;
            }
            self.dirty = true;
        }
    }

    // ── Add a friend ────────────────────────────────────────────────────────

    /// AF-1, with the paste box focused. The friend will need this computer's
    /// address, so the background program starts (OD-3; RX first while
    /// receiving was never answered), and my cards are asked for afresh.
    fn open_add_friend(&mut self) {
        self.share = None;
        self.share_asked = None;
        self.set_screen(Screen::AddFriend(Box::new(AddFriendState::new(self.now))));
        self.add_friend_opened();
    }

    fn add_friend_mut(&mut self) -> Option<&mut AddFriendState> {
        match &mut self.screen {
            Screen::AddFriend(add) => Some(add),
            _ => None,
        }
    }

    /// My key (hex), for the paste's own-invite check: no key store.
    fn me_pub_hex(&self) -> String {
        self.me
            .as_ref()
            .map(|me| me.pub_hex.clone())
            .unwrap_or_default()
    }

    /// AF-1's paste box takes text now: a pasted line break goes there.
    fn paste_box_takes_text(&self) -> bool {
        matches!(&self.screen, Screen::AddFriend(add) if !add.naming && add.update.is_none())
            && self.overlays.is_empty()
            && !self.too_small()
    }

    /// Text into AF-1's paste box, parsed at once. It never goes on by
    /// itself: only Enter does, and not within the paste guard.
    fn paste_box_input(&mut self, text: &str) {
        let (me, now) = (self.me_pub_hex(), self.now);
        if let Some(add) = self.add_friend_mut() {
            add.input(text, &me, now);
            self.dirty = true;
        }
    }

    /// AF-1's keys (AF-2's once it is there). Ctrl+C anywhere opens COPY;
    /// Tab switches the box; Esc closes [U]'s question, else goes back to
    /// Home. A text key that follows a paste closely is the rest of it, in
    /// either box: never L, C or S.
    fn on_add_friend_key(&mut self, key: KeyEvent) {
        let Screen::AddFriend(add) = &self.screen else {
            return;
        };
        if add.naming {
            self.on_name_friend_key(key);
            return;
        }
        if is_ctrl(key, 'c') {
            self.open_copy();
            return;
        }
        let (focus, asking, follows) =
            (add.focus, add.update.is_some(), add.follows_input(self.now));
        if let (Some(c), true, false) = (plain_char(key), follows, asking) {
            self.paste_box_input(c.encode_utf8(&mut [0; 4]));
            return;
        }
        match key.code {
            KeyCode::Esc if asking => {
                if let Some(add) = self.add_friend_mut() {
                    add.update = None;
                }
                self.dirty = true;
            }
            KeyCode::Esc => self.set_screen(Screen::Home),
            KeyCode::Tab | KeyCode::BackTab if !has_ctrl_or_alt(key) => {
                if let Some(add) = self.add_friend_mut() {
                    add.focus = match add.focus {
                        AddFocus::Share => AddFocus::Paste,
                        AddFocus::Paste => AddFocus::Share,
                    };
                }
                self.dirty = true;
            }
            _ => match focus {
                AddFocus::Share => self.on_share_key(key),
                AddFocus::Paste => self.on_paste_box_key(key),
            },
        }
    }

    /// The share box: L turns my address in the card on or off (saved), C
    /// opens COPY, S shows my invite without an address where that is
    /// offered, N opens PASSFILE when the background program needs its
    /// passphrase file, ? opens HELP.
    fn on_share_key(&mut self, key: KeyEvent) {
        let Some(view) = self.share_view() else {
            return;
        };
        match plain_char(key) {
            Some('l' | 'L') if matches!(view.state, ShareState::Ready { .. }) => {
                self.settings.include_lan_in_card = !self.settings.include_lan_in_card;
                self.save_settings();
                self.dirty = true;
            }
            Some('c' | 'C') => self.open_copy(),
            // The share box's 'Press N to see how'.
            Some('n' | 'N') if view.state == ShareState::NeedsSetup => {
                self.open_overlay(Overlay::PassFile);
            }
            Some('s' | 'S') if view.offers_anyway() => {
                if let Some(add) = self.add_friend_mut() {
                    add.share_anyway = true;
                }
                self.dirty = true;
            }
            Some('?') => self.open_overlay(Overlay::Help { scroll: 0 }),
            _ => {}
        }
    }

    /// The paste box. Until it parses, typing is text there (Backspace
    /// edits, Ctrl+U empties). Once it holds a friend, Enter goes on to AF-2
    /// (not within the paste guard), Backspace or Ctrl+U starts again, and a
    /// friend already saved has O (open the chat) and U (their new
    /// addresses, after a confirmation code).
    fn on_paste_box_key(&mut self, key: KeyEvent) {
        let (me, now) = (self.me_pub_hex(), self.now);
        let Screen::AddFriend(add) = &self.screen else {
            return;
        };
        if add.update.is_some() {
            self.on_update_code_key(key);
            return;
        }
        if is_ctrl(key, 'u') {
            if let Some(add) = self.add_friend_mut() {
                add.erase(true, &me, now);
            }
            self.dirty = true;
            return;
        }
        let Some(friend) = add.friend().cloned() else {
            match (key.code, plain_char(key)) {
                (_, Some(c)) => self.paste_box_input(c.encode_utf8(&mut [0; 4])),
                (KeyCode::Backspace, _) if !has_ctrl_or_alt(key) => {
                    if let Some(add) = self.add_friend_mut() {
                        add.erase(false, &me, now);
                    }
                    self.dirty = true;
                }
                _ => {}
            }
            return;
        };
        let saved = self.friend(&friend.pub_hex).cloned();
        match (key.code, plain_char(key), saved) {
            (_, Some('o' | 'O'), Some(saved)) => self.open_chat(&saved.pub_hex),
            (_, Some('u' | 'U'), Some(saved)) if routes_differ(&friend, &saved) => {
                if let Some(add) = self.add_friend_mut() {
                    add.update = Some(ConfirmCode::new(false));
                    add.update_error = None;
                }
                self.dirty = true;
            }
            (KeyCode::Backspace | KeyCode::Delete, _, _) => {
                if let Some(add) = self.add_friend_mut() {
                    add.erase(true, &me, now);
                }
                self.dirty = true;
            }
            (_, _, None) if self.confirms(key) => {
                let note = !self.settings.names_note_shown;
                if let Some(add) = self.add_friend_mut() {
                    add.naming = true;
                    add.name_problem = None;
                    add.names_note |= note;
                }
                if note {
                    self.settings.names_note_shown = true;
                    self.save_notes();
                }
                self.dirty = true;
            }
            _ => {}
        }
    }

    /// [U]'s code field: typing is text, Backspace edits, Enter checks it
    /// (not within the paste guard). Right, the new routes are saved; with
    /// letters of another alphabet, the keyboard hint and the same code;
    /// wrong, a new code is drawn.
    fn on_update_code_key(&mut self, key: KeyEvent) {
        let confirms = self.confirms(key);
        let Some(add) = self.add_friend_mut() else {
            return;
        };
        let Some(update) = add.update.as_mut() else {
            return;
        };
        let mut save = None;
        match (key.code, plain_char(key)) {
            (_, Some(c)) => update.type_text(c.encode_utf8(&mut [0; 4])),
            (KeyCode::Backspace, _) if !has_ctrl_or_alt(key) => {
                update.typed.pop();
            }
            _ if confirms && bridge::confirm_code_matches(&update.typed, &update.code) => {
                add.update = None;
                add.updating = true;
                save = add.friend().cloned();
            }
            _ if confirms && bridge::code_has_non_latin_letters(&update.typed) => {
                update.keyboard = true;
            }
            _ if confirms => *update = ConfirmCode::new(true),
            _ => return,
        }
        if let Some(friend) = save {
            self.job(Cmd::Store(StoreJob::UpdateAddresses(friend)));
        }
        self.dirty = true;
    }

    /// The [U] save's answer: saved, the friend's chat opens with a toast;
    /// refused, AF-1 says why in plain words.
    fn addresses_updated(&mut self, pub_hex: &str, result: Result<(), String>) {
        match result {
            Ok(()) => {
                let name = self.shown_name(pub_hex);
                self.push_toast(&format!("Raven saved {name}'s new address."));
                self.load_contacts();
                if matches!(self.screen, Screen::AddFriend(_)) {
                    self.open_chat(pub_hex);
                }
            }
            Err(why) => {
                let plain = errors::explain_contact_add(&why);
                if let Some(add) = self.add_friend_mut() {
                    add.updating = false;
                    add.update_error = Some(plain.headline);
                }
                self.dirty = true;
            }
        }
    }

    /// COPY: my invite on the plain terminal, alone, while one is on show.
    /// The first time, a note says to clear it afterwards (UXF.9).
    fn open_copy(&mut self) {
        let Some(line) = self.share_view().and_then(|view| view.line) else {
            return;
        };
        let note = !self.settings.copy_note_shown;
        self.peeking = true;
        self.cmds.push(Cmd::Peek(add_friend::copy_lines(
            &line,
            cfg!(windows),
            note,
        )));
        if note {
            self.settings.copy_note_shown = true;
            self.save_notes();
        }
    }

    /// Home, with the saved friend `pub_hex`'s conversation open.
    fn open_chat(&mut self, pub_hex: &str) {
        self.set_screen(Screen::Home);
        if let Some(at) = self
            .friends
            .iter()
            .position(|friend| friend.eq_ignore_ascii_case(pub_hex))
        {
            self.highlight = at;
            self.open_highlighted();
        }
    }

    /// AF-2: every letter is text, Backspace edits, Enter checks the name
    /// (not within the paste guard), Esc goes back to AF-1 keeping the paste;
    /// Ctrl+C opens QUIT.
    fn on_name_friend_key(&mut self, key: KeyEvent) {
        if is_ctrl(key, 'c') {
            self.open_overlay(Overlay::Quit);
            return;
        }
        match (key.code, plain_char(key)) {
            (_, Some(c)) => self.type_friend_name(c.encode_utf8(&mut [0; 4])),
            _ if self.confirms(key) => self.name_entered(),
            (KeyCode::Esc, _) => {
                if let Some(add) = self.add_friend_mut() {
                    add.naming = false;
                }
                self.dirty = true;
            }
            (KeyCode::Backspace, _) if !has_ctrl_or_alt(key) => {
                if let Some(add) = self.add_friend_mut() {
                    add.name.pop();
                    add.name_full = false;
                    add.name_problem = None;
                }
                self.dirty = true;
            }
            _ => {}
        }
    }

    /// Adds `text` to AF-2's field as one line without control characters,
    /// until the name fills [`NAME_CELLS`] cells.
    fn type_friend_name(&mut self, text: &str) {
        let Some(add) = self.add_friend_mut() else {
            return;
        };
        for c in display::field_input(text, false).chars() {
            add.name.push(c);
            if display::width(&add.name) > NAME_CELLS {
                add.name.pop();
                add.name_full = true;
                break;
            }
        }
        add.name_problem = None;
        self.dirty = true;
    }

    /// Enter on AF-2: the name against the saved friends'. Taken by a friend
    /// not verified: say so. A verified friend's (or one that looks the same)
    /// on another key: NAME-CLASH, nothing saved. Else the codes are checked
    /// next (VF), which saves the friend.
    fn name_entered(&mut self) {
        let Screen::AddFriend(add) = &self.screen else {
            return;
        };
        let Some(friend) = add.friend() else {
            return;
        };
        match controller::check_name(&self.contacts, &add.name, &friend.pub_hex) {
            NameCheck::Empty => self.set_name_problem(NameProblem::Empty),
            NameCheck::Taken(other) => self.set_name_problem(NameProblem::Taken(other)),
            NameCheck::VerifiedClash(verified) => {
                bridge::note_key_change_attempt(&verified);
                let back = (**add).clone();
                self.set_screen(Screen::NameClash(Box::new(ClashState { back, verified })));
            }
            NameCheck::Free => {
                let add = (**add).clone();
                self.open_verify(VerifyWho::New(Box::new(add)));
            }
        }
    }

    fn set_name_problem(&mut self, problem: NameProblem) {
        if let Some(add) = self.add_friend_mut() {
            add.name_problem = Some(problem);
        }
        self.dirty = true;
    }

    /// NAME-CLASH: O opens the verified friend's page (CI), where X removes
    /// them; Esc goes back to AF-2; Ctrl+C opens QUIT. Nothing is saved from
    /// here.
    fn on_clash_key(&mut self, key: KeyEvent) {
        let Screen::NameClash(clash) = &self.screen else {
            return;
        };
        if is_ctrl(key, 'c') {
            self.open_overlay(Overlay::Quit);
            return;
        }
        match (key.code, plain_char(key)) {
            (KeyCode::Esc, _) => {
                let back = clash.back.clone();
                self.set_screen(Screen::AddFriend(Box::new(back)));
            }
            (_, Some('o' | 'O')) => {
                let verified = clash.verified.clone();
                self.open_friend_page(&verified);
            }
            _ => {}
        }
    }

    // ── Verifying, a friend added, the friend's page ────────────────────────

    /// VF for `who`, typing their security words (Ctrl+O: their old code); a
    /// friend verified already shows both lists, with nothing to do.
    fn open_verify(&mut self, who: VerifyWho) {
        let (verified, open) = match &who {
            VerifyWho::New(_) => (false, false),
            VerifyWho::Saved { pub_hex, .. } => (
                self.friend(pub_hex).is_some_and(|f| f.pinned),
                self.notices_about(pub_hex).next().is_some(),
            ),
        };
        // A verified friend with an open security notice is checked again
        // at once (P6.31), as `raven contact verify` does at a terminal.
        let step = if verified && !open {
            VerifyStep::AlreadyVerified
        } else {
            VerifyStep::Comparing(None)
        };
        self.set_screen(Screen::Verify(Box::new(VerifyState {
            who,
            helper: 0,
            entry: Entry::default(),
            marked: None,
            mismatches: 0,
            step,
        })));
    }

    fn verify_mut(&mut self) -> Option<&mut VerifyState> {
        match &mut self.screen {
            Screen::Verify(vf) => Some(vf),
            _ => None,
        }
    }

    fn set_verify_step(&mut self, step: VerifyStep) {
        if let Some(vf) = self.verify_mut() {
            vf.step = step;
        }
        self.dirty = true;
    }

    /// VF's keys. Typing goes into its field (the friend's words or old
    /// code, then the confirmation code), so no letter or digit is a
    /// shortcut. Enter checks (not within the paste guard, and no more once
    /// VF has stopped). In the words field Tab picks the word suggested; with
    /// nothing typed after the chips (in code mode, and once VF has stopped:
    /// always) it is Later for a friend not saved yet, and back again. Ctrl+O
    /// switches between the words and the old code. Left and Right move the
    /// read-aloud helper over my code (code mode); ? opens HELP; Esc leaves
    /// and saves nothing. While the save runs only Ctrl+C (QUIT) works; after
    /// a failure D shows its details.
    fn on_verify_key(&mut self, key: KeyEvent) {
        if is_ctrl(key, 'c') {
            self.open_overlay(Overlay::Quit);
            return;
        }
        let confirms = self.confirms(key);
        let Screen::Verify(vf) = &self.screen else {
            return;
        };
        let new = matches!(vf.who, VerifyWho::New(_));
        let code = vf.entry.mode == EntryMode::Code;
        let picks = !code && !vf.entry.current.is_empty() && !vf.stopped();
        match (&vf.step, key.code, plain_char(key)) {
            (VerifyStep::Saving { .. }, _, _) => {}
            (VerifyStep::OlderMethod { .. }, KeyCode::Esc, _) => self.keep_newer_method(),
            (_, KeyCode::Esc, _) => self.leave_verify(),
            // Never part of the words or a code.
            (_, _, Some('?')) => self.open_overlay(Overlay::Help { scroll: 0 }),
            (VerifyStep::Failed(_), _, Some('d' | 'D')) => {
                if let Some(VerifyState {
                    step: VerifyStep::Failed(failure),
                    ..
                }) = self.verify_mut()
                {
                    failure.details = !failure.details;
                }
                self.dirty = true;
            }
            (VerifyStep::Failed(_), _, _) => {}
            (VerifyStep::Comparing(_) | VerifyStep::AlreadyVerified, _, _) if is_ctrl(key, 'o') => {
                self.switch_entry();
            }
            (_, KeyCode::Left, _) if code => self.move_helper(-1),
            (_, KeyCode::Right, _) if code => self.move_helper(1),
            (VerifyStep::Comparing(_), KeyCode::Tab, _) if picks => self.verify_pick(),
            (VerifyStep::Comparing(_), KeyCode::Tab, _) if new => {
                self.set_verify_step(VerifyStep::Later(ConfirmCode::new(false)));
            }
            (VerifyStep::Later(_), KeyCode::Tab | KeyCode::BackTab, _) => {
                self.set_verify_step(VerifyStep::Comparing(None));
            }
            (VerifyStep::AlreadyVerified, _, _) if confirms => self.verify_again(),
            (VerifyStep::AlreadyVerified, _, _) => {}
            (_, _, Some(c)) => self.verify_input(c.encode_utf8(&mut [0; 4]), false),
            (_, KeyCode::Backspace, _) if !has_ctrl_or_alt(key) => self.verify_erase(),
            _ if confirms => self.verify_enter(),
            _ => {}
        }
    }

    /// Ctrl+O on VF: the words field becomes the old code's, or back. What
    /// was typed and what the last Enter said go; the count of entries that
    /// were not theirs stays.
    fn switch_entry(&mut self) {
        let Some(vf) = self.verify_mut() else {
            return;
        };
        let mode = match vf.entry.mode {
            EntryMode::Words => EntryMode::Code,
            EntryMode::Code => EntryMode::Words,
        };
        vf.entry = Entry {
            mode,
            ..Entry::default()
        };
        vf.marked = None;
        if let VerifyStep::Comparing(problem) = &mut vf.step {
            *problem = None;
        }
        self.dirty = true;
    }

    /// Tab in the words field: the word suggested becomes a chip. One that
    /// can't (no Raven word, or the start of several) says why.
    fn verify_pick(&mut self) {
        let Some(vf) = self.verify_mut() else {
            return;
        };
        let VerifyStep::Comparing(problem) = &mut vf.step else {
            return;
        };
        *problem = if vf.entry.chip() {
            None
        } else {
            vf.entry.word_problem().map(CodeProblem::Words)
        };
        self.dirty = true;
    }

    /// Text into VF's field, typed or `pasted`. In the words field: letters,
    /// the words they make, and why a word that ended is not a Raven word
    /// ([`Entry::type_words`]). Of the friend's code only letters and digits
    /// are kept (the field draws the groups itself), Persian and Arabic-Indic
    /// digits as 0-9; a group that comes to be complete gets its mark. A
    /// change clears what the last Enter said. Letters of another alphabet
    /// are not kept: they bring the keyboard hint, which stays until a Latin
    /// letter comes.
    fn verify_input(&mut self, text: &str, pasted: bool) {
        let now = self.now;
        let Screen::Verify(vf) = &self.screen else {
            return;
        };
        let expected = self.expected_code(vf).unwrap_or_default();
        let Some(vf) = self.verify_mut() else {
            return;
        };
        match &mut vf.step {
            VerifyStep::Comparing(problem) if vf.entry.mode == EntryMode::Words => {
                let (other, said) = vf.entry.type_words(text, pasted);
                let latin = text
                    .chars()
                    .any(|c| matches!(word_char(c), WordChar::Letter(_)));
                let keyboard = other || (*problem == Some(CodeProblem::Keyboard) && !latin);
                *problem = if keyboard {
                    Some(CodeProblem::Keyboard)
                } else {
                    said.map(CodeProblem::Words)
                };
            }
            VerifyStep::Comparing(problem) => {
                let marked = |typed: &str| {
                    code_marks(typed, &expected)
                        .iter()
                        .filter(|(_, mark)| mark.is_some())
                        .count()
                };
                let before = marked(&vf.entry.code);
                let text = bridge::fold_code_digits(text);
                for c in text.chars().filter(char::is_ascii_alphanumeric) {
                    if vf.entry.code.len() >= SECURITY_CODE_MAX {
                        break;
                    }
                    vf.entry.code.push(c);
                }
                let keyboard = bridge::code_has_non_latin_letters(&text)
                    || (*problem == Some(CodeProblem::Keyboard)
                        && !text.chars().any(|c| c.is_ascii_alphabetic()));
                *problem = keyboard.then_some(CodeProblem::Keyboard);
                let after = marked(&vf.entry.code);
                if after > before {
                    vf.marked = Some((after - 1, now));
                }
            }
            VerifyStep::Matched { confirm, .. } | VerifyStep::Later(confirm) => {
                confirm.type_text(text);
            }
            // The word must be typed: a paste clears it.
            VerifyStep::OlderMethod { typed } if pasted => typed.clear(),
            VerifyStep::OlderMethod { typed } => {
                for c in text.chars().filter(|c| !c.is_control()) {
                    if typed.chars().count() < LINE_FIELD_MAX {
                        typed.push(c);
                    }
                }
            }
            _ => return,
        }
        self.dirty = true;
    }

    /// Backspace in VF's field. The keyboard hint stays: erasing doesn't
    /// change the keyboard.
    fn verify_erase(&mut self) {
        let Some(vf) = self.verify_mut() else {
            return;
        };
        match &mut vf.step {
            VerifyStep::Comparing(problem) => {
                vf.entry.erase();
                vf.marked = None;
                if *problem != Some(CodeProblem::Keyboard) {
                    *problem = None;
                }
            }
            VerifyStep::Matched { confirm, .. } | VerifyStep::Later(confirm) => {
                confirm.typed.pop();
            }
            VerifyStep::OlderMethod { typed } => {
                typed.pop();
            }
            _ => return,
        }
        self.dirty = true;
    }

    /// Left (`by` -1) or Right: the read-aloud helper spells another group
    /// of my code.
    fn move_helper(&mut self, by: isize) {
        let groups = self
            .me
            .as_ref()
            .map_or(0, |me| wizard::code_groups(&me.fingerprint).len());
        let Some(vf) = self.verify_mut() else {
            return;
        };
        let new = vf
            .helper
            .saturating_add_signed(by)
            .min(groups.saturating_sub(1));
        if new != vf.helper {
            vf.helper = new;
            self.dirty = true;
        }
    }

    /// Enter on VF. Comparing: what is typed against the friend's key as
    /// cli.rs compares them (the words field through [`bridge::words_check`],
    /// the old code through [`bridge::security_check`], where case counts).
    /// A match shows their words and code and asks for a fresh confirmation
    /// code. Words that are not 10 valid ones say why (that depends only on
    /// what was typed); else the keyboard hint (letters of another alphabet
    /// were typed), the case hint or the mismatch, and nothing is saved.
    /// After [`MAX_MISMATCHES`] entries that were not theirs (the case hint
    /// counts), Enter checks no more. On a confirmation question the right
    /// code saves (with the pin only after the match, checked once more);
    /// letters of another alphabet keep the code and what is typed, with the
    /// keyboard hint; a wrong code draws a new one.
    fn verify_enter(&mut self) {
        let now = self.now;
        let Screen::Verify(vf) = &self.screen else {
            return;
        };
        if matches!(vf.step, VerifyStep::OlderMethod { .. }) {
            return self.older_method_enter();
        }
        let Some(key) = self.expected_key(vf) else {
            return;
        };
        let typed = vf.entry.text();
        let check = match vf.entry.mode {
            EntryMode::Words => bridge::words_check(&typed, &key),
            EntryMode::Code => bridge::security_check(&typed, &key),
        };
        let matches = check == bridge::SecurityCheck::Match;
        let confirm = match &vf.step {
            VerifyStep::Comparing(_) if typed.is_empty() || vf.stopped() => return,
            // "Check again" (P6.31): a match resolves the friend's notices
            // at once; nothing is saved, so no confirmation code.
            VerifyStep::Comparing(_) if matches && self.rechecking(vf) => {
                let VerifyWho::Saved { pub_hex, .. } = &vf.who else {
                    return;
                };
                let job = StoreJob::Recheck {
                    pub_hex: pub_hex.clone(),
                    typed,
                };
                self.set_verify_step(VerifyStep::Saving { verified: true });
                self.job(Cmd::Store(job));
                return;
            }
            VerifyStep::Comparing(problem) => {
                let keyboard = *problem == Some(CodeProblem::Keyboard);
                let (step, mismatch) = match check {
                    bridge::SecurityCheck::Match => (
                        VerifyStep::Matched {
                            at: now,
                            confirm: ConfirmCode::new(false),
                        },
                        false,
                    ),
                    _ if keyboard => (VerifyStep::Comparing(Some(CodeProblem::Keyboard)), false),
                    bridge::SecurityCheck::Invalid(why) => {
                        (VerifyStep::Comparing(Some(CodeProblem::Words(why))), false)
                    }
                    bridge::SecurityCheck::CodeCaseOnly => {
                        (VerifyStep::Comparing(Some(CodeProblem::CaseOnly)), true)
                    }
                    bridge::SecurityCheck::Mismatch => {
                        (VerifyStep::Comparing(Some(CodeProblem::Mismatch)), true)
                    }
                };
                if let Some(vf) = self.verify_mut().filter(|_| mismatch) {
                    vf.mismatches = vf.mismatches.saturating_add(1);
                }
                return self.set_verify_step(step);
            }
            VerifyStep::Matched { confirm, .. } | VerifyStep::Later(confirm) => confirm,
            _ => return,
        };
        if confirm.typed.is_empty() {
            return;
        }
        let verified = matches!(vf.step, VerifyStep::Matched { .. });
        if !bridge::confirm_code_matches(&confirm.typed, &confirm.code) {
            if bridge::code_has_non_latin_letters(&confirm.typed) {
                if let Some(VerifyState {
                    step: VerifyStep::Matched { confirm, .. } | VerifyStep::Later(confirm),
                    ..
                }) = self.verify_mut()
                {
                    confirm.keyboard = true;
                }
                self.dirty = true;
                return;
            }
            let step = match &vf.step {
                VerifyStep::Matched { at, .. } => VerifyStep::Matched {
                    at: *at,
                    confirm: ConfirmCode::new(true),
                },
                _ => VerifyStep::Later(ConfirmCode::new(true)),
            };
            return self.set_verify_step(step);
        }
        if verified && !matches {
            return self.set_verify_step(VerifyStep::Comparing(Some(CodeProblem::Mismatch)));
        }
        let job = match &vf.who {
            VerifyWho::New(add) => {
                let Some(friend) = add.friend().cloned() else {
                    return;
                };
                let verify = if verified {
                    Verify::Pinned { typed_fp: typed }
                } else {
                    Verify::Unpinned
                };
                StoreJob::SaveFriend {
                    friend,
                    name: add.name.trim().to_owned(),
                    verify,
                }
            }
            VerifyWho::Saved { pub_hex, .. } if verified => StoreJob::VerifyExisting {
                pub_hex: pub_hex.clone(),
                typed_fp: typed,
            },
            // A saved friend has no Later: they are saved already.
            VerifyWho::Saved { .. } => return,
        };
        self.set_verify_step(VerifyStep::Saving { verified });
        self.job(Cmd::Store(job));
    }

    /// Esc on VF: nothing is saved. A friend from AF-2 goes back to it as it
    /// was; a saved one to where VF was opened.
    fn leave_verify(&mut self) {
        let Screen::Verify(vf) = &self.screen else {
            return;
        };
        match &vf.who {
            VerifyWho::New(add) => {
                let add = add.clone();
                self.set_screen(Screen::AddFriend(add));
            }
            VerifyWho::Saved {
                pub_hex,
                back: Back::FriendPage,
            } => {
                let pub_hex = pub_hex.clone();
                self.open_friend_page(&pub_hex);
            }
            VerifyWho::Saved {
                back: Back::Home, ..
            } => self.set_screen(Screen::Home),
        }
    }

    /// A change to a friend saved, or refused. Saved: the friends are loaded
    /// again and what changed shows at once, and the screen moves on (AF-3
    /// for a new friend, the page for one verified, Home after a removal).
    /// Refused: the screen that asked says why, in plain words.
    fn friend_changed(
        &mut self,
        change: FriendChange,
        pub_hex: &str,
        result: Result<(), String>,
        notes: Vec<String>,
    ) {
        if let Err(why) = result {
            self.change_failed(errors::explain_contact_add(&why));
            return;
        }
        self.load_contacts();
        // MEET's step 3 saved it: the guide says so itself.
        if change == FriendChange::Address && matches!(self.screen, Screen::Meet(_)) {
            self.meet_saved(pub_hex);
            return;
        }
        let name = self.shown_name(pub_hex);
        let edit = match &self.screen {
            Screen::FriendPage(page) => page.edit.clone(),
            _ => None,
        };
        match (change, edit) {
            (FriendChange::Add, _) => self.friend_added(),
            (FriendChange::Verify, _) => {
                self.edit_contact(pub_hex, |c| c.pinned = true);
                if matches!(self.screen, Screen::Verify(_)) {
                    self.open_friend_page(pub_hex);
                }
                // What the match resolved of their security notices.
                if let Some(note) = notes.first() {
                    self.push_toast(note);
                    self.load_security();
                }
            }
            (FriendChange::Rename, edit) => {
                if let Some(PageEdit::Rename { name, .. }) = edit {
                    self.edit_contact(pub_hex, |c| c.label = name.trim().to_owned());
                }
                self.page_saved();
                self.push_toast("Raven saved the new name.");
            }
            (FriendChange::Address, edit) => {
                if let Some(PageEdit::Address { text, .. }) = edit {
                    self.edit_contact(pub_hex, |c| c.lan_dial = text.trim().to_owned());
                }
                self.page_saved();
                self.push_toast(&format!("Raven saved {name}'s new address."));
            }
            (FriendChange::Remove, _) => {
                self.contacts
                    .retain(|c| !c.pub_hex.eq_ignore_ascii_case(pub_hex));
                self.set_friends(self.contacts.iter().map(|c| c.pub_hex.clone()).collect());
                if matches!(self.screen, Screen::FriendPage(_)) {
                    self.set_screen(Screen::Home);
                }
                self.push_toast(&format!("Removed {name}. Your messages with them stay."));
            }
            (FriendChange::Unblock, _) => {
                self.edit_contact(pub_hex, |c| c.blocked = false);
                self.page_saved();
                self.push_toast(&format!("{name} is unblocked."));
            }
            (FriendChange::ForgetAddress, _) => {
                self.edit_contact(pub_hex, |c| {
                    c.lan_dial.clear();
                    c.internet_dial.clear();
                });
                self.page_saved();
                if notes.is_empty() {
                    self.push_toast(&format!("Raven forgot {name}'s saved address."));
                } else {
                    // Review D-lock-tui-8: part of what Raven learned about
                    // reaching them is still on disk; the page says so, with
                    // the notes in Details.
                    self.change_partly_done(errors::explain_forget_partial(&name, &notes));
                }
            }
        }
    }

    /// A change saved, but not in full: the friend page shows it as it shows
    /// a failure ([D] Details); any other screen gets the headline as a
    /// toast.
    fn change_partly_done(&mut self, plain: Plain) {
        let details = self.settings.show_details;
        match self.page_mut() {
            Some(page) => page.failure = Some(Failure::new(plain, details)),
            None => self.push_toast(&plain.headline),
        }
        self.dirty = true;
    }

    /// The friend from VF is saved: AF-3, with the friend in the list at
    /// once (the load asked for brings the file's own row). If no background
    /// program runs yet, it starts now, as OD-3 and OD-18 allow.
    fn friend_added(&mut self) {
        let Screen::Verify(vf) = &self.screen else {
            return;
        };
        let (VerifyWho::New(add), VerifyStep::Saving { verified }) = (&vf.who, &vf.step) else {
            return;
        };
        let Some(friend) = add.friend() else {
            return;
        };
        let name = add.name.trim().to_owned();
        let view = ContactView {
            pub_hex: friend.pub_hex.to_ascii_lowercase(),
            address: friend.address.clone(),
            label: name.clone(),
            tag: String::new(),
            fingerprint: friend.fingerprint.clone(),
            pinned: *verified,
            blocked: false,
            lan_dial: friend.lan.clone(),
            internet_dial: friend.internet.clone(),
            p2p: friend
                .p2p
                .as_ref()
                .map(|p2p| p2p.peer_id.clone())
                .unwrap_or_default(),
            tor: *verified && friend.onion.is_some(),
            learned: false,
        };
        let added = AddedState {
            pub_hex: view.pub_hex.clone(),
            name,
            verified: *verified,
            at: self.now,
        };
        match self
            .contacts
            .iter_mut()
            .find(|c| c.pub_hex.eq_ignore_ascii_case(&view.pub_hex))
        {
            Some(saved) => *saved = view,
            None => self.contacts.push(view),
        }
        self.set_friends(self.contacts.iter().map(|c| c.pub_hex.clone()).collect());
        self.set_screen(Screen::Added(added));
        self.request_auto_start(AutoStart::AddFriend);
    }

    /// A change to a friend failed (or its job did): the screen that asked
    /// says why; any other, a toast.
    fn change_failed(&mut self, plain: Plain) {
        let details = self.settings.show_details;
        match &mut self.screen {
            Screen::Verify(vf) if matches!(vf.step, VerifyStep::Saving { .. }) => {
                vf.step = VerifyStep::Failed(Failure::new(plain, details));
            }
            Screen::FriendPage(page) if page.saving => {
                page.saving = false;
                page.edit = None;
                page.failure = Some(Failure::new(plain, details));
            }
            // MEET keeps the address as typed: Enter tries again.
            Screen::Meet(meet) => {
                if let MeetStep::Find(find) = &mut meet.step {
                    find.saving = false;
                }
                self.push_toast(&plain.headline);
            }
            _ => self.push_toast(&plain.headline),
        }
        self.dirty = true;
    }

    /// The saved friend `pub_hex` as a saved change left them, until the
    /// load asked for brings the file's row.
    fn edit_contact(&mut self, pub_hex: &str, edit: impl FnOnce(&mut ContactView)) {
        if let Some(friend) = self
            .contacts
            .iter_mut()
            .find(|c| c.pub_hex.eq_ignore_ascii_case(pub_hex))
        {
            edit(friend);
        }
        self.dirty = true;
    }

    /// AF-3: Enter opens the chat (not within the paste guard), 1 shows my
    /// invite (AF-1's share box), A adds another friend, ? opens HELP, Esc
    /// goes Home; Ctrl+C opens QUIT.
    fn on_added_key(&mut self, key: KeyEvent) {
        if is_ctrl(key, 'c') {
            self.open_overlay(Overlay::Quit);
            return;
        }
        let Screen::Added(added) = &self.screen else {
            return;
        };
        let pub_hex = added.pub_hex.clone();
        match (key.code, plain_char(key)) {
            (_, Some('1')) => {
                self.open_add_friend();
                if let Some(add) = self.add_friend_mut() {
                    add.focus = AddFocus::Share;
                }
            }
            (_, Some('a' | 'A')) => self.open_add_friend(),
            (_, Some('?')) => self.open_overlay(Overlay::Help { scroll: 0 }),
            (KeyCode::Esc, _) => self.set_screen(Screen::Home),
            _ if self.confirms(key) => self.open_chat(&pub_hex),
            _ => {}
        }
    }

    /// CI for the saved friend `pub_hex`, with no field open.
    fn open_friend_page(&mut self, pub_hex: &str) {
        self.set_screen(Screen::FriendPage(Box::new(PageState {
            pub_hex: pub_hex.to_owned(),
            edit: None,
            saving: false,
            failure: None,
        })));
    }

    fn page_mut(&mut self) -> Option<&mut PageState> {
        match &mut self.screen {
            Screen::FriendPage(page) => Some(page),
            _ => None,
        }
    }

    /// CI's keys. With no field open: R renames, E edits the local-network
    /// address, V verifies (VF), X asks before removing, U unblocks (only
    /// while blocked), D shows a failure's details, ? opens HELP, Esc goes
    /// Home. In a field typing is text, Enter saves (not within the paste
    /// guard) and Esc closes it. While a change is saved only Ctrl+C (QUIT)
    /// works.
    fn on_page_key(&mut self, key: KeyEvent) {
        if is_ctrl(key, 'c') {
            self.open_overlay(Overlay::Quit);
            return;
        }
        let Screen::FriendPage(page) = &self.screen else {
            return;
        };
        if page.saving {
            return;
        }
        if page.edit.is_some() {
            self.on_page_edit_key(key);
            return;
        }
        let pub_hex = page.pub_hex.clone();
        let failed = page.failure.is_some();
        let Some(friend) = self.friend(&pub_hex).cloned() else {
            // Not saved any more: only the way back.
            if key.code == KeyCode::Esc {
                self.set_screen(Screen::Home);
            }
            return;
        };
        match (key.code, plain_char(key)) {
            (KeyCode::Esc, _) => self.set_screen(Screen::Home),
            (_, Some('?')) => self.open_overlay(Overlay::Help { scroll: 0 }),
            (_, Some('d' | 'D')) if failed => {
                if let Some(failure) = self.page_mut().and_then(|page| page.failure.as_mut()) {
                    failure.details = !failure.details;
                }
                self.dirty = true;
            }
            (_, Some('r' | 'R')) => self.open_page_edit(PageEdit::Rename {
                name: String::new(),
                full: false,
                problem: None,
            }),
            (_, Some('e' | 'E')) => self.open_page_edit(PageEdit::Address {
                text: String::new(),
                bad: false,
            }),
            (_, Some('v' | 'V')) => self.open_verify(VerifyWho::Saved {
                pub_hex,
                back: Back::FriendPage,
            }),
            (_, Some('x' | 'X')) => self.open_page_edit(PageEdit::Remove {
                typed: String::new(),
            }),
            (_, Some('u' | 'U')) if friend.blocked => {
                self.page_saving();
                self.job(Cmd::Store(StoreJob::UnblockFriend { pub_hex }));
            }
            (_, Some('c' | 'C')) if self.privacy.is_some() => {
                self.open_overlay(Overlay::DeleteChat {
                    peer: convo_key(&pub_hex),
                    typed: String::new(),
                });
            }
            (_, Some('f' | 'F')) if self.privacy.is_some() => {
                self.open_overlay(Overlay::ForgetAddress {
                    peer: convo_key(&pub_hex),
                });
            }
            (_, Some('w' | 'W')) => self.open_security(Some(&pub_hex)),
            (_, Some('p' | 'P')) => self.toggle_pause(&pub_hex),
            _ => {}
        }
    }

    fn open_page_edit(&mut self, edit: PageEdit) {
        if let Some(page) = self.page_mut() {
            page.edit = Some(edit);
            page.failure = None;
        }
        self.dirty = true;
    }

    /// A field on CI: Esc closes it, typing is text, Backspace edits, Enter
    /// saves.
    fn on_page_edit_key(&mut self, key: KeyEvent) {
        match (key.code, plain_char(key)) {
            (KeyCode::Esc, _) => {
                if let Some(page) = self.page_mut() {
                    page.edit = None;
                }
                self.dirty = true;
            }
            (_, Some(c)) => self.page_input(c.encode_utf8(&mut [0; 4])),
            (KeyCode::Backspace, _) if !has_ctrl_or_alt(key) => self.page_erase(),
            _ if self.confirms(key) => self.page_enter(),
            _ => {}
        }
    }

    /// Text into CI's open field, as one line: a name up to [`NAME_CELLS`]
    /// cells, an address (Persian and Arabic-Indic digits as 0-9) or
    /// 'remove' up to [`LINE_FIELD_MAX`] characters.
    fn page_input(&mut self, text: &str) {
        let add = display::field_input(text, false);
        let Some(edit) = self.page_mut().and_then(|page| page.edit.as_mut()) else {
            return;
        };
        let line = |field: &mut String, add: &str| {
            for c in add.chars() {
                if field.chars().count() >= LINE_FIELD_MAX {
                    break;
                }
                field.push(c);
            }
        };
        match edit {
            PageEdit::Rename {
                name,
                full,
                problem,
            } => {
                for c in add.chars() {
                    name.push(c);
                    if display::width(name) > NAME_CELLS {
                        name.pop();
                        *full = true;
                        break;
                    }
                }
                *problem = None;
            }
            PageEdit::Address { text, bad } => {
                line(text, &bridge::fold_code_digits(&add));
                *bad = false;
            }
            PageEdit::Remove { typed } => line(typed, &add),
        }
        self.dirty = true;
    }

    /// Backspace in CI's open field.
    fn page_erase(&mut self) {
        let Some(edit) = self.page_mut().and_then(|page| page.edit.as_mut()) else {
            return;
        };
        match edit {
            PageEdit::Rename {
                name,
                full,
                problem,
            } => {
                name.pop();
                *full = false;
                *problem = None;
            }
            PageEdit::Address { text, bad } => {
                text.pop();
                *bad = false;
            }
            PageEdit::Remove { typed } => {
                typed.pop();
            }
        }
        self.dirty = true;
    }

    /// Enter in CI's open field. A name is checked as AF-2 checks one (a
    /// friend's, verified or not, is taken); an address as `contact
    /// set-dial` checks it; 'remove' must be typed. Then the store worker
    /// saves it.
    fn page_enter(&mut self) {
        let Screen::FriendPage(page) = &self.screen else {
            return;
        };
        let pub_hex = page.pub_hex.clone();
        let job = match &page.edit {
            Some(PageEdit::Rename { name, .. }) => {
                match controller::check_name(&self.contacts, name, &pub_hex) {
                    NameCheck::Free => StoreJob::RenameFriend {
                        name: name.trim().to_owned(),
                        pub_hex,
                    },
                    NameCheck::Empty => return self.set_rename_problem(NameProblem::Empty),
                    NameCheck::Taken(other) | NameCheck::VerifiedClash(other) => {
                        return self.set_rename_problem(NameProblem::Taken(other))
                    }
                }
            }
            Some(PageEdit::Address { text, .. }) => match bridge::parse_lan_dial(text) {
                Ok(address) => StoreJob::SetFriendAddress { pub_hex, address },
                Err(_) => {
                    if let Some(PageEdit::Address { bad, .. }) =
                        self.page_mut().and_then(|page| page.edit.as_mut())
                    {
                        *bad = true;
                    }
                    self.dirty = true;
                    return;
                }
            },
            Some(PageEdit::Remove { typed }) if typed.trim().eq_ignore_ascii_case(REMOVE_WORD) => {
                StoreJob::RemoveFriend { pub_hex }
            }
            _ => return,
        };
        self.page_saving();
        self.job(Cmd::Store(job));
    }

    fn set_rename_problem(&mut self, problem: NameProblem) {
        if let Some(PageEdit::Rename { problem: was, .. }) =
            self.page_mut().and_then(|page| page.edit.as_mut())
        {
            *was = Some(problem);
        }
        self.dirty = true;
    }

    /// CI's change goes to the store worker: the keys wait for it.
    fn page_saving(&mut self) {
        if let Some(page) = self.page_mut() {
            page.saving = true;
            page.failure = None;
        }
        self.dirty = true;
    }

    /// CI's change is saved: its field closes.
    fn page_saved(&mut self) {
        if let Some(page) = self.page_mut() {
            page.saving = false;
            page.edit = None;
        }
        self.dirty = true;
    }

    // ── Security notices (Phase 6b P6.31) ───────────────────────────────────

    /// Reads the security notices and the paused friends on the store
    /// worker, once the identity exists and no read runs (else as soon as
    /// that is so).
    fn load_security(&mut self) {
        if self.identity != IdentityStatus::Ready || self.security_loading {
            self.security_due = true;
            return;
        }
        self.security_loading = true;
        self.security_due = false;
        self.job(Cmd::Store(StoreJob::LoadSecurity));
    }

    /// The read answered: it replaces the last one whole. Not available
    /// (no identity yet, or the read failed) keeps what was shown.
    fn security_read(&mut self, read: Result<SecurityView, NotAvailable>) {
        self.security_loading = false;
        if let Ok(read) = read {
            if self.security.as_ref() != Some(&read) {
                self.security = Some(read);
                self.dirty = true;
            }
        }
        // SEC's choice stays inside the list as it is now.
        let shown = self.notices().len();
        if let Some(Overlay::Security(sec)) = self.overlays.last_mut() {
            sec.chosen = sec.chosen.min(shown.saturating_sub(1));
        }
        if self.security_due {
            self.load_security();
        }
    }

    /// The security notices and paused friends as last read; None before
    /// the first read answered.
    pub(super) fn security(&self) -> Option<&SecurityView> {
        self.security.as_ref()
    }

    /// The open alerts and warnings, the most severe and the latest first.
    pub(super) fn notices(&self) -> &[SecNotice] {
        self.security
            .as_ref()
            .map_or(&[], |read| read.notices.as_slice())
    }

    /// The open notices about the friend `pub_hex`, most severe first.
    pub(super) fn notices_about<'a>(
        &'a self,
        pub_hex: &'a str,
    ) -> impl Iterator<Item = &'a SecNotice> + 'a {
        self.notices().iter().filter(move |notice| {
            notice
                .peer
                .as_deref()
                .is_some_and(|peer| peer.eq_ignore_ascii_case(pub_hex.trim()))
        })
    }

    /// Sending to the friend `pub_hex` is paused (P: their outbox hold).
    pub(super) fn paused(&self, pub_hex: &str) -> bool {
        self.security.as_ref().is_some_and(|read| {
            read.paused
                .iter()
                .any(|held| held.eq_ignore_ascii_case(pub_hex.trim()))
        })
    }

    /// The security events about the friend `pub_hex` the last 7 days
    /// counted, or how many notices about them are open when that is more
    /// (a count not written yet).
    pub(super) fn problems_this_week(&self, pub_hex: &str) -> u64 {
        let counted = self.security.as_ref().map_or(0, |read| {
            read.week
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(pub_hex.trim()))
                .map_or(0, |(_, n)| *n)
        });
        let open = u64::try_from(self.notices_about(pub_hex).count()).unwrap_or(u64::MAX);
        counted.max(open)
    }

    /// P offers itself for the friend `pub_hex`: a notice about them is
    /// open, or sending to them is paused (so it can always be resumed).
    pub(super) fn pause_offered(&self, pub_hex: &str) -> bool {
        self.paused(pub_hex) || self.notices_about(pub_hex).next().is_some()
    }

    /// SEC, its choice on the first notice about `about` (else the first).
    fn open_security(&mut self, about: Option<&str>) {
        let chosen = about
            .and_then(|key| {
                self.notices().iter().position(|notice| {
                    notice
                        .peer
                        .as_deref()
                        .is_some_and(|peer| peer.eq_ignore_ascii_case(key))
                })
            })
            .unwrap_or(0);
        self.open_overlay(Overlay::Security(SecState {
            chosen,
            details: false,
        }));
    }

    /// SEC's keys: Up and Down (or k and j) choose a notice, D shows its
    /// details, R resolves it, V compares security words with the friend it
    /// is about (a saved one), Esc or W closes; Ctrl+C opens QUIT.
    fn on_security_key(&mut self, key: KeyEvent, sec: SecState) {
        if is_ctrl(key, 'c') {
            self.open_overlay(Overlay::Quit);
            return;
        }
        let count = self.notices().len();
        let chosen = self.notices().get(sec.chosen).cloned();
        let set = |app: &mut App, new: SecState| {
            if let Some(Overlay::Security(open)) = app.overlays.last_mut() {
                if *open != new {
                    *open = new;
                    app.dirty = true;
                }
            }
        };
        match (key.code, plain_char(key)) {
            (KeyCode::Esc, _) | (_, Some('w' | 'W')) => self.close_overlay(),
            (KeyCode::Up, _) | (_, Some('k')) => set(
                self,
                SecState {
                    chosen: sec.chosen.saturating_sub(1),
                    details: false,
                },
            ),
            (KeyCode::Down, _) | (_, Some('j')) => set(
                self,
                SecState {
                    chosen: (sec.chosen + 1).min(count.saturating_sub(1)),
                    details: false,
                },
            ),
            (_, Some('d' | 'D')) if chosen.is_some() => set(
                self,
                SecState {
                    details: !sec.details,
                    ..sec
                },
            ),
            (_, Some('r' | 'R')) => {
                if let Some(notice) = chosen {
                    self.job(Cmd::Store(StoreJob::ResolveNotice { id: notice.id }));
                }
            }
            (_, Some('v' | 'V')) => {
                let saved = chosen
                    .and_then(|notice| notice.peer)
                    .filter(|peer| self.friend(peer).is_some());
                if let Some(pub_hex) = saved {
                    self.close_overlay();
                    self.open_verify(VerifyWho::Saved {
                        pub_hex,
                        back: Back::Home,
                    });
                }
            }
            _ => {}
        }
    }

    /// R answered: what is open is read again (a notice resolved somewhere
    /// else meanwhile is gone either way).
    fn notice_resolved(&mut self, result: Result<bool, String>) {
        if let Err(why) = result {
            self.push_toast(&errors::explain_security(NOT_RESOLVED, &why).headline);
        }
        self.load_security();
    }

    /// P on the friend `pub_hex`: sending to them is paused, or resumed if
    /// it was (never by itself). Only while a notice about them is open or
    /// it is paused.
    fn toggle_pause(&mut self, pub_hex: &str) {
        if !self.pause_offered(pub_hex) {
            return;
        }
        let on = !self.paused(pub_hex);
        self.job(Cmd::Store(StoreJob::SetSendHold {
            pub_hex: convo_key(pub_hex),
            on,
        }));
    }

    /// P answered: the paused friends as they are now, and a toast saying
    /// what changed.
    fn send_hold_set(&mut self, pub_hex: &str, on: bool, result: Result<bool, String>) {
        let name = self.shown_name(pub_hex);
        match result {
            Ok(paused) => {
                if let Some(read) = self.security.as_mut() {
                    let key = convo_key(pub_hex);
                    read.paused.retain(|held| *held != key);
                    if paused {
                        read.paused.push(key);
                    }
                }
                self.dirty = true;
                self.push_toast(&if paused {
                    format!("Sending to {name} is paused. Press P again to resume.")
                } else {
                    format!("Sending to {name} is on again.")
                });
            }
            Err(why) => {
                let headline = if on {
                    format!("Raven couldn't pause sending to {name}.")
                } else {
                    format!("Raven couldn't resume sending to {name}.")
                };
                self.push_toast(&errors::explain_security(&headline, &why).headline);
            }
        }
        self.load_security();
    }

    /// VF's "Check again" (Enter on a verified friend): their words are
    /// compared again, from an empty field.
    fn verify_again(&mut self) {
        let Some(vf) = self.verify_mut() else {
            return;
        };
        vf.entry = Entry {
            mode: vf.entry.mode,
            ..Entry::default()
        };
        vf.marked = None;
        self.set_verify_step(VerifyStep::Comparing(None));
    }

    /// VF is checking a verified friend again: a match resolves their
    /// notices, and nothing is saved.
    fn rechecking(&self, vf: &VerifyState) -> bool {
        matches!(&vf.who, VerifyWho::Saved { pub_hex, .. }
            if self.friend(pub_hex).is_some_and(|friend| friend.pinned))
    }

    /// "Check again" answered. The older method may be accepted: VF asks
    /// for 'accept'. Otherwise the friend's page, and a toast with what the
    /// match resolved.
    fn rechecked(&mut self, pub_hex: &str, result: Result<Resolved, String>) {
        let resolved = match result {
            Ok(resolved) => resolved,
            Err(why) => {
                return self.change_failed(errors::explain_security(NOT_RESOLVED, &why));
            }
        };
        self.load_security();
        let name = self.shown_name(pub_hex);
        let toast = if resolved.notices > 0 {
            format!(
                "They match. {}",
                bridge::resolved_by_verify(&name, resolved.notices)
            )
        } else {
            format!("They match. Nothing about {name} was open.")
        };
        if !matches!(self.screen, Screen::Verify(_)) {
            self.push_toast(&toast);
            return;
        }
        if resolved.older_method {
            self.push_toast(&toast);
            self.set_verify_step(VerifyStep::OlderMethod {
                typed: String::new(),
            });
            return;
        }
        self.open_friend_page(pub_hex);
        self.push_toast(&toast);
    }

    /// Enter on VF's older-method question: 'accept' typed accepts it (the
    /// words typed for the match go along); anything else keeps the newer
    /// one.
    fn older_method_enter(&mut self) {
        let Screen::Verify(vf) = &self.screen else {
            return;
        };
        let (VerifyWho::Saved { pub_hex, .. }, VerifyStep::OlderMethod { typed }) =
            (&vf.who, &vf.step)
        else {
            return;
        };
        if !typed_word_is(typed, ACCEPT_WORD) {
            return self.keep_newer_method();
        }
        let job = StoreJob::AcceptOlderMethod {
            pub_hex: pub_hex.clone(),
            typed: vf.entry.text(),
        };
        self.set_verify_step(VerifyStep::Saving { verified: true });
        self.job(Cmd::Store(job));
    }

    /// Esc (or Enter without 'accept') on the older-method question: the
    /// newer one stays expected; the friend's page.
    fn keep_newer_method(&mut self) {
        let Screen::Verify(vf) = &self.screen else {
            return;
        };
        let VerifyWho::Saved { pub_hex, .. } = &vf.who else {
            return;
        };
        let pub_hex = pub_hex.clone();
        let name = self.shown_name(&pub_hex);
        self.open_friend_page(&pub_hex);
        self.push_toast(&bridge::floor_kept(&name));
    }

    /// The older method accepted (or why not): the friend's page.
    fn older_method_accepted(&mut self, pub_hex: &str, result: Result<bool, String>) {
        if let Err(why) = result {
            let name = self.shown_name(pub_hex);
            let headline = format!("Raven couldn't accept the older method for {name}.");
            return self.change_failed(errors::explain_security(&headline, &why));
        }
        let name = self.shown_name(pub_hex);
        if matches!(self.screen, Screen::Verify(_)) {
            self.open_friend_page(pub_hex);
        }
        self.push_toast(&format!("Accepted: {}", bridge::floor_accepted(&name)));
    }

    // ── Privacy (privacy pack PP.21) ────────────────────────────────────────

    /// Reads the privacy pack's state on the store worker, once the identity
    /// exists, unless a read runs: that one's end reads again.
    fn load_privacy(&mut self) {
        if self.identity != IdentityStatus::Ready {
            return;
        }
        if self.privacy_loading {
            self.privacy_due = true;
            return;
        }
        self.privacy_loading = true;
        self.privacy_due = false;
        self.job(Cmd::Store(StoreJob::LoadPrivacy));
    }

    /// The privacy read answered. Not available hides every part that
    /// needs it: a box of theirs that is open goes (ERASE only before its
    /// erase began), and SET leaves 'Keep chats for' and 'Erase Raven from
    /// this computer'.
    fn privacy_read(&mut self, read: Result<PrivacyRead, NotAvailable>) {
        self.privacy_loading = false;
        let read = read.ok();
        if read != self.privacy {
            self.privacy = read;
            self.dirty = true;
            // HELP over CI lists C and F only while they work.
            self.clamp_help_scroll();
        }
        if self.privacy.is_none() {
            self.overlays.retain(|overlay| !overlay.needs_privacy());
            if let Some(set) = self.settings_mut() {
                match set.row {
                    SetRow::KeepChats => set.row = SetRow::Details,
                    SetRow::Erase => set.row = SetRow::LockNow,
                    _ => {}
                }
            }
        }
        if self.privacy_due {
            self.load_privacy();
        }
    }

    /// The privacy pack's read as it last answered; None while its parts
    /// are hidden.
    pub(super) fn privacy(&self) -> Option<&PrivacyRead> {
        self.privacy.as_ref()
    }

    /// SET's rows as shown: 'Keep chats for' and 'Erase Raven from this
    /// computer' only once the privacy read answered.
    pub(super) fn set_rows(&self) -> Vec<SetRow> {
        SetRow::ALL
            .into_iter()
            .filter(|row| {
                !matches!(row, SetRow::KeepChats | SetRow::Erase) || self.privacy.is_some()
            })
            .filter(|row| self.lock_v2_row_shown(*row))
            .collect()
    }

    /// KEEP over SET, on the setting as it is.
    fn open_keep_chooser(&mut self) {
        if let Some(read) = self.privacy {
            self.open_overlay(Overlay::KeepChats { choice: read.keep });
        }
    }

    /// KEEP: Up and Down (or k and j) choose; Enter (not right after a
    /// paste) saves the choice, Esc keeps the setting as it was; Ctrl+C
    /// opens QUIT.
    fn on_keep_key(&mut self, key: KeyEvent, choice: ChatKeepView) {
        if is_ctrl(key, 'c') {
            self.open_overlay(Overlay::Quit);
            return;
        }
        let all = ChatKeepView::ALL;
        let at = all.iter().position(|keep| *keep == choice).unwrap_or(0);
        let new = match (key.code, plain_char(key)) {
            (KeyCode::Esc, _) => return self.close_overlay(),
            (KeyCode::Up, _) | (_, Some('k')) => at.saturating_sub(1),
            (KeyCode::Down, _) | (_, Some('j')) => (at + 1).min(all.len() - 1),
            _ if self.confirms(key) => {
                self.close_overlay();
                return self.save_chat_keep(choice);
            }
            _ => return,
        };
        if let Some(Overlay::KeepChats { choice }) = self.overlays.last_mut() {
            *choice = all[new];
        }
        self.dirty = true;
    }

    /// 'Keep chats for' is `keep` from now on, saved by one store job; a
    /// choice of the setting it has already saves nothing.
    fn save_chat_keep(&mut self, keep: ChatKeepView) {
        let Some(read) = self.privacy.as_mut() else {
            return;
        };
        if read.keep == keep {
            return;
        }
        read.keep = keep;
        // Nothing is deleted any more: the retention notice says nothing.
        if keep == ChatKeepView::Keep {
            read.notices.retention_from = None;
        }
        self.dirty = true;
        self.job(Cmd::Store(StoreJob::SetChatKeep(keep)));
    }

    /// KEEP's save answered: the setting stays as chosen (a read that was
    /// out before the save may have said the old one), or a toast says it
    /// was not saved; then it is read again either way.
    fn chat_keep_saved(&mut self, keep: ChatKeepView, result: Result<(), String>) {
        match result {
            Ok(()) => {
                if let Some(read) = self.privacy.as_mut() {
                    read.keep = keep;
                }
                self.dirty = true;
            }
            Err(_) => self.push_toast(KEEP_NOT_SAVED),
        }
        self.load_privacy();
    }

    /// DEL: what is typed goes into the word (a Persian keyboard's letter
    /// keys arrive as the Latin letters on them, as in every box); Backspace
    /// edits; Enter (not right after a paste) deletes once the word is
    /// 'delete', and means nothing before; Esc keeps the chat; Ctrl+C opens
    /// QUIT.
    fn on_delete_chat_key(&mut self, key: KeyEvent, peer: &str, typed: &str) {
        if is_ctrl(key, 'c') {
            self.open_overlay(Overlay::Quit);
            return;
        }
        match (key.code, plain_char(key)) {
            (KeyCode::Esc, _) => self.close_overlay(),
            (_, Some(c)) => {
                if let Some(typed) = self.delete_word_mut() {
                    if typed.chars().count() < LINE_FIELD_MAX && !c.is_control() {
                        typed.push(c);
                    }
                }
                self.dirty = true;
            }
            (KeyCode::Backspace, _) if !has_ctrl_or_alt(key) => {
                if let Some(typed) = self.delete_word_mut() {
                    typed.pop();
                }
                self.dirty = true;
            }
            _ if self.confirms(key) && typed_word_is(typed, DELETE_WORD) => {
                self.close_overlay();
                self.page_saving();
                self.job(Cmd::Store(StoreJob::DeleteChat {
                    pub_hex: peer.to_owned(),
                }));
            }
            _ => {}
        }
    }

    /// DEL's word, while DEL is on top.
    fn delete_word_mut(&mut self) -> Option<&mut String> {
        match self.overlays.last_mut() {
            Some(Overlay::DeleteChat { typed, .. }) => Some(typed),
            _ => None,
        }
    }

    /// A paste (or an Enter that was part of one) while DEL or ERASE's
    /// question is on top: its word is cleared, since it must be typed.
    /// Whether one was there.
    fn clear_typed_word(&mut self) -> bool {
        let typed = match self.overlays.last_mut() {
            Some(Overlay::DeleteChat { typed, .. })
            | Some(Overlay::Erase(EraseState::Asking { typed, .. })) => typed,
            Some(Overlay::Updates(_)) => return self.clear_update_word(),
            _ => return false,
        };
        typed.clear();
        self.dirty = true;
        true
    }

    /// FORGET: Enter (not right after a paste) forgets the friend's saved
    /// address, Esc keeps it; Ctrl+C opens QUIT.
    fn on_forget_key(&mut self, key: KeyEvent, peer: &str) {
        if is_ctrl(key, 'c') {
            self.open_overlay(Overlay::Quit);
        } else if key.code == KeyCode::Esc {
            self.close_overlay();
        } else if self.confirms(key) {
            self.close_overlay();
            self.page_saving();
            self.job(Cmd::Store(StoreJob::ForgetAddress {
                pub_hex: peer.to_owned(),
            }));
        }
    }

    /// DEL's delete answered: CI's keys come back and the toasts say how
    /// many messages went, how many to the friend still wait to be sent
    /// (they stay), and any received one that could not go now. Their
    /// conversation is read again from the history, and their read marker
    /// goes (saved now). A failure stays on CI, as a change's does.
    fn chat_deleted(&mut self, pub_hex: &str, result: Result<DeleteChatOutcome, String>) {
        let outcome = match result {
            Ok(outcome) => outcome,
            Err(why) => return self.change_failed(errors::explain_delete_chat(&why)),
        };
        self.page_saved();
        let name = self.shown_name(pub_hex);
        let name = if name.is_empty() {
            NO_NAME.to_owned()
        } else {
            name
        };
        for text in chat_deleted_toasts(&name, outcome) {
            self.push_toast(&text);
        }
        let key = convo_key(pub_hex);
        if self.settings.remove_read_mark(&key) {
            self.marks_due = Some(self.now);
        }
        if self.open_friend.as_deref().map(convo_key) == Some(key) {
            self.scroll = 0;
            self.chosen = None;
            self.expanded.clear();
        }
        self.load_history();
    }

    /// NOTICE, once each (PP.21): the sealing notice, then the retention
    /// notice, as the privacy read has them due; then, once Raven runs
    /// again, that Raven's login item stays off (PP.23). Like NOTE they wait
    /// for Home with no other box open and no field that has the keys.
    fn privacy_notice_upkeep(&mut self) {
        if self.identity != IdentityStatus::Ready
            || self.screen != Screen::Home
            || !self.overlays.is_empty()
            || self.field_takes_text()
        {
            return;
        }
        if let Some(notice) = self.notice_due() {
            self.open_overlay(Overlay::PrivacyNotice(notice));
        }
    }

    /// The first one-time notice due and not answered in this session.
    fn notice_due(&self) -> Option<Notice> {
        let read = self.privacy.as_ref()?;
        let notices = read.notices;
        [
            (Notice::Sealing, notices.sealing),
            (Notice::Retention, notices.retention_from.is_some()),
            (
                Notice::LoginItemOff,
                read.login_item_stays_off && self.node.running(),
            ),
        ]
        .into_iter()
        .find(|(notice, due)| *due && !self.notices_shown.contains(notice))
        .map(|(notice, _)| notice)
    }

    /// NOTICE: Enter (not right after a paste) or Esc is OK: it is marked
    /// shown, so neither this app nor the CLI says it again (the login
    /// item's word is not recorded: it is said in this session only). Ctrl+C
    /// opens QUIT over it.
    fn on_notice_key(&mut self, key: KeyEvent, notice: Notice) {
        if is_ctrl(key, 'c') {
            self.open_overlay(Overlay::Quit);
        } else if key.code == KeyCode::Esc || self.confirms(key) {
            self.close_overlay();
            self.notices_shown.push(notice);
            if notice != Notice::LoginItemOff {
                self.job(Cmd::Store(StoreJob::MarkNoticeShown(notice)));
            }
        }
    }

    // ── Settings ────────────────────────────────────────────────────────────

    /// SET, from the friend list, on its first row.
    fn open_settings(&mut self) {
        self.set_screen(Screen::Settings(SettingsState::new()));
        // Lock v2's rows (P6.40), read again each time.
        self.lock_v2_settings_opened();
    }

    fn settings_mut(&mut self) -> Option<&mut SettingsState> {
        match &mut self.screen {
            Screen::Settings(set) => Some(set),
            _ => None,
        }
    }

    /// SET: Up and Down (or k and j) choose a row; Right or Enter changes its
    /// value to the next one, Left to the one before. Enter on 'Your name'
    /// opens its field, on 'Switch to the classic menu now' leaves for that
    /// menu, on 'Lock now' opens LOCK, and on 'Erase Raven from this
    /// computer' opens ERASE; on 'Keep chats for' Enter, Right and Left open
    /// KEEP. Esc goes back to Home; ? and Q open HELP and QUIT, and Ctrl+C
    /// QUIT.
    fn on_settings_key(&mut self, key: KeyEvent) -> Vec<Cmd> {
        if is_ctrl(key, 'c') {
            self.open_overlay(Overlay::Quit);
            return Vec::new();
        }
        let Screen::Settings(set) = &self.screen else {
            return Vec::new();
        };
        if set.name.is_some() {
            self.on_settings_name_key(key);
            return Vec::new();
        }
        if set.asking_stop {
            self.on_settings_stop_key(key);
            return Vec::new();
        }
        let row = set.row;
        match (key.code, plain_char(key)) {
            (KeyCode::Esc, _) => self.set_screen(Screen::Home),
            (KeyCode::Up, _) | (_, Some('k')) => self.choose_setting(-1),
            (KeyCode::Down, _) | (_, Some('j')) => self.choose_setting(1),
            (_, Some('?')) => self.open_overlay(Overlay::Help { scroll: 0 }),
            (_, Some('q' | 'Q')) => self.open_overlay(Overlay::Quit),
            (KeyCode::Right, _) if !has_ctrl_or_alt(key) => self.change_setting(row, true),
            (KeyCode::Left, _) if !has_ctrl_or_alt(key) => self.change_setting(row, false),
            _ if self.confirms(key) => match row {
                SetRow::Name => {
                    let name = self.settings.display_name.clone();
                    if let Some(set) = self.settings_mut() {
                        set.name = Some(name);
                        set.name_full = false;
                    }
                    self.dirty = true;
                }
                SetRow::ClassicNow => return self.switch_to_classic(),
                SetRow::LockNow => self.open_lock(),
                SetRow::Erase => self.open_erase(),
                _ => self.change_setting(row, true),
            },
            _ => {}
        }
        Vec::new()
    }

    /// Up or Down on SET: the row before or after, stopping at the ends.
    fn choose_setting(&mut self, by: isize) {
        let rows = self.set_rows();
        let Some(set) = self.settings_mut() else {
            return;
        };
        let at = rows.iter().position(|row| *row == set.row);
        let at = at.unwrap_or(0);
        let new = at.saturating_add_signed(by).min(rows.len() - 1);
        set.row = rows[new];
        if new != at {
            self.dirty = true;
        }
    }

    /// The value of `row` changed to the next one (`forward`) or the one
    /// before, and saved. Motion, colours and symbols apply at once;
    /// receiving as [`App::toggle_receive`] says; 'Always open the classic
    /// menu' at the next start, when the gate reads it. Colours are left as
    /// they are while NO_COLOR decides them. The rows that are no value
    /// change nothing.
    fn change_setting(&mut self, row: SetRow, forward: bool) {
        let settings = &mut self.settings;
        match row {
            // Two values, shown as the motion in use: Automatic, the
            // default, follows the terminal, and a change chooses one.
            SetRow::Motion => {
                settings.motion = match self.look.motion {
                    Motion::Full => MotionSetting::Reduced,
                    Motion::Reduced => MotionSetting::Full,
                };
                self.look.motion = self.look_env.motion(settings.motion);
            }
            SetRow::Colors if self.look_env.term.no_color => return,
            SetRow::Colors => {
                let choice = ColorChoice::of(settings);
                state_file::step(&ColorChoice::ALL, choice, forward).apply(settings);
                self.look.theme =
                    Theme::for_setting(settings.colors, settings.palette, &self.look_env.term);
            }
            SetRow::Symbols => {
                settings.symbols = state_file::step(&SymbolSetting::ALL, settings.symbols, forward);
                self.look.glyphs = self.look_env.glyphs(settings.symbols);
                // Rows of HELP and NET depend on the glyphs' widths.
                self.clamp_help_scroll();
                self.clamp_net_scroll();
            }
            SetRow::OnQuit => {
                settings.on_quit = state_file::step(&OnQuit::ALL, settings.on_quit, forward);
            }
            SetRow::Receive => return self.toggle_receive(),
            // KEEP chooses, and saves only what it chose.
            SetRow::KeepChats => return self.open_keep_chooser(),
            SetRow::ShareAddress => settings.include_lan_in_card = !settings.include_lan_in_card,
            SetRow::Details => settings.show_details = !settings.show_details,
            SetRow::AlwaysClassic => settings.always_classic = !settings.always_classic,
            // Lock v2's rows (P6.40) save themselves.
            SetRow::SleepLock | SetRow::IdleLock | SetRow::Passphrase => {
                return self.change_lock_setting(row, forward)
            }
            SetRow::Name
            | SetRow::LoginStart
            | SetRow::ClassicNow
            | SetRow::LockNow
            | SetRow::Erase => return,
        }
        self.dirty = true;
        self.save_settings();
    }

    /// 'Receive messages on this computer', saved. On applies now: the
    /// background program starts by itself as it would at launch, unless a
    /// node this app starts listens on this computer only this session (the
    /// loopback listen address was set): then at the next start. Off applies
    /// at the next start, and offers to stop a background program this app
    /// started (Y or N).
    fn toggle_receive(&mut self) {
        self.dirty = true;
        if self.settings.receive == Receive::On {
            self.settings.receive = Receive::Off;
            self.save_settings();
            let started_here = self.node.started_by_app.is_some()
                && self.node.started_by_app == self.node.running_pid();
            if started_here && self.net_keys().stop {
                if let Some(set) = self.settings_mut() {
                    set.asking_stop = true;
                }
            }
            return;
        }
        self.settings.receive = Receive::On;
        if self.listen == ListenOverride::Loopback {
            self.save_settings();
            return;
        }
        // An answer of No not carried out yet is undone, before the save
        // would wait behind it.
        if mem::take(&mut self.loopback_wanted) {
            for cmd in mem::take(&mut self.held) {
                self.job(cmd);
            }
        }
        self.save_settings();
        if self.contacts_loaded && !self.friends.is_empty() {
            self.request_auto_start(AutoStart::Launch);
        }
    }

    /// Receiving applies only from the next start: this session's node
    /// would listen on this computer only.
    pub(super) fn receive_waits_for_restart(&self) -> bool {
        self.listen == ListenOverride::Loopback
    }

    /// SET's stop question: Y stops the background program this app
    /// started, N or Esc keeps it running.
    fn on_settings_stop_key(&mut self, key: KeyEvent) {
        let stop = match (key.code, plain_char(key)) {
            (_, Some('y' | 'Y')) => true,
            (KeyCode::Esc, _) | (_, Some('n' | 'N')) => false,
            _ => return,
        };
        if let Some(set) = self.settings_mut() {
            set.asking_stop = false;
        }
        self.dirty = true;
        if stop && self.net_keys().stop {
            self.ask_node_to_stop();
        }
    }

    /// 'Your name' while it is typed: every letter is text, Backspace edits,
    /// Enter saves it (trimmed; empty is fine; not right after a paste), Esc
    /// leaves it as it was.
    fn on_settings_name_key(&mut self, key: KeyEvent) {
        match (key.code, plain_char(key)) {
            (KeyCode::Esc, _) => {
                if let Some(set) = self.settings_mut() {
                    set.name = None;
                    set.name_full = false;
                }
                self.dirty = true;
            }
            (KeyCode::Backspace, _) if !has_ctrl_or_alt(key) => {
                if let Some(set) = self.settings_mut() {
                    if let Some(name) = set.name.as_mut() {
                        name.pop();
                    }
                    set.name_full = false;
                }
                self.dirty = true;
            }
            (_, Some(c)) => self.settings_name_input(c.encode_utf8(&mut [0; 4])),
            _ if self.confirms(key) => {
                let typed = self.settings_mut().and_then(|set| {
                    set.name_full = false;
                    set.name.take()
                });
                if let Some(name) = typed {
                    self.settings.display_name = name.trim().to_owned();
                    self.save_settings();
                }
                self.dirty = true;
            }
            _ => {}
        }
    }

    /// Adds `text` to SET's name field as one line without control
    /// characters, until the name fills [`NAME_CELLS`] cells: the rest is
    /// dropped, and the field says why.
    fn settings_name_input(&mut self, text: &str) {
        let Some(set) = self.settings_mut() else {
            return;
        };
        let Some(name) = set.name.as_mut() else {
            return;
        };
        for c in display::field_input(text, false).chars() {
            name.push(c);
            if display::width(name) > NAME_CELLS {
                name.pop();
                set.name_full = true;
                break;
            }
        }
        self.dirty = true;
    }

    /// The classic menu, unless a save or a send would be cut short: then a
    /// toast says to wait.
    fn switch_to_classic(&mut self) -> Vec<Cmd> {
        if self.jobs_in_flight.holds_classic() {
            self.push_toast(FINISHING_TOAST);
            return Vec::new();
        }
        vec![Cmd::SwitchToClassic]
    }

    /// The friend list after a load. The highlight stays on the same friend
    /// while they are listed; the open conversation closes if its friend is
    /// gone.
    fn set_friends(&mut self, friends: Vec<String>) {
        let highlighted = self.friends.get(self.highlight).cloned();
        let group = self.group_under_highlight();
        self.friends = friends;
        let kept = highlighted.and_then(|key| self.friends.iter().position(|f| *f == key));
        self.highlight = kept
            .unwrap_or(self.highlight)
            .min(self.friends.len().saturating_sub(1));
        // A group's row (lab) keeps the highlight below the friends.
        self.keep_group_highlight(group);
        if let Some(open) = &self.open_friend {
            if !self.friends.contains(open) {
                self.open_friend = None;
                self.focus = Focus::Friends;
                self.chosen = None;
            }
        }
        self.dirty = true;
    }

    fn move_highlight(&mut self, by: isize) {
        // The friends, then the groups (lab; none while they are not live).
        let last = (self.friends.len() + self.group_list().len()).saturating_sub(1);
        let new = self.highlight.saturating_add_signed(by).min(last);
        if new != self.highlight {
            self.highlight = new;
            self.dirty = true;
        }
    }

    fn open_highlighted(&mut self) {
        if self.open_highlighted_group() {
            return;
        }
        if let Some(friend) = self.friends.get(self.highlight).cloned() {
            if self.open_friend.as_ref() != Some(&friend) {
                self.scroll = 0;
            }
            self.close_group();
            self.open_friend = Some(friend);
            self.focus = Focus::Composer;
            self.chosen = None;
            self.dirty = true;
        }
    }

    /// Tab and Shift+Tab. Without an open conversation only the list can
    /// take the keys.
    fn move_focus(&mut self, step: fn(Focus) -> Focus) {
        if self.open_friend.is_some() {
            self.set_focus(step(self.focus));
        } else if self.open_group().is_some() {
            self.group_move_focus(step);
        }
    }

    /// Messages focus starts on the newest message.
    fn set_focus(&mut self, focus: Focus) {
        if focus != self.focus {
            self.focus = focus;
            self.chosen = (focus == Focus::Messages).then_some(0);
            self.dirty = true;
        }
    }

    /// Opens `overlay` over the others, unless the same kind is on top
    /// already.
    fn open_overlay(&mut self, overlay: Overlay) {
        let on_top = self
            .overlays
            .last()
            .is_some_and(|top| mem::discriminant(top) == mem::discriminant(&overlay));
        if !on_top {
            self.overlays.push(overlay);
            self.dirty = true;
        }
    }

    fn close_overlay(&mut self) {
        self.overlays.pop();
        self.dirty = true;
    }

    /// After a resize HELP may hold fewer rows: keep its scroll in range.
    fn clamp_help_scroll(&mut self) {
        let max = overlays::help_max_scroll(
            &self.look,
            &self.screen,
            (self.privacy.is_some(), self.groups_live()),
            self.size,
        );
        for overlay in &mut self.overlays {
            if let Overlay::Help { scroll } = overlay {
                *scroll = (*scroll).min(max);
            }
        }
    }

    /// Shows `text` once the toasts before it have gone. The same text
    /// already shown starts its time again; already waiting, it is not added
    /// twice.
    fn push_toast(&mut self, text: &str) {
        if let Some(shown) = self.toasts.front_mut().filter(|t| t.text == text) {
            shown.until = Some(self.now + TOAST_TIME);
            self.dirty = true;
            return;
        }
        if self.toasts.iter().any(|t| t.text == text) {
            return;
        }
        if self.toasts.len() >= MAX_TOASTS {
            // The oldest of those waiting; the one on show keeps its time.
            self.toasts.remove(1);
        }
        let until = self.toasts.is_empty().then(|| self.now + TOAST_TIME);
        self.toasts.push_back(Toast {
            text: text.to_owned(),
            until,
        });
        self.dirty = true;
    }

    /// Takes away the toast on show once its time is up, and starts the next
    /// one's time.
    fn expire_toasts(&mut self) {
        let now = self.now;
        while self
            .toasts
            .front()
            .is_some_and(|t| t.until.is_some_and(|until| until <= now))
        {
            self.toasts.pop_front();
            if let Some(next) = self.toasts.front_mut() {
                next.until = Some(now + TOAST_TIME);
            }
            self.dirty = true;
        }
    }
}

/// `typed` is `word` in any case, also as the keys of a Persian (or Arabic
/// 101) keyboard layout typed it: the Latin letters on the same keys (as
/// `raven chats delete` reads it; input tolerance only).
fn typed_word_is(typed: &str, word: &str) -> bool {
    let latin: String = typed
        .trim()
        .chars()
        .map(|c| keys_fa::latin(c).unwrap_or(c))
        .collect();
    latin.eq_ignore_ascii_case(word)
}

/// DEL's toasts (the privacy pack's UX copy): how many messages went, then
/// how many to the friend `name` still wait to be sent, and how many
/// received ones could not be deleted now.
pub(super) fn chat_deleted_toasts(name: &str, outcome: DeleteChatOutcome) -> Vec<String> {
    let s = |n: u32| if n == 1 { "" } else { "s" };
    let n = outcome.deleted;
    let mut toasts = vec![format!(
        "Deleted your chat with {name} on this computer ({n} message{}).",
        s(n)
    )];
    let k = outcome.still_waiting;
    if k > 0 {
        let are = if k == 1 { "is" } else { "are" };
        toasts.push(format!(
            "{k} message{} to {name} {are} still waiting to be sent.",
            s(k)
        ));
    }
    let k = outcome.skipped_pending;
    if k > 0 {
        toasts.push(format!(
            "{k} received message{} could not be deleted now: delete the chat again later.",
            s(k)
        ));
    }
    toasts
}

/// What is typed of a security code (its letters and digits) in groups of 4,
/// each with its mark once it is complete: whether it is that group of
/// `expected`. A group is complete at 4 characters, or as long as the group
/// it is checked against (the last one may be shorter); a group past the end
/// of `expected` is wrong at once.
pub(super) fn code_marks(typed: &str, expected: &str) -> Vec<(String, Option<bool>)> {
    let want = wizard::code_groups(expected);
    wizard::code_groups(typed)
        .into_iter()
        .enumerate()
        .map(|(i, group)| {
            let len = group.chars().count();
            let mark = match want.get(i) {
                Some(theirs) if len >= 4 || len >= theirs.chars().count() => Some(group == *theirs),
                Some(_) => None,
                None => Some(false),
            };
            (group, mark)
        })
        .collect()
}

/// Whether a paste of `friend`'s invite would change any route saved for
/// them: a route it has replaces the saved one (cli.rs), one it lacks keeps
/// it.
pub(super) fn routes_differ(friend: &FriendPreview, saved: &ContactView) -> bool {
    (!friend.lan.is_empty() && friend.lan != saved.lan_dial)
        || (!friend.internet.is_empty() && friend.internet != saved.internet_dial)
        || friend
            .p2p
            .as_ref()
            .is_some_and(|p2p| p2p.peer_id != saved.p2p)
}

fn has_ctrl_or_alt(key: KeyEvent) -> bool {
    key.modifiers
        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
}

/// The character of a key typed without Ctrl or Alt (Shift is fine).
fn plain_char(key: KeyEvent) -> Option<char> {
    match key.code {
        KeyCode::Char(c) if !has_ctrl_or_alt(key) => Some(c),
        _ => None,
    }
}

/// Ctrl+`letter`, with or without Shift.
fn is_ctrl(key: KeyEvent, letter: char) -> bool {
    key.modifiers.contains(KeyModifiers::CONTROL)
        && !key.modifiers.contains(KeyModifiers::ALT)
        && matches!(key.code, KeyCode::Char(c) if c.eq_ignore_ascii_case(&letter))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The app at 80x24 with the render tests' look, drawn once.
    fn app() -> App {
        let mut app = testkit::app((80, 24));
        assert!(app.take_dirty(), "a new app has a first frame to draw");
        app
    }

    /// The app at 80x24 with three friends, drawn once.
    fn with_friends() -> App {
        let mut app = app();
        app.set_friends(vec!["aa01".into(), "bb02".into(), "cc03".into()]);
        app.take_dirty();
        app
    }

    fn key(code: KeyCode, modifiers: KeyModifiers, kind: KeyEventKind) -> Msg {
        Msg::Key(Key::Event(KeyEvent::new_with_kind(code, modifiers, kind)))
    }

    fn resize(app: &mut App, cols: u16, rows: u16) -> Vec<Cmd> {
        testkit::send(app, Msg::Resize { cols, rows })
    }

    /// The toast on show, as text.
    fn toast_text(app: &App) -> Option<&str> {
        app.toast().map(|t| t.text.as_str())
    }

    #[test]
    fn ctrl_c_opens_quit_and_a_second_one_does_not_quit() {
        let mut app = app();
        assert!(testkit::ctrl(&mut app, 'c').is_empty());
        assert_eq!(app.overlays(), [Overlay::Quit]);
        assert!(app.take_dirty());
        assert!(
            testkit::ctrl(&mut app, 'c').is_empty(),
            "a second Ctrl+C does nothing more"
        );
        assert_eq!(app.overlays(), [Overlay::Quit]);
        assert!(!app.take_dirty());
        assert_eq!(
            testkit::press(&mut app, KeyCode::Enter),
            [Cmd::Exit(ExitPlan::quit(None))]
        );
    }

    #[test]
    fn q_opens_quit_and_esc_stays() {
        let mut app = app();
        for q in ['q', 'Q'] {
            assert!(testkit::press(&mut app, KeyCode::Char(q)).is_empty());
            assert_eq!(app.overlays(), [Overlay::Quit]);
            assert!(testkit::press(&mut app, KeyCode::Esc).is_empty());
            assert!(app.overlays().is_empty());
        }
        // Keys QUIT does not know change nothing.
        testkit::press(&mut app, KeyCode::Char('q'));
        app.take_dirty();
        for code in [KeyCode::Char('q'), KeyCode::Char('y'), KeyCode::Up] {
            assert!(testkit::press(&mut app, code).is_empty());
        }
        assert_eq!(app.overlays(), [Overlay::Quit]);
        assert!(!app.take_dirty());
        // Ctrl+Enter or Alt+Enter is not Enter.
        let alt_enter = key(KeyCode::Enter, KeyModifiers::ALT, KeyEventKind::Press);
        assert!(testkit::send(&mut app, alt_enter).is_empty());
    }

    #[test]
    fn release_and_repeat_events_are_ignored() {
        let mut app = app();
        for kind in [KeyEventKind::Release, KeyEventKind::Repeat] {
            let ctrl_c = key(KeyCode::Char('c'), KeyModifiers::CONTROL, kind);
            assert!(testkit::send(&mut app, ctrl_c).is_empty());
            let help = key(KeyCode::Char('?'), KeyModifiers::NONE, kind);
            assert!(testkit::send(&mut app, help).is_empty());
        }
        assert!(app.overlays().is_empty());
        assert!(!app.take_dirty());
        testkit::press(&mut app, KeyCode::Char('q'));
        let enter_up = key(KeyCode::Enter, KeyModifiers::NONE, KeyEventKind::Release);
        assert!(
            testkit::send(&mut app, enter_up).is_empty(),
            "a released Enter quits nothing"
        );
        assert_eq!(app.overlays(), [Overlay::Quit]);
    }

    #[test]
    fn a_paste_never_quits() {
        let mut app = app();
        testkit::press(&mut app, KeyCode::Char('q'));
        app.take_dirty();
        assert!(testkit::send(&mut app, Msg::Key(Key::PastedEnter)).is_empty());
        for via in [PasteVia::Bracketed, PasteVia::Keystrokes] {
            assert!(testkit::paste(&mut app, "q\n\r\n", via).is_empty());
        }
        assert_eq!(app.overlays(), [Overlay::Quit]);
        assert!(!app.take_dirty());
    }

    #[test]
    fn help_opens_scrolls_within_its_rows_and_closes() {
        let mut app = app();
        let max = overlays::help_max_scroll(
            app.look(),
            app.screen(),
            (app.privacy().is_some(), false),
            app.size(),
        );
        assert!(max > 0, "HELP has more rows than 80x24 shows");
        testkit::press(&mut app, KeyCode::Char('?'));
        assert_eq!(app.overlays(), [Overlay::Help { scroll: 0 }]);
        testkit::press(&mut app, KeyCode::Up);
        assert_eq!(app.overlays(), [Overlay::Help { scroll: 0 }]);
        for _ in 0..50 {
            testkit::press(&mut app, KeyCode::Down);
        }
        assert_eq!(app.overlays(), [Overlay::Help { scroll: max }]);
        app.take_dirty();
        testkit::press(&mut app, KeyCode::Down);
        assert!(!app.take_dirty(), "nothing moved at the end");
        testkit::press(&mut app, KeyCode::Up);
        assert_eq!(app.overlays(), [Overlay::Help { scroll: max - 1 }]);

        // Ctrl+C opens QUIT over HELP; Esc goes back to HELP.
        testkit::ctrl(&mut app, 'c');
        assert_eq!(
            app.overlays(),
            [Overlay::Help { scroll: max - 1 }, Overlay::Quit]
        );
        testkit::press(&mut app, KeyCode::Esc);
        testkit::press(&mut app, KeyCode::Esc);
        assert!(app.overlays().is_empty());
        testkit::press(&mut app, KeyCode::Char('?'));
        testkit::press(&mut app, KeyCode::Char('?'));
        assert!(app.overlays().is_empty(), "? closes HELP too");
    }

    #[test]
    fn a_resize_keeps_help_scroll_in_range() {
        // The smallest window scrolls furthest: HELP is shorter there.
        let mut app = testkit::app((60, 16));
        testkit::press(&mut app, KeyCode::Char('?'));
        for _ in 0..50 {
            testkit::press(&mut app, KeyCode::Down);
        }
        let small = overlays::help_max_scroll(
            app.look(),
            app.screen(),
            (app.privacy().is_some(), false),
            (60, 16),
        );
        assert_eq!(app.overlays(), [Overlay::Help { scroll: small }]);
        app.take_dirty();
        resize(&mut app, 100, 30);
        assert_eq!(app.size(), (100, 30));
        assert!(app.take_dirty());
        let large = overlays::help_max_scroll(
            app.look(),
            app.screen(),
            (app.privacy().is_some(), false),
            (100, 30),
        );
        assert!(large < small);
        assert_eq!(app.overlays(), [Overlay::Help { scroll: large }]);
    }

    #[test]
    fn ctrl_l_redraws_everywhere() {
        let mut app = app();
        assert_eq!(testkit::ctrl(&mut app, 'l'), [Cmd::Redraw]);
        assert!(app.take_dirty());
        testkit::press(&mut app, KeyCode::Char('q'));
        assert_eq!(testkit::ctrl(&mut app, 'L'), [Cmd::Redraw]);
        assert_eq!(app.overlays(), [Overlay::Quit]);
        resize(&mut app, 40, 10);
        assert_eq!(testkit::ctrl(&mut app, 'l'), [Cmd::Redraw], "SMALL too");
    }

    #[test]
    fn signals_and_dead_threads_end_the_app() {
        let mut app = app();
        let stderr = Msg::Stderr("raven: note".into());
        assert!(testkit::send(&mut app, stderr).is_empty());
        let reader_died = Msg::ThreadDied(workers::STDERR_THREAD);
        assert!(testkit::send(&mut app, reader_died).is_empty());
        assert!(!app.take_dirty());
        for name in [workers::INPUT_THREAD, workers::SIGNAL_THREAD] {
            let [Cmd::Exit(plan)] = &testkit::send(&mut app, Msg::ThreadDied(name))[..] else {
                panic!("{name} died: the app must exit");
            };
            assert_eq!(
                (plan.code, plan.line.as_deref(), plan.quiet),
                (1, Some(PART_FAILED), false)
            );
        }
        let expected = [
            (OsSignal::Terminate, 143, false),
            (OsSignal::HangUp, 129, true),
            (OsSignal::ConsoleClosed, 1, true),
            (OsSignal::Break, 1, false),
        ];
        for (signal, code, quiet) in expected {
            assert_eq!(
                testkit::send(&mut app, Msg::OsSignal(signal)),
                [Cmd::Exit(ExitPlan {
                    code,
                    line: None,
                    quiet,
                    clear: false,
                    save: None,
                })],
                "{signal:?}"
            );
        }
    }

    #[test]
    fn a_failed_draw_exits_silently() {
        let plan = ExitPlan::draw_failed(None);
        assert_eq!(
            (plan.code, plan.line.as_deref(), plan.quiet),
            (1, None, true)
        );
        assert_eq!(ExitPlan::draw_failed(Some(OsSignal::HangUp)).code, 129);
        assert_eq!(ExitPlan::draw_failed(Some(OsSignal::Terminate)).code, 1);
        assert_eq!(ExitPlan::draw_failed(Some(OsSignal::ConsoleClosed)).code, 1);
    }

    #[test]
    fn update_keeps_the_time_it_was_given() {
        let mut app = app();
        let later = app.now() + Duration::from_secs(5);
        testkit::send(&mut app, Msg::Tick);
        app.update(Msg::Tick, later, 1_700_000_000_123);
        assert_eq!((app.now(), app.now_ms()), (later, 1_700_000_000_123));
        assert!(!app.take_dirty(), "a tick with nothing due draws nothing");
    }

    #[test]
    fn small_window_offers_the_classic_menu_and_quit() {
        let mut app = app();
        assert!(!app.too_small());
        for (cols, rows) in [(59, 24), (80, 15), (40, 3), (0, 0)] {
            resize(&mut app, cols, rows);
            assert!(app.too_small(), "{cols}x{rows}");
        }
        resize(&mut app, MIN_COLS, MIN_ROWS);
        assert!(!app.too_small(), "60x16 is big enough");

        resize(&mut app, 40, 3);
        app.take_dirty();
        // Only C and Q mean something there; ? and Ctrl+C open nothing.
        for code in [
            KeyCode::Char('?'),
            KeyCode::Enter,
            KeyCode::Esc,
            KeyCode::Tab,
        ] {
            assert!(testkit::press(&mut app, code).is_empty());
        }
        assert!(testkit::ctrl(&mut app, 'c').is_empty());
        assert!(app.overlays().is_empty());
        assert!(!app.take_dirty());
        assert_eq!(
            testkit::press(&mut app, KeyCode::Char('c')),
            [Cmd::SwitchToClassic]
        );
        assert_eq!(
            testkit::press(&mut app, KeyCode::Char('C')),
            [Cmd::SwitchToClassic]
        );
        assert_eq!(
            testkit::press(&mut app, KeyCode::Char('q')),
            [Cmd::Exit(ExitPlan::quit(None))]
        );
        // A paste is never C or Q.
        assert!(testkit::paste(&mut app, "cq", PasteVia::Keystrokes).is_empty());
        // Ctrl+Q is not Q.
        let ctrl_q = key(
            KeyCode::Char('q'),
            KeyModifiers::CONTROL,
            KeyEventKind::Press,
        );
        assert!(testkit::send(&mut app, ctrl_q).is_empty());
    }

    #[test]
    fn the_classic_menu_waits_for_a_save_or_a_send() {
        let mut app = testkit::app((40, 3));
        for kind in [JobKind::Send, JobKind::Critical] {
            app.jobs_in_flight.start(kind);
            assert!(
                testkit::press(&mut app, KeyCode::Char('c')).is_empty(),
                "{kind:?} in flight"
            );
            assert_eq!(toast_text(&app), Some(FINISHING_TOAST));
            app.jobs_in_flight.finish(kind);
        }
        // Loads and the background program hold nothing up.
        app.jobs_in_flight.start(JobKind::Store);
        app.jobs_in_flight.start(JobKind::Node);
        assert!(!app.jobs_in_flight().idle());
        assert_eq!(
            testkit::press(&mut app, KeyCode::Char('c')),
            [Cmd::SwitchToClassic]
        );
    }

    #[test]
    fn job_counts_add_up_by_kind() {
        let mut jobs = JobCounts::default();
        assert!(jobs.idle() && !jobs.holds_classic());
        jobs.start(JobKind::Send);
        jobs.start(JobKind::Send);
        jobs.finish(JobKind::Send);
        assert!(jobs.holds_classic());
        jobs.finish(JobKind::Send);
        assert!(jobs.idle());
        // An answer for a job never counted leaves the count at zero.
        jobs.finish(JobKind::Critical);
        assert!(jobs.idle());
        jobs.start(JobKind::Critical);
        assert!(jobs.holds_classic() && !jobs.idle());
        jobs.finish(JobKind::Critical);
        jobs.start(JobKind::Node);
        assert!(!jobs.holds_classic() && !jobs.idle());
    }

    #[test]
    fn toasts_show_one_at_a_time_and_expire() {
        let mut app = app();
        let t0 = app.now();
        testkit::ctrl(&mut app, 'z');
        assert_eq!(toast_text(&app), Some(PAUSE_TOAST));
        assert_eq!(app.toast().and_then(Toast::until), Some(t0 + TOAST_TIME));
        assert!(app.take_dirty());

        // The same toast again starts its time again, and is not queued.
        testkit::tick(&mut app, Duration::from_secs(3));
        testkit::ctrl(&mut app, 'z');
        assert_eq!(app.toasts.len(), 1);
        let until = t0 + Duration::from_secs(3) + TOAST_TIME;
        assert_eq!(app.toast().and_then(Toast::until), Some(until));

        // Another waits its turn, then gets its own full time.
        app.push_toast(FINISHING_TOAST);
        assert_eq!(toast_text(&app), Some(PAUSE_TOAST));
        app.take_dirty();
        app.update(Msg::Tick, until - Duration::from_millis(1), 0);
        assert_eq!(toast_text(&app), Some(PAUSE_TOAST));
        assert!(!app.take_dirty());
        app.update(Msg::Tick, until, 0);
        assert_eq!(toast_text(&app), Some(FINISHING_TOAST));
        assert_eq!(app.toast().and_then(Toast::until), Some(until + TOAST_TIME));
        assert!(app.take_dirty());
        // Any message carries the clock: a key long after clears it too.
        app.update(
            Msg::Key(Key::Event(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE))),
            until + TOAST_TIME,
            0,
        );
        assert_eq!(app.toast(), None);
        assert!(app.take_dirty());
    }

    #[test]
    fn a_flood_of_toasts_keeps_the_one_on_show() {
        let mut app = app();
        for i in 0..10 {
            app.push_toast(&format!("note {i}"));
        }
        let texts: Vec<&str> = app.toasts.iter().map(|t| t.text.as_str()).collect();
        assert_eq!(texts, ["note 0", "note 8", "note 9"]);
        assert!(app.toasts.iter().skip(1).all(|t| t.until.is_none()));
    }

    #[test]
    fn tab_cycles_the_focus_while_a_conversation_is_open() {
        let mut app = with_friends();
        // Nothing open: the list keeps the keys.
        for code in [KeyCode::Tab, KeyCode::BackTab] {
            testkit::press(&mut app, code);
            assert_eq!(app.focus(), Focus::Friends);
        }
        assert!(!app.take_dirty());

        testkit::press(&mut app, KeyCode::Down);
        testkit::press(&mut app, KeyCode::Enter);
        assert_eq!(app.open_friend(), Some("bb02"));
        assert_eq!(app.focus(), Focus::Composer);
        let mut order = Vec::new();
        for _ in 0..4 {
            testkit::press(&mut app, KeyCode::Tab);
            order.push(app.focus());
        }
        assert_eq!(
            order,
            [
                Focus::Messages,
                Focus::Friends,
                Focus::Composer,
                Focus::Messages
            ]
        );
        let mut back = Vec::new();
        for _ in 0..3 {
            testkit::press(&mut app, KeyCode::BackTab);
            back.push(app.focus());
        }
        assert_eq!(back, [Focus::Composer, Focus::Friends, Focus::Messages]);
        // Esc goes back one level: messages to composer, composer to list.
        testkit::press(&mut app, KeyCode::Esc);
        assert_eq!(app.focus(), Focus::Composer);
        testkit::press(&mut app, KeyCode::Esc);
        assert_eq!(app.focus(), Focus::Friends);
        assert_eq!(app.open_friend(), Some("bb02"), "Esc closes nothing");
    }

    #[test]
    fn up_and_down_move_the_highlight_never_the_open_friend() {
        let mut app = with_friends();
        testkit::press(&mut app, KeyCode::Enter);
        assert_eq!(app.open_friend(), Some("aa01"));
        for focus in [Focus::Composer, Focus::Messages] {
            app.set_focus(focus);
            for _ in 0..10 {
                testkit::press(&mut app, KeyCode::Down);
            }
            testkit::press(&mut app, KeyCode::Up);
            assert_eq!(
                (app.highlight(), app.open_friend()),
                (0, Some("aa01")),
                "{focus:?}"
            );
        }
        app.set_focus(Focus::Friends);
        for _ in 0..10 {
            testkit::press(&mut app, KeyCode::Down);
        }
        assert_eq!((app.highlight(), app.open_friend()), (2, Some("aa01")));
        testkit::press(&mut app, KeyCode::Char('k'));
        assert_eq!(app.highlight(), 1);
        testkit::press(&mut app, KeyCode::Char('j'));
        assert_eq!(app.highlight(), 2);
        for _ in 0..5 {
            testkit::press(&mut app, KeyCode::Up);
        }
        assert_eq!((app.highlight(), app.open_friend()), (0, Some("aa01")));
        assert_eq!(app.focus(), Focus::Friends);
    }

    #[test]
    fn the_composer_takes_letters_as_text() {
        let mut app = with_friends();
        testkit::press(&mut app, KeyCode::Enter);
        app.take_dirty();
        for c in ['q', 'Q', 'j', 'k', 'a', '?'] {
            assert!(testkit::press(&mut app, KeyCode::Char(c)).is_empty());
        }
        assert!(app.overlays().is_empty());
        assert_eq!(app.focus(), Focus::Composer);
        assert_eq!(app.composer().map(Composer::text), Some("qQjka?"));
        assert!(app.take_dirty());
        // Ctrl+C still opens QUIT; ? opens HELP once the composer is empty.
        testkit::ctrl(&mut app, 'c');
        assert_eq!(app.overlays(), [Overlay::Quit]);
        testkit::press(&mut app, KeyCode::Esc);
        for _ in 0..6 {
            testkit::press(&mut app, KeyCode::Backspace);
        }
        assert_eq!(app.composer().map(Composer::is_empty), Some(true));
        testkit::press(&mut app, KeyCode::Char('?'));
        assert_eq!(app.overlays(), [Overlay::Help { scroll: 0 }]);
        // Q in the conversation is a shortcut again.
        testkit::press(&mut app, KeyCode::Esc);
        testkit::press(&mut app, KeyCode::Tab);
        assert_eq!(app.focus(), Focus::Messages);
        testkit::press(&mut app, KeyCode::Char('q'));
        assert_eq!(app.overlays(), [Overlay::Quit]);
    }

    #[test]
    fn a_reloaded_list_keeps_the_highlighted_friend() {
        let mut app = with_friends();
        testkit::press(&mut app, KeyCode::Down);
        testkit::press(&mut app, KeyCode::Down);
        testkit::press(&mut app, KeyCode::Enter);
        app.set_focus(Focus::Friends);
        testkit::press(&mut app, KeyCode::Up);
        assert_eq!((app.highlight(), app.open_friend()), (1, Some("cc03")));
        // A friend added above: the cursor follows bb02.
        app.set_friends(vec![
            "00new".into(),
            "aa01".into(),
            "bb02".into(),
            "cc03".into(),
        ]);
        assert_eq!((app.highlight(), app.open_friend()), (2, Some("cc03")));
        // bb02 removed: the cursor stays in place, within the list.
        app.set_friends(vec!["00new".into(), "aa01".into(), "cc03".into()]);
        assert_eq!(app.highlight(), 2);
        app.set_focus(Focus::Messages);
        // The open friend removed: the conversation closes.
        app.set_friends(vec!["aa01".into()]);
        assert_eq!(
            (app.highlight(), app.open_friend(), app.focus()),
            (0, None, Focus::Friends)
        );
        app.set_friends(Vec::new());
        assert_eq!(app.highlight(), 0);
        testkit::press(&mut app, KeyCode::Down);
        testkit::press(&mut app, KeyCode::Enter);
        assert_eq!((app.highlight(), app.open_friend()), (0, None));
    }

    #[test]
    fn overlays_stack_and_survive_a_small_window() {
        let mut app = app();
        testkit::press(&mut app, KeyCode::Char('?'));
        testkit::ctrl(&mut app, 'c');
        assert_eq!(app.overlays(), [Overlay::Help { scroll: 0 }, Overlay::Quit]);
        // The same kind never stacks on itself.
        app.open_overlay(Overlay::Quit);
        app.open_overlay(Overlay::Help { scroll: 3 });
        app.open_overlay(Overlay::Help { scroll: 4 });
        assert_eq!(
            app.overlays(),
            [
                Overlay::Help { scroll: 0 },
                Overlay::Quit,
                Overlay::Help { scroll: 3 }
            ]
        );
        app.close_overlay();

        // SMALL takes the keys: Esc and Enter reach no overlay.
        resize(&mut app, 50, 12);
        testkit::press(&mut app, KeyCode::Esc);
        assert!(testkit::press(&mut app, KeyCode::Enter).is_empty());
        assert_eq!(app.overlays(), [Overlay::Help { scroll: 0 }, Overlay::Quit]);
        // Back at a usable size, the top one has the keys again.
        resize(&mut app, 80, 24);
        testkit::press(&mut app, KeyCode::Esc);
        assert_eq!(app.overlays(), [Overlay::Help { scroll: 0 }]);
        testkit::press(&mut app, KeyCode::Esc);
        assert!(app.overlays().is_empty());
    }

    // ── the session, jobs and the background program ───────────────────────

    use raven_core::identity::Identity;
    use raven_core::ipc::{IpcResponse, OutboxItem, IPC_VERSION};
    use std::path::Path;

    fn me() -> MeView {
        bridge::me_view(&Identity::from_seed(&[7; 32]))
    }

    fn session(receive: Receive) -> Session {
        Session {
            identity: IdentityStart::Ready(me()),
            data_dir: testkit::FOLDER.into(),
            settings: testkit::notes_seen(TuiState {
                receive,
                ..TuiState::default()
            }),
            program: Program {
                binary: "/opt/raven/raven-node".into(),
                exe_known: true,
            },
            listen: ListenOverride::None,
            over_ssh: false,
            gates: testkit::release_gates(),
            look_env: LookEnv::default(),
            locked: false,
        }
    }

    fn not_running() -> Probe {
        Probe::of(&Err(
            "raven-node is not running; start it (nothing listens)".into(),
        ))
    }

    fn listening(pid: u32, lan_listen: &str) -> Probe {
        Probe::of(&Ok(IpcResponse::Status {
            v: IPC_VERSION,
            bridge: false,
            store: false,
            relay: false,
            forward_pending: 0,
            capabilities: vec!["ipc".into(), "lan_direct".into()],
            p2p: None,
            pid: Some(pid),
            lan_listen: Some(lan_listen.into()),
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

    fn answer(app: &mut App, result: JobResult) -> Vec<Cmd> {
        testkit::send(app, Msg::Job(result))
    }

    fn contacts(app: &mut App, friends: u8) -> Vec<Cmd> {
        answer(
            app,
            JobResult::Contacts {
                contacts: Ok((1..=friends).map(testkit::friend).collect()),
                stamp: FileStamp::default(),
            },
        )
    }

    /// The first history load answered: no conversation yet.
    fn history(app: &mut App) -> Vec<Cmd> {
        answer(
            app,
            JobResult::History {
                history: Ok(Conversations::new()),
                stamp: FileStamp::default(),
            },
        )
    }

    fn vault(app: &mut App, needs_passphrase_file: bool) -> Vec<Cmd> {
        answer(
            app,
            JobResult::Vault(Vault {
                profile: needs_passphrase_file,
                needs_passphrase_file,
                ..Vault::default()
            }),
        )
    }

    /// The app started with `receive`, its first jobs answered: no vault
    /// problem, no node running, not a login service, no history, the
    /// privacy read not available, and `friends` friends.
    fn ready(receive: Receive, friends: u8) -> (App, Vec<Cmd>) {
        let mut app = app();
        let mut cmds = app.start(session(receive));
        cmds.extend(history(&mut app));
        cmds.extend(answer(&mut app, JobResult::Privacy(Err(NotAvailable))));
        cmds.extend(vault(&mut app, false));
        cmds.extend(answer(&mut app, JobResult::Probed(not_running())));
        cmds.extend(answer(&mut app, JobResult::Managed(None)));
        cmds.extend(contacts(&mut app, friends));
        (app, cmds)
    }

    fn starts(cmds: &[Cmd]) -> bool {
        cmds.contains(&Cmd::Node(NodeJob::Ensure))
    }

    fn saves(cmds: &[Cmd]) -> Option<&TuiState> {
        cmds.iter().find_map(|cmd| match cmd {
            Cmd::Store(StoreJob::SaveSettings(state)) => Some(state),
            _ => None,
        })
    }

    #[test]
    fn a_ready_profile_starts_with_its_first_jobs() {
        let mut app = app();
        let cmds = app.start(session(Receive::On));
        assert_eq!(
            cmds,
            [
                Cmd::Poll(PollCtl::Start),
                Cmd::Store(StoreJob::LoadContacts),
                Cmd::Store(StoreJob::LoadHistory),
                Cmd::Store(StoreJob::LoadPrivacy),
                Cmd::Node(NodeJob::VaultCheck),
                Cmd::Node(NodeJob::Probe),
                Cmd::Node(NodeJob::DetectManaged),
                Cmd::Poll(PollCtl::Hints(PollHints::default())),
            ]
        );
        assert_eq!(app.identity(), &IdentityStatus::Ready);
        assert_eq!(app.me(), Some(&me()));
        assert_eq!(app.settings().receive, Receive::On);
        assert_eq!(
            app.node().program.binary,
            Path::new("/opt/raven/raven-node")
        );
        // Until the node is asked, the chip says nothing.
        assert_eq!(app.chip(), None);
        assert!(!app.jobs_in_flight().idle());
    }

    #[test]
    fn a_missing_or_unreadable_identity_touches_nothing() {
        for identity in [
            IdentityStart::Missing,
            IdentityStart::Unavailable("continuity".into()),
        ] {
            let mut app = app();
            let cmds = app.start(Session {
                identity: identity.clone(),
                ..session(Receive::On)
            });
            assert!(cmds.is_empty(), "{identity:?}: {cmds:?}");
            assert_eq!(app.chip(), None);
            assert_eq!(app.me(), None);
            // No start by itself, whatever happens.
            app.add_friend_opened();
            assert!(app.take_cmds().is_empty());
        }
    }

    #[test]
    fn the_node_starts_at_launch_with_a_friend() {
        let (app, cmds) = ready(Receive::On, 1);
        assert!(starts(&cmds), "{cmds:?}");
        assert!(matches!(app.node().state, NodeState::Starting { .. }));
        assert!(matches!(app.chip(), Some(Chip::Starting { .. })));
        // The poller asks every second meanwhile, and reads the service log.
        assert!(cmds.contains(&Cmd::Poll(PollCtl::Hints(PollHints {
            starting: true,
            live: false,
            read_log: true,
        }))));
    }

    #[test]
    fn nothing_starts_before_the_vault_check() {
        let mut app = app();
        app.start(session(Receive::On));
        assert!(!starts(&contacts(&mut app, 2)));
        assert!(starts(&vault(&mut app, false)));
    }

    /// Review E-harness-docs-ci-3: the app opened on a profile `raven lock`
    /// locked (mod.rs kept the lock). UNLOCK asks at once, and nothing starts
    /// Raven (the start by itself at launch, Add a friend's, NET's S) until
    /// its Enter cleared the lock; the start it held goes then. Esc keeps
    /// Raven stopped, and a toast says how to start it; NET's S asks again.
    #[test]
    fn after_raven_lock_the_app_asks_before_raven_starts() {
        let mut app = app();
        let mut cmds = app.start(Session {
            locked: true,
            ..session(Receive::On)
        });
        assert_eq!(app.overlays(), [Overlay::Unlock]);
        cmds.extend(history(&mut app));
        cmds.extend(answer(&mut app, JobResult::Privacy(Err(NotAvailable))));
        cmds.extend(vault(&mut app, false));
        cmds.extend(answer(&mut app, JobResult::Probed(not_running())));
        cmds.extend(answer(&mut app, JobResult::Managed(None)));
        cmds.extend(contacts(&mut app, 1));
        app.add_friend_opened();
        cmds.extend(app.take_cmds());
        assert!(!starts(&cmds), "{cmds:?}");
        assert!(app.cli_locked());
        // Esc: it stays stopped, and how to start it.
        let cmds = testkit::press(&mut app, KeyCode::Esc);
        assert!(!starts(&cmds) && !cmds.contains(&Cmd::Node(NodeJob::Unlock)));
        assert!(app.overlays().is_empty());
        assert_eq!(toasts(&app), [UNLOCK_KEPT_TOAST]);
        assert!(app.cli_locked());
        toasts_gone(&mut app);
        // NET's S asks again; Enter clears the lock first ...
        testkit::press(&mut app, KeyCode::Char('n'));
        let cmds = testkit::press(&mut app, KeyCode::Char('s'));
        assert!(!starts(&cmds), "{cmds:?}");
        assert_eq!(app.overlays(), [Overlay::Unlock]);
        let cmds = testkit::press(&mut app, KeyCode::Enter);
        assert!(cmds.contains(&Cmd::Node(NodeJob::Unlock)), "{cmds:?}");
        assert!(!starts(&cmds));
        assert!(app.overlays().is_empty());
        // ... and Raven starts once it is gone; the privacy read is asked
        // again (it says whether Raven's login item stays off).
        let cmds = answer(&mut app, JobResult::Unlocked(Ok(())));
        assert!(starts(&cmds), "{cmds:?}");
        assert!(
            cmds.contains(&Cmd::Store(StoreJob::LoadPrivacy)),
            "{cmds:?}"
        );
        assert!(!app.cli_locked());
    }

    /// UNLOCK's Enter at launch: the start by itself the lock held goes once
    /// the lock is gone. A lock that could not be cleared stays, a toast
    /// says how to clear it, and nothing starts; NET's S asks again.
    #[test]
    fn unlocks_enter_starts_what_the_lock_held() {
        let locked = |app: &mut App| {
            app.start(Session {
                locked: true,
                ..session(Receive::On)
            });
            vault(app, false);
            answer(app, JobResult::Probed(not_running()));
            assert!(!starts(&contacts(app, 1)));
            let cmds = testkit::press(app, KeyCode::Enter);
            assert!(cmds.contains(&Cmd::Node(NodeJob::Unlock)), "{cmds:?}");
            assert!(!starts(&cmds));
        };
        {
            let mut app = app();
            locked(&mut app);
            let cmds = answer(&mut app, JobResult::Unlocked(Ok(())));
            assert!(starts(&cmds), "{cmds:?}");
            assert!(!app.cli_locked());
        }
        {
            let mut app = app();
            locked(&mut app);
            let failed = answer(
                &mut app,
                JobResult::Unlocked(Err("privacy.json: permission denied".into())),
            );
            assert!(!starts(&failed), "{failed:?}");
            assert!(app.cli_locked());
            assert_eq!(toasts(&app), [UNLOCK_FAILED_TOAST]);
            testkit::press(&mut app, KeyCode::Char('n'));
            testkit::press(&mut app, KeyCode::Char('s'));
            assert_eq!(app.overlays(), [Overlay::Unlock]);
            testkit::press(&mut app, KeyCode::Enter);
            assert!(starts(&answer(&mut app, JobResult::Unlocked(Ok(())))));
        }
        // A profile `raven lock` did not lock never sees UNLOCK.
        let (plain, cmds) = ready(Receive::On, 1);
        assert!(plain.overlays().is_empty() && starts(&cmds));
    }

    /// UNLOCK when Raven runs anyway (started at login by a login item the
    /// lock left on): nothing to start, so it closes; the lock stays.
    #[test]
    fn unlock_closes_when_raven_runs_anyway() {
        let mut app = app();
        app.start(Session {
            locked: true,
            ..session(Receive::On)
        });
        assert_eq!(app.overlays(), [Overlay::Unlock]);
        answer(
            &mut app,
            JobResult::Probed(listening(4242, "127.0.0.1:55001")),
        );
        assert!(app.overlays().is_empty());
        assert!(app.cli_locked());
    }

    /// `raven lock` run in another window while the app is open: the start
    /// or send it refuses says Raven is locked, and NET's S then asks
    /// UNLOCK first instead of trying again.
    #[test]
    fn a_lock_set_while_the_app_runs_makes_nets_s_ask() {
        let (mut app, _) = ready(Receive::On, 1);
        let refused = Ensured {
            result: Err(raven_core::privacy::LOCKED_TEXT.to_owned()),
            after: not_running(),
            started_by_app: None,
            captured: String::new(),
            ring: 0..0,
        };
        answer(&mut app, JobResult::Ensured(refused));
        let NodeState::StartFailed(plain) = &app.node().state else {
            panic!("{:?}", app.node().state);
        };
        assert_eq!(plain.headline, "Raven is locked: `raven lock` stopped it.");
        assert_eq!(plain.next, "Press N, then S to start Raven again.");
        assert!(app.cli_locked());
        testkit::press(&mut app, KeyCode::Char('n'));
        let cmds = testkit::press(&mut app, KeyCode::Char('s'));
        assert!(!starts(&cmds));
        assert_eq!(app.overlays(), [Overlay::Unlock]);
    }

    #[test]
    fn without_a_friend_it_starts_when_add_a_friend_opens() {
        let (mut app, cmds) = ready(Receive::On, 0);
        assert!(!starts(&cmds));
        assert_eq!(app.chip(), Some(Chip::StartsWithFirstFriend));
        app.add_friend_opened();
        assert!(starts(&app.take_cmds()));
        // Opened again while it starts: one start.
        app.add_friend_opened();
        assert!(!starts(&app.take_cmds()));
    }

    #[test]
    fn a_vault_profile_without_a_passphrase_file_never_starts() {
        let mut app = app();
        app.start(session(Receive::On));
        vault(&mut app, true);
        let cmds = contacts(&mut app, 1);
        assert!(!starts(&cmds));
        assert_eq!(app.node().state, NodeState::NeedsPassphraseFile);
        assert_eq!(app.overlays(), [Overlay::PassFile]);
        assert_eq!(app.chip(), Some(Chip::NeedsSetup));
        // Esc closes it; a later skipped start does not show it again.
        testkit::press(&mut app, KeyCode::Esc);
        app.add_friend_opened();
        assert!(!starts(&app.take_cmds()));
        assert!(app.overlays().is_empty());
        // A node that runs anyway (with a file the user set) is shown.
        testkit::send(&mut app, Msg::Poll(PollUpdate::Status(not_running())));
        assert_eq!(app.node().state, NodeState::NeedsPassphraseFile);
        testkit::send(
            &mut app,
            Msg::Poll(PollUpdate::Status(listening(42, "0.0.0.0:7420"))),
        );
        assert_eq!(app.chip(), Some(Chip::Listening { port: Some(7420) }));
    }

    #[test]
    fn no_start_when_raven_cannot_tell_its_own_path() {
        let mut app = app();
        app.start(Session {
            program: Program {
                binary: "raven-node".into(),
                exe_known: false,
            },
            ..session(Receive::On)
        });
        vault(&mut app, false);
        assert!(!starts(&contacts(&mut app, 1)));
        app.add_friend_opened();
        assert!(!starts(&app.take_cmds()));
    }

    #[test]
    fn with_receiving_off_nothing_starts() {
        let (mut app, cmds) = ready(Receive::Off, 1);
        assert!(!starts(&cmds));
        assert_eq!(app.chip(), Some(Chip::ReceiveOff));
        app.add_friend_opened();
        assert!(!starts(&app.take_cmds()));
        assert!(app.overlays().is_empty());
    }

    #[test]
    fn rx_comes_before_the_first_start_and_yes_starts_it() {
        let (mut app, cmds) = ready(Receive::Unset, 1);
        assert!(!starts(&cmds));
        assert_eq!(
            app.overlays(),
            [Overlay::Receive(RxState {
                trigger: AutoStart::Launch,
                yes: true
            })]
        );
        let cmds = testkit::press(&mut app, KeyCode::Char('y'));
        assert!(starts(&cmds), "{cmds:?}");
        assert_eq!(saves(&cmds).map(|s| s.receive), Some(Receive::On));
        assert_eq!(app.settings().receive, Receive::On);
        assert!(app.overlays().is_empty());
        assert!(!cmds.contains(&Cmd::ApplyListenLoopback));
    }

    #[test]
    fn rx_no_sets_the_loopback_address_only_once_no_job_runs() {
        let mut app = app();
        app.start(session(Receive::Unset));
        vault(&mut app, false);
        contacts(&mut app, 1);
        history(&mut app);
        answer(&mut app, JobResult::Privacy(Err(NotAvailable)));
        // RX waits for the background program's first word (E1).
        assert!(app.overlays().is_empty());
        answer(&mut app, JobResult::Probed(not_running()));
        // The login-service check is still out.
        assert!(matches!(app.overlays(), [Overlay::Receive(_)]));
        let cmds = testkit::press(&mut app, KeyCode::Char('n'));
        assert!(!cmds.contains(&Cmd::ApplyListenLoopback), "{cmds:?}");
        assert_eq!(saves(&cmds), None, "the save waits behind it");
        assert_eq!(
            app.toast().map(|t| t.text.as_str()),
            Some(RECEIVE_OFF_TOAST)
        );
        assert_eq!(app.settings().receive, Receive::Off);
        // The last one answers: the address first, then what waited.
        let cmds = answer(&mut app, JobResult::Managed(None));
        let jobs: Vec<&Cmd> = cmds
            .iter()
            .filter(|cmd| !matches!(cmd, Cmd::Poll(_)))
            .collect();
        assert_eq!(jobs.len(), 2, "{cmds:?}");
        assert_eq!(jobs[0], &Cmd::ApplyListenLoopback);
        assert!(
            matches!(jobs[1], Cmd::Store(StoreJob::SaveSettings(s)) if s.receive == Receive::Off)
        );
        assert_eq!(app.listen, ListenOverride::Loopback);
        assert_eq!(app.chip(), Some(Chip::ReceiveOff));
        // Never twice, and nothing starts.
        let cmds = answer(&mut app, JobResult::SettingsSaved(Ok(())));
        assert!(!cmds.contains(&Cmd::ApplyListenLoopback));
        app.add_friend_opened();
        assert!(!starts(&app.take_cmds()));
    }

    #[test]
    fn rx_no_leaves_the_users_own_listen_address_alone() {
        let mut app = app();
        app.start(Session {
            listen: ListenOverride::User,
            ..session(Receive::Unset)
        });
        vault(&mut app, false);
        contacts(&mut app, 1);
        let mut cmds = testkit::press(&mut app, KeyCode::Char('N'));
        cmds.extend(answer(&mut app, JobResult::Probed(not_running())));
        cmds.extend(answer(&mut app, JobResult::Managed(None)));
        assert!(!cmds.contains(&Cmd::ApplyListenLoopback), "{cmds:?}");
        assert_eq!(app.listen, ListenOverride::User);
    }

    /// E1: a background program of this folder that receives already (a
    /// login item's, a script's) is the answer: RX never asks, and On is
    /// saved, so Settings says On too.
    #[test]
    fn rx_is_not_asked_while_this_folders_program_receives() {
        let mut app = app();
        app.start(session(Receive::Unset));
        vault(&mut app, false);
        contacts(&mut app, 1);
        history(&mut app);
        answer(&mut app, JobResult::Privacy(Err(NotAvailable)));
        assert!(app.overlays().is_empty(), "waits for its first word");
        let cmds = answer(
            &mut app,
            JobResult::Probed(listening(4242, "0.0.0.0:17420")),
        );
        assert!(app.overlays().is_empty(), "{:?}", app.overlays());
        assert_eq!(app.settings().receive, Receive::On);
        assert_eq!(saves(&cmds).map(|s| s.receive), Some(Receive::On));
        assert!(!starts(&cmds), "one runs already");

        // RX open, and then it starts receiving (started elsewhere): RX
        // closes with the same answer.
        let (mut asked, _) = ready(Receive::Unset, 1);
        assert!(matches!(asked.overlays(), [Overlay::Receive(_)]));
        let cmds = testkit::send(
            &mut asked,
            Msg::Poll(PollUpdate::Status(listening(77, "0.0.0.0:17420"))),
        );
        assert!(asked.overlays().is_empty());
        assert_eq!(saves(&cmds).map(|s| s.receive), Some(Receive::On));

        // Windows: not for another Raven folder's program.
        let mut other = self::app();
        other.set_windows_for_tests(true);
        other.start(session(Receive::Unset));
        vault(&mut other, false);
        contacts(&mut other, 1);
        testkit::send(
            &mut other,
            Msg::Poll(PollUpdate::NodeFolder {
                pid: 77,
                folder: NodeFolder::Other("D:\\other".into()),
            }),
        );
        answer(&mut other, JobResult::Probed(listening(77, "0.0.0.0:7420")));
        assert_eq!(other.settings().receive, Receive::Unset);
        // This folder's: nothing is asked or saved before its command line
        // is read; then On.
        let mut ours = self::app();
        ours.set_windows_for_tests(true);
        ours.start(session(Receive::Unset));
        vault(&mut ours, false);
        contacts(&mut ours, 1);
        answer(&mut ours, JobResult::Probed(listening(77, "0.0.0.0:17420")));
        assert!(ours.overlays().is_empty());
        assert_eq!(ours.settings().receive, Receive::Unset);
        let cmds = testkit::send(
            &mut ours,
            Msg::Poll(PollUpdate::NodeFolder {
                pid: 77,
                folder: NodeFolder::This,
            }),
        );
        assert_eq!(saves(&cmds).map(|s| s.receive), Some(Receive::On));
        assert!(ours.overlays().is_empty());
    }

    /// E1: RX names the port this folder's background program uses, not
    /// 7420 always.
    #[test]
    fn rx_names_the_port_of_this_profile() {
        let (mut app, _) = ready(Receive::Unset, 1);
        app.set_service_port_for_tests(17420);
        let screen = testkit::screen_text(&testkit::render(&app, 80, 24));
        assert!(screen.contains("(port 17420)"), "{screen}");
        // One that runs, not receiving from the network: its own port.
        testkit::send(
            &mut app,
            Msg::Poll(PollUpdate::Status(listening(4242, "127.0.0.1:27420"))),
        );
        assert!(matches!(app.overlays(), [Overlay::Receive(_)]));
        let screen = testkit::screen_text(&testkit::render(&app, 80, 24));
        assert!(screen.contains("(port 27420)"), "{screen}");
    }

    #[test]
    fn rx_keys_esc_is_not_now_and_a_paste_answers_nothing() {
        let (mut app, _) = ready(Receive::Unset, 1);
        // The arrows move the highlight; a pasted Enter answers nothing.
        testkit::press(&mut app, KeyCode::Down);
        assert!(matches!(
            app.overlays(),
            [Overlay::Receive(RxState { yes: false, .. })]
        ));
        testkit::paste(&mut app, "\n", PasteVia::Keystrokes);
        assert!(testkit::press(&mut app, KeyCode::Enter).is_empty());
        testkit::send(&mut app, Msg::Key(Key::PastedEnter));
        assert!(matches!(app.overlays(), [Overlay::Receive(_)]));
        // 300 ms on, Enter gives the highlighted answer: No.
        testkit::tick(&mut app, PASTE_GUARD);
        let cmds = testkit::press(&mut app, KeyCode::Enter);
        assert_eq!(app.settings().receive, Receive::Off);
        assert!(!starts(&cmds));

        // Esc is Not now, saved like N, so the next start doesn't ask
        // again (E1).
        let (mut app, _) = ready(Receive::Unset, 1);
        let cmds = testkit::press(&mut app, KeyCode::Esc);
        assert!(app.overlays().is_empty());
        assert_eq!(saves(&cmds).map(|s| s.receive), Some(Receive::Off));
        assert_eq!(app.settings().receive, Receive::Off);
        assert_eq!(
            app.toast().map(|t| t.text.as_str()),
            Some(RECEIVE_OFF_TOAST)
        );
        app.add_friend_opened();
        assert!(app
            .take_cmds()
            .iter()
            .all(|cmd| !matches!(cmd, Cmd::Node(_))));
        assert!(app.overlays().is_empty(), "not asked again");
        // Ctrl+C on RX opens QUIT over it.
        let (mut app, _) = ready(Receive::Unset, 1);
        testkit::ctrl(&mut app, 'c');
        assert!(matches!(
            app.overlays(),
            [Overlay::Receive(_), Overlay::Quit]
        ));
    }

    #[test]
    fn a_start_ends_in_what_the_node_says() {
        let (mut app, _) = ready(Receive::On, 1);
        // Its Status while starting does not end the spinner.
        testkit::send(
            &mut app,
            Msg::Poll(PollUpdate::Status(listening(4242, "127.0.0.1:55001"))),
        );
        assert!(matches!(app.chip(), Some(Chip::Starting { .. })));
        let cmds = answer(
            &mut app,
            JobResult::Ensured(Ensured {
                result: Ok(()),
                after: listening(4242, "127.0.0.1:55001"),
                started_by_app: Some(4242),
                captured: String::new(),
                ring: 0..0,
            }),
        );
        assert_eq!(app.chip(), Some(Chip::LocalOnly));
        assert_eq!(app.node().started_by_app, Some(4242));
        assert!(cmds.contains(&Cmd::Poll(PollCtl::Hints(PollHints::default()))));
        // Quitting leaves it running, and says so.
        testkit::press(&mut app, KeyCode::Char('q'));
        let cmds = testkit::press(&mut app, KeyCode::Enter);
        let [Cmd::Exit(plan)] = &cmds[..] else {
            panic!("{cmds:?}");
        };
        assert_eq!(plan.line, Some(still_running_line(4242)));
        assert!(plan.line.as_deref().is_some_and(
            |line| line.starts_with("Raven is still running in the background (process 4242)")
        ));
        // It went away: no longer ours, and nothing to name at quit.
        testkit::send(&mut app, Msg::Poll(PollUpdate::Status(not_running())));
        assert_eq!(app.node().started_by_app, None);
        assert_eq!(
            testkit::press(&mut app, KeyCode::Enter),
            [Cmd::Exit(ExitPlan::quit(None))]
        );
    }

    #[test]
    fn a_failed_start_says_why() {
        let failed = |why: &str| {
            let (mut app, _) = ready(Receive::On, 1);
            answer(
                &mut app,
                JobResult::Ensured(Ensured {
                    result: Err(why.into()),
                    after: not_running(),
                    started_by_app: None,
                    captured: String::new(),
                    ring: 0..0,
                }),
            );
            app
        };
        let app = failed(
            "this profile's keys are in a passphrase-protected vault (x) and this program \
             cannot ask for the passphrase. Set RAVEN_KEYSTORE_PASSPHRASE_FILE=<file>",
        );
        assert_eq!(app.node().state, NodeState::NeedsPassphraseFile);
        assert_eq!(app.overlays(), [Overlay::PassFile]);
        let app = failed(
            "could not start /x/raven-node (No such file or directory (os error 2)); build or \
             install raven-node next to ash",
        );
        match &app.node().state {
            NodeState::StartFailed(plain) => {
                assert_eq!(plain.headline, "Raven's background program is missing.");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(app.chip(), Some(Chip::NotRunning));
        assert!(app.overlays().is_empty());
        // One answers after all (another start won): no failure shown.
        let (mut app, _) = ready(Receive::On, 1);
        answer(
            &mut app,
            JobResult::Ensured(Ensured {
                result: Err("raven-node service exited during startup".into()),
                after: listening(7, "0.0.0.0:7420"),
                started_by_app: None,
                captured: String::new(),
                ring: 0..0,
            }),
        );
        assert_eq!(app.node().state, NodeState::Listening { port: Some(7420) });
        // A start that panicked.
        let (mut app, _) = ready(Receive::On, 1);
        answer(
            &mut app,
            JobResult::Failed {
                job: JobName::NodeEnsure,
                plain: errors::explain_panic("boom", ""),
            },
        );
        assert!(matches!(app.node().state, NodeState::StartFailed(_)));
        assert_eq!(
            app.toast().map(|t| t.text.as_str()),
            Some("Something went wrong inside Raven.")
        );
    }

    const WATCHDOG: &str =
        "raven: still waiting for macOS Keychain access (your Raven identity) after 3s.";

    #[test]
    fn a_keychain_wait_opens_kc_while_a_job_runs() {
        // Nothing runs: nothing can be waiting.
        let (mut app, _) = ready(Receive::Off, 0);
        assert!(app.jobs_in_flight().idle());
        testkit::send(&mut app, Msg::Stderr(WATCHDOG.into()));
        assert_eq!(app.keychain(), None);

        let mut app = app_started(Receive::On);
        testkit::send(&mut app, Msg::Stderr(WATCHDOG.into()));
        assert_eq!(app.overlays(), [Overlay::Keychain]);
        let kc = app.keychain().expect("a wait");
        assert_eq!(
            (kc.wait.item, kc.wait.service),
            ("your Raven identity", false)
        );
        assert_eq!(app.chip(), Some(Chip::WaitingForPermission));
        assert_eq!(app.keychain_pulse(), Some(app.now()));
        assert!(app.poll_hints().read_log);
        // Esc hides it; the chip still says so, and the same wait stays hidden.
        testkit::press(&mut app, KeyCode::Esc);
        assert!(app.overlays().is_empty());
        assert_eq!(app.keychain_pulse(), None);
        assert_eq!(app.chip(), Some(Chip::WaitingForPermission));
        testkit::send(&mut app, Msg::Stderr(WATCHDOG.into()));
        assert!(app.overlays().is_empty());
        // Every job answered: the wait is over.
        vault(&mut app, false);
        answer(&mut app, JobResult::Probed(not_running()));
        answer(&mut app, JobResult::Managed(None));
        history(&mut app);
        answer(&mut app, JobResult::Privacy(Err(NotAvailable)));
        assert!(app.keychain().is_some(), "contacts still loading");
        contacts(&mut app, 0);
        assert_eq!(app.keychain(), None);
        assert_eq!(app.chip(), Some(Chip::StartsWithFirstFriend));
    }

    #[test]
    fn the_service_log_says_what_raven_node_waits_for() {
        let (mut app, _) = ready(Receive::On, 1);
        let marker = raven_core::macos_keychain::daemon_marker_line(
            raven_core::macos_keychain::KeychainWhat::SessionSecret,
            33,
        );
        testkit::send(
            &mut app,
            Msg::Poll(PollUpdate::ServiceLog(format!("{marker}\n"))),
        );
        let kc = app.keychain().expect("a wait");
        assert_eq!(
            (kc.wait.item, kc.wait.service),
            ("a conversation key", true)
        );
        assert_eq!(app.overlays(), [Overlay::Keychain]);
        // ext.rs's own note about it is the same wait.
        testkit::press(&mut app, KeyCode::Esc);
        testkit::send(
            &mut app,
            Msg::Stderr(
                "note: raven-node (the background service) is waiting for macOS Keychain \
                 access to a conversation key."
                    .into(),
            ),
        );
        assert!(app.overlays().is_empty());
        // Only while starting: a marker read later means nothing.
        let (mut app, _) = ready(Receive::Off, 1);
        app.jobs_in_flight.start(JobKind::Store);
        testkit::send(&mut app, Msg::Poll(PollUpdate::ServiceLog(marker)));
        assert_eq!(app.keychain(), None);
    }

    /// Started with `receive`, its first jobs still out.
    fn app_started(receive: Receive) -> App {
        let mut app = app();
        app.start(session(receive));
        app
    }

    #[test]
    fn contacts_load_again_when_the_file_changes() {
        let (mut app, _) = ready(Receive::On, 0);
        let changed = FileStamp::of(&std::env::current_exe().expect("a file"));
        let seen = |app: &mut App, stamp| {
            testkit::send(
                app,
                Msg::Poll(PollUpdate::File {
                    watched: Watched::Contacts,
                    stamp,
                }),
            )
        };
        // What the load saw: nothing to do.
        assert!(seen(&mut app, FileStamp::default()).is_empty());
        assert_eq!(
            seen(&mut app, changed),
            [Cmd::Store(StoreJob::LoadContacts)]
        );
        // Changed again while that load runs: one load at a time, then
        // another for what it may have missed.
        let again = FileStamp::of(&std::env::temp_dir());
        assert!(seen(&mut app, again).is_empty());
        let cmds = contacts(&mut app, 1);
        assert!(
            cmds.contains(&Cmd::Store(StoreJob::LoadContacts)),
            "{cmds:?}"
        );
        // The history file loads the conversations, not the friends.
        let history = testkit::send(
            &mut app,
            Msg::Poll(PollUpdate::File {
                watched: Watched::History,
                stamp: changed,
            }),
        );
        assert_eq!(history, [Cmd::Store(StoreJob::LoadHistory)]);
        // A list that can't be read keeps the friends, and says why.
        answer(
            &mut app,
            JobResult::Contacts {
                contacts: Err("contacts.json: corrupt".into()),
                stamp: again,
            },
        );
        assert_eq!(app.friends.len(), 1);
        assert_eq!(
            app.contacts_error.as_deref(),
            Some("contacts.json: corrupt")
        );
        assert_eq!(app.contacts, [testkit::friend(1)]);
    }

    #[test]
    fn a_live_outbox_has_the_poller_look_more_often() {
        let (mut app, _) = ready(Receive::Off, 0);
        let item = |state: &str| OutboxItem {
            state: state.into(),
            ..OutboxItem::default()
        };
        let list = |app: &mut App, peer: Option<String>, items| {
            testkit::send(app, Msg::Poll(PollUpdate::Outbox { peer, items }))
        };
        let live = Cmd::Poll(PollCtl::Hints(PollHints {
            live: true,
            ..PollHints::default()
        }));
        assert_eq!(
            list(&mut app, None, vec![item("queued")]),
            std::slice::from_ref(&live)
        );
        assert!(list(&mut app, None, vec![item("held")]).is_empty());
        // One friend's list says nothing about the others.
        assert!(list(&mut app, Some("ab".repeat(32)), vec![item("delivered")]).is_empty());
        assert_eq!(
            list(&mut app, None, vec![item("delivered"), item("cancelled")]),
            [Cmd::Poll(PollCtl::Hints(PollHints::default()))]
        );
        assert_eq!(
            list(&mut app, Some("ab".repeat(32)), vec![item("sent")]),
            [live]
        );
        // Windows' stopped polling is kept for NET.
        testkit::send(&mut app, Msg::Poll(PollUpdate::StatusStopped));
        assert!(app.node().polling_stopped);
    }

    #[test]
    fn job_counts_follow_the_answers() {
        let mut app = app_started(Receive::On);
        assert_eq!(
            app.jobs_in_flight,
            JobCounts {
                store: 3,
                node: 3,
                ..JobCounts::default()
            }
        );
        let names = [
            JobResult::Managed(Some(Managed::LaunchAgent)).name(),
            JobResult::SettingsSaved(Ok(())).name(),
            JobResult::Stopped(Stopped {
                outcome: StopOutcome::NotRunning,
                after: not_running(),
            })
            .name(),
        ];
        assert_eq!(
            names,
            [
                JobName::NodeManaged,
                JobName::SaveSettings,
                JobName::NodeStop
            ]
        );
        let stop = NodeJob::Stop {
            started_by_app: Some(42),
            managed: false,
        };
        assert_eq!(stop.name(), JobName::NodeStop);
        assert_eq!(JobName::NodeStop.kind(), JobKind::Node);
        assert_eq!(JobName::SaveSettings.kind(), JobKind::Store);
        answer(&mut app, JobResult::Managed(Some(Managed::LaunchAgent)));
        assert_eq!(app.node().managed, Some(Managed::LaunchAgent));
        answer(
            &mut app,
            JobResult::Stopped(Stopped {
                outcome: StopOutcome::Stopped,
                after: not_running(),
            }),
        );
        assert_eq!(app.node().state, NodeState::NotRunning);
        // A settings save that failed is said.
        answer(&mut app, JobResult::SettingsSaved(Err("disk full".into())));
        assert_eq!(
            app.toast().map(|t| t.text.as_str()),
            Some(SETTINGS_NOT_SAVED)
        );
    }

    #[test]
    fn ctrl_z_explains_instead_of_pausing() {
        let mut app = app();
        assert!(testkit::ctrl(&mut app, 'z').is_empty());
        assert_eq!(toast_text(&app), Some(PAUSE_TOAST));
        // Under an overlay and in SMALL too, leaving both as they were.
        testkit::press(&mut app, KeyCode::Char('?'));
        testkit::tick(&mut app, TOAST_TIME);
        assert_eq!(toast_text(&app), None);
        testkit::ctrl(&mut app, 'z');
        assert_eq!(toast_text(&app), Some(PAUSE_TOAST));
        assert_eq!(app.overlays(), [Overlay::Help { scroll: 0 }]);
        let mut app = testkit::app((40, 3));
        assert!(testkit::ctrl(&mut app, 'Z').is_empty());
        assert_eq!(toast_text(&app), Some(PAUSE_TOAST));
        assert!(app.too_small());
    }

    // ── the first run ───────────────────────────────────────────────────────

    /// The identity the store worker reports made (seed 9), and its warning.
    fn made(prekey_warning: Option<&str>) -> JobResult {
        JobResult::Created {
            result: Ok(NewIdentity {
                me: bridge::me_view(&Identity::from_seed(&[9; 32])),
                prekey_warning: prekey_warning.map(str::to_owned),
            }),
            captured: String::new(),
        }
    }

    /// A creation raven-core refused with `e`.
    fn refused(e: raven_core::IdentityStoreError, captured: &str) -> JobResult {
        JobResult::Created {
            result: Err(e.redacted_display()),
            captured: captured.into(),
        }
    }

    fn step(app: &App) -> &WizardStep {
        match app.screen() {
            Screen::Wizard(step) => step,
            other => panic!("not the wizard: {other:?}"),
        }
    }

    fn failure(app: &App) -> &Failure {
        match app.screen() {
            Screen::IdentityError(failure)
            | Screen::Wizard(WizardStep::Creating(Creating::Failed(failure))) => failure,
            other => panic!("no failure on show: {other:?}"),
        }
    }

    /// The wizard on WZ-4 with `name` typed and the receive question
    /// answered `yes`: the vault check is out. Returns what the answer asked.
    fn to_creating(name: &str, yes: bool) -> (App, Vec<Cmd>) {
        let mut app = testkit::wizard_app((80, 24));
        testkit::press(&mut app, KeyCode::Enter);
        for c in name.chars() {
            testkit::press(&mut app, KeyCode::Char(c));
        }
        testkit::press(&mut app, KeyCode::Enter);
        let cmds = testkit::press(&mut app, KeyCode::Char(if yes { 'y' } else { 'n' }));
        (app, cmds)
    }

    #[test]
    fn the_wizard_walks_from_welcome_to_ready() {
        let mut app = testkit::wizard_app((80, 24));
        assert!(matches!(step(&app), WizardStep::Welcome { since: Some(_) }));
        assert_eq!(app.identity(), &IdentityStatus::Missing);
        assert_eq!(app.folder(), Path::new(testkit::FOLDER));
        // No job until the receive question is answered.
        assert!(testkit::press(&mut app, KeyCode::Enter).is_empty());
        assert_eq!(step(&app), &WizardStep::Name);
        for c in " Sam ".chars() {
            assert!(testkit::press(&mut app, KeyCode::Char(c)).is_empty());
        }
        assert!(testkit::press(&mut app, KeyCode::Enter).is_empty());
        assert_eq!(step(&app), &WizardStep::Receive { yes: true });
        assert_eq!(app.settings().display_name, "Sam", "trimmed");
        // N: receiving off, so a node started from now on listens on this
        // computer only; nothing runs, so the address is set at once. Then
        // the vault check.
        let cmds = testkit::press(&mut app, KeyCode::Char('n'));
        assert_eq!(
            cmds,
            [Cmd::ApplyListenLoopback, Cmd::Store(StoreJob::CheckVault)]
        );
        assert_eq!(app.listen, ListenOverride::Loopback);
        assert_eq!(app.settings().receive, Receive::Off);
        assert_eq!(toast_text(&app), Some(RECEIVE_OFF_TOAST));
        assert!(matches!(
            step(&app),
            WizardStep::Creating(Creating::Working { .. })
        ));
        assert!(app.finishing_setup());
        // No prompt needed: the store worker makes it, as a critical job.
        let cmds = answer(&mut app, JobResult::VaultChecked { prompts: false });
        assert_eq!(cmds, [Cmd::Store(StoreJob::CreateIdentity)]);
        assert!(app.jobs_in_flight().holds_classic());
        // Made: the name and the answer are saved first, then the first
        // jobs go out as for a profile that had an identity.
        let cmds = answer(&mut app, made(None));
        assert_eq!(app.identity(), &IdentityStatus::Ready);
        assert_eq!(
            app.me(),
            Some(&bridge::me_view(&Identity::from_seed(&[9; 32])))
        );
        assert!(matches!(step(&app), WizardStep::Words { .. }));
        assert!(!app.finishing_setup());
        assert_eq!(
            cmds,
            [
                Cmd::Store(StoreJob::SaveSettings(TuiState {
                    display_name: "Sam".into(),
                    receive: Receive::Off,
                    ..TuiState::default()
                })),
                Cmd::Poll(PollCtl::Start),
                Cmd::Store(StoreJob::LoadContacts),
                Cmd::Store(StoreJob::LoadHistory),
                Cmd::Store(StoreJob::LoadPrivacy),
                Cmd::Node(NodeJob::VaultCheck),
                Cmd::Node(NodeJob::Probe),
                Cmd::Node(NodeJob::DetectManaged),
                Cmd::Poll(PollCtl::Hints(PollHints::default())),
            ]
        );
        // WZ-5 has no way back, and only Enter goes on; WZ-6's Enter opens
        // Raven.
        for code in [KeyCode::Esc, KeyCode::Char('q'), KeyCode::Backspace] {
            testkit::press(&mut app, code);
        }
        assert!(matches!(step(&app), WizardStep::Words { .. }));
        testkit::press(&mut app, KeyCode::Enter);
        assert_eq!(step(&app), &WizardStep::Ready);
        assert!(testkit::press(&mut app, KeyCode::Enter).is_empty());
        assert_eq!(app.screen(), &Screen::Home);
    }

    #[test]
    fn a_vault_profile_makes_its_identity_on_the_plain_terminal() {
        let (mut app, cmds) = to_creating("", true);
        assert_eq!(cmds, [Cmd::Store(StoreJob::CheckVault)]);
        assert_eq!(app.settings().receive, Receive::On);
        assert_eq!(app.settings().display_name, "");
        let cmds = answer(&mut app, JobResult::VaultChecked { prompts: true });
        assert_eq!(cmds, [Cmd::Suspend(SuspendJob::CreateIdentity)]);
        assert_eq!(
            app.jobs_in_flight,
            JobCounts {
                critical: 1,
                ..JobCounts::default()
            }
        );
        // The UI thread hands its result back as a worker does. A missing
        // prekey is a toast, and Raven goes on.
        answer(&mut app, made(Some("prekey: disk full")));
        assert_eq!(toast_text(&app), Some(PREKEY_TOAST));
        assert!(matches!(step(&app), WizardStep::Words { .. }));
        assert_eq!(app.jobs_in_flight.critical, 0);
    }

    #[test]
    fn the_name_field_takes_text_and_stops_at_its_limit() {
        let mut app = testkit::wizard_app((80, 24));
        testkit::press(&mut app, KeyCode::Enter);
        // Letters that are shortcuts elsewhere are text here.
        for c in ['q', 'Q', '?', 'c', 'y'] {
            assert!(testkit::press(&mut app, KeyCode::Char(c)).is_empty());
        }
        assert_eq!(app.name(), "qQ?cy");
        assert!(app.overlays().is_empty());
        for _ in 0..6 {
            testkit::press(&mut app, KeyCode::Backspace);
        }
        assert_eq!(app.name(), "");
        // Typing stops at 32 cells, and says why; a wide character takes
        // two of them.
        for _ in 0..40 {
            testkit::press(&mut app, KeyCode::Char('x'));
        }
        assert_eq!(app.name(), "x".repeat(NAME_CELLS));
        assert!(app.name_full());
        testkit::press(&mut app, KeyCode::Backspace);
        assert!(!app.name_full());
        testkit::press(&mut app, KeyCode::Char('名'));
        assert_eq!(app.name().len(), NAME_CELLS - 1, "no room for two cells");
        assert!(app.name_full());

        // A paste is one line without control characters, and never goes on.
        let mut app = testkit::wizard_app((80, 24));
        testkit::paste(&mut app, "ignored", PasteVia::Bracketed);
        testkit::tick(&mut app, PASTE_GUARD);
        testkit::press(&mut app, KeyCode::Enter);
        assert_eq!(app.name(), "", "only WZ-2 takes text");
        testkit::paste(&mut app, "Sa\r\nm\t\u{7}!", PasteVia::Keystrokes);
        assert_eq!(app.name(), "Sam !");
        assert_eq!(step(&app), &WizardStep::Name);
        // A pasted Enter, or one right after a paste, goes nowhere.
        testkit::send(&mut app, Msg::Key(Key::PastedEnter));
        testkit::press(&mut app, KeyCode::Enter);
        assert_eq!(step(&app), &WizardStep::Name);
        let rest = "y".repeat(100);
        testkit::paste(&mut app, &rest, PasteVia::Bracketed);
        assert_eq!(display::width(app.name()), NAME_CELLS);
        assert!(app.name_full());
        // Esc goes back, keeping the name; WZ-1's letters are all there.
        testkit::press(&mut app, KeyCode::Esc);
        assert_eq!(step(&app), &WizardStep::Welcome { since: None });
        testkit::tick(&mut app, PASTE_GUARD);
        testkit::press(&mut app, KeyCode::Enter);
        assert_eq!(step(&app), &WizardStep::Name);
        assert_eq!(display::width(app.name()), NAME_CELLS);
        // Ctrl+C still opens QUIT.
        testkit::ctrl(&mut app, 'c');
        assert_eq!(app.overlays(), [Overlay::Quit]);
    }

    #[test]
    fn the_receive_step_moves_its_highlight_and_goes_back() {
        let mut app = testkit::wizard_app((80, 24));
        testkit::press(&mut app, KeyCode::Enter);
        testkit::press(&mut app, KeyCode::Enter);
        let mut seen = Vec::new();
        for code in [KeyCode::Down, KeyCode::Tab, KeyCode::Left] {
            assert!(testkit::press(&mut app, code).is_empty());
            seen.push(step(&app).clone());
        }
        assert_eq!(
            seen,
            [false, true, false].map(|yes| WizardStep::Receive { yes })
        );
        // A pasted Enter answers nothing.
        testkit::paste(&mut app, "\n", PasteVia::Keystrokes);
        assert!(testkit::press(&mut app, KeyCode::Enter).is_empty());
        testkit::send(&mut app, Msg::Key(Key::PastedEnter));
        assert_eq!(step(&app), &WizardStep::Receive { yes: false });
        // Esc goes back to the name; Enter there asks again, Yes first.
        testkit::press(&mut app, KeyCode::Esc);
        assert_eq!(step(&app), &WizardStep::Name);
        testkit::tick(&mut app, PASTE_GUARD);
        testkit::press(&mut app, KeyCode::Enter);
        assert_eq!(step(&app), &WizardStep::Receive { yes: true });
        // Enter gives the highlighted answer.
        testkit::press(&mut app, KeyCode::Up);
        let cmds = testkit::press(&mut app, KeyCode::Enter);
        assert_eq!(app.settings().receive, Receive::Off);
        assert!(cmds.contains(&Cmd::ApplyListenLoopback));

        // The user's own listen address is left alone.
        let mut app = testkit::app((80, 24));
        app.start(Session {
            identity: IdentityStart::Missing,
            listen: ListenOverride::User,
            ..session(Receive::Unset)
        });
        testkit::press(&mut app, KeyCode::Enter);
        testkit::press(&mut app, KeyCode::Enter);
        let cmds = testkit::press(&mut app, KeyCode::Char('N'));
        assert_eq!(cmds, [Cmd::Store(StoreJob::CheckVault)]);
        assert_eq!(app.listen, ListenOverride::User);
        // Y: receiving on, and nothing more until the identity exists.
        let (app, cmds) = to_creating("", true);
        assert_eq!(cmds, [Cmd::Store(StoreJob::CheckVault)]);
        assert_eq!(app.settings().receive, Receive::On);
        assert_eq!(app.toast(), None);
    }

    #[test]
    fn welcome_offers_the_classic_menu_help_and_quit() {
        let mut app = testkit::wizard_app((80, 24));
        for c in ['c', 'C'] {
            assert_eq!(
                testkit::press(&mut app, KeyCode::Char(c)),
                [Cmd::SwitchToClassic]
            );
        }
        // Nothing runs yet: Q and Esc quit at once.
        for code in [KeyCode::Char('q'), KeyCode::Char('Q'), KeyCode::Esc] {
            assert_eq!(
                testkit::press(&mut app, code),
                [Cmd::Exit(ExitPlan::quit(None))]
            );
        }
        testkit::press(&mut app, KeyCode::Char('?'));
        assert_eq!(app.overlays(), [Overlay::Help { scroll: 0 }]);
        testkit::press(&mut app, KeyCode::Esc);
        testkit::ctrl(&mut app, 'c');
        assert_eq!(app.overlays(), [Overlay::Quit]);
        assert_eq!(
            testkit::press(&mut app, KeyCode::Enter),
            [Cmd::Exit(ExitPlan::quit(None))]
        );
        testkit::press(&mut app, KeyCode::Esc);
        // A paste starts nothing.
        testkit::paste(&mut app, "\n", PasteVia::Bracketed);
        testkit::press(&mut app, KeyCode::Enter);
        testkit::send(&mut app, Msg::Key(Key::PastedEnter));
        assert!(matches!(step(&app), WizardStep::Welcome { .. }));
    }

    #[test]
    fn a_refusal_over_leftover_files_is_err_id_and_never_a_retry() {
        let (mut app, _) = to_creating("Sam", true);
        answer(&mut app, JobResult::VaultChecked { prompts: false });
        let continuity = raven_core::IdentityStoreError::Continuity(
            "profile contains state but has no identity continuity record",
        );
        let cmds = answer(&mut app, refused(continuity, "printed\n"));
        assert!(cmds.is_empty(), "{cmds:?}");
        assert!(matches!(app.screen(), Screen::IdentityError(_)));
        let shown = failure(&app);
        assert!(shown
            .plain
            .headline
            .starts_with("This folder has Raven files but no identity."));
        assert!(shown.plain.technical.contains("continuity"));
        assert!(shown.plain.technical.ends_with("printed"));
        assert!(!shown.details);
        assert_eq!(app.identity(), &IdentityStatus::Missing);
        // Nothing there makes a new identity.
        assert!(testkit::press(&mut app, KeyCode::Char('r')).is_empty());
        assert!(testkit::press(&mut app, KeyCode::Enter).is_empty());
        testkit::press(&mut app, KeyCode::Char('d'));
        assert!(failure(&app).details);
        testkit::press(&mut app, KeyCode::Char('D'));
        assert!(!failure(&app).details);
        assert_eq!(
            testkit::press(&mut app, KeyCode::Char('c')),
            [Cmd::SwitchToClassic]
        );
    }

    #[test]
    fn any_other_failure_stays_on_wz4_with_try_again() {
        let (mut app, _) = to_creating("Sam", true);
        answer(&mut app, JobResult::VaultChecked { prompts: false });
        let denied =
            raven_core::IdentityStoreError::SecureStore("keychain get status -25293".into());
        answer(&mut app, refused(denied, ""));
        assert_eq!(
            failure(&app).plain.headline,
            "Raven wasn't allowed to read your identity from the system keychain."
        );
        assert!(matches!(
            step(&app),
            WizardStep::Creating(Creating::Failed(_))
        ));
        testkit::press(&mut app, KeyCode::Char('d'));
        assert!(failure(&app).details);
        // R starts again from the vault check.
        assert_eq!(
            testkit::press(&mut app, KeyCode::Char('R')),
            [Cmd::Store(StoreJob::CheckVault)]
        );
        assert!(app.finishing_setup());
        // A job that panicked says so the same way.
        answer(
            &mut app,
            JobResult::Failed {
                job: JobName::CheckVault,
                plain: errors::explain_panic("boom", ""),
            },
        );
        assert_eq!(
            failure(&app).plain.headline,
            "Something went wrong inside Raven."
        );
        assert_eq!(
            testkit::press(&mut app, KeyCode::Char('q')),
            [Cmd::Exit(ExitPlan::quit(None))]
        );
    }

    #[test]
    fn quit_waits_while_the_identity_is_made() {
        let (mut app, _) = to_creating("", true);
        // Only Ctrl+C means something on WZ-4 while it works.
        for code in [
            KeyCode::Char('q'),
            KeyCode::Char('r'),
            KeyCode::Esc,
            KeyCode::Enter,
        ] {
            assert!(testkit::press(&mut app, code).is_empty());
        }
        assert!(app.overlays().is_empty());
        testkit::ctrl(&mut app, 'c');
        assert_eq!(app.overlays(), [Overlay::Quit]);
        assert!(
            testkit::press(&mut app, KeyCode::Enter).is_empty(),
            "no quitting while it is made"
        );
        assert_eq!(app.overlays(), [Overlay::Quit]);
        // Nor the classic menu, once the identity is being written.
        answer(&mut app, JobResult::VaultChecked { prompts: false });
        resize(&mut app, 40, 3);
        assert!(testkit::press(&mut app, KeyCode::Char('c')).is_empty());
        assert_eq!(toast_text(&app), Some(FINISHING_TOAST));
        resize(&mut app, 80, 24);
        // Made: QUIT asks as usual, and Enter quits. A new profile quits
        // with receiving on for the first time: the laptop note (UXF.9).
        answer(&mut app, made(None));
        assert_eq!(app.overlays(), [Overlay::Quit]);
        assert!(!app.finishing_setup());
        let seen = TuiState {
            exit_note_shown: true,
            ..app.settings().clone()
        };
        assert_eq!(
            testkit::press(&mut app, KeyCode::Enter),
            [Cmd::Exit(ExitPlan {
                line: Some(EXIT_NOTE.to_owned()),
                save: Some(seen),
                ..ExitPlan::quit(None)
            })]
        );
    }

    #[test]
    fn an_unreadable_identity_store_opens_err_id() {
        let mut app = app();
        let denied =
            raven_core::IdentityStoreError::SecureStore("keychain get status -25293".into());
        let cmds = app.start(Session {
            identity: IdentityStart::Unavailable(denied.redacted_display()),
            ..session(Receive::On)
        });
        assert!(cmds.is_empty(), "nothing touches the profile: {cmds:?}");
        assert_eq!(
            failure(&app).plain.headline,
            "Raven wasn't allowed to read your identity from the system keychain."
        );
        // ERR-ID has no help key, takes no text and offers no identity.
        for code in [KeyCode::Char('?'), KeyCode::Char('r'), KeyCode::Enter] {
            assert!(testkit::press(&mut app, code).is_empty());
        }
        testkit::paste(&mut app, "q\n", PasteVia::Bracketed);
        assert!(app.overlays().is_empty());
        testkit::press(&mut app, KeyCode::Char('d'));
        assert!(failure(&app).details);
        testkit::ctrl(&mut app, 'c');
        assert_eq!(app.overlays(), [Overlay::Quit]);
        testkit::press(&mut app, KeyCode::Esc);
        assert_eq!(
            testkit::press(&mut app, KeyCode::Char('C')),
            [Cmd::SwitchToClassic]
        );
        for code in [KeyCode::Char('q'), KeyCode::Esc] {
            assert_eq!(
                testkit::press(&mut app, code),
                [Cmd::Exit(ExitPlan::quit(None))]
            );
        }
    }

    #[test]
    fn add_a_friend_on_wz6_starts_the_node_only_when_receiving() {
        for yes in [true, false] {
            let (mut app, _) = to_creating("Sam", yes);
            answer(&mut app, JobResult::VaultChecked { prompts: false });
            answer(&mut app, made(None));
            vault(&mut app, false);
            answer(&mut app, JobResult::Probed(not_running()));
            answer(&mut app, JobResult::Managed(None));
            contacts(&mut app, 0);
            // WZ-6's header chip.
            let chip = if yes {
                Chip::StartsWithFirstFriend
            } else {
                Chip::ReceiveOff
            };
            assert_eq!(app.chip(), Some(chip), "{yes}");
            testkit::press(&mut app, KeyCode::Enter);
            assert_eq!(step(&app), &WizardStep::Ready);
            let cmds = testkit::press(&mut app, KeyCode::Char('a'));
            assert!(matches!(app.screen(), Screen::AddFriend(_)), "{yes}");
            assert_eq!(starts(&cmds), yes, "{cmds:?}");
            // Esc there goes on to Home.
            testkit::press(&mut app, KeyCode::Esc);
            assert_eq!(app.screen(), &Screen::Home);
        }
    }

    // ── Home: conversations, unread, the composer ──────────────────────────

    /// Bob (1) and Alice (2), both reachable, receiving off, `rows` loaded,
    /// at 100x30; drawn once.
    fn home(rows: &[(u8, RowView)]) -> App {
        let mut app = testkit::home_app(
            (100, 30),
            Receive::Off,
            vec![testkit::reachable(1), testkit::reachable(2)],
            testkit::conversations(rows),
        );
        app.take_dirty();
        app
    }

    /// The key friend `n`'s conversation goes by.
    fn key_of(n: u8) -> String {
        testkit::friend(n).pub_hex
    }

    /// The read markers a save among `cmds` carries.
    fn marks(cmds: &[Cmd]) -> Option<&TuiState> {
        cmds.iter().find_map(|cmd| match cmd {
            Cmd::Store(StoreJob::SaveReadMarks(state)) => Some(state),
            _ => None,
        })
    }

    fn history_changed(app: &mut App, stamp: FileStamp) -> Vec<Cmd> {
        testkit::send(
            app,
            Msg::Poll(PollUpdate::File {
                watched: Watched::History,
                stamp,
            }),
        )
    }

    #[test]
    fn the_first_history_load_is_seen_at_the_start_and_later_rows_are_new() {
        let first = [
            (1, testkit::row(1, false, "", 10, "hi")),
            (1, testkit::row(2, true, "queued", 9, "hello?")),
        ];
        let mut app = home(&first);
        assert!(app
            .rows(&key_of(1))
            .iter()
            .all(|row| row.seen_at_start && row.touched.is_none()));
        // The poller saw the file change: one load, and one at a time.
        testkit::tick(&mut app, Duration::from_secs(3));
        let at = Touch {
            at: app.now(),
            at_ms: app.now_ms(),
        };
        let changed = FileStamp::of(&std::env::current_exe().expect("a file"));
        assert_eq!(
            history_changed(&mut app, changed),
            [Cmd::Store(StoreJob::LoadHistory)]
        );
        let again = FileStamp::of(&std::env::temp_dir());
        assert!(history_changed(&mut app, again).is_empty());
        // Bob's reply came, and the one waiting was delivered.
        let later = [
            first[0].clone(),
            (1, testkit::row(2, true, "delivered", 9, "hello?")),
            (1, testkit::row(3, false, "", 0, "yes!")),
        ];
        let cmds = testkit::reload(&mut app, &later, changed);
        let (hints, jobs): (Vec<&Cmd>, Vec<&Cmd>) =
            cmds.iter().partition(|cmd| matches!(cmd, Cmd::Poll(_)));
        assert_eq!(
            jobs,
            [&Cmd::Store(StoreJob::LoadHistory)],
            "it changed again while it was read"
        );
        // Nothing of yours waits now: the outbox is listed less often.
        assert!(
            matches!(&hints[..], [Cmd::Poll(PollCtl::Hints(h))] if !h.live),
            "{hints:?}"
        );
        assert!(app.take_dirty());
        let rows = app.rows(&key_of(1));
        assert_eq!(rows.len(), 3);
        assert!(rows[0].seen_at_start && rows[0].touched.is_none());
        assert!(rows[1].seen_at_start, "the same row as at the start");
        assert_eq!(rows[1].touched, Some(at), "delivered since");
        assert!(!rows[2].seen_at_start);
        assert_eq!(rows[2].touched, Some(at));
        assert!(app.rows(&key_of(2)).is_empty());
        // Order is the history's, whatever the clocks say.
        let bodies: Vec<&str> = rows.iter().map(|row| row.view.body.as_str()).collect();
        assert_eq!(bodies, ["hi", "hello?", "yes!"]);
        // A load that fails keeps the conversations, and says why.
        testkit::send(
            &mut app,
            Msg::Job(JobResult::History {
                history: Err("chat history is corrupt".into()),
                stamp: again,
            }),
        );
        assert_eq!(app.rows(&key_of(1)).len(), 3);
        assert_eq!(app.history_error(), Some("chat history is corrupt"));
        assert!(app.jobs_in_flight().idle());
        // A load that panicked too.
        history_changed(&mut app, changed);
        testkit::send(
            &mut app,
            Msg::Job(JobResult::Failed {
                job: JobName::LoadHistory,
                plain: errors::explain_panic("boom", ""),
            }),
        );
        assert_eq!(app.history_error(), Some("panic: boom"));
        assert!(app.jobs_in_flight().idle());
    }

    #[test]
    fn unread_counts_their_messages_after_the_last_one_read() {
        let rows = [
            (1, testkit::row(1, false, "", 10, "a")),
            (1, testkit::row(2, true, "delivered", 9, "b")),
            (1, testkit::row(3, false, "", 8, "c")),
            (2, testkit::row(4, false, "", 7, "d")),
        ];
        let mut app = home(&rows);
        assert_eq!((app.unread(&key_of(1)), app.unread(&key_of(2))), (2, 1));
        assert_eq!(app.marks_due(), None, "nothing is read before it is open");
        // Opening Bob reads him to his newest message; the save waits 2 s.
        let t0 = app.now();
        let cmds = testkit::press(&mut app, KeyCode::Enter);
        assert_eq!(marks(&cmds), None);
        assert_eq!(app.unread(&key_of(1)), 0);
        assert_eq!(
            app.settings().last_read.get(&key_of(1)),
            Some(&rows[2].1.id)
        );
        assert_eq!(app.marks_due(), Some(t0 + MARKS_SAVE_AFTER));
        // The UI thread wakes for it (Home's clock wakes it each second
        // anyway, UXF.10).
        assert!(anim::next_wait(&app, t0).is_some_and(|wait| wait <= MARKS_SAVE_AFTER));
        // What arrives meanwhile is read too, in the same save.
        testkit::tick(&mut app, Duration::from_secs(1));
        let mut more = rows.to_vec();
        more.push((1, testkit::row(5, false, "", 0, "e")));
        assert_eq!(
            marks(&testkit::reload(&mut app, &more, FileStamp::default())),
            None
        );
        assert_eq!(app.unread(&key_of(1)), 0);
        assert_eq!(app.marks_due(), Some(t0 + MARKS_SAVE_AFTER));
        let cmds = testkit::tick(&mut app, Duration::from_secs(1));
        let saved = marks(&cmds).expect("saved once due");
        assert_eq!(saved.last_read.get(&key_of(1)), Some(&more[4].1.id));
        assert_eq!(saved.last_read.get(&key_of(2)), None);
        assert_eq!(app.marks_due(), None);
        assert_eq!(
            StoreJob::SaveReadMarks(saved.clone()).name().kind(),
            JobKind::Store
        );
        assert_eq!(
            marks(&testkit::tick(&mut app, Duration::from_secs(5))),
            None,
            "once"
        );
        // Its answer says nothing, saved or not.
        for result in [Ok(true), Ok(false), Err("disk full".to_owned())] {
            answer(&mut app, JobResult::ReadMarksSaved(result));
        }
        assert_eq!(app.toast(), None);
        assert_eq!(app.unread(&key_of(2)), 1);
        // A marker whose message is gone counts everything again.
        app.settings.last_read.insert(key_of(2), "ff".repeat(16));
        assert_eq!(app.unread(&key_of(2)), 1);
    }

    #[test]
    fn a_conversation_out_of_sight_is_not_read() {
        let rows = [(1, testkit::row(1, false, "", 10, "a"))];
        let mut app = home(&rows);
        // One pane: the list in front, the conversation behind it.
        testkit::resize(&mut app, 70, 20);
        testkit::press(&mut app, KeyCode::Enter);
        assert_eq!(app.unread(&key_of(1)), 0);
        testkit::press(&mut app, KeyCode::Esc);
        assert!(!app.conversation_visible());
        let mut more = rows.to_vec();
        more.push((1, testkit::row(2, false, "", 0, "b")));
        testkit::reload(&mut app, &more, FileStamp::default());
        assert_eq!(app.unread(&key_of(1)), 1);
        testkit::press(&mut app, KeyCode::Enter);
        assert_eq!(app.unread(&key_of(1)), 0);
        // Behind SMALL nothing is read either.
        testkit::resize(&mut app, 40, 10);
        more.push((1, testkit::row(3, false, "", 0, "c")));
        testkit::reload(&mut app, &more, FileStamp::default());
        assert_eq!(app.unread(&key_of(1)), 1);
        testkit::resize(&mut app, 100, 30);
        assert_eq!(app.unread(&key_of(1)), 0, "read once it shows again");
    }

    /// The markers as the desktop app saved them: friend `n` read up to
    /// `row`.
    fn desktop_marks(marks: &[(u8, &RowView)]) -> ReadMarks {
        marks
            .iter()
            .map(|(n, row)| {
                let mark = ReadMark {
                    id: row.id.clone(),
                    at_ms: Some(row.created_at_ms),
                };
                (key_of(*n), mark)
            })
            .collect()
    }

    #[test]
    fn a_chat_read_in_the_desktop_app_is_read_here() {
        let rows = [
            (1, testkit::row(1, false, "", 10, "a")),
            (1, testkit::row(2, false, "", 9, "b")),
            (2, testkit::row(3, false, "", 8, "c")),
        ];
        let mut app = home(&rows);
        assert_eq!((app.unread(&key_of(1)), app.unread(&key_of(2))), (2, 1));
        // The poller saw tui_state.json change: one read at a time.
        let changed = |app: &mut App| {
            testkit::send(
                app,
                Msg::Poll(PollUpdate::File {
                    watched: Watched::ReadMarks,
                    stamp: FileStamp::default(),
                }),
            )
        };
        assert_eq!(changed(&mut app), [Cmd::Store(StoreJob::LoadReadMarks)]);
        assert!(changed(&mut app).is_empty());
        // The desktop app read Bob to his newest message.
        let cmds = answer(
            &mut app,
            JobResult::ReadMarks(desktop_marks(&[(1, &rows[1].1)])),
        );
        assert_eq!(cmds, [Cmd::Store(StoreJob::LoadReadMarks)], "changed again");
        assert_eq!((app.unread(&key_of(1)), app.unread(&key_of(2))), (0, 1));
        assert_eq!(app.marks_due(), None, "nothing to save: it is saved");
        // An older marker of the desktop app moves nothing back.
        answer(
            &mut app,
            JobResult::ReadMarks(desktop_marks(&[(1, &rows[0].1)])),
        );
        assert_eq!(app.unread(&key_of(1)), 0);
        // A marker for a message this app has not loaded yet: what came
        // before it is read.
        let newer = testkit::row(9, false, "", 1, "not loaded yet");
        answer(
            &mut app,
            JobResult::ReadMarks(desktop_marks(&[(2, &newer)])),
        );
        assert_eq!(app.unread(&key_of(2)), 0);
        // Opening Alice now keeps that newer marker.
        testkit::press(&mut app, KeyCode::Down);
        testkit::press(&mut app, KeyCode::Enter);
        assert!(app.conversation_visible());
        assert_eq!(app.open_friend(), Some(key_of(2).as_str()));
        assert_eq!(app.settings().last_read.get(&key_of(2)), Some(&newer.id));
        assert_eq!(app.marks_due(), None);
        // A read that failed: read again at the next change.
        answer(
            &mut app,
            JobResult::Failed {
                job: JobName::LoadReadMarks,
                plain: errors::explain_panic("boom", ""),
            },
        );
        assert_eq!(changed(&mut app), [Cmd::Store(StoreJob::LoadReadMarks)]);
    }

    #[test]
    fn an_older_apps_marker_gets_its_time_from_the_history_once() {
        let rows = [
            (1, testkit::row(1, false, "", 10, "a")),
            (1, testkit::row(2, false, "", 9, "b")),
        ];
        // tui_state.json from before: an id only.
        let mut session = testkit::session(Receive::Off);
        session
            .settings
            .last_read
            .insert(key_of(1), rows[0].1.id.clone());
        let mut app = testkit::home_app_from(
            testkit::simple_mono(),
            (100, 30),
            session,
            vec![testkit::reachable(1), testkit::reachable(2)],
            testkit::conversations(&rows),
        );
        assert_eq!(app.unread(&key_of(1)), 1, "counted by its id meanwhile");
        let mark = app.settings().read_mark(&key_of(1)).expect("a marker");
        assert_eq!(mark.at_ms, Some(rows[0].1.created_at_ms));
        let t0 = app.now();
        assert_eq!(app.marks_due(), Some(t0 + MARKS_SAVE_AFTER));
        let saved = marks(&testkit::tick(&mut app, MARKS_SAVE_AFTER))
            .expect("saved")
            .clone();
        assert_eq!(saved.read_mark(&key_of(1)), Some(mark));
        assert_eq!(saved.last_read.get(&key_of(1)), Some(&rows[0].1.id));
        // Once: the next load finds nothing to time.
        testkit::reload(&mut app, &rows, FileStamp::default());
        assert_eq!(app.marks_due(), None);
    }

    #[test]
    fn a_paste_on_the_list_says_where_a_card_goes() {
        let mut app = home(&[]);
        for via in [PasteVia::Bracketed, PasteVia::Keystrokes] {
            let cmds = testkit::paste(&mut app, "raven:rvn1x:00ff\n", via);
            assert!(cmds.is_empty(), "{cmds:?}");
            assert_eq!(toast_text(&app), Some(LIST_PASTE_TOAST));
        }
        assert_eq!(app.open_friend(), None);
        assert_eq!(app.focus(), Focus::Friends);
    }

    /// Field test E3: Enter right after fast text (tmux's keys, a paste
    /// without brackets) did not send, a second Enter did. A paste's own
    /// line breaks stay text; the user's Enter right after a paste sends
    /// what is there, as after typing.
    #[test]
    fn enter_right_after_a_paste_sends_what_is_in_the_composer() {
        for via in [PasteVia::Bracketed, PasteVia::Keystrokes] {
            let mut app = home(&[]);
            testkit::press(&mut app, KeyCode::Enter);
            assert!(testkit::paste(&mut app, "hello bob", via).is_empty());
            let cmds = testkit::press(&mut app, KeyCode::Enter);
            assert_eq!(
                testkit::send_job(&cmds).map(|(_, text)| text).as_deref(),
                Some("hello bob"),
                "{via:?}: {cmds:?}"
            );
            assert_eq!(app.composer().map(Composer::text), Some(""));
        }
    }

    #[test]
    fn the_composer_takes_pastes_and_line_breaks_as_text_and_never_sends() {
        let mut app = home(&[]);
        testkit::press(&mut app, KeyCode::Enter);
        let text = |app: &App| app.composer().map(|c| c.text().to_owned());
        assert!(
            testkit::paste(&mut app, "hello\r\nworld\u{1b}[2J", PasteVia::Bracketed).is_empty()
        );
        assert_eq!(text(&app).as_deref(), Some("hello\nworld[2J"));
        assert_eq!(app.composer().and_then(Composer::problem), None);
        // A pasted Enter sends nothing: a line break.
        assert!(testkit::send(&mut app, Msg::Key(Key::PastedEnter)).is_empty());
        assert_eq!(toast_text(&app), None);
        assert_eq!(text(&app).as_deref(), Some("hello\nworld[2J\n"));
        // Ctrl+J is a new line; Backspace takes one character back.
        testkit::ctrl(&mut app, 'j');
        testkit::press(&mut app, KeyCode::Backspace);
        testkit::press(&mut app, KeyCode::Backspace);
        assert_eq!(text(&app).as_deref(), Some("hello\nworld[2J"));
        // Editing in the middle: Home, End, Left, Right, Delete.
        testkit::press(&mut app, KeyCode::Home);
        testkit::press(&mut app, KeyCode::Delete);
        testkit::press(&mut app, KeyCode::Right);
        testkit::press(&mut app, KeyCode::Char('W'));
        assert_eq!(text(&app).as_deref(), Some("hello\noWrld[2J"));
        testkit::press(&mut app, KeyCode::End);
        testkit::press(&mut app, KeyCode::Left);
        testkit::press(&mut app, KeyCode::Char('!'));
        assert_eq!(text(&app).as_deref(), Some("hello\noWrld[2!J"));
        // A grapheme goes whole: e and its accent.
        testkit::press(&mut app, KeyCode::End);
        testkit::paste(&mut app, "e\u{301}", PasteVia::Bracketed);
        testkit::press(&mut app, KeyCode::Backspace);
        assert_eq!(text(&app).as_deref(), Some("hello\noWrld[2!J"));
        // Enter sends the draft as it is to the open friend, also right
        // after a paste (field test E3), and the composer is empty again.
        let cmds = testkit::press(&mut app, KeyCode::Enter);
        let to = key_of(1);
        assert!(
            matches!(
                &cmds[..],
                [Cmd::Send(SendJob::Send { pub_hex, text, .. }), ..]
                    if *pub_hex == to && text == "hello\noWrld[2!J"
            ),
            "{cmds:?}"
        );
        assert_eq!(text(&app).as_deref(), Some(""));
        assert_eq!(toast_text(&app), None);
    }

    #[test]
    fn the_composer_refuses_what_raven_cant_send_and_stops_at_48_kib() {
        let mut app = home(&[]);
        testkit::press(&mut app, KeyCode::Enter);
        testkit::paste(&mut app, "RVNAPP/1 hi", PasteVia::Bracketed);
        assert_eq!(
            app.composer().and_then(Composer::problem),
            Some(RESERVED_REFUSED)
        );
        testkit::tick(&mut app, PASTE_GUARD);
        testkit::press(&mut app, KeyCode::Enter);
        assert_eq!(toast_text(&app), None, "nothing to send");
        testkit::press(&mut app, KeyCode::Home);
        for _ in 0.."RVNAPP/".len() {
            testkit::press(&mut app, KeyCode::Delete);
        }
        assert_eq!(app.composer().map(Composer::text), Some("1 hi"));
        assert_eq!(app.composer().and_then(Composer::problem), None);
        // No control character can be typed or pasted; cli.rs's check
        // stays behind that.
        let typed = Composer {
            text: "a\u{1b}[Ab".into(),
            cursor: 0,
        };
        assert_eq!(typed.problem(), Some(CONTROL_REFUSED));
        testkit::paste(&mut app, "\u{7}\u{7f}\u{9b}", PasteVia::Bracketed);
        assert_eq!(app.composer().map(Composer::text), Some("1 hi"));
        // The size limit: a paste stops there, and typing too.
        let max = bridge::MAX_LAN_ENDPOINT_TEXT;
        testkit::paste(&mut app, &"x".repeat(max), PasteVia::Bracketed);
        let len = |app: &App| app.composer().map_or(0, |c| c.text().len());
        assert_eq!(len(&app), max);
        testkit::press(&mut app, KeyCode::Char('y'));
        assert_eq!(len(&app), max);
        testkit::press(&mut app, KeyCode::Backspace);
        // One byte left: a two-byte character does not fit.
        testkit::press(&mut app, KeyCode::Char('\u{e9}'));
        assert_eq!(len(&app), max - 1);
        testkit::press(&mut app, KeyCode::Char('z'));
        assert_eq!(len(&app), max);
    }

    #[test]
    fn each_friend_has_their_own_draft() {
        let mut app = home(&[]);
        testkit::press(&mut app, KeyCode::Enter);
        for c in "for bob".chars() {
            testkit::press(&mut app, KeyCode::Char(c));
        }
        for key in [KeyCode::Esc, KeyCode::Down, KeyCode::Enter] {
            testkit::press(&mut app, key);
        }
        assert_eq!(app.open_friend(), Some(key_of(2).as_str()));
        assert_eq!(app.composer().map(Composer::text), Some(""));
        testkit::press(&mut app, KeyCode::Char('x'));
        for key in [KeyCode::Esc, KeyCode::Up, KeyCode::Enter] {
            testkit::press(&mut app, key);
        }
        assert_eq!(app.composer().map(Composer::text), Some("for bob"));
        // Without an open friend there is no composer.
        let app = home(&[]);
        assert_eq!(app.composer(), None);
    }

    #[test]
    fn ten_downs_scroll_the_conversation_and_never_change_the_friend() {
        let rows: Vec<(u8, RowView)> = (0..40)
            .map(|i| (1, testkit::row(i, i % 2 == 0, "delivered", 60, "line")))
            .collect();
        let mut app = home(&rows);
        testkit::press(&mut app, KeyCode::Enter);
        // The composer: Up and Down scroll a row at a time.
        for _ in 0..10 {
            testkit::press(&mut app, KeyCode::Up);
        }
        assert_eq!(app.scroll(), 10);
        for _ in 0..10 {
            testkit::press(&mut app, KeyCode::Down);
        }
        assert_eq!(
            (app.scroll(), app.highlight(), app.open_friend()),
            (0, 0, Some(key_of(1).as_str()))
        );
        // The messages: Up and Down choose a message, from the newest, and
        // the window follows it. Each one here is two rows high.
        app.set_focus(Focus::Messages);
        assert_eq!(app.chosen(), Some(0));
        let window = home::page_rows(&app) + 1;
        for _ in 0..10 {
            testkit::press(&mut app, KeyCode::Up);
        }
        assert_eq!(app.chosen(), Some(10));
        assert_eq!(app.scroll(), 22 - window, "the 11th newest at the top");
        for _ in 0..10 {
            testkit::press(&mut app, KeyCode::Down);
        }
        assert_eq!(
            (
                app.chosen(),
                app.scroll(),
                app.highlight(),
                app.open_friend()
            ),
            (Some(0), 0, 0, Some(key_of(1).as_str()))
        );
        // A window at a time, never past the oldest row.
        let page = home::page_rows(&app);
        testkit::press(&mut app, KeyCode::PageUp);
        assert_eq!(app.scroll(), page);
        for _ in 0..50 {
            testkit::press(&mut app, KeyCode::PageUp);
        }
        let top = app.scroll();
        assert!(top > page && top < 80, "{top}");
        app.take_dirty();
        app.set_focus(Focus::Composer);
        app.take_dirty();
        testkit::press(&mut app, KeyCode::Up);
        assert_eq!(app.scroll(), top);
        assert!(!app.take_dirty(), "nothing moved at the top");
        testkit::press(&mut app, KeyCode::PageDown);
        assert_eq!(app.scroll(), top - page);
        // In the list, Down moves only the highlight.
        app.set_focus(Focus::Friends);
        for _ in 0..10 {
            testkit::press(&mut app, KeyCode::Down);
        }
        assert_eq!(
            (app.scroll(), app.highlight(), app.open_friend()),
            (top - page, 1, Some(key_of(1).as_str()))
        );
        // Opening another friend starts at their newest message.
        testkit::press(&mut app, KeyCode::Enter);
        assert_eq!(app.scroll(), 0);
    }

    #[test]
    fn ages_are_drawn_again_each_minute() {
        let mut app = home(&[(1, testkit::row(1, false, "", 1, "hi"))]);
        // The test clock is 20 s into a minute.
        testkit::tick(&mut app, Duration::from_secs(30));
        assert!(!app.take_dirty());
        testkit::tick(&mut app, Duration::from_secs(10));
        assert!(app.take_dirty(), "a new minute");
        testkit::tick(&mut app, Duration::from_secs(10));
        assert!(!app.take_dirty());
    }

    // ── how long a message can wait ─────────────────────────────────────────

    /// The friends each horizon read among `cmds` asks about.
    fn horizon_reads(cmds: &[Cmd]) -> Vec<Vec<String>> {
        cmds.iter()
            .filter_map(|cmd| match cmd {
                Cmd::Store(StoreJob::LoadHorizons { peers }) => Some(peers.clone()),
                _ => None,
            })
            .collect()
    }

    /// The poller's word that the horizons are due.
    fn horizons_due(app: &mut App) -> Vec<Cmd> {
        testkit::send(app, Msg::Poll(PollUpdate::HorizonsDue))
    }

    const HOUR_MS: u64 = 3_600_000;

    #[test]
    fn the_poller_has_the_store_worker_read_the_horizons() {
        // Asked before the friends are loaded: read once they are.
        let mut app = app_started(Receive::Off);
        assert!(horizon_reads(&horizons_due(&mut app)).is_empty());
        let cmds = contacts(&mut app, 2);
        assert_eq!(horizon_reads(&cmds), [vec![key_of(1), key_of(2)]]);
        // One read at a time: asked again meanwhile, read again after it.
        assert!(horizon_reads(&horizons_due(&mut app)).is_empty());
        let until = app.now_ms() + 3 * HOUR_MS;
        let can_wait = bridge::QueueReach::CanWait { until_ms: until };
        let found = Horizons::from([
            (key_of(1), can_wait),
            (key_of(2), bridge::QueueReach::NeverPaired),
        ]);
        let cmds = answer(&mut app, JobResult::Horizons(found.clone()));
        assert_eq!(horizon_reads(&cmds).len(), 1, "{cmds:?}");
        assert_eq!(app.horizon(&key_of(1).to_uppercase()), Some(can_wait));
        assert_eq!(
            app.horizon(&key_of(2)),
            Some(bridge::QueueReach::NeverPaired)
        );
        assert_eq!(app.horizon(&key_of(3)), None);
        // An answer replaces the last whole: nothing known, no line.
        let cmds = answer(&mut app, JobResult::Horizons(Horizons::new()));
        assert!(horizon_reads(&cmds).is_empty());
        assert_eq!(app.horizon(&key_of(1)), None);
        // A read that failed: not known either.
        horizons_due(&mut app);
        answer(&mut app, JobResult::Horizons(found));
        horizons_due(&mut app);
        answer(
            &mut app,
            JobResult::Failed {
                job: JobName::LoadHorizons,
                plain: errors::explain_panic("boom", ""),
            },
        );
        assert_eq!(app.horizon(&key_of(2)), None);
        assert!(!app.horizons_loading);
        // No friends: nothing to read. The security notices are read on
        // the same word (P6.31), friends or not.
        let (mut alone, _) = ready(Receive::Off, 0);
        let cmds = horizons_due(&mut alone);
        assert!(horizon_reads(&cmds).is_empty());
        assert_eq!(stores(&cmds), [&StoreJob::LoadSecurity]);
    }

    #[test]
    fn once_the_poller_asked_sends_and_changes_read_the_horizons_again() {
        let delivered = || testkit::delivered_to("192.168.1.11:7420");
        let mut app = composing(&[]);
        // Before the poller's first word, nothing reads them by itself.
        let (id, _) = testkit::type_and_send(&mut app, "hi").expect("a send");
        let mut cmds = testkit::send(&mut app, testkit::sent(id, delivered()));
        cmds.extend(testkit::reload_rows(
            &mut app,
            &[(1, testkit::row(1, true, "delivered", 0, "hi"))],
        ));
        assert!(horizon_reads(&cmds).is_empty(), "{cmds:?}");
        // Then a send's end reads them again: it may have set up a secure
        // connection.
        assert_eq!(horizon_reads(&horizons_due(&mut app)).len(), 1);
        answer(&mut app, JobResult::Horizons(Horizons::new()));
        let (id, _) = testkit::type_and_send(&mut app, "again").expect("a send");
        let cmds = testkit::send(&mut app, testkit::sent(id, delivered()));
        assert_eq!(horizon_reads(&cmds).len(), 1, "{cmds:?}");
        answer(&mut app, JobResult::Horizons(Horizons::new()));
        // So do a new message in the history and a change to the friends,
        // but not the same friends again.
        let rows = [
            (1, testkit::row(1, true, "delivered", 0, "hi")),
            (1, testkit::row(2, false, "", 0, "hello")),
        ];
        let cmds = testkit::reload_rows(&mut app, &rows);
        assert_eq!(horizon_reads(&cmds).len(), 1, "{cmds:?}");
        answer(&mut app, JobResult::Horizons(Horizons::new()));
        let friends = |n: u8| JobResult::Contacts {
            contacts: Ok((1..=n).map(testkit::reachable).collect()),
            stamp: FileStamp::default(),
        };
        assert!(horizon_reads(&answer(&mut app, friends(2))).is_empty());
        let cmds = answer(&mut app, friends(3));
        assert_eq!(
            horizon_reads(&cmds),
            [vec![key_of(1), key_of(2), key_of(3)]]
        );
    }

    // ── sending ─────────────────────────────────────────────────────────────

    /// Home with friend 1 open in the composer and `rows` loaded.
    fn composing(rows: &[(u8, RowView)]) -> App {
        let mut app = home(rows);
        testkit::press(&mut app, KeyCode::Enter);
        app
    }

    /// The tick of friend 1's newest message.
    fn newest(app: &App) -> Option<Tick> {
        let bubbles = app.bubbles(&key_of(1));
        app.tick_view(*bubbles.last()?).map(|view| view.tick)
    }

    /// The ticks of friend 1's messages of yours, oldest first.
    fn ticks(app: &App) -> Vec<Tick> {
        app.bubbles(&key_of(1))
            .into_iter()
            .filter_map(|bubble| app.tick_view(bubble).map(|view| view.tick))
            .collect()
    }

    /// Friend 1's newest message's write evidence and actions.
    fn newest_view(app: &App) -> (WriteEvidence, Actions) {
        let bubbles = app.bubbles(&key_of(1));
        let view = app
            .tick_view(*bubbles.last().expect("a message"))
            .expect("one of yours");
        (view.evidence, view.actions)
    }

    #[test]
    fn a_message_shows_at_once_and_its_tick_follows_its_job() {
        let mut app = composing(&[]);
        testkit::send(&mut app, testkit::node_up());
        let (one, text) = testkit::type_and_send(&mut app, "one").expect("a send");
        assert_eq!(text, "one");
        assert_eq!(app.sends().len(), 1);
        assert_eq!(app.sends()[0].body, "one");
        assert_eq!(
            app.composer().map(Composer::text),
            Some(""),
            "the draft went"
        );
        // Connecting first, then Sending once its row is written (field
        // test E3: the other way round read wrong).
        assert_eq!(ticks(&app), [Tick::Connecting]);
        assert!(
            app.jobs_in_flight().holds_classic(),
            "QUIT and C wait for it"
        );
        // A second one waits behind it.
        let (two, _) = testkit::type_and_send(&mut app, "two").expect("a send");
        assert_eq!(ticks(&app), [Tick::Connecting, Tick::WaitingToSend]);
        // The first was delivered; the second's job runs now.
        testkit::send(
            &mut app,
            testkit::sent(one, testkit::delivered_to("192.168.1.11:7420")),
        );
        assert_eq!(ticks(&app), [Tick::Delivered, Tick::Connecting]);
        // Their rows come: the second's is written while it dials.
        let rows = [
            (1, testkit::row(1, true, "delivered", 0, "one")),
            (1, testkit::row(2, true, "queued", 0, "two")),
        ];
        testkit::reload(&mut app, &rows, FileStamp::default());
        assert_eq!(
            app.bubbles(&key_of(1)).len(),
            2,
            "each send has its row now"
        );
        assert_eq!(ticks(&app), [Tick::Delivered, Tick::Sending]);
        // Its friend did not answer: queued, and raven-node keeps trying. The
        // poller lists that friend's outbox soon, and often while it waits.
        let cmds = testkit::send(
            &mut app,
            testkit::sent(two, SendResult::Failed(testkit::queued_outcome(1, true))),
        );
        assert!(
            cmds.contains(&Cmd::Poll(PollCtl::Burst { peer: key_of(1) })),
            "{cmds:?}"
        );
        assert!(
            cmds.iter()
                .any(|cmd| matches!(cmd, Cmd::Poll(PollCtl::Hints(h)) if h.live)),
            "{cmds:?}"
        );
        assert_eq!(
            newest(&app),
            Some(Tick::Waiting(Waiting::Retried { expires_at_ms: 0 }))
        );
        assert!(app.jobs_in_flight().idle());
        // It never reached Bob's Raven: sending it again would be safe, but
        // it waits, so R tries it now and C stops it.
        assert_eq!(
            newest_view(&app),
            (
                WriteEvidence::NeverWritten,
                Actions {
                    try_now: true,
                    stop: true,
                    ..Actions::default()
                }
            )
        );
        // The outbox tells until when it can wait, then that it tried a
        // carrier.
        let mut item = testkit::outbox_item(1, 2, "queued");
        testkit::send(&mut app, testkit::outbox(vec![item.clone()]));
        assert_eq!(
            newest(&app),
            Some(Tick::Waiting(Waiting::Retried {
                expires_at_ms: item.expires_at_ms
            }))
        );
        // raven-node's own tries that failed: still never left.
        item.attempts = 2;
        item.carrier = "lan_dial".into();
        testkit::send(&mut app, testkit::outbox(vec![item.clone()]));
        assert_eq!(newest_view(&app).0, WriteEvidence::NeverWritten);
        // Written, no ACK: it may have arrived from now on, whatever comes.
        item.state = "sent".into();
        testkit::send(&mut app, testkit::outbox(vec![item.clone()]));
        assert_eq!(newest(&app), Some(Tick::Sent));
        item.state = "queued".into();
        testkit::send(&mut app, testkit::outbox(vec![item]));
        assert_eq!(newest_view(&app).0, WriteEvidence::MaybeWritten);
        // Delivered once it is: never taken back by a stale list.
        testkit::reload(
            &mut app,
            &[
                rows[0].clone(),
                (1, testkit::row(2, true, "delivered", 0, "two")),
            ],
            FileStamp::default(),
        );
        testkit::send(
            &mut app,
            testkit::outbox(vec![testkit::outbox_item(1, 2, "sent")]),
        );
        assert_eq!(ticks(&app), [Tick::Delivered, Tick::Delivered]);
    }

    #[test]
    fn waiting_says_who_sends_it_again_and_sent_is_never_typed_again() {
        let mut app = composing(&[]);
        // No background program answers: nobody retries it now.
        let (one, _) = testkit::type_and_send(&mut app, "hi").expect("a send");
        testkit::send(
            &mut app,
            testkit::sent(one, SendResult::Failed(testkit::queued_outcome(1, true))),
        );
        assert_eq!(newest(&app), Some(Tick::Waiting(Waiting::NotRetried)));
        // A raven-node without an outbox: the next send does.
        testkit::send(&mut app, testkit::node_up());
        let (two, _) = testkit::type_and_send(&mut app, "hi").expect("a send");
        testkit::send(
            &mut app,
            testkit::sent(two, SendResult::Failed(testkit::queued_outcome(1, false))),
        );
        assert_eq!(newest(&app), Some(Tick::Waiting(Waiting::NextSend)));
        // Written, not confirmed: no key sends it again.
        let (three, _) = testkit::type_and_send(&mut app, "hi").expect("a send");
        testkit::send(
            &mut app,
            testkit::sent(three, SendResult::Failed(testkit::unconfirmed_outcome(1))),
        );
        assert_eq!(newest(&app), Some(Tick::Sent));
        assert_eq!(newest_view(&app).1, Actions::default());
        testkit::press(&mut app, KeyCode::Tab);
        assert_eq!(app.focus(), Focus::Messages);
        assert!(testkit::press(&mut app, KeyCode::Char('r')).is_empty());
        // A send job that panicked: not sent, so R sends it again.
        let mut app = composing(&[]);
        testkit::type_and_send(&mut app, "hi").expect("a send");
        testkit::send(
            &mut app,
            Msg::Job(JobResult::Failed {
                job: JobName::Send,
                plain: errors::explain_panic("boom", ""),
            }),
        );
        assert_eq!(newest(&app), Some(Tick::NotSent));
        assert!(app.jobs_in_flight().idle());
        assert_eq!(newest_view(&app).0, WriteEvidence::NeverWritten);
    }

    #[test]
    fn r_and_c_act_on_the_chosen_message() {
        let mut app = composing(&[]);
        testkit::send(&mut app, testkit::node_up());
        let (one, _) = testkit::type_and_send(&mut app, "hi").expect("a send");
        testkit::reload(
            &mut app,
            &[(1, testkit::row(7, true, "queued", 0, "hi"))],
            FileStamp::default(),
        );
        testkit::send(
            &mut app,
            testkit::sent(one, SendResult::Failed(testkit::queued_outcome(1, true))),
        );
        let mid = format!("{:032x}", 7);
        // Messages focus chooses the newest; R asks raven-node to try it now.
        testkit::press(&mut app, KeyCode::Tab);
        assert_eq!(app.chosen(), Some(0));
        let cmds = testkit::press(&mut app, KeyCode::Char('r'));
        assert_eq!(
            cmds.first(),
            Some(&Cmd::Send(SendJob::Retry {
                mid: mid.clone(),
                peer: key_of(1)
            }))
        );
        let cmds = testkit::send(
            &mut app,
            Msg::Job(JobResult::Retried {
                mid: mid.clone(),
                peer: key_of(1),
                result: Ok(()),
                captured: String::new(),
            }),
        );
        assert_eq!(toast_text(&app), Some(RETRYING_TOAST));
        assert!(cmds.contains(&Cmd::Poll(PollCtl::Burst { peer: key_of(1) })));
        // C asks first; N keeps it, Y stops it.
        assert!(testkit::press(&mut app, KeyCode::Char('c')).is_empty());
        let confirm = Overlay::Confirm(ConfirmState {
            peer: key_of(1),
            action: ConfirmAction::StopTrying { mid: mid.clone() },
        });
        assert_eq!(app.overlays(), std::slice::from_ref(&confirm));
        // A paste or Enter answers nothing.
        assert!(testkit::paste(&mut app, "y", PasteVia::Bracketed).is_empty());
        assert!(testkit::press(&mut app, KeyCode::Enter).is_empty());
        assert!(testkit::press(&mut app, KeyCode::Char('n')).is_empty());
        assert!(app.overlays().is_empty());
        testkit::press(&mut app, KeyCode::Char('c'));
        let cmds = testkit::press(&mut app, KeyCode::Char('y'));
        assert_eq!(
            cmds.first(),
            Some(&Cmd::Send(SendJob::Cancel {
                mid: mid.clone(),
                peer: key_of(1)
            }))
        );
        assert!(app.overlays().is_empty());
        // ext.rs says it never left this computer: R sends it again, as new.
        testkit::send(
            &mut app,
            Msg::Job(JobResult::Cancelled {
                mid: mid.clone(),
                peer: key_of(1),
                result: Ok(()),
                captured: "cancelled: raven-node stops trying to deliver your message \"hi\" \
                           to Friend 1."
                    .into(),
            }),
        );
        assert!(app.toasts_for_tests().contains(&STOPPED_TOAST));
        testkit::reload(
            &mut app,
            &[(1, testkit::row(7, true, "cancelled", 0, "hi"))],
            FileStamp::default(),
        );
        assert_eq!(newest(&app), Some(Tick::Ended { expired: false }));
        assert_eq!(newest_view(&app).0, WriteEvidence::NeverWritten);
        let again = testkit::press(&mut app, KeyCode::Char('r'));
        assert_eq!(testkit::send_job(&again), Some((2, "hi".into())));
        assert_eq!(app.bubbles(&key_of(1)).len(), 2, "the old row stays");
    }

    #[test]
    fn a_message_that_may_have_arrived_goes_again_only_after_the_warning() {
        let mut app = composing(&[]);
        testkit::send(&mut app, testkit::node_up());
        let (one, _) = testkit::type_and_send(&mut app, "hi").expect("a send");
        testkit::reload(
            &mut app,
            &[(1, testkit::row(7, true, "queued", 0, "hi"))],
            FileStamp::default(),
        );
        testkit::send(
            &mut app,
            testkit::sent(one, SendResult::Failed(testkit::queued_outcome(1, true))),
        );
        let mid = format!("{:032x}", 7);
        // The cancel says it was written once.
        testkit::send(
            &mut app,
            Msg::Job(JobResult::Cancelled {
                mid: mid.clone(),
                peer: key_of(1),
                result: Ok(()),
                captured: format!(
                    "It was already sent once, so Friend 1 {}.",
                    delivery::MAY_HAVE_IT
                ),
            }),
        );
        testkit::reload(
            &mut app,
            &[(1, testkit::row(7, true, "cancelled", 0, "hi"))],
            FileStamp::default(),
        );
        assert_eq!(newest(&app), Some(Tick::Ended { expired: false }));
        assert_eq!(
            newest_view(&app),
            (
                WriteEvidence::MaybeWritten,
                Actions {
                    send_again_anyway: true,
                    ..Actions::default()
                }
            )
        );
        // No R; Enter opens MSG, where S asks first.
        testkit::press(&mut app, KeyCode::Tab);
        assert!(testkit::press(&mut app, KeyCode::Char('r')).is_empty());
        testkit::press(&mut app, KeyCode::Enter);
        let msg = Overlay::Message(MessageView {
            peer: key_of(1),
            key: BubbleKey::Mid(mid.clone()),
            details: false,
        });
        assert_eq!(app.overlays(), std::slice::from_ref(&msg));
        assert!(testkit::press(&mut app, KeyCode::Char('r')).is_empty());
        testkit::press(&mut app, KeyCode::Char('d'));
        assert!(matches!(
            app.overlays(),
            [Overlay::Message(MessageView { details: true, .. })]
        ));
        assert!(testkit::press(&mut app, KeyCode::Char('s')).is_empty());
        assert!(matches!(
            app.overlays(),
            [
                Overlay::Message(_),
                Overlay::Confirm(ConfirmState {
                    action: ConfirmAction::SendAgain { .. },
                    ..
                })
            ]
        ));
        // Esc keeps it as it is; Y sends it again and closes MSG.
        testkit::press(&mut app, KeyCode::Esc);
        assert_eq!(app.overlays().len(), 1);
        testkit::press(&mut app, KeyCode::Char('s'));
        let cmds = testkit::press(&mut app, KeyCode::Char('y'));
        assert_eq!(testkit::send_job(&cmds), Some((2, "hi".into())));
        assert!(app.overlays().is_empty());
        // A cancel that came too late: delivered first.
        testkit::send(
            &mut app,
            Msg::Job(JobResult::Cancelled {
                mid,
                peer: key_of(1),
                result: Ok(()),
                captured: "status delivered - Friend 1 confirmed it before it could be cancelled"
                    .into(),
            }),
        );
        assert!(app.toasts_for_tests().contains(&DELIVERED_FIRST_TOAST));
    }

    #[test]
    fn an_address_a_send_learned_is_saved_for_the_friend() {
        let mut app = composing(&[]);
        let (one, _) = testkit::type_and_send(&mut app, "hi").expect("a send");
        let cmds = testkit::send(
            &mut app,
            Msg::Job(JobResult::Sent {
                local_id: one,
                outcome: SendOutcome {
                    result: testkit::delivered_to("192.168.1.99:7420"),
                    learned_dial_used: Some("192.168.1.99:7420".into()),
                    captured: String::new(),
                },
            }),
        );
        let save = Cmd::Store(StoreJob::SaveLearnedDial {
            pub_hex: key_of(1),
            dial: "192.168.1.99:7420".into(),
        });
        assert!(cmds.contains(&save), "{cmds:?}");
        assert_eq!(
            StoreJob::SaveLearnedDial {
                pub_hex: String::new(),
                dial: String::new()
            }
            .name()
            .kind(),
            JobKind::Critical,
            "it writes contacts.json"
        );
        assert!(app.jobs_in_flight().holds_classic());
        testkit::send(&mut app, Msg::Job(JobResult::LearnedDialSaved(Ok(()))));
        assert!(app.jobs_in_flight().idle());
    }

    #[test]
    fn enter_in_the_messages_shows_a_long_body_whole_then_opens_msg() {
        let long = "x".repeat(bridge::TTY_BODY_MAX_CHARS + 10);
        let mut app = composing(&[(1, testkit::row(3, true, "delivered", 0, &long))]);
        testkit::press(&mut app, KeyCode::Tab);
        let key = BubbleKey::Mid(format!("{:032x}", 3));
        assert!(!app.expanded(&key));
        testkit::press(&mut app, KeyCode::Enter);
        assert!(app.expanded(&key));
        assert!(app.overlays().is_empty());
        testkit::press(&mut app, KeyCode::Enter);
        assert!(matches!(app.overlays(), [Overlay::Message(_)]));
        // Esc closes it; D opens it with the details.
        testkit::press(&mut app, KeyCode::Esc);
        testkit::press(&mut app, KeyCode::Char('d'));
        assert!(matches!(
            app.overlays(),
            [Overlay::Message(MessageView { details: true, .. })]
        ));
    }

    // ── Meeting toasts (UXF.8) ──────────────────────────────────────────────

    /// Messages `ids` of yours to friend `n`, as the history says `delivery`.
    fn mine(n: u8, ids: &[u32], delivery: &str) -> Vec<(u8, RowView)> {
        ids.iter()
            .map(|&id| (n, testkit::row(id, true, delivery, 30, "see you")))
            .collect()
    }

    /// Messages `ids` from friend `n`, written `minutes_ago`.
    fn theirs(n: u8, ids: &[u32], minutes_ago: u64) -> Vec<(u8, RowView)> {
        ids.iter()
            .map(|&id| (n, testkit::row(id, false, "", minutes_ago, "news")))
            .collect()
    }

    /// Every toast, the one on show first.
    fn toasts(app: &App) -> Vec<&str> {
        app.toasts_for_tests()
    }

    /// The clock moved past every toast on show.
    fn toasts_gone(app: &mut App) {
        testkit::tick(app, TOAST_TIME * 4);
        assert!(toasts(app).is_empty(), "{:?}", toasts(app));
    }

    #[test]
    fn a_friends_waiting_messages_all_delivered_say_so_once() {
        let mut app = home(&mine(1, &[1, 2], "queued"));
        testkit::send(&mut app, testkit::node_up());
        // One went: the other still waits, so nothing yet.
        let mut rows = mine(1, &[1], "delivered");
        rows.extend(mine(1, &[2], "queued"));
        testkit::reload_rows(&mut app, &rows);
        assert!(toasts(&app).is_empty(), "{:?}", toasts(&app));
        // Both did.
        testkit::reload_rows(&mut app, &mine(1, &[1, 2], "delivered"));
        assert_eq!(toasts(&app), ["Delivered 2 messages to Friend 1."]);
        // Nothing more to say about them.
        toasts_gone(&mut app);
        testkit::reload_rows(&mut app, &mine(1, &[1, 2], "delivered"));
        assert!(toasts(&app).is_empty());

        // One message; raven-node's list can say it first.
        let mut app = home(&mine(2, &[5], "queued"));
        testkit::send(&mut app, testkit::node_up());
        testkit::send(
            &mut app,
            testkit::outbox(vec![testkit::outbox_item(2, 5, "delivered")]),
        );
        assert!(toasts(&app).is_empty(), "the list alone says nothing");
        testkit::reload_rows(&mut app, &mine(2, &[5], "delivered"));
        assert_eq!(toasts(&app), ["Delivered 1 message to Friend 2."]);

        // One that ran out of time doesn't count; the others still say so.
        let mut app = home(&mine(1, &[1, 2, 3], "queued"));
        let mut rows = mine(1, &[1], "expired");
        rows.extend(mine(1, &[2, 3], "delivered"));
        testkit::reload_rows(&mut app, &rows);
        assert_eq!(toasts(&app), ["Delivered 2 messages to Friend 1."]);
        // All ended: nothing was delivered, nothing to say.
        let mut app = home(&mine(1, &[1], "queued"));
        testkit::reload_rows(&mut app, &mine(1, &[1], "failed"));
        assert!(toasts(&app).is_empty());
    }

    #[test]
    fn messages_that_never_waited_bring_no_toast() {
        // Delivered before Raven opened.
        let mut app = home(&mine(1, &[1], "delivered"));
        testkit::reload_rows(&mut app, &mine(1, &[1], "delivered"));
        assert!(toasts(&app).is_empty());
        // Sent and delivered straight away, or written and then confirmed.
        let mut app = home(&[]);
        testkit::reload_rows(&mut app, &mine(1, &[1], "delivered"));
        testkit::reload_rows(&mut app, &mine(1, &[1, 2], "delivered"));
        let mut rows = mine(1, &[1, 2], "delivered");
        rows.extend(mine(1, &[3], "sent"));
        testkit::reload_rows(&mut app, &rows);
        testkit::reload_rows(&mut app, &mine(1, &[1, 2, 3], "delivered"));
        assert!(toasts(&app).is_empty(), "{:?}", toasts(&app));
    }

    #[test]
    fn delivered_shows_once_a_minute_for_a_friend() {
        let mut app = home(&mine(1, &[1], "queued"));
        testkit::reload_rows(&mut app, &mine(1, &[1], "delivered"));
        assert_eq!(toasts(&app), ["Delivered 1 message to Friend 1."]);
        toasts_gone(&mut app);
        // Another waited and went within the minute: not said again.
        let mut rows = mine(1, &[1], "delivered");
        rows.extend(mine(1, &[2], "queued"));
        testkit::reload_rows(&mut app, &rows);
        testkit::reload_rows(&mut app, &mine(1, &[1, 2], "delivered"));
        assert!(toasts(&app).is_empty(), "{:?}", toasts(&app));
        // Another friend's are theirs to say.
        let mut rows = mine(1, &[1, 2], "delivered");
        rows.extend(mine(2, &[3], "queued"));
        testkit::reload_rows(&mut app, &rows);
        rows.pop();
        rows.extend(mine(2, &[3], "delivered"));
        testkit::reload_rows(&mut app, &rows);
        assert_eq!(toasts(&app), ["Delivered 1 message to Friend 2."]);
        // A minute after the first, friend 1's are said again.
        testkit::tick(&mut app, MEETING_TOAST_EVERY);
        assert!(toasts(&app).is_empty());
        let mut later = rows.clone();
        later.extend(mine(1, &[4], "queued"));
        testkit::reload_rows(&mut app, &later);
        later.pop();
        later.extend(mine(1, &[4], "delivered"));
        testkit::reload_rows(&mut app, &later);
        assert_eq!(toasts(&app), ["Delivered 1 message to Friend 1."]);
    }

    #[test]
    fn a_burst_after_an_hour_of_none_says_they_were_written_while_apart() {
        // Their last message came two hours ago.
        let old = theirs(1, &[1], 120);
        let mut app = home(&old);
        let mut rows = old.clone();
        rows.extend(theirs(1, &[2, 3, 4], 100));
        testkit::reload_rows(&mut app, &rows);
        assert_eq!(
            toasts(&app),
            ["3 new messages from Friend 1 (written while you were apart)."]
        );

        // Over two loads within the minute: said once they are 3.
        let mut app = home(&old);
        let mut rows = old.clone();
        rows.extend(theirs(1, &[2, 3], 100));
        testkit::reload_rows(&mut app, &rows);
        assert!(toasts(&app).is_empty());
        testkit::tick(&mut app, Duration::from_secs(30));
        rows.extend(theirs(1, &[4, 5], 90));
        testkit::reload_rows(&mut app, &rows);
        assert_eq!(
            toasts(&app),
            ["4 new messages from Friend 1 (written while you were apart)."]
        );
        // A fifth soon after: not said again within the minute.
        toasts_gone(&mut app);
        rows.extend(theirs(1, &[6], 80));
        testkit::reload_rows(&mut app, &rows);
        assert!(toasts(&app).is_empty(), "{:?}", toasts(&app));
    }

    #[test]
    fn no_burst_toast_in_a_conversation_or_for_a_few() {
        // Two only.
        let old = theirs(1, &[1], 120);
        let mut app = home(&old);
        let mut rows = old.clone();
        rows.extend(theirs(1, &[2, 3], 100));
        testkit::reload_rows(&mut app, &rows);
        // Three, but over more than a minute.
        testkit::tick(&mut app, BURST_WITHIN);
        rows.extend(theirs(1, &[4], 100));
        testkit::reload_rows(&mut app, &rows);
        assert!(toasts(&app).is_empty(), "{:?}", toasts(&app));
        // One came ten minutes before them: a conversation.
        let mut app = home(&old);
        let mut rows = old.clone();
        rows.extend(theirs(1, &[2], 15));
        testkit::reload_rows(&mut app, &rows);
        testkit::tick(&mut app, Duration::from_secs(600));
        rows.extend(theirs(1, &[3, 4, 5], 5));
        testkit::reload_rows(&mut app, &rows);
        assert!(toasts(&app).is_empty(), "{:?}", toasts(&app));
        // One written ten minutes ago was there when Raven opened.
        let recent = theirs(1, &[1], 10);
        let mut app = home(&recent);
        let mut rows = recent.clone();
        rows.extend(theirs(1, &[2, 3, 4], 5));
        testkit::reload_rows(&mut app, &rows);
        assert!(toasts(&app).is_empty(), "{:?}", toasts(&app));
        // Rows of the first load never are a burst.
        let mut first = old.clone();
        first.extend(theirs(1, &[2, 3, 4], 100));
        let app = home(&first);
        assert!(toasts(&app).is_empty());
    }

    #[test]
    fn meeting_toasts_wait_for_home() {
        let mut rows = mine(1, &[1], "queued");
        rows.extend(theirs(1, &[2], 120));
        let mut app = home(&rows);
        // NET is open when they come.
        testkit::press(&mut app, KeyCode::Char('n'));
        assert!(matches!(app.screen(), Screen::Network(_)));
        let mut later = mine(1, &[1], "delivered");
        later.extend(theirs(1, &[2], 120));
        later.extend(theirs(1, &[3, 4, 5], 90));
        testkit::reload_rows(&mut app, &later);
        assert!(toasts(&app).is_empty(), "{:?}", toasts(&app));
        // Back on Home: both, for the same friend.
        testkit::press(&mut app, KeyCode::Esc);
        assert_eq!(app.screen(), &Screen::Home);
        assert_eq!(
            toasts(&app),
            [
                "Delivered 1 message to Friend 1.",
                "3 new messages from Friend 1 (written while you were apart).",
            ]
        );
    }

    #[test]
    fn a_burst_needs_three_within_a_minute_after_an_hour() {
        const T0_MS: u64 = 1_760_000_000_000;
        let t0 = Instant::now();
        // Theirs, arrived `secs` after t0.
        let arrived = |secs: u64| Row {
            view: testkit::row(0, false, "", 600, "x"),
            seen_at_start: false,
            touched: Some(Touch {
                at: t0 + Duration::from_secs(secs),
                at_ms: T0_MS + secs * 1000,
            }),
        };
        // Theirs, there at the first load, written `secs` after t0.
        let at_start = |secs: u64| Row {
            view: RowView {
                created_at_ms: T0_MS + secs * 1000,
                ..testkit::row(0, false, "", 0, "x")
            },
            seen_at_start: true,
            touched: None,
        };
        let (now, now_ms) = (t0 + Duration::from_secs(7200), T0_MS + 7200 * 1000);
        let check = |rows: Vec<Row>| burst_after_silence(&rows, now, now_ms);
        let three = || vec![arrived(7150), arrived(7170), arrived(7199)];
        let with = |row: Row| {
            let mut rows = vec![row];
            rows.extend(three());
            rows
        };
        assert_eq!(check(three()), Some(3));
        // The one before them came an hour before the first, or less.
        assert_eq!(check(with(arrived(7150 - 3600))), Some(3));
        assert_eq!(check(with(arrived(7150 - 3599))), None);
        // Two within the minute; three over more than a minute.
        assert_eq!(check(three().split_off(1)), None);
        let spread = vec![arrived(7140), arrived(7170), arrived(7199)];
        assert_eq!(check(spread), None);
        // Yours don't count, either way.
        let mut one_mine = three();
        one_mine[0].view.outgoing = true;
        assert_eq!(check(one_mine), None);
        let delivered = Row {
            view: testkit::row(0, true, "delivered", 1, "x"),
            ..arrived(7190)
        };
        assert_eq!(check(with(delivered)), Some(3));
        // A row of the first load counts as arriving when it was written;
        // one written ahead of this clock, as arriving now.
        assert_eq!(check(with(at_start(7150 - 1800))), None);
        assert_eq!(check(with(at_start(7150 - 3600))), Some(3));
        assert_eq!(check(with(at_start(7200 + 3600))), None);
    }

    // ── Add a friend ────────────────────────────────────────────────────────

    /// Bob, a friend to add, and someone else.
    const BOB: u8 = 0xB0;
    const EVE: u8 = 0xE0;

    /// AF-1 opened with A from Home: `friends` saved, receiving `receive`.
    fn add_friend(receive: Receive, friends: Vec<ContactView>) -> (App, Vec<Cmd>) {
        let mut app = testkit::home_app((80, 24), receive, friends, Conversations::new());
        let cmds = testkit::press(&mut app, KeyCode::Char('a'));
        assert!(matches!(app.screen(), Screen::AddFriend(_)));
        (app, cmds)
    }

    fn adding(app: &App) -> &AddFriendState {
        match app.screen() {
            Screen::AddFriend(add) => add,
            other => panic!("not adding a friend: {other:?}"),
        }
    }

    /// The paste guard runs out.
    fn later(app: &mut App) -> Vec<Cmd> {
        testkit::tick(app, PASTE_GUARD)
    }

    fn stores(cmds: &[Cmd]) -> Vec<&StoreJob> {
        cmds.iter()
            .filter_map(|cmd| match cmd {
                Cmd::Store(job) => Some(job),
                _ => None,
            })
            .collect()
    }

    /// Every frame of `app` at 80x24 and 60x16: neither Bob's security code
    /// nor any of its groups, nor his security words in a row. (A frame that
    /// depends on his key in any other way: [`assert_blind`].)
    fn assert_no_code(app: &App) {
        let me = testkit::me(BOB);
        let (code, words) = (me.fingerprint, me.words.join(" "));
        for (cols, rows) in [(80, 24), (60, 16)] {
            let rows = testkit::render(app, cols, rows);
            let text = rows.join("\n");
            assert!(!text.contains(&code), "{code}:\n{text}");
            for group in code.split('-') {
                assert!(!text.contains(group), "{group} of {code}:\n{text}");
            }
            let read = testkit::screen_text(&rows);
            assert!(!read.contains(&words), "{words}:\n{text}");
        }
    }

    #[test]
    fn a_opens_add_a_friend_and_asks_for_my_card() {
        let (app, cmds) = add_friend(Receive::On, Vec::new());
        assert!(starts(&cmds), "OD-3: {cmds:?}");
        assert!(
            cmds.contains(&Cmd::Store(StoreJob::ShareCard { listen: None })),
            "{cmds:?}"
        );
        assert_eq!(adding(&app).focus, AddFocus::Paste);
        assert!(matches!(
            app.share_view().map(|view| view.state),
            Some(ShareState::Starting { .. })
        ));
        // Never asked receiving: RX first, and no start yet.
        let (app, cmds) = add_friend(Receive::Unset, Vec::new());
        assert!(!starts(&cmds));
        assert!(matches!(app.overlays(), [Overlay::Receive(_)]));
        // Esc goes back to Home.
        let (mut app, _) = add_friend(Receive::Off, Vec::new());
        testkit::press(&mut app, KeyCode::Esc);
        assert_eq!(app.screen(), &Screen::Home);
    }

    #[test]
    fn my_card_follows_the_listener_and_never_a_stale_answer() {
        let (mut app, _) = add_friend(Receive::On, Vec::new());
        let cmds = answer(
            &mut app,
            JobResult::Ensured(Ensured {
                result: Ok(()),
                after: listening(4242, "0.0.0.0:7420"),
                started_by_app: Some(4242),
                captured: String::new(),
                ring: 0..0,
            }),
        );
        let listen = Some("0.0.0.0:7420".to_owned());
        assert!(
            cmds.contains(&Cmd::Store(StoreJob::ShareCard {
                listen: listen.clone()
            })),
            "the node turned Ready: {cmds:?}"
        );
        // The first job's answer, for no listener, is not this one's.
        let card = |lan: &str| testkit::card(7, lan);
        answer(
            &mut app,
            JobResult::Shared {
                listen: None,
                share: Share {
                    lan: None,
                    with_lan: None,
                    plain: Ok(card("")),
                },
            },
        );
        assert!(matches!(
            app.share_view().map(|view| view.state),
            Some(ShareState::Starting { .. })
        ));
        answer(
            &mut app,
            JobResult::Shared {
                listen: listen.clone(),
                share: Share {
                    lan: Some(Ok("192.168.1.20:7420".into())),
                    with_lan: Some(Ok(card("192.168.1.20:7420"))),
                    plain: Ok(card("")),
                },
            },
        );
        let view = app.share_view().expect("AF-1");
        assert_eq!(
            view.state,
            ShareState::Ready {
                lan: "192.168.1.20:7420".into()
            }
        );
        assert_eq!(view.line, Some(card("192.168.1.20:7420")));
        assert!(view.with_address && !view.offers_anyway());
        // S is not offered while Raven can share its address.
        testkit::press(&mut app, KeyCode::Tab);
        testkit::press(&mut app, KeyCode::Char('s'));
        assert!(!adding(&app).share_anyway);
        // The node goes to this computer only: asked again, no address.
        let cmds = testkit::send(
            &mut app,
            Msg::Poll(PollUpdate::Status(listening(4242, "127.0.0.1:7420"))),
        );
        assert!(
            cmds.contains(&Cmd::Store(StoreJob::ShareCard { listen: None })),
            "{cmds:?}"
        );
        let view = app.share_view().expect("AF-1");
        assert_eq!(
            view.state,
            ShareState::LocalOnly {
                ip: "127.0.0.1".into()
            }
        );
        assert_eq!(view.line, None, "only after S");
        testkit::press(&mut app, KeyCode::Char('s'));
        let view = app.share_view().expect("AF-1");
        assert!(view.line.is_some() && !view.with_address);
    }

    #[test]
    fn a_paste_never_advances_by_itself() {
        let card = testkit::card(BOB, "192.168.1.30:7420");
        for via in [PasteVia::Bracketed, PasteVia::Keystrokes] {
            let (mut app, _) = add_friend(Receive::Off, Vec::new());
            let cmds = testkit::paste(&mut app, &format!("{card}\n"), via);
            assert!(stores(&cmds).is_empty(), "{cmds:?}");
            assert!(adding(&app).friend().is_some(), "{via:?}");
            // Its line break, and an Enter right after it, go on to nothing.
            testkit::send(&mut app, Msg::Key(Key::PastedEnter));
            testkit::press(&mut app, KeyCode::Enter);
            testkit::tick(&mut app, Duration::from_millis(299));
            testkit::press(&mut app, KeyCode::Enter);
            assert!(!adding(&app).naming, "{via:?}");
            later(&mut app);
            testkit::press(&mut app, KeyCode::Enter);
            assert!(adding(&app).naming, "{via:?}");
            // Esc goes back to AF-1, the paste still there.
            testkit::press(&mut app, KeyCode::Esc);
            assert!(!adding(&app).naming);
            assert!(adding(&app).friend().is_some());
        }
    }

    #[test]
    fn a_card_split_over_two_lines_parses() {
        let card = testkit::card(BOB, "192.168.1.30:7420");
        let at = card.find(" pub_hex=").expect("a key field") + 30;
        for split in [
            format!("{}\n{}", &card[..at], &card[at..]),
            format!("{}\r\n{}", &card[..at], &card[at..]),
        ] {
            let (mut app, _) = add_friend(Receive::Off, Vec::new());
            testkit::paste(&mut app, &split, PasteVia::Keystrokes);
            let friend = adding(&app).friend().expect("parsed").clone();
            assert_eq!(friend.pub_hex, testkit::me(BOB).pub_hex);
            assert_eq!(friend.lan, "192.168.1.30:7420");
        }
        // Typed in two pastes close together: the second is the rest of it.
        let (mut app, _) = add_friend(Receive::Off, Vec::new());
        testkit::paste(&mut app, &card[..at], PasteVia::Keystrokes);
        assert!(adding(&app).friend().is_none());
        testkit::tick(&mut app, Duration::from_millis(50));
        testkit::paste(&mut app, &card[at..], PasteVia::Keystrokes);
        assert_eq!(
            adding(&app).friend().map(|f| f.lan.as_str()),
            Some("192.168.1.30:7420")
        );
        // A paste after the guard replaces what parsed.
        later(&mut app);
        testkit::paste(&mut app, &testkit::me(EVE).invite, PasteVia::Bracketed);
        assert_eq!(
            adding(&app).friend().map(|f| f.pub_hex.clone()),
            Some(testkit::me(EVE).pub_hex)
        );
    }

    #[test]
    fn my_own_invite_and_a_tampered_one_are_refused() {
        let bob = testkit::me(BOB);
        let forged = testkit::card(BOB, "").replace(&bob.pub_hex, &testkit::me(EVE).pub_hex);
        for (text, want) in [
            (testkit::me(7).invite, "own"),
            (testkit::card(7, "192.168.1.20:7420"), "own"),
            (forged, "tampered"),
            (
                format!("raven:{}:{}", bob.address, testkit::me(EVE).pub_hex),
                "tampered",
            ),
        ] {
            let (mut app, _) = add_friend(Receive::Off, Vec::new());
            testkit::paste(&mut app, &text, PasteVia::Bracketed);
            match (&adding(&app).parsed, want) {
                (Some(Err(PasteProblem::OwnInvite)), "own")
                | (Some(Err(PasteProblem::Tampered(_))), "tampered") => {}
                (other, _) => panic!("{text}: {other:?}"),
            }
            later(&mut app);
            let cmds = testkit::press(&mut app, KeyCode::Enter);
            assert!(!adding(&app).naming && stores(&cmds).is_empty());
            assert_no_code(&app);
        }
    }

    #[test]
    fn typing_in_the_paste_box_is_text_until_it_parses() {
        let (mut app, _) = add_friend(Receive::Off, Vec::new());
        let invite = testkit::me(BOB).invite;
        for c in invite.chars() {
            testkit::press(&mut app, KeyCode::Char(c));
            testkit::tick(&mut app, Duration::from_millis(400));
        }
        assert!(adding(&app).friend().is_some());
        // Letters typed now are no text; Backspace starts again.
        testkit::press(&mut app, KeyCode::Char('x'));
        assert_eq!(adding(&app).text, invite);
        testkit::press(&mut app, KeyCode::Backspace);
        assert_eq!(adding(&app).text, "");
        // Backspace takes one character of text that doesn't parse;
        // Ctrl+U all of it.
        for c in "rav".chars() {
            testkit::press(&mut app, KeyCode::Char(c));
        }
        testkit::press(&mut app, KeyCode::Backspace);
        assert_eq!(adding(&app).text, "ra");
        assert!(matches!(
            adding(&app).parsed,
            Some(Err(PasteProblem::NotACard(_)))
        ));
        testkit::ctrl(&mut app, 'u');
        assert_eq!(
            (adding(&app).text.as_str(), &adding(&app).parsed),
            ("", &None)
        );
    }

    #[test]
    fn a_keystroke_paste_in_the_share_box_goes_into_the_paste_box() {
        let (mut app, _) = add_friend(Receive::On, Vec::new());
        answer(
            &mut app,
            JobResult::Ensured(Ensured {
                result: Ok(()),
                after: listening(4242, "0.0.0.0:7420"),
                started_by_app: Some(4242),
                captured: String::new(),
                ring: 0..0,
            }),
        );
        answer(
            &mut app,
            JobResult::Shared {
                listen: Some("0.0.0.0:7420".into()),
                share: Share {
                    lan: Some(Ok("192.168.1.20:7420".into())),
                    with_lan: Some(Ok(testkit::card(7, "192.168.1.20:7420"))),
                    plain: Ok(testkit::card(7, "")),
                },
            },
        );
        testkit::press(&mut app, KeyCode::Tab);
        assert_eq!(adding(&app).focus, AddFocus::Share);
        let card = testkit::card(BOB, "192.168.1.30:7420");
        // Windows: keystrokes, the l and c of 'lan=' and 'card' in it.
        let cmds = testkit::paste(&mut app, &format!("{card}\n"), PasteVia::Keystrokes);
        assert!(
            !cmds
                .iter()
                .any(|cmd| matches!(cmd, Cmd::Peek(_) | Cmd::Store(_))),
            "{cmds:?}"
        );
        assert!(app.settings().include_lan_in_card, "L did not fire");
        assert!(!app.peeking(), "C did not fire");
        assert_eq!(adding(&app).focus, AddFocus::Paste);
        assert!(adding(&app).friend().is_some());
        // A key or two the input thread did not join up, right after: text
        // too, even back in the share box.
        testkit::press(&mut app, KeyCode::Tab);
        for c in ['l', 'c'] {
            let cmds = testkit::press(&mut app, KeyCode::Char(c));
            assert!(cmds.is_empty(), "{cmds:?}");
        }
        assert!(app.settings().include_lan_in_card && !app.peeking());
        assert!(adding(&app).text.ends_with("lc"), "{}", adding(&app).text);
        // Later, L and C are keys again.
        later(&mut app);
        testkit::press(&mut app, KeyCode::Tab);
        assert_eq!(adding(&app).focus, AddFocus::Share);
        testkit::press(&mut app, KeyCode::Char('l'));
        assert!(!app.settings().include_lan_in_card);
    }

    #[test]
    fn copy_shows_my_invite_on_the_plain_terminal_until_any_key() {
        let (mut app, _) = add_friend(Receive::Off, Vec::new());
        // Nothing to copy yet (no S): Ctrl+C does nothing, and is no quit.
        assert!(testkit::ctrl(&mut app, 'c').is_empty());
        assert!(app.overlays().is_empty() && !app.peeking());
        answer(
            &mut app,
            JobResult::Shared {
                listen: None,
                share: Share {
                    lan: None,
                    with_lan: None,
                    plain: Ok(testkit::card(7, "")),
                },
            },
        );
        testkit::press(&mut app, KeyCode::Tab);
        testkit::press(&mut app, KeyCode::Char('s'));
        app.take_dirty();
        let cmds = testkit::press(&mut app, KeyCode::Char('c'));
        assert_eq!(
            cmds,
            [Cmd::Peek(add_friend::copy_lines(
                &testkit::card(7, ""),
                cfg!(windows),
                false
            ))]
        );
        assert!(app.peeking());
        // Nothing is drawn meanwhile: no frame is due and nothing moves.
        let t0 = app.now();
        app.mark_drawn(t0);
        assert!(anim::moving(&app).is_empty());
        assert_eq!(anim::next_wait(&app, t0), None);
        // A paste is not a key; any key comes back, and is nothing more.
        assert!(testkit::paste(&mut app, "x", PasteVia::Bracketed).is_empty());
        assert!(app.peeking());
        assert_eq!(testkit::press(&mut app, KeyCode::Char('q')), [Cmd::Unpeek]);
        assert!(!app.peeking() && app.overlays().is_empty() && app.take_dirty());
        // Ctrl+C anywhere on AF-1 opens it too, in the paste box as well.
        testkit::press(&mut app, KeyCode::Tab);
        assert_eq!(adding(&app).focus, AddFocus::Paste);
        assert!(matches!(testkit::ctrl(&mut app, 'c')[..], [Cmd::Peek(_)]));
        assert_eq!(testkit::ctrl(&mut app, 'c'), [Cmd::Unpeek], "no QUIT");
        assert!(app.overlays().is_empty());
    }

    /// Phase 6b P6.25 (S12): NAME-CLASH (another key under a verified
    /// friend's name) is noted as the CLI notes a refused key change:
    /// `SEC_KEY_CHANGE_ATTEMPT` about that friend, once per clash, and
    /// nothing while the events gate is shut. The events gate opens for this
    /// thread only (a release build cannot open it: nothing to check there).
    #[test]
    fn name_clash_notes_a_key_change_attempt_about_the_verified_friend() {
        use raven_core::security_events::{
            clear_sink, set_sink, Attribution, SecEvent, SecKind, SecSink, Severity,
        };
        use raven_core::security_gate::{self, SecGate};
        use std::sync::{Arc, Mutex};
        struct Seen(Arc<Mutex<Vec<SecKind>>>, [u8; 32]);
        impl SecSink for Seen {
            fn accept(&self, ev: &SecEvent, _: Severity) {
                if ev.who == (Attribution::Contact { peer: self.1 }) {
                    self.0.lock().unwrap().push(ev.kind);
                }
            }
        }
        // A key only this test uses: the sink is the process's, and other
        // tests here open NAME-CLASH for BOB on their own threads (with the
        // suite's lab switches, the gate is live on theirs too).
        let bob = testkit::saved_as(0xB9, "Bob", true, "192.168.1.30:7420");
        let bob_key: [u8; 32] = hex::decode(&bob.pub_hex).unwrap().try_into().unwrap();
        let clash = |events: bool| {
            security_gate::set_lab_for_this_thread(SecGate::Events, Some(events));
            let (mut app, _) = add_friend(Receive::Off, vec![bob.clone()]);
            testkit::paste(
                &mut app,
                &testkit::card(EVE, "192.168.1.66:7420"),
                PasteVia::Bracketed,
            );
            later(&mut app);
            testkit::press(&mut app, KeyCode::Enter);
            for c in "bob".chars() {
                testkit::press(&mut app, KeyCode::Char(c));
            }
            testkit::press(&mut app, KeyCode::Enter);
            assert!(matches!(app.screen(), Screen::NameClash(_)));
            security_gate::set_lab_for_this_thread(SecGate::Events, None);
        };
        let seen = Arc::new(Mutex::new(Vec::new()));
        set_sink(Box::new(Seen(Arc::clone(&seen), bob_key)));
        clash(false);
        assert!(seen.lock().unwrap().is_empty(), "nothing while shut");
        security_gate::set_lab_for_this_thread(SecGate::Events, Some(true));
        let live = security_gate::live(SecGate::Events);
        security_gate::set_lab_for_this_thread(SecGate::Events, None);
        clash(true);
        clear_sink();
        let want = if live {
            vec![SecKind::KeyChangeAttempt]
        } else {
            Vec::new()
        };
        assert_eq!(*seen.lock().unwrap(), want);
    }

    #[test]
    fn a_name_a_friend_has_is_refused_and_a_verified_friends_is_name_clash() {
        // Carol, not verified; Bob, verified, with key A.
        let carol = testkit::saved_as(0xC0, "Carol", false, "");
        let bob = testkit::saved_as(BOB, "Bob", true, "192.168.1.30:7420");
        let name_it = |name: &str| {
            let (mut app, _) = add_friend(Receive::Off, vec![carol.clone(), bob.clone()]);
            // Key B.
            testkit::paste(
                &mut app,
                &testkit::card(EVE, "192.168.1.66:7420"),
                PasteVia::Bracketed,
            );
            later(&mut app);
            testkit::press(&mut app, KeyCode::Enter);
            assert!(adding(&app).naming);
            for c in name.chars() {
                testkit::press(&mut app, KeyCode::Char(c));
            }
            let cmds = testkit::press(&mut app, KeyCode::Enter);
            assert!(stores(&cmds).is_empty(), "nothing is saved: {cmds:?}");
            app
        };
        let app = name_it("CAROL");
        assert_eq!(
            adding(&app).name_problem,
            Some(NameProblem::Taken(carol.pub_hex.clone()))
        );
        assert!(testkit::screen_text(&testkit::render(&app, 80, 24))
            .contains("You already have a friend called Carol. Pick another name."));
        let app = name_it("   ");
        assert_eq!(adding(&app).name_problem, Some(NameProblem::Empty));
        // Bob's name, in any case or with a look-alike letter: NAME-CLASH.
        for name in ["bob", "BOB", "b\u{043E}b"] {
            let mut app = name_it(name);
            let Screen::NameClash(clash) = app.screen() else {
                panic!("{name}: {:?}", app.screen());
            };
            assert_eq!(clash.verified, bob.pub_hex);
            // Nothing is saved from here, whatever is pressed.
            for code in [KeyCode::Enter, KeyCode::Char('y'), KeyCode::Char('x')] {
                assert!(stores(&testkit::press(&mut app, code)).is_empty());
            }
            assert!(matches!(app.screen(), Screen::NameClash(_)));
            // Esc: back to AF-2 as it was.
            testkit::press(&mut app, KeyCode::Esc);
            assert!(adding(&app).naming);
            assert_eq!(adding(&app).name, name);
            // O: the old Bob's page (CI), where X removes him; Esc, Home.
            testkit::press(&mut app, KeyCode::Enter);
            testkit::press(&mut app, KeyCode::Char('o'));
            let Screen::FriendPage(page) = app.screen() else {
                panic!("{name}: {:?}", app.screen());
            };
            assert_eq!(page.pub_hex, bob.pub_hex);
            testkit::press(&mut app, KeyCode::Esc);
            assert_eq!(app.screen(), &Screen::Home);
        }
        // Ctrl+C on AF-2 is QUIT.
        let mut app = name_it("");
        testkit::ctrl(&mut app, 'c');
        assert_eq!(app.overlays(), [Overlay::Quit]);
    }

    #[test]
    fn new_addresses_for_a_saved_friend_need_the_code() {
        let bob = testkit::saved_as(BOB, "Bob", true, "192.168.1.30:7420");
        let (mut app, _) = add_friend(Receive::Off, vec![bob.clone()]);
        let new = testkit::card(BOB, "192.168.1.44:7420");
        testkit::paste(&mut app, &new, PasteVia::Bracketed);
        later(&mut app);
        // A saved friend never goes on to AF-2.
        testkit::press(&mut app, KeyCode::Enter);
        assert!(!adding(&app).naming);
        testkit::press(&mut app, KeyCode::Char('u'));
        let code = app.update_code_for_tests().expect("a code").to_owned();
        assert_no_code(&app);
        // A paste can't answer it.
        testkit::paste(&mut app, &code, PasteVia::Bracketed);
        testkit::send(&mut app, Msg::Key(Key::PastedEnter));
        assert_eq!(
            adding(&app).update.as_ref().map(|u| u.typed.as_str()),
            Some("")
        );
        later(&mut app);
        // A wrong code saves nothing and draws a new one.
        for c in "22222".chars() {
            testkit::press(&mut app, KeyCode::Char(c));
        }
        let cmds = testkit::press(&mut app, KeyCode::Enter);
        assert!(stores(&cmds).is_empty(), "{cmds:?}");
        let update = adding(&app).update.clone().expect("asked again");
        assert!(update.wrong && update.typed.is_empty());
        // The code, typed: the new routes are saved, the pin kept (the
        // controller's job).
        let code = update.code;
        for c in code.to_lowercase().chars() {
            testkit::press(&mut app, KeyCode::Char(c));
        }
        let cmds = testkit::press(&mut app, KeyCode::Enter);
        let friend = bridge::parse_card_or_invite(&new).expect("Bob's card");
        assert_eq!(
            stores(&cmds),
            [&StoreJob::UpdateAddresses(friend)],
            "{cmds:?}"
        );
        assert!(adding(&app).updating && adding(&app).update.is_none());
        assert!(
            app.jobs_in_flight().holds_classic(),
            "it writes contacts.json"
        );
        // Saved: Bob's chat opens.
        let cmds = answer(
            &mut app,
            JobResult::AddressesUpdated {
                pub_hex: bob.pub_hex.clone(),
                result: Ok(()),
            },
        );
        assert!(cmds.contains(&Cmd::Store(StoreJob::LoadContacts)));
        assert_eq!(app.screen(), &Screen::Home);
        assert_eq!(app.open_friend(), Some(bob.pub_hex.as_str()));
        assert_eq!(toast_text(&app), Some("Raven saved Bob's new address."));

        // A refusal says why, on AF-1.
        let (mut app, _) = add_friend(Receive::Off, vec![bob.clone()]);
        testkit::paste(&mut app, &new, PasteVia::Bracketed);
        later(&mut app);
        testkit::press(&mut app, KeyCode::Char('u'));
        let code = app.update_code_for_tests().expect("a code").to_owned();
        for c in code.chars() {
            testkit::press(&mut app, KeyCode::Char(c));
        }
        testkit::press(&mut app, KeyCode::Enter);
        answer(
            &mut app,
            JobResult::AddressesUpdated {
                pub_hex: bob.pub_hex.clone(),
                result: Err("contacts.json: expected value".into()),
            },
        );
        assert_eq!(
            adding(&app).update_error.as_deref(),
            Some("Your friends list can't be read.")
        );
        // O opens the chat at once.
        testkit::press(&mut app, KeyCode::Char('o'));
        assert_eq!(app.screen(), &Screen::Home);
        assert_eq!(app.open_friend(), Some(bob.pub_hex.as_str()));
        assert_eq!(app.focus(), Focus::Composer);
    }

    #[test]
    fn no_frame_shows_the_friends_code() {
        let card = testkit::card(BOB, "192.168.1.30:7420");
        let (mut app, _) = add_friend(Receive::Off, Vec::new());
        // Every part of the paste as it arrives, before and after it parses.
        for end in [20, card.len() / 2, card.len() - 20, card.len()] {
            testkit::paste(&mut app, &card[..end], PasteVia::Keystrokes);
            assert_no_code(&app);
            testkit::ctrl(&mut app, 'u');
        }
        // Wrapped by the terminal inside the code.
        let at = card.find("fingerprint=").expect("its code") + 15;
        testkit::paste(
            &mut app,
            &format!("{}\n{}", &card[..at], &card[at..]),
            PasteVia::Keystrokes,
        );
        assert_no_code(&app);
        later(&mut app);
        testkit::press(&mut app, KeyCode::Enter);
        assert!(adding(&app).naming);
        assert_no_code(&app);
        for c in "Bob".chars() {
            testkit::press(&mut app, KeyCode::Char(c));
        }
        assert_no_code(&app);
    }

    // ── VF, AF-3 and CI ─────────────────────────────────────────────────────

    /// Alice, saved and not verified.
    const ALICE: u8 = 0xA1;

    /// From AF-1: Bob's card pasted, named 'Bob' on AF-2, Enter: VF.
    fn to_vf(app: &mut App) {
        testkit::paste(
            app,
            &testkit::card(BOB, "192.168.1.30:7420"),
            PasteVia::Bracketed,
        );
        later(app);
        testkit::press(app, KeyCode::Enter);
        type_into(app, "Bob");
        testkit::press(app, KeyCode::Enter);
        assert!(
            matches!(app.screen(), Screen::Verify(_)),
            "{:?}",
            app.screen()
        );
    }

    /// VF for Bob, with `friends` saved, receiving off, taking his old code
    /// (Ctrl+O).
    fn verifying(friends: Vec<ContactView>) -> App {
        let mut app = verifying_words(friends);
        testkit::ctrl(&mut app, 'o');
        assert_eq!(vf(&app).entry.mode, EntryMode::Code);
        app
    }

    /// VF for Bob, with `friends` saved, receiving off: his words.
    fn verifying_words(friends: Vec<ContactView>) -> App {
        let (mut app, _) = add_friend(Receive::Off, friends);
        to_vf(&mut app);
        assert_eq!(vf(&app).entry.mode, EntryMode::Words);
        app
    }

    fn vf(app: &App) -> &VerifyState {
        match app.screen() {
            Screen::Verify(vf) => vf,
            other => panic!("not on VF: {other:?}"),
        }
    }

    fn page(app: &App) -> &PageState {
        match app.screen() {
            Screen::FriendPage(page) => page,
            other => panic!("not on a friend's page: {other:?}"),
        }
    }

    /// `text` typed key by key, and the commands it gave.
    fn type_into(app: &mut App, text: &str) -> Vec<Cmd> {
        let mut cmds = Vec::new();
        for c in text.chars() {
            cmds.extend(testkit::press(app, KeyCode::Char(c)));
        }
        cmds
    }

    fn erase(app: &mut App, keys: usize) {
        for _ in 0..keys {
            testkit::press(app, KeyCode::Backspace);
        }
    }

    /// The security code of seed `seed`, as its owner reads it out: its
    /// letters and digits.
    fn code_of(seed: u8) -> String {
        testkit::me(seed).fingerprint.replace('-', "")
    }

    /// `code` with its first letter in the other case.
    fn first_letter_flipped(code: &str) -> String {
        let mut flipped = false;
        code.chars()
            .map(|c| match (flipped, c.is_ascii_alphabetic()) {
                (false, true) => {
                    flipped = true;
                    if c.is_ascii_uppercase() {
                        c.to_ascii_lowercase()
                    } else {
                        c.to_ascii_uppercase()
                    }
                }
                _ => c,
            })
            .collect()
    }

    /// The confirmation code on show, typed, then Enter: the commands.
    fn confirm(app: &mut App) -> Vec<Cmd> {
        let code = app.verify_code_for_tests().expect("a code").to_owned();
        let mut cmds = type_into(app, &code.to_lowercase());
        cmds.extend(testkit::press(app, KeyCode::Enter));
        cmds
    }

    fn saved(change: FriendChange, pub_hex: &str, result: Result<(), String>) -> JobResult {
        JobResult::FriendChanged {
            change,
            pub_hex: pub_hex.to_owned(),
            result,
            notes: Vec::new(),
        }
    }

    #[test]
    fn bob_is_saved_verified_only_after_both_codes() {
        let mut app = verifying(Vec::new());
        let bob = testkit::me(BOB);
        let code = code_of(BOB);
        let mut cmds = testkit::press(&mut app, KeyCode::Enter);
        assert_eq!(vf(&app).step, VerifyStep::Comparing(None), "nothing typed");
        // A wrong code: the mismatch, and nothing saved.
        cmds.extend(type_into(&mut app, "zzzzyyyyxxxx"));
        cmds.extend(testkit::press(&mut app, KeyCode::Enter));
        assert_eq!(
            vf(&app).step,
            VerifyStep::Comparing(Some(CodeProblem::Mismatch))
        );
        // Editing it clears what Enter said.
        erase(&mut app, 12);
        assert_eq!(
            (vf(&app).entry.code.as_str(), &vf(&app).step),
            ("", &VerifyStep::Comparing(None))
        );
        // One letter in the wrong case: the case hint.
        cmds.extend(type_into(&mut app, &first_letter_flipped(&code)));
        cmds.extend(testkit::press(&mut app, KeyCode::Enter));
        assert_eq!(
            vf(&app).step,
            VerifyStep::Comparing(Some(CodeProblem::CaseOnly))
        );
        // As Bob reads it, separators and all (the field keeps letters and
        // digits): it matches, his code shows, and a confirmation code is
        // asked for.
        erase(&mut app, code.len());
        cmds.extend(type_into(&mut app, &bob.fingerprint));
        assert_eq!(vf(&app).entry.code, code);
        assert!(app.verify_view().expect("VF").theirs.is_none());
        cmds.extend(testkit::press(&mut app, KeyCode::Enter));
        assert!(matches!(vf(&app).step, VerifyStep::Matched { .. }));
        assert_eq!(
            app.verify_view().expect("VF").theirs,
            Some(bob.fingerprint.split('-').map(str::to_owned).collect())
        );
        // A wrong confirmation code ('1' is no code letter): nothing saved,
        // and a new code.
        cmds.extend(type_into(&mut app, "11111"));
        cmds.extend(testkit::press(&mut app, KeyCode::Enter));
        assert!(stores(&cmds).is_empty(), "{cmds:?}");
        let VerifyStep::Matched { confirm: wrong, .. } = &vf(&app).step else {
            panic!("{:?}", vf(&app).step);
        };
        assert!(wrong.wrong && wrong.typed.is_empty());
        // The code (in any case): Bob saved with the pin, the code as typed.
        let cmds = confirm(&mut app);
        let friend = bridge::parse_card_or_invite(&testkit::card(BOB, "192.168.1.30:7420"))
            .expect("Bob's card");
        assert_eq!(
            stores(&cmds),
            [&StoreJob::SaveFriend {
                friend,
                name: "Bob".into(),
                verify: Verify::Pinned {
                    typed_fp: code.clone()
                },
            }]
        );
        assert_eq!(vf(&app).step, VerifyStep::Saving { verified: true });
        assert!(
            app.jobs_in_flight().holds_classic(),
            "it writes contacts.json"
        );
        // While it saves, the keys wait.
        for key in [KeyCode::Esc, KeyCode::Enter, KeyCode::Char('x')] {
            assert!(stores(&testkit::press(&mut app, key)).is_empty());
        }
        assert_eq!(vf(&app).step, VerifyStep::Saving { verified: true });
        // Saved: AF-3, and Bob is in the list at once, verified.
        let cmds = answer(&mut app, saved(FriendChange::Add, &bob.pub_hex, Ok(())));
        assert!(cmds.contains(&Cmd::Store(StoreJob::LoadContacts)));
        let Screen::Added(added) = app.screen() else {
            panic!("{:?}", app.screen());
        };
        assert!(added.verified && added.name == "Bob");
        assert!(app.friend(&bob.pub_hex).is_some_and(|f| f.pinned));
        // Enter opens his chat.
        testkit::press(&mut app, KeyCode::Enter);
        assert_eq!(app.screen(), &Screen::Home);
        assert_eq!(app.open_friend(), Some(bob.pub_hex.as_str()));
        assert_eq!(app.focus(), Focus::Composer);
    }

    #[test]
    fn later_saves_bob_as_not_verified_after_the_code() {
        let mut app = verifying(Vec::new());
        type_into(&mut app, "M0");
        testkit::press(&mut app, KeyCode::Tab);
        assert!(matches!(vf(&app).step, VerifyStep::Later(_)));
        assert!(app.verify_view().expect("VF").theirs.is_none());
        // Tab again: back to the code, what was typed kept.
        testkit::press(&mut app, KeyCode::Tab);
        assert_eq!(
            (vf(&app).entry.code.as_str(), &vf(&app).step),
            ("M0", &VerifyStep::Comparing(None))
        );
        testkit::press(&mut app, KeyCode::Tab);
        let mut cmds = type_into(&mut app, "11111");
        cmds.extend(testkit::press(&mut app, KeyCode::Enter));
        assert!(stores(&cmds).is_empty(), "{cmds:?}");
        assert!(matches!(&vf(&app).step, VerifyStep::Later(code) if code.wrong));
        let cmds = confirm(&mut app);
        assert!(
            matches!(
                stores(&cmds)[..],
                [StoreJob::SaveFriend {
                    verify: Verify::Unpinned,
                    ..
                }]
            ),
            "{cmds:?}"
        );
        answer(
            &mut app,
            saved(FriendChange::Add, &testkit::me(BOB).pub_hex, Ok(())),
        );
        assert!(matches!(app.screen(), Screen::Added(added) if !added.verified));
        assert!(app
            .friend(&testkit::me(BOB).pub_hex)
            .is_some_and(|f| !f.pinned));
        // 1 shows my invite again; A adds another friend.
        testkit::press(&mut app, KeyCode::Char('1'));
        assert_eq!(adding(&app).focus, AddFocus::Share);
    }

    #[test]
    fn a_code_in_persian_or_arabic_indic_digits_verifies() {
        let bob = testkit::me(BOB);
        let code = code_of(BOB);
        let friend = bridge::parse_card_or_invite(&testkit::card(BOB, "192.168.1.30:7420"))
            .expect("Bob's card");
        for zero in [testkit::PERSIAN_ZERO, testkit::ARABIC_INDIC_ZERO] {
            let mut app = verifying(Vec::new());
            let typed = testkit::digits_from(&bob.fingerprint, zero);
            assert_ne!(typed, bob.fingerprint, "Bob's code has digits");
            type_into(&mut app, &typed);
            // The field keeps 0-9, and its groups are marked from them.
            assert_eq!(vf(&app).entry.code, code);
            let marks = app.verify_view().expect("VF").typed;
            assert!(
                marks.iter().all(|(_, mark)| *mark == Some(true)),
                "{marks:?}"
            );
            testkit::press(&mut app, KeyCode::Enter);
            assert!(
                matches!(vf(&app).step, VerifyStep::Matched { .. }),
                "{:?}",
                vf(&app).step
            );
            // The confirmation code with the same digits: Bob saved with
            // the pin, his code as cli.rs reads it.
            let asked = app.verify_code_for_tests().expect("a code").to_owned();
            let mut cmds = type_into(&mut app, &testkit::digits_from(&asked, zero));
            let VerifyStep::Matched { confirm: field, .. } = &vf(&app).step else {
                panic!("{:?}", vf(&app).step);
            };
            assert_eq!(field.typed, asked);
            cmds.extend(testkit::press(&mut app, KeyCode::Enter));
            assert_eq!(
                stores(&cmds),
                [&StoreJob::SaveFriend {
                    friend: friend.clone(),
                    name: "Bob".into(),
                    verify: Verify::Pinned {
                        typed_fp: code.clone()
                    },
                }]
            );
        }
        // A confirmation field reads them as 0-9 as they are typed.
        let mut field = ConfirmCode::new(false);
        field.type_text(&testkit::digits_from("7k3", testkit::PERSIAN_ZERO));
        field.type_text(&testkit::digits_from("q9", testkit::ARABIC_INDIC_ZERO));
        assert_eq!(field.typed, "7k3q9");
    }

    #[test]
    fn persian_letters_get_the_keyboard_hint_not_the_attack_warning() {
        let bob = testkit::me(BOB);
        let code = code_of(BOB);
        let digits: String = code.chars().filter(char::is_ascii_digit).collect();
        let keyboard = VerifyStep::Comparing(Some(CodeProblem::Keyboard));
        let mut app = verifying(Vec::new());
        // Bob's code as a Persian keyboard types it: its letters are not
        // kept, its digits are read as 0-9, and the hint shows at once.
        let (first, rest) = bob.fingerprint.split_at(1);
        let mut cmds = type_into(&mut app, &testkit::on_persian_keyboard(first));
        assert_eq!(
            (vf(&app).entry.code.as_str(), &vf(&app).step),
            ("", &keyboard)
        );
        cmds.extend(type_into(&mut app, &testkit::on_persian_keyboard(rest)));
        assert_eq!(
            (vf(&app).entry.code.as_str(), &vf(&app).step),
            (digits.as_str(), &keyboard)
        );
        // Enter keeps the hint: never the mismatch's warning, and nothing
        // is saved.
        cmds.extend(testkit::press(&mut app, KeyCode::Enter));
        assert_eq!(vf(&app).step, keyboard);
        assert!(stores(&cmds).is_empty(), "{cmds:?}");
        // Erasing, digits and separators don't change the keyboard.
        erase(&mut app, 1);
        let last = &digits[digits.len() - 1..];
        type_into(
            &mut app,
            &testkit::digits_from(&format!("-{last} "), testkit::PERSIAN_ZERO),
        );
        assert_eq!(
            (vf(&app).entry.code.as_str(), &vf(&app).step),
            (digits.as_str(), &keyboard)
        );
        // A Latin letter says the keyboard is on English letters again: the
        // hint goes, and a wrong code gets the mismatch.
        erase(&mut app, digits.len());
        type_into(&mut app, "zzzzyyyyxxxx");
        assert_eq!(vf(&app).step, VerifyStep::Comparing(None));
        testkit::press(&mut app, KeyCode::Enter);
        assert_eq!(
            vf(&app).step,
            VerifyStep::Comparing(Some(CodeProblem::Mismatch))
        );
        // A letter of another alphabet then: the hint, in its place.
        type_into(&mut app, &testkit::on_persian_keyboard("x"));
        assert_eq!(vf(&app).step, keyboard);
        testkit::press(&mut app, KeyCode::Enter);
        assert_eq!(vf(&app).step, keyboard);
        // Bob's code in Latin letters matches.
        erase(&mut app, 12);
        type_into(&mut app, &bob.fingerprint);
        assert_eq!(vf(&app).step, VerifyStep::Comparing(None));
        testkit::press(&mut app, KeyCode::Enter);
        assert!(matches!(vf(&app).step, VerifyStep::Matched { .. }));
        // The confirmation code with a letter of another alphabet: the hint,
        // and the same code and what was typed stay; nothing is saved.
        let asked = app.verify_code_for_tests().expect("a code").to_owned();
        let mut cmds = type_into(&mut app, &testkit::on_persian_keyboard("x2"));
        cmds.extend(testkit::press(&mut app, KeyCode::Enter));
        assert!(stores(&cmds).is_empty(), "{cmds:?}");
        let VerifyStep::Matched { confirm: field, .. } = &vf(&app).step else {
            panic!("{:?}", vf(&app).step);
        };
        let typed = format!("{}2", testkit::on_persian_keyboard("x"));
        assert!(field.keyboard && !field.wrong);
        assert_eq!(
            (field.code.as_str(), field.typed.as_str()),
            (asked.as_str(), typed.as_str())
        );
        // In Latin letters: Bob saved, verified.
        erase(&mut app, 2);
        let cmds = confirm(&mut app);
        assert!(
            matches!(
                stores(&cmds)[..],
                [StoreJob::SaveFriend {
                    verify: Verify::Pinned { .. },
                    ..
                }]
            ),
            "{cmds:?}"
        );
        // Later's code alike.
        let mut app = verifying(Vec::new());
        testkit::press(&mut app, KeyCode::Tab);
        let mut cmds = type_into(&mut app, &testkit::on_persian_keyboard("x"));
        cmds.extend(testkit::press(&mut app, KeyCode::Enter));
        assert!(stores(&cmds).is_empty(), "{cmds:?}");
        assert!(
            matches!(&vf(&app).step, VerifyStep::Later(field) if field.keyboard && !field.wrong),
            "{:?}",
            vf(&app).step
        );
    }

    #[test]
    fn vf_case_still_matters_after_folding() {
        let mut app = verifying(Vec::new());
        let typed =
            testkit::digits_from(&first_letter_flipped(&code_of(BOB)), testkit::PERSIAN_ZERO);
        type_into(&mut app, &typed);
        testkit::press(&mut app, KeyCode::Enter);
        assert_eq!(
            vf(&app).step,
            VerifyStep::Comparing(Some(CodeProblem::CaseOnly))
        );
    }

    #[test]
    fn the_update_code_reads_persian_digits_and_hints_at_the_keyboard() {
        let bob = testkit::saved_as(BOB, "Bob", true, "192.168.1.30:7420");
        let (mut app, _) = add_friend(Receive::Off, vec![bob]);
        let new = testkit::card(BOB, "192.168.1.44:7420");
        testkit::paste(&mut app, &new, PasteVia::Bracketed);
        later(&mut app);
        testkit::press(&mut app, KeyCode::Char('u'));
        let code = app.update_code_for_tests().expect("a code").to_owned();
        // A letter of another alphabet: the keyboard hint, and the same code
        // and what was typed stay; nothing is saved.
        let mut cmds = type_into(&mut app, &testkit::on_persian_keyboard("x2"));
        cmds.extend(testkit::press(&mut app, KeyCode::Enter));
        assert!(stores(&cmds).is_empty(), "{cmds:?}");
        let update = adding(&app).update.clone().expect("still asked");
        let typed = format!("{}2", testkit::on_persian_keyboard("x"));
        assert!(update.keyboard && !update.wrong);
        assert_eq!(
            (update.code.as_str(), update.typed.as_str()),
            (code.as_str(), typed.as_str())
        );
        // The code with Persian digits: the new routes are saved.
        erase(&mut app, 2);
        let mut cmds = type_into(
            &mut app,
            &testkit::digits_from(&code.to_lowercase(), testkit::PERSIAN_ZERO),
        );
        cmds.extend(testkit::press(&mut app, KeyCode::Enter));
        let friend = bridge::parse_card_or_invite(&new).expect("Bob's card");
        assert_eq!(stores(&cmds), [&StoreJob::UpdateAddresses(friend)]);
    }

    #[test]
    fn an_address_typed_with_persian_digits_is_kept_with_0_to_9() {
        let alice = testkit::saved_as(ALICE, "Alice", false, "");
        let mut app = testkit::home_app(
            (80, 24),
            Receive::Off,
            vec![alice.clone()],
            Conversations::new(),
        );
        testkit::press(&mut app, KeyCode::Char('e'));
        testkit::press(&mut app, KeyCode::Char('e'));
        let address = "192.168.1.44:7420";
        let typed = Some(PageEdit::Address {
            text: address.into(),
            bad: false,
        });
        type_into(
            &mut app,
            &testkit::digits_from(address, testkit::PERSIAN_ZERO),
        );
        assert_eq!(page(&app).edit, typed);
        // Pasted in Arabic-Indic digits, the same.
        erase(&mut app, address.len());
        testkit::paste(
            &mut app,
            &testkit::digits_from(address, testkit::ARABIC_INDIC_ZERO),
            PasteVia::Bracketed,
        );
        assert_eq!(page(&app).edit, typed);
        later(&mut app);
        let cmds = testkit::press(&mut app, KeyCode::Enter);
        assert_eq!(
            stores(&cmds),
            [&StoreJob::SetFriendAddress {
                pub_hex: alice.pub_hex.clone(),
                address: address.into()
            }]
        );
        answer(
            &mut app,
            saved(FriendChange::Address, &alice.pub_hex, Ok(())),
        );
        assert_eq!(
            app.friend(&alice.pub_hex).map(|f| f.lan_dial.as_str()),
            Some(address)
        );
    }

    #[test]
    fn a_pasted_code_and_its_enter_answer_nothing() {
        let mut app = verifying(Vec::new());
        let bob = testkit::me(BOB);
        let mut cmds = testkit::paste(&mut app, &bob.fingerprint, PasteVia::Bracketed);
        cmds.extend(testkit::send(&mut app, Msg::Key(Key::PastedEnter)));
        cmds.extend(testkit::press(&mut app, KeyCode::Enter));
        testkit::tick(&mut app, Duration::from_millis(299));
        cmds.extend(testkit::press(&mut app, KeyCode::Enter));
        assert_eq!(
            (vf(&app).entry.code.as_str(), &vf(&app).step),
            (code_of(BOB).as_str(), &VerifyStep::Comparing(None))
        );
        later(&mut app);
        testkit::press(&mut app, KeyCode::Enter);
        assert!(matches!(vf(&app).step, VerifyStep::Matched { .. }));
        // The confirmation code pasted, as keystrokes, with its line break.
        let code = app.verify_code_for_tests().expect("a code").to_owned();
        cmds.extend(testkit::paste(&mut app, &code, PasteVia::Keystrokes));
        cmds.extend(testkit::send(&mut app, Msg::Key(Key::PastedEnter)));
        cmds.extend(testkit::press(&mut app, KeyCode::Enter));
        assert!(stores(&cmds).is_empty(), "{cmds:?}");
        later(&mut app);
        let cmds = testkit::press(&mut app, KeyCode::Enter);
        assert_eq!(stores(&cmds).len(), 1, "{cmds:?}");
    }

    #[test]
    fn esc_on_vf_saves_nothing() {
        let code = code_of(BOB);
        for step in 0..4 {
            let mut app = verifying(Vec::new());
            let mut cmds = match step {
                0 => Vec::new(),
                1 => {
                    let mut cmds = type_into(&mut app, "zzzz");
                    cmds.extend(testkit::press(&mut app, KeyCode::Enter));
                    cmds
                }
                2 => {
                    let mut cmds = type_into(&mut app, &code);
                    cmds.extend(testkit::press(&mut app, KeyCode::Enter));
                    let confirm = app.verify_code_for_tests().expect("a code").to_owned();
                    cmds.extend(type_into(&mut app, &confirm));
                    cmds
                }
                _ => {
                    let mut cmds = testkit::press(&mut app, KeyCode::Tab);
                    let confirm = app.verify_code_for_tests().expect("a code").to_owned();
                    cmds.extend(type_into(&mut app, &confirm));
                    cmds
                }
            };
            cmds.extend(testkit::press(&mut app, KeyCode::Esc));
            assert!(stores(&cmds).is_empty(), "step {step}: {cmds:?}");
            // Back on AF-2 as it was.
            assert!(adding(&app).naming && adding(&app).name == "Bob", "{step}");
        }
        // A saved friend: back where VF was opened, Home or their page.
        let alice = testkit::saved_as(ALICE, "Alice", false, "");
        let mut app = testkit::home_app(
            (80, 24),
            Receive::Off,
            vec![alice.clone()],
            Conversations::new(),
        );
        testkit::press(&mut app, KeyCode::Char('v'));
        testkit::ctrl(&mut app, 'o');
        type_into(&mut app, &code_of(ALICE));
        testkit::press(&mut app, KeyCode::Enter);
        assert!(stores(&testkit::press(&mut app, KeyCode::Esc)).is_empty());
        assert_eq!(app.screen(), &Screen::Home);
        testkit::press(&mut app, KeyCode::Char('e'));
        testkit::press(&mut app, KeyCode::Char('v'));
        assert!(matches!(app.screen(), Screen::Verify(_)));
        testkit::press(&mut app, KeyCode::Esc);
        assert_eq!(page(&app).pub_hex, alice.pub_hex);
    }

    #[test]
    fn no_frame_before_the_match_shows_bobs_code() {
        let fingerprint = testkit::me(BOB).fingerprint;
        // The frames at both sizes: Bob's code nowhere, and of its groups
        // only those the user typed.
        let check = |app: &App, typed: &str| {
            for (cols, rows) in [(80, 24), (60, 16)] {
                let text = testkit::render(app, cols, rows).join("\n");
                assert!(!text.contains(&fingerprint), "{fingerprint}:\n{text}");
                for group in fingerprint
                    .split('-')
                    .filter(|group| !typed.contains(*group))
                {
                    assert!(!text.contains(group), "{group}:\n{text}");
                }
            }
        };
        let mut app = verifying(Vec::new());
        check(&app, "");
        let code = code_of(BOB);
        for typed in [
            "zzzz".to_owned(),
            "zzzzyyyyxx".to_owned(),
            code[..4].to_owned(),
            first_letter_flipped(&code),
        ] {
            type_into(&mut app, &typed);
            check(&app, &typed);
            testkit::press(&mut app, KeyCode::Enter);
            check(&app, &typed);
            erase(&mut app, typed.len());
        }
        // Later shows no code either.
        testkit::press(&mut app, KeyCode::Tab);
        check(&app, "");
    }

    // ── VF's security words ────────────────────────────────────────────────

    /// The security words of seed `seed`, as their owner reads them out.
    fn words_of(seed: u8) -> Vec<String> {
        testkit::me(seed).words.to_vec()
    }

    /// Ctrl+O twice: back in the words field, emptied.
    fn empty_words(app: &mut App) {
        testkit::ctrl(app, 'o');
        testkit::ctrl(app, 'o');
        assert_eq!(vf(app).entry, Entry::default());
    }

    #[test]
    fn bob_is_saved_verified_only_after_his_words_and_the_code() {
        let mut app = verifying_words(Vec::new());
        let bob = words_of(BOB);
        testkit::press(&mut app, KeyCode::Enter);
        assert_eq!(vf(&app).step, VerifyStep::Comparing(None), "nothing typed");
        // Three letters suggest the one word they start; Tab picks it.
        type_into(&mut app, &bob[0][..3]);
        let view = app.verify_view().expect("VF");
        assert_eq!(view.suggestions, [bob[0].as_str()]);
        assert!(view.chips.is_empty());
        testkit::press(&mut app, KeyCode::Tab);
        assert_eq!(vf(&app).step, VerifyStep::Comparing(None), "Tab picked");
        // A whole word in capitals, then Space; a plural, then a comma.
        type_into(&mut app, &format!("{} ", bob[1].to_uppercase()));
        type_into(&mut app, &format!("{}s,", bob[2]));
        let chips: Vec<String> = vf(&app)
            .entry
            .chips
            .iter()
            .map(|&i| bridge::list_word(i).to_owned())
            .collect();
        assert_eq!(chips, bob[..3]);
        assert_eq!(vf(&app).entry.current, "");
        // The rest as he reads them: the last word stays typed.
        type_into(&mut app, &bob[3..].join(" "));
        assert_eq!(vf(&app).entry.chips.len(), 9);
        assert_eq!(vf(&app).entry.current, bob[9]);
        assert_eq!(vf(&app).entry.text(), bob.join(" "));
        let view = app.verify_view().expect("VF");
        assert_eq!((view.theirs, view.theirs_words), (None, None));
        // Enter: they match. His words and code show, and a confirmation
        // code is asked for.
        testkit::press(&mut app, KeyCode::Enter);
        assert!(matches!(vf(&app).step, VerifyStep::Matched { .. }));
        let view = app.verify_view().expect("VF");
        assert_eq!(view.theirs_words, Some(bob.clone()));
        assert_eq!(
            view.theirs,
            Some(
                testkit::me(BOB)
                    .fingerprint
                    .split('-')
                    .map(str::to_owned)
                    .collect()
            )
        );
        // The code: Bob saved with the pin, his words as the core checks
        // them again.
        let cmds = confirm(&mut app);
        let friend = bridge::parse_card_or_invite(&testkit::card(BOB, "192.168.1.30:7420"))
            .expect("Bob's card");
        assert_eq!(
            stores(&cmds),
            [&StoreJob::SaveFriend {
                friend,
                name: "Bob".into(),
                verify: Verify::Pinned {
                    typed_fp: bob.join(" ")
                },
            }]
        );
    }

    #[test]
    fn typed_words_get_their_status_and_never_one_from_bobs() {
        let mut app = verifying_words(Vec::new());
        let bob = words_of(BOB);
        let invalid = |problem| VerifyStep::Comparing(Some(CodeProblem::Words(problem)));
        // A word that is not a Raven word stays typed, and says so at once.
        type_into(&mut app, "zzz ");
        assert_eq!(vf(&app).entry.current, "zzz");
        assert_eq!(
            vf(&app).step,
            invalid(bridge::ParseError::Unknown { position: 1 })
        );
        // Typing on clears it; a letter that starts several words is not
        // picked by Tab or Space.
        erase(&mut app, 3);
        assert_eq!(vf(&app).step, VerifyStep::Comparing(None));
        type_into(&mut app, "s");
        assert!(app.verify_view().expect("VF").suggestions.len() > 1);
        testkit::press(&mut app, KeyCode::Tab);
        type_into(&mut app, " ");
        assert_eq!(
            (vf(&app).entry.current.as_str(), &vf(&app).step),
            ("s", &invalid(bridge::ParseError::Ambiguous { position: 1 }))
        );
        // Letters of another alphabet are not kept: the keyboard hint, until
        // an English letter comes.
        erase(&mut app, 1);
        type_into(&mut app, &testkit::on_persian_keyboard("tu"));
        assert_eq!(vf(&app).entry, Entry::default());
        assert_eq!(
            vf(&app).step,
            VerifyStep::Comparing(Some(CodeProblem::Keyboard))
        );
        testkit::press(&mut app, KeyCode::Enter);
        assert_eq!(
            vf(&app).step,
            VerifyStep::Comparing(Some(CodeProblem::Keyboard))
        );
        type_into(&mut app, "t");
        assert_eq!(vf(&app).step, VerifyStep::Comparing(None));
        // Whole entries: what Enter says depends on the words typed alone.
        // 3 words are not the old code here: too few words, no mismatch.
        let swapped = format!("{} {} {}", bob[1], bob[0], bob[2..].join(" "));
        let eleven = format!("{} {}", bob.join(" "), bob[0]);
        for (typed, problem) in [
            (
                bob[..3].join(" "),
                bridge::ParseError::WrongCount { count: 3 },
            ),
            (
                bob[..9].join(" "),
                bridge::ParseError::WrongCount { count: 9 },
            ),
            (eleven, bridge::ParseError::WrongCount { count: 11 }),
            (swapped, bridge::ParseError::BadCheck),
            (format!("{} zzzz", bob[..9].join(" ")), {
                bridge::ParseError::Unknown { position: 10 }
            }),
        ] {
            empty_words(&mut app);
            type_into(&mut app, &typed);
            testkit::press(&mut app, KeyCode::Enter);
            assert_eq!(vf(&app).step, invalid(problem), "{typed}");
            assert_eq!(vf(&app).mismatches, 0, "{typed}");
        }
        // Eve's words are real words, but not Bob's: a mismatch, counted.
        empty_words(&mut app);
        type_into(&mut app, &words_of(EVE).join(" "));
        let cmds = testkit::press(&mut app, KeyCode::Enter);
        assert!(stores(&cmds).is_empty());
        assert_eq!(
            vf(&app).step,
            VerifyStep::Comparing(Some(CodeProblem::Mismatch))
        );
        assert_eq!(vf(&app).mismatches, 1);
        assert_eq!(app.verify_view().expect("VF").theirs_words, None);
    }

    #[test]
    fn three_entries_that_are_not_bobs_stop_the_check() {
        let mut app = verifying_words(Vec::new());
        let eve = words_of(EVE).join(" ");
        // Two of Eve's sets, and a wrong old code: it counts too.
        for _ in 0..2 {
            empty_words(&mut app);
            type_into(&mut app, &eve);
            testkit::press(&mut app, KeyCode::Enter);
        }
        testkit::ctrl(&mut app, 'o');
        type_into(&mut app, "zzzzyyyyxxxx");
        testkit::press(&mut app, KeyCode::Enter);
        assert!(vf(&app).stopped());
        let text = testkit::screen_text(&testkit::render(&app, 80, 24));
        assert!(text.contains("That doesn't match."), "{text}");
        assert!(
            text.contains(
                "Stop here. Check with Bob another way (in person), or save Bob as not verified."
            ),
            "{text}"
        );
        // Bob's own words now: Enter checks no more.
        testkit::ctrl(&mut app, 'o');
        type_into(&mut app, &words_of(BOB).join(" "));
        let cmds = testkit::press(&mut app, KeyCode::Enter);
        assert!(stores(&cmds).is_empty());
        assert!(matches!(vf(&app).step, VerifyStep::Comparing(_)));
        assert_eq!(app.verify_view().expect("VF").theirs_words, None);
        // Only Later and Esc are left: Tab is Later, and back.
        testkit::press(&mut app, KeyCode::Tab);
        assert!(matches!(vf(&app).step, VerifyStep::Later(_)));
        testkit::press(&mut app, KeyCode::Tab);
        assert!(vf(&app).stopped());
        testkit::press(&mut app, KeyCode::Enter);
        assert!(matches!(vf(&app).step, VerifyStep::Comparing(_)));
        // A saved friend: the same, with Esc alone.
        let alice = testkit::saved_as(ALICE, "Alice", false, "");
        let mut app = testkit::home_app(
            (80, 24),
            Receive::Off,
            vec![alice.clone()],
            Conversations::new(),
        );
        testkit::press(&mut app, KeyCode::Char('v'));
        for _ in 0..3 {
            empty_words(&mut app);
            type_into(&mut app, &eve);
            testkit::press(&mut app, KeyCode::Enter);
        }
        empty_words(&mut app);
        type_into(&mut app, &words_of(ALICE).join(" "));
        let cmds = testkit::press(&mut app, KeyCode::Enter);
        assert!(stores(&cmds).is_empty());
        let rows = testkit::render(&app, 80, 24);
        let text = testkit::screen_text(&rows);
        assert!(
            text.contains("Stop here. Check with Alice another way (in person).")
                && text.contains("[Esc] Cancel")
                && !text.contains("[Enter]")
                && !text.contains("[Tab]"),
            "{text}"
        );
        testkit::press(&mut app, KeyCode::Esc);
        assert_eq!(app.screen(), &Screen::Home);
    }

    #[test]
    fn pasted_words_are_text_and_their_enter_answers_nothing() {
        let mut app = verifying_words(Vec::new());
        let bob = words_of(BOB);
        // Numbered, as a chat message might hold them: the numbers go.
        let numbered: Vec<String> = bob
            .iter()
            .enumerate()
            .map(|(i, word)| format!("{}. {word}", i + 1))
            .collect();
        let mut cmds = testkit::paste(&mut app, &numbered.join("\n"), PasteVia::Bracketed);
        cmds.extend(testkit::send(&mut app, Msg::Key(Key::PastedEnter)));
        cmds.extend(testkit::press(&mut app, KeyCode::Enter));
        testkit::tick(&mut app, Duration::from_millis(299));
        cmds.extend(testkit::press(&mut app, KeyCode::Enter));
        assert!(stores(&cmds).is_empty());
        assert_eq!(vf(&app).step, VerifyStep::Comparing(None));
        assert_eq!(vf(&app).entry.text(), bob.join(" "));
        later(&mut app);
        testkit::press(&mut app, KeyCode::Enter);
        assert!(matches!(vf(&app).step, VerifyStep::Matched { .. }));
        // A pasted word that is not a Raven word: the words after it stay
        // apart, and the paste says which one.
        let mut app = verifying_words(Vec::new());
        let text = format!("{} zzzz {}", bob[0], bob[2..].join(" "));
        testkit::paste(&mut app, &text, PasteVia::Keystrokes);
        assert_eq!(vf(&app).entry.chips.len(), 1);
        assert_eq!(vf(&app).entry.text(), text);
        assert_eq!(
            vf(&app).step,
            VerifyStep::Comparing(Some(CodeProblem::Words(bridge::ParseError::Unknown {
                position: 2
            })))
        );
        later(&mut app);
        testkit::press(&mut app, KeyCode::Enter);
        let said = testkit::screen_text(&testkit::render(&app, 80, 24));
        assert!(
            said.contains("'zzzz' isn't one of Raven's words."),
            "{said}"
        );
    }

    #[test]
    fn ctrl_o_switches_between_the_words_and_the_old_code() {
        let mut app = verifying_words(Vec::new());
        type_into(&mut app, "zzz ");
        testkit::ctrl(&mut app, 'o');
        // The code's field, empty, and nothing said.
        assert_eq!(
            vf(&app).entry,
            Entry {
                mode: EntryMode::Code,
                ..Entry::default()
            }
        );
        assert_eq!(vf(&app).step, VerifyStep::Comparing(None));
        // In it, letters are the code's, and Tab is Later.
        type_into(&mut app, "M0");
        assert_eq!(vf(&app).entry.code, "M0");
        let text = testkit::screen_text(&testkit::render(&app, 80, 24));
        assert!(text.contains("Type Bob's code as they read it:"), "{text}");
        // Back to the words: emptied. The count of entries that were not
        // his stays.
        testkit::press(&mut app, KeyCode::Enter);
        assert_eq!(vf(&app).mismatches, 1);
        testkit::ctrl(&mut app, 'o');
        assert_eq!(vf(&app).entry, Entry::default());
        assert_eq!(vf(&app).mismatches, 1);
        // A friend verified already: both lists, or with Ctrl+O both codes.
        let bob = testkit::saved_as(BOB, "Bob", true, "192.168.1.30:7420");
        let mut app = testkit::home_app((80, 24), Receive::Off, vec![bob], Conversations::new());
        testkit::press(&mut app, KeyCode::Char('v'));
        let view = app.verify_view().expect("VF");
        assert_eq!(view.theirs_words, Some(words_of(BOB)));
        assert_eq!(vf(&app).entry.mode, EntryMode::Words);
        testkit::ctrl(&mut app, 'o');
        assert_eq!(vf(&app).entry.mode, EntryMode::Code);
        assert_eq!(vf(&app).step, VerifyStep::AlreadyVerified);
    }

    /// The frames of `bob` and `eve` (two friends of the same name, with
    /// other keys) at 80x24 and 60x16, after the same keys: the same (but for
    /// Later's random confirmation code), so no frame depends on the
    /// friend's key. Neither shows Bob's code or words.
    fn assert_blind(bob: &App, eve: &App, step: &str) {
        let frame = |app: &App, cols, rows| {
            let code = app.verify_code_for_tests().unwrap_or("K7Q3M").to_owned();
            testkit::render(app, cols, rows)
                .into_iter()
                .map(|row| row.replace(&code, "K7Q3M"))
                .collect::<Vec<_>>()
        };
        for (cols, rows) in [(80, 24), (60, 16)] {
            assert_eq!(
                frame(bob, cols, rows),
                frame(eve, cols, rows),
                "{step} at {cols}x{rows}"
            );
        }
        assert_no_code(bob);
    }

    #[test]
    fn no_frame_before_the_match_depends_on_bobs_key() {
        // Bob, and Eve also named 'Bob': the same keys pressed on both.
        let mut bob = verifying_words(Vec::new());
        let (mut eve, _) = add_friend(Receive::Off, Vec::new());
        testkit::paste(
            &mut eve,
            &testkit::card(EVE, "192.168.1.30:7420"),
            PasteVia::Bracketed,
        );
        later(&mut eve);
        testkit::press(&mut eve, KeyCode::Enter);
        type_into(&mut eve, "Bob");
        testkit::press(&mut eve, KeyCode::Enter);
        assert!(matches!(eve.screen(), Screen::Verify(_)));
        assert_blind(&bob, &eve, "opened");
        // Carol's words are neither's: every check fails alike.
        let words = words_of(BOB);
        let carol = words_of(0xC0);
        let swapped = format!("{} {} {}", carol[1], carol[0], carol[2..].join(" "));
        // What each step does to an app.
        type Keys = Box<dyn Fn(&mut App)>;
        let steps: Vec<(&str, Keys)> = vec![
            ("one letter", Box::new(|app| drop(type_into(app, "t")))),
            ("two letters", Box::new(|app| drop(type_into(app, "u")))),
            (
                "Tab",
                Box::new(|app| drop(testkit::press(app, KeyCode::Tab))),
            ),
            ("Bob's first 3 letters", {
                let start = words[0][..3].to_owned();
                Box::new(move |app| drop(type_into(app, &start)))
            }),
            ("Space", Box::new(|app| drop(type_into(app, " ")))),
            ("unknown", Box::new(|app| drop(type_into(app, "zzz ")))),
            (
                "Enter",
                Box::new(|app| drop(testkit::press(app, KeyCode::Enter))),
            ),
            ("erased", Box::new(|app| erase(app, 30))),
            (
                "another alphabet",
                Box::new(|app| drop(type_into(app, &testkit::on_persian_keyboard("q")))),
            ),
            (
                "Enter",
                Box::new(|app| drop(testkit::press(app, KeyCode::Enter))),
            ),
            ("3 words", {
                let text = carol[..3].join(" ");
                Box::new(move |app| {
                    type_into(app, &text);
                    testkit::press(app, KeyCode::Enter);
                })
            }),
            ("swapped", {
                let text = swapped.clone();
                Box::new(move |app| {
                    empty_words(app);
                    type_into(app, &text);
                    testkit::press(app, KeyCode::Enter);
                })
            }),
            ("pasted", {
                let text = carol.join(" ");
                Box::new(move |app| {
                    empty_words(app);
                    testkit::paste(app, &text, PasteVia::Bracketed);
                    later(app);
                })
            }),
            (
                "mismatch 1",
                Box::new(|app| drop(testkit::press(app, KeyCode::Enter))),
            ),
            (
                "mismatch 2",
                Box::new(|app| drop(testkit::press(app, KeyCode::Enter))),
            ),
            (
                "mismatch 3",
                Box::new(|app| drop(testkit::press(app, KeyCode::Enter))),
            ),
            ("stopped, typing", {
                let text = carol[..2].join(" ");
                Box::new(move |app| {
                    empty_words(app);
                    type_into(app, &text);
                })
            }),
            (
                "Later",
                Box::new(|app| drop(testkit::press(app, KeyCode::Tab))),
            ),
            (
                "back",
                Box::new(|app| drop(testkit::press(app, KeyCode::Tab))),
            ),
            (
                "the code field, a group begun",
                Box::new(|app| {
                    testkit::ctrl(app, 'o');
                    type_into(app, "zz");
                }),
            ),
        ];
        for (step, keys) in steps {
            keys(&mut bob);
            keys(&mut eve);
            assert_blind(&bob, &eve, step);
        }
        assert!(vf(&bob).stopped() && vf(&eve).stopped());
    }

    #[test]
    fn suggestions_are_the_same_whichever_friend_is_verified() {
        let mut bob = verifying_words(Vec::new());
        let alice = testkit::saved_as(ALICE, "Alice", false, "");
        let mut alices =
            testkit::home_app((80, 24), Receive::Off, vec![alice], Conversations::new());
        testkit::press(&mut alices, KeyCode::Char('v'));
        let letters: Vec<char> = ('a'..='z').collect();
        let mut tokens: Vec<String> = letters.iter().map(char::to_string).collect();
        for a in &letters {
            tokens.extend(letters.iter().map(|b| format!("{a}{b}")));
        }
        for i in 0..=u8::MAX {
            let word = bridge::list_word(i);
            tokens.extend([word[..3].to_owned(), word.to_owned(), format!("{word}s")]);
        }
        for token in tokens {
            let mut views = Vec::new();
            for app in [&mut bob, &mut alices] {
                let Screen::Verify(vf) = &mut app.screen else {
                    panic!("not on VF");
                };
                vf.entry.current = token.clone();
                views.push(app.verify_view().expect("VF").suggestions);
            }
            // The whole list's, in list order: whoever is verified.
            let want: Vec<&str> = bridge::word_suggestions(&token)
                .into_iter()
                .map(bridge::list_word)
                .collect();
            let order: Vec<u8> = bridge::word_suggestions(&token);
            assert!(order.windows(2).all(|w| w[0] < w[1]), "{token}");
            assert_eq!(views[0], want, "{token}");
            assert_eq!(views[1], want, "{token}");
        }
    }

    #[test]
    fn left_and_right_spell_another_group_and_letters_are_text() {
        let mut app = verifying(Vec::new());
        let groups = code_of(7).len().div_ceil(4);
        assert_eq!(vf(&app).helper, 0);
        testkit::press(&mut app, KeyCode::Left);
        assert_eq!(vf(&app).helper, 0);
        for _ in 0..groups + 2 {
            testkit::press(&mut app, KeyCode::Right);
        }
        assert_eq!(vf(&app).helper, groups - 1);
        testkit::press(&mut app, KeyCode::Left);
        assert_eq!(vf(&app).helper, groups - 2);
        // q and l are letters of a code, never Quit or Later; ? is help.
        type_into(&mut app, "ql");
        assert!(app.overlays().is_empty());
        assert_eq!(vf(&app).entry.code, "ql");
        testkit::press(&mut app, KeyCode::Char('?'));
        assert!(matches!(app.overlays(), [Overlay::Help { .. }]));
        testkit::press(&mut app, KeyCode::Esc);
        assert!(app.overlays().is_empty() && matches!(app.screen(), Screen::Verify(_)));
        // Ctrl+C is QUIT, as everywhere.
        testkit::ctrl(&mut app, 'c');
        assert_eq!(app.overlays(), [Overlay::Quit]);
    }

    #[test]
    fn a_saved_friend_is_verified_from_home() {
        let bob = testkit::saved_as(BOB, "Bob", true, "192.168.1.30:7420");
        let alice = testkit::saved_as(ALICE, "Alice", false, "");
        let mut app = testkit::home_app(
            (80, 24),
            Receive::Off,
            vec![bob.clone(), alice.clone()],
            Conversations::new(),
        );
        // Bob, verified already: both codes; Tab and letters do nothing,
        // and Enter checks again (P6.31): his code is hidden again until
        // it matches.
        testkit::press(&mut app, KeyCode::Char('v'));
        assert_eq!(vf(&app).step, VerifyStep::AlreadyVerified);
        assert!(app.verify_view().expect("VF").theirs.is_some());
        let mut cmds = testkit::press(&mut app, KeyCode::Tab);
        cmds.extend(type_into(&mut app, "x"));
        assert!(stores(&cmds).is_empty());
        assert_eq!(vf(&app).step, VerifyStep::AlreadyVerified);
        assert!(stores(&testkit::press(&mut app, KeyCode::Enter)).is_empty());
        assert_eq!(vf(&app).step, VerifyStep::Comparing(None));
        assert!(app.verify_view().expect("VF").theirs.is_none());
        testkit::press(&mut app, KeyCode::Esc);
        // Alice: her code, then the confirmation code. No Later: she is
        // saved already.
        testkit::press(&mut app, KeyCode::Down);
        testkit::press(&mut app, KeyCode::Char('V'));
        testkit::ctrl(&mut app, 'o');
        testkit::press(&mut app, KeyCode::Tab);
        assert_eq!(vf(&app).step, VerifyStep::Comparing(None));
        type_into(&mut app, &code_of(ALICE));
        testkit::press(&mut app, KeyCode::Enter);
        let cmds = confirm(&mut app);
        assert_eq!(
            stores(&cmds),
            [&StoreJob::VerifyExisting {
                pub_hex: alice.pub_hex.clone(),
                typed_fp: code_of(ALICE),
            }]
        );
        // Verified: her page, with her code.
        answer(
            &mut app,
            saved(FriendChange::Verify, &alice.pub_hex, Ok(())),
        );
        assert_eq!(page(&app).pub_hex, alice.pub_hex);
        assert!(app.friend(&alice.pub_hex).is_some_and(|f| f.pinned));
        // A refusal says why, in plain words, with its details on D.
        let mut app = testkit::home_app(
            (80, 24),
            Receive::Off,
            vec![alice.clone()],
            Conversations::new(),
        );
        testkit::press(&mut app, KeyCode::Char('v'));
        testkit::ctrl(&mut app, 'o');
        type_into(&mut app, &code_of(ALICE));
        testkit::press(&mut app, KeyCode::Enter);
        confirm(&mut app);
        answer(
            &mut app,
            saved(
                FriendChange::Verify,
                &alice.pub_hex,
                Err("KEY_CHANGE_REFUSED_WITHOUT_REPIN".into()),
            ),
        );
        let VerifyStep::Failed(failure) = &vf(&app).step else {
            panic!("{:?}", vf(&app).step);
        };
        assert_eq!(
            failure.plain.headline,
            "You verified this person with a different key, so nothing was saved."
        );
        testkit::press(&mut app, KeyCode::Char('d'));
        assert!(matches!(&vf(&app).step, VerifyStep::Failed(f) if f.details));
    }

    #[test]
    fn the_friend_page_renames_edits_removes_and_unblocks() {
        let carol = testkit::saved_as(0xC0, "Carol", false, "");
        let alice = ContactView {
            blocked: true,
            ..testkit::saved_as(ALICE, "Alice", false, "")
        };
        let mut app = testkit::home_app(
            (80, 24),
            Receive::Off,
            vec![alice.clone(), carol.clone()],
            Conversations::new(),
        );
        let me = alice.pub_hex.clone();
        testkit::press(&mut app, KeyCode::Char('e'));
        assert_eq!(page(&app).pub_hex, me);
        // A name Carol has is refused; another is saved.
        testkit::press(&mut app, KeyCode::Char('r'));
        let mut cmds = type_into(&mut app, "carol");
        cmds.extend(testkit::press(&mut app, KeyCode::Enter));
        assert!(stores(&cmds).is_empty(), "{cmds:?}");
        assert!(matches!(
            &page(&app).edit,
            Some(PageEdit::Rename { problem: Some(NameProblem::Taken(other)), .. })
                if *other == carol.pub_hex
        ));
        erase(&mut app, 5);
        type_into(&mut app, "Ally");
        let cmds = testkit::press(&mut app, KeyCode::Enter);
        assert_eq!(
            stores(&cmds),
            [&StoreJob::RenameFriend {
                pub_hex: me.clone(),
                name: "Ally".into()
            }]
        );
        assert!(page(&app).saving && app.jobs_in_flight().holds_classic());
        // While it saves, the keys wait.
        assert!(stores(&testkit::press(&mut app, KeyCode::Char('u'))).is_empty());
        answer(&mut app, saved(FriendChange::Rename, &me, Ok(())));
        assert!(!page(&app).saving && page(&app).edit.is_none());
        assert_eq!(app.shown_name(&me), "Ally");
        assert!(app
            .toasts_for_tests()
            .contains(&"Raven saved the new name."));
        // An address is checked first.
        testkit::press(&mut app, KeyCode::Char('e'));
        let mut cmds = type_into(&mut app, "192.168.1.44");
        cmds.extend(testkit::press(&mut app, KeyCode::Enter));
        assert!(stores(&cmds).is_empty());
        assert!(matches!(
            page(&app).edit,
            Some(PageEdit::Address { bad: true, .. })
        ));
        type_into(&mut app, ":7420");
        let cmds = testkit::press(&mut app, KeyCode::Enter);
        assert_eq!(
            stores(&cmds),
            [&StoreJob::SetFriendAddress {
                pub_hex: me.clone(),
                address: "192.168.1.44:7420".into()
            }]
        );
        answer(&mut app, saved(FriendChange::Address, &me, Ok(())));
        assert_eq!(
            app.friend(&me).map(|f| f.lan_dial.as_str()),
            Some("192.168.1.44:7420")
        );
        // A refusal says why on the page, with D for its details.
        testkit::press(&mut app, KeyCode::Char('e'));
        type_into(&mut app, "192.168.1.45:7420");
        testkit::press(&mut app, KeyCode::Enter);
        answer(
            &mut app,
            saved(
                FriendChange::Address,
                &me,
                Err("contacts.json: expected value".into()),
            ),
        );
        let failure = page(&app).failure.clone().expect("a failure");
        assert_eq!(failure.plain.headline, "Your friends list can't be read.");
        testkit::press(&mut app, KeyCode::Char('d'));
        assert!(page(&app).failure.as_ref().is_some_and(|f| f.details));
        // U unblocks, only while blocked.
        let cmds = testkit::press(&mut app, KeyCode::Char('u'));
        assert_eq!(
            stores(&cmds),
            [&StoreJob::UnblockFriend {
                pub_hex: me.clone()
            }]
        );
        answer(&mut app, saved(FriendChange::Unblock, &me, Ok(())));
        assert!(app.friend(&me).is_some_and(|f| !f.blocked));
        assert!(stores(&testkit::press(&mut app, KeyCode::Char('u'))).is_empty());
        // X removes, only once 'remove' is typed.
        testkit::press(&mut app, KeyCode::Char('x'));
        let mut cmds = type_into(&mut app, "remov");
        cmds.extend(testkit::press(&mut app, KeyCode::Enter));
        assert!(stores(&cmds).is_empty());
        type_into(&mut app, "e");
        let cmds = testkit::press(&mut app, KeyCode::Enter);
        assert_eq!(
            stores(&cmds),
            [&StoreJob::RemoveFriend {
                pub_hex: me.clone()
            }]
        );
        answer(&mut app, saved(FriendChange::Remove, &me, Ok(())));
        assert_eq!(app.screen(), &Screen::Home);
        assert!(app.friend(&me).is_none());
        assert!(app
            .toasts_for_tests()
            .contains(&"Removed Ally. Your messages with them stay."));
    }

    #[test]
    fn a_save_that_failed_or_panicked_says_so_and_saves_nothing() {
        // The name was taken meanwhile: plain words on VF, and Esc back to
        // AF-2 to pick another.
        let mut app = verifying(Vec::new());
        testkit::press(&mut app, KeyCode::Tab);
        confirm(&mut app);
        answer(
            &mut app,
            saved(
                FriendChange::Add,
                &testkit::me(BOB).pub_hex,
                Err(
                    "petname \"Bob\" is already used by another contact (fp=Ab3d-Ef9h-Kq3x) \
                     — choose a distinct petname"
                        .into(),
                ),
            ),
        );
        let VerifyStep::Failed(failure) = &vf(&app).step else {
            panic!("{:?}", vf(&app).step);
        };
        assert_eq!(
            failure.plain.headline,
            "You already have a friend called Bob."
        );
        assert!(!failure.plain.technical.contains("Ab3d-Ef9h-Kq3x"));
        assert!(app.friend(&testkit::me(BOB).pub_hex).is_none());
        testkit::press(&mut app, KeyCode::Esc);
        assert!(adding(&app).naming);
        // A job that panicked: the same, and the toast.
        let mut app = verifying(Vec::new());
        testkit::press(&mut app, KeyCode::Tab);
        confirm(&mut app);
        answer(
            &mut app,
            JobResult::Failed {
                job: JobName::ChangeFriend(FriendChange::Add),
                plain: errors::explain_panic("boom", ""),
            },
        );
        assert!(matches!(vf(&app).step, VerifyStep::Failed(_)));
        assert!(!app.jobs_in_flight().holds_classic());
    }

    #[test]
    fn a_friend_added_starts_the_background_program_if_none_runs() {
        let (mut app, cmds) = add_friend(Receive::On, Vec::new());
        assert!(starts(&cmds));
        // That start failed: none runs.
        answer(
            &mut app,
            JobResult::Ensured(Ensured {
                result: Err("raven-node exited at once".into()),
                after: not_running(),
                started_by_app: None,
                captured: String::new(),
                ring: 0..0,
            }),
        );
        to_vf(&mut app);
        testkit::press(&mut app, KeyCode::Tab);
        confirm(&mut app);
        let cmds = answer(
            &mut app,
            saved(FriendChange::Add, &testkit::me(BOB).pub_hex, Ok(())),
        );
        assert!(matches!(app.screen(), Screen::Added(_)));
        assert!(starts(&cmds), "{cmds:?}");
        // Receiving off: nothing starts.
        let mut app = verifying(Vec::new());
        testkit::press(&mut app, KeyCode::Tab);
        confirm(&mut app);
        let cmds = answer(
            &mut app,
            saved(FriendChange::Add, &testkit::me(BOB).pub_hex, Ok(())),
        );
        assert!(!starts(&cmds), "{cmds:?}");
    }

    // ── shortcuts on a Persian keyboard (UXF.4) ─────────────────────────────

    /// The keys of `latin` pressed with a Persian keyboard layout on, and the
    /// commands they gave.
    fn on_persian(app: &mut App, latin: &str) -> Vec<Cmd> {
        type_into(app, &testkit::on_persian_keyboard(latin))
    }

    #[test]
    fn q_on_a_persian_keyboard_opens_quit_from_home() {
        // The Q key types DAD there.
        assert_eq!(testkit::on_persian_keyboard("q"), "\u{0636}");
        let mut app = app();
        assert!(on_persian(&mut app, "q").is_empty());
        assert_eq!(app.overlays(), [Overlay::Quit]);
        assert!(app.take_dirty());
        testkit::press(&mut app, KeyCode::Esc);
        assert!(app.overlays().is_empty());
        // The friend list's other keys, and Arabic 101's N.
        let mut app = with_friends();
        on_persian(&mut app, "j");
        assert_eq!(app.highlight(), 1);
        on_persian(&mut app, "k");
        assert_eq!(app.highlight(), 0);
        on_persian(&mut app, "q");
        assert_eq!(app.overlays(), [Overlay::Quit]);
        testkit::press(&mut app, KeyCode::Esc);
        type_into(&mut app, "\u{0649}");
        assert!(matches!(app.screen(), Screen::Network(_)));
        testkit::press(&mut app, KeyCode::Esc);
        on_persian(&mut app, "s");
        assert!(matches!(app.screen(), Screen::Settings(_)));
    }

    #[test]
    fn a_persian_letter_in_the_composer_is_text_not_a_shortcut() {
        let mut app = with_friends();
        testkit::press(&mut app, KeyCode::Enter);
        app.take_dirty();
        let typed = testkit::on_persian_keyboard("qjka");
        assert!(type_into(&mut app, &typed).is_empty());
        assert!(app.overlays().is_empty());
        assert_eq!(app.focus(), Focus::Composer);
        assert_eq!(app.composer().map(Composer::text), Some(typed.as_str()));
        assert!(app.take_dirty());
        // In the conversation the Q key is Quit again.
        testkit::press(&mut app, KeyCode::Tab);
        assert_eq!(app.focus(), Focus::Messages);
        on_persian(&mut app, "q");
        assert_eq!(app.overlays(), [Overlay::Quit]);
    }

    #[test]
    fn no_shortcut_while_a_code_field_has_the_keys() {
        let dad = testkit::on_persian_keyboard("q");
        // VF's field for Bob's code: a letter of another alphabet, never a
        // Q (or QUIT).
        let mut app = verifying(Vec::new());
        assert!(on_persian(&mut app, "q").is_empty());
        assert!(app.overlays().is_empty());
        assert_eq!(
            (vf(&app).entry.code.as_str(), &vf(&app).step),
            ("", &VerifyStep::Comparing(Some(CodeProblem::Keyboard)))
        );
        // The confirmation code after the match keeps the letter as typed.
        type_into(&mut app, &testkit::me(BOB).fingerprint);
        testkit::press(&mut app, KeyCode::Enter);
        on_persian(&mut app, "q");
        assert!(
            matches!(&vf(&app).step, VerifyStep::Matched { confirm, .. } if confirm.typed == dad),
            "{:?}",
            vf(&app).step
        );
        // Later's alike.
        let mut app = verifying(Vec::new());
        testkit::press(&mut app, KeyCode::Tab);
        on_persian(&mut app, "q");
        assert!(
            matches!(&vf(&app).step, VerifyStep::Later(field) if field.typed == dad),
            "{:?}",
            vf(&app).step
        );
        // AF-1 holding a saved friend's card: U opens [U]'s code, whose
        // field then keeps the letter.
        let bob = testkit::saved_as(BOB, "Bob", true, "192.168.1.30:7420");
        let (mut app, _) = add_friend(Receive::Off, vec![bob]);
        let new = testkit::card(BOB, "192.168.1.44:7420");
        testkit::paste(&mut app, &new, PasteVia::Bracketed);
        later(&mut app);
        on_persian(&mut app, "u");
        assert!(adding(&app).update.is_some());
        on_persian(&mut app, "q");
        assert_eq!(
            adding(&app).update.as_ref().map(|code| code.typed.as_str()),
            Some(dad.as_str())
        );
        assert!(app.overlays().is_empty());
    }

    #[test]
    fn name_paste_and_address_fields_keep_the_persian_letter() {
        let dad = testkit::on_persian_keyboard("q");
        // WZ-2's name.
        let mut app = testkit::wizard_app((80, 24));
        testkit::press(&mut app, KeyCode::Enter);
        on_persian(&mut app, "q");
        assert_eq!(app.name(), dad);
        assert!(app.overlays().is_empty());
        // AF-1's paste box before it parses, and the rest of a paste in the
        // share box; then AF-2's name.
        let (mut app, _) = add_friend(Receive::Off, Vec::new());
        on_persian(&mut app, "q");
        assert_eq!(adding(&app).text, dad);
        testkit::press(&mut app, KeyCode::Tab);
        assert_eq!(adding(&app).focus, AddFocus::Share);
        on_persian(&mut app, "l");
        assert_eq!(
            adding(&app).text,
            format!("{dad}{}", testkit::on_persian_keyboard("l"))
        );
        testkit::ctrl(&mut app, 'u');
        testkit::paste(
            &mut app,
            &testkit::card(BOB, "192.168.1.30:7420"),
            PasteVia::Bracketed,
        );
        later(&mut app);
        testkit::press(&mut app, KeyCode::Enter);
        assert!(adding(&app).naming);
        on_persian(&mut app, "q");
        assert_eq!(adding(&app).name, dad);
        // CI, opened with E; R, E and X open its fields, which keep the
        // letter.
        let alice = testkit::saved_as(ALICE, "Alice", false, "");
        let mut app = testkit::home_app((80, 24), Receive::Off, vec![alice], Conversations::new());
        on_persian(&mut app, "e");
        assert!(matches!(app.screen(), Screen::FriendPage(_)));
        on_persian(&mut app, "rq");
        assert_eq!(
            page(&app).edit,
            Some(PageEdit::Rename {
                name: dad.clone(),
                full: false,
                problem: None,
            })
        );
        testkit::press(&mut app, KeyCode::Esc);
        on_persian(&mut app, "eq");
        assert_eq!(
            page(&app).edit,
            Some(PageEdit::Address {
                text: dad.clone(),
                bad: false,
            })
        );
        testkit::press(&mut app, KeyCode::Esc);
        on_persian(&mut app, "xq");
        assert_eq!(
            page(&app).edit,
            Some(PageEdit::Remove { typed: dad.clone() })
        );
        testkit::press(&mut app, KeyCode::Esc);
        testkit::press(&mut app, KeyCode::Esc);
        // SET's name, opened with S from a Persian keyboard.
        on_persian(&mut app, "s");
        testkit::press(&mut app, KeyCode::Enter);
        let Screen::Settings(set) = app.screen() else {
            panic!("not on SET: {:?}", app.screen());
        };
        let typed = format!("{}{dad}", set.name.clone().expect("the name field"));
        on_persian(&mut app, "q");
        assert!(
            matches!(app.screen(), Screen::Settings(set) if set.name.as_deref() == Some(typed.as_str())),
            "{:?}",
            app.screen()
        );
        assert!(app.overlays().is_empty());
    }

    #[test]
    fn added_takes_1_from_a_persian_number_row() {
        // AF-3, once Bob is saved.
        let added = || {
            let mut app = verifying(Vec::new());
            testkit::press(&mut app, KeyCode::Tab);
            confirm(&mut app);
            answer(
                &mut app,
                saved(FriendChange::Add, &testkit::me(BOB).pub_hex, Ok(())),
            );
            assert!(matches!(app.screen(), Screen::Added(_)));
            app
        };
        // 1 shows my invite: AF-1 with the share box focused.
        for zero in [testkit::PERSIAN_ZERO, testkit::ARABIC_INDIC_ZERO] {
            let mut app = added();
            type_into(&mut app, &testkit::digits_from("1", zero));
            assert_eq!(adding(&app).focus, AddFocus::Share);
        }
        // A adds another friend: the paste box focused.
        let mut app = added();
        on_persian(&mut app, "a");
        assert_eq!(adding(&app).focus, AddFocus::Paste);
    }

    #[test]
    fn retry_and_stop_trying_take_their_keys_from_a_persian_keyboard() {
        let mut app = composing(&[]);
        testkit::send(&mut app, testkit::node_up());
        let (one, _) = testkit::type_and_send(&mut app, "hi").expect("a send");
        testkit::reload(
            &mut app,
            &[(1, testkit::row(7, true, "queued", 0, "hi"))],
            FileStamp::default(),
        );
        testkit::send(
            &mut app,
            testkit::sent(one, SendResult::Failed(testkit::queued_outcome(1, true))),
        );
        let mid = format!("{:032x}", 7);
        testkit::press(&mut app, KeyCode::Tab);
        // R: try it now.
        let cmds = on_persian(&mut app, "r");
        assert_eq!(
            cmds.first(),
            Some(&Cmd::Send(SendJob::Retry {
                mid: mid.clone(),
                peer: key_of(1)
            }))
        );
        testkit::send(
            &mut app,
            Msg::Job(JobResult::Retried {
                mid: mid.clone(),
                peer: key_of(1),
                result: Ok(()),
                captured: String::new(),
            }),
        );
        // C asks first and N keeps it, on Persian and on Arabic 101 keys; Y
        // stops it.
        on_persian(&mut app, "c");
        assert!(matches!(app.overlays(), [Overlay::Confirm(_)]));
        on_persian(&mut app, "n");
        assert!(app.overlays().is_empty());
        type_into(&mut app, "\u{0624}");
        assert!(matches!(app.overlays(), [Overlay::Confirm(_)]));
        type_into(&mut app, "\u{0649}");
        assert!(app.overlays().is_empty());
        on_persian(&mut app, "c");
        let cmds = on_persian(&mut app, "y");
        assert_eq!(
            cmds.first(),
            Some(&Cmd::Send(SendJob::Cancel {
                mid,
                peer: key_of(1)
            }))
        );
        assert!(app.overlays().is_empty());
    }

    // ── the notes shown once (UXF.9) ────────────────────────────────────────

    /// [`ready`] with `friends`, for a profile that has seen every note
    /// shown once but the ones `unseen` clears.
    fn before_note(receive: Receive, friends: u8, unseen: fn(&mut TuiState)) -> App {
        let mut settings = testkit::notes_seen(TuiState {
            receive,
            ..TuiState::default()
        });
        unseen(&mut settings);
        let mut app = app();
        app.start(Session {
            settings,
            ..session(receive)
        });
        history(&mut app);
        vault(&mut app, false);
        answer(&mut app, JobResult::Probed(not_running()));
        answer(&mut app, JobResult::Managed(None));
        contacts(&mut app, friends);
        app
    }

    fn no_exit_note(state: &mut TuiState) {
        state.exit_note_shown = false;
    }

    /// The one exit QUIT's `key` (after Q) asks for.
    fn quit_with(app: &mut App, key: KeyCode) -> ExitPlan {
        testkit::press(app, KeyCode::Char('q'));
        match &testkit::press(app, key)[..] {
            [Cmd::Exit(plan)] => plan.clone(),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn the_first_quit_with_receiving_on_says_who_could_read_the_chats() {
        assert_eq!(
            EXIT_NOTE,
            "If someone gets this laptop while you're logged in, they can read your Raven \
             chats. Lock Raven or your screen when you step away."
        );
        // Nothing runs: the note is the line, and the settings that remember
        // it go with the plan, to be saved before the screen goes.
        let mut app = before_note(Receive::On, 0, no_exit_note);
        let seen = TuiState {
            exit_note_shown: true,
            ..app.settings().clone()
        };
        let plan = quit_with(&mut app, KeyCode::Enter);
        assert_eq!(
            plan,
            ExitPlan {
                line: Some(EXIT_NOTE.to_owned()),
                save: Some(seen),
                ..ExitPlan::quit(None)
            }
        );
        // Under the line about a background program that keeps running.
        let mut app = before_note(Receive::On, 0, no_exit_note);
        answer(&mut app, JobResult::Probed(listening(4242, "0.0.0.0:7420")));
        let plan = quit_with(&mut app, KeyCode::Enter);
        assert_eq!(
            plan.line,
            Some(format!("{}\n{EXIT_NOTE}", still_running_line(4242)))
        );
        assert!(plan.save.is_some_and(|state| state.exit_note_shown));
        // Under the line about one that was stopped.
        let mut app = before_note(Receive::On, 0, no_exit_note);
        answer(&mut app, JobResult::Probed(listening(4242, "0.0.0.0:7420")));
        testkit::press(&mut app, KeyCode::Char('q'));
        testkit::press(&mut app, KeyCode::Char('s'));
        let cmds = answer(
            &mut app,
            JobResult::Stopped(Stopped {
                outcome: StopOutcome::Stopped,
                after: not_running(),
            }),
        );
        let [Cmd::Exit(plan)] = &cmds[..] else {
            panic!("{cmds:?}");
        };
        assert_eq!(plan.line, Some(format!("{STOPPED_LINE}\n{EXIT_NOTE}")));
        assert!(plan.save.is_some());
        // SMALL's Q quits with it too.
        let mut app = before_note(Receive::On, 0, no_exit_note);
        resize(&mut app, 40, 3);
        let cmds = testkit::press(&mut app, KeyCode::Char('q'));
        assert!(
            matches!(&cmds[..], [Cmd::Exit(plan)] if plan.line.as_deref() == Some(EXIT_NOTE)),
            "{cmds:?}"
        );
        // A signal ends the app with nothing to say.
        let mut app = before_note(Receive::On, 0, no_exit_note);
        assert_eq!(
            testkit::send(&mut app, Msg::OsSignal(OsSignal::Terminate)),
            [Cmd::Exit(ExitPlan::signal(OsSignal::Terminate))]
        );
    }

    #[test]
    fn the_exit_note_is_said_once_and_only_with_receiving_on() {
        // Once saved as shown, the next quit says nothing more.
        let mut first = before_note(Receive::On, 0, no_exit_note);
        let saved = quit_with(&mut first, KeyCode::Enter).save.expect("a save");
        let mut next = app();
        next.start(Session {
            settings: saved,
            ..session(Receive::On)
        });
        assert_eq!(quit_with(&mut next, KeyCode::Enter), ExitPlan::quit(None));
        // Receiving off: friends can't reach this computer, and QUIT says
        // nothing more.
        let mut app = before_note(Receive::Off, 0, no_exit_note);
        assert_eq!(quit_with(&mut app, KeyCode::Enter), ExitPlan::quit(None));
        // Before the identity exists nothing can be saved, so nothing is
        // said: WZ-1's Q.
        let mut app = testkit::wizard_app((80, 24));
        assert_eq!(
            testkit::press(&mut app, KeyCode::Char('q')),
            [Cmd::Exit(ExitPlan::quit(None))]
        );
        // LOCK's line stands alone on its cleared terminal.
        assert_eq!(ExitPlan::locked(false).save, None);
    }

    #[test]
    fn copy_says_to_clear_the_terminal_the_first_time() {
        let mut app = before_note(Receive::Off, 0, |state| state.copy_note_shown = false);
        testkit::press(&mut app, KeyCode::Char('a'));
        answer(
            &mut app,
            JobResult::Shared {
                listen: None,
                share: Share {
                    lan: None,
                    with_lan: None,
                    plain: Ok(testkit::card(7, "")),
                },
            },
        );
        testkit::press(&mut app, KeyCode::Tab);
        testkit::press(&mut app, KeyCode::Char('s'));
        let cmds = testkit::press(&mut app, KeyCode::Char('c'));
        let seen = TuiState {
            copy_note_shown: true,
            ..app.settings().clone()
        };
        assert_eq!(
            cmds,
            [
                Cmd::Peek(add_friend::copy_lines(
                    &testkit::card(7, ""),
                    cfg!(windows),
                    true
                )),
                Cmd::Store(StoreJob::SaveReadMarks(seen)),
            ]
        );
        // Not the next time.
        assert_eq!(testkit::press(&mut app, KeyCode::Char('x')), [Cmd::Unpeek]);
        assert_eq!(
            testkit::press(&mut app, KeyCode::Char('c')),
            [Cmd::Peek(add_friend::copy_lines(
                &testkit::card(7, ""),
                cfg!(windows),
                false
            ))]
        );
    }

    /// Which notes shown once `app` shows, each brought about in turn on
    /// Home with friend 1, a node this app started: NOTE, step 2a's hotspot
    /// note, AF-2's nickname hint, COPY's note and the exit note. Every save
    /// asked for is carried out by `carry`, as the store worker and the UI
    /// thread carry them out.
    fn notes_shown(app: &mut App, carry: &dyn Fn(&[Cmd])) -> Vec<&'static str> {
        let mut shown = Vec::new();
        carry(&testkit::started_here(app, 4242));
        if app.overlays() == [Overlay::NetworkNote] {
            shown.push("network");
            testkit::press(app, KeyCode::Esc);
        }
        assert!(app.overlays().is_empty(), "{:?}", app.overlays());
        testkit::press(app, KeyCode::Char('g'));
        carry(&testkit::press(app, KeyCode::Char('1')));
        if matches!(app.screen(), Screen::Meet(meet) if meet.hotspot_note) {
            shown.push("hotspot");
        }
        testkit::press(app, KeyCode::Esc);
        testkit::press(app, KeyCode::Char('a'));
        answer(
            app,
            JobResult::Shared {
                listen: Some("0.0.0.0:7420".into()),
                share: Share {
                    lan: Some(Ok("192.168.1.20:7420".into())),
                    with_lan: Some(Ok(testkit::card(7, "192.168.1.20:7420"))),
                    plain: Ok(testkit::card(7, "")),
                },
            },
        );
        testkit::press(app, KeyCode::Tab);
        let cmds = testkit::press(app, KeyCode::Char('c'));
        carry(&cmds);
        let Some(Cmd::Peek(lines)) = cmds.first() else {
            panic!("{cmds:?}");
        };
        if lines.iter().any(|line| line.starts_with("Clear this")) {
            shown.push("copy");
        }
        testkit::press(app, KeyCode::Char('x'));
        testkit::press(app, KeyCode::Tab);
        testkit::paste(app, &testkit::card(0xB0, ""), PasteVia::Bracketed);
        later(app);
        carry(&testkit::press(app, KeyCode::Enter));
        if adding(app).names_note {
            shown.push("names");
        }
        testkit::press(app, KeyCode::Esc);
        testkit::press(app, KeyCode::Esc);
        assert_eq!(app.screen(), &Screen::Home);
        let plan = quit_with(app, KeyCode::Enter);
        if plan
            .line
            .as_deref()
            .is_some_and(|line| line.ends_with(EXIT_NOTE))
        {
            shown.push("exit");
        }
        carry(&[Cmd::Exit(plan)]);
        shown
    }

    #[test]
    fn each_note_shows_once_and_never_again_after_it_is_saved() {
        testkit::lab_backends();
        let dir = testkit::short_dir();
        let controller = controller::Controller::with_egress(dir.path(), || None);
        let me = controller.create_identity().result.expect("create").me;
        // A session of the profile on disk, from the settings saved there,
        // its first jobs answered: one friend, no node running yet.
        let open = || {
            let mut app = app();
            app.start(Session {
                identity: IdentityStart::Ready(me.clone()),
                data_dir: dir.path().to_path_buf(),
                settings: TuiState {
                    receive: Receive::On,
                    ..state_file::peek(dir.path())
                },
                ..session(Receive::On)
            });
            history(&mut app);
            vault(&mut app, false);
            answer(&mut app, JobResult::Probed(not_running()));
            answer(&mut app, JobResult::Managed(None));
            contacts(&mut app, 1);
            app
        };
        let carry = |cmds: &[Cmd]| {
            for cmd in cmds {
                if let Cmd::Store(StoreJob::SaveReadMarks(state))
                | Cmd::Exit(ExitPlan {
                    save: Some(state), ..
                }) = cmd
                {
                    assert_eq!(controller.save_read_marks(state), Ok(true));
                }
            }
        };
        let mut first = open();
        assert_eq!(
            notes_shown(&mut first, &carry),
            ["network", "hotspot", "copy", "names", "exit"]
        );
        let saved = state_file::peek(dir.path());
        assert!(
            saved.network_note_shown
                && saved.hotspot_note_shown
                && saved.names_note_shown
                && saved.exit_note_shown
                && saved.copy_note_shown,
            "{saved:?}"
        );
        // The next session, from the file: none of them again.
        let mut next = open();
        assert!(notes_shown(&mut next, &carry).is_empty());
    }

    #[test]
    fn delete_chat_toasts_say_how_many_in_plain_words() {
        let toasts = |deleted, still_waiting, skipped_pending| {
            chat_deleted_toasts(
                "Bob",
                DeleteChatOutcome {
                    deleted,
                    still_waiting,
                    skipped_pending,
                },
            )
        };
        assert_eq!(
            toasts(1, 0, 0),
            ["Deleted your chat with Bob on this computer (1 message)."]
        );
        assert_eq!(
            toasts(12, 1, 0),
            [
                "Deleted your chat with Bob on this computer (12 messages).",
                "1 message to Bob is still waiting to be sent.",
            ]
        );
        assert_eq!(
            toasts(0, 3, 2),
            [
                "Deleted your chat with Bob on this computer (0 messages).",
                "3 messages to Bob are still waiting to be sent.",
                "2 received messages could not be deleted now: delete the chat again later.",
            ]
        );
        // The typed word: any case, around spaces, and the keys of a Persian
        // or Arabic 101 layout; nothing else.
        for typed in [
            "delete",
            "DELETE",
            " Delete ",
            &testkit::on_persian_keyboard("delete"),
        ] {
            assert!(typed_word_is(typed, DELETE_WORD), "{typed:?}");
        }
        for typed in ["", "delet", "deleted", "remove", "d e l e t e"] {
            assert!(!typed_word_is(typed, DELETE_WORD), "{typed:?}");
        }
    }
}
