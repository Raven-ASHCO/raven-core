//! The app's blocking work, run on worker threads: one method per job, each
//! reaching the CLI through `bridge`.
//!
//! - The [`Controller`] holds the identity; the App only ever gets its public
//!   half ([`MeView`]).
//! - Every change to contacts.json or the block list runs in a critical
//!   section (a signal waits for it), with what it prints captured, and comes
//!   back as [`Captured`] with every security code of a friend not verified
//!   on this computer taken out.
//! - The security code and the confirmation code are checked in the App
//!   before it asks for a save; `add_contact_with_routes` checks the security
//!   code again.
//! - Nothing here writes into a profile before its identity exists, and no
//!   background program is started before then either.
//! - Every call that can start raven-node holds the node gate: ext.rs decides
//!   a socket is stale and removes it outside its own lock.
//! - A send is `raven send --contact`'s, through bridge's mirror of it: the
//!   background program first, then the friend's planned routes with no
//!   address from the environment (OD-17); retry and cancel are `raven
//!   outbox`'s, never a prompt.
//! - Groups (lab) are `raven group`'s, through raven-core's `group` module:
//!   a read may first refresh the copies' delivery and park the work
//!   waiting; after a send or a change raven-node is asked to send the
//!   copies, and started first when none answers, as a chat send starts it.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::Duration;

use raven_core::chat_history::BlockList;
use raven_core::group::{self, GroupId, GroupSummary, GroupView, Key as GroupKey};
use raven_core::identity::Identity;
use raven_core::sanitize::sanitize_terminal_line;

#[cfg(test)]
use super::app::{
    App, Cmd, FriendChange, JobResult, Msg, PasteVia, Screen, SendJob, StoreJob, SuspendJob,
};
#[cfg(all(test, unix))]
use super::app::{
    EXT_NOT_WAITING, EXT_NO_OUTBOX, NOT_RETRIED_TOAST, NOT_WAITING_TOAST, STOPPED_TOAST,
};
use super::bridge::{
    self, ChatKeepView, ContactView, DeleteChatOutcome, DialCarrier, EraseEnd, ErasePlanView,
    FriendPreview, IdentityLoad, LoginItemView, MeView, NotAvailable, Notice, OutboxCmd,
    PrivacyNotices, Resolved, SecurityView,
};
#[cfg(all(test, unix))]
use super::errors::{self, NodeStartProblem};
use super::hidden;
use super::live::{Carrier, Route};
use super::node::{self, Ensured, Probe, StopOutcome, Stopped};
use super::read_marks::{self, ReadMarks};
use super::state_file::{self, TuiState};
use super::stdio::{self, JobCapture};
#[cfg(test)]
use super::testkit;
use super::workers::{self, Critical, FileStamp};

/// Every job that needs the identity, while the profile has none.
pub(super) const NO_IDENTITY: &str = "this profile has no Raven identity yet";
/// Every job once ERASE's erase began (PP.22): nothing opens the profile
/// again.
pub(super) const ERASED: &str = "Raven is being erased from this computer";
/// A job about a friend who is not saved.
pub(super) const NOT_SAVED: &str = "that friend is not saved on this computer";
/// A friend saved without a name (AF-2 asks for one).
pub(super) const NO_NAME: &str = "a friend needs a name on this computer";
/// The user's own key, as a friend (parse_friend_paste refuses it first).
pub(super) const OWN_KEY: &str = "that is this profile's own identity, not a friend's";
/// What a job's text shows instead of a security code the user has not
/// verified.
pub(super) const HIDDEN_CODE: &str = "[security code hidden until verified]";
/// How long a start waits for the stderr reader to reach its sentinel, so
/// the line saying which process it spawned is in the ring.
const SYNC_WAIT: Duration = Duration::from_secs(1);
/// A paste longer than this, or with more lines, holds no invite or card: a
/// card is one line of at most `CARD_MAX_LEN` characters, and a whoami block
/// is four lines.
const PASTE_MAX_BYTES: usize = 8 * 1024;
const PASTE_MAX_LINES: usize = 32;
/// A send to a friend on the block list (ext.rs refuses one in these words,
/// which its classifier reads as blocked).
pub(super) const BLOCKED: &str = "send refused: peer is on the local block list";
/// The listen address a send passes: `raven send`'s default and the menu's.
const SEND_LISTEN: &str = "127.0.0.1:0";
/// The words of cli.rs's card and invite refusals that mean the address, the
/// key and the code don't belong together (`parse_card`, `parse_raven_invite`).
pub(super) const TAMPER_MARKS: &[&str] = &[
    "does not belong to its pub_hex",
    "address/pub mismatch",
    "fingerprint does not match its key",
];

/// Proof that this profile's identity exists. Only this file builds one,
/// once the controller holds a loaded or created identity, and writing
/// tui_state.json needs one (`TuiState::save`): raven-core refuses to create
/// an identity over files it does not know (identity_store.rs:280-309,
/// 375-437), so the app writes nothing into a profile before its identity.
#[derive(Debug)]
pub(super) struct IdentityReady(());

/// The one way to make an [`IdentityReady`]: call it only once the
/// controller holds the identity, as its saves check first.
fn identity_ready() -> IdentityReady {
    IdentityReady(())
}

/// For tests that save state in a temporary profile with no identity.
#[cfg(test)]
pub(super) fn identity_ready_for_tests() -> IdentityReady {
    identity_ready()
}

/// An [`IdentityReady`] for a writer that is not this app (the desktop
/// engine's read markers, read_marks.rs): only while raven-core has the
/// profile's identity on record (its marker files; no keystore call).
#[cfg_attr(not(feature = "engine"), allow(dead_code))]
pub(super) fn identity_on_record(data_dir: &Path) -> Option<IdentityReady> {
    raven_core::identity_store::identity_recorded(data_dir)
        .unwrap_or(false)
        .then(identity_ready)
}

/// What [`Controller::load_identity`] found.
#[derive(Debug)]
pub(super) enum IdentityState {
    Ready {
        me: MeView,
    },
    /// No identity yet: the wizard can create one.
    Missing,
    /// The identity store can't be read (raven-core's redacted reason).
    /// Never offer to create an identity over it.
    Unavailable(String),
}

/// A new identity (or the one a race created first).
#[derive(Debug)]
pub(super) struct Created {
    pub(super) me: MeView,
    /// The identity is there, but its first prekey (or device certificate)
    /// is not: a toast, as the menu prints a `prekey:` line, and no failure.
    pub(super) prekey_warning: Option<String>,
}

/// A job's result and what it printed meanwhile (stdout; stderr goes to the
/// ring). Both are raw: shown only through display.rs, and the printed text
/// only on request (Details).
#[derive(Debug)]
pub(super) struct Captured<T> {
    pub(super) result: Result<T, String>,
    pub(super) captured: String,
}

/// How a friend is saved, decided in the App: pinned only after the code the
/// user typed matched (and the confirmation code did).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Verify {
    /// The code as the user typed it: `add_contact_with_routes` checks it
    /// against the key's own code again and pins only on a match.
    Pinned { typed_fp: String },
    /// Saved as not verified.
    Unpinned,
}

impl Verify {
    fn typed_fp(&self) -> Option<&str> {
        match self {
            Verify::Pinned { typed_fp } => Some(typed_fp),
            Verify::Unpinned => None,
        }
    }
}

/// Why a card gets no network address from the node's listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum NoCardLan {
    /// It listens on this computer only: a friend can't reach that.
    LocalOnly,
    /// It listens on every address, and this computer's own can't be told
    /// (offline).
    NoAddress,
    /// Not an address with a port.
    Unknown,
}

/// Why a paste is not a friend to add (AF-1). The text is the technical
/// reason, for Details.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum PasteProblem {
    /// Not an invite or a card, or more than one person's.
    NotACard(String),
    /// Its address and key don't match, or its code isn't its key's.
    Tampered(String),
    /// The user's own invite or card.
    OwnInvite,
}

/// The name typed for a friend, against the saved ones (AF-2 and rename).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum NameCheck {
    Free,
    /// Nothing but spaces.
    Empty,
    /// A friend who is not verified already has it (`pub_hex`): pick
    /// another. Names compare ignoring case, as cli.rs's petnames do.
    Taken(String),
    /// A verified friend with another key has it, or a name that looks the
    /// same ([`fold_confusables`]) (`pub_hex`): NAME-CLASH, and nothing is
    /// saved.
    VerifiedClash(String),
}

/// A name that may be saved, but can pass for another one: AF-2 (and
/// rename) say so before it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum NameWarning {
    /// Latin, Cyrillic or Greek letters mixed in one name.
    MixedScript,
    /// It looks the same as the name of the friend `pub_hex` (not verified)
    /// once look-alike letters are folded, though the letters differ.
    LooksLike(String),
}

/// Look-alike letters, after lower-casing, and the Latin letter each passes
/// for: Cyrillic а е о р с у х і ј and Greek ο α ε ρ ν. A small table on
/// purpose: these are the ones a name is most easily faked with.
const CONFUSABLES: &[(char, char)] = &[
    ('\u{0430}', 'a'),
    ('\u{0435}', 'e'),
    ('\u{043E}', 'o'),
    ('\u{0440}', 'p'),
    ('\u{0441}', 'c'),
    ('\u{0443}', 'y'),
    ('\u{0445}', 'x'),
    ('\u{0456}', 'i'),
    ('\u{0458}', 'j'),
    ('\u{03BF}', 'o'),
    ('\u{03B1}', 'a'),
    ('\u{03B5}', 'e'),
    ('\u{03C1}', 'p'),
    ('\u{03BD}', 'v'),
];

/// Whether a card from this release's AF-2 labels its Internet and p2p
/// routes Preview: their carriers are off in production
/// (`*_PRODUCTION_ENABLED`, read only).
pub(super) const INTERNET_PREVIEW: bool = !raven_core::INTERNET_DIRECT_PRODUCTION_ENABLED;
pub(super) const P2P_PREVIEW: bool = !raven_core::P2P_PRODUCTION_ENABLED;

/// My invite for AF-1, made for the listener a node reported: the address a
/// friend reaches it at, the card with that address, and the card without
/// one (for S, or with L off). Public material only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Share {
    /// From the listener ([`Controller::card_lan`]); None when no listener
    /// was given.
    pub(super) lan: Option<Result<String, NoCardLan>>,
    /// The card with `lan`, once there is one.
    pub(super) with_lan: Option<Result<String, String>>,
    /// The card with no address.
    pub(super) plain: Result<String, String>,
}

/// One message of a conversation, as the history keeps it. The body is raw
/// (bodies are not sanitized at rest): display.rs shapes it when drawn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RowView {
    /// The message id (hex), as the history row has it; empty on some legacy
    /// rows.
    pub(super) id: String,
    /// Sent from this computer (`out`); anything else came from the friend.
    pub(super) outgoing: bool,
    /// When the sender's computer made it (its clock, not this one's).
    pub(super) created_at_ms: u64,
    /// The history's delivery state: `queued`, `delivered`, `read`,
    /// `failed`, `expired`, `cancelled`, or empty.
    pub(super) delivery: String,
    pub(super) body: String,
}

/// Every friend's conversation, by key (`pub_hex`, lower case), each in the
/// order the history wrote it: never sorted by `created_at_ms`, which is the
/// sender's clock.
pub(super) type Conversations = HashMap<String, Vec<RowView>>;

/// What a message written now could do for each friend whose answer is
/// known, by key (`pub_hex`, lower case): wait until when it would run out,
/// or not at all (the last secure connection ended: meet first; none yet: a
/// first message goes only while both are online). A friend not in it is
/// not known.
pub(super) type Horizons = HashMap<String, bridge::QueueReach>;

/// How a send job ended, and what it printed meanwhile (raw, for Details).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SendOutcome {
    pub(super) result: SendResult,
    /// The send reached the friend at the address it learned for them, not
    /// the saved one: the App has the store worker save it.
    pub(super) learned_dial_used: Option<String>,
    pub(super) captured: String,
}

/// Where a send stands when its job ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum SendResult {
    /// Their Raven confirmed it; the carrier and the address it went to.
    Delivered(Route),
    /// The send's outcome text (ext.rs's): queued here, sent but not
    /// confirmed, or not sent (a refusal before any dial too).
    Failed(String),
    /// The background program could not be started or reached, so nothing
    /// was dialled and nothing written to the history.
    NodeUnavailable(String),
}

/// What the privacy pack's read found (PP.21): SET's "Keep chats for",
/// Home's one-time notices still due, and how much free disk space sealing
/// waits for (NET); and whether opening the app cleared a lock that turned
/// Raven's login item off, which stays off until `raven unlock` (PP.23).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PrivacyRead {
    pub(super) keep: ChatKeepView,
    pub(super) notices: PrivacyNotices,
    pub(super) disk_needed: Option<u64>,
    pub(super) login_item_stays_off: bool,
}

/// The newest messages a group's chat reads (scrolling up goes no further).
pub(super) const GROUP_MESSAGES: usize = 200;

/// What a groups read found (lab: docs/design/2026-10-groups.md): every
/// group, the newest activity first, and the open group's chat. The errors
/// are raven-core's technical text: the App says it in its own words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct GroupsRead {
    pub(super) groups: Result<Vec<GroupSummary>, String>,
    /// The group asked for, and its chat or why it can't be read.
    pub(super) open: Option<(GroupId, Result<GroupChat, String>)>,
    /// groups.json just before it was read (after a refresh wrote it).
    pub(super) stamp: FileStamp,
}

/// One group's chat as its pane shows it: the group with its members, and
/// its newest messages (oldest first) with every name already resolved, as
/// `raven group show` resolves them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct GroupChat {
    pub(super) view: GroupView,
    pub(super) messages: Vec<GroupMessage>,
}

/// One message of a group. Names and the body are raw: display.rs shapes
/// them when drawn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct GroupMessage {
    pub(super) id: [u8; 16],
    /// Written here.
    pub(super) mine: bool,
    /// Its author: a friend's name, else the name the admin gave them.
    pub(super) author: String,
    /// The member that passed it on, when it did not come from its author.
    pub(super) via: Option<String>,
    pub(super) body: String,
    /// When it was stored here (this computer's clock).
    pub(super) at_ms: u64,
    /// When its author wrote it (the author's clock): yours, when you sent
    /// it.
    pub(super) sent_ms: u64,
    /// A member's: how the copy that brought it came, when known (E2 r9).
    pub(super) path: Option<raven_core::arrivals::ArrivedVia>,
    /// Mine only: where it stands for each member it was for.
    pub(super) lines: Vec<MemberLine>,
    pub(super) delivered: usize,
    pub(super) total: usize,
}

/// One member's copy of a message of yours.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct MemberLine {
    pub(super) name: String,
    /// raven-core's word: `waiting`, `sent`, `delivered` or `failed`.
    pub(super) state: String,
    /// Reached through another member (not your friend).
    pub(super) relayed: bool,
}

/// A change to a group, run on the send worker: each makes copies (a
/// roster, a leave) that raven-node sends. Keys are identity keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum GroupChange {
    /// A new group named `name`, with these friends and the names the
    /// others will see for them; this profile is its admin.
    Create {
        name: String,
        members: Vec<(GroupKey, String)>,
    },
    /// The admin adds friends.
    Add {
        group: GroupId,
        members: Vec<(GroupKey, String)>,
    },
    /// The admin removes a member (`name`: as the group showed them).
    Remove {
        group: GroupId,
        member: GroupKey,
        name: String,
    },
    /// This profile leaves (never the admin).
    Leave { group: GroupId },
}

/// How a group send or change went: its answer (the message's or the
/// group's id, or raven-core's sentence), and whether raven-node took the
/// copies (it was asked to send them, and started first when none ran).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct GroupDone<T> {
    pub(super) result: Result<T, String>,
    pub(super) kicked: bool,
}

/// The jobs, shared by the store, send and node workers.
pub(super) struct Controller {
    data_dir: PathBuf,
    /// Set by the first load or create that finds one, and never replaced:
    /// later jobs never ask the key store again.
    id: OnceLock<Arc<Identity>>,
    /// Held while the background program is started or checked for a send,
    /// so two starts never race.
    node_gate: Mutex<()>,
    /// This computer's IPv4 address on the network (tests inject one).
    egress: fn() -> Option<Ipv4Addr>,
    /// Starts the profile's raven-node unless one answers: ext.rs's, as a
    /// send runs it (tests inject one).
    ensure: fn(&Path) -> Result<(), String>,
    /// How long a message to a friend could wait: bridge.rs's read (tests
    /// inject one).
    horizon: fn(&Path, &str, u64) -> Option<bridge::QueueReach>,
    /// Erases the profile, calling its argument once the erase can no
    /// longer be taken back: bridge.rs's (tests inject one).
    erase: fn(&Path, &mut dyn FnMut()) -> EraseEnd,
    /// Raven's own login item for this profile, and unloading it for this
    /// login session (PP.23): bridge.rs's (tests inject the lab's).
    login_item: fn(&Path) -> Result<Option<LoginItemView>, NotAvailable>,
    stop_for_session: fn(&Path) -> Result<(), String>,
    /// The epoch whose key the running raven-node uses, for my card's
    /// `p2p=` (review D-2): bridge.rs's IPC read (tests inject one).
    rotation_epoch: fn(&Path) -> Option<u64>,
    /// Opening the app, or UNLOCK's yes, cleared a lock that turned Raven's
    /// login item off ([`Controller::reopen_after_lock`],
    /// [`Controller::unlock`]).
    login_item_stays_off: AtomicBool,
    /// Set once ERASE's erase began (PP.22): from then on every job refuses
    /// and every save is a no-op, so nothing writes into the profile, or
    /// makes its folder again, while it goes or after it went.
    closed: AtomicBool,
}

impl Controller {
    pub(super) fn new(data_dir: &Path) -> Controller {
        Controller::with_egress(data_dir, bridge::egress_v4)
    }

    pub(super) fn with_egress(data_dir: &Path, egress: fn() -> Option<Ipv4Addr>) -> Controller {
        Controller {
            data_dir: data_dir.to_path_buf(),
            id: OnceLock::new(),
            node_gate: Mutex::new(()),
            egress,
            ensure: bridge::ensure_mac_lan_daemon,
            horizon: bridge::queue_horizon,
            erase: bridge::erase,
            login_item: bridge::own_login_item,
            stop_for_session: bridge::stop_for_session,
            rotation_epoch: bridge::own_rotation_epoch,
            login_item_stays_off: AtomicBool::new(false),
            closed: AtomicBool::new(false),
        }
    }

    /// A controller whose starts run `ensure` instead of ext.rs's.
    #[cfg(test)]
    pub(super) fn with_ensure(
        data_dir: &Path,
        ensure: fn(&Path) -> Result<(), String>,
    ) -> Controller {
        Controller {
            ensure,
            ..Controller::new(data_dir)
        }
    }

    /// A controller whose running node says it uses the key of the epoch
    /// `rotation_epoch` returns, instead of asking it.
    #[cfg(test)]
    pub(super) fn with_rotation_epoch(
        data_dir: &Path,
        rotation_epoch: fn(&Path) -> Option<u64>,
    ) -> Controller {
        Controller {
            rotation_epoch,
            ..Controller::new(data_dir)
        }
    }

    /// A controller whose horizon reads run `horizon` instead of bridge.rs's.
    #[cfg(test)]
    pub(super) fn with_horizon(
        data_dir: &Path,
        horizon: fn(&Path, &str, u64) -> Option<bridge::QueueReach>,
    ) -> Controller {
        Controller {
            horizon,
            ..Controller::new(data_dir)
        }
    }

    /// A controller whose erase runs `erase` instead of bridge.rs's.
    #[cfg(test)]
    pub(super) fn with_erase(
        data_dir: &Path,
        erase: fn(&Path, &mut dyn FnMut()) -> EraseEnd,
    ) -> Controller {
        Controller {
            erase,
            ..Controller::new(data_dir)
        }
    }

    /// A controller that finds Raven's login item in the lab beside the
    /// profile and unloads it with the lab's fake tools (bridge.rs's
    /// `own_login_item_in_lab`): no real login item is read or changed.
    #[cfg(all(test, unix))]
    pub(super) fn with_lab_login_item(data_dir: &Path) -> Controller {
        Controller {
            login_item: bridge::own_login_item_in_lab,
            stop_for_session: bridge::stop_for_session_in_lab,
            ..Controller::new(data_dir)
        }
    }

    pub(super) fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// The node gate. A job that panicked holding it does not keep it.
    pub(super) fn node_gate(&self) -> MutexGuard<'_, ()> {
        self.node_gate
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// The profile's identity, through cli.rs's `try_load_identity`; once
    /// found it is kept, and asked for again never. Run it on the plain
    /// terminal: the vault passphrase and Keychain prompts appear there.
    pub(super) fn load_identity(&self) -> IdentityState {
        if self.closed() {
            return IdentityState::Unavailable(ERASED.to_owned());
        }
        if let Some(id) = self.id.get() {
            return IdentityState::ready(id);
        }
        match bridge::load_identity(&self.data_dir) {
            IdentityLoad::Ready(id) => IdentityState::ready(self.keep(id)),
            IdentityLoad::Missing => IdentityState::Missing,
            IdentityLoad::Unavailable(why) => IdentityState::Unavailable(why),
        }
    }

    /// Creates the identity as the menu's first run does: raven-core's
    /// `load_or_create_identity`, then `ensure_local_prekey` (which also
    /// makes the device certificate), whose failure is only a warning. Call
    /// it only for a Missing identity, never over an Unavailable one.
    pub(super) fn create_identity(&self) -> Captured<Created> {
        let _critical = Critical::enter();
        let capture = JobCapture::start();
        let result = self.create();
        Captured {
            result,
            captured: capture.finish(),
        }
    }

    fn create(&self) -> Result<Created, String> {
        if self.closed() {
            return Err(ERASED.to_owned());
        }
        let id = match self.id.get() {
            Some(id) => id,
            None => self.keep(bridge::load_or_create_identity(&self.data_dir)?),
        };
        let prekey_warning = bridge::ensure_local_prekey(&self.data_dir, id).err();
        Ok(Created {
            me: bridge::me_view(id),
            prekey_warning,
        })
    }

    /// Whether creating the identity will ask for a new passphrase on the
    /// terminal: a passphrase-vault profile (Unix other than macOS, with no
    /// desktop keyring). Then the full screen steps aside while it asks.
    /// Records nothing in the profile (raven-core's `uses_vault` without
    /// recording); it may ask Secret Service, with a timeout, so it runs on
    /// the store worker.
    pub(super) fn creation_prompts(&self) -> bool {
        #[cfg(all(unix, not(target_os = "macos")))]
        {
            matches!(bridge::uses_vault(&self.data_dir), Ok(true))
        }
        #[cfg(not(all(unix, not(target_os = "macos"))))]
        {
            false
        }
    }

    fn keep(&self, id: Arc<Identity>) -> &Arc<Identity> {
        self.id.get_or_init(|| id)
    }

    /// The identity, for a job that needs it: refused before there is one,
    /// and once the erase began.
    fn identity(&self) -> Result<&Arc<Identity>, String> {
        if self.closed() {
            return Err(ERASED.to_owned());
        }
        self.id.get().ok_or_else(|| NO_IDENTITY.to_owned())
    }

    /// ERASE's erase began: the profile is closed to this app.
    pub(super) fn closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// My public identity; None before there is one.
    pub(super) fn me(&self) -> Option<MeView> {
        self.id.get().map(|id| bridge::me_view(id))
    }

    /// My invite line, `raven:<address>:<pub_hex>`.
    #[cfg(test)]
    pub(super) fn my_invite(&self) -> Option<String> {
        self.me().map(|me| me.invite)
    }

    /// The address a card offers for a node bound to `lan_listen` (its
    /// Status): the bound IP and port, or with every address bound, this
    /// computer's own IPv4 address and that port. Never a listener on this
    /// computer only.
    pub(super) fn card_lan(&self, lan_listen: &str) -> Result<String, NoCardLan> {
        let bound: SocketAddr = lan_listen.trim().parse().map_err(|_| NoCardLan::Unknown)?;
        if bound.ip().is_loopback() {
            return Err(NoCardLan::LocalOnly);
        }
        if bound.port() == 0 {
            return Err(NoCardLan::Unknown);
        }
        if bound.ip().is_unspecified() {
            let ip = (self.egress)().ok_or(NoCardLan::NoAddress)?;
            return Ok(SocketAddr::from((ip, bound.port())).to_string());
        }
        Ok(bound.to_string())
    }

    /// My card line, as `whoami --card` makes it: `lan` (from
    /// [`Controller::card_lan`] only, and only while the user shares it) is
    /// checked like `--lan`, and the p2p part follows node_policy.json and,
    /// while PeerId rotation is on, the key the running node uses (its
    /// epoch's PeerId, never the fixed one it left).
    pub(super) fn my_card(&self, lan: Option<&str>) -> Result<String, String> {
        let id = self.identity()?;
        let lan = lan.map(bridge::parse_lan_dial).transpose()?;
        let policy = bridge::try_load_policy(&self.data_dir)?;
        let p2p = bridge::own_card_p2p(id, &policy, (self.rotation_epoch)(&self.data_dir))?;
        let card = bridge::with_own_onion(
            bridge::format_card_with(id, "", lan.as_deref().unwrap_or(""), p2p.as_ref())?,
            &self.data_dir,
            id,
        );
        if card.len() > bridge::CARD_MAX_LEN {
            return Err(format!(
                "this card would be {} characters, more than the {} a card may have",
                card.len(),
                bridge::CARD_MAX_LEN
            ));
        }
        Ok(card)
    }

    /// AF-1's cards for a node bound to `listen` (its Status's listener, only
    /// while it listens on the network), or None for a card with no address:
    /// both cards are made, so L and S need no second job.
    pub(super) fn share(&self, listen: Option<&str>) -> Share {
        let lan = listen.map(|listen| self.card_lan(listen));
        let with_lan = match &lan {
            Some(Ok(lan)) => Some(self.my_card(Some(lan))),
            _ => None,
        };
        Share {
            lan,
            with_lan,
            plain: self.my_card(None),
        }
    }

    /// The saved friends, in file order. A corrupt contacts.json or block
    /// list is an error, never an empty list.
    pub(super) fn load_contacts(&self) -> Result<Vec<ContactView>, String> {
        self.identity()?;
        bridge::contact_views(&self.data_dir)
    }

    /// [`Controller::load_contacts`], with contacts.json's size and time
    /// taken just before it is read: a change the poller reports after that
    /// is one this load may not have seen.
    pub(super) fn load_contacts_stamped(&self) -> (Result<Vec<ContactView>, String>, FileStamp) {
        let stamp = FileStamp::of(&bridge::contacts_path(&self.data_dir));
        (self.load_contacts(), stamp)
    }

    /// Saves the app's settings (tui_state.json; in a sealed profile the read
    /// markers and the name in tui_private.rms), once the identity exists.
    /// After an erase began, nothing (review R15): a no-op.
    pub(super) fn save_settings(&self, state: &TuiState) -> Result<(), String> {
        if self.closed() {
            return Ok(());
        }
        self.identity()?;
        state.save(&self.data_dir, &identity_ready())
    }

    /// Saves `state` for its read markers: a save the user did not ask for.
    /// A tui_state.json that can't be read is left as it is (the user may
    /// still repair it) until the user changes a setting; Ok(false) then. So
    /// is a sealed profile's tui_private.rms that can't be opened (PP.24).
    pub(super) fn save_read_marks(&self, state: &TuiState) -> Result<bool, String> {
        if self.closed() {
            return Ok(false);
        }
        self.identity()?;
        if let (_, state_file::LoadNote::Unreadable(_)) = state_file::load(&self.data_dir) {
            return Ok(false);
        }
        state.save(&self.data_dir, &identity_ready())?;
        Ok(true)
    }

    /// The read markers as saved, the desktop engine's among them
    /// (read_marks.rs). Reads only.
    pub(super) fn load_read_marks(&self) -> ReadMarks {
        read_marks::load(&self.data_dir)
    }

    /// Every friend's conversation from the chat history, rows grouped by
    /// friend in the order they were written, without the messages deleted
    /// in a desktop app (hidden.rs: the desktop apps' own rule, E1). Needs
    /// the identity: loading takes the history's lock, which creates its
    /// file.
    pub(super) fn load_history(&self) -> Result<Conversations, String> {
        self.identity()?;
        let hidden = hidden::load_set(&self.data_dir);
        let mut conversations = Conversations::new();
        for entry in bridge::load_history(&self.data_dir)?
            .into_iter()
            .filter(|entry| !hidden::hides(&hidden, &entry.message_id_hex))
        {
            conversations
                .entry(entry.peer_pub_hex.to_ascii_lowercase())
                .or_default()
                .push(RowView {
                    id: entry.message_id_hex,
                    outgoing: entry.direction == "out",
                    created_at_ms: entry.created_at_ms,
                    delivery: entry.delivery,
                    // Legacy rows kept only the preview (as `ash messages`).
                    body: if entry.body.is_empty() {
                        entry.preview
                    } else {
                        entry.body
                    },
                });
        }
        Ok(conversations)
    }

    /// [`Controller::load_history`], with the history file's size and time
    /// taken just before it is read, as for the contacts.
    pub(super) fn load_history_stamped(&self) -> (Result<Conversations, String>, FileStamp) {
        let stamp = FileStamp::of(&bridge::history_path(&self.data_dir));
        (self.load_history(), stamp)
    }

    /// How long a message written now could wait for each of `peers` (keys,
    /// hex): the store worker's read, one friend at a time. Those not known
    /// are left out; before the identity exists, every one.
    pub(super) fn horizons(&self, peers: &[String]) -> Horizons {
        if self.identity().is_err() {
            return Horizons::new();
        }
        let now_ms = bridge::now_ms();
        peers
            .iter()
            .filter_map(|peer| {
                (self.horizon)(&self.data_dir, peer, now_ms)
                    .map(|until| (peer.to_ascii_lowercase(), until))
            })
            .collect()
    }

    // ── The background program ──────────────────────────────────────────────

    /// Its Status now.
    pub(super) fn probe_node(&self) -> Probe {
        node::probe(&self.data_dir)
    }

    /// Starts the profile's raven-node unless one answers, as a send does, and
    /// tells whether this app started the one running after (only if none ran
    /// before and the one now is the process ext.rs said it spawned). Holds
    /// the node gate; refuses before the identity exists, because `raven-node
    /// service` would create one itself.
    pub(super) fn ensure_node(&self) -> Ensured {
        let _gate = self.node_gate();
        if let Err(no_identity) = self.identity() {
            return Ensured {
                result: Err(no_identity),
                after: node::probe(&self.data_dir),
                started_by_app: None,
                captured: String::new(),
                ring: 0..0,
            };
        }
        let before = node::probe(&self.data_dir);
        let first = stdio::ring_next_seq();
        let capture = JobCapture::start();
        let result = (self.ensure)(&self.data_dir);
        let captured = capture.finish();
        // Every line the start wrote to stderr is in the ring below `end`
        // once the reader reaches the sentinel written after them.
        let synced = workers::sync_stderr(SYNC_WAIT);
        let end = synced.unwrap_or_else(stdio::ring_next_seq);
        let lines = stdio::ring_lines(first..end);
        let notice = node::notice_pid(lines.iter().map(|(_, line)| line.as_str()));
        let after = node::probe(&self.data_dir);
        Ensured {
            result,
            started_by_app: node::started_by_app(before.reach, after.pid, notice, synced.is_some()),
            after,
            captured,
            ring: first..end,
        }
    }

    /// The start a send makes before it dials (ext.rs's, under the node gate,
    /// so it never races [`Controller::ensure_node`]).
    pub(super) fn ensure_for_send(&self) -> Result<(), String> {
        let _gate = self.node_gate();
        self.identity()?;
        (self.ensure)(&self.data_dir)
    }

    /// Stops the profile's raven-node as the stop rules allow (node.rs's
    /// `stop_plan`); the app asked the user first. Holds the node gate.
    pub(super) fn stop_node(&self, started_by_app: Option<u32>, managed: bool) -> Stopped {
        let _gate = self.node_gate();
        node::stop(&self.data_dir, started_by_app, managed)
    }

    // ── Lock (privacy pack PP.23) ───────────────────────────────────────────

    /// Raven's own login item for this profile (bridge.rs's
    /// `own_login_item`; read only), or [`NotAvailable`] where this build
    /// reads no login items.
    pub(super) fn login_item(&self) -> Result<Option<LoginItemView>, NotAvailable> {
        (self.login_item)(&self.data_dir)
    }

    /// LOCK's stop (PP.23), as `raven lock` does it without its questions
    /// and never turning the login item off (OD-11): the lock recorded
    /// first (`privacy.json` `locked_by_user`, so no send in another window
    /// starts Raven while it stops); with `own_item`, Raven's own login item
    /// unloaded for this login session; then the stop step for whatever
    /// still runs this profile (a node the item ran that is still going
    /// down, one ash started; `managed`: where this build reads no login
    /// items, a login service runs it, and the stop leaves it alone). When
    /// Raven still runs after it, the lock is taken back, as `raven lock`
    /// does. Holds the node gate.
    pub(super) fn lock_node(
        &self,
        started_by_app: Option<u32>,
        own_item: bool,
        managed: bool,
    ) -> Stopped {
        let _gate = self.node_gate();
        let recorded = self
            .identity()
            .and_then(|_| bridge::set_locked_by_user(&self.data_dir, true));
        if let Err(why) = recorded {
            return Stopped {
                outcome: StopOutcome::Failed(why),
                after: node::probe(&self.data_dir),
            };
        }
        if own_item {
            // A job that was not loaded fails to unload and is stopped all
            // the same: the stop below checks.
            let _ = (self.stop_for_session)(&self.data_dir);
        }
        let stopped = node::stop(&self.data_dir, started_by_app, managed);
        if !stopped.gone() {
            let _ = bridge::set_locked_by_user(&self.data_dir, false);
        }
        stopped
    }

    /// Opening the app is its way to start Raven again after its own Lock
    /// (PP.23): that lock is cleared (bridge.rs's `reopen_after_lock`), and
    /// whether Raven's login item stays off is kept for the privacy read
    /// (also when nothing was locked: review D-lock-tui-4).
    /// A lock `raven lock` set is kept, and this says true: the app asks
    /// first (UNLOCK, review E-harness-docs-ci-3). Raven's login item is
    /// never turned on or off here. Run once on the plain terminal, once the
    /// identity is there and before any start (mod.rs). A lock that can't
    /// be cleared stays: the start then says so.
    pub(super) fn reopen_after_lock(&self) -> bool {
        if self.identity().is_err() {
            return false;
        }
        match bridge::reopen_after_lock(&self.data_dir) {
            Ok(bridge::Reopened::Kept) => true,
            Ok(
                bridge::Reopened::Cleared { stays_off } | bridge::Reopened::NotLocked { stays_off },
            ) => {
                self.login_item_stays_off.store(stays_off, Ordering::SeqCst);
                false
            }
            Err(_) => false,
        }
    }

    /// UNLOCK's Start (review E-harness-docs-ci-3): the lock `raven lock`
    /// set is cleared (bridge.rs's `unlock_from_app`); the App then starts
    /// Raven as it always does. Whether Raven's login item stays off is kept
    /// for the privacy read. Holds the node gate.
    pub(super) fn unlock(&self) -> Result<(), String> {
        let _gate = self.node_gate();
        self.identity()?;
        let stays_off = bridge::unlock_from_app(&self.data_dir)?;
        self.login_item_stays_off.store(stays_off, Ordering::SeqCst);
        Ok(())
    }

    /// The vault check: a vault profile, and whether raven-node can't
    /// unlock it for want of a passphrase file (node.rs's `vault_check`).
    pub(super) fn vault_check(&self) -> node::Vault {
        node::vault_check(&self.data_dir)
    }

    /// The service log's last lines for NET's log view, raw, or why they
    /// can't be read (the profile's folder is not in the reason).
    pub(super) fn service_log_tail(&self) -> Result<Vec<String>, String> {
        node::service_log_tail(&self.data_dir, node::LOG_VIEW_LINES).map_err(|e| e.to_string())
    }

    // ── Sending ─────────────────────────────────────────────────────────────

    /// Sends `text` to the saved friend with key `pub_hex`, as `raven send
    /// --contact` does:
    ///
    /// 1. the background program is started first, under the node gate; if
    ///    it can't be, nothing is dialled and nothing written to the history;
    /// 2. a friend on the block list gets nothing;
    /// 3. the routes are planned as `raven send --contact` plans them, with
    ///    no address from the environment (OD-17): no Internet direct route
    ///    while you hide your IP from the friend, and the LAN addresses
    ///    learned for the friend tried after the saved one;
    /// 4. the send itself (bridge's mirror of cli.rs's).
    ///
    /// What it printed is captured.
    pub(super) fn send(&self, pub_hex: &str, text: &str) -> SendOutcome {
        let capture = JobCapture::start();
        let (result, learned_dial_used) = self.dial(pub_hex, text);
        SendOutcome {
            result,
            learned_dial_used,
            captured: capture.finish(),
        }
    }

    fn dial(&self, pub_hex: &str, text: &str) -> (SendResult, Option<String>) {
        let id = match self.identity() {
            Ok(id) => Arc::clone(id),
            Err(why) => return (SendResult::Failed(why), None),
        };
        if let Err(why) = self.ensure_for_send() {
            return (SendResult::NodeUnavailable(why), None);
        }
        let contacts = match bridge::load_contacts(&self.data_dir) {
            Ok(contacts) => contacts,
            Err(why) => return (SendResult::Failed(why), None),
        };
        let Some(friend) = contacts
            .iter()
            .find(|c| c.pub_hex.eq_ignore_ascii_case(pub_hex.trim()))
        else {
            return (SendResult::Failed(NOT_SAVED.into()), None);
        };
        match BlockList::load_checked(&self.data_dir) {
            Ok(blocks) if blocks.is_blocked(&friend.pub_hex) => {
                return (SendResult::Failed(BLOCKED.into()), None);
            }
            Ok(_) => {}
            Err(why) => return (SendResult::Failed(format!("block list: {why}")), None),
        }
        let plan = match bridge::plan_friend_send(&self.data_dir, friend) {
            Ok(plan) => plan,
            Err(why) => return (SendResult::Failed(why), None),
        };
        bridge::nearby_foreground(&self.data_dir, &plan.routes, &friend.pub_hex);
        match bridge::send_routes(
            &self.data_dir,
            &id,
            &plan.routes,
            &friend.pub_hex,
            SEND_LISTEN,
            text,
            &plan.unrecorded,
        ) {
            Ok(used) => {
                // Kept only once it reached and authenticated the friend there.
                let learned_used = (used.carrier == DialCarrier::Lan
                    && plan.learned_lan_dials.contains(&used.dial))
                .then(|| used.dial.clone());
                let route = Route {
                    carrier: Carrier::of_dial(used.carrier),
                    dial: Some(used.dial),
                    path: String::new(),
                };
                (SendResult::Delivered(route), learned_used)
            }
            Err(outcome) => (SendResult::Failed(outcome), None),
        }
    }

    /// `raven outbox retry <mid>`: raven-node tries the waiting message now.
    pub(super) fn retry(&self, mid: &str) -> Captured<()> {
        self.outbox_job(OutboxCmd::Retry { mid: mid.into() })
    }

    /// `raven outbox cancel <mid> --yes` (the App asked first): raven-node
    /// stops trying the message. What it printed says whether the friend may
    /// have it anyway (delivery.rs reads that).
    pub(super) fn cancel(&self, mid: &str) -> Captured<()> {
        self.outbox_job(OutboxCmd::Cancel {
            mid: mid.into(),
            yes: true,
        })
    }

    fn outbox_job(&self, cmd: OutboxCmd) -> Captured<()> {
        if let Err(why) = self.identity() {
            return Captured {
                result: Err(why),
                captured: String::new(),
            };
        }
        let capture = JobCapture::start();
        let result = bridge::cmd_outbox(&self.data_dir, cmd);
        Captured {
            result,
            captured: capture.finish(),
        }
    }

    /// Saves a new friend from a paste, with the name given here and the
    /// paste's routes, as `contact add --card` does.
    pub(super) fn save_friend(
        &self,
        friend: &FriendPreview,
        petname: &str,
        verify: &Verify,
    ) -> Captured<()> {
        self.contact_job(&friend.pub_hex, |data_dir| {
            if petname.trim().is_empty() {
                return Err(NO_NAME.into());
            }
            if self
                .me()
                .is_some_and(|me| me.pub_hex.eq_ignore_ascii_case(friend.pub_hex.trim()))
            {
                return Err(OWN_KEY.into());
            }
            bridge::add_contact_with_routes(
                data_dir,
                &friend.address,
                &friend.pub_hex,
                petname,
                "",
                verify.typed_fp(),
                &friend.lan,
                &friend.internet,
                friend.p2p.as_ref(),
            )?;
            bridge::keep_card_onion(data_dir, &friend.pub_hex, friend.onion.as_deref())
        })
    }

    /// A saved friend's routes from a new paste of their invite or card ([U]
    /// on AF-1, after the confirmation code). The name and the pin stay.
    pub(super) fn update_addresses(&self, friend: &FriendPreview) -> Captured<()> {
        self.contact_job(&friend.pub_hex, |data_dir| {
            self.saved(&friend.pub_hex)?;
            bridge::add_contact_with_routes(
                data_dir,
                &friend.address,
                &friend.pub_hex,
                "",
                "",
                None,
                &friend.lan,
                &friend.internet,
                friend.p2p.as_ref(),
            )?;
            bridge::keep_card_onion(data_dir, &friend.pub_hex, friend.onion.as_deref())
        })
    }

    /// Verifies a saved friend: pinned when `typed_fp` matches their code.
    /// The name and routes stay.
    pub(super) fn verify_existing(&self, pub_hex: &str, typed_fp: &str) -> Captured<()> {
        self.resave(pub_hex, "", Some(typed_fp))
    }

    /// A saved friend's name on this computer. The pin and routes stay.
    pub(super) fn rename(&self, pub_hex: &str, name: &str) -> Captured<()> {
        if name.trim().is_empty() {
            return self.contact_job(pub_hex, |_| Err(NO_NAME.into()));
        }
        self.resave(pub_hex, name, None)
    }

    /// `add_contact_with_routes` for a saved friend with no new route: an
    /// empty name keeps theirs, and no code keeps the pin as it is.
    fn resave(&self, pub_hex: &str, petname: &str, typed_fp: Option<&str>) -> Captured<()> {
        self.contact_job(pub_hex, |data_dir| {
            let friend = self.saved(pub_hex)?;
            bridge::add_contact_with_routes(
                data_dir,
                &friend.address,
                &friend.pub_hex,
                petname,
                "",
                typed_fp,
                "",
                "",
                None,
            )
        })
    }

    /// A saved friend's local-network address as the user typed it (E on
    /// CI), checked as `contact set-dial` checks it.
    pub(super) fn set_lan_address(&self, pub_hex: &str, raw: &str) -> Captured<()> {
        self.contact_job(pub_hex, |data_dir| {
            let dial = bridge::parse_lan_dial(raw)?;
            bridge::update_contact_lan_dial(data_dir, pub_hex, &dial)
        })
    }

    /// The address a send just reached a friend at, when it was not the
    /// saved one (as `raven send` keeps it).
    pub(super) fn save_learned_dial(&self, pub_hex: &str, dial: &str) -> Captured<()> {
        self.contact_job(pub_hex, |data_dir| {
            bridge::update_contact_lan_dial(data_dir, pub_hex, dial)
        })
    }

    /// Removes a saved friend and their pin, as `contact remove --yes` does
    /// (the App asked first). Messages with them stay.
    pub(super) fn remove(&self, pub_hex: &str) -> Captured<()> {
        self.contact_job(pub_hex, |data_dir| {
            let friend = self.saved(pub_hex)?;
            bridge::cmd_contact_remove(data_dir, &friend.address)
        })
    }

    /// Takes a key off the block list, as `contact unblock` does.
    pub(super) fn unblock(&self, pub_hex: &str) -> Captured<()> {
        self.contact_job(pub_hex, |data_dir| {
            bridge::cmd_contact_unblock(data_dir, pub_hex)
        })
    }

    // ── Privacy (privacy pack PP.21) ────────────────────────────────────────

    /// What SET's "Keep chats for", CI's privacy actions and Home's one-time
    /// notices need: [`NotAvailable`] before the identity exists, or when
    /// this profile can't use them (the App then hides them all). Small
    /// reads of `privacy.json`, no keystore call.
    pub(super) fn read_privacy(&self) -> Result<PrivacyRead, NotAvailable> {
        self.identity().map_err(|_| NotAvailable)?;
        Ok(PrivacyRead {
            keep: bridge::chat_keep(&self.data_dir)?,
            notices: bridge::privacy_notices(&self.data_dir),
            disk_needed: bridge::disk_space_needed(&self.data_dir),
            login_item_stays_off: self.login_item_stays_off.load(Ordering::SeqCst),
        })
    }

    /// Saves "Keep chats for", as `raven chats keep` does.
    pub(super) fn set_chat_keep(&self, keep: ChatKeepView) -> Result<(), String> {
        self.identity()?;
        bridge::set_chat_keep(&self.data_dir, keep)
    }

    /// One of Home's one-time notices was shown and the user said OK: the
    /// CLI does not say it again.
    pub(super) fn mark_notice_shown(&self, notice: Notice) {
        if self.identity().is_ok() {
            bridge::mark_notice_shown(&self.data_dir, notice);
        }
    }

    // ── Security notices (Phase 6b P6.31) ───────────────────────────────

    /// The security notices and the friends sending is paused to, for the
    /// header chip, the friend list, Home's banner, SEC, NET and CI: read
    /// once a minute (the poller) and after a change. A read: the ledger is
    /// never created by it. [`NotAvailable`] before the identity exists.
    pub(super) fn read_security(&self) -> Result<SecurityView, NotAvailable> {
        self.identity().map_err(|_| NotAvailable)?;
        Ok(bridge::security_view(&self.data_dir))
    }

    /// R on SEC: the notice with the ledger's `id` is resolved.
    pub(super) fn resolve_notice(&self, id: i64) -> Result<bool, String> {
        self.identity()?;
        bridge::resolve_notice(&self.data_dir, id)
    }

    /// P: sending to the friend `pub_hex` paused (`on`) or resumed, in a
    /// critical section (it writes the policy); whether it is paused now.
    pub(super) fn set_send_hold(&self, pub_hex: &str, on: bool) -> Result<bool, String> {
        self.identity()?;
        let _critical = Critical::enter();
        bridge::set_send_hold(&self.data_dir, pub_hex, on)
    }

    /// After a match in VF with `typed` (the words or the old code): the
    /// friend's open security notices are resolved, and whether the older
    /// method may be accepted is read (`raven contact verify`'s steps).
    pub(super) fn resolve_on_match(&self, pub_hex: &str, typed: &str) -> Result<Resolved, String> {
        self.identity()?;
        bridge::resolve_on_match(&self.data_dir, pub_hex, typed)
    }

    /// What a first verification of a saved friend resolved, for its toast:
    /// none when nothing was open, or the ledger could not be changed (the
    /// friend is verified either way).
    pub(super) fn resolved_notes(&self, pub_hex: &str, typed: &str) -> Vec<String> {
        match self.resolve_on_match(pub_hex, typed) {
            Ok(resolved) if resolved.notices > 0 => {
                let name = self
                    .saved(pub_hex)
                    .map(|friend| sanitize_terminal_line(&friend.label))
                    .unwrap_or_default();
                vec![bridge::resolved_by_verify(&name, resolved.notices)]
            }
            _ => Vec::new(),
        }
    }

    /// 'accept' typed after "Check again" matched with the words `typed`:
    /// the friend's older security method is accepted, in a critical
    /// section (it writes their capability floor).
    pub(super) fn accept_older_method(&self, pub_hex: &str, typed: &str) -> Result<bool, String> {
        self.identity()?;
        let _critical = Critical::enter();
        bridge::accept_older_method(&self.data_dir, pub_hex, typed)
    }

    /// Deletes the chat with the friend `pub_hex` on this computer, as
    /// `raven chats delete --yes` does (the App asked for the typed word
    /// first), in a critical section with what it prints captured. Messages
    /// still waiting to be sent to them stay, and are counted.
    pub(super) fn delete_chat(&self, pub_hex: &str) -> Captured<DeleteChatOutcome> {
        if let Err(why) = self.identity() {
            return Captured {
                result: Err(why),
                captured: String::new(),
            };
        }
        let _critical = Critical::enter();
        let capture = JobCapture::start();
        let key = pub_hex.trim().to_ascii_lowercase();
        let result = bridge::delete_chat(&self.data_dir, &key);
        if result.is_ok() {
            // Its read marker goes with it, from the file too: the App's
            // next save would otherwise take it back from there.
            let _ = read_marks::forget(&self.data_dir, &identity_ready(), &key);
        }
        Captured {
            result,
            captured: capture.finish(),
        }
    }

    /// Forgets a saved friend's addresses, as `contact forget-address --yes`
    /// does (the App asked first): their name, pin and the rest stay. What
    /// Raven learned about reaching them that could not be forgotten comes
    /// back, one note each (review D-lock-tui-8).
    pub(super) fn forget_address(&self, pub_hex: &str) -> Captured<Vec<String>> {
        self.contact_job_notes(pub_hex, |data_dir| {
            let friend = self.saved(pub_hex)?;
            bridge::forget_address(data_dir, &friend.pub_hex)
        })
    }

    // ── Erase (privacy pack PP.22) ──────────────────────────────────────────

    /// What ERASE lists: what erasing this profile deletes, or why erase
    /// refuses it. Reads only.
    pub(super) fn erase_plan(&self) -> Result<ErasePlanView, String> {
        self.identity()?;
        bridge::erase_plan(&self.data_dir)
    }

    /// Erases this profile as `raven erase` does (the App asked for the
    /// typed word and waited until no other job ran), in a critical section
    /// with what it prints captured. Once the erase can no longer be taken
    /// back (the marker is down, the node gone), and before the first key
    /// or file goes, this app's hold on the profile ends: every later job
    /// refuses, every save is a no-op, and the at-rest keys cached in this
    /// process are forgotten. Nothing erased (Raven still runs): the
    /// profile is this app's again as it was.
    pub(super) fn erase(&self) -> EraseEnd {
        if self.closed() {
            return EraseEnd::NotErased(ERASED.to_owned());
        }
        if let Err(why) = self.identity() {
            return EraseEnd::NotErased(why);
        }
        let _critical = Critical::enter();
        let capture = JobCapture::start();
        let end = (self.erase)(&self.data_dir, &mut || self.close());
        let _ = capture.finish();
        if matches!(end, EraseEnd::Ran { .. }) {
            self.close();
        }
        end
    }

    /// The erase began: nothing of this app opens the profile again.
    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        bridge::forget_profile_keys(&self.data_dir);
    }

    // ── Groups (lab: docs/design/2026-10-groups.md) ─────────────────────────

    /// Every group, the newest activity first, and the chat of `open`. With
    /// `refresh`, first what `raven group show` does: the copies' delivery
    /// read from the chat history, and the work waiting parked
    /// (`group::run_pending`); that may write groups.json, so the stamp is
    /// taken after it, just before the read. Reads only without it.
    pub(super) fn groups_read(&self, open: Option<GroupId>, refresh: bool) -> GroupsRead {
        let path = group::store::groups_path(&self.data_dir);
        let id = match self.identity() {
            Ok(id) => Arc::clone(id),
            Err(why) => {
                return GroupsRead {
                    groups: Err(why.clone()),
                    open: open.map(|group| (group, Err(why))),
                    stamp: FileStamp::of(&path),
                }
            }
        };
        if refresh {
            let _ = group::run_pending(&self.data_dir, &id, bridge::now_ms());
        }
        let stamp = FileStamp::of(&path);
        GroupsRead {
            groups: group::list(&self.data_dir).map_err(|e| e.to_string()),
            open: open.map(|group| (group, self.group_chat(&group))),
            stamp,
        }
    }

    /// One group's members and newest messages, names resolved.
    fn group_chat(&self, group: &GroupId) -> Result<GroupChat, String> {
        let view = group::view(&self.data_dir, group).map_err(|e| e.to_string())?;
        let history = group::history(&self.data_dir, group, None, GROUP_MESSAGES)
            .map_err(|e| e.to_string())?;
        let names = group::friend_names(&self.data_dir);
        let messages = history
            .into_iter()
            .map(|m| GroupMessage {
                id: m.id,
                mine: m.mine,
                author: view.name_of(&m.from, &names),
                via: m.via.map(|via| view.name_of(&via, &names)),
                body: m.body,
                at_ms: m.received_ms,
                sent_ms: m.sent_ms,
                path: m.path,
                lines: m
                    .lines
                    .iter()
                    .map(|(key, state, via)| MemberLine {
                        name: view.name_of(key, &names),
                        state: state.clone(),
                        relayed: via == group::store::VIA_RELAY,
                    })
                    .collect(),
                delivered: m.delivered,
                total: m.total,
            })
            .collect();
        Ok(GroupChat { view, messages })
    }

    /// Every message of `group` received until now is read here.
    pub(super) fn group_mark_read(&self, group: &GroupId) -> Result<(), String> {
        self.identity()?;
        group::mark_read(&self.data_dir, group, bridge::now_ms())
            .map(drop)
            .map_err(|e| e.to_string())
    }

    /// `raven group send`: `text` to every member, one copy parked for each
    /// friend among them, then raven-node is asked to send them.
    pub(super) fn group_send(&self, group: &GroupId, text: &str) -> GroupDone<[u8; 16]> {
        let id = match self.identity() {
            Ok(id) => Arc::clone(id),
            Err(why) => {
                return GroupDone {
                    result: Err(why),
                    kicked: false,
                }
            }
        };
        let result = group::send(&self.data_dir, &id, group, text, bridge::now_ms())
            .map(|report| report.id)
            .map_err(|e| e.sentence());
        GroupDone {
            kicked: result.is_ok() && self.group_kick(),
            result,
        }
    }

    /// `raven group create|add|remove|leave`, then raven-node is asked to
    /// send what the change made. The group's id, or raven-core's sentence.
    pub(super) fn group_change(&self, change: &GroupChange) -> GroupDone<GroupId> {
        let id = match self.identity() {
            Ok(id) => Arc::clone(id),
            Err(why) => {
                return GroupDone {
                    result: Err(why),
                    kicked: false,
                }
            }
        };
        let (dir, now) = (self.data_dir.as_path(), bridge::now_ms());
        let result = match change {
            GroupChange::Create { name, members } => group::create(dir, &id, name, members, now),
            GroupChange::Add { group, members } => {
                group::add_members(dir, &id, group, members, now).map(|_| *group)
            }
            GroupChange::Remove { group, member, .. } => {
                group::remove_members(dir, &id, group, &[*member], now).map(|_| *group)
            }
            GroupChange::Leave { group } => group::leave(dir, &id, group, now).map(|()| *group),
        }
        .map_err(|e| e.sentence());
        GroupDone {
            kicked: result.is_ok() && self.group_kick(),
            result,
        }
    }

    /// Asks raven-node to send what was parked; when none answers, starts
    /// it as a send does (under the node gate) and asks again. Whether one
    /// took it.
    fn group_kick(&self) -> bool {
        bridge::outbox_kick(&self.data_dir)
            || (self.ensure_for_send().is_ok() && bridge::outbox_kick(&self.data_dir))
    }

    /// The saved friend with this key.
    fn saved(&self, pub_hex: &str) -> Result<ContactView, String> {
        bridge::contact_views(&self.data_dir)?
            .into_iter()
            .find(|c| c.pub_hex.eq_ignore_ascii_case(pub_hex.trim()))
            .ok_or_else(|| NOT_SAVED.to_owned())
    }

    /// Runs one change to contacts.json or the block list about the friend
    /// `subject`: only once the identity exists, in a critical section, with
    /// what it prints captured. The security code of every friend not
    /// verified before or after the change is taken out of the error and the
    /// captured text, and the subject's own unless they are verified now (so
    /// a 'got <code>' in a refused pin never shows).
    fn contact_job(
        &self,
        subject: &str,
        job: impl FnOnce(&Path) -> Result<(), String>,
    ) -> Captured<()> {
        let done = self.contact_job_notes(subject, |data_dir| job(data_dir).map(|()| Vec::new()));
        Captured {
            result: done.result.map(drop),
            captured: done.captured,
        }
    }

    /// [`Controller::contact_job`] for a change that comes back with notes
    /// (what it could not do in full): the codes are taken out of them too.
    fn contact_job_notes(
        &self,
        subject: &str,
        job: impl FnOnce(&Path) -> Result<Vec<String>, String>,
    ) -> Captured<Vec<String>> {
        if let Err(why) = self.identity() {
            return Captured {
                result: Err(why),
                captured: String::new(),
            };
        }
        let _critical = Critical::enter();
        let before = bridge::contact_views(&self.data_dir).unwrap_or_default();
        let capture = JobCapture::start();
        let result = job(&self.data_dir);
        let captured = capture.finish();
        let after = bridge::contact_views(&self.data_dir).unwrap_or_default();
        let is_subject = |c: &ContactView| c.pub_hex.eq_ignore_ascii_case(subject.trim());
        let verified_now = after.iter().any(|c| c.pinned && is_subject(c));
        let mut hidden: Vec<String> = before
            .iter()
            .chain(&after)
            .filter(|c| !c.pinned && !(verified_now && is_subject(c)))
            .map(|c| c.fingerprint.clone())
            .collect();
        if !verified_now {
            hidden.extend(bridge::fingerprint_of(subject));
        }
        Captured {
            result: result
                .map(|notes| notes.iter().map(|n| hide_codes(n, &hidden)).collect())
                .map_err(|e| hide_codes(&e, &hidden)),
            captured: hide_codes(&captured, &hidden),
        }
    }
}

impl IdentityState {
    fn ready(id: &Identity) -> IdentityState {
        IdentityState::Ready {
            me: bridge::me_view(id),
        }
    }
}

/// `text` with every one of `codes` replaced by [`HIDDEN_CODE`].
fn hide_codes(text: &str, codes: &[String]) -> String {
    let mut text = text.to_owned();
    // A key that did not parse has `—` for a code: nothing to hide.
    for code in codes.iter().filter(|code| looks_like_code(code)) {
        text = text.replace(code.as_str(), HIDDEN_CODE);
    }
    text
}

/// A security code as raven-core writes it: letters and digits in groups
/// joined by '-' (e.g. `If4x-36FU-omFi`).
fn looks_like_code(code: &str) -> bool {
    code.len() >= 8 && code.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// A friend's invite or card from pasted text, pure: no file, no key store.
///
/// Persian and Arabic-Indic digits are read as 0-9 (an address typed with a
/// Persian keyboard) and line breaks are normalised, then each candidate
/// goes through cli.rs's `parse_card_or_invite`, in order: the lines joined
/// with a space, joined with nothing (a line a terminal broke inside a
/// word), then each line on its own (a whoami block). Exactly one identity
/// must come out; the first candidate that parses gives the routes. The
/// user's own key, compared with `me_pub_hex` (MeView's), is refused.
pub(super) fn parse_friend_paste(
    text: &str,
    me_pub_hex: &str,
) -> Result<FriendPreview, PasteProblem> {
    if text.len() > PASTE_MAX_BYTES {
        return Err(PasteProblem::NotACard(format!(
            "more than {PASTE_MAX_BYTES} bytes: longer than any invite or card"
        )));
    }
    let text = bridge::fold_code_digits(text)
        .replace("\r\n", "\n")
        .replace('\r', "\n");
    let lines: Vec<String> = text
        .lines()
        .map(|line| line.replace('\t', " ").trim().to_owned())
        .filter(|line| !line.is_empty())
        .collect();
    if lines.is_empty() {
        return Err(PasteProblem::NotACard("nothing was pasted".into()));
    }
    if lines.len() > PASTE_MAX_LINES {
        return Err(PasteProblem::NotACard(format!(
            "more than {PASTE_MAX_LINES} lines: an invite or a card is one line"
        )));
    }
    let mut candidates = vec![lines.join(" "), lines.concat()];
    if lines.len() > 1 {
        candidates.extend(lines);
    }
    candidates.dedup();

    let mut found: Option<FriendPreview> = None;
    let mut tampered: Option<String> = None;
    let mut card_like: Option<String> = None;
    let mut other: Option<String> = None;
    for candidate in &candidates {
        match bridge::parse_card_or_invite(candidate) {
            Ok(friend) => match &found {
                None => found = Some(friend),
                Some(first) if first.pub_hex == friend.pub_hex => {}
                Some(_) => {
                    return Err(PasteProblem::NotACard(
                        "the pasted text holds more than one Raven identity".into(),
                    ))
                }
            },
            Err(why) if TAMPER_MARKS.iter().any(|mark| why.contains(mark)) => {
                tampered.get_or_insert(why);
            }
            Err(why)
                if candidate.starts_with("raven-card/")
                    || bridge::parse_raven_invite(candidate).is_some() =>
            {
                card_like.get_or_insert(why);
            }
            Err(why) => {
                other.get_or_insert(why);
            }
        }
    }
    match found {
        Some(friend) if friend.pub_hex.eq_ignore_ascii_case(me_pub_hex.trim()) => {
            Err(PasteProblem::OwnInvite)
        }
        Some(friend) => Ok(friend),
        None => Err(match tampered {
            Some(why) => PasteProblem::Tampered(why),
            None => PasteProblem::NotACard(card_like.or(other).unwrap_or_default()),
        }),
    }
}

/// The name typed for the friend with key `pub_hex`, against the other saved
/// friends' names: as cli.rs compares petnames (sanitized, ignoring case),
/// and a verified friend first, whose name also clashes with one that only
/// looks the same ([`fold_confusables`]).
pub(super) fn check_name(contacts: &[ContactView], name: &str, pub_hex: &str) -> NameCheck {
    let want = name_key(name);
    if want.is_empty() {
        return NameCheck::Empty;
    }
    let folded = fold_confusables(&want);
    let others = || {
        contacts
            .iter()
            .filter(|c| !c.pub_hex.eq_ignore_ascii_case(pub_hex.trim()))
    };
    if let Some(verified) = others().find(|c| {
        let theirs = name_key(&c.label);
        c.pinned && (theirs == want || fold_confusables(&theirs) == folded)
    }) {
        return NameCheck::VerifiedClash(verified.pub_hex.clone());
    }
    match others().find(|c| name_key(&c.label) == want) {
        Some(other) => NameCheck::Taken(other.pub_hex.clone()),
        None => NameCheck::Free,
    }
}

/// What to point out about a name [`check_name`] lets through: letters of
/// two alphabets, else another friend's name it looks the same as.
pub(super) fn name_warning(
    contacts: &[ContactView],
    name: &str,
    pub_hex: &str,
) -> Option<NameWarning> {
    let want = name_key(name);
    if want.is_empty() {
        return None;
    }
    if mixed_script(&want) {
        return Some(NameWarning::MixedScript);
    }
    let folded = fold_confusables(&want);
    contacts
        .iter()
        .filter(|c| !c.pub_hex.eq_ignore_ascii_case(pub_hex.trim()))
        .find(|c| {
            let theirs = name_key(&c.label);
            theirs != want && fold_confusables(&theirs) == folded
        })
        .map(|c| NameWarning::LooksLike(c.pub_hex.clone()))
}

/// A name as names are compared: sanitized as cli.rs saves a petname, and in
/// lower case.
fn name_key(name: &str) -> String {
    sanitize_terminal_line(name.trim()).to_lowercase()
}

/// `name` (lower case) with each look-alike letter of [`CONFUSABLES`] as the
/// Latin letter it passes for.
pub(super) fn fold_confusables(name: &str) -> String {
    name.chars()
        .map(|c| {
            CONFUSABLES
                .iter()
                .find(|(from, _)| *from == c)
                .map_or(c, |(_, to)| *to)
        })
        .collect()
}

/// Whether `name` has letters of more than one of the Latin, Cyrillic and
/// Greek alphabets.
pub(super) fn mixed_script(name: &str) -> bool {
    let (mut latin, mut cyrillic, mut greek) = (false, false, false);
    for c in name.chars().filter(|c| c.is_alphabetic()) {
        match c {
            'a'..='z' | 'A'..='Z' | '\u{00C0}'..='\u{024F}' | '\u{1E00}'..='\u{1EFF}' => {
                latin = true
            }
            '\u{0400}'..='\u{052F}' => cyrillic = true,
            '\u{0370}'..='\u{03FF}' | '\u{1F00}'..='\u{1FFF}' => greek = true,
            _ => {}
        }
    }
    u8::from(latin) + u8::from(cyrillic) + u8::from(greek) > 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use raven_core::chat_history::{BlockList, ChatHistory, ChatHistoryEntry};

    /// This computer's address as the e2e test injects it.
    fn loopback_egress() -> Option<Ipv4Addr> {
        Some(Ipv4Addr::LOCALHOST)
    }

    fn offline() -> Option<Ipv4Addr> {
        None
    }

    /// A fresh profile whose identity the controller created (locked-file).
    fn profile() -> (tempfile::TempDir, Controller) {
        testkit::lab_backends();
        let dir = testkit::short_dir();
        let controller = Controller::with_egress(dir.path(), loopback_egress);
        let created = controller.create_identity().result.expect("create");
        assert_eq!(created.prekey_warning, None);
        (dir, controller)
    }

    /// Someone with a fixed key, and their card with `lan` (or none).
    fn someone(seed: u8, lan: &str) -> (MeView, String) {
        let id = Identity::from_seed(&[seed; 32]);
        let card = bridge::format_card_with(&id, "", lan, None).expect("a card");
        (bridge::me_view(&id), card)
    }

    fn saved(controller: &Controller, pub_hex: &str) -> Option<ContactView> {
        controller
            .load_contacts()
            .expect("contacts")
            .into_iter()
            .find(|c| c.pub_hex == pub_hex)
    }

    /// A friend added the way the App adds one: paste, a name, then the save
    /// the App asks for once the codes checked out.
    fn add(controller: &Controller, card: &str, name: &str, verify: Verify) {
        let me = controller.me().expect("an identity");
        let friend = parse_friend_paste(card, &me.pub_hex).expect("a friend's card");
        controller
            .save_friend(&friend, name, &verify)
            .result
            .expect("save");
    }

    /// Neither the code nor any of its groups of 4.
    fn assert_no_code(text: &str, code: &str) {
        assert!(!text.contains(code), "the code {code} is in:\n{text}");
        for group in code.split('-') {
            assert!(!text.contains(group), "a group of {code} is in:\n{text}");
        }
    }

    fn entries(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .expect("read the profile")
            .map(|e| {
                e.expect("an entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names.sort();
        names
    }

    #[test]
    fn a_new_identity_shares_its_invite_and_cards() {
        let (dir, controller) = profile();
        let me = controller.me().expect("me");
        assert_eq!(controller.my_invite().as_deref(), Some(me.invite.as_str()));
        let invite = bridge::parse_raven_invite(&me.invite)
            .expect("an invite line")
            .expect("a valid invite");
        assert_eq!(
            (invite.address, invite.pub_hex, invite.fingerprint),
            (
                me.address.clone(),
                me.pub_hex.clone(),
                me.fingerprint.clone()
            )
        );
        // Creating again, or loading in a second session, finds the same one.
        let again = controller.create_identity().result.expect("again");
        assert_eq!(again.me, me);
        match Controller::new(dir.path()).load_identity() {
            IdentityState::Ready { me: loaded, .. } => assert_eq!(loaded, me),
            other => panic!("{other:?}"),
        }

        // A node bound to every address, with this computer at 127.0.0.1.
        let lan = controller.card_lan("0.0.0.0:7420").expect("a lan");
        assert_eq!(lan, "127.0.0.1:7420");
        let card = controller.my_card(Some(&lan)).expect("card");
        assert!(card.contains(" lan=127.0.0.1:7420"), "{card}");
        assert!(card.len() <= bridge::CARD_MAX_LEN);
        let back = bridge::parse_card_or_invite(&card).expect("parses");
        assert_eq!(
            (back.pub_hex, back.fingerprint, back.lan),
            (me.pub_hex.clone(), me.fingerprint.clone(), lan)
        );
        // Listening on this computer only, or sharing turned off: no lan=.
        assert_eq!(
            controller.card_lan("127.0.0.1:7420"),
            Err(NoCardLan::LocalOnly)
        );
        assert_eq!(controller.card_lan("[::1]:7420"), Err(NoCardLan::LocalOnly));
        let plain = controller.my_card(None).expect("card");
        assert!(!plain.contains("lan="), "{plain}");
        assert_eq!(
            bridge::parse_card_or_invite(&plain)
                .expect("parses")
                .pub_hex,
            me.pub_hex
        );
        // A specific bound address is the one shared.
        assert_eq!(
            controller.card_lan("192.168.1.20:7424").as_deref(),
            Ok("192.168.1.20:7424")
        );
        let unplugged = Controller::with_egress(dir.path(), offline);
        assert_eq!(
            unplugged.card_lan("0.0.0.0:7420"),
            Err(NoCardLan::NoAddress)
        );
        for junk in ["", "7420", "localhost:7420", "0.0.0.0:0", "lan=1.2.3.4:5"] {
            assert_eq!(controller.card_lan(junk), Err(NoCardLan::Unknown), "{junk}");
        }
        assert!(controller.my_card(Some("not an address")).is_err());
    }

    /// Review D-2: while the running node uses the key of epoch 41 (IPC
    /// status `rotation`), my card's `p2p=` names that epoch's PeerId, as
    /// `whoami --card` does, never the fixed one it left; without a
    /// rotation it stays the fixed PeerId.
    #[test]
    fn my_card_names_the_running_nodes_epoch_peer_id() {
        let (dir, controller) = profile();
        raven_core::node_policy::save_policy(
            dir.path(),
            &raven_core::NodePolicy {
                p2p_listen: "7423".into(),
                ..raven_core::NodePolicy::default()
            },
        )
        .unwrap();
        let id = Arc::clone(controller.identity().expect("id"));
        let fixed = raven_core::p2p_route::local_peer_id(&id);
        let p2p_of = |card: &str| {
            bridge::parse_card_or_invite(card)
                .expect("parses")
                .p2p
                .expect("a p2p route")
                .peer_id
        };
        assert_eq!(p2p_of(&controller.my_card(None).expect("card")), fixed);
        let rotating = Controller::with_rotation_epoch(dir.path(), |_| Some(41));
        assert!(matches!(
            rotating.load_identity(),
            IdentityState::Ready { .. }
        ));
        let card = rotating.my_card(None).expect("card");
        assert_eq!(
            p2p_of(&card),
            raven_core::peer_rotation::epoch_peer_id(&id, 41)
        );
        assert!(!card.contains("p2pn="), "a /2 card: {card}");
    }

    #[test]
    fn pastes_parse_like_contact_add_card() {
        let (_dir, controller) = profile();
        let me = controller.me().expect("me");
        let (bob, card) = someone(0xB0, "192.168.1.30:7420");
        let whole = parse_friend_paste(&card, &me.pub_hex).expect("one line");
        assert_eq!(
            (whole.pub_hex.as_str(), whole.lan.as_str()),
            (bob.pub_hex.as_str(), "192.168.1.30:7420")
        );
        assert_eq!(whole.fingerprint, bob.fingerprint);

        // A terminal broke the line at a space, or inside a word.
        let at_space = card.find(" fingerprint=").expect("a fingerprint field");
        let mid_word = card.find("pub_hex=").expect("a key field") + 20;
        for text in [
            format!("{}\n{}", &card[..at_space], &card[at_space + 1..]),
            format!("  {}\r\n{}  \n", &card[..mid_word], &card[mid_word..]),
        ] {
            assert_eq!(
                parse_friend_paste(&text, &me.pub_hex).as_ref(),
                Ok(&whole),
                "{text}"
            );
        }

        // A whole `ash whoami` block: its invite line, with no routes.
        let block = format!(
            "address       {}\nfingerprint   {}\npub_hex       {}\ninvite        {}\n",
            bob.address, bob.fingerprint, bob.pub_hex, bob.invite
        );
        let from_block = parse_friend_paste(&block, &me.pub_hex).expect("whoami block");
        assert_eq!(from_block.pub_hex, bob.pub_hex);
        assert!(from_block.lan.is_empty() && from_block.p2p.is_none());

        for nothing in ["", " \n\t\r\n"] {
            assert!(matches!(
                parse_friend_paste(nothing, &me.pub_hex),
                Err(PasteProblem::NotACard(_))
            ));
        }
        let long = format!("{card}\n").repeat(PASTE_MAX_LINES + 1);
        assert!(matches!(
            parse_friend_paste(&long, &me.pub_hex),
            Err(PasteProblem::NotACard(_))
        ));
    }

    #[test]
    fn a_paste_reads_persian_and_arabic_indic_digits_as_0_to_9() {
        let (_dir, controller) = profile();
        let me = controller.me().expect("me");
        let lan = "192.168.1.30:7420";
        let (bob, card) = someone(0xB0, lan);
        let whole = parse_friend_paste(&card, &me.pub_hex).expect("Bob's card");
        // Its address typed again with a Persian keyboard.
        let retyped = card.replace(lan, &testkit::digits_from(lan, testkit::PERSIAN_ZERO));
        assert_ne!(retyped, card);
        assert_eq!(parse_friend_paste(&retyped, &me.pub_hex), Ok(whole));
        // Every digit of the card, or of the invite, as Arabic-Indic digits.
        for text in [&card, &bob.invite] {
            let arabic = testkit::digits_from(text, testkit::ARABIC_INDIC_ZERO);
            let friend = parse_friend_paste(&arabic, &me.pub_hex).expect("read as 0-9");
            assert_eq!(friend.pub_hex, bob.pub_hex);
        }
        // My own invite is still mine, however its digits are written.
        assert_eq!(
            parse_friend_paste(
                &testkit::digits_from(&me.invite, testkit::PERSIAN_ZERO),
                &me.pub_hex
            ),
            Err(PasteProblem::OwnInvite)
        );
    }

    #[test]
    fn own_invite_is_refused_without_asking_the_key_store() {
        let (dir, controller) = profile();
        let me = controller.me().expect("me");
        let lock = dir.path().join(".identity_store.lock.sqlite");
        let modified = || std::fs::metadata(&lock).and_then(|m| m.modified()).ok();
        let before = modified();
        assert!(
            before.is_some(),
            "no identity lock in {:?}",
            entries(dir.path())
        );
        let card = controller.my_card(None).expect("card");
        for (text, mine) in [
            (me.invite.as_str(), me.pub_hex.clone()),
            (card.as_str(), me.pub_hex.clone()),
            (me.invite.as_str(), me.pub_hex.to_uppercase()),
        ] {
            assert_eq!(
                parse_friend_paste(text, &mine),
                Err(PasteProblem::OwnInvite),
                "{text}"
            );
        }
        assert_eq!(modified(), before);
        // The CLI refuses it too, in its own words.
        assert!(bridge::OWN_INVITE_REFUSAL.contains("YOUR OWN invite"));
        // A save of the own key is refused as well (a backstop).
        let own = bridge::parse_card_or_invite(&card).expect("parses");
        let refused = controller.save_friend(&own, "Me", &Verify::Unpinned);
        assert_eq!(refused.result, Err(OWN_KEY.to_owned()));
        assert!(controller.load_contacts().expect("contacts").is_empty());
    }

    #[test]
    fn tampered_pastes_are_refused() {
        let (_dir, controller) = profile();
        let me = controller.me().expect("me");
        let (bob, card) = someone(0xB0, "192.168.1.30:7420");
        let (eve, _) = someone(0xE0, "");
        for forged in [
            // Bob's address with Eve's key.
            format!("raven:{}:{}", bob.address, eve.pub_hex),
            format!("invite        raven:{}:{}", bob.address, eve.pub_hex),
            card.replace(&bob.pub_hex, &eve.pub_hex),
            // Bob's key with Eve's code.
            card.replace(&bob.fingerprint, &eve.fingerprint),
        ] {
            match parse_friend_paste(&forged, &me.pub_hex) {
                Err(PasteProblem::Tampered(why)) => assert_no_code(&why, &bob.fingerprint),
                other => panic!("{forged}: {other:?}"),
            }
        }
        // Two people in one paste, or no card at all.
        for text in [
            format!("{}\n{}", bob.invite, eve.invite),
            "hello, it's Bob".to_owned(),
            "raven-card/9 address=x".to_owned(),
        ] {
            assert!(
                matches!(
                    parse_friend_paste(&text, &me.pub_hex),
                    Err(PasteProblem::NotACard(_))
                ),
                "{text}"
            );
        }
    }

    #[test]
    fn saving_takes_both_codes_and_never_shows_an_unverified_code() {
        let (_dir, controller) = profile();
        let me = controller.me().expect("me");
        let (bob, card) = someone(0xB0, "192.168.1.30:7420");
        let friend = parse_friend_paste(&card, &me.pub_hex).expect("Bob's card");
        let code = bridge::new_confirm_code(&mut rand::thread_rng());

        // The right security code but a wrong confirmation code: the App asks
        // for no save, so nothing is saved.
        assert!(bridge::fingerprint_matches(
            &bob.fingerprint,
            &friend.fingerprint
        ));
        assert!(!bridge::confirm_code_matches("WRONG", &code));
        assert!(controller.load_contacts().expect("contacts").is_empty());

        // The code in the wrong case: the App gives the case hint, and the
        // core refuses it too, without showing Bob's code.
        let wrong_case: String = bob
            .fingerprint
            .chars()
            .map(|c| {
                if c.is_ascii_uppercase() {
                    c.to_ascii_lowercase()
                } else {
                    c.to_ascii_uppercase()
                }
            })
            .collect();
        assert!(bridge::fingerprint_case_only_mismatch(
            &wrong_case,
            &friend.fingerprint
        ));
        let refused = controller.save_friend(
            &friend,
            "Bob",
            &Verify::Pinned {
                typed_fp: wrong_case,
            },
        );
        let why = refused.result.expect_err("a wrong-case code pins nothing");
        assert!(why.contains(bridge::FINGERPRINT_CASE_HINT), "{why}");
        assert!(why.contains(&format!("got {HIDDEN_CODE}")), "{why}");
        assert!(!why.contains(&bob.fingerprint), "{why}");
        assert_eq!(saved(&controller, &bob.pub_hex), None);

        // Later (not verified), after the confirmation code: saved unpinned,
        // with the card's address, and Bob's code nowhere in what it printed.
        assert!(bridge::confirm_code_matches(&code.to_lowercase(), &code));
        let later = controller.save_friend(&friend, "Bob", &Verify::Unpinned);
        later.result.expect("saved unverified");
        assert!(
            later.captured.contains("contact saved"),
            "{}",
            later.captured
        );
        assert!(later.captured.contains(HIDDEN_CODE), "{}", later.captured);
        assert_no_code(&later.captured, &bob.fingerprint);
        let row = saved(&controller, &bob.pub_hex).expect("Bob");
        assert!(!row.pinned && !row.blocked);
        assert_eq!(
            (
                row.label.as_str(),
                row.lan_dial.as_str(),
                row.address.as_str()
            ),
            ("Bob", "192.168.1.30:7420", bob.address.as_str())
        );
        assert_eq!(row.fingerprint, bob.fingerprint);

        // Verified later with the right code: pinned, name and routes as
        // they were. Now the code may show.
        let verified = controller.verify_existing(&bob.pub_hex, &bob.fingerprint);
        verified.result.expect("verified");
        assert!(verified.captured.contains(&bob.fingerprint));
        let pinned = saved(&controller, &bob.pub_hex).expect("Bob");
        assert!(pinned.pinned);
        assert_eq!(
            pinned,
            ContactView {
                pinned: true,
                ..row
            }
        );
    }

    #[test]
    fn rename_and_address_edits_keep_the_pin() {
        let (_dir, controller) = profile();
        let (bob, card) = someone(0xB0, "192.168.1.30:7420");
        let (carol, carol_card) = someone(0xC0, "");
        add(
            &controller,
            &card,
            "Bob",
            Verify::Pinned {
                typed_fp: bob.fingerprint.clone(),
            },
        );
        add(&controller, &carol_card, "Carol", Verify::Unpinned);
        let row = saved(&controller, &bob.pub_hex).expect("Bob");
        assert!(row.pinned);

        controller
            .rename(&bob.pub_hex, "Robert")
            .result
            .expect("rename");
        let renamed = saved(&controller, &bob.pub_hex).expect("Bob");
        assert_eq!(
            renamed,
            ContactView {
                label: "Robert".into(),
                ..row.clone()
            }
        );
        // An empty name, or one another friend has, changes nothing.
        assert_eq!(
            controller.rename(&bob.pub_hex, "  ").result,
            Err(NO_NAME.to_owned())
        );
        let taken = controller.rename(&bob.pub_hex, "carol");
        let why = taken.result.expect_err("Carol has that name");
        assert!(why.contains("already used"), "{why}");
        assert_no_code(&why, &carol.fingerprint);
        assert_eq!(saved(&controller, &bob.pub_hex).as_ref(), Some(&renamed));

        // The address, checked like `contact set-dial`.
        controller
            .set_lan_address(&bob.pub_hex, " 192.168.1.44:7420 ")
            .result
            .expect("an address");
        let moved = saved(&controller, &bob.pub_hex).expect("Bob");
        assert_eq!(moved.lan_dial, "192.168.1.44:7420");
        assert!(moved.pinned);
        for bad in ["not an address", "192.168.1.44", "192.168.1.44:0", ""] {
            let refused = controller.set_lan_address(&bob.pub_hex, bad);
            assert!(refused.result.is_err(), "{bad}");
            assert_eq!(saved(&controller, &bob.pub_hex).as_ref(), Some(&moved));
        }
        let (dave, _) = someone(0xD0, "");
        assert!(controller
            .set_lan_address(&dave.pub_hex, "192.168.1.9:7420")
            .result
            .is_err());
        // An address a send learned.
        controller
            .save_learned_dial(&bob.pub_hex, "192.168.1.45:7420")
            .result
            .expect("learned");
        assert_eq!(
            saved(&controller, &bob.pub_hex).expect("Bob").lan_dial,
            "192.168.1.45:7420"
        );
    }

    #[test]
    fn address_updates_from_a_paste_need_the_code_and_keep_the_pin() {
        let (_dir, controller) = profile();
        let me = controller.me().expect("me");
        let (bob, card) = someone(0xB0, "192.168.1.30:7420");
        add(
            &controller,
            &card,
            "Bob",
            Verify::Pinned {
                typed_fp: bob.fingerprint.clone(),
            },
        );
        let before = saved(&controller, &bob.pub_hex).expect("Bob");
        let (_, new_card) = someone(0xB0, "192.168.1.44:7420");
        let update = parse_friend_paste(&new_card, &me.pub_hex).expect("Bob's new card");

        // [U] shows a code; a wrong one asks for no update.
        let code = bridge::new_confirm_code(&mut rand::thread_rng());
        assert!(!bridge::confirm_code_matches("", &code));
        assert!(!bridge::confirm_code_matches("WRONG", &code));
        assert_eq!(saved(&controller, &bob.pub_hex).as_ref(), Some(&before));

        assert!(bridge::confirm_code_matches(&code, &code));
        controller
            .update_addresses(&update)
            .result
            .expect("updated");
        assert_eq!(
            saved(&controller, &bob.pub_hex),
            Some(ContactView {
                lan_dial: "192.168.1.44:7420".into(),
                ..before
            })
        );
        // Only a saved friend's addresses can be updated.
        let (_, stranger) = someone(0xE0, "192.168.1.66:7420");
        let stranger = parse_friend_paste(&stranger, &me.pub_hex).expect("a card");
        assert_eq!(
            controller.update_addresses(&stranger).result,
            Err(NOT_SAVED.to_owned())
        );
        assert_eq!(controller.load_contacts().expect("contacts").len(), 1);
    }

    #[test]
    fn af1_gets_both_cards_for_the_listener_it_shares() {
        let (_dir, controller) = profile();
        let me = controller.me().expect("me");
        let share = controller.share(Some("0.0.0.0:7420"));
        assert_eq!(share.lan, Some(Ok("127.0.0.1:7420".to_owned())));
        let with_lan = share.with_lan.expect("asked").expect("a card");
        assert!(with_lan.ends_with(" lan=127.0.0.1:7420"), "{with_lan}");
        let plain = share.plain.expect("a card");
        assert!(!plain.contains("lan="), "{plain}");
        for card in [&with_lan, &plain] {
            assert_eq!(
                bridge::parse_card_or_invite(card).expect("parses").pub_hex,
                me.pub_hex
            );
        }
        // No listener to share, or one a friend can't reach: no address.
        let none = controller.share(None);
        assert_eq!((none.lan, none.with_lan), (None, None));
        assert_eq!(none.plain.as_ref(), Ok(&plain));
        let local = controller.share(Some("127.0.0.1:7420"));
        assert_eq!(local.lan, Some(Err(NoCardLan::LocalOnly)));
        assert_eq!(local.with_lan, None);
        let unplugged = Controller::with_egress(controller.data_dir(), offline);
        assert!(matches!(
            unplugged.load_identity(),
            IdentityState::Ready { .. }
        ));
        let offline_share = unplugged.share(Some("0.0.0.0:7420"));
        assert_eq!(offline_share.lan, Some(Err(NoCardLan::NoAddress)));
        assert!(offline_share.plain.is_ok());
    }

    /// A saved friend `label`, verified or not, with key seed `seed`.
    fn named(seed: u8, label: &str, pinned: bool) -> ContactView {
        let them = bridge::me_view(&Identity::from_seed(&[seed; 32]));
        ContactView {
            pub_hex: them.pub_hex,
            address: them.address,
            label: label.into(),
            tag: String::new(),
            fingerprint: them.fingerprint,
            pinned,
            blocked: false,
            lan_dial: String::new(),
            internet_dial: String::new(),
            p2p: String::new(),
        }
    }

    #[test]
    fn look_alike_letters_fold_and_mixed_alphabets_are_seen() {
        // Cyrillic а е о р с у х і ј and Greek ο α ε ρ ν.
        assert_eq!(
            fold_confusables(
                "\u{0430}\u{0435}\u{043E}\u{0440}\u{0441}\u{0443}\u{0445}\u{0456}\u{0458}"
            ),
            "aeopcyxij"
        );
        assert_eq!(
            fold_confusables("\u{03BF}\u{03B1}\u{03B5}\u{03C1}\u{03BD}"),
            "oaepv"
        );
        assert_eq!(fold_confusables("bob"), "bob");
        // Other letters stay as they are.
        assert_eq!(fold_confusables("\u{0431}\u{03B2}"), "\u{0431}\u{03B2}");
        for mixed in [
            "B\u{043E}b",
            "Al\u{03B5}x",
            "\u{0410}\u{03B1}",
            "Zo\u{0451}",
        ] {
            assert!(mixed_script(mixed), "{mixed}");
        }
        for single in [
            "Bob",
            "Jos\u{00E9}",
            "\u{0411}\u{043E}\u{0440}\u{0438}\u{0441}",
            "\u{0391}\u{03BB}\u{03AD}\u{03BE}",
            "R2-D2",
            "\u{5F20}\u{4F1F} Wei",
        ] {
            assert!(!mixed_script(single), "{single}");
        }
    }

    #[test]
    fn a_name_that_only_looks_like_a_verified_friends_clashes_too() {
        let bob = named(0xB0, "Bob", true);
        let carol = named(0xC0, "Carol", false);
        let contacts = vec![bob.clone(), carol.clone()];
        let new = named(0xE0, "", false).pub_hex;
        // Bob, verified: the same name in another case, or with a Cyrillic о.
        for name in ["bob", "BOB", "B\u{043E}b", "b\u{03BF}b"] {
            assert_eq!(
                check_name(&contacts, name, &new),
                NameCheck::VerifiedClash(bob.pub_hex.clone()),
                "{name}"
            );
        }
        // Carol, not verified: the same name is taken; one that only looks
        // like hers may be saved, with a warning.
        assert_eq!(
            check_name(&contacts, "carol", &new),
            NameCheck::Taken(carol.pub_hex.clone())
        );
        let looks_like = "\u{0441}arol";
        assert_eq!(check_name(&contacts, looks_like, &new), NameCheck::Free);
        assert_eq!(
            name_warning(&contacts, looks_like, &new),
            Some(NameWarning::MixedScript)
        );
        let cop = named(0xD0, "cop", false);
        let all_cyrillic = "\u{0441}\u{043E}\u{0440}";
        assert!(!mixed_script(all_cyrillic));
        assert_eq!(
            name_warning(std::slice::from_ref(&cop), all_cyrillic, &new),
            Some(NameWarning::LooksLike(cop.pub_hex.clone()))
        );
        // Nothing to say about a plain new name, or a friend's own one.
        assert_eq!(name_warning(&contacts, "Dave", &new), None);
        assert_eq!(
            name_warning(std::slice::from_ref(&cop), "cop", &cop.pub_hex),
            None
        );
        assert_eq!(name_warning(&contacts, "  ", &new), None);
    }

    #[test]
    fn remove_runs_with_stdin_closed() {
        if testkit::run_in_child(&format!(
            "{}::remove_runs_with_stdin_closed",
            module_path!()
        ))
        .is_some()
        {
            return;
        }
        // In the child: stdin is /dev/null, so any prompt would cancel.
        let (_dir, controller) = profile();
        let (bob, card) = someone(0xB0, "192.168.1.30:7420");
        add(&controller, &card, "Bob", Verify::Unpinned);
        let removed = controller.remove(&bob.pub_hex);
        removed.result.expect("removed");
        assert!(removed.captured.contains("removed"), "{}", removed.captured);
        assert_no_code(&removed.captured, &bob.fingerprint);
        assert!(controller.load_contacts().expect("contacts").is_empty());
        assert_eq!(
            controller.remove(&bob.pub_hex).result,
            Err(NOT_SAVED.to_owned())
        );
    }

    #[test]
    fn a_verified_friends_name_on_a_new_key_saves_nothing() {
        let (dir, controller) = profile();
        let me = controller.me().expect("me");
        // Hand-built: Bob, verified, with key A.
        let (bob, _) = someone(0xB0, "");
        let book = serde_json::json!([{
            "petname": "Bob",
            "address": bob.address,
            "pub_hex": bob.pub_hex,
            "pinned": true,
            "lan_dial": "192.168.1.30:7420",
        }]);
        std::fs::write(
            bridge::contacts_path(dir.path()),
            serde_json::to_vec_pretty(&book).expect("json"),
        )
        .expect("write contacts.json");
        let contacts = controller.load_contacts().expect("contacts");

        // Someone pastes key B and calls it 'bob'.
        let (mallory, card) = someone(0xE0, "192.168.1.66:7420");
        let pasted = parse_friend_paste(&card, &me.pub_hex).expect("a card");
        assert_eq!(
            check_name(&contacts, " bob ", &pasted.pub_hex),
            NameCheck::VerifiedClash(bob.pub_hex.clone())
        );
        // Bob renamed to his own name is no clash.
        assert_eq!(check_name(&contacts, "BOB", &bob.pub_hex), NameCheck::Free);
        assert_eq!(
            check_name(&contacts, "\t", &pasted.pub_hex),
            NameCheck::Empty
        );
        assert_eq!(
            check_name(&contacts, "Bobby", &pasted.pub_hex),
            NameCheck::Free
        );
        // The core refuses the save as well: the book is unchanged.
        let refused = controller.save_friend(&pasted, "bob", &Verify::Unpinned);
        assert!(refused.result.is_err());
        assert_eq!(controller.load_contacts().expect("contacts"), contacts);
        assert_no_code(&refused.result.unwrap_err(), &mallory.fingerprint);

        // The same name as an unverified friend: taken, and that friend's
        // code stays hidden in the core's refusal.
        let (carol, carol_card) = someone(0xC0, "");
        add(&controller, &carol_card, "Carol", Verify::Unpinned);
        let contacts = controller.load_contacts().expect("contacts");
        assert_eq!(
            check_name(&contacts, "CAROL", &pasted.pub_hex),
            NameCheck::Taken(carol.pub_hex.clone())
        );
        let refused = controller.save_friend(&pasted, "carol", &Verify::Unpinned);
        let why = refused.result.expect_err("Carol has that name");
        assert!(why.contains(HIDDEN_CODE), "{why}");
        assert_no_code(&why, &carol.fingerprint);
        assert_eq!(controller.load_contacts().expect("contacts"), contacts);
    }

    /// Runs every store job among `cmds` as the store worker runs them, and
    /// the jobs their answers ask for in turn; anything else is dropped.
    fn run_stores(app: &mut App, controller: &Controller, cmds: Vec<Cmd>) {
        let mut queue: std::collections::VecDeque<Cmd> = cmds.into();
        while let Some(cmd) = queue.pop_front() {
            if let Cmd::Store(job) = cmd {
                let result = workers::store_job(controller, job);
                queue.extend(testkit::send(app, Msg::Job(result)));
            }
        }
    }

    /// `text` typed key by key, and the commands it gave.
    fn type_into(app: &mut App, text: &str) -> Vec<Cmd> {
        let mut cmds = Vec::new();
        for c in text.chars() {
            cmds.extend(testkit::press(app, crossterm::event::KeyCode::Char(c)));
        }
        cmds
    }

    /// AF-1 from Home or AF-3 (A), `card` pasted and named `name` on AF-2:
    /// VF.
    fn to_vf(app: &mut App, controller: &Controller, card: &str, name: &str) {
        use crossterm::event::KeyCode;
        let mut cmds = testkit::press(app, KeyCode::Char('a'));
        cmds.extend(testkit::paste(app, card, PasteVia::Bracketed));
        cmds.extend(testkit::tick(app, std::time::Duration::from_millis(300)));
        cmds.extend(testkit::press(app, KeyCode::Enter));
        cmds.extend(type_into(app, name));
        cmds.extend(testkit::press(app, KeyCode::Enter));
        run_stores(app, controller, cmds);
        assert!(
            matches!(app.screen(), Screen::Verify(_)),
            "{:?}",
            app.screen()
        );
    }

    /// The confirmation code on show, typed, then Enter: the commands.
    fn confirmed(app: &mut App) -> Vec<Cmd> {
        let code = app.verify_code_for_tests().expect("a code").to_owned();
        let mut cmds = type_into(app, &code);
        cmds.extend(testkit::press(app, crossterm::event::KeyCode::Enter));
        cmds
    }

    /// VF on a real profile, its store jobs run as the store worker runs
    /// them: Bob is pinned in contacts.json only after his security words and
    /// the confirmation code; Alice is saved as not verified after the
    /// confirmation code alone, verified later from Home by her old code, and
    /// removed from her page once 'remove' is typed.
    #[test]
    fn vf_pins_a_friend_in_the_profile_only_after_both_codes() {
        use crossterm::event::KeyCode;
        let (_dir, controller) = profile();
        let (bob, bob_card) = someone(0xB0, "192.168.1.30:7420");
        let (alice, alice_card) = someone(0xA1, "");
        let mut app = testkit::home_app(
            (80, 24),
            state_file::Receive::Off,
            Vec::new(),
            Conversations::new(),
        );
        to_vf(&mut app, &controller, &bob_card, "Bob");
        // His words as he reads them; a wrong confirmation code saves
        // nothing.
        let mut cmds = type_into(&mut app, &bob.words.join(" "));
        cmds.extend(testkit::press(&mut app, KeyCode::Enter));
        cmds.extend(type_into(&mut app, "11111"));
        cmds.extend(testkit::press(&mut app, KeyCode::Enter));
        run_stores(&mut app, &controller, cmds);
        assert!(controller.load_contacts().expect("contacts").is_empty());
        let cmds = confirmed(&mut app);
        run_stores(&mut app, &controller, cmds);
        let row = saved(&controller, &bob.pub_hex).expect("Bob");
        assert!(row.pinned);
        assert_eq!(
            (row.label.as_str(), row.lan_dial.as_str()),
            ("Bob", "192.168.1.30:7420")
        );
        assert!(matches!(app.screen(), Screen::Added(added) if added.verified));
        // The reload brought the file's own row.
        assert_eq!(app.friend(&bob.pub_hex), Some(&row));

        // Alice: Later, then the confirmation code.
        to_vf(&mut app, &controller, &alice_card, "Alice");
        testkit::press(&mut app, KeyCode::Tab);
        let cmds = confirmed(&mut app);
        run_stores(&mut app, &controller, cmds);
        let row = saved(&controller, &alice.pub_hex).expect("Alice");
        assert!(!row.pinned);
        assert!(matches!(app.screen(), Screen::Added(added) if !added.verified));
        // Verified later from Home: pinned, her name kept.
        testkit::press(&mut app, KeyCode::Esc);
        let at = app
            .contacts()
            .iter()
            .position(|c| c.pub_hex == alice.pub_hex)
            .expect("Alice listed");
        for _ in 0..at {
            testkit::press(&mut app, KeyCode::Down);
        }
        // Her old code (Ctrl+O), for a friend with an older Raven.
        testkit::press(&mut app, KeyCode::Char('v'));
        testkit::ctrl(&mut app, 'o');
        let mut cmds = type_into(&mut app, &alice.fingerprint);
        cmds.extend(testkit::press(&mut app, KeyCode::Enter));
        cmds.extend(confirmed(&mut app));
        run_stores(&mut app, &controller, cmds);
        let row = saved(&controller, &alice.pub_hex).expect("Alice");
        assert!(row.pinned && row.label == "Alice");
        assert!(matches!(app.screen(), Screen::FriendPage(_)));
        // Removed from her page, only once 'remove' is typed.
        let mut cmds = testkit::press(&mut app, KeyCode::Char('x'));
        cmds.extend(type_into(&mut app, "remove"));
        cmds.extend(testkit::press(&mut app, KeyCode::Enter));
        run_stores(&mut app, &controller, cmds);
        assert_eq!(saved(&controller, &alice.pub_hex), None);
        assert!(saved(&controller, &bob.pub_hex).is_some_and(|c| c.pinned));
        assert_eq!(app.screen(), &Screen::Home);
        assert!(app.friend(&alice.pub_hex).is_none());
    }

    #[test]
    fn unblock_takes_a_friend_off_the_block_list() {
        let (dir, controller) = profile();
        let (bob, card) = someone(0xB0, "");
        add(&controller, &card, "Bob", Verify::Unpinned);
        let mut blocks = BlockList::load_checked(dir.path()).expect("block list");
        blocks.block(&bob.pub_hex);
        blocks.save(dir.path()).expect("block Bob");
        assert!(saved(&controller, &bob.pub_hex).expect("Bob").blocked);

        let unblocked = controller.unblock(&bob.pub_hex);
        unblocked.result.expect("unblocked");
        assert!(unblocked.captured.contains("unblocked"));
        assert_no_code(&unblocked.captured, &bob.fingerprint);
        assert!(!saved(&controller, &bob.pub_hex).expect("Bob").blocked);
        let again = controller.unblock(&bob.pub_hex);
        let why = again.result.expect_err("not blocked");
        assert_no_code(&why, &bob.fingerprint);

        // A corrupt block list is an error, never 'nobody is blocked'.
        let blocked = raven_core::chat_history::blocked_path(dir.path());
        std::fs::write(&blocked, "{").expect("corrupt it");
        let why = controller
            .load_contacts()
            .expect_err("a corrupt block list");
        assert!(why.contains("block list"), "{why}");
    }

    #[test]
    fn a_profile_without_an_identity_stays_inert() {
        testkit::lab_backends();
        let dir = testkit::short_dir();
        let controller = Controller::with_egress(dir.path(), loopback_egress);
        assert!(matches!(controller.load_identity(), IdentityState::Missing));
        let (bob, card) = someone(0xB0, "192.168.1.30:7420");
        let friend = parse_friend_paste(&card, "").expect("Bob's card");
        // Every job refuses, and touches nothing.
        assert_eq!(controller.me(), None);
        assert_eq!(controller.my_invite(), None);
        assert_eq!(controller.my_card(None), Err(NO_IDENTITY.to_owned()));
        assert_eq!(controller.load_contacts(), Err(NO_IDENTITY.to_owned()));
        assert_eq!(controller.load_history(), Err(NO_IDENTITY.to_owned()));
        assert_eq!(
            controller.save_read_marks(&TuiState::default()),
            Err(NO_IDENTITY.to_owned())
        );
        let jobs = [
            controller.save_friend(&friend, "Bob", &Verify::Unpinned),
            controller.update_addresses(&friend),
            controller.verify_existing(&bob.pub_hex, &bob.fingerprint),
            controller.rename(&bob.pub_hex, "Bob"),
            controller.set_lan_address(&bob.pub_hex, "192.168.1.30:7420"),
            controller.save_learned_dial(&bob.pub_hex, "192.168.1.30:7420"),
            controller.remove(&bob.pub_hex),
            controller.unblock(&bob.pub_hex),
        ];
        for job in jobs {
            assert_eq!(job.result, Err(NO_IDENTITY.to_owned()));
            assert_eq!(job.captured, "");
        }
        let forgot = controller.forget_address(&bob.pub_hex);
        assert_eq!(forgot.result, Err(NO_IDENTITY.to_owned()));
        assert_eq!(forgot.captured, "");
        // The privacy pack's parts (PP.21): not available, and refused.
        assert_eq!(controller.read_privacy(), Err(NotAvailable));
        assert_eq!(
            controller.set_chat_keep(ChatKeepView::Days7),
            Err(NO_IDENTITY.to_owned())
        );
        assert_eq!(
            controller.delete_chat(&bob.pub_hex).result,
            Err(NO_IDENTITY.to_owned())
        );
        controller.mark_notice_shown(Notice::Sealing);
        // Only the identity store's lock (and the keystore choice), which
        // raven-core allows before the first identity.
        for name in entries(dir.path()) {
            assert!(
                name.starts_with(".identity_store.lock.sqlite")
                    || name == raven_core::keystore_select::KEYSTORE_MARKER_NAME,
                "{name} in a profile with no identity"
            );
        }
        assert!(!bridge::contacts_path(dir.path()).exists());
        // So the identity can still be made: no continuity refusal.
        let created = controller.create_identity();
        let created = created.result.expect("create after an idle session");
        assert_eq!(controller.me(), Some(created.me));
    }

    /// The entries raven-core allows in a profile before its identity (its
    /// FIRST_INSTALL_INERT_FILES, as far as this app could leave them).
    fn inert(name: &str) -> bool {
        name.starts_with(".identity_store.lock.sqlite")
            || name == raven_core::keystore_select::KEYSTORE_MARKER_NAME
    }

    /// The entries a new identity brings (the identity store, the device
    /// certificate and keys, the first prekey and its locks), and the app's
    /// settings.
    fn of_a_new_identity(name: &str) -> bool {
        inert(name)
            || name.starts_with("identity.")
            || name.starts_with("device_")
            || name.starts_with(".device_registry.lock.sqlite")
            || name.starts_with("prekey_")
            || name.starts_with(".lan_peer_cache.lock.sqlite")
            // Home's first history load takes the history's lock.
            || name.starts_with(".chat_history.lock.sqlite")
            || name == state_file::FILE_NAME
            // Taken by every save of the read markers (read_marks.rs).
            || name.starts_with(read_marks::LOCK)
            // Phase 6b P6.36: while the random-port gate is live a new
            // profile saves the LAN port it picked.
            || (name == raven_core::node_policy::POLICY_FILE
                && raven_core::security_gate::live(raven_core::security_gate::SecGate::RandomPort))
    }

    /// testing §2: a session with no identity idles, the workers and the
    /// poller up and the clock ticking, and leaves only inert entries. Then
    /// the wizard's own jobs make the identity through the store worker (or
    /// as the UI thread would, for a vault profile), with no continuity
    /// refusal, and the profile holds only what a new identity brings and
    /// tui_state.json. No node is involved: every node job is dropped.
    #[test]
    fn a_missing_session_stays_inert_then_the_wizard_makes_the_identity() {
        use crossterm::event::KeyCode;
        use std::time::Instant;

        testkit::lab_backends();
        let dir = testkit::short_dir();
        let controller = Arc::new(Controller::with_egress(dir.path(), loopback_egress));
        assert!(matches!(controller.load_identity(), IdentityState::Missing));
        let (tx, rx) = std::sync::mpsc::channel();
        let hub = workers::Hub::start(Arc::clone(&controller), &tx).expect("the workers");
        let mut app = testkit::wizard_app((80, 24));
        let mut keys = vec![KeyCode::Enter];
        keys.extend("Sam".chars().map(KeyCode::Char));
        keys.push(KeyCode::Enter);
        for key in keys {
            assert!(testkit::press(&mut app, key).is_empty(), "{key:?}");
        }
        let idle_until = Instant::now() + Duration::from_secs(5);
        while Instant::now() < idle_until {
            assert!(testkit::tick(&mut app, Duration::from_millis(250)).is_empty());
            std::thread::sleep(Duration::from_millis(250));
        }
        assert!(rx.try_recv().is_err(), "nothing ran");
        for name in entries(dir.path()) {
            assert!(inert(&name), "{name} in a profile with no identity");
        }
        // The vault check records nothing either.
        let before = entries(dir.path());
        let _ = controller.creation_prompts();
        assert_eq!(entries(dir.path()), before);
        #[cfg(not(all(unix, not(target_os = "macos"))))]
        assert!(!controller.creation_prompts());

        // WZ-3's Yes: the vault check, then the identity, then its first jobs.
        let mut cmds = testkit::press(&mut app, KeyCode::Char('y'));
        let (mut saved, mut loaded) = (false, false);
        let deadline = Instant::now() + Duration::from_secs(60);
        while !(saved && loaded) {
            let mut next = Vec::new();
            for cmd in cmds {
                match cmd {
                    Cmd::Suspend(SuspendJob::CreateIdentity) => {
                        let made = workers::created(controller.create_identity());
                        next.extend(testkit::send(&mut app, Msg::Job(made)));
                    }
                    Cmd::Node(_) => {}
                    cmd => hub.dispatch(cmd),
                }
            }
            cmds = next;
            if !cmds.is_empty() {
                continue;
            }
            let left = deadline
                .checked_duration_since(Instant::now())
                .expect("the wizard's jobs took too long");
            if let Msg::Job(result) = rx.recv_timeout(left).expect("a job's answer") {
                match &result {
                    JobResult::Created { result, .. } => {
                        assert!(result.is_ok(), "{result:?}");
                    }
                    JobResult::SettingsSaved(done) => {
                        assert_eq!(done, &Ok(()));
                        saved = true;
                    }
                    JobResult::Contacts { contacts, .. } => {
                        assert_eq!(contacts, &Ok(Vec::new()));
                        loaded = true;
                    }
                    _ => {}
                }
                cmds = testkit::send(&mut app, Msg::Job(result));
            }
        }
        hub.shut_down();
        assert_eq!(app.me(), controller.me().as_ref());
        let names = entries(dir.path());
        for name in &names {
            assert!(
                of_a_new_identity(name),
                "{name} in a new profile: {names:?}"
            );
        }
        for made in [
            state_file::FILE_NAME,
            "device_registry.json",
            "prekey_store.json",
        ] {
            assert!(
                names.iter().any(|name| name == made),
                "no {made}: {names:?}"
            );
        }
        let state = state_file::peek(dir.path());
        assert_eq!(
            (state.display_name.as_str(), state.receive),
            ("Sam", state_file::Receive::On)
        );
    }

    #[test]
    fn an_unreadable_identity_store_is_unavailable() {
        // A data folder that is a file: no key store is asked.
        let dir = tempfile::tempdir().expect("tempdir");
        let not_a_dir = dir.path().join("profile");
        std::fs::write(&not_a_dir, b"not a folder").expect("write");
        let controller = Controller::new(&not_a_dir);
        match controller.load_identity() {
            IdentityState::Unavailable(why) => assert!(!why.is_empty()),
            other => panic!("{other:?}"),
        }
        assert_eq!(controller.me(), None);
        assert_eq!(controller.load_contacts(), Err(NO_IDENTITY.to_owned()));
    }

    /// B-offline-lan-1 (any-network plan P2.R1): a friend whose only route
    /// is a learned one (cutoff F7's guess at the address they last came
    /// from, for a friend added from an invite line) goes down the app's
    /// one-route LAN send (`bridge::send_routes`). A message queued there
    /// while the friend is away records no copy of that address for
    /// raven-node's outbox, whose worker plans it again at each attempt
    /// through its own on-link filter (a recorded copy would be dialled on
    /// every retry, on any network). `raven send`'s side:
    /// pair_init_lab's `a_cli_send_queued_on_a_learned_route_alone_never_records_it`.
    #[cfg(unix)]
    #[test]
    fn a_message_queued_on_a_learned_route_alone_never_records_it() {
        testkit::lab_backends();
        let (a_dir, b_dir) = (testkit::short_dir(), testkit::short_dir());
        let a = a_dir.path();
        // The fake node answers first: no send here ever starts a real one.
        let fake = testkit::FakeNode::start(a, testkit::FakeStatus::listening(4242, SEND_LISTEN));
        let alice_ctl = Controller::with_egress(a, loopback_egress);
        let bob_ctl = Controller::with_egress(b_dir.path(), loopback_egress);
        for controller in [&alice_ctl, &bob_ctl] {
            let created = controller.create_identity().result.expect("create");
            assert_eq!(created.prekey_warning, None);
        }
        let alice = Arc::clone(alice_ctl.identity().expect("Alice"));
        let bob = Arc::clone(bob_ctl.identity().expect("Bob"));
        // Alice added Bob from a card with no address: nothing saved.
        let card = |id: &Identity| bridge::format_card_with(id, "", "", None).expect("a card");
        add(&alice_ctl, &card(&bob), "Bob", Verify::Unpinned);
        add(&bob_ctl, &card(&alice), "Alice", Verify::Unpinned);
        let bob_hex = hex::encode(bob.public_key_bytes());
        assert_eq!(saved(&alice_ctl, &bob_hex).expect("Bob").lan_dial, "");
        fake.answer_dials_as(testkit::DialPeer {
            dir: b_dir.path().to_path_buf(),
            id: Arc::clone(&bob),
            from_dir: a.to_path_buf(),
            from_id: Arc::clone(&alice),
        });
        let guess = "192.168.1.44:7420".to_owned();
        let routes = vec![bridge::DialRoute {
            carrier: DialCarrier::Lan,
            dial: guess.clone(),
        }];
        let unrecorded = vec![guess.clone()];
        // Reached there once: a confirmed session, so later sends queue.
        let used = bridge::send_routes(
            a,
            &alice,
            &routes,
            &bob_hex,
            SEND_LISTEN,
            "hello",
            &unrecorded,
        )
        .expect("delivered");
        assert_eq!(used.dial, guess);
        fake.refuse_dials(&format!(
            "lan connect: cannot connect to {guess} ({guess}: Connection refused (os error 61))"
        ));
        let records = || {
            raven_core::outbox::object_route_records(a, bridge::now_ms())
                .expect("route records")
                .into_values()
                .filter(|r| r.peer_pub_hex == bob_hex)
                .collect::<Vec<_>>()
        };
        // The app's send while Bob is away: queued, and recorded without
        // the guess.
        let queued = bridge::send_routes(
            a,
            &alice,
            &routes,
            &bob_hex,
            SEND_LISTEN,
            "while away",
            &unrecorded,
        )
        .expect_err("queued");
        assert!(queued.starts_with(bridge::QUEUED_PREFIX), "{queued}");
        let records = records();
        assert_eq!(records.len(), 1, "{records:?}");
        assert!(
            !records[0].routes.iter().any(|r| r.dial == guess),
            "the learned route was recorded: {records:?}"
        );
    }

    /// Starting the background program, against real profiles. Unix only:
    /// there each profile has its own socket, so nothing here can reach a
    /// node outside its profile (on Windows the pipe is per user).
    #[cfg(unix)]
    mod node_starts {
        use super::*;
        use node::Reach;
        use std::sync::atomic::{AtomicUsize, Ordering};

        /// A profile with an identity whose starts run `ensure`.
        fn profile_ensuring(
            ensure: fn(&Path) -> Result<(), String>,
        ) -> (tempfile::TempDir, Controller) {
            let (dir, _) = profile();
            let controller = Controller::with_ensure(dir.path(), ensure);
            assert!(matches!(
                controller.load_identity(),
                IdentityState::Ready { .. }
            ));
            (dir, controller)
        }

        /// Whether ext.rs could find a raven-node to start from this test
        /// binary: then a real start would listen on the network, so the tests
        /// that use ext.rs's own start don't run.
        fn a_real_node_could_start() -> bool {
            let found = bridge::raven_node_bin_public().exists();
            if found {
                eprintln!("skipped: a raven-node sits next to the test binary");
            }
            found
        }

        #[test]
        fn without_its_program_the_background_program_is_missing() {
            let (dir, controller) = profile();
            if a_real_node_could_start() {
                return;
            }
            let ensured = controller.ensure_node();
            let why = ensured.result.expect_err("no raven-node to start");
            match errors::explain_node_start(&why) {
                NodeStartProblem::Failed(plain) => {
                    assert_eq!(plain.headline, "Raven's background program is missing.");
                }
                other => panic!("{other:?}"),
            }
            assert_eq!(ensured.after.reach, Reach::NotRunning);
            assert_eq!(ensured.started_by_app, None);
            // ext.rs opened the service log for the start it tried, in the profile.
            assert!(bridge::service_log_path(dir.path()).exists());
        }

        #[test]
        fn a_node_that_already_listens_was_not_started_by_the_app() {
            for (lan_listen, reach) in [
                ("0.0.0.0:7420", Reach::Listening { port: Some(7420) }),
                ("127.0.0.1:7420", Reach::LocalOnly),
            ] {
                let (dir, controller) = profile();
                if a_real_node_could_start() {
                    return;
                }
                let fake = testkit::FakeNode::start(
                    dir.path(),
                    testkit::FakeStatus::listening(4242, lan_listen),
                );
                let ensured = controller.ensure_node();
                assert_eq!(ensured.result, Ok(()), "{lan_listen}");
                assert_eq!(ensured.after.reach, reach, "{lan_listen}");
                assert_eq!(ensured.after.pid, Some(4242));
                assert_eq!(ensured.started_by_app, None, "it ran before");
                assert_eq!(controller.probe_node(), ensured.after);
                let ops = fake.ops();
                assert!(ops.contains(&"ping".to_owned()), "{ops:?}");
                assert!(!ops.iter().any(|op| op.starts_with("outbox")), "{ops:?}");
                // Nothing was spawned, so no service log was opened.
                assert!(!bridge::service_log_path(dir.path()).exists());
            }
        }

        /// How many fake starts run at once, at most, and how many ran.
        static RUNNING: AtomicUsize = AtomicUsize::new(0);
        static MOST: AtomicUsize = AtomicUsize::new(0);
        static RAN: AtomicUsize = AtomicUsize::new(0);

        fn slow_ensure(_: &Path) -> Result<(), String> {
            let now = RUNNING.fetch_add(1, Ordering::SeqCst) + 1;
            MOST.fetch_max(now, Ordering::SeqCst);
            std::thread::sleep(std::time::Duration::from_millis(150));
            RUNNING.fetch_sub(1, Ordering::SeqCst);
            RAN.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        /// What raven-node says when nothing listens at the friend's address.
        const REFUSED: &str = "lan connect: cannot connect to 127.0.0.1:9 (127.0.0.1:9: \
                               Connection refused (os error 61))";

        /// The App drawn at 100x30, as one line of words.
        fn screen(app: &App) -> String {
            testkit::screen_text(&testkit::render(app, 100, 30))
        }

        /// The send job `cmds` hand the send worker, run here as the worker
        /// runs it.
        fn send_as_the_worker(controller: &Controller, cmds: &[Cmd]) -> JobResult {
            let job = cmds.iter().find_map(|cmd| match cmd {
                Cmd::Send(SendJob::Send {
                    local_id,
                    pub_hex,
                    text,
                }) => Some((*local_id, pub_hex.clone(), text.clone())),
                _ => None,
            });
            let (local_id, pub_hex, text) = job.expect("a send job");
            JobResult::Sent {
                local_id,
                outcome: controller.send(&pub_hex, &text),
            }
        }

        /// A first message to a friend whose computer answers but runs no
        /// Raven, against a fake raven-node that answers LanDial with that
        /// error: Sending while the job runs, then Not sent with the friend's
        /// own fix ('Ask Bob to open Raven'), in the tick and in MSG. Nothing
        /// reached the history, and R sends the same text again.
        #[test]
        fn a_send_the_friends_computer_refuses_is_not_sent() {
            use crossterm::event::KeyCode;

            // The horizon held on this thread (the send runs here), whatever
            // RAVEN_LAB_HORIZON the suite runs with: with it a first message
            // to a friend who cannot take it is parked, not refused (P5.8).
            raven_core::horizon::set_lab_horizon_for_this_thread(Some(false));
            let (dir, controller) = profile();
            if a_real_node_could_start() {
                return;
            }
            let (bob, card) = someone(0xB0, "127.0.0.1:9");
            add(&controller, &card, "Bob", Verify::Unpinned);
            let fake = testkit::FakeNode::start(
                dir.path(),
                testkit::FakeStatus::listening(4242, "127.0.0.1:0"),
            );
            fake.refuse_dials(REFUSED);
            let mut app = testkit::home_app(
                (100, 30),
                state_file::Receive::Off,
                controller.load_contacts().expect("contacts"),
                controller.load_history().expect("history"),
            );
            testkit::press(&mut app, KeyCode::Enter);
            for c in "hello bob".chars() {
                testkit::press(&mut app, KeyCode::Char(c));
            }
            let cmds = testkit::press(&mut app, KeyCode::Enter);
            assert!(
                screen(&app).contains("You - just now | Sending..."),
                "{}",
                screen(&app)
            );
            let answer = send_as_the_worker(&controller, &cmds);
            match &answer {
                JobResult::Sent {
                    outcome:
                        SendOutcome {
                            result: SendResult::Failed(text),
                            learned_dial_used: None,
                            ..
                        },
                    ..
                } => assert!(text.starts_with("NOT SENT: "), "{text}"),
                other => panic!("{other:?}"),
            }
            testkit::send(&mut app, Msg::Job(answer));
            let shown = screen(&app);
            assert!(
                shown.contains(
                    "You - just now x Not sent: Bob's computer is there, but Raven isn't \
                     receiving right now (it may be locked or closed). Press R to try again."
                ),
                "{shown}"
            );
            let sends = app.sends();
            let plain = sends[0]
                .outcome
                .as_ref()
                .and_then(|outcome| outcome.plain())
                .expect("its words");
            assert_eq!(plain.next, "Ask Bob to open Raven.");
            assert_eq!(plain.action, errors::Action::Retry);
            // Nothing was written: no row in the history, and raven-node was
            // asked to dial, never to queue or kick anything.
            assert!(!controller
                .load_history()
                .expect("history")
                .contains_key(&bob.pub_hex));
            let ops = fake.ops();
            assert!(ops.contains(&"lan_dial".to_owned()), "{ops:?}");
            assert!(!ops.iter().any(|op| op.starts_with("outbox")), "{ops:?}");

            // MSG says it in full, with the friend's fix.
            testkit::press(&mut app, KeyCode::Tab);
            testkit::press(&mut app, KeyCode::Enter);
            let shown = screen(&app);
            for words in [
                "Message to Bob - just now",
                "\"hello bob\"",
                "Status: Not sent. Nothing was queued.",
                "Why: Bob's computer is there, but Raven isn't receiving right now (it may be locked or closed).",
                "What you can do: Ask Bob to open Raven. Then press R to try again.",
                "[R] Send again [D] Details [Esc] Close",
            ] {
                assert!(shown.contains(words), "{words}: {shown}");
            }
            // R there sends the same text again, as a new message.
            let cmds = testkit::press(&mut app, KeyCode::Char('r'));
            assert!(app.overlays().is_empty(), "MSG closes");
            assert!(
                cmds.iter().any(|cmd| matches!(
                    cmd,
                    Cmd::Send(SendJob::Send { text, .. }) if text == "hello bob"
                )),
                "{cmds:?}"
            );
            assert_eq!(
                app.sends().len(),
                1,
                "the new send takes the old one's place"
            );
            assert_eq!(app.sends()[0].outcome, None);
        }

        /// R and C reach raven-node's outbox through `raven outbox`, never a
        /// prompt; a fake that runs no outbox worker refuses the retry's kick
        /// and knows no such message to cancel, which the App words.
        #[test]
        fn retry_and_cancel_go_through_raven_outbox() {
            let (dir, controller) = profile();
            let (bob, _) = someone(0xB0, "");
            let fake = testkit::FakeNode::start(
                dir.path(),
                testkit::FakeStatus::listening(4242, "127.0.0.1:0"),
            );
            let mid = "ab".repeat(16);
            fake.set_outbox(vec![raven_core::ipc::OutboxItem {
                message_id_hex: mid.clone(),
                peer_pub_hex: bob.pub_hex.clone(),
                kind: "message".into(),
                state: "queued".into(),
                ..raven_core::ipc::OutboxItem::default()
            }]);
            let retried = controller.retry(&mid);
            let not_retried = retried.result.expect_err("no outbox worker takes the kick");
            assert!(not_retried.contains(EXT_NO_OUTBOX), "{not_retried}");
            let ops = fake.ops();
            assert!(ops.contains(&"outbox_kick".to_owned()), "{ops:?}");
            let cancelled = controller.cancel(&mid);
            let not_waiting = cancelled.result.expect_err("nothing of it is in the store");
            assert!(not_waiting.contains(EXT_NOT_WAITING), "{not_waiting}");
            // The App words both.
            let mut app = testkit::home_app(
                (80, 24),
                state_file::Receive::Off,
                Vec::new(),
                Conversations::new(),
            );
            for (result, toast) in [
                (
                    JobResult::Retried {
                        mid: mid.clone(),
                        peer: bob.pub_hex.clone(),
                        result: Err(not_retried),
                        captured: retried.captured,
                    },
                    NOT_RETRIED_TOAST,
                ),
                (
                    JobResult::Cancelled {
                        mid: mid.clone(),
                        peer: bob.pub_hex.clone(),
                        result: Err(not_waiting),
                        captured: cancelled.captured,
                    },
                    NOT_WAITING_TOAST,
                ),
            ] {
                testkit::send(&mut app, Msg::Job(result));
                assert!(
                    app.toasts_for_tests().contains(&toast),
                    "{:?}",
                    app.toasts_for_tests()
                );
            }
        }

        /// Review cross-4 (fixed with 5a-1): C on a message parked until
        /// its deadline (Phase 5a: listed as waiting, no outbox row) stops
        /// it. The cancel goes through, the App says Raven stopped trying,
        /// and nothing is left to seal again.
        #[test]
        fn cancel_stops_a_parked_message() {
            let (dir, controller) = profile();
            let (bob, _) = someone(0xB1, "");
            let peer: [u8; 32] = hex::decode(&bob.pub_hex)
                .expect("hex")
                .try_into()
                .expect("32 bytes");
            let mid = [0x5c; 16];
            let now = raven_core::clock::now_ms();
            let zero = raven_core::horizon::SENTINEL_BINDING;
            raven_core::ensure_outbound_queued_history(
                dir.path(),
                &peer,
                &zero,
                &zero,
                &mid,
                now,
                Some("parked hello"),
            )
            .expect("history");
            let deadline = raven_core::horizon::message_deadline(now);
            let parked = |dd: &Path| {
                raven_core::IndexedSessionStore::open(dd)
                    .expect("store")
                    .parked_for_recipient(&peer)
                    .expect("parked rows")
            };
            assert!(raven_core::IndexedSessionStore::open(dir.path())
                .expect("store")
                .park_outbound(&peer, &mid, None, now, deadline, now)
                .expect("park"));
            assert_eq!(parked(dir.path()).len(), 1);
            let cancelled = controller.cancel(&hex::encode(mid));
            cancelled
                .result
                .clone()
                .expect("a parked message is cancelled");
            assert!(
                cancelled.captured.contains("raven-node stops trying"),
                "{}",
                cancelled.captured
            );
            assert!(parked(dir.path()).is_empty(), "never sealed again");
            let history = controller.load_history().expect("history");
            let delivery: Vec<&str> = history
                .values()
                .flatten()
                .filter(|row| row.id == hex::encode(mid))
                .map(|row| row.delivery.as_str())
                .collect();
            assert_eq!(delivery, ["cancelled"]);
            let mut app = testkit::home_app(
                (80, 24),
                state_file::Receive::Off,
                Vec::new(),
                Conversations::new(),
            );
            testkit::send(
                &mut app,
                Msg::Job(JobResult::Cancelled {
                    mid: hex::encode(mid),
                    peer: bob.pub_hex.clone(),
                    result: cancelled.result,
                    captured: cancelled.captured,
                }),
            );
            assert!(
                app.toasts_for_tests().contains(&STOPPED_TOAST),
                "{:?}",
                app.toasts_for_tests()
            );
        }

        #[test]
        fn the_node_gate_serialises_a_start_and_a_sends_start() {
            let (_dir, controller) = profile_ensuring(slow_ensure);
            let controller = Arc::new(controller);
            let node_worker = {
                let controller = Arc::clone(&controller);
                std::thread::spawn(move || controller.ensure_node().result)
            };
            let send_worker = {
                let controller = Arc::clone(&controller);
                std::thread::spawn(move || controller.ensure_for_send())
            };
            assert_eq!(node_worker.join().expect("node worker"), Ok(()));
            assert_eq!(send_worker.join().expect("send worker"), Ok(()));
            assert_eq!(RAN.load(Ordering::SeqCst), 2);
            assert_eq!(MOST.load(Ordering::SeqCst), 1, "the two starts overlapped");
        }
    }

    #[test]
    fn no_start_before_the_identity_exists() {
        let dir = testkit::short_dir();
        let controller = Controller::with_ensure(dir.path(), |_| {
            panic!("a start before the identity (expected never to run)")
        });
        assert_eq!(controller.ensure_for_send(), Err(NO_IDENTITY.to_owned()));
        #[cfg(unix)]
        {
            let ensured = controller.ensure_node();
            assert_eq!(ensured.result, Err(NO_IDENTITY.to_owned()));
            assert_eq!(ensured.started_by_app, None);
        }
        assert_eq!(
            controller.save_settings(&TuiState::default()),
            Err(NO_IDENTITY.to_owned())
        );
        assert!(!dir.path().join(state_file::FILE_NAME).exists());
    }

    /// A failing start, as ext.rs words one.
    fn no_node(_: &Path) -> Result<(), String> {
        Err(
            "local raven-node service is not running and could not be started: raven-node \
             exited before it answered"
                .into(),
        )
    }

    fn started(_: &Path) -> Result<(), String> {
        Ok(())
    }

    /// The App's answer to a send job of `controller`'s for `text` to the
    /// one friend in `app`, after Enter in the composer.
    fn sent_from(app: &mut App, controller: &Controller, text: &str) -> JobResult {
        use crossterm::event::KeyCode;
        testkit::press(app, KeyCode::Enter);
        for c in text.chars() {
            testkit::press(app, KeyCode::Char(c));
        }
        let cmds = testkit::press(app, KeyCode::Enter);
        let Some(Cmd::Send(SendJob::Send {
            local_id,
            pub_hex,
            text,
        })) = cmds.into_iter().find(|cmd| matches!(cmd, Cmd::Send(_)))
        else {
            panic!("no send job");
        };
        JobResult::Sent {
            local_id,
            outcome: controller.send(&pub_hex, &text),
        }
    }

    /// The background program can't be started: the send dials nothing and
    /// writes nothing, and the App says it was not sent, and why.
    #[test]
    fn a_send_without_the_background_program_writes_nothing() {
        let (dir, _) = profile();
        let controller = Controller::with_ensure(dir.path(), no_node);
        assert!(matches!(
            controller.load_identity(),
            IdentityState::Ready { .. }
        ));
        let (bob, card) = someone(0xB0, "127.0.0.1:9");
        add(&controller, &card, "Bob", Verify::Unpinned);
        let mut app = testkit::home_app(
            (100, 30),
            state_file::Receive::Off,
            controller.load_contacts().expect("contacts"),
            Conversations::new(),
        );
        let answer = sent_from(&mut app, &controller, "hello");
        let JobResult::Sent { outcome, .. } = &answer else {
            panic!("{answer:?}");
        };
        assert!(
            matches!(&outcome.result, SendResult::NodeUnavailable(why) if why.contains("could not be started")),
            "{outcome:?}"
        );
        assert!(controller.load_history().expect("history").is_empty());
        testkit::send(&mut app, Msg::Job(answer));
        let shown = testkit::screen_text(&testkit::render(&app, 100, 30));
        assert!(
            shown.contains(
                "You - just now x Not sent: Raven's background program isn't running on this \
                 computer. Press R to try again."
            ),
            "{shown}"
        );
        assert!(
            app.bubbles(&bob.pub_hex).len() == 1,
            "the send shows on its own"
        );
    }

    /// A blocked friend gets nothing, whatever the background program does.
    #[test]
    fn a_blocked_friend_gets_nothing() {
        let (dir, _) = profile();
        let controller = Controller::with_ensure(dir.path(), started);
        assert!(matches!(
            controller.load_identity(),
            IdentityState::Ready { .. }
        ));
        let (bob, card) = someone(0xB0, "127.0.0.1:9");
        add(&controller, &card, "Bob", Verify::Unpinned);
        let mut blocks = BlockList::load_checked(dir.path()).expect("block list");
        blocks.block(&bob.pub_hex);
        blocks.save(dir.path()).expect("block Bob");
        let sent = controller.send(&bob.pub_hex, "hello");
        assert_eq!(sent.result, SendResult::Failed(BLOCKED.into()));
        assert!(controller.load_history().expect("history").is_empty());
        // Nor anyone not saved; and nothing at all before an identity.
        let (carol, _) = someone(0xC0, "");
        assert_eq!(
            controller.send(&carol.pub_hex, "hello").result,
            SendResult::Failed(NOT_SAVED.into())
        );
        let empty = testkit::short_dir();
        assert_eq!(
            Controller::with_ensure(empty.path(), started)
                .send(&bob.pub_hex, "hello")
                .result,
            SendResult::Failed(NO_IDENTITY.into())
        );
    }

    #[test]
    fn settings_save_once_the_identity_exists() {
        let (dir, controller) = profile();
        let state = TuiState {
            display_name: "Sam".into(),
            ..TuiState::default()
        };
        controller.save_settings(&state).expect("saved");
        assert_eq!(state_file::peek(dir.path()), state);
        // The stamp is taken before the read.
        let (contacts, stamp) = controller.load_contacts_stamped();
        assert_eq!(contacts, Ok(Vec::new()));
        assert_eq!(stamp, FileStamp::default(), "no contacts.json yet");
    }

    /// A history row as raven-core writes one.
    fn entry(peer: &str, id: u8, direction: &str, at: u64, body: &str) -> ChatHistoryEntry {
        ChatHistoryEntry {
            message_id_hex: format!("{id:02x}").repeat(16),
            direction: direction.into(),
            peer_petname: String::new(),
            peer_tag: String::new(),
            peer_pub_hex: peer.into(),
            created_at_ms: at,
            delivery: if direction == "out" {
                "queued".into()
            } else {
                String::new()
            },
            preview: String::new(),
            body: body.into(),
            stored_at_ms: None,
        }
    }

    #[test]
    fn history_comes_by_friend_in_the_order_it_was_written() {
        let (dir, controller) = profile();
        // No history yet: no conversation, and no file to watch.
        let (history, stamp) = controller.load_history_stamped();
        assert_eq!(history, Ok(Conversations::new()));
        assert_eq!(stamp, FileStamp::default());
        let (bob, _) = someone(0xB0, "");
        let (alice, _) = someone(0xA1, "");
        // Bob's clock is behind: the history's order counts, not the times.
        for e in [
            entry(&bob.pub_hex, 1, "in", 3_000, "first"),
            entry(&alice.pub_hex, 2, "out", 1_000, "to alice"),
            entry(&bob.pub_hex, 3, "out", 2_000, "second"),
            entry(&bob.pub_hex.to_uppercase(), 4, "in", 500, "third"),
            ChatHistoryEntry {
                preview: "kept as a preview".into(),
                ..entry(&alice.pub_hex, 5, "in", 4_000, "")
            },
        ] {
            ChatHistory::append_persisted(dir.path(), e).expect("a row");
        }
        let (history, stamp) = controller.load_history_stamped();
        assert_ne!(stamp, FileStamp::default());
        let history = history.expect("the history");
        assert_eq!(history.len(), 2);
        let bodies = |key: &str| -> Vec<(bool, String)> {
            history[key]
                .iter()
                .map(|row| (row.outgoing, row.body.clone()))
                .collect()
        };
        assert_eq!(
            bodies(&bob.pub_hex),
            [
                (false, "first".to_owned()),
                (true, "second".to_owned()),
                (false, "third".to_owned())
            ]
        );
        assert_eq!(
            bodies(&alice.pub_hex),
            [
                (true, "to alice".to_owned()),
                (false, "kept as a preview".to_owned())
            ]
        );
        let first = &history[&bob.pub_hex][0];
        assert_eq!(
            (
                first.id.as_str(),
                first.created_at_ms,
                first.delivery.as_str()
            ),
            ("01".repeat(16).as_str(), 3_000, "")
        );
        assert_eq!(history[&alice.pub_hex][0].delivery, "queued");
    }

    /// E1: a message deleted in a desktop app (its id in
    /// desktop_hidden.json) is left out here too, by the apps' one rule; the
    /// history row itself stays.
    #[test]
    fn messages_deleted_in_a_desktop_app_are_left_out() {
        let (dir, controller) = profile();
        let (bob, _) = someone(0xB0, "");
        for e in [
            entry(&bob.pub_hex, 1, "out", 1_000, "kept"),
            ChatHistoryEntry {
                delivery: "failed".into(),
                ..entry(&bob.pub_hex, 2, "out", 2_000, "deleted in the app")
            },
            entry(&bob.pub_hex, 3, "in", 3_000, "an answer"),
        ] {
            ChatHistory::append_persisted(dir.path(), e).expect("a row");
        }
        hidden::save(dir.path(), &["02".repeat(16).to_uppercase()]).expect("saved");
        let history = controller.load_history().expect("the history");
        let bodies: Vec<&str> = history[&bob.pub_hex]
            .iter()
            .map(|row| row.body.as_str())
            .collect();
        assert_eq!(bodies, ["kept", "an answer"]);
        assert_eq!(bridge::load_history(dir.path()).expect("rows").len(), 3);
    }

    #[test]
    fn read_marks_leave_an_unreadable_settings_file_alone() {
        let (dir, controller) = profile();
        let path = dir.path().join(state_file::FILE_NAME);
        std::fs::write(&path, b"{ not json").expect("a damaged file");
        let mut state = TuiState::default();
        state.last_read.insert("ab".repeat(32), "01".repeat(16));
        assert_eq!(controller.save_read_marks(&state), Ok(false));
        assert_eq!(std::fs::read(&path).expect("still there"), b"{ not json");
        // A setting the user changes replaces it; read marks are saved from
        // then on.
        controller
            .save_settings(&TuiState::default())
            .expect("saved");
        assert_eq!(controller.save_read_marks(&state), Ok(true));
        assert_eq!(state_file::peek(dir.path()), state);
    }

    #[test]
    fn the_node_gate_outlives_a_job_that_panicked() {
        // No profile is read: the gate is only a lock.
        let controller = Arc::new(Controller::new(Path::new("unused")));
        let holder = Arc::clone(&controller);
        let died = std::thread::spawn(move || {
            let _gate = holder.node_gate();
            panic!("a node job died holding the gate");
        })
        .join();
        assert!(died.is_err());
        drop(controller.node_gate());
    }

    /// A horizon read that knows friend 1's (3 h left) and friend 2's (none
    /// can wait: their secure connection ended), and nobody else's.
    fn two_known(_: &Path, peer: &str, now_ms: u64) -> Option<bridge::QueueReach> {
        match peer.get(..2) {
            Some("01") => Some(bridge::QueueReach::CanWait {
                until_ms: now_ms + 3 * 3_600_000,
            }),
            Some("02") => Some(bridge::QueueReach::Ended { at_ms: now_ms }),
            _ => None,
        }
    }

    #[test]
    fn horizons_keep_what_is_known_once_there_is_an_identity() {
        testkit::lab_backends();
        let dir = testkit::short_dir();
        let controller = Controller::with_horizon(dir.path(), two_known);
        let peers: Vec<String> = [1, 2, 3]
            .into_iter()
            .map(|n| testkit::friend(n).pub_hex.to_uppercase())
            .collect();
        // Nothing is read for a profile without an identity.
        assert_eq!(controller.horizons(&peers), Horizons::new());
        controller.create_identity().result.expect("create");
        let before = bridge::now_ms();
        let found = match workers::store_job(&controller, StoreJob::LoadHorizons { peers }) {
            JobResult::Horizons(found) => found,
            other => panic!("{other:?}"),
        };
        assert_eq!(found.len(), 2, "{found:?}");
        assert!(matches!(
            found.get(&testkit::friend(2).pub_hex),
            Some(bridge::QueueReach::Ended { .. })
        ));
        let until = found
            .get(&testkit::friend(1).pub_hex)
            .and_then(|reach| reach.horizon())
            .expect("friend 1's, by its key in lower case");
        assert!(
            until >= before + 3 * 3_600_000,
            "read at the time of the read"
        );
    }

    #[test]
    fn the_store_worker_reads_the_horizons_and_a_draw_never_does() {
        // The reads are counted on this thread: the App's update and every
        // draw run here, and so does the store job below. The long horizon
        // is on in release builds since 2026-10 (then a first message waits
        // too: `bridge`'s horizon tests); here it is off on this thread, so
        // the never-paired words are the ones read and drawn.
        raven_core::horizon::set_lab_horizon_for_this_thread(Some(false));
        let (_dir, controller) = profile();
        let friends = vec![testkit::reachable(1), testkit::reachable(2)];
        let peers: Vec<String> = friends.iter().map(|f| f.pub_hex.clone()).collect();
        let mut app = testkit::home_app(
            (80, 24),
            state_file::Receive::Off,
            friends,
            Conversations::new(),
        );
        let reads = bridge::horizon_reads();
        testkit::press(&mut app, crossterm::event::KeyCode::Enter);
        let until = app.now_ms() + 3_600_000;
        let known = Horizons::from([
            (
                peers[0].clone(),
                bridge::QueueReach::CanWait { until_ms: until },
            ),
            (peers[1].clone(), bridge::QueueReach::Ended { at_ms: 0 }),
        ]);
        testkit::send(&mut app, Msg::Job(JobResult::Horizons(known)));
        let mut shown = Vec::new();
        for (cols, rows) in [(80, 24), (70, 20), (60, 16), (100, 30)] {
            shown.extend(testkit::render(&app, cols, rows));
        }
        assert!(
            testkit::screen_text(&shown).contains("keeps trying until"),
            "the line is drawn"
        );
        assert_eq!(bridge::horizon_reads(), reads, "a draw never reads");
        // The poller's word: the update hands the read to the store worker
        // and reads nothing itself.
        let cmds = testkit::send(&mut app, Msg::Poll(workers::PollUpdate::HorizonsDue));
        assert_eq!(bridge::horizon_reads(), reads);
        let job = cmds
            .into_iter()
            .find_map(|cmd| match cmd {
                Cmd::Store(job @ StoreJob::LoadHorizons { .. }) => Some(job),
                _ => None,
            })
            .expect("a read for the store worker");
        let answer = workers::store_job(&controller, job);
        assert_eq!(bridge::horizon_reads(), reads + 2, "one per friend");
        // raven-core's read (CP.6): no secure connection with either friend
        // in this profile yet, so nothing can wait for them: a first message
        // goes only while both are online (E1).
        let none = peers
            .iter()
            .map(|p| (p.to_ascii_lowercase(), bridge::QueueReach::NeverPaired))
            .collect::<Horizons>();
        assert_eq!(answer, JobResult::Horizons(none));
        testkit::send(&mut app, Msg::Job(answer));
        let screen = testkit::screen_text(&testkit::render(&app, 80, 24));
        assert!(!screen.contains("keeps trying until"), "{screen}");
        assert!(screen.contains("needs you and"), "{screen}");
        assert!(!screen.contains("meet first"), "{screen}");
        assert_eq!(bridge::horizon_reads(), reads + 2);
        raven_core::horizon::set_lab_horizon_for_this_thread(None);
    }

    /// Privacy pack PP.21: the App's privacy jobs, through the store worker
    /// on a real profile: the read, a 'Keep chats for' save, Delete chat
    /// (Bob's messages go, Alice's stay) and Forget address.
    /// The starts the reopen test's fake start ran, each once the lock was
    /// gone.
    static REOPEN_STARTS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    fn start_after_the_lock(data_dir: &Path) -> Result<(), String> {
        assert!(
            !bridge::lock_state_for_tests(data_dir).0,
            "the lock goes before the start"
        );
        REOPEN_STARTS.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    /// Opening the app is its way to start Raven again after its own Lock
    /// (PP.23); after `raven lock` it asks first (review
    /// E-harness-docs-ci-3). That lock stays when the app opens (nothing
    /// could start Raven: a start is refused) and goes only with UNLOCK's
    /// yes, before Raven's one start. The login item is never turned on (a
    /// `raven lock` that turned it off leaves it off, and the privacy read
    /// says so for Home).
    #[test]
    fn opening_a_locked_profile_clears_the_lock_before_its_one_start() {
        let (dir, _made) = profile();
        bridge::lock_for_tests(dir.path(), Some("disabled"));
        let controller = Controller::with_ensure(dir.path(), start_after_the_lock);
        assert!(matches!(
            controller.load_identity(),
            IdentityState::Ready { .. }
        ));
        assert!(controller.reopen_after_lock(), "`raven lock`'s is kept");
        assert_eq!(
            bridge::lock_state_for_tests(dir.path()),
            (true, Some("disabled"))
        );
        assert!(
            !controller
                .read_privacy()
                .expect("the read")
                .login_item_stays_off
        );
        assert_eq!(controller.unlock(), Ok(()));
        assert_eq!(
            bridge::lock_state_for_tests(dir.path()),
            (false, Some("disabled"))
        );
        assert!(
            controller
                .read_privacy()
                .expect("the read")
                .login_item_stays_off
        );
        assert_eq!(controller.ensure_node().result, Ok(()));
        assert_eq!(REOPEN_STARTS.load(Ordering::SeqCst), 1);
        // A profile that isn't locked: nothing to clear, but the login item
        // the lock turned off is still off, and the next session says so
        // too (review D-lock-tui-4), until `raven unlock`.
        let again = Controller::new(dir.path());
        again.load_identity();
        assert!(!again.reopen_after_lock());
        assert!(again.read_privacy().expect("the read").login_item_stays_off);
        assert_eq!(
            bridge::lock_state_for_tests(dir.path()),
            (false, Some("disabled"))
        );
        // With nothing recorded: nothing to say.
        let (other, _made) = profile();
        let plain = Controller::new(other.path());
        plain.load_identity();
        assert!(!plain.reopen_after_lock());
        assert!(!plain.read_privacy().expect("the read").login_item_stays_off);
        // The app's own Lock: cleared when the app opens, nothing asked.
        bridge::set_locked_by_user(dir.path(), true).expect("locked");
        assert!(!again.reopen_after_lock());
        assert!(!bridge::lock_state_for_tests(dir.path()).0);
        // Before the identity loads, nothing is touched.
        bridge::lock_for_tests(dir.path(), None);
        assert!(!Controller::new(dir.path()).reopen_after_lock());
        assert!(bridge::lock_state_for_tests(dir.path()).0);
        assert!(Controller::new(dir.path()).unlock().is_err());
        assert!(bridge::lock_state_for_tests(dir.path()).0);
    }

    #[test]
    fn the_privacy_jobs_run_on_the_profile() {
        let (dir, controller) = profile();
        let (bob, card) = someone(0xB0, "192.168.1.30:7420");
        let (alice, _) = someone(0xA1, "");
        add(&controller, &card, "Bob", Verify::Unpinned);
        let job = |job| workers::store_job(&controller, job);
        let read = |keep| {
            JobResult::Privacy(Ok(PrivacyRead {
                keep,
                notices: PrivacyNotices::default(),
                disk_needed: None,
                login_item_stays_off: false,
            }))
        };
        // A plain profile: 30 days, and no notice due.
        assert_eq!(job(StoreJob::LoadPrivacy), read(ChatKeepView::Days30));
        assert_eq!(
            job(StoreJob::SetChatKeep(ChatKeepView::Days90)),
            JobResult::ChatKeepSaved {
                keep: ChatKeepView::Days90,
                result: Ok(()),
            }
        );
        assert_eq!(job(StoreJob::LoadPrivacy), read(ChatKeepView::Days90));
        // Nothing due: marking one changes nothing.
        assert_eq!(
            job(StoreJob::MarkNoticeShown(Notice::Retention)),
            JobResult::NoticeMarked(Notice::Retention)
        );
        // Delete chat: both directions with Bob go, Alice's stay.
        for e in [
            entry(&bob.pub_hex, 1, "in", 3_000, "hi"),
            entry(&alice.pub_hex, 2, "in", 1_000, "hello"),
            entry(&bob.pub_hex, 3, "out", 2_000, "hi back"),
        ] {
            ChatHistory::append_persisted(dir.path(), e).expect("a row");
        }
        assert_eq!(
            job(StoreJob::DeleteChat {
                pub_hex: bob.pub_hex.clone()
            }),
            JobResult::ChatDeleted {
                pub_hex: bob.pub_hex.clone(),
                result: Ok(DeleteChatOutcome {
                    deleted: 2,
                    still_waiting: 0,
                    skipped_pending: 0,
                }),
            }
        );
        let history = controller.load_history().expect("the history");
        assert_eq!(history.keys().collect::<Vec<_>>(), [&alice.pub_hex]);
        // Forget address: Bob's goes, his name stays.
        assert_eq!(
            job(StoreJob::ForgetAddress {
                pub_hex: bob.pub_hex.clone()
            }),
            JobResult::FriendChanged {
                change: FriendChange::ForgetAddress,
                pub_hex: bob.pub_hex.clone(),
                result: Ok(()),
                notes: Vec::new(),
            }
        );
        let saved_bob = saved(&controller, &bob.pub_hex).expect("Bob");
        assert_eq!(
            (saved_bob.label.as_str(), saved_bob.lan_dial.as_str()),
            ("Bob", "")
        );
        // A part that can't be forgotten now (where Bob last connected from
        // can't be read): the saved address is gone all the same, and the
        // answer says what is left (review D-lock-tui-8).
        std::fs::create_dir(dir.path().join("lan_seen.json")).expect("a folder in its place");
        let JobResult::FriendChanged {
            change: FriendChange::ForgetAddress,
            result: Ok(()),
            notes,
            ..
        } = job(StoreJob::ForgetAddress {
            pub_hex: bob.pub_hex.clone(),
        })
        else {
            panic!("not a partial forget");
        };
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert!(
            notes[0].starts_with("could not forget where it last connected from ("),
            "{notes:?}"
        );
        // Someone not saved: refused.
        let forgot = controller.forget_address(&alice.pub_hex);
        assert_eq!(forgot.result, Err(NOT_SAVED.to_owned()));
    }

    // ── Erase (privacy pack PP.22) ──────────────────────────────────────────

    /// A profile `a` in a folder of its own (bridge.rs's lab erase keeps
    /// Raven's login item in `lab` beside it), its identity made by a
    /// controller that erases with `erase`, Bob saved and a chat with him,
    /// sealed as a command's top seals it.
    fn erasable(
        erase: fn(&Path, &mut dyn FnMut()) -> EraseEnd,
    ) -> (tempfile::TempDir, PathBuf, Controller) {
        testkit::lab_backends();
        let root = testkit::short_dir();
        let dd = root.path().join("a");
        std::fs::create_dir_all(&dd).expect("the profile");
        let dd = std::fs::canonicalize(dd).expect("the profile");
        let controller = Controller::with_erase(&dd, erase);
        controller.create_identity().result.expect("create");
        let (bob, card) = someone(0xB0, "192.168.1.30:7420");
        add(&controller, &card, "Bob", Verify::Unpinned);
        ChatHistory::append_persisted(&dd, entry(&bob.pub_hex, 1, "in", 1_000, "hi"))
            .expect("a row");
        raven_core::privacy::migrate_all(
            &dd,
            bridge::now_ms(),
            raven_core::at_rest::MigratePolicy::Allow,
        )
        .expect("sealed");
        (root, dd, controller)
    }

    thread_local! {
        /// What [`recording_erase`] saw when the controller closed.
        static AT_CLOSE: std::cell::RefCell<Vec<String>> = const {
            std::cell::RefCell::new(Vec::new())
        };
    }

    /// bridge.rs's lab erase, noting at the controller's close whether the
    /// marker was down, the key file still there and the at-rest keys
    /// cached, and whether they still were after it.
    fn recording_erase(dd: &Path, close: &mut dyn FnMut()) -> EraseEnd {
        let cached = || raven_core::at_rest::keys_cached(dd).is_ok();
        bridge::erase_in_lab(dd, &mut || {
            let before = format!(
                "marker {}, key file {}, keys cached {}",
                raven_core::erase::in_progress(dd),
                dd.join(raven_core::at_rest::META_KEY_FILE).exists(),
                cached()
            );
            close();
            let after = format!("keys cached {}", cached());
            AT_CLOSE.with(|seen| seen.borrow_mut().extend([before, after]));
        })
    }

    /// The app's hold on the profile ends once the erase can't be taken back
    /// (the marker is down) and before the first key or file goes: once,
    /// the at-rest keys forgotten, every later job refused.
    #[test]
    fn stores_closed_before_execute() {
        let (_root, dd, controller) = erasable(recording_erase);
        assert!(raven_core::at_rest::keys_cached(&dd).is_ok(), "sealed here");
        AT_CLOSE.with(|seen| seen.borrow_mut().clear());
        let JobResult::Erased(EraseEnd::Ran { finished, lines }) =
            workers::store_job(&controller, StoreJob::Erase)
        else {
            panic!("the erase did not run");
        };
        assert!(finished, "{lines:?}");
        assert_eq!(
            AT_CLOSE.with(|seen| seen.borrow().clone()),
            [
                "marker true, key file true, keys cached true",
                "keys cached false"
            ]
        );
        assert!(controller.closed());
        assert!(!dd.exists());
    }

    /// After the erase nothing writes into the profile or makes its folder
    /// again: saves are no-ops, every job refuses (review R15).
    #[test]
    fn nothing_is_saved_after_erase() {
        let (root, dd, controller) = erasable(bridge::erase_in_lab);
        let job = |job| workers::store_job(&controller, job);
        let JobResult::Erased(EraseEnd::Ran {
            finished: true,
            lines,
        }) = job(StoreJob::Erase)
        else {
            panic!("the erase did not finish");
        };
        assert!(
            lines[0].starts_with("Erased: identity, friends, chats, waiting messages and "),
            "{lines:?}"
        );
        assert!(!dd.exists());
        let state = TuiState {
            display_name: "Sam".into(),
            ..TuiState::default()
        };
        assert_eq!(controller.save_settings(&state), Ok(()));
        assert_eq!(controller.save_read_marks(&state), Ok(false));
        let refused = Err(ERASED.to_owned());
        assert_eq!(controller.load_contacts().map(|_| ()), refused);
        assert_eq!(controller.load_history().map(|_| ()), refused);
        assert_eq!(controller.set_chat_keep(ChatKeepView::Days7), refused);
        assert_eq!(controller.read_privacy(), Err(NotAvailable));
        assert_eq!(controller.erase_plan(), Err(ERASED.to_owned()));
        assert!(controller.ensure_node().result.is_err());
        assert!(controller.ensure_for_send().is_err());
        assert!(controller.create_identity().result.is_err());
        assert!(matches!(
            controller.load_identity(),
            IdentityState::Unavailable(_)
        ));
        controller.mark_notice_shown(Notice::Sealing);
        assert_eq!(controller.erase(), EraseEnd::NotErased(ERASED.to_owned()));
        for store in [
            StoreJob::SaveSettings(state.clone()),
            StoreJob::SaveReadMarks(state.clone()),
            StoreJob::LoadContacts,
            StoreJob::LoadHistory,
            StoreJob::LoadPrivacy,
            StoreJob::MarkNoticeShown(Notice::Retention),
            StoreJob::ShareCard { listen: None },
            StoreJob::CreateIdentity,
        ] {
            job(store);
        }
        let (bob, _) = someone(0xB0, "");
        assert!(controller.delete_chat(&bob.pub_hex).result.is_err());
        assert!(controller.forget_address(&bob.pub_hex).result.is_err());
        assert!(controller.rename(&bob.pub_hex, "Robert").result.is_err());
        assert!(matches!(
            controller.send(&bob.pub_hex, "hi").result,
            SendResult::Failed(_)
        ));
        assert!(!dd.exists(), "the profile's folder was made again");
        // Beside it only the lab's folder for the login item.
        assert_eq!(entries(root.path()), ["lab"]);
    }

    /// An erase that changed nothing (Raven still runs) leaves the profile
    /// the app's as it was: it saves again.
    #[test]
    fn an_erase_that_changed_nothing_keeps_the_profile_open() {
        fn still_running(_: &Path, _: &mut dyn FnMut()) -> EraseEnd {
            EraseEnd::NotErased("Raven is still running, so erase can't continue".into())
        }
        let (_root, dd, controller) = erasable(still_running);
        assert!(matches!(
            workers::store_job(&controller, StoreJob::Erase),
            JobResult::Erased(EraseEnd::NotErased(_))
        ));
        assert!(!controller.closed());
        assert_eq!(controller.save_settings(&TuiState::default()), Ok(()));
        assert!(dd.join("tui_state.json").exists());
        assert_eq!(controller.load_contacts().map(|c| c.len()), Ok(1));
    }
}
