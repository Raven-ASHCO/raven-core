//! The desktop engine's way into the CLI (node/crates/raven-client).
//!
//! The only file that names items of cli.rs, ext.rs, pair_init_lab.rs,
//! p2p_cli.rs and ipc_client.rs for the engine, in the manner of the terminal
//! app's `tui/bridge.rs` (branch feature/terminal-app). Types the CLI keeps
//! private come out as plain views ([`ContactView`], [`FriendPreview`]), so
//! the engine never reaches into a cli.rs struct, and the friend's security
//! code is never part of a view.
//!
//! Nothing here exits the process or reads stdin, and the CLI's own printing
//! is switched off for the process by [`set_quiet`] (the engine calls it once).
//! The functions that mirror a CLI command (a card without printing it, a send
//! to a saved friend with the identity the engine already holds) name the
//! cli.rs function they follow: change both together.

use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::time::Duration;

use raven_core::chat_history::BlockList;
use raven_core::identity::Identity;
use raven_core::ipc::{IpcRequest, IpcResponse};

use super::pair_init_lab::{DialCarrier, DialRoute};

/// Drops everything the CLI code prints on stdout, for the rest of this
/// process (cli.rs's `print_stdout`). Its stderr notes are left alone.
pub fn set_quiet() {
    super::STDOUT_QUIET.store(true, Ordering::Relaxed);
}

// ── Profile and identity ────────────────────────────────────────────────────

/// The profile folder the CLI uses without `--data-dir`: `RAVEN_DATA_DIR`,
/// else `ASH_DATA_DIR`, else `~/.raven` (raven-core's lookup, as cli.rs's
/// `default_ash_data_dir`).
pub fn default_data_dir() -> Result<PathBuf, String> {
    super::default_ash_data_dir()
}

/// The profile's identity (cli.rs's `try_load_identity`): None before there
/// is one; the error is raven-core's redacted reason.
pub fn try_load_identity(data_dir: &Path) -> Result<Option<Identity>, String> {
    super::try_load_identity(data_dir)
}

/// Creates the profile folder owner-only (0700) when it is missing, as the
/// CLI does at start (cli.rs's `create_private_data_dir`).
pub fn create_private_data_dir(dir: &Path) -> std::io::Result<()> {
    super::create_private_data_dir(dir)
}

// ── Opening the profile (cli.rs `run`, before every command) ────────────────

/// Why the profile is closed to everything but the CLI command that
/// finishes what was left unfinished (cli.rs `run`'s refusals). The text is
/// raven-core's, whole: it names that command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Closed {
    /// An erase of this profile did not finish (privacy pack PP.16):
    /// [`ERASE_UNFINISHED_TEXT`].
    EraseUnfinished(String),
    /// A `raven privacy rotate-meta` did not finish, or the `raven privacy
    /// unseal` that ends one (PP.18): stores may still be keyed under the
    /// old key.
    MetaRotationUnfinished(String),
}

impl Closed {
    /// raven-core's sentence, which names the command that finishes it.
    pub fn text(&self) -> &str {
        match self {
            Closed::EraseUnfinished(text) | Closed::MetaRotationUnfinished(text) => text,
        }
    }
}

/// cli.rs `run`'s two refusals as they stand now: file reads only (no
/// keystore call, no lock, nothing written), so a process that keeps the
/// profile open can ask before each operation.
pub fn closed(data_dir: &Path) -> Option<Closed> {
    if let Err(text) = raven_core::erase::refuse_if_unfinished(data_dir) {
        return Some(Closed::EraseUnfinished(text));
    }
    raven_core::privacy::refuse_if_meta_rotation_unfinished(data_dir)
        .err()
        .map(Closed::MetaRotationUnfinished)
}

/// What cli.rs's `run` does before every command but `raven erase` (the
/// terminal app is started from there too), in its order, for a process
/// that keeps the profile open: the erase refusal (PP.16); the folder made
/// owner-only; the at-rest key loaded and what is still plain sealed
/// ([`load_at_rest`], PP.4); friends' unused addresses, chats older than
/// the setting and old data keys taken off the disk while no raven-node runs
/// (cli.rs's `prune_without_node`: PP.7, PP.9, PP.10, PP.12); the
/// rotate-meta refusal (PP.18); and `raven lan off` for this process
/// (Phase 3). The one-time notices are not said: they stay due for the next
/// command that says them. Change both together.
///
/// At the top level only: never under a data-dir lock or inside a store
/// transaction (raven-core's `at_rest::keys_load` asserts it in debug
/// builds); it may wait on a keychain dialog.
pub fn open_profile(data_dir: &Path) -> Result<(), Closed> {
    if let Err(text) = raven_core::erase::refuse_if_unfinished(data_dir) {
        return Err(Closed::EraseUnfinished(text));
    }
    let _ = super::create_private_data_dir(data_dir);
    load_at_rest(data_dir);
    super::prune_without_node(data_dir);
    raven_core::privacy::refuse_if_meta_rotation_unfinished(data_dir)
        .map_err(Closed::MetaRotationUnfinished)?;
    super::ext::lan_off_now(data_dir);
    Ok(())
}

/// cli.rs's `prepare_at_rest` without its notices: this profile's at-rest
/// key loaded (a sealed profile's; the keystore is asked at most once per
/// process while it gives the key), what is still plain sealed (a release
/// build, or a debug build with `RAVEN_LAB_AT_REST=1`) unless an older
/// raven-node answers for the profile, and the terminal app's private
/// fields moved (review D-lock-tui-1). An unavailable key is no error here.
/// Whether this process holds the key afterwards. The same rules as
/// [`open_profile`].
pub fn load_at_rest(data_dir: &Path) -> bool {
    let _ = super::at_rest_notices(data_dir, raven_core::at_rest::MigratePolicy::Auto, false);
    at_rest_keys_loaded(data_dir)
}

/// Whether this process holds the profile's at-rest key (raven-core's
/// `at_rest::keys_cached`; no keystore call).
pub fn at_rest_keys_loaded(data_dir: &Path) -> bool {
    raven_core::at_rest::keys_cached(data_dir).is_ok()
}

/// A sealed profile whose at-rest key this process does not hold: its
/// friends list, history and the rest can't be read or written until
/// [`load_at_rest`] gets the key. File reads only.
pub fn at_rest_key_missing(data_dir: &Path) -> bool {
    raven_core::privacy::mode(data_dir) == raven_core::at_rest::Mode::Sealed
        && !at_rest_keys_loaded(data_dir)
}

// ── Contacts ────────────────────────────────────────────────────────────────

/// One saved friend, as contacts.json and the block list have them. Strings
/// are as stored (raw): the engine sanitises what it shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactView {
    pub pub_hex: String,
    pub address: String,
    /// cli.rs's `Contact::primary_label`: the name on this computer, else
    /// `@tag`, else the address.
    pub label: String,
    /// The name given on this computer (petname), or empty.
    pub petname: String,
    /// Verified: the user checked the friend's words or code and it matched.
    pub pinned: bool,
    pub blocked: bool,
    pub lan_dial: String,
    pub internet_dial: String,
    /// The friend's p2p PeerId, or empty.
    pub p2p: String,
}

/// The saved friends in file order. A corrupt contacts.json or block list is
/// an error, never an empty list.
pub fn contact_views(data_dir: &Path) -> Result<Vec<ContactView>, String> {
    let contacts = super::load_contacts(data_dir)?;
    let blocks = BlockList::load_checked(data_dir).map_err(|e| format!("block list: {e}"))?;
    Ok(contacts
        .iter()
        .map(|c| ContactView {
            pub_hex: c.pub_hex.clone(),
            address: c.address.clone(),
            label: c.primary_label(),
            petname: c.petname.clone(),
            pinned: c.pinned,
            blocked: blocks.is_blocked(&c.pub_hex),
            lan_dial: c.lan_dial.clone(),
            internet_dial: c.internet_dial.clone(),
            p2p: c.p2p.clone(),
        })
        .collect())
}

/// contacts.json in `data_dir` (its size and time say when it changed).
pub fn contacts_path(data_dir: &Path) -> PathBuf {
    super::contacts_path(data_dir)
}

// ── Deleted messages (shared with the terminal app: tui/hidden.rs) ─────────

/// `desktop_hidden.json`'s ids: ended messages of yours deleted in a desktop
/// app, which the terminal app leaves out of its chats too (none when the
/// file is missing or unreadable).
pub fn load_hidden(data_dir: &Path) -> Vec<String> {
    super::tui::hidden::load(data_dir)
}

/// Writes the deleted messages' ids, the newest 2000 of them.
pub fn save_hidden(data_dir: &Path, ids: &[String]) -> Result<(), String> {
    super::tui::hidden::save(data_dir, ids)
}

// ── Read markers (the terminal app's, shared: tui/read_marks.rs) ───────────

/// One friend's marker, every friend's, and a conversation's message as the
/// count reads it: the terminal app's own types, so both apps count alike.
pub type ReadMark = super::tui::read_marks::ReadMark;
pub type ReadMarks = super::tui::read_marks::ReadMarks;
pub type Row<'a> = super::tui::read_marks::Row<'a>;

/// The friend's unread messages after `mark`, as the terminal app counts
/// them (rows in history order; yours never count).
pub fn unread<'a>(rows: impl IntoIterator<Item = Row<'a>>, mark: Option<&ReadMark>) -> usize {
    super::tui::read_marks::unread(rows, mark)
}

/// Whether `candidate` is a later marker than `current` for one friend
/// (`place`: a message's index in the conversation, when known).
pub fn later_read_mark(
    candidate: &ReadMark,
    current: &ReadMark,
    place: &dyn Fn(&str) -> Option<usize>,
) -> bool {
    super::tui::read_marks::later(candidate, current, place)
}

/// The files the read markers live in (tui_state.json, and tui_private.rms
/// in a sealed profile): a change to either may be the terminal app's read.
pub fn read_marks_files(data_dir: &Path) -> [PathBuf; 2] {
    super::tui::read_marks::files(data_dir)
}

/// Every friend's read marker as saved, read as the terminal app reads them
/// (none on any problem). Reads only.
pub fn read_marks(data_dir: &Path) -> ReadMarks {
    super::tui::read_marks::load(data_dir)
}

/// The friend `pub_hex`'s chat read up to `mark` in the shared markers,
/// unless the saved one is later (`place`: a message's index in that
/// friend's conversation). Whether it was saved; refused before the
/// identity exists, and a file that can't be read is left as it is (the
/// reason comes back).
pub fn mark_read(
    data_dir: &Path,
    pub_hex: &str,
    mark: ReadMark,
    place: &dyn Fn(&str) -> Option<usize>,
) -> Result<bool, String> {
    super::tui::read_marks::mark_read(data_dir, pub_hex, mark, place)
}

/// A card's p2p route: a PeerId and its `via=` multiaddrs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct P2pView {
    pub peer_id: String,
    pub via: Vec<String>,
    /// The owner's next PeerId (a `raven-card/3`'s `p2pn=`, PeerId
    /// rotation), kept with the route as `contact add --card` keeps it.
    pub next: Option<String>,
}

impl P2pView {
    /// Back to cli.rs's route, validated again as a card's would be.
    fn route(&self) -> Result<super::P2pRoute, String> {
        let via: Vec<&str> = self.via.iter().map(String::as_str).collect();
        let route = super::P2pRoute::parse(&self.peer_id, &via).map_err(|e| format!("p2p: {e}"))?;
        match &self.next {
            Some(next) => route.with_next(next),
            None => Ok(route),
        }
    }
}

/// A friend's invite or card, parsed and self-consistent (cli.rs's
/// `parse_card_or_invite`: the address is the one the key encodes to, a
/// card's code is its key's own). The routes are hints, never identity. The
/// friend's code is left out on purpose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FriendPreview {
    pub address: String,
    pub pub_hex: String,
    /// The local-network route (`lan=`), or empty.
    pub lan: String,
    /// The Internet route (`inet=`), or empty.
    pub internet: String,
    pub p2p: Option<P2pView>,
    /// The friend's Tor onion binding (a card's `onion=`, lab), as text:
    /// signed by the friend's key, checked when the card was read.
    pub onion: Option<String>,
}

/// One card line or invite line, as `contact add --card` reads it.
pub fn parse_card_or_invite(text: &str) -> Result<FriendPreview, String> {
    super::parse_card_or_invite(text).map(|card| FriendPreview {
        p2p: card.p2p.as_ref().map(|r| P2pView {
            peer_id: r.peer_id.clone(),
            via: r.via.clone(),
            next: r.next.clone(),
        }),
        address: card.address,
        pub_hex: card.pub_hex,
        lan: card.lan,
        internet: card.internet,
        onion: card
            .onion
            .as_ref()
            .map(raven_core::onion::OnionBinding::to_text),
    })
}

/// A friend's Tor onion binding from their card (`onion`, binding text),
/// kept in their book row as `contact add --card` keeps it (the newest one
/// their key signed): the onion route is then planned for `raven send` and
/// the outbox as soon as the friend is verified (E2 r40 P1: the app's add
/// dropped it, and sends to a friend reachable only over Tor tried p2p
/// alone until the friend dialled in).
pub fn keep_card_onion(data_dir: &Path, pub_hex: &str, onion: Option<&str>) -> Result<(), String> {
    let Some(text) = onion else {
        return Ok(());
    };
    let binding = raven_core::onion::OnionBinding::from_text(text.trim())
        .ok_or("their Tor onion address could not be read")?;
    let key = super::parse_pub_hex_strict(pub_hex)?;
    raven_core::onion::store_contact_binding(data_dir, &key, &binding).map(drop)
}

/// Whether `text` is shaped like a card or an invite (whether or not it is a
/// valid one).
pub fn looks_like_card_or_invite(text: &str) -> bool {
    text.trim_start().starts_with("raven-card/") || super::parse_raven_invite(text).is_some()
}

/// cli.rs's `add_contact_with_routes`, the one way a friend is saved: the key
/// and address checked again, the pin decided by `verify_fp` against the
/// key's own code, names kept unique. An empty name or route keeps what is
/// saved; `p2p` None keeps the saved one.
#[allow(clippy::too_many_arguments)]
pub fn add_contact_with_routes(
    data_dir: &Path,
    address: &str,
    pub_hex: &str,
    petname: &str,
    verify_fp: Option<&str>,
    lan_dial: &str,
    internet_dial: &str,
    p2p: Option<&P2pView>,
) -> Result<(), String> {
    let p2p = p2p.map(P2pView::route).transpose()?;
    super::add_contact_with_routes(
        data_dir,
        address,
        pub_hex,
        petname,
        "",
        verify_fp,
        lan_dial,
        internet_dial,
        p2p.as_ref(),
    )
}

/// `contact remove --address <address> --yes` (the app asked first).
pub fn remove_contact(data_dir: &Path, address: &str) -> Result<(), String> {
    super::cmd_contact_remove(data_dir, None, None, Some(address), true)
}

/// `contact set-dial --address <address> <lan>`: checked as the CLI checks
/// it; the outbox plans from the book again, and what the friend told this
/// computer (its route hints, its PeerId) stays.
pub fn set_contact_lan(data_dir: &Path, address: &str, lan: &str) -> Result<(), String> {
    super::cmd_contact_set_dial(data_dir, None, None, Some(address), lan)
}

/// A LAN address as the CLI saves one (`host:port`), or why not.
pub fn parse_lan_dial(raw: &str) -> Result<String, String> {
    super::parse_lan_dial(raw)
}

/// The old code the user typed against a friend's: separators ignored, case
/// not (cli.rs).
pub fn fingerprint_matches(typed: &str, fp: &str) -> bool {
    super::fingerprint_matches(typed, fp)
}

/// The right characters in the wrong upper or lower case.
pub fn fingerprint_case_only_mismatch(typed: &str, fp: &str) -> bool {
    super::fingerprint_case_only_mismatch(typed, fp)
}

// ── Cards ───────────────────────────────────────────────────────────────────

/// This profile's card, as `raven whoami --card [--lan <lan>]` prints it
/// (mirrors cli.rs's `cmd_whoami_card` without `--inet`, `--via` and
/// `--compat`, returning the line instead of printing it): the p2p part
/// follows what the running raven-node does, else node_policy.json, and
/// names the PeerId of the node's rotation epoch while rotation is live.
pub fn card_line(data_dir: &Path, id: &Identity, lan: &str) -> Result<String, String> {
    let lan = if lan.trim().is_empty() {
        String::new()
    } else {
        super::parse_lan_dial(lan).map_err(|e| format!("--lan: {e}"))?
    };
    let v3_ok = raven_core::route_hints::route_hints_live() && lan.is_empty();
    let rotation_live = raven_core::peer_rotation_live_enabled();
    let daemon = super::ipc_client::ipc_request_timeout(
        data_dir,
        &IpcRequest::status(),
        Duration::from_millis(1500),
    );
    let policy = super::card_policy(data_dir, &daemon);
    let rotation = if rotation_live {
        super::card_rotation_epoch(&daemon)
    } else {
        None
    };
    let p2p = super::own_card_route(id, &[], &policy, v3_ok)?.map(|route| match rotation {
        Some(epoch) => super::rotating_card_route(id, route, epoch),
        None => route,
    });
    let version = super::whoami_card_version(p2p.as_ref(), v3_ok);
    // With this profile's Tor onion binding, as `raven whoami --card` (E2
    // r40 P1: a friend reachable only over Tor needs it from the card).
    let card = super::with_onion_field(
        super::format_card_as(version, id, "", &lan, p2p.as_ref()),
        super::own_card_onion(data_dir, id, false).as_ref(),
    );
    if card.len() > version.max_len() {
        return Err(format!(
            "this card would be {} characters, more than the {} a card may have",
            card.len(),
            version.max_len()
        ));
    }
    Ok(card)
}

/// A `raven-card/1` with no route at all: the fallback when [`card_line`]
/// cannot read the node's settings.
pub fn plain_card(id: &Identity) -> String {
    super::format_card_as(super::CardVersion::V1, id, "", "", None)
}

// ── Sending ─────────────────────────────────────────────────────────────────

/// How ext.rs starts an outcome text whose message is queued on this
/// computer.
pub const QUEUED_PREFIX: &str = super::ext::QUEUED_PREFIX;
/// How ext.rs starts an outcome text whose message was written to the
/// friend's computer, which has not confirmed it.
pub const UNCONFIRMED_PREFIX: &str = super::ext::UNCONFIRMED_PREFIX;
/// The words of a queued outcome that say raven-node keeps retrying it.
pub const BACKGROUND_RETRY: &str = super::ext::BACKGROUND_RETRY;

/// What the CLI refuses in typed message text before anything is sent: an
/// escape sequence or another control character (tab and line breaks are
/// fine). cli.rs's `tty_message_problem`.
pub fn message_problem(text: &str) -> Option<&'static str> {
    super::tty_message_problem(text)
}

/// ext.rs's reading of a raw send failure, one variant per variant of
/// ext.rs's `Cause` (the match below fails to compile when ext.rs adds one).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cause {
    NotListening,
    NotReachable,
    NameNotFound,
    ClosedEarly,
    PeerRefused,
    WrongIdentity,
    NoAddress,
    BadAddress,
    ServiceDown,
    ServiceStart,
    ServiceSlow,
    KeychainDenied,
    HistoryLocked,
    HistoryUnreadable,
    TooLarge,
    BadCharacters,
    Blocked,
    SendInProgress,
    EmptyMessage,
    PinStoreUnreadable,
    LanOff,
    /// macOS refused this computer's own connection on the local network
    /// (Local Network permission), not the contact.
    LocalNetworkRefused,
    Other,
}

/// ext.rs's `classify_cause` (the CLI's own classifier, so a failure text
/// the CLI learns to explain is explained in the app too).
pub fn classify_cause(raw: &str) -> Cause {
    use super::ext::Cause as C;
    match super::ext::classify_cause(raw) {
        C::NotListening => Cause::NotListening,
        C::NotReachable => Cause::NotReachable,
        C::NameNotFound => Cause::NameNotFound,
        C::ClosedEarly => Cause::ClosedEarly,
        C::PeerRefused => Cause::PeerRefused,
        C::WrongIdentity => Cause::WrongIdentity,
        C::NoAddress => Cause::NoAddress,
        C::BadAddress => Cause::BadAddress,
        C::ServiceDown => Cause::ServiceDown,
        C::ServiceStart => Cause::ServiceStart,
        C::ServiceSlow => Cause::ServiceSlow,
        C::KeychainDenied => Cause::KeychainDenied,
        C::HistoryLocked => Cause::HistoryLocked,
        C::HistoryUnreadable => Cause::HistoryUnreadable,
        C::TooLarge => Cause::TooLarge,
        C::BadCharacters => Cause::BadCharacters,
        C::Blocked => Cause::Blocked,
        C::SendInProgress => Cause::SendInProgress,
        C::EmptyMessage => Cause::EmptyMessage,
        C::PinStoreUnreadable => Cause::PinStoreUnreadable,
        C::LanOff => Cause::LanOff,
        C::LocalNetworkRefused => Cause::LocalNetworkRefused,
        C::Other => Cause::Other,
    }
}

/// A carrier a message went over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Carrier {
    Lan,
    Internet,
    P2p,
    /// Bluetooth nearby (Phase 5): the friend was in radio range.
    Nearby,
    /// The friend's Tor onion service (lab, `RAVEN_LAB_TOR`).
    Onion,
}

/// A send that ended with a signed receipt (`Ok` of [`send_to_contact`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivered {
    pub carrier: Carrier,
    /// The address (or p2p dial string) that took it.
    pub dial: String,
    /// A learned LAN address that reached and authenticated the friend: save
    /// it over the old one ([`save_learned_lan`]).
    pub save_lan: Option<String>,
    /// A learned PeerId a p2p link proved: save it ([`save_learned_p2p`]).
    pub save_p2p: Option<String>,
}

/// The listen address a send passes (`raven send`'s default).
const SEND_LISTEN: &str = "127.0.0.1:0";

/// One message to the saved friend with key `pub_hex`, as `raven send
/// --contact` sends it, with the identity the engine holds and no LAN address
/// from the environment (`RAVEN_PEER` is the CLI's; as the terminal app,
/// OD-17). Mirrors cli.rs's `resolve_send_target` (the contact branch, as
/// the terminal app's `tui/bridge.rs` `plan_friend_send` does), `run_send`
/// (which loads the identity through a helper that exits) and the saves
/// `cmd_send_cli` makes after a delivery, which the caller makes under its
/// own lock. `Ok` only after the friend's signed receipt; `Err` is the CLI's
/// outcome text (queued, sent but not confirmed, or not sent).
pub fn send_to_contact(
    data_dir: &Path,
    id: &Identity,
    pub_hex: &str,
    text: &str,
) -> Result<Delivered, String> {
    // `raven lan off` as this profile says it now (the app stays open while
    // it is typed in a terminal).
    super::ext::lan_off_now(data_dir);
    let contacts = super::load_contacts(data_dir)?;
    let contact = contacts
        .iter()
        .find(|c| c.pub_hex.eq_ignore_ascii_case(pub_hex.trim()))
        .ok_or_else(|| "that friend is not saved on this computer".to_string())?;
    let choice = super::CarrierChoice::Auto;
    let p2p_live = raven_core::p2p_live_enabled();
    let hidden = super::hides_ip_from(data_dir, contact);
    // A PeerId its route hints name is planned like a saved one.
    let learned_p2p = super::learned_peer_id(data_dir, contact, p2p_live);
    let mut planned = contact.clone();
    if let Some(peer_id) = &learned_p2p {
        planned.p2p = peer_id.clone();
    }
    // Hide my IP: no Internet direct dial, as if none were saved.
    if hidden {
        planned.internet_dial.clear();
    }
    // Where the LAN beacon found the friend just now: first among its LAN
    // routes, never saved; nothing learned is planned for LAN then.
    let found = super::beacon_routes(data_dir, &planned, choice);
    // No LAN address saved: what was learned about reaching the friend
    // stands in for one (route hints; cutoff F7).
    let unsaved_lan = if found.is_empty() {
        let guess_live = raven_core::outbox::default_port_guess_live();
        super::unsaved_lan_routes(data_dir, &planned, choice, guess_live)
    } else {
        Vec::new()
    };
    // Bluetooth nearby, for a verified friend once this build has it
    // (cli.rs's `with_nearby_route`; raven-node finds out whether the
    // friend is in range), then Tor last (lab: the friend's signed onion
    // address; raced against the others as `raven send` does).
    let (mut routes, env_lan_dial) = super::with_card_onion_route(
        &planned,
        choice,
        raven_core::onion_live_enabled(),
        super::with_nearby_route(
            &planned,
            choice,
            raven_core::nearby_live_enabled(),
            super::plan_contact_routes_with(
                data_dir,
                &planned,
                choice,
                None,
                raven_core::internet_direct_live_enabled(),
                p2p_live,
                &unsaved_lan,
                &found,
            ),
        ),
    )
    .map_err(|e| {
        if hidden && !contact.internet_dial.trim().is_empty() {
            super::hidden_ip_text(contact)
        } else {
            e
        }
    })?;
    let found: Vec<String> = found
        .into_iter()
        .filter(|dial| routes.contains(&super::lan_route(dial)))
        .collect();
    let unsaved_lan: Vec<String> = unsaved_lan
        .into_iter()
        .filter(|dial| routes.contains(&super::lan_route(dial)))
        .collect();
    let (unrecorded, learned_lan_dials) = if !found.is_empty() {
        // Dialled now; never recorded for the outbox and never saved.
        (found, Vec::new())
    } else if !unsaved_lan.is_empty() {
        (unsaved_lan.clone(), unsaved_lan.clone())
    } else if env_lan_dial.is_none() {
        super::add_learned_routes(data_dir, &planned, &mut routes)
    } else {
        (Vec::new(), Vec::new())
    };
    let learned_p2p = learned_p2p.filter(|peer_id| routes.contains(&super::p2p_route(peer_id)));
    let target = super::SendTarget {
        routes,
        pub_hex: planned.pub_hex.clone(),
        listen: SEND_LISTEN.to_string(),
        env_lan_dial,
        learned_lan_dials,
        unrecorded,
        learned_p2p,
        explicit_dial: false,
        lan_unsaved: !unsaved_lan.is_empty(),
    };
    // Bluetooth nearby (Phase 5): the user works with this friend now, so
    // raven-node may advertise for them while this waits (cli.rs).
    if target
        .routes
        .iter()
        .any(|r| r.carrier == DialCarrier::Nearby)
    {
        super::nearby_cli::foreground(data_dir, &target.pub_hex);
    }
    let used = run_send(data_dir, id, &target, text, choice)?;
    // A learned LAN address (the friend had none saved, or it moved) that
    // just reached and authenticated the friend: keep it.
    let save_lan = (used.carrier == DialCarrier::Lan
        && target.learned_lan_dials.contains(&used.dial))
    .then(|| used.dial.clone());
    let save_p2p = target
        .learned_p2p
        .as_deref()
        .filter(|peer_id| {
            used.carrier == DialCarrier::P2p
                && used.dial == raven_core::p2p_route::peer_route(peer_id)
                && super::learned_peer_id_proven(data_dir, &target.pub_hex, peer_id)
        })
        .map(str::to_owned);
    Ok(Delivered {
        carrier: match used.carrier {
            DialCarrier::Lan => Carrier::Lan,
            DialCarrier::Internet => Carrier::Internet,
            DialCarrier::P2p => Carrier::P2p,
            DialCarrier::Nearby => Carrier::Nearby,
            DialCarrier::Onion => Carrier::Onion,
        },
        dial: used.dial,
        save_lan,
        save_p2p,
    })
}

/// cli.rs's `run_send` with the identity given instead of loaded.
fn run_send(
    data_dir: &Path,
    id: &Identity,
    target: &super::SendTarget,
    text: &str,
    choice: super::CarrierChoice,
) -> Result<DialRoute, String> {
    let (recorded, custody_ok) = super::send_intent(choice, target.explicit_dial);
    match target.routes.as_slice() {
        // A learned route (cutoff F7's guess) is dialled, never recorded.
        [only] if only.carrier == DialCarrier::Lan => super::ext::run_send_secure(
            data_dir,
            id,
            &only.dial,
            &target.pub_hex,
            &target.listen,
            text,
            "",
            "",
            recorded,
            custody_ok,
            &target.unrecorded,
        )
        .map(|()| only.clone()),
        [only] if choice == super::CarrierChoice::Internet && only.carrier != DialCarrier::P2p => {
            super::ext::run_send_secure_on(
                data_dir,
                id,
                &only.dial,
                &target.pub_hex,
                &target.listen,
                text,
                "",
                "",
                only.carrier,
            )
            .map(|()| only.clone())
        }
        routes => super::ext::run_send_secure_routes(
            data_dir,
            id,
            routes,
            &target.pub_hex,
            text,
            matches!(
                choice,
                super::CarrierChoice::Internet
                    | super::CarrierChoice::P2p
                    | super::CarrierChoice::Nearby
            ),
            recorded,
            &target.unrecorded,
        ),
    }
}

/// Saves the learned LAN address a delivery used (as `raven send` does).
pub fn save_learned_lan(data_dir: &Path, pub_hex: &str, dial: &str) -> Result<(), String> {
    super::update_contact_lan_dial(data_dir, pub_hex, dial)
}

/// Saves a proved learned PeerId into the friend's row (as `raven send`
/// does); Ok(false) when the row already had one.
pub fn save_learned_p2p(data_dir: &Path, pub_hex: &str, peer_id: &str) -> Result<bool, String> {
    super::update_contact_p2p(data_dir, pub_hex, peer_id)
}

/// Keeps a message of yours that was never sent (nothing was queued or
/// written: not sent, the background program unavailable, or stopped before
/// it ran) in the chat history as `failed`, under a new random message id,
/// the way a message raven-node gave up on stays there: the chat shows it
/// with Send again and Delete after the app starts again too (E1: it was
/// gone), and the terminal app lists it as not delivered. Its id (hex).
pub fn record_not_sent(
    data_dir: &Path,
    pub_hex: &str,
    text: &str,
    written_ms: u64,
) -> Result<String, String> {
    use rand::RngCore;
    let peer = super::parse_pub_hex(pub_hex)?;
    let mut mid = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut mid);
    raven_core::persist_lan_chat_history(
        data_dir,
        "out",
        &peer,
        &mid,
        written_ms,
        raven_core::outbox::HISTORY_FAILED,
        text.as_bytes(),
    )?;
    Ok(hex::encode(mid))
}

/// `raven outbox retry <mid>`: raven-node tries the waiting message now.
pub fn outbox_retry(data_dir: &Path, mid: &str) -> Result<(), String> {
    super::ext::cmd_outbox(data_dir, super::ext::OutboxCmd::Retry { mid: mid.into() })
}

/// Ask raven-node's outbox to send what waits now (every friend), as `raven
/// group` does after it parked group copies: `true` only when a worker took
/// it (pair_init_lab.rs's `outbox_kick`).
pub fn outbox_kick_all(data_dir: &Path) -> bool {
    super::pair_init_lab::outbox_kick(data_dir, None)
}

/// Asks raven-node to try every waiting message to `peer_hex` now
/// (pair_init_lab.rs `outbox_retry_kick`, what `raven outbox retry` sends);
/// false when no node takes it.
pub fn outbox_retry_kick(data_dir: &Path, peer_hex: &str) -> bool {
    let Ok(peer) = super::parse_pub_hex(peer_hex) else {
        return false;
    };
    super::pair_init_lab::outbox_retry_kick(data_dir, Some(&peer))
}

/// `raven outbox cancel <mid> --yes` (the app asked first): raven-node stops
/// trying the message.
pub fn outbox_cancel(data_dir: &Path, mid: &str) -> Result<(), String> {
    super::ext::cmd_outbox(
        data_dir,
        super::ext::OutboxCmd::Cancel {
            mid: mid.into(),
            yes: true,
        },
    )
}

// ── The background program ──────────────────────────────────────────────────

/// The record of the raven-node one engine started (ext.rs keeps one per
/// process for the CLI; the engine keeps one per profile).
pub struct NodeSlot(super::ext::StartedDaemon);

impl NodeSlot {
    pub fn new() -> NodeSlot {
        NodeSlot(std::sync::Mutex::new(None))
    }
}

impl Default for NodeSlot {
    fn default() -> Self {
        NodeSlot::new()
    }
}

/// Starts the profile's raven-node unless one answers, as a send does
/// (ext.rs's `ensure_mac_lan_daemon`: the same arguments, detached, its
/// output in the 0600 service log, the stale-socket and Keychain-aware
/// wait, and the same refusal while `raven lock` holds the profile or an
/// erase did not finish: [`LOCKED_TEXT`], [`ERASE_UNFINISHED_TEXT`]), with
/// `program` and `listen` given. `Ok(Some(pid))`: the one running now is
/// the one this slot started.
pub fn ensure_node(
    data_dir: &Path,
    program: &Path,
    listen: &str,
    slot: &NodeSlot,
) -> Result<Option<u32>, String> {
    // `raven lan off` for this process, as the CLI reads it at its start
    // (cli.rs's `run`): a node started while it holds binds no LAN listener,
    // so none is waited for.
    super::ext::lan_off_now(data_dir);
    super::ext::ensure_daemon_in(data_dir, program, listen, &slot.0)
}

/// [`ensure_node`]'s whole `Err` while `raven lock` stopped this profile
/// (privacy pack PP.15): only `raven unlock` starts it again.
pub const LOCKED_TEXT: &str = raven_core::privacy::LOCKED_TEXT;
/// [`ensure_node`]'s whole `Err` while an erase of this profile did not
/// finish (PP.16): only `raven erase` may touch it.
pub const ERASE_UNFINISHED_TEXT: &str = raven_core::erase::UNFINISHED_TEXT;

/// The raven-node the CLI starts: next to this program, else `raven-node` on
/// PATH when this program's own path is unknown (ext.rs).
pub fn cli_node_program() -> PathBuf {
    super::ext::raven_node_bin_public()
}

/// `RAVEN_SERVICE_LAN_LISTEN` when set: where a node the CLI starts listens.
pub fn service_lan_listen_env() -> Option<String> {
    super::ext::service_lan_listen_env()
}

/// Where a node the CLI starts for the profile in `data_dir` listens
/// without that variable: every interface on the profile's own port (the
/// one it picked, Phase 6b P6.36, else the default port), or `auto[:port]`,
/// every network of this computer, while that gate is live (ext.rs's
/// `default_service_lan_listen_for`, what `ensure_mac_lan_daemon` uses).
pub fn default_service_lan_listen_for(data_dir: &Path) -> String {
    super::ext::default_service_lan_listen_for(data_dir)
}

/// A listen address on this computer only (a loopback IP, or `localhost…`).
pub fn listen_is_loopback(listen: &str) -> bool {
    super::ext::listen_is_loopback(listen)
}

/// Where the profile's raven-node stands, as `raven status` reads its
/// Status (cli.rs's `classify_node_reach`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeReach {
    /// Its LAN listener is up on the network.
    Receiving,
    /// Up on a loopback address: only programs on this computer reach it.
    LocalOnly,
    /// Running, its LAN listener down; why, when the CLI can tell.
    SendOnly(Option<NotReceiving>),
    NotRunning,
    /// Something owns the profile's endpoint but does not answer sensibly.
    NotAnswering,
}

/// Why a running raven-node does not receive (cli.rs's `ListenerDown`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotReceiving {
    /// The address it is bound or set to listen on is not on this computer
    /// now (a new network, a new DHCP lease; cutoff pack CP.5).
    AddrNotHere,
    /// Another program on this computer has its port.
    PortInUse,
    /// `raven lan off` (Phase 3).
    LanOff,
}

/// `status` (an answer or its error) as `raven status` and the terminal app
/// read it, its listen address checked against this computer's own
/// addresses (raven-core's `netifs::is_on_this_computer`, as the terminal
/// app's `Probe::read`).
pub fn node_reach(status: &Result<IpcResponse, String>) -> NodeReach {
    node_reach_here(status, raven_core::netifs::is_on_this_computer)
}

/// [`node_reach`] where `here` says whether an address is one of this
/// computer's own (None: can't be told). Change with cli.rs's
/// `classify_node_reach` (the match below fails to compile when it gains a
/// variant).
pub fn node_reach_here(
    status: &Result<IpcResponse, String>,
    here: impl Fn(std::net::IpAddr) -> Option<bool>,
) -> NodeReach {
    use super::{ListenerDown as D, NodeReach as R};
    match super::classify_node_reach(status, here) {
        R::SendAndReceive => NodeReach::Receiving,
        R::ReceiveLocalOnly { .. } => NodeReach::LocalOnly,
        R::SendOnly { down } => NodeReach::SendOnly(match down {
            D::AddrNotHere { .. } => Some(NotReceiving::AddrNotHere),
            D::PortInUse { .. } => Some(NotReceiving::PortInUse),
            D::LanOff => Some(NotReceiving::LanOff),
            // Lock v2 holds it (`lock.state` says so): no reason of its own
            // here, as before cli.rs told it apart.
            D::Locked | D::Unsaid => None,
        }),
        R::NotRunning => NodeReach::NotRunning,
        R::NotAnswering => NodeReach::NotAnswering,
    }
}

/// One IPC request to the profile's raven-node, waiting at most `timeout`.
pub fn ipc_request_timeout(
    data_dir: &Path,
    req: &IpcRequest,
    timeout: Duration,
) -> Result<IpcResponse, String> {
    super::ipc_client::ipc_request_timeout(data_dir, req, timeout)
}

/// Whether the profile's raven-node answers a Ping within `timeout`.
pub fn ipc_daemon_up_within(data_dir: &Path, timeout: Duration) -> bool {
    super::ipc_client::ipc_daemon_up_within(data_dir, timeout)
}

/// An IPC error that means no raven-node runs for the profile.
pub fn error_means_not_running(err: &str) -> bool {
    super::ipc_client::error_means_not_running(err)
}

/// An IPC error that means raven-node took the request and never answered.
pub fn error_means_no_answer(err: &str) -> bool {
    super::ipc_client::error_means_no_answer(err)
}

/// How to stop this profile's node and no other, by hand.
pub fn profile_stop_advice(data_dir: &Path, pid: Option<u32>) -> String {
    super::ext::profile_stop_advice(data_dir, pid)
}

// ── Network: every way to reach friends (desktop/api/NETWORK_PARITY.md) ─────
//
// The CLI's own commands for each way, with no question asked (the app asks
// the person first and says what it means) and nothing printed (the CLI's
// printing is off in the engine: `set_quiet`). Where a command returns its
// lines, they come back as the CLI says them; the engine shows its own words
// and keeps those lines as details.

/// How long one of these asks the running raven-node (as `raven lan` does).
const NET_ASK: Duration = Duration::from_secs(3);

/// One IPC request to the profile's raven-node, as the network commands ask.
fn ask_node(data_dir: &Path) -> impl FnMut(&IpcRequest) -> Result<IpcResponse, String> + '_ {
    move |req| super::ipc_client::ipc_request_timeout(data_dir, req, NET_ASK)
}

/// `raven lan on|off` (cli.rs `lan_switch`), or `raven lan on --for <time>`
/// (`lan_open_for`: `30m`, `1h`, up to `24h`): saved first, then told to the
/// running raven-node. The CLI's lines.
pub fn lan_set(data_dir: &Path, on: bool, for_time: Option<&str>) -> Result<Vec<String>, String> {
    match for_time {
        Some(time) if on => super::lan_open_for(data_dir, time, ask_node(data_dir)),
        Some(_) => Err("a time applies only to turning LAN on".into()),
        None => super::lan_switch(data_dir, on, ask_node(data_dir)),
    }
}

/// `raven lan status` as data: the setting ash reads, the meeting end of
/// `raven lan on --for`, verified-only, and the CLI's own rows (the `LAN` row
/// of status and doctor, and the LAN beacon's `nearby search` row).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanView {
    /// `on`, `off`, or `unreadable` (node_policy.json can't be read: LAN
    /// stays off until it is turned on, which repairs it).
    pub setting: &'static str,
    /// When `raven lan on --for` turns LAN off again (wall ms).
    pub meeting_until_ms: Option<u64>,
    /// `raven lan verified-only on`.
    pub verified_only: bool,
    /// The CLI's `LAN` row.
    pub row: String,
    /// The CLI's `nearby search` row (the LAN beacon), while there is one.
    pub beacon_row: Option<String>,
}

/// [`LanView`] of the profile, with the running raven-node's `status`.
pub fn lan_view(data_dir: &Path, status: &Result<IpcResponse, String>) -> LanView {
    let setting = super::LanSetting::read(data_dir);
    let extras = super::LanExtras::read(data_dir);
    let contacts = super::load_contacts(data_dir).unwrap_or_default();
    LanView {
        setting: match setting {
            super::LanSetting::On => "on",
            super::LanSetting::Off => "off",
            super::LanSetting::Unreadable(_) => "unreadable",
        },
        meeting_until_ms: extras.meeting.as_ref().map(|m| m.until_ms),
        verified_only: extras.verified_only,
        row: super::lan_row_with(&setting, &extras, status),
        beacon_row: super::nearby_row(status, extras.verified_only, &contacts),
    }
}

/// `raven node internet on --listen <addr>` (`Some`) or `off` (`None`)
/// (cli.rs `cmd_node_internet`): node_policy.json's `internet_listen`,
/// applied when raven-node starts again.
pub fn internet_set(data_dir: &Path, listen: Option<&str>) -> Result<(), String> {
    super::cmd_node_internet(data_dir, listen)
}

/// The `internet` row of `raven status` (cli.rs `internet_reach_row`).
pub fn internet_row(status: &Result<IpcResponse, String>, configured: &str) -> String {
    super::internet_reach_row(
        status,
        configured,
        raven_core::internet_direct_live_enabled(),
    )
}

/// `raven node p2p on --listen <listen> [--relay <r>]… [--upnp|--no-upnp]`
/// (`Some`) or `p2p off` (`None`) (p2p_cli.rs `cmd_node_p2p_with`, off a
/// terminal: no question; an unset UPnP choice stays unset). `relays`
/// empty keeps the saved ones; a relay is a multiaddr or a friend's name
/// or tag (the relay they offer). Applied when raven-node starts again.
pub fn p2p_set(
    data_dir: &Path,
    on: Option<(String, Vec<String>, Option<bool>)>,
) -> Result<(), String> {
    let on = on.map(|(listen, relay, upnp)| super::p2p_cli::P2pOnArgs {
        listen,
        relay,
        upnp,
    });
    super::p2p_cli::cmd_node_p2p_with(data_dir, on, false, |_| None)
}

/// `raven node upnp on|off` (router port mapping for the p2p port: UPnP,
/// and NAT-PMP or PCP while that gate is live). Applied when raven-node
/// starts again.
pub fn port_mapping_set(data_dir: &Path, on: bool) -> Result<(), String> {
    super::p2p_cli::cmd_node_upnp(data_dir, on)
}

/// `raven node proxy <auto|off|http://host:port>` (p2p_cli.rs
/// `node_proxy_set`: a user name or password is refused). The CLI's lines.
pub fn proxy_set(data_dir: &Path, text: &str) -> Result<Vec<String>, String> {
    let daemon = super::ipc_client::ipc_request_timeout(data_dir, &IpcRequest::status(), NET_ASK);
    super::p2p_cli::node_proxy_set(data_dir, text, &daemon)
}

/// `raven node proxy` without a setting (p2p_cli.rs `node_proxy_show`).
pub fn proxy_lines(data_dir: &Path, status: &Result<IpcResponse, String>) -> Vec<String> {
    super::p2p_cli::node_proxy_show(data_dir, status)
}

/// `raven relay offer on|off` (p2p_cli.rs `relay_offer_with`, no question:
/// the default port, the default 443 choice, no external address). The
/// CLI's lines.
pub fn relay_offer_set(data_dir: &Path, on: bool) -> Result<Vec<String>, String> {
    use super::p2p_cli::{RelayOfferArg, RelayOfferOn};
    let daemon = super::ipc_client::ipc_request_timeout(data_dir, &IpcRequest::status(), NET_ASK);
    let arg = if on {
        RelayOfferArg::On(RelayOfferOn {
            port: None,
            also_443: None,
            external: Vec::new(),
        })
    } else {
        RelayOfferArg::Off
    };
    super::p2p_cli::relay_offer_with(data_dir, arg, &daemon, false, |_| None)
}

/// What `raven node custody on` asks first: what this computer learns and
/// keeps while it holds sealed messages for friends.
pub const CARRY_FOR_FRIENDS_CONSENT: &str = super::custody_cli::CUSTODIAN_CONSENT;
/// What `raven custody use on` asks first: what friends learn while they
/// hold your mail.
pub const FRIENDS_CARRY_MINE_CONSENT: &str = super::custody_cli::MAILBOX_QUESTION;
/// What `raven node custody handoff on` says first: what this computer
/// sees while it passes mail on between friends.
pub const HANDOFF_CONSENT: &str = super::custody_cli::HANDOFF_DISCLOSURE;

/// `raven node custody on --yes` (the person agreed to
/// [`CARRY_FOR_FRIENDS_CONSENT`] in the app) or `raven node custody off`
/// (what is held stays until it is collected or expires). The CLI's lines.
pub fn carry_for_friends_set(data_dir: &Path, on: bool) -> Result<Vec<String>, String> {
    if on {
        return super::custody_cli::custody_on_with(data_dir, true, false, |_| None)
            .map_err(|r| r.text);
    }
    super::cmd_node_custody(data_dir, super::CustodyState::Off { purge: false })?;
    Ok(vec!["ok friend custody off".into()])
}

/// `raven custody use on --yes` (the person agreed to
/// [`FRIENDS_CARRY_MINE_CONSENT`]) or `off`. The CLI's lines.
pub fn friends_carry_mine_set(data_dir: &Path, on: bool) -> Result<Vec<String>, String> {
    use super::custody_cli::UseArg;
    let arg = if on {
        UseArg::On { yes: true }
    } else {
        UseArg::Off
    };
    super::custody_cli::custody_use_with(data_dir, arg, false, |_| None).map_err(|r| r.text)
}

/// `raven node custody handoff on|off` (custody_cli.rs `handoff_switch`).
pub fn handoff_set(data_dir: &Path, on: bool) -> Result<Vec<String>, String> {
    super::custody_cli::handoff_switch(data_dir, on)
}

/// Who carries mail, both ways, as `raven custody status` and `raven node
/// custody status` count it (counts only).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CarryView {
    /// `raven custody use`: friends hold your mail (None: never answered).
    pub friends_carry_mine: Option<bool>,
    /// Mail friends this node collects from now.
    pub mail_friends: usize,
    /// They were chosen by hand (`raven custody home`).
    pub mail_friends_by_hand: bool,
    /// Verified friends that offer to hold mail (over the internet too,
    /// and reachable from it).
    pub offering: usize,
    pub offering_internet: usize,
    pub offering_reachable: usize,
    /// Contacts with mail friends listed by hand (`contact set-addr
    /// --custodian`).
    pub listed: usize,
    /// `raven node custody on`: this computer holds mail for friends.
    pub carry_for_friends: bool,
    pub held_messages: i64,
    pub held_bytes: i64,
    /// `raven node custody handoff`: it also passes mail on between friends.
    pub handoff: bool,
    /// `raven node custody status`'s handoff rows (counts).
    pub handoff_lines: Vec<String>,
    /// The letters this computer left with friends (`raven node custody
    /// status`; their names are this profile's own contacts).
    pub letters_left: Vec<String>,
    /// Learned custody (friend mailboxes) runs in this build.
    pub hints_live: bool,
}

/// [`CarryView`] of the profile (custody_cli.rs `gather_facts`).
pub fn carry_view(data_dir: &Path) -> CarryView {
    let f = super::custody_cli::gather_facts(data_dir);
    let policy = raven_core::node_policy::try_load_policy(data_dir).unwrap_or_default();
    CarryView {
        friends_carry_mine: f.consent,
        mail_friends: f.home,
        mail_friends_by_hand: f.manual,
        offering: f.offering,
        offering_internet: f.offering_wan,
        offering_reachable: f.offering_reachable,
        listed: f.listed,
        carry_for_friends: f.holding_on,
        held_messages: f.held_rows,
        held_bytes: f.held_bytes,
        handoff: policy.custody_handoff,
        handoff_lines: super::custody_cli::handoff_status_lines(data_dir),
        letters_left: super::ext::letters_left_rows(data_dir, raven_core::clock::now_ms()),
        hints_live: f.hints_live,
    }
}

/// `raven nearby enable|disable` (nearby_cli.rs `cmd_nearby`: refused while
/// this build holds nearby). The CLI's lines.
pub fn nearby_set(data_dir: &Path, on: bool) -> Result<Vec<String>, String> {
    use super::nearby_cli::NearbyArg;
    let arg = if on {
        NearbyArg::Enable
    } else {
        NearbyArg::Disable
    };
    super::nearby_cli::cmd_nearby(data_dir, arg)
}

/// Bluetooth nearby as `raven nearby status` reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NearbyView {
    /// `held` (this build holds it), `node_held` (the running raven-node
    /// does not run it), `not_running`, or `live`.
    pub state: &'static str,
    /// The saved choice (`raven nearby enable|disable`).
    pub saved: Option<bool>,
    /// What the running raven-node reports, while `live`.
    pub info: Option<raven_core::ipc::NearbyStatusInfo>,
    /// The CLI's NEARBY rows (label, value).
    pub rows: Vec<(&'static str, String)>,
}

/// [`NearbyView`] of the profile, with the running raven-node's `status`.
pub fn nearby_view(data_dir: &Path, status: &Result<IpcResponse, String>) -> NearbyView {
    use super::nearby_cli::NearbyView as V;
    let view = super::nearby_cli::view(data_dir, status);
    let rows = super::nearby_cli::status_rows(&view);
    let saved = raven_core::node_policy::try_load_policy(data_dir)
        .ok()
        .and_then(|p| p.nearby);
    let (state, info) = match view {
        V::Held { .. } => ("held", None),
        V::NodeHeld { .. } => ("node_held", None),
        V::NotRunning { .. } => ("not_running", None),
        V::Live(info) => ("live", Some(*info)),
    };
    NearbyView {
        state,
        saved,
        info,
        rows,
    }
}

/// `raven node hide-ip on|off` (every contact).
pub fn hide_ip_set(data_dir: &Path, on: bool) -> Result<(), String> {
    super::cmd_node_hide_ip(data_dir, on)
}

/// `raven contact hide-ip <address> on|off` (one contact).
pub fn contact_hide_ip_set(data_dir: &Path, address: &str, on: bool) -> Result<(), String> {
    super::cmd_contact_hide_ip(data_dir, address, on)
}

/// `raven contact set-addr --address <address> [--internet A] [--p2p ID]
/// [--via M]… [--clear lan|internet|p2p]…` (cli.rs `cmd_contact_set_routes`:
/// every value checked before the book is read).
pub fn set_contact_routes(
    data_dir: &Path,
    address: &str,
    internet: Option<&str>,
    p2p: Option<&str>,
    via: &[String],
    clear: &[String],
) -> Result<(), String> {
    super::cmd_contact_set_routes(
        data_dir,
        None,
        None,
        None,
        Some(address),
        None,
        internet,
        p2p,
        via,
        clear,
    )
}

/// `raven contact set-addr --address <address> --custodian <c>…` (none:
/// `--clear-custodians`) (cli.rs `set_custodians_lines`: verified contacts
/// only, at most two). `custodians` are saved friends' addresses, passed to
/// the CLI as it names them (their name on this computer, else `@tag`). The
/// CLI's lines.
pub fn set_contact_custodians(
    data_dir: &Path,
    address: &str,
    custodians: &[String],
) -> Result<Vec<String>, String> {
    let contacts = super::load_contacts(data_dir)?;
    let names = custodians
        .iter()
        .map(|a| {
            let c = contacts
                .iter()
                .find(|c| c.address.eq_ignore_ascii_case(a.trim()))
                .ok_or_else(|| "a friend named as a mail friend is not saved here".to_string())?;
            if !c.petname.trim().is_empty() {
                Ok(c.petname.clone())
            } else if !c.public_tag.trim().is_empty() {
                Ok(format!("@{}", super::normalize_tag(&c.public_tag)))
            } else {
                Err("that friend has no name on this computer: give them one first".to_string())
            }
        })
        .collect::<Result<Vec<String>, String>>()?;
    super::set_custodians_lines(data_dir, None, None, None, Some(address), &names)
}

/// A friend's saved routes beyond the LAN address and the p2p PeerId of
/// [`ContactView`] (contacts.json).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoutesView {
    /// The p2p route's relay addresses (`via=`).
    pub p2p_via: Vec<String>,
    /// The friend's next PeerId (PeerId rotation).
    pub p2p_next: String,
    /// Mail friends listed by hand, by key (lower-case hex).
    pub custodians: Vec<String>,
    /// `raven contact hide-ip`: this computer's IP is hidden from them.
    pub hide_ip: bool,
}

/// [`RoutesView`] of the saved friend with key `pub_hex`.
pub fn contact_routes(data_dir: &Path, pub_hex: &str) -> Result<RoutesView, String> {
    let contacts = super::load_contacts(data_dir)?;
    let c = contacts
        .iter()
        .find(|c| c.pub_hex.eq_ignore_ascii_case(pub_hex.trim()))
        .ok_or_else(|| "that friend is not saved on this computer".to_string())?;
    Ok(RoutesView {
        p2p_via: c.p2p_via.clone(),
        p2p_next: c.p2p_next.clone(),
        custodians: c.custodians.clone(),
        hide_ip: c.hide_ip,
    })
}

/// Who carries a friend's mail, as `raven contact show` says it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CarriersView {
    pub hints_live: bool,
    /// Mail friends the friend told about that are your verified contacts:
    /// (key, takes mail another friend passes on).
    pub told: Vec<(String, bool)>,
    /// How many more it told about.
    pub told_unknown: usize,
    /// Mail friends you listed for it: (key, usable now).
    pub listed: Vec<(String, bool)>,
    /// Its offline delivery class: (token, name, how long it may be away);
    /// None while it is not verified or blocked.
    pub coverage: Option<(&'static str, &'static str, &'static str)>,
    /// Your receipts for its messages cannot go back through friends.
    pub receipts_stranded: bool,
}

/// [`CarriersView`] of the friend with key `pub_hex` (custody_cli.rs
/// `contact_carriers`, the helpers of `raven contact show`).
pub fn contact_carriers(
    data_dir: &Path,
    pub_hex: &str,
    status: &Result<IpcResponse, String>,
) -> Result<CarriersView, String> {
    let c = super::custody_cli::contact_carriers(data_dir, pub_hex, status)?;
    Ok(CarriersView {
        hints_live: c.hints_live,
        told: c.told,
        told_unknown: c.told_unknown,
        listed: c.listed,
        coverage: c.coverage.map(|k| (k.token(), k.name(), k.ceiling())),
        receipts_stranded: c.receipts_stranded,
    })
}

/// How long a message written now to the friend with key `pub_hex` could
/// wait for them, by the rule `raven contact list` and the terminal app use
/// (`ext::away_reach`, E1): until a time (`CanWait`), or why none can: the
/// last secure connection ended (`Ended`: meet first), or RAVEN hasn't
/// connected with them yet (`NeverPaired`: a first message needs both
/// online). None when it is not known.
pub fn away_reach(
    data_dir: &Path,
    pub_hex: &str,
    now_ms: u64,
) -> Option<raven_core::outbox::QueueReach> {
    let key = super::parse_pub_hex(pub_hex).ok()?;
    super::ext::away_reach(data_dir, &key, now_ms).ok()
}

/// When a waiting message of yours written at `written_ms` runs out for good,
/// by the rule raven-node's outbox applies (`ext::waits_until`, E1): with the
/// long message horizon live, 7 days after it was written, not its
/// envelope's day.
pub fn waits_until(item: &raven_core::ipc::OutboxItem, written_ms: Option<u64>) -> u64 {
    super::ext::waits_until(item, written_ms)
}

/// Where the friend with key `pub_hex` was last reached on the local
/// network, as raven-node saw it, with when: the address the friend last
/// reached this computer from over an authenticated link
/// (`raven_core::lan_seen`, kept 30 days), on the port of its saved LAN
/// address (`saved_dial`), as `raven send` dials it next to the saved one;
/// with no LAN address saved, on the default LAN port (cutoff F7). The saved
/// address itself when the friend came from there. For a friend not verified
/// only a local-network address (the rule the sends follow). None without a
/// sighting.
pub fn lan_seen_dial(
    data_dir: &Path,
    pub_hex: &str,
    saved_dial: &str,
    pinned: bool,
    now_ms: u64,
) -> Option<(String, u64)> {
    let peer = super::parse_pub_hex(pub_hex).ok()?;
    let at = raven_core::lan_seen::sighting_times(data_dir)?
        .get(&pub_hex.trim().to_ascii_lowercase())
        .copied()
        .filter(|at| now_ms.saturating_sub(*at) <= raven_core::lan_seen::MAX_AGE_MS)?;
    let saved = saved_dial.trim();
    let dial = if saved.is_empty() {
        raven_core::lan_seen::learned_lan_dial_default_port(data_dir, &peer, pinned, now_ms)?
    } else {
        raven_core::lan_seen::learned_lan_dial(data_dir, &peer, saved, pinned, now_ms)
            .unwrap_or_else(|| saved.to_owned())
    };
    Some((dial, at))
}

/// A delivery at least this long after the message was written is a late
/// one: the apps say when it came (ext.rs, as `raven outbox` and the
/// terminal app do).
pub const LATE_DELIVERY_MS: u64 = super::ext::LATE_DELIVERY_MS;

/// When something past happened, on this computer's clock: "today at
/// 15:10", "yesterday at 15:10", or how long ago without the local offset
/// (ext.rs `ended_text`).
pub fn ended_text(at_ms: u64, now_ms: u64) -> String {
    super::ext::ended_text(at_ms, now_ms)
}

/// `raven doctor`'s SUMMARY: its rows (label, value) and the next step.
pub fn doctor_summary(data_dir: &Path) -> (Vec<(&'static str, String)>, String) {
    let s = super::doctor_summary(data_dir);
    (s.rows, s.next)
}

/// `raven doctor`'s network lines (key=value; cli.rs
/// `doctor_network_lines`), with the running raven-node's `status`.
pub fn doctor_network_lines(data_dir: &Path, status: &Result<IpcResponse, String>) -> Vec<String> {
    super::doctor_network_lines(data_dir, status)
}

/// `raven doctor`'s `receiving:` value.
pub fn doctor_receiving(status: &Result<IpcResponse, String>) -> String {
    super::doctor_receiving_key(&super::classify_node_reach(
        status,
        raven_core::netifs::is_on_this_computer,
    ))
}

/// `raven doctor --router`'s lines: asks this computer's router, read-only,
/// which port mapping it speaks (router_probe.rs; up to about 4 s).
pub fn router_lines() -> Vec<String> {
    super::router_probe::doctor_router_lines(&super::router_probe::probe())
}

/// One open security notice as `raven security` shows it to the app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoticeView {
    pub id: i64,
    /// An alert; else a warning.
    pub alert: bool,
    /// The friend it is about, by key in lower-case hex.
    pub peer: Option<String>,
    pub name: String,
    pub headline: String,
    pub did: String,
    pub todo: String,
    /// When, coarse ("this morning").
    pub when: String,
    /// (label, value): about whom, how serious, the code, Raven's action.
    pub details: Vec<(&'static str, String)>,
}

/// The security notices as the terminal app's SEC screen reads them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecurityView {
    /// `off` (not in this build), `unsealed` (the profile is not encrypted,
    /// so it keeps none) or `live`.
    pub kept: &'static str,
    pub notices: Vec<NoticeView>,
    /// How many smaller notices are only counted.
    pub counted: usize,
}

/// [`SecurityView`] (security_cli.rs `app_read`: never creates the ledger,
/// writes nothing).
pub fn security_view(data_dir: &Path) -> Result<SecurityView, String> {
    use super::security_cli::Kept;
    let read = super::security_cli::app_read(data_dir)?;
    Ok(SecurityView {
        kept: match read.kept {
            Kept::Off => "off",
            Kept::Unsealed => "unsealed",
            Kept::Live => "live",
        },
        notices: read
            .notices
            .into_iter()
            .map(|n| NoticeView {
                id: n.id,
                alert: n.alert,
                peer: n.peer,
                name: n.name,
                headline: n.text.headline,
                did: n.text.did,
                todo: n.text.todo,
                when: n.when,
                details: n.details,
            })
            .collect(),
        counted: read.counted,
    })
}

/// Lock v2 is offered (lock_cli.rs `node_lock_v2`): its gate is live in
/// this build and the profile's raven-node serves it; whether it is
/// locked. None: no node, an older one, or a gate shut (Lock now v1).
pub fn lock_v2_state(data_dir: &Path) -> Option<bool> {
    super::lock_cli::node_lock_v2(data_dir)
}

/// Whether the profile has a Raven passphrase (None: can't be told).
pub fn has_passphrase(data_dir: &Path) -> Option<bool> {
    raven_core::keystore_select::has_passphrase(data_dir).ok()
}

/// IPC `Lock` (lock_cli.rs `lock_once`): `Ok(true)` locked, `Ok(false)` the
/// node does not serve Lock v2.
pub fn lock_now(data_dir: &Path) -> Result<bool, String> {
    super::lock_cli::lock_once(data_dir)
}

/// What one unlock came to (lock_cli.rs `UnlockAnswer`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unlocked {
    /// Unlocked: the lines to say.
    Opened(Vec<String>),
    /// That passphrase is not right.
    Wrong(String),
    /// Wait after a wrong one.
    Wait(String),
    /// This profile has a Raven passphrase and none came.
    NeedsPassphrase(String),
    Failed(String),
}

/// IPC `Unlock` with `passphrase` (lock_cli.rs `unlock_once`).
pub fn unlock(data_dir: &Path, passphrase: Option<&[u8]>) -> Unlocked {
    use super::lock_cli::UnlockAnswer as A;
    match super::lock_cli::unlock_once(data_dir, passphrase) {
        A::Opened(lines) => Unlocked::Opened(lines),
        A::Wrong(m) => Unlocked::Wrong(m),
        A::Wait(m) => Unlocked::Wait(m),
        A::NeedsPassphrase(m) => Unlocked::NeedsPassphrase(m),
        A::Failed(m) => Unlocked::Failed(m),
    }
}

/// `raven update status` as the terminal app's NET screen reads it
/// (update_install.rs `view(dir, false)`: nothing staged, stored or noted).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpdatesView {
    /// The release-bundle gate is live.
    pub live: bool,
    /// What `raven update status` says.
    pub lines: Vec<String>,
    /// NET's row.
    pub net_row: Option<String>,
    /// A release a friend offered, waiting for the download approval.
    pub offer: Option<Vec<String>>,
}

/// [`UpdatesView`] of the profile.
pub fn updates_view(data_dir: &Path) -> UpdatesView {
    let v = super::update_install::view(data_dir, false);
    UpdatesView {
        live: v.live,
        lines: v.lines,
        net_row: v.net_row,
        offer: v.offer.map(|o| o.lines),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// E2 r40 P1: the app's add keeps a card's onion binding (the friend's
    /// own signature checked again), so the friend's onion route is
    /// planned once it is verified; a binding someone else signed is not
    /// kept.
    #[test]
    fn a_card_onion_binding_is_kept_and_planned_once_verified() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let friend = Identity::from_seed(&[0x71; 32]);
        let hs_id = Identity::from_seed(&[0x72; 32]).public_key_bytes();
        let binding =
            raven_core::onion::OnionBinding::sign(&friend, hs_id, raven_core::onion::now_s());
        let card = super::super::with_onion_field(
            super::super::format_card_as(super::super::CardVersion::V1, &friend, "", "", None),
            Some(&binding),
        );
        let preview = parse_card_or_invite(&card).unwrap();
        assert_eq!(preview.onion.as_deref(), Some(binding.to_text().as_str()));
        add_contact_with_routes(
            d,
            &preview.address,
            &preview.pub_hex,
            "Bea",
            None,
            "",
            "",
            None,
        )
        .unwrap();
        keep_card_onion(d, &preview.pub_hex, preview.onion.as_deref()).unwrap();
        let mut c = super::super::load_contacts(d)
            .unwrap()
            .into_iter()
            .find(|c| c.pub_hex.eq_ignore_ascii_case(&preview.pub_hex))
            .unwrap();
        assert_eq!(c.onion, binding.to_text());
        // Verified: Tor is planned (alone, nothing else is known).
        c.pinned = true;
        let planned = super::super::with_card_onion_route(
            &c,
            super::super::CarrierChoice::Auto,
            true,
            Err("no address known".into()),
        )
        .unwrap()
        .0;
        assert_eq!(planned.len(), 1);
        assert_eq!(
            planned[0].carrier,
            super::super::pair_init_lab::DialCarrier::Onion
        );
        // Someone else's binding for this friend: not kept.
        let other = raven_core::onion::OnionBinding::sign(
            &Identity::from_seed(&[0x73; 32]),
            [0x74; 32],
            raven_core::onion::now_s() + 1,
        );
        keep_card_onion(d, &preview.pub_hex, Some(&other.to_text())).unwrap();
        let kept = super::super::load_contacts(d)
            .unwrap()
            .into_iter()
            .find(|c| c.pub_hex.eq_ignore_ascii_case(&preview.pub_hex))
            .unwrap()
            .onion;
        assert_eq!(kept, binding.to_text());
        assert!(keep_card_onion(d, &preview.pub_hex, None).is_ok());
    }
}
