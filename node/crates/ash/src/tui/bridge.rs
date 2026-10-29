//! The only tui file that may name items of cli.rs, ext.rs, pair_init_lab.rs,
//! p2p_cli.rs and ipc_client.rs.
//!
//! Types the CLI keeps private come out as plain views ([`MeView`],
//! [`ContactView`], [`FriendPreview`]), so the rest of the app never reaches
//! into a cli.rs struct. testkit's `bridge_api_pins` names every item here
//! with the type the app relies on.

use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use raven_core::chat_history::{BlockList, ChatHistory, ChatHistoryEntry};
use raven_core::identity::Identity;
use raven_core::ipc::{IpcRequest, IpcResponse, P2pStatusInfo};
use raven_core::macos_keychain::KeychainWhat;
use raven_core::netifs;
use raven_core::node_policy::NodePolicy;
use raven_core::sanitize::sanitize_terminal_line;
use raven_core::security_words;

use super::node::Managed;
use super::state_file::TuiPrivate;

// Characters of a message body shown on a terminal before it is clipped.
pub(super) use super::super::TTY_BODY_MAX_CHARS;
// Shown under a friend's message whose id it later re-used with other text.
pub(super) use super::super::ID_CONFLICT_NOTE;
// Contacts as cli.rs stores them.
pub(super) use super::super::{load_contacts, Contact};
// Cards: the longest line `contact add --card` takes.
pub(super) use super::super::CARD_MAX_LEN;
// Addresses: the check `contact set-dial` makes, and the store worker's save.
pub(super) use super::super::{parse_lan_dial, update_contact_lan_dial};
// Unblocking: `contact unblock`.
pub(super) use super::super::cmd_contact_unblock;
// The CLI's refusal of the user's own invite: reference text for tests.
#[cfg(test)]
pub(super) use super::super::OWN_INVITE_REFUSAL;
// The identity's first prekey and device certificate (lan_dispatch.rs).
pub(super) use raven_core::ensure_local_prekey;

/// The listen address a node this app starts uses while receiving is off:
/// this computer only, any free port.
const LOOPBACK_LISTEN: &str = "127.0.0.1:0";

/// cli.rs's clip for a long message body: the first `max` characters, then
/// `… (+N more characters)`; `None` keeps everything.
pub(super) fn clip_body(text: String, max: Option<usize>) -> String {
    super::super::clip_body(text, max)
}

/// cli.rs's wall clock: milliseconds since the Unix epoch, 0 if the clock is
/// before it. Message rows carry times on this clock.
pub(super) fn now_ms() -> u64 {
    super::super::now_ms()
}

/// How long ago `then_ms` was, as `ash messages` says it: "just now",
/// "5 min ago", "2 h ago", "3 d ago"; "" for an unknown time (0). No time
/// zone is needed, so it reads the same on every computer.
pub(super) fn short_age(now_ms: u64, then_ms: u64) -> String {
    super::super::short_age(now_ms, then_ms)
}

// ── The composer ────────────────────────────────────────────────────────────

/// The most bytes one message may hold (raven-core's LAN endpoint text cap,
/// as `raven send` reads it).
pub(super) use raven_core::lan_noise::MAX_LAN_ENDPOINT_TEXT;

/// What cli.rs's message prompt refuses before anything is sent: an escape
/// sequence or another control character (TAB and line breaks are fine).
/// The composer drops these as they are typed; this is the backstop.
pub(super) fn tty_message_problem(text: &str) -> Option<&'static str> {
    super::super::tty_message_problem(text)
}

/// Whether chat text may be sent as it is: it must not start with the prefix
/// raven-core keeps for app frames (`RVNAPP/`).
pub(super) fn chat_text_allowed(text: &str) -> bool {
    raven_core::app_channel::chat_text_allowed(text)
}

/// Asks raven-node's outbox to send what waits now (pair_init_lab.rs's
/// kick, as `raven group` sends it after a change): whether a running
/// raven-node took it. Starts nothing.
pub(super) fn outbox_kick(data_dir: &Path) -> bool {
    super::super::pair_init_lab::outbox_kick(data_dir, None)
}

/// The classic line menu (cli.rs's `interactive`): what a no-argument run
/// opens when the gate says Classic, or when the user leaves the full screen
/// for it.
pub(super) fn interactive(data_dir: &Path) {
    super::super::interactive(data_dir)
}

/// What [`load_identity`] found in the profile.
pub(super) enum IdentityLoad {
    Ready(Arc<Identity>),
    /// No identity yet: nothing may be written into the profile until one is
    /// created.
    Missing,
    /// The identity store could not be read (raven-core's redacted reason).
    /// Never offer to create an identity over it.
    Unavailable(String),
}

/// The profile's identity, through cli.rs's `try_load_identity`. Called on the
/// main thread before the screen is up: the vault passphrase prompt, macOS
/// Keychain dialogs and the identity-lock notice all need the plain terminal.
pub(super) fn load_identity(data_dir: &Path) -> IdentityLoad {
    match super::super::try_load_identity(data_dir) {
        Ok(Some(id)) => IdentityLoad::Ready(Arc::new(id)),
        Ok(None) => IdentityLoad::Missing,
        Err(e) => IdentityLoad::Unavailable(e),
    }
}

/// Creates the profile's identity, or loads the one already there, as the
/// menu's first run does (raven-core's `load_or_create_profile_identity`: a
/// profile created here picks its random LAN port too, Phase 6b P6.36,
/// while that gate is live). The error is raven-core's redacted reason; a
/// refusal to bind a new key over leftover state says `continuity`.
pub(super) fn load_or_create_identity(data_dir: &Path) -> Result<Arc<Identity>, String> {
    raven_core::load_or_create_profile_identity(data_dir)
        .map(|(id, _backend)| Arc::new(id))
        .map_err(|e| e.redacted_display())
}

/// `RAVEN_SERVICE_LAN_LISTEN` when set to anything (ext.rs): the listen
/// address of a node ash starts, which the app leaves alone.
pub(super) fn service_lan_listen_env() -> Option<String> {
    super::super::ext::service_lan_listen_env()
}

/// The port a background program this app starts listens on:
/// RAVEN_SERVICE_LAN_LISTEN's, else ext.rs's default for the profile in
/// `data_dir` (its own port where it picked one), else 7420.
pub(super) fn service_port(data_dir: &Path) -> u16 {
    service_lan_listen_env()
        .unwrap_or_else(|| super::super::ext::default_service_lan_listen_for(data_dir))
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse().ok())
        .unwrap_or(raven_core::paths::DEFAULT_LAN_PORT)
}

/// Receiving is off: a node this app starts listens on this computer only.
/// Sets `RAVEN_SERVICE_LAN_LISTEN` for the process, so it must run while no
/// other thread can read the environment: before the app's threads start, or
/// while every worker is idle.
pub(super) fn set_listen_loopback_env() {
    std::env::set_var("RAVEN_SERVICE_LAN_LISTEN", LOOPBACK_LISTEN);
}

/// The IPv4 address this computer reaches the network from (raven-core's
/// `route_memory::egress_addrs`; nothing is sent). None when offline.
pub(super) fn egress_v4() -> Option<Ipv4Addr> {
    raven_core::route_memory::egress_addrs().0
}

/// Whether this computer is on any network: `Some(false)` on none at all
/// (no Wi-Fi, cable or hotspot), None when that can't be told. The poller
/// reads it, never a draw.
///
/// It reads raven-core's interfaces (`netifs::read`): `Some(true)` when an
/// interface that is up has an address a friend could dial (what
/// [`lan_addresses_for_friends`] lists) other than a virtual machine's or a
/// container's network (`netifs::on_a_network`), `Some(false)` when none
/// has, None when the read fails. Not "any address but loopback": a Mac's
/// tunnels and peer-to-peer Wi-Fi always carry an fe80 address, and a VM
/// bridge stays up with Wi-Fi off, so that would never say no network.
/// [`egress_v4`] can't tell either (a cable with no router has no route out).
///
/// A link with only fe80:: (a cable nobody hands addresses on) counts when
/// the running raven-node saw a friend lately: `friends_here` is its
/// Status's count ([`friends_here_10m`]; `netifs::on_a_network_seen`).
pub(super) fn on_any_network(friends_here: Option<u32>) -> Option<bool> {
    let all = netifs::read().ok()?;
    Some(netifs::on_a_network_seen(all, friends_here))
}

/// How many contacts the running raven-node saw on this computer's networks
/// in the last ten minutes (`Status.lan.friends_here_10m`); None with no
/// answer, and from an older raven-node.
pub(super) fn friends_here_10m(status: &Result<IpcResponse, String>) -> Option<u32> {
    match status {
        Ok(IpcResponse::Status { lan: Some(lan), .. }) => lan.friends_here_10m,
        _ => None,
    }
}

/// Every address of this computer a friend could dial (raven-core's
/// `netifs`): IPv4 first, the hotspot this computer hosts at the top. None
/// when the interfaces can't be read; empty on no network. A virtual
/// machine's or a container's network is left out: the screens show bare
/// addresses, and a friend can't dial that one (`ash listen` labels it).
/// Nothing is sent. The node worker reads it, never a draw.
pub(super) fn lan_addresses_for_friends() -> Option<Vec<IpAddr>> {
    let all = netifs::read().ok()?;
    Some(
        netifs::for_friends(all)
            .into_iter()
            .filter(|a| !netifs::is_virtual(a))
            .map(|a| a.ip)
            .collect(),
    )
}

/// Whether a listener bound to `listen` takes connections to `ip`
/// (raven-core's `netifs::listener_takes`): 0.0.0.0 takes no IPv6 address.
/// Pure: a draw may ask.
pub(super) fn listener_takes(listen: IpAddr, ip: IpAddr) -> bool {
    netifs::listener_takes(listen, ip)
}

/// node_policy.json, or why it can't be read (as cli.rs words it when it
/// refuses to edit the file). A missing file is the defaults.
pub(super) fn try_load_policy(data_dir: &Path) -> Result<NodePolicy, String> {
    raven_core::node_policy::try_load_policy(data_dir).map_err(|e| {
        format!(
            "node_policy.json is unreadable ({})",
            sanitize_terminal_line(&e.to_string())
        )
    })
}

// ── Plain views ─────────────────────────────────────────────────────────────

/// This profile's own public identity, as `ash whoami` prints it (cli.rs's
/// `print_public_identity`). Public material only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct MeView {
    pub(super) address: String,
    pub(super) pub_hex: String,
    /// The security code, e.g. `If4x-36FU-omFi`: the old-style code, for
    /// friends with an older Raven.
    pub(super) fingerprint: String,
    /// The security words, in order (raven-core's `words_v1`): what friends
    /// read out and type. Boxed, so the views stay small.
    pub(super) words: Box<[String; WORDS]>,
    /// The invite line, `raven:<address>:<pub_hex>`.
    pub(super) invite: String,
}

/// The public half of `id`. Never a seed or a private key.
pub(super) fn me_view(id: &Identity) -> MeView {
    let key = id.public_key_bytes();
    let address = id.address();
    let pub_hex = hex::encode(key);
    MeView {
        invite: format!("raven:{address}:{pub_hex}"),
        fingerprint: raven_core::fingerprint::device_fingerprint_v1(&key),
        words: key_words(&key),
        address,
        pub_hex,
    }
}

/// The security words of `key`, in order.
fn key_words(key: &[u8; 32]) -> Box<[String; WORDS]> {
    Box::new(security_words::words_v1(key).map(String::from))
}

/// A card's p2p route: a PeerId and at most two `via=` multiaddrs, and the
/// next epoch's PeerId a `raven-card/3` may name (`p2pn=`, Phase 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct P2pView {
    pub(super) peer_id: String,
    pub(super) via: Vec<String>,
    pub(super) next: Option<String>,
}

impl P2pView {
    fn of(route: &super::super::P2pRoute) -> P2pView {
        P2pView {
            peer_id: route.peer_id.clone(),
            via: route.via.clone(),
            next: route.next.clone(),
        }
    }

    /// Back to cli.rs's route, validated again as a card's would be.
    fn route(&self) -> Result<super::super::P2pRoute, String> {
        let via: Vec<&str> = self.via.iter().map(String::as_str).collect();
        let route =
            super::super::P2pRoute::parse(&self.peer_id, &via).map_err(|e| format!("p2p: {e}"))?;
        match &self.next {
            Some(next) => route.with_next(next).map_err(|e| format!("p2p: {e}")),
            None => Ok(route),
        }
    }
}

/// A friend's invite or card, parsed and self-consistent: the address is the
/// one the key encodes to, and the card's fingerprint (if it had one) is the
/// key's own. Public material only; the routes are hints, never identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct FriendPreview {
    pub(super) address: String,
    pub(super) pub_hex: String,
    /// The friend's security code, from their key. Never drawn before what
    /// the user types matches it.
    pub(super) fingerprint: String,
    /// The friend's security words, from their key. Hidden as `fingerprint`
    /// is: drawn only through VF's `theirs`, after a match.
    pub(super) words: Box<[String; WORDS]>,
    /// The local-network route (`lan=`), or empty.
    pub(super) lan: String,
    /// The Internet route (`inet=`), or empty.
    pub(super) internet: String,
    pub(super) p2p: Option<P2pView>,
    /// The friend's Tor onion binding (`onion=`, lab): one their own key
    /// signed (cli.rs's `parse_card` refuses any other).
    pub(super) onion: Option<Box<raven_core::onion::OnionBinding>>,
}

impl FriendPreview {
    fn of(card: super::super::ContactCard) -> Result<FriendPreview, String> {
        let key = super::super::parse_pub_hex_strict(&card.pub_hex)?;
        Ok(FriendPreview {
            onion: card.onion.map(Box::new),
            p2p: card.p2p.as_ref().map(P2pView::of),
            address: card.address,
            pub_hex: card.pub_hex,
            fingerprint: card.fingerprint,
            words: key_words(&key),
            lan: card.lan,
            internet: card.internet,
        })
    }
}

/// One saved friend. The strings are as stored (the label as the CLI shows
/// it); display.rs shapes every one before it is drawn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ContactView {
    pub(super) pub_hex: String,
    pub(super) address: String,
    /// cli.rs's `Contact::primary_label`: the name given on this computer,
    /// else `@tag`, else the address.
    pub(super) label: String,
    /// The public tag the friend claims, or empty.
    pub(super) tag: String,
    /// The friend's security code (`—` for a key that does not parse). Drawn
    /// only while `pinned`.
    pub(super) fingerprint: String,
    /// Verified: the user typed this friend's code and it matched.
    pub(super) pinned: bool,
    /// On the block list.
    pub(super) blocked: bool,
    pub(super) lan_dial: String,
    pub(super) internet_dial: String,
    /// The friend's p2p PeerId, or empty.
    pub(super) p2p: String,
}

impl ContactView {
    fn of(c: &Contact, blocks: &BlockList) -> ContactView {
        ContactView {
            pub_hex: c.pub_hex.clone(),
            address: c.address.clone(),
            label: c.primary_label(),
            tag: c.public_tag.clone(),
            fingerprint: super::super::contact_fingerprint(c),
            pinned: c.pinned,
            blocked: blocks.is_blocked(&c.pub_hex),
            lan_dial: c.lan_dial.clone(),
            internet_dial: c.internet_dial.clone(),
            p2p: c.p2p.clone(),
        }
    }
}

// ── Contacts ────────────────────────────────────────────────────────────────

/// The saved friends, in file order, each with its blocked state. A corrupt
/// contacts.json or block list is an error, never an empty list.
pub(super) fn contact_views(data_dir: &Path) -> Result<Vec<ContactView>, String> {
    let contacts = load_contacts(data_dir)?;
    let blocks = BlockList::load_checked(data_dir).map_err(|e| format!("block list: {e}"))?;
    Ok(contacts
        .iter()
        .map(|c| ContactView::of(c, &blocks))
        .collect())
}

/// contacts.json in `data_dir`: the poller watches its size and time.
pub(super) fn contacts_path(data_dir: &Path) -> PathBuf {
    super::super::contacts_path(data_dir)
}

/// The security code of a key given as hex (cli.rs's parse, then
/// `device_fingerprint_v1`); None when it is not a key.
pub(super) fn fingerprint_of(pub_hex: &str) -> Option<String> {
    super::super::parse_pub_hex(pub_hex)
        .ok()
        .map(|key| raven_core::fingerprint::device_fingerprint_v1(&key))
}

/// cli.rs's `add_contact_with_routes`, the one way a friend is saved: the
/// key and address checked again, the pin decided by `verify_fp` (typed by
/// the user, its digits folded as [`fingerprint_matches`] folds them)
/// against the key's own code, petnames kept unique. An empty petname or
/// route keeps what is saved; `p2p` None keeps the saved one.
#[allow(clippy::too_many_arguments)]
pub(super) fn add_contact_with_routes(
    data_dir: &Path,
    address: &str,
    pub_hex: &str,
    petname: &str,
    public_tag: &str,
    verify_fp: Option<&str>,
    lan_dial: &str,
    internet_dial: &str,
    p2p: Option<&P2pView>,
) -> Result<(), String> {
    let p2p = p2p.map(P2pView::route).transpose()?;
    let verify_fp = verify_fp.map(fold_code_digits);
    super::super::add_contact_with_routes(
        data_dir,
        address,
        pub_hex,
        petname,
        public_tag,
        verify_fp.as_deref(),
        lan_dial,
        internet_dial,
        p2p.as_ref(),
    )
}

/// NAME-CLASH (another key under a verified friend's name) noted as cli.rs
/// notes a refused key change: `SEC_KEY_CHANGE_ATTEMPT` about that friend
/// (`pinned_pub_hex`). Nothing while the security events gate is shut.
pub(super) fn note_key_change_attempt(pinned_pub_hex: &str) {
    super::super::note_key_change_attempt(pinned_pub_hex)
}

/// cli.rs's `contact remove --address <address> --yes`: always confirmed
/// (the app asks first), so it never prompts.
pub(super) fn cmd_contact_remove(data_dir: &Path, address: &str) -> Result<(), String> {
    super::super::cmd_contact_remove(data_dir, None, None, Some(address), true)
}

// ── Cards and invites ───────────────────────────────────────────────────────

/// A friend's Tor onion binding from their card (lab), kept in their book
/// row as `contact add --card` keeps it (the newest one their key signed).
pub(super) fn keep_card_onion(
    data_dir: &Path,
    pub_hex: &str,
    onion: Option<&raven_core::onion::OnionBinding>,
) -> Result<(), String> {
    let Some(binding) = onion else {
        return Ok(());
    };
    let key = super::super::parse_pub_hex_strict(pub_hex)?;
    raven_core::onion::store_contact_binding(data_dir, &key, binding).map(drop)
}

/// `card` with this profile's Tor onion binding (`onion=`, lab), as `whoami
/// --card` adds it.
pub(super) fn with_own_onion(card: String, data_dir: &Path, id: &Identity) -> String {
    super::super::with_onion_field(
        card,
        super::super::own_card_onion(data_dir, id, false).as_ref(),
    )
}

/// A card line or an invite line, as `contact add --card` reads it.
pub(super) fn parse_card_or_invite(text: &str) -> Result<FriendPreview, String> {
    super::super::parse_card_or_invite(text).and_then(FriendPreview::of)
}

/// An invite line (`raven:<rvn1>:<pub_hex>`, with or without its label):
/// None when `text` is not one at all, an error when it is one whose address
/// and key don't match.
pub(super) fn parse_raven_invite(text: &str) -> Option<Result<FriendPreview, String>> {
    super::super::parse_raven_invite(text).map(|parsed| {
        parsed.and_then(|i| {
            let key = super::super::parse_pub_hex_strict(&i.pub_hex)?;
            Ok(FriendPreview {
                address: i.address,
                pub_hex: i.pub_hex,
                fingerprint: i.fingerprint,
                words: key_words(&key),
                lan: String::new(),
                internet: String::new(),
                p2p: None,
                onion: None,
            })
        })
    })
}

/// The p2p part of this profile's card, as `whoami --card` makes it without
/// `--via` (cli.rs's `own_card_route`, never a `raven-card/3` route): from
/// the policy's p2p setting and relays; None for a v1 card. `rotation`: the
/// epoch whose key the running raven-node uses ([`own_rotation_epoch`]), so
/// `p2p=` names that epoch's PeerId as `whoami --card` does (cli.rs's
/// `rotating_card_route`); a /2 card carries no `p2pn=`.
pub(super) fn own_card_p2p(
    id: &Identity,
    policy: &NodePolicy,
    rotation: Option<u64>,
) -> Result<Option<P2pView>, String> {
    super::super::own_card_route(id, &[], policy, false).map(|route| {
        route
            .map(|route| match rotation {
                Some(epoch) => super::super::rotating_card_route(id, route, epoch),
                None => route,
            })
            .as_ref()
            .map(P2pView::of)
    })
}

/// The epoch whose key this profile's running raven-node uses (IPC status
/// `rotation`, as `whoami --card` asks it: cli.rs's
/// `card_rotation_epoch`), while the PeerId rotation gate is live; `None`
/// with the gate closed, the fixed key, or no node answering.
pub(super) fn own_rotation_epoch(data_dir: &Path) -> Option<u64> {
    if !raven_core::peer_rotation_live_enabled() {
        return None;
    }
    let status = ipc_request_timeout(
        data_dir,
        &IpcRequest::status(),
        std::time::Duration::from_millis(1500),
    );
    super::super::card_rotation_epoch(&status)
}

/// What a running node says about p2p in its Status (p2p_cli.rs); None when
/// no node answers, or an older one does not say.
pub(super) fn service_p2p(status: &Result<IpcResponse, String>) -> Option<&P2pStatusInfo> {
    super::super::p2p_cli::service_p2p(status)
}

/// This profile's card line (cli.rs's `format_card_as`): `raven-card/2`
/// with a p2p route, `/1` without, never a `/3` (cli.rs's
/// `whoami_card_version` with `/3` not allowed, as `whoami --card --compat`
/// prints it). Public material only. The routes are taken as given; check
/// them first.
pub(super) fn format_card_with(
    id: &Identity,
    internet: &str,
    lan: &str,
    p2p: Option<&P2pView>,
) -> Result<String, String> {
    let p2p = p2p.map(P2pView::route).transpose()?;
    let version = super::super::whoami_card_version(p2p.as_ref(), false);
    Ok(super::super::format_card_as(
        version,
        id,
        internet,
        lan,
        p2p.as_ref(),
    ))
}

// ── Security words and codes ────────────────────────────────────────────────

/// The hint cli.rs adds when a typed security code differs from the real one
/// only in upper and lower case.
pub(super) const FINGERPRINT_CASE_HINT: &str = super::super::FINGERPRINT_CASE_HINT;

/// `s` with Persian (U+06F0-U+06F9) and Arabic-Indic (U+0660-U+0669) digits
/// as '0'-'9', everything else as it is: a code or an address typed with a
/// Persian keyboard reads as the same one. Input tolerance only: nothing is
/// shown in another script. cli.rs's `fold_digits` (cutoff pack CP.8), which
/// its code comparisons also apply; folding twice changes nothing.
pub(super) fn fold_code_digits(s: &str) -> String {
    super::super::fold_digits(s)
}

/// Whether `s` holds letters of the Arabic script (U+0600-U+06FF without
/// the digits [`fold_code_digits`] reads, U+0750-U+077F, U+08A0-U+08FF,
/// U+FB50-U+FDFF, U+FE70-U+FEFF): no code has them, so the keyboard is on
/// Persian letters. cli.rs's (cutoff pack CP.8).
pub(super) fn code_has_non_latin_letters(s: &str) -> bool {
    super::super::code_has_non_latin_letters(s)
}

/// What cli.rs says for a code typed with Arabic-script letters, instead of
/// the mismatch (VF and AF-1 show the same words).
pub(super) const CODE_KEYBOARD_HINT: &str = super::super::CODE_KEYBOARD_HINT;

/// The code the user typed against a security code: separators ignored,
/// case not (cli.rs), Persian and Arabic-Indic digits read as 0-9. VF
/// compares through [`security_check`]; the tests check codes with it.
#[cfg(test)]
pub(super) fn fingerprint_matches(typed: &str, fp: &str) -> bool {
    super::super::fingerprint_matches(&fold_code_digits(typed), fp)
}

/// Right characters, wrong upper and lower case: still no match, but worth
/// saying so. Digits are folded as [`fingerprint_matches`] folds them.
#[cfg(test)]
pub(super) fn fingerprint_case_only_mismatch(typed: &str, fp: &str) -> bool {
    super::super::fingerprint_case_only_mismatch(&fold_code_digits(typed), fp)
}

/// What the user typed while a friend read out their security words or old
/// code, against the friend's key (cli.rs's `Check`): `Match`, `Mismatch`,
/// `Invalid` with raven-core's parse status (it depends only on what was
/// typed), or `CodeCaseOnly`. It never holds the friend's words or code.
pub(super) use super::super::Check as SecurityCheck;

/// `typed` against the key `pub_hex`, through cli.rs's one comparator
/// (`security_check`): 4 or more tokens are security words (raven-core's
/// parse, then a constant-time compare), fewer are the old code (separators
/// ignored, case not, Persian and Arabic-Indic digits read as 0-9). A key
/// that does not parse matches nothing. VF's Enter calls it (the words field
/// through [`words_check`]).
pub(super) fn security_check(typed: &str, pub_hex: &str) -> SecurityCheck {
    match super::super::parse_pub_hex(pub_hex) {
        Ok(key) => super::super::security_check(typed, &key),
        Err(_) => SecurityCheck::Mismatch,
    }
}

/// [`security_check`] for VF's words field, where what is typed is words
/// whatever its length: fewer than 4 tokens are not read as the old code but
/// get raven-core's parse status (never `Match`), which depends only on the
/// typed text.
pub(super) fn words_check(typed: &str, pub_hex: &str) -> SecurityCheck {
    if security_words::looks_like_words(typed) {
        return security_check(typed, pub_hex);
    }
    match security_words::parse(typed) {
        Err(e) => SecurityCheck::Invalid(e),
        Ok(_) => security_check(typed, pub_hex),
    }
}

/// Why typed security words are not 10 valid words, and why one word is not
/// a Raven word (raven-core's): both depend only on the typed text. A set
/// has [`WORDS`] words.
pub(super) use raven_core::security_words::{ParseError, TokenError, WORDS};

/// The Raven word at `index` of the list.
pub(super) fn list_word(index: u8) -> &'static str {
    security_words::list_v1()[usize::from(index)]
}

/// VF's autocomplete: the list indexes `token` can stand for. A Raven word,
/// its plural or 3 letters of one: that word; else every word it starts, in
/// list order (raven-core's `candidates`, which takes no key: never ordered
/// or filtered by a friend's words).
pub(super) fn word_suggestions(token: &str) -> Vec<u8> {
    match security_words::resolve(token) {
        Ok(index) => vec![index],
        Err(_) => security_words::candidates(token),
    }
}

/// One typed word to its list index (raven-core's `resolve`).
pub(super) fn resolve_word(token: &str) -> Result<u8, TokenError> {
    security_words::resolve(token)
}

/// Typed security words as raven-core splits them: separators, invisible
/// characters and position numbers out.
pub(super) fn word_tokens(text: &str) -> Vec<String> {
    security_words::split_tokens(text)
}

/// The security words of a key given as hex; None when it is not a key.
pub(super) fn words_of(pub_hex: &str) -> Option<Box<[String; WORDS]>> {
    super::super::parse_pub_hex(pub_hex)
        .ok()
        .map(|key| key_words(&key))
}

/// A fresh 5-character code for one save: drawn when the question appears,
/// so whoever wrote a pasted card can't know it.
pub(super) fn new_confirm_code<R: rand::Rng>(rng: &mut R) -> String {
    super::super::new_confirm_code(rng)
}

/// The code the user typed against [`new_confirm_code`]'s (case, spaces and
/// dashes ignored; Persian and Arabic-Indic digits read as 0-9).
pub(super) fn confirm_code_matches(typed: &str, code: &str) -> bool {
    super::super::confirm_code_matches(&fold_code_digits(typed), code)
}

// ── Send outcomes ───────────────────────────────────────────────────────────

// How ext.rs starts each outcome text, the words that say raven-node keeps
// retrying, and its classifier of the raw failure behind an outcome
// (pub(super) in ext.rs for the app, OD-8). errors.rs words each for the screen.
pub(super) use super::super::ext::{
    classify_cause, is_noise_pin_mismatch, Cause, BACKGROUND_RETRY, QUEUED_PREFIX,
    UNCONFIRMED_PREFIX,
};
// What `raven status` says on no network at all (P3.C6): the network
// screen says the same words.
pub(super) use super::super::ext::NOT_ON_ANY_NETWORK_TEXT;
// The rule a first message goes by, as `raven contact list` and a send's
// NOT SENT say it (E1): Home and the outcome say the same words.
pub(super) use super::super::ext::first_message_rule;
// The CLI's own outcome and refusal texts, for errors.rs's tests to read as
// the app gets them.
#[cfg(test)]
pub(super) use super::super::ext::{
    earlier_unconfirmed_text, earlier_undelivered_text, not_sent_text, offline_stage_full_text,
    peer_reset_unreachable_text, queue_full_text, queued_text, send_ctx, unconfirmed_text,
    verified_only_text, RetryNote, SendCtx,
};
#[cfg(test)]
pub(super) use super::super::pair_init_lab::{
    unverified_carrier_text, unverified_remote_lan_text, INTERNET_DIRECT_HOLD,
    RESERVED_PREFIX_REFUSAL,
};

/// When a waiting message runs out of time, in words. Never "UTC": a time
/// on another clock than the user's invites a wrong meeting time. Both
/// `short` and `long` read on after "until", "before" or "Expires:".
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DeadlineText {
    /// For a label: "tomorrow 09:10", or "about 22 h from now" when this
    /// computer's clock time is not known.
    pub(super) short: String,
    /// For a sentence: "tomorrow at 09:10 (about 22 hours from now)", or
    /// "about 22 hours from now".
    pub(super) long: String,
    /// The time on this computer's clock ("14:05"), when it can be read.
    pub(super) hh_mm: Option<String>,
    /// How long is left; 0 once it has run out.
    pub(super) left_ms: u64,
}

/// [`DeadlineText`] for `expires_at_ms`, seen at `now_ms`: the time on this
/// computer's clock (`raven_core::local_time`, CP.6) when its offset can be
/// read, "tomorrow 09:10" / "tomorrow at 09:10 (about 19 hours from now)";
/// else only how long is left, minutes under 2 h, then hours ("about 19 h
/// from now"). The OS is asked here, on the caller's thread.
pub(super) fn deadline_text(expires_at_ms: u64, now_ms: u64) -> DeadlineText {
    deadline_text_with(
        expires_at_ms,
        now_ms,
        local_offset(expires_at_ms),
        local_offset(now_ms),
    )
}

/// The time on this computer's clock at `now_ms`, with seconds and its zone
/// ("14:05:33 UTC+1"; E2 r38: the header's time named no zone, while the
/// CLI's times do), for Home's header (UXF.10); None when its offset from UTC
/// can't be read (and under test unless a test set one): no time on another
/// clock is shown.
pub(super) fn clock_text(now_ms: u64) -> Option<String> {
    let off_s = local_offset(now_ms)?;
    let off = i64::from(off_s);
    let secs = i64::try_from(now_ms / 1000).ok()? + off;
    let of_day = secs.rem_euclid(86_400);
    Some(format!(
        "{:02}:{:02}:{:02} {}",
        of_day / 3600,
        of_day % 3600 / 60,
        of_day % 60,
        super::super::ext::zone_label(Some(off_s)).unwrap_or_default()
    ))
}

/// When a message of yours was delivered, for its tick, when that came more
/// than `ext::LATE_DELIVERY_MS` after it was written (E1: a message that
/// waited an hour said only "Delivered"): "today at 15:10", "yesterday at
/// 15:10", or how long ago without the local offset. None when it went at
/// once.
pub(super) fn delivered_text(delivered_ms: u64, written_ms: u64, now_ms: u64) -> Option<String> {
    if delivered_ms < written_ms.saturating_add(super::super::ext::LATE_DELIVERY_MS) {
        return None;
    }
    let d = raven_core::local_time::deadline_with_offsets(
        delivered_ms,
        now_ms,
        local_offset(delivered_ms),
        local_offset(now_ms),
    );
    Some(super::super::ext::ended_words(&d, delivered_ms, now_ms))
}

/// When something happened, as a clock time with its zone: "today at
/// 01:42 (UTC+1)" (E2 r9: the group view had only "2 min ago"); `None`
/// without this computer's offset (the age shown beside it says enough).
pub(super) fn happened_text(at_ms: u64, now_ms: u64) -> Option<String> {
    let off = local_offset(at_ms)?;
    Some(super::super::ext::ended_zoned_with_offset(
        at_ms,
        now_ms,
        Some(off),
    ))
}

/// The day `at_ms` is on this computer's calendar, seen at `now_ms`, for a
/// conversation's day lines (Calm): "Today", "Yesterday", else "Tue 21 Oct".
/// None when the offset from UTC can't be read: no day on another clock is
/// shown.
pub(super) fn day_text(at_ms: u64, now_ms: u64) -> Option<String> {
    let d = raven_core::local_time::deadline_with_offsets(
        at_ms,
        now_ms,
        local_offset(at_ms),
        local_offset(now_ms),
    );
    if !d.local {
        return None;
    }
    Some(match d.days_ahead {
        0 => "Today".to_owned(),
        -1 => "Yesterday".to_owned(),
        _ => format!("{} {} {}", d.weekday, d.day, d.month),
    })
}

/// This computer's offset from UTC at `at_ms`. Under test it is the one a
/// test set ([`with_local_offset`]), else unknown, so every rendered screen
/// reads the same in every time zone.
fn local_offset(at_ms: u64) -> Option<i32> {
    #[cfg(not(test))]
    return raven_core::local_time::utc_offset_s(at_ms);
    #[cfg(test)]
    {
        let _ = at_ms;
        TEST_OFFSET.with(std::cell::Cell::get)
    }
}

#[cfg(test)]
thread_local! {
    /// The offset [`deadline_text`] uses on this thread (None: unknown).
    static TEST_OFFSET: std::cell::Cell<Option<i32>> = const { std::cell::Cell::new(None) };
}

/// Runs `f` with this computer's offset from UTC taken to be `off`.
#[cfg(test)]
pub(super) fn with_local_offset<T>(off: Option<i32>, f: impl FnOnce() -> T) -> T {
    let before = TEST_OFFSET.with(|o| o.replace(off));
    let out = f();
    TEST_OFFSET.with(|o| o.set(before));
    out
}

/// [`deadline_text`] with this computer's offset from UTC at the deadline
/// (`off_at`) and now (`off_now`): across a daylight saving change they
/// differ, and "today" / "tomorrow" follow the wall calendar.
fn deadline_text_with(
    expires_at_ms: u64,
    now_ms: u64,
    off_at: Option<i32>,
    off_now: Option<i32>,
) -> DeadlineText {
    let left_ms = expires_at_ms.saturating_sub(now_ms);
    let minutes = left_ms / 60_000;
    let (short, long) = match minutes {
        0 => (
            "less than a minute".to_owned(),
            "less than a minute".to_owned(),
        ),
        1 => ("about 1 min".to_owned(), "about a minute".to_owned()),
        2..=119 => (
            format!("about {minutes} min"),
            format!("about {minutes} minutes"),
        ),
        _ => {
            let hours = (minutes + 30) / 60;
            (format!("about {hours} h"), format!("about {hours} hours"))
        }
    };
    let d = raven_core::local_time::deadline_with_offsets(expires_at_ms, now_ms, off_at, off_now);
    if !d.local {
        return DeadlineText {
            short: format!("{short} from now"),
            long: format!("{long} from now"),
            hh_mm: None,
            left_ms,
        };
    }
    let day = match d.days_ahead {
        0 => "today".to_owned(),
        1 => "tomorrow".to_owned(),
        2..=5 => d.weekday.to_owned(),
        _ => format!("{} {} {}", d.weekday, d.day, d.month),
    };
    DeadlineText {
        short: format!("{day} {}", d.hh_mm),
        long: format!("{day} at {} ({long} from now)", d.hh_mm),
        hh_mm: Some(d.hh_mm),
        left_ms,
    }
}

/// What a message written now to the friend `peer` (their key, hex) could
/// do: wait until when (a secure connection with them can still take new
/// messages), or not at all: the last one ended (they have to meet first),
/// or there was none yet (a first message goes only while both are online).
/// None when it is not known (Home then shows no line). Run it on the store
/// worker, never while drawing.
///
/// It is the rule `raven contact list` and the desktop apps use too
/// (`ext::away_reach`, E1): with the long message horizon live, the
/// message's own deadline 7 days from now, a secure connection or not (a
/// first message parks too); otherwise `raven_core::outbox::queue_reach`
/// (CP.6): the expiry a message sealed now would get, from the session
/// store's metadata only (no protected load, so no Keychain prompt), and
/// only when that store exists (it never creates one).
pub(super) fn queue_horizon(data_dir: &Path, peer: &str, now_ms: u64) -> Option<QueueReach> {
    #[cfg(test)]
    HORIZON_READS.with(|reads| reads.set(reads.get() + 1));
    let key = super::super::parse_pub_hex_strict(peer).ok()?;
    super::super::ext::away_reach(data_dir, &key, now_ms).ok()
}

/// raven-node's outbox rows with the time the outbox gives each waiting
/// message up (`ext::with_message_deadlines`, E1): with the long message
/// horizon live, 7 days after it was written, not its envelope's day. Run it
/// on the poller, never while drawing.
pub(super) fn with_message_deadlines(data_dir: &Path, items: &mut [raven_core::ipc::OutboxItem]) {
    super::super::ext::with_message_deadlines(data_dir, items);
}

// What a message written now could do for a friend ([`queue_horizon`]).
pub(super) use raven_core::outbox::QueueReach;

#[cfg(test)]
thread_local! {
    /// [`queue_horizon`]'s runs on this thread.
    static HORIZON_READS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// How many times [`queue_horizon`] ran on this thread: tests check that a
/// draw never reads.
#[cfg(test)]
pub(super) fn horizon_reads() -> usize {
    HORIZON_READS.with(std::cell::Cell::get)
}

// ── Sending ─────────────────────────────────────────────────────────────────

// A route a send dials, and its carrier (pair_init_lab.rs).
pub(super) use super::super::pair_init_lab::{DialCarrier, DialRoute};
// What `raven send --carrier` asks for: the app always sends `auto`.
pub(super) use super::super::CarrierChoice;
// `raven outbox` as the app runs it: only `Retry`, and `Cancel` with
// `yes: true` (the app asked first).
pub(super) use super::super::ext::OutboxCmd;

/// cli.rs's plan for a send to a saved friend: their routes in plan order
/// (LAN, Internet, p2p) as the gates and their verified state allow, the
/// LAN dial taken from `env` (the app passes None: OD-17), the learned LAN
/// routes of a friend with no LAN address saved in its place, and where the
/// LAN beacon found the friend just now (`found`) first among the LAN
/// routes. `data_dir`: the profile, for the hint printed for a friend with
/// no address at all.
#[allow(clippy::too_many_arguments)]
pub(super) fn plan_contact_routes_with(
    data_dir: &Path,
    c: &Contact,
    choice: CarrierChoice,
    env: Option<String>,
    internet_live: bool,
    p2p_live: bool,
    unsaved_lan: &[String],
    found: &[String],
) -> Result<(Vec<DialRoute>, Option<String>), String> {
    super::super::plan_contact_routes_with(
        data_dir,
        c,
        choice,
        env,
        internet_live,
        p2p_live,
        unsaved_lan,
        found,
    )
}

/// Where the LAN beacon found a friend just now (cli.rs's `beacon_routes`,
/// Phase 3): raven-node's answer to IPC `LanLocate`, at most two local
/// addresses, none while its gate is closed, LAN is off or the program does
/// not answer. Dialled first, never recorded or saved.
pub(super) fn beacon_routes(
    data_dir: &Path,
    contact: &Contact,
    choice: CarrierChoice,
) -> Vec<String> {
    super::super::beacon_routes(data_dir, contact, choice)
}

/// The LAN routes learned for a friend with no LAN address saved (cli.rs's
/// `unsaved_lan_routes`: route hints, and cutoff F7 when `guess_live`):
/// what a send tries instead of saying the friend has no address.
pub(super) fn unsaved_lan_routes(
    data_dir: &Path,
    contact: &Contact,
    choice: CarrierChoice,
    guess_live: bool,
) -> Vec<String> {
    super::super::unsaved_lan_routes(data_dir, contact, choice, guess_live)
}

/// The friend's learned LAN addresses as extra routes after the saved one
/// (cli.rs's `add_learned_routes`): every one added (never recorded for
/// raven-node's outbox), and those to save when a send reached them there.
pub(super) fn add_learned_routes(
    data_dir: &Path,
    contact: &Contact,
    routes: &mut Vec<DialRoute>,
) -> (Vec<String>, Vec<String>) {
    super::super::add_learned_routes(data_dir, contact, routes)
}

/// A send to a saved friend, planned as `raven send --contact` plans it.
pub(super) struct FriendSend {
    /// The routes, in plan order.
    pub(super) routes: Vec<DialRoute>,
    /// The learned LAN routes planned, or where the LAN beacon found the
    /// friend (a subset of `routes`): dialled now, never recorded for
    /// raven-node's outbox (cli.rs's `SendTarget::unrecorded`).
    pub(super) unrecorded: Vec<String>,
    /// The learned LAN routes that may replace the saved address once a send
    /// reached the friend there (`SendTarget::learned_lan_dials`).
    pub(super) learned_lan_dials: Vec<String>,
}

/// The routes of a send to the saved friend `c`: cli.rs's
/// `resolve_send_target` for `--contact`, mirrored with no address from the
/// environment (OD-17) and the `auto` carrier. Hide my IP drops the Internet
/// direct route (with cli.rs's refusal when that was the only one), a PeerId
/// the friend's route hints name is planned like a saved one, and the
/// learned LAN routes follow the saved one (or, with none saved, stand in
/// for it: route hints, cutoff F7), unless the LAN beacon found the friend
/// just now: then its finds go first, and nothing learned is planned for
/// LAN. testkit's drift hash of that function's body fails when it changes:
/// then update this one. A learned PeerId is not saved into the book here
/// (the CLI saves one a p2p link proved; the app leaves it learned).
pub(super) fn plan_friend_send(data_dir: &Path, c: &Contact) -> Result<FriendSend, String> {
    let choice = CarrierChoice::Auto;
    let p2p_live = raven_core::p2p_live_enabled();
    let hidden = super::super::hides_ip_from(data_dir, c);
    if hidden && choice == CarrierChoice::Internet {
        return Err(super::super::hidden_ip_text(c));
    }
    let learned_p2p = super::super::learned_peer_id(data_dir, c, p2p_live);
    let mut planned = c.clone();
    if let Some(peer_id) = &learned_p2p {
        planned.p2p = peer_id.clone();
    }
    if hidden {
        planned.internet_dial.clear();
    }
    // Where the LAN beacon found the friend just now: first among the LAN
    // routes, never saved (no address from the environment here, so always
    // asked).
    let found = beacon_routes(data_dir, &planned, choice);
    // No LAN address saved: what was learned stands in for one (no address
    // from the environment here, so always asked unless the beacon found
    // the friend).
    let unsaved_lan = if found.is_empty() {
        let guess_live = raven_core::outbox::default_port_guess_live();
        unsaved_lan_routes(data_dir, &planned, choice, guess_live)
    } else {
        Vec::new()
    };
    let (mut routes, env_lan_dial) = super::super::with_card_onion_route(
        &planned,
        choice,
        raven_core::onion_live_enabled(),
        super::super::with_nearby_route(
            &planned,
            choice,
            raven_core::nearby_live_enabled(),
            plan_contact_routes_with(
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
        if hidden && choice == CarrierChoice::Auto && !c.internet_dial.trim().is_empty() {
            super::super::hidden_ip_text(c)
        } else {
            e
        }
    })?;
    let planned_lan = |dial: &String| {
        routes
            .iter()
            .any(|r| r.carrier == DialCarrier::Lan && r.dial == *dial)
    };
    let found: Vec<String> = found.into_iter().filter(planned_lan).collect();
    let unsaved_lan: Vec<String> = unsaved_lan.into_iter().filter(planned_lan).collect();
    let (unrecorded, learned_lan_dials) = if !found.is_empty() {
        // Dialled now; never recorded for the outbox and never saved.
        (found, Vec::new())
    } else if !unsaved_lan.is_empty() {
        (unsaved_lan.clone(), unsaved_lan)
    } else if env_lan_dial.is_none() {
        add_learned_routes(data_dir, &planned, &mut routes)
    } else {
        (Vec::new(), Vec::new())
    };
    Ok(FriendSend {
        routes,
        unrecorded,
        learned_lan_dials,
    })
}

/// A send to a friend over a plan with a nearby route (Phase 5): tell the
/// running raven-node the user works with them now (nearby_cli.rs, best
/// effort and silent).
pub(super) fn nearby_foreground(data_dir: &Path, routes: &[DialRoute], pub_hex: &str) {
    if routes.iter().any(|r| r.carrier == DialCarrier::Nearby) {
        super::super::nearby_cli::foreground(data_dir, pub_hex);
    }
}

/// What a send records for raven-node's outbox: the carrier choice, and
/// whether a friend may carry it (cli.rs).
pub(super) fn send_intent(
    carrier: CarrierChoice,
    explicit_dial: bool,
) -> (raven_core::outbox::CarrierChoice, bool) {
    super::super::send_intent(carrier, explicit_dial)
}

/// ext.rs's send over one LAN address, `listen` its fallback; `unrecorded`
/// as in [`run_send_secure_routes`].
#[allow(clippy::too_many_arguments)]
pub(super) fn run_send_secure(
    data_dir: &Path,
    id: &Identity,
    peer: &str,
    peer_pub_hex: &str,
    listen: &str,
    text: &str,
    choice: raven_core::outbox::CarrierChoice,
    custody_ok: bool,
    unrecorded: &[String],
) -> Result<(), String> {
    super::super::ext::run_send_secure(
        data_dir,
        id,
        peer,
        peer_pub_hex,
        listen,
        text,
        "",
        "",
        choice,
        custody_ok,
        unrecorded,
    )
}

/// ext.rs's send over one address on a named carrier.
pub(super) fn run_send_secure_on(
    data_dir: &Path,
    id: &Identity,
    peer: &str,
    peer_pub_hex: &str,
    listen: &str,
    text: &str,
    carrier: DialCarrier,
) -> Result<(), String> {
    super::super::ext::run_send_secure_on(
        data_dir,
        id,
        peer,
        peer_pub_hex,
        listen,
        text,
        "",
        "",
        carrier,
    )
}

/// ext.rs's send over a friend's routes in order, and the route that took it;
/// `unrecorded` are never recorded for raven-node's outbox.
#[allow(clippy::too_many_arguments)]
pub(super) fn run_send_secure_routes(
    data_dir: &Path,
    id: &Identity,
    routes: &[DialRoute],
    peer_pub_hex: &str,
    text: &str,
    show_carrier: bool,
    choice: raven_core::outbox::CarrierChoice,
    unrecorded: &[String],
) -> Result<DialRoute, String> {
    super::super::ext::run_send_secure_routes(
        data_dir,
        id,
        routes,
        peer_pub_hex,
        text,
        show_carrier,
        choice,
        unrecorded,
    )
}

/// One message to a saved friend over `routes` (planned as above, with its
/// `unrecorded` learned routes), as `raven send --contact` sends it: cli.rs's
/// `run_send`, mirrored with the identity the app already holds (cli.rs's
/// caller loads it through a helper that exits), the routes the app planned
/// (cli.rs's come from `resolve_send_target`) and the `auto` carrier.
/// testkit's drift hash of that function's body fails when it changes: then
/// update this one. Ok is the route that delivered it; Err the outcome text
/// (queued, sent but not confirmed, or not sent).
#[allow(clippy::too_many_arguments)]
pub(super) fn send_routes(
    data_dir: &Path,
    id: &Identity,
    routes: &[DialRoute],
    pub_hex: &str,
    listen: &str,
    text: &str,
    unrecorded: &[String],
) -> Result<DialRoute, String> {
    let choice = CarrierChoice::Auto;
    let (recorded, custody_ok) = send_intent(choice, false);
    match routes {
        // One LAN route: the path every LAN send has always taken. A learned
        // route (cutoff F7's guess) is dialled, never recorded.
        [only] if only.carrier == DialCarrier::Lan => run_send_secure(
            data_dir, id, &only.dial, pub_hex, listen, text, recorded, custody_ok, unrecorded,
        )
        .map(|()| only.clone()),
        // `--carrier internet` with one route: never the app's, which sends
        // `auto`; kept so this reads as cli.rs's.
        [only] if choice == CarrierChoice::Internet && only.carrier != DialCarrier::P2p => {
            run_send_secure_on(
                data_dir,
                id,
                &only.dial,
                pub_hex,
                listen,
                text,
                only.carrier,
            )
            .map(|()| only.clone())
        }
        routes => run_send_secure_routes(
            data_dir,
            id,
            routes,
            pub_hex,
            text,
            matches!(
                choice,
                CarrierChoice::Internet | CarrierChoice::P2p | CarrierChoice::Nearby
            ),
            recorded,
            unrecorded,
        ),
    }
}

/// `raven outbox retry|cancel` (ext.rs): what it prints is the job's.
pub(super) fn cmd_outbox(data_dir: &Path, cmd: OutboxCmd) -> Result<(), String> {
    super::super::ext::cmd_outbox(data_dir, cmd)
}

// ── The background program ──────────────────────────────────────────────────

// What the profile's raven-node says about itself (cli.rs's reading of its
// Status, as `ash status` shows it).
pub(super) use super::super::NodeReach;
// Why its listener is down, as cli.rs reads it from that Status.
pub(super) use super::super::ListenerDown;
// How to stop this profile's node and no other: by the pid its Status gave,
// else by a pattern anchored to the profile (ext.rs).
pub(super) use super::super::ext::profile_stop_advice;
// The stop step itself (node_control.rs: the rules, carrying them out, and
// Windows tools by absolute path), which `raven lock` runs too (privacy
// pack PP.15); and the scheduled task Raven's Windows installer registers.
pub(super) use super::super::node_control::{
    carry_out_stop, stop_plan, system_tool, StopOutcome, StopPlan, SCHEDULED_TASK,
};
// SIGTERM to one process (node_control.rs): the signal tests send it to the
// test process itself.
#[cfg(all(test, unix))]
pub(super) use super::super::node_control::kill_term;
// The vault: where a program without a terminal finds the passphrase (Unix
// other than macOS has it).
#[cfg(all(unix, not(target_os = "macos")))]
pub(super) use raven_core::keystore_vault::PASSPHRASE_FILE_ENV;
#[cfg(any(test, all(unix, not(target_os = "macos"))))]
pub(super) use raven_core::keystore_vault::SYSTEMD_CREDENTIAL_NAME;

/// The passphrase file this computer keeps for this vault profile, if one
/// is there (review D-lock-tui-2): cli.rs's lookup for `raven lock`, the
/// one `RAVEN_KEYSTORE_PASSPHRASE_FILE` names, the systemd credential, the
/// one Raven's own login item hands raven-node, then PASSFILE's default.
/// Reads only; Raven's login item only where this build reads login items.
/// Node worker only.
#[cfg(any(test, all(unix, not(target_os = "macos"))))]
pub(super) fn saved_passphrase_file(data_dir: &Path) -> Option<PathBuf> {
    let login = super::super::node_control::LoginEnv::current().ok();
    super::super::profile_passphrase_file(data_dir, login.as_ref(), &|name| std::env::var_os(name))
}

/// `raven lock`'s paragraph about a saved passphrase file, for LOCK
/// (review D-lock-tui-2): `file` as the screen shapes it (display.rs).
pub(super) fn passphrase_file_paragraph(file: &str) -> String {
    super::super::passphrase_file_paragraph(file)
}

/// cli.rs's reading of a Status answer (or its error): listening, on this
/// computer only, sending only, not running, or not answering. `here` says
/// whether an address is this computer's ([`is_on_this_computer`]): a
/// listener bound to an address that has left it is not receiving.
pub(super) fn classify_node_reach(
    status: &Result<IpcResponse, String>,
    here: impl Fn(IpAddr) -> Option<bool>,
) -> NodeReach {
    super::super::classify_node_reach(status, here)
}

/// Whether `ip` is one of this computer's addresses (raven-core's
/// `netifs::is_on_this_computer`); None when the interfaces can't be read.
/// Reads the system: the poller and the probe ask it, never a draw.
pub(super) fn is_on_this_computer(ip: IpAddr) -> Option<bool> {
    netifs::is_on_this_computer(ip)
}

/// A listen address on this computer only (ext.rs: a loopback IP, or
/// `localhost…`), as [`classify_node_reach`] counts it (testkit pins the
/// forms).
#[cfg(test)]
pub(super) fn listen_is_loopback(listen: &str) -> bool {
    super::super::ext::listen_is_loopback(listen)
}

/// The raven-node program a start runs: next to this program, else a PATH
/// lookup when this program's own path is unknown (ext.rs).
pub(super) fn raven_node_bin_public() -> PathBuf {
    super::super::ext::raven_node_bin_public()
}

/// Starts the profile's raven-node unless one answers already, as a send
/// does (ext.rs): the same arguments, detached, its output in the 0600
/// service log, the stale-socket and Keychain-aware wait. Says on stderr
/// what it started (`started raven-node (process N)`).
pub(super) fn ensure_mac_lan_daemon(data_dir: &Path) -> Result<(), String> {
    super::super::ext::ensure_mac_lan_daemon(data_dir)
}

/// One IPC request to the profile's raven-node, waiting at most `timeout`
/// for the answer (ipc_client.rs; one connect, no retry).
pub(super) fn ipc_request_timeout(
    data_dir: &Path,
    req: &IpcRequest,
    timeout: Duration,
) -> Result<IpcResponse, String> {
    super::super::ipc_client::ipc_request_timeout(data_dir, req, timeout)
}

/// An IPC error that means raven-node took the request and never answered.
pub(super) fn error_means_no_answer(err: &str) -> bool {
    super::super::ipc_client::error_means_no_answer(err)
}

/// Whether the profile keeps its keys in the passphrase vault (Unix without
/// a system keychain). Nothing is recorded: a profile with no identity gets
/// no keystore marker from it.
#[cfg(all(unix, not(target_os = "macos")))]
pub(super) fn uses_vault(data_dir: &Path) -> Result<bool, String> {
    raven_core::keystore_select::uses_vault(data_dir, false)
}

/// raven-node's own output, in the profile (0600; ext.rs writes it).
pub(super) fn service_log_path(data_dir: &Path) -> PathBuf {
    data_dir.join(raven_core::paths::SERVICE_LOG_NAME)
}

/// The chat history file, which raven-node writes as messages arrive.
pub(super) fn history_path(data_dir: &Path) -> PathBuf {
    raven_core::chat_history::history_path(data_dir)
}

/// The profile's chat history, both directions, in the order it was written
/// (raven-core's `ChatHistory::load`, as `ash messages` reads it). It takes
/// the history's lock and creates its lock file, so only once the identity
/// exists. An unreadable history is an error, never an empty one.
pub(super) fn load_history(data_dir: &Path) -> Result<Vec<ChatHistoryEntry>, String> {
    ChatHistory::load(data_dir)
        .map(|history| history.without_group_copies().entries)
        .map_err(|e| sanitize_terminal_line(&e.to_string()))
}

/// What raven-core calls each item it reads from the macOS Keychain, in plain
/// words (`KeychainWhat::label`): the only texts the KC overlay shows.
pub(super) const KEYCHAIN_ITEMS: [&str; 4] = [
    KeychainWhat::IdentitySeed.label(),
    KeychainWhat::ChatHistoryKey.label(),
    KeychainWhat::SessionSecret.label(),
    KeychainWhat::PrekeyState.label(),
];

/// The item a waiting raven-node names in its service log
/// (`BLOCKED_ON_KEYCHAIN`, the newest marker in `log_tail`), as ext.rs reads
/// it; None when the log shows no such wait.
pub(super) fn service_keychain_wait(log_tail: &str) -> Option<&'static str> {
    const ALL: [KeychainWhat; 4] = [
        KeychainWhat::IdentitySeed,
        KeychainWhat::ChatHistoryKey,
        KeychainWhat::SessionSecret,
        KeychainWhat::PrekeyState,
    ];
    let marker = raven_core::macos_keychain::last_daemon_marker(log_tail)?;
    Some(
        ALL.iter()
            .find(|what| what.token() == marker.what)
            .map_or(UNKNOWN_KEYCHAIN_ITEM, |what| what.label()),
    )
}

/// What the Keychain wait names when raven-core's words are not known here.
pub(super) const UNKNOWN_KEYCHAIN_ITEM: &str = "a saved secret";

/// The inbound firewall rule for `port`, as text for the user to run
/// (cli.rs's `internet_firewall_hint`; Raven never changes the firewall).
/// FW shows it with the LAN port.
pub(super) fn internet_firewall_hint(port: &str) -> String {
    super::super::internet_firewall_hint(port)
}

// ── Privacy (privacy pack PP.21) ────────────────────────────────────────────

// The privacy pack's words the app shows as they are (its UX copy): the
// one-time sealing notice (with the keychain sentence on macOS), and NET's
// rows for a key root that can't be read now, one that is gone, and a
// profile the user unsealed.
pub(super) use raven_core::privacy::{
    KEYCHAIN_AT_START_TEXT, KEY_LOST_TEXT, KEY_UNAVAILABLE_TEXT, SEALING_NOTICE, UNSEALED_TEXT,
};

/// A privacy setting or action this profile can't use now: it has no
/// identity on record (raven-core refuses the setting then), or this build
/// has no privacy pack (the terminal app's branch before its merge); or, for
/// Raven's login item ([`own_login_item`]), this build reads none. The app
/// hides every row and action that needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct NotAvailable;

/// How long chats are kept on this computer (raven-core's `ChatKeep`, as
/// `raven chats keep 7d|30d|90d|always` sets it), as SET's chooser offers it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ChatKeepView {
    Days7,
    Days30,
    Days90,
    /// Until the user deletes them (`always`).
    Keep,
}

impl ChatKeepView {
    /// The chooser's order.
    pub(super) const ALL: [ChatKeepView; 4] = [
        ChatKeepView::Days7,
        ChatKeepView::Days30,
        ChatKeepView::Days90,
        ChatKeepView::Keep,
    ];

    fn of(keep: raven_core::privacy::ChatKeep) -> ChatKeepView {
        use raven_core::privacy::ChatKeep;
        match keep {
            ChatKeep::Days7 => ChatKeepView::Days7,
            ChatKeep::Days30 => ChatKeepView::Days30,
            ChatKeep::Days90 => ChatKeepView::Days90,
            ChatKeep::Always => ChatKeepView::Keep,
        }
    }

    fn core(self) -> raven_core::privacy::ChatKeep {
        use raven_core::privacy::ChatKeep;
        match self {
            ChatKeepView::Days7 => ChatKeep::Days7,
            ChatKeepView::Days30 => ChatKeep::Days30,
            ChatKeepView::Days90 => ChatKeep::Days90,
            ChatKeepView::Keep => ChatKeep::Always,
        }
    }
}

/// How long this profile keeps chats (raven-core's `privacy::chat_keep`; a
/// `privacy.json` it can't read keeps everything). [`NotAvailable`] before
/// the profile has an identity on record.
pub(super) fn chat_keep(data_dir: &Path) -> Result<ChatKeepView, NotAvailable> {
    if !raven_core::identity_store::identity_recorded(data_dir).unwrap_or(false) {
        return Err(NotAvailable);
    }
    Ok(ChatKeepView::of(raven_core::privacy::chat_keep(data_dir)))
}

/// "Keep chats for" saved, as `raven chats keep` saves it (raven-core's
/// `privacy::set_chat_keep`, in `privacy.json`). The next retention pass
/// deletes what is older.
pub(super) fn set_chat_keep(data_dir: &Path, keep: ChatKeepView) -> Result<(), String> {
    raven_core::privacy::set_chat_keep(data_dir, keep.core())
        .map_err(|e| sanitize_terminal_line(&e))
}

/// What "Delete chat with {name}" did: counts only.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct DeleteChatOutcome {
    /// Messages deleted, both directions (the history's rows, or the
    /// session store's received rows when more of those went).
    pub(super) deleted: u32,
    /// Messages to the friend still waiting to be sent: they stay.
    pub(super) still_waiting: u32,
    /// Received messages that could not be deleted now (one still being
    /// stored): a second delete takes them.
    pub(super) skipped_pending: u32,
}

/// "Delete chat with {name}": `raven chats delete --yes`'s path (privacy
/// pack PP.8): ext.rs's `delete_chat_with` (the session store's received
/// rows go first, each leaving a tombstone so the chat stays deleted, then
/// every history row with the friend `peer`), then ext.rs's count of the
/// messages to them still waiting to be sent, which stay. Store worker only.
pub(super) fn delete_chat(data_dir: &Path, peer: &str) -> Result<DeleteChatOutcome, String> {
    let deleted = super::super::ext::delete_chat_with(data_dir, peer)?;
    let waiting = super::super::ext::waiting_messages_to(data_dir, peer);
    Ok(DeleteChatOutcome {
        deleted: deleted.history.max(deleted.inbox.deleted),
        still_waiting: u32::try_from(waiting).unwrap_or(u32::MAX),
        skipped_pending: deleted.inbox.skipped,
    })
}

/// "Forget {name}'s address": `raven contact forget-address --yes`'s path
/// (privacy pack PP.7) for the friend `peer`: their saved LAN and Internet
/// addresses are cleared (name, pin and the rest stay) and what Raven
/// learned about reaching them is forgotten. What could not be forgotten
/// comes back, one note each, raw (review D-lock-tui-8: the app says so,
/// with the notes in Details, where it used to say only that it forgot).
pub(super) fn forget_address(data_dir: &Path, peer: &str) -> Result<Vec<String>, String> {
    super::super::forget_contact_address(data_dir, peer)
}

/// The privacy pack's one-time notices still to show (PP.4, PP.9).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct PrivacyNotices {
    /// The sealing notice: the profile is sealed and it was never shown.
    pub(super) sealing: bool,
    /// The retention notice: chats will be deleted after a setting, from
    /// this time on (milliseconds since the Unix epoch).
    pub(super) retention_from: Option<u64>,
}

/// One of the notices of [`PrivacyNotices`], or Home's word after opening
/// the app cleared a lock that turned Raven's login item off (PP.23:
/// [`reopen_after_lock`]; said once each time, nothing is recorded).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Notice {
    Sealing,
    Retention,
    LoginItemOff,
}

/// The notices due in this profile (`privacy.json`), read without taking
/// them: the app marks one shown once the user said OK.
pub(super) fn privacy_notices(data_dir: &Path) -> PrivacyNotices {
    PrivacyNotices {
        sealing: raven_core::privacy::sealing_notice_due(data_dir),
        retention_from: raven_core::privacy::retention_notice_due(data_dir),
    }
}

/// `notice` was shown: the CLI does not say it again (raven-core's
/// `take_sealing_notice` / `take_retention_notice`; a notice is never worth
/// an error).
pub(super) fn mark_notice_shown(data_dir: &Path, notice: Notice) {
    match notice {
        Notice::Sealing => {
            let _ = raven_core::privacy::take_sealing_notice(data_dir);
        }
        Notice::Retention => {
            let _ = raven_core::privacy::take_retention_notice(data_dir);
        }
        // Said again whenever opening the app clears such a lock.
        Notice::LoginItemOff => {}
    }
}

/// The retention notice in the UX copy's words, for `keep`, the first
/// deletion at `first_ms` seen at `now_ms`: "on Sat 25 Oct" on this
/// computer's clock, or "in about 7 days" when its offset can't be read.
/// Pure: a draw may ask.
pub(super) fn retention_notice_text(keep: ChatKeepView, first_ms: u64, now_ms: u64) -> String {
    let d = raven_core::local_time::deadline_with_offsets(
        first_ms,
        now_ms,
        local_offset(first_ms),
        local_offset(now_ms),
    );
    let when = if d.local {
        format!("on {} {} {}", d.weekday, d.day, d.month)
    } else {
        d.rel
    };
    raven_core::privacy::retention_notice_text(keep.core(), &when)
}

/// The profile's at-rest state as raven-node's Status says it (`at_rest`,
/// PP.4). Words this build does not know are [`AtRestStateView::Other`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AtRestStateView {
    Sealed,
    /// raven-node is loading the at-rest key (a keychain dialog may wait).
    WaitingForKeychain,
    /// The keystore did not give the key: nobody can connect, nothing is sent.
    KeyUnavailable,
    /// The key is gone from the keystore (review A-keys-format-4): the same,
    /// until it is put back or the profile is erased.
    KeyLost,
    Migrating,
    Plain,
    /// `raven privacy unseal` ran: nothing seals until `seal-now`.
    UnsealedByUser,
    /// Sealing waits for free disk space.
    NeedsDiskSpace,
    Other,
}

impl AtRestStateView {
    /// Raven can't open the friends list: NET's chip says so.
    pub(super) fn locked_out(self) -> bool {
        matches!(
            self,
            AtRestStateView::KeyUnavailable
                | AtRestStateView::KeyLost
                | AtRestStateView::WaitingForKeychain
        )
    }
}

/// [`AtRestStateView`] of a Status answer; None for an error, or a node of a
/// build before the privacy pack (its Status has no `at_rest`).
pub(super) fn at_rest_state(status: &Result<IpcResponse, String>) -> Option<AtRestStateView> {
    use raven_core::privacy as p;
    let Ok(IpcResponse::Status {
        at_rest: Some(at_rest),
        ..
    }) = status
    else {
        return None;
    };
    Some(match at_rest.state.as_str() {
        p::STATE_SEALED => AtRestStateView::Sealed,
        p::STATE_WAITING_FOR_KEYCHAIN => AtRestStateView::WaitingForKeychain,
        p::STATE_KEY_UNAVAILABLE => AtRestStateView::KeyUnavailable,
        p::STATE_KEY_LOST => AtRestStateView::KeyLost,
        p::STATE_MIGRATING => AtRestStateView::Migrating,
        p::STATE_PLAIN => AtRestStateView::Plain,
        p::STATE_UNSEALED_BY_USER => AtRestStateView::UnsealedByUser,
        p::STATE_NEEDS_DISK_SPACE => AtRestStateView::NeedsDiskSpace,
        _ => AtRestStateView::Other,
    })
}

/// About how many bytes sealing this profile waits for (`privacy.json`), or
/// None when it waits for none. A few small reads, no keystore call.
pub(super) fn disk_space_needed(data_dir: &Path) -> Option<u64> {
    raven_core::privacy::status(data_dir).needs_disk_space
}

/// NET's row while sealing waits for free disk space (UX copy), with how
/// much when it is known.
pub(super) fn disk_space_text(needed: Option<u64>) -> String {
    match needed {
        Some(needed) => raven_core::privacy::disk_space_text(needed),
        None => "Raven needs more free disk space to finish encrypting this profile. Nothing \
                 was changed."
            .to_owned(),
    }
}

// ── Erase (privacy pack PP.22) ──────────────────────────────────────────────

// `raven erase`'s question (the UX copy): ERASE shows its title, then its
// paragraph.
pub(super) use super::super::{ERASE_PARAGRAPH, ERASE_TITLE};

/// What erasing this profile deletes, counted for ERASE's list.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct ErasePlanView {
    /// Saved friends; None when the friends list can't be read now.
    pub(super) friends: Option<u32>,
    /// Messages still waiting to be sent, to any friend.
    pub(super) waiting: u32,
    /// This profile's keys in the system's keystore (the macOS keychain, or
    /// the Secret Service): none on Windows, a passphrase vault or a lab
    /// profile, whose keys are files in the profile.
    pub(super) keychain_keys: u32,
}

/// What erase would delete here, or why it refuses this folder (`raven
/// erase`'s step 0 and its plan, raven-core's `erase::refusal` and
/// `erase::plan`: both read only). The friends are read from the book and
/// the waiting messages from raven-node's outbox (or the store when none
/// answers). Store worker only.
pub(super) fn erase_plan(data_dir: &Path) -> Result<ErasePlanView, String> {
    if let Some(why) = raven_core::erase::refusal(data_dir) {
        return Err(why);
    }
    erase_plan_view(data_dir)
}

/// [`erase_plan`] past its refusal.
fn erase_plan_view(data_dir: &Path) -> Result<ErasePlanView, String> {
    use raven_core::erase::{self, KeystoreItem};
    let plan = erase::plan(data_dir)?;
    let count = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
    let keychain_keys = plan
        .keystore
        .iter()
        .filter(|item| matches!(item, KeystoreItem::Platform { .. }))
        .count();
    Ok(ErasePlanView {
        friends: load_contacts(data_dir)
            .ok()
            .map(|contacts| count(contacts.len())),
        waiting: count(super::super::ext::waiting_messages(data_dir, None)),
        keychain_keys: count(keychain_keys),
    })
}

/// How an erase from the app ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum EraseEnd {
    /// It ran. `lines`: what the plain terminal gets (the UX copy). Not
    /// `finished`: something is left, the marker stays and every Raven
    /// command but `raven erase` refuses the profile; the app ends either
    /// way.
    Ran { finished: bool, lines: Vec<String> },
    /// Nothing was erased (Raven still runs, the folder is refused, or this
    /// build can't reach Raven's login item): why, in the CLI's words. The
    /// profile is as it was.
    NotErased(String),
}

/// Erases this profile as `raven erase` does once `erase` was typed, after
/// the same refusal: cli.rs's `erase_profile` (Raven's own login item
/// unloaded and the node stopped and confirmed gone, the marker, the login
/// item removed, then `close`, then the keys first and Raven's files). It
/// never prompts and prints nothing. Store worker only.
pub(super) fn erase(data_dir: &Path, close: &mut dyn FnMut()) -> EraseEnd {
    if let Some(why) = raven_core::erase::refusal(data_dir) {
        return EraseEnd::NotErased(why);
    }
    match super::super::node_control::LoginEnv::current() {
        Ok(env) => erase_with(data_dir, &env, close),
        Err(why) => EraseEnd::NotErased(why),
    }
}

/// [`erase`] past its refusal, with Raven's login item in `env`.
fn erase_with(
    data_dir: &Path,
    env: &super::super::node_control::LoginEnv,
    close: &mut dyn FnMut(),
) -> EraseEnd {
    let passphrase_file = super::super::erase_passphrase_file(data_dir, env);
    match super::super::erase_profile(data_dir, env, &mut |_| {}, close) {
        Ok(erased) if erased.report.finished => EraseEnd::Ran {
            finished: true,
            lines: super::super::erase_result_lines(&erased, passphrase_file.as_deref(), data_dir),
        },
        Ok(erased) => {
            let report = &erased.report;
            let failed: Vec<String> = report.failures.iter().map(|f| f.what.clone()).collect();
            EraseEnd::Ran {
                finished: false,
                lines: vec![format!(
                    "Erase stopped: {}. Still on this computer: {}. Run `raven erase` to finish.",
                    failed.join("; "),
                    report.still_here().join(", ")
                )],
            }
        }
        // The marker went down, then the plan could not be made: the
        // profile is closed until `raven erase` finishes.
        Err(why) if raven_core::erase::in_progress(data_dir) => EraseEnd::Ran {
            finished: false,
            lines: vec![why],
        },
        Err(why) => EraseEnd::NotErased(why),
    }
}

/// [`erase`] in a test: past the refusal (no lab erase root needed), with
/// an empty lab folder for Raven's login item in `lab` beside the profile,
/// so no real login item is read and no tool runs.
#[cfg(test)]
pub(super) fn erase_in_lab(data_dir: &Path, close: &mut dyn FnMut()) -> EraseEnd {
    use super::super::node_control::{LoginEnv, Platform};
    let lab = data_dir
        .parent()
        .expect("a profile in a folder")
        .join("lab");
    std::fs::create_dir_all(&lab).expect("the lab folder");
    let env = LoginEnv::lab(Platform::THIS, &lab, &lab.join("tools"), 501);
    erase_with(data_dir, &env, close)
}

/// Forgets this profile's at-rest keys cached in this process (raven-core's
/// `at_rest::forget_cached_keys`): the app holds them no longer once its
/// erase has begun.
pub(super) fn forget_profile_keys(data_dir: &Path) {
    raven_core::at_rest::forget_cached_keys(data_dir);
}

// ── Lock (privacy pack PP.23) ───────────────────────────────────────────────

/// Raven's own login item for this profile, as the app knows it: the
/// installer's item, running `raven-node service` for this data dir
/// (node_control.rs's `own_login_item`). It starts Raven again at the next
/// login. The app only ever unloads it for this login session, and never
/// turns it off or on (OD-11; OD-PP-12 option (a)): `raven lock` and `raven
/// unlock` do that.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct LoginItemView {
    /// launchd's agent, the systemd user unit or the scheduled task.
    pub(super) managed: Managed,
    /// A `raven lock` turned it off (`privacy.json` records
    /// `lock_login_item: disabled`), and only `raven unlock` turns it on
    /// again: it starts nothing at the next login (review D-lock-tui-7).
    pub(super) stays_off: bool,
}

/// Raven's own login item for this profile, or None: no item, another
/// profile's, one someone else wrote, or one that can't be read.
/// [`NotAvailable`] when this build reads no login items: a debug build
/// without both lab switches (node_control.rs's guard), or a computer with
/// no home folder (no SystemRoot on Windows). Read-only. Node worker only.
pub(super) fn own_login_item(data_dir: &Path) -> Result<Option<LoginItemView>, NotAvailable> {
    let env = super::super::node_control::LoginEnv::current().map_err(|_| NotAvailable)?;
    Ok(login_item_in(&env, data_dir))
}

/// [`own_login_item`] with Raven's login items in `env`.
fn login_item_in(
    env: &super::super::node_control::LoginEnv,
    data_dir: &Path,
) -> Option<LoginItemView> {
    use super::super::node_control::{self, Platform};
    use raven_core::privacy::{lock_state, LockedItem};
    let item = node_control::own_login_item(env, data_dir)?;
    let managed = match item.platform() {
        Platform::MacOs => Managed::LaunchAgent,
        Platform::Linux => Managed::SystemdUser,
        Platform::Windows => Managed::ScheduledTask,
    };
    Some(LoginItemView {
        managed,
        stays_off: lock_state(data_dir).login_item == Some(LockedItem::Disabled),
    })
}

/// LOCK's first step when Raven's own login item runs this profile: its job
/// is unloaded for this login session (`launchctl bootout`, `systemctl
/// --user stop`, `schtasks /End`: launchd's KeepAlive would start a stopped
/// node again within about 10 s), and the lock records that, so `raven
/// unlock` loads it again. The item stays on for the next login. The item
/// is looked for again here; none now unloads nothing. A job that was not
/// loaded fails to unload and is stopped all the same: the stop after this
/// checks. Node worker only.
pub(super) fn stop_for_session(data_dir: &Path) -> Result<(), String> {
    let env = super::super::node_control::LoginEnv::current()?;
    stop_for_session_in(&env, data_dir)
}

/// [`stop_for_session`] with Raven's login items in `env`.
fn stop_for_session_in(
    env: &super::super::node_control::LoginEnv,
    data_dir: &Path,
) -> Result<(), String> {
    use super::super::node_control;
    let Some(item) = node_control::own_login_item(env, data_dir) else {
        return Ok(());
    };
    let unloaded = node_control::stop_for_session(env, &item);
    raven_core::privacy::set_locked_by_app(
        data_dir,
        Some(raven_core::privacy::LockedItem::Unloaded),
    )?;
    unloaded
}

/// The lock `raven lock` keeps in `privacy.json` (PP.15): while it is set,
/// neither a send (which starts Raven when it isn't running) nor `raven
/// listen` starts Raven. The app's Lock sets it before the stop, as the
/// app's own (opening the app clears it; review E-harness-docs-ci-3), and
/// takes it back when Raven still runs after it. A Raven setting, not a
/// login setting.
pub(super) fn set_locked_by_user(data_dir: &Path, locked: bool) -> Result<(), String> {
    if locked {
        raven_core::privacy::set_locked_by_app(data_dir, None)
    } else {
        raven_core::privacy::set_unlocked(data_dir)
    }
}

/// What opening the app did to a lock ([`reopen_after_lock`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Reopened {
    /// None was set: nothing was written. `stays_off`: Raven's login item a
    /// `raven lock` turned off is still off (review D-lock-tui-4: after the
    /// app's UNLOCK, or a `raven lock` of an older build that turned it off
    /// and then did not stop Raven), until `raven unlock`.
    NotLocked { stays_off: bool },
    /// The app's own Lock set it: cleared. `stays_off`: Raven's login item
    /// a `raven lock` turned off stays off until `raven unlock`.
    Cleared { stays_off: bool },
    /// `raven lock` set it: kept until the user answers UNLOCK (review
    /// E-harness-docs-ci-3: the app used to clear it without a word, and
    /// start Raven, which `raven lock` promised would not happen).
    Kept,
}

/// Opening the app is its way to start Raven again after its own Lock
/// (PP.23; LOCK says "until you open Raven again"): that lock is cleared
/// before anything starts, so the app's start and its sends are not
/// refused. A lock `raven lock` set is kept: the app asks first (UNLOCK)
/// and clears it only on a yes ([`unlock_from_app`]). Raven's login item is
/// never touched (OD-11). Writes nothing unless it clears.
pub(super) fn reopen_after_lock(data_dir: &Path) -> Result<Reopened, String> {
    use raven_core::privacy::{self, LockedItem};
    let state = privacy::lock_state(data_dir);
    if !state.locked_by_user {
        return Ok(Reopened::NotLocked {
            stays_off: state.login_item == Some(LockedItem::Disabled),
        });
    }
    if !state.by_app {
        return Ok(Reopened::Kept);
    }
    privacy::set_unlocked(data_dir)?;
    Ok(Reopened::Cleared {
        stays_off: state.login_item == Some(LockedItem::Disabled),
    })
}

/// UNLOCK's Start (review E-harness-docs-ci-3): the user said yes to
/// starting Raven again after `raven lock`. The lock is cleared, as `raven
/// unlock` clears it first, and the app then starts Raven as it always does.
/// Raven's login item is never touched (OD-11): one the lock turned off
/// stays off until `raven unlock`, and then this says true.
pub(super) fn unlock_from_app(data_dir: &Path) -> Result<bool, String> {
    use raven_core::privacy::{self, LockedItem};
    let state = privacy::lock_state(data_dir);
    privacy::set_unlocked(data_dir)?;
    Ok(state.login_item == Some(LockedItem::Disabled))
}

/// The lab's Raven login items for a test profile: the item's file is
/// looked for in `lab` beside the profile, and the fake tools in
/// `lab/tools` (node_control.rs's shims), so no real login item is read and
/// no real tool runs.
#[cfg(all(test, unix))]
fn lab_login_env(data_dir: &Path) -> super::super::node_control::LoginEnv {
    use super::super::node_control::{LoginEnv, Platform};
    let lab = data_dir
        .parent()
        .expect("a profile in a folder")
        .join("lab");
    LoginEnv::lab(Platform::THIS, &lab, &lab.join("tools"), 501)
}

/// [`own_login_item`] in a test, with the lab's login items.
#[cfg(all(test, unix))]
pub(super) fn own_login_item_in_lab(
    data_dir: &Path,
) -> Result<Option<LoginItemView>, NotAvailable> {
    Ok(login_item_in(&lab_login_env(data_dir), data_dir))
}

/// [`stop_for_session`] in a test, with the lab's login items.
#[cfg(all(test, unix))]
pub(super) fn stop_for_session_in_lab(data_dir: &Path) -> Result<(), String> {
    stop_for_session_in(&lab_login_env(data_dir), data_dir)
}

/// The lab of [`own_login_item_in_lab`] for a test profile: Raven's login
/// item for `runs` (the installer's file, as node_control.rs's tests write
/// it) and fake tools that record each run. The record's path.
#[cfg(all(test, unix))]
pub(super) fn lab_login_item_for_tests(data_dir: &Path, runs: &Path) -> PathBuf {
    use super::super::node_control::{tests, Platform};
    let lab = data_dir
        .parent()
        .expect("a profile in a folder")
        .join("lab");
    std::fs::create_dir_all(&lab).expect("the lab folder");
    std::fs::write(
        lab.join(Platform::THIS.item_file()),
        tests::fixture(Platform::THIS, runs),
    )
    .expect("the login item");
    tests::shims(&lab, false).1
}

/// What the lab's fake tools ran, one run per line.
#[cfg(all(test, unix))]
pub(super) fn lab_tool_runs(log: &Path) -> Vec<String> {
    super::super::node_control::tests::calls(log)
}

/// `raven lock`'s record in a test (PP.15): `item` is "unloaded" or
/// "disabled" (what the lock did to Raven's own login item), or None.
#[cfg(test)]
pub(super) fn lock_for_tests(data_dir: &Path, item: Option<&str>) {
    use raven_core::privacy::{self, LockedItem};
    let item = item.map(|word| match word {
        "unloaded" => LockedItem::Unloaded,
        _ => LockedItem::Disabled,
    });
    privacy::set_locked(data_dir, item).expect("the lock is recorded");
}

/// The lock as `privacy.json` has it, in a test: whether it is set, and
/// what it did to Raven's own login item ("unloaded" or "disabled").
#[cfg(test)]
pub(super) fn lock_state_for_tests(data_dir: &Path) -> (bool, Option<&'static str>) {
    let state = raven_core::privacy::lock_state(data_dir);
    (
        state.locked_by_user,
        state.login_item.map(|item| item.as_str()),
    )
}

// ── Lock now v2 and the Raven passphrase (Phase 6 P6.40) ────────────────────

pub(super) use super::super::lock_cli::{PassOp, Typed, UnlockAnswer};
pub(super) use raven_core::raven_passphrase::Offer as PassOffer;

/// Lock v2's gate (`LOCAL_PROTECTION`) in this build: LOCKED, the lock
/// settings and the idle lock exist only while it is live.
pub(super) fn lock_v2_live() -> bool {
    raven_core::security_gate::live(raven_core::security_gate::SecGate::LocalProtection)
}

/// IPC `Lock` of this profile's raven-node: `Ok(true)` locked, `Ok(false)`
/// it does not serve Lock v2 (the app's Lock now v1 then).
pub(super) fn lock_node_v2(data_dir: &Path) -> Result<bool, String> {
    super::super::lock_cli::lock_once(data_dir)
}

/// One IPC `Unlock` with what LOCKED typed (wiped by the caller).
pub(super) fn unlock_node_v2(data_dir: &Path, passphrase: Option<&[u8]>) -> UnlockAnswer {
    super::super::lock_cli::unlock_once(data_dir, passphrase)
}

/// A change of the Raven passphrase with raven-node held locked meanwhile,
/// as `raven passphrase` does it: the lines to say, or why not.
pub(super) fn change_passphrase(
    data_dir: &Path,
    op: PassOp,
    typed: &Typed,
) -> Result<Vec<String>, String> {
    super::super::lock_cli::run_op(data_dir, op, typed)
}

/// What this profile is offered for its Raven passphrase.
pub(super) fn passphrase_offer(data_dir: &Path) -> PassOffer {
    raven_core::raven_passphrase::offer(data_dir)
}

/// A new passphrase's rules, in the user's words.
pub(super) fn check_new_passphrase(passphrase: &[u8]) -> Result<(), String> {
    raven_core::raven_passphrase::check_new(passphrase).map_err(|e| e.to_string())
}

/// The two new passphrases differ.
pub(super) const PASSPHRASES_DIFFER: &str = super::super::lock_cli::DIFFER;

/// 'Lock Raven when the computer sleeps' as it applies to this profile.
pub(super) fn sleep_lock(data_dir: &Path) -> bool {
    super::super::lock_cli::sleep_lock(data_dir)
}

/// Saves 'Lock Raven when the computer sleeps'.
pub(super) fn set_sleep_lock(data_dir: &Path, on: bool) -> Result<(), String> {
    super::super::lock_cli::set_sleep_lock(data_dir, on)
}

/// LOCKED's first line (UX copy).
pub(super) const LOCKED_SCREEN: &str = raven_core::privacy::LOCKED_V2_SCREEN;

/// What a lock does not protect on a profile without a Raven passphrase.
pub(super) fn keys_open_to_login_text() -> &'static str {
    raven_core::privacy::keys_open_to_login_text()
}

// ── Raven updates (Phase 6 P6.47) ───────────────────────────────────────────

// update_install.rs: `raven update`'s own checks and swap; the overlay shows
// its view and runs its install with the app's node.
#[cfg(test)]
pub(super) use super::super::update_install::OfferView;
#[cfg(test)]
pub(super) use super::super::update_install::ReadyView as UpdateReady;
pub(super) use super::super::update_install::UpdateView;

/// UPDATES (U) and NET's row are offered: the release bundle gate is live.
pub(super) fn updates_offered() -> bool {
    super::super::update_install::live()
}

/// What waits to be installed, NET's row and (`full`, for UPDATES) what
/// installing it shows; a read (nothing is staged, stored or noted).
pub(super) fn update_view(data_dir: &Path, full: bool) -> UpdateView {
    super::super::update_install::view(data_dir, full)
}

/// UPDATES' Y on a friend's offer (P6.49): the download approved, this
/// profile's raven-node woken, and the view read again.
pub(super) fn approve_download(data_dir: &Path, digest: &[u8; 32]) -> UpdateView {
    super::super::update_install::approve_from_app(data_dir, digest)
}

/// UPDATES' install of the build `serial` once its word was typed: the
/// programs swapped with this profile's node stopped around it (the app's
/// own node, `started_by_app`, may be ended on Windows), started again and
/// checked; the old programs back when it doesn't answer. With the node it
/// started from this app, which is the app's own now.
pub(super) fn install_update(
    data_dir: &Path,
    serial: u64,
    started_by_app: Option<u32>,
) -> (Result<Vec<String>, String>, Option<u32>) {
    super::super::update_install::install_from_app(data_dir, serial, started_by_app)
}

// ── The read markers and the name (privacy pack PP.24) ──────────────────────

/// Where a sealed profile keeps the app's read markers and the user's own
/// name (state_file.rs's `TuiPrivate`): raven-core's registered at-rest file
/// of kind 10 (RMS1 under the profile's at-rest keys), written under its own
/// writer lock (`.at_rest.tui_private.lock.sqlite`).
pub(super) const TUI_PRIVATE_FILE: &str = "tui_private.rms";

/// What [`load_tui_private`] read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum TuiPrivateRead {
    /// No such file.
    Missing,
    Loaded(TuiPrivate),
    /// It is there, but can't be opened or parsed now (why): the at-rest key
    /// is not loaded in this process (the keystore did not give it), a byte
    /// changed, another profile's file, not a regular file.
    Unreadable(String),
}

/// Whether this profile is sealed (raven-core's `privacy::mode`; a
/// `privacy.json` it can't read counts as sealed): the read markers and the
/// name are saved to [`TUI_PRIVATE_FILE`] then, never to tui_state.json.
pub(super) fn tui_private_sealed(data_dir: &Path) -> bool {
    raven_core::privacy::mode(data_dir) == raven_core::at_rest::Mode::Sealed
}

/// [`TUI_PRIVATE_FILE`] read (raven-core's `at_rest::load_json`): RMS1
/// opened with the keys this process loaded at its start (no keystore call),
/// or plain JSON as `raven privacy unseal` writes it back.
pub(super) fn load_tui_private(data_dir: &Path) -> TuiPrivateRead {
    let path = data_dir.join(TUI_PRIVATE_FILE);
    match std::fs::metadata(&path) {
        Ok(meta) if meta.is_file() => {}
        // A FIFO or a device here would block the read.
        Ok(_) => return TuiPrivateRead::Unreadable("not a regular file".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return TuiPrivateRead::Missing,
        Err(e) => return TuiPrivateRead::Unreadable(sanitize_terminal_line(&e.to_string())),
    }
    match raven_core::at_rest::load_json(data_dir, &path, raven_core::at_rest::Kind::TuiPrivate) {
        Ok(Some(private)) => TuiPrivateRead::Loaded(private),
        Ok(None) => TuiPrivateRead::Missing,
        Err(e) => TuiPrivateRead::Unreadable(sanitize_terminal_line(&e.to_string())),
    }
}

/// Writes [`TUI_PRIVATE_FILE`] (raven-core's `at_rest::store_json`, under
/// its writer lock): RMS1 in a sealed profile, with the keys this process
/// loaded; with none loaded it fails, never falling back to plaintext.
pub(super) fn store_tui_private(data_dir: &Path, private: &TuiPrivate) -> Result<(), String> {
    let path = data_dir.join(TUI_PRIVATE_FILE);
    raven_core::at_rest::store_json(
        data_dir,
        &path,
        raven_core::at_rest::Kind::TuiPrivate,
        private,
    )
    .map_err(|e| sanitize_terminal_line(&e.to_string()))
}

/// Whether this process holds the profile's at-rest keys (raven-core's
/// `at_rest::keys_cached`: the top of the command or the app's start loaded
/// them). Asks no keystore.
pub(super) fn at_rest_keys_loaded(data_dir: &Path) -> bool {
    raven_core::at_rest::keys_cached(data_dir).is_ok()
}

/// A sealed profile's [`TUI_PRIVATE_FILE`] in plain (`raven privacy unseal`
/// wrote it back so, and the migration after `raven privacy seal-now` seals
/// only its own files) is sealed in place: raven-core's
/// `at_rest::migrate_file`, under its writer lock, with the keys this
/// process loaded (review D-lock-tui-1). Whether it was; nothing in a
/// profile that is not sealed, or when there is no plain one (no lock
/// taken then).
pub(super) fn seal_tui_private_in_place(data_dir: &Path) -> Result<bool, String> {
    use raven_core::at_rest::{self, Kind, Migrated};
    if !tui_private_sealed(data_dir) || !tui_private_in_plain(data_dir) {
        return Ok(false);
    }
    let path = data_dir.join(TUI_PRIVATE_FILE);
    match at_rest::migrate_file(data_dir, &path, Kind::TuiPrivate) {
        Ok(Migrated::Sealed) => Ok(true),
        Ok(Migrated::AlreadySealed | Migrated::Missing) => Ok(false),
        Err(e) => Err(sanitize_terminal_line(&e.to_string())),
    }
}

/// [`TUI_PRIVATE_FILE`] is there and not sealed (its first bytes are not
/// RMS1 of kind 10). Reads only, and only a regular file (a FIFO or a
/// device would block the read).
pub(super) fn tui_private_in_plain(data_dir: &Path) -> bool {
    use std::io::Read;
    let path = data_dir.join(TUI_PRIVATE_FILE);
    if !std::fs::metadata(&path).is_ok_and(|meta| meta.is_file()) {
        return false;
    }
    let Ok(file) = std::fs::File::open(path) else {
        return false;
    };
    let mut head = Vec::new();
    if file.take(64).read_to_end(&mut head).is_err() {
        return false;
    }
    !raven_core::at_rest::is_sealed_as(raven_core::at_rest::Kind::TuiPrivate, &head)
}

/// Deletes [`TUI_PRIVATE_FILE`] under its writer lock, when there is one
/// (a profile that is not sealed keeps both in tui_state.json); none: no
/// lock taken, nothing written.
pub(super) fn remove_tui_private(data_dir: &Path) -> Result<(), String> {
    let path = data_dir.join(TUI_PRIVATE_FILE);
    if std::fs::symlink_metadata(&path).is_err() {
        return Ok(());
    }
    let _lock =
        raven_core::at_rest::lock_file(data_dir, &path, raven_core::at_rest::Kind::TuiPrivate)
            .map_err(|e| sanitize_terminal_line(&e.to_string()))?;
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(sanitize_terminal_line(&e.to_string())),
    }
}

// ── What this build lets on ─────────────────────────────────────────────────

/// One gate as this process has it: its `*_PRODUCTION_ENABLED` constant, and
/// its live function (the constant, or a debug build's lab switch
/// `RAVEN_LAB_TEST_A=1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Gate {
    pub(super) production: bool,
    pub(super) live: bool,
}

/// The gates of the ways to reach friends (raven-core's lan_gate.rs,
/// internet_gate.rs, p2p_gate.rs and custody_gate.rs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Gates {
    pub(super) lan: Gate,
    pub(super) internet: Gate,
    pub(super) p2p: Gate,
    /// Friends holding mail (friend custody).
    pub(super) custody: Gate,
    /// Bluetooth nearby (Phase 5).
    pub(super) nearby: Gate,
}

/// The gates, read now: constants and the environment only. Read-only:
/// nothing here turns one on.
pub(super) fn gates_now() -> Gates {
    use raven_core::custody_gate::{CustodyGates, FRIEND_CUSTODY_PRODUCTION_ENABLED};
    Gates {
        lan: Gate {
            production: raven_core::LAN_DIRECT_PRODUCTION_ENABLED,
            live: raven_core::lan_direct_live_enabled(),
        },
        internet: Gate {
            production: raven_core::INTERNET_DIRECT_PRODUCTION_ENABLED,
            live: raven_core::internet_direct_live_enabled(),
        },
        p2p: Gate {
            production: raven_core::P2P_PRODUCTION_ENABLED,
            live: raven_core::p2p_live_enabled(),
        },
        custody: Gate {
            production: FRIEND_CUSTODY_PRODUCTION_ENABLED,
            live: CustodyGates::current().live,
        },
        nearby: Gate {
            production: raven_core::NEARBY_PRODUCTION_ENABLED,
            live: raven_core::nearby_live_enabled(),
        },
    }
}

// ── Security notices (Phase 6b P6.31) ───────────────────────────────────────

// security_text.rs: the one English table of the notices' words, which the
// CLI reads too; the older-method question's words.
pub(super) use super::super::security_text::{
    floor_accepted, floor_intro, floor_kept, floor_question, notices_line, resolved_by_verify,
    strangers_line, Act as SecAct, NOT_IN_THIS_VERSION, NOT_KEPT_UNSEALED,
};
// A notice's words, for the render tests' notices.
#[cfg(test)]
pub(super) use super::super::security_text::NoticeText;
// One open notice and whether this profile keeps them, as security_cli.rs
// reads the ledger for the app.
pub(super) use super::super::security_cli::{AppNotice as SecNotice, Kept as SecKept};

/// What the app reads of the security notices, and the friends sending is
/// paused to: on the store worker, every minute and after a change.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct SecurityView {
    pub(super) kept: SecKept,
    /// The open alerts and warnings, the most severe and the latest first.
    pub(super) notices: Vec<SecNotice>,
    /// How many smaller notices are only counted.
    pub(super) counted: usize,
    /// Per friend, by key in lower case: the events the last 7 days counted.
    pub(super) week: Vec<(String, u64)>,
    /// The friends sending is paused to (`node_policy` `send_hold`), by key
    /// in lower case: read whatever the gates, so a pause can always be seen
    /// and lifted.
    pub(super) paused: Vec<String>,
    /// Why the ledger can't be read (raven-core's words), if it can't.
    pub(super) unreadable: Option<String>,
    /// Security notices from the Raven project (Phase 6 P6.45): what the
    /// applied one refuses, turns off and warns about, one line each
    /// (raven-core's words, notice text sanitized); none while that gate
    /// is shut.
    pub(super) updates: Vec<String>,
}

/// The notices (the ledger is never created by a read) and the paused
/// friends (none from a policy that can't be read: raven-node then holds
/// nobody either).
pub(super) fn security_view(data_dir: &Path) -> SecurityView {
    let updates = raven_core::suite_policy::status_lines(data_dir, raven_core::clock::now_ms());
    let paused = raven_core::node_policy::try_load_policy(data_dir)
        .map(|policy| {
            policy
                .send_hold
                .iter()
                .map(|held| held.trim().to_ascii_lowercase())
                .collect()
        })
        .unwrap_or_default();
    match super::super::security_cli::app_read(data_dir) {
        Ok(read) => SecurityView {
            kept: read.kept,
            notices: read.notices,
            counted: read.counted,
            week: read.week,
            paused,
            unreadable: None,
            updates,
        },
        Err(why) => SecurityView {
            kept: SecKept::Live,
            paused,
            unreadable: Some(why),
            updates,
            ..SecurityView::default()
        },
    }
}

/// R on SEC: the person is done with notice `id` (what Raven did about it
/// stays). `Ok(false)`: it was not open any more.
pub(super) fn resolve_notice(data_dir: &Path, id: i64) -> Result<bool, String> {
    super::super::security_cli::app_resolve(data_dir, id)
}

/// P: pause (`on`) or resume sending to the friend `pub_hex`
/// (`node_policy` `send_hold`, read by raven-node's outbox worker). After a
/// resume the running raven-node is asked to try their waiting messages now
/// (best effort: without it they go at their next retry). Whether sending
/// is paused now.
pub(super) fn set_send_hold(data_dir: &Path, pub_hex: &str, on: bool) -> Result<bool, String> {
    let key = super::super::parse_pub_hex(pub_hex)?;
    let held = raven_core::node_policy::set_send_hold(data_dir, &key, on)
        .map_err(|e| sanitize_terminal_line(&e.to_string()))?;
    if !held {
        let kick = IpcRequest::OutboxKick {
            v: raven_core::ipc::IPC_VERSION,
            peer_pub_hex: Some(hex::encode(key)),
            retry: false,
            custody_now: false,
        };
        let _ = ipc_request_timeout(data_dir, &kick, Duration::from_millis(1500));
    }
    Ok(held)
}

/// What a match in VF changed for the friend's notices.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct Resolved {
    /// The open notices about the friend the match resolved.
    pub(super) notices: usize,
    /// The friend's Raven offered an older security method than before (an
    /// open downgrade in their capability floor, or a downgrade alert the
    /// match resolved) and the security words matched: the older method may
    /// be accepted now, once `accept` is typed.
    pub(super) older_method: bool,
}

/// After a match in VF (`typed`: the words, or the old code), as `raven
/// contact verify` does it: every open notice about the friend is resolved
/// (`SecurityLedger::resolve_contact`), and whether the older method may be
/// accepted is read. Nothing while no ledger is kept.
pub(super) fn resolve_on_match(
    data_dir: &Path,
    pub_hex: &str,
    typed: &str,
) -> Result<Resolved, String> {
    use raven_core::capability_floor::{self, CodeMatch};
    let key = super::super::parse_pub_hex(pub_hex)?;
    let verified = super::super::security_cli::resolve_on_match(data_dir, &key)?;
    let older_method = capability_floor::floor(data_dir, &key)
        .is_some_and(|floor| floor.open_downgrade() || verified.floor_alert)
        && CodeMatch::check(typed, &key).is_some();
    Ok(Resolved {
        notices: verified.resolved,
        older_method,
    })
}

/// "Accept the older method", after the person typed `accept` (design A
/// R9): the friend's capability floor starts afresh. Only with their
/// security words (`typed`; the token is made from them again, the old code
/// is not enough). `Ok(false)`: the friend had no floor.
pub(super) fn accept_older_method(
    data_dir: &Path,
    pub_hex: &str,
    typed: &str,
) -> Result<bool, String> {
    use raven_core::capability_floor::{self, CodeMatch};
    let key = super::super::parse_pub_hex(pub_hex)?;
    let matched = CodeMatch::check(typed, &key)
        .ok_or_else(|| "the security words did not match".to_owned())?;
    capability_floor::lower_floor(data_dir, &matched, now_ms())
}

/// raven-node's security counts (IPC `Status.security`, present only while
/// the security events gate is live there), as NET shows them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SecurityCounts {
    /// Strangers refused in the last hour.
    pub(super) strangers_1h: u32,
    /// Network sources banned now.
    pub(super) bans: u16,
    /// Alerts open in the ledger.
    pub(super) alerts_open: u16,
}

/// What a running node's Status says of security; None when no node
/// answers, or it says nothing (an older one, or its gate is shut).
pub(super) fn security_counts(status: &Result<IpcResponse, String>) -> Option<SecurityCounts> {
    match status {
        Ok(IpcResponse::Status {
            security: Some(security),
            ..
        }) => Some(SecurityCounts {
            strangers_1h: security.strangers_refused_1h,
            bans: security.bans_active,
            alerts_open: security.alerts_open,
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::super::testkit::{self, digits_from, ARABIC_INDIC_ZERO, PERSIAN_ZERO};
    use super::*;

    /// P6.31, through the profile: "Check again" offers the older method
    /// only for a floor with an open downgrade and only with the security
    /// words, and accepting it lowers that floor (the old code never does);
    /// "Pause sending" round trips through node_policy and reads back as
    /// paused, in lower case.
    #[test]
    fn check_again_and_pause_sending_go_through_the_profile() {
        use raven_core::capability_floor::{floor, Floor, CAPABILITY_FLOOR_FILE};
        let dir = tempfile::tempdir().expect("tempdir");
        let dd = dir.path();
        let key = Identity::from_seed(&[0x5a; 32]).public_key_bytes();
        let pub_hex = hex::encode(key);
        let words = key_words(&key).join(" ");
        let code = fingerprint_of(&pub_hex).expect("a key");
        assert_eq!(
            resolve_on_match(dd, &pub_hex, &words),
            Ok(Resolved::default()),
            "no ledger, no floor: nothing"
        );
        let open = Floor {
            refused_profile: Some(1),
            ..Floor::new(1)
        };
        std::fs::write(
            dd.join(CAPABILITY_FLOOR_FILE),
            serde_json::json!({ "floors": { pub_hex.clone(): open } }).to_string(),
        )
        .expect("floor file");
        assert!(
            !resolve_on_match(dd, &pub_hex, &code)
                .expect("read")
                .older_method,
            "the old code is not enough"
        );
        assert!(
            resolve_on_match(dd, &pub_hex, &words)
                .expect("read")
                .older_method
        );
        assert!(accept_older_method(dd, &pub_hex, &code).is_err());
        assert!(floor(dd, &key).expect("floor").open_downgrade());
        assert_eq!(accept_older_method(dd, &pub_hex, &words), Ok(true));
        assert!(!floor(dd, &key).expect("floor").open_downgrade());
        assert!(
            !resolve_on_match(dd, &pub_hex, &words)
                .expect("read")
                .older_method
        );
        // Pause sending, and back.
        assert!(security_view(dd).paused.is_empty());
        assert_eq!(set_send_hold(dd, &pub_hex.to_uppercase(), true), Ok(true));
        assert_eq!(security_view(dd).paused, vec![pub_hex.clone()]);
        assert!(raven_core::node_policy::load_policy(dd).send_held(&key));
        assert_eq!(set_send_hold(dd, &pub_hex, false), Ok(false));
        assert!(security_view(dd).paused.is_empty());
        assert!(set_send_hold(dd, "not a key", true).is_err());
    }

    #[test]
    fn an_unreadable_identity_store_is_unavailable() {
        // A data folder that is a file: the identity lock cannot be taken, so
        // this fails before any key store is asked.
        let dir = tempfile::tempdir().expect("tempdir");
        let not_a_dir = dir.path().join("profile");
        std::fs::write(&not_a_dir, b"not a folder").expect("write");
        match load_identity(&not_a_dir) {
            IdentityLoad::Unavailable(reason) => assert!(!reason.is_empty()),
            IdentityLoad::Missing => panic!("an unreadable store is not a missing identity"),
            IdentityLoad::Ready(id) => panic!("loaded {} from a file", id.address()),
        }
    }

    #[test]
    fn views_carry_the_public_parts_only() {
        let id = Identity::from_seed(&[0x31; 32]);
        let me = me_view(&id);
        assert_eq!(me.pub_hex, hex::encode(id.public_key_bytes()));
        assert_eq!(me.address, id.address());
        assert_eq!(fingerprint_of(&me.pub_hex), Some(me.fingerprint.clone()));
        assert_eq!(fingerprint_of("not a key"), None);
        // The invite and a card both parse back to the same key.
        let from_invite = parse_raven_invite(&me.invite)
            .expect("an invite line")
            .expect("a valid invite");
        assert_eq!(
            (from_invite.address.as_str(), from_invite.pub_hex.as_str()),
            (me.address.as_str(), me.pub_hex.as_str())
        );
        assert_eq!(from_invite.fingerprint, me.fingerprint);
        // The security words are the key's own (raven-core's), and a pasted
        // invite or card carries the same ones.
        assert_eq!(
            *me.words,
            security_words::words_v1(&id.public_key_bytes()).map(String::from)
        );
        assert_eq!(from_invite.words, me.words);
        let p2p = P2pView {
            peer_id: raven_core::p2p_route::local_peer_id(&id),
            via: Vec::new(),
            next: None,
        };
        let card = format_card_with(&id, "", "192.168.1.20:7420", Some(&p2p)).unwrap();
        let back = parse_card_or_invite(&card).unwrap();
        assert_eq!(back.pub_hex, me.pub_hex);
        assert_eq!(back.words, me.words);
        assert_eq!(back.lan, "192.168.1.20:7420");
        assert_eq!(back.p2p, Some(p2p));
        let seed_hex = hex::encode([0x31u8; 32]);
        for text in [&me.invite, &card] {
            assert!(!text.contains(&seed_hex), "{text}");
        }
        // A route that is not one is refused before cli.rs sees it.
        let bad = P2pView {
            peer_id: "not-a-peer-id".into(),
            via: Vec::new(),
            next: None,
        };
        assert!(format_card_with(&id, "", "", Some(&bad)).is_err());
    }

    #[test]
    fn deadlines_are_words_that_read_after_until() {
        const MIN: u64 = 60_000;
        let now = 1_760_000_000_000;
        for (left, short, long) in [
            (0, "less than a minute", "less than a minute"),
            (59_999, "less than a minute", "less than a minute"),
            (MIN, "about 1 min", "about a minute"),
            (45 * MIN, "about 45 min", "about 45 minutes"),
            (90 * MIN, "about 90 min", "about 90 minutes"),
            (119 * MIN, "about 119 min", "about 119 minutes"),
            (120 * MIN, "about 2 h", "about 2 hours"),
            (149 * MIN, "about 2 h", "about 2 hours"),
            (150 * MIN, "about 3 h", "about 3 hours"),
            (22 * 60 * MIN, "about 22 h", "about 22 hours"),
        ] {
            let d = deadline_text(now + left, now);
            assert_eq!(d.short, format!("{short} from now"), "{left}");
            assert_eq!(d.long, format!("{long} from now"), "{left}");
            assert_eq!((d.hh_mm.as_deref(), d.left_ms), (None, left));
        }
        // Run out: nothing left, and never a time in the past.
        let gone = deadline_text(now - MIN, now);
        assert_eq!(gone.left_ms, 0);
        assert_eq!(gone.long, "less than a minute from now");
    }

    #[test]
    fn deadlines_name_this_computers_clock_time_when_it_is_known() {
        const MIN: u64 = 60_000;
        const HOUR: u64 = 60 * MIN;
        // 2026-10-20 (a Tuesday) 10:35 UTC: 14:05 in Tehran (UTC+3:30).
        let at = 1_792_492_500_000;
        let tehran = |now: u64| with_local_offset(Some(12_600), || deadline_text(at, now));
        let d = tehran(at - 3 * HOUR);
        assert_eq!(d.short, "today 14:05");
        assert_eq!(d.long, "today at 14:05 (about 3 hours from now)");
        assert_eq!((d.hh_mm.as_deref(), d.left_ms), (Some("14:05"), 3 * HOUR));
        let d = tehran(at - 19 * HOUR);
        assert_eq!(d.short, "tomorrow 14:05");
        assert_eq!(d.long, "tomorrow at 14:05 (about 19 hours from now)");
        assert_eq!(tehran(at - 50 * HOUR).short, "Tue 14:05");
        assert_eq!(tehran(at - 7 * 24 * HOUR).short, "Tue 20 Oct 14:05");
        // The offset stays with the test that set it: unknown again here.
        assert_eq!(deadline_text(at, at - 3 * HOUR).hh_mm, None);
        // Never another clock's time.
        for off in [Some(12_600), Some(-18_000), Some(0), None] {
            for left in [0, 45 * MIN, 3 * HOUR, 22 * HOUR, 9 * 24 * HOUR] {
                let d = with_local_offset(off, || deadline_text(at, at - left));
                assert!(!d.short.contains("UTC") && !d.long.contains("UTC"), "{d:?}");
            }
        }
    }

    /// Review C-time-deadlines-3: the night the clocks go back (Berlin, CEST
    /// +2 h to CET +1 h), at 00:30 CEST a deadline at 10:00 CET is today.
    #[test]
    fn a_deadline_after_a_daylight_saving_change_keeps_the_wall_calendar() {
        let now = 1_792_881_000_000; // 2026-10-24 22:30 UTC
        let at = 1_792_918_800_000; // 2026-10-25 09:00 UTC
        let d = deadline_text_with(at, now, Some(3_600), Some(7_200));
        assert_eq!(d.short, "today 10:00");
        assert_eq!(d.long, "today at 10:00 (about 11 hours from now)");
    }

    // ── Security words ──────────────────────────────────────────────────────

    /// Alice's words in shared-vectors/rvn1/security_words/words_alice_001.json.
    const ALICE_WORDS: &str = "turtle frog bread wolf paper laptop funnel mango honey wagon";

    /// Alice of the vectors: RFC 8032's first key, whose code is [`FP`].
    fn alice() -> MeView {
        let seed = hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
            .expect("hex");
        me_view(&Identity::from_seed(
            &seed.try_into().expect("a 32-byte seed"),
        ))
    }

    #[test]
    fn my_words_are_the_vectors() {
        let alice = alice();
        assert_eq!(
            alice.pub_hex,
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        assert_eq!(alice.fingerprint, FP);
        assert_eq!(alice.words.join(" "), ALICE_WORDS);
        assert_eq!(alice.words.len(), WORDS);
    }

    #[test]
    fn security_check_takes_words_or_the_old_code() {
        use security_words::ParseError;
        let alice = alice();
        let check = |typed: &str| security_check(typed, &alice.pub_hex);
        // Her words: as read, in capitals, by 3-letter starts, numbered.
        assert_eq!(check(ALICE_WORDS), SecurityCheck::Match);
        assert_eq!(check(&ALICE_WORDS.to_uppercase()), SecurityCheck::Match);
        assert_eq!(
            check("tur fro bre wol pap lap fun man hon wag"),
            SecurityCheck::Match
        );
        assert_eq!(
            check(
                "1. turtle 2. frog 3. bread 4. wolf 5. paper 6. laptop 7. funnel 8. mango \
                 9. honey 10. wagon"
            ),
            SecurityCheck::Match
        );
        // Her old code, as before: separators ignored, case not, Persian and
        // Arabic-Indic digits read as 0-9.
        assert_eq!(check("If4x 36FU omFi"), SecurityCheck::Match);
        for zero in [PERSIAN_ZERO, ARABIC_INDIC_ZERO] {
            assert_eq!(check(&digits_from(FP, zero)), SecurityCheck::Match);
        }
        assert_eq!(check("if4x-36fu-omfi"), SecurityCheck::CodeCaseOnly);
        assert_eq!(check("If4x-36FU-omFj"), SecurityCheck::Mismatch);
        // Bob's words are real words, but not hers; and his code is not hers.
        let bob = me_view(&Identity::from_seed(&[0xB0; 32]));
        assert_eq!(check(&bob.words.join(" ")), SecurityCheck::Mismatch);
        assert_eq!(check(&bob.fingerprint), SecurityCheck::Mismatch);
        // What is wrong with an entry depends on what was typed alone.
        let words: Vec<&str> = ALICE_WORDS.split(' ').collect();
        let with = |at: usize, word: &str| {
            let mut changed = words.clone();
            changed[at] = word;
            changed.join(" ")
        };
        for (typed, status) in [
            (with(0, "turtel"), ParseError::Unknown { position: 1 }),
            (with(1, "fr"), ParseError::Ambiguous { position: 2 }),
            (
                with(2, "\u{0646}\u{0627}\u{0646}"),
                ParseError::NonLatin { position: 3 },
            ),
            (words[..9].join(" "), ParseError::WrongCount { count: 9 }),
            (
                format!("{ALICE_WORDS} wagon"),
                ParseError::WrongCount { count: 11 },
            ),
            (
                format!("frog turtle {}", words[2..].join(" ")),
                ParseError::BadCheck,
            ),
        ] {
            assert_eq!(check(&typed), SecurityCheck::Invalid(status), "{typed}");
            assert_eq!(
                security_check(&typed, &bob.pub_hex),
                SecurityCheck::Invalid(status),
                "{typed}"
            );
        }
        // A key that does not parse matches nothing.
        assert_eq!(
            security_check(ALICE_WORDS, "not a key"),
            SecurityCheck::Mismatch
        );
        assert_eq!(
            security_check("\u{2014}", "not a key"),
            SecurityCheck::Mismatch
        );
    }

    // ── Codes typed with a Persian keyboard ─────────────────────────────────

    const FP: &str = "If4x-36FU-omFi";

    #[test]
    fn persian_and_arabic_indic_digits_read_as_0_to_9() {
        for zero in [PERSIAN_ZERO, ARABIC_INDIC_ZERO] {
            let digits = digits_from("0123456789", zero);
            assert_eq!(digits.chars().count(), 10);
            assert_eq!(fold_code_digits(&digits), "0123456789");
        }
        // Nothing else changes: Latin and Arabic-script letters, separators,
        // and digits of other scripts or styles (full-width, Devanagari,
        // superscript, circled). Folding twice changes nothing.
        let other = "If4x-36FU \u{0645}\u{06CC}\u{FF11}\u{0967}\u{00B2}\u{2460}";
        assert_eq!(fold_code_digits(other), other);
        let once = fold_code_digits(&digits_from(other, PERSIAN_ZERO));
        assert_eq!(once, other);
        assert_eq!(fold_code_digits(&once), once);
    }

    #[test]
    fn persian_digits_match_the_code() {
        let typed = digits_from(FP, PERSIAN_ZERO);
        assert_ne!(typed, FP);
        assert!(fingerprint_matches(&typed, FP));
        assert!(fingerprint_matches(&typed.replace('-', " "), FP));
        assert!(!fingerprint_case_only_mismatch(&typed, FP));
        // Some digits one way, some the other.
        assert!(fingerprint_matches("If\u{06F4}x-3\u{0666}FU-omFi", FP));
        // The confirmation code too.
        assert!(confirm_code_matches(
            &digits_from("7k3qm", PERSIAN_ZERO),
            "7K3QM"
        ));
    }

    #[test]
    fn arabic_indic_digits_match() {
        let typed = digits_from(FP, ARABIC_INDIC_ZERO);
        assert_ne!(typed, FP);
        assert!(fingerprint_matches(&typed, FP));
        assert!(confirm_code_matches(
            &digits_from("7K 3QM", ARABIC_INDIC_ZERO),
            "7K3QM"
        ));
    }

    #[test]
    fn case_still_matters_after_folding() {
        for zero in [PERSIAN_ZERO, ARABIC_INDIC_ZERO] {
            let wrong_case = digits_from("if4x-36fu-omfi", zero);
            assert!(!fingerprint_matches(&wrong_case, FP));
            assert!(fingerprint_case_only_mismatch(&wrong_case, FP));
            // A wrong digit is no case mistake.
            let wrong_digit = digits_from("if5x-36fu-omfi", zero);
            assert!(!fingerprint_case_only_mismatch(&wrong_digit, FP));
        }
        // The confirmation code still ignores case (its letters are all
        // capitals).
        assert!(confirm_code_matches(
            &digits_from("7k3qm", ARABIC_INDIC_ZERO),
            "7K3QM"
        ));
    }

    #[test]
    fn fold_never_turns_a_mismatch_into_a_match() {
        // Each character of a code changed to each character a keyboard or a
        // paste could give there: it matches only when it is the same
        // character, or a Persian or Arabic-Indic digit of the same value.
        // Other scripts' digits, look-alikes and Arabic-script letters
        // never do.
        let mut candidates: Vec<char> = ('0'..='9').chain('a'..='z').chain('A'..='Z').collect();
        for zero in [PERSIAN_ZERO, ARABIC_INDIC_ZERO] {
            candidates.extend(digits_from("0123456789", zero).chars());
        }
        candidates.extend([
            '\u{FF10}', '\u{FF14}', '\u{0966}', '\u{096A}', '\u{00B2}', '\u{2074}', '\u{2463}',
            '\u{0647}', '\u{0627}', '\u{06CC}', '\u{06D5}', '\u{0665}', '\u{06F5}', '-', ' ',
        ]);
        let read_as = |c: char| fold_code_digits(&c.to_string());
        let changed = |code: &str, at: usize, c: char| -> String {
            code.chars()
                .enumerate()
                .map(|(i, was)| if i == at { c } else { was })
                .collect()
        };
        for fp in [FP, "M026-RjXE-NoLA", "0123-4567-89aB"] {
            for (at, want) in fp.chars().enumerate().filter(|(_, c)| *c != '-') {
                for &c in &candidates {
                    let typed = changed(fp, at, c);
                    assert_eq!(
                        fingerprint_matches(&typed, fp),
                        read_as(c) == want.to_string(),
                        "{typed:?} against {fp}"
                    );
                }
            }
        }
        // The confirmation code alike, its case aside.
        let code = "27K3Q";
        for (at, want) in code.chars().enumerate() {
            for &c in &candidates {
                let typed = changed(code, at, c);
                assert_eq!(
                    confirm_code_matches(&typed, code),
                    read_as(c).to_ascii_uppercase() == want.to_string(),
                    "{typed:?} against {code}"
                );
            }
        }
    }

    #[test]
    fn only_arabic_script_letters_ask_for_another_keyboard() {
        // What a Persian keyboard's letter keys type, then each block's
        // edges: the folded digits are no letters, and the blocks around
        // them (Hebrew, Syriac, Thaana, Devanagari, Hebrew presentation
        // forms, variation selectors, small and full-width forms) are not
        // Arabic.
        for c in testkit::on_persian_keyboard("abcdefghijklmnopqrstuvwxyz").chars() {
            assert!(code_has_non_latin_letters(&c.to_string()), "{c:?}");
        }
        for (c, letter) in [
            ('\u{05FF}', false),
            ('\u{0600}', true),
            ('\u{060C}', true),
            ('\u{065F}', true),
            ('\u{0660}', false),
            ('\u{0669}', false),
            ('\u{066A}', true),
            ('\u{06EF}', true),
            ('\u{06F0}', false),
            ('\u{06F9}', false),
            ('\u{06FA}', true),
            ('\u{06FF}', true),
            ('\u{0700}', false),
            ('\u{074F}', false),
            ('\u{0750}', true),
            ('\u{077F}', true),
            ('\u{0780}', false),
            ('\u{089F}', false),
            ('\u{08A0}', true),
            ('\u{08FF}', true),
            ('\u{0900}', false),
            ('\u{FB4F}', false),
            ('\u{FB50}', true),
            ('\u{FDFF}', true),
            ('\u{FE00}', false),
            ('\u{FE6F}', false),
            ('\u{FE70}', true),
            ('\u{FEFF}', true),
            ('\u{FF00}', false),
        ] {
            assert_eq!(
                code_has_non_latin_letters(&format!("If4x{c}")),
                letter,
                "U+{:04X}",
                u32::from(c)
            );
        }
        for text in [
            "",
            FP,
            "If4x 36FU omFi",
            "caf\u{e9}",
            "\u{0436}\u{03B1}\u{4E2D}",
            &digits_from("0123456789", PERSIAN_ZERO),
            &digits_from("0123456789", ARABIC_INDIC_ZERO),
        ] {
            assert!(!code_has_non_latin_letters(text), "{text:?}");
        }
    }

    #[test]
    fn a_code_in_persian_digits_pins_through_the_cli() {
        // cli.rs checks the typed code again before it pins: it gets it
        // folded.
        testkit::lab_backends();
        let bob = me_view(&Identity::from_seed(&[0xB0; 32]));
        let save = |dir: &Path, typed: &str| {
            add_contact_with_routes(
                dir,
                &bob.address,
                &bob.pub_hex,
                "Bob",
                "",
                Some(typed),
                "",
                "",
                None,
            )
        };
        let saved = |dir: &Path| -> Vec<(String, bool)> {
            contact_views(dir)
                .expect("contacts")
                .into_iter()
                .map(|c| (c.pub_hex, c.pinned))
                .collect()
        };
        // Bob's code with one digit changed.
        let at = bob
            .fingerprint
            .find(|c: char| c.is_ascii_digit())
            .expect("a digit in Bob's code");
        let digit = bob.fingerprint.as_bytes()[at] - b'0';
        let mut wrong = bob.fingerprint.clone();
        wrong.replace_range(at..=at, &((digit + 1) % 10).to_string());
        for zero in [PERSIAN_ZERO, ARABIC_INDIC_ZERO] {
            let dir = testkit::short_dir();
            // A wrong digit, written the same way, pins nothing.
            assert!(save(dir.path(), &digits_from(&wrong, zero)).is_err());
            assert!(saved(dir.path()).is_empty());
            save(dir.path(), &digits_from(&bob.fingerprint, zero)).expect("pinned");
            assert_eq!(saved(dir.path()), [(bob.pub_hex.clone(), true)]);
        }
    }

    #[test]
    fn a_friend_send_is_planned_as_raven_send_contact_plans_it() {
        // What cli.rs's `resolve_send_target` plans for `--contact` (its own
        // test `a_send_records_no_learned_lan_route`): the saved LAN route,
        // then where the friend last reached us from, left out of the outbox
        // and saved over the old address once it worked; hide my IP refuses
        // a friend with only an Internet address with cli.rs's text.
        testkit::lab_backends();
        let bob = me_view(&Identity::from_seed(&[0xB0; 32]));
        let dir = testkit::short_dir();
        let save = |lan: &str, internet: &str| {
            add_contact_with_routes(
                dir.path(),
                &bob.address,
                &bob.pub_hex,
                "Bob",
                "",
                Some(&bob.fingerprint),
                lan,
                internet,
                None,
            )
            .expect("Bob saved")
        };
        let bob_row = || {
            load_contacts(dir.path())
                .expect("contacts")
                .into_iter()
                .find(|c| c.pub_hex == bob.pub_hex)
                .expect("Bob's row")
        };
        // Without the nearby route `auto` plans last for a verified friend
        // once this build has nearby (debug RAVEN_LAB_TEST_A=1
        // RAVEN_LAB_NEARBY=1; cli.rs's tests check where it goes), so the LAN
        // plan reads the same with and without that switch.
        let plan = |friend: &Contact| {
            plan_friend_send(dir.path(), friend).map(|p| {
                let mut routes = p.routes;
                if raven_core::nearby_live_enabled() {
                    routes.retain(|r| r.carrier != DialCarrier::Nearby);
                }
                (routes, p.unrecorded, p.learned_lan_dials)
            })
        };
        let lan = |dial: &str| DialRoute {
            carrier: DialCarrier::Lan,
            dial: dial.into(),
        };
        save("192.168.1.30:7420", "");
        assert_eq!(
            plan(&bob_row()),
            Ok((vec![lan("192.168.1.30:7420")], Vec::new(), Vec::new()))
        );
        let key = super::super::super::parse_pub_hex_strict(&bob.pub_hex).expect("Bob's key");
        raven_core::lan_seen::record_contact_seen(
            dir.path(),
            &key,
            "192.168.1.33".parse().expect("an IP"),
            None,
            now_ms(),
        )
        .expect("seen");
        let learned = vec!["192.168.1.33:7420".to_string()];
        assert_eq!(
            plan(&bob_row()),
            Ok((
                vec![lan("192.168.1.30:7420"), lan("192.168.1.33:7420")],
                learned.clone(),
                learned,
            ))
        );
        // Only an Internet address, hidden from Bob: cli.rs's refusal.
        std::fs::remove_file(contacts_path(dir.path())).expect("book removed");
        save("", "203.0.113.9:7420");
        let mut hidden = bob_row();
        hidden.hide_ip = true;
        // With nearby, `auto` plans a verified friend it has nothing else for
        // over nearby alone instead of refusing (`with_nearby_route`).
        let nearby_only = || {
            Ok(vec![DialRoute {
                carrier: DialCarrier::Nearby,
                dial: raven_core::outbox::nearby_dial_for(&key),
            }])
        };
        if raven_core::nearby_live_enabled() {
            assert_eq!(
                plan_friend_send(dir.path(), &hidden).map(|p| p.routes),
                nearby_only()
            );
        } else {
            assert_eq!(
                plan(&hidden),
                Err(super::super::super::hidden_ip_text(&hidden))
            );
        }
        // No address saved (an invite line), seen and pinned (M0): cli.rs's
        // learned routes stand in for one (cutoff F7, by this run's gates).
        std::fs::remove_file(contacts_path(dir.path())).expect("book removed");
        save("", "");
        let pin_key = raven_core::lan_noise_pin::PinKey::derive(&raven_core::Identity::from_seed(
            &[0xC0; 32],
        ));
        raven_core::lan_noise_pin::record(dir.path(), &pin_key, &key, &[0x51; 32]).expect("pinned");
        let port = raven_core::lan_gate::lab_default_lan_port()
            .unwrap_or(raven_core::paths::DEFAULT_LAN_PORT);
        let guess = format!("192.168.1.33:{port}");
        assert_eq!(
            unsaved_lan_routes(dir.path(), &bob_row(), CarrierChoice::Auto, true),
            [guess.as_str()]
        );
        let hints = raven_core::route_hints::route_hints_live();
        if raven_core::outbox::default_port_guess_live() && !hints {
            assert_eq!(
                plan(&bob_row()),
                Ok((vec![lan(&guess)], vec![guess.clone()], vec![guess]))
            );
        } else if !hints && raven_core::nearby_live_enabled() {
            assert_eq!(
                plan_friend_send(dir.path(), &bob_row()).map(|p| p.routes),
                nearby_only()
            );
        } else if !hints {
            assert!(plan(&bob_row()).is_err_and(|e| e.contains("has no reachable lan_dial")));
        }
    }

    /// E1: a message delivered more than a minute after it was written says
    /// when it came, on this computer's clock (how long ago without it); one
    /// that went at once says nothing more.
    #[test]
    fn a_late_delivery_says_when_it_came() {
        let written = 1_792_492_500_000;
        let at = written + 2 * 3_600_000;
        let now = at + 5 * 60_000;
        with_local_offset(Some(0), || {
            assert_eq!(delivered_text(written + 30_000, written, now), None);
            assert_eq!(
                delivered_text(at, written, now).as_deref(),
                Some("today at 12:35 (UTC)")
            );
        });
        assert_eq!(
            delivered_text(at, written, now).as_deref(),
            Some("about 5 min ago")
        );
    }

    #[test]
    fn the_horizon_is_raven_cores_metadata_read() {
        // With the long message horizon off, raven-core reads it from the
        // session store's metadata alone (CP.6): a profile with no store has
        // no secure connection with anybody yet, so nothing can wait (a first
        // message goes only while both are online), and the read creates no
        // store. Not a key: not known.
        let dir = tempfile::tempdir().expect("tempdir");
        let before = horizon_reads();
        raven_core::horizon::set_lab_horizon_for_this_thread(Some(false));
        let off = [
            queue_horizon(dir.path(), &"ab".repeat(32), 1),
            queue_horizon(dir.path(), &"AB".repeat(32), 1),
            queue_horizon(dir.path(), "not a key", 1),
        ];
        // With the long message horizon live, the rule `raven contact list`
        // and the desktop apps use (E1: "until tomorrow" here, "up to 7 days"
        // in the app): 7 days from now, connection or not, so a first
        // message waits too.
        raven_core::horizon::set_lab_horizon_for_this_thread(Some(true));
        let live = queue_horizon(dir.path(), &"ab".repeat(32), 1);
        raven_core::horizon::set_lab_horizon_for_this_thread(None);
        let never = Some(QueueReach::NeverPaired);
        assert_eq!(off, [never, never, None]);
        assert_eq!(
            live,
            Some(QueueReach::CanWait {
                until_ms: raven_core::horizon::message_deadline(1)
            })
        );
        assert_eq!(horizon_reads(), before + 4);
        let entries: Vec<_> = std::fs::read_dir(dir.path()).expect("list").collect();
        assert!(entries.is_empty(), "{entries:?}");
    }

    #[test]
    fn the_network_state_is_raven_cores_interface_read() {
        // raven-core reads the interfaces on every system (CP.4): known, and
        // on a network exactly when there is an address a friend could dial.
        let addresses = lan_addresses_for_friends().expect("this host's interfaces");
        let all = netifs::read().expect("this host's interfaces");
        assert_eq!(on_any_network(None), Some(netifs::on_a_network(all)));
        // No virtual machine's network among them, so on one exactly when
        // one is listed.
        assert_eq!(on_any_network(None), Some(!addresses.is_empty()));
        // A friend seen lately never takes a network away.
        if !addresses.is_empty() {
            assert_eq!(on_any_network(Some(0)), Some(true));
            assert_eq!(on_any_network(Some(3)), Some(true));
        }
        for ip in &addresses {
            assert!(!ip.is_loopback() && !ip.is_unspecified(), "{ip}");
        }
        // IPv4 first.
        let first_v6 = addresses.iter().position(IpAddr::is_ipv6);
        assert!(
            first_v6.is_none_or(|at| addresses[at..].iter().all(IpAddr::is_ipv6)),
            "{addresses:?}"
        );
    }

    // ── Privacy (privacy pack PP.21) ────────────────────────────────────────

    /// A history row with `peer`, message `n`, `direction` ("in" or "out").
    fn row(peer: &str, n: u8, direction: &str) -> ChatHistoryEntry {
        ChatHistoryEntry {
            message_id_hex: format!("{n:02x}").repeat(16),
            direction: direction.into(),
            peer_petname: String::new(),
            peer_tag: String::new(),
            peer_pub_hex: peer.into(),
            created_at_ms: now_ms(),
            delivery: if direction == "out" {
                "delivered".into()
            } else {
                "received".into()
            },
            preview: "hi".into(),
            body: "hi".into(),
            stored_at_ms: None,
            id_conflict: false,
        }
    }

    #[test]
    fn chat_keeping_is_raven_cores_setting() {
        testkit::lab_backends();
        let dir = testkit::short_dir();
        let dd = dir.path();
        // No identity yet: not available, refused, and nothing written.
        assert_eq!(chat_keep(dd), Err(NotAvailable));
        assert!(set_chat_keep(dd, ChatKeepView::Days90).is_err());
        assert_eq!(privacy_notices(dd), PrivacyNotices::default());
        assert!(!dd.join(raven_core::privacy::PRIVACY_FILE).exists());
        // With one: 30 days until it is changed, then what `raven chats
        // keep` reads.
        load_or_create_identity(dd).expect("an identity");
        assert_eq!(chat_keep(dd), Ok(ChatKeepView::Days30));
        for keep in ChatKeepView::ALL {
            set_chat_keep(dd, keep).expect("saved");
            assert_eq!(chat_keep(dd), Ok(keep));
            assert_eq!(raven_core::privacy::chat_keep(dd), keep.core());
        }
        // A plain profile: no notice due, no free disk space waited for.
        assert_eq!(privacy_notices(dd), PrivacyNotices::default());
        assert_eq!(disk_space_needed(dd), None);
        assert!(disk_space_text(None).starts_with("Raven needs more free disk space"));
        assert_eq!(
            disk_space_text(Some(150 << 20)),
            raven_core::privacy::disk_space_text(150 << 20)
        );
    }

    #[test]
    fn a_sealed_profile_with_chats_has_both_notices_until_marked() {
        use raven_core::at_rest::MigratePolicy;
        testkit::lab_backends();
        let dir = testkit::short_dir();
        let dd = dir.path();
        load_or_create_identity(dd).expect("an identity");
        let bob = me_view(&Identity::from_seed(&[0xB0; 32]));
        ChatHistory::append_persisted(dd, row(&bob.pub_hex, 1, "in")).expect("a row");
        let now = now_ms();
        raven_core::privacy::migrate_all(dd, now, MigratePolicy::Allow).expect("sealed");
        let notices = privacy_notices(dd);
        assert!(notices.sealing, "{notices:?}");
        let first = notices.retention_from.expect("the retention notice");
        assert!(first > now, "a grace before the first deletion");
        // Reading takes nothing.
        assert_eq!(privacy_notices(dd), notices);
        mark_notice_shown(dd, Notice::Sealing);
        assert_eq!(
            privacy_notices(dd),
            PrivacyNotices {
                sealing: false,
                retention_from: Some(first),
            }
        );
        mark_notice_shown(dd, Notice::Retention);
        assert_eq!(privacy_notices(dd), PrivacyNotices::default());
        // The CLI says neither again.
        assert!(!raven_core::privacy::take_sealing_notice(dd));
        assert_eq!(raven_core::privacy::take_retention_notice(dd), None);
    }

    #[test]
    fn delete_chat_and_forget_address_take_the_clis_paths() {
        testkit::lab_backends();
        let dir = testkit::short_dir();
        let dd = dir.path();
        load_or_create_identity(dd).expect("an identity");
        let bob = me_view(&Identity::from_seed(&[0xB0; 32]));
        let carol = me_view(&Identity::from_seed(&[0xC0; 32]));
        for (who, name, lan, internet) in [
            (&bob, "Bob", "192.168.1.30:7420", "203.0.113.9:7420"),
            (&carol, "Carol", "192.168.1.31:7420", ""),
        ] {
            add_contact_with_routes(
                dd,
                &who.address,
                &who.pub_hex,
                name,
                "",
                None,
                lan,
                internet,
                None,
            )
            .expect("saved");
        }
        for (n, (who, direction)) in [(&bob, "in"), (&carol, "in"), (&bob, "out")]
            .into_iter()
            .enumerate()
        {
            let n = u8::try_from(n).expect("a few rows");
            ChatHistory::append_persisted(dd, row(&who.pub_hex, n, direction)).expect("a row");
        }
        // Both directions with Bob go; Carol's stay. No raven-node and no
        // session store: nothing waits, and no store is made to count.
        assert_eq!(
            delete_chat(dd, &bob.pub_hex),
            Ok(DeleteChatOutcome {
                deleted: 2,
                still_waiting: 0,
                skipped_pending: 0,
            })
        );
        let left = load_history(dd).expect("the history");
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].peer_pub_hex, carol.pub_hex);
        assert!(!dd
            .join(raven_core::indexed_session_store::INDEXED_SESSION_METADATA_FILE)
            .exists());
        assert_eq!(delete_chat(dd, &bob.pub_hex).map(|o| o.deleted), Ok(0));
        // Bob's addresses go, his name stays; Carol's stay.
        forget_address(dd, &bob.pub_hex).expect("forgotten");
        let book = contact_views(dd).expect("the book");
        let of = |who: &MeView| {
            let c = book
                .iter()
                .find(|c| c.pub_hex == who.pub_hex)
                .expect("saved");
            (c.label.clone(), c.lan_dial.clone(), c.internet_dial.clone())
        };
        assert_eq!(of(&bob), ("Bob".into(), String::new(), String::new()));
        assert_eq!(
            of(&carol),
            ("Carol".into(), "192.168.1.31:7420".into(), String::new())
        );
        // Someone not saved: refused.
        let dave = me_view(&Identity::from_seed(&[0xD0; 32]));
        assert!(forget_address(dd, &dave.pub_hex).is_err());
    }

    #[test]
    fn the_at_rest_state_is_read_from_the_status() {
        use raven_core::ipc::{AtRestStatus, IPC_VERSION};
        let status = |at_rest: Option<&str>| -> Result<IpcResponse, String> {
            Ok(IpcResponse::Status {
                v: IPC_VERSION,
                bridge: false,
                store: false,
                relay: false,
                forward_pending: 0,
                capabilities: Vec::new(),
                p2p: None,
                pid: Some(1),
                lan_listen: None,
                last_paths: Vec::new(),
                route_hints: None,
                unreachable: Vec::new(),
                egress: None,
                lan_listen_wanted: None,
                lan_bind_error: None,
                clock_skew: Vec::new(),
                unanswered: Vec::new(),
                at_rest: at_rest.map(|state| AtRestStatus {
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
            })
        };
        for (word, state, locked_out) in [
            ("sealed", AtRestStateView::Sealed, false),
            (
                "waiting_for_keychain",
                AtRestStateView::WaitingForKeychain,
                true,
            ),
            ("key_unavailable", AtRestStateView::KeyUnavailable, true),
            ("key_lost", AtRestStateView::KeyLost, true),
            ("migrating", AtRestStateView::Migrating, false),
            ("plain", AtRestStateView::Plain, false),
            ("unsealed_by_user", AtRestStateView::UnsealedByUser, false),
            ("needs_disk_space", AtRestStateView::NeedsDiskSpace, false),
            ("a_newer_word", AtRestStateView::Other, false),
        ] {
            assert_eq!(at_rest_state(&status(Some(word))), Some(state), "{word}");
            assert_eq!(state.locked_out(), locked_out, "{word}");
        }
        // An older node, or no answer: not known.
        assert_eq!(at_rest_state(&status(None)), None);
        assert_eq!(
            at_rest_state(&Err("raven-node is not running".into())),
            None
        );
    }

    // ── Erase (privacy pack PP.22) ──────────────────────────────────────────

    /// A profile `name` in `root` with an identity, Bob and Carol saved and a
    /// chat with Bob, sealed as a command's top seals it (its canonical
    /// path).
    fn erasable_profile(root: &Path, name: &str) -> PathBuf {
        use raven_core::at_rest::MigratePolicy;
        let dd = root.join(name);
        std::fs::create_dir_all(&dd).expect("the profile");
        load_or_create_identity(&dd).expect("an identity");
        for (seed, petname) in [(0xB0, "Bob"), (0xC0, "Carol")] {
            let who = me_view(&Identity::from_seed(&[seed; 32]));
            add_contact_with_routes(
                &dd,
                &who.address,
                &who.pub_hex,
                petname,
                "",
                None,
                "192.168.1.30:7420",
                "",
                None,
            )
            .expect("saved");
        }
        let bob = me_view(&Identity::from_seed(&[0xB0; 32]));
        ChatHistory::append_persisted(&dd, row(&bob.pub_hex, 1, "in")).expect("a row");
        raven_core::privacy::migrate_all(&dd, now_ms(), MigratePolicy::Allow).expect("sealed");
        std::fs::canonicalize(dd).expect("the profile")
    }

    #[test]
    fn erase_plan_counts_what_goes_and_refuses_as_raven_erase_does() {
        testkit::lab_backends();
        let root = testkit::short_dir();
        let dd = erasable_profile(root.path(), "a");
        // Bob and Carol; nothing waits (no raven-node, and no store is made
        // to count); a lab profile keeps its keys in files, none in the
        // keychain.
        assert_eq!(
            erase_plan_view(&dd),
            Ok(ErasePlanView {
                friends: Some(2),
                waiting: 0,
                keychain_keys: 0,
            })
        );
        assert!(!dd
            .join(raven_core::indexed_session_store::INDEXED_SESSION_METADATA_FILE)
            .exists());
        // A debug build erases only inside the lab's erase root (unset in a
        // test run): refused before anything, the app's close never runs
        // and nothing is touched.
        if cfg!(debug_assertions) && std::env::var_os("RAVEN_LAB_ERASE_ROOT").is_none() {
            let guard = Err(raven_core::erase::LAB_GUARD_TEXT.to_owned());
            assert_eq!(erase_plan(&dd), guard);
            let mut closed = 0;
            assert_eq!(
                erase(&dd, &mut || closed += 1),
                EraseEnd::NotErased(raven_core::erase::LAB_GUARD_TEXT.to_owned())
            );
            assert_eq!(closed, 0);
            assert!(contacts_path(&dd).exists());
        }
        // A folder that isn't a Raven profile: refused.
        let photos = root.path().join("photos");
        std::fs::create_dir_all(&photos).expect("a folder");
        assert!(erase_plan(&photos).is_err());
    }

    #[test]
    fn the_apps_erase_is_raven_erases_and_closes_once() {
        testkit::lab_backends();
        let root = testkit::short_dir();
        let a = erasable_profile(root.path(), "a");
        let b = erasable_profile(root.path(), "b");
        let b_book = std::fs::read(contacts_path(&b)).expect("B's book");
        // A file Raven didn't make stays, and is counted.
        std::fs::write(a.join("notes.txt"), b"mine").expect("a file of the user's");
        let mut closed = Vec::new();
        let end = erase_in_lab(&a, &mut || {
            closed.push(raven_core::erase::in_progress(&a));
        });
        let EraseEnd::Ran {
            finished: true,
            lines,
        } = end
        else {
            panic!("{end:?}");
        };
        assert_eq!(closed, [true], "closed once, with the marker down");
        assert!(
            lines[0].starts_with("Erased: identity, friends, chats, waiting messages and "),
            "{lines:?}"
        );
        assert!(
            lines[0].contains("Not erased: your shell history and terminal scrollback;"),
            "{lines:?}"
        );
        assert_eq!(
            lines[1],
            format!(
                "Left in this folder because Raven didn't create them: 1 file ({}).",
                a.display()
            )
        );
        assert_eq!(lines.len(), 2, "{lines:?}");
        let left: Vec<_> = std::fs::read_dir(&a)
            .expect("the folder stays for the user's file")
            .map(|entry| entry.expect("an entry").file_name())
            .collect();
        assert_eq!(left, ["notes.txt"]);
        assert_eq!(std::fs::read(contacts_path(&b)).expect("B's book"), b_book);
    }

    /// Part-way: exactly what is left, and `raven erase` to finish; the
    /// profile stays closed. Then the app's erase again finishes it.
    #[cfg(unix)]
    #[test]
    fn an_erase_that_stops_part_way_says_what_is_left() {
        use std::os::unix::fs::PermissionsExt;
        testkit::lab_backends();
        let root = testkit::short_dir();
        let a = erasable_profile(root.path(), "a");
        let relay = a.join("friend_relay");
        std::fs::create_dir_all(&relay).expect("a relay folder");
        std::fs::write(relay.join("relay_key.ed25519"), [7u8; 32]).expect("a relay key");
        std::fs::set_permissions(&relay, std::fs::Permissions::from_mode(0o500))
            .expect("read only");
        let end = erase_in_lab(&a, &mut || {});
        std::fs::set_permissions(&relay, std::fs::Permissions::from_mode(0o700))
            .expect("writable again");
        let EraseEnd::Ran {
            finished: false,
            lines,
        } = end
        else {
            panic!("{end:?}");
        };
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].starts_with("Erase stopped: "), "{lines:?}");
        assert!(
            lines[0].contains("friend_relay/relay_key.ed25519"),
            "{lines:?}"
        );
        assert!(
            lines[0].ends_with(". Run `raven erase` to finish."),
            "{lines:?}"
        );
        assert!(
            raven_core::erase::in_progress(&a),
            "the profile stays closed"
        );
        assert!(matches!(
            erase_in_lab(&a, &mut || {}),
            EraseEnd::Ran { finished: true, .. }
        ));
        assert!(!a.exists());
    }

    // ── Lock (PP.23) ────────────────────────────────────────────────────────

    /// What the platform's tool runs to unload Raven's job for this login
    /// session (node_control.rs's shims record it), and nothing else.
    #[cfg(unix)]
    fn session_stop_run() -> &'static str {
        if cfg!(target_os = "macos") {
            "launchctl bootout gui/501/com.raven.raven-node"
        } else {
            "systemctl --user stop raven-node.service"
        }
    }

    /// Two profiles side by side with identities, and Raven's login item in
    /// their lab for `a` only (the installer's one item per OS user).
    #[cfg(unix)]
    fn two_profiles(root: &Path) -> (PathBuf, PathBuf, PathBuf) {
        testkit::lab_backends();
        let (a, b) = (root.join("a"), root.join("b"));
        for dd in [&a, &b] {
            std::fs::create_dir_all(dd).expect("the profile");
            load_or_create_identity(dd).expect("an identity");
        }
        let log = lab_login_item_for_tests(&a, &a);
        (a, b, log)
    }

    #[cfg(unix)]
    #[test]
    fn only_this_profiles_login_item_is_its_own() {
        let root = testkit::short_dir();
        let (a, b, log) = two_profiles(root.path());
        let launchd = if cfg!(target_os = "macos") {
            Managed::LaunchAgent
        } else {
            Managed::SystemdUser
        };
        assert_eq!(
            own_login_item_in_lab(&a),
            Ok(Some(LoginItemView {
                managed: launchd,
                stays_off: false,
            }))
        );
        // A `raven lock` turned it off (review D-lock-tui-7): it stays off,
        // locked or not, until `raven unlock` clears the record.
        lock_for_tests(&a, Some("unloaded"));
        assert_eq!(
            own_login_item_in_lab(&a).map(|item| item.map(|item| item.stays_off)),
            Ok(Some(false))
        );
        lock_for_tests(&a, Some("disabled"));
        raven_core::privacy::set_unlocked(&a).expect("unlocked");
        assert_eq!(
            own_login_item_in_lab(&a),
            Ok(Some(LoginItemView {
                managed: launchd,
                stays_off: true,
            }))
        );
        // The second profile: the item is there but runs another profile,
        // so it is not this one's (UXF.7's check said Managed here).
        assert_eq!(own_login_item_in_lab(&b), Ok(None));
        // Reading runs no tool.
        assert!(lab_tool_runs(&log).is_empty());
        // A debug build without both lab switches reads no real login item.
        let unset = ["RAVEN_LAB_LOGIN_ITEM_ROOT", "RAVEN_LAB_LOGIN_ITEM_TOOLS"]
            .iter()
            .all(|key| std::env::var_os(key).is_none());
        if cfg!(debug_assertions) && unset {
            assert_eq!(own_login_item(&a), Err(NotAvailable));
            assert!(stop_for_session(&a).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn the_session_stop_unloads_only_and_the_lock_records_it() {
        let root = testkit::short_dir();
        let (a, b, log) = two_profiles(root.path());
        // Not this profile's item: nothing runs, nothing is recorded.
        assert_eq!(stop_for_session_in_lab(&b), Ok(()));
        assert!(lab_tool_runs(&log).is_empty());
        assert_eq!(lock_state_for_tests(&b), (false, None));
        // This profile's: unloaded for this login session, never turned off
        // (no `disable`, no `enable`), and recorded so `raven unlock` loads
        // it again.
        set_locked_by_user(&a, true).expect("locked");
        assert_eq!(stop_for_session_in_lab(&a), Ok(()));
        assert_eq!(lab_tool_runs(&log), [session_stop_run()]);
        assert_eq!(lock_state_for_tests(&a), (true, Some("unloaded")));
        // A lock that turned it off before stays recorded as off.
        lock_for_tests(&a, Some("disabled"));
        assert_eq!(stop_for_session_in_lab(&a), Ok(()));
        assert_eq!(lock_state_for_tests(&a), (true, Some("disabled")));
        for run in lab_tool_runs(&log) {
            assert!(!run.contains("disable") && !run.contains("enable"), "{run}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn the_apps_lock_is_set_and_taken_back_and_opening_the_app_clears_it() {
        let root = testkit::short_dir();
        let (a, b, log) = two_profiles(root.path());
        // Set and taken back; a profile without an identity has no lock.
        set_locked_by_user(&a, true).expect("locked");
        assert_eq!(lock_state_for_tests(&a), (true, None));
        set_locked_by_user(&a, false).expect("unlocked");
        assert_eq!(lock_state_for_tests(&a), (false, None));
        let empty = root.path().join("empty");
        std::fs::create_dir_all(&empty).expect("a folder");
        assert!(set_locked_by_user(&empty, true).is_err());
        // Not locked: opening the app writes nothing.
        let settings = || std::fs::read(b.join("privacy.json")).ok();
        let before = settings();
        assert_eq!(
            reopen_after_lock(&b),
            Ok(Reopened::NotLocked { stays_off: false })
        );
        assert_eq!(settings(), before);
        // The app's own Lock (and the login item it unloaded): cleared.
        set_locked_by_user(&a, true).expect("locked");
        assert_eq!(
            reopen_after_lock(&a),
            Ok(Reopened::Cleared { stays_off: false })
        );
        assert_eq!(lock_state_for_tests(&a), (false, None));
        // `raven lock` (review E-harness-docs-ci-3), whatever it did to the
        // item: kept, written over by nothing, until UNLOCK's yes clears it.
        for item in [None, Some("unloaded"), Some("disabled")] {
            lock_for_tests(&a, item);
            let before = std::fs::read(a.join("privacy.json")).ok();
            assert_eq!(reopen_after_lock(&a), Ok(Reopened::Kept));
            assert_eq!(std::fs::read(a.join("privacy.json")).ok(), before);
            assert_eq!(lock_state_for_tests(&a), (true, item));
            // The yes: cleared; a `raven lock` that turned the item off
            // leaves it off (only `raven unlock` turns it back on).
            assert_eq!(unlock_from_app(&a), Ok(item == Some("disabled")));
            assert!(!lock_state_for_tests(&a).0);
        }
        // Again, with nothing locked any more: nothing to clear, but the
        // item the last `raven lock` turned off is still off, and opening
        // the app says so (review D-lock-tui-4), writing nothing.
        let before = std::fs::read(a.join("privacy.json")).ok();
        assert_eq!(
            reopen_after_lock(&a),
            Ok(Reopened::NotLocked { stays_off: true })
        );
        assert_eq!(std::fs::read(a.join("privacy.json")).ok(), before);
        // The app's Lock over `raven lock`'s keeps it `raven lock`'s.
        lock_for_tests(&a, None);
        set_locked_by_user(&a, true).expect("locked");
        assert_eq!(reopen_after_lock(&a), Ok(Reopened::Kept));
        // No tool ever ran: the app never turns a login item on or off.
        assert!(lab_tool_runs(&log).is_empty());
    }
}
