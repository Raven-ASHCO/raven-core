//! The friend relay (any-network plan C6, Phase 2): `raven-node service`
//! relays for the profile's verified contacts under a relay key of its own,
//! never the profile PeerId (owner decision 7). One supervised task, [`run`],
//! keeps it in step every [`SYNC`]:
//!
//! - **Consent** (D2): `relay_offer` in node_policy.json (`raven relay offer
//!   on|off`), or the start flag (`raven-node service --relay`,
//!   `--relay-open`, `RAVEN_P2P_RELAY=1`), which stands for a `relay_offer`
//!   never set or set on: a saved `raven relay offer off` wins over it. It is
//!   applied live: turning it off stops the relay without a restart of the
//!   service.
//! - **Hide my IP** for everyone (`raven node hide-ip on`) stops it too,
//!   whatever the consent, and it starts again once that is off: the relay
//!   would show this computer's IP to the contacts who use it (`raven relay
//!   offer on` refuses for the same reason).
//! - **Gate**: [`raven_core::friend_relay_live_enabled`]. While it is closed
//!   nothing listens, and consent is answered once with `FRIEND_RELAY_HOLD`.
//!   With the gate open and no consent the task idles (status: `off`).
//! - **The relay** is [`crate::relay::run_relay`] on `<profile>/friend_relay/`
//!   ([`friend_relay_dir`]), a folder that holds no Raven identity, only the
//!   relay's own `relay_key.ed25519` (made on its first start). It listens
//!   on TCP and QUIC at `relay_port` ([`FRIEND_RELAY_PORT`] unless set; the
//!   debug `RAVEN_LAB_FRIEND_RELAY_LISTEN` for harnesses), on TCP 443 too
//!   with `relay_also_443` (best effort), with the friends' limits, an
//!   AutoNAT v2 server, and UPnP while the policy has it on. A change of
//!   port, of 443 or of UPnP starts it over with the same key, and so does a
//!   network change ([`network_changed`]: a fresh gateway search, fresh
//!   listeners). It is always stopped through its stop future (connections
//!   closed, its folder lock released) and aborted only if it has not ended
//!   [`STOP_GRACE`] later. A failure is logged and retried with backoff.
//! - **Members** ([`derive_members`]): the verified, unblocked contacts the
//!   p2p peer gate admits ([`raven_core::outbox::p2p_gate_peers`]; a learned
//!   PeerId only once a link proved it) that this node may show its IP to
//!   (hide my IP off for them), plus the manual allow-list of the profile
//!   (`relay_allow.json`), minus its deny list and minus every blocked
//!   contact (a block holds over the manual list too: by PeerId, and by the
//!   contact an entry names). They reach the relay
//!   in memory ([`PolicySource::Shared`]) and are read again when one of
//!   their files changes. Unreadable contacts keep the manual list only; an
//!   unreadable manual list or block list admits nobody.
//! - **Addresses it names** ([`externals`]): in its reservations, and in the
//!   offers route hints carry to members.
//! - **The offer** ([`offer`], RAVEN_ROUTE_HINTS_V1 §11.4): while offers are
//!   live ([`raven_core::relay_offers_live`]) and the relay is up with an
//!   address worth offering, route hints tell each member about it
//!   ([`Offer::offer_for`]): its own key, at most four of the addresses it
//!   names, its flags. A change of that record wakes the route-hints
//!   announcer ([`crate::hints::own_changed`]).
//!
//! Lines carry counts and ports only.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::Duration;

use raven_core::clock::now_ms;
use raven_core::ipc::FriendRelayInfo;
use raven_core::node_policy::{NodePolicy, MAX_RELAY_EXTERNAL};
use raven_core::outbox::{BlockedP2p, P2pGatePeer};
use raven_core::p2p_route::{
    is_global_ip, parse_host_transport, parse_peer_id, ExtraTcp, P2pListen, FRIEND_RELAY_PORT,
};
use raven_core::relay_allow::{
    friend_relay_dir, load_relay_allow, load_relay_status, RelayAllowEntry, RelayAllowList,
    RelayStatusFile, RELAY_ALLOW_FILE,
};
use raven_core::route_hints::{
    RelayOfferRecord, FLAG_AUTONAT, FLAG_CONFIRMED, FLAG_PORT_443, MAX_OFFER_ADDRS,
    OFFER_ADDR_MAX_LEN, OFFER_ADDR_MIN_LEN,
};
use raven_swarm::host::{addr_ip, AllowPolicy, RelayLimits};
use raven_swarm::libp2p::multiaddr::Protocol;
use raven_swarm::libp2p::{Multiaddr, PeerId};
use tokio::sync::{oneshot, watch, Notify};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::netutil::{RESTART_BACKOFF_MAX, RESTART_BACKOFF_MIN, RESTART_STABLE};
use crate::p2p::{file_stamp, FileStamp, OwnP2p};
use crate::relay::{PolicySource, RelayCmd, RelayExit};

/// How often consent, settings, members and addresses are looked at.
const SYNC: Duration = Duration::from_secs(2);
/// A relay asked to stop that has not ended this long after is aborted.
const STOP_GRACE: Duration = Duration::from_secs(3);
/// Starts every line, the relay's own too ([`RelayCmd::label`]).
const LABEL: &str = "raven-node friend relay";
/// A counts line at most this often (and only when the counts changed).
const COUNTS_EVERY: Duration = Duration::from_secs(30);
/// A reservation from a globally routable IP confirms the relay this long
/// (RAVEN_ROUTE_HINTS_V1 §11.1 CONFIRMED).
const CONFIRMED_FOR_MS: u64 = 24 * 3_600_000;
/// The last offer is kept this long while the relay runs on with the same
/// settings but its record cannot be made for a moment: it was started over
/// after a wake or a network change and has not reported yet, or the p2p
/// host re-homed and does not know this computer's address or reach yet.
/// Members then do not drop a relay that is still there. A real withdrawal
/// (consent, the gate, hide my IP, offers off, members unreadable) or a
/// relay that does not run (it failed) ends it at once. As long as members
/// wait for a lost relay (relay_select's REPLACE_AFTER_MS).
const OFFER_GRACE: Duration = Duration::from_secs(600);

/// What [`status`] reports: the task's last round.
static STATE: Mutex<Option<FriendRelayInfo>> = Mutex::new(None);

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

fn restart_notify() -> &'static Notify {
    static NOTIFY: OnceLock<Notify> = OnceLock::new();
    NOTIFY.get_or_init(Notify::new)
}

fn shutdown_notify() -> &'static Notify {
    static NOTIFY: OnceLock<Notify> = OnceLock::new();
    NOTIFY.get_or_init(Notify::new)
}

fn stopped_notify() -> &'static Notify {
    static NOTIFY: OnceLock<Notify> = OnceLock::new();
    NOTIFY.get_or_init(Notify::new)
}

/// This machine's network changed and the paths out cannot be trusted
/// (`netwatch`): a running friend relay starts over, for a fresh UPnP
/// gateway search (libp2p-upnp looks for one once per start), fresh
/// listeners and addresses from the new external IP. A relay that does not
/// run is not started by it.
pub(crate) fn network_changed() {
    restart_notify().notify_one();
}

/// `raven-node service` is stopping: stop a running friend relay cleanly
/// (its members see their reservations end at once) and wait at most
/// `wait` for it.
pub(crate) async fn shutdown(wait: Duration) {
    shutdown_notify().notify_one();
    let _ = tokio::time::timeout(wait, stopped_notify().notified()).await;
}

/// The friend relay as status shows it (IPC `Status`,
/// [`crate::p2p::status_snapshot`]): `off` while its gate is open and
/// consent is not given; `None` while the gate is closed and consent is not
/// given (and outside `raven-node service`).
pub(crate) fn status() -> Option<FriendRelayInfo> {
    lock(&STATE).clone()
}

/// [`status`] says `info` (other modules' tests).
#[cfg(test)]
pub(crate) fn set_status_for_test(info: Option<FriendRelayInfo>) {
    *lock(&STATE) = info;
}

/// What the friend relay offers its members in route hints
/// (RAVEN_ROUTE_HINTS_V1 §11.4), as of the task's last round.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Offer {
    /// The profile it relays for.
    data_dir: PathBuf,
    /// What every member is told: the relay's own key, its addresses and
    /// flags.
    pub(crate) record: RelayOfferRecord,
    /// The PeerIds it admits.
    members: Arc<HashSet<PeerId>>,
}

impl Offer {
    /// The record for the contact whose libp2p PeerId is `contact_peer_id`:
    /// `None` unless the relay admits that PeerId. Whether this node may
    /// show the contact its IP, and whether the contact gets a full
    /// snapshot, is the caller's part (`hints::snapshot_for`).
    pub(crate) fn offer_for(&self, contact_peer_id: &str) -> Option<RelayOfferRecord> {
        let peer: PeerId = contact_peer_id.parse().ok()?;
        self.members.contains(&peer).then(|| self.record.clone())
    }

    /// `record` offered to the PeerIds `members` of the profile in
    /// `data_dir` (other modules' tests).
    #[cfg(test)]
    pub(crate) fn of(data_dir: &Path, record: RelayOfferRecord, members: &[String]) -> Self {
        Self {
            data_dir: data_dir.to_path_buf(),
            record,
            members: Arc::new(members.iter().filter_map(|p| p.parse().ok()).collect()),
        }
    }
}

/// [`Offer`] as [`run`] last published it: `None` while the relay does not
/// offer.
static OFFER: Mutex<Option<Offer>> = Mutex::new(None);

/// The friend relay's offer for the profile in `data_dir`: `None` while
/// offers are off, the relay is not up, or it names no address worth
/// offering (and outside `raven-node service`).
pub(crate) fn offer(data_dir: &Path) -> Option<Offer> {
    lock(&OFFER)
        .as_ref()
        .filter(|o| o.data_dir == data_dir)
        .cloned()
}

/// Keep `offer` for route hints; a new record (the relay came up, went
/// down, moved, or a flag changed) wakes the route-hints announcer, whose
/// digest covers it. A change of members alone reaches each contact with its
/// next snapshot.
fn publish_offer(offer: Option<Offer>) {
    let changed = {
        let mut held = lock(&OFFER);
        let changed = held.as_ref().map(|o| &o.record) != offer.as_ref().map(|o| &o.record);
        *held = offer;
        changed
    };
    if changed {
        crate::hints::own_changed();
    }
}

/// The key of this profile's own friend relay, from the status it last
/// wrote (it stays after the relay stops): a relay route hints offer this
/// node under that key is its own and is never kept. `None` when it never
/// ran.
pub(crate) fn own_relay_key(data_dir: &Path) -> Option<[u8; 32]> {
    let status = load_relay_status(&friend_relay_dir(data_dir)).ok()??;
    parse_peer_id(&status.peer_id).ok()
}

/// Where consent comes from (`FriendRelayInfo::consent`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Consent {
    /// Never asked: off.
    Unset,
    No,
    Yes,
    /// `raven-node service --relay` (`--relay-open`, `RAVEN_P2P_RELAY=1`):
    /// consent for this run, unless the policy says no.
    Flag,
}

impl Consent {
    /// A saved "no" (`raven relay offer off`) wins over the start flag: the
    /// flag gives consent only where the policy gives none or says yes, so
    /// `raven relay offer off` stops a relay the service was started with.
    fn of(relay_offer: Option<bool>, flag: bool) -> Self {
        match (flag, relay_offer) {
            (_, Some(false)) => Self::No,
            (true, _) => Self::Flag,
            (false, None) => Self::Unset,
            (false, Some(true)) => Self::Yes,
        }
    }

    fn given(self) -> bool {
        matches!(self, Self::Yes | Self::Flag)
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Unset => "unset",
            Self::No => "no",
            Self::Yes => "yes",
            Self::Flag => "flag",
        }
    }
}

/// What the relay is started with that only a new start can change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RunKey {
    listen: P2pListen,
    also_443: bool,
    upnp: bool,
}

/// The friend relay's settings: node_policy.json and the start flag.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Settings {
    consent: Consent,
    key: RunKey,
    /// `relay_external`: the addresses the operator declared, host and
    /// transport only ([`parse_host_transport`]), at most
    /// [`MAX_RELAY_EXTERNAL`].
    declared: Vec<Multiaddr>,
    /// `relay_external` entries left out (not host and transport, or past
    /// the limit).
    ignored: usize,
    /// Hide my IP for everyone (`raven node hide-ip on`): the relay does not
    /// run, whatever the consent.
    hide_ip: bool,
}

/// The port of `listen` (0: the OS picks one).
fn listen_port(listen: &P2pListen) -> u16 {
    match listen {
        P2pListen::All(port) => *port,
        P2pListen::One(addr) => addr.port(),
        P2pListen::RelayOnly => 0,
    }
}

/// [`Settings`] from the policy, the start flag and the debug listen
/// address (`RAVEN_LAB_FRIEND_RELAY_LISTEN`).
fn settings(policy: &NodePolicy, flag: bool, lab_listen: Option<SocketAddr>) -> Settings {
    let listen = match lab_listen {
        Some(addr) => P2pListen::One(addr),
        None => P2pListen::All(policy.relay_port.unwrap_or(FRIEND_RELAY_PORT)),
    };
    let mut declared: Vec<Multiaddr> = Vec::new();
    let mut ignored = 0;
    for text in &policy.relay_external {
        let addr = parse_host_transport(text)
            .ok()
            .and_then(|t| t.parse::<Multiaddr>().ok());
        match addr {
            Some(addr) if declared.contains(&addr) => {}
            Some(addr) if declared.len() < MAX_RELAY_EXTERNAL => declared.push(addr),
            _ => ignored += 1,
        }
    }
    Settings {
        consent: Consent::of(policy.relay_offer, flag),
        key: RunKey {
            listen,
            // 443 as the relay's own port needs no second listener.
            also_443: policy.relay_also_443 && listen_port(&listen) != 443,
            upnp: policy.upnp == Some(true),
        },
        declared,
        ignored,
        hide_ip: policy.hide_ip,
    }
}

/// The relay to run now: none unless the gate is open and consent is given,
/// and never while this node hides its IP from every contact (the relay
/// would show it to them).
fn wanted(settings: &Settings, gate: bool) -> Option<RunKey> {
    (gate && settings.consent.given() && !settings.hide_ip).then_some(settings.key)
}

/// Who the friend relay admits, with the counts its status shows.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Members {
    policy: AllowPolicy,
    /// PeerIds on the manual allow-list.
    manual: u32,
    /// PeerIds on the deny list.
    denied: u32,
    /// Members its offer goes to: verified contacts it admits that this
    /// node may show its IP (hide my IP off for them and for everyone).
    offered: u32,
    /// The contact book or the block list cannot be read: no contact is
    /// admitted by itself, only the manual allow-list counts, and with the
    /// block list unreadable not even that ([`members_from`]).
    contacts_unreadable: bool,
    /// The block list cannot be read: nobody is admitted.
    blocks_unreadable: bool,
    /// When the next manual entry expires (a relay schedule's PeerId,
    /// `expires_ms`): the members are read again then, although no file
    /// changed.
    expires_next: Option<u64>,
}

impl Members {
    fn count(&self) -> u32 {
        match &self.policy {
            AllowPolicy::Peers(peers) => peers.len() as u32,
            AllowPolicy::Open | AllowPolicy::Unreadable => 0,
        }
    }
}

/// The members, from the profile's files (blocking).
fn derive_members(dd: &Path) -> Members {
    let manual = load_relay_allow(dd);
    let denied = denied_contacts_p2p(dd, &manual);
    members_with_denied(
        raven_core::outbox::p2p_gate_peers(dd),
        manual,
        raven_core::outbox::blocked_p2p(dd),
        &denied,
    )
}

/// Every PeerId the contacts the deny list names are known by
/// ([`RelayAllowList::denied_contacts`],
/// [`raven_core::outbox::contact_p2p_peer_ids`]): their card's `p2p=` and
/// `p2pn=`, what their route hints named and every epoch their PeerId
/// schedule names, so a deny holds over a rotating contact's coming
/// PeerIds too (peer rotation spec §9). None while the list cannot be read
/// (it then admits nobody anyway).
fn denied_contacts_p2p(dd: &Path, manual: &Result<Option<RelayAllowList>, String>) -> Vec<String> {
    let Ok(Some(list)) = manual else {
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::new();
    for key in list.denied_contacts() {
        for peer_id in raven_core::outbox::contact_p2p_peer_ids(dd, &key) {
            if !out.contains(&peer_id) {
                out.push(peer_id);
            }
        }
    }
    out
}

/// [`members_with_denied`] with no denied contact's PeerIds.
#[cfg(test)]
fn members_from(
    contacts: Result<Vec<P2pGatePeer>, String>,
    manual: Result<Option<RelayAllowList>, String>,
    blocked: Result<BlockedP2p, String>,
) -> Members {
    members_with_denied(contacts, manual, blocked, &[])
}

/// The member rule: the verified contacts the p2p peer gate admits that
/// this node may show its IP to (hide my IP off for them; a learned PeerId
/// only once a link proved it), plus the manual allow-list (`peers`), minus
/// its deny list and minus `blocked` (blocked contacts: a block holds over
/// the manual list too, by their PeerIds and by the contact an entry names,
/// [`RelayAllowEntry::contact`]). A contact this node hides its IP from is
/// no member by itself: the relay runs at this node's IP, and it gets no
/// offer either; the operator may still allow it by hand. Unreadable
/// contacts keep the manual list only; an unreadable manual list, or an
/// unreadable block list (a blocked contact on the manual list could not
/// be told), admits nobody (fail closed). The offer goes to the contacts
/// among them the gate does not hide. A contact the deny list names
/// ([`RelayAllowEntry::contact`]) is turned away under every PeerId it is
/// known by (`denied`, [`denied_contacts_p2p`]) and every manual entry
/// naming it, as a block is.
fn members_with_denied(
    contacts: Result<Vec<P2pGatePeer>, String>,
    manual: Result<Option<RelayAllowList>, String>,
    blocked: Result<BlockedP2p, String>,
    denied: &[String],
) -> Members {
    let contacts_unreadable = contacts.is_err() || blocked.is_err();
    let nobody = Members {
        policy: AllowPolicy::Unreadable,
        manual: 0,
        denied: 0,
        offered: 0,
        contacts_unreadable,
        blocks_unreadable: blocked.is_err(),
        expires_next: None,
    };
    let (Ok(list), Ok(blocked)) = (manual, blocked) else {
        return nobody;
    };
    let list = list.unwrap_or_default();
    let parse = |entries: &[RelayAllowEntry]| -> Option<HashSet<PeerId>> {
        entries.iter().map(|e| e.peer_id.parse().ok()).collect()
    };
    let (Some(mut manual), Some(deny)) = (parse(&list.peers), parse(&list.deny)) else {
        return nobody;
    };
    // An expired manual entry (a relay schedule's old PeerId) admits nobody,
    // as on a dedicated relay ([`crate::relay::allow_policy`]).
    let now = now_ms();
    let expired = list.peers.iter().filter(|e| e.expired(now));
    for e in expired {
        if let Ok(p) = e.peer_id.parse::<PeerId>() {
            manual.remove(&p);
        }
    }
    let expires_next = list
        .peers
        .iter()
        .filter_map(|e| e.expires_ms)
        .filter(|at| *at >= now)
        .min();
    let contacts = contacts.unwrap_or_default();
    // `hidden`: hide my IP for them (or for everyone), or a learned PeerId
    // no link proved yet.
    // Every PeerId of each: a rotating contact's others too (Phase 4,
    // [`P2pGatePeer::rotated`]), as the p2p peer gate admits them.
    let mut peers: HashSet<PeerId> = contacts
        .iter()
        .filter(|p| !p.hidden)
        .flat_map(|p| p.peer_ids())
        .filter_map(|p| p.parse().ok())
        .collect();
    peers.extend(manual.iter().copied());
    let mut out: HashSet<PeerId> = blocked
        .peer_ids
        .iter()
        .filter_map(|p| p.parse().ok())
        .collect();
    let denied_keys = list.denied_contacts();
    out.extend(
        list.peers
            .iter()
            .filter(|e| {
                blocked
                    .keys
                    .iter()
                    .chain(&denied_keys)
                    .any(|k| e.contact.eq_ignore_ascii_case(k))
            })
            .filter_map(|e| e.peer_id.parse::<PeerId>().ok()),
    );
    out.extend(denied.iter().filter_map(|p| p.parse::<PeerId>().ok()));
    peers.retain(|p| !deny.contains(p) && !out.contains(p));
    let offered: HashSet<PeerId> = contacts
        .iter()
        .filter(|p| !p.hidden)
        .filter_map(|p| p.peer_id.parse().ok())
        .filter(|p| peers.contains(p))
        .collect();
    Members {
        policy: AllowPolicy::Peers(peers),
        manual: manual.len() as u32,
        denied: deny.len() as u32,
        offered: offered.len() as u32,
        contacts_unreadable,
        blocks_unreadable: false,
        expires_next,
    }
}

/// The files the members are read from: contacts.json, the block list,
/// what route hints taught (a learned PeerId, proved or not), the profile's
/// relay_allow.json (manual and deny lists), node_policy.json (hide my IP,
/// for the offer's count) and contacts' PeerId schedules (Phase 4); with the
/// contact book's reload generation, which moves when the at-rest key
/// arrives (privacy pack PP.4), and the PeerId rotation clock window
/// ([`crate::p2p::rotation_window`]: a rotating contact's admitted PeerIds
/// move with the clock).
type MemberStamp = ([Option<FileStamp>; 6], u64, u64);

fn member_stamp(dd: &Path) -> MemberStamp {
    (
        [
            file_stamp(&dd.join(raven_core::contact_book::CONTACTS_FILE)),
            file_stamp(&raven_core::chat_history::blocked_path(dd)),
            file_stamp(&dd.join(raven_core::learned_routes::LEARNED_ROUTES_FILE)),
            file_stamp(&dd.join(RELAY_ALLOW_FILE)),
            file_stamp(&raven_core::policy_path(dd)),
            file_stamp(&dd.join(raven_core::peer_rotation::PEER_SCHEDULES_FILE)),
        ],
        raven_core::contact_book::reload_generation(dd),
        crate::p2p::rotation_window(),
    )
}

/// Whether an address with `ip` may be named: globally routable, or (debug
/// `RAVEN_LAB_P2P_LOCAL_CANDIDATES=1`, `local_ok`) any unicast address.
fn usable_ip(ip: IpAddr, local_ok: bool) -> bool {
    is_global_ip(ip) || (local_ok && !ip.is_unspecified() && !ip.is_multicast())
}

/// TCP (`true`) or QUIC, and the port, of a listen address.
fn transport(addr: &Multiaddr) -> Option<(bool, u16)> {
    let mut udp = None;
    for p in addr.iter() {
        match p {
            Protocol::Tcp(port) => return Some((true, port)),
            Protocol::Udp(port) => udp = Some(port),
            Protocol::QuicV1 => return udp.map(|port| (false, port)),
            _ => {}
        }
    }
    None
}

/// The relay's TCP and QUIC ports, from its listen addresses (the first of
/// each; TCP 443 counts only when it is the relay's own port), and whether
/// a TCP 443 listener is open besides.
fn relay_ports(listen: &[Multiaddr], also_443: bool) -> (Option<u16>, Option<u16>, bool) {
    let (mut tcp, mut quic, mut port_443) = (None, None, false);
    for addr in listen {
        match transport(addr) {
            Some((true, 443)) if also_443 => port_443 = true,
            Some((true, port)) => {
                tcp.get_or_insert(port);
            }
            Some((false, port)) => {
                quic.get_or_insert(port);
            }
            None => {}
        }
    }
    (tcp, quic, port_443)
}

/// The addresses the friend relay names for itself, in its reservations and
/// in the offers route hints carry:
/// 1. the operator's `relay_external`, alone;
/// 2. else what UPnP mapped for the relay's own ports;
/// 3. else the IPs the profile's p2p host is known at (its confirmed, then,
///    auto-reach, `found`: the public IP STUN discovery found where the NAT
///    keeps ports, [`crate::autoreach::forward_ip`], then its listen
///    addresses) with the relay's ports: TCP and QUIC, and TCP 443 while that
///    listener is open;
/// 4. and with 2 or 3, the relay's own global listen addresses (IPv6, in
///    practice).
///
/// Globally routable IPs only, except under `local_ok`
/// ([`raven_core::p2p_local_candidates_enabled`]: loopback harnesses).
/// Nothing but the declared ones before the relay reports its listeners.
fn externals(
    declared: &[Multiaddr],
    relay: Option<&RelayStatusFile>,
    host: Option<&OwnP2p>,
    found: Option<IpAddr>,
    also_443: bool,
    local_ok: bool,
) -> Vec<Multiaddr> {
    if !declared.is_empty() {
        return declared.to_vec();
    }
    let Some(relay) = relay else {
        return Vec::new();
    };
    let parse = |texts: &[String]| -> Vec<Multiaddr> {
        texts.iter().filter_map(|t| t.parse().ok()).collect()
    };
    let named = |a: &Multiaddr| addr_ip(a).is_some_and(|ip| usable_ip(ip, local_ok));
    let listen = parse(&relay.listen_addrs);
    let mut out: Vec<Multiaddr> = parse(&relay.upnp_addrs).into_iter().filter(named).collect();
    if out.is_empty() {
        let (tcp, quic, port_443) = relay_ports(&listen, also_443);
        let mut ips: Vec<IpAddr> = Vec::new();
        let confirmed = host.map(|h| parse(&h.confirmed)).unwrap_or_default();
        let listening = host.map(|h| parse(&h.listen)).unwrap_or_default();
        let candidates = confirmed
            .iter()
            .filter_map(addr_ip)
            .chain(found)
            .chain(listening.iter().filter_map(addr_ip));
        for ip in candidates {
            if usable_ip(ip, local_ok) && !ips.contains(&ip) {
                ips.push(ip);
            }
        }
        for ip in ips {
            let base = Multiaddr::from(ip);
            out.extend(tcp.map(|p| base.clone().with(Protocol::Tcp(p))));
            out.extend(quic.map(|p| base.clone().with(Protocol::Udp(p)).with(Protocol::QuicV1)));
            if port_443 {
                out.push(base.with(Protocol::Tcp(443)));
            }
        }
    }
    for addr in listen.into_iter().filter(named) {
        if !out.contains(&addr) {
            out.push(addr);
        }
    }
    out
}

/// CONFIRMED (RAVEN_ROUTE_HINTS_V1 §11.1): a member reserved from a globally
/// routable IP within the last 24 hours, or UPnP mapped the relay's port.
fn confirmed(relay: &RelayStatusFile, now_ms: u64) -> bool {
    relay.upnp.starts_with("mapped")
        || (relay.confirmed_at_ms != 0
            && now_ms.saturating_sub(relay.confirmed_at_ms) <= CONFIRMED_FOR_MS)
}

/// An address worth offering (RAVEN_ROUTE_HINTS_V1 §11.4): it names one, and
/// the profile's reach class is public or mapped, the relay is confirmed, the
/// operator declared its addresses, or (auto-reach) STUN discovery `found`
/// this computer's public address, which the relay names with its own ports
/// (unconfirmed until a member reserves from outside).
fn worth_offering(
    names: &[Multiaddr],
    declared: bool,
    confirmed: bool,
    reach: &str,
    found: bool,
) -> bool {
    !names.is_empty() && (declared || confirmed || found || matches!(reach, "public" | "mapped"))
}

/// The RELAY_OFFER record for the relay that reports `relay` and names
/// `names` (RAVEN_ROUTE_HINTS_V1 §11.1): its own key, the first
/// [`MAX_OFFER_ADDRS`] distinct names a member may dial (canonical host and
/// transport text of 8 to 120 characters; an IP only when globally
/// routable, any unicast one under `local_ok`), and its flags: AUTONAT
/// always (it runs an AutoNAT v2 server), CONFIRMED by [`confirmed`],
/// PORT_443 when one of them is TCP 443. `None` when no such address is
/// worth offering ([`worth_offering`]).
fn offer_record(
    relay: &RelayStatusFile,
    names: &[Multiaddr],
    declared: bool,
    reach: &str,
    found: bool,
    now_ms: u64,
    local_ok: bool,
) -> Option<RelayOfferRecord> {
    let relay_pub = parse_peer_id(&relay.peer_id).ok()?;
    let mut dialable: Vec<Multiaddr> = Vec::new();
    let mut addrs: Vec<String> = Vec::new();
    for name in names {
        if addrs.len() == MAX_OFFER_ADDRS {
            break;
        }
        let Ok(text) = parse_host_transport(&name.to_string()) else {
            continue;
        };
        if (OFFER_ADDR_MIN_LEN..=OFFER_ADDR_MAX_LEN).contains(&text.len())
            && addr_ip(name).is_none_or(|ip| usable_ip(ip, local_ok))
            && !addrs.contains(&text)
        {
            addrs.push(text);
            dialable.push(name.clone());
        }
    }
    let is_confirmed = confirmed(relay, now_ms);
    if !worth_offering(&dialable, declared, is_confirmed, reach, found) {
        return None;
    }
    let mut flags = FLAG_AUTONAT;
    if is_confirmed {
        flags |= FLAG_CONFIRMED;
    }
    if addrs.iter().any(|a| a.ends_with("/tcp/443")) {
        flags |= FLAG_PORT_443;
    }
    Some(RelayOfferRecord {
        flags,
        relay_pub,
        addrs,
    })
}

/// The last record offered, with the settings of the run that made it
/// and when it was last made ([`OFFER_GRACE`]).
#[derive(Clone, Debug)]
struct Kept {
    record: RelayOfferRecord,
    key: RunKey,
    at: Instant,
}

/// One run of the relay.
struct Running {
    key: RunKey,
    /// Resolves the relay's stop future.
    stop: Option<oneshot::Sender<()>>,
    task: JoinHandle<Result<(), RelayExit>>,
    started: Instant,
}

/// How a relay asked to stop ended.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Stopped {
    /// Through its stop future: connections closed, lock released.
    Clean,
    /// It had failed by itself before the stop came.
    Failed(String),
    /// It did not end within [`STOP_GRACE`].
    Aborted,
}

/// What one [`FriendRelay::round`] did (tests).
#[derive(Debug, Default, PartialEq, Eq)]
struct Round {
    stopped: Option<Stopped>,
    started: bool,
}

/// The friend relay's supervisor: [`run`] drives it every [`SYNC`].
struct FriendRelay {
    data_dir: PathBuf,
    /// [`raven_core::friend_relay_live_enabled`], read once.
    gate: bool,
    policy_tx: watch::Sender<AllowPolicy>,
    ext_tx: watch::Sender<Vec<Multiaddr>>,
    sink: Arc<Mutex<Option<RelayStatusFile>>>,
    running: Option<Running>,
    members: Option<Members>,
    stamp: Option<MemberStamp>,
    settings: Option<Settings>,
    /// `FRIEND_RELAY_HOLD` was logged for the consent given now.
    hold_logged: bool,
    /// `relay_external` entries left out, as last logged.
    ignored_logged: usize,
    /// The settings of a run that failed by itself (state `failed`), until
    /// the next start.
    failed: Option<RunKey>,
    /// No new start before this, after a failure.
    retry_at: Option<Instant>,
    backoff: Duration,
    /// The last record offered ([`Self::offered_record`]).
    kept: Option<Kept>,
}

impl FriendRelay {
    fn new(data_dir: PathBuf, gate: bool) -> Self {
        Self {
            data_dir,
            gate,
            policy_tx: watch::Sender::new(AllowPolicy::Peers(HashSet::new())),
            ext_tx: watch::Sender::new(Vec::new()),
            sink: Arc::new(Mutex::new(None)),
            running: None,
            members: None,
            stamp: None,
            settings: None,
            hold_logged: false,
            ignored_logged: 0,
            failed: None,
            retry_at: None,
            backoff: RESTART_BACKOFF_MIN,
            kept: None,
        }
    }

    /// One round: stop what must stop (consent withdrawn, other settings, a
    /// network change), start what is wanted (unless a failure's backoff is
    /// still running), then keep the members and named addresses current.
    async fn round(&mut self, settings: Settings, restart: bool) -> Round {
        let mut round = Round::default();
        self.note(&settings);
        let want = wanted(&settings, self.gate);
        if self.running.as_ref().is_some_and(|r| r.task.is_finished()) {
            if let Some(run) = self.running.take() {
                self.failed(run).await;
            }
        }
        if let Some(key) = self.running.as_ref().map(|r| r.key) {
            let why = match want {
                None if settings.hide_ip && settings.consent.given() => {
                    Some("turned off (hide my IP is on for every contact)")
                }
                None => Some("turned off"),
                Some(w) if w != key => Some("restarting (settings changed)"),
                Some(_) if restart => Some("restarting (network changed)"),
                Some(_) => None,
            };
            if let Some(why) = why {
                eprintln!("{LABEL}: {why}");
                round.stopped = self.stop().await;
            }
        }
        if self.failed.is_some() && self.failed != want {
            // Other settings (or none): no need to wait for the backoff.
            self.failed = None;
            self.retry_at = None;
        }
        if let Some(key) = want {
            let due = self.retry_at.is_none_or(|at| Instant::now() >= at);
            if self.running.is_none() && due {
                self.start(key, &settings.declared).await;
                round.started = true;
            }
        }
        if self.running.is_some() {
            self.refresh_members().await;
            self.feed(&settings);
        }
        self.settings = Some(settings);
        round
    }

    /// Lines about the settings: `FRIEND_RELAY_HOLD` once when consent is
    /// given while the gate is closed, and ignored `relay_external` entries.
    fn note(&mut self, settings: &Settings) {
        let held = !self.gate && settings.consent.given();
        if held && !self.hold_logged {
            eprintln!(
                "{LABEL}: {} (consent: {})",
                raven_core::FRIEND_RELAY_HOLD,
                settings.consent.as_str()
            );
        }
        self.hold_logged = held;
        if settings.ignored != self.ignored_logged {
            if settings.ignored > 0 {
                eprintln!(
                    "{LABEL}: {} relay_external address(es) in node_policy.json ignored (a \
                     host and a transport only, at most {MAX_RELAY_EXTERNAL})",
                    settings.ignored
                );
            }
            self.ignored_logged = settings.ignored;
        }
    }

    /// What one run is started with.
    fn command(&self, key: RunKey, declared: &[Multiaddr]) -> RelayCmd {
        RelayCmd {
            data_dir: friend_relay_dir(&self.data_dir),
            listen: key.listen,
            open: false,
            autonat_server: true,
            limits: RelayLimits::friends(),
            external: declared.to_vec(),
            also_tcp: if key.also_443 {
                vec![ExtraTcp {
                    local: 443,
                    public: 443,
                }]
            } else {
                Vec::new()
            },
            extra_best_effort: true,
            wss: None,
            counts_every: COUNTS_EVERY,
            upnp: key.upnp,
            policy: PolicySource::Shared(self.policy_tx.subscribe()),
            external_feed: Some(self.ext_tx.subscribe()),
            status_sink: Some(self.sink.clone()),
            label: LABEL,
        }
    }

    /// Start a run, with the members read first.
    async fn start(&mut self, key: RunKey, declared: &[Multiaddr]) {
        self.refresh_members().await;
        let cmd = self.command(key, declared);
        let (stop, stopped) = oneshot::channel::<()>();
        let task = tokio::spawn(crate::relay::run_relay(cmd, async move {
            let _ = stopped.await;
        }));
        self.running = Some(Running {
            key,
            stop: Some(stop),
            task,
            started: Instant::now(),
        });
    }

    /// Stop the running relay through its stop future, and abort it only if
    /// it has not ended [`STOP_GRACE`] later. Its status and named addresses
    /// are cleared either way.
    async fn stop(&mut self) -> Option<Stopped> {
        let mut run = self.running.take()?;
        if let Some(stop) = run.stop.take() {
            let _ = stop.send(());
        }
        let ended = match tokio::time::timeout(STOP_GRACE, &mut run.task).await {
            Ok(Ok(Ok(()))) => Stopped::Clean,
            Ok(Ok(Err(e))) => Stopped::Failed(e.to_string()),
            Ok(Err(e)) => Stopped::Failed(format!("task ended abnormally: {e}")),
            Err(_) => {
                run.task.abort();
                // Its folder lock and sockets go with the task.
                let _ = tokio::time::timeout(STOP_GRACE, run.task).await;
                eprintln!(
                    "{LABEL}: did not stop within {}s; aborted",
                    STOP_GRACE.as_secs()
                );
                Stopped::Aborted
            }
        };
        self.clear();
        Some(ended)
    }

    /// A run that ended by itself: say why and try again after the backoff
    /// (back to its minimum after a run that lasted). Right after an unlock
    /// (Lock v2 stopped the relay a moment ago, [`crate::lock::settling`])
    /// it is tried again at the next round, with no line.
    async fn failed(&mut self, run: Running) {
        let why = match run.task.await {
            Ok(Ok(())) => "exited unexpectedly".to_string(),
            Ok(Err(e)) => e.to_string(),
            Err(e) => format!("task ended abnormally: {e}"),
        };
        if crate::lock::settling() {
            self.clear();
            return;
        }
        if run.started.elapsed() >= RESTART_STABLE {
            self.backoff = RESTART_BACKOFF_MIN;
        }
        eprintln!(
            "{LABEL}: failed: {why}; retrying in {}s",
            self.backoff.as_secs()
        );
        self.retry_at = Some(Instant::now() + self.backoff);
        self.backoff = (self.backoff * 2).min(RESTART_BACKOFF_MAX);
        self.failed = Some(run.key);
        self.clear();
    }

    /// No run: no status, nothing named. The next run starts from an empty
    /// feed it has seen, so the first addresses it is given always reach it.
    fn clear(&mut self) {
        *lock(&self.sink) = None;
        self.ext_tx.send_replace(Vec::new());
    }

    /// Read the members again when one of their files changed (or never
    /// was read), and hand them to the relay.
    async fn refresh_members(&mut self) {
        let stamp = member_stamp(&self.data_dir);
        let expiry_due = self
            .members
            .as_ref()
            .and_then(|m| m.expires_next)
            .is_some_and(|at| now_ms() > at);
        if self.members.is_some() && self.stamp.as_ref() == Some(&stamp) && !expiry_due {
            return;
        }
        let dd = self.data_dir.clone();
        let members = tokio::task::spawn_blocking(move || derive_members(&dd))
            .await
            .unwrap_or(Members {
                policy: AllowPolicy::Unreadable,
                manual: 0,
                denied: 0,
                offered: 0,
                contacts_unreadable: true,
                blocks_unreadable: true,
                expires_next: None,
            });
        // Lock v2, or the key loading after an unlock: the book opens by
        // itself, so it is no fault, and what was read now is not kept (the
        // next round reads it again, E1).
        let held = members.contacts_unreadable && raven_core::contact_book::is_held(&self.data_dir);
        let was = self
            .members
            .as_ref()
            .map(|m| (m.contacts_unreadable, m.blocks_unreadable));
        let now = (members.contacts_unreadable, members.blocks_unreadable);
        if was != Some(now) {
            match now {
                (_, true) => eprintln!(
                    "{LABEL}: the block list cannot be read: nobody is admitted until it is fixed"
                ),
                (true, false) if held => {}
                (true, false) => eprintln!(
                    "{LABEL}: the contact book cannot be read: only the manual allow-list is \
                     admitted until it is fixed"
                ),
                (false, false) => {
                    if was.is_some_and(|(contacts, blocks)| contacts || blocks) {
                        eprintln!("{LABEL}: the contact book can be read again");
                    }
                }
            }
        }
        self.policy_tx.send_replace(members.policy.clone());
        self.members = Some(members);
        self.stamp = (!held).then_some(stamp);
    }

    /// Name what [`externals`] gives now (a change reaches the running relay
    /// at once).
    fn feed(&mut self, settings: &Settings) {
        let relay = lock(&self.sink).clone();
        let names = externals(
            &settings.declared,
            relay.as_ref(),
            crate::p2p::own_routes().as_ref(),
            crate::autoreach::forward_ip().map(IpAddr::V4),
            settings.key.also_443,
            raven_core::p2p_local_candidates_enabled(),
        );
        self.ext_tx.send_if_modified(|held| {
            if *held == names {
                false
            } else {
                *held = names;
                true
            }
        });
    }

    /// The record route hints offer members ([`offer_record`]): only while
    /// offers are live (`offers_live`, [`raven_core::relay_offers_live`]),
    /// the relay is up and its members could be read. `reach` is the p2p
    /// host's reach class.
    fn record(&self, now_ms: u64, reach: &str, offers_live: bool) -> Option<RelayOfferRecord> {
        let settings = self.settings.as_ref().filter(|_| offers_live)?;
        self.running.as_ref()?;
        if !matches!(
            self.members.as_ref().map(|m| &m.policy),
            Some(AllowPolicy::Peers(_))
        ) {
            return None;
        }
        let relay = lock(&self.sink).clone()?;
        offer_record(
            &relay,
            &self.ext_tx.borrow(),
            !settings.declared.is_empty(),
            reach,
            crate::autoreach::forward_ip().is_some(),
            now_ms,
            raven_core::p2p_local_candidates_enabled(),
        )
    }

    /// The last record offered while it may still stand in for one that
    /// cannot be made now: offers are live, the members can be read, the
    /// relay is wanted and runs with the settings it was made with (started
    /// over, the same key and ports), and it is younger than
    /// [`OFFER_GRACE`].
    fn kept_record(&self, offers_live: bool) -> Option<&RelayOfferRecord> {
        let want = self.settings.as_ref().and_then(|s| wanted(s, self.gate));
        let members = matches!(
            self.members.as_ref().map(|m| &m.policy),
            Some(AllowPolicy::Peers(_))
        );
        let runs = self.running.as_ref().map(|r| r.key);
        self.kept
            .as_ref()
            .filter(|k| offers_live && members && want == Some(k.key) && runs == Some(k.key))
            .filter(|k| k.at.elapsed() < OFFER_GRACE)
            .map(|k| &k.record)
    }

    /// [`Self::record`], kept as the last one offered; when none can be made
    /// now, the last one while [`Self::kept_record`] lets it stand (a
    /// restart or a re-home does not withdraw the offer), else none, and the
    /// last one is forgotten.
    fn offered_record(
        &mut self,
        now_ms: u64,
        reach: &str,
        offers_live: bool,
    ) -> Option<RelayOfferRecord> {
        if let Some(record) = self.record(now_ms, reach, offers_live) {
            if let Some(key) = self.running.as_ref().map(|r| r.key) {
                self.kept = Some(Kept {
                    record: record.clone(),
                    key,
                    at: Instant::now(),
                });
            }
            return Some(record);
        }
        let kept = self.kept_record(offers_live).cloned();
        if kept.is_none() {
            self.kept = None;
        }
        kept
    }

    /// [`Self::offered_record`] with the PeerIds it goes to: what [`run`]
    /// publishes for route hints.
    fn offer(&mut self, now_ms: u64, reach: &str, offers_live: bool) -> Option<Offer> {
        let record = self.offered_record(now_ms, reach, offers_live)?;
        let Some(AllowPolicy::Peers(members)) = self.members.as_ref().map(|m| &m.policy) else {
            return None;
        };
        Some(Offer {
            data_dir: self.data_dir.clone(),
            record,
            members: Arc::new(members.clone()),
        })
    }

    /// What status shows. While consent is not given and nothing runs:
    /// `off` with the consent (`unset` or `no`) when the gate is open, so
    /// ash can tell a node that could relay from an older raven-node, and
    /// `None` when it is closed (a release build shows nothing). Consent
    /// given while hide my IP is on for every contact: `hidden` (stopped
    /// until that is off). `reach` is the p2p host's reach class,
    /// `offers_live` [`raven_core::relay_offers_live`].
    fn info(&self, now_ms: u64, reach: &str, offers_live: bool) -> Option<FriendRelayInfo> {
        let settings = self.settings.as_ref()?;
        let stopped = |state: &str| FriendRelayInfo {
            state: state.into(),
            consent: settings.consent.as_str().into(),
            port: listen_port(&settings.key.listen),
            also_443: settings.key.also_443,
            ..FriendRelayInfo::default()
        };
        if !settings.consent.given() && self.running.is_none() {
            return self.gate.then(|| stopped("off"));
        }
        if self.gate && settings.hide_ip && self.running.is_none() {
            return Some(stopped("hidden"));
        }
        let offering = self.record(now_ms, reach, offers_live).is_some()
            || self.kept_record(offers_live).is_some();
        let relay = lock(&self.sink).clone();
        let state = match (&self.running, &relay) {
            (Some(_), Some(_)) => "up",
            (Some(_), None) => "starting",
            (None, _) if !self.gate => "held",
            (None, _) if self.failed.is_some() => "failed",
            (None, _) => "starting",
        };
        let names = self.ext_tx.borrow().clone();
        let is_confirmed = relay.as_ref().is_some_and(|r| confirmed(r, now_ms));
        let listen: Vec<Multiaddr> = relay
            .iter()
            .flat_map(|r| r.listen_addrs.iter().filter_map(|t| t.parse().ok()))
            .collect();
        let members = self.members.as_ref().filter(|_| self.running.is_some());
        let (tcp, _, open_443) = relay_ports(&listen, settings.key.also_443);
        Some(FriendRelayInfo {
            state: state.into(),
            consent: settings.consent.as_str().into(),
            port: tcp.unwrap_or_else(|| listen_port(&settings.key.listen)),
            also_443: settings.key.also_443,
            // What the relay reported, not what was asked for: a 443 it may
            // not open is skipped (best effort).
            port_443_open: (settings.key.also_443 && self.running.is_some() && relay.is_some())
                .then_some(open_443),
            members: members.map_or(0, Members::count),
            manual: members.map_or(0, |m| m.manual),
            denied: members.map_or(0, |m| m.denied),
            counts: relay.as_ref().map(|r| r.counts.clone()).unwrap_or_default(),
            reachable: if names.is_empty() {
                "no_address"
            } else if is_confirmed {
                "confirmed"
            } else {
                "unconfirmed"
            }
            .into(),
            confirmed_age_s: relay
                .as_ref()
                .filter(|r| r.confirmed_at_ms != 0)
                .map(|r| now_ms.saturating_sub(r.confirmed_at_ms) / 1000),
            offering,
            offered_to: members.filter(|_| offering).map_or(0, |m| m.offered),
        })
    }
}

/// The supervised friend relay task of `raven-node service`: `flag` is the
/// consent given at start (`--relay`, `--relay-open`, `RAVEN_P2P_RELAY=1`).
/// It never ends on its own.
pub(crate) async fn run(data_dir: PathBuf, flag: bool) -> Result<(), String> {
    let mut relay = FriendRelay::new(data_dir.clone(), raven_core::friend_relay_live_enabled());
    let lab_listen = raven_core::lab_friend_relay_listen();
    let policy_file = raven_core::policy_path(&data_dir);
    let mut policy: Option<(Option<FileStamp>, NodePolicy)> = None;
    let mut tick = tokio::time::interval(SYNC);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        let restart = tokio::select! {
            biased;
            () = shutdown_notify().notified() => {
                relay.stop().await;
                *lock(&STATE) = None;
                *lock(&OFFER) = None;
                stopped_notify().notify_one();
                return std::future::pending().await;
            }
            () = restart_notify().notified() => true,
            _ = tick.tick() => false,
        };
        // node_policy.json is read again only when it changed.
        let stamp = file_stamp(&policy_file);
        let read = match policy.take() {
            Some((held, p)) if held == stamp => p,
            _ => {
                let dd = data_dir.clone();
                tokio::task::spawn_blocking(move || raven_core::load_policy(&dd))
                    .await
                    .map_err(|e| format!("friend relay blocking join: {e}"))?
            }
        };
        let now = settings(&read, flag, lab_listen);
        policy = Some((stamp, read));
        relay.round(now, restart).await;
        let reach = crate::p2p::status_snapshot()
            .map(|s| s.reach)
            .unwrap_or_default();
        let (at, offers_live) = (now_ms(), raven_core::relay_offers_live());
        *lock(&STATE) = relay.info(at, &reach, offers_live);
        publish_offer(relay.offer(at, &reach, offers_live));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use raven_core::relay_allow::{relay_is_running, RELAY_KEY_FILE};

    fn peer(seed: u8) -> String {
        raven_core::p2p_route::local_peer_id(&raven_core::Identity::from_seed(&[seed; 32]))
    }

    fn pid(seed: u8) -> PeerId {
        peer(seed).parse().unwrap()
    }

    fn a(text: &str) -> Multiaddr {
        text.parse().unwrap()
    }

    fn texts(addrs: &[Multiaddr]) -> Vec<String> {
        addrs.iter().map(|a| a.to_string()).collect()
    }

    fn policy_with(relay_offer: Option<bool>) -> NodePolicy {
        NodePolicy {
            relay_offer,
            ..NodePolicy::default()
        }
    }

    /// Settings that run the relay on `listen` (loopback in tests).
    fn on(listen: SocketAddr) -> Settings {
        settings(&policy_with(Some(true)), false, Some(listen))
    }

    fn loopback(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    /// A port free for TCP and UDP on loopback right now.
    fn free_port() -> u16 {
        loop {
            let tcp = std::net::TcpListener::bind(loopback(0)).unwrap();
            let port = tcp.local_addr().unwrap().port();
            if std::net::UdpSocket::bind(loopback(port)).is_ok() {
                return port;
            }
        }
    }

    /// Until the running relay reports a TCP listener: its PeerId and that
    /// listen address. Lab only.
    async fn up(relay: &FriendRelay) -> (String, String) {
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(st) = lock(&relay.sink).clone() {
                if let Some(tcp) = st.listen_addrs.iter().find(|t| t.contains("/tcp/")) {
                    return (st.peer_id.clone(), tcp.clone());
                }
            }
            assert!(
                relay
                    .running
                    .as_ref()
                    .is_some_and(|r| !r.task.is_finished()),
                "the friend relay ended before it was up"
            );
            assert!(
                std::time::Instant::now() < deadline,
                "the friend relay never came up"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    fn row(key: u8, pinned: bool, p2p: &str) -> serde_json::Value {
        serde_json::json!({ "pub_hex": hex::encode([key; 32]), "pinned": pinned, "p2p": p2p,
            "p2p_via": [] })
    }

    fn write_book(dd: &Path, rows: &[serde_json::Value]) {
        std::fs::write(
            dd.join("contacts.json"),
            serde_json::Value::Array(rows.to_vec()).to_string(),
        )
        .unwrap();
    }

    fn peers(members: &Members) -> HashSet<PeerId> {
        match &members.policy {
            AllowPolicy::Peers(p) => p.clone(),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn members_are_verified_contacts_plus_manual_minus_deny() {
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        // No book, no list: nobody.
        assert_eq!(peers(&derive_members(dd)), HashSet::new());
        write_book(
            dd,
            &[
                // Verified.
                row(1, true, &peer(1)),
                // Not verified.
                row(2, false, &peer(2)),
                // Verified, then blocked.
                row(3, true, &peer(3)),
                // Verified, then denied.
                row(4, true, &peer(4)),
                // Verified, no PeerId.
                row(5, true, ""),
            ],
        );
        let mut blocks = raven_core::chat_history::BlockList::default();
        blocks.block(&hex::encode([3u8; 32]));
        blocks.save(dd).unwrap();
        // A manual peer that is no contact, and the denied contact.
        raven_core::relay_allow::relay_allow(dd, &peer(6), "box").unwrap();
        raven_core::relay_allow::relay_deny(dd, &peer(4), true).unwrap();
        let members = derive_members(dd);
        assert_eq!(peers(&members), HashSet::from([pid(1), pid(6)]));
        assert_eq!((members.manual, members.denied), (1, 1));
        assert!(!members.contacts_unreadable);
        assert_eq!(members.count(), 2);
        // A blocked contact on the manual list (`raven relay allow @name`
        // before the block) is no member: a block holds over the list.
        raven_core::relay_allow::relay_allow(dd, &peer(3), "dana").unwrap();
        let members = derive_members(dd);
        assert_eq!(peers(&members), HashSet::from([pid(1), pid(6)]));
        assert_eq!(members.manual, 2);
        // Unblocked again: the manual entry admits it.
        raven_core::chat_history::BlockList::default()
            .save(dd)
            .unwrap();
        assert_eq!(
            peers(&derive_members(dd)),
            HashSet::from([pid(1), pid(3), pid(6)])
        );
        let mut blocks = raven_core::chat_history::BlockList::default();
        blocks.block(&hex::encode([3u8; 32]));
        blocks.save(dd).unwrap();
        raven_core::relay_allow::relay_deny(dd, &peer(3), false).unwrap();
        // A denied manual peer is no member either.
        raven_core::relay_allow::relay_deny(dd, &peer(6), true).unwrap();
        let members = derive_members(dd);
        assert_eq!(peers(&members), HashSet::from([pid(1)]));
        assert_eq!((members.manual, members.denied), (0, 2));
    }

    /// A learned PeerId lives only in route hints, which a block forgets
    /// (ash `forget_outbox_routes`). A contact allowed by hand by such a
    /// PeerId (`raven relay allow @name`, which records the contact) stays
    /// no member once blocked, and so does one allowed by that PeerId alone
    /// before: the forget tags its entry with the contact first
    /// (`relay_allow::tag_contact`). Unblocked, the entry admits it again.
    #[test]
    fn a_blocked_contact_allowed_by_its_learned_peer_id_is_no_member() {
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        let (gus, hal) = (hex::encode([7u8; 32]), hex::encode([8u8; 32]));
        // Verified, no p2p= in the book: their PeerIds were learned.
        write_book(dd, &[row(7, true, ""), row(8, true, "")]);
        let learned = |key: &str, seed: u8| {
            let now = crate::now_ms();
            serde_json::json!({
                "pub_hex": key,
                "generation": 7,
                "received_at_ms": now,
                "expires_at_ms": now + 3_600_000,
                "via": "p2p",
                "peer_id": peer(seed),
                "peer_id_proven": true,
            })
        };
        let routes = dd.join(raven_core::learned_routes::LEARNED_ROUTES_FILE);
        std::fs::write(
            &routes,
            serde_json::to_vec(&[learned(&gus, 7), learned(&hal, 8)]).unwrap(),
        )
        .unwrap();
        // `raven relay allow @gus` (it names Gus); Hal by his PeerId alone,
        // as before this was recorded.
        raven_core::relay_allow::relay_allow_contact(dd, &peer(7), "gus", &gus).unwrap();
        raven_core::relay_allow::relay_allow(dd, &peer(8), "hal").unwrap();
        assert_eq!(peers(&derive_members(dd)), HashSet::from([pid(7), pid(8)]));
        // Both blocked: the block forgets their routes, after the tag.
        let mut blocks = raven_core::chat_history::BlockList::default();
        for key in [&gus, &hal] {
            let ids = raven_core::outbox::contact_p2p_peer_ids(dd, key);
            raven_core::relay_allow::tag_contact(dd, key, &ids).unwrap();
            blocks.block(key);
        }
        blocks.save(dd).unwrap();
        std::fs::remove_file(&routes).unwrap();
        assert_eq!(
            raven_core::outbox::contact_p2p_peer_ids(dd, &gus),
            Vec::<String>::new()
        );
        let members = derive_members(dd);
        assert_eq!(peers(&members), HashSet::new());
        assert_eq!(members.manual, 2);
        // Gus unblocked: his entry admits him again.
        blocks.unblock(&gus);
        blocks.save(dd).unwrap();
        assert_eq!(peers(&derive_members(dd)), HashSet::from([pid(7)]));
    }

    /// A manual entry whose `expires_ms` has passed (a relay schedule's old
    /// PeerId) is no member, as on a dedicated relay, and the members are
    /// read again when the next one expires.
    #[test]
    fn expired_manual_entries_are_no_members() {
        let now = now_ms();
        let entry = |seed: u8, expires_ms: Option<u64>| RelayAllowEntry {
            peer_id: peer(seed),
            label: String::new(),
            contact: String::new(),
            expires_ms,
        };
        let list = RelayAllowList {
            peers: vec![
                entry(1, None),
                entry(2, Some(now - 1)),
                entry(3, Some(now + 3_600_000)),
                entry(4, Some(now + 7_200_000)),
            ],
            ..RelayAllowList::default()
        };
        let members = members_from(Ok(Vec::new()), Ok(Some(list)), Ok(BlockedP2p::default()));
        assert_eq!(peers(&members), HashSet::from([pid(1), pid(3), pid(4)]));
        assert_eq!(members.manual, 3);
        assert_eq!(members.expires_next, Some(now + 3_600_000));
        let members = members_from(Ok(Vec::new()), Ok(None), Ok(BlockedP2p::default()));
        assert_eq!(members.expires_next, None);
    }

    /// Phase 4: the friend relay follows a rotating contact's schedule. Its
    /// other PeerIds (the ones the p2p peer gate admits,
    /// [`P2pGatePeer::rotated`]) are members with it; a contact this node
    /// hides its IP from is none under any of them, a denied or blocked one
    /// is taken out alone, and a new schedule makes the members be read
    /// again.
    #[test]
    fn friend_relay_allow_list_follows_a_contacts_schedule() {
        let rotating = |seed: u8, rotated: &[u8], hidden: bool| P2pGatePeer {
            peer_id: peer(seed),
            relays: Vec::new(),
            hidden,
            learned: false,
            proven: true,
            rotated: rotated.iter().map(|n| peer(*n)).collect(),
        };
        let members = members_from(
            Ok(vec![
                rotating(1, &[2, 3, 4], false),
                rotating(5, &[6], true),
            ]),
            Ok(None),
            Ok(BlockedP2p::default()),
        );
        assert_eq!(
            peers(&members),
            HashSet::from([pid(1), pid(2), pid(3), pid(4)])
        );
        assert_eq!(members.offered, 1, "offered once, under its card PeerId");
        // One of its epochs denied, another named by a block: those alone go.
        let deny = RelayAllowList {
            deny: vec![RelayAllowEntry {
                peer_id: peer(3),
                label: String::new(),
                contact: String::new(),
                expires_ms: None,
            }],
            ..RelayAllowList::default()
        };
        let blocked = BlockedP2p {
            keys: Vec::new(),
            peer_ids: vec![peer(4)],
        };
        let members = members_from(
            Ok(vec![rotating(1, &[2, 3, 4], false)]),
            Ok(Some(deny)),
            Ok(blocked),
        );
        assert_eq!(peers(&members), HashSet::from([pid(1), pid(2)]));
        // A contact's schedule arriving is a reason to read them again.
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        let before = member_stamp(dd);
        let id = raven_core::Identity::from_seed(&[0x41; 32]);
        let s = raven_core::peer_rotation::ContactSchedule::from_announced(
            &raven_core::peer_rotation::announced_schedule(&id, Some((40, false)), 600),
            1_800_000_000_000,
        );
        raven_core::peer_rotation::save_schedule(dd, &hex::encode([0x41; 32]), &s).unwrap();
        assert_ne!(member_stamp(dd), before);
    }

    /// Review D-5: a contact denied by name (its deny entry names it,
    /// [`raven_core::relay_allow::relay_deny_contact`]) is turned away
    /// under every PeerId it is known by: its card's, and every epoch its
    /// schedule names, the ones the clock reaches after its next boundary
    /// too. Another contact stays a member. Denying the one PeerId alone
    /// (as before the fix) left its epochs admitted.
    #[test]
    fn a_denied_contact_is_turned_away_under_every_peer_id() {
        use raven_core::peer_rotation as pr;
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        let bob = raven_core::Identity::from_seed(&[0x42; 32]);
        let bob_hex = hex::encode(bob.public_key_bytes());
        let legacy = raven_core::p2p_route::active_peer_id(&bob, None);
        std::fs::write(
            dd.join(raven_core::contact_book::CONTACTS_FILE),
            serde_json::json!([
                { "pub_hex": bob_hex, "pinned": true, "p2p": legacy, "p2p_via": [] },
                { "pub_hex": hex::encode([0x43; 32]), "pinned": true, "p2p": peer(9),
                  "p2p_via": [] },
            ])
            .to_string(),
        )
        .unwrap();
        let len = 600u64;
        let now = now_ms();
        let schedule = pr::ContactSchedule::from_announced(
            &pr::announced_schedule(&bob, Some((40, false)), len),
            now,
        );
        pr::save_schedule(dd, &bob_hex, &schedule).unwrap();
        raven_core::relay_allow::relay_deny_contact(dd, &legacy, &bob_hex).unwrap();
        let manual = load_relay_allow(dd);
        let denied = denied_contacts_p2p(dd, &manual);
        for later in [0, len, 2 * len] {
            let at = now / 1000 + later;
            let bob_ids = pr::admitted_peer_ids(Some(&legacy), None, Some(&schedule), at);
            assert!(bob_ids.len() > 2, "{bob_ids:?}");
            let gate = || {
                Ok(vec![
                    P2pGatePeer {
                        peer_id: legacy.clone(),
                        relays: Vec::new(),
                        hidden: false,
                        learned: false,
                        proven: true,
                        rotated: bob_ids[1..].to_vec(),
                    },
                    P2pGatePeer {
                        peer_id: peer(9),
                        relays: Vec::new(),
                        hidden: false,
                        learned: false,
                        proven: true,
                        rotated: Vec::new(),
                    },
                ])
            };
            let members =
                members_with_denied(gate(), manual.clone(), Ok(BlockedP2p::default()), &denied);
            let admitted = peers(&members);
            for id in &bob_ids {
                assert!(
                    !admitted.contains(&id.parse().unwrap()),
                    "{id} at +{later}s"
                );
            }
            assert_eq!(admitted, HashSet::from([pid(9)]));
            // The PeerId alone: its epochs stayed members.
            let one = members_from(gate(), manual.clone(), Ok(BlockedP2p::default()));
            assert_eq!(peers(&one).len(), bob_ids.len());
        }
    }

    #[test]
    fn an_unproven_learned_peer_id_is_not_a_member() {
        let gate_peer = |seed: u8, learned: bool, proven: bool| P2pGatePeer {
            peer_id: peer(seed),
            relays: Vec::new(),
            hidden: !proven,
            learned,
            proven,
            rotated: Vec::new(),
        };
        let members = members_from(
            Ok(vec![
                // The book's PeerId.
                gate_peer(1, false, true),
                // Learned from route hints, not proved by any link yet.
                gate_peer(2, true, false),
                // Learned and proved.
                gate_peer(3, true, true),
            ]),
            Ok(None),
            Ok(BlockedP2p::default()),
        );
        assert_eq!(peers(&members), HashSet::from([pid(1), pid(3)]));
        // A contact this node hides its IP from is no member by itself (the
        // relay runs at this node's IP), unless it is allowed by hand.
        let hidden = P2pGatePeer {
            hidden: true,
            ..gate_peer(4, true, true)
        };
        let members = members_from(
            Ok(vec![hidden.clone()]),
            Ok(None),
            Ok(BlockedP2p::default()),
        );
        assert_eq!(peers(&members), HashSet::new());
        let by_hand = RelayAllowList {
            peers: vec![RelayAllowEntry {
                peer_id: peer(4),
                label: String::new(),
                contact: String::new(),
                expires_ms: None,
            }],
            ..RelayAllowList::default()
        };
        let members = members_from(
            Ok(vec![hidden]),
            Ok(Some(by_hand)),
            Ok(BlockedP2p::default()),
        );
        assert_eq!(peers(&members), HashSet::from([pid(4)]));
    }

    /// E1 (three machines): after Lock v2 and Unlock the friend relay said
    /// the contact book cannot be read and never admitted a contact again.
    /// A book held while the key loads (Lock v2, the unlock's key loader) is
    /// read again once it opens.
    #[tokio::test]
    async fn a_book_held_by_the_lock_is_read_again_once_it_opens() {
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        write_book(dd, &[row(1, true, &peer(1))]);
        raven_core::contact_book::enable_process_cache(dd);
        let mut relay = FriendRelay::new(dd.to_path_buf(), true);
        relay.refresh_members().await;
        assert_eq!(
            peers(relay.members.as_ref().unwrap()),
            HashSet::from([pid(1)])
        );
        // Lock v2, then the unlock's loader holds it while the key loads:
        // nothing read from a held book is kept.
        raven_core::contact_book::hold(dd, "locked");
        relay.refresh_members().await;
        assert!(relay.members.as_ref().unwrap().contacts_unreadable);
        assert_eq!(relay.stamp, None, "a held book is read again next round");
        raven_core::contact_book::hold(dd, "the at-rest key is loading");
        let mut after = FriendRelay::new(dd.to_path_buf(), true);
        after.refresh_members().await;
        relay.refresh_members().await;
        assert!(after.members.as_ref().unwrap().contacts_unreadable);
        // The key is back: both read the book again.
        raven_core::contact_book::enable_process_cache(dd);
        for r in [&mut relay, &mut after] {
            r.refresh_members().await;
            let members = r.members.as_ref().unwrap();
            assert!(!members.contacts_unreadable);
            assert_eq!(peers(members), HashSet::from([pid(1)]));
        }
    }

    #[test]
    fn unreadable_contacts_keep_manual_only_and_an_unreadable_manual_or_block_list_admits_nobody() {
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        write_book(dd, &[row(1, true, &peer(1))]);
        raven_core::relay_allow::relay_allow(dd, &peer(6), "box").unwrap();
        assert_eq!(peers(&derive_members(dd)), HashSet::from([pid(1), pid(6)]));
        // A broken contact book: the manual list only.
        std::fs::write(dd.join("contacts.json"), b"[{").unwrap();
        let members = derive_members(dd);
        assert_eq!(peers(&members), HashSet::from([pid(6)]));
        assert!(members.contacts_unreadable);
        // A broken block list: nobody, not even the manual list (a blocked
        // contact on it could not be told apart).
        write_book(dd, &[row(1, true, &peer(1))]);
        std::fs::write(raven_core::chat_history::blocked_path(dd), b"{broken").unwrap();
        let members = derive_members(dd);
        assert_eq!(members.policy, AllowPolicy::Unreadable);
        assert_eq!(members.count(), 0);
        assert!(members.contacts_unreadable && members.blocks_unreadable);
        std::fs::remove_file(raven_core::chat_history::blocked_path(dd)).unwrap();
        assert_eq!(peers(&derive_members(dd)), HashSet::from([pid(1), pid(6)]));
        // A broken manual list: nobody, contacts or not.
        std::fs::write(dd.join(RELAY_ALLOW_FILE), b"{broken").unwrap();
        let members = derive_members(dd);
        assert_eq!(members.policy, AllowPolicy::Unreadable);
        assert_eq!(members.count(), 0);
        let none = members_from(
            Err("unreadable".into()),
            Err("unreadable".into()),
            Ok(BlockedP2p::default()),
        );
        assert_eq!(none.policy, AllowPolicy::Unreadable);
    }

    #[tokio::test]
    async fn consent_and_gate_decide_whether_the_relay_runs() {
        let cases = [
            (None, false, Consent::Unset),
            (Some(false), false, Consent::No),
            (Some(true), false, Consent::Yes),
            (None, true, Consent::Flag),
            (Some(true), true, Consent::Flag),
            // A saved "no" (`raven relay offer off`) wins over the start
            // flag: offer off stops a relay the service was started with.
            (Some(false), true, Consent::No),
        ];
        for (relay_offer, flag, consent) in cases {
            let s = settings(&policy_with(relay_offer), flag, None);
            assert_eq!(s.consent, consent);
            assert_eq!(wanted(&s, false), None, "{consent:?}: gate closed");
            assert_eq!(
                wanted(&s, true).is_some(),
                consent.given(),
                "{consent:?}: gate open"
            );
            // Hide my IP for everyone: never, whatever the consent.
            let hidden = NodePolicy {
                hide_ip: true,
                ..policy_with(relay_offer)
            };
            let s = settings(&hidden, flag, None);
            assert_eq!(s.consent, consent);
            assert_eq!(wanted(&s, true), None, "{consent:?}: hide my IP");
        }
        // The gate closed: nothing starts; consent shows as held (the hold
        // line is written once, until consent goes away).
        let dir = tempfile::tempdir().unwrap();
        let mut closed = FriendRelay::new(dir.path().to_path_buf(), false);
        for restart in [false, true, false] {
            let s = settings(&policy_with(Some(true)), false, None);
            assert_eq!(closed.round(s, restart).await, Round::default());
            assert!(closed.running.is_none() && closed.hold_logged);
            let info = closed.info(now_ms(), "public", true).unwrap();
            assert_eq!(
                (info.state.as_str(), info.consent.as_str()),
                ("held", "yes")
            );
            assert!(!info.offering);
        }
        closed
            .round(settings(&policy_with(None), false, None), false)
            .await;
        assert!(!closed.hold_logged);
        assert_eq!(closed.info(now_ms(), "public", true), None);
        // The gate open and no consent: it idles, and status says `off`
        // with the consent (ash then suggests or respects it).
        let mut idle = FriendRelay::new(dir.path().to_path_buf(), true);
        for (relay_offer, consent) in [(None, "unset"), (Some(false), "no")] {
            let s = settings(&policy_with(relay_offer), false, None);
            assert_eq!(idle.round(s, false).await, Round::default());
            assert!(idle.running.is_none() && !idle.hold_logged);
            assert_eq!(
                idle.info(now_ms(), "public", true),
                Some(FriendRelayInfo {
                    state: "off".into(),
                    consent: consent.into(),
                    port: FRIEND_RELAY_PORT,
                    ..FriendRelayInfo::default()
                }),
                "{relay_offer:?}"
            );
        }
        // Consent given while hide my IP is on for everyone: nothing starts,
        // and status says why.
        let mut hidden = FriendRelay::new(dir.path().to_path_buf(), true);
        for (relay_offer, flag, consent) in [(Some(true), false, "yes"), (None, true, "flag")] {
            let policy = NodePolicy {
                hide_ip: true,
                ..policy_with(relay_offer)
            };
            let s = settings(&policy, flag, None);
            assert_eq!(hidden.round(s, false).await, Round::default());
            assert!(hidden.running.is_none());
            let info = hidden.info(now_ms(), "public", true).unwrap();
            assert_eq!(
                (info.state.as_str(), info.consent.as_str(), info.port),
                ("hidden", consent, FRIEND_RELAY_PORT)
            );
            assert!(!info.offering);
        }
        // Nothing was created: no relay folder.
        assert!(!friend_relay_dir(dir.path()).exists());
    }

    /// E1: a run that fails in the seconds after an unlock (the relay the
    /// lock stopped may hold its folder or ports a moment longer) is tried
    /// again at the next round, with no line and no failure; later it is a
    /// failure, with its backoff.
    #[tokio::test]
    async fn a_failure_right_after_an_unlock_is_tried_again_quietly() {
        let dir = tempfile::tempdir().unwrap();
        let mut relay = FriendRelay::new(dir.path().to_path_buf(), true);
        let key = settings(&policy_with(Some(true)), false, None).key;
        let failing = || Running {
            key,
            stop: None,
            task: tokio::spawn(async {
                Err(RelayExit::Folder("Access is denied. (os error 5)".into()))
            }),
            started: Instant::now(),
        };
        crate::lock::unlocked_for_test(Duration::from_secs(1));
        relay.failed(failing()).await;
        assert_eq!(relay.failed, None);
        assert_eq!(relay.retry_at, None, "due at the next round");
        assert_eq!(relay.backoff, RESTART_BACKOFF_MIN);
        crate::lock::unlocked_for_test(Duration::from_secs(6));
        relay.failed(failing()).await;
        assert_eq!(relay.failed, Some(key));
        assert!(relay.retry_at.is_some());
        assert_eq!(relay.backoff, RESTART_BACKOFF_MIN * 2);
    }

    /// `raven node hide-ip on` stops a running relay (its users would see
    /// this computer's IP), and `off` starts it again. Lab only.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn hide_ip_for_everyone_stops_a_running_relay_until_it_is_off() {
        if !raven_core::p2p_live_enabled() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let listen = loopback(0);
        let with = |hide_ip: bool, relay_offer: Option<bool>, flag: bool| {
            let policy = NodePolicy {
                hide_ip,
                ..policy_with(relay_offer)
            };
            settings(&policy, flag, Some(listen))
        };
        let mut relay = FriendRelay::new(dir.path().to_path_buf(), true);
        // Consent from the start flag: running.
        assert!(relay.round(with(false, None, true), false).await.started);
        up(&relay).await;
        let round = relay.round(with(true, None, true), false).await;
        assert_eq!(
            round,
            Round {
                stopped: Some(Stopped::Clean),
                started: false
            }
        );
        assert_eq!(
            relay.info(now_ms(), "", true).unwrap().state.as_str(),
            "hidden"
        );
        assert!(relay.round(with(false, None, true), false).await.started);
        up(&relay).await;
        // `raven relay offer off` wins over the start flag.
        let round = relay.round(with(false, Some(false), true), false).await;
        assert_eq!(round.stopped, Some(Stopped::Clean));
        let off = relay.info(now_ms(), "", true).unwrap();
        assert_eq!((off.state.as_str(), off.consent.as_str()), ("off", "no"));
    }

    /// Status reports whether the TCP 443 listener is open, as the running
    /// relay reported it, not that it was asked for: a 443 this user may not
    /// open (a Linux user service) is skipped, and status says so.
    #[tokio::test]
    async fn info_says_whether_the_443_listener_is_open() {
        let dir = tempfile::tempdir().unwrap();
        let mut relay = FriendRelay::new(dir.path().to_path_buf(), true);
        let policy = NodePolicy {
            relay_also_443: true,
            ..policy_with(Some(true))
        };
        let s = settings(&policy, false, None);
        assert!(s.key.also_443);
        relay.running = Some(Running {
            key: s.key,
            stop: None,
            task: tokio::spawn(std::future::pending()),
            started: Instant::now(),
        });
        relay.settings = Some(s);
        let open_443 = |relay: &FriendRelay| relay.info(now_ms(), "", false).unwrap().port_443_open;
        // Not reported yet: unknown.
        assert_eq!(open_443(&relay), None);
        let reported = |listen: &[&str]| RelayStatusFile {
            version: 1,
            listen_addrs: listen.iter().map(|t| t.to_string()).collect(),
            ..RelayStatusFile::default()
        };
        *lock(&relay.sink) = Some(reported(&[
            "/ip4/192.168.1.5/tcp/7427",
            "/ip4/192.168.1.5/udp/7427/quic-v1",
        ]));
        let info = relay.info(now_ms(), "", false).unwrap();
        assert_eq!(
            (
                info.state.as_str(),
                info.port,
                info.also_443,
                info.port_443_open
            ),
            ("up", 7427, true, Some(false)),
            "asked for, skipped"
        );
        *lock(&relay.sink) = Some(reported(&[
            "/ip4/192.168.1.5/tcp/7427",
            "/ip4/192.168.1.5/udp/7427/quic-v1",
            "/ip4/192.168.1.5/tcp/443",
        ]));
        assert_eq!(open_443(&relay), Some(true));
        // Not asked for: nothing to say.
        let mut s = relay.settings.clone().unwrap();
        s.key.also_443 = false;
        relay.settings = Some(s);
        assert_eq!(open_443(&relay), None);
        relay.running.take().unwrap().task.abort();
    }

    /// A relay offered on CONFIRMED alone (nothing declared) keeps its offer
    /// while it restarts (a wake, a network change) or the p2p host
    /// re-homes and names no address for a moment: members do not drop it.
    /// A real withdrawal ends the offer at once; past [`OFFER_GRACE`] it
    /// ends too.
    #[tokio::test]
    async fn the_offer_outlives_a_restart_but_not_a_withdrawal() {
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        let now = now_ms();
        let s = settings(&policy_with(Some(true)), false, None);
        let key = s.key;
        let fake_run = || Running {
            key,
            stop: None,
            task: tokio::spawn(std::future::pending()),
            started: Instant::now(),
        };
        let mut relay = FriendRelay::new(dd.to_path_buf(), true);
        relay.settings = Some(s.clone());
        relay.members = Some(members_from(
            Ok(vec![P2pGatePeer {
                peer_id: peer(1),
                relays: Vec::new(),
                hidden: false,
                learned: false,
                proven: true,
                rotated: Vec::new(),
            }]),
            Ok(None),
            Ok(BlockedP2p::default()),
        ));
        let up = |relay: &mut FriendRelay| {
            relay.running = Some(fake_run());
            *lock(&relay.sink) = Some(RelayStatusFile {
                version: 1,
                peer_id: peer(0x63),
                confirmed_at_ms: now - 60_000,
                ..RelayStatusFile::default()
            });
            relay.ext_tx.send_replace(vec![a("/ip4/11.0.2.7/tcp/7427")]);
        };
        let down = |relay: &mut FriendRelay| {
            if let Some(run) = relay.running.take() {
                run.task.abort();
            }
            relay.clear();
        };
        // Started over with the same settings, not reported yet.
        let restarted = |relay: &mut FriendRelay| {
            down(relay);
            relay.running = Some(fake_run());
        };
        up(&mut relay);
        // The p2p host re-homed: its reach is not known yet.
        let first = relay.offer(now, "unknown", true).expect("confirmed");
        assert_eq!(first.record.flags, FLAG_AUTONAT | FLAG_CONFIRMED);
        // The relay is started over (a wake, a network change): the offer
        // stands.
        restarted(&mut relay);
        assert_eq!(relay.record(now, "unknown", true), None);
        assert_eq!(relay.offer(now, "unknown", true), Some(first.clone()));
        assert!(relay.info(now, "unknown", true).unwrap().offering);
        // Reported again: the record is made again.
        up(&mut relay);
        assert_eq!(relay.offer(now, "unknown", true), Some(first.clone()));
        // The address is gone for a moment (the host re-homed): kept.
        relay.ext_tx.send_replace(Vec::new());
        assert_eq!(relay.offer(now, "unknown", true), Some(first.clone()));
        // Past the grace: withdrawn.
        relay.kept.as_mut().unwrap().at = Instant::now()
            .checked_sub(OFFER_GRACE)
            .expect("an instant that old");
        assert_eq!(relay.offer(now, "unknown", true), None);
        assert!(relay.kept.is_none());
        // A relay that does not run (it failed to start) is not offered.
        up(&mut relay);
        assert!(relay.offer(now, "unknown", true).is_some());
        down(&mut relay);
        assert_eq!(relay.offer(now, "unknown", true), None, "not running");
        // A withdrawal ends it at once: consent, hide my IP, offers off,
        // other settings, members unreadable.
        let withdrawals: [&dyn Fn(&mut FriendRelay); 5] = [
            &|r: &mut FriendRelay| {
                r.settings = Some(settings(&policy_with(Some(false)), false, None))
            },
            &|r: &mut FriendRelay| {
                let hidden = NodePolicy {
                    hide_ip: true,
                    ..policy_with(Some(true))
                };
                r.settings = Some(settings(&hidden, false, None));
            },
            &|r: &mut FriendRelay| r.gate = false,
            &|r: &mut FriendRelay| {
                let moved = NodePolicy {
                    relay_port: Some(7444),
                    ..policy_with(Some(true))
                };
                r.settings = Some(settings(&moved, false, None));
            },
            &|r: &mut FriendRelay| r.members.as_mut().unwrap().policy = AllowPolicy::Unreadable,
        ];
        for (n, withdraw) in withdrawals.iter().enumerate() {
            let mut relay = FriendRelay::new(dd.to_path_buf(), true);
            relay.settings = Some(s.clone());
            relay.members = Some(members_from(
                Ok(Vec::new()),
                Ok(None),
                Ok(BlockedP2p::default()),
            ));
            up(&mut relay);
            assert!(relay.offer(now, "unknown", true).is_some(), "{n}");
            restarted(&mut relay);
            withdraw(&mut relay);
            assert_eq!(relay.offer(now, "unknown", true), None, "{n}");
        }
        let mut relay = FriendRelay::new(dd.to_path_buf(), true);
        relay.settings = Some(s);
        relay.members = Some(members_from(
            Ok(Vec::new()),
            Ok(None),
            Ok(BlockedP2p::default()),
        ));
        up(&mut relay);
        assert!(relay.offer(now, "unknown", true).is_some());
        assert_eq!(relay.offer(now, "unknown", false), None, "offers off");
        down(&mut relay);
    }

    #[test]
    fn settings_follow_the_policy() {
        let s = settings(&NodePolicy::default(), false, None);
        assert_eq!(s.key.listen, P2pListen::All(FRIEND_RELAY_PORT));
        assert!(!s.key.also_443 && !s.key.upnp);
        let policy = NodePolicy {
            relay_port: Some(7443),
            relay_also_443: true,
            upnp: Some(true),
            relay_external: vec![
                "/dns4/home.example.net/tcp/7427".into(),
                "/dns4/home.example.net/tcp/7427".into(),
                "/ip4/203.0.113.7/tcp/7427/p2p/x".into(),
                "not an address".into(),
                "/ip4/203.0.113.7/udp/7427/quic-v1".into(),
                "/ip4/203.0.113.7/tcp/443".into(),
                "/ip6/2001:db8::7/tcp/7427".into(),
                "/ip4/203.0.113.8/tcp/7427".into(),
            ],
            ..NodePolicy::default()
        };
        let s = settings(&policy, false, None);
        assert_eq!(s.key.listen, P2pListen::All(7443));
        assert!(s.key.also_443 && s.key.upnp);
        assert_eq!(
            texts(&s.declared),
            [
                "/dns4/home.example.net/tcp/7427",
                "/ip4/203.0.113.7/udp/7427/quic-v1",
                "/ip4/203.0.113.7/tcp/443",
                "/ip6/2001:db8::7/tcp/7427",
            ]
        );
        // Two that are not a host and a transport, one past the limit.
        assert_eq!(s.ignored, 3);
        // The lab listen address wins over the port; 443 as the port needs
        // no second listener.
        let s = settings(&policy, false, Some(loopback(0)));
        assert_eq!(s.key.listen, P2pListen::One(loopback(0)));
        let own_443 = NodePolicy {
            relay_port: Some(443),
            ..policy
        };
        assert!(!settings(&own_443, false, None).key.also_443);
    }

    #[test]
    fn the_relay_key_is_its_own() {
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        let policy = NodePolicy {
            relay_also_443: true,
            ..policy_with(Some(true))
        };
        let s = settings(&policy, false, None);
        let relay = FriendRelay::new(dd.to_path_buf(), true);
        let cmd = relay.command(s.key, &s.declared);
        // Its own folder inside the profile, its own key there, the
        // friends' limits, an AutoNAT server, members from memory, 443 best
        // effort.
        assert_eq!(cmd.data_dir, dd.join("friend_relay"));
        assert_eq!(cmd.label, LABEL);
        assert!(!cmd.open && cmd.autonat_server && cmd.extra_best_effort);
        assert!(matches!(cmd.policy, PolicySource::Shared(_)));
        assert_eq!(cmd.listen, P2pListen::All(FRIEND_RELAY_PORT));
        assert_eq!(
            cmd.also_tcp,
            [ExtraTcp {
                local: 443,
                public: 443
            }]
        );
        assert_eq!(cmd.limits, RelayLimits::friends());
        // The key the relay makes is not the profile's PeerId, and lives
        // owner-only in friend_relay/, never in the profile itself.
        std::fs::write(dd.join("contacts.json"), b"[]").unwrap();
        let profile_peer = peer(7);
        raven_core::paths::ensure_private_dir(&cmd.data_dir).unwrap();
        let key = crate::relay::load_or_create_relay_key(&cmd.data_dir).unwrap();
        let relay_peer = key.public().to_peer_id().to_string();
        assert_ne!(relay_peer, profile_peer);
        assert!(cmd.data_dir.join(RELAY_KEY_FILE).is_file());
        assert!(!dd.join(RELAY_KEY_FILE).exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(cmd.data_dir.join(RELAY_KEY_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_running_relay_uses_its_own_key() {
        if !raven_core::p2p_live_enabled() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        // A profile folder: the relay runs in its sub-folder all the same.
        std::fs::write(dd.join("contacts.json"), b"[]").unwrap();
        let mut relay = FriendRelay::new(dd.to_path_buf(), true);
        let round = relay.round(on(loopback(0)), false).await;
        assert!(round.started);
        let (relay_peer, _) = up(&relay).await;
        let key = crate::relay::load_or_create_relay_key(&friend_relay_dir(dd)).unwrap();
        assert_eq!(relay_peer, key.public().to_peer_id().to_string());
        assert!(!dd.join(RELAY_KEY_FILE).exists());
        assert_eq!(relay.stop().await, Some(Stopped::Clean));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_port_change_restarts_the_relay_with_the_same_key() {
        if !raven_core::p2p_live_enabled() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let mut relay = FriendRelay::new(dir.path().to_path_buf(), true);
        // First the OS picks the port, then a fixed one.
        assert!(relay.round(on(loopback(0)), false).await.started);
        let (peer_before, tcp) = up(&relay).await;
        let second = loop {
            let port = free_port();
            if !tcp.ends_with(&format!("/tcp/{port}")) {
                break port;
            }
        };
        // The same settings: nothing happens.
        assert_eq!(relay.round(on(loopback(0)), false).await, Round::default());
        // Another port: a clean stop, then a start with the same key.
        let round = relay.round(on(loopback(second)), false).await;
        assert_eq!(
            round,
            Round {
                stopped: Some(Stopped::Clean),
                started: true
            }
        );
        let (peer_after, tcp) = up(&relay).await;
        assert!(tcp.ends_with(&format!("/tcp/{second}")), "{tcp}");
        assert_eq!(peer_after, peer_before);
        let info = relay.info(now_ms(), "", false).unwrap();
        assert_eq!((info.state.as_str(), info.port), ("up", second));
        assert_eq!(relay.stop().await, Some(Stopped::Clean));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn network_changed_restarts_a_running_relay_only() {
        // The hook wakes the task.
        network_changed();
        tokio::time::timeout(Duration::from_secs(1), restart_notify().notified())
            .await
            .expect("woken");
        // Nothing runs: a network change starts nothing, gate open or not.
        let dir = tempfile::tempdir().unwrap();
        for (gate, relay_offer) in [(true, None), (false, Some(true))] {
            let mut relay = FriendRelay::new(dir.path().to_path_buf(), gate);
            let s = settings(&policy_with(relay_offer), false, None);
            assert_eq!(relay.round(s, true).await, Round::default());
            assert!(relay.running.is_none());
        }
        if !raven_core::p2p_live_enabled() {
            return;
        }
        // A running relay starts over, with the same key.
        let mut relay = FriendRelay::new(dir.path().to_path_buf(), true);
        let listen = loopback(0);
        assert!(relay.round(on(listen), false).await.started);
        let (peer_before, _) = up(&relay).await;
        let round = relay.round(on(listen), true).await;
        assert_eq!(
            round,
            Round {
                stopped: Some(Stopped::Clean),
                started: true
            }
        );
        let (peer_after, _) = up(&relay).await;
        assert_eq!(peer_after, peer_before);
        assert_eq!(relay.round(on(listen), false).await, Round::default());
        assert_eq!(relay.stop().await, Some(Stopped::Clean));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stop_is_graceful() {
        if !raven_core::p2p_live_enabled() {
            return;
        }
        use futures::StreamExt;
        use raven_swarm::gate::{GateHandle, PeerClass};
        use raven_swarm::host::{build_endpoint_swarm, EndpointConfig, HostGate};
        use raven_swarm::libp2p::identity::Keypair;
        use raven_swarm::libp2p::swarm::dial_opts::DialOpts;
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        // A member (on the manual list), connected when consent goes away.
        let member_key = Keypair::ed25519_from_bytes([5u8; 32]).unwrap();
        let member = member_key.public().to_peer_id();
        raven_core::relay_allow::relay_allow(dd, &member.to_string(), "m").unwrap();
        let mut relay = FriendRelay::new(dd.to_path_buf(), true);
        assert!(relay.round(on(loopback(0)), false).await.started);
        let (relay_peer, tcp) = up(&relay).await;
        assert_eq!(
            peers(relay.members.as_ref().unwrap()),
            HashSet::from([member])
        );
        let relay_peer: PeerId = relay_peer.parse().unwrap();
        let gate = GateHandle::default();
        gate.replace(
            std::collections::HashMap::from([(relay_peer, PeerClass::OWN_RELAY)]),
            false,
            std::time::Instant::now(),
        );
        let mut client = build_endpoint_swarm(
            &HostGate::open(true).unwrap(),
            member_key,
            EndpointConfig {
                gate,
                ..EndpointConfig::default()
            },
        )
        .unwrap();
        client
            .dial(
                DialOpts::peer_id(relay_peer)
                    .addresses(vec![tcp.parse().unwrap()])
                    .build(),
            )
            .unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while !client.is_connected(&relay_peer) {
            tokio::time::timeout_at(deadline, client.select_next_some())
                .await
                .expect("the member connects");
        }
        // Kept (the relay admits its member) while the client is driven.
        let kept = tokio::time::timeout(Duration::from_millis(500), async {
            while client.is_connected(&relay_peer) {
                client.select_next_some().await;
            }
        })
        .await;
        assert!(kept.is_err(), "the member was disconnected");
        // Consent withdrawn: the relay is stopped, not aborted.
        let asked = std::time::Instant::now();
        let round = relay
            .round(settings(&policy_with(Some(false)), false, None), false)
            .await;
        assert_eq!(
            round,
            Round {
                stopped: Some(Stopped::Clean),
                started: false
            }
        );
        assert!(asked.elapsed() < STOP_GRACE, "{:?}", asked.elapsed());
        // The member sees its connection end at once.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while client.is_connected(&relay_peer) {
            tokio::time::timeout_at(deadline, client.select_next_some())
                .await
                .expect("the member is disconnected within 3 s");
        }
        assert!(!relay_is_running(&friend_relay_dir(dd)), "lock released");
        assert!(lock(&relay.sink).is_none());
        assert!(relay.ext_tx.borrow().is_empty());
        let off = relay.info(now_ms(), "", false).unwrap();
        assert_eq!((off.state.as_str(), off.consent.as_str()), ("off", "no"));
        assert_eq!((off.members, off.counts.reservations), (0, 0));
    }

    #[test]
    fn declared_externals_win_then_upnp_then_profile_ip_with_the_relay_port_global_only() {
        let status = |listen: &[&str], upnp: &[&str]| RelayStatusFile {
            version: 1,
            listen_addrs: listen.iter().map(|t| t.to_string()).collect(),
            upnp_addrs: upnp.iter().map(|t| t.to_string()).collect(),
            ..RelayStatusFile::default()
        };
        let host = OwnP2p {
            peer_id: peer(1),
            relays: Vec::new(),
            confirmed: vec!["/ip4/8.8.8.8/tcp/7423".into()],
            listen: vec![
                "/ip4/127.0.0.1/tcp/7423".into(),
                "/ip4/192.168.1.5/tcp/7423".into(),
                "/ip4/8.8.8.8/udp/7423/quic-v1".into(),
                "/ip6/2001:4860::5/tcp/7423".into(),
                "/ip6/::1/tcp/7423".into(),
            ],
            nat: None,
            discovered: Vec::new(),
            inet: Vec::new(),
        };
        let relay = status(
            &[
                "/ip4/127.0.0.1/tcp/7427",
                "/ip4/192.168.1.5/tcp/7427",
                "/ip4/192.168.1.5/udp/7427/quic-v1",
                "/ip4/192.168.1.5/tcp/443",
                "/ip6/2001:4860::5/tcp/7427",
                "/ip6/2001:4860::5/udp/7427/quic-v1",
                "/ip6/::1/tcp/7427",
            ],
            &[],
        );
        // 1. Declared addresses win alone, whatever else is known.
        let declared = [a("/dns4/home.example.net/tcp/7427")];
        assert_eq!(
            externals(&declared, Some(&relay), Some(&host), None, true, false),
            declared
        );
        assert_eq!(
            externals(&declared, None, None, None, false, false),
            declared
        );
        // Nothing known before the relay reports its listeners.
        assert!(externals(&[], None, Some(&host), None, false, false).is_empty());
        // 3. The profile host's global IPs with the relay's ports (TCP 443
        // while it listens there), then the relay's own global listen
        // addresses; no loopback or LAN address.
        assert_eq!(
            texts(&externals(
                &[],
                Some(&relay),
                Some(&host),
                None,
                true,
                false
            )),
            [
                "/ip4/8.8.8.8/tcp/7427",
                "/ip4/8.8.8.8/udp/7427/quic-v1",
                "/ip4/8.8.8.8/tcp/443",
                "/ip6/2001:4860::5/tcp/7427",
                "/ip6/2001:4860::5/udp/7427/quic-v1",
                "/ip6/2001:4860::5/tcp/443",
            ]
        );
        // Without 443 set, a TCP 443 listener is not named as one.
        let plain = texts(&externals(
            &[],
            Some(&relay),
            Some(&host),
            None,
            false,
            false,
        ));
        assert!(!plain.iter().any(|t| t.ends_with("/tcp/443")), "{plain:?}");
        // No host: only the relay's own global listen addresses.
        assert_eq!(
            texts(&externals(&[], Some(&relay), None, None, true, false)),
            [
                "/ip6/2001:4860::5/tcp/7427",
                "/ip6/2001:4860::5/udp/7427/quic-v1"
            ]
        );
        // 2. What UPnP mapped for the relay beats the host's IPs.
        let mapped = status(
            &relay
                .listen_addrs
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            &[
                "/ip4/192.168.0.1/tcp/7427",
                "/ip4/9.9.9.9/tcp/7427",
                "/ip4/9.9.9.9/udp/7427/quic-v1",
            ],
        );
        assert_eq!(
            texts(&externals(
                &[],
                Some(&mapped),
                Some(&host),
                None,
                true,
                false
            )),
            [
                "/ip4/9.9.9.9/tcp/7427",
                "/ip4/9.9.9.9/udp/7427/quic-v1",
                "/ip6/2001:4860::5/tcp/7427",
                "/ip6/2001:4860::5/udp/7427/quic-v1",
            ]
        );
        // Loopback harnesses (debug RAVEN_LAB_P2P_LOCAL_CANDIDATES=1): local
        // addresses too, with the port the relay really got.
        let lab = status(
            &[
                "/ip4/127.0.0.1/tcp/50001",
                "/ip4/127.0.0.1/udp/50002/quic-v1",
            ],
            &[],
        );
        let lab_host = OwnP2p {
            listen: vec!["/ip4/127.0.0.1/tcp/50000".into()],
            confirmed: Vec::new(),
            ..host
        };
        assert_eq!(
            texts(&externals(
                &[],
                Some(&lab),
                Some(&lab_host),
                None,
                false,
                true
            )),
            [
                "/ip4/127.0.0.1/tcp/50001",
                "/ip4/127.0.0.1/udp/50002/quic-v1"
            ]
        );
        assert!(externals(&[], Some(&lab), Some(&lab_host), None, false, false).is_empty());
    }

    /// Auto-reach: a host behind NAT (private listen addresses only, no
    /// confirmed one) whose public address STUN discovery found where the
    /// NAT keeps ports: the relay names that address with its own ports, and
    /// nothing private.
    #[test]
    fn the_discovered_public_ip_is_named_with_the_relays_ports() {
        let host = OwnP2p {
            peer_id: peer(1),
            relays: Vec::new(),
            confirmed: Vec::new(),
            listen: vec![
                "/ip4/192.168.1.5/tcp/17423".into(),
                "/ip4/192.168.1.5/udp/17423/quic-v1".into(),
            ],
            nat: None,
            discovered: vec!["/ip4/11.0.3.7/udp/17423/quic-v1".into()],
            inet: Vec::new(),
        };
        let relay = RelayStatusFile {
            version: 1,
            listen_addrs: vec![
                "/ip4/192.168.1.5/tcp/17427".into(),
                "/ip4/192.168.1.5/udp/17427/quic-v1".into(),
            ],
            ..RelayStatusFile::default()
        };
        let found = Some(IpAddr::from([11, 0, 3, 7]));
        assert_eq!(
            texts(&externals(
                &[],
                Some(&relay),
                Some(&host),
                found,
                false,
                false
            )),
            ["/ip4/11.0.3.7/tcp/17427", "/ip4/11.0.3.7/udp/17427/quic-v1"]
        );
        // Without it (no discovery, or a NAT that shifts ports): nothing to
        // name, the field case before auto-reach.
        assert!(externals(&[], Some(&relay), Some(&host), None, false, false).is_empty());
    }

    #[test]
    fn offering_needs_an_address_and_a_reason() {
        let now = 10 * CONFIRMED_FOR_MS;
        let names = [a("/ip4/8.8.8.8/tcp/7427")];
        let at = |confirmed_at_ms: u64, upnp: &str| RelayStatusFile {
            confirmed_at_ms,
            upnp: upnp.into(),
            ..RelayStatusFile::default()
        };
        assert!(!confirmed(&at(0, ""), now));
        assert!(!confirmed(&at(0, "on"), now));
        assert!(confirmed(&at(0, "mapped 7427"), now));
        assert!(confirmed(&at(now - CONFIRMED_FOR_MS, ""), now));
        assert!(!confirmed(&at(now - CONFIRMED_FOR_MS - 1, ""), now));
        assert!(
            !worth_offering(&[], true, true, "public", true),
            "no address"
        );
        assert!(!worth_offering(&names, false, false, "relayed", false));
        assert!(!worth_offering(&names, false, false, "", false));
        assert!(worth_offering(&names, false, false, "public", false));
        assert!(worth_offering(&names, false, false, "mapped", false));
        assert!(worth_offering(&names, false, true, "unreachable", false));
        assert!(worth_offering(&names, true, false, "unknown", false));
        // Auto-reach: STUN discovery found the public address.
        assert!(worth_offering(&names, false, false, "unknown", true));
        assert!(worth_offering(&names, false, false, "relayed", true));
    }

    /// RAVEN_ROUTE_HINTS_V1 §11.1/§11.4: the relay's own key, the first four
    /// distinct names a member may dial, and the flags its status gives.
    #[test]
    fn the_offer_names_its_own_key_up_to_four_dialable_addresses_and_its_flags() {
        let now = 10 * CONFIRMED_FOR_MS;
        // Any Ed25519 PeerId stands for the relay's own key here.
        let relay_peer = peer(0x63);
        let status = |confirmed_at_ms: u64, upnp: &str| RelayStatusFile {
            version: 1,
            peer_id: relay_peer.clone(),
            confirmed_at_ms,
            upnp: upnp.into(),
            ..RelayStatusFile::default()
        };
        let long = format!("/dns4/{}.example.org/tcp/7427", "r".repeat(110));
        let names = [
            a("/ip4/11.0.2.7/tcp/7427"),
            a("/ip4/192.168.1.5/tcp/7427"),
            a("/ip4/11.0.2.7/udp/7427/quic-v1"),
            a("/ip4/11.0.2.7/tcp/7427"),
            a(&long),
            a("/ip4/11.0.2.7/tcp/443"),
            a("/ip6/2001:4860::5/tcp/7427"),
            a("/dns4/relay.example.org/tcp/7427"),
        ];
        // Confirmed a moment ago: CONFIRMED, and PORT_443 for the TCP 443
        // address. No private, repeated or overlong name; four at most.
        let r = offer_record(&status(now - 1, ""), &names, false, "", false, now, false).unwrap();
        assert_eq!(r.relay_peer_id(), relay_peer);
        assert_eq!(
            r.addrs,
            [
                "/ip4/11.0.2.7/tcp/7427",
                "/ip4/11.0.2.7/udp/7427/quic-v1",
                "/ip4/11.0.2.7/tcp/443",
                "/ip6/2001:4860::5/tcp/7427",
            ]
        );
        assert_eq!(r.flags, FLAG_AUTONAT | FLAG_CONFIRMED | FLAG_PORT_443);
        // A record receivers accept as it is.
        let body = raven_core::route_hints::encode_offer(&r);
        assert_eq!(raven_core::route_hints::decode_offer(&body), Ok(r.clone()));
        // UPnP mapped confirms too; no TCP 443 name, no PORT_443.
        let r = offer_record(
            &status(0, "mapped 7427"),
            &names[..3],
            false,
            "",
            false,
            now,
            false,
        );
        assert_eq!(r.unwrap().flags, FLAG_AUTONAT | FLAG_CONFIRMED);
        // Unconfirmed: offered only on a public or mapped node, or with
        // declared addresses, and then without CONFIRMED.
        let cold = status(0, "on");
        assert_eq!(
            offer_record(&cold, &names, false, "unknown", false, now, false),
            None
        );
        assert_eq!(
            offer_record(&cold, &names, false, "relayed", false, now, false),
            None
        );
        for (declared, reach) in [(false, "public"), (false, "mapped"), (true, "")] {
            let r = offer_record(&cold, &names[..1], declared, reach, false, now, false).unwrap();
            assert_eq!(r.flags, FLAG_AUTONAT, "{declared} {reach}");
        }
        // Auto-reach: an address STUN discovery found is offered on an
        // unknown node too, unconfirmed (a forward makes it right).
        let found = offer_record(&cold, &names[..3], false, "unknown", true, now, false).unwrap();
        assert_eq!(found.flags, FLAG_AUTONAT);
        assert_eq!(
            found.addrs,
            ["/ip4/11.0.2.7/tcp/7427", "/ip4/11.0.2.7/udp/7427/quic-v1"]
        );
        // Only names a member may not dial: nothing to offer, except that
        // the debug lab switch admits loopback and private ones.
        let local = [
            a("/ip4/127.0.0.1/tcp/7427"),
            a("/ip4/192.168.1.5/udp/7427/quic-v1"),
        ];
        assert_eq!(
            offer_record(&cold, &local, true, "", false, now, false),
            None
        );
        let lab = offer_record(&cold, &local, true, "", false, now, true).unwrap();
        assert_eq!(texts(&local), lab.addrs);
        // No name at all, or a status without a usable PeerId: nothing.
        assert_eq!(
            offer_record(&status(now, ""), &[], true, "public", true, now, false),
            None
        );
        let nameless = RelayStatusFile {
            peer_id: "garbage".into(),
            ..status(now, "")
        };
        assert_eq!(
            offer_record(&nameless, &names, true, "public", true, now, false),
            None
        );
    }

    #[test]
    fn offered_to_counts_members_this_node_may_show_its_ip() {
        let gate_peer = |seed: u8, hidden: bool, learned: bool, proven: bool| P2pGatePeer {
            peer_id: peer(seed),
            relays: Vec::new(),
            hidden,
            learned,
            proven,
            rotated: Vec::new(),
        };
        let members = members_from(
            Ok(vec![
                gate_peer(1, false, false, true),
                // Hide my IP for it: neither a member nor offered.
                gate_peer(2, true, false, true),
                // Learned and not proved: neither.
                gate_peer(3, true, true, false),
                // Learned and proved.
                gate_peer(4, false, true, true),
                // Denied below.
                gate_peer(5, false, false, true),
            ]),
            Ok(Some(RelayAllowList {
                peers: vec![RelayAllowEntry {
                    peer_id: peer(6),
                    label: String::new(),
                    contact: String::new(),
                    expires_ms: None,
                }],
                deny: vec![RelayAllowEntry {
                    peer_id: peer(5),
                    label: String::new(),
                    contact: String::new(),
                    expires_ms: None,
                }],
                ..RelayAllowList::default()
            })),
            Ok(BlockedP2p::default()),
        );
        assert_eq!(peers(&members), HashSet::from([pid(1), pid(4), pid(6)]));
        // The manual peer is no contact: route hints never reach it.
        assert_eq!(members.offered, 2);
        assert_eq!(
            members_from(Err("broken".into()), Ok(None), Ok(BlockedP2p::default())).offered,
            0
        );

        // From the files: hide my IP for everyone offers to nobody.
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        write_book(dd, &[row(1, true, &peer(1)), row(2, true, &peer(2))]);
        assert_eq!(derive_members(dd).offered, 2);
        raven_core::save_policy(
            dd,
            &NodePolicy {
                hide_ip: true,
                ..NodePolicy::default()
            },
        )
        .unwrap();
        let members = derive_members(dd);
        assert_eq!((members.count(), members.offered), (0, 0));
    }

    /// The offer goes to the PeerIds the relay admits, and only for the
    /// profile it runs for; a new record wakes the announcer.
    #[test]
    fn offer_for_needs_a_member_and_is_kept_for_its_profile_only() {
        let dir = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let record = RelayOfferRecord {
            flags: FLAG_AUTONAT,
            relay_pub: parse_peer_id(&peer(9)).unwrap(),
            addrs: vec!["/ip4/11.0.2.7/tcp/7427".into()],
        };
        let offer = Offer {
            data_dir: dir.path().to_path_buf(),
            record: record.clone(),
            members: Arc::new(HashSet::from([pid(1), pid(2)])),
        };
        assert_eq!(offer.offer_for(&peer(1)), Some(record.clone()));
        assert_eq!(offer.offer_for(&peer(3)), None, "not a member");
        assert_eq!(offer.offer_for("garbage"), None);
        publish_offer(Some(offer.clone()));
        assert_eq!(super::offer(dir.path()), Some(offer));
        assert_eq!(super::offer(other.path()), None, "another profile");
        publish_offer(None);
        assert_eq!(super::offer(dir.path()), None);
    }

    /// A relay that is up offers its own key to its members while offers
    /// are live, and never otherwise; its key stays known to this node after
    /// it stops (a contact may not offer it back). Lab only.
    #[tokio::test]
    async fn a_running_relay_offers_its_own_key_to_members_while_offers_are_live() {
        if !raven_core::p2p_live_enabled() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        write_book(dd, &[row(1, true, &peer(1)), row(2, true, &peer(2))]);
        let declared = "/ip4/11.0.2.7/tcp/7427";
        let policy = NodePolicy {
            relay_offer: Some(true),
            relay_external: vec![declared.into()],
            ..NodePolicy::default()
        };
        let mut relay = FriendRelay::new(dd.to_path_buf(), true);
        assert_eq!(relay.offer(now_ms(), "public", true), None, "not running");
        assert!(
            relay
                .round(settings(&policy, false, Some(loopback(0))), false)
                .await
                .started
        );
        let (relay_peer, _) = up(&relay).await;
        let offer = relay
            .offer(now_ms(), "", true)
            .expect("declared: worth offering");
        assert_eq!(offer.record.relay_peer_id(), relay_peer);
        assert_eq!(offer.record.addrs, [declared]);
        assert_eq!(offer.record.flags, FLAG_AUTONAT);
        assert_eq!(offer.offer_for(&peer(1)), Some(offer.record.clone()));
        assert_eq!(offer.offer_for(&peer(3)), None, "not a member");
        let info = relay.info(now_ms(), "", true).unwrap();
        assert_eq!((info.offering, info.offered_to), (true, 2));
        // Offers off (the friend relay switch or route hints): nothing.
        assert_eq!(relay.offer(now_ms(), "", false), None);
        let info = relay.info(now_ms(), "", false).unwrap();
        assert_eq!((info.offering, info.offered_to), (false, 0));
        // Its key, from the status it wrote.
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        while own_relay_key(dd).is_none() {
            assert!(std::time::Instant::now() < deadline, "no relay status");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(own_relay_key(dd), Some(offer.record.relay_pub));
        assert_eq!(relay.stop().await, Some(Stopped::Clean));
        assert_eq!(relay.offer(now_ms(), "", true), None, "stopped");
        assert_eq!(own_relay_key(dd), Some(offer.record.relay_pub));
    }
}
