//! raven-node's side of the security events (`docs/roadmap/plans/phase6-design.json`,
//! step P6.24; design A §3, sensing points S1-S5, S13 and S21): what the link layer
//! notes, the node's sink and the counts `Status.security` reports.
//!
//! **What is noted, and where.**
//! - A link that fails before the handler knows whom it serves (Noise
//!   garbage, a handshake that never finishes, a contact gate refusal) is
//!   noted by the accept loop against the network source
//!   ([`inbound_refused`], `netutil::serve_connections` and the p2p
//!   responder): the stranger's key is throwaway and never kept. A tag
//!   failure that early is garbage too (`SEC_PREAUTH_MALFORMED`): a path
//!   needs a known peer.
//! - Once a contact is past the gate (inbound) or its bind or hello is
//!   verified (dialled), a transport tag failure is `SEC_LINK_TAG_FAIL`
//!   about that contact's path on this network ([`inbound_link_error`],
//!   [`dial_link_error`], [`dial_reply`]). The link closes exactly as before.
//! - Another key at a contact's address (the M0 pin, a bind or hello for
//!   someone else) is `SEC_ADDRESS_IMPOSTOR` ([`address_impostor`]); the
//!   dial stops where it stopped before.
//! - The p2p peer gate's refusals ([`p2p_gate_hook`]) and a relayed p2p link
//!   that breaks inside ([`relay_link_broken`]).
//!
//! Everything is a no-op while [`SecGate::Events`] is shut: no event, no
//! log line, no error text changes (release builds behave byte for byte as
//! before). The one thing that does not wait for the gate is
//! [`exclude_dial`]: a dial whose link was tampered with must never teach
//! learning connectivity anything (6b risk 7), whichever gates are open.
//!
//! **The penalty box (design A R1, step P6.26; the responses gate).** One
//! [`PenaltyBox`] for the whole process, memory only: strangers' pre-auth
//! failures at the LAN and Internet listeners, the listeners' per-source cap
//! refusals, the p2p peer gate's inbound refusals and the LAN beacon
//! answerer's replays and rate-limit hits are strikes against the source's
//! address; 16 in a minute ban it. A source on the local network at the
//! LAN listener or the beacon is its whole address, any other IPv6 source
//! its /64 (the Internet listener, the p2p gate, and a global source from
//! outside the local network at the LAN listener: [`penalty_key`], Phase 6
//! review sensing-2 and its re-verify). A banned source is refused
//! by the listeners ([`admit_source`], one probation connection per 10 s; a
//! contact that authenticates on it clears the source,
//! [`source_authenticated`]), by the p2p peer gate before Noise
//! ([`p2p_admit_hook`]; a contact the gate admits on a direct inbound
//! connection clears it too, [`p2p_authenticated_hook`], Phase 6 review
//! sensing-7) and by the beacon answerer ([`beacon_banned`]). Each ban
//! notes `SEC_PREAUTH_FLOOD` once (a day count in the ledger). Loopback is
//! never banned unless the debug switch `RAVEN_LAB_SEC_PENALTY_LOOPBACK=1`
//! says so. The p2p responder's and the radio pipes' sources are keys made
//! from a PeerId or a contact, not addresses: they strike nothing (a
//! stranger replaying a contact's nearby token must not get that contact's
//! pipe banned).
//!
//! **Early re-key and rollback recovery (design A R2, R3, step P6.27; the
//! responses gate and `node_policy.security_auto_rekey`).** The writer
//! thread answers an object of a contact's that failed authentication or
//! was replayed, and a third index jump of one in an hour, with an early
//! re-key ([`raven_core::session_renewal::request_early`], then
//! `renewal::request_early`); a rollback of this computer's state with a
//! prekey rotation and a re-key for every contact with a live session.
//! Each writes its alert's `action` (`REKEY_REQUESTED`, `PREKEY_ROTATED`).
//! Only the contact's signature or this disk raises those events, so no
//! third party can spend a contact's re-key budget; nothing is ever
//! blocked, unpinned or removed.
//!
//! **Paths, custodians, depositors and relays (design A R4-R8, step P6.28;
//! the responses gate).** The writer thread also answers: a Suspicious tag
//! failure on a contact's link with that contact's routes over that carrier
//! last on this network for 10 minutes (R4,
//! [`raven_core::route_memory::note_interference`]; the outbox plans its
//! other routes, friend custody included, first); a Suspicious impostor at
//! a contact's LAN address by forgetting that learned address (R5,
//! `lan_seen` and the learned LAN part; the address saved by hand stays);
//! what a custodian served failing Raven's checks with a strike, the third
//! in a day parking it for a day (R6, `crate::custody::strike_misbehaved`,
//! lifted by `raven outbox retry`); a depositor whose tenth object in an
//! hour was refused, which the custodian code then answers RATE_LIMITED for
//! an hour (R7, `raven_core::friend_custody::depositor_throttled`); and a
//! Suspicious relay with that relay last in circuit order for an hour (R8's
//! fallback while learning does not score relays, [`relay_demoted`]; never
//! left out). Each writes its alert's `action` (`PATH_DEMOTED`,
//! `ADDRESS_FORGOTTEN`, `CUSTODIAN_PARKED`, `DEPOSITS_THROTTLED`,
//! `RELAY_DEMOTED`), and each ends by itself.
//!
//! **Capability floors (design A R9, step P6.29; the events gate).** A link
//! with a contact raises the contact's high-water mark of link features
//! ([`link_features`], `raven_core::capability_floor`): a verified hello's
//! caps on Internet direct and p2p (complete), the dialer's RLX1 caps on a
//! LAN listener and the listener's RRH1 on a LAN dialer (seen only). A
//! feature a complete showing lacks after it was seen is
//! `SEC_CAPABILITY_DOWNGRADE` about that contact; the link goes on as
//! before.
//!
//! **The sink ([`start`]).** While the gate is live, `raven-node service`
//! registers [`NodeSink`]: every event goes into a bounded queue (1,024; a
//! full queue drops and counts) and one writer thread puts it into the
//! profile's security ledger (`raven_core::security_ledger`). Network
//! events stay in memory and go into the ledger as one count per kind and
//! day, by the hour: a stranger's connection costs no write. The writer
//! opens the ledger only when it has something to write, so a profile that
//! is not sealed (or whose key is not loaded yet) keeps everything in
//! memory. `Status.security` ([`status`]) reports counts kept here: never an
//! address, a key or a time of day.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use raven_core::capability_floor;
use raven_core::clock::now_ms;
use raven_core::custody_client::FetchReport;
use raven_core::indexed_session_store::IndexedSessionStore;
use raven_core::ipc::SecurityStatus;
use raven_core::outbox::OutboxCarrier;
use raven_core::security_events::{
    self as events, Admit, Attribution, CarrierRole, PenaltyBox, SecEvent, SecKind, SecSink,
    Severity, SourceKey, Verdict, Via, CAP_REFUSAL_STRIKE, INTERNET_FRAME_LENGTH, LINK_TAG_FAILED,
    NOISE_HANDSHAKE_FAILED,
};
use raven_core::security_gate::{self, SecGate};
use raven_core::security_ledger::{LedgerError, SecurityLedger};
use raven_core::session_renewal;
use raven_swarm::gate::{AdmitHook, AuthenticatedHook, GateHandle, RefusalHook, RefusalKind};

use crate::netutil::{ReplyWait, PEER_CLOSED};

const MINUTE_MS: u64 = 60_000;
const HOUR_MS: u64 = 60 * MINUTE_MS;
const DAY_MS: u64 = 24 * HOUR_MS;

/// The writer's queue (design A §3): past it, events are dropped and counted.
const QUEUE: usize = 1_024;
/// The writer's own pass: the ledger's due writes, at least this often.
const TICK: Duration = Duration::from_secs(60);
/// A ledger that would not open (not sealed yet, the key not loaded, busy)
/// is tried again after this long.
const REOPEN_MS: u64 = MINUTE_MS;
/// Network counts are kept for this many days while the ledger cannot take
/// them (older days are dropped: they are counts, nothing more).
const NETWORK_DAYS: u64 = 2;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn live() -> bool {
    security_gate::live(SecGate::Events)
}

/// Whether events are noted at all: the link code asks before it reads
/// anything only an event needs (a link's features, [`LinkFeatures`]).
pub(crate) fn events_live() -> bool {
    live()
}

/// Note one event (the node's sensing points come here, never to
/// `security_events::note` directly). Nothing happens while the gate is
/// shut.
pub(crate) fn note(ev: SecEvent) {
    if !live() {
        return;
    }
    #[cfg(test)]
    tests::captured(&ev);
    events::note(ev);
}

/// The network this computer is on now: the first 8 bytes of its egress tag
/// (`route_memory::egress_tag`, a digest of its source addresses), for the
/// per-network rules (and the outbox's R4 order). `None` without a default
/// route.
pub(crate) fn network() -> Option<[u8; 8]> {
    raven_core::route_memory::egress_tag_bytes()
}

/// A contact-attributed event, with the network it was seen on.
fn about_contact(kind: SecKind, peer: &[u8; 32], via: Via) {
    let ev = SecEvent::new(kind, Attribution::Contact { peer: *peer }, via, now_ms());
    note(match network() {
        Some(tag) => ev.on_network(tag),
        None => ev,
    });
}

// ── Listeners ──────────────────────────────────────────────────────────────

/// The carrier of a listener as `netutil::serve_connections` names it.
pub(crate) fn listener_carrier(name: &str) -> OutboxCarrier {
    match name {
        "internet_direct" => OutboxCarrier::Internet,
        "p2p" => OutboxCarrier::P2p,
        "nearby" => OutboxCarrier::Nearby,
        _ => OutboxCarrier::Lan,
    }
}

/// An inbound link from `source` over `carrier` ended with `error` before
/// its handler knew whom it served (S2, S3): the matching kind about that
/// network source (memory only). A tag failure this early is garbage, not
/// a path. Texts that are no event (a hang-up, a timeout of ours) are
/// nothing.
pub(crate) fn inbound_refused(source: IpAddr, carrier: OutboxCarrier, error: &str) {
    if !live() {
        return;
    }
    let Some(kind) = events::classify_link_error(error) else {
        return;
    };
    let kind = match kind {
        SecKind::LinkTagFail => SecKind::PreauthMalformed,
        other => other,
    };
    let via = Via::DirectLink(carrier);
    note(SecEvent::new(
        kind,
        Attribution::Network {
            source: SourceKey::of(source),
        },
        via,
        now_ms(),
    ));
    // R1: only a listener's source is an address (the p2p responder's is
    // made from a PeerId, a radio pipe's from its contact).
    if listener_has_addresses(carrier) {
        strike(source, events::strike_weight(kind), carrier);
    }
}

/// Does `carrier`'s listener know its sources by address (the TCP
/// listeners)?
fn listener_has_addresses(carrier: OutboxCarrier) -> bool {
    matches!(carrier, OutboxCarrier::Lan | OutboxCarrier::Internet)
}

/// A read on an inbound link from `peer` (past the contact gate) failed
/// with `error`: a tag failure is `SEC_LINK_TAG_FAIL` about that
/// contact's path on this network (S1); a frame that broke PAD1 link
/// padding (`crate::link`, P6.34) is `SEC_CONTACT_MALFORMED` about the
/// contact (its frames are authenticated, so it is the contact's own).
pub(crate) fn inbound_link_error(peer: &[u8; 32], carrier: OutboxCarrier, error: &str) {
    if !live() {
        return;
    }
    if error == LINK_TAG_FAILED {
        about_contact(SecKind::LinkTagFail, peer, Via::DirectLink(carrier));
    } else if crate::link::is_pad_refusal(error) {
        about_contact(SecKind::ContactMalformed, peer, Via::DirectLink(carrier));
    }
}

// ── Dials ──────────────────────────────────────────────────────────────────

/// A read on a dialled link to `peer` (its bind or hello verified) failed
/// with `error`: a tag failure is `SEC_LINK_TAG_FAIL` about that contact's
/// path on this network (S1), and the dial teaches learning nothing
/// ([`exclude_dial`]); a frame that broke PAD1 link padding is
/// `SEC_CONTACT_MALFORMED` about the contact (P6.34; not the path's).
pub(crate) fn dial_link_error(peer: &[u8; 32], carrier: OutboxCarrier, error: &str) {
    if crate::link::is_pad_refusal(error) {
        if live() {
            about_contact(SecKind::ContactMalformed, peer, Via::Dial(carrier));
        }
        return;
    }
    if error != LINK_TAG_FAILED {
        return;
    }
    exclude_dial(peer, carrier);
    if live() {
        about_contact(SecKind::LinkTagFail, peer, Via::Dial(carrier));
    }
}

/// [`dial_link_error`] for one wait on a dialled link's replies.
pub(crate) fn dial_reply(got: &ReplyWait, hints: &crate::hints::LinkCtl) {
    if let ReplyWait::Closed(why) = got {
        let (peer, carrier) = hints.link_of();
        dial_link_error(&peer, carrier, why);
    }
}

/// Another key answered at `expected`'s address over `carrier` (the M0 pin,
/// a bind or hello naming someone else): `SEC_ADDRESS_IMPOSTOR` about that
/// contact (S13). The dial stops where it stopped before. `at`: the LAN
/// address dialled, kept in memory for R5 ([`impostor_at`]) before the event
/// is noted; the event itself never carries it.
pub(crate) fn address_impostor(expected: &[u8; 32], carrier: OutboxCarrier, at: Option<IpAddr>) {
    if live() {
        if let Some(ip) = at.filter(|_| carrier == OutboxCarrier::Lan) {
            impostor_at(expected, ip, now_ms());
        }
        about_contact(SecKind::AddressImpostor, expected, Via::Dial(carrier));
    }
}

/// A contact's LAN beacon query, link knock or Bluetooth token matched only
/// with the pair's static root while this node expects the contact to use
/// their pair seed (Phase 6b P6.38, design B §5, `SEC_PAIR_SEED_ROOT`): a
/// Notice, and nothing is refused (the root is the fallback that keeps
/// friends from being locked out; the next link agrees on a new seed).
pub(crate) fn pair_seed_root(peer: &[u8; 32], via: Via) {
    if live() {
        about_contact(SecKind::PairSeedRoot, peer, via);
    }
}

/// The link features one link showed of its contact (design A R9, step
/// P6.29), read only while the events gate is live.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LinkFeatures {
    /// A verified hello's caps (Internet direct, p2p): everything the
    /// contact's build offers on this carrier, signed by the contact.
    Complete(u32),
    /// What a LAN link happened to show (a dialer's message 3 asks for RRH1
    /// only on a dial that reads; a listener sends RRH1 only to a dialer
    /// that asked): it raises the mark, and nothing missing is a downgrade.
    Seen(u32),
}

/// A contact's link features as one link showed them go into its capability
/// floor ([`capability_floor`]): a feature it showed before that a complete
/// showing lacks now is `SEC_CAPABILITY_DOWNGRADE` about it, at the level of
/// what went missing (route hints a Notice, padding or the knock
/// Suspicious), at most once a day per feature. `knock`: whether the link
/// carried the RLK1 knock (P6.35, `crate::link_knock`), `None` when it
/// cannot tell (p2p, nearby, the knock shut here); a LAN or Internet direct
/// link always can, so a knock seen before and missing now is a downgrade
/// on a seen-only showing too. The link goes on exactly as before: link
/// features are never refused. Blocking (the floor is a file); nothing
/// while the gate is shut.
pub(crate) fn link_features(
    data_dir: &Path,
    peer: &[u8; 32],
    features: LinkFeatures,
    knock: Option<bool>,
    via: Via,
) {
    if !live() {
        return;
    }
    let now = now_ms();
    let down = match features {
        LinkFeatures::Complete(caps) => {
            capability_floor::observe_link(data_dir, peer, caps, knock, now)
        }
        LinkFeatures::Seen(caps) => {
            capability_floor::observe_link_seen(data_dir, peer, caps, knock, now)
        }
    };
    let Some((ev, severity)) = down
        .ok()
        .flatten()
        .and_then(|down| down.event(peer, via, now))
    else {
        return;
    };
    #[cfg(test)]
    tests::captured(&ev);
    events::note_at_least(ev, severity);
}

/// Did a relayed p2p link break inside (`error`, as the link returned it)?
/// A Noise failure, garbage where a frame belongs, a reply that failed its
/// tag, or the stream cut once both hellos were verified. Not the contact's
/// own refusal (`LINK_NOT_ACCEPTED`) and not a hang-up during the handshake
/// (a busy contact sheds load that way too).
pub(crate) fn link_broke(error: &str) -> bool {
    [
        LINK_TAG_FAILED,
        NOISE_HANDSHAKE_FAILED,
        INTERNET_FRAME_LENGTH,
        PEER_CLOSED,
    ]
    .contains(&error)
        || (error.contains("_DIAL_BAD_REPLY") && error.contains(LINK_TAG_FAILED))
}

/// A relayed p2p dial whose link broke inside ([`link_broke`], S21):
/// `SEC_RELAY_LINK_BROKEN` about each relay the link went through
/// (`relays`: their PeerIds' bytes, `p2p::broken_link_relays`; noted under
/// [`events::relay_subject`], never the PeerId).
pub(crate) fn relay_link_broken<I>(relays: I)
where
    I: IntoIterator<Item = Vec<u8>>,
{
    if !live() {
        return;
    }
    let at = now_ms();
    for relay in relays {
        note(SecEvent::new(
            SecKind::RelayLinkBroken,
            Attribution::Carrier {
                carrier: events::relay_subject(&relay),
                role: CarrierRole::Relay,
            },
            Via::Relay,
            at,
        ));
        relay_signal(&relay);
    }
}

/// A relayed dial through `relay` (its PeerId's bytes) brought no receipt
/// while the same contact's receipt came over another path within an hour
/// (S21, `crate::delivery_paths`): `SEC_RELAY_NO_RECEIPT` about that relay
/// (its [`events::relay_subject`]), Suspicious when more than half of its
/// last 10 such dials went that way (`suspicious`; a share of dials, not a
/// count of events, so the caller decides it).
pub(crate) fn relay_no_receipt(relay: &[u8], suspicious: bool) {
    if !live() {
        return;
    }
    let ev = SecEvent::new(
        SecKind::RelayNoReceipt,
        Attribution::Carrier {
            carrier: events::relay_subject(relay),
            role: CarrierRole::Relay,
        },
        Via::Relay,
        now_ms(),
    );
    #[cfg(test)]
    tests::captured(&ev);
    if suspicious {
        relay_signal(relay);
    }
    let floor = if suspicious {
        Severity::Suspicious
    } else {
        Severity::Notice
    };
    events::note_at_least(ev, floor);
}

// ── Custody and nearby (S18-S20, P6.25) ─────────────────────────────────────

/// What a fetch round at `custodian` saw (S18): its misbehaviour about the
/// custodian, and the refusals of objects their senders signed about those
/// contacts, all fetched from it.
pub(crate) fn custody_fetched(custodian: &[u8; 32], report: &FetchReport) {
    if !live() {
        return;
    }
    let at = now_ms();
    let via = Via::Custodian(*custodian);
    for &kind in &report.misbehaviour {
        note(SecEvent::new(
            kind,
            Attribution::Carrier {
                carrier: *custodian,
                role: CarrierRole::Custodian,
            },
            via,
            at,
        ));
    }
    for &(peer, kind) in &report.sender_events {
        note(SecEvent::new(kind, Attribution::Contact { peer }, via, at));
    }
}

/// `custodian` answered `HOP_REFUSED` to a HANDOFF this node sent it over
/// `carrier` (S20): `SEC_HANDOFF_REFUSED` about it. Only the outer signer
/// may ask for a further hop, and this node asks for its own objects only;
/// a DELIVER is never refused that way.
pub(crate) fn handoff_refused(custodian: &[u8; 32], carrier: OutboxCarrier) {
    if live() {
        note(SecEvent::new(
            SecKind::HandoffRefused,
            Attribution::Carrier {
                carrier: *custodian,
                role: CarrierRole::Custodian,
            },
            Via::Dial(carrier),
            now_ms(),
        ));
    }
}

/// A LAN or Internet direct listener (`carrier`) read a message 1 from
/// `source` whose RLK1 knock matched a contact with a nonce matched before
/// (P6.35, `SEC_KNOCK_REPLAY`): about that network source, and R1 strike 4.
/// The connection goes on as a stranger's.
pub(crate) fn knock_replayed(source: IpAddr, carrier: OutboxCarrier) {
    if !live() {
        return;
    }
    let via = Via::DirectLink(carrier);
    note(SecEvent::new(
        SecKind::KnockReplay,
        Attribution::Network {
            source: SourceKey::of(source),
        },
        via,
        now_ms(),
    ));
    if listener_has_addresses(carrier) {
        strike(source, events::strike_weight(SecKind::KnockReplay), carrier);
    }
}

/// An RNK1 knock on the pipe for a pair failed (S20, `SEC_KNOCK_FAIL`):
/// about the radio source `source` (the pipe's admission key, memory only;
/// nobody on the radio has an address), `dialled` when this node knocked.
/// No penalty-box strike (P6.26): that key is the pipe's contact's, so a
/// stranger replaying the contact's token must not earn the contact a ban.
pub(crate) fn knock_failed(source: IpAddr, dialled: bool) {
    if live() {
        let via = if dialled {
            Via::Dial(OutboxCarrier::Nearby)
        } else {
            Via::DirectLink(OutboxCarrier::Nearby)
        };
        note(SecEvent::new(
            SecKind::KnockFail,
            Attribution::Network {
                source: SourceKey::of(source),
            },
            via,
            now_ms(),
        ));
    }
}

// ── The p2p peer gate (S5) ─────────────────────────────────────────────────

/// The hook the p2p host gives its peer gate: `None` while the gate is
/// shut, so nothing is installed and the gate behaves as before.
pub(crate) fn p2p_gate_hook() -> Option<RefusalHook> {
    live().then(|| Arc::new(p2p_gate_refused) as RefusalHook)
}

/// [`p2p_gate_hook`] for the gate whose set `peers` holds: while that set
/// could not be read from the contact book or block list (the book held
/// while the at-rest key loads after a start or an Unlock), it admits the
/// relays only and judges nobody else, so a refusal then is noted nowhere
/// and is no strike (E1: a verified friend was counted a stranger).
pub(crate) fn p2p_gate_hook_of(peers: GateHandle) -> Option<RefusalHook> {
    let hook = p2p_gate_hook()?;
    Some(Arc::new(move |ip, kind| {
        let (_, _, unreadable) = peers.summary();
        if !unreadable {
            hook(ip, kind);
        }
    }))
}

/// The peer gate refused a connection from (or, dialled, to) `ip`:
/// `SEC_P2P_GATE_REFUSED` about that network source.
fn p2p_gate_refused(ip: IpAddr, kind: RefusalKind) {
    let via = match kind {
        RefusalKind::Outbound => Via::Dial(OutboxCarrier::P2p),
        RefusalKind::Inbound | RefusalKind::Relayed => Via::DirectLink(OutboxCarrier::P2p),
    };
    note(SecEvent::new(
        SecKind::P2pGateRefused,
        Attribution::Network {
            source: SourceKey::of(ip),
        },
        via,
        now_ms(),
    ));
    // R1: a stranger that connected to us; a dial of ours that reached one
    // is no strike against that address.
    if kind == RefusalKind::Inbound {
        strike(
            ip,
            events::strike_weight(SecKind::P2pGateRefused),
            OutboxCarrier::P2p,
        );
    }
}

/// The hook the p2p host gives its peer gate for direct inbound sources
/// (asked before Noise): `None` while the responses gate is shut, so
/// nothing is installed and nothing is asked.
pub(crate) fn p2p_admit_hook() -> Option<AdmitHook> {
    responding().then(|| Arc::new(p2p_admit) as AdmitHook)
}

/// May a direct p2p connection from `ip` go on to Noise? A banned source's
/// probation connection may (its peer then meets the class check).
fn p2p_admit(ip: IpAddr) -> bool {
    admit_source(ip, OutboxCarrier::P2p) != Admit::Deny
}

/// The hook the p2p host gives its peer gate for the direct inbound
/// connections it admits as a contact's (Phase 6 review sensing-7): the
/// source is forgotten, as a TCP listener's is when a contact
/// authenticates there ([`source_authenticated`]), so a friend behind the
/// same CGNAT address or /64 as a stranger gets through at once. `None`
/// while the responses gate is shut.
pub(crate) fn p2p_authenticated_hook() -> Option<AuthenticatedHook> {
    responding().then(|| {
        Arc::new(|ip: IpAddr| source_authenticated(ip, OutboxCarrier::P2p)) as AuthenticatedHook
    })
}

// ── The penalty box (design A R1) ──────────────────────────────────────────

/// The process's one box (the listeners, the p2p peer gate and the beacon
/// answerer share it), made at first use: memory only.
static PENALTY: OnceLock<Mutex<PenaltyBox>> = OnceLock::new();

fn penalty() -> MutexGuard<'static, PenaltyBox> {
    lock(PENALTY.get_or_init(|| {
        Mutex::new(PenaltyBox::with_loopback_exempt(
            !security_gate::lab_penalty_loopback(),
        ))
    }))
}

/// The responses gate (it sits on the events gate): the box is asked and
/// struck only while it is live, so a build with it shut never even locks
/// the box.
fn responding() -> bool {
    security_gate::live(SecGate::Responses)
}

/// The box's clock: tokio's (a paused test runtime moves it), which is the
/// monotonic clock everywhere else.
fn clock() -> Instant {
    tokio::time::Instant::now().into_std()
}

/// The penalty box's key for the source `ip` met on `carrier` (Phase 6
/// review sensing-2): [`penalty_key_with`], with this computer's own
/// networks ([`lan_on_link`]).
pub(crate) fn penalty_key(ip: IpAddr, carrier: OutboxCarrier) -> SourceKey {
    penalty_key_with(ip, carrier, lan_on_link)
}

/// [`penalty_key`] with `on_link` telling whether an address is on one of
/// this computer's networks. A host on the local network that reaches the
/// LAN listener or the beacon is its whole address
/// ([`SourceKey::of_local`]): every link-local host shares fe80::/64 and
/// every SLAAC host one LAN's /64, so one stranger on the Wi-Fi must not
/// get its neighbours banned. That is a link-local, unique-local or
/// loopback address, or one inside a prefix of this computer's networks
/// (`raven_core::paths::lan_source_is_local`). Any other source is its /64
/// ([`SourceKey::of`]: a host on the Internet holds the whole /64, and
/// would dodge its ban by moving inside it): at the Internet listener and
/// the p2p gate, and a global IPv6 source from outside the local network
/// that reaches the LAN listener (it accepts dials from anywhere before
/// they authenticate; a pinned contact may dial it remotely). IPv4 keys
/// are the whole address either way.
pub(crate) fn penalty_key_with(
    ip: IpAddr,
    carrier: OutboxCarrier,
    on_link: impl Fn(IpAddr) -> bool,
) -> SourceKey {
    let local = carrier == OutboxCarrier::Lan
        && matches!(ip.to_canonical(), IpAddr::V6(_))
        && raven_core::paths::lan_source_is_local(ip, on_link);
    if local {
        SourceKey::of_local(ip)
    } else {
        SourceKey::of(ip)
    }
}

/// A test's own [`lan_on_link`].
#[cfg(test)]
type OnLinkFn = fn(IpAddr) -> bool;

#[cfg(test)]
thread_local! {
    /// [`lan_on_link`]'s answer on this thread (tests: the networks of the
    /// test machine are not the test's).
    static ON_LINK_FOR_TEST: std::cell::Cell<Option<OnLinkFn>> =
        const { std::cell::Cell::new(None) };
}

/// This thread's [`lan_on_link`] (tests), back to the system's on drop.
#[cfg(test)]
pub(crate) struct OnLinkForTest(());

#[cfg(test)]
impl OnLinkForTest {
    pub(crate) fn set(on_link: OnLinkFn) -> Self {
        ON_LINK_FOR_TEST.with(|c| c.set(Some(on_link)));
        Self(())
    }
}

#[cfg(test)]
impl Drop for OnLinkForTest {
    fn drop(&mut self) {
        ON_LINK_FOR_TEST.with(|c| c.set(None));
    }
}

/// Is `ip` on one of this computer's networks (`lan_direct`'s rule for a
/// local source)? Asked only for a global IPv6 source at the LAN listener
/// or the beacon.
fn lan_on_link(ip: IpAddr) -> bool {
    #[cfg(test)]
    if let Some(on_link) = ON_LINK_FOR_TEST.with(std::cell::Cell::get) {
        return on_link(ip);
    }
    crate::lan_direct::on_link(ip)
}

/// May a new connection from `ip` on `carrier` go on (a listener's
/// admission, the p2p gate's)? `Allow` while the responses gate is shut.
pub(crate) fn admit_source(ip: IpAddr, carrier: OutboxCarrier) -> Admit {
    if !responding() {
        return Admit::Allow;
    }
    penalty().admit(penalty_key(ip, carrier), clock())
}

/// A connection from `ip` on `carrier` authenticated as a contact: its
/// source is forgotten (a friend behind an attacker's address gets
/// through).
pub(crate) fn source_authenticated(ip: IpAddr, carrier: OutboxCarrier) {
    if responding() {
        penalty().authenticated(penalty_key(ip, carrier));
    }
}

/// A listener for `carrier` refused a connection from `ip` at its own
/// per-source cap: one strike (design A R1).
pub(crate) fn cap_refused(ip: IpAddr, carrier: OutboxCarrier) {
    if listener_has_addresses(carrier) {
        strike(ip, CAP_REFUSAL_STRIKE, carrier);
    }
}

/// A strike of `weight` against `ip`'s source on `carrier`, now.
fn strike(ip: IpAddr, weight: u32, carrier: OutboxCarrier) {
    strike_at(ip, weight, carrier, clock());
}

/// A strike of `weight` against `ip`'s source on `carrier` (a connection
/// to this node: `Via::DirectLink`) at `now`, while the responses gate is
/// live. The strike that bans notes `SEC_PREAUTH_FLOOD` once (the ledger
/// keeps a count per day, never the source).
fn strike_at(ip: IpAddr, weight: u32, carrier: OutboxCarrier, now: Instant) {
    if weight == 0 || !responding() {
        return;
    }
    let source = penalty_key(ip, carrier);
    let verdict = penalty().strike(source, weight, now);
    if let Verdict::Banned(_) = verdict {
        note(SecEvent::new(
            SecKind::PreauthFlood,
            Attribution::Network { source },
            Via::DirectLink(carrier),
            now_ms(),
        ));
    }
}

/// Is `ip`'s source banned at `now` (the beacon answerer answers no banned
/// source; it only looks, so no probation is used)? Never while the
/// responses gate is shut. The beacon's sources are on the local network.
pub(crate) fn beacon_banned(ip: IpAddr, now: Instant) -> bool {
    responding() && penalty().is_banned(penalty_key(ip, OutboxCarrier::Lan), now)
}

/// The beacon answerer dropped a query from `ip` at `now` (S22): a replay
/// of a query that matched one of our contacts (`SEC_BEACON_REPLAY`,
/// strike 4) or one over its source's rate limit (`SEC_BEACON_FLOOD`,
/// strike 1 like a listener's cap refusal).
pub(crate) fn beacon_refused(ip: IpAddr, replay: bool, now: Instant) {
    if !live() {
        return;
    }
    let kind = if replay {
        SecKind::BeaconReplay
    } else {
        SecKind::BeaconFlood
    };
    let via = Via::DirectLink(OutboxCarrier::Lan);
    note(SecEvent::new(
        kind,
        Attribution::Network {
            source: SourceKey::of(ip),
        },
        via,
        now_ms(),
    ));
    strike_at(ip, beacon_strike_weight(replay), OutboxCarrier::Lan, now);
}

/// A dropped beacon query's strike: a replay 4, a query over the rate 1.
pub(crate) fn beacon_strike_weight(replay: bool) -> u32 {
    if replay {
        events::strike_weight(SecKind::BeaconReplay)
    } else {
        CAP_REFUSAL_STRIKE
    }
}

/// Sources banned now (`Status.security.bans_active`).
fn bans_active() -> u16 {
    if !responding() {
        return 0;
    }
    u16::try_from(penalty().bans_active(clock())).unwrap_or(u16::MAX)
}

/// Is `ip`'s source on the LAN banned now (tests)?
#[cfg(test)]
pub(crate) fn source_banned(ip: IpAddr) -> bool {
    source_banned_on(ip, OutboxCarrier::Lan)
}

/// Is `ip`'s source on `carrier` banned now (tests)?
#[cfg(test)]
pub(crate) fn source_banned_on(ip: IpAddr, carrier: OutboxCarrier) -> bool {
    penalty().is_banned(penalty_key(ip, carrier), clock())
}

// ── Learning connectivity (6b risk 7) ──────────────────────────────────────

/// Dials whose link raised `SEC_LINK_TAG_FAIL`, until learning
/// connectivity's observer looks: the contact, the carrier and when.
static EXCLUDED: Mutex<Vec<([u8; 32], OutboxCarrier, u64)>> = Mutex::new(Vec::new());
/// At most this many held, each at most this long (a dial's observation
/// follows its result at once).
const EXCLUDED_MAX: usize = 64;
const EXCLUDED_FOR_MS: u64 = 2 * MINUTE_MS;

/// The dial to `contact` over `carrier` that just ended had its link
/// tampered with: learning must drop its observation, so whoever breaks
/// some links cannot steer the learned routes (merge amendment of P6.24).
pub(crate) fn exclude_dial(contact: &[u8; 32], carrier: OutboxCarrier) {
    let now = now_ms();
    let mut held = lock(&EXCLUDED);
    held.retain(|&(c, k, at)| {
        now.saturating_sub(at) < EXCLUDED_FOR_MS && (c, k) != (*contact, carrier)
    });
    if held.len() >= EXCLUDED_MAX {
        held.remove(0);
    }
    held.push((*contact, carrier, now));
}

/// Was the dial to `contact` over `carrier` that just ended excluded
/// ([`exclude_dial`])? Answers once. Learning connectivity's `observe_dial`
/// (Phase 6a P6.11) asks it while learning is on and drops the observation
/// when this is true.
pub(crate) fn take_excluded_dial(contact: &[u8; 32], carrier: OutboxCarrier) -> bool {
    let now = now_ms();
    let mut found = false;
    lock(&EXCLUDED).retain(|&(c, k, at)| {
        let fresh = now.saturating_sub(at) < EXCLUDED_FOR_MS;
        if fresh && (c, k) == (*contact, carrier) {
            found = true;
            return false;
        }
        fresh
    });
    found
}

// ── Early re-key and rollback recovery (design A R2, R3; step P6.27) ──────

/// What R2 did, as the alert's `action` ([`SecurityLedger::set_action`]).
pub(crate) const REKEY_REQUESTED: &str = "REKEY_REQUESTED";
/// What R3 did when it rotated the prekey (it asks for the re-keys too).
pub(crate) const PREKEY_ROTATED: &str = "PREKEY_ROTATED";
/// SEC_INDEX_JUMP from one contact this many times within
/// [`JUMP_WINDOW_MS`] asks for a re-key (one or two are a lost message or
/// two).
const JUMPS_FOR_REKEY: usize = 3;
const JUMP_WINDOW_MS: u64 = HOUR_MS;
/// Contacts whose index jumps are counted, and whose last re-key request is
/// remembered, at most (the oldest goes).
const RESPONDER_CONTACTS: usize = 256;
/// R3 as a whole (a prekey rotation and a re-key per contact) at most this
/// often: each rotation keeps a prekey generation for its grace (the
/// lifecycle holds at most four), and the store a rollback is found in
/// notes it again whenever it is opened.
const ROLLBACK_MIN_GAP_MS: u64 = raven_core::session_renewal::EARLY_MIN_GAP_MS;

/// What an event asks of the responder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Response {
    /// R2: renew the session with this contact early (the reason).
    Rekey([u8; 32], SecKind),
    /// R3: rotate this computer's prekey, then R2 for every contact with a
    /// live session.
    Rollback,
}

/// Which events ask for a response (OD6b-5 option 1): those only the
/// contact's own signature (an object that failed authentication or was
/// replayed under it, a third index jump in an hour) or this computer's own
/// disk (a rollback) can raise. A stranger's junk, a custodian's, a
/// depositor's or a relay's misbehaviour and a path's tag failures are
/// never one: they are about a network source, a carrier or a path.
#[derive(Default)]
struct Triggers {
    /// (contact, the times of its index jumps in the window), oldest first.
    jumps: Vec<([u8; 32], Vec<u64>)>,
}

impl Triggers {
    fn response(&mut self, ev: &SecEvent) -> Option<Response> {
        match (ev.kind, ev.who) {
            (SecKind::ObjectAuthFail | SecKind::ObjectReplay, Attribution::Contact { peer }) => {
                Some(Response::Rekey(peer, ev.kind))
            }
            (SecKind::IndexJump, Attribution::Contact { peer }) => self
                .jumped(peer, ev.at_ms)
                .then_some(Response::Rekey(peer, SecKind::IndexJump)),
            (SecKind::LocalRollback, Attribution::Local) => Some(Response::Rollback),
            _ => None,
        }
    }

    /// One index jump from `peer` at `at_ms`: `true` for the third within
    /// [`JUMP_WINDOW_MS`] (the count then starts again).
    fn jumped(&mut self, peer: [u8; 32], at_ms: u64) -> bool {
        let at = match self.jumps.iter().position(|(p, _)| *p == peer) {
            Some(at) => at,
            None => {
                if self.jumps.len() >= RESPONDER_CONTACTS {
                    self.jumps.remove(0);
                }
                self.jumps.push((peer, Vec::new()));
                self.jumps.len() - 1
            }
        };
        let times = &mut self.jumps[at].1;
        times.retain(|&t| t <= at_ms && at_ms - t < JUMP_WINDOW_MS);
        times.push(at_ms);
        if times.len() < JUMPS_FOR_REKEY {
            return false;
        }
        times.clear();
        true
    }
}

/// What carries R2 and R3 out: [`NodeAct`] (the profile's session store,
/// the renewer, the prekey), or a test's recorder.
trait Act {
    /// `node_policy.security_auto_rekey` while the responses gate is live.
    fn auto_rekey_on(&self) -> bool;
    /// R2 for `peer`: was the early re-key noted?
    fn rekey(&mut self, peer: &[u8; 32], reason: SecKind, now_ms: u64) -> bool;
    /// R3's prekey rotation: did it rotate? `None`: it cannot be tried yet
    /// (the identity comes with the outbox worker).
    fn rotate_prekey(&mut self) -> Option<bool>;
    /// R3's re-keys: for how many contacts was one noted? `None`: they
    /// cannot be asked yet.
    fn rekey_live_peers(&mut self, now_ms: u64) -> Option<usize>;
    /// R4: `peer`'s routes over `carrier` go last on `network` until
    /// `until_ms`. Was it noted?
    fn demote_path(
        &mut self,
        peer: &[u8; 32],
        network: [u8; 8],
        carrier: OutboxCarrier,
        until_ms: u64,
    ) -> bool;
    /// R5: forget the learned LAN addresses another key answered at for
    /// `peer` (within a day of `now_ms`). How many were forgotten?
    fn forget_impostor(&mut self, peer: &[u8; 32], now_ms: u64) -> usize;
    /// R6: one misbehaviour strike against `custodian`. Did it park it?
    fn strike_custodian(&mut self, custodian: &[u8; 32]) -> bool;
    /// R7: are `depositor`'s deposits throttled at `now_ms`?
    fn depositor_throttled(&mut self, depositor: &[u8; 32], now_ms: u64) -> bool;
    /// R8: put the relay noted as `subject` last until `until_ms`. Was it
    /// (the fallback for profiles whose learning does not score relays)?
    fn relay_last(&mut self, subject: &[u8; 32], until_ms: u64) -> bool;
}

/// The responder (the ledger writer's thread runs it for each event): the
/// response an event asks for, done, at most once per contact per
/// [`raven_core::session_renewal::EARLY_MIN_GAP_MS`] (the store's cap,
/// mirrored here so a contact's stream of bad objects opens no store) and
/// R3 at most once per [`ROLLBACK_MIN_GAP_MS`]. Never a block, an unpin or
/// a removal: a source scan (`security::tests`) holds it to that.
struct Responder<A> {
    triggers: Triggers,
    act: A,
    /// (contact, when its last re-key was asked for), oldest first.
    asked: Vec<([u8; 32], u64)>,
    rollback_at_ms: Option<u64>,
}

impl<A: Act> Responder<A> {
    fn new(act: A) -> Self {
        Self {
            triggers: Triggers::default(),
            act,
            asked: Vec::new(),
            rollback_at_ms: None,
        }
    }

    /// Respond to `ev` at `now_ms`: the code for its alert's `action`, or
    /// `None` (nothing asked, the gate shut, the policy off, or capped).
    fn respond(&mut self, ev: &SecEvent, now_ms: u64) -> Option<&'static str> {
        if !responding() {
            return None;
        }
        let response = self.triggers.response(ev)?;
        if !self.act.auto_rekey_on() {
            return None;
        }
        match response {
            Response::Rekey(peer, reason) => {
                self.rekey(&peer, reason, now_ms).then_some(REKEY_REQUESTED)
            }
            Response::Rollback => {
                if self
                    .rollback_at_ms
                    .is_some_and(|at| at.abs_diff(now_ms) < ROLLBACK_MIN_GAP_MS)
                {
                    return None;
                }
                let rotated = self.act.rotate_prekey();
                let asked = self.act.rekey_live_peers(now_ms);
                if rotated.is_none() && asked.is_none() {
                    // Not yet (a rollback found while the service starts):
                    // the next SEC_LOCAL_ROLLBACK tries again.
                    return None;
                }
                self.rollback_at_ms = Some(now_ms);
                if rotated == Some(true) {
                    Some(PREKEY_ROTATED)
                } else {
                    (asked.unwrap_or(0) > 0).then_some(REKEY_REQUESTED)
                }
            }
        }
    }

    /// Respond to `ev`, noted with `severity`, at `now_ms` (what the writer
    /// runs): R4-R8 for the events they take ([`path_answer`]), else R2
    /// and R3 ([`Self::respond`]). The code for its alert's `action`, or
    /// `None`.
    fn respond_at(
        &mut self,
        ev: &SecEvent,
        severity: Severity,
        now_ms: u64,
    ) -> Option<&'static str> {
        if !responding() {
            return None;
        }
        let Some(answer) = path_answer(ev, severity) else {
            return self.respond(ev, now_ms);
        };
        let act = &mut self.act;
        match answer {
            PathAnswer::Interference {
                peer,
                network,
                carrier,
            } => act
                .demote_path(
                    &peer,
                    network,
                    carrier,
                    now_ms.saturating_add(INTERFERENCE_MS),
                )
                .then_some(PATH_DEMOTED),
            PathAnswer::Impostor(peer) => {
                (act.forget_impostor(&peer, now_ms) > 0).then_some(ADDRESS_FORGOTTEN)
            }
            PathAnswer::Custodian(custodian) => {
                act.strike_custodian(&custodian).then_some(CUSTODIAN_PARKED)
            }
            PathAnswer::Depositor(depositor) => act
                .depositor_throttled(&depositor, now_ms)
                .then_some(DEPOSITS_THROTTLED),
            PathAnswer::Relay(subject) => act
                .relay_last(&subject, now_ms.saturating_add(RELAY_LAST_MS))
                .then_some(RELAY_DEMOTED),
        }
    }

    fn rekey(&mut self, peer: &[u8; 32], reason: SecKind, now_ms: u64) -> bool {
        let gap = raven_core::session_renewal::EARLY_MIN_GAP_MS;
        if self
            .asked
            .iter()
            .any(|(p, at)| p == peer && at.abs_diff(now_ms) < gap)
        {
            return false;
        }
        // Remembered once noted: a request the store could not take (busy,
        // its key not loaded yet) is asked again by the next event.
        let noted = self.act.rekey(peer, reason, now_ms);
        if noted {
            self.asked.retain(|(p, _)| p != peer);
            if self.asked.len() >= RESPONDER_CONTACTS {
                self.asked.remove(0);
            }
            self.asked.push((*peer, now_ms));
        }
        noted
    }
}

/// [`Act`] for real: the profile at `data_dir`.
struct NodeAct {
    data_dir: PathBuf,
}

impl Act for NodeAct {
    fn auto_rekey_on(&self) -> bool {
        raven_core::node_policy::load_policy(&self.data_dir).security_auto_rekey_on()
    }

    fn rekey(&mut self, peer: &[u8; 32], reason: SecKind, now_ms: u64) -> bool {
        let noted = IndexedSessionStore::open(&self.data_dir)
            .and_then(|mut store| session_renewal::request_early(&mut store, peer, reason, now_ms))
            .unwrap_or(false);
        if noted {
            crate::renewal::request_early(peer);
        }
        noted
    }

    fn rotate_prekey(&mut self) -> Option<bool> {
        // The worker's identity (none before the outbox runs).
        let ctx = crate::outbox::attempt_ctx()?;
        match raven_core::lan_dispatch::rotate_local_prekey_now(
            &self.data_dir,
            &ctx.identity,
            SecKind::LocalRollback.name(),
        ) {
            Ok(()) => Some(true),
            Err(_) => {
                eprintln!(
                    "raven-node security: the prekey could not be rotated after a rollback; \
                     still offering the current one"
                );
                Some(false)
            }
        }
    }

    fn rekey_live_peers(&mut self, now_ms: u64) -> Option<usize> {
        let ctx = crate::outbox::attempt_ctx()?;
        let local = ctx.identity.public_key_bytes();
        let asked = IndexedSessionStore::open(&self.data_dir).and_then(|mut store| {
            session_renewal::request_early_for_live_peers(
                &mut store,
                &local,
                SecKind::LocalRollback,
                now_ms,
            )
        });
        let Ok(asked) = asked else {
            return Some(0);
        };
        for peer in &asked {
            crate::renewal::request_early(peer);
        }
        Some(asked.len())
    }

    fn demote_path(
        &mut self,
        peer: &[u8; 32],
        network: [u8; 8],
        carrier: OutboxCarrier,
        until_ms: u64,
    ) -> bool {
        raven_core::route_memory::note_interference(peer, network, carrier, until_ms);
        true
    }

    fn forget_impostor(&mut self, peer: &[u8; 32], now_ms: u64) -> usize {
        take_impostor_addrs(peer, now_ms)
            .into_iter()
            .map(|ip| {
                let seen = raven_core::lan_seen::forget_at(&self.data_dir, peer, ip);
                let learned = raven_core::learned_routes::forget_lan_at(&self.data_dir, peer, ip);
                usize::from(seen == Ok(true) || learned == Ok(true))
            })
            .sum()
    }

    fn strike_custodian(&mut self, custodian: &[u8; 32]) -> bool {
        crate::custody::strike_misbehaved(custodian)
    }

    fn depositor_throttled(&mut self, depositor: &[u8; 32], now_ms: u64) -> bool {
        raven_core::friend_custody::depositor_throttled(depositor, now_ms)
    }

    fn relay_last(&mut self, subject: &[u8; 32], until_ms: u64) -> bool {
        if learning_scores_relays() {
            return false;
        }
        put_relay_last(subject, until_ms);
        true
    }
}

// ── Path, custodian, depositor and relay responses (design A R4-R8) ──────

/// R4's action: that contact's routes over that carrier go last on this
/// network ([`raven_core::route_memory::note_interference`]).
pub(crate) const PATH_DEMOTED: &str = "PATH_DEMOTED";
/// R5's: the learned address another key answered at was forgotten.
pub(crate) const ADDRESS_FORGOTTEN: &str = "ADDRESS_FORGOTTEN";
/// R6's: the custodian is not used as a mailbox for a day.
pub(crate) const CUSTODIAN_PARKED: &str = "CUSTODIAN_PARKED";
/// R7's: the depositor's deposits are answered RATE_LIMITED for an hour.
pub(crate) const DEPOSITS_THROTTLED: &str = "DEPOSITS_THROTTLED";
/// R8's: the relay goes last in every circuit order for an hour.
pub(crate) const RELAY_DEMOTED: &str = "RELAY_DEMOTED";
/// R4: how long the routes go last.
const INTERFERENCE_MS: u64 = raven_core::route_memory::INTERFERENCE_MS;
/// R8: how long a relay goes last.
const RELAY_LAST_MS: u64 = HOUR_MS;

/// What one event asks of R4-R8 (design A; step P6.28). Each is about a
/// path, a carrier or a depositor, never a block, an unpin or a removal of
/// a contact, and each ends by itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PathAnswer {
    /// R4: a Suspicious tag failure on a contact's link: its routes over
    /// that carrier go last on that network.
    Interference {
        peer: [u8; 32],
        network: [u8; 8],
        carrier: OutboxCarrier,
    },
    /// R5: another key answered at a contact's address often enough to be
    /// Suspicious: forget that learned address.
    Impostor([u8; 32]),
    /// R6: what a custodian served failed Raven's checks: a strike.
    Custodian([u8; 32]),
    /// R7: an object a depositor left here was refused.
    Depositor([u8; 32]),
    /// R8: a relay that lost receipts (Suspicious) or broke a link inside:
    /// last for an hour.
    Relay([u8; 32]),
}

/// Which events R4-R8 take, at what level. A custodian's or a relay's
/// misbehaviour is about that carrier only; a contact's bad letter (its
/// signature verified) is the sender's, not the custodian's.
fn path_answer(ev: &SecEvent, severity: Severity) -> Option<PathAnswer> {
    let suspicious = severity >= Severity::Suspicious;
    match (ev.kind, ev.who) {
        (SecKind::LinkTagFail, Attribution::Contact { peer }) if suspicious => {
            let carrier = match ev.via {
                Via::DirectLink(carrier) | Via::Dial(carrier) => carrier,
                Via::Custodian(_) | Via::Relay | Via::Local => return None,
            };
            Some(PathAnswer::Interference {
                peer,
                network: ev.network?,
                carrier,
            })
        }
        (SecKind::AddressImpostor, Attribution::Contact { peer }) if suspicious => {
            Some(PathAnswer::Impostor(peer))
        }
        (
            SecKind::CustodianBadObject | SecKind::CustodianUnrequested | SecKind::LetterBad,
            Attribution::Carrier {
                carrier,
                role: CarrierRole::Custodian,
            },
        ) => Some(PathAnswer::Custodian(carrier)),
        (SecKind::DepositorBadObject, Attribution::Contact { peer }) => {
            Some(PathAnswer::Depositor(peer))
        }
        (
            SecKind::RelayNoReceipt | SecKind::RelayLinkBroken,
            Attribution::Carrier {
                carrier,
                role: CarrierRole::Relay,
            },
        ) if suspicious => Some(PathAnswer::Relay(carrier)),
        _ => None,
    }
}

/// Where another key answered for a contact on the LAN (R5): the contact,
/// the address, when. Memory only, at most [`IMPOSTOR_ADDRS`] (the oldest
/// goes); R5 takes a contact's once its SEC_ADDRESS_IMPOSTOR is Suspicious.
static IMPOSTORS: Mutex<Vec<([u8; 32], IpAddr, u64)>> = Mutex::new(Vec::new());
const IMPOSTOR_ADDRS: usize = 64;

/// Another key answered at `ip` when this node dialled `contact` there, at
/// `now_ms` ([`address_impostor`]).
fn impostor_at(contact: &[u8; 32], ip: IpAddr, now_ms: u64) {
    if !responding() {
        return;
    }
    let mut held = lock(&IMPOSTORS);
    held.retain(|&(c, a, _)| (c, a) != (*contact, ip));
    if held.len() >= IMPOSTOR_ADDRS {
        held.remove(0);
    }
    held.push((*contact, ip, now_ms));
}

/// The addresses another key answered at for `contact` within a day of
/// `now_ms`, taken (R5 forgets each once).
fn take_impostor_addrs(contact: &[u8; 32], now_ms: u64) -> Vec<IpAddr> {
    let mut taken = Vec::new();
    lock(&IMPOSTORS).retain(|&(c, ip, at)| {
        if c != *contact {
            return true;
        }
        if at.abs_diff(now_ms) < DAY_MS {
            taken.push(ip);
        }
        false
    });
    taken
}

/// Does learning connectivity score relays (Phase 6a P6.15: learning live
/// and on for this profile)? Then a relay's security events go to its relay
/// term as a negative-only signal (`learning::relay_security_signal`,
/// bounded like the term) where its PeerId is known ([`relay_link_broken`],
/// [`relay_no_receipt`]), and nothing is put last by hand: the fallback
/// below is for profiles with learning off (P6.28's merge amendment).
fn learning_scores_relays() -> bool {
    crate::learning::live_on()
}

/// R8 for a profile that learns: the events R8 takes ([`path_answer`]: a
/// broken link, a Suspicious lost receipt) lower `relay`'s term instead of
/// putting it last. Only while the responses gate is live, like R8.
fn relay_signal(relay: &[u8]) {
    if responding() && learning_scores_relays() {
        crate::learning::relay_security_signal(relay);
    }
}

/// Relays put last in every circuit order (R8's fallback): their
/// [`events::relay_subject`] and until when (wall ms). Memory only, at most
/// [`RELAYS_LAST`] (the one ending first goes). A relay is never left out:
/// with no other relay it is still dialled.
static RELAYS_DEMOTED: Mutex<Vec<([u8; 32], u64)>> = Mutex::new(Vec::new());
const RELAYS_LAST: usize = 64;

fn put_relay_last(subject: &[u8; 32], until_ms: u64) {
    let mut held = lock(&RELAYS_DEMOTED);
    if let Some(entry) = held.iter_mut().find(|(s, _)| s == subject) {
        entry.1 = entry.1.max(until_ms);
        return;
    }
    if held.len() >= RELAYS_LAST {
        if let Some(first) = (0..held.len()).min_by_key(|&i| held[i].1) {
            held.swap_remove(first);
        }
    }
    held.push((*subject, until_ms));
}

/// Is any relay put last now (R8; a dial asks before it looks at each)?
/// Never while the responses gate is shut.
pub(crate) fn any_relay_demoted() -> bool {
    let now = now_ms();
    responding() && lock(&RELAYS_DEMOTED).iter().any(|(_, until)| now < *until)
}

/// Does the relay with PeerId bytes `relay` go last in circuit order now
/// (R8)? Never while the responses gate is shut.
pub(crate) fn relay_demoted(relay: &[u8]) -> bool {
    relay_demoted_at(relay, now_ms())
}

/// [`put_relay_last`] for the relay with PeerId bytes `relay` (other
/// modules' tests).
#[cfg(test)]
pub(crate) fn relay_last_for_test(relay: &[u8], until_ms: u64) {
    put_relay_last(&events::relay_subject(relay), until_ms);
}

fn relay_demoted_at(relay: &[u8], now_ms: u64) -> bool {
    if !responding() {
        return false;
    }
    let held = lock(&RELAYS_DEMOTED);
    if held.is_empty() {
        return false;
    }
    let subject = events::relay_subject(relay);
    held.iter()
        .any(|(s, until)| *s == subject && now_ms < *until)
}

// ── Status counts ──────────────────────────────────────────────────────────

/// Events per `SPAN_MS` slot over the last `N` slots.
struct Window<const N: usize, const SPAN_MS: u64> {
    /// (slot number, events in it).
    slots: [(u64, u32); N],
}

impl<const N: usize, const SPAN_MS: u64> Window<N, SPAN_MS> {
    const fn new() -> Self {
        Self { slots: [(0, 0); N] }
    }

    fn add(&mut self, at_ms: u64) {
        let slot = at_ms / SPAN_MS;
        let held = &mut self.slots[(slot % N as u64) as usize];
        if held.0 != slot {
            *held = (slot, 0);
        }
        held.1 = held.1.saturating_add(1);
    }

    fn sum(&self, now_ms: u64) -> u32 {
        let now = now_ms / SPAN_MS;
        self.slots
            .iter()
            .filter(|&&(slot, _)| slot <= now && now - slot < N as u64)
            .fold(0u32, |sum, &(_, n)| sum.saturating_add(n))
    }
}

/// What `Status.security` counts (memory only).
struct Counts {
    strangers: Window<60, MINUTE_MS>,
    preauth: Window<60, MINUTE_MS>,
    tag_failures: Window<24, HOUR_MS>,
}

static COUNTS: Mutex<Counts> = Mutex::new(Counts {
    strangers: Window::new(),
    preauth: Window::new(),
    tag_failures: Window::new(),
});
/// Events the queue dropped since raven-node started.
static DROPPED: AtomicU64 = AtomicU64::new(0);
/// Open alerts in the ledger, as the writer last read them.
static ALERTS_OPEN: AtomicU16 = AtomicU16::new(0);

fn count(ev: &SecEvent) {
    let mut counts = lock(&COUNTS);
    match ev.kind {
        SecKind::StrangerRefused
        | SecKind::BlockedRefused
        | SecKind::UnverifiedRemote
        | SecKind::P2pGateRefused => counts.strangers.add(ev.at_ms),
        SecKind::HandshakeFail | SecKind::PreauthMalformed => counts.preauth.add(ev.at_ms),
        SecKind::LinkTagFail => counts.tag_failures.add(ev.at_ms),
        _ => {}
    }
}

/// `Status.security`: `None` while the gate is shut (a release build's
/// Status is what it was).
pub(crate) fn status() -> Option<SecurityStatus> {
    if !live() {
        return None;
    }
    let now = now_ms();
    let bans_active = bans_active();
    let counts = lock(&COUNTS);
    Some(SecurityStatus {
        strangers_refused_1h: counts.strangers.sum(now),
        preauth_failures_1h: counts.preauth.sum(now),
        bans_active,
        link_tag_failures_24h: counts.tag_failures.sum(now),
        alerts_open: ALERTS_OPEN.load(Ordering::Relaxed),
        responses_live: security_gate::live(SecGate::Responses),
        dropped: u32::try_from(DROPPED.load(Ordering::Relaxed)).unwrap_or(u32::MAX),
    })
}

// ── The sink and its writer ────────────────────────────────────────────────

enum Msg {
    Event(SecEvent, Severity),
}

/// raven-node's [`SecSink`]: counts the event for `Status` and queues it
/// for the writer thread; never blocks (a full queue drops and counts).
pub(crate) struct NodeSink {
    tx: SyncSender<Msg>,
}

impl SecSink for NodeSink {
    fn accept(&self, ev: &SecEvent, severity: Severity) {
        count(ev);
        match self.tx.try_send(Msg::Event(*ev, severity)) {
            Ok(()) => {}
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                DROPPED.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// The writer's responder: the alert `action` code for an event it
/// answered, given the severity it was noted with ([`Responder::respond_at`]).
type Respond = Box<dyn FnMut(&SecEvent, Severity, u64) -> Option<&'static str> + Send>;

/// What the writer thread does with the queue: the responses (R2, R3), and
/// the ledger, opened when there is something to write.
struct Writer<O> {
    open: O,
    respond: Respond,
    ledger: Option<SecurityLedger>,
    /// When the next open may be tried.
    reopen_at_ms: u64,
    /// Network events by (day, kind), for the hourly count.
    network: BTreeMap<(u64, SecKind), u64>,
    /// Drops already added to the ledger's counter.
    dropped_written: u64,
    next_hour_ms: u64,
}

impl<O: FnMut() -> Result<SecurityLedger, LedgerError>> Writer<O> {
    fn new(open: O, now_ms: u64) -> Self {
        Self {
            open,
            respond: Box::new(|_, _, _| None),
            ledger: None,
            reopen_at_ms: 0,
            network: BTreeMap::new(),
            dropped_written: 0,
            next_hour_ms: now_ms.saturating_add(HOUR_MS),
        }
    }

    /// Answer the events the responder takes ([`Responder`]).
    fn responding_with(mut self, respond: Respond) -> Self {
        self.respond = respond;
        self
    }

    fn ledger(&mut self, now_ms: u64) -> Option<&mut SecurityLedger> {
        if self.ledger.is_none() && now_ms >= self.reopen_at_ms {
            match (self.open)() {
                Ok(ledger) => self.ledger = Some(ledger),
                // Not sealed, the key not loaded yet, busy or damaged: in
                // memory until the next try (best effort, never fatal).
                Err(_) => self.reopen_at_ms = now_ms.saturating_add(REOPEN_MS),
            }
        }
        self.ledger.as_mut()
    }

    fn event(&mut self, ev: &SecEvent, severity: Severity, now_ms: u64) {
        if let Attribution::Network { .. } = ev.who {
            let day = ev.at_ms / DAY_MS;
            let n = self.network.entry((day, ev.kind)).or_default();
            *n = n.saturating_add(1);
            let newest = self.network.keys().map(|&(d, _)| d).max().unwrap_or(day);
            self.network
                .retain(|&(d, _), _| d.saturating_add(NETWORK_DAYS) > newest);
            return;
        }
        // The responses first: a response never waits for the ledger (a
        // profile that is not sealed has none).
        let action = (self.respond)(ev, severity, now_ms);
        let Some(ledger) = self.ledger(now_ms) else {
            return;
        };
        // On an error the event stays pending in the ledger for its next
        // write (a lost write loses a count, never more).
        if let (Ok(Some(alert)), Some(code)) = (ledger.record(ev, severity, now_ms), action) {
            let _ = ledger.set_action(alert, code);
        }
        self.read_alerts();
    }

    /// The minute pass, and the hour's when it is due.
    fn tick(&mut self, now_ms: u64) {
        if let Some(ledger) = self.ledger.as_mut() {
            ledger.sweep_due(now_ms);
        }
        if now_ms >= self.next_hour_ms {
            self.next_hour_ms = now_ms.saturating_add(HOUR_MS);
            self.hourly(now_ms);
        }
    }

    /// The network counts, the dropped events, retention.
    fn hourly(&mut self, now_ms: u64) {
        let dropped = DROPPED.load(Ordering::Relaxed);
        let has_news = !self.network.is_empty() || dropped > self.dropped_written;
        if !has_news && self.ledger.is_none() {
            return;
        }
        let network = std::mem::take(&mut self.network);
        let dropped_written = self.dropped_written;
        let Some(ledger) = self.ledger(now_ms) else {
            self.network = network;
            return;
        };
        // What does not go in is kept for the next hour.
        let mut kept = BTreeMap::new();
        for ((day, kind), n) in network {
            if ledger.add_network_count(day, kind, n).is_err() {
                kept.insert((day, kind), n);
            }
        }
        let new_drops = dropped.saturating_sub(dropped_written);
        let noted = new_drops == 0 || ledger.note_dropped(new_drops).is_ok();
        let _ = ledger.prune(now_ms);
        if noted {
            self.dropped_written = dropped;
        }
        self.network = kept;
        self.read_alerts();
    }

    fn read_alerts(&mut self) {
        if let Some(n) = self.ledger.as_ref().and_then(|l| l.open_alert_count().ok()) {
            ALERTS_OPEN.store(u16::try_from(n).unwrap_or(u16::MAX), Ordering::Relaxed);
        }
    }

    /// At the end: what is held goes now.
    fn finish(&mut self, now_ms: u64) {
        self.hourly(now_ms);
        if let Some(ledger) = self.ledger.as_mut() {
            let _ = ledger.flush(now_ms);
        }
    }
}

/// The writer thread: queued events, a pass every [`TICK`], and the end
/// once every sender is gone.
fn run_writer<O>(rx: Receiver<Msg>, mut writer: Writer<O>)
where
    O: FnMut() -> Result<SecurityLedger, LedgerError>,
{
    let mut next_tick = now_ms().saturating_add(TICK.as_millis() as u64);
    loop {
        let wait = Duration::from_millis(next_tick.saturating_sub(now_ms()));
        match rx.recv_timeout(wait) {
            Ok(Msg::Event(ev, severity)) => writer.event(&ev, severity, now_ms()),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        let now = now_ms();
        if now >= next_tick {
            next_tick = now.saturating_add(TICK.as_millis() as u64);
            writer.tick(now);
        }
    }
    writer.finish(now_ms());
}

/// The running sink's sender (to end it) and the writer's "done" signal.
static RUNNING: Mutex<Option<(SyncSender<Msg>, Receiver<()>)>> = Mutex::new(None);

/// `raven-node service`: register [`NodeSink`] for `data_dir`, only while
/// the events gate is live (otherwise nothing starts, and `note` stays the
/// one-load no-op it is).
pub(crate) fn start(data_dir: &Path) {
    if !live() {
        return;
    }
    let mut running = lock(&RUNNING);
    if running.is_some() {
        return;
    }
    let (tx, rx) = mpsc::sync_channel(QUEUE);
    let (done_tx, done_rx) = mpsc::channel();
    let dd: PathBuf = data_dir.to_path_buf();
    let spawned = std::thread::Builder::new()
        .name("security-ledger".into())
        .spawn(move || {
            let mut responder = Responder::new(NodeAct {
                data_dir: dd.clone(),
            });
            let writer = Writer::new(move || SecurityLedger::open(&dd), now_ms()).responding_with(
                Box::new(move |ev, severity, now| responder.respond_at(ev, severity, now)),
            );
            run_writer(rx, writer);
            let _ = done_tx.send(());
        });
    if let Err(e) = spawned {
        eprintln!(
            "raven-node security: the ledger writer did not start ({e}); events stay in memory"
        );
        return;
    }
    events::set_sink(Box::new(NodeSink { tx: tx.clone() }));
    *running = Some((tx, done_rx));
}

/// At the service's end: stop taking events and let the writer put what it
/// holds into the ledger, waiting at most `wait`.
pub(crate) fn shutdown(wait: Duration) {
    let Some((tx, done)) = lock(&RUNNING).take() else {
        return;
    };
    events::clear_sink();
    drop(tx);
    let _ = done.recv_timeout(wait);
}

#[cfg(test)]
pub(crate) mod tests;
