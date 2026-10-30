//! Background outbox worker (transports design 2026-10 §2.4, phase P2a).
//!
//! `raven send` stages a message durably before it dials. When that dial does
//! not deliver (the peer is asleep, off the network, restarting), this worker
//! keeps retrying the **exact staged bytes** from the session store's outbox
//! until the first verified ACK or the envelope's expiry, so the message
//! arrives when the peer comes back, with no new `raven send`.
//!
//! - **Work source:** `IndexedSessionStore::pending_endpoint_outbound()` (not
//!   yet handed to a carrier) and `awaiting_ack_endpoint_outbound()` (written,
//!   no ACK yet). There is no second queue: the schedule below is in memory
//!   only and rebuilt from the store at every start.
//! - **Schedule:** monotonic (`tokio::time::Instant`), so a wall-clock step
//!   never stalls or rushes a retry; the wall clock decides expiry only. Per
//!   object: 5 s doubling to 10 min, ±50 % jitter, never sooner than 5 s after
//!   a failed attempt. Only due objects are dialled, each with its own count,
//!   plus that peer's strictly older waiting objects: they ride in the same
//!   dial, in write order, so a newer message never overtakes an older one.
//! - **Same rules as `raven send`:** the same per-peer
//!   [`raven_core::outbox::PeerSendLock`], the same store calls and the same
//!   ACK check ([`raven_core::outbox::accept_sealed_ack`]) and history
//!   functions. The lock is held only for store work: one attempt reads and
//!   validates under it, dials without it, and records the result under it
//!   again, so `raven send` never waits behind a dial.
//! - **Routes:** each object's own record (its `--carrier` choice and routes;
//!   no record means LAN from the contact book only), the contact's current
//!   addresses first, the LAN and Internet gates, Internet for verified
//!   contacts only and LAN addresses of unverified ones on the local network
//!   only. A route that answered with the wrong identity or refused this node
//!   is not retried for that object until `raven outbox retry`. A route that
//!   took an object's frames without a verified ACK coming back goes last in
//!   that object's next attempt, which starts at the route after it, round the
//!   plan (in memory only, G3): a link that keeps taking frames silently
//!   cannot keep its other routes from being tried. A route that recently
//!   reached the contact after a route above it failed goes first, on the
//!   same network, for a fixed 30 min ([`raven_core::route_memory`], G2, lab
//!   only): order only, after every rule above; the G3 rotation still moves
//!   a route that took an object's frames silently to the end. While route
//!   memory is live (lab), a learned LAN address ([`raven_core::lan_seen`])
//!   on none of this computer's current networks (`netwatch`) is not
//!   dialled: it is from a network this computer left (unless a
//!   point-to-point network, a VPN, may route to it). Saved addresses
//!   always are. Last of all, a p2p route whose contact is connected to this
//!   node right now goes first, so what waits for a contact behind a NAT
//!   rides the connection it opened (deliberate reversal, dial plan §2.3
//!   step 1): order only, and never G3's silent route. A p2p write records
//!   how its link travelled (`direct` / `reversed` / `relayed` /
//!   `hole_punched`, `raven outbox status`); a delivery that only rode the
//!   contact's own connection never earns a route memory lead (it cannot be
//!   repeated on demand). The Bluetooth nearby route (Phase 5, gated;
//!   [`crate::nearby`]) is derived live for a verified contact the nearby
//!   engine holds a pair key for, planned last and first only while its pipe
//!   is up; `NEARBY_NOT_IN_RANGE` (and `NEARBY_BUSY`: in range, every link
//!   in use) fails at once, and nothing nearby teaches the route memory or
//!   blocks a route.
//! - **Triggers:** an IPC `OutboxKick` right after a send stages, the backoff
//!   timer, a listener coming up (service start or a supervised restart), a
//!   change of this machine's network (`netwatch`; a wake from sleep and a
//!   moved default route count as one), and an authenticated inbound link
//!   from that contact (at most once a minute per contact).
//!   **Backoff restarts (G5):** the failure count starts over on an IPC
//!   `OutboxKick` (a send, `raven outbox retry`/`cancel`, a reset step; not an
//!   app submit), on a verified ACK from that contact (its other objects and
//!   owed ACKs), on its inbound link (at most once per 10 min) and on a
//!   network change (everybody's, each contact due within 5 s; `netwatch`
//!   debounces and spaces the changes). A write without an ACK never restarts
//!   anything.
//!   **Sibling wake (cutoff pack F5, behind the offline-LAN gate and M0):**
//!   a contact that answered on the local network (a verified ACK over a
//!   LAN dial of ours, or its authenticated inbound LAN link from a local
//!   address) proves the network works: every other contact whose last
//!   attempt planned a LAN route and that has a noise pin, with something
//!   waiting, is due within 5 s, its backoff started over under the same
//!   10 min per-contact cooldown as an inbound link's; at most once a
//!   minute in all. Internet and p2p successes wake nobody.
//! - **Stops:** a verified ACK (history `delivered`, and never back); expiry
//!   (abandoned, history `expired`); a revoked peer lineage (abandoned, history
//!   `failed`). With the long message horizon live (Phase 5a,
//!   [`raven_core::horizon`]) an expired message before its deadline is
//!   parked instead ([`raven_core::outbox::park_or_give_up_expired`]): it
//!   leaves the schedule, and its contact gets one `waiting` probe entry
//!   ([`Entry::is_probe`]) that keeps the normal backoff. A removed, blocked or not-verified-enough contact fails closed:
//!   the object is held, nothing is dialled. A row this node holds no message
//!   body for (sealed by `SealUnderSession`) is never touched.
//! - **ACKs we owe (F8):** an ACK whose reply could not be written on the
//!   inbound link is pushed to the sender, in the same dial as our own due
//!   objects to it.
//!
//! Logs carry counts and fixed codes only: no peer key, address or message id.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::Duration;

use raven_core::clock::now_ms;
use raven_core::device_cert::{ensure_local_device_certificate, DeviceCertificate};
use raven_core::envelope::{EnvType, Envelope};
use raven_core::identity::Identity;
use raven_core::indexed_session_store::{
    AuthorizedEndpointDevice, EndpointDeliveryState, EndpointOutbound, EndpointOutboundKind,
    EndpointOutboxState, IndexedSessionRecordKey, IndexedSessionStore, IndexedSessionStoreError,
};
use raven_core::ipc::OutboxItem;
use raven_core::learning::carry::{carry_token, CARRY_CAP};
use raven_core::learning::explain::Why;
use raven_core::learning::rank::Order;
use raven_core::outbox::{
    abandon_undelivered_to_peer, accept_sealed_ack, ack_frames, clear_object_routes,
    contact_admission, give_up_outbound, is_ack_frame, localize_lan_route, object_route_records,
    outbound_already_delivered, park_expired_message, park_or_give_up_expired, peer_lineage_denied,
    plan_object_routes, plan_object_routes_preferring, plan_object_routes_ranked,
    record_outbound_delivered, retry_delay, send_lock_busy, AckRejected, CarrierChoice,
    CarrierGates, ContactAdmission, ContactRoutes, DeliveryPath, ExpiredMessage, GiveUp,
    ObjectRoutes, OutboxCarrier, OutboxRoute, PeerSendLock, RoutePlan, RouteRefusal,
    CONTACT_NOT_VERIFIED, HISTORY_EXPIRED, HISTORY_FAILED, LOCALIZE_RESOLVE_TIMEOUT, RETRY_BASE,
    RETRY_MAX,
};
use raven_core::paths::PRIMARY_DEVICE_ID;
use tokio::time::Instant;

use crate::learning::DialMeta;
use crate::netutil;
use crate::onion::race::{RaceGuard, Side as RaceSide};

/// Without a kick or a due object the store is still re-read this often while
/// something is tracked, so a message staged by an older `raven send` (which
/// does not kick) is found.
const IDLE_REFRESH: Duration = Duration::from_secs(60);
/// With nothing tracked the store is re-read only as often as the expiry
/// prune reads it (`lan_direct::DURABLE_PRUNE_INTERVAL`): every send kicks, and
/// on a real install each store open reads the protected session state.
const IDLE_REFRESH_EMPTY: Duration = crate::lan_direct::DURABLE_PRUNE_INTERVAL;
/// After any attempt that did not finish an object, it waits at least this
/// long (no hot loop, even past its expiry when the store keeps failing).
const MIN_RETRY: Duration = RETRY_BASE;
/// How long one attempt waits for `raven send` (or another attempt) to release
/// the peer's send lock before it steps back.
const LOCK_WAIT: Duration = Duration::from_secs(2);
/// When the lock was busy: try again soon, without counting a failure.
const LOCK_BUSY_RETRY: Duration = Duration::from_secs(5);
/// Hard bound on one dial (the carriers have their own 40 s deadline).
const DIAL_DEADLINE: Duration = Duration::from_secs(45);
/// An exploration probe's carrier gives up at the probe's deadline; the
/// worker's bound on it is this much later (a p2p dial reads the book
/// before its clock starts).
const PROBE_OUTER_SLACK: Duration = Duration::from_secs(5);
/// Objects (and owed ACKs) sent in one dial at most; the rest go next round.
const MAX_FRAMES_PER_DIAL: usize = 16;
/// Live objects tracked at most (the store's one-prepared-message-per-session
/// rule keeps the real number small).
const MAX_TRACKED: usize = 1024;
/// Finished objects kept for `OutboxStatus` / `OutboxList`.
const MAX_DONE: usize = 256;
/// ACKs owed to senders whose inbound link dropped before the reply (F8), in
/// all and per sender (one contact cannot push out everybody else's).
const MAX_UNSENT_ACKS: usize = 256;
const MAX_UNSENT_ACKS_PER_PEER: usize = 32;
/// A contact's inbound link triggers a dial-back at most this often.
const DIALBACK_INTERVAL: Duration = Duration::from_secs(60);
/// A contact that had an authenticated LAN link within
/// [`crate::delivery_paths::HERE_SPAN`] and could not be reached is tried
/// again within this (E1: a friend's node restarted or locked for a few
/// minutes waited for a backoff of minutes after it came back; a LAN dial
/// costs little).
const LAN_SEEN_RETRY: Duration = Duration::from_secs(15);
/// A contact's inbound link starts its backoff over at most this often: one
/// that keeps dialling in while our dial-backs fail (NAT, a port we do not
/// know) keeps the normal backoff in between (G5).
const PEER_RESTART_COOLDOWN: Duration = RETRY_MAX;
/// After a network change each contact's objects are due at one uniform point
/// within this (G1, G5): its objects still share one dial, and the other
/// nodes on that network, which see the same change, do not all dial at once.
const NETWORK_SPREAD: Duration = RETRY_BASE;
/// A contact that answered on the local network wakes its LAN siblings
/// ([`network_proven`], cutoff pack F5) at most this often in all: with the
/// per-contact [`PEER_RESTART_COOLDOWN`] it bounds what a busy network costs.
const SIBLING_WAKE_MIN: Duration = Duration::from_secs(60);
/// A refusal of an object sealed under an older session counts as "this
/// session is gone for good" only after this many in a row, over this long:
/// transient receiver errors look the same on the wire.
const SUPERSEDED_REFUSALS: u32 = 3;
const SUPERSEDED_SPAN: Duration = Duration::from_secs(120);
/// One worker attempt per object at a time; `raven send` may hold the other.
/// Transports design §2.3: at most 2 concurrent attempts per object.
pub(crate) const MAX_CONCURRENT_ATTEMPTS_PER_OBJECT: usize = 2;

const _: () = assert!(MAX_CONCURRENT_ATTEMPTS_PER_OBJECT >= 1);
const _: () = assert!(MAX_UNSENT_ACKS_PER_PEER <= MAX_UNSENT_ACKS);

/// Stable codes for `last_error_code` (`raven outbox status`).
pub(crate) mod code {
    pub const NOT_A_CONTACT: &str = "NOT_A_CONTACT";
    pub const CONTACT_BLOCKED: &str = "CONTACT_BLOCKED";
    pub const CONTACTS_UNREADABLE: &str = "CONTACTS_UNREADABLE";
    /// The user paused sending to the contact ("Pause sending", Phase 6b
    /// P6.31: `node_policy` `send_hold`): held, nothing is dialled.
    pub const SENDING_PAUSED: &str = "SENDING_PAUSED";
    pub const NO_ROUTE: &str = "NO_ROUTE";
    /// Not dialled this round: the dial already carried MAX_FRAMES_PER_DIAL.
    pub const DEFERRED: &str = "DEFERRED";
    pub const SEND_IN_PROGRESS: &str = "SEND_IN_PROGRESS";
    pub const LOCK: &str = "LOCK";
    pub const LOCAL_DEVICE: &str = "LOCAL_DEVICE";
    pub const LOCAL_DEVICE_REVOKED: &str = "LOCAL_DEVICE_REVOKED";
    pub const PEER_REVOKED: &str = "PEER_REVOKED";
    pub const NO_PEER_CERT: &str = "NO_PEER_CERT";
    pub const NO_LOCAL_BODY: &str = "NO_LOCAL_BODY";
    pub const HISTORY: &str = "HISTORY";
    pub const CLOCK: &str = "CLOCK";
    pub const STORE: &str = "STORE";
    pub const NO_ACK_YET: &str = "NO_ACK_YET";
    pub const STAGE: &str = "STAGE";
    pub const SUPERSEDED: &str = "SUPERSEDED";
    pub const EXPIRED: &str = "EXPIRED";
    pub const INTERNET_HOLD: &str = "INTERNET_HOLD";
    pub const P2P_HOLD: &str = "P2P_HOLD";
    pub const P2P_NOT_RUNNING: &str = "P2P_NOT_RUNNING";
    // The Bluetooth nearby carrier (Phase 5, RNL1).
    pub const NEARBY_HOLD: &str = "NEARBY_HOLD";
    pub const NEARBY_NOT_RUNNING: &str = "NEARBY_NOT_RUNNING";
    /// The contact's beacon is not seen now: fails fast, never route
    /// evidence, never blocks the route.
    pub const NEARBY_NOT_IN_RANGE: &str = "NEARBY_NOT_IN_RANGE";
    /// The contact is in range but every nearby link (this node's or the
    /// contact's) is in use: as [`NEARBY_NOT_IN_RANGE`].
    pub const NEARBY_BUSY: &str = "NEARBY_BUSY";
    // The Tor onion carrier (lab, RAVEN_ONION_CARRIER_V1).
    pub const ONION_HOLD: &str = "ONION_HOLD";
    /// Tor is not ready on this computer (starting, blocked): never route
    /// evidence, never blocks the route.
    pub const ONION_NOT_READY: &str = "ONION_NOT_READY";
    /// The contact's onion service did not answer over Tor (offline, its
    /// service still publishing, Tor slow): as NOT_REACHABLE, for Tor.
    pub const ONION_UNREACHABLE: &str = "ONION_UNREACHABLE";
    pub const LINK_NOT_ACCEPTED: &str = "LINK_NOT_ACCEPTED";
    pub const PEER_REFUSED: &str = "PEER_REFUSED";
    pub const WRONG_IDENTITY: &str = "WRONG_IDENTITY";
    pub const NOT_LISTENING: &str = "NOT_LISTENING";
    pub const NOT_REACHABLE: &str = "NOT_REACHABLE";
    pub const CLOSED_EARLY: &str = "CLOSED_EARLY";
    pub const DIAL_FAILED: &str = "DIAL_FAILED";
    /// This node's noise pin store exists but cannot be read (M0): no dial
    /// goes out to anyone until it is fixed (`ash doctor` names the file).
    pub const PIN_STORE_UNREADABLE: &str = "PIN_STORE_UNREADABLE";
    // Session reset (lost-state recovery).
    pub use raven_core::session_reset::code::{PEER_RESET, PEER_RESET_NO_BODY, RESEAL_CAP};
    /// A sealed copy is held by a friend (custodian); not delivered yet.
    pub const IN_CUSTODY: &str = "IN_CUSTODY";
    // Friend custody status (Phase 3, RAVEN_ERROR_CODES_V1): shown instead of
    // a waiting message's reachability code, never a failure of their own
    // ([`super::custody_status`]).
    /// The contact collects mail only from friends this node has not
    /// verified (no announced custodian matched).
    pub const NO_SHARED_CUSTODIAN: &str = "NO_SHARED_CUSTODIAN";
    /// The friend the contact announced does not offer custody to this
    /// node, or not over the Internet while only Internet routes reach it.
    pub const CUSTODIAN_NOT_OFFERING: &str = "CUSTODIAN_NOT_OFFERING";
    /// Friend mailboxes are off here (`raven custody use on`) while the
    /// contact announced a friend this node knows.
    pub const MAILBOX_OFF: &str = "MAILBOX_OFF";
    // Sealed letters (Phase 5b, P5.15): a message in a letter that no friend
    // holds yet says why, never a failure of its own.
    pub use raven_core::letter_deposits::code::WAITING_FOR_CARRIER;
    pub use raven_core::letter_deposits::code::{CARRIER_FULL, NO_SHARED_CARRIER};
}

/// Where an object stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EntryState {
    /// Staged, not handed to a carrier yet.
    Queued,
    /// Written to the peer at least once, no ACK yet.
    Sent,
    /// Not tried: the contact was removed, blocked or is not verified enough
    /// for the routes left, the send lock was busy, ... (`last_error`).
    Held,
    Delivered,
    Expired,
    Failed,
    /// Left the store without the worker seeing why (`raven send` delivered or
    /// gave it up, `raven outbox cancel`, a prune): the history knows.
    Gone,
    /// A contact's parked messages (the long message horizon, Phase 5a):
    /// their envelopes ran out and they wait for a new session, until their
    /// deadlines. Only a probe entry ([`Entry::is_probe`]) is in this state.
    Waiting,
}

impl EntryState {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Sent => "sent",
            Self::Held => "held",
            Self::Delivered => "delivered",
            Self::Expired => "expired",
            Self::Failed => "failed",
            Self::Gone => "gone",
            Self::Waiting => "waiting",
        }
    }

    fn is_final(self) -> bool {
        matches!(
            self,
            Self::Delivered | Self::Expired | Self::Failed | Self::Gone
        )
    }
}

/// One tracked object (no plaintext, no ciphertext: the bytes stay in the store).
#[derive(Clone, Debug)]
pub(crate) struct Entry {
    pub(crate) object_digest: [u8; 32],
    pub(crate) kind: EndpointOutboundKind,
    pub(crate) session_id: [u8; 32],
    pub(crate) message_id: [u8; 16],
    pub(crate) recipient: [u8; 32],
    /// Wall-clock ms: expiry is the only wall-clock decision.
    pub(crate) expires_at_ms: u64,
    /// The envelope's creation time: a peer's objects go out in this order.
    pub(crate) created_at_ms: u64,
    /// Write order inside its session lane (the ratchet index).
    pub(crate) ratchet_index: u32,
    pub(crate) state: EntryState,
    /// Attempts the worker made (dials, monotonic).
    pub(crate) attempts: u32,
    /// Consecutive failures: drives the backoff. Back to 0 when the backoff
    /// starts over ([`Inner::restart_backoff`], G5).
    pub(crate) failures: u32,
    /// Monotonic: when the next attempt is due.
    pub(crate) next_due: Instant,
    pub(crate) last_carrier: Option<OutboxCarrier>,
    /// How the last p2p write travelled ([`DeliveryPath`]); `None` for a LAN
    /// or Internet direct write, so their views stay as they were.
    pub(crate) last_path: Option<DeliveryPath>,
    pub(crate) last_error: &'static str,
    /// Wall-clock ms when the attempt that delivered it ended (its verified
    /// receipt came back); 0 otherwise.
    pub(crate) delivered_at_ms: u64,
    /// Missing from the last store scan: the next attempt finds out why.
    pub(crate) vanished: bool,
    /// Routes that answered with the wrong identity or refused this node: not
    /// retried for this object until an explicit kick for its contact (an
    /// IPC or app kick: `raven outbox retry`, and also any send or app
    /// submit to that contact, [`kick`]).
    pub(crate) blocked_routes: Vec<OutboxRoute>,
    pub(crate) blocked_code: &'static str,
    /// Routes where another key answered before our Noise message 3 (M0, a
    /// noise pin mismatch; shown as WRONG_IDENTITY), for this object only:
    /// another object to the same contact plans them again. Scoped, unlike
    /// `blocked_routes`: private addresses repeat across networks, so the
    /// contact is often back at that very address later. Cleared by a
    /// network change, by the contact's own authenticated link or new route
    /// hints, and by an explicit kick for the contact (`raven outbox retry`,
    /// and any send or app submit to it). Each dial there stops at message 2
    /// again. In memory only.
    pub(crate) pin_blocked: Vec<OutboxRoute>,
    /// The route (as planned) that last took this object's frames without a
    /// verified ACK coming back on that dial: the next attempt starts at the
    /// route after it and tries it last (G3). Plan order when `None` or no
    /// longer planned. In memory only, like `blocked_routes`.
    pub(crate) unacked_route: Option<OutboxRoute>,
    /// Consecutive refusals by the peer, and when the first of them came.
    pub(crate) refusals: u32,
    pub(crate) first_refusal: Option<Instant>,
    /// Friends holding a sealed copy (friend custody).
    pub(crate) in_custody: u8,
    /// One of them took it to pass on to the contact's own friend (custody
    /// handoff, [`ObjectRoutes::custody_forwarded`]): once time runs out
    /// its delivery was not confirmed, rather than not collected (review
    /// handoff-3). Set by each `Deposited` outcome; a finished row keeps it.
    pub(crate) custody_forwarded: bool,
    /// Which friends, as its route record named them at its last attempt
    /// (Phase 6a carry choice, P6.16: kept only while carry choice is live).
    /// A delivery, expiry or park later credits them, also once the record
    /// is gone. In memory only.
    pub(crate) carried: Vec<[u8; 32]>,
    /// It never left this computer: the store held it as staged with no
    /// route record saying a contact read it ([`ObjectRoutes::written`]), or
    /// its route record as unsent (handed to the queue while the peer could
    /// not be reached), and no attempt since wrote it or gave a friend a
    /// copy. A finished (expired) row keeps it: "time ran out" (cutoff pack
    /// CP.6).
    pub(crate) never_sent: bool,
    /// The carriers its last attempt dialled, in order (E2 r40: the
    /// waiting reason names them all). In memory only.
    pub(crate) tried: Vec<OutboxCarrier>,
    /// Its attempts by how they ended, in the order each first happened
    /// (`raven outbox status`, E2 r40). In memory only.
    pub(crate) outcomes: Vec<(&'static str, u32)>,
}

/// Distinct ways an object's attempts are counted by
/// ([`Entry::outcomes`]); a further one adds to the last.
const OUTCOME_KINDS_MAX: usize = 8;

impl Entry {
    /// One more attempt that ended as `code` ([`Entry::outcomes`]).
    fn count_outcome(&mut self, code: &'static str) {
        if let Some((_, n)) = self.outcomes.iter_mut().find(|(c, _)| *c == code) {
            *n = n.saturating_add(1);
        } else if self.outcomes.len() < OUTCOME_KINDS_MAX {
            self.outcomes.push((code, 1));
        } else if let Some((_, n)) = self.outcomes.last_mut() {
            *n = n.saturating_add(1);
        }
    }

    /// The one entry that stands for a contact's parked messages (the long
    /// message horizon, Phase 5a; [`probe_row`]): it makes an attempt for
    /// the contact due on the normal backoff, and dials nothing of its own.
    /// Keyed by the contact's key, which no object digest is; no session.
    pub(crate) fn is_probe(&self) -> bool {
        self.object_digest == self.recipient
            && self.kind == EndpointOutboundKind::Message
            && self.session_id == [0u8; 32]
    }

    /// A parked message the horizon step gave up at its deadline, as a
    /// finished entry (`expired`; `never_sent` from its route record).
    fn parked_expired(peer: &[u8; 32], mid: &[u8; 16], never_sent: bool, now: Instant) -> Self {
        let row = ScanRow {
            object_digest: [0u8; 32],
            kind: EndpointOutboundKind::Message,
            session_id: [0u8; 32],
            message_id: *mid,
            recipient: *peer,
            expires_at_ms: 0,
            created_at_ms: 0,
            ratchet_index: 0,
            state: EntryState::Expired,
            never_sent,
        };
        Self {
            last_error: code::EXPIRED,
            never_sent,
            ..Self::from_row(&row, now)
        }
    }

    pub(crate) fn from_row(row: &ScanRow, now: Instant) -> Self {
        Self {
            object_digest: row.object_digest,
            kind: row.kind,
            session_id: row.session_id,
            message_id: row.message_id,
            recipient: row.recipient,
            expires_at_ms: row.expires_at_ms,
            created_at_ms: row.created_at_ms,
            ratchet_index: row.ratchet_index,
            state: row.state,
            attempts: 0,
            failures: 0,
            next_due: now,
            last_carrier: None,
            last_path: None,
            last_error: "",
            delivered_at_ms: 0,
            vanished: false,
            blocked_routes: Vec::new(),
            blocked_code: "",
            pin_blocked: Vec::new(),
            unacked_route: None,
            refusals: 0,
            first_refusal: None,
            in_custody: 0,
            custody_forwarded: false,
            carried: Vec::new(),
            tried: Vec::new(),
            outcomes: Vec::new(),
            never_sent: row.kind == EndpointOutboundKind::Message
                && row.state == EntryState::Queued
                && row.never_sent,
        }
    }

    /// The IPC view: the next attempt as wall-clock ms (0 when none).
    pub(crate) fn item(&self, now: Instant, wall_ms: u64) -> OutboxItem {
        OutboxItem {
            message_id_hex: hex::encode(self.message_id),
            peer_pub_hex: hex::encode(self.recipient),
            kind: match self.kind {
                EndpointOutboundKind::Message => "message".into(),
                EndpointOutboundKind::Ack => "ack".into(),
            },
            state: self.state.label().into(),
            carrier: self
                .last_carrier
                .map(|c| c.label().to_string())
                .unwrap_or_default(),
            attempts: self.attempts,
            next_attempt_ms: if self.state.is_final() {
                0
            } else {
                wall_ms
                    .saturating_add(self.next_due.saturating_duration_since(now).as_millis() as u64)
            },
            last_error_code: self.last_error.into(),
            delivered_at_ms: self.delivered_at_ms,
            expires_at_ms: self.expires_at_ms,
            path: self
                .last_path
                .map(|p| p.label().to_string())
                .unwrap_or_default(),
            why: String::new(),
            // Only once time ran out: until then it may still go.
            never_sent: self.never_sent && self.state == EntryState::Expired,
            in_custody: self.in_custody,
            custody_forwarded: self.custody_forwarded && self.in_custody > 0,
            tried: self.tried.iter().map(|c| c.label().to_string()).collect(),
            outcomes: self
                .outcomes
                .iter()
                .map(|(code, count)| raven_core::ipc::AttemptCount {
                    code: (*code).to_string(),
                    count: *count,
                })
                .collect(),
        }
    }
}

/// One outbox row as a store scan sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ScanRow {
    pub(crate) object_digest: [u8; 32],
    pub(crate) kind: EndpointOutboundKind,
    pub(crate) session_id: [u8; 32],
    pub(crate) message_id: [u8; 16],
    pub(crate) recipient: [u8; 32],
    pub(crate) expires_at_ms: u64,
    pub(crate) created_at_ms: u64,
    pub(crate) ratchet_index: u32,
    pub(crate) state: EntryState,
    /// No carrier ever wrote it, as far as the store and its route record
    /// tell (see [`Entry::never_sent`]).
    pub(crate) never_sent: bool,
}

/// An ACK we sealed for a message from `peer` whose reply was never written
/// on the inbound link (F8). The exact bytes from the store's ACK row.
#[derive(Clone, Debug)]
pub(crate) struct UnsentAck {
    pub(crate) peer: [u8; 32],
    pub(crate) bytes: Vec<u8>,
    pub(crate) expires_at_ms: u64,
    /// Consecutive failed pushes: drives the backoff. Back to 0 when the
    /// backoff starts over ([`Inner::restart_backoff`], G5).
    pub(crate) failures: u32,
    pub(crate) next_due: Instant,
    /// Also in `owed_acks.sqlite` (friend custody §9): never evicted here.
    pub(crate) durable: bool,
    /// Its session, when known (needed to file it with a custodian).
    pub(crate) session_id: Option<[u8; 32]>,
    /// Custodians already holding a copy.
    pub(crate) held_by: Vec<[u8; 32]>,
    /// May be left with a custodian (not a rebuilt, push-only entry).
    pub(crate) may_deposit: bool,
}

/// Everything due for one peer, handed to one attempt.
#[derive(Debug)]
pub(crate) struct DueWork {
    pub(crate) peer: [u8; 32],
    pub(crate) entries: Vec<Entry>,
    pub(crate) acks: Vec<([u8; 32], UnsentAck)>,
}

#[derive(Default)]
struct Inner {
    running: bool,
    entries: BTreeMap<[u8; 32], Entry>,
    done: VecDeque<Entry>,
    in_flight: HashSet<[u8; 32]>,
    /// Kicked while an attempt was in flight: due again as soon as it ends.
    kicked: HashSet<[u8; 32]>,
    /// Explicitly kicked while in flight: also forget blocked routes.
    clear_blocks: HashSet<[u8; 32]>,
    /// A noise pin block was cleared (M0: the contact's inbound link or new
    /// route hints) while an attempt was in flight: what that attempt found
    /// is cleared too once it is applied. Only ever peers in flight.
    clear_pins_after: HashSet<[u8; 32]>,
    /// In flight when the network changed: the route that attempt found
    /// silent is old-network evidence (G3), not recorded.
    net_changed: HashSet<[u8; 32]>,
    /// A scan found a new object for a peer it had to leave alone (in flight):
    /// scan again as soon as that peer's attempt is applied.
    rescan_after: HashSet<[u8; 32]>,
    /// Objects that were not due but rode along in their peer's dial (older
    /// than a due one): a failed dial does not count against their backoff.
    riding: HashSet<[u8; 32]>,
    unsent_acks: BTreeMap<[u8; 32], UnsentAck>,
    refresh: bool,
    /// Bumped by every applied attempt; a store scan older than a peer's last
    /// attempt is not merged for that peer (it may predate what it finished).
    apply_seq: u64,
    last_apply: HashMap<[u8; 32], u64>,
    last_dialback: HashMap<[u8; 32], Instant>,
    /// When an inbound link, or new routes from the contact, last started a
    /// contact's backoff over (G5).
    last_peer_restart: HashMap<[u8; 32], Instant>,
    /// When the contact's route hints last made its objects due
    /// ([`peer_routes_changed`]).
    last_routes_kick: HashMap<[u8; 32], Instant>,
    /// When a sign that the contact is back last made what waits for it due
    /// ([`peer_back`], [`Inner::back_now`]).
    last_back_kick: HashMap<[u8; 32], Instant>,
    /// When a contact's custody offer or announced custodians last made
    /// everything due ([`custodians_changed`]).
    last_custody_kick: Option<Instant>,
    /// A change that came inside [`MIN_RETRY`] of that kick: one more kick
    /// at this time (trailing edge, review D-7), so an attempt that read
    /// the routes before the change is not left to its backoff.
    custody_kick_pending: Option<Instant>,
    /// Sibling wakes are live (cutoff pack F5, [`sibling_wake_live`]): read
    /// once when the worker starts. Off, a LAN success wakes nobody else.
    sibling_wake: bool,
    /// Contacts whose last attempt planned a LAN route and found a noise pin
    /// for them ([`lan_wakeable`]): the ones another contact's success on
    /// this network may wake (F5).
    lan_wakeable: HashSet<[u8; 32]>,
    /// When a success on this network last woke anybody (F5).
    last_sibling_wake: Option<Instant>,
}

pub(crate) struct Outbox {
    inner: Mutex<Inner>,
    wake: tokio::sync::Notify,
}

static OUTBOX: OnceLock<Outbox> = OnceLock::new();

fn outbox() -> &'static Outbox {
    OUTBOX.get_or_init(|| Outbox {
        inner: Mutex::new(Inner::default()),
        wake: tokio::sync::Notify::new(),
    })
}

fn lock(m: &Mutex<Inner>) -> MutexGuard<'_, Inner> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn jitter() -> f64 {
    use rand::Rng;
    rand::thread_rng().gen_range(0.0..=1.0)
}

/// The wait after a failed attempt: the backoff, no later than the expiry (so
/// an expiring object is finished promptly), never sooner than [`MIN_RETRY`].
fn retry_wait(failures: u32, expires_at_ms: u64, wall_ms: u64, jitter: f64) -> Duration {
    let mut wait = retry_delay(failures, jitter);
    let to_expiry = expires_at_ms.saturating_sub(wall_ms);
    if to_expiry > 0 {
        wait = wait.min(Duration::from_millis(to_expiry));
    }
    wait.max(MIN_RETRY)
}

/// Is the worker running in this process (`raven-node service`)?
pub(crate) fn is_running() -> bool {
    lock(&outbox().inner).running
}

/// Make the objects to `peer` (or every object) due now and re-read the
/// store. `explicit` (an IPC or app kick: a send, an app submit, `raven
/// outbox retry`) also forgets routes blocked for those objects; `restart`
/// (a user's kick, not a machine's) also starts their backoff over (G5).
/// `false` when no worker runs in this process: nothing is retried in the
/// background then.
pub(crate) fn kick(peer: Option<&[u8; 32]>, explicit: bool, restart: bool) -> bool {
    let ob = outbox();
    let mut inner = lock(&ob.inner);
    if !inner.running {
        return false;
    }
    inner.kick_restart(peer, explicit, restart, Instant::now());
    drop(inner);
    ob.wake.notify_one();
    true
}

/// Groups (`raven_core::group`): a receive recorded work (a forward, a
/// receipt, a roster to send). The next scan runs `group::run_pending`,
/// which parks the copies, before it reads the store.
fn group_work() {
    let ob = outbox();
    let mut inner = lock(&ob.inner);
    if !inner.running {
        return;
    }
    inner.refresh = true;
    drop(inner);
    ob.wake.notify_one();
}

/// An authenticated contact just connected to us: it is online now. At most
/// one dial-back per contact per [`DIALBACK_INTERVAL`], and its backoff starts
/// over at most once per [`PEER_RESTART_COOLDOWN`] (G5).
pub(crate) fn peer_seen(peer: &[u8; 32]) {
    let ob = outbox();
    let mut inner = lock(&ob.inner);
    if !inner.running || !inner.peer_seen_now(peer, Instant::now()) {
        return;
    }
    drop(inner);
    ob.wake.notify_one();
}

/// A sign that `peer` is back (E1: a friend's node came back after a few
/// minutes, our node reached its listener 6 s later for another reason, and
/// what waited for it still waited for its backoff, over a minute): a dial of
/// ours of any purpose (custody, route hints, session renewal, a probe)
/// authenticated it, or its LAN address answered one. What waits for it goes
/// now ([`Inner::back_now`]).
pub(crate) fn peer_back(peer: &[u8; 32]) {
    let ob = outbox();
    let mut inner = lock(&ob.inner);
    if !inner.running || !inner.back_now(peer, Instant::now()) {
        return;
    }
    drop(inner);
    ob.wake.notify_one();
}

/// A contact told us new routes (its RRH1 changed what we plan for it):
/// retry what we hold for it now, even inside the dial-back window, at most
/// once per [`MIN_RETRY`]; its backoff starts over under the same
/// [`PEER_RESTART_COOLDOWN`] as an inbound link's (G5). An attempt in flight
/// is due again as soon as it ends.
pub(crate) fn peer_routes_changed(peer: &[u8; 32]) {
    let ob = outbox();
    let mut inner = lock(&ob.inner);
    if !inner.running || !inner.routes_changed_now(peer, Instant::now()) {
        return;
    }
    drop(inner);
    ob.wake.notify_one();
}

/// A contact's custody offer or the custodians it announced changed (its
/// RRH1, Phase 3): a friend may now take what waits for anybody (a custodian
/// that offers over the internet since its restart, say). Everything waiting
/// is due now, at most once per [`MIN_RETRY`] (a change inside it is not
/// dropped: everything is due again once it has passed); no backoff starts
/// over.
pub(crate) fn custodians_changed() {
    let ob = outbox();
    let mut inner = lock(&ob.inner);
    if !inner.running || !inner.custodians_changed_now(Instant::now()) {
        return;
    }
    drop(inner);
    ob.wake.notify_one();
}

/// A listener came up: at service start, when its supervisor restarted it
/// after a failure, or when the p2p host re-homed because every relay went
/// silent (a path loss, no network change). A plain kick, the backoff is not
/// started over. A network change (a wake from sleep and a moved default
/// route included, and the p2p host re-homing for one) goes through
/// [`network_changed`] instead.
pub(crate) fn listener_up() {
    let _ = kick(None, false, false);
}

/// This machine's network changed (`netwatch`, which debounces and spaces
/// the changes): every object and owed ACK starts its backoff over and is due
/// within [`NETWORK_SPREAD`]. How many wait; `None` when no worker runs in
/// this process.
pub(crate) fn network_changed() -> Option<usize> {
    let ob = outbox();
    let mut inner = lock(&ob.inner);
    if !inner.running {
        return None;
    }
    let waiting = inner.network_changed(Instant::now());
    drop(inner);
    ob.wake.notify_one();
    Some(waiting)
}

/// Sibling wakes (cutoff pack F5) are live: the offline-LAN gate, and M0
/// with it. With M0 off they wake nobody: a dial made sooner at a stale
/// address would hand over our identity to whatever answers there.
pub(crate) fn sibling_wake_live() -> bool {
    raven_core::offline_lan_live() && raven_core::lan_noise_pin_live()
}

/// May another contact's success on this network wake `peer` (F5)? Its plan
/// (`plan`, plain order) has a LAN route and it has a noise pin (an
/// unreadable pin store is no pin). `live` ([`sibling_wake_live`]) closed,
/// nothing is read.
fn lan_wakeable(data_dir: &Path, peer: &[u8; 32], plan: &[OutboxRoute], live: bool) -> bool {
    live && plan.iter().any(|r| r.carrier == OutboxCarrier::Lan)
        && matches!(
            raven_core::lan_noise_pin::load_pin(data_dir, peer),
            Ok(Some(_))
        )
}

/// Does an authenticated inbound LAN link from `source` say anything about
/// the local network (F5)? Only from a local address: the LAN listener also
/// takes a verified contact from anywhere, and that says nothing about it.
pub(crate) fn inbound_proves_network(source: Option<IpAddr>) -> bool {
    source.is_some_and(raven_core::outbox::is_local_network_ip)
}

/// Lines about sibling wakes (F5): counts only, one per 10 min at most.
static SIBLING_LOG: netutil::LogLimiter = netutil::LogLimiter::new(PEER_RESTART_COOLDOWN);

fn log_sibling_wake(woke: usize) {
    if woke > 0 {
        netutil::log_limited(
            &SIBLING_LOG,
            "raven-node outbox",
            format_args!("a contact answered on this network; retrying {woke} others"),
        );
    }
}

/// `except` just answered on the local network: its authenticated inbound
/// LAN link from a local address ([`inbound_proves_network`]; the worker
/// itself handles a verified ACK over a LAN dial of ours). Internet direct
/// and the p2p inner link never call this: they say nothing about the
/// local network. Its LAN siblings go now ([`Inner::network_proven_now`]).
pub(crate) fn network_proven(except: &[u8; 32]) {
    let ob = outbox();
    let mut inner = lock(&ob.inner);
    if !inner.running {
        return;
    }
    let woke = inner.network_proven_now(except, Instant::now());
    drop(inner);
    if woke > 0 {
        log_sibling_wake(woke);
        ob.wake.notify_one();
    }
}

/// The contacts something waits for: a live object or an ACK owed to them
/// (F8), the one waiting longest first, at most `limit`. The LAN beacon looks
/// for them after an interface or network change and polls the interfaces
/// sooner while there are any (RAVEN_LAN_BEACON_V1 §8). Empty when no worker
/// runs in this process.
pub(crate) fn waiting_peers(limit: usize) -> Vec<[u8; 32]> {
    let inner = lock(&outbox().inner);
    if !inner.running {
        return Vec::new();
    }
    inner.waiting_peers(limit)
}

/// Reply frames for `peer` that the inbound link could not write. The ACKs
/// among them are pushed to the sender later (F8); anything else (an RLB1
/// offer, a PairResponse the initiator retries anyway) is dropped.
pub(crate) fn note_unsent_replies(peer: &[u8; 32], replies: &[Vec<u8>]) {
    let ob = outbox();
    let mut inner = lock(&ob.inner);
    if !inner.running {
        return;
    }
    inner.note_unsent_acks(peer, replies, Instant::now(), now_ms());
    drop(inner);
    ob.wake.notify_one();
}

/// What the worker knows about one of our messages (live or recently done).
pub(crate) fn status(message_id: &[u8; 16]) -> Option<OutboxItem> {
    let inner = lock(&outbox().inner);
    let (now, wall) = (Instant::now(), now_ms());
    inner
        .entries
        .values()
        .find(|e| e.message_id == *message_id)
        .or_else(|| {
            inner
                .done
                .iter()
                .rev()
                .find(|e| e.message_id == *message_id)
        })
        .map(|e| e.item(now, wall))
}

/// Tracked objects (oldest first), then recently finished ones, at most `limit`.
pub(crate) fn list(peer: Option<&[u8; 32]>, limit: usize) -> Vec<OutboxItem> {
    let inner = lock(&outbox().inner);
    let (now, wall) = (Instant::now(), now_ms());
    let wanted = |e: &&Entry| peer.is_none_or(|p| *p == e.recipient);
    let mut live: Vec<&Entry> = inner.entries.values().filter(wanted).collect();
    live.sort_by_key(|e| (e.expires_at_ms, e.message_id));
    live.into_iter()
        .chain(inner.done.iter().rev().filter(wanted))
        .take(limit)
        .map(|e| e.item(now, wall))
        .collect()
}

/// The history's word (`delivered`, `expired`, `failed`, ...) and peer for our
/// outbound messages, by message id hex. Loaded once per IPC call, and only
/// when an answer needs it.
type HistoryStates = HashMap<String, (String, String)>;

fn load_history_states(data_dir: &Path) -> HistoryStates {
    raven_core::ChatHistory::load(data_dir)
        .map(|h| {
            h.entries
                .into_iter()
                .filter(|e| e.direction == "out")
                .map(|e| {
                    (
                        e.message_id_hex.to_ascii_lowercase(),
                        (e.peer_pub_hex, e.delivery),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Fill in what only the history knows about finished objects, loading the
/// history at most once (`load`) and only if some item needs it.
fn resolve_from_history(items: &mut [OutboxItem], load: impl FnOnce() -> HistoryStates) {
    let mut load = Some(load);
    let mut states: Option<HistoryStates> = None;
    for item in items
        .iter_mut()
        .filter(|i| i.state == EntryState::Gone.label())
    {
        let states = states.get_or_insert_with(|| (load.take().expect("loaded once"))());
        if let Some((_, delivery)) = states.get(&item.message_id_hex.to_ascii_lowercase()) {
            item.state = raven_core::sanitize::sanitize_terminal_line(delivery);
        }
    }
}

/// App channel objects: label them `app`, and give a finished one the state
/// its app record holds (they have no history row). No app store: no change.
fn resolve_app_items(data_dir: &Path, items: &mut [OutboxItem]) {
    use raven_core::app_store::{AppStore, MetadataOnly};
    if items.is_empty() || !raven_core::app_store::app_store_path(data_dir).exists() {
        return;
    }
    let Ok(store) = AppStore::open(data_dir, &MetadataOnly) else {
        return;
    };
    for item in items.iter_mut() {
        let Some(mid) = hex::decode(&item.message_id_hex)
            .ok()
            .and_then(|v| <[u8; 16]>::try_from(v).ok())
        else {
            continue;
        };
        if let Ok(Some(rec)) = store.record_by_message(&mid) {
            item.kind = "app".into();
            if item.state == EntryState::Gone.label() || rec.state.is_final() {
                item.state = rec.state.as_str().into();
                if item.last_error_code.is_empty() {
                    item.last_error_code = rec.last_error_code.clone();
                }
            }
        }
    }
}

/// An app object only its record still knows (§8.6 `status_anywhere`).
fn app_record_item(data_dir: &Path, message_id: &[u8; 16]) -> Option<OutboxItem> {
    use raven_core::app_store::{AppStore, MetadataOnly};
    if !raven_core::app_store::app_store_path(data_dir).exists() {
        return None;
    }
    let rec = AppStore::open(data_dir, &MetadataOnly)
        .ok()?
        .record_by_message(message_id)
        .ok()??;
    Some(OutboxItem {
        message_id_hex: hex::encode(message_id),
        peer_pub_hex: hex::encode(rec.peer_device),
        kind: "app".into(),
        state: rec.state.as_str().into(),
        last_error_code: rec.last_error_code,
        expires_at_ms: rec.expires_at_ms,
        ..OutboxItem::default()
    })
}

/// The long message horizon (Phase 5a, lab only): `peer`'s parked messages
/// (everybody's for `None`) as `waiting` items in send order, each with its
/// own deadline (`expires_at_ms`); the schedule (next attempt, attempts,
/// last error) is their contact's probe entry's (`schedule`). Empty while
/// the horizon is off. Blocking (store).
fn parked_items(
    data_dir: &Path,
    peer: Option<&[u8; 32]>,
    schedule: impl Fn(&[u8; 32]) -> Option<OutboxItem>,
) -> Vec<OutboxItem> {
    if !raven_core::horizon::horizon_live_enabled() {
        return Vec::new();
    }
    let Ok(store) = IndexedSessionStore::open(data_dir) else {
        return Vec::new();
    };
    let peers: Vec<[u8; 32]> = match peer {
        Some(p) => vec![*p],
        None => store
            .parked_peers()
            .map(|ps| ps.into_iter().map(|p| p.peer).collect())
            .unwrap_or_default(),
    };
    let mut items = Vec::new();
    for p in peers {
        let probe = schedule(&p).unwrap_or_default();
        for row in store.parked_for_recipient(&p).unwrap_or_default() {
            items.push(OutboxItem {
                message_id_hex: hex::encode(row.message_id),
                peer_pub_hex: hex::encode(p),
                kind: "message".into(),
                state: EntryState::Waiting.label().into(),
                attempts: probe.attempts,
                next_attempt_ms: probe.next_attempt_ms,
                last_error_code: probe.last_error_code.clone(),
                expires_at_ms: row.deadline_ms,
                ..OutboxItem::default()
            });
        }
    }
    items
}

/// The worker's probe entry for `peer`'s parked messages, as an item.
fn probe_status(peer: &[u8; 32]) -> Option<OutboxItem> {
    let inner = lock(&outbox().inner);
    let (now, wall) = (Instant::now(), now_ms());
    inner
        .entries
        .get(peer)
        .filter(|e| e.is_probe())
        .map(|e| e.item(now, wall))
}

/// Replace each probe item (state `waiting`: only a probe has it) by its
/// contact's parked messages ([`parked_items`]), at most `limit` items in
/// all.
fn expand_probes(data_dir: &Path, items: Vec<OutboxItem>, limit: usize) -> Vec<OutboxItem> {
    let waiting = EntryState::Waiting.label();
    if !items.iter().any(|i| i.state == waiting) {
        return items;
    }
    let mut out = Vec::new();
    for item in items {
        if item.state != waiting {
            out.push(item);
            continue;
        }
        let Some(peer) = hex::decode(&item.peer_pub_hex)
            .ok()
            .and_then(|v| <[u8; 32]>::try_from(v).ok())
        else {
            continue;
        };
        out.extend(parked_items(data_dir, Some(&peer), |_| Some(item.clone())));
    }
    out.truncate(limit);
    out
}

/// `OutboxStatus`: the worker's view, else the store's, else the history's.
/// Blocking (store, history). A parked message (the long message horizon) is
/// `waiting`, on its contact's probe schedule.
pub(crate) fn status_anywhere(data_dir: &Path, message_id: &[u8; 16]) -> Option<OutboxItem> {
    let (now, wall) = (Instant::now(), now_ms());
    let mid_hex = hex::encode(message_id);
    if let Some(item) = parked_items(data_dir, None, probe_status)
        .into_iter()
        .find(|i| i.message_id_hex == mid_hex)
    {
        return Some(item);
    }
    let found = status(message_id)
        .filter(|i| i.state != EntryState::Waiting.label())
        .or_else(|| {
            scan_store(data_dir)
                .ok()?
                .iter()
                .find(|r| r.message_id == *message_id && r.state != EntryState::Waiting)
                .map(|r| {
                    let mut item = Entry::from_row(r, now).item(now, wall);
                    item.next_attempt_ms = 0;
                    item
                })
        });
    let mut items = match found {
        Some(item) => vec![item],
        None => {
            if let Some(item) = app_record_item(data_dir, message_id) {
                return Some(item);
            }
            let states = load_history_states(data_dir);
            let (peer, delivery) = states.get(&hex::encode(message_id))?;
            return Some(OutboxItem {
                message_id_hex: hex::encode(message_id),
                peer_pub_hex: peer.to_ascii_lowercase(),
                kind: "message".into(),
                state: raven_core::sanitize::sanitize_terminal_line(delivery),
                ..OutboxItem::default()
            });
        }
    };
    resolve_app_items(data_dir, &mut items);
    resolve_from_history(&mut items, || load_history_states(data_dir));
    items.pop()
}

/// `OutboxList`: the worker's schedule when it runs, else the store's rows
/// (nothing retries them then). Blocking.
pub(crate) fn list_anywhere(
    data_dir: &Path,
    peer: Option<&[u8; 32]>,
    limit: usize,
) -> Result<(bool, Vec<OutboxItem>), String> {
    let running = is_running();
    let (now, wall) = (Instant::now(), now_ms());
    let items = if running {
        let mut items = list(peer, limit);
        // A message a send queued while the worker was busy (an attempt that
        // waits on Tor holds it for up to a minute) is listed at once, not
        // at the worker's next scan (E2 r40: 1 of 3 quick sends listed).
        if let Ok(rows) = scan_store(data_dir) {
            add_untracked(&mut items, &rows, peer, limit, now, wall);
        }
        items
    } else {
        scan_store(data_dir)?
            .iter()
            .filter(|r| peer.is_none_or(|p| *p == r.recipient))
            .take(limit)
            .map(|r| {
                let mut item = Entry::from_row(r, now).item(now, wall);
                item.next_attempt_ms = 0;
                item
            })
            .collect()
    };
    let mut items = expand_probes(data_dir, items, limit);
    resolve_app_items(data_dir, &mut items);
    resolve_from_history(&mut items, || load_history_states(data_dir));
    Ok((running, items))
}

/// The store's message rows to `peer` (to anyone for `None`) the worker does
/// not track yet, after the live ones in `items` (before the finished
/// ones), as queued: `items` stays within `limit`.
fn add_untracked(
    items: &mut Vec<OutboxItem>,
    rows: &[ScanRow],
    peer: Option<&[u8; 32]>,
    limit: usize,
    now: Instant,
    wall: u64,
) {
    let tracked: HashSet<[u8; 16]> = {
        let inner = lock(&outbox().inner);
        inner
            .entries
            .values()
            .chain(inner.done.iter())
            .map(|e| e.message_id)
            .collect()
    };
    merge_untracked(items, rows, &tracked, peer, limit, now, wall);
}

/// [`add_untracked`] with the worker's message ids (`tracked`) given.
fn merge_untracked(
    items: &mut Vec<OutboxItem>,
    rows: &[ScanRow],
    tracked: &HashSet<[u8; 16]>,
    peer: Option<&[u8; 32]>,
    limit: usize,
    now: Instant,
    wall: u64,
) {
    let new: Vec<OutboxItem> = rows
        .iter()
        .filter(|r| peer.is_none_or(|p| *p == r.recipient))
        .filter(|r| r.kind == EndpointOutboundKind::Message && !tracked.contains(&r.message_id))
        .filter(|r| r.object_digest != r.recipient)
        .map(|r| {
            let mut item = Entry::from_row(r, now).item(now, wall);
            // Due at once: the worker takes it when its attempt ends.
            item.next_attempt_ms = 0;
            item
        })
        .collect();
    if new.is_empty() {
        return;
    }
    let at = items
        .iter()
        .position(|i| !matches!(i.state.as_str(), "queued" | "sent" | "held" | "waiting"))
        .unwrap_or(items.len());
    items.splice(at..at, new);
    items.truncate(limit);
}

/// Whether raven-node's outbox carries a message to `peer` now: an attempt
/// for it runs, or a message to it waits (tracked, or staged by a send the
/// worker has not scanned yet). `false` while no worker runs.
pub(crate) fn carrying(data_dir: &Path, peer: &[u8; 32]) -> bool {
    {
        let inner = lock(&outbox().inner);
        if !inner.running {
            return false;
        }
        if inner.in_flight.contains(peer)
            || inner.entries.values().any(|e| {
                e.recipient == *peer
                    && e.kind == EndpointOutboundKind::Message
                    && !e.is_probe()
                    && matches!(e.state, EntryState::Queued | EntryState::Sent)
            })
        {
            return true;
        }
    }
    scan_store(data_dir).is_ok_and(|rows| {
        rows.iter().any(|r| {
            r.recipient == *peer
                && r.kind == EndpointOutboundKind::Message
                && r.object_digest != r.recipient
        })
    })
}

/// Every row the store still holds for us (no lock, read only).
pub(crate) fn scan_store(data_dir: &Path) -> Result<Vec<ScanRow>, String> {
    let store = IndexedSessionStore::open(data_dir).map_err(|e| e.redacted_display())?;
    let mut rows = Vec::new();
    let pending = store
        .pending_endpoint_outbound()
        .map_err(|e| e.redacted_display())?;
    let awaiting = store
        .awaiting_ack_endpoint_outbound()
        .map_err(|e| e.redacted_display())?;
    // Handed to the queue while the peer was unreachable and never written by a
    // carrier: still "queued", although the store holds it as awaiting an ACK.
    // A prepared one a contact read and refused was written (review
    // C-time-deadlines-1). Read as evidence: past its deadline too.
    let records = raven_core::outbox::object_route_evidence(data_dir, now_ms()).unwrap_or_default();
    let unsent = |r: &EndpointOutbound| records.get(&r.message_id).is_some_and(|o| o.unsent);
    let written = |r: &EndpointOutbound| records.get(&r.message_id).is_some_and(|o| o.written);
    for (row, state, never_sent) in pending
        .iter()
        .map(|r| (r, EntryState::Queued, !written(r)))
        .chain(awaiting.iter().map(|r| {
            if unsent(r) {
                (r, EntryState::Queued, true)
            } else {
                (r, EntryState::Sent, false)
            }
        }))
    {
        rows.push(scan_row(row, state, never_sent));
    }
    // The long message horizon (Phase 5a, lab only): one probe entry per
    // contact with parked messages.
    if raven_core::horizon::horizon_live_enabled() {
        let peers = store.parked_peers().map_err(|e| e.redacted_display())?;
        for p in peers {
            let parked = store
                .parked_for_recipient(&p.peer)
                .map_err(|e| e.redacted_display())?;
            if let Some(row) = probe_row(&p, &parked) {
                rows.push(row);
            }
        }
    }
    Ok(rows)
}

/// A contact's probe entry ([`Entry::is_probe`]): keyed by its key, due at
/// its first deadline at the latest (`expires_at_ms`, so the worker wakes
/// to settle what ran out), its oldest message first among what waits for
/// it (`created_at_ms`, `message_id`). `None` without parked messages.
fn probe_row(
    peer: &raven_core::indexed_session_store::ParkedPeer,
    parked: &[raven_core::indexed_session_store::ParkedOutbound],
) -> Option<ScanRow> {
    let oldest = parked.first()?;
    Some(ScanRow {
        object_digest: peer.peer,
        kind: EndpointOutboundKind::Message,
        session_id: [0u8; 32],
        message_id: oldest.message_id,
        recipient: peer.peer,
        expires_at_ms: peer.first_deadline_ms,
        created_at_ms: oldest.created_at_ms,
        ratchet_index: 0,
        state: EntryState::Waiting,
        never_sent: false,
    })
}

fn scan_row(row: &EndpointOutbound, state: EntryState, never_sent: bool) -> ScanRow {
    let envelope = Envelope::unpack(&row.immutable_envelope_bytes);
    ScanRow {
        object_digest: row.object_digest,
        kind: row.kind,
        session_id: row.session_id,
        message_id: row.message_id,
        recipient: row.recipient_device,
        expires_at_ms: envelope.as_ref().map(|e| e.expires_at).unwrap_or(0),
        created_at_ms: envelope.as_ref().map(|e| e.created_at).unwrap_or(0),
        ratchet_index: row.ratchet_index,
        state,
        never_sent,
    }
}

impl Inner {
    /// [`Self::kick_now`], after starting the backoff of the same objects
    /// over when `restart` (G5).
    fn kick_restart(
        &mut self,
        peer: Option<&[u8; 32]>,
        explicit: bool,
        restart: bool,
        now: Instant,
    ) {
        if restart {
            self.restart_backoff(peer);
        }
        self.kick_now(peer, explicit, now);
    }

    /// Start the backoff of `peer`'s objects and owed ACKs (or everybody's)
    /// over (G5): the next failure waits RETRY_BASE again, not up to
    /// RETRY_MAX. The schedule, attempts, refusal counts, blocked routes and
    /// last error are left alone. An attempt in flight records its result on
    /// top of this (its failure counts as the first). `true` when anything
    /// had failed.
    fn restart_backoff(&mut self, peer: Option<&[u8; 32]>) -> bool {
        let mut any = false;
        for entry in self
            .entries
            .values_mut()
            .filter(|e| peer.is_none_or(|p| *p == e.recipient))
        {
            any |= entry.failures > 0;
            entry.failures = 0;
        }
        for ack in self
            .unsent_acks
            .values_mut()
            .filter(|a| peer.is_none_or(|p| *p == a.peer))
        {
            any |= ack.failures > 0;
            ack.failures = 0;
        }
        any
    }

    fn kick_now(&mut self, peer: Option<&[u8; 32]>, explicit: bool, now: Instant) {
        self.kick_at(peer, explicit, |_| now);
    }

    /// Make the objects and owed ACKs to `peer` (or everybody's) due by
    /// `due(their contact)` at the latest and re-read the store; a contact
    /// whose attempt is in flight is due again as soon as it ends. `explicit`
    /// also forgets the routes blocked for those objects.
    fn kick_at(
        &mut self,
        peer: Option<&[u8; 32]>,
        explicit: bool,
        mut due: impl FnMut(&[u8; 32]) -> Instant,
    ) {
        for entry in self.entries.values_mut() {
            if peer.is_none_or(|p| *p == entry.recipient) {
                entry.next_due = entry.next_due.min(due(&entry.recipient));
                if explicit {
                    entry.blocked_routes.clear();
                    entry.blocked_code = "";
                    entry.pin_blocked.clear();
                }
            }
        }
        for ack in self.unsent_acks.values_mut() {
            if peer.is_none_or(|p| *p == ack.peer) {
                ack.next_due = ack.next_due.min(due(&ack.peer));
            }
        }
        // An attempt in flight works from what it was given: due again when
        // it ends, so this kick is not lost behind its backoff.
        let in_flight: Vec<[u8; 32]> = self
            .in_flight
            .iter()
            .filter(|p| peer.is_none_or(|k| k == *p))
            .copied()
            .collect();
        for p in in_flight {
            self.kicked.insert(p);
            if explicit {
                self.clear_blocks.insert(p);
            }
        }
        self.refresh = true;
    }

    /// This machine's network changed (G1): what failed on the old network
    /// says nothing about the new one. Every object and owed ACK starts its
    /// backoff over (G5) and is due within [`NETWORK_SPREAD`], at one offset
    /// per contact (its objects still share one dial). An attempt in flight
    /// records its result on top of the reset (its failure counts as the
    /// first) and is due again when it ends. Which route stayed silent (G3) is
    /// old-network evidence too: every object goes back to plan order, and an
    /// attempt in flight does not record the one it found silent. Blocked
    /// routes, refusal counts and the session-query pacing
    /// (`AttemptCtx::reset_backoff`) stay: they are the contact's answers, not
    /// our network's. A noise pin mismatch (`pin_blocked`) is the old
    /// network's answer: its routes are tried again, and an attempt in
    /// flight does not record the one it found. How many wait.
    fn network_changed(&mut self, now: Instant) -> usize {
        self.restart_backoff(None);
        for entry in self.entries.values_mut() {
            entry.unacked_route = None;
            entry.pin_blocked.clear();
        }
        // An attempt in flight wrote on the old network: what it reports
        // silent must not undo the reset above.
        self.net_changed.extend(self.in_flight.iter().copied());
        let mut offsets: HashMap<[u8; 32], Duration> = HashMap::new();
        self.kick_at(None, false, |p| {
            now + *offsets
                .entry(*p)
                .or_insert_with(|| NETWORK_SPREAD.mul_f64(jitter()))
        });
        self.entries.len() + self.unsent_acks.len()
    }

    /// [`waiting_peers`]: each contact with a live object or an owed ACK
    /// once, the oldest first by what it holds (an object's creation time;
    /// for an ACK owed on a dropped link, its expiry less the envelope
    /// lifetime, which is when it was sealed unless its session ended
    /// sooner), at most `limit`.
    fn waiting_peers(&self, limit: usize) -> Vec<[u8; 32]> {
        let mut oldest: HashMap<[u8; 32], u64> = HashMap::new();
        let mut note = |peer: [u8; 32], at: u64| {
            let t = oldest.entry(peer).or_insert(at);
            *t = (*t).min(at);
        };
        for e in self.entries.values().filter(|e| !e.state.is_final()) {
            note(e.recipient, e.created_at_ms);
        }
        for a in self.unsent_acks.values() {
            note(
                a.peer,
                a.expires_at_ms
                    .saturating_sub(raven_core::outbox::ENVELOPE_VALIDITY_MS),
            );
        }
        let mut peers: Vec<([u8; 32], u64)> = oldest.into_iter().collect();
        peers.sort_by_key(|&(peer, at)| (at, peer));
        peers
            .into_iter()
            .take(limit)
            .map(|(peer, _)| peer)
            .collect()
    }

    /// Cutoff pack F5: `except` answered on this network, so it works. Every
    /// other contact the last attempt found [`lan_wakeable`] that has
    /// something waiting (objects or owed ACKs) and no attempt in flight (it
    /// is being tried) is due within [`NETWORK_SPREAD`], at one offset per
    /// contact, its backoff started over at most once per
    /// [`PEER_RESTART_COOLDOWN`] ([`Self::restart_if_cool`], shared with its
    /// own inbound link). At most once per [`SIBLING_WAKE_MIN`] in all; a
    /// proof that woke nobody uses nothing up. No subnet matching: a host's
    /// saved routes for its clients are stale anyway, and the cooldowns
    /// bound the cost. How many contacts were woken (0 while
    /// [`Self::sibling_wake`] is off).
    fn network_proven_now(&mut self, except: &[u8; 32], now: Instant) -> usize {
        if !self.sibling_wake
            || self
                .last_sibling_wake
                .is_some_and(|t| now.saturating_duration_since(t) < SIBLING_WAKE_MIN)
        {
            return 0;
        }
        let waiting: BTreeSet<[u8; 32]> = self
            .entries
            .values()
            .filter(|e| !e.state.is_final())
            .map(|e| e.recipient)
            .chain(self.unsent_acks.values().map(|a| a.peer))
            .filter(|p| p != except && self.lan_wakeable.contains(p) && !self.in_flight.contains(p))
            .collect();
        if waiting.is_empty() {
            return 0;
        }
        self.last_sibling_wake = Some(now);
        for peer in &waiting {
            self.restart_if_cool(peer, now);
            let at = now + NETWORK_SPREAD.mul_f64(jitter());
            self.kick_at(Some(peer), false, |_| at);
        }
        waiting.len()
    }

    fn dialback_allowed(&mut self, peer: &[u8; 32], now: Instant) -> bool {
        match self.last_dialback.get(peer) {
            Some(last) if now.saturating_duration_since(*last) < DIALBACK_INTERVAL => false,
            _ => {
                self.last_dialback.insert(*peer, now);
                // Bounded: forget contacts not seen for a while.
                if self.last_dialback.len() > MAX_TRACKED {
                    self.last_dialback
                        .retain(|_, t| now.saturating_duration_since(*t) < DIALBACK_INTERVAL);
                }
                true
            }
        }
    }

    /// An authenticated inbound link from `peer`: one dial-back per
    /// [`DIALBACK_INTERVAL`] at most, and its backoff starts over at most once
    /// per [`PEER_RESTART_COOLDOWN`] (G5). Inside that window what waits for
    /// it still goes, as for any sign that it is back ([`Self::back_now`]).
    /// `false` when nothing was scheduled.
    fn peer_seen_now(&mut self, peer: &[u8; 32], now: Instant) -> bool {
        // The contact itself just authenticated: where another key answered
        // for it before (M0) is worth a try again, whether or not this link
        // earns a dial-back (the next attempt tries it).
        self.clear_pin_blocks(peer);
        if !self.dialback_allowed(peer, now) {
            return self.back_now(peer, now);
        }
        self.last_back_kick.insert(*peer, now);
        self.restart_if_cool(peer, now);
        self.kick_now(Some(peer), false, now);
        true
    }

    /// A sign that `peer` is back ([`peer_back`], or its inbound link inside
    /// the dial-back window): what waits for it (objects or owed ACKs) is
    /// due now, its backoff started over under [`PEER_RESTART_COOLDOWN`], at
    /// most once per [`MIN_RETRY`] (not the custody fetch's once a minute).
    /// Nothing while an attempt for it is in flight (that attempt is what
    /// reached it, or ends soon) or while nothing waits for it. `true` when
    /// it kicked.
    fn back_now(&mut self, peer: &[u8; 32], now: Instant) -> bool {
        let waits = self
            .entries
            .values()
            .any(|e| e.recipient == *peer && !e.state.is_final())
            || self.unsent_acks.values().any(|a| a.peer == *peer);
        let recent = self
            .last_back_kick
            .get(peer)
            .is_some_and(|t| now.saturating_duration_since(*t) < MIN_RETRY);
        if !waits || recent || self.in_flight.contains(peer) {
            return false;
        }
        self.last_back_kick.insert(*peer, now);
        // Bounded like the dial-back times.
        if self.last_back_kick.len() > MAX_TRACKED {
            self.last_back_kick
                .retain(|_, t| now.saturating_duration_since(*t) < MIN_RETRY);
        }
        self.restart_if_cool(peer, now);
        self.kick_now(Some(peer), false, now);
        true
    }

    /// `peer`'s route hints changed what we plan for it
    /// ([`peer_routes_changed`]): due now, inside the dial-back window too,
    /// at most once per [`MIN_RETRY`]; it uses up the dial-back window and
    /// shares the restart cooldown with [`Self::peer_seen_now`]. `false` when
    /// nothing was scheduled.
    fn routes_changed_now(&mut self, peer: &[u8; 32], now: Instant) -> bool {
        // Its routes changed: a noise pin mismatch on an old one says nothing
        // about them (M0).
        self.clear_pin_blocks(peer);
        if self
            .last_routes_kick
            .get(peer)
            .is_some_and(|t| now.saturating_duration_since(*t) < MIN_RETRY)
        {
            return false;
        }
        self.last_routes_kick.insert(*peer, now);
        // Bounded like the dial-back times.
        if self.last_routes_kick.len() > MAX_TRACKED {
            self.last_routes_kick
                .retain(|_, t| now.saturating_duration_since(*t) < MIN_RETRY);
        }
        self.last_dialback.insert(*peer, now);
        if self.last_dialback.len() > MAX_TRACKED {
            self.last_dialback
                .retain(|_, t| now.saturating_duration_since(*t) < DIALBACK_INTERVAL);
        }
        // A sign that it is back ([`Self::back_now`]) right after waits too.
        self.last_back_kick.insert(*peer, now);
        if self.last_back_kick.len() > MAX_TRACKED {
            self.last_back_kick
                .retain(|_, t| now.saturating_duration_since(*t) < MIN_RETRY);
        }
        self.restart_if_cool(peer, now);
        self.kick_now(Some(peer), false, now);
        true
    }

    /// [`custodians_changed`]: every object and owed ACK due now, at most
    /// once per [`MIN_RETRY`], the backoffs kept. A change inside
    /// [`MIN_RETRY`] of the last kick is not dropped: one kick is scheduled
    /// for when [`MIN_RETRY`] has passed ([`Self::fire_custody_kick`]).
    /// `false` when nothing new was scheduled (one is pending already).
    fn custodians_changed_now(&mut self, now: Instant) -> bool {
        if let Some(last) = self.last_custody_kick {
            if now.saturating_duration_since(last) < MIN_RETRY {
                if self.custody_kick_pending.is_some() {
                    return false;
                }
                self.custody_kick_pending = Some(last + MIN_RETRY);
                // The worker wakes to sleep until then at the latest.
                return true;
            }
        }
        self.custody_kick_now(now);
        true
    }

    /// The custody kick [`Self::custodians_changed_now`] scheduled, once its
    /// time came (the worker, each round). `true` when it kicked.
    fn fire_custody_kick(&mut self, now: Instant) -> bool {
        if !self.custody_kick_pending.is_some_and(|at| at <= now) {
            return false;
        }
        self.custody_kick_now(now);
        true
    }

    fn custody_kick_now(&mut self, now: Instant) {
        self.last_custody_kick = Some(now);
        self.custody_kick_pending = None;
        self.kick_now(None, false, now);
    }

    /// Forget the routes where another key answered for `peer` (M0). An
    /// attempt in flight forgets what it found too, once it is applied.
    fn clear_pin_blocks(&mut self, peer: &[u8; 32]) {
        for entry in self.entries.values_mut().filter(|e| e.recipient == *peer) {
            entry.pin_blocked.clear();
        }
        if self.in_flight.contains(peer) {
            self.clear_pins_after.insert(*peer);
        }
    }

    /// Start `peer`'s backoff over (G5) unless it did within
    /// [`PEER_RESTART_COOLDOWN`]; only a restart that changed something uses
    /// up the cooldown. The one restart rule of [`Self::peer_seen_now`] and
    /// [`Self::routes_changed_now`].
    fn restart_if_cool(&mut self, peer: &[u8; 32], now: Instant) {
        let cooling = self
            .last_peer_restart
            .get(peer)
            .is_some_and(|t| now.saturating_duration_since(*t) < PEER_RESTART_COOLDOWN);
        if !cooling && self.restart_backoff(Some(peer)) {
            self.last_peer_restart.insert(*peer, now);
            // Bounded: forget restarts whose cooldown is over.
            if self.last_peer_restart.len() > MAX_TRACKED {
                self.last_peer_restart
                    .retain(|_, t| now.saturating_duration_since(*t) < PEER_RESTART_COOLDOWN);
            }
        }
    }

    fn note_unsent_acks(&mut self, peer: &[u8; 32], replies: &[Vec<u8>], now: Instant, wall: u64) {
        for reply in replies {
            let Some(env) = Envelope::unpack(reply) else {
                continue;
            };
            if env.env_type != EnvType::Ack as u8 || env.expires_at <= wall {
                continue;
            }
            let digest = raven_core::authenticated_object_digest(&env);
            if self.unsent_acks.contains_key(&digest) {
                continue;
            }
            // Per sender first, then in all: the one that expires first goes.
            let mine = self
                .unsent_acks
                .values()
                .filter(|a| a.peer == *peer)
                .count();
            let full =
                mine >= MAX_UNSENT_ACKS_PER_PEER || self.unsent_acks.len() >= MAX_UNSENT_ACKS;
            if full {
                let victim = self
                    .unsent_acks
                    .iter()
                    .filter(|(_, a)| !a.durable)
                    .filter(|(_, a)| mine < MAX_UNSENT_ACKS_PER_PEER || a.peer == *peer)
                    .min_by_key(|(_, a)| a.expires_at_ms)
                    .map(|(k, _)| *k);
                if let Some(victim) = victim {
                    self.unsent_acks.remove(&victim);
                }
            }
            self.unsent_acks.insert(
                digest,
                UnsentAck {
                    peer: *peer,
                    bytes: reply.clone(),
                    expires_at_ms: env.expires_at,
                    failures: 0,
                    next_due: now,
                    durable: false,
                    session_id: None,
                    held_by: Vec::new(),
                    may_deposit: true,
                },
            );
        }
        self.refresh = true;
    }

    /// Durable owed ACKs (friend custody §9) join the in-memory queue; they
    /// are never evicted, and leave only through `acks_done`.
    fn merge_owed(&mut self, owed: Vec<raven_core::owed_acks::OwedAck>, now: Instant) {
        for o in owed {
            match self.unsent_acks.get_mut(&o.ack_digest) {
                Some(entry) => {
                    entry.durable = true;
                    entry.session_id = entry.session_id.or(o.session_id);
                    entry.held_by = o.held_by;
                    entry.may_deposit = o.origin.may_deposit();
                }
                None => {
                    self.unsent_acks.insert(
                        o.ack_digest,
                        UnsentAck {
                            peer: o.peer,
                            bytes: o.bytes,
                            expires_at_ms: o.expires_at_ms,
                            failures: 0,
                            next_due: now,
                            durable: true,
                            session_id: o.session_id,
                            held_by: o.held_by,
                            may_deposit: o.origin.may_deposit(),
                        },
                    );
                }
            }
        }
    }

    /// The apply sequence a store scan started at (see [`Self::merge`]).
    fn scan_seq(&self) -> u64 {
        self.apply_seq
    }

    /// Fold a store scan into the schedule: new rows are due now (this is the
    /// rebuild at start-up), known rows take the store's state, and rows the
    /// store no longer holds are flagged for their peer's next attempt. A peer
    /// whose attempt finished after the scan started (`scan_seq`), or is in
    /// flight, is left alone: the scan may predate what that attempt did.
    fn merge(&mut self, rows: Vec<ScanRow>, scan_seq: u64, now: Instant, wall: u64) {
        let fresh = |inner: &Self, peer: &[u8; 32]| {
            !inner.in_flight.contains(peer)
                && inner
                    .last_apply
                    .get(peer)
                    .is_none_or(|seq| *seq <= scan_seq)
        };
        let seen: HashSet<[u8; 32]> = rows.iter().map(|r| r.object_digest).collect();
        for row in rows {
            if !fresh(self, &row.recipient) {
                // A row this schedule has never seen (staged while that peer's
                // attempt ran) must not wait for the idle refresh (up to 10
                // min). Only rows a fresh merge would track count: never an
                // expired ACK or one past MAX_TRACKED, or this rescans forever.
                let would_track = !self.entries.contains_key(&row.object_digest)
                    && !(row.kind == EndpointOutboundKind::Ack && row.expires_at_ms <= wall)
                    && self.entries.len() < MAX_TRACKED;
                if would_track {
                    if self.in_flight.contains(&row.recipient) {
                        self.rescan_after.insert(row.recipient);
                    } else {
                        self.refresh = true;
                    }
                }
                continue;
            }
            if row.kind == EndpointOutboundKind::Ack && row.expires_at_ms <= wall {
                // Never sendable again; the store retires it.
                self.entries.remove(&row.object_digest);
                continue;
            }
            if let Some(entry) = self.entries.get_mut(&row.object_digest) {
                entry.vanished = false;
                if entry.is_probe() {
                    // What waits for the contact changes under it.
                    entry.message_id = row.message_id;
                    entry.expires_at_ms = row.expires_at_ms;
                    entry.created_at_ms = row.created_at_ms;
                }
                if entry.state != EntryState::Held {
                    entry.state = row.state;
                }
                // Written meanwhile (`raven send` dialled it itself, or the
                // contact read it and refused it).
                if row.state == EntryState::Sent || !row.never_sent {
                    entry.never_sent = false;
                }
                continue;
            }
            if self.entries.len() >= MAX_TRACKED {
                continue;
            }
            self.entries
                .insert(row.object_digest, Entry::from_row(&row, now));
        }
        let stale: Vec<[u8; 32]> = self
            .entries
            .values()
            .filter(|e| !seen.contains(&e.object_digest) && fresh(self, &e.recipient))
            .map(|e| e.object_digest)
            .collect();
        for digest in stale {
            if let Some(entry) = self.entries.get_mut(&digest) {
                if !entry.vanished {
                    entry.vanished = true;
                    entry.next_due = now;
                }
            }
        }
    }

    /// The work that is due now, by peer, each peer marked in flight (one
    /// attempt per peer at a time, so one per object). Only due objects go.
    fn take_due(&mut self, now: Instant) -> Vec<DueWork> {
        let mut by_peer: BTreeMap<[u8; 32], DueWork> = BTreeMap::new();
        for entry in self.entries.values() {
            if entry.next_due <= now && !self.in_flight.contains(&entry.recipient) {
                by_peer
                    .entry(entry.recipient)
                    .or_insert_with(|| DueWork {
                        peer: entry.recipient,
                        entries: Vec::new(),
                        acks: Vec::new(),
                    })
                    .entries
                    .push(entry.clone());
            }
        }
        for (digest, ack) in &self.unsent_acks {
            if ack.next_due <= now && !self.in_flight.contains(&ack.peer) {
                by_peer
                    .entry(ack.peer)
                    .or_insert_with(|| DueWork {
                        peer: ack.peer,
                        entries: Vec::new(),
                        acks: Vec::new(),
                    })
                    .acks
                    .push((*digest, ack.clone()));
            }
        }
        for peer in by_peer.keys() {
            self.in_flight.insert(*peer);
        }
        for work in by_peer.values_mut() {
            // Each object backs off on its own jittered timer, so a queue can
            // split. Once a peer is dialled, its strictly older waiting objects
            // ride along (no extra connection), so nothing newer overtakes
            // them; each still keeps its own failure count.
            let newest_due = work
                .entries
                .iter()
                .map(|e| e.created_at_ms)
                .max()
                .unwrap_or(0);
            let taken: HashSet<[u8; 32]> = work.entries.iter().map(|e| e.object_digest).collect();
            for entry in self.entries.values() {
                if entry.recipient == work.peer
                    && !taken.contains(&entry.object_digest)
                    && matches!(entry.state, EntryState::Queued | EntryState::Sent)
                    && entry.created_at_ms < newest_due
                {
                    self.riding.insert(entry.object_digest);
                    work.entries.push(entry.clone());
                }
            }
            // `entries` is keyed by digest: send in write order instead. In a
            // session lane the ratchet index is that order (a clock step cannot
            // reorder it); lanes go by the first object's creation time.
            let mut lane_start: HashMap<([u8; 32], bool), u64> = HashMap::new();
            for e in &work.entries {
                let lane = (e.session_id, e.kind == EndpointOutboundKind::Ack);
                let start = lane_start.entry(lane).or_insert(e.created_at_ms);
                *start = (*start).min(e.created_at_ms);
            }
            work.entries.sort_by_key(|e| {
                let lane = (e.session_id, e.kind == EndpointOutboundKind::Ack);
                (lane_start[&lane], lane, e.ratchet_index)
            });
        }
        by_peer.into_values().collect()
    }

    /// How long until the next due object or the pending custody kick
    /// (`None`: nothing scheduled).
    fn next_due_in(&self, now: Instant) -> Option<Duration> {
        self.entries
            .values()
            .filter(|e| !self.in_flight.contains(&e.recipient))
            .map(|e| e.next_due)
            .chain(
                self.unsent_acks
                    .values()
                    .filter(|a| !self.in_flight.contains(&a.peer))
                    .map(|a| a.next_due),
            )
            .chain(self.custody_kick_pending)
            .min()
            .map(|t| t.saturating_duration_since(now))
    }

    fn idle_refresh(&self) -> Duration {
        if self.entries.is_empty() && self.unsent_acks.is_empty() {
            IDLE_REFRESH_EMPTY
        } else {
            IDLE_REFRESH
        }
    }

    /// Apply one peer attempt's report. A verified ACK over a LAN dial to a
    /// local, non-loopback address ([`PeerReport::lan_proved`]) proves this
    /// network (cutoff pack F5): how many other contacts that woke
    /// ([`Self::network_proven_now`]).
    fn apply(&mut self, peer: &[u8; 32], report: PeerReport, now: Instant, wall: u64) -> usize {
        self.in_flight.remove(peer);
        match report.lan_wakeable {
            Some(true) => {
                self.lan_wakeable.insert(*peer);
                // Bounded: forget contacts with nothing waiting.
                if self.lan_wakeable.len() > MAX_TRACKED {
                    let waiting: HashSet<[u8; 32]> = self
                        .entries
                        .values()
                        .map(|e| e.recipient)
                        .chain(self.unsent_acks.values().map(|a| a.peer))
                        .collect();
                    self.lan_wakeable.retain(|p| waiting.contains(p));
                }
            }
            Some(false) => {
                self.lan_wakeable.remove(peer);
            }
            None => {}
        }
        // Only a delivery at a local, non-loopback address proves it.
        let lan_reached = report.lan_proved;
        let old_network = self.net_changed.remove(peer);
        // Another key at a saved LAN address on this network: `raven status`
        // says so for ten minutes (P3.C6, M0).
        if !old_network
            && report
                .pin_blocked
                .values()
                .flatten()
                .any(|r| r.carrier == OutboxCarrier::Lan)
        {
            crate::delivery_paths::pin_blocked(peer);
        }
        self.apply_seq += 1;
        self.last_apply.insert(*peer, self.apply_seq);
        // A verified ACK on this attempt's own dial proves the peer reachable
        // and answering right now (G5): everything else waiting for it starts
        // its backoff over, this attempt's objects before their own result.
        // Each object is delivered once, so this cannot loop; a write without
        // an ACK never restarts anything.
        let reached = report
            .outcomes
            .values()
            .any(|o| matches!(o, Outcome::Delivered { carrier: Some(_) }));
        for digest in &report.acks_done {
            self.unsent_acks.remove(digest);
        }
        for digest in &report.acks_failed {
            if let Some(ack) = self.unsent_acks.get_mut(digest) {
                if reached {
                    ack.failures = 0;
                }
                let wait = retry_wait(ack.failures, ack.expires_at_ms, wall, jitter());
                ack.failures = ack.failures.saturating_add(1);
                ack.next_due = now + wait;
            }
        }
        self.unsent_acks.retain(|_, a| a.expires_at_ms > wall);
        // Objects whose own result was applied (each starts from it).
        let mut charged: HashSet<[u8; 32]> = HashSet::new();
        for digest in &report.attempted {
            let rode_along = self.riding.remove(digest);
            let Some(entry) = self.entries.get_mut(digest) else {
                continue;
            };
            if let Some(blocked) = report.blocked.get(digest) {
                for (route, why) in blocked {
                    if !entry.blocked_routes.contains(route) {
                        entry.blocked_routes.push(route.clone());
                    }
                    entry.blocked_code = why;
                }
            }
            // A mismatch found before the network changed is the old
            // network's answer, cleared already (`network_changed`): not
            // recorded, like the silent route below. One that really
            // happened here costs one more dial, which stops at message 2.
            for route in report
                .pin_blocked
                .get(digest)
                .into_iter()
                .flatten()
                .filter(|_| !old_network)
            {
                if !entry.pin_blocked.contains(route) {
                    entry.pin_blocked.push(route.clone());
                }
            }
            // Only ever with a `Sent` outcome, which is progress: a rider
            // records it too. Not from an attempt the network changed under.
            if let Some(route) = report.unacked.get(digest).filter(|_| !old_network) {
                entry.unacked_route = Some(route.clone());
            }
            if let Some(held) = report.carried.get(digest) {
                entry.carried.clone_from(held);
            }
            if let Some(tried) = report.tried.get(digest) {
                entry.tried.clone_from(tried);
            }
            let outcome = report
                .outcomes
                .get(digest)
                .cloned()
                .or_else(|| report.held.map(Outcome::Held))
                .unwrap_or(Outcome::Held(code::STORE));
            // Written on this attempt: how that write travelled (p2p only).
            if matches!(
                outcome,
                Outcome::Delivered { carrier: Some(_) }
                    | Outcome::Sent {
                        carrier: Some(_),
                        ..
                    }
                    | Outcome::AckSent { .. }
            ) {
                entry.last_path = report.paths.get(digest).copied();
            }
            let probe = entry.is_probe();
            let moved = match outcome {
                // Not finished (its route record stays, keyed by message
                // id): the new copy replaces it at the next scan, due at once.
                Outcome::Resealed => true,
                // Parked (the long message horizon): its contact's probe
                // entry stands for it from the next scan.
                Outcome::Parked => !probe,
                // A probe whose messages were sealed again (they come back
                // as new copies at the next scan) or are all gone.
                Outcome::Repaired | Outcome::Gone => probe,
                _ => false,
            };
            if moved {
                self.entries.remove(digest);
                self.refresh = true;
                continue;
            }
            // It was not due: a failed dial says nothing new about it (its own
            // backoff stands); only progress (written, delivered, final) counts.
            let failed = matches!(outcome, Outcome::Unreachable { .. } | Outcome::Held(_));
            if rode_along && failed {
                continue;
            }
            if reached {
                entry.failures = 0;
            }
            if matches!(outcome, Outcome::Deposited { .. }) {
                entry.custody_forwarded = report.custody_forwarded.contains(digest);
            }
            let unreached = matches!(outcome, Outcome::Unreachable { .. });
            apply_outcome(entry, outcome, now, wall);
            // Seen on this network lately: most likely away for a moment (a
            // restart, a lock), not for its whole backoff (E1).
            if unreached && report.lan_seen_lately {
                entry.next_due = entry.next_due.min(now + LAN_SEEN_RETRY);
            }
            if probe {
                // A probe only ever waits (a hold keeps its code).
                entry.state = EntryState::Waiting;
            }
            charged.insert(*digest);
            if entry.state.is_final() {
                let finished = self.entries.remove(digest).expect("entry present");
                self.done.push_back(finished);
                while self.done.len() > MAX_DONE {
                    self.done.pop_front();
                }
            }
        }
        if self.clear_blocks.remove(peer) {
            for entry in self.entries.values_mut().filter(|e| e.recipient == *peer) {
                entry.blocked_routes.clear();
                entry.blocked_code = "";
                entry.pin_blocked.clear();
            }
        }
        // The contact's inbound link or new route hints cleared its noise pin
        // blocks while this attempt ran: what it found goes too.
        if self.clear_pins_after.remove(peer) {
            self.clear_pin_blocks(peer);
        }
        if self.kicked.remove(peer) {
            for entry in self.entries.values_mut().filter(|e| e.recipient == *peer) {
                entry.next_due = now;
            }
            // The kick may be for an object staged during the attempt, which
            // no scan has merged yet (a scan skips a peer in flight): rescan
            // now instead of at the idle refresh (up to 10 min).
            self.refresh = true;
        }
        if self.rescan_after.remove(peer) || report.rescan {
            self.refresh = true;
        }
        for (mid, never_sent) in &report.horizon_expired {
            self.done
                .push_back(Entry::parked_expired(peer, mid, *never_sent, now));
            while self.done.len() > MAX_DONE {
                self.done.pop_front();
            }
        }
        // What else waits for a peer that just answered (not charged in this
        // attempt, so without a fresh backoff of its own: not tried, or a rider
        // that was skipped) starts over and goes now instead of at its backoff,
        // and so do the ACKs we owe it that were not in this dial (those that
        // were and failed started from 0 above).
        if reached {
            for entry in self
                .entries
                .values_mut()
                .filter(|e| e.recipient == *peer && !charged.contains(&e.object_digest))
            {
                entry.failures = 0;
                entry.next_due = entry.next_due.min(now);
            }
            for (digest, ack) in self.unsent_acks.iter_mut().filter(|(_, a)| a.peer == *peer) {
                if !report.acks_failed.contains(digest) {
                    ack.failures = 0;
                    ack.next_due = ack.next_due.min(now);
                }
            }
        }
        // F5: Internet and p2p deliveries say nothing about the local network,
        // nor does a LAN one to a public or loopback address.
        if lan_reached {
            self.network_proven_now(peer, now)
        } else {
            0
        }
    }
}

/// What one attempt found for one object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    Delivered {
        carrier: Option<OutboxCarrier>,
    },
    /// Written (or already written), no ACK yet.
    Sent {
        carrier: Option<OutboxCarrier>,
        code: &'static str,
    },
    /// A prepared ACK object of ours was handed to a carrier.
    AckSent {
        carrier: OutboxCarrier,
    },
    /// The dial failed: back off.
    Unreachable {
        carrier: Option<OutboxCarrier>,
        code: &'static str,
    },
    /// Not tried (fail closed or busy): back off (or retry soon when busy).
    Held(&'static str),
    Expired,
    Failed(&'static str),
    /// No longer in the store, for a reason the history holds.
    Gone,
    /// Sealed again under a new session after the contact lost the old one:
    /// the new copy is tracked from the next scan (same message id).
    Resealed,
    /// Not delivered, but a sealed copy is held by `held` friends (friend
    /// custody, FORWARDED): direct retries continue.
    Deposited {
        held: u8,
    },
    /// The long message horizon (Phase 5a): its envelope ran out before its
    /// deadline, so it was parked and waits for a new session (for a probe
    /// entry: its contact's parked messages still wait). Not finished.
    Parked,
    /// The horizon step (P5.7) sealed a probe's parked messages again,
    /// re-pairing first when needed: the new copies are tracked from the
    /// next scan.
    Repaired,
}

/// How an attempt that dialled ended, as [`Entry::outcomes`] counts it.
const DELIVERED_OUTCOME: &str = "DELIVERED";

fn apply_outcome(entry: &mut Entry, outcome: Outcome, now: Instant, wall: u64) {
    // The attempts that dialled it (they count below), by how they ended.
    let counted: Option<&'static str> = match &outcome {
        Outcome::Delivered { carrier: Some(_) } | Outcome::AckSent { .. } => {
            Some(DELIVERED_OUTCOME)
        }
        Outcome::Sent {
            carrier: Some(_),
            code,
        }
        | Outcome::Unreachable {
            carrier: Some(_),
            code,
        } => Some(code),
        _ => None,
    };
    if let Some(code) = counted {
        entry.count_outcome(code);
    }
    let backoff = |entry: &mut Entry| {
        let wait = retry_wait(entry.failures, entry.expires_at_ms, wall, jitter());
        entry.failures = entry.failures.saturating_add(1);
        entry.next_due = now + wait;
    };
    let refused = matches!(
        outcome,
        Outcome::Unreachable {
            code: code::PEER_REFUSED,
            ..
        }
    );
    if refused {
        entry.refusals = entry.refusals.saturating_add(1);
        entry.first_refusal.get_or_insert(now);
    } else if !matches!(outcome, Outcome::Held(_)) {
        entry.refusals = 0;
        entry.first_refusal = None;
    }
    // It left this computer: a carrier wrote it (the peer read it before a
    // refusal, too), or a friend holds a copy.
    if refused
        || matches!(
            outcome,
            Outcome::Delivered { carrier: Some(_) }
                | Outcome::Sent {
                    carrier: Some(_),
                    ..
                }
                | Outcome::AckSent { .. }
                | Outcome::Deposited { .. }
        )
    {
        entry.never_sent = false;
    }
    match outcome {
        Outcome::Delivered { carrier } => {
            entry.state = EntryState::Delivered;
            entry.delivered_at_ms = wall;
            if carrier.is_some() {
                // The attempt that got the ACK counts too.
                entry.attempts = entry.attempts.saturating_add(1);
            }
            entry.last_carrier = carrier.or(entry.last_carrier);
            entry.last_error = "";
        }
        Outcome::Sent { carrier, code } => {
            entry.state = EntryState::Sent;
            if carrier.is_some() {
                entry.attempts = entry.attempts.saturating_add(1);
                entry.last_carrier = carrier;
            }
            entry.last_error = code;
            backoff(entry);
        }
        Outcome::AckSent { carrier } => {
            entry.attempts = entry.attempts.saturating_add(1);
            entry.last_carrier = Some(carrier);
            entry.last_error = "";
            entry.state = EntryState::Delivered;
        }
        Outcome::Unreachable { carrier, code } => {
            if entry.state == EntryState::Held {
                entry.state = EntryState::Queued;
            }
            if carrier.is_some() {
                entry.attempts = entry.attempts.saturating_add(1);
                entry.last_carrier = carrier;
            }
            entry.last_error = code;
            backoff(entry);
        }
        Outcome::Held(why) if why == code::DEFERRED => {
            // Only the dial's frame cap kept it out: next round, no failure.
            entry.last_error = why;
            entry.next_due = now;
        }
        Outcome::Held(why) if why == code::PEER_RESET && entry.last_error != code::PEER_RESET => {
            // The contact lost its session: the reset step runs at once, once.
            entry.state = EntryState::Held;
            entry.last_error = why;
            entry.next_due = now;
        }
        Outcome::Held(why) if why == code::SEND_IN_PROGRESS => {
            // `raven send` is handling this peer right now: no failure.
            entry.last_error = why;
            entry.next_due = now + LOCK_BUSY_RETRY.max(MIN_RETRY);
        }
        Outcome::Held(why) => {
            entry.state = EntryState::Held;
            entry.last_error = why;
            backoff(entry);
        }
        Outcome::Expired => {
            entry.state = EntryState::Expired;
            entry.last_error = code::EXPIRED;
        }
        Outcome::Failed(why) => {
            entry.state = EntryState::Failed;
            entry.last_error = why;
        }
        Outcome::Gone | Outcome::Resealed | Outcome::Repaired => entry.state = EntryState::Gone,
        Outcome::Parked => {
            // Waits for a new session: retried on the normal backoff, no
            // later than its (first) deadline.
            entry.state = EntryState::Waiting;
            entry.last_error = "";
            backoff(entry);
        }
        Outcome::Deposited { held } => {
            entry.state = EntryState::Sent;
            entry.last_error = code::IN_CUSTODY;
            entry.in_custody = held;
            backoff(entry);
        }
    }
}

/// The outcome of one attempt on one peer.
#[derive(Debug, Default)]
pub(crate) struct PeerReport {
    /// The objects this attempt was given (the due ones).
    pub(crate) attempted: Vec<[u8; 32]>,
    pub(crate) outcomes: HashMap<[u8; 32], Outcome>,
    /// Applies to every attempted object that has no outcome of its own.
    pub(crate) held: Option<&'static str>,
    /// Owed ACKs that went out, expired, or are owed to a non-contact (F8).
    pub(crate) acks_done: Vec<[u8; 32]>,
    /// Owed ACKs whose push failed: they back off.
    pub(crate) acks_failed: Vec<[u8; 32]>,
    /// Routes no longer to be tried for an object, with why.
    pub(crate) blocked: HashMap<[u8; 32], Vec<(OutboxRoute, &'static str)>>,
    /// Routes where another key answered (M0, WRONG_IDENTITY): not tried
    /// again until the network or the contact says otherwise
    /// ([`Entry::pin_blocked`]).
    pub(crate) pin_blocked: HashMap<[u8; 32], Vec<OutboxRoute>>,
    /// Objects a route took on this attempt's dial without a verified ACK on
    /// it, with that route (as planned): it goes last next time (G3).
    pub(crate) unacked: HashMap<[u8; 32], OutboxRoute>,
    /// How the link that took an object travelled, for objects a p2p route
    /// took on this attempt.
    pub(crate) paths: HashMap<[u8; 32], DeliveryPath>,
    /// The carriers whose dials took each object on this attempt, in order
    /// ([`Entry::tried`]).
    pub(crate) tried: HashMap<[u8; 32], Vec<OutboxCarrier>>,
    /// May another contact's success on this network wake this one
    /// ([`lan_wakeable`], cutoff pack F5)? `None`: no plan was made, the
    /// last answer stands.
    pub(crate) lan_wakeable: Option<bool>,
    /// A verified ACK came back for an object a LAN dial of ours carried to
    /// a local-network address other than loopback: this network works
    /// (cutoff pack F5, [`lan_delivery_proves_network`]).
    pub(crate) lan_proved: bool,
    /// Whether the contact's plan (gates applied) holds a route on another
    /// carrier than LAN (Phase 3 diagnosis, [`lan_reason`]). `None`: no
    /// plan was made.
    pub(crate) planned_other: Option<bool>,
    /// The horizon step (P5.7) sealed parked messages again: their new copies
    /// are scanned at once, whether or not their contact's probe was due.
    pub(crate) rescan: bool,
    /// Parked messages the horizon step gave up at their deadline, each with
    /// whether it never left this computer: finished entries of their own
    /// ("time ran out", CP.6), as no entry tracked them.
    pub(crate) horizon_expired: Vec<([u8; 16], bool)>,
    /// Objects with a `Deposited` outcome that a friend holds to pass on to
    /// the contact's own friend (custody handoff, taken on this attempt or
    /// an earlier one: [`ObjectRoutes::custody_forwarded`]; review
    /// handoff-3).
    pub(crate) custody_forwarded: HashSet<[u8; 32]>,
    /// Carry choice (Phase 6a P6.16, only while live): the friends holding
    /// each attempted message, as its route record named them when the
    /// attempt began, with the ones this attempt left it with
    /// ([`Entry::carried`]).
    pub(crate) carried: HashMap<[u8; 32], Vec<[u8; 32]>>,
    /// The contact had an authenticated LAN link within
    /// [`crate::delivery_paths::HERE_SPAN`] when the attempt ended: an
    /// object it could not reach waits at most [`LAN_SEEN_RETRY`].
    pub(crate) lan_seen_lately: bool,
}

impl PeerReport {
    fn hold_all(mut self, why: &'static str) -> Self {
        self.held = Some(why);
        self
    }

    /// `raven-node outbox: delivered N (<carrier>[, <path>]); contact #ab12`,
    /// one per carrier and path, for the objects this attempt delivered to
    /// `peer`: counts, the carrier and a p2p link's path only, and the
    /// contact's short tag of this run (never its key or an address). Field
    /// test E3 round 2: a delivery over Tor or the LAN logged nothing, so
    /// only the route hint lines showed that a message went.
    fn delivered_lines(&self, peer: &[u8; 32]) -> Vec<String> {
        let mut by_way: BTreeMap<(&'static str, &'static str), usize> = BTreeMap::new();
        for (digest, outcome) in &self.outcomes {
            let Outcome::Delivered { carrier } = outcome else {
                continue;
            };
            let label = carrier.map_or("delivered", |c| c.label());
            let path = match carrier {
                Some(OutboxCarrier::P2p) => self.paths.get(digest).map_or("", |p| p.label()),
                _ => "",
            };
            *by_way.entry((label, path)).or_default() += 1;
        }
        let tag = netutil::link_tag(peer);
        by_way
            .into_iter()
            .map(|((carrier, path), n)| {
                if path.is_empty() {
                    format!("raven-node outbox: delivered {n} ({carrier}); contact {tag}")
                } else {
                    format!("raven-node outbox: delivered {n} ({carrier}, {path}); contact {tag}")
                }
            })
            .collect()
    }
}

/// How one carrier attempt is made. Production dials over the network
/// (`lan_direct::dial` / `internet_direct::dial`); tests hand the frames to a
/// second profile's dispatcher in process.
pub(crate) trait Dialer: Send + Sync {
    fn dial(
        &self,
        data_dir: &Path,
        route: &OutboxRoute,
        expected_pub_hex: &str,
        frames: &[Vec<u8>],
    ) -> Result<Vec<Vec<u8>>, String>;

    /// [`Self::dial`] that gives up after `deadline` (at most the worker's
    /// own). Test dialers answer at once and need not override it.
    fn dial_within(
        &self,
        data_dir: &Path,
        route: &OutboxRoute,
        expected_pub_hex: &str,
        frames: &[Vec<u8>],
        deadline: Duration,
    ) -> Result<Vec<Vec<u8>>, String> {
        let _ = deadline;
        self.dial(data_dir, route, expected_pub_hex, frames)
    }

    /// [`Self::dial`] plus how the link travelled (p2p knows it; `None`:
    /// unknown). Test dialers need not override it.
    fn dial_path(
        &self,
        data_dir: &Path,
        route: &OutboxRoute,
        expected_pub_hex: &str,
        frames: &[Vec<u8>],
    ) -> Result<(Vec<Vec<u8>>, Option<DeliveryPath>), String> {
        self.dial(data_dir, route, expected_pub_hex, frames)
            .map(|replies| (replies, None))
    }

    /// [`Self::dial_path`] with the worker's facts about the dial
    /// ([`DialMeta`], Phase 6a: a resend of an object that went silent
    /// gives learning no reply-time sample). Every other caller dials with
    /// the default. Test dialers need not override it.
    fn dial_path_meta(
        &self,
        data_dir: &Path,
        route: &OutboxRoute,
        expected_pub_hex: &str,
        frames: &[Vec<u8>],
        meta: DialMeta,
    ) -> Result<(Vec<Vec<u8>>, Option<DeliveryPath>), String> {
        let _ = meta;
        self.dial_path(data_dir, route, expected_pub_hex, frames)
    }

    /// A frame-less probe of `route` that gives up after `deadline`
    /// (learning connectivity's exploration, Phase 6a): an authenticated
    /// link and nothing else. It takes no frames, so a probe can never carry
    /// a user message. The deadline is the carrier's own
    /// ([`DialMeta::within`]), so a probe that runs out of time still
    /// reaches learning through the carrier's hook. Test dialers need not
    /// override it.
    fn probe_within(
        &self,
        data_dir: &Path,
        route: &OutboxRoute,
        expected_pub_hex: &str,
        deadline: Duration,
    ) -> Result<Option<DeliveryPath>, String> {
        let none: [Vec<u8>; 0] = [];
        let meta = DialMeta {
            within: Some(deadline),
            ..DialMeta::default()
        };
        self.dial_path_meta(data_dir, route, expected_pub_hex, &none, meta)
            .map(|(_, path)| path)
    }
}

/// A dial's deadline when its caller names none: [`DIAL_DEADLINE`], and an
/// onion dial Tor's (design 2026-10-tor-fallback §3.5; field test S15: a
/// first Tor rendezvous may take most of a minute, and 45 s cut the
/// worker's onion dials that `raven send`, with Tor's wait, got through).
fn default_deadline(route: &OutboxRoute) -> Duration {
    if route.carrier == OutboxCarrier::Onion {
        raven_core::onion::ONION_DIAL_DEADLINE + PROBE_OUTER_SLACK
    } else {
        DIAL_DEADLINE
    }
}

/// The real carriers. Runs on a blocking-pool thread, so it may block on the
/// runtime.
struct NetDialer {
    handle: tokio::runtime::Handle,
}

impl NetDialer {
    /// One dial within `deadline` (at most [`DIAL_DEADLINE`]), and its path:
    /// LAN and Internet direct links are always `direct`. `meta`: the
    /// worker's facts about it (the default for every other caller).
    fn dial_path_within(
        &self,
        data_dir: &Path,
        route: &OutboxRoute,
        expected_pub_hex: &str,
        frames: &[Vec<u8>],
        deadline: Duration,
        meta: DialMeta,
    ) -> Result<(Vec<Vec<u8>>, Option<DeliveryPath>), String> {
        // An onion dial has Tor's waits (design 2026-10-tor-fallback §3.5).
        let deadline = deadline.min(default_deadline(route));
        let direct = |replies| (replies, Some(DeliveryPath::Direct));
        self.handle.block_on(async {
            let work = async {
                match route.carrier {
                    OutboxCarrier::Lan => crate::lan_direct::dial_with_meta(
                        data_dir,
                        &route.dial,
                        expected_pub_hex,
                        frames,
                        meta,
                    )
                    .await
                    .map(direct),
                    OutboxCarrier::Internet => crate::internet_direct::dial_with_meta(
                        data_dir,
                        &route.dial,
                        expected_pub_hex,
                        frames,
                        meta,
                    )
                    .await
                    .map(direct),
                    OutboxCarrier::P2p => {
                        crate::p2p::dial_with_path_meta(
                            data_dir,
                            &route.dial,
                            expected_pub_hex,
                            frames,
                            meta,
                        )
                        .await
                    }
                    OutboxCarrier::Nearby => {
                        crate::nearby::dial(data_dir, &route.dial, expected_pub_hex, frames)
                            .await
                            .map(direct)
                    }
                    // Its path is Tor (the carrier says it): no DeliveryPath.
                    OutboxCarrier::Onion => crate::onion::dial_with_meta(
                        data_dir,
                        &route.dial,
                        expected_pub_hex,
                        frames,
                        meta,
                    )
                    .await
                    .map(|replies| (replies, None)),
                }
            };
            // In the outbox race (Tor's happy eyeballs): a dial whose other
            // side already won is cut at once; it wrote nothing (it claims
            // before its first frame, `netutil::ReplyCollector::begin`).
            let raced = async {
                match meta.race {
                    Some(ticket) => tokio::select! {
                        done = work => done,
                        () = crate::onion::race::lost(ticket) => {
                            Err(crate::onion::race::RACE_LOST.to_string())
                        }
                    },
                    None => work.await,
                }
            };
            tokio::time::timeout(deadline, raced)
                .await
                .unwrap_or_else(|_| Err(format!("outbox dial exceeded {}s", deadline.as_secs())))
        })
    }
}

impl Dialer for NetDialer {
    fn dial(
        &self,
        data_dir: &Path,
        route: &OutboxRoute,
        expected_pub_hex: &str,
        frames: &[Vec<u8>],
    ) -> Result<Vec<Vec<u8>>, String> {
        self.dial_within(
            data_dir,
            route,
            expected_pub_hex,
            frames,
            default_deadline(route),
        )
    }

    fn dial_within(
        &self,
        data_dir: &Path,
        route: &OutboxRoute,
        expected_pub_hex: &str,
        frames: &[Vec<u8>],
        deadline: Duration,
    ) -> Result<Vec<Vec<u8>>, String> {
        self.dial_path_within(
            data_dir,
            route,
            expected_pub_hex,
            frames,
            deadline,
            DialMeta::default(),
        )
        .map(|(replies, _)| replies)
    }

    fn dial_path(
        &self,
        data_dir: &Path,
        route: &OutboxRoute,
        expected_pub_hex: &str,
        frames: &[Vec<u8>],
    ) -> Result<(Vec<Vec<u8>>, Option<DeliveryPath>), String> {
        self.dial_path_meta(
            data_dir,
            route,
            expected_pub_hex,
            frames,
            DialMeta::default(),
        )
    }

    fn dial_path_meta(
        &self,
        data_dir: &Path,
        route: &OutboxRoute,
        expected_pub_hex: &str,
        frames: &[Vec<u8>],
        meta: DialMeta,
    ) -> Result<(Vec<Vec<u8>>, Option<DeliveryPath>), String> {
        self.dial_path_within(
            data_dir,
            route,
            expected_pub_hex,
            frames,
            default_deadline(route),
            meta,
        )
    }

    /// The carrier itself gives up at `deadline` ([`DialMeta::within`]), so
    /// its hook still tells learning how the probe ended; the worker's own
    /// bound is [`PROBE_OUTER_SLACK`] later, for what the carrier does before
    /// its clock starts (review learning-8: cut from outside, a probe that
    /// ran out of time taught nothing).
    fn probe_within(
        &self,
        data_dir: &Path,
        route: &OutboxRoute,
        expected_pub_hex: &str,
        deadline: Duration,
    ) -> Result<Option<DeliveryPath>, String> {
        let none: [Vec<u8>; 0] = [];
        let meta = DialMeta {
            within: Some(deadline),
            ..DialMeta::default()
        };
        self.dial_path_within(
            data_dir,
            route,
            expected_pub_hex,
            &none,
            deadline + PROBE_OUTER_SLACK,
            meta,
        )
        .map(|(_, path)| path)
    }
}

/// Everything an attempt needs, shared by all attempts of the worker.
pub(crate) struct AttemptCtx {
    pub(crate) data_dir: PathBuf,
    pub(crate) identity: Arc<Identity>,
    pub(crate) dialer: Arc<dyn Dialer>,
    /// The LAN direct gate with `raven lan off` applied (the worker's
    /// `raven_core::lan_usable_now`), read at every attempt.
    pub(crate) lan_live: fn() -> bool,
    /// The Internet direct gate, read at every attempt.
    pub(crate) internet_live: fn() -> bool,
    /// The p2p gate with this node's host (the worker's
    /// `crate::p2p::dials_possible`: no host, no p2p route), read at every
    /// attempt.
    pub(crate) p2p_live: fn() -> bool,
    /// The nearby gate (`nearby_live_enabled`), read at every attempt.
    pub(crate) nearby_live: fn() -> bool,
    /// Whether the planners add a contact's nearby route (the worker's
    /// [`crate::nearby::available`]: the engine runs, can go on the air (not
    /// from a fixed public address) and holds a pair key for it), read at
    /// every plan.
    pub(crate) nearby_available: fn(&[u8; 32]) -> bool,
    /// The Tor onion gate (`onion_live_enabled`), read at every attempt.
    pub(crate) onion_live: fn() -> bool,
    /// Whether a worker attempt plans a contact's onion route (the worker's
    /// [`crate::onion::available`]: the Tor helper is ready), read at every
    /// attempt's plan. Only dials that carry something plan it: the worker's
    /// attempts ([`attempt_plan`]) and AppSubmit ([`send_plan`]); the
    /// route-hints announcer and learning's prober never do (design
    /// 2026-10-tor-fallback §3.6).
    pub(crate) onion_available: fn() -> bool,
    /// The direct paths' head start in the Tor race (the worker's
    /// [`crate::onion::head_start`]).
    pub(crate) onion_head_start: fn() -> Duration,
    /// This computer's network tag for the route memory
    /// ([`raven_core::route_memory::network_tag`]), read at every attempt;
    /// `None` turns the memory off.
    pub(crate) net_tag: fn() -> Option<String>,
    /// Whether a learned LAN address is on one of this computer's current
    /// networks (lab, [`learned_lan_on_link`]), read at every attempt;
    /// `Some(false)` leaves that learned route out, `None` (not known) keeps it.
    pub(crate) on_link: fn(IpAddr) -> Option<bool>,
    /// Whether a p2p route's contact is connected to this node right now,
    /// or a nearby route's contact has a pipe up ([`route_connected_now`]):
    /// such a route goes first ([`connected_first`]).
    pub(crate) connected: fn(&OutboxRoute) -> bool,
    /// Where the LAN beacon found a contact's LAN listener (Phase 3,
    /// RAVEN_LAN_BEACON_V1 §9; the worker's `lan_beacon::candidates`): at
    /// most two dial strings, IPv4 first. Read by an attempt in which LAN
    /// may carry something due ([`attempt_plan`]); none in tests.
    pub(crate) lan_beacon_routes: fn(&[u8; 32]) -> Vec<String>,
    /// Ask the LAN beacon to look for a contact (§8, the worker's
    /// `lan_beacon::want` with `Want::Outbox`), in the same attempts.
    pub(crate) lan_want: fn(&[u8; 32]),
    /// A dial to one of those finds (as planned) did not reach the contact:
    /// the beacon forgets it (§7; the worker's `lan_beacon::dial_failed`).
    pub(crate) lan_beacon_failed: fn(&[u8; 32], &str),
    /// Session-reset query backoff per (peer, session): when the next query
    /// may go, and how many went without an answer.
    pub(crate) reset_backoff: Mutex<QueryBackoffs>,
}

/// Per (peer, session): when the next session-reset query may go, and how
/// many went unanswered.
type QueryBackoffs = HashMap<([u8; 32], [u8; 32]), (Instant, u32)>;

/// A session-reset query of one attempt: (session, queried bytes, replies).
type SessionQuery = ([u8; 32], Vec<u8>, Vec<Vec<u8>>);

/// Query backoff after unanswered queries: at once, then 1, 4, 16, 60 min.
fn reset_query_wait(unanswered: u32) -> Duration {
    const STEPS: [u64; 5] = [0, 60, 240, 960, 3_600];
    Duration::from_secs(STEPS[(unanswered as usize).min(STEPS.len() - 1)])
}

/// The worker side of a reset step (and of a session renewal step,
/// `crate::renewal`): the attempt's store under the peer's send lock per call
/// (never across a dial), and the attempt's dialer.
pub(crate) struct WorkerIo<'a> {
    ctx: &'a AttemptCtx,
    peer: &'a [u8; 32],
    store: &'a mut IndexedSessionStore,
}

impl<'a> WorkerIo<'a> {
    pub(crate) fn new(
        ctx: &'a AttemptCtx,
        peer: &'a [u8; 32],
        store: &'a mut IndexedSessionStore,
    ) -> Self {
        Self { ctx, peer, store }
    }
}

impl raven_core::session_reset::ResetIo for WorkerIo<'_> {
    fn locked(
        &mut self,
        f: &mut dyn FnMut(&mut IndexedSessionStore) -> Result<(), String>,
    ) -> Result<(), String> {
        let _lock = PeerSendLock::acquire_within(&self.ctx.data_dir, self.peer, LOCK_WAIT)?;
        f(self.store)
    }

    fn dial(&mut self, route: &OutboxRoute, frames: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, String> {
        self.ctx
            .dialer
            .dial(&self.ctx.data_dir, route, &hex::encode(self.peer), frames)
    }
}

/// Map dial error text to a stable code (no addresses, no ids).
pub(crate) fn dial_error_code(detail: &str) -> &'static str {
    let l = detail.to_ascii_lowercase();
    let has = |needles: &[&str]| needles.iter().any(|n| l.contains(n));
    if has(&["internet_direct_hold"]) {
        code::INTERNET_HOLD
    } else if has(&["p2p_hold"]) {
        code::P2P_HOLD
    } else if has(&["p2p_not_running"]) {
        code::P2P_NOT_RUNNING
    } else if has(&["nearby_hold"]) {
        code::NEARBY_HOLD
    } else if has(&["nearby_not_in_range"]) {
        code::NEARBY_NOT_IN_RANGE
    } else if has(&["nearby_busy"]) {
        code::NEARBY_BUSY
    } else if has(&["nearby_not_running", "nearby not running"]) {
        code::NEARBY_NOT_RUNNING
    } else if has(&["onion_hold"]) {
        code::ONION_HOLD
    } else if has(&["onion_not_ready"]) {
        code::ONION_NOT_READY
    } else if has(&["onion_unreachable", "onion dial to"]) {
        code::ONION_UNREACHABLE
    } else if has(&["contact_not_verified", "lan_verified_only"]) {
        // `raven lan verified-only on` (P3.C2): the contact needs verifying.
        CONTACT_NOT_VERIFIED
    } else if has(&[PIN_STORE_NEEDLE]) {
        // Ours, not the contact's: nothing was dialled.
        code::PIN_STORE_UNREADABLE
    } else if has(&["link_not_accepted"]) {
        code::LINK_NOT_ACCEPTED
    } else if has(&["_dial_peer_closed"]) {
        code::PEER_REFUSED
    } else if has(&[
        "identity bind does not match",
        "rlb1 offer identity mismatch",
        "identity mismatch",
        NOISE_PIN_NEEDLE,
    ]) {
        code::WRONG_IDENTITY
    } else if has(&["blocked peer"]) {
        code::CONTACT_BLOCKED
    } else if has(&["connection refused", "actively refused"]) {
        code::NOT_LISTENING
    } else if has(&[
        "closed the connection during the handshake",
        "peer closed the connection",
        "early eof",
        "connection reset",
        "broken pipe",
    ]) {
        code::CLOSED_EARLY
    } else if has(&[
        "timed out",
        "timeout",
        "exceeded",
        "cannot connect",
        "connect budget",
        "no route",
        "unreachable",
        "host is down",
    ]) {
        code::NOT_REACHABLE
    } else {
        code::DIAL_FAILED
    }
}

/// Whether a LAN try that failed as a dial does (nobody answered, nobody was
/// receiving, it hung up), `prev`, says more than the p2p dial after it that
/// failed with `detail`: that dial's reason only says the contact's own
/// direct addresses did not answer, or that this computer has no route to
/// the internet. The send result says the LAN's then (ash `p2p_reason`), and
/// so must the outbox's last error (E1: `raven outbox list` said "no answer
/// at their internet address" where the LAN said its computer was there).
///
/// E2 r9 #4: when that LAN try was at an address on one of this computer's
/// networks (`lan_on_net`), the LAN's answer says more than any p2p reason
/// (never "both behind NAT" for a friend whose saved address is here), and
/// a refusal there (its computer is there, Raven isn't answering: closed or
/// asleep) more than any other carrier's failure, Tor's included.
fn lan_failure_says_more(
    prev: Option<(OutboxCarrier, &'static str)>,
    carrier: OutboxCarrier,
    detail: &str,
    lan_on_net: bool,
) -> bool {
    use raven_core::reach_diag::{Diag, Why};
    let Some((
        OutboxCarrier::Lan,
        lan @ (code::NOT_REACHABLE | code::NOT_LISTENING | code::CLOSED_EARLY),
    )) = prev
    else {
        return false;
    };
    if lan_on_net && (carrier == OutboxCarrier::P2p || lan == code::NOT_LISTENING) {
        return true;
    }
    carrier == OutboxCarrier::P2p
        && Diag::find(detail).is_some_and(|d| matches!(d.why, Why::DirectFailed | Why::NoRoute))
}

/// Whether a LAN dial (`ip:port`) is at an address on one of this
/// computer's networks now (a name is not).
fn dial_on_our_network(dial: &str) -> bool {
    dial.trim()
        .parse::<std::net::SocketAddr>()
        .is_ok_and(|a| raven_core::netifs::on_our_networks(a.ip()) == Some(true))
}

/// A route answer that will not change by retrying: the peer at that address
/// is someone else, or it does not accept this node.
fn blocks_route(why: &str) -> bool {
    why == code::WRONG_IDENTITY || why == code::LINK_NOT_ACCEPTED
}

/// What every noise pin mismatch says ([`crate::lan_direct::NOISE_PIN_MISMATCH`]).
const NOISE_PIN_NEEDLE: &str = "lan noise pin mismatch";
/// What an unreadable pin store says ([`crate::lan_direct::NOISE_PIN_UNAVAILABLE`]).
const PIN_STORE_NEEDLE: &str = "lan noise pin unavailable";

/// Another key answered before our Noise message 3 (M0): a WRONG_IDENTITY
/// whose block is scoped ([`Entry::pin_blocked`]), not kept until an
/// explicit retry.
fn is_noise_pin_mismatch(detail: &str) -> bool {
    detail.to_ascii_lowercase().contains(NOISE_PIN_NEEDLE)
}

/// An object's routes for this attempt: when a route took its frames last
/// time without the ACK coming back, start at the route after it and try it
/// last, round the plan, so a link that keeps taking frames silently cannot
/// keep the others from being tried (G3). Only reorders: nothing is added or
/// dropped, so the send's choice, the gates and the verified-contact rule
/// stand.
fn rotate_past(routes: &mut [(OutboxRoute, OutboxRoute)], unacked: Option<&OutboxRoute>) {
    if let Some(i) = unacked.and_then(|u| routes.iter().position(|(p, _)| p == u)) {
        // i + 1 <= len: the last route gives plan order again.
        routes.rotate_left(i + 1);
    }
}

/// Dial plan step 1 (transports design §2.3): a p2p route whose contact is
/// connected to this node right now goes first, so the link rides that
/// connection (when the contact opened it: deliberate reversal), and so does
/// a nearby route whose pipe is up (Phase 5, owner decision O5-13: nearby is
/// tried last unless a pipe is already up). Applied last, after
/// [`rotate_past`]. Only reorders, keeping the rest in order; never adds a
/// route, and never moves `silent` (G3's route that took the object's frames
/// without an ACK) forward.
fn connected_first(
    routes: &mut Vec<(OutboxRoute, OutboxRoute)>,
    connected: fn(&OutboxRoute) -> bool,
    silent: Option<&OutboxRoute>,
) {
    let (mut first, rest): (Vec<_>, Vec<_>) =
        std::mem::take(routes)
            .into_iter()
            .partition(|(planned, dial)| {
                matches!(planned.carrier, OutboxCarrier::P2p | OutboxCarrier::Nearby)
                    && Some(planned) != silent
                    && connected(dial)
            });
    first.extend(rest);
    *routes = first;
}

/// Phase 6b R4 (design A, step P6.28): one object's routes after its
/// contact's links over the carriers in `interfered` were tampered with on
/// this network. Their routes go last, behind the contact's other routes;
/// when friend custody may carry the object (`custody`), they are set aside
/// for this attempt instead, so custody comes before them. With no other
/// route and no custody nothing changes (retries go on as before). Only
/// reorders or holds back for one attempt: never adds a route. `true` when
/// routes were set aside.
fn demote_interfered(
    routes: &mut Vec<(OutboxRoute, OutboxRoute)>,
    interfered: &[OutboxCarrier],
    custody: bool,
) -> bool {
    if interfered.is_empty() {
        return false;
    }
    let (hit, mut other): (Vec<_>, Vec<_>) = std::mem::take(routes)
        .into_iter()
        .partition(|(planned, _)| interfered.contains(&planned.carrier));
    if hit.is_empty() || (other.is_empty() && !custody) {
        other.extend(hit);
        *routes = other;
        return false;
    }
    let set_aside = custody;
    if !set_aside {
        other.extend(hit);
    }
    *routes = other;
    set_aside
}

/// Phase 6b R4: the carriers whose routes to `peer` go last on this network
/// at `wall` ([`raven_core::route_memory::interfered_carriers`]). None while
/// the responses gate is shut or nothing is noted for `peer` (the egress
/// tag is read only then).
fn interfered_carriers(peer: &[u8; 32], wall: u64) -> Vec<OutboxCarrier> {
    if !raven_core::route_memory::interference_noted(peer, wall) {
        return Vec::new();
    }
    raven_core::route_memory::interfered_carriers(peer, crate::security::network(), wall)
}

/// The worker's [`AttemptCtx::connected`]: a p2p route whose contact is
/// connected to this node now ([`crate::p2p::route_connected`]), or a
/// nearby route whose pipe is up ([`crate::nearby::route_connected`]).
fn route_connected_now(route: &OutboxRoute) -> bool {
    crate::p2p::route_connected(route) || crate::nearby::route_connected(route)
}

/// The carrier gates, read now.
pub(crate) fn carrier_gates(ctx: &AttemptCtx) -> CarrierGates {
    CarrierGates {
        lan: (ctx.lan_live)(),
        internet: (ctx.internet_live)(),
        p2p: (ctx.p2p_live)(),
        nearby: (ctx.nearby_live)(),
        onion: (ctx.onion_live)(),
    }
}

/// One contact as a dial plans it: THE resolver of the worker
/// ([`attempt_peer_inner`]), `AppSubmit` (`app_channel::resolve`) and the
/// route-hints announcer (`hints::announce_routes`), so the three never
/// disagree on where a contact is.
pub(crate) struct PeerPlan {
    /// The book's routes plus what was learned
    /// ([`raven_core::outbox::with_learned_routes_where`]: `lan_seen`, and
    /// RRH1 while route hints are live), minus a learned LAN address on none
    /// of this computer's networks (`ctx.on_link == Some(false)`). In a
    /// worker attempt with LAN beacon finds ([`attempt_plan`]): the finds
    /// first among the LAN routes and no learned LAN route.
    pub(crate) contact: ContactRoutes,
    pub(crate) gates: CarrierGates,
    /// `ctx.net_tag()`; `None`: the route memory is off.
    pub(crate) net: Option<String>,
    /// The route memory's route on this network; never while learning
    /// connectivity is on (it supersedes the memory: neither read nor
    /// taught, OD6a-10).
    pub(crate) preferred: Option<OutboxRoute>,
    /// Learning connectivity's carrier order for this contact on this
    /// network (Phase 6a, [`crate::learning::plan`] of the static carriers
    /// of [`PeerPlan::plain`]): while learning is on, every plan of the
    /// contact is ranked by it ([`PeerPlan::object_routes`]) instead of by
    /// `preferred`. `None` while learning is off.
    pub(crate) learned: Option<Order>,
    /// The learning network tag `learned` was ranked on.
    pub(crate) learned_net: Option<String>,
    /// A plan of this resolve already noted a contradiction
    /// ([`PeerPlan::object_routes`]): it is counted once.
    contradicted: AtomicBool,
    /// The LAN beacon's finds in `contact` (LAN dial strings, at most two):
    /// in memory only, never taught to the route memory, and one that a
    /// dial does not reach the contact at is forgotten (RAVEN_LAN_BEACON_V1
    /// §7, §9). Empty outside a worker attempt.
    pub(crate) beacon: Vec<String>,
}

/// [`PeerPlan`] for the admitted contact `peer` (after
/// [`contact_admission`]) at `wall`: AppSubmit's and the route-hints
/// announcer's, with no LAN beacon finds.
pub(crate) fn peer_plan(
    ctx: &AttemptCtx,
    peer: &[u8; 32],
    admitted: ContactRoutes,
    wall: u64,
) -> PeerPlan {
    peer_plan_with(ctx, peer, admitted, wall, &[])
}

/// The static carrier order of `peer`'s plan for any carrier
/// ([`peer_plan`], [`PeerPlan::plain`]): what learning connectivity's IPC
/// `LearningPlan` ranks (Phase 6a). `Err`: no worker runs
/// (`OUTBOX_WORKER_OFF`), or the admission hold code.
pub(crate) fn static_carriers(peer: &[u8; 32]) -> Result<Vec<OutboxCarrier>, &'static str> {
    let ctx = attempt_ctx().ok_or("OUTBOX_WORKER_OFF")?;
    static_carriers_with(&ctx, peer)
}

fn static_carriers_with(
    ctx: &AttemptCtx,
    peer: &[u8; 32],
) -> Result<Vec<OutboxCarrier>, &'static str> {
    match contact_admission(&ctx.data_dir, peer) {
        ContactAdmission::Allowed(c) => {
            let plan = peer_plan(ctx, peer, c, now_ms());
            Ok(raven_core::learning::rank::carriers_of(&plan.plain(peer)))
        }
        ContactAdmission::NotContact => Err(code::NOT_A_CONTACT),
        ContactAdmission::Blocked => Err(code::CONTACT_BLOCKED),
        ContactAdmission::Unreadable => Err(code::CONTACTS_UNREADABLE),
    }
}

/// Every custodian `peer`'s mail may be left with now
/// ([`raven_core::custody_client::custodian_candidates`]: the ones it
/// announced, then the ones listed for it): what learning connectivity's
/// IPC `LearningPlan` names carry choice's pick from (Phase 6a P6.16). None
/// while no worker runs or friend custody is not live, or for a contact
/// that is no verified, unblocked one. Blocking (reads the book).
pub(crate) fn custodian_candidates(peer: &[u8; 32]) -> Vec<([u8; 32], Option<u8>)> {
    let Some(ctx) = attempt_ctx() else {
        return Vec::new();
    };
    let allowed = matches!(
        contact_admission(&ctx.data_dir, peer),
        ContactAdmission::Allowed(c) if c.pinned
    );
    if !allowed || !raven_core::custody_gate::CustodyGates::current().live {
        return Vec::new();
    }
    raven_core::custody_client::custodian_candidates(
        &ctx.data_dir,
        &ctx.identity.public_key_bytes(),
        peer,
        now_ms(),
    )
}

/// Learning connectivity's exploration (Phase 6a, design §5): the
/// admitted, verified contact `peer`'s routes for any carrier as a dial
/// would plan them now ([`peer_plan`]: the gates, hide-IP and the learned
/// order applied, before localizing), and its static carrier order
/// ([`PeerPlan::plain`]). `None` for a stranger, a blocked or an unverified
/// contact, one whose sending the user paused (Phase 6b P6.31: nothing is
/// planned or dialled to it, a probe included), or an unreadable book.
/// Blocking (reads the book and the node policy).
pub(crate) fn explore_plan(
    ctx: &AttemptCtx,
    peer: &[u8; 32],
) -> Option<(Vec<OutboxRoute>, Vec<OutboxCarrier>)> {
    if raven_core::node_policy::load_policy(&ctx.data_dir).send_held(peer) {
        return None;
    }
    let ContactAdmission::Allowed(contact) = contact_admission(&ctx.data_dir, peer) else {
        return None;
    };
    if !contact.pinned {
        return None;
    }
    let plan = peer_plan(ctx, peer, contact, now_ms());
    let routes = plan.card_lan_localized(plan.object_routes(peer, Some(&auto_record(peer))).routes);
    let statics = raven_core::learning::rank::carriers_of(&plan.plain(peer));
    Some((routes, statics))
}

/// The route an exploration probe of `carrier` dials: the first of `routes`
/// (an [`explore_plan`]) on that carrier that localizes as the worker's do
/// (`pinned`: the contact is verified), as (planned, dialled). A refused
/// route is skipped. Blocking (an unverified LAN name resolves).
pub(crate) fn probe_route(
    routes: &[OutboxRoute],
    carrier: OutboxCarrier,
    pinned: bool,
) -> Option<(OutboxRoute, OutboxRoute)> {
    routes
        .iter()
        .filter(|r| r.carrier == carrier)
        .find_map(|r| {
            localize_lan_route(r, pinned, LOCALIZE_RESOLVE_TIMEOUT)
                .ok()
                .map(|d| (r.clone(), d))
        })
}

/// [`peer_plan`] for one worker attempt (Phase 3 P3.11, RAVEN_LAN_BEACON_V1
/// §8-§9): while the LAN gate is open (`raven lan off` closes it) and LAN
/// may carry something due (`lan_due`), the LAN beacon is asked to look for
/// the contact ([`AttemptCtx::lan_want`]), and where it found the contact
/// ([`AttemptCtx::lan_beacon_routes`]) goes first among the LAN routes.
/// They are LAN routes like any other: the send's carrier choice, the gates,
/// the verified-contact rule, an unverified contact's dial-time check and
/// lan_direct's noise pin (M0) apply to them as to the saved one.
fn attempt_plan(
    ctx: &AttemptCtx,
    peer: &[u8; 32],
    admitted: ContactRoutes,
    wall: u64,
    lan_due: bool,
) -> PeerPlan {
    let found = if lan_due && (ctx.lan_live)() {
        (ctx.lan_want)(peer);
        (ctx.lan_beacon_routes)(peer)
    } else {
        Vec::new()
    };
    let mut plan = peer_plan_with(ctx, peer, admitted, wall, &found);
    // The Tor onion route (lab): derived live, planned last and raced
    // against the others by the worker (design 2026-10-tor-fallback §3.4);
    // only while the gate is open and the helper is ready.
    if plan.gates.onion {
        plan.contact = raven_core::outbox::with_onion_route(
            plan.contact,
            peer,
            // A binding learned from route hints is kept in the book row
            // (`crate::onion::learn_binding`): `contact.onion` holds it.
            None,
            (ctx.onion_available)(),
            raven_core::onion::now_s(),
        );
    }
    plan
}

/// [`peer_plan`] with the contact's Tor onion route planned last, as a
/// worker attempt plans it ([`attempt_plan`], without asking the LAN beacon):
/// for a dial that carries something besides the worker's, AppSubmit (an app
/// payload), so a first session with a friend reachable only over Tor can be
/// set up (design 2026-10-tor-fallback §3.6).
pub(crate) fn send_plan(
    ctx: &AttemptCtx,
    peer: &[u8; 32],
    admitted: ContactRoutes,
    wall: u64,
) -> PeerPlan {
    attempt_plan(ctx, peer, admitted, wall, false)
}

/// [`peer_plan`] with the LAN beacon's finds (`found`): with any usable one
/// ([`raven_core::outbox::beacon_lan_dials`]) the finds lead the LAN routes
/// and nothing learned is added for LAN
/// ([`raven_core::outbox::with_beacon_lan_routes`]: `keep = |_| false`).
fn peer_plan_with(
    ctx: &AttemptCtx,
    peer: &[u8; 32],
    admitted: ContactRoutes,
    wall: u64,
    found: &[String],
) -> PeerPlan {
    use raven_core::outbox::{
        beacon_lan_dials, with_beacon_lan_routes, with_learned_routes_where, with_nearby_route,
    };
    let beacon = beacon_lan_dials(found);
    let contact = if beacon.is_empty() {
        with_learned_routes_where(&ctx.data_dir, peer, admitted, |ip| {
            (ctx.on_link)(ip) != Some(false)
        })
    } else {
        with_beacon_lan_routes(
            with_learned_routes_where(&ctx.data_dir, peer, admitted, |_| false),
            &beacon,
        )
    };
    // Phase 5 nearby: derived live, never stored, planned last (a verified
    // contact the engine holds a pair key for).
    let contact = with_nearby_route(contact, peer, (ctx.nearby_available)(peer));
    let gates = carrier_gates(ctx);
    let net = (ctx.net_tag)();
    // Learning connectivity (Phase 6a): while on, its carrier order ranks
    // the plans and the route memory is neither read nor taught (OD6a-10).
    let learning = crate::learning::live_on();
    let (learned, learned_net) = if learning {
        crate::learning::plan(peer, &static_carriers_of(peer, &contact, gates))
            .map_or((None, None), |(order, net)| (Some(order), net))
    } else {
        (None, None)
    };
    let preferred = net.as_deref().filter(|_| !learning).and_then(|n| {
        raven_core::route_memory::preferred_route(&ctx.data_dir, peer, Some(n), wall)
    });
    PeerPlan {
        contact,
        gates,
        net,
        preferred,
        learned,
        learned_net,
        contradicted: AtomicBool::new(false),
        beacon,
    }
}

/// The static carrier order of `contact`'s plan for any carrier (an Auto
/// record, no memory, no learned order: [`PeerPlan::plain`]): what learning
/// connectivity ranks.
fn static_carriers_of(
    peer: &[u8; 32],
    contact: &ContactRoutes,
    gates: CarrierGates,
) -> Vec<OutboxCarrier> {
    raven_core::learning::rank::carriers_of(
        &plan_object_routes(Some(&auto_record(peer)), contact, gates).routes,
    )
}

/// The contact's plan for one of the daemon's own dials (Phase 3 P3.14): the
/// worker's attempt ([`attempt_peer_inner`]) and the session renewer
/// (`crate::renewal`). [`contact_admission`] first, then [`attempt_plan`]:
/// what was learned, the LAN beacon's finds while `lan_due`, the gates (LAN
/// from [`AttemptCtx::lan_live`], `raven lan off` included) and the route
/// memory's route. `Err` is the hold code: [`code::NOT_A_CONTACT`],
/// [`code::CONTACT_BLOCKED`] or [`code::CONTACTS_UNREADABLE`].
pub(crate) fn plan_inputs(
    ctx: &AttemptCtx,
    peer: &[u8; 32],
    wall: u64,
    lan_due: bool,
) -> Result<PeerPlan, &'static str> {
    match contact_admission(&ctx.data_dir, peer) {
        ContactAdmission::Allowed(c) => Ok(attempt_plan(ctx, peer, c, wall, lan_due)),
        ContactAdmission::NotContact => Err(code::NOT_A_CONTACT),
        ContactAdmission::Blocked => Err(code::CONTACT_BLOCKED),
        ContactAdmission::Unreadable => Err(code::CONTACTS_UNREADABLE),
    }
}

/// May LAN carry something this attempt holds for the contact (the outbox's
/// want, RAVEN_LAN_BEACON_V1 §8)? An owed ACK or an ACK row goes over any
/// carrier; a message by its send's carrier choice (no record: LAN only, as
/// [`plan_object_routes`] plans it).
fn lan_may_carry(
    due: &[Entry],
    owed_acks: &[([u8; 32], UnsentAck)],
    records: &BTreeMap<[u8; 16], ObjectRoutes>,
) -> bool {
    !owed_acks.is_empty()
        || due.iter().any(|e| {
            e.kind == EndpointOutboundKind::Ack
                || records
                    .get(&e.message_id)
                    .map_or(CarrierChoice::Lan, |r| r.choice)
                    .allows(OutboxCarrier::Lan)
        })
}

/// A failed dial that says the LAN beacon's find does not lead to the
/// contact (§7): nobody listens there, the connection broke off, another key
/// answered or the dial failed otherwise. A refusal by the contact itself,
/// and a dial refused here before it went out, say nothing about the
/// address.
fn find_failed(why: &str) -> bool {
    [
        code::NOT_REACHABLE,
        code::NOT_LISTENING,
        code::CLOSED_EARLY,
        code::WRONG_IDENTITY,
        code::DIAL_FAILED,
    ]
    .contains(&why)
}

/// A custody fetch or deposit dial of `planned` (a custodian route as
/// planned, before localizing) failed with `err`: was it one of the LAN
/// beacon's finds (`finds`, as the beacon gave them) that does not lead to
/// the custodian ([`find_failed`])? Then the beacon must forget it, as a
/// delivery dial makes it (review A-5): else it is dialled first on every
/// pass for up to ten minutes and holds back the query that would find the
/// custodian's new address.
pub(crate) fn custody_find_failed(finds: &[String], planned: &OutboxRoute, err: &str) -> bool {
    planned.carrier == OutboxCarrier::Lan
        && raven_core::outbox::beacon_lan_dials(finds).contains(&planned.dial)
        && find_failed(dial_error_code(err))
}

impl PeerPlan {
    /// Plain plan order for any carrier (an Auto record, no memory, no
    /// learned order): the ranks the route memory learns by, and the static
    /// order learning connectivity ranks.
    pub(crate) fn plain(&self, peer: &[u8; 32]) -> Vec<OutboxRoute> {
        plan_object_routes(Some(&auto_record(peer)), &self.contact, self.gates).routes
    }

    /// The routes of one object to `peer` (its send's `record`; `None`: LAN
    /// only), before blocks, localizing and the per-object reorders: ranked
    /// by the learned carrier order while learning is on
    /// ([`plan_object_routes_ranked`]), else with the remembered route
    /// first ([`plan_object_routes_preferring`]). Order only, either way. A
    /// learned order that is no pure reorder of the plan gives the static
    /// plan ([`RoutePlan::learning_contradiction`]) and, once per resolve,
    /// pins this contact-network to the static order for an hour
    /// ([`crate::learning::contradiction`]).
    pub(crate) fn object_routes(
        &self,
        peer: &[u8; 32],
        record: Option<&ObjectRoutes>,
    ) -> RoutePlan {
        let Some(order) = self.learned.as_ref() else {
            return plan_object_routes_preferring(
                record,
                &self.contact,
                self.gates,
                self.preferred.as_ref(),
            );
        };
        let plan = plan_object_routes_ranked(record, &self.contact, self.gates, Some(order));
        if plan.learning_contradiction && !self.contradicted.swap(true, AtomicOrdering::Relaxed) {
            crate::learning::contradiction(peer, self.learned_net.as_deref());
        }
        plan
    }

    /// A plan of this resolve got a learned order that was no pure reorder
    /// of it ([`Self::object_routes`]).
    pub(crate) fn contradicted(&self) -> bool {
        self.contradicted.load(AtomicOrdering::Relaxed)
    }

    /// Any carrier, in dial order: the learned order (or the remembered
    /// route first), each route localized (refused ones dropped), then a
    /// connected contact's p2p route first ([`connected_first`]). As
    /// (planned, dialled).
    pub(crate) fn auto_dial(
        &self,
        peer: &[u8; 32],
        connected: fn(&OutboxRoute) -> bool,
        localize: &mut dyn FnMut(&OutboxRoute, bool) -> Result<OutboxRoute, RouteRefusal>,
    ) -> Vec<(OutboxRoute, OutboxRoute)> {
        let mut routes: Vec<(OutboxRoute, OutboxRoute)> = self
            .object_routes(peer, Some(&auto_record(peer)))
            .routes
            .into_iter()
            .filter_map(|r| {
                localize(&r, self.contact.localize_pinned(&r))
                    .ok()
                    .map(|d| (r, d))
            })
            .collect();
        connected_first(&mut routes, connected, None);
        routes
    }

    /// The routes a session renewal (`crate::renewal`) may use, in order:
    /// any carrier (an Auto record) in the learned order, or with the
    /// remembered route first. The gates, hide-IP and the verified-contact
    /// rule apply as to any send ([`Self::object_routes`]); the renewal step
    /// localizes LAN routes itself.
    pub(crate) fn renewal_routes(&self, peer: &[u8; 32]) -> Vec<OutboxRoute> {
        self.card_lan_localized(self.object_routes(peer, Some(&auto_record(peer))).routes)
    }

    /// `routes` with each of the book's LAN routes that keep the
    /// local-network rule ([`raven_core::outbox::ContactRoutes::lan_local_only`]:
    /// a card's) localized now as an unverified contact's (the address it
    /// resolves to on the local network, or left out): for the steps that
    /// localize with the contact's verified state alone (renewal, the
    /// horizon, an exploration probe). Blocking (a name resolves).
    fn card_lan_localized(&self, routes: Vec<OutboxRoute>) -> Vec<OutboxRoute> {
        routes
            .into_iter()
            .filter_map(|r| {
                if self.contact.pinned && self.contact.lan_local_only(&r) {
                    localize_lan_route(&r, false, LOCALIZE_RESOLVE_TIMEOUT).ok()
                } else {
                    Some(r)
                }
            })
            .collect()
    }
}

/// Any carrier over the contact's own routes: what owed ACKs, `AppSubmit`
/// and the announcer plan with (no routes of its own, never expires).
fn auto_record(peer: &[u8; 32]) -> ObjectRoutes {
    ObjectRoutes {
        peer_pub_hex: hex::encode(peer),
        choice: CarrierChoice::Auto,
        routes: Vec::new(),
        expires_at_ms: u64::MAX,
        unsent: false,
        written: false,
        custodians_held: Vec::new(),
        custody_forwarded: false,
        custody: false,
    }
}

/// One object about to be dialled: its exact bytes and its routes.
struct Candidate {
    digest: [u8; 32],
    kind: EndpointOutboundKind,
    key: IndexedSessionRecordKey,
    session_id: [u8; 32],
    message_id: [u8; 16],
    /// Still `Prepared`: the handoff is recorded once a dial took it.
    pending: bool,
    /// When its envelope runs out (wall clock ms).
    expires_at_ms: u64,
    bytes: Vec<u8>,
    /// (as planned, as dialled): blocking uses the planned form.
    routes: Vec<(OutboxRoute, OutboxRoute)>,
    sent: Option<OutboxCarrier>,
    /// The route (as planned) that took it in this attempt.
    sent_on: Option<OutboxRoute>,
    /// That route as dialled (an unverified contact's name resolved).
    sent_via: Option<OutboxRoute>,
    /// How that p2p route's link travelled.
    path: Option<DeliveryPath>,
    last_try: Option<(OutboxCarrier, &'static str)>,
    /// A LAN dial of it failed at an address on one of this computer's
    /// networks in this attempt (E2 r9 #4: its answer then says more than
    /// any NAT reason).
    lan_on_net: bool,
    /// Left out of a dial only because it was full: due again at once, not a
    /// failure.
    deferred: bool,
    superseded: bool,
    refusals: u32,
    first_refusal: Option<Instant>,
    /// The route whose dial the peer closed on it (session reset query).
    refused_on: Option<OutboxRoute>,
    /// No direct route, kept only for friend custody: the hold reason.
    held_why: Option<&'static str>,
    /// Custodians that took it in this attempt.
    custody_new: Vec<[u8; 32]>,
    /// One of them took it to pass on (a custody handoff FORWARD).
    custody_forwarded: bool,
    /// It went silent on a route before (`Entry::unacked_route`): a dial
    /// that resends it gives learning no reply-time sample (Karn).
    unacked: bool,
    /// The carriers whose dials took it in this attempt, in order.
    tried: Vec<OutboxCarrier>,
}

impl Candidate {
    /// A dial over `carrier` took it (whatever came of that).
    fn dialled_over(&mut self, carrier: OutboxCarrier) {
        if !self.tried.contains(&carrier) {
            self.tried.push(carrier);
        }
    }
}

/// Message bodies this node holds (staged or in the history), read once per
/// attempt: a row without one was not staged by `raven send` (it was sealed
/// by `SealUnderSession` for another path) and is never touched.
struct LocalBodies {
    staged: Option<HashSet<String>>,
    history: Option<HashSet<String>>,
    /// App channel objects to this peer: sealed by `AppSubmit`, recorded in
    /// the app outbox (no stage, no history row). `None` until first asked;
    /// an unreadable app store gives the empty set (held, never abandoned).
    app: Option<HashSet<[u8; 16]>>,
}

impl LocalBodies {
    fn new() -> Self {
        Self {
            staged: None,
            history: None,
            app: None,
        }
    }

    /// Is this an app channel object (no history step, no chat body)?
    fn is_app(&mut self, data_dir: &Path, peer: &[u8; 32], message_id: &[u8; 16]) -> bool {
        self.app
            .get_or_insert_with(|| {
                use raven_core::app_store::{AppStore, MetadataOnly};
                if !raven_core::app_store::app_store_path(data_dir).exists() {
                    return HashSet::new();
                }
                AppStore::open(data_dir, &MetadataOnly)
                    .and_then(|s| s.message_ids_for_device(peer))
                    .unwrap_or_default()
            })
            .contains(message_id)
    }

    fn has(&mut self, data_dir: &Path, peer: &[u8; 32], message_id: &[u8; 16]) -> bool {
        if self.is_app(data_dir, peer, message_id) {
            return true;
        }
        let mid = hex::encode(message_id);
        let peer_hex = hex::encode(peer);
        let staged = self.staged.get_or_insert_with(|| {
            raven_core::list_staged_outbound_bodies(data_dir)
                .map(|all| {
                    all.into_iter()
                        .filter(|s| s.peer_pub_hex.eq_ignore_ascii_case(&peer_hex))
                        .map(|s| s.message_id_hex.to_ascii_lowercase())
                        .collect()
                })
                .unwrap_or_default()
        });
        if staged.contains(&mid) {
            return true;
        }
        let history = self.history.get_or_insert_with(|| {
            raven_core::ChatHistory::load(data_dir)
                .map(|h| {
                    h.entries
                        .into_iter()
                        .filter(|e| {
                            e.direction == "out"
                                && !e.body.is_empty()
                                && e.peer_pub_hex.eq_ignore_ascii_case(&peer_hex)
                        })
                        .map(|e| e.message_id_hex.to_ascii_lowercase())
                        .collect()
                })
                .unwrap_or_default()
        });
        history.contains(&mid)
    }
}

/// One attempt on the due objects (and owed ACKs) of `peer`. Blocking (store,
/// history, DNS, dials): run it on the blocking pool. The send lock is taken
/// for the store work before and after the dial, never across it.
pub(crate) fn attempt_peer(
    ctx: &AttemptCtx,
    peer: &[u8; 32],
    due: &[Entry],
    owed_acks: &[([u8; 32], UnsentAck)],
) -> PeerReport {
    let mut report = attempt_peer_inner(ctx, peer, due, owed_acks);
    report.lan_seen_lately = crate::delivery_paths::lan_linked_within_span(peer);
    // Carry choice (P6.16): who held what this attempt finished.
    carry_outcomes(peer, due, &report);
    // Why LAN could not carry it (Phase 3 diagnosis), before the custody
    // status replaces the reachability codes it reads.
    if let Some(facts) = lan_reason(&report, due, raven_core::lan_user_off(), || {
        beacon_asked_in_vain(peer)
    }) {
        let them = raven_core::reach_diag::TheirFacts {
            heard_s: crate::delivery_paths::heard_age(peer).map(|a| a.as_secs()),
            ..Default::default()
        };
        let why = raven_core::reach_diag::diagnose_lan(&facts, &them);
        crate::delivery_paths::note_lan(peer, why);
    }
    custody_status_codes(ctx, peer, due, &mut report);
    // Every owed ACK ends up in exactly one list; one this attempt could not
    // send (or decide) backs off.
    report.acks_done.sort_unstable();
    report.acks_done.dedup();
    let done: HashSet<[u8; 32]> = report.acks_done.iter().copied().collect();
    report.acks_failed = owed_acks
        .iter()
        .map(|(d, _)| *d)
        .filter(|d| !done.contains(d))
        .collect();
    let durable_done: Vec<[u8; 32]> = owed_acks
        .iter()
        .filter(|(d, a)| a.durable && done.contains(d))
        .map(|(d, _)| *d)
        .collect();
    if !durable_done.is_empty() {
        if let Ok(Some(mut owed)) = raven_core::owed_acks::OwedAcks::open_existing(&ctx.data_dir) {
            let _ = owed.clear(&durable_done);
        }
    }
    report
}

/// Carry choice's evidence from one attempt (Phase 6a P6.16, design §7):
/// each message of `due` that friends held ([`PeerReport::carried`], else
/// [`Entry::carried`]) and that this attempt found delivered (a verified
/// ACK, on its dial or another way) credits them; one whose time ran out
/// (expired, or parked by the long message horizon, P5.6) debits them. A
/// message no friend held is no evidence, and nor is any other outcome (a
/// give-up for a revoked contact or a dead session says nothing about the
/// friends). Nor is the time running out on a message a friend took to pass
/// on to the contact's own friend (custody handoff, [`Entry::custody_forwarded`]):
/// its receipt comes back only if the contact verified that friend too, so
/// it was not confirmed rather than not carried (review handoff-3). Nothing
/// while carry choice is not live.
fn carry_outcomes(peer: &[u8; 32], due: &[Entry], report: &PeerReport) {
    if !crate::learning::carry_live() {
        return;
    }
    for entry in due
        .iter()
        .filter(|e| e.kind == EndpointOutboundKind::Message && !e.is_probe())
    {
        let forwarded =
            entry.custody_forwarded || report.custody_forwarded.contains(&entry.object_digest);
        let delivered = match report.outcomes.get(&entry.object_digest) {
            Some(Outcome::Delivered { .. }) => true,
            Some(Outcome::Expired | Outcome::Parked) if !forwarded => false,
            _ => continue,
        };
        let mut holders: Vec<[u8; 32]> = report
            .carried
            .get(&entry.object_digest)
            .cloned()
            .unwrap_or_default();
        for h in &entry.carried {
            if !holders.contains(h) {
                holders.push(*h);
            }
        }
        crate::learning::carry_outcome(peer, &holders, delivered);
    }
}

/// One dial's frames in the worker's loop: owed ACKs (when the route may
/// carry them) and due objects of the planned route not sent yet, at most
/// [`MAX_FRAMES_PER_DIAL`]; the objects over the cap are `over_cap` (the
/// caller defers them for this attempt).
struct Batch {
    frames: Vec<Vec<u8>>,
    in_batch: Vec<usize>,
    acks: Vec<[u8; 32]>,
    over_cap: Vec<usize>,
}

/// The [`Batch`] of `planned` now (pure: the caller applies the deferrals).
fn batch_for(
    planned: &OutboxRoute,
    candidates: &[Candidate],
    owed: &[&([u8; 32], UnsentAck)],
    acks_sent: &HashSet<[u8; 32]>,
    ack_routes: &[(OutboxRoute, OutboxRoute)],
    wall: u64,
) -> Batch {
    let mut b = Batch {
        frames: Vec::new(),
        in_batch: Vec::new(),
        acks: Vec::new(),
        over_cap: Vec::new(),
    };
    if ack_routes.iter().any(|(p, _)| p == planned) {
        for (digest, ack) in owed.iter().map(|e| &**e) {
            if b.frames.len() < MAX_FRAMES_PER_DIAL
                && !acks_sent.contains(digest)
                && ack.expires_at_ms > wall
            {
                b.frames.push(ack.bytes.clone());
                b.acks.push(*digest);
            }
        }
    }
    for (i, c) in candidates.iter().enumerate() {
        if c.sent.is_none() && !c.deferred && c.routes.iter().any(|(p, _)| p == planned) {
            if b.frames.len() < MAX_FRAMES_PER_DIAL {
                b.frames.push(c.bytes.clone());
                b.in_batch.push(i);
            } else {
                b.over_cap.push(i);
            }
        }
    }
    b
}

/// What one dial of the worker brings back ([`Dialer::dial_path_meta`]).
type DialResult = Result<(Vec<Vec<u8>>, Option<DeliveryPath>), String>;

/// The onion side of an attempt's race: its batch (taken when the attempt
/// began) and its thread.
struct OnionBranch {
    batch: Batch,
    handle: std::thread::JoinHandle<DialResult>,
}

fn attempt_peer_inner(
    ctx: &AttemptCtx,
    peer: &[u8; 32],
    due: &[Entry],
    owed_acks: &[([u8; 32], UnsentAck)],
) -> PeerReport {
    let mut report = PeerReport {
        attempted: due.iter().map(|e| e.object_digest).collect(),
        ..PeerReport::default()
    };
    let data_dir = ctx.data_dir.as_path();
    let wall = now_ms();
    let mono = Instant::now();
    let peer_hex = hex::encode(peer);

    // Each send's own record (its carrier choice, the routes it used): read
    // first, for the LAN beacon below.
    let records: BTreeMap<[u8; 16], ObjectRoutes> =
        object_route_records(data_dir, wall).unwrap_or_default();
    // Carry choice (P6.16): who holds each due message as the attempt
    // begins (a delivery below clears its record).
    if crate::learning::carry_live() {
        for e in due
            .iter()
            .filter(|e| e.kind == EndpointOutboundKind::Message)
        {
            let held = records.get(&e.message_id).map_or_else(Vec::new, |r| {
                r.custodians_held
                    .iter()
                    .filter_map(|h| <[u8; 32]>::try_from(hex::decode(h).ok()?).ok())
                    .collect()
            });
            if !held.is_empty() {
                report.carried.insert(e.object_digest, held);
            }
        }
    }
    // Contact and block list first: nothing (not even an owed ACK) goes to a
    // key that is not a current, unblocked contact. Then the resolver
    // AppSubmit and the announcer share ([`peer_plan`]): what it taught us
    // (where it last reached us from and, while route hints are live, what
    // its RRH1 said; a learned local address off this computer's networks
    // is left out), the gates and the route memory; and when LAN may carry
    // something due, where the LAN beacon found the contact, first among its
    // LAN routes instead of what was learned ([`attempt_plan`]).
    // "Pause sending" (Phase 6b P6.31) comes first: the user asked that
    // nothing go to this contact, so nothing is planned or dialled (not even
    // the LAN beacon's search), and its messages and owed ACKs wait as they
    // are until the user resumes.
    if raven_core::node_policy::load_policy(data_dir).send_held(peer) {
        return report.hold_all(code::SENDING_PAUSED);
    }
    let resolved: Option<PeerPlan> =
        match plan_inputs(ctx, peer, wall, lan_may_carry(due, owed_acks, &records)) {
            Ok(plan) => Some(plan),
            Err(held) => {
                // A key that is no contact (or a blocked one) is owed no ACK;
                // an unreadable book keeps them for later.
                if held != code::CONTACTS_UNREADABLE {
                    report.acks_done = owed_acks.iter().map(|(d, _)| *d).collect();
                }
                report.held = Some(held);
                None
            }
        };

    let mut store = match IndexedSessionStore::open(data_dir) {
        Ok(store) => store,
        Err(_) => return report.hold_all(code::STORE),
    };

    // Plans (no lock, no store writes): records (above), gates, trust,
    // localization.
    let gates = resolved
        .as_ref()
        .map_or_else(|| carrier_gates(ctx), |p| p.gates);
    // Route memory (G2, lab only): the route that last reached this contact
    // after a route above it failed goes first, on this network, for a
    // while. Order only, after every other rule. Without a contact there is
    // no memory. Learning connectivity supersedes it while on (below).
    let net: Option<&str> = resolved.as_ref().and_then(|p| p.net.as_deref());
    let preferred: Option<&OutboxRoute> = resolved.as_ref().and_then(|p| p.preferred.as_ref());
    // The LAN beacon's finds in the plan (RAVEN_LAN_BEACON_V1 §7, §9).
    let found: &[String] = resolved.as_ref().map_or(&[], |p| p.beacon.as_slice());
    let is_find = |r: &OutboxRoute| r.carrier == OutboxCarrier::Lan && found.contains(&r.dial);
    // (route as planned, reached) per dial of ours, for the memory.
    let mut dialled: Vec<(OutboxRoute, bool)> = Vec::new();
    // Learning connectivity (Phase 6a): while on, the resolver ranked every
    // plan of this contact by the learned carrier order
    // (`PeerPlan::learned`, OD6a-10: the route memory is neither read nor
    // taught); blocks, localizing, G3's rotation and a connected route
    // still apply per object, in that order. The ACKs each dial brought
    // back, for a retraction when every one of them is refused.
    let learning = crate::learning::live_on();
    let learned: Option<(&Order, Option<&str>)> = resolved
        .as_ref()
        .and_then(|p| Some((p.learned.as_ref()?, p.learned_net.as_deref())));
    let mut dial_acks: Vec<(OutboxCarrier, u64, Vec<Vec<u8>>)> = Vec::new();
    let reset_live = raven_core::session_reset::session_reset_live_enabled();
    let mut reset_finished: Vec<[u8; 16]> = Vec::new();
    if let (true, Some(p)) = (reset_live, &resolved) {
        run_reset_for_attempt(
            ctx,
            peer,
            &p.contact,
            gates,
            due,
            &mut store,
            &mut report,
            &mut reset_finished,
        );
    }
    // The long message horizon (Phase 5a): parked messages sealed again
    // into a fresh session (re-paired first when needed), right after the
    // reset step; an unknown or blocked contact's are only settled.
    let horizon_live = raven_core::horizon::horizon_live_enabled();
    if horizon_live {
        run_horizon_for_attempt(
            ctx,
            peer,
            resolved.as_ref(),
            due,
            &mut store,
            &mut report,
            &mut reset_finished,
        );
    }
    let mut localized: HashMap<OutboxRoute, Result<OutboxRoute, RouteRefusal>> = HashMap::new();
    let mut localize = |route: &OutboxRoute, pinned: bool| {
        localized
            .entry(route.clone())
            .or_insert_with(|| localize_lan_route(route, pinned, LOCALIZE_RESOLVE_TIMEOUT))
            .clone()
    };
    // The contact's plain plan order (saved LAN, learned LAN, Internet, p2p
    // behind the gates): the ranks the route memory learns by.
    let normal: Vec<OutboxRoute> = resolved.as_ref().map(|p| p.plain(peer)).unwrap_or_default();
    if let Some((order, _)) = learned {
        crate::learning::planned(order, &raven_core::learning::rank::carriers_of(&normal));
    }
    // F5: may another contact's success on this network wake this one? (No
    // contact, no plan: no.)
    report.lan_wakeable = Some(lan_wakeable(data_dir, peer, &normal, sibling_wake_live()));
    report.planned_other = Some(normal.iter().any(|r| r.carrier != OutboxCarrier::Lan));
    // Phase 6b R4: carriers whose links to this contact were tampered with
    // on this network lately go last (none while the responses gate is
    // shut).
    let interfered = interfered_carriers(peer, wall);
    // Owed ACKs go over the contact's own routes, any carrier allowed.
    let mut ack_routes: Vec<(OutboxRoute, OutboxRoute)> = resolved
        .as_ref()
        .map(|p| p.auto_dial(peer, ctx.connected, &mut localize))
        .unwrap_or_default();
    demote_interfered(&mut ack_routes, &interfered, false);
    // Sealed letters (Phase 5b): a message in a letter session that is still
    // provisional goes out directly only once a replay of its PairInit on
    // these routes completed the session; without a PairResponse its copies
    // are parked again for the horizon's re-pair, run now.
    if resolved.is_some()
        && crate::letters::settle_letter_rows(
            ctx,
            &mut store,
            peer,
            &ack_routes,
            due,
            &mut report,
            wall,
        )
    {
        run_horizon_for_attempt(
            ctx,
            peer,
            resolved.as_ref(),
            due,
            &mut store,
            &mut report,
            &mut reset_finished,
        );
    }

    // Session-bound peer certificates (revocation, ACK checks). A missing one
    // is fetched by a frame-less probe, which caches the peer's bundle.
    let mut keys: HashMap<[u8; 32], Option<IndexedSessionRecordKey>> = HashMap::new();
    for entry in due {
        keys.entry(entry.session_id).or_insert_with(|| {
            store
                .record_key_for_session_id(&entry.session_id)
                .ok()
                .flatten()
        });
    }
    let cert_for = |store: &mut IndexedSessionStore, key: &IndexedSessionRecordKey| {
        raven_core::lan_dispatch::session_bound_peer_certificate(data_dir, store, key, peer)
            .ok()
            .flatten()
    };
    let mut certs: HashMap<[u8; 32], Option<DeviceCertificate>> = HashMap::new();
    for (sid, key) in &keys {
        let cert = key.as_ref().and_then(|k| cert_for(&mut store, k));
        certs.insert(*sid, cert);
    }
    // Only for messages that can still go out: an expired one needs no dial.
    let missing_cert = resolved.is_some()
        && due.iter().any(|e| {
            e.kind == EndpointOutboundKind::Message
                && e.expires_at_ms > wall
                && keys.get(&e.session_id).is_some_and(Option::is_some)
                && certs.get(&e.session_id).is_some_and(Option::is_none)
        });
    if missing_cert {
        if let Some((planned, dial)) = ack_routes.first() {
            // A frame-less probe that authenticated is reachability evidence,
            // unless it only rode the contact's own connection.
            let ok = ctx
                .dialer
                .dial_path(data_dir, dial, &peer_hex, &[])
                .is_ok_and(|(_, path)| path != Some(DeliveryPath::Reversed));
            dialled.push((planned.clone(), ok));
            for (sid, key) in &keys {
                if certs.get(sid).is_some_and(Option::is_none) {
                    let cert = key.as_ref().and_then(|k| cert_for(&mut store, k));
                    certs.insert(*sid, cert);
                }
            }
            // Session reset E2 (§12.2): the probe cached the contact's own,
            // verified certificate. If it is not the one bound into these
            // sessions, the contact cannot use them any more: retire them, and
            // the rows go to the reset step (Held PEER_RESET below).
            if reset_live && certs.values().any(Option::is_none) {
                if let Ok(Some(bundle)) = raven_core::load_cached_peer_bundle(data_dir, peer) {
                    if let Ok(_lock) = PeerSendLock::acquire_within(data_dir, peer, LOCK_WAIT) {
                        let _ = raven_core::session_reset::note_presented_cert(
                            data_dir,
                            &mut store,
                            peer,
                            &bundle.cert,
                            wall,
                        );
                    }
                }
            }
        }
    }
    // The peer's certificate for the owed-ACK revocation check.
    let any_cert: Option<DeviceCertificate> =
        certs.values().flatten().next().cloned().or_else(|| {
            raven_core::load_cached_peer_bundle(data_dir, peer)
                .ok()
                .flatten()
                .map(|b| b.cert)
        });

    // ── Under the send lock: decide everything local, capture the bytes ──
    let lock = match PeerSendLock::acquire_within(data_dir, peer, LOCK_WAIT) {
        Ok(lock) => lock,
        Err(e) => {
            return report.hold_all(if send_lock_busy(&e) {
                code::SEND_IN_PROGRESS
            } else {
                code::LOCK
            });
        }
    };
    if reset_live || horizon_live {
        let _ = raven_core::session_reset::reconcile_resealed_outbound(
            data_dir,
            &ctx.identity,
            &mut store,
            peer,
            wall,
        );
    }
    let rows: Vec<EndpointOutbound> = match (
        store.pending_endpoint_outbound_for_recipient(Some(peer)),
        store.awaiting_ack_endpoint_outbound_for_recipient(Some(peer)),
    ) {
        (Ok(mut p), Ok(a)) => {
            p.extend(a);
            p
        }
        _ => return report.hold_all(code::STORE),
    };
    let mut bodies = LocalBodies::new();
    let mut live: Vec<(&Entry, &EndpointOutbound)> = Vec::new();
    let mut finished: Vec<[u8; 16]> = reset_finished;
    for entry in due {
        if report.outcomes.contains_key(&entry.object_digest) {
            // Decided by the reset step above.
            continue;
        }
        if entry.is_probe() {
            // The contact's parked messages, when the horizon step above
            // decided nothing for them: still there, the probe waits on.
            let outcome = match store.parked_for_recipient(peer) {
                Ok(parked) if parked.is_empty() => Outcome::Gone,
                Ok(_) => Outcome::Parked,
                Err(_) => Outcome::Held(code::STORE),
            };
            report.outcomes.insert(entry.object_digest, outcome);
            continue;
        }
        let Some(row) = rows.iter().find(|r| r.object_digest == entry.object_digest) else {
            // It left the store since the last scan: why? No dial needed.
            let outcome = finalize_vanished(data_dir, &mut store, peer, entry, wall);
            if matches!(
                outcome,
                Outcome::Delivered { .. } | Outcome::Expired | Outcome::Failed(_) | Outcome::Gone
            ) {
                finished.push(entry.message_id);
            }
            report.outcomes.insert(entry.object_digest, outcome);
            continue;
        };
        if row.kind == EndpointOutboundKind::Message
            && store.session_is_retired(&row.session_id).unwrap_or(false)
        {
            // The contact lost this session: never sealed, resent or retried
            // again here; the reset step re-seals it.
            report
                .outcomes
                .insert(entry.object_digest, Outcome::Held(code::PEER_RESET));
            continue;
        }
        if let Some(outcome) = settle_locally(
            data_dir,
            &mut store,
            &keys,
            &mut bodies,
            peer,
            entry,
            row,
            wall,
        ) {
            if !matches!(outcome, Outcome::Held(_) | Outcome::Parked) {
                finished.push(entry.message_id);
            }
            report.outcomes.insert(entry.object_digest, outcome);
            continue;
        }
        live.push((entry, row));
    }
    let Some(resolver) = resolved.as_ref() else {
        drop(lock);
        let _ = clear_object_routes(data_dir, &finished);
        return report;
    };
    let contact = &resolver.contact;

    // Revocation: never seal to, resend to or push an ACK to a revoked lineage.
    // An unreadable revocation store denies everything and destroys nothing.
    let verdicts: Vec<Result<bool, String>> = certs
        .values()
        .flatten()
        .chain(any_cert.iter())
        .map(|c| peer_lineage_denied(data_dir, c))
        .collect();
    if verdicts.iter().any(Result::is_err) {
        drop(lock);
        let _ = clear_object_routes(data_dir, &finished);
        for (entry, _) in &live {
            report
                .outcomes
                .insert(entry.object_digest, Outcome::Held(code::STORE));
        }
        return report;
    }
    if verdicts.iter().any(|v| matches!(v, Ok(true))) {
        let _ = abandon_undelivered_to_peer(data_dir, &mut store, peer);
        drop(lock);
        report.acks_done = owed_acks.iter().map(|(d, _)| *d).collect();
        for (entry, _) in &live {
            report
                .outcomes
                .insert(entry.object_digest, Outcome::Failed(code::PEER_REVOKED));
            finished.push(entry.message_id);
        }
        let _ = clear_object_routes(data_dir, &finished);
        return report;
    }
    // Without a certificate revocation cannot be checked: owed ACKs wait.
    let owed: Vec<&([u8; 32], UnsentAck)> = match &any_cert {
        Some(_) => owed_acks.iter().collect(),
        None => Vec::new(),
    };

    let (local_cert, registry) =
        match ensure_local_device_certificate(data_dir, &ctx.identity, PRIMARY_DEVICE_ID) {
            Ok(v) => v,
            Err(_) => {
                drop(lock);
                for (entry, _) in &live {
                    report
                        .outcomes
                        .insert(entry.object_digest, Outcome::Held(code::LOCAL_DEVICE));
                }
                return report;
            }
        };
    let local_device =
        match AuthorizedEndpointDevice::authorize(&local_cert, &ctx.identity, &registry, wall) {
            Ok(d) => d,
            Err(_) => {
                drop(lock);
                for (entry, _) in &live {
                    report.outcomes.insert(
                        entry.object_digest,
                        Outcome::Held(code::LOCAL_DEVICE_REVOKED),
                    );
                }
                return report;
            }
        };
    let newest = store.find_sendable_session_for_peer(peer).ok().flatten();

    // Friend custody (gated): may this message still go to a friend? The
    // custodians the contact announced and that offer custody (learned,
    // Phase 3), then the ones listed for it, each with its offer; while
    // carry choice is live, the ones it picks from all of them (P6.16).
    let custody_live = raven_core::custody_gate::CustodyGates::current().live && contact.pinned;
    let (custody_set, carry): (CustodySet, Option<CarryChoice>) = if custody_live {
        custodians_for(data_dir, &ctx.identity.public_key_bytes(), peer, wall)
    } else {
        (Vec::new(), None)
    };
    // A custodian of the plan (handoff: a FORWARD may go where a pair park
    // stops a DEPOSIT).
    let custody_planned = custody_live && !custody_steps(ctx, peer, &custody_set, wall).is_empty();
    let custody_possible =
        |mid: &[u8; 16]| custody_planned && records.get(mid).is_some_and(|r| r.custody);
    let mut candidates: Vec<Candidate> = Vec::new();
    for (entry, row) in live {
        let mut held_why: Option<&'static str> = None;
        let Some(key) = keys.get(&row.session_id).cloned().flatten() else {
            report.outcomes.insert(entry.object_digest, Outcome::Gone);
            continue;
        };
        let routes: Vec<(OutboxRoute, OutboxRoute)> = if row.kind == EndpointOutboundKind::Ack {
            ack_routes.clone()
        } else {
            // Learned order or remembered route ([`PeerPlan::object_routes`]);
            // a contradiction plans the static order.
            let plan = resolver.object_routes(peer, records.get(&row.message_id));
            let mut unlocal = false;
            let mut unresolved = false;
            let blocked =
                |r: &OutboxRoute| entry.blocked_routes.contains(r) || entry.pin_blocked.contains(r);
            let mut routes: Vec<(OutboxRoute, OutboxRoute)> = plan
                .routes
                .iter()
                .filter(|r| !blocked(r))
                .filter_map(|r| match localize(r, contact.localize_pinned(r)) {
                    Ok(d) => Some((r.clone(), d)),
                    Err(RouteRefusal::NotLocal) => {
                        unlocal = true;
                        None
                    }
                    Err(RouteRefusal::Unresolved(_)) => {
                        unresolved = true;
                        None
                    }
                })
                .collect();
            // After the blocks and the localization: a blocked or no longer
            // planned silent route simply means plan order.
            rotate_past(&mut routes, entry.unacked_route.as_ref());
            connected_first(&mut routes, ctx.connected, entry.unacked_route.as_ref());
            let set_aside =
                demote_interfered(&mut routes, &interfered, custody_possible(&row.message_id));
            if routes.is_empty() {
                let why: &'static str = if set_aside {
                    // R4: friend custody first, the tampered path later.
                    code::NOT_REACHABLE
                } else if !plan.routes.is_empty() && plan.routes.iter().all(blocked) {
                    if !plan.routes.iter().any(|r| entry.blocked_routes.contains(r)) {
                        // Only where another key answered (M0).
                        code::WRONG_IDENTITY
                    } else if entry.blocked_code.is_empty() {
                        code::LINK_NOT_ACCEPTED
                    } else {
                        entry.blocked_code
                    }
                } else if plan.unverified_withheld || (unlocal && !contact.pinned) {
                    CONTACT_NOT_VERIFIED
                } else if unresolved {
                    code::NOT_REACHABLE
                } else {
                    code::NO_ROUTE
                };
                if custody_possible(&row.message_id) {
                    // A friend may still carry it: captured with no route.
                    held_why = Some(why);
                } else {
                    report
                        .outcomes
                        .insert(entry.object_digest, Outcome::Held(why));
                    continue;
                }
            }
            routes
        };
        if row.kind == EndpointOutboundKind::Ack && routes.is_empty() {
            report
                .outcomes
                .insert(entry.object_digest, Outcome::Held(code::NO_ROUTE));
            continue;
        }
        if row.kind == EndpointOutboundKind::Message {
            let Some(cert) = certs.get(&row.session_id).cloned().flatten() else {
                report
                    .outcomes
                    .insert(entry.object_digest, Outcome::Held(code::NO_PEER_CERT));
                continue;
            };
            if raven_core::refuse_if_session_lineage_revoked(data_dir, &local_cert, &cert).is_err()
            {
                report.outcomes.insert(
                    entry.object_digest,
                    Outcome::Held(code::LOCAL_DEVICE_REVOKED),
                );
                continue;
            }
            // History must hold the body before the message can be delivered.
            // An app channel object has no chat history: its record lives in
            // the app outbox (design §8.6).
            let history = if bodies.is_app(data_dir, peer, &row.message_id) {
                Ok(())
            } else {
                raven_core::ensure_outbound_queued_history(
                    data_dir,
                    peer,
                    &row.session_id,
                    &row.object_digest,
                    &row.message_id,
                    wall,
                    None,
                )
            };
            if let Err(e) = history {
                let outcome = if e.contains("outbound body unavailable") {
                    Outcome::Held(code::NO_LOCAL_BODY)
                } else if e.contains("binding mismatch") {
                    match give_up_outbound(
                        data_dir,
                        &mut store,
                        &key,
                        peer,
                        &row.session_id,
                        &row.object_digest,
                        &row.message_id,
                        HISTORY_FAILED,
                    ) {
                        Ok(GiveUp::Abandoned) => Outcome::Failed(code::STAGE),
                        Ok(GiveUp::Delivered) => Outcome::Delivered { carrier: None },
                        Err(_) => Outcome::Held(code::STORE),
                    }
                } else {
                    Outcome::Held(code::HISTORY)
                };
                if !matches!(outcome, Outcome::Held(_)) {
                    finished.push(row.message_id);
                }
                report.outcomes.insert(entry.object_digest, outcome);
                continue;
            }
        }
        match capture(&mut store, &key, row, &local_device, wall) {
            Captured::Bytes { bytes, pending } => candidates.push(Candidate {
                digest: row.object_digest,
                kind: row.kind,
                key: key.clone(),
                session_id: row.session_id,
                message_id: row.message_id,
                pending,
                expires_at_ms: entry.expires_at_ms,
                bytes,
                routes,
                sent: None,
                sent_on: None,
                sent_via: None,
                path: None,
                last_try: None,
                lan_on_net: false,
                deferred: false,
                superseded: newest.as_ref().is_some_and(|n| *n != key),
                refusals: entry.refusals,
                first_refusal: entry.first_refusal,
                refused_on: None,
                held_why,
                custody_new: Vec::new(),
                custody_forwarded: false,
                unacked: entry.unacked_route.is_some(),
                tried: Vec::new(),
            }),
            Captured::Delivered => {
                let _ = record_outbound_delivered(
                    data_dir,
                    &mut store,
                    peer,
                    &row.session_id,
                    &row.message_id,
                );
                finished.push(row.message_id);
                report
                    .outcomes
                    .insert(entry.object_digest, Outcome::Delivered { carrier: None });
            }
            Captured::Gone => {
                report.outcomes.insert(entry.object_digest, Outcome::Gone);
            }
            Captured::NotValid => {
                // Expired by the envelope's own clock: give up (park it
                // before its deadline, the long message horizon). Otherwise
                // the wall clock moved (a step backwards): hold and retry
                // later.
                let outcome = if entry.expires_at_ms <= wall {
                    expired_outcome(park_or_give_up_expired(
                        data_dir,
                        &mut store,
                        &key,
                        peer,
                        &row.session_id,
                        &row.object_digest,
                        &row.message_id,
                        entry.never_sent,
                        wall,
                    ))
                } else {
                    Outcome::Held(code::CLOCK)
                };
                if !matches!(outcome, Outcome::Held(_) | Outcome::Parked) {
                    finished.push(row.message_id);
                }
                report.outcomes.insert(entry.object_digest, outcome);
            }
            Captured::Failed => {
                report
                    .outcomes
                    .insert(entry.object_digest, Outcome::Held(code::STORE));
            }
        }
    }
    // From here on any of these may reach the peer: never "unsent" while it
    // is in flight (a `raven outbox cancel` meanwhile must not tell the user
    // the peer cannot have it). Restored below for what was not written.
    let was_unsent: Vec<usize> = candidates
        .iter()
        .enumerate()
        .filter(|(_, c)| {
            c.kind == EndpointOutboundKind::Message
                && records.get(&c.message_id).is_some_and(|r| r.unsent)
        })
        .map(|(i, _)| i)
        .collect();
    for &i in &was_unsent {
        let _ =
            raven_core::outbox::set_object_unsent(data_dir, &candidates[i].message_id, false, wall);
    }
    // App channel objects among them: their records follow the writes below.
    let app_objects: Vec<bool> = candidates
        .iter()
        .map(|c| {
            c.kind == EndpointOutboundKind::Message && bodies.is_app(data_dir, peer, &c.message_id)
        })
        .collect();
    drop(lock);

    // Learning connectivity's ACK-only exploration (Phase 6a, design §5): a
    // batch of owed ACKs and ACK rows with no message may put the stalest
    // eligible carrier of a verified contact first, within the exploration
    // budget ([`crate::learning::explore_ack_order`]). A batch with any
    // message keeps the exploit order: a user message never explores.
    if learning
        && candidates
            .iter()
            .all(|c| c.kind != EndpointOutboundKind::Message)
        && (!candidates.is_empty() || owed.iter().any(|(_, a)| a.expires_at_ms > wall))
    {
        let statics = raven_core::learning::rank::carriers_of(&normal);
        if crate::learning::explore_ack_order(peer, contact.pinned, &statics, &mut ack_routes)
            .is_some()
        {
            // Every candidate left is an ACK row: it rides the same order.
            for c in &mut candidates {
                c.routes.clone_from(&ack_routes);
            }
        }
    }

    // ── Without the lock: one dial per route, every due frame in it ──
    let mut acks_sent: HashSet<[u8; 32]> = HashSet::new();
    let mut replies: Vec<Vec<u8>> = Vec::new();
    // The carrier each reply came back on (the security events of a refused
    // ACK name the dial).
    let mut reply_carriers: Vec<OutboxCarrier> = Vec::new();
    let mut order: Vec<(OutboxRoute, OutboxRoute)> = Vec::new();
    let ack_route_count = if owed.is_empty() { 0 } else { ack_routes.len() };
    for route in candidates
        .iter()
        .flat_map(|c| c.routes.iter())
        .chain(ack_routes[..ack_route_count].iter())
    {
        if !order.contains(route) {
            order.push(route.clone());
        }
    }
    // The Tor race (design 2026-10-tor-fallback §2, §3.4; happy eyeballs):
    // with an onion route and another route in this attempt, the onion dial
    // runs on its own thread after the direct paths' head start (at once
    // when they are all tried), and the first link that authenticates
    // claims the attempt (`crate::onion::race`); the other writes nothing.
    let mut onion_branch: Option<OnionBranch> = None;
    let race: Option<Arc<RaceGuard>> = order
        .iter()
        .find(|(p, _)| p.carrier == OutboxCarrier::Onion)
        .filter(|_| order.iter().any(|(p, _)| p.carrier != OutboxCarrier::Onion))
        .and_then(|(planned, dial)| {
            let batch = batch_for(planned, &candidates, &owed, &acks_sent, &ack_routes, wall);
            if batch.frames.is_empty() {
                return None;
            }
            for &i in &batch.over_cap {
                candidates[i].deferred = true;
            }
            let race = Arc::new(RaceGuard::new());
            let meta = DialMeta {
                karn_exclude: batch.in_batch.iter().any(|&i| candidates[i].unacked),
                race: Some(race.ticket(RaceSide::Onion)),
                ..DialMeta::default()
            };
            let (dialer, dd, hex) = (ctx.dialer.clone(), data_dir.to_path_buf(), peer_hex.clone());
            let (frames, dial, waiter) = (batch.frames.clone(), dial.clone(), race.clone());
            // Every direct route just failed for a send (E2 r40): Tor
            // first, at once.
            let direct: Vec<OutboxCarrier> = order.iter().map(|(p, _)| p.carrier).collect();
            let head = if crate::delivery_paths::direct_routes_failed_lately(peer, &direct) {
                Duration::ZERO
            } else {
                (ctx.onion_head_start)()
            };
            let handle = std::thread::Builder::new()
                .name("onion-race".into())
                .spawn(move || {
                    if !waiter.wait_head_start(head) {
                        return Err(crate::onion::race::RACE_LOST.to_string());
                    }
                    dialer.dial_path_meta(&dd, &dial, &hex, &frames, meta)
                })
                .ok()?;
            onion_branch = Some(OnionBranch { batch, handle });
            Some(race)
        });
    for (planned, dial) in &order {
        // `raven lan off` (or the end of a meeting) while this attempt runs:
        // its LAN routes left are not dialled (B-3); the next attempt plans
        // without them.
        if planned.carrier == OutboxCarrier::Lan && !(ctx.lan_live)() {
            continue;
        }
        let is_onion = planned.carrier == OutboxCarrier::Onion;
        // The onion side won the race: no other path is dialled.
        if !is_onion
            && race
                .as_ref()
                .is_some_and(|r| r.winner() == Some(RaceSide::Onion))
        {
            continue;
        }
        let batch = batch_for(planned, &candidates, &owed, &acks_sent, &ack_routes, wall);
        for &i in &batch.over_cap {
            candidates[i].deferred = true;
        }
        let (result, in_batch, acks_in_batch) = match onion_branch.take() {
            Some(branch) if is_onion => {
                if let Some(r) = race.as_ref() {
                    r.direct_exhausted();
                }
                let got = branch
                    .handle
                    .join()
                    .unwrap_or_else(|_| Err("onion dial thread ended abnormally".into()));
                match got {
                    // A direct path won: what it could not carry (a send
                    // limited to Tor's side) goes over Tor now, unraced.
                    Err(e) if crate::onion::race::is_race_lost(&e) => {
                        if batch.frames.is_empty() {
                            continue;
                        }
                        let meta = DialMeta {
                            karn_exclude: batch.in_batch.iter().any(|&i| candidates[i].unacked),
                            ..DialMeta::default()
                        };
                        (
                            ctx.dialer.dial_path_meta(
                                data_dir,
                                dial,
                                &peer_hex,
                                &batch.frames,
                                meta,
                            ),
                            batch.in_batch,
                            batch.acks,
                        )
                    }
                    // Its own batch, minus what another path carried
                    // meanwhile (an unraced nearby dial).
                    got => {
                        let in_batch: Vec<usize> = branch
                            .batch
                            .in_batch
                            .into_iter()
                            .filter(|&i| candidates[i].sent.is_none())
                            .collect();
                        let acks: Vec<[u8; 32]> = branch
                            .batch
                            .acks
                            .into_iter()
                            .filter(|d| !acks_sent.contains(d))
                            .collect();
                        (got, in_batch, acks)
                    }
                }
            }
            branch => {
                onion_branch = branch;
                if batch.frames.is_empty() {
                    continue;
                }
                // Karn (Phase 6a): an ACK on a dial that resends a silent
                // object may answer its earlier copy, so its reply time is
                // no sample.
                let raced = matches!(
                    planned.carrier,
                    OutboxCarrier::Lan | OutboxCarrier::Internet | OutboxCarrier::P2p
                );
                let meta = DialMeta {
                    karn_exclude: batch.in_batch.iter().any(|&i| candidates[i].unacked),
                    race: race
                        .as_ref()
                        .filter(|_| raced)
                        .map(|r| r.ticket(RaceSide::Direct)),
                    ..DialMeta::default()
                };
                (
                    ctx.dialer
                        .dial_path_meta(data_dir, dial, &peer_hex, &batch.frames, meta),
                    batch.in_batch,
                    batch.acks,
                )
            }
        };
        // A dial that lost the race wrote nothing: neither evidence nor a
        // failure of its route.
        if result
            .as_ref()
            .err()
            .is_some_and(|e| crate::onion::race::is_race_lost(e))
        {
            continue;
        }
        // The route memory's evidence, by the planned route (its key). A dial
        // that carried messages and got no ACK back did not show the route
        // works (G3 tries it last next time): it never earns the lead. Nor
        // does a link that rode the contact's own connection (reversed):
        // that cannot be repeated on demand.
        let silent = in_batch
            .iter()
            .any(|&i| candidates[i].kind == EndpointOutboundKind::Message)
            && result
                .as_ref()
                .is_ok_and(|(got, _)| ack_frames(got).is_empty());
        let reversed = result
            .as_ref()
            .is_ok_and(|(_, path)| *path == Some(DeliveryPath::Reversed));
        dialled.push((planned.clone(), result.is_ok() && !silent && !reversed));
        match result {
            Ok((got, path)) => {
                if learning {
                    let acks: Vec<Vec<u8>> =
                        ack_frames(&got).into_iter().map(<[u8]>::to_vec).collect();
                    if !acks.is_empty() {
                        dial_acks.push((planned.carrier, now_ms(), acks));
                    }
                }
                replies.extend(got);
                reply_carriers.resize(replies.len(), planned.carrier);
                acks_sent.extend(acks_in_batch);
                // Recorded for p2p only: LAN and Internet views stay as they
                // were.
                let path = path.filter(|_| planned.carrier == OutboxCarrier::P2p);
                for i in in_batch {
                    candidates[i].dialled_over(planned.carrier);
                    candidates[i].sent = Some(planned.carrier);
                    candidates[i].sent_on = Some(planned.clone());
                    candidates[i].sent_via = Some(dial.clone());
                    candidates[i].path = path;
                }
            }
            Err(e) => {
                let why = dial_error_code(&e);
                // A find that does not lead to the contact is one no longer
                // (§7): the beacon forgets it.
                if is_find(planned) && find_failed(why) {
                    (ctx.lan_beacon_failed)(peer, &planned.dial);
                }
                let on_net =
                    planned.carrier == OutboxCarrier::Lan && dial_on_our_network(&dial.dial);
                for i in in_batch {
                    let c = &mut candidates[i];
                    c.dialled_over(planned.carrier);
                    c.lan_on_net |= on_net;
                    // A refusal on one route says more than a transport failure
                    // on another (say, a stale learned address): keep it, so the
                    // refusal count and the reported reason stay right. Not
                    // being in Bluetooth range, or every nearby link in use,
                    // says less than any other carrier's answer.
                    let keep = matches!(c.last_try, Some((_, prev)) if prev == code::PEER_REFUSED)
                        || (matches!(why, code::NEARBY_NOT_IN_RANGE | code::NEARBY_BUSY)
                            && c.last_try.is_some())
                        || lan_failure_says_more(c.last_try, planned.carrier, &e, c.lan_on_net);
                    if !keep {
                        c.last_try = Some((planned.carrier, why));
                    }
                    if why == code::PEER_REFUSED && c.refused_on.is_none() {
                        c.refused_on = Some(dial.clone());
                    }
                    if blocks_route(why) && is_noise_pin_mismatch(&e) {
                        report
                            .pin_blocked
                            .entry(c.digest)
                            .or_default()
                            .push(planned.clone());
                    } else if blocks_route(why) {
                        report
                            .blocked
                            .entry(c.digest)
                            .or_default()
                            .push((planned.clone(), why));
                    }
                }
            }
        }
    }
    // The race ends here: an onion dial still waiting or connecting stops
    // (its route was not reached, a hold skipped it).
    drop(onion_branch);
    drop(race);
    // What this attempt saw teaches the route memory, without the send lock
    // (it has its own). Custodian, reset and query dials are not ours to
    // learn from. `wall` (the attempt start) bounds what a forget removes.
    // The LAN beacon's finds stay in memory only (§9): not taught, and the
    // routes after them rank as if they were not there. Nor is a nearby
    // route (Phase 5): derived live from a pipe or a sighting, never stored,
    // so neither its delivery nor NEARBY_NOT_IN_RANGE is route evidence.
    // While learning connectivity is on it supersedes the memory (OD6a-10):
    // nothing is taught, and an attempt that reached the contact makes the
    // order it applied the start of the next ranking (its hysteresis). Not
    // an order that contradicted a plan: that contact-network is pinned to
    // the static order.
    if learning {
        let reached = dialled.iter().any(|(_, ok)| *ok);
        if let (true, Some((order, lnet))) = (reached, learned) {
            if !resolver.contradicted() {
                crate::learning::remember_order(peer, lnet, order);
            }
        }
    } else {
        // Nor an onion route (derived live, never stored, like nearby).
        let untaught = |r: &OutboxRoute| {
            matches!(r.carrier, OutboxCarrier::Nearby | OutboxCarrier::Onion) || is_find(r)
        };
        let (normal, dialled): (Vec<OutboxRoute>, Vec<(OutboxRoute, bool)>) = (
            normal.into_iter().filter(|r| !untaught(r)).collect(),
            dialled.into_iter().filter(|(r, _)| !untaught(r)).collect(),
        );
        let _ = raven_core::route_memory::learn(
            data_dir,
            peer,
            &normal,
            preferred,
            &dialled,
            net,
            wall,
            now_ms(),
        );
    }
    for (digest, ack) in &owed {
        if acks_sent.contains(digest) || ack.expires_at_ms <= wall {
            report.acks_done.push(*digest);
        }
    }
    // Session reset: a dial the peer closed on a Message: ask, alone, whether
    // it still holds that session (one query per session, backed off).
    let queries = if reset_live {
        query_refused_sessions(ctx, peer, &candidates)
    } else {
        Vec::new()
    };
    // Friend custody: leave what could not go directly with the contact's
    // friends (design §7.3 step 3), without the lock.
    let mut owed_held: Vec<([u8; 32], [u8; 32])> = Vec::new();
    let mut letter_moved: HashMap<[u8; 16], (Outcome, bool)> = HashMap::new();
    if custody_live && !custody_set.is_empty() {
        letter_moved = deposit_with_custodians(
            ctx,
            peer,
            &custody_set,
            carry.as_ref(),
            &mut store,
            &records,
            &mut candidates,
            &owed,
            &acks_sent,
            wall,
            &mut owed_held,
        );
    }
    // Moved into a letter session: the new copies are scanned at once. A
    // waiting letter message whose letter was just placed says so.
    report.rescan |= !letter_moved.is_empty();
    crate::letters::restatus(data_dir, peer, due, &mut report);
    if !owed_held.is_empty() {
        // An owed ACK left with a friend stays owed (direct pushes go on) and
        // is not filed there again. One that was only in memory (F8) is
        // written down first, so the friend is not asked again every attempt.
        if let Ok((mut table, _)) = raven_core::owed_acks::OwedAcks::open(data_dir) {
            for (digest, custodian) in &owed_held {
                if let Some((_, ack)) = owed.iter().map(|e| &**e).find(|(d, _)| d == digest) {
                    if !ack.durable {
                        let _ = table.record(
                            &ack.peer,
                            ack.session_id,
                            digest,
                            &ack.bytes,
                            ack.expires_at_ms,
                            raven_core::owed_acks::Origin::Link,
                            wall,
                        );
                    }
                }
                let _ = table.add_held(digest, custodian);
            }
        }
    }
    if candidates.is_empty() {
        let _ = clear_object_routes(data_dir, &finished);
        return report;
    }
    // A prepared message the contact read and refused stays prepared: say so
    // durably, so that after a restart its expiry does not read "it never
    // left this computer" (review C-time-deadlines-1).
    for c in candidates.iter().filter(|c| {
        c.kind == EndpointOutboundKind::Message
            && c.pending
            && c.sent.is_none()
            && matches!(c.last_try, Some((_, why)) if why == code::PEER_REFUSED)
    }) {
        let _ = raven_core::outbox::set_object_written(
            data_dir,
            &c.message_id,
            peer,
            c.expires_at_ms,
            now_ms(),
        );
    }

    // ── Under the lock again: record handoffs, verify the ACKs ──
    let Ok(_lock) = PeerSendLock::acquire_within(data_dir, peer, LOCK_WAIT * 5) else {
        // `raven send` holds the peer: record nothing now. The next attempt
        // re-sends the same bytes and gets the same ACK back (a duplicate).
        // ACKs not checked: whether this route stayed silent is unknown, so
        // no `unacked` (G3).
        for c in &candidates {
            let outcome = match c.sent {
                Some(carrier) => Outcome::Sent {
                    carrier: Some(carrier),
                    code: code::SEND_IN_PROGRESS,
                },
                None => Outcome::Held(code::SEND_IN_PROGRESS),
            };
            report.outcomes.insert(c.digest, outcome);
        }
        let _ = clear_object_routes(data_dir, &finished);
        return report;
    };
    let wall_after = now_ms();
    // A message a friend now holds was handed over: Prepared becomes Queued
    // (delivery state Sent), like a carrier write.
    for c in candidates
        .iter()
        .filter(|c| c.sent.is_none() && c.pending && !c.custody_new.is_empty())
    {
        let _ = store.retry_endpoint_outbound(
            &c.key,
            &c.digest,
            &local_device,
            wall_after,
            &mut |d: &[u8; 32], _: &[u8]| Ok(*d),
        );
    }
    for c in candidates.iter().filter(|c| !c.custody_new.is_empty()) {
        let _ = raven_core::outbox::add_object_holds(
            data_dir,
            &c.message_id,
            &c.custody_new,
            c.custody_forwarded,
            wall_after,
        );
    }
    for c in candidates.iter().filter(|c| c.sent.is_some() && c.pending) {
        let _ = store.retry_endpoint_outbound(
            &c.key,
            &c.digest,
            &local_device,
            wall_after,
            &mut |d: &[u8; 32], _: &[u8]| Ok(*d),
        );
    }
    let mut delivered: HashSet<[u8; 16]> = HashSet::new();
    let sessions: Vec<(IndexedSessionRecordKey, [u8; 32])> = {
        let mut s: Vec<(IndexedSessionRecordKey, [u8; 32])> = Vec::new();
        for c in &candidates {
            if !s.iter().any(|(k, _)| *k == c.key) {
                s.push((c.key.clone(), c.session_id));
            }
        }
        s
    };
    // Written: a carrier took it, the peer read it before refusing, or a
    // friend now holds a copy (friend custody).
    let written = |c: &Candidate| {
        c.sent.is_some()
            || matches!(c.last_try, Some((_, why)) if why == code::PEER_REFUSED)
            || !c.custody_new.is_empty()
            || letter_moved
                .get(&c.message_id)
                .is_some_and(|(_, held)| *held)
    };
    for &i in &was_unsent {
        if !written(&candidates[i]) {
            let _ = raven_core::outbox::set_object_unsent(
                data_dir,
                &candidates[i].message_id,
                true,
                wall,
            );
        }
    }
    // App channel records: on the wire from now on (design §8.8).
    for (i, c) in candidates.iter().enumerate() {
        if app_objects[i] && written(c) {
            let _ = raven_core::app_channel::mark_app_outbound(
                data_dir,
                &c.message_id,
                "sent",
                "",
                wall_after,
            );
        }
    }
    let mut refused_acks: Vec<&[u8]> = Vec::new();
    let acks = replies
        .iter()
        .zip(&reply_carriers)
        .filter(|(frame, _)| is_ack_frame(frame));
    for (ack, &carrier) in acks {
        for (key, session_id) in &sessions {
            let Some(cert) = certs.get(session_id).cloned().flatten() else {
                continue;
            };
            match accept_sealed_ack(data_dir, &mut store, key, &cert, ack, carrier) {
                Ok(mid) => {
                    // The one rule: a message is delivered only by an ACK
                    // that names it.
                    let _ = record_outbound_delivered(data_dir, &mut store, peer, session_id, &mid);
                    delivered.insert(mid);
                    break;
                }
                Err(AckRejected::OtherSession) => continue,
                Err(AckRejected::Refused(_)) => {
                    refused_acks.push(ack);
                    break;
                }
            }
        }
    }
    // Learning connectivity: a dial whose every ACK was refused gave no
    // receipt after all (the carrier counted one).
    for (carrier, at, acks) in &dial_acks {
        if acks.iter().all(|a| refused_acks.contains(&a.as_slice())) {
            crate::learning::retract(peer, *carrier, *at);
        }
    }
    let mut retired_now: HashSet<[u8; 32]> = HashSet::new();
    for (session_id, queried, answer) in &queries {
        let outcome = raven_core::session_reset::apply_query_replies(
            &mut store,
            &local_cert.device_ed_pub,
            peer,
            queried,
            answer,
            now_ms(),
        );
        let answered = !matches!(
            outcome,
            Ok(raven_core::session_reset::QueryOutcome::NoAnswer) | Err(_)
        );
        if answered {
            if let Ok(mut backoff) = ctx.reset_backoff.lock() {
                backoff.remove(&(*peer, *session_id));
            }
        }
        if let Ok(raven_core::session_reset::QueryOutcome::Retired { session_id, .. }) = outcome {
            retired_now.insert(session_id);
        }
    }
    if !retired_now.is_empty() {
        eprintln!(
            "raven-node outbox: contact reset: retired={} resealed=0 held={} expired=0",
            retired_now.len(),
            candidates
                .iter()
                .filter(|c| retired_now.contains(&c.session_id) && c.sent.is_none())
                .count()
        );
    }
    let custody_live = raven_core::custody_gate::CustodyGates::current().live;
    // Carry choice (P6.16): the friends this attempt left a message with
    // hold it too.
    if carry.is_some() {
        for c in candidates.iter().filter(|c| !c.custody_new.is_empty()) {
            let held = report.carried.entry(c.digest).or_default();
            for f in &c.custody_new {
                if !held.contains(f) {
                    held.push(*f);
                }
            }
        }
    }
    for c in &candidates {
        if !c.tried.is_empty() {
            report.tried.insert(c.digest, c.tried.clone());
        }
        // Moved into a letter session (or parked for one): its new copy is
        // tracked from the next scan.
        if let Some((outcome, _)) = letter_moved.get(&c.message_id) {
            report.outcomes.insert(c.digest, outcome.clone());
            continue;
        }
        // A reachable peer that keeps refusing a message sealed under a
        // superseded session: given up below, whoever holds a copy.
        let refused_superseded = matches!(c.last_try, Some((_, why)) if why == code::PEER_REFUSED)
            && c.kind == EndpointOutboundKind::Message
            && c.superseded
            && c.refusals + 1 >= SUPERSEDED_REFUSALS
            && c.first_refusal
                .is_some_and(|t| mono.saturating_duration_since(t) >= SUPERSEDED_SPAN);
        let outcome = match (c.kind, c.sent) {
            (EndpointOutboundKind::Message, None) if retired_now.contains(&c.session_id) => {
                Outcome::Held(code::PEER_RESET)
            }
            (EndpointOutboundKind::Message, None)
                if custody_live
                    && !refused_superseded
                    && !delivered.contains(&c.message_id)
                    && (!c.custody_new.is_empty()
                        || records
                            .get(&c.message_id)
                            .is_some_and(|r| !r.custodians_held.is_empty())) =>
            {
                let record = records.get(&c.message_id);
                let before = record.map_or(0, |r| r.custodians_held.len());
                // A friend holds it to pass on: whether the contact
                // collected it may never be known (review handoff-3).
                if c.custody_forwarded || record.is_some_and(|r| r.custody_forwarded) {
                    report.custody_forwarded.insert(c.digest);
                }
                Outcome::Deposited {
                    held: u8::try_from(before + c.custody_new.len()).unwrap_or(u8::MAX),
                }
            }
            (_, None) if c.held_why.is_some() => {
                Outcome::Held(c.held_why.unwrap_or(code::NO_ROUTE))
            }
            (EndpointOutboundKind::Ack, Some(carrier)) => Outcome::AckSent { carrier },
            (_, Some(carrier)) if delivered.contains(&c.message_id) => Outcome::Delivered {
                carrier: Some(carrier),
            },
            (_, Some(carrier)) => Outcome::Sent {
                carrier: Some(carrier),
                code: code::NO_ACK_YET,
            },
            (_, None) if c.deferred && c.last_try.is_none() => Outcome::Held(code::DEFERRED),
            (_, None) => {
                let (carrier, why) = c
                    .last_try
                    .map(|(c, w)| (Some(c), w))
                    .unwrap_or((None, code::NO_ROUTE));
                // Several ways and none answered: one reason, whichever
                // dial ended last (E2 r40: it flipped between "over Tor"
                // and "their computer" across retries).
                let why = no_answer_on_any(&c.tried, why);
                let routes_left = c
                    .routes
                    .iter()
                    .filter(|(p, _)| {
                        !report
                            .blocked
                            .get(&c.digest)
                            .is_some_and(|b| b.iter().any(|(r, _)| r == p))
                            && !report
                                .pin_blocked
                                .get(&c.digest)
                                .is_some_and(|b| b.contains(p))
                    })
                    .count();
                let span_ok = c
                    .first_refusal
                    .is_some_and(|t| mono.saturating_duration_since(t) >= SUPERSEDED_SPAN);
                if why == code::PEER_REFUSED
                    && c.kind == EndpointOutboundKind::Message
                    && c.superseded
                    && c.refusals + 1 >= SUPERSEDED_REFUSALS
                    && span_ok
                {
                    // Sealed under a session the reachable peer keeps refusing
                    // while a newer one exists: it can never be accepted.
                    match give_up_outbound(
                        data_dir,
                        &mut store,
                        &c.key,
                        peer,
                        &c.session_id,
                        &c.digest,
                        &c.message_id,
                        HISTORY_FAILED,
                    ) {
                        Ok(GiveUp::Abandoned) => Outcome::Failed(code::SUPERSEDED),
                        Ok(GiveUp::Delivered) => Outcome::Delivered { carrier: None },
                        Err(_) => Outcome::Unreachable { carrier, code: why },
                    }
                } else if routes_left == 0 {
                    Outcome::Held(why)
                } else {
                    Outcome::Unreachable { carrier, code: why }
                }
            }
        };
        // Written on that route and no ACK came back on it: try it last next
        // time, so the object's other routes get their turn (G3).
        if let (
            Outcome::Sent {
                code: code::NO_ACK_YET,
                ..
            },
            Some(route),
        ) = (&outcome, &c.sent_on)
        {
            report.unacked.insert(c.digest, route.clone());
        }
        if let (Some(_), Some(path)) = (c.sent, c.path) {
            report.paths.insert(c.digest, path);
        }
        if matches!(
            outcome,
            Outcome::Delivered { .. } | Outcome::Failed(_) | Outcome::Expired
        ) {
            finished.push(c.message_id);
        }
        report.outcomes.insert(c.digest, outcome);
    }
    drop(_lock);
    let _ = clear_object_routes(data_dir, &finished);
    report.lan_proved = lan_delivery_proves_network(&candidates, &report.outcomes);
    report
}

/// The reason of an object no dial of an attempt reached: `why` (the last
/// dial's), except that several carriers none of which answered are one
/// reason, [`code::NOT_REACHABLE`], whichever of them ended last.
fn no_answer_on_any(tried: &[OutboxCarrier], why: &'static str) -> &'static str {
    if tried.len() > 1 && matches!(why, code::ONION_UNREACHABLE | code::NOT_REACHABLE) {
        code::NOT_REACHABLE
    } else {
        why
    }
}

/// F5: did a verified ACK come back for an object a LAN dial of ours carried
/// to a local-network address other than loopback
/// ([`raven_core::outbox::lan_route_proves_network`])? A LAN route to a
/// public address (a verified contact's) or to this computer says nothing
/// about the local network. Nothing is looked up.
fn lan_delivery_proves_network(
    candidates: &[Candidate],
    outcomes: &HashMap<[u8; 32], Outcome>,
) -> bool {
    let lan_delivered = Outcome::Delivered {
        carrier: Some(OutboxCarrier::Lan),
    };
    candidates.iter().any(|c| {
        outcomes.get(&c.digest) == Some(&lan_delivered)
            && c.sent_via
                .as_ref()
                .is_some_and(raven_core::outbox::lan_route_proves_network)
    })
}

/// The local network's facts for the Phase 3 diagnosis
/// ([`raven_core::reach_diag::diagnose_lan`]) after an attempt that left a
/// message waiting for a route (unreached, as [`custody_status_codes`]
/// reads it): `lan_off` (`raven lan off`), `no_answer` (the LAN beacon asked
/// for the contact in vain, read only when LAN is on) and whether the plan
/// held a route on another carrier. `None` when no message waits that way,
/// or no plan was made: the last reason stands. Counts and fixed words only.
fn lan_reason(
    report: &PeerReport,
    due: &[Entry],
    lan_off: bool,
    no_answer: impl FnOnce() -> bool,
) -> Option<raven_core::reach_diag::LanFacts> {
    const UNREACHED: [&str; 4] = [
        code::NOT_REACHABLE,
        code::NO_ROUTE,
        code::NOT_LISTENING,
        code::DIAL_FAILED,
    ];
    let other_route = report.planned_other?;
    let waiting = due.iter().any(|e| {
        e.kind == EndpointOutboundKind::Message
            && matches!(
                report.outcomes.get(&e.object_digest),
                Some(Outcome::Unreachable { code, .. } | Outcome::Held(code))
                    if UNREACHED.contains(code)
            )
    });
    waiting.then(|| raven_core::reach_diag::LanFacts {
        lan_off,
        beacon_no_answer: !lan_off && no_answer(),
        other_route,
    })
}

/// Friend custody status (Phase 3): a message this attempt could not carry,
/// that friend custody may carry and that no friend holds, shows why no
/// friend takes it ([`custody_status`]) instead of its reachability code.
/// The outcome itself (held or unreachable, and its backoff) is unchanged.
fn custody_status_codes(ctx: &AttemptCtx, peer: &[u8; 32], due: &[Entry], report: &mut PeerReport) {
    if !raven_core::custody_gate::CustodyGates::current().live {
        return;
    }
    // Only a contact that could not be reached: a refusal, a wrong
    // identity or a held carrier keeps its own code (and what it drives).
    const UNREACHED: [&str; 4] = [
        code::NOT_REACHABLE,
        code::NO_ROUTE,
        code::NOT_LISTENING,
        code::DIAL_FAILED,
    ];
    let waiting = |e: &Entry| {
        e.kind == EndpointOutboundKind::Message
            && match report.outcomes.get(&e.object_digest) {
                Some(Outcome::Unreachable { code, .. } | Outcome::Held(code)) => {
                    UNREACHED.contains(code)
                }
                _ => false,
            }
    };
    if !due.iter().any(waiting) {
        return;
    }
    let wall = now_ms();
    let records = object_route_records(&ctx.data_dir, wall).unwrap_or_default();
    let targets: Vec<[u8; 32]> = due
        .iter()
        .filter(|e| waiting(e))
        .filter(|e| {
            records
                .get(&e.message_id)
                .is_some_and(|r| r.custody && r.custodians_held.is_empty())
        })
        .map(|e| e.object_digest)
        .collect();
    if targets.is_empty() {
        return;
    }
    let Some(status) = custody_status(ctx, peer, wall) else {
        return;
    };
    for digest in targets {
        match report.outcomes.get_mut(&digest) {
            Some(Outcome::Unreachable { code, .. }) => *code = status,
            Some(Outcome::Held(why)) => *why = status,
            _ => {}
        }
    }
}

/// Why no friend takes a message for `peer` (Phase 3, spec RRH1 §12.2),
/// while custody rides route hints and `peer` (a verified, unblocked
/// contact) announced custodians: [`code::MAILBOX_OFF`] when this node
/// never answered `raven custody use` and knows one of them;
/// with friend mailboxes on, [`code::NO_SHARED_CUSTODIAN`] when it knows
/// none of them, [`code::CUSTODIAN_NOT_OFFERING`] when every one it knows
/// offers nothing, or offers custody on LAN links only while only Internet
/// or p2p routes reach it. `None` otherwise: a friend this node listed for
/// `peer` itself, or one that offers custody, may still take it.
fn custody_status(ctx: &AttemptCtx, peer: &[u8; 32], wall: u64) -> Option<&'static str> {
    use raven_core::custody_client::custodian_routes;
    use raven_core::custody_gate::OFFER_WAN;
    if !raven_core::custody_gate::custody_hints_live() {
        return None;
    }
    let data_dir = ctx.data_dir.as_path();
    let local = ctx.identity.public_key_bytes();
    let learned = raven_core::learned_routes::learned_custody_all(data_dir, wall);
    let told = learned.get(peer)?;
    if told.tags.is_empty() && told.plain.is_empty() {
        return None;
    }
    let book = raven_core::outbox::pinned_unblocked_contacts(data_dir).ok()?;
    if !book.contains(peer) {
        return None;
    }
    let consent = raven_core::node_policy::try_load_policy(data_dir)
        .ok()?
        .custody_use;
    let set = raven_core::custody_client::deposit_custodians(data_dir, &local, peer, wall);
    if set.iter().any(|(_, offer)| offer.is_none()) {
        return None; // a friend listed for `peer` by hand
    }
    let matched: Vec<[u8; 32]> = book
        .iter()
        .filter(|c| *c != peer && **c != local)
        .filter(|c| {
            told.tags
                .contains(&raven_core::route_hints::custodian_tag(peer, &local, c))
                || told.plain.contains(c)
        })
        .copied()
        .collect();
    let keep = |ip| (ctx.on_link)(ip) != Some(false);
    let not_offering = |c: &[u8; 32]| match learned.get(c).and_then(|l| l.offer) {
        None => true,
        Some(flags) if flags & OFFER_WAN != 0 => false,
        // LAN only: not offering to us if only Internet or p2p routes
        // reach it now.
        Some(flags) => {
            let finds = (ctx.lan_beacon_routes)(c);
            custodian_routes(data_dir, c, Some(flags), &finds, keep).is_empty()
                && !custodian_routes(data_dir, c, None, &finds, keep).is_empty()
        }
    };
    match consent {
        Some(false) => None,
        None => (!matched.is_empty()).then_some(code::MAILBOX_OFF),
        Some(true) if matched.is_empty() => Some(code::NO_SHARED_CUSTODIAN),
        Some(true) => matched
            .iter()
            .all(not_offering)
            .then_some(code::CUSTODIAN_NOT_OFFERING),
    }
}

/// A FORWARD is planned for an object only while this much of its validity
/// is left (cutoff addendum: an object that would expire on the way does not
/// spend two friends' budgets); it keeps its other paths.
const FORWARD_MIN_REMAINING_MS: u64 = 2 * 60 * 60 * 1000;

/// Custodians for one contact's mail, each with the custody offer it
/// announced (`None`: one this node listed itself), in the order they are
/// used ([`raven_core::custody_client::deposit_custodians`]).
pub(crate) type CustodySet = Vec<([u8; 32], Option<u8>)>;

/// Carry choice's part in one attempt's custody (Phase 6a P6.16).
#[derive(Debug)]
struct CarryChoice {
    /// Why the custodians are these (the custody log's `carry=` token).
    why: Why,
    /// Every candidate they were picked from: an object's holders among
    /// them count against [`CARRY_CAP`] (spray-and-wait: no copy beyond
    /// today's), a holder no longer among them (unpinned, blocked, no
    /// longer announced) does not.
    candidates: Vec<[u8; 32]>,
}

/// The custodians the worker leaves `peer`'s mail with (§7.3 step 3), each
/// with its custody offer: today's
/// ([`raven_core::custody_client::deposit_custodians`]), or, while carry
/// choice is live (Phase 6a P6.16, [`crate::learning::carry_live`]), the at
/// most [`CARRY_CAP`] it picks from every candidate, in its order, with
/// what it picked from ([`CarryChoice`]). Their order is the order of the
/// custody plan, the letters and the dials.
fn custodians_for(
    data_dir: &Path,
    local: &[u8; 32],
    peer: &[u8; 32],
    wall: u64,
) -> (CustodySet, Option<CarryChoice>) {
    if crate::learning::carry_live() {
        let cands = raven_core::custody_client::custodian_candidates(data_dir, local, peer, wall);
        if let Some((pick, why)) = crate::learning::carry_pick(peer, &cands) {
            let candidates = cands.iter().map(|(c, _)| *c).collect();
            return (pick, Some(CarryChoice { why, candidates }));
        }
    }
    (
        raven_core::custody_client::deposit_custodians(data_dir, local, peer, wall),
        None,
    )
}

/// The custody plan for `peer` over its custodians `custodians`
/// ([`raven_core::custody_client::deposit_custodians`]; handoff spec §3.5,
/// [`raven_core::custody_client::custody_plan`]): DEPOSIT at a custodian the
/// contact announced (or at every one without a fresh announcement),
/// HANDOFF/FORWARD at another one towards a custodian the contact announced
/// with `HANDOFF_INBOX`, while the handoff gate is live. A plain park of the
/// pair (RECIPIENT_NOT_ACCEPTED) blocks DEPOSITs only; handoff parks, a
/// plain park of the whole custodian and the capability cache's "no handoff
/// ops there" block FORWARDs. With the gate closed this is Phase 3's plan:
/// every custodian not parked for the pair, DEPOSIT.
fn custody_steps(
    ctx: &AttemptCtx,
    peer: &[u8; 32],
    custodians: &[([u8; 32], Option<u8>)],
    wall: u64,
) -> Vec<raven_core::custody_client::PlanStep> {
    use raven_core::custody_client::{announced_custodians, custody_plan};
    let local = ctx.identity.public_key_bytes();
    let listed: Vec<[u8; 32]> = custodians.iter().map(|(c, _)| *c).collect();
    let live = raven_core::custody_gate::handoff_live();
    let announced = if live {
        announced_custodians(ctx.data_dir.as_path(), &local, peer, wall)
    } else {
        None
    };
    let plain_parked = |c: &[u8; 32]| crate::custody::parked(c, Some(peer)).is_some();
    let handoff_parked = |c: &[u8; 32], hop: Option<&[u8; 32]>| {
        crate::custody::handoff_parked(c, hop)
            || crate::letters::handoff_supported(c, wall) == Some(false)
    };
    custody_plan(
        &listed,
        announced.as_deref(),
        live,
        peer,
        &local,
        &plain_parked,
        &handoff_parked,
    )
}

/// Friend custody, §7.3 step 3: messages whose direct path failed (or that
/// have none) and owed ACKs that could not be pushed go to the contact's
/// custodians (`custodians`: [`raven_core::custody_client::deposit_custodians`],
/// each with the custody offer it announced), exact bytes, at most 16 and
/// 512 KiB per dial ([`raven_core::custody_client::deposit_chunks`]); the
/// answers park or record. A message waits [`crate::custody::custody_after_for`]
/// first (no wait while `raven outbox hand-off` is armed).
///
/// Custody handoff (Phase 5 P5.21, handoff spec §3.5): the custodians get
/// what [`custody_steps`] plans, a DEPOSIT or a HANDOFF/FORWARD to the final
/// custodian the contact announced, mixed in the same dials
/// ([`raven_core::custody_client::custody_batch`]). A FORWARD is planned for
/// an object only while at least [`FORWARD_MIN_REMAINING_MS`] of its validity
/// is left and its envelope fits RHW1; otherwise that custodian gets the
/// plain DEPOSIT (Phase 3). A FORWARD answered STORED or DUPLICATE counts as
/// held there, like a deposit (never as delivered). NEXT_HOP_UNKNOWN parks
/// the pair for a day, HOLD / POLICY_DENIED to a FORWARD park handoff there
/// for an hour, UNSUPPORTED for a day; those parks are handoff-only.
///
/// Carry choice (Phase 6a P6.16, `carry` while live): `custodians` are its
/// pick in its order ([`custodians_for`]), so the plan, the letters and the
/// dials follow it; an object already held by [`CARRY_CAP`] of the
/// candidates gets no further copy, and the log lines end with its token
/// (`carry=cold|ranked`).
#[allow(clippy::too_many_arguments)]
fn deposit_with_custodians(
    ctx: &AttemptCtx,
    peer: &[u8; 32],
    custodians: &[([u8; 32], Option<u8>)],
    carry: Option<&CarryChoice>,
    store: &mut IndexedSessionStore,
    records: &BTreeMap<[u8; 16], ObjectRoutes>,
    candidates: &mut [Candidate],
    owed: &[&([u8; 32], UnsentAck)],
    acks_sent: &HashSet<[u8; 32]>,
    wall: u64,
    owed_held: &mut Vec<([u8; 32], [u8; 32])>,
) -> HashMap<[u8; 16], (Outcome, bool)> {
    use raven_core::custody_client::{
        custodian_routes, custody_batch, deposit_chunks, CustodyItem, ItemAnswer, PlanStep,
        CUSTODY_MIN_REMAINING_MS,
    };
    use raven_core::custody_handoff::MAX_RHW1_ENVELOPE;
    use raven_core::friend_custody::{rfc1_rso1, CustodyCode, MAX_RFC1_ENVELOPE};
    let data_dir = ctx.data_dir.as_path();
    let steps = custody_steps(ctx, peer, custodians, wall);
    if steps.is_empty() {
        return HashMap::new();
    }
    // Letters (Phase 5b) go where a plain deposit may, as before handoff.
    let plain: Vec<([u8; 32], Option<u8>)> = custodians
        .iter()
        .filter(|(c, _)| crate::custody::parked(c, Some(peer)).is_none())
        .copied()
        .collect();
    struct Obj {
        cand: Option<usize>,
        ack: Option<[u8; 32]>,
        rso1: Vec<u8>,
        held: Vec<[u8; 32]>,
        /// Whether a FORWARD may carry it: validity and size (§3.5).
        forwardable: bool,
    }
    let forwardable = |bytes: &[u8], expires_at: u64| {
        bytes.len() <= MAX_RHW1_ENVELOPE
            && expires_at.saturating_sub(wall) >= FORWARD_MIN_REMAINING_MS
    };
    let hex32 = |h: &String| -> Option<[u8; 32]> {
        let mut out = [0u8; 32];
        hex::decode_to_slice(h, &mut out).ok().map(|_| out)
    };
    let after = crate::custody::custody_after_for(peer);
    // Only what the direct path could not carry in this attempt (a frame cap
    // deferral is not a failure), that friend custody may carry, waiting
    // long enough.
    let custody_may = |c: &Candidate| -> bool {
        if c.kind != EndpointOutboundKind::Message
            || c.sent.is_some()
            || (c.deferred && c.last_try.is_none() && c.held_why.is_none())
            || !records.get(&c.message_id).is_some_and(|r| r.custody)
        {
            return false;
        }
        Envelope::unpack(&c.bytes).is_some_and(|env| {
            wall.saturating_sub(env.created_at) >= after
                && env.expires_at.saturating_sub(wall) >= CUSTODY_MIN_REMAINING_MS
        })
    };
    // Sealed letters (Phase 5b) first, with the custodians that serve them:
    // what moved into a letter session is not left as it was.
    let direct: Vec<raven_core::horizon::letters::DirectCopy> = candidates
        .iter()
        .filter(|c| custody_may(c))
        .map(|c| raven_core::horizon::letters::DirectCopy {
            message_id: c.message_id,
            session_id: c.session_id,
        })
        .collect();
    let letters = if plain.is_empty() {
        crate::letters::LetterBranch::default()
    } else {
        crate::letters::letter_branch(ctx, store, peer, &plain, &direct, owed, wall)
    };
    let mut objects: Vec<Obj> = Vec::new();
    for (i, c) in candidates.iter().enumerate() {
        if !custody_may(c) || letters.moved.contains_key(&c.message_id) {
            continue;
        }
        let Some(record) = records.get(&c.message_id) else {
            continue;
        };
        if c.bytes.len() > MAX_RFC1_ENVELOPE {
            continue;
        }
        let Ok(tag) = store.outbound_store_tag_for_object(&c.key, &c.bytes, wall) else {
            continue;
        };
        let Ok(rso1) = rfc1_rso1(tag, &c.bytes) else {
            continue;
        };
        objects.push(Obj {
            cand: Some(i),
            ack: None,
            rso1,
            held: record.custodians_held.iter().filter_map(hex32).collect(),
            forwardable: forwardable(&c.bytes, c.expires_at_ms),
        });
    }
    for entry in owed {
        let (digest, ack) = (&entry.0, &entry.1);
        if acks_sent.contains(digest)
            || !ack.may_deposit
            || ack.expires_at_ms.saturating_sub(wall) < CUSTODY_MIN_REMAINING_MS
            || crate::letters::rides_reply(store, ack)
        {
            continue;
        }
        let sid = ack
            .session_id
            .or_else(|| store.outbound_session_for_object(digest).ok().flatten());
        let Some(key) = sid.and_then(|s| store.record_key_for_session_id(&s).ok().flatten()) else {
            continue;
        };
        let Ok(tag) = store.outbound_store_tag_for_object(&key, &ack.bytes, wall) else {
            continue;
        };
        let Ok(rso1) = rfc1_rso1(tag, &ack.bytes) else {
            continue;
        };
        objects.push(Obj {
            cand: None,
            ack: Some(*digest),
            rso1,
            held: ack.held_by.clone(),
            forwardable: forwardable(&ack.bytes, ack.expires_at_ms),
        });
    }
    if objects.is_empty() {
        return letters.moved;
    }
    let offer_of = |c: &[u8; 32]| {
        custodians
            .iter()
            .find(|(k, _)| k == c)
            .and_then(|(_, offer)| *offer)
    };
    for step in steps {
        let (custodian, next_hop) = match step {
            PlanStep::Deposit(c) => (c, None),
            PlanStep::Forward { via, next_hop } => (via, Some(next_hop)),
        };
        let offer = offer_of(&custodian);
        // Per object: a FORWARD when the plan says so and the object may
        // take one; else a DEPOSIT (Phase 3), unless the pair is parked.
        // While carry choice is live, never a copy beyond its cap.
        let plain_ok = crate::custody::parked(&custodian, Some(peer)).is_none();
        let room = |held: &[[u8; 32]]| {
            carry.is_none_or(|c| {
                held.iter().filter(|h| c.candidates.contains(h)).count() < CARRY_CAP
            })
        };
        let todo: Vec<(usize, Option<[u8; 32]>)> = (0..objects.len())
            .filter(|&j| !objects[j].held.contains(&custodian) && room(&objects[j].held))
            .filter_map(|j| match next_hop {
                Some(hop) if objects[j].forwardable => Some((j, Some(hop))),
                _ if plain_ok => Some((j, None)),
                _ => None,
            })
            .collect();
        if todo.is_empty() {
            continue;
        }
        // The resolver's on-link filter, as for the contact itself, and
        // where the LAN beacon found the custodian just now (they lead).
        let finds = (ctx.lan_beacon_routes)(&custodian);
        let mut routes = custodian_routes(data_dir, &custodian, offer, &finds, |ip| {
            (ctx.on_link)(ip) != Some(false)
        });
        // Phase 5: over a nearby pipe too (last), under the custody gates.
        routes.extend(crate::nearby::custodian_route(&custodian));
        if routes.is_empty() {
            continue;
        }
        let expected = hex::encode(custodian);
        let mut stored_any = false;
        let sizes: Vec<usize> = todo.iter().map(|&(j, _)| objects[j].rso1.len()).collect();
        for range in deposit_chunks(&sizes) {
            let chunk = &todo[range];
            let items: Vec<CustodyItem> = chunk
                .iter()
                .map(|&(j, hop)| match hop {
                    Some(next_hop) => CustodyItem::Forward {
                        next_hop,
                        rso1: objects[j].rso1.clone(),
                    },
                    None => CustodyItem::Deposit {
                        recipient: *peer,
                        rso1: objects[j].rso1.clone(),
                    },
                })
                .collect();
            let forwards_only = chunk.iter().all(|(_, hop)| hop.is_some());
            let mut linked: Option<(OutboxCarrier, Option<DeliveryPath>)> = None;
            let mut dial = |frames: &[Vec<u8>]| {
                let mut last = Err("no custodian route".to_string());
                for (planned, route) in &routes {
                    last = ctx
                        .dialer
                        .dial_path(data_dir, route, &expected, frames)
                        .map(|(replies, path)| {
                            linked = Some((route.carrier, path));
                            replies
                        });
                    match &last {
                        Ok(_) => break,
                        // A find that does not lead to the custodian is
                        // one no longer (§7, review A-5).
                        Err(e) if custody_find_failed(&finds, planned, e) => {
                            (ctx.lan_beacon_failed)(&custodian, &planned.dial);
                        }
                        Err(_) => {}
                    }
                }
                last
            };
            let answered = crate::letters::with_handoff_caps(&custodian, |caps| {
                custody_batch(&custodian, &items, caps, wall, &mut dial)
            });
            if let Some((_, Some(path))) = linked {
                crate::custody::note_path(&custodian, path);
            }
            match answered {
                Ok(answers) => {
                    let held = |forward: bool| {
                        answers
                            .iter()
                            .zip(chunk)
                            .filter(|(a, (_, hop))| {
                                hop.is_some() == forward && a.is_some_and(ItemAnswer::held)
                            })
                            .count()
                    };
                    let (deposited, forwarded) = (held(false), held(true));
                    // Counts only, the carrier and the path (and, while
                    // carry choice is live, its fixed reason token).
                    let (carrier, path) = linked.unwrap_or((OutboxCarrier::Lan, None));
                    let how = match path {
                        Some(path) => format!("{}, {}", carrier.label(), path.label()),
                        None => carrier.label().to_string(),
                    };
                    let why = carry.map_or(String::new(), |c| format!(" {}", carry_token(c.why)));
                    if deposited > 0 {
                        eprintln!(
                            "raven-node custody: left {deposited} with a friend ({how}){why}"
                        );
                    }
                    if forwarded > 0 {
                        eprintln!(
                            "raven-node custody: left {forwarded} with a friend to pass on \
                             ({how}){why}"
                        );
                    }
                    for (k, answer) in answers.iter().enumerate() {
                        let (j, hop) = chunk[k];
                        match (*answer, hop) {
                            (Some(a), _) if a.held() => {
                                stored_any = true;
                                objects[j].held.push(custodian);
                                match (objects[j].cand, objects[j].ack) {
                                    (Some(i), _) => {
                                        candidates[i].custody_new.push(custodian);
                                        candidates[i].custody_forwarded |= hop.is_some();
                                    }
                                    (None, Some(d)) => owed_held.push((d, custodian)),
                                    _ => {}
                                }
                            }
                            (Some(ItemAnswer::Code(CustodyCode::NextHopUnknown)), Some(hop)) => {
                                crate::custody::park_handoff_pair(
                                    &custodian,
                                    &hop,
                                    crate::custody::PARK_DAY,
                                );
                            }
                            (
                                Some(ItemAnswer::Code(
                                    c @ (CustodyCode::PolicyDenied | CustodyCode::Hold),
                                )),
                                Some(_),
                            ) => crate::custody::park_handoff(
                                &custodian,
                                crate::custody::PARK_HOUR,
                                c.registry(),
                            ),
                            (Some(ItemAnswer::Unsupported), _) => crate::custody::park_handoff(
                                &custodian,
                                crate::custody::PARK_DAY,
                                "CUSTODY_HANDOFF_UNSUPPORTED",
                            ),
                            (Some(ItemAnswer::Code(c)), _) => {
                                // A FORWARD of this node's own object refused
                                // for its signer (Phase 6b S20).
                                if c == CustodyCode::HopRefused {
                                    crate::security::handoff_refused(&custodian, carrier);
                                }
                                crate::custody::park_for_code(&custodian, peer, c)
                            }
                            (None, _) => {}
                        }
                    }
                }
                Err(e) => {
                    if dial_error_code(&e) == code::PEER_REFUSED {
                        // A dial of FORWARDs alone that the custodian
                        // closed is a handoff strike (handoff spec §7).
                        if forwards_only {
                            crate::custody::strike_handoff(&custodian);
                        } else {
                            crate::custody::strike(&custodian);
                        }
                    }
                    break;
                }
            }
        }
        if stored_any {
            crate::custody::note_deposit(&custodian);
        }
    }
    letters.moved
}

/// Session reset, first thing in an attempt (gate on): when the peer has
/// Message rows in sessions it lost, run the shared reset step and map what it
/// did onto the due entries.
#[allow(clippy::too_many_arguments)]
fn run_reset_for_attempt(
    ctx: &AttemptCtx,
    peer: &[u8; 32],
    contact: &ContactRoutes,
    gates: CarrierGates,
    due: &[Entry],
    store: &mut IndexedSessionStore,
    report: &mut PeerReport,
    finished: &mut Vec<[u8; 16]>,
) {
    use raven_core::session_reset::{run_reset_step, ResetEnv, ResetStep};
    let pending = store
        .retired_undelivered_messages_for_recipient(peer)
        .map(|rows| !rows.is_empty())
        .unwrap_or(false);
    let resealed_before = store
        .resealed_message_ids(peer)
        .map(|ids| !ids.is_empty())
        .unwrap_or(false);
    if !pending && !resealed_before {
        return;
    }
    let retired: HashSet<[u8; 32]> = due
        .iter()
        .filter(|e| store.session_is_retired(&e.session_id).unwrap_or(false))
        .map(|e| e.session_id)
        .collect();
    let wall = now_ms();
    // The contact's routes, then the routes the retired messages were sent on
    // (a learned or recorded address the query may just have used).
    let mut routes: Vec<OutboxRoute> = plan_object_routes(None, contact, gates).routes;
    let records = object_route_records(&ctx.data_dir, wall).unwrap_or_default();
    for e in due.iter().filter(|e| retired.contains(&e.session_id)) {
        if let Some(record) = records.get(&e.message_id) {
            for r in plan_object_routes(Some(record), contact, gates).routes {
                if !routes.contains(&r) {
                    routes.push(r);
                }
            }
        }
    }
    routes.retain(|r| r.carrier.confidential_to_endpoint());
    let env = ResetEnv {
        data_dir: &ctx.data_dir,
        identity: &ctx.identity,
        peer: *peer,
        routes: &routes,
        user_confirmed: false,
        now_ms: wall,
    };
    let step = {
        let mut io = WorkerIo::new(ctx, peer, store);
        run_reset_step(&env, &mut io)
    };
    let in_retired =
        |e: &Entry| e.kind == EndpointOutboundKind::Message && retired.contains(&e.session_id);
    match step {
        Ok(ResetStep::Nothing) => {}
        Ok(ResetStep::Resealed(r)) => {
            eprintln!(
                "raven-node outbox: contact reset: retired={} resealed={} held=0 expired={}",
                retired.len(),
                r.resealed.len(),
                r.expired.len()
            );
            for e in due {
                let outcome = if r.resealed.iter().any(|x| x.old_digest == e.object_digest) {
                    Some(Outcome::Resealed)
                } else if !in_retired(e) {
                    None
                } else if r.delivered.contains(&e.message_id) {
                    Some(Outcome::Delivered { carrier: None })
                } else if r.expired.contains(&e.message_id) {
                    Some(Outcome::Expired)
                } else if r.parked.contains(&e.message_id) {
                    Some(Outcome::Parked)
                } else if r.capped.contains(&e.message_id) {
                    Some(Outcome::Failed(code::RESEAL_CAP))
                } else if r.no_body.contains(&e.message_id) {
                    Some(Outcome::Failed(code::PEER_RESET_NO_BODY))
                } else if r.revoked.contains(&e.message_id) {
                    Some(Outcome::Failed(code::PEER_REVOKED))
                } else {
                    None
                };
                if let Some(outcome) = outcome {
                    if matches!(
                        outcome,
                        Outcome::Delivered { .. } | Outcome::Expired | Outcome::Failed(_)
                    ) {
                        finished.push(e.message_id);
                    }
                    report.outcomes.insert(e.object_digest, outcome);
                }
            }
        }
        Ok(ResetStep::Held { code: why, .. }) => {
            for e in due.iter().filter(|e| in_retired(e)) {
                report.outcomes.insert(e.object_digest, Outcome::Held(why));
            }
        }
        Ok(ResetStep::Unreachable(detail)) => {
            let why = dial_error_code(&detail);
            for e in due.iter().filter(|e| in_retired(e)) {
                report.outcomes.insert(
                    e.object_digest,
                    Outcome::Unreachable {
                        carrier: None,
                        code: why,
                    },
                );
            }
        }
        Err(e) => {
            let why = if send_lock_busy(&e) {
                code::SEND_IN_PROGRESS
            } else {
                code::STORE
            };
            for e in due.iter().filter(|e| in_retired(e)) {
                report.outcomes.insert(e.object_digest, Outcome::Held(why));
            }
        }
    }
}

/// The horizon step for one attempt (Phase 5a, [`raven_core::horizon`]), when
/// `peer` has parked messages: with a plan, [`run_horizon_step`] over the
/// contact's renewal routes (the store under the peer's send lock per call,
/// never across a dial); without one (not a contact, blocked, an unreadable
/// book), only what needs no send ([`settle_parked`]). Messages that left for
/// good are `finished` (their route records go); a probe entry in `due` gets
/// the step's outcome: `Repaired` once anything was sealed again (the new
/// copies are scanned at once, due now), `Gone` with nothing left parked,
/// else `Parked`, or `Unreachable` when no route answered. Logs counts only.
///
/// [`run_horizon_step`]: raven_core::horizon::run_horizon_step
/// [`settle_parked`]: raven_core::horizon::settle_parked
fn run_horizon_for_attempt(
    ctx: &AttemptCtx,
    peer: &[u8; 32],
    plan: Option<&PeerPlan>,
    due: &[Entry],
    store: &mut IndexedSessionStore,
    report: &mut PeerReport,
    finished: &mut Vec<[u8; 16]>,
) {
    use raven_core::horizon::{
        run_horizon_step, settle_parked, HorizonEnv, HorizonReport, HorizonStep,
    };
    if !store
        .parked_for_recipient(peer)
        .is_ok_and(|rows| !rows.is_empty())
    {
        return;
    }
    let wall = now_ms();
    let mut done = HorizonReport::default();
    let step = match plan {
        Some(plan) => {
            let routes = plan.renewal_routes(peer);
            let env = HorizonEnv {
                data_dir: &ctx.data_dir,
                identity: &ctx.identity,
                peer: *peer,
                routes: &routes,
                pinned: plan.contact.pinned,
                now_ms: wall,
            };
            let mut io = WorkerIo::new(ctx, peer, store);
            run_horizon_step(&env, &mut io).map(|(step, r)| {
                done = r;
                Some(step)
            })
        }
        None => PeerSendLock::acquire_within(&ctx.data_dir, peer, LOCK_WAIT)
            .and_then(|_lock| {
                settle_parked(&ctx.data_dir, &ctx.identity, store, peer, wall, &mut done)
            })
            .map(|()| None),
    };
    if !done.is_empty() {
        eprintln!(
            "raven-node outbox: horizon: parked={} resealed={} expired={}",
            done.parked,
            done.resealed.len(),
            done.expired.len()
        );
    }
    finished.extend(done.finished());
    report.rescan |= !done.resealed.is_empty();
    report.horizon_expired.extend(done.expired.iter().copied());
    let outcome = match &step {
        Err(e) if send_lock_busy(e) => Outcome::Held(code::SEND_IN_PROGRESS),
        Err(_) => Outcome::Held(code::STORE),
        // Settled only: the probe branch below decides.
        Ok(None) => return,
        Ok(Some(_)) if !done.resealed.is_empty() => Outcome::Repaired,
        Ok(Some(_)) if done.parked == 0 => Outcome::Gone,
        Ok(Some(HorizonStep::Unreachable(detail))) => Outcome::Unreachable {
            carrier: None,
            code: dial_error_code(detail),
        },
        Ok(Some(_)) => Outcome::Parked,
    };
    for e in due.iter().filter(|e| e.is_probe()) {
        report.outcomes.insert(e.object_digest, outcome.clone());
    }
}

/// One SESSION_QUERY per session whose Message the peer refused in this
/// attempt (the first such Message), alone in its own dial on the refusing
/// route, when that session's backoff allows. `(session, queried, replies)`.
fn query_refused_sessions(
    ctx: &AttemptCtx,
    peer: &[u8; 32],
    candidates: &[Candidate],
) -> Vec<SessionQuery> {
    let mut out: Vec<SessionQuery> = Vec::new();
    let now = Instant::now();
    for c in candidates {
        let Some(route) = &c.refused_on else {
            continue;
        };
        if c.kind != EndpointOutboundKind::Message
            || c.sent.is_some()
            || out.iter().any(|(sid, _, _)| *sid == c.session_id)
        {
            continue;
        }
        let key = (*peer, c.session_id);
        {
            let Ok(mut backoff) = ctx.reset_backoff.lock() else {
                continue;
            };
            let (next, unanswered) = backoff.get(&key).copied().unwrap_or((now, 0));
            if now < next {
                continue;
            }
            backoff.insert(
                key,
                (
                    now + reset_query_wait(unanswered + 1),
                    unanswered.saturating_add(1),
                ),
            );
            if backoff.len() > MAX_TRACKED {
                backoff.retain(|_, (next, _)| *next > now);
            }
        }
        let Ok(frame) =
            raven_core::session_reset::session_query_frame(&ctx.identity, peer, &c.bytes, now_ms())
        else {
            continue;
        };
        let replies = ctx
            .dialer
            .dial(&ctx.data_dir, route, &hex::encode(peer), &[frame])
            .unwrap_or_default();
        out.push((c.session_id, c.bytes.clone(), replies));
    }
    out
}

/// The decisions that need no network, under the lock: already delivered,
/// not ours to send, expired. `None`: it needs a dial.
#[allow(clippy::too_many_arguments)]
fn settle_locally(
    data_dir: &Path,
    store: &mut IndexedSessionStore,
    keys: &HashMap<[u8; 32], Option<IndexedSessionRecordKey>>,
    bodies: &mut LocalBodies,
    peer: &[u8; 32],
    entry: &Entry,
    row: &EndpointOutbound,
    wall: u64,
) -> Option<Outcome> {
    let expired = entry.expires_at_ms <= wall;
    if row.kind == EndpointOutboundKind::Ack {
        // A prepared ACK past its validity is retired by the store itself.
        return expired.then_some(Outcome::Expired);
    }
    // An ACK that came back another way (pushed by the receiver, F8) already
    // delivered it: record that and never dial it again.
    match outbound_already_delivered(store, &row.session_id, &row.message_id, peer) {
        Ok(true) => {
            return Some(
                match record_outbound_delivered(
                    data_dir,
                    store,
                    peer,
                    &row.session_id,
                    &row.message_id,
                ) {
                    Ok(()) => Outcome::Delivered { carrier: None },
                    Err(_) => Outcome::Held(code::HISTORY),
                },
            );
        }
        Ok(false) => {}
        Err(_) => return Some(Outcome::Held(code::STORE)),
    }
    let Some(key) = keys.get(&row.session_id).cloned().flatten() else {
        return Some(Outcome::Gone);
    };
    // Not staged by `raven send` (sealed by `SealUnderSession` for another
    // path): no body to record a delivery against, so never dialled and never
    // abandoned here; its session's prune removes it.
    if !bodies.has(data_dir, peer, &row.message_id) {
        return Some(Outcome::Held(code::NO_LOCAL_BODY));
    }
    if expired {
        // Parked instead before its deadline (the long message horizon);
        // with its gate off, given up exactly as before.
        return Some(expired_outcome(park_or_give_up_expired(
            data_dir,
            store,
            &key,
            peer,
            &row.session_id,
            &row.object_digest,
            &row.message_id,
            entry.never_sent,
            wall,
        )));
    }
    None
}

/// The outcome of [`park_or_give_up_expired`].
fn expired_outcome(result: Result<ExpiredMessage, String>) -> Outcome {
    match result {
        Ok(ExpiredMessage::GaveUp(GiveUp::Abandoned)) => Outcome::Expired,
        Ok(ExpiredMessage::GaveUp(GiveUp::Delivered)) => Outcome::Delivered { carrier: None },
        Ok(ExpiredMessage::Parked { .. }) => Outcome::Parked,
        Err(_) => Outcome::Held(code::STORE),
    }
}

/// The exact bytes of one object, validated by the store (session, signer,
/// time window) without handing anything off: the callback refuses, so the
/// store changes nothing.
enum Captured {
    Bytes {
        bytes: Vec<u8>,
        pending: bool,
    },
    /// The store says nothing is left to send (an ACK delivered it).
    Delivered,
    Gone,
    /// `EndpointNotCurrentlyValid`: expired, or the clock moved.
    NotValid,
    Failed,
}

fn capture(
    store: &mut IndexedSessionStore,
    key: &IndexedSessionRecordKey,
    row: &EndpointOutbound,
    local_device: &AuthorizedEndpointDevice<'_>,
    wall: u64,
) -> Captured {
    let taken = RefCell::new(None::<Vec<u8>>);
    let mut grab = |d: &[u8; 32], bytes: &[u8]| {
        if *d == row.object_digest {
            *taken.borrow_mut() = Some(bytes.to_vec());
        }
        Err(())
    };
    let pending = row.state == EndpointOutboxState::Prepared;
    let result = if pending {
        store.retry_endpoint_outbound(key, &row.object_digest, local_device, wall, &mut grab)
    } else {
        store.resend_queued_endpoint_outbound(
            key,
            &row.object_digest,
            local_device,
            wall,
            &mut grab,
        )
    };
    match result {
        Err(IndexedSessionStoreError::OutboundQueueHandoff) => match taken.into_inner() {
            Some(bytes) => Captured::Bytes { bytes, pending },
            None => Captured::Failed,
        },
        // A resend the store skipped: the outstanding row is no longer `Sent`.
        Ok(_) if !pending => Captured::Delivered,
        // A prepared row that is already queued (handed off meanwhile).
        Ok(_) => {
            let again = RefCell::new(None::<Vec<u8>>);
            match store.resend_queued_endpoint_outbound(
                key,
                &row.object_digest,
                local_device,
                wall,
                &mut |d: &[u8; 32], bytes: &[u8]| {
                    if *d == row.object_digest {
                        *again.borrow_mut() = Some(bytes.to_vec());
                    }
                    Err(())
                },
            ) {
                Err(IndexedSessionStoreError::OutboundQueueHandoff) => match again.into_inner() {
                    Some(bytes) => Captured::Bytes {
                        bytes,
                        pending: false,
                    },
                    None => Captured::Failed,
                },
                Ok(_) => Captured::Delivered,
                Err(IndexedSessionStoreError::EndpointNotCurrentlyValid) => Captured::NotValid,
                Err(
                    IndexedSessionStoreError::NotFound | IndexedSessionStoreError::BindingConflict,
                ) => Captured::Gone,
                Err(_) => Captured::Failed,
            }
        }
        Err(IndexedSessionStoreError::EndpointNotCurrentlyValid) => Captured::NotValid,
        Err(IndexedSessionStoreError::NotFound | IndexedSessionStoreError::BindingConflict) => {
            Captured::Gone
        }
        Err(_) => Captured::Failed,
    }
}

/// An object the store no longer holds: delivered (an ACK reached us some
/// other way: the history is repaired too), or given up elsewhere. A message
/// pruned with its expired session still has its staged body: record it as
/// expired, which nobody else would. One the prune already settled as
/// expired (review C-time-deadlines-2) is reported as expired too. With the
/// long message horizon live, a message that ran out before its deadline is
/// parked instead (from its gone session), and one parked already (by the
/// prune, or another attempt) is reported parked.
fn finalize_vanished(
    data_dir: &Path,
    store: &mut IndexedSessionStore,
    peer: &[u8; 32],
    gone: &Entry,
    wall: u64,
) -> Outcome {
    match store.outstanding_delivery_state(&gone.session_id, &gone.message_id, peer) {
        Ok(Some(EndpointDeliveryState::Delivered | EndpointDeliveryState::Read)) => {
            let _ = raven_core::outbox::record_inbound_ack_delivery(
                data_dir,
                peer,
                &gone.session_id,
                &gone.message_id,
            );
            return Outcome::Delivered { carrier: None };
        }
        Ok(Some(EndpointDeliveryState::Sent))
            if gone.kind == EndpointOutboundKind::Message
                && store
                    .live_copy_elsewhere(peer, &gone.message_id, &gone.session_id)
                    .unwrap_or(false) =>
        {
            // Re-sealed under a new session after the contact reset.
            return Outcome::Resealed;
        }
        Ok(Some(EndpointDeliveryState::Sent)) if is_parked(store, peer, gone) => {
            // Parked: its outstanding row stays for a late ACK.
            return Outcome::Parked;
        }
        Ok(Some(EndpointDeliveryState::Sent)) => {
            // Still outstanding but no longer listed (a scan race): look
            // again next round.
            return Outcome::Sent {
                carrier: None,
                code: gone.last_error,
            };
        }
        Ok(None) | Err(_) => {}
    }
    if gone.kind != EndpointOutboundKind::Message {
        return Outcome::Gone;
    }
    if is_parked(store, peer, gone) {
        return Outcome::Parked;
    }
    let staged = raven_core::load_staged_outbound_body(data_dir, &gone.message_id)
        .ok()
        .flatten()
        .filter(|s| {
            s.peer_pub_hex.eq_ignore_ascii_case(&hex::encode(peer))
                && s.session_id_hex
                    .eq_ignore_ascii_case(&hex::encode(gone.session_id))
        });
    if staged.is_none() {
        // An app channel object has no stage: settle its record instead.
        if raven_core::app_channel::is_app_outbound(data_dir, &gone.message_id).unwrap_or(false) {
            let (delivery, code, outcome) = if gone.expires_at_ms <= wall {
                (HISTORY_EXPIRED, "", Outcome::Expired)
            } else {
                (HISTORY_FAILED, code::STORE, Outcome::Failed(code::STORE))
            };
            let _ = raven_core::app_channel::mark_app_outbound(
                data_dir,
                &gone.message_id,
                delivery,
                code,
                wall,
            );
            return outcome;
        }
        let settled_expired = gone.expires_at_ms <= wall
            && load_history_states(data_dir)
                .get(&hex::encode(gone.message_id))
                .is_some_and(|(_, delivery)| delivery == HISTORY_EXPIRED);
        return if settled_expired {
            Outcome::Expired
        } else {
            Outcome::Gone
        };
    }
    if gone.expires_at_ms <= wall {
        // Pruned with its session before its deadline (the long message
        // horizon; with its gate off nothing is parked).
        match park_expired_message(
            data_dir,
            store,
            peer,
            &gone.message_id,
            Some(&gone.session_id),
            gone.never_sent,
            wall,
        ) {
            Ok(Some(_)) => return Outcome::Parked,
            Ok(None) => {}
            Err(_) => return Outcome::Held(code::STORE),
        }
    }
    let (delivery, outcome) = if gone.expires_at_ms <= wall {
        (HISTORY_EXPIRED, Outcome::Expired)
    } else {
        (HISTORY_FAILED, Outcome::Failed(code::STORE))
    };
    match raven_core::outbox::mark_outbound_undelivered(
        data_dir,
        peer,
        &gone.session_id,
        &gone.object_digest,
        &gone.message_id,
        delivery,
    ) {
        Ok(()) => outcome,
        Err(_) => Outcome::Gone,
    }
}

/// Is `gone` (a message) parked for `peer` (the long message horizon)? An
/// unreadable store says no.
fn is_parked(store: &IndexedSessionStore, peer: &[u8; 32], gone: &Entry) -> bool {
    gone.kind == EndpointOutboundKind::Message
        && store
            .parked_for_recipient(peer)
            .is_ok_and(|rows| rows.iter().any(|r| r.message_id == gone.message_id))
}

/// A failed or panicking pass is logged once an hour at most.
static WORKER_LOG: netutil::LogLimiter = netutil::LogLimiter::new(Duration::from_secs(3600));

/// The worker's [`AttemptCtx::on_link`]: netwatch's current networks while
/// route memory is live (lab, [`raven_core::route_memory::live`]); otherwise,
/// and where netwatch does not run, not known (every learned route is kept).
/// The custody fetcher asks it too.
pub(crate) fn learned_lan_on_link(ip: IpAddr) -> Option<bool> {
    #[cfg(any(unix, windows))]
    {
        if raven_core::route_memory::live() {
            return crate::netwatch::on_link(ip);
        }
        None
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = ip;
        None
    }
}

/// The worker's [`AttemptCtx::lan_beacon_routes`]: where the LAN beacon found
/// `peer` ([`crate::lan_beacon::candidates`]); none where raven-node runs no
/// beacon.
fn beacon_candidates(peer: &[u8; 32]) -> Vec<String> {
    #[cfg(any(unix, windows))]
    {
        crate::lan_beacon::candidates(peer)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = peer;
        Vec::new()
    }
}

/// The worker's [`AttemptCtx::lan_want`]: the LAN beacon looks for `peer`
/// for the outbox ([`crate::lan_beacon::want`]).
fn beacon_want(peer: &[u8; 32]) {
    #[cfg(any(unix, windows))]
    crate::lan_beacon::want(peer, crate::lan_beacon::Want::Outbox);
    #[cfg(not(any(unix, windows)))]
    let _ = peer;
}

/// Did the LAN beacon ask for `peer` in vain
/// ([`crate::lan_beacon::asked_in_vain`])? Never where raven-node runs no
/// beacon.
fn beacon_asked_in_vain(peer: &[u8; 32]) -> bool {
    #[cfg(any(unix, windows))]
    {
        crate::lan_beacon::asked_in_vain(peer)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = peer;
        false
    }
}

/// The worker's [`AttemptCtx::lan_beacon_failed`]
/// ([`crate::lan_beacon::dial_failed`]).
fn beacon_find_failed(peer: &[u8; 32], dial: &str) {
    #[cfg(any(unix, windows))]
    crate::lan_beacon::dial_failed(peer, dial);
    #[cfg(not(any(unix, windows)))]
    let _ = (peer, dial);
}

/// The service's outbox worker (supervised in `main`).
pub async fn run_worker(data_dir: PathBuf) -> Result<(), String> {
    let identity = Arc::new(
        netutil::retry_until_ok("outbox", || {
            let dd = data_dir.clone();
            async move {
                tokio::task::spawn_blocking(move || {
                    raven_core::load_identity_required(&dd).map_err(|e| e.to_string())
                })
                .await
                .map_err(|e| format!("outbox blocking join: {e}"))?
            }
        })
        .await,
    );
    let ctx = Arc::new(AttemptCtx {
        data_dir,
        identity,
        dialer: Arc::new(NetDialer {
            handle: tokio::runtime::Handle::current(),
        }),
        // `raven lan off` (Phase 3) holds LAN routes at once, for the app
        // channel too (it shares this context).
        lan_live: raven_core::lan_usable_now,
        internet_live: raven_core::internet_direct_live_enabled,
        p2p_live: crate::p2p::dials_possible,
        nearby_live: raven_core::nearby_live_enabled,
        nearby_available: crate::nearby::available,
        onion_live: raven_core::onion_live_enabled,
        onion_available: crate::onion::available,
        onion_head_start: crate::onion::head_start,
        net_tag: raven_core::route_memory::network_tag,
        on_link: learned_lan_on_link,
        connected: route_connected_now,
        // The LAN beacon (Phase 3): its finds lead a contact's LAN routes,
        // and an attempt in which LAN may carry something asks it to look.
        lan_beacon_routes: beacon_candidates,
        lan_want: beacon_want,
        lan_beacon_failed: beacon_find_failed,
        reset_backoff: Mutex::default(),
    });
    // The app channel's AppSubmit reuses the worker's identity, dialer and
    // gates (design §8.6): this worker's, until it ends (a lock, Lock v2).
    *worker_ctx() = Some(Arc::clone(&ctx));
    // Groups: a receive that leaves work asks for a scan at once.
    raven_core::group::set_work_notifier(group_work);
    // App channel at start (§7.3, §8.6), best effort: committed app rows
    // reach the app inbox, and records the store no longer knows settle.
    let dd = ctx.data_dir.clone();
    let _ = tokio::task::spawn_blocking(move || {
        let now = now_ms();
        let _ = raven_core::app_channel::ingest_pending_committed(&dd, now);
        if let Ok(store) = IndexedSessionStore::open(&dd) {
            let _ = raven_core::app_channel::reconcile_app_outbound(&dd, &store, now);
        }
    })
    .await;
    run_loop(ctx).await
}

static WORKER_CTX: Mutex<Option<Arc<AttemptCtx>>> = Mutex::new(None);

/// The running worker's attempt context; `None` without a worker.
pub(crate) fn attempt_ctx() -> Option<Arc<AttemptCtx>> {
    if !is_running() {
        return None;
    }
    worker_ctx().clone()
}

fn worker_ctx() -> MutexGuard<'static, Option<Arc<AttemptCtx>>> {
    WORKER_CTX
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Set by an unlock (Lock v2, P6.40): the next worker makes everything it
/// holds due at once.
static AFTER_UNLOCK: AtomicBool = AtomicBool::new(false);

/// Lock v2: raven-node was unlocked. What waited while it was locked is due
/// as soon as the worker runs again.
pub(crate) fn after_unlock() {
    AFTER_UNLOCK.store(true, AtomicOrdering::SeqCst);
    let _ = kick(None, false, false);
}

struct RunningGuard;

impl Drop for RunningGuard {
    fn drop(&mut self) {
        let mut inner = lock(&outbox().inner);
        inner.running = false;
        inner.in_flight.clear();
        inner.net_changed.clear();
        inner.clear_pins_after.clear();
        drop(inner);
        // Its identity goes with it (a lock, Lock v2).
        *worker_ctx() = None;
    }
}

async fn run_loop(ctx: Arc<AttemptCtx>) -> Result<(), String> {
    let ob = outbox();
    {
        let mut inner = lock(&ob.inner);
        inner.running = true;
        inner.refresh = true;
        inner.sibling_wake = sibling_wake_live();
        if AFTER_UNLOCK.swap(false, AtomicOrdering::SeqCst) {
            inner.kick_restart(None, false, false, Instant::now());
        }
    }
    let _running = RunningGuard;
    eprintln!("raven-node outbox: running");
    let mut last_scan = Instant::now();
    loop {
        let (refresh, idle_refresh, scan_seq) = {
            let mut inner = lock(&ob.inner);
            inner.fire_custody_kick(Instant::now());
            (
                std::mem::take(&mut inner.refresh),
                inner.idle_refresh(),
                inner.scan_seq(),
            )
        };
        if refresh || last_scan.elapsed() >= idle_refresh {
            last_scan = Instant::now();
            let dd = ctx.data_dir.clone();
            let identity = Arc::clone(&ctx.identity);
            match tokio::task::spawn_blocking(move || {
                // Groups first: the copies they park are in this scan.
                if raven_core::group::group_live_enabled() {
                    let _ = raven_core::group::run_pending(&dd, &identity, now_ms());
                }
                let owed = raven_core::owed_acks::OwedAcks::open_existing(&dd)
                    .ok()
                    .flatten()
                    .and_then(|mut o| o.list(now_ms()).ok())
                    .unwrap_or_default();
                // A full disk shows up here as "unable to open database file":
                // say so (measured here, off the runtime).
                scan_store(&dd)
                    .map(|rows| (rows, owed))
                    .map_err(|e| raven_core::disk_space::with_disk_full_note(&dd, e))
            })
            .await
            {
                Ok(Ok((rows, owed))) => {
                    let mut inner = lock(&ob.inner);
                    inner.merge(rows, scan_seq, Instant::now(), now_ms());
                    inner.merge_owed(owed, Instant::now());
                }
                Ok(Err(e)) => netutil::log_limited(&WORKER_LOG, "outbox scan failed", e),
                Err(e) => netutil::log_limited(&WORKER_LOG, "outbox scan failed", e),
            }
        }
        let due = lock(&ob.inner).take_due(Instant::now());
        for work in due {
            let ctx = Arc::clone(&ctx);
            tokio::spawn(async move {
                let peer = work.peer;
                let attempted: Vec<[u8; 32]> =
                    work.entries.iter().map(|e| e.object_digest).collect();
                let report = tokio::task::spawn_blocking(move || {
                    attempt_peer(&ctx, &work.peer, &work.entries, &work.acks)
                })
                .await
                .unwrap_or_else(|e| {
                    netutil::log_limited(&WORKER_LOG, "outbox attempt failed", e);
                    PeerReport {
                        attempted,
                        held: Some(code::STORE),
                        ..PeerReport::default()
                    }
                });
                let delivered = report.delivered_lines(&peer);
                let ob = outbox();
                let woke = lock(&ob.inner).apply(&peer, report, Instant::now(), now_ms());
                for line in delivered {
                    eprintln!("{line}");
                }
                log_sibling_wake(woke);
                ob.wake.notify_one();
            });
        }
        let wait = {
            let inner = lock(&ob.inner);
            // A merge that left a new object of a busy peer behind asked for
            // another scan: go round again instead of sleeping on it.
            let idle = if inner.refresh {
                Duration::ZERO
            } else {
                inner.idle_refresh().saturating_sub(last_scan.elapsed())
            };
            inner
                .next_due_in(Instant::now())
                .map(|d| d.min(idle))
                .unwrap_or(idle)
        };
        tokio::select! {
            _ = tokio::time::sleep(wait.max(Duration::from_millis(50))) => {}
            _ = ob.wake.notified() => {}
        }
    }
}

/// The worker's test rig, shared with the app channel's and the route-hints
/// announcer's tests (`use crate::outbox::test_rig as rig`, qualified: a glob
/// would clash with their own names): B's side of a dial in process
/// ([`FakeNet`]), a dialer that must never dial ([`NoDial`]), contact books,
/// the context's fns and the route memory.
#[cfg(test)]
pub(crate) mod test_rig {
    use super::*;
    use raven_core::lan_dispatch::{create_initiator_pair_init, dispatch_frame, wrap_pair_init};
    use raven_core::{classify_packed_envelope, LanBundle, PairInitOobClassify};
    use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

    /// The lab file backends; these tests never reach an OS keystore. Set once
    /// (a restore would race the other tests, which use the same backends).
    pub(crate) fn lab_backends() -> bool {
        static ONCE: std::sync::Once = std::sync::Once::new();
        if !cfg!(debug_assertions) {
            eprintln!("skipped: the lab locked-file backends need a debug build");
            return false;
        }
        ONCE.call_once(|| {
            for key in [
                "RAVEN_SESSION_BACKEND",
                "RAVEN_PREKEY_BACKEND",
                "RAVEN_CHAT_HISTORY_BACKEND",
                "RAVEN_IDENTITY_BACKEND",
            ] {
                // Edition 2021: a plain call. Set before any store opens.
                std::env::set_var(key, "locked-file");
            }
        });
        true
    }

    pub(crate) const UP: u8 = 0;
    pub(crate) const DOWN: u8 = 1;
    pub(crate) const REFUSE: u8 = 2;
    pub(crate) const WRONG_ID: u8 = 3;
    pub(crate) const NOT_ACCEPTED: u8 = 4;
    /// Like the real listener: frames in order, the link closes at the first
    /// refused one; a close with nothing beyond the offer is PEER_CLOSED.
    pub(crate) const STRICT: u8 = 5;
    /// The link comes up and takes the frames, then nothing comes back
    /// within the first reply wait (ReplyCollector::first, Idle): only the
    /// offer. Bob never sees them.
    pub(crate) const SILENT: u8 = 6;
    /// Bob takes and commits the frames; his ACK is lost on the way back.
    pub(crate) const ACK_LOST: u8 = 7;
    /// Another key answered at Bob's address before our Noise message 3
    /// (M0, a noise pin mismatch).
    pub(crate) const PIN_MISMATCH: u8 = 8;
    /// The dial reads Alice's noise pin store first, as the real one does
    /// (M0: `lan_direct::NoisePins::load`, gate open), then goes on as `UP`.
    pub(crate) const PIN_STORE: u8 = 9;
    /// A nearby dial to a contact whose beacon is not seen now: it fails at
    /// once (Phase 5, `crate::nearby::NEARBY_NOT_IN_RANGE`).
    pub(crate) const NOT_IN_RANGE: u8 = 10;
    /// Bob takes and commits the frames; his ACK comes back with its
    /// signature broken, so Alice refuses it (`AckRejected::Refused`).
    pub(crate) const BAD_ACK: u8 = 11;

    /// B's side of a dial, in process: the frames go to B's real dispatcher.
    pub(crate) struct FakeNet {
        pub(crate) b_dir: PathBuf,
        pub(crate) bob: Identity,
        pub(crate) a_bundle: LanBundle,
        pub(crate) alice_pub: [u8; 32],
        pub(crate) mode: AtomicU8,
        /// Per dialled route, overriding `mode`.
        pub(crate) route_modes: Mutex<HashMap<OutboxRoute, u8>>,
        pub(crate) dials: AtomicUsize,
        pub(crate) internet_dials: AtomicUsize,
        /// (route dialled, frames) per dial.
        pub(crate) log: Mutex<Vec<(OutboxRoute, usize)>>,
        /// Set by a test: the A data dir whose send lock a dial checks.
        pub(crate) lock_probe: Mutex<Option<(PathBuf, [u8; 32])>>,
        pub(crate) lock_free_during_dial: AtomicBool,
        /// RSR1 frames dialled (session reset queries).
        pub(crate) rsr1_frames: AtomicUsize,
        /// With `lock_probe` set: dials made, and dials made while the send
        /// lock was held.
        pub(crate) probed_dials: AtomicUsize,
        pub(crate) dials_with_lock_held: AtomicUsize,
        /// How a dial of that route travelled ([`Dialer::dial_path`]).
        pub(crate) paths: Mutex<HashMap<OutboxRoute, DeliveryPath>>,
        /// (route dialled, the worker's facts) per dial
        /// ([`Dialer::dial_path_meta`]).
        pub(crate) metas: Mutex<Vec<(OutboxRoute, DialMeta)>>,
        /// Set by a test: the times the learning hook reports (the reply
        /// time only on a dial that brought an ACK); none by default.
        pub(crate) timing: Mutex<Option<raven_core::learning::observe::DialTiming>>,
    }

    impl Dialer for FakeNet {
        fn dial_path(
            &self,
            data_dir: &Path,
            route: &OutboxRoute,
            expected: &str,
            frames: &[Vec<u8>],
        ) -> Result<(Vec<Vec<u8>>, Option<DeliveryPath>), String> {
            self.dial_path_meta(data_dir, route, expected, frames, DialMeta::default())
        }

        fn dial_path_meta(
            &self,
            data_dir: &Path,
            route: &OutboxRoute,
            expected: &str,
            frames: &[Vec<u8>],
            meta: DialMeta,
        ) -> Result<(Vec<Vec<u8>>, Option<DeliveryPath>), String> {
            self.metas.lock().unwrap().push((route.clone(), meta));
            let path = self.paths.lock().unwrap().get(route).copied();
            let net = crate::learning::net();
            let result = self.dial(data_dir, route, expected, frames);
            let mut timing = self.timing.lock().unwrap().unwrap_or_default();
            if !result.as_ref().is_ok_and(|got| !ack_frames(got).is_empty()) {
                timing.reply_ms = None;
            }
            // The carriers' learning hook (Phase 6a), as the real LAN,
            // Internet and p2p dials make it (nearby is never ranked).
            let contact: Option<[u8; 32]> =
                hex::decode(expected).ok().and_then(|k| k.try_into().ok());
            if let (Some(contact), false) = (contact, route.carrier == OutboxCarrier::Nearby) {
                crate::learning::observe_dial(
                    &contact,
                    route.carrier,
                    path,
                    None,
                    frames,
                    &result,
                    &timing,
                    crate::learning::Expired::default(),
                    meta,
                    net,
                );
            }
            result.map(|replies| (replies, path))
        }

        fn dial(
            &self,
            data_dir: &Path,
            route: &OutboxRoute,
            expected: &str,
            frames: &[Vec<u8>],
        ) -> Result<Vec<Vec<u8>>, String> {
            self.dials.fetch_add(1, Ordering::SeqCst);
            self.log.lock().unwrap().push((route.clone(), frames.len()));
            let rsr1 = frames
                .iter()
                .filter(|f| raven_core::session_reset::is_rsr1(f))
                .count();
            self.rsr1_frames.fetch_add(rsr1, Ordering::SeqCst);
            if let Some((dir, peer)) = self.lock_probe.lock().unwrap().clone() {
                let free = PeerSendLock::acquire_within(&dir, &peer, Duration::ZERO).is_ok();
                self.lock_free_during_dial.store(free, Ordering::SeqCst);
                self.probed_dials.fetch_add(1, Ordering::SeqCst);
                if !free {
                    self.dials_with_lock_held.fetch_add(1, Ordering::SeqCst);
                }
            }
            if route.carrier == OutboxCarrier::Internet {
                self.internet_dials.fetch_add(1, Ordering::SeqCst);
            }
            let mode = self
                .route_modes
                .lock()
                .unwrap()
                .get(route)
                .copied()
                .unwrap_or_else(|| self.mode.load(Ordering::SeqCst));
            match mode {
                DOWN => {
                    return Err(
                        "lan connect: cannot connect to 127.0.0.1:9 (Connection refused)".into(),
                    )
                }
                REFUSE => {
                    return Err(
                        "LAN_DIAL_PEER_CLOSED: the peer closed the connection without \
                                replying; the frames were sent"
                            .into(),
                    )
                }
                WRONG_ID => return Err("rlb1 offer identity mismatch".into()),
                NOT_ACCEPTED => return Err(crate::netutil::LINK_NOT_ACCEPTED.into()),
                PIN_MISMATCH => return Err(crate::lan_direct::NOISE_PIN_MISMATCH.into()),
                NOT_IN_RANGE => return Err(crate::nearby::NEARBY_NOT_IN_RANGE.into()),
                PIN_STORE => {
                    let contact: [u8; 32] = hex::decode(expected)
                        .ok()
                        .and_then(|k| k.try_into().ok())
                        .ok_or("bad expected key")?;
                    crate::lan_direct::NoisePins { live: true }.load(data_dir, &contact)?;
                }
                _ => {}
            }
            let strict = mode == STRICT;
            let mut replies = vec![raven_core::encode_local_offer(&self.b_dir, &self.bob).unwrap()];
            if mode == SILENT {
                return Ok(replies);
            }
            for f in frames {
                match dispatch_frame(&self.b_dir, &self.bob, &self.a_bundle, &self.alice_pub, f) {
                    Ok(_) if mode == ACK_LOST => {}
                    Ok(more) => replies.extend(more),
                    Err(_) if strict && replies.len() == 1 => {
                        return Err("LAN_DIAL_PEER_CLOSED: the peer closed the connection \
                                    without replying; the frames were sent"
                            .into())
                    }
                    Err(_) if strict => break,
                    Err(_) => {}
                }
            }
            if mode == BAD_ACK {
                for reply in replies.iter_mut().skip(1) {
                    if Envelope::unpack(reply).is_some_and(|e| e.env_type == EnvType::Ack as u8) {
                        if let Some(last) = reply.last_mut() {
                            *last ^= 0x01;
                        }
                    }
                }
            }
            Ok(replies)
        }
    }

    pub(crate) fn contacts(dir: &Path, peer: &[u8; 32], lan: &str, inet: &str, pinned: bool) {
        std::fs::write(
            dir.join("contacts.json"),
            format!(
                r#"[{{"petname":"Peer","public_tag":"","alias":"","address":"","pub_hex":"{}","pinned":{pinned},"lan_dial":"{lan}","internet_dial":"{inet}"}}]"#,
                hex::encode(peer)
            ),
        )
        .unwrap();
    }

    /// [`contacts`] with the LAN route typed on this computer (or learned
    /// after a delivery), not taken from a card: a verified contact's may
    /// lie beyond the local network.
    pub(crate) fn contacts_typed(dir: &Path, peer: &[u8; 32], lan: &str, inet: &str, pinned: bool) {
        std::fs::write(
            dir.join("contacts.json"),
            format!(
                r#"[{{"petname":"Peer","public_tag":"","alias":"","address":"","pub_hex":"{}","pinned":{pinned},"lan_dial":"{lan}","internet_dial":"{inet}","lan_dial_trusted":true}}]"#,
                hex::encode(peer)
            ),
        )
        .unwrap();
    }

    pub(crate) fn pair(
        a: &Path,
        alice: &Identity,
        b: &Path,
        bob: &Identity,
        a_bundle: &LanBundle,
        b_bundle: &LanBundle,
    ) -> IndexedSessionRecordKey {
        let (init, key) = create_initiator_pair_init(a, alice, b_bundle).unwrap();
        let replies = dispatch_frame(
            b,
            bob,
            a_bundle,
            &alice.public_key_bytes(),
            &wrap_pair_init(alice, &init).unwrap(),
        )
        .unwrap();
        let response = replies
            .iter()
            .find_map(|f| match classify_packed_envelope(f) {
                PairInitOobClassify::PairResponse(w) => {
                    raven_core::pair_init::decode_response(&w).ok()
                }
                _ => None,
            })
            .expect("PairResponse");
        IndexedSessionStore::open(a)
            .unwrap()
            .confirm_verified_pair_response(&key, &init, &response, now_ms())
            .unwrap();
        key
    }

    pub(crate) fn on() -> bool {
        true
    }

    pub(crate) fn off() -> bool {
        false
    }

    pub(crate) fn no_net() -> Option<String> {
        None
    }

    pub(crate) fn test_net() -> Option<String> {
        Some("test-net".into())
    }

    /// netwatch's view not known (as without the lab): every learned route
    /// is kept.
    pub(crate) fn unknown_link(_: IpAddr) -> Option<bool> {
        None
    }

    pub(crate) fn never_connected(_: &OutboxRoute) -> bool {
        false
    }

    /// No nearby engine: no contact's nearby route is planned.
    pub(crate) fn no_nearby(_: &[u8; 32]) -> bool {
        false
    }

    /// A nearby engine holding every contact's pair key.
    pub(crate) fn nearby_everyone(_: &[u8; 32]) -> bool {
        true
    }

    /// Every nearby route's pipe is up right now.
    pub(crate) fn nearby_connected(route: &OutboxRoute) -> bool {
        route.carrier == OutboxCarrier::Nearby
    }

    /// Every p2p route's contact is connected right now.
    pub(crate) fn p2p_connected(route: &OutboxRoute) -> bool {
        route.carrier == OutboxCarrier::P2p
    }

    /// No LAN beacon: nothing found for anyone.
    pub(crate) fn no_finds(_: &[u8; 32]) -> Vec<String> {
        Vec::new()
    }

    /// No LAN beacon: nobody is looked for.
    pub(crate) fn no_want(_: &[u8; 32]) {}

    /// No LAN beacon: nothing to forget.
    pub(crate) fn no_find_failed(_: &[u8; 32], _: &str) {}

    /// Bob verified, with a saved LAN address and a p2p PeerId: his p2p
    /// route.
    pub(crate) fn contacts_p2p(dir: &Path, peer: &[u8; 32], lan: &str) -> OutboxRoute {
        let peer_id = raven_core::p2p_route::local_peer_id(&Identity::from_seed(&[0x77; 32]));
        std::fs::write(
            dir.join("contacts.json"),
            format!(
                r#"[{{"petname":"Peer","public_tag":"","alias":"","address":"","pub_hex":"{}","pinned":true,"lan_dial":"{lan}","internet_dial":"","p2p":"{peer_id}"}}]"#,
                hex::encode(peer)
            ),
        )
        .unwrap();
        OutboxRoute {
            carrier: OutboxCarrier::P2p,
            dial: raven_core::p2p_route::peer_route(&peer_id),
        }
    }

    pub(crate) fn lan(d: &str) -> OutboxRoute {
        OutboxRoute {
            carrier: OutboxCarrier::Lan,
            dial: d.into(),
        }
    }

    pub(crate) fn inet(d: &str) -> OutboxRoute {
        OutboxRoute {
            carrier: OutboxCarrier::Internet,
            dial: d.into(),
        }
    }

    impl FakeNet {
        /// B (`bob`, data dir `b_dir`) for A (`alice_pub`, whose bundle is
        /// `a_bundle`): every route down, nothing counted yet.
        pub(crate) fn new(
            b_dir: PathBuf,
            bob: Identity,
            a_bundle: LanBundle,
            alice_pub: [u8; 32],
        ) -> Self {
            Self {
                b_dir,
                bob,
                a_bundle,
                alice_pub,
                mode: AtomicU8::new(DOWN),
                route_modes: Mutex::new(HashMap::new()),
                dials: AtomicUsize::new(0),
                internet_dials: AtomicUsize::new(0),
                log: Mutex::new(Vec::new()),
                lock_probe: Mutex::new(None),
                lock_free_during_dial: AtomicBool::new(false),
                rsr1_frames: AtomicUsize::new(0),
                probed_dials: AtomicUsize::new(0),
                dials_with_lock_held: AtomicUsize::new(0),
                paths: Mutex::new(HashMap::new()),
                metas: Mutex::new(Vec::new()),
                timing: Mutex::new(None),
            }
        }
    }

    /// A dialer for tests that must not dial (and need no backends): it
    /// counts the dials and fails each one.
    #[derive(Default)]
    pub(crate) struct NoDial {
        pub(crate) dials: AtomicUsize,
    }

    impl NoDial {
        pub(crate) fn dials(&self) -> usize {
            self.dials.load(Ordering::SeqCst)
        }
    }

    impl Dialer for NoDial {
        fn dial(
            &self,
            _data_dir: &Path,
            _route: &OutboxRoute,
            _expected: &str,
            _frames: &[Vec<u8>],
        ) -> Result<Vec<Vec<u8>>, String> {
            self.dials.fetch_add(1, Ordering::SeqCst);
            Err("NoDial: this test must not dial".into())
        }
    }

    /// An attempt context on `data_dir` with only LAN on: the route memory
    /// off (`no_net`), netwatch's view not known, nobody connected.
    pub(crate) fn test_ctx(
        data_dir: &Path,
        identity: Arc<Identity>,
        dialer: Arc<dyn Dialer>,
    ) -> AttemptCtx {
        AttemptCtx {
            data_dir: data_dir.to_path_buf(),
            identity,
            dialer,
            lan_live: on,
            internet_live: off,
            p2p_live: off,
            nearby_live: off,
            nearby_available: no_nearby,
            onion_live: || false,
            onion_available: || false,
            onion_head_start: crate::onion::head_start,
            net_tag: no_net,
            on_link: unknown_link,
            connected: never_connected,
            lan_beacon_routes: no_finds,
            lan_want: no_want,
            lan_beacon_failed: no_find_failed,
            reset_backoff: Mutex::default(),
        }
    }

    /// Bob verified, with a saved LAN address, an Internet address and a p2p
    /// PeerId: his p2p route.
    pub(crate) fn contacts_all(dir: &Path, peer: &[u8; 32], lan: &str, inet: &str) -> OutboxRoute {
        let peer_id = raven_core::p2p_route::local_peer_id(&Identity::from_seed(&[0x77; 32]));
        std::fs::write(
            dir.join("contacts.json"),
            format!(
                r#"[{{"petname":"Peer","public_tag":"","alias":"","address":"","pub_hex":"{}","pinned":true,"lan_dial":"{lan}","internet_dial":"{inet}","p2p":"{peer_id}"}}]"#,
                hex::encode(peer)
            ),
        )
        .unwrap();
        OutboxRoute {
            carrier: OutboxCarrier::P2p,
            dial: raven_core::p2p_route::peer_route(&peer_id),
        }
    }

    /// `route` reached `peer` on `net` right after a LAN route above it
    /// failed: the route memory holds it there.
    pub(crate) fn remember(data_dir: &Path, peer: &[u8; 32], route: &OutboxRoute, net: &str) {
        let above = lan("192.168.1.250:7420");
        let now = now_ms();
        raven_core::route_memory::learn(
            data_dir,
            peer,
            &[above.clone(), route.clone()],
            None,
            &[(above, false), (route.clone(), true)],
            Some(net),
            now,
            now,
        )
        .unwrap();
    }
}

#[cfg(test)]
mod carry_tests;

#[cfg(test)]
mod tests {
    use super::test_rig::*;
    use super::*;
    use raven_core::lan_dispatch::{cache_peer_bundle, dispatch_frame, local_bundle};
    use raven_core::outbox::record_object_routes;
    use raven_core::LanBundle;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct Rig {
        a: tempfile::TempDir,
        b: tempfile::TempDir,
        alice: Arc<Identity>,
        bob_pub: [u8; 32],
        b_bundle: LanBundle,
        net: Arc<FakeNet>,
        key: IndexedSessionRecordKey,
    }

    impl Rig {
        /// Alice and Bob, mutual contacts with a confirmed session (Alice
        /// initiated), and Bob's bundle in Alice's durable cache.
        fn new(seed: u8) -> Self {
            let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
            let alice = Identity::from_seed(&[seed; 32]);
            let bob = Identity::from_seed(&[seed.wrapping_add(1); 32]);
            for (dir, id) in [(a.path(), &alice), (b.path(), &bob)] {
                ensure_local_device_certificate(dir, id, PRIMARY_DEVICE_ID).unwrap();
                raven_core::ensure_local_prekey(dir, id).unwrap();
            }
            let (alice_pub, bob_pub) = (alice.public_key_bytes(), bob.public_key_bytes());
            contacts(a.path(), &bob_pub, "127.0.0.1:9", "", false);
            contacts(b.path(), &alice_pub, "", "", false);
            let a_bundle = local_bundle(a.path(), &alice).unwrap();
            let b_bundle = local_bundle(b.path(), &bob).unwrap();
            cache_peer_bundle(a.path(), &b_bundle).unwrap();
            let key = pair(a.path(), &alice, b.path(), &bob, &a_bundle, &b_bundle);
            let net = Arc::new(FakeNet::new(
                b.path().to_path_buf(),
                bob,
                a_bundle,
                alice_pub,
            ));
            Self {
                a,
                b,
                alice: Arc::new(alice),
                bob_pub,
                b_bundle,
                net,
                key,
            }
        }

        fn set(&self, mode: u8) {
            self.net.mode.store(mode, Ordering::SeqCst);
        }

        /// Dials of `route` behave as `mode`; every other route follows `set`.
        fn set_route(&self, route: OutboxRoute, mode: u8) {
            self.net.route_modes.lock().unwrap().insert(route, mode);
        }

        /// Dials of `route` say they travelled `path`.
        fn set_path(&self, route: OutboxRoute, path: DeliveryPath) {
            self.net.paths.lock().unwrap().insert(route, path);
        }

        /// The routes dialled so far, in order.
        fn dialled(&self) -> Vec<OutboxRoute> {
            self.net
                .log
                .lock()
                .unwrap()
                .iter()
                .map(|(route, _)| route.clone())
                .collect()
        }

        /// Bob loses his Raven state (sessions, prekeys, lifecycle, history)
        /// and starts again from the same seed; his device certificate stays
        /// unless `fresh_cert`.
        fn wipe_bob(&self, fresh_cert: bool) {
            // Prekey ids are seconds since 2020 and an install may run one
            // ahead of the clock: a real reinstall is never this fast, so wait
            // until a fresh id is above Bob's old one.
            let old_id = raven_core::PrekeyStore::load_checked(self.b.path())
                .ok()
                .and_then(|s| s.fetch_valid(&self.bob_pub, now_ms()))
                .map_or(0, |b| b.signed_prekey_id);
            while raven_core::prekey_lifecycle::time_floor_signed_prekey_id(now_ms()) <= old_id {
                std::thread::sleep(Duration::from_millis(50));
            }
            // Windows CI: antivirus or the indexer may hold a just-closed file
            // for a moment (sharing violation); elsewhere one attempt.
            fn remove_retrying(path: &Path) {
                let mut attempt = 0;
                loop {
                    let removed = if path.is_dir() {
                        std::fs::remove_dir_all(path)
                    } else {
                        std::fs::remove_file(path)
                    };
                    match removed {
                        Ok(()) => return,
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
                        Err(_) if cfg!(windows) && attempt < 50 => {
                            attempt += 1;
                            std::thread::sleep(Duration::from_millis(100));
                        }
                        Err(e) => panic!("cannot remove {}: {e}", path.display()),
                    }
                }
            }
            for entry in std::fs::read_dir(self.b.path()).unwrap() {
                let entry = entry.unwrap();
                let name = entry.file_name().to_string_lossy().into_owned();
                if name == "contacts.json" || (!fresh_cert && name.starts_with("device")) {
                    continue;
                }
                remove_retrying(&entry.path());
            }
            ensure_local_device_certificate(self.b.path(), &self.net.bob, PRIMARY_DEVICE_ID)
                .unwrap();
            raven_core::ensure_local_prekey(self.b.path(), &self.net.bob).unwrap();
        }

        fn dials(&self) -> usize {
            self.net.dials.load(Ordering::SeqCst)
        }

        /// The route memory off (`no_net`): every test's dial order is the
        /// plain plan's.
        fn ctx_with(&self, lan_live: fn() -> bool, internet_live: fn() -> bool) -> AttemptCtx {
            AttemptCtx {
                data_dir: self.a.path().to_path_buf(),
                identity: Arc::clone(&self.alice),
                dialer: self.net.clone(),
                lan_live,
                internet_live,
                p2p_live: off,
                nearby_live: off,
                nearby_available: no_nearby,
                onion_live: || false,
                onion_available: || false,
                onion_head_start: crate::onion::head_start,
                net_tag: no_net,
                on_link: unknown_link,
                connected: never_connected,
                lan_beacon_routes: no_finds,
                lan_want: no_want,
                lan_beacon_failed: no_find_failed,
                reset_backoff: Mutex::default(),
            }
        }

        /// [`Self::ctx_with`] with the route memory on, on network `test-net`.
        fn ctx_net(&self, lan_live: fn() -> bool, internet_live: fn() -> bool) -> AttemptCtx {
            AttemptCtx {
                net_tag: test_net,
                ..self.ctx_with(lan_live, internet_live)
            }
        }

        fn ctx(&self) -> AttemptCtx {
            self.ctx_with(on, off)
        }

        /// `raven send` while Bob is down: staged (history `queued`, protected
        /// body), its dial failed, so the row stays pending. Sealed at
        /// `created`, valid for `validity_ms` (capped by the session).
        fn stage_at(&self, text: &str, created: u64, validity_ms: u64) -> [u8; 16] {
            self.stage_with(text, created, validity_ms, false)
        }

        /// Staged and handed to the outbox queue (`raven send` to an unreachable
        /// peer): the row is queued, not prepared, so another one can follow.
        fn stage_queued(&self, text: &str, validity_ms: u64) -> [u8; 16] {
            self.stage_with(text, now_ms(), validity_ms, true)
        }

        fn stage_with(
            &self,
            text: &str,
            created: u64,
            validity_ms: u64,
            hand_off: bool,
        ) -> [u8; 16] {
            let (cert, registry) =
                ensure_local_device_certificate(self.a.path(), &self.alice, PRIMARY_DEVICE_ID)
                    .unwrap();
            let device =
                AuthorizedEndpointDevice::authorize(&cert, &self.alice, &registry, created)
                    .unwrap();
            let mut store = IndexedSessionStore::open(self.a.path()).unwrap();
            let session = store.session_id_for_record_key(&self.key).unwrap();
            let session_end = store.session_expires_at(&self.key).unwrap();
            let staged = std::cell::Cell::new(None::<[u8; 16]>);
            let (a_dir, bob_pub) = (self.a.path().to_path_buf(), self.bob_pub);
            let result = store.send_message_envelope(
                &self.key,
                text,
                &device,
                created,
                (created + validity_ms).min(session_end),
                created,
                &mut rand::rngs::OsRng,
                &mut |digest: &[u8; 32], bytes: &[u8]| {
                    let env = Envelope::unpack(bytes).unwrap();
                    raven_core::ensure_outbound_queued_history(
                        &a_dir,
                        &bob_pub,
                        &session,
                        digest,
                        &env.message_id,
                        created,
                        Some(text),
                    )
                    .unwrap();
                    staged.set(Some(env.message_id));
                    if hand_off {
                        Ok(*digest)
                    } else {
                        Err(())
                    }
                },
            );
            if hand_off {
                result.expect("handed to the outbox queue");
                return staged.get().expect("staged");
            }
            let err = result.expect_err("the dial failed: the row stays pending");
            staged
                .get()
                .unwrap_or_else(|| panic!("not staged: {}", err.redacted_display()))
        }

        fn stage(&self, text: &str, validity_ms: u64) -> [u8; 16] {
            self.stage_at(text, now_ms(), validity_ms)
        }

        fn record(&self, mid: &[u8; 16], choice: CarrierChoice, routes: &[OutboxRoute]) {
            record_object_routes(
                self.a.path(),
                mid,
                &self.bob_pub,
                choice,
                routes,
                now_ms() + DAY,
                now_ms(),
            )
            .unwrap();
        }

        fn due(&self) -> Vec<Entry> {
            let now = Instant::now();
            scan_store(self.a.path())
                .unwrap()
                .iter()
                .map(|r| Entry::from_row(r, now))
                .collect()
        }

        fn attempt_with(&self, ctx: &AttemptCtx) -> PeerReport {
            attempt_peer(ctx, &self.bob_pub, &self.due(), &[])
        }

        fn attempt(&self) -> PeerReport {
            self.attempt_with(&self.ctx())
        }

        fn history(&self, mid: &[u8; 16]) -> Option<String> {
            raven_core::ChatHistory::load(self.a.path())
                .unwrap()
                .entries
                .into_iter()
                .find(|e| e.direction == "out" && e.message_id_hex == hex::encode(mid))
                .map(|e| e.delivery)
        }

        fn bob_inbox(&self) -> Vec<String> {
            IndexedSessionStore::open(self.b.path())
                .unwrap()
                .list_endpoint_inbox()
                .unwrap()
                .into_iter()
                .map(|r| String::from_utf8_lossy(&r.plaintext).into_owned())
                .collect()
        }

        /// The exact staged bytes of the one pending row.
        fn staged_bytes(&self) -> Vec<u8> {
            IndexedSessionStore::open(self.a.path())
                .unwrap()
                .pending_endpoint_outbound()
                .unwrap()
                .remove(0)
                .immutable_envelope_bytes
        }

        /// Bob accepts `bytes` directly (our dial broke before the reply) and
        /// returns his sealed ACK.
        fn bob_accepts(&self, bytes: &[u8]) -> Vec<u8> {
            dispatch_frame(
                self.b.path(),
                &self.net.bob,
                &self.net.a_bundle,
                &self.alice.public_key_bytes(),
                bytes,
            )
            .unwrap()
            .into_iter()
            .find(|f| Envelope::unpack(f).is_some())
            .expect("Bob's ACK")
        }
    }

    const DAY: u64 = 24 * 60 * 60 * 1000;

    // ── The Tor race (design 2026-10-tor-fallback §2, §3.4) ──────────────

    /// A dialer that plays the race as the real carriers do: each carrier
    /// takes its handshake time, then a dial in a race claims it right
    /// before its first frame (`netutil::ReplyCollector::begin`) or writes
    /// nothing (RACE_LOST); a failing carrier fails after its time without
    /// claiming. What a winner writes goes to Bob's real dispatcher
    /// ([`FakeNet`]).
    struct RaceNet {
        inner: Arc<FakeNet>,
        delays: HashMap<OutboxCarrier, Duration>,
        failing: HashSet<OutboxCarrier>,
        /// (carrier, frames, when) per dial that got past its handshake.
        wrote: Mutex<Vec<(OutboxCarrier, usize, std::time::Instant)>>,
        started: Mutex<Vec<OutboxCarrier>>,
        t0: std::time::Instant,
    }

    impl RaceNet {
        fn new(
            inner: Arc<FakeNet>,
            delays: &[(OutboxCarrier, u64)],
            failing: &[OutboxCarrier],
        ) -> Self {
            Self {
                inner,
                delays: delays
                    .iter()
                    .map(|(c, ms)| (*c, Duration::from_millis(*ms)))
                    .collect(),
                failing: failing.iter().copied().collect(),
                wrote: Mutex::new(Vec::new()),
                started: Mutex::new(Vec::new()),
                t0: std::time::Instant::now(),
            }
        }

        fn wrote(&self) -> Vec<(OutboxCarrier, usize)> {
            self.wrote
                .lock()
                .unwrap()
                .iter()
                .map(|(c, n, _)| (*c, *n))
                .collect()
        }

        fn started(&self) -> Vec<OutboxCarrier> {
            self.started.lock().unwrap().clone()
        }
    }

    impl Dialer for RaceNet {
        fn dial(
            &self,
            data_dir: &Path,
            route: &OutboxRoute,
            expected: &str,
            frames: &[Vec<u8>],
        ) -> Result<Vec<Vec<u8>>, String> {
            self.dial_path_meta(data_dir, route, expected, frames, DialMeta::default())
                .map(|(r, _)| r)
        }

        fn dial_path_meta(
            &self,
            data_dir: &Path,
            route: &OutboxRoute,
            expected: &str,
            frames: &[Vec<u8>],
            meta: DialMeta,
        ) -> Result<(Vec<Vec<u8>>, Option<DeliveryPath>), String> {
            self.started.lock().unwrap().push(route.carrier);
            std::thread::sleep(self.delays.get(&route.carrier).copied().unwrap_or_default());
            if self.failing.contains(&route.carrier) {
                return Err("connect: cannot connect (Connection refused)".into());
            }
            if let Some(ticket) = meta.race.filter(|_| !frames.is_empty()) {
                if !crate::onion::race::claim(ticket) {
                    return Err(crate::onion::race::RACE_LOST.into());
                }
            }
            self.wrote.lock().unwrap().push((
                route.carrier,
                frames.len(),
                std::time::Instant::now(),
            ));
            let _ = self.t0;
            self.inner
                .dial_path_meta(data_dir, route, expected, frames, meta)
        }
    }

    /// Alice's book: Bob verified at `lan` (none when empty), with his onion
    /// binding (a card's `onion=`, signed by Bob).
    fn bob_with_onion(rig: &Rig, lan: &str) -> OutboxRoute {
        let hs_id = Identity::from_seed(&[0x3c; 32]).public_key_bytes();
        let binding =
            raven_core::onion::OnionBinding::sign(&rig.net.bob, hs_id, raven_core::onion::now_s());
        std::fs::write(
            rig.a.path().join("contacts.json"),
            format!(
                r#"[{{"petname":"Bob","pub_hex":"{}","pinned":true,"lan_dial":"{lan}","onion":"{}"}}]"#,
                hex::encode(rig.bob_pub),
                binding.to_text()
            ),
        )
        .unwrap();
        OutboxRoute {
            carrier: OutboxCarrier::Onion,
            dial: raven_core::onion::dial_for(&hs_id),
        }
    }

    fn race_ctx(rig: &Rig, dialer: Arc<RaceNet>, head_start: fn() -> Duration) -> AttemptCtx {
        AttemptCtx {
            dialer,
            onion_live: on,
            onion_available: on,
            onion_head_start: head_start,
            ..rig.ctx()
        }
    }

    /// A direct path that answers at once wins: the onion dial never starts
    /// (the head start ends with the direct side's claim), and only the LAN
    /// link wrote the message.
    #[test]
    fn tor_race_a_quick_direct_path_wins_and_tor_is_never_dialled() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x91);
        rig.set(UP);
        bob_with_onion(&rig, "127.0.0.1:9");
        let mid = rig.stage_queued("direct first", DAY);
        rig.record(&mid, CarrierChoice::Auto, &[]);
        let net = Arc::new(RaceNet::new(
            rig.net.clone(),
            &[(OutboxCarrier::Lan, 0), (OutboxCarrier::Onion, 200)],
            &[],
        ));
        let report = rig.attempt_with(&race_ctx(&rig, net.clone(), || Duration::from_millis(300)));
        assert_eq!(
            only(&report),
            Outcome::Delivered {
                carrier: Some(OutboxCarrier::Lan)
            }
        );
        assert_eq!(net.wrote(), [(OutboxCarrier::Lan, 1)]);
        assert!(
            !net.started().contains(&OutboxCarrier::Onion),
            "{:?}",
            net.started()
        );
        assert_eq!(rig.bob_inbox(), ["direct first"]);
    }

    /// Both direct paths fail (here: refused at once): the onion dial does
    /// not wait out its head start, and Tor delivers.
    #[test]
    fn tor_race_when_every_direct_path_failed_tor_goes_at_once_and_delivers() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x93);
        rig.set(UP);
        bob_with_onion(&rig, "127.0.0.1:9");
        let mid = rig.stage_queued("over tor", DAY);
        rig.record(&mid, CarrierChoice::Auto, &[]);
        let net = Arc::new(RaceNet::new(
            rig.net.clone(),
            &[(OutboxCarrier::Lan, 0), (OutboxCarrier::Onion, 50)],
            &[OutboxCarrier::Lan],
        ));
        let t = std::time::Instant::now();
        let report = rig.attempt_with(&race_ctx(&rig, net.clone(), || Duration::from_secs(20)));
        assert!(t.elapsed() < Duration::from_secs(10), "{:?}", t.elapsed());
        assert_eq!(
            only(&report),
            Outcome::Delivered {
                carrier: Some(OutboxCarrier::Onion)
            }
        );
        assert_eq!(net.wrote(), [(OutboxCarrier::Onion, 1)]);
        assert_eq!(rig.bob_inbox(), ["over tor"]);
    }

    /// A direct path that hangs (a black-holed address) loses to Tor: Tor
    /// starts after its head start and claims the attempt; the direct dial
    /// writes nothing when it finally authenticates, and its loss is no
    /// failure of its route.
    #[test]
    fn tor_race_a_slow_direct_path_loses_to_tor_and_writes_nothing() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x95);
        rig.set(UP);
        bob_with_onion(&rig, "127.0.0.1:9");
        let mid = rig.stage_queued("tor was quicker", DAY);
        rig.record(&mid, CarrierChoice::Auto, &[]);
        let net = Arc::new(RaceNet::new(
            rig.net.clone(),
            &[(OutboxCarrier::Lan, 1_500), (OutboxCarrier::Onion, 100)],
            &[],
        ));
        let report = rig.attempt_with(&race_ctx(&rig, net.clone(), || Duration::from_millis(200)));
        assert_eq!(
            only(&report),
            Outcome::Delivered {
                carrier: Some(OutboxCarrier::Onion)
            }
        );
        assert_eq!(
            net.wrote(),
            [(OutboxCarrier::Onion, 1)],
            "the LAN link wrote nothing"
        );
        assert_eq!(rig.bob_inbox(), ["tor was quicker"]);
        assert!(report.blocked.is_empty(), "no route blocked by a lost race");
    }

    /// With no other route (the contact's card has only its onion
    /// address), there is no race: Tor is dialled at once.
    #[test]
    fn tor_race_an_onion_only_contact_is_dialled_without_a_race() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x97);
        rig.set(UP);
        bob_with_onion(&rig, "");
        let mid = rig.stage_queued("only tor", DAY);
        rig.record(&mid, CarrierChoice::Auto, &[]);
        let net = Arc::new(RaceNet::new(rig.net.clone(), &[], &[]));
        let report = rig.attempt_with(&race_ctx(&rig, net.clone(), || Duration::from_secs(20)));
        assert_eq!(
            only(&report),
            Outcome::Delivered {
                carrier: Some(OutboxCarrier::Onion)
            }
        );
        assert_eq!(net.started(), [OutboxCarrier::Onion]);
    }

    /// The gate closed or the helper not ready: no onion route, the plan of
    /// before, nothing raced.
    #[test]
    fn tor_race_no_onion_route_without_the_gate_or_a_ready_helper() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x99);
        rig.set(UP);
        bob_with_onion(&rig, "127.0.0.1:9");
        let mid = rig.stage_queued("no tor", DAY);
        rig.record(&mid, CarrierChoice::Auto, &[]);
        for (live, ready) in [(off as fn() -> bool, on as fn() -> bool), (on, off)] {
            let net = Arc::new(RaceNet::new(rig.net.clone(), &[], &[OutboxCarrier::Lan]));
            let ctx = AttemptCtx {
                onion_live: live,
                onion_available: ready,
                ..race_ctx(&rig, net.clone(), || Duration::ZERO)
            };
            let _ = rig.attempt_with(&ctx);
            assert_eq!(net.started(), [OutboxCarrier::Lan]);
        }
    }

    /// Field test S15: a message whose first try failed (here: the LAN
    /// address is stale and Tor was not ready yet) is retried by the worker
    /// over Tor once the helper is ready, the stale LAN route raced and
    /// lost, as `raven send` does.
    #[test]
    fn tor_race_a_queued_message_goes_over_tor_on_a_later_retry() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x9b);
        rig.set(UP);
        bob_with_onion(&rig, "127.0.0.1:9");
        // As `raven send` records it: auto, with the LAN route it tried.
        let mid = rig.stage_queued("later over tor", DAY);
        let lan = OutboxRoute {
            carrier: OutboxCarrier::Lan,
            dial: "127.0.0.1:9".into(),
        };
        rig.record(&mid, CarrierChoice::Auto, std::slice::from_ref(&lan));
        // Retry 1: Tor not ready yet. LAN fails; nothing else to try.
        let net = Arc::new(RaceNet::new(rig.net.clone(), &[], &[OutboxCarrier::Lan]));
        let first = rig.attempt_with(&AttemptCtx {
            onion_available: off,
            ..race_ctx(&rig, net.clone(), || Duration::from_millis(100))
        });
        assert!(
            !matches!(only(&first), Outcome::Delivered { .. }),
            "{first:?}"
        );
        assert_eq!(net.started(), [OutboxCarrier::Lan]);
        // Retry 2: Tor ready. The stale LAN address hangs; Tor goes after
        // its head start and delivers.
        let net = Arc::new(RaceNet::new(
            rig.net.clone(),
            &[(OutboxCarrier::Lan, 2_000), (OutboxCarrier::Onion, 50)],
            &[OutboxCarrier::Lan],
        ));
        let again = rig.attempt_with(&race_ctx(&rig, net.clone(), || Duration::from_millis(100)));
        assert_eq!(
            only(&again),
            Outcome::Delivered {
                carrier: Some(OutboxCarrier::Onion)
            }
        );
        assert!(net.started().contains(&OutboxCarrier::Onion));
        assert_eq!(net.wrote(), [(OutboxCarrier::Onion, 1)]);
        assert_eq!(rig.bob_inbox(), ["later over tor"]);
    }

    /// `raven send --carrier onion` (lab): the worker retries over Tor only,
    /// the contact's LAN address left out (field tests of Tor between two
    /// computers on one LAN).
    #[test]
    fn tor_race_a_send_forced_onto_tor_is_retried_over_tor_only() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x9d);
        rig.set(UP);
        bob_with_onion(&rig, "127.0.0.1:9");
        let mid = rig.stage_queued("tor only", DAY);
        rig.record(&mid, CarrierChoice::Onion, &[]);
        let net = Arc::new(RaceNet::new(
            rig.net.clone(),
            &[(OutboxCarrier::Lan, 0), (OutboxCarrier::Onion, 50)],
            &[],
        ));
        let report = rig.attempt_with(&race_ctx(&rig, net.clone(), || Duration::from_secs(20)));
        assert_eq!(
            only(&report),
            Outcome::Delivered {
                carrier: Some(OutboxCarrier::Onion)
            }
        );
        assert_eq!(net.started(), [OutboxCarrier::Onion]);
        assert_eq!(rig.bob_inbox(), ["tor only"]);
    }

    /// The worker's onion dials get Tor's deadline, not the 45 s of a direct
    /// dial (field test S15: a first rendezvous may take most of a minute).
    #[test]
    fn an_onion_dial_gets_tors_deadline() {
        let onion = OutboxRoute {
            carrier: OutboxCarrier::Onion,
            dial: "onion:00".into(),
        };
        let lan = OutboxRoute {
            carrier: OutboxCarrier::Lan,
            dial: "192.168.1.9:7420".into(),
        };
        assert_eq!(default_deadline(&lan), DIAL_DEADLINE);
        assert_eq!(
            default_deadline(&onion),
            raven_core::onion::ONION_DIAL_DEADLINE + PROBE_OUTER_SLACK
        );
        assert!(default_deadline(&onion) > DIAL_DEADLINE);
    }

    fn only(report: &PeerReport) -> Outcome {
        assert_eq!(report.outcomes.len(), 1, "{:?}", report.outcomes);
        report.outcomes.values().next().unwrap().clone()
    }

    fn sched_row(d: u8, peer: u8, expires_at_ms: u64) -> ScanRow {
        ScanRow {
            object_digest: [d; 32],
            kind: EndpointOutboundKind::Message,
            session_id: [9; 32],
            message_id: [d; 16],
            recipient: [peer; 32],
            expires_at_ms,
            created_at_ms: 0,
            ratchet_index: 0,
            state: EntryState::Queued,
            never_sent: true,
        }
    }

    /// E2 r40 #C: a message a send queued while the worker was busy is
    /// listed at once (queued, due now), after the live rows and before the
    /// finished ones; tracked ones, probes, ACKs and other peers' are not
    /// added twice.
    #[test]
    fn untracked_store_rows_are_listed_at_once() {
        let (now, wall) = (Instant::now(), 1_000_000);
        let live = Entry::from_row(&sched_row(1, 7, wall + 60_000), now).item(now, wall);
        let mut finished = Entry::from_row(&sched_row(2, 7, wall + 60_000), now);
        finished.state = EntryState::Delivered;
        let finished = finished.item(now, wall);
        let mut items = vec![live.clone(), finished.clone()];
        let mut ack = sched_row(4, 7, wall + 60_000);
        ack.kind = EndpointOutboundKind::Ack;
        let mut probe = sched_row(7, 7, wall + 60_000);
        probe.object_digest = [7; 32];
        let rows = [
            sched_row(1, 7, wall + 60_000),
            sched_row(3, 7, wall + 60_000),
            sched_row(5, 8, wall + 60_000),
            ack,
            probe,
        ];
        let tracked: HashSet<[u8; 16]> = [[1; 16], [2; 16]].into_iter().collect();
        merge_untracked(&mut items, &rows, &tracked, Some(&[7; 32]), 10, now, wall);
        let ids: Vec<String> = items.iter().map(|i| i.message_id_hex.clone()).collect();
        assert_eq!(
            ids,
            [
                hex::encode([1u8; 16]),
                hex::encode([3u8; 16]),
                hex::encode([2u8; 16])
            ]
        );
        assert_eq!(
            (items[1].state.as_str(), items[1].next_attempt_ms),
            ("queued", 0)
        );
        // Within the limit.
        let mut items = vec![live, finished];
        merge_untracked(&mut items, &rows, &tracked, None, 2, now, wall);
        assert_eq!(items.len(), 2);
        assert_eq!(items[1].message_id_hex, hex::encode([3u8; 16]));
    }

    /// E2 r40 #D, #E: each attempt that dialled counts by how it ended, and
    /// several ways none of which answered are one reason.
    #[test]
    fn attempts_count_by_outcome_and_no_answer_on_several_ways_is_one_reason() {
        let (now, wall) = (Instant::now(), 1_000_000);
        let mut e = Entry::from_row(&sched_row(1, 7, wall + 3_600_000), now);
        let lost = |code| Outcome::Unreachable {
            carrier: Some(OutboxCarrier::Onion),
            code,
        };
        for _ in 0..9 {
            apply_outcome(&mut e, lost(code::NOT_REACHABLE), now, wall);
        }
        // Not dialled: not counted.
        apply_outcome(&mut e, Outcome::Held(code::SEND_IN_PROGRESS), now, wall);
        apply_outcome(
            &mut e,
            Outcome::Unreachable {
                carrier: None,
                code: code::NO_ROUTE,
            },
            now,
            wall,
        );
        apply_outcome(
            &mut e,
            Outcome::Delivered {
                carrier: Some(OutboxCarrier::Onion),
            },
            now,
            wall,
        );
        assert_eq!(e.attempts, 10);
        let item = e.item(now, wall);
        let counts: Vec<(&str, u32)> = item
            .outcomes
            .iter()
            .map(|c| (c.code.as_str(), c.count))
            .collect();
        assert_eq!(counts, [("NOT_REACHABLE", 9), ("DELIVERED", 1)]);
        assert_eq!(item.carrier, "onion_dial");
        // At most OUTCOME_KINDS_MAX kinds; more add to the last.
        let mut e = Entry::from_row(&sched_row(2, 7, wall + 3_600_000), now);
        let kinds = [
            "A_1", "A_2", "A_3", "A_4", "A_5", "A_6", "A_7", "A_8", "A_9",
        ];
        for k in kinds {
            e.count_outcome(k);
        }
        assert_eq!(e.outcomes.len(), OUTCOME_KINDS_MAX);
        assert_eq!(e.outcomes.last(), Some(&("A_8", 2)));
        // The reason: one for several silent ways, as it was for one way
        // or for an answer that says more.
        let (lan, p2p, tor) = (OutboxCarrier::Lan, OutboxCarrier::P2p, OutboxCarrier::Onion);
        assert_eq!(
            no_answer_on_any(&[lan, p2p, tor], code::ONION_UNREACHABLE),
            code::NOT_REACHABLE
        );
        assert_eq!(
            no_answer_on_any(&[lan, tor], code::NOT_REACHABLE),
            code::NOT_REACHABLE
        );
        assert_eq!(
            no_answer_on_any(&[tor], code::ONION_UNREACHABLE),
            code::ONION_UNREACHABLE
        );
        assert_eq!(
            no_answer_on_any(&[lan, tor], code::NOT_LISTENING),
            code::NOT_LISTENING
        );
        assert_eq!(
            no_answer_on_any(&[lan, tor], code::ONION_NOT_READY),
            code::ONION_NOT_READY
        );
        // The ways tried reach the IPC view in order.
        let mut e = Entry::from_row(&sched_row(3, 7, wall + 3_600_000), now);
        e.tried = vec![lan, p2p, tor];
        assert_eq!(
            e.item(now, wall).tried,
            ["lan_dial", "p2p_dial", "onion_dial"]
        );
    }

    fn report_for(digest: [u8; 32], outcome: Outcome) -> PeerReport {
        let mut r = PeerReport {
            attempted: vec![digest],
            ..PeerReport::default()
        };
        r.outcomes.insert(digest, outcome);
        r
    }

    fn unreachable() -> Outcome {
        Outcome::Unreachable {
            carrier: Some(OutboxCarrier::Lan),
            code: code::NOT_REACHABLE,
        }
    }

    /// An ACK owed to `peer` (scheduling only: no bytes).
    fn owed(peer: [u8; 32], failures: u32, next_due: Instant, expires_at_ms: u64) -> UnsentAck {
        UnsentAck {
            peer,
            bytes: Vec::new(),
            expires_at_ms,
            failures,
            next_due,
            durable: false,
            session_id: None,
            held_by: Vec::new(),
            may_deposit: true,
        }
    }

    /// Phase 3 diagnosis (P3.23): the local network's facts only after an
    /// attempt that planned something and left a message unreached; the
    /// beacon is asked only while LAN is on; a delivered, held-for-another-
    /// reason or ACK-only attempt gives none (the last reason stands).
    #[test]
    fn lan_reason_needs_a_plan_and_a_message_left_unreached() {
        use raven_core::reach_diag::{diagnose_lan, LanFacts, TheirFacts, Why};
        let now = Instant::now();
        let msg = Entry::from_row(&sched_row(1, 0xB0, u64::MAX), now);
        let mut ack = Entry::from_row(&sched_row(2, 0xB0, u64::MAX), now);
        ack.kind = EndpointOutboundKind::Ack;
        let with = |outcome: Outcome, other: Option<bool>| PeerReport {
            planned_other: other,
            ..report_for(msg.object_digest, outcome)
        };
        let why = |f: Option<LanFacts>| {
            f.and_then(|f| diagnose_lan(&f, &TheirFacts::default()))
                .map(|d| d.why)
        };
        let due = [msg.clone()];
        for outcome in [
            unreachable(),
            Outcome::Held(code::NO_ROUTE),
            Outcome::Unreachable {
                carrier: Some(OutboxCarrier::Lan),
                code: code::NOT_LISTENING,
            },
            Outcome::Held(code::DIAL_FAILED),
        ] {
            let r = with(outcome.clone(), Some(false));
            assert_eq!(why(lan_reason(&r, &due, true, || true)), Some(Why::LanOff));
            assert_eq!(
                why(lan_reason(&r, &due, false, || true)),
                Some(Why::LanNoAnswer)
            );
            // Facts, but LAN is not why: the old local reason goes.
            let f = lan_reason(&r, &due, false, || false);
            assert_eq!(
                f,
                Some(LanFacts {
                    lan_off: false,
                    beacon_no_answer: false,
                    other_route: false,
                })
            );
            assert_eq!(why(f), None);
            // Another carrier has a route: its reason, not LAN's.
            let r = with(outcome, Some(true));
            assert_eq!(why(lan_reason(&r, &due, true, || true)), None);
        }
        // LAN off: the beacon is not asked.
        let r = with(unreachable(), Some(false));
        let f = lan_reason(&r, &due, true, || panic!("asked")).unwrap();
        assert!(f.lan_off && !f.beacon_no_answer);
        // No plan, nothing left unreached, or only an ACK: nothing.
        assert_eq!(
            lan_reason(&with(unreachable(), None), &due, true, || true),
            None
        );
        for outcome in [
            Outcome::Delivered {
                carrier: Some(OutboxCarrier::Lan),
            },
            Outcome::Held(code::STORE),
            Outcome::Held(code::SEND_IN_PROGRESS),
        ] {
            let r = with(outcome, Some(false));
            assert_eq!(lan_reason(&r, &due, true, || true), None);
        }
        let r = PeerReport {
            planned_other: Some(false),
            ..report_for(ack.object_digest, unreachable())
        };
        assert_eq!(lan_reason(&r, &[ack], true, || true), None);
    }

    /// One attempt on `peer` at `at` in which `digest` is unreachable: the
    /// wait that gives it.
    fn fail_at(
        inner: &mut Inner,
        peer: &[u8; 32],
        digest: [u8; 32],
        at: Instant,
        wall: u64,
    ) -> Duration {
        let due = inner.take_due(at);
        assert!(due.iter().any(|w| w.peer == *peer), "due at {at:?}");
        inner.apply(peer, report_for(digest, unreachable()), at, wall);
        inner.entries[&digest].next_due - at
    }

    #[test]
    fn a_queued_message_is_retried_until_the_ack_and_then_left_alone() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x81);
        let mid = rig.stage("while you were away", DAY);
        assert_eq!(rig.history(&mid).as_deref(), Some("queued"));
        // Bob is down: one dial, backed off, still queued.
        let outcome = only(&rig.attempt());
        assert_eq!(
            outcome,
            Outcome::Unreachable {
                carrier: Some(OutboxCarrier::Lan),
                code: code::NOT_LISTENING
            }
        );
        assert_eq!(rig.dials(), 1);
        assert_eq!(rig.history(&mid).as_deref(), Some("queued"));
        assert!(rig.bob_inbox().is_empty());
        // Bob is back: the exact staged bytes go out, the sealed ACK verifies.
        rig.set(UP);
        assert_eq!(
            only(&rig.attempt()),
            Outcome::Delivered {
                carrier: Some(OutboxCarrier::Lan)
            }
        );
        assert_eq!(rig.history(&mid).as_deref(), Some("delivered"));
        assert_eq!(rig.bob_inbox(), vec!["while you were away"]);
        assert!(raven_core::load_staged_outbound_body(rig.a.path(), &mid)
            .unwrap()
            .is_none());
        // Cancel on ACK: nothing is left to send, nothing is dialled again.
        let dials = rig.dials();
        assert!(scan_store(rig.a.path()).unwrap().is_empty());
        assert!(attempt_peer(&rig.ctx(), &rig.bob_pub, &[], &[])
            .outcomes
            .is_empty());
        assert_eq!(rig.dials(), dials);
        assert_eq!(rig.bob_inbox(), vec!["while you were away"], "exactly once");
    }

    #[test]
    fn an_expired_message_is_abandoned_and_the_history_says_expired() {
        if !lab_backends() {
            return;
        }
        // The horizon held, whatever RAVEN_LAB_HORIZON the suite runs with:
        // with it the row is parked (`expired_row_parks_with_horizon_gate`).
        let _horizon = Horizon::set(false);
        let rig = Rig::new(0x83);
        rig.set(UP);
        let mid = rig.stage("too late", 1_500);
        std::thread::sleep(Duration::from_millis(1_600));
        assert_eq!(only(&rig.attempt()), Outcome::Expired);
        assert_eq!(rig.dials(), 0, "nothing dialled");
        assert_eq!(rig.history(&mid).as_deref(), Some(HISTORY_EXPIRED));
        assert!(scan_store(rig.a.path()).unwrap().is_empty());
        assert!(rig.bob_inbox().is_empty());
    }

    /// This thread's horizon lab switch for the life of a test (restored
    /// when it ends, also on a failed assertion).
    struct Horizon;

    impl Horizon {
        fn set(on: bool) -> Self {
            raven_core::horizon::set_lab_horizon_for_this_thread(Some(on));
            Self
        }
    }

    impl Drop for Horizon {
        fn drop(&mut self) {
            raven_core::horizon::set_lab_horizon_for_this_thread(None);
        }
    }

    /// P5.6 (the long message horizon): with its gate on, a message whose
    /// envelope ran out before its deadline is parked, not given up: no
    /// dial, history `queued`, stage kept, its route record kept to the
    /// deadline and marked unsent (it never left this computer); its
    /// contact's probe entry stands for it (`waiting`), on the IPC too.
    #[test]
    fn expired_row_parks_with_horizon_gate() {
        if !lab_backends() {
            return;
        }
        let _horizon = Horizon::set(true);
        let rig = Rig::new(0x6b);
        rig.set(UP);
        let written = now_ms();
        let mid = rig.stage_at("waits for a new session", written, 1_500);
        rig.record(&mid, CarrierChoice::Auto, &[]);
        let tracked = rig.due();
        std::thread::sleep(Duration::from_millis(1_600));
        let report = attempt_peer(&rig.ctx(), &rig.bob_pub, &tracked, &[]);
        assert_eq!(only(&report), Outcome::Parked);
        assert_eq!(rig.dials(), 0, "nothing dialled");
        assert_eq!(rig.history(&mid).as_deref(), Some("queued"));
        assert!(raven_core::load_staged_outbound_body(rig.a.path(), &mid)
            .unwrap()
            .is_some());
        let deadline = raven_core::horizon::message_deadline(written);
        let store = IndexedSessionStore::open(rig.a.path()).unwrap();
        let parked = store.parked_for_recipient(&rig.bob_pub).unwrap();
        assert_eq!(parked.len(), 1);
        assert_eq!(
            (parked[0].message_id, parked[0].deadline_ms),
            (mid, deadline)
        );
        assert!(store.pending_endpoint_outbound().unwrap().is_empty());
        drop(store);
        let later = now_ms() + 25 * 60 * 60 * 1_000;
        let records = object_route_records(rig.a.path(), later).unwrap();
        assert_eq!(records[&mid].choice, CarrierChoice::Auto);
        assert_eq!(records[&mid].expires_at_ms, deadline);
        assert!(records[&mid].unsent, "it never left this computer");
        // The schedule: the object leaves, its contact's probe comes in.
        let (t0, wall) = (Instant::now(), now_ms());
        let mut inner = Inner::default();
        inner.merge(tracked.iter().map(scan_row_of).collect(), 0, t0, wall);
        assert_eq!(inner.take_due(t0).len(), 1);
        inner.apply(&rig.bob_pub, report, t0, wall);
        assert!(inner.entries.is_empty() && inner.done.is_empty());
        assert!(inner.refresh, "rescan for the probe");
        let rows = scan_store(rig.a.path()).unwrap();
        assert_eq!(rows.len(), 1);
        let probe = &rows[0];
        assert_eq!(probe.state, EntryState::Waiting);
        assert_eq!(
            (probe.object_digest, probe.message_id, probe.expires_at_ms),
            (rig.bob_pub, mid, deadline)
        );
        inner.merge(rows, inner.scan_seq(), t0, wall);
        assert!(inner.entries[&rig.bob_pub].is_probe());
        // The IPC: one `waiting` item per parked message, with its deadline.
        let (running, items) = list_anywhere(rig.a.path(), None, 50).unwrap();
        assert!(!running);
        assert_eq!(items.len(), 1);
        assert_eq!(
            (items[0].state.as_str(), items[0].expires_at_ms),
            ("waiting", deadline)
        );
        assert_eq!(items[0].message_id_hex, hex::encode(mid));
        let item = status_anywhere(rig.a.path(), &mid).unwrap();
        assert_eq!(
            (item.state.as_str(), item.expires_at_ms),
            ("waiting", deadline)
        );
        assert!(!item.never_sent, "only once its time ran out");
        // P5.7: the probe's attempt runs the horizon step, which seals it
        // again under its own id (Bob is up): the probe leaves, the new copy
        // is scanned at once, and the next attempt delivers it.
        let due = inner.take_due(t0);
        let report = attempt_peer(&rig.ctx(), &rig.bob_pub, &due[0].entries, &[]);
        assert_eq!(only(&report), Outcome::Repaired);
        assert!(report.rescan);
        assert!(IndexedSessionStore::open(rig.a.path())
            .unwrap()
            .parked_for_recipient(&rig.bob_pub)
            .unwrap()
            .is_empty());
        assert_eq!(rig.history(&mid).as_deref(), Some("queued"));
        inner.apply(&rig.bob_pub, report, t0, wall);
        assert!(inner.entries.is_empty() && inner.done.is_empty());
        assert!(inner.refresh);
        let rows = scan_store(rig.a.path()).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            (rows[0].message_id, rows[0].state),
            (mid, EntryState::Queued)
        );
        let report = rig.attempt();
        assert!(matches!(only(&report), Outcome::Delivered { .. }));
        assert_eq!(rig.bob_inbox(), vec!["waits for a new session".to_string()]);
        assert_eq!(rig.history(&mid).as_deref(), Some("delivered"));
    }

    /// P5.6: a tracked message whose row left the store unsettled after its
    /// envelope ran out (as a prune takes it with its session; the stage
    /// still there) is parked from that session; a later attempt finds it
    /// parked already.
    #[test]
    fn vanished_row_parks_with_from_session() {
        if !lab_backends() {
            return;
        }
        let _horizon = Horizon::set(true);
        let rig = Rig::new(0x6d);
        let mid = rig.stage("pruned with its session", 1_500);
        let tracked = rig.due();
        let session = tracked[0].session_id;
        std::thread::sleep(Duration::from_millis(1_600));
        let mut store = IndexedSessionStore::open(rig.a.path()).unwrap();
        assert!(store
            .abandon_undelivered_outbound(&rig.key, &tracked[0].object_digest)
            .unwrap());
        drop(store);
        assert!(scan_store(rig.a.path())
            .unwrap()
            .iter()
            .all(|r| r.message_id != mid || r.state == EntryState::Waiting));
        let report = attempt_peer(&rig.ctx(), &rig.bob_pub, &tracked, &[]);
        assert_eq!(only(&report), Outcome::Parked);
        assert_eq!(rig.history(&mid).as_deref(), Some("queued"));
        let mut store = IndexedSessionStore::open(rig.a.path()).unwrap();
        let parked = store.parked_for_recipient(&rig.bob_pub).unwrap();
        assert_eq!(parked.len(), 1);
        assert_eq!(parked[0].from_session, Some(session));
        // No session to seal it into (P5.7's horizon step only probes Bob,
        // who is down): a later attempt finds it parked already.
        store
            .retire_session(
                &rig.key,
                &rig.bob_pub,
                raven_core::indexed_session_store::SessionRetireCause::PeerNoSession,
                now_ms(),
            )
            .unwrap();
        drop(store);
        let again = attempt_peer(&rig.ctx(), &rig.bob_pub, &tracked, &[]);
        assert_eq!(only(&again), Outcome::Parked, "parked already");
        assert_eq!(rig.dials(), 1, "the horizon step's probe only");
    }

    /// P5.7: a parked message with no session left to seal it into is sealed
    /// again after a re-pair by the probe's attempt: the horizon step's probe
    /// and its PairInit go out with the peer's send lock free (it is taken
    /// per store step, never across a dial, as the reset step's), the round
    /// counts in the shared re-pair budget, and the new copy goes out next.
    #[test]
    fn send_lock_not_held_across_horizon_dials() {
        if !lab_backends() {
            return;
        }
        let _horizon = Horizon::set(true);
        let rig = Rig::new(0x67);
        let mid = rig.stage("sealed again after a re-pair", 1_500);
        let tracked = rig.due();
        std::thread::sleep(Duration::from_millis(1_600));
        let report = attempt_peer(&rig.ctx(), &rig.bob_pub, &tracked, &[]);
        assert_eq!(only(&report), Outcome::Parked);
        assert_eq!(rig.dials(), 0);
        // Its session takes no new copy: only a re-pair can carry it.
        IndexedSessionStore::open(rig.a.path())
            .unwrap()
            .retire_session(
                &rig.key,
                &rig.bob_pub,
                raven_core::indexed_session_store::SessionRetireCause::PeerNoSession,
                now_ms(),
            )
            .unwrap();
        rig.set(STRICT);
        *rig.net.lock_probe.lock().unwrap() = Some((rig.a.path().to_path_buf(), rig.bob_pub));
        let report = rig.attempt();
        assert_eq!(only(&report), Outcome::Repaired, "the probe's attempt");
        assert!(
            rig.net.probed_dials.load(Ordering::SeqCst) >= 2,
            "probe and PairInit"
        );
        assert_eq!(rig.net.dials_with_lock_held.load(Ordering::SeqCst), 0);
        assert_eq!(
            IndexedSessionStore::open(rig.a.path())
                .unwrap()
                .peer_renewal_state(&rig.bob_pub)
                .unwrap()
                .attempts_in_window,
            1,
            "one round of the shared budget"
        );
        let report = rig.attempt();
        assert!(matches!(only(&report), Outcome::Delivered { .. }));
        assert_eq!(rig.net.dials_with_lock_held.load(Ordering::SeqCst), 0);
        assert_eq!(
            rig.bob_inbox(),
            vec!["sealed again after a re-pair".to_string()]
        );
        assert_eq!(rig.history(&mid).as_deref(), Some("delivered"));
    }

    /// P5.7: a parked message past its deadline is given up by the horizon
    /// step of its contact's attempt (no dial) and shows as a finished
    /// `expired` entry that never left this computer (CP.6), its route
    /// record gone.
    #[test]
    fn horizon_gives_up_past_deadline_as_finished_entry() {
        if !lab_backends() {
            return;
        }
        let _horizon = Horizon::set(true);
        let rig = Rig::new(0x69);
        let mid = rig.stage("too late", 1_500);
        rig.record(&mid, CarrierChoice::Auto, &[]);
        let tracked = rig.due();
        std::thread::sleep(Duration::from_millis(1_600));
        assert_eq!(
            only(&attempt_peer(&rig.ctx(), &rig.bob_pub, &tracked, &[])),
            Outcome::Parked
        );
        // Its deadline, moved to just now (the store keeps the earliest).
        let mut store = IndexedSessionStore::open(rig.a.path()).unwrap();
        let row = store.parked_for_recipient(&rig.bob_pub).unwrap().remove(0);
        assert!(store
            .park_outbound(
                &rig.bob_pub,
                &mid,
                None,
                row.created_at_ms,
                now_ms() + 1,
                now_ms()
            )
            .unwrap());
        drop(store);
        std::thread::sleep(Duration::from_millis(5));
        let (t0, wall) = (Instant::now(), now_ms());
        let mut inner = Inner::default();
        inner.merge(scan_store(rig.a.path()).unwrap(), 0, t0, wall);
        let due = inner.take_due(t0);
        let report = attempt_peer(&rig.ctx(), &rig.bob_pub, &due[0].entries, &[]);
        assert_eq!(only(&report), Outcome::Gone);
        assert_eq!(rig.dials(), 0, "nothing dialled");
        assert_eq!(report.horizon_expired, vec![(mid, true)]);
        assert_eq!(rig.history(&mid).as_deref(), Some("expired"));
        assert!(!object_route_records(rig.a.path(), now_ms())
            .unwrap()
            .contains_key(&mid));
        inner.apply(&rig.bob_pub, report, t0, wall);
        assert!(inner.entries.is_empty());
        let item = inner.done.back().unwrap().item(t0, wall);
        assert_eq!(item.message_id_hex, hex::encode(mid));
        assert_eq!(item.state, "expired");
        assert!(item.never_sent, "it never left this computer");
    }

    /// P5.6: with the horizon gate off an expired message is given up
    /// exactly as before (`give_up_outbound` with HISTORY_EXPIRED): history
    /// `expired` with its body, stage and route record gone, nothing
    /// parked, no probe; the same as a direct give-up on a twin.
    #[test]
    fn gate_off_expired_is_byte_identical_to_today() {
        if !lab_backends() {
            return;
        }
        let _horizon = Horizon::set(false);
        let worker = Rig::new(0x6f);
        let direct = Rig::new(0x6f);
        let mids: Vec<[u8; 16]> = [&worker, &direct]
            .iter()
            .map(|rig| {
                let mid = rig.stage("too late", 1_500);
                rig.record(&mid, CarrierChoice::Auto, &[]);
                mid
            })
            .collect();
        std::thread::sleep(Duration::from_millis(1_600));
        assert_eq!(only(&worker.attempt()), Outcome::Expired);
        let mut store = IndexedSessionStore::open(direct.a.path()).unwrap();
        let row = store.pending_endpoint_outbound().unwrap().remove(0);
        assert_eq!(
            give_up_outbound(
                direct.a.path(),
                &mut store,
                &direct.key,
                &direct.bob_pub,
                &row.session_id,
                &row.object_digest,
                &row.message_id,
                HISTORY_EXPIRED,
            )
            .unwrap(),
            GiveUp::Abandoned
        );
        drop(store);
        let _ = clear_object_routes(direct.a.path(), &[row.message_id]);
        let view = |rig: &Rig, mid: &[u8; 16]| {
            let entry = raven_core::ChatHistory::load(rig.a.path())
                .unwrap()
                .entries
                .into_iter()
                .find(|e| e.direction == "out" && e.message_id_hex == hex::encode(mid))
                .unwrap();
            let store = IndexedSessionStore::open(rig.a.path()).unwrap();
            (
                entry.delivery,
                entry.body,
                raven_core::load_staged_outbound_body(rig.a.path(), mid)
                    .unwrap()
                    .is_some(),
                store.parked_peers().unwrap().len(),
                store.pending_endpoint_outbound().unwrap().len()
                    + store.awaiting_ack_endpoint_outbound().unwrap().len(),
                object_route_evidence_has(rig, mid),
            )
        };
        assert_eq!(view(&worker, &mids[0]), view(&direct, &mids[1]));
        assert_eq!(
            view(&worker, &mids[0]),
            (
                HISTORY_EXPIRED.to_string(),
                "too late".to_string(),
                false,
                0,
                0,
                false
            )
        );
        assert!(scan_store(worker.a.path()).unwrap().is_empty(), "no probe");
        assert_eq!(worker.dials(), 0);
    }

    fn object_route_evidence_has(rig: &Rig, mid: &[u8; 16]) -> bool {
        raven_core::outbox::object_route_evidence(rig.a.path(), now_ms())
            .unwrap()
            .contains_key(mid)
    }

    /// The scan row a tracked entry came from (a schedule built from it).
    fn scan_row_of(e: &Entry) -> ScanRow {
        ScanRow {
            object_digest: e.object_digest,
            kind: e.kind,
            session_id: e.session_id,
            message_id: e.message_id,
            recipient: e.recipient,
            expires_at_ms: e.expires_at_ms,
            created_at_ms: e.created_at_ms,
            ratchet_index: e.ratchet_index,
            state: e.state,
            never_sent: e.never_sent,
        }
    }

    /// P5.6: a contact's probe entry (its parked messages) backs off from 5 s
    /// to 10 min, no later than its first deadline, and starts over on the
    /// contact's inbound link, a network change and an explicit kick; it
    /// never finishes into the done list, and leaves when nothing is parked.
    #[test]
    fn parked_peer_probe_backoff_and_peer_seen_kick() {
        let t0 = Instant::now();
        let wall = 1_000_000_000u64;
        let peer = [0xB4; 32];
        let probe = |deadline: u64| {
            probe_row(
                &raven_core::indexed_session_store::ParkedPeer {
                    peer,
                    parked: 1,
                    first_deadline_ms: deadline,
                    last_deadline_ms: deadline,
                },
                &[raven_core::indexed_session_store::ParkedOutbound {
                    recipient_device: peer,
                    message_id: [4; 16],
                    created_at_ms: wall - DAY,
                    deadline_ms: deadline,
                    parked_at_ms: wall,
                    from_session: None,
                    send_order: 1,
                }],
            )
            .unwrap()
        };
        let mut inner = Inner::default();
        inner.merge(vec![probe(wall + 6 * DAY)], 0, t0, wall);
        let entry = &inner.entries[&peer];
        assert!(entry.is_probe() && entry.state == EntryState::Waiting);
        assert_eq!(entry.item(t0, wall).state, "waiting");
        assert!(!entry.state.is_final());
        let mut now = t0;
        let mut waits = Vec::new();
        for _ in 0..12 {
            let due = inner.take_due(now);
            assert_eq!(due.len(), 1, "due by its backoff");
            inner.apply(&peer, report_for(peer, Outcome::Parked), now, wall);
            let e = &inner.entries[&peer];
            assert_eq!(e.state, EntryState::Waiting);
            let wait = e.next_due.saturating_duration_since(now);
            waits.push(wait);
            now = e.next_due;
        }
        assert!(waits[0] >= MIN_RETRY && waits[0] <= Duration::from_millis(7_500));
        assert!(waits.iter().all(|w| *w <= RETRY_MAX));
        assert!(waits[11] >= RETRY_MAX.mul_f64(0.5), "{waits:?}");
        // A hold keeps it waiting, with its code.
        let held = now;
        assert_eq!(inner.take_due(held).len(), 1);
        inner.apply(
            &peer,
            report_for(peer, Outcome::Held(code::STORE)),
            held,
            wall,
        );
        assert_eq!(inner.entries[&peer].state, EntryState::Waiting);
        assert_eq!(inner.entries[&peer].last_error, code::STORE);
        // The contact's inbound link: its backoff starts over, due now.
        let seen = held + Duration::from_secs(1);
        assert!(inner.peer_seen_now(&peer, seen));
        assert_eq!(inner.entries[&peer].failures, 0);
        assert_eq!(inner.entries[&peer].next_due, seen);
        // A network change: due within the spread, from 0 again.
        assert_eq!(inner.take_due(seen).len(), 1);
        inner.apply(&peer, report_for(peer, Outcome::Parked), seen, wall);
        inner.entries.get_mut(&peer).unwrap().failures = 9;
        inner.network_changed(seen);
        assert_eq!(inner.entries[&peer].failures, 0);
        assert!(inner.entries[&peer].next_due <= seen + NETWORK_SPREAD);
        // An explicit kick (a send, `raven outbox retry`): due now, from 0.
        inner.entries.get_mut(&peer).unwrap().failures = 9;
        inner.entries.get_mut(&peer).unwrap().next_due = seen + RETRY_MAX;
        inner.kick_restart(Some(&peer), true, true, seen);
        assert_eq!(inner.entries[&peer].failures, 0);
        assert_eq!(inner.entries[&peer].next_due, seen);
        // No later than its first deadline, once that is near.
        inner.merge(vec![probe(wall + 30_000)], inner.scan_seq(), seen, wall);
        assert_eq!(inner.entries[&peer].expires_at_ms, wall + 30_000);
        inner.entries.get_mut(&peer).unwrap().failures = 9;
        assert_eq!(inner.take_due(seen).len(), 1);
        inner.apply(&peer, report_for(peer, Outcome::Parked), seen, wall);
        assert!(inner.entries[&peer].next_due <= seen + Duration::from_secs(30));
        // Nothing parked any more: the probe leaves, not into `done`.
        let gone = inner.entries[&peer].next_due;
        assert_eq!(inner.take_due(gone).len(), 1);
        inner.apply(&peer, report_for(peer, Outcome::Gone), gone, wall);
        assert!(inner.entries.is_empty() && inner.done.is_empty());
        // A probe re-paired by the horizon step (P5.7) leaves too.
        inner.merge(vec![probe(wall + DAY)], inner.scan_seq(), gone, wall);
        assert_eq!(inner.take_due(gone).len(), 1);
        inner.apply(&peer, report_for(peer, Outcome::Repaired), gone, wall);
        assert!(inner.entries.is_empty() && inner.done.is_empty());
        assert!(inner.refresh);
    }

    #[test]
    fn a_removed_or_blocked_contact_fails_closed_and_nothing_is_dialled() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x85);
        rig.set(UP);
        let mid = rig.stage("hold this", DAY);
        let mut blocks = raven_core::BlockList::default();
        blocks.block(&hex::encode(rig.bob_pub));
        blocks.save(rig.a.path()).unwrap();
        assert_eq!(rig.attempt().held, Some(code::CONTACT_BLOCKED));
        assert_eq!(rig.dials(), 0);
        raven_core::BlockList::default().save(rig.a.path()).unwrap();
        std::fs::write(rig.a.path().join("contacts.json"), "[]").unwrap();
        assert_eq!(rig.attempt().held, Some(code::NOT_A_CONTACT));
        assert_eq!(rig.dials(), 0);
        // Held, not destroyed: still queued, and restoring the contact resumes.
        assert_eq!(rig.history(&mid).as_deref(), Some("queued"));
        assert_eq!(scan_store(rig.a.path()).unwrap().len(), 1);
        contacts(rig.a.path(), &rig.bob_pub, "127.0.0.1:9", "", false);
        assert!(matches!(only(&rig.attempt()), Outcome::Delivered { .. }));
        assert_eq!(rig.history(&mid).as_deref(), Some("delivered"));
        // An unreadable book trusts nobody.
        let mid2 = rig.stage("second", DAY);
        std::fs::write(rig.a.path().join("contacts.json"), "{not json").unwrap();
        let dials = rig.dials();
        assert!(rig.attempt().held.is_some());
        assert_eq!(rig.dials(), dials);
        assert_eq!(rig.history(&mid2).as_deref(), Some("queued"));
    }

    /// "Pause sending" (Phase 6b P6.31): a contact the user paused gets
    /// nothing, its message waits as it was, and once the user resumes it
    /// is delivered. Another contact's hold changes nothing for this one.
    #[test]
    fn a_paused_contact_is_held_until_the_user_resumes() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x86);
        rig.set(UP);
        let mid = rig.stage("wait for me", DAY);
        raven_core::node_policy::set_send_hold(rig.a.path(), &[0x33; 32], true).unwrap();
        raven_core::node_policy::set_send_hold(rig.a.path(), &rig.bob_pub, true).unwrap();
        assert_eq!(rig.attempt().held, Some(code::SENDING_PAUSED));
        assert_eq!(rig.dials(), 0);
        assert_eq!(rig.history(&mid).as_deref(), Some("queued"));
        assert_eq!(scan_store(rig.a.path()).unwrap().len(), 1);
        raven_core::node_policy::set_send_hold(rig.a.path(), &rig.bob_pub, false).unwrap();
        assert!(matches!(only(&rig.attempt()), Outcome::Delivered { .. }));
        assert_eq!(rig.history(&mid).as_deref(), Some("delivered"));
    }

    #[test]
    fn a_revoked_peer_lineage_is_abandoned_before_any_dial() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x87);
        rig.set(UP);
        let mid = rig.stage("not to a revoked device", DAY);
        let bob = Identity::from_seed(&[0x88; 32]);
        let mut store = raven_core::RevocationStore::load_checked(rig.a.path()).unwrap();
        let rec =
            raven_core::RevocationRecord::issue(&bob, PRIMARY_DEVICE_ID, 1, 10, "test").unwrap();
        assert!(store.apply(rec).unwrap());
        store.save(rig.a.path()).unwrap();
        assert_eq!(only(&rig.attempt()), Outcome::Failed(code::PEER_REVOKED));
        assert_eq!(rig.dials(), 0);
        assert_eq!(rig.history(&mid).as_deref(), Some(HISTORY_FAILED));
        assert!(rig.bob_inbox().is_empty());
    }

    /// The Internet gate and the verified-contact rule hold for the worker.
    #[test]
    fn the_internet_gate_and_the_verified_contact_rule_hold() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x89);
        rig.set(UP);
        contacts(rig.a.path(), &rig.bob_pub, "", "203.0.113.7:7422", false);
        let mid = rig.stage("over the internet", DAY);
        rig.record(&mid, CarrierChoice::Auto, &[]);
        assert_eq!(
            only(&rig.attempt_with(&rig.ctx_with(on, off))),
            Outcome::Held(code::NO_ROUTE)
        );
        assert_eq!(
            only(&rig.attempt_with(&rig.ctx_with(on, on))),
            Outcome::Held(CONTACT_NOT_VERIFIED)
        );
        assert_eq!(rig.net.internet_dials.load(Ordering::SeqCst), 0);
        assert_eq!(rig.history(&mid).as_deref(), Some("queued"));
        contacts(rig.a.path(), &rig.bob_pub, "", "203.0.113.7:7422", true);
        assert_eq!(
            only(&rig.attempt_with(&rig.ctx_with(on, off))),
            Outcome::Held(code::NO_ROUTE),
            "the gate still decides"
        );
        assert_eq!(rig.net.internet_dials.load(Ordering::SeqCst), 0);
        assert_eq!(
            only(&rig.attempt_with(&rig.ctx_with(on, on))),
            Outcome::Delivered {
                carrier: Some(OutboxCarrier::Internet)
            }
        );
    }

    /// M: LAN routes need the LAN gate; with both gates off nothing is planned.
    #[test]
    fn the_lan_gate_is_honoured_and_both_gates_off_plan_nothing() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x8a);
        rig.set(UP);
        rig.stage("gated", DAY);
        assert_eq!(
            only(&rig.attempt_with(&rig.ctx_with(off, off))),
            Outcome::Held(code::NO_ROUTE)
        );
        assert_eq!(
            only(&rig.attempt_with(&rig.ctx_with(off, on))),
            Outcome::Held(code::NO_ROUTE),
            "no record: LAN only, and LAN is gated"
        );
        assert_eq!(rig.dials(), 0);
        assert!(matches!(only(&rig.attempt()), Outcome::Delivered { .. }));
    }

    /// K: the worker takes `raven send`'s lock, steps back while ash holds it,
    /// and never holds it across a dial.
    #[test]
    fn the_send_lock_is_shared_with_raven_send_but_never_held_across_a_dial() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x8b);
        rig.set(UP);
        rig.stage("wait for ash", DAY);
        let ash = PeerSendLock::acquire_within(rig.a.path(), &rig.bob_pub, Duration::ZERO)
            .expect("ash takes the lock");
        assert_eq!(rig.attempt().held, Some(code::SEND_IN_PROGRESS));
        assert_eq!(rig.dials(), 0);
        let t = Instant::now();
        let mut entry = rig.due().remove(0);
        apply_outcome(
            &mut entry,
            Outcome::Held(code::SEND_IN_PROGRESS),
            t,
            now_ms(),
        );
        assert_eq!(entry.failures, 0);
        assert_eq!(entry.next_due, t + LOCK_BUSY_RETRY);
        drop(ash);
        *rig.net.lock_probe.lock().unwrap() = Some((rig.a.path().to_path_buf(), rig.bob_pub));
        assert!(matches!(only(&rig.attempt()), Outcome::Delivered { .. }));
        assert!(
            rig.net.lock_free_during_dial.load(Ordering::SeqCst),
            "`raven send` could take the lock while the worker dialled"
        );
    }

    /// The schedule lives in memory only: a new process rebuilds it from the
    /// store, every object due at once, without a new send.
    #[test]
    fn the_schedule_is_rebuilt_from_the_store_after_a_restart() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x8d);
        rig.stage("survives a restart", DAY);
        let t0 = Instant::now();
        let mut inner = Inner::default();
        inner.merge(scan_store(rig.a.path()).unwrap(), 0, t0, now_ms());
        assert_eq!(inner.entries.len(), 1);
        let entry = inner.entries.values().next().unwrap().clone();
        assert_eq!((entry.state, entry.attempts), (EntryState::Queued, 0));
        assert_eq!(entry.next_due, t0, "due at once");
        let due = inner.take_due(t0);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].peer, rig.bob_pub);
        assert!(inner.take_due(t0).is_empty(), "one attempt per peer");
        inner.apply(
            &rig.bob_pub,
            report_for(entry.object_digest, unreachable()),
            t0,
            now_ms(),
        );
        let after = inner.entries.values().next().unwrap().clone();
        assert_eq!((after.attempts, after.failures), (1, 1));
        let wait = after.next_due - t0;
        assert!(
            (MIN_RETRY..=Duration::from_millis(7_500)).contains(&wait),
            "{wait:?}"
        );
        let seq = inner.scan_seq();
        inner.merge(
            scan_store(rig.a.path()).unwrap(),
            seq,
            t0 + Duration::from_secs(1),
            now_ms(),
        );
        assert_eq!(
            inner.entries.values().next().unwrap().next_due,
            after.next_due
        );
    }

    /// A peer's due objects go out in the order they were written, not in the
    /// digest order the schedule is keyed by.
    #[test]
    fn due_objects_are_dispatched_in_creation_order() {
        let t0 = Instant::now();
        let mut inner = Inner::default();
        let mut rows = vec![sched_row(0xf0, 1, u64::MAX), sched_row(0x10, 1, u64::MAX)];
        rows[0].created_at_ms = 2_000; // largest digest, written first ...
        rows[0].ratchet_index = 0;
        rows[1].created_at_ms = 1_000; // ... though the clock stepped back
        rows[1].ratchet_index = 1;
        inner.merge(rows, 0, t0, 0);
        let due = inner.take_due(t0);
        assert_eq!(due.len(), 1);
        let order: Vec<[u8; 32]> = due[0].entries.iter().map(|e| e.object_digest).collect();
        assert_eq!(
            order,
            vec![[0xf0; 32], [0x10; 32]],
            "ratchet order in a lane"
        );
    }

    /// Per-object jitter splits a peer's queue: when a newer object is due,
    /// the older ones still backing off ride in the same dial, first.
    #[test]
    fn older_waiting_objects_ride_along_with_a_due_one() {
        let t0 = Instant::now();
        let mut inner = Inner::default();
        let mut rows = vec![sched_row(0x01, 1, u64::MAX), sched_row(0x02, 1, u64::MAX)];
        rows[0].created_at_ms = 1_000;
        rows[0].ratchet_index = 0;
        rows[1].created_at_ms = 2_000;
        rows[1].ratchet_index = 1;
        inner.merge(rows, 0, t0, 0);
        // The older one backs off for minutes; the newer one is due now.
        inner.entries.get_mut(&[0x01; 32]).unwrap().next_due = t0 + Duration::from_secs(300);
        let due = inner.take_due(t0);
        assert_eq!(due.len(), 1);
        let order: Vec<[u8; 32]> = due[0].entries.iter().map(|e| e.object_digest).collect();
        assert_eq!(order, vec![[0x01; 32], [0x02; 32]]);
        // The dial fails: the due one backs off, the rider keeps its own timer.
        let mut report = report_for([0x02; 32], unreachable());
        report.attempted.push([0x01; 32]);
        report.outcomes.insert([0x01; 32], unreachable());
        inner.apply(&[1; 32], report, t0, 1);
        assert_eq!(inner.entries[&[0x01; 32]].failures, 0, "not charged");
        assert_eq!(
            inner.entries[&[0x01; 32]].next_due,
            t0 + Duration::from_secs(300),
            "own backoff stands"
        );
        assert_eq!(inner.entries[&[0x02; 32]].failures, 1);
        assert!(inner.riding.is_empty());
    }

    /// A message staged while an attempt to the same peer is in flight is
    /// scheduled as soon as that attempt ends: its kick asks for a rescan (the
    /// scan during the flight skips the peer), and a delivery makes the rest
    /// of that peer's queue due at once instead of at its own backoff.
    #[test]
    fn a_message_staged_during_an_attempt_is_scheduled_when_it_ends() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x8e);
        rig.stage_queued("first", DAY);
        let t0 = Instant::now();
        let mut inner = Inner::default();
        inner.merge(scan_store(rig.a.path()).unwrap(), 0, t0, now_ms());
        let first = inner.entries.values().next().unwrap().object_digest;
        assert_eq!(inner.take_due(t0).len(), 1, "first is in flight");

        rig.stage_queued("second", DAY);
        inner.kick_now(Some(&rig.bob_pub), false, t0);
        let seq = inner.scan_seq();
        inner.refresh = false;
        inner.merge(scan_store(rig.a.path()).unwrap(), seq, t0, now_ms());
        assert_eq!(inner.entries.len(), 1, "a scan skips the peer in flight");
        assert!(
            inner.rescan_after.contains(&rig.bob_pub),
            "but notes that it saw a new object for it"
        );

        inner.apply(
            &rig.bob_pub,
            report_for(first, Outcome::Delivered { carrier: None }),
            t0,
            now_ms(),
        );
        assert!(
            inner.refresh,
            "the kick during the flight asks for a rescan"
        );
        let seq = inner.scan_seq();
        inner.merge(scan_store(rig.a.path()).unwrap(), seq, t0, now_ms());
        // (The fake report did not remove `first` from the store, so the
        // rescan lists it again; what matters is that `second` is now known.)
        let second = inner
            .entries
            .values()
            .find(|e| e.object_digest != first)
            .expect("the second message is scheduled");
        assert_eq!(second.next_due, t0, "due at once");
    }

    /// A delivery proves the peer reachable: its other objects stop waiting
    /// out their own backoff.
    #[test]
    fn a_delivery_makes_the_rest_of_the_peers_queue_due() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x8f);
        rig.stage_queued("one", DAY);
        rig.stage_queued("two", DAY);
        let t0 = Instant::now();
        let mut inner = Inner::default();
        inner.merge(scan_store(rig.a.path()).unwrap(), 0, t0, now_ms());
        let digests: Vec<[u8; 32]> = inner.entries.keys().copied().collect();
        assert_eq!(digests.len(), 2);
        // `two` is backing off after a long outage.
        inner.entries.get_mut(&digests[1]).unwrap().next_due = t0 + Duration::from_secs(600);
        inner.entries.get_mut(&digests[1]).unwrap().failures = 9;
        inner.in_flight.insert(rig.bob_pub);
        inner.apply(
            &rig.bob_pub,
            report_for(
                digests[0],
                Outcome::Delivered {
                    carrier: Some(OutboxCarrier::Lan),
                },
            ),
            t0,
            now_ms(),
        );
        assert_eq!(
            inner.entries[&digests[1]].next_due, t0,
            "due now, not in 10 min"
        );
        assert_eq!(
            inner.entries[&digests[1]].failures, 0,
            "and its backoff starts over (G5)"
        );
    }

    /// A: an expired object whose finalization fails (store, lock, abandon)
    /// backs off at least 5 s from now: no hot loop past an expiry.
    #[test]
    fn an_expired_object_that_cannot_be_finalized_backs_off() {
        let t0 = Instant::now();
        let wall = 1_000_000_000u64;
        let mut inner = Inner::default();
        inner.merge(vec![sched_row(1, 0xB0, wall - 5_000)], 0, t0, wall);
        let peer = [0xB0; 32];
        let mut now = t0;
        for why in [code::STORE, code::LOCK, code::STORE, code::STORE] {
            let due = inner.take_due(now);
            assert_eq!(due.len(), 1, "due once");
            inner.apply(&peer, report_for([1; 32], Outcome::Held(why)), now, wall);
            let wait = inner.next_due_in(now).unwrap();
            assert!(wait >= MIN_RETRY, "{why}: due again after {wait:?}");
            assert!(inner.take_due(now).is_empty());
            now += wait;
        }
        // And with the real store: a broken session (secret gone) past expiry,
        // with the horizon held (with it the row is parked, not finalized).
        if !lab_backends() {
            return;
        }
        let _horizon = Horizon::set(false);
        let rig = Rig::new(0x8f);
        rig.stage("expires on a broken session", 1_200);
        std::thread::sleep(Duration::from_millis(1_300));
        for e in std::fs::read_dir(rig.a.path().join("indexed-session-secrets")).unwrap() {
            std::fs::remove_file(e.unwrap().path()).unwrap();
        }
        let report = rig.attempt();
        assert!(
            matches!(only(&report), Outcome::Held(_)),
            "{:?}",
            report.outcomes
        );
        let mut entry = rig.due().remove(0);
        let t = Instant::now();
        apply_outcome(&mut entry, only(&report), t, now_ms());
        assert!(entry.next_due >= t + MIN_RETRY);
        assert_eq!(rig.dials(), 0);
    }

    /// H: only due objects are dialled, each with its own failure count.
    #[test]
    fn only_due_objects_are_attempted_each_with_its_own_backoff() {
        let t0 = Instant::now();
        let wall = 1_000_000_000u64;
        let mut inner = Inner::default();
        inner.merge(
            vec![
                sched_row(1, 0xB0, wall + DAY),
                sched_row(2, 0xB0, wall + DAY),
            ],
            0,
            t0,
            wall,
        );
        inner.entries.get_mut(&[2; 32]).unwrap().next_due = t0 + Duration::from_secs(300);
        inner.entries.get_mut(&[2; 32]).unwrap().failures = 6;
        let due = inner.take_due(t0);
        assert_eq!(due[0].entries.len(), 1, "only the due object goes");
        assert_eq!(due[0].entries[0].object_digest, [1; 32]);
        inner.apply(&[0xB0; 32], report_for([1; 32], unreachable()), t0, wall);
        let one = &inner.entries[&[1; 32]];
        let two = &inner.entries[&[2; 32]];
        assert_eq!((one.failures, two.failures), (1, 6), "own counts");
        assert_eq!(two.next_due, t0 + Duration::from_secs(300), "untouched");
    }

    /// G: a kick that arrives while the peer's attempt is in flight makes its
    /// objects due again as soon as that attempt ends.
    #[test]
    fn a_kick_during_an_in_flight_attempt_is_honoured() {
        let t0 = Instant::now();
        let wall = 1_000_000_000u64;
        let peer = [0xB0; 32];
        let mut inner = Inner::default();
        inner.merge(vec![sched_row(1, 0xB0, wall + DAY)], 0, t0, wall);
        inner.entries.get_mut(&[1; 32]).unwrap().failures = 8;
        assert_eq!(inner.take_due(t0).len(), 1);
        inner.kick_now(Some(&peer), false, t0 + Duration::from_secs(3));
        let end = t0 + Duration::from_secs(6);
        inner.apply(&peer, report_for([1; 32], unreachable()), end, wall);
        assert_eq!(
            inner.entries[&[1; 32]].next_due, end,
            "due at once, not in 10 min"
        );
        assert_eq!(inner.take_due(end).len(), 1);
    }

    /// G5: after a long outage the backoff sits at its cap. A plain kick (a
    /// friend's custody fetch) makes the object due but keeps that cap; a
    /// user's kick (a send, `raven outbox retry`) starts the count over, for
    /// that contact's owed ACKs too: 5-7.5 s, then <= 15 s, then <= 30 s.
    #[test]
    fn a_long_outage_backoff_restarts_on_an_explicit_kick_only() {
        let t0 = Instant::now();
        let wall = 1_000_000_000u64;
        let parked = t0 + RETRY_MAX;
        let peer = [0xB0; 32];
        let mut inner = Inner::default();
        inner.merge(
            vec![
                sched_row(1, 0xB0, wall + DAY),
                sched_row(2, 0xB1, wall + DAY),
            ],
            0,
            t0,
            wall,
        );
        for (digest, failures) in [([1; 32], 20), ([2; 32], 9)] {
            let e = inner.entries.get_mut(&digest).unwrap();
            e.failures = failures;
            e.next_due = parked;
        }
        inner
            .unsent_acks
            .insert([0xA0; 32], owed(peer, 7, parked, wall + DAY));

        let t1 = t0 + Duration::from_secs(1);
        inner.kick_restart(Some(&peer), false, false, t1);
        assert_eq!(inner.entries[&[1; 32]].next_due, t1, "due now");
        let wait = fail_at(&mut inner, &peer, [1; 32], t1, wall);
        assert!(
            (Duration::from_secs(300)..=RETRY_MAX).contains(&wait),
            "a plain kick keeps the cap: {wait:?}"
        );

        let t2 = inner.entries[&[1; 32]].next_due - Duration::from_secs(100);
        inner.kick_restart(Some(&peer), true, true, t2);
        let one = &inner.entries[&[1; 32]];
        assert_eq!((one.failures, one.next_due), (0, t2));
        assert_eq!(inner.unsent_acks[&[0xA0; 32]].failures, 0, "owed ACKs too");
        let mut at = t2;
        for ceiling_ms in [7_500, 15_000, 30_000] {
            let wait = fail_at(&mut inner, &peer, [1; 32], at, wall);
            assert!(
                wait >= MIN_RETRY && wait <= Duration::from_millis(ceiling_ms),
                "{wait:?}"
            );
            at += wait;
        }
        let two = &inner.entries[&[2; 32]];
        assert_eq!(
            (two.failures, two.next_due),
            (9, parked),
            "another contact is untouched"
        );
    }

    /// G5: an app submit (driven by a machine, not a user) makes the
    /// contact's objects due and forgets blocked routes, but the backoff
    /// stands.
    #[test]
    fn an_app_submit_kick_makes_due_but_keeps_the_backoff() {
        let t0 = Instant::now();
        let wall = 1_000_000_000u64;
        let peer = [0xB0; 32];
        let mut inner = Inner::default();
        inner.merge(vec![sched_row(1, 0xB0, wall + DAY)], 0, t0, wall);
        {
            let e = inner.entries.get_mut(&[1; 32]).unwrap();
            e.failures = 9;
            e.next_due = t0 + RETRY_MAX;
            e.blocked_routes = vec![lan("127.0.0.1:9")];
        }
        inner.kick_restart(Some(&peer), true, false, t0);
        let e = &inner.entries[&[1; 32]];
        assert_eq!((e.failures, e.next_due), (9, t0));
        assert!(e.blocked_routes.is_empty(), "explicit: blocks forgotten");
        let wait = fail_at(&mut inner, &peer, [1; 32], t0, wall);
        assert!(wait >= Duration::from_secs(300), "{wait:?}");
    }

    /// G5: a user's kick while the contact's attempt is in flight resets the
    /// schedule's copy in place: that attempt's failure counts as the first.
    #[test]
    fn an_explicit_kick_during_flight_counts_its_failure_as_the_first() {
        let t0 = Instant::now();
        let wall = 1_000_000_000u64;
        let peer = [0xB0; 32];
        let mut inner = Inner::default();
        inner.merge(vec![sched_row(1, 0xB0, wall + DAY)], 0, t0, wall);
        inner.entries.get_mut(&[1; 32]).unwrap().failures = 8;
        assert_eq!(inner.take_due(t0).len(), 1, "in flight");
        inner.kick_restart(Some(&peer), true, true, t0 + Duration::from_secs(3));
        let end = t0 + Duration::from_secs(6);
        inner.apply(&peer, report_for([1; 32], unreachable()), end, wall);
        let e = &inner.entries[&[1; 32]];
        assert_eq!((e.failures, e.next_due), (1, end), "the first, due again");
        let wait = fail_at(&mut inner, &peer, [1; 32], end, wall);
        assert!(wait <= Duration::from_secs(15), "{wait:?}");
    }

    /// G5: a verified ACK on the worker's own dial starts the rest of that
    /// contact's queue over (a sibling written without an ACK in the same
    /// dial included, before its own result) and makes it due now, owed ACKs
    /// too. An ACK that came another way (no carrier) restarts nothing, and
    /// another contact is never touched.
    #[test]
    fn a_verified_ack_starts_the_rest_of_the_peers_backoff_over() {
        let wall = 1_000_000_000u64;
        let peer = [0xB0; 32];
        for verified in [true, false] {
            let t0 = Instant::now();
            let parked = t0 + RETRY_MAX;
            let mut inner = Inner::default();
            let mut rows = vec![
                sched_row(1, 0xB0, wall + DAY),
                sched_row(2, 0xB0, wall + DAY),
                sched_row(3, 0xB0, wall + DAY),
                sched_row(4, 0xB1, wall + DAY),
            ];
            for (i, row) in rows.iter_mut().enumerate().take(3) {
                row.created_at_ms = 1_000 * (i as u64 + 1);
                row.ratchet_index = i as u32;
            }
            inner.merge(rows, 0, t0, wall);
            for e in inner.entries.values_mut() {
                e.failures = 9;
            }
            inner.entries.get_mut(&[3; 32]).unwrap().next_due = parked;
            inner.entries.get_mut(&[4; 32]).unwrap().next_due = parked;
            inner
                .unsent_acks
                .insert([0xA0; 32], owed(peer, 7, parked, wall + DAY));
            let due = inner.take_due(t0);
            assert_eq!(due.len(), 1);
            let taken: Vec<[u8; 32]> = due[0].entries.iter().map(|e| e.object_digest).collect();
            assert_eq!(taken, vec![[1; 32], [2; 32]]);
            assert!(due[0].acks.is_empty());

            let carrier = verified.then_some(OutboxCarrier::Lan);
            let mut report = report_for([1; 32], Outcome::Delivered { carrier });
            report.attempted.push([2; 32]);
            report.outcomes.insert(
                [2; 32],
                Outcome::Sent {
                    carrier: Some(OutboxCarrier::Lan),
                    code: code::NO_ACK_YET,
                },
            );
            inner.apply(&peer, report, t0, wall);
            assert!(inner.done.iter().any(|e| e.object_digest == [1; 32]));
            let two = &inner.entries[&[2; 32]];
            let three = &inner.entries[&[3; 32]];
            let ack = &inner.unsent_acks[&[0xA0; 32]];
            if verified {
                assert_eq!(two.failures, 1, "its own result counts from 0");
                let wait = two.next_due - t0;
                assert!(
                    (MIN_RETRY..=Duration::from_millis(7_500)).contains(&wait),
                    "{wait:?}"
                );
                assert_eq!((three.failures, three.next_due), (0, t0));
                assert_eq!((ack.failures, ack.next_due), (0, t0));
            } else {
                assert_eq!(two.failures, 10);
                assert_eq!((three.failures, three.next_due), (9, parked));
                assert_eq!((ack.failures, ack.next_due), (7, parked));
            }
            let four = &inner.entries[&[4; 32]];
            assert_eq!(
                (four.failures, four.next_due),
                (9, parked),
                "another contact is untouched"
            );
        }
    }

    /// G5 hot-loop guard: a write without an ACK (Sent / NO_ACK_YET) shows
    /// nothing about the contact answering, so it never starts anything over:
    /// two objects that keep being written cannot restart each other.
    #[test]
    fn written_without_an_ack_never_restarts_anything() {
        let t0 = Instant::now();
        let wall = 1_000_000_000u64;
        let peer = [0xB0; 32];
        let mut inner = Inner::default();
        let mut rows = vec![
            sched_row(1, 0xB0, wall + DAY),
            sched_row(2, 0xB0, wall + DAY),
        ];
        rows[1].created_at_ms = 1_000;
        rows[1].ratchet_index = 1;
        inner.merge(rows, 0, t0, wall);
        let mut now = t0;
        let mut wait = Duration::ZERO;
        for round in 1..=12u32 {
            // At the later of the two timers both are due: one dial, both
            // written, neither ACKed.
            now = now.max(inner.entries.values().map(|e| e.next_due).max().unwrap());
            let due = inner.take_due(now);
            assert_eq!((due.len(), due[0].entries.len()), (1, 2));
            let mut report = PeerReport::default();
            for e in &due[0].entries {
                report.attempted.push(e.object_digest);
                report.outcomes.insert(
                    e.object_digest,
                    Outcome::Sent {
                        carrier: Some(OutboxCarrier::Lan),
                        code: code::NO_ACK_YET,
                    },
                );
            }
            inner.apply(&peer, report, now, wall);
            for e in inner.entries.values() {
                assert_eq!(e.failures, round, "only grows");
            }
            wait = inner
                .entries
                .values()
                .map(|e| e.next_due - now)
                .min()
                .unwrap();
        }
        assert!(wait >= Duration::from_secs(300), "{wait:?}");
    }

    /// G5: an inbound link from a contact starts its backoff over at most
    /// once per PEER_RESTART_COOLDOWN, and only a restart that cleared
    /// something uses that up.
    #[test]
    fn an_inbound_link_restarts_at_most_once_per_cooldown() {
        let t0 = Instant::now();
        let wall = 1_000_000_000u64;
        let t61 = t0 + Duration::from_secs(61);
        let bob = [0xB0; 32];
        let mut inner = Inner::default();
        inner.merge(vec![sched_row(1, 0xB0, wall + DAY)], 0, t0, wall);
        {
            let e = inner.entries.get_mut(&[1; 32]).unwrap();
            e.failures = 9;
            e.next_due = t0 + RETRY_MAX;
        }
        assert!(inner.peer_seen_now(&bob, t0));
        let e = &inner.entries[&[1; 32]];
        assert_eq!((e.failures, e.next_due), (0, t0));
        let mut at = t0;
        for _ in 0..3 {
            at += fail_at(&mut inner, &bob, [1; 32], at, wall);
        }
        assert_eq!(inner.entries[&[1; 32]].failures, 3);
        // Inside the dial-back window what waits still goes (E1), at most
        // once per MIN_RETRY, the backoff kept while the restart cools down.
        assert!(!inner.peer_seen_now(&bob, t0 + MIN_RETRY - Duration::from_secs(1)));
        assert!(inner.peer_seen_now(&bob, t0 + Duration::from_secs(30)));
        assert_eq!(inner.entries[&[1; 32]].failures, 3, "cooling down");
        assert!(inner.peer_seen_now(&bob, t61));
        let e = &inner.entries[&[1; 32]];
        assert!(e.next_due <= t61, "due now");
        assert_eq!(e.failures, 3, "cooling down: the backoff stands");
        assert!(inner.peer_seen_now(&bob, t0 + PEER_RESTART_COOLDOWN + Duration::from_secs(1)));
        assert_eq!(inner.entries[&[1; 32]].failures, 0, "cooled down");

        // A link while nothing had failed does not use up the cooldown.
        let mut inner = Inner::default();
        inner.merge(vec![sched_row(1, 0xB0, wall + DAY)], 0, t0, wall);
        assert!(inner.peer_seen_now(&bob, t0));
        assert!(!inner.last_peer_restart.contains_key(&bob));
        let mut at = t0;
        for _ in 0..2 {
            at += fail_at(&mut inner, &bob, [1; 32], at, wall);
        }
        assert_eq!(inner.entries[&[1; 32]].failures, 2);
        assert!(inner.peer_seen_now(&bob, t61));
        assert_eq!(inner.entries[&[1; 32]].failures, 0);
    }

    /// Phase 3 (P3.22, s30w): a changed custody offer makes what waits for
    /// every contact due at once (a custodian may take it now), at most once
    /// per MIN_RETRY, and starts no backoff over.
    #[test]
    fn custodians_changed_makes_everything_due_once_per_min_retry_keeping_the_backoff() {
        let t0 = Instant::now();
        let wall = 1_000_000_000u64;
        let secs = Duration::from_secs;
        let mut inner = Inner::default();
        inner.merge(
            vec![
                sched_row(1, 0xB0, wall + DAY),
                sched_row(2, 0xC0, wall + DAY),
            ],
            0,
            t0,
            wall,
        );
        let park = |inner: &mut Inner, at: Instant| {
            for e in inner.entries.values_mut() {
                e.failures = 5;
                e.next_due = at + RETRY_MAX;
            }
        };
        park(&mut inner, t0);
        assert!(inner.custodians_changed_now(t0));
        for e in inner.entries.values() {
            assert!(e.next_due <= t0, "due now");
            assert_eq!(e.failures, 5, "the backoff is kept");
        }
        park(&mut inner, t0);
        // Review D-7: a second change inside MIN_RETRY is not dropped. It
        // schedules one kick for t0 + MIN_RETRY (the worker sleeps until
        // then at the latest); a third adds nothing.
        let soon = t0 + secs(2);
        assert!(inner.custodians_changed_now(soon));
        assert!(!inner.custodians_changed_now(soon + secs(1)));
        assert!(inner.entries.values().all(|e| e.next_due > t0 + MIN_RETRY));
        assert_eq!(inner.next_due_in(soon), Some(MIN_RETRY - secs(2)));
        assert!(!inner.fire_custody_kick(t0 + MIN_RETRY - secs(1)));
        assert!(inner.fire_custody_kick(t0 + MIN_RETRY));
        for e in inner.entries.values() {
            assert!(e.next_due <= t0 + MIN_RETRY, "due at the trailing kick");
            assert_eq!(e.failures, 5, "the backoff is kept");
        }
        assert!(!inner.fire_custody_kick(t0 + MIN_RETRY + secs(1)), "once");
        // The trailing kick counts: the next change inside MIN_RETRY of it
        // waits again, one after that kicks at once.
        park(&mut inner, t0 + MIN_RETRY);
        assert!(inner.custodians_changed_now(t0 + MIN_RETRY + secs(1)));
        assert!(inner
            .entries
            .values()
            .all(|e| e.next_due > t0 + 2 * MIN_RETRY));
        assert!(inner.custodians_changed_now(t0 + 3 * MIN_RETRY));
        assert!(inner
            .entries
            .values()
            .all(|e| e.next_due <= t0 + 3 * MIN_RETRY));
        assert_eq!(
            inner.custody_kick_pending, None,
            "the kick at once took its place"
        );
        // Without a worker nothing happens (and nothing panics).
        custodians_changed();
    }

    /// RRH1: a contact's new routes make its objects due at once, inside
    /// the dial-back window an inbound link of its own just used too, but
    /// at most once per MIN_RETRY; they use up the dial-back window, and the
    /// backoff restart shares PEER_RESTART_COOLDOWN with peer_seen.
    #[test]
    fn peer_routes_changed_kicks_inside_the_dialback_window_at_most_once_per_min_retry() {
        let t0 = Instant::now();
        let wall = 1_000_000_000u64;
        let secs = Duration::from_secs;
        let bob = [0xB0; 32];
        let parked = |inner: &mut Inner, failures: u32, at: Instant| {
            let e = inner.entries.get_mut(&[1; 32]).unwrap();
            e.failures = failures;
            e.next_due = at + RETRY_MAX;
        };
        let mut inner = Inner::default();
        inner.merge(vec![sched_row(1, 0xB0, wall + DAY)], 0, t0, wall);

        // An inbound link used the dial-back window and the restart.
        parked(&mut inner, 9, t0);
        assert!(inner.peer_seen_now(&bob, t0));
        assert_eq!(inner.entries[&[1; 32]].failures, 0);
        parked(&mut inner, 4, t0);
        assert!(!inner.peer_seen_now(&bob, t0 + secs(1)), "dial-back window");

        // New routes a second later: due at once all the same, the backoff
        // kept (the restart is cooling down).
        let t1 = t0 + secs(1);
        assert!(inner.routes_changed_now(&bob, t1));
        let e = &inner.entries[&[1; 32]];
        assert!(e.next_due <= t1, "due now");
        assert_eq!(e.failures, 4, "the cooldown peer_seen started");

        // Once per MIN_RETRY.
        parked(&mut inner, 4, t1);
        assert!(!inner.routes_changed_now(&bob, t1 + MIN_RETRY - secs(1)));
        assert!(inner.entries[&[1; 32]].next_due > t1 + MIN_RETRY);
        assert!(inner.routes_changed_now(&bob, t1 + MIN_RETRY));
        assert!(inner.entries[&[1; 32]].next_due <= t1 + MIN_RETRY);
        // It used up the dial-back window: an inbound link right after
        // schedules nothing more.
        assert!(!inner.peer_seen_now(&bob, t1 + MIN_RETRY + secs(1)));

        // Past the cooldown it restarts the backoff, and then peer_seen is
        // the one cooling down.
        let t2 = t0 + PEER_RESTART_COOLDOWN + secs(1);
        parked(&mut inner, 6, t2);
        assert!(inner.routes_changed_now(&bob, t2));
        assert_eq!(inner.entries[&[1; 32]].failures, 0, "restarted");
        parked(&mut inner, 3, t2);
        assert!(inner.peer_seen_now(&bob, t2 + DIALBACK_INTERVAL));
        assert_eq!(inner.entries[&[1; 32]].failures, 3, "the shared cooldown");

        // In flight: due again as soon as the attempt ends.
        let mut inner = Inner::default();
        inner.merge(vec![sched_row(1, 0xB0, wall + DAY)], 0, t0, wall);
        inner.in_flight.insert(bob);
        assert!(inner.routes_changed_now(&bob, t0));
        assert!(inner.kicked.contains(&bob));
        // Without a worker nothing happens (and nothing panics).
        peer_routes_changed(&[0xEE; 32]);
    }

    /// E1: a LAN try that failed as a dial does is the object's last error
    /// over a p2p dial after it whose reason only says the contact's direct
    /// addresses did not answer (or that this computer has no route), as
    /// `raven send` says it; any other p2p reason, and any other LAN answer,
    /// leave the p2p dial's.
    #[test]
    fn a_lan_failure_stays_the_last_error_over_a_direct_failed_p2p_dial() {
        let lan = |code| Some((OutboxCarrier::Lan, code));
        let p2p = "p2p_dial /p2p/12D3KooWx: cannot reach the contact; reach: why=";
        for why in ["direct_failed", "no_route"] {
            let detail = format!("{p2p}{why}");
            for code in [code::NOT_LISTENING, code::NOT_REACHABLE, code::CLOSED_EARLY] {
                assert!(
                    lan_failure_says_more(lan(code), OutboxCarrier::P2p, &detail, false),
                    "{code} {why}"
                );
            }
            assert!(!lan_failure_says_more(
                lan(code::PEER_REFUSED),
                OutboxCarrier::P2p,
                &detail,
                false
            ));
            assert!(!lan_failure_says_more(
                Some((OutboxCarrier::Internet, code::NOT_REACHABLE)),
                OutboxCarrier::P2p,
                &detail,
                false
            ));
            assert!(!lan_failure_says_more(
                None,
                OutboxCarrier::P2p,
                &detail,
                false
            ));
            assert!(!lan_failure_says_more(
                lan(code::NOT_LISTENING),
                OutboxCarrier::Internet,
                &detail,
                false
            ));
        }
        for why in ["contact_offline", "both_nat", "relay_asleep"] {
            assert!(!lan_failure_says_more(
                lan(code::NOT_LISTENING),
                OutboxCarrier::P2p,
                &format!("{p2p}{why}"),
                false
            ));
        }
        assert!(!lan_failure_says_more(
            lan(code::NOT_LISTENING),
            OutboxCarrier::P2p,
            "p2p_dial: no reason block",
            false
        ));
        // E2 r9 #4: the friend's saved address is on this computer's own
        // network: its LAN answer beats every p2p reason (never NAT advice),
        // and a refusal there beats Tor's failure too.
        for why in [
            "contact_offline",
            "both_nat",
            "relay_asleep",
            "direct_failed",
        ] {
            for code in [code::NOT_LISTENING, code::NOT_REACHABLE, code::CLOSED_EARLY] {
                assert!(
                    lan_failure_says_more(
                        lan(code),
                        OutboxCarrier::P2p,
                        &format!("{p2p}{why}"),
                        true
                    ),
                    "{code} {why}"
                );
            }
        }
        let tor = "onion_dial: ONION_UNREACHABLE: the contact's onion service did not answer";
        let on_net = |code, carrier| lan_failure_says_more(lan(code), carrier, tor, true);
        assert!(on_net(code::NOT_LISTENING, OutboxCarrier::Onion));
        assert!(!on_net(code::NOT_REACHABLE, OutboxCarrier::Onion));
        assert!(!on_net(code::PEER_REFUSED, OutboxCarrier::P2p));
        assert!(!lan_failure_says_more(
            lan(code::NOT_LISTENING),
            OutboxCarrier::Onion,
            tor,
            false
        ));
        assert!(!dial_on_our_network("lan-name.local:7420"));
    }

    /// E1: a sign that a contact is back (a dial of ours of any purpose
    /// reached it, or its LAN address answered one; its inbound link inside
    /// the dial-back window) makes what waits for it due at once, its
    /// backoff started over, at most once per MIN_RETRY; not while its own
    /// attempt is in flight, nor when nothing waits for it.
    #[test]
    fn a_sign_that_a_contact_is_back_sends_what_waits_at_once() {
        let t0 = Instant::now();
        let wall = 1_000_000_000u64;
        let secs = Duration::from_secs;
        let (bob, carol) = ([0xB0; 32], [0xC0; 32]);
        let mut inner = Inner::default();
        inner.merge(vec![sched_row(1, 0xB0, wall + DAY)], 0, t0, wall);
        let parked = |inner: &mut Inner, at: Instant| {
            let e = inner.entries.get_mut(&[1; 32]).unwrap();
            e.failures = 8;
            e.next_due = at + RETRY_MAX;
        };
        parked(&mut inner, t0);
        assert!(inner.back_now(&bob, t0));
        let e = &inner.entries[&[1; 32]];
        assert_eq!((e.failures, e.next_due), (0, t0), "due now, backoff over");
        parked(&mut inner, t0);
        assert!(!inner.back_now(&bob, t0 + MIN_RETRY - secs(1)));
        assert!(inner.entries[&[1; 32]].next_due > t0 + MIN_RETRY);
        assert!(inner.back_now(&bob, t0 + MIN_RETRY));
        let e = &inner.entries[&[1; 32]];
        assert!(e.next_due <= t0 + MIN_RETRY);
        assert_eq!(e.failures, 8, "the restart cools down");
        // Nothing waits for Carol: nothing happens.
        assert!(!inner.back_now(&carol, t0));
        // An ACK owed to Carol waits: it goes now.
        inner
            .unsent_acks
            .insert([7; 32], owed(carol, 4, t0 + RETRY_MAX, wall + DAY));
        assert!(inner.back_now(&carol, t0));
        assert!(inner.unsent_acks[&[7; 32]].next_due <= t0);
        // Its own attempt in flight: that attempt is what reached it.
        let later = t0 + 4 * MIN_RETRY;
        parked(&mut inner, later);
        inner.in_flight.insert(bob);
        assert!(!inner.back_now(&bob, later));
        assert!(!inner.kicked.contains(&bob));
        assert!(inner.entries[&[1; 32]].next_due > later);
        // Without a worker nothing happens (and nothing panics).
        peer_back(&[0xEE; 32]);
    }

    /// E1: an object for a contact with an authenticated LAN link in the
    /// last ten minutes that could not be reached waits at most
    /// LAN_SEEN_RETRY, whatever its backoff; without one, its backoff.
    #[test]
    fn a_contact_seen_on_the_lan_lately_is_tried_again_within_15_s() {
        let t0 = Instant::now();
        let wall = 1_000_000_000u64;
        let bob = [0xB0; 32];
        for (lately, failures) in [(true, 9), (true, 0), (false, 9)] {
            let mut inner = Inner::default();
            inner.merge(vec![sched_row(1, 0xB0, wall + DAY)], 0, t0, wall);
            inner.entries.get_mut(&[1; 32]).unwrap().failures = failures;
            let due = inner.take_due(t0);
            assert!(due.iter().any(|w| w.peer == bob));
            let mut report = report_for([1; 32], unreachable());
            report.lan_seen_lately = lately;
            inner.apply(&bob, report, t0, wall);
            let wait = inner.entries[&[1; 32]].next_due - t0;
            if lately {
                assert!(wait <= LAN_SEEN_RETRY, "{failures}: {wait:?}");
            } else {
                assert!(wait > LAN_SEEN_RETRY, "{wait:?}");
            }
        }
    }

    /// E1: each delivered object keeps when it was delivered (two messages
    /// on one dial both say so in `raven outbox list`).
    #[test]
    fn a_delivered_object_keeps_when_it_was_delivered() {
        let t0 = Instant::now();
        let wall = 1_000_000_000u64;
        let bob = [0xB0; 32];
        let mut inner = Inner::default();
        inner.merge(
            vec![
                sched_row(1, 0xB0, wall + DAY),
                sched_row(2, 0xB0, wall + DAY),
            ],
            0,
            t0,
            wall,
        );
        let _ = inner.take_due(t0);
        let mut report = PeerReport {
            attempted: vec![[1; 32], [2; 32]],
            ..PeerReport::default()
        };
        for d in [[1; 32], [2; 32]] {
            report.outcomes.insert(
                d,
                Outcome::Delivered {
                    carrier: Some(OutboxCarrier::Lan),
                },
            );
        }
        inner.apply(&bob, report, t0, wall + 5);
        let items: Vec<OutboxItem> = inner.done.iter().map(|e| e.item(t0, wall + 9)).collect();
        assert_eq!(items.len(), 2);
        for item in items {
            assert_eq!(
                (item.state.as_str(), item.delivered_at_ms),
                ("delivered", wall + 5)
            );
        }
    }

    /// G5: a restart touches the failure count only. Refusals (the
    /// SUPERSEDED rule), attempts, the last error (the once-only PEER_RESET
    /// rule) and blocked routes stay; only an explicit kick forgets blocked
    /// routes, as before.
    #[test]
    fn restart_leaves_refusals_blocks_and_attempts_alone() {
        let t0 = Instant::now();
        let wall = 1_000_000_000u64;
        let peer = [0xB0; 32];
        let mut inner = Inner::default();
        let mut rows = vec![
            sched_row(1, 0xB0, wall + DAY),
            sched_row(2, 0xB0, wall + DAY),
        ];
        rows[1].created_at_ms = 1_000;
        inner.merge(rows, 0, t0, wall);
        {
            let e = inner.entries.get_mut(&[1; 32]).unwrap();
            e.refusals = 2;
            e.first_refusal = Some(t0);
            e.blocked_routes = vec![lan("127.0.0.1:9")];
            e.blocked_code = code::WRONG_IDENTITY;
            e.attempts = 5;
            e.last_error = code::PEER_RESET;
            e.state = EntryState::Held;
        }
        let kept = |inner: &Inner| {
            let e = &inner.entries[&[1; 32]];
            (
                e.refusals,
                e.first_refusal,
                e.attempts,
                e.last_error,
                e.state,
            )
        };
        let blocks = |inner: &Inner| {
            let e = &inner.entries[&[1; 32]];
            (e.blocked_routes.clone(), e.blocked_code)
        };
        let before = (kept(&inner), blocks(&inner));
        let set_failures =
            |inner: &mut Inner| inner.entries.get_mut(&[1; 32]).unwrap().failures = 9;

        // An inbound link.
        set_failures(&mut inner);
        assert!(inner.peer_seen_now(&peer, t0));
        assert_eq!(inner.entries[&[1; 32]].failures, 0);
        assert_eq!((kept(&inner), blocks(&inner)), before);

        // A verified ACK for its sibling.
        set_failures(&mut inner);
        inner.in_flight.insert(peer);
        inner.apply(
            &peer,
            report_for(
                [2; 32],
                Outcome::Delivered {
                    carrier: Some(OutboxCarrier::Lan),
                },
            ),
            t0,
            wall,
        );
        assert_eq!(inner.entries[&[1; 32]].failures, 0);
        assert_eq!((kept(&inner), blocks(&inner)), before);

        // A user's kick: blocked routes go too, as before; the rest stays.
        set_failures(&mut inner);
        inner.kick_restart(Some(&peer), true, true, t0);
        assert_eq!(inner.entries[&[1; 32]].failures, 0);
        assert_eq!(kept(&inner), before.0);
        assert_eq!(blocks(&inner), (Vec::new(), ""));

        // PEER_RESET again right after a restart still backs off: the
        // immediate retry stays once only.
        assert_eq!(inner.take_due(t0).len(), 1);
        inner.apply(
            &peer,
            report_for([1; 32], Outcome::Held(code::PEER_RESET)),
            t0,
            wall,
        );
        let e = &inner.entries[&[1; 32]];
        assert_eq!(e.failures, 1);
        assert!(e.next_due >= t0 + MIN_RETRY, "backs off");
    }

    /// G1 + G5: a network change starts every contact's backoff over and
    /// makes each contact due within NETWORK_SPREAD, at one offset per contact
    /// (its objects share one dial), owed ACKs too, and re-reads the store.
    /// Blocked routes and refusals stay (the session-query pacing lives in
    /// `AttemptCtx`, which this never reaches).
    #[test]
    fn a_network_change_restarts_every_backoff_and_spreads_each_peer() {
        let t0 = Instant::now();
        let wall = 1_000_000_000u64;
        let parked = t0 + RETRY_MAX;
        let carol = [0xB1; 32];
        let mut inner = Inner::default();
        let mut rows = vec![
            sched_row(1, 0xB0, wall + DAY),
            sched_row(2, 0xB0, wall + DAY),
            sched_row(3, 0xB1, wall + DAY),
        ];
        rows[1].created_at_ms = 1_000;
        rows[1].ratchet_index = 1;
        inner.merge(rows, 0, t0, wall);
        for e in inner.entries.values_mut() {
            e.failures = 7;
            e.next_due = parked;
        }
        {
            let e = inner.entries.get_mut(&[3; 32]).unwrap();
            e.blocked_routes = vec![lan("127.0.0.1:9")];
            e.blocked_code = code::WRONG_IDENTITY;
            e.refusals = 2;
            e.first_refusal = Some(t0);
        }
        inner
            .unsent_acks
            .insert([0xA0; 32], owed([0xB2; 32], 5, parked, wall + DAY));
        inner.refresh = false;

        let t = t0 + Duration::from_secs(1);
        assert_eq!(inner.network_changed(t), 4, "3 objects and 1 owed ACK");
        assert!(inner.refresh, "the store is read again");
        let spread = t..=t + NETWORK_SPREAD;
        for e in inner.entries.values() {
            assert_eq!(e.failures, 0);
            assert!(spread.contains(&e.next_due), "{:?}", e.next_due - t);
        }
        assert_eq!(
            inner.entries[&[1; 32]].next_due, inner.entries[&[2; 32]].next_due,
            "one contact, one dial"
        );
        let ack = &inner.unsent_acks[&[0xA0; 32]];
        assert_eq!(ack.failures, 0);
        assert!(spread.contains(&ack.next_due), "{:?}", ack.next_due - t);
        let three = &inner.entries[&[3; 32]];
        assert_eq!(
            (
                three.blocked_routes.clone(),
                three.blocked_code,
                three.refusals,
                three.first_refusal
            ),
            (vec![lan("127.0.0.1:9")], code::WRONG_IDENTITY, 2, Some(t0)),
            "the contact's answers stay"
        );
        // The next failure waits the first step again, not up to 10 min.
        let at = three.next_due;
        let wait = fail_at(&mut inner, &carol, [3; 32], at, wall);
        assert!(
            (MIN_RETRY..=Duration::from_millis(7_500)).contains(&wait),
            "{wait:?}"
        );
    }

    /// G1 + G5: an attempt in flight when the network changed (started on the
    /// old network) counts its failure as the first and is due again as soon
    /// as it ends.
    #[test]
    fn a_network_change_reaches_an_attempt_in_flight() {
        let t0 = Instant::now();
        let wall = 1_000_000_000u64;
        let peer = [0xB0; 32];
        let mut inner = Inner::default();
        inner.merge(vec![sched_row(1, 0xB0, wall + DAY)], 0, t0, wall);
        inner.entries.get_mut(&[1; 32]).unwrap().failures = 9;
        assert_eq!(inner.take_due(t0).len(), 1, "in flight");
        assert_eq!(inner.network_changed(t0 + Duration::from_secs(3)), 1);
        let end = t0 + Duration::from_secs(6);
        inner.apply(&peer, report_for([1; 32], unreachable()), end, wall);
        let e = &inner.entries[&[1; 32]];
        assert_eq!((e.failures, e.next_due), (1, end), "the first, due again");
        let wait = fail_at(&mut inner, &peer, [1; 32], end, wall);
        assert!(wait <= Duration::from_secs(15), "{wait:?}");
    }

    /// Outside `raven-node service` there is no worker: netwatch's hook says
    /// so instead of counting anything.
    #[test]
    fn a_network_change_without_a_running_worker_is_none() {
        assert_eq!(network_changed(), None);
    }

    /// Cutoff pack F5's schedule: Bob (0xB0, object 1) and Dave (0xB2, an
    /// owed ACK) wait on long backoffs and are LAN-wakeable; Carol (0xB1,
    /// object 3) is the contact that answers; Eve (0xB3, object 4) waits
    /// too, but her last attempt found no LAN route or no noise pin.
    fn siblings(t0: Instant, wall: u64) -> Inner {
        let parked = t0 + RETRY_MAX;
        let mut inner = Inner {
            sibling_wake: true,
            ..Inner::default()
        };
        inner.merge(
            vec![
                sched_row(1, 0xB0, wall + DAY),
                sched_row(3, 0xB1, wall + DAY),
                sched_row(4, 0xB3, wall + DAY),
            ],
            0,
            t0,
            wall,
        );
        for e in inner.entries.values_mut() {
            e.failures = 7;
            e.next_due = parked;
        }
        inner
            .unsent_acks
            .insert([0xA0; 32], owed([0xB2; 32], 5, parked, wall + DAY));
        inner
            .lan_wakeable
            .extend([[0xB0; 32], [0xB1; 32], [0xB2; 32]]);
        inner.refresh = false;
        inner
    }

    /// Phase 3 (the LAN beacon, step 10): every contact with a live object
    /// or an owed ACK once, the one waiting longest first, at most `limit`;
    /// a finished object makes its contact wait for nothing.
    #[test]
    fn waiting_peers_bounded_and_oldest_first() {
        let t0 = Instant::now();
        let wall = 1_000_000_000u64;
        let row = |d: u8, peer: u8, created_at_ms: u64| ScanRow {
            created_at_ms,
            ..sched_row(d, peer, wall + DAY)
        };
        let mut inner = Inner::default();
        assert!(inner.waiting_peers(64).is_empty());
        inner.merge(
            vec![
                row(1, 0xB0, wall - 5_000),
                row(2, 0xB1, wall - 9_000),
                // Bob's older object decides his place.
                row(3, 0xB0, wall - 20_000),
                row(4, 0xB3, wall - 1_000),
            ],
            0,
            t0,
            wall,
        );
        // An ACK owed to 0xB2 since it was sealed 30 s ago (a day's
        // lifetime).
        inner
            .unsent_acks
            .insert([0xA0; 32], owed([0xB2; 32], 0, t0, wall - 30_000 + DAY));
        let (b0, b1, b2, b3) = ([0xB0; 32], [0xB1; 32], [0xB2; 32], [0xB3; 32]);
        assert_eq!(inner.waiting_peers(64), vec![b2, b0, b1, b3]);
        assert_eq!(inner.waiting_peers(2), vec![b2, b0]);
        assert!(inner.waiting_peers(0).is_empty());
        inner.entries.get_mut(&[4; 32]).unwrap().state = EntryState::Delivered;
        assert_eq!(inner.waiting_peers(64), vec![b2, b0, b1]);
    }

    /// (failures, next due) of object `d`.
    fn sched_of(inner: &Inner, d: u8) -> (u32, Instant) {
        let e = &inner.entries[&[d; 32]];
        (e.failures, e.next_due)
    }

    fn lan_delivered() -> Outcome {
        Outcome::Delivered {
            carrier: Some(OutboxCarrier::Lan),
        }
    }

    /// `digest` delivered over a LAN dial to a local, non-loopback address:
    /// the attempt's proof of this network.
    fn lan_proof(digest: [u8; 32]) -> PeerReport {
        PeerReport {
            lan_proved: true,
            ..report_for(digest, lan_delivered())
        }
    }

    /// F5: a verified ACK over a LAN dial of ours proves this network: every
    /// other LAN-wakeable contact with something waiting (objects or owed
    /// ACKs) starts its backoff over and is due within NETWORK_SPREAD; one
    /// that is not wakeable keeps its backoff.
    #[test]
    fn a_lan_delivery_makes_lan_siblings_due_within_5s() {
        let t0 = Instant::now();
        let wall = 1_000_000_000u64;
        let parked = t0 + RETRY_MAX;
        let (bob, carol) = ([0xB0; 32], [0xB1; 32]);
        let mut inner = siblings(t0, wall);
        let t = t0 + Duration::from_secs(1);
        inner.entries.get_mut(&[3; 32]).unwrap().next_due = t;
        assert_eq!(inner.take_due(t).len(), 1, "Carol's attempt");
        let woke = inner.apply(&carol, lan_proof([3; 32]), t, wall);
        assert_eq!(woke, 2, "Bob's object and Dave's owed ACK");
        assert!(!inner.entries.contains_key(&[3; 32]), "Carol's delivered");
        let spread = t..=t + NETWORK_SPREAD;
        let (failures, due) = sched_of(&inner, 1);
        assert_eq!(failures, 0, "a fresh backoff");
        assert!(spread.contains(&due), "{:?}", due - t);
        let ack = &inner.unsent_acks[&[0xA0; 32]];
        assert_eq!(ack.failures, 0);
        assert!(spread.contains(&ack.next_due), "{:?}", ack.next_due - t);
        assert_eq!(sched_of(&inner, 4), (7, parked), "Eve is not wakeable");
        assert!(inner.refresh, "the store is read again");
        assert_eq!(inner.last_sibling_wake, Some(t));
        // Bob's next failure waits the first step again, not up to 10 min.
        let wait = fail_at(&mut inner, &bob, [1; 32], due, wall);
        assert!(
            (MIN_RETRY..=Duration::from_millis(7_500)).contains(&wait),
            "{wait:?}"
        );
    }

    /// F5: a contact's authenticated inbound LAN link from a local address
    /// does the same (`lan_direct` calls `network_proven` next to
    /// `peer_seen`, which handles that contact itself). A sibling whose
    /// attempt is in flight is being tried already: not kicked again.
    #[test]
    fn an_inbound_link_does_too() {
        let t0 = Instant::now();
        let wall = 1_000_000_000u64;
        let parked = t0 + RETRY_MAX;
        let (carol, dave) = ([0xB1; 32], [0xB2; 32]);
        let mut inner = siblings(t0, wall);
        inner.in_flight.insert(dave);
        let t = t0 + Duration::from_secs(1);
        assert_eq!(inner.network_proven_now(&carol, t), 1, "Bob");
        let (failures, due) = sched_of(&inner, 1);
        assert_eq!(failures, 0);
        assert!((t..=t + NETWORK_SPREAD).contains(&due), "{:?}", due - t);
        assert_eq!(
            sched_of(&inner, 3),
            (7, parked),
            "Carol's own link does hers"
        );
        assert!(!inner.kicked.contains(&dave), "in flight");
        assert_eq!(inner.unsent_acks[&[0xA0; 32]].failures, 5);
        // Which inbound LAN links say something about the local network.
        for (source, proves) in [
            (Some("127.0.0.1"), true),
            (Some("192.168.1.20"), true),
            (Some("10.1.2.3"), true),
            (Some("172.20.10.2"), true),
            (Some("169.254.10.2"), true),
            (Some("fe80::1"), true),
            (Some("::ffff:192.168.1.20"), true),
            (Some("203.0.113.7"), false),
            (Some("2001:db8::7"), false),
            (Some("100.64.1.1"), false),
            (None, false),
        ] {
            let ip = source.map(|s| s.parse::<IpAddr>().unwrap());
            assert_eq!(inbound_proves_network(ip), proves, "{source:?}");
        }
        // The listener's call, next to its peer_seen; outside `raven-node
        // service` (no worker) it does nothing.
        let listener = include_str!("lan_direct.rs");
        let call = listener
            .find("crate::outbox::network_proven(&remote_ed)")
            .expect("lan_direct calls network_proven");
        let seen = listener
            .find("crate::outbox::peer_seen(&remote_ed)")
            .unwrap();
        assert!(call > seen && call - seen < 400, "next to peer_seen");
        network_proven(&carol);
    }

    /// F5's bounds: at most once per SIBLING_WAKE_MIN in all (a proof that
    /// woke nobody uses nothing up), and each contact's backoff starts over
    /// at most once per PEER_RESTART_COOLDOWN, shared with its own inbound
    /// link (a wake inside the cooldown only makes it due).
    #[test]
    fn cooldowns_bound_sibling_wakes() {
        let t0 = Instant::now();
        let wall = 1_000_000_000u64;
        let secs = Duration::from_secs;
        let (bob, carol) = ([0xB0; 32], [0xB1; 32]);
        let park = |inner: &mut Inner, failures: u32, at: Instant| {
            let e = inner.entries.get_mut(&[1; 32]).unwrap();
            e.failures = failures;
            e.next_due = at + RETRY_MAX;
        };

        let mut idle = Inner {
            sibling_wake: true,
            ..Inner::default()
        };
        assert_eq!(idle.network_proven_now(&carol, t0), 0);
        assert_eq!(idle.last_sibling_wake, None, "nothing used up");

        let mut inner = siblings(t0, wall);
        assert_eq!(inner.network_proven_now(&carol, t0), 2);
        assert_eq!(sched_of(&inner, 1).0, 0);

        // Within SIBLING_WAKE_MIN: nobody, whoever answers.
        park(&mut inner, 3, t0);
        let parked = sched_of(&inner, 1);
        assert_eq!(inner.network_proven_now(&carol, t0 + secs(30)), 0);
        assert_eq!(inner.network_proven_now(&[0xB3; 32], t0 + secs(59)), 0);
        assert_eq!(sched_of(&inner, 1), parked);

        // After it: due again, but the backoff stands (cooling down).
        let t61 = t0 + secs(61);
        assert_eq!(inner.network_proven_now(&carol, t61), 2);
        let (failures, due) = sched_of(&inner, 1);
        assert_eq!(failures, 3, "the per-contact cooldown");
        assert!(due <= t61 + NETWORK_SPREAD);
        // Bob's own inbound link shares that cooldown.
        park(&mut inner, 3, t61);
        assert!(inner.peer_seen_now(&bob, t61 + secs(1)));
        assert_eq!(sched_of(&inner, 1).0, 3, "shared with peer_seen");

        // Past the cooldown it starts over again.
        let later = t0 + PEER_RESTART_COOLDOWN + secs(1);
        park(&mut inner, 3, later);
        assert_eq!(inner.network_proven_now(&carol, later), 2);
        assert_eq!(sched_of(&inner, 1).0, 0, "cooled down");
    }

    /// F5: Internet and p2p deliveries say nothing about the local network,
    /// and neither does a LAN write without an ACK, an ACK that came another
    /// way (no carrier), a failed LAN dial, or a LAN delivery the attempt
    /// did not count as proof (to a public or loopback address:
    /// `only_a_lan_delivery_at_a_local_address_proves_the_network`).
    #[test]
    fn a_p2p_success_wakes_nobody() {
        let t0 = Instant::now();
        let wall = 1_000_000_000u64;
        let parked = t0 + RETRY_MAX;
        let carol = [0xB1; 32];
        for outcome in [
            Outcome::Delivered {
                carrier: Some(OutboxCarrier::P2p),
            },
            Outcome::Delivered {
                carrier: Some(OutboxCarrier::Internet),
            },
            Outcome::Delivered { carrier: None },
            Outcome::Sent {
                carrier: Some(OutboxCarrier::Lan),
                code: code::NO_ACK_YET,
            },
            unreachable(),
            lan_delivered(),
        ] {
            let mut inner = siblings(t0, wall);
            inner.entries.get_mut(&[3; 32]).unwrap().next_due = t0;
            assert_eq!(inner.take_due(t0).len(), 1);
            let woke = inner.apply(&carol, report_for([3; 32], outcome.clone()), t0, wall);
            assert_eq!(woke, 0, "{outcome:?}");
            assert_eq!(sched_of(&inner, 1), (7, parked), "{outcome:?}");
            let ack = &inner.unsent_acks[&[0xA0; 32]];
            assert_eq!((ack.failures, ack.next_due), (5, parked), "{outcome:?}");
            assert_eq!(inner.last_sibling_wake, None, "{outcome:?}");
        }
    }

    /// F5 (B-offline-lan-3): a verified ACK over a LAN dial proves this
    /// network only when the address dialled is on the local network and is
    /// not loopback. A verified contact's LAN route at a public address (a
    /// friend's home IP on a national network) or on this computer says
    /// nothing about it, and wakes nobody.
    #[test]
    fn only_a_lan_delivery_at_a_local_address_proves_the_network() {
        if !lab_backends() {
            return;
        }
        for (seed, dial, proves) in [
            (0xD1, "192.168.1.20:7420", true),
            (0xD3, "203.0.113.7:7420", false),
            (0xD5, "127.0.0.1:9", false),
        ] {
            let rig = Rig::new(seed);
            // Bob is verified and his LAN route was typed here: it may be
            // any address.
            contacts_typed(rig.a.path(), &rig.bob_pub, dial, "", true);
            rig.set(UP);
            rig.stage("hello", DAY);
            let report = rig.attempt();
            assert_eq!(only(&report), lan_delivered(), "{dial}");
            assert_eq!(rig.dialled(), [lan(dial)], "{dial}");
            assert_eq!(report.lan_proved, proves, "{dial}");
            // That report applied to a queue where three other LAN-wakeable
            // contacts wait: woken by a proof only.
            let t0 = Instant::now();
            let mut inner = siblings(t0, 1_000_000_000);
            let woke = inner.apply(&rig.bob_pub, report, t0, 1_000_000_000);
            assert_eq!(woke, if proves { 3 } else { 0 }, "{dial}");
            assert_eq!(inner.last_sibling_wake.is_some(), proves, "{dial}");
        }
    }

    /// F5: an inbound link over Internet direct or the p2p inner link calls
    /// `peer_seen` only (that contact's own objects), never
    /// `network_proven`; nor does a LAN link from a non-local address.
    #[test]
    fn an_internet_or_p2p_inbound_link_wakes_nobody() {
        let t0 = Instant::now();
        let wall = 1_000_000_000u64;
        let parked = t0 + RETRY_MAX;
        let carol = [0xB1; 32];
        let mut inner = siblings(t0, wall);
        assert!(inner.peer_seen_now(&carol, t0));
        assert_eq!(sched_of(&inner, 3), (0, t0), "Carol's own objects");
        assert_eq!(sched_of(&inner, 1), (7, parked), "Bob waits on");
        assert_eq!(inner.unsent_acks[&[0xA0; 32]].failures, 5);
        assert_eq!(inner.last_sibling_wake, None);
        for (name, source) in [
            ("internet_direct.rs", include_str!("internet_direct.rs")),
            ("p2p.rs", include_str!("p2p.rs")),
        ] {
            assert!(!source.contains("network_proven"), "{name}");
        }
        assert!(!inbound_proves_network(Some(
            "198.51.100.4".parse().unwrap()
        )));
    }

    /// F5 wakes only a contact with a noise pin (M0): with none, a dial made
    /// sooner at a stale address would hand over our identity. A LAN route
    /// is needed too; an unreadable pin store is no pin; what the contact's
    /// last attempt found decides (no plan: the last answer stands).
    #[test]
    fn a_contact_without_a_noise_pin_is_not_woken() {
        let dir = tempfile::tempdir().unwrap();
        let (bob, carol) = ([0xB0; 32], [0xB1; 32]);
        let key = raven_core::lan_noise_pin::PinKey::derive(&Identity::from_seed(&[0xC0; 32]));
        raven_core::lan_noise_pin::record(dir.path(), &key, &bob, &[7; 32]).unwrap();
        let with_lan = [lan("127.0.0.1:9"), inet("203.0.113.9:7422")];
        let inet_only = [inet("203.0.113.9:7422")];
        assert!(lan_wakeable(dir.path(), &bob, &with_lan, true));
        assert!(!lan_wakeable(dir.path(), &carol, &with_lan, true), "no pin");
        assert!(
            !lan_wakeable(dir.path(), &bob, &inet_only, true),
            "no LAN route"
        );
        assert!(!lan_wakeable(dir.path(), &bob, &[], true), "no contact");
        assert!(
            !lan_wakeable(dir.path(), &bob, &with_lan, false),
            "gate closed"
        );
        let broken = tempfile::tempdir().unwrap();
        std::fs::create_dir(
            broken
                .path()
                .join(raven_core::lan_noise_pin::NOISE_PIN_FILE),
        )
        .unwrap();
        assert!(
            !lan_wakeable(broken.path(), &bob, &with_lan, true),
            "unreadable"
        );

        // Bob's last attempt found no pin: a proof passes him by.
        let t0 = Instant::now();
        let wall = 1_000_000_000u64;
        let mut inner = siblings(t0, wall);
        inner.entries.get_mut(&[1; 32]).unwrap().next_due = t0;
        assert_eq!(inner.take_due(t0).len(), 1);
        let mut report = report_for([1; 32], unreachable());
        report.lan_wakeable = Some(false);
        inner.apply(&bob, report, t0, wall);
        assert!(!inner.lan_wakeable.contains(&bob));
        let before = sched_of(&inner, 1);
        let t = t0 + Duration::from_secs(1);
        assert_eq!(inner.network_proven_now(&carol, t), 1, "Dave only");
        assert_eq!(sched_of(&inner, 1), before);
        // An attempt that made no plan keeps the last answer; one that
        // found a pin again makes him wakeable.
        for (said, wakeable) in [(None, false), (Some(true), true), (None, true)] {
            let at = sched_of(&inner, 1).1;
            assert!(inner.take_due(at).iter().any(|w| w.peer == bob));
            let mut report = report_for([1; 32], unreachable());
            report.lan_wakeable = said;
            inner.apply(&bob, report, at, wall);
            assert_eq!(inner.lan_wakeable.contains(&bob), wakeable, "{said:?}");
        }
    }

    /// F5 with its gate closed (the worker read `sibling_wake_live` false at
    /// start, as every release build does until CP.16): a LAN delivery and
    /// an inbound link wake nobody else, exactly as before.
    #[test]
    fn gate_closed_is_today() {
        let t0 = Instant::now();
        let wall = 1_000_000_000u64;
        let parked = t0 + RETRY_MAX;
        let carol = [0xB1; 32];
        let mut inner = siblings(t0, wall);
        inner.sibling_wake = false;
        inner.entries.get_mut(&[3; 32]).unwrap().next_due = t0;
        assert_eq!(inner.take_due(t0).len(), 1);
        assert_eq!(inner.apply(&carol, lan_proof([3; 32]), t0, wall), 0);
        assert_eq!(inner.network_proven_now(&carol, t0), 0);
        assert_eq!(sched_of(&inner, 1), (7, parked));
        assert_eq!(sched_of(&inner, 4), (7, parked));
        let ack = &inner.unsent_acks[&[0xA0; 32]];
        assert_eq!((ack.failures, ack.next_due), (5, parked));
        assert_eq!(inner.last_sibling_wake, None);
        assert!(!inner.refresh);
        assert!(
            !Inner::default().sibling_wake,
            "off until the worker reads the gate"
        );
    }

    /// D(a): the schedule is monotonic: a wall-clock step either way neither
    /// stalls nor rushes a retry.
    #[test]
    fn a_wall_clock_step_does_not_move_the_schedule() {
        let t0 = Instant::now();
        let wall = 1_000_000_000_000u64;
        for stepped in [wall - 3 * 3_600_000, wall + 3 * 3_600_000] {
            let mut e = Entry::from_row(&sched_row(1, 0xB0, wall + DAY), t0);
            apply_outcome(&mut e, unreachable(), t0, stepped);
            let wait = e.next_due - t0;
            assert!(
                (MIN_RETRY..=Duration::from_millis(7_500)).contains(&wait),
                "{wait:?}"
            );
        }
        // The IPC view shows the next try relative to the wall clock now.
        let mut e = Entry::from_row(&sched_row(1, 0xB0, wall + DAY), t0);
        e.next_due = t0 + Duration::from_secs(40);
        assert_eq!(e.item(t0, wall).next_attempt_ms, wall + 40_000);
    }

    /// Cutoff pack CP.6: an expired message that no carrier ever wrote (and
    /// no friend holds) says it never left this computer; one that was
    /// written, refused after reading, or deposited does not, and neither
    /// does one still waiting.
    #[test]
    fn an_expired_row_says_whether_it_never_left_this_computer() {
        let t0 = Instant::now();
        let wall = 1_000_000_000_000u64;
        let expire = |mut e: Entry| {
            apply_outcome(&mut e, Outcome::Expired, t0, wall);
            e.item(t0, wall).never_sent
        };
        let queued = || Entry::from_row(&sched_row(1, 0xB0, wall + DAY), t0);
        let mut waiting = queued();
        apply_outcome(&mut waiting, unreachable(), t0, wall);
        assert!(!waiting.item(t0, wall).never_sent, "not while it waits");
        assert!(expire(waiting), "dials failed: it never left");
        let refused = Outcome::Unreachable {
            carrier: Some(OutboxCarrier::Lan),
            code: code::PEER_REFUSED,
        };
        for left in [
            Outcome::Sent {
                carrier: Some(OutboxCarrier::Lan),
                code: code::NO_ACK_YET,
            },
            refused,
            Outcome::Deposited { held: 1 },
        ] {
            let mut e = queued();
            apply_outcome(&mut e, left.clone(), t0, wall);
            assert!(!expire(e), "{left:?}");
        }
        // Written before this worker saw it (the store holds it as sent).
        let mut sent = sched_row(2, 0xB0, wall + DAY);
        sent.state = EntryState::Sent;
        assert!(!expire(Entry::from_row(&sent, t0)));
        // A scan that finds a tracked row written meanwhile clears it.
        let mut inner = Inner::default();
        inner.merge(vec![sched_row(3, 0xB0, wall + DAY)], 0, t0, wall);
        let mut again = sched_row(3, 0xB0, wall + DAY);
        again.state = EntryState::Sent;
        inner.merge(vec![again], 1, t0, wall);
        assert!(!inner.entries[&[3; 32]].never_sent);
    }

    /// Review C-time-deadlines-1: a prepared message the contact read and
    /// refused stays prepared in the store, yet after a restart (a fresh
    /// schedule from the store) its expiry does not say it never left this
    /// computer; one whose dials only failed still does.
    #[test]
    fn a_refused_prepared_message_is_written_across_a_restart() {
        if !lab_backends() {
            return;
        }
        // A fresh schedule from the store, then time runs out.
        let expired_after_restart = |rig: &Rig| {
            let (t0, wall) = (Instant::now(), now_ms());
            let mut inner = Inner::default();
            inner.merge(scan_store(rig.a.path()).unwrap(), 0, t0, wall);
            assert_eq!(inner.entries.len(), 1);
            let mut entry = inner.entries.values().next().unwrap().clone();
            apply_outcome(&mut entry, Outcome::Expired, t0, wall);
            entry.item(t0, wall).never_sent
        };
        let rig = Rig::new(0x61);
        let mid = rig.stage("read and refused", DAY);
        rig.set(REFUSE);
        assert_eq!(
            only(&rig.attempt()),
            Outcome::Unreachable {
                carrier: Some(OutboxCarrier::Lan),
                code: code::PEER_REFUSED
            }
        );
        let store = IndexedSessionStore::open(rig.a.path()).unwrap();
        assert_eq!(
            store.pending_endpoint_outbound().unwrap().len(),
            1,
            "still prepared"
        );
        assert!(
            raven_core::outbox::object_route_records(rig.a.path(), now_ms()).unwrap()[&mid].written
        );
        assert!(!expired_after_restart(&rig), "Bob read it");
        // Dials that only failed: it never left.
        let rig = Rig::new(0x63);
        rig.stage("never reached", DAY);
        assert_eq!(
            only(&rig.attempt()),
            Outcome::Unreachable {
                carrier: Some(OutboxCarrier::Lan),
                code: code::NOT_LISTENING
            }
        );
        assert!(expired_after_restart(&rig));
    }

    /// I: a scan that started before an attempt finished does not re-add what
    /// that attempt finished.
    #[test]
    fn a_stale_scan_does_not_re_add_a_finished_object() {
        let t0 = Instant::now();
        let wall = 1_000_000_000u64;
        let peer = [0xB0; 32];
        let mut inner = Inner::default();
        inner.merge(vec![sched_row(1, 0xB0, wall + DAY)], 0, t0, wall);
        assert_eq!(inner.take_due(t0).len(), 1);
        let seq = inner.scan_seq();
        let stale = vec![sched_row(1, 0xB0, wall + DAY)];
        inner.apply(
            &peer,
            report_for(
                [1; 32],
                Outcome::Delivered {
                    carrier: Some(OutboxCarrier::Lan),
                },
            ),
            t0,
            wall,
        );
        inner.merge(stale, seq, t0, wall);
        assert!(
            inner.entries.is_empty(),
            "the delivered object stays finished"
        );
        assert_eq!(inner.done.len(), 1);
        // A scan started after the attempt is merged as usual.
        let fresh = inner.scan_seq();
        inner.merge(vec![sched_row(2, 0xB0, wall + DAY)], fresh, t0, wall);
        assert_eq!(inner.entries.len(), 1);
    }

    /// B: a row sealed by `SealUnderSession` (no staged body, no history row)
    /// is never dialled and never destroyed by the worker.
    #[test]
    fn rows_without_a_local_body_are_held_not_destroyed() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x91);
        rig.set(UP);
        raven_core::seal_app_payload_under_session(
            rig.a.path(),
            &rig.alice,
            &hex::encode(rig.bob_pub),
            b"sealed by the daemon for the bridge",
        )
        .unwrap();
        assert_eq!(scan_store(rig.a.path()).unwrap().len(), 1);
        assert_eq!(only(&rig.attempt()), Outcome::Held(code::NO_LOCAL_BODY));
        assert_eq!(rig.dials(), 0, "nothing dialled");
        assert_eq!(scan_store(rig.a.path()).unwrap().len(), 1, "row kept");
    }

    /// C: an ACK that arrived on an inbound link (F8) settles the row; and a
    /// row still `Prepared` whose message an ACK already delivered is
    /// recorded, never dialled.
    #[test]
    fn a_message_delivered_by_an_inbound_ack_is_never_dialled_again() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x93);
        let mid = rig.stage("delivered behind our back", DAY);
        let ack = rig.bob_accepts(&rig.staged_bytes());
        // Bob's outbox pushes the owed ACK to Alice's listener.
        dispatch_frame(rig.a.path(), &rig.alice, &rig.b_bundle, &rig.bob_pub, &ack).unwrap();
        assert_eq!(rig.history(&mid).as_deref(), Some("delivered"));
        assert!(
            scan_store(rig.a.path()).unwrap().is_empty(),
            "the row is settled"
        );
        // Without the settle (an ACK accepted elsewhere): the worker records it.
        let mid2 = rig.stage("second", DAY);
        let ack2 = rig.bob_accepts(&rig.staged_bytes());
        IndexedSessionStore::open(rig.a.path())
            .unwrap()
            .accept_ack_envelope(&rig.key, &ack2, &rig.b_bundle.cert, false, now_ms())
            .unwrap();
        assert_eq!(scan_store(rig.a.path()).unwrap().len(), 1, "still listed");
        assert_eq!(only(&rig.attempt()), Outcome::Delivered { carrier: None });
        assert_eq!(rig.dials(), 0, "a delivered message is not dialled");
        assert_eq!(rig.history(&mid2).as_deref(), Some("delivered"));
        assert!(scan_store(rig.a.path()).unwrap().is_empty());
    }

    /// F: an object that left the store delivered (ACK committed, history not
    /// recorded) has its history repaired when the worker finalizes it.
    #[test]
    fn a_vanished_delivered_object_repairs_the_history() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x95);
        let mid = rig.stage("acked, not recorded", DAY);
        let bytes = rig.staged_bytes();
        let (cert, registry) =
            ensure_local_device_certificate(rig.a.path(), &rig.alice, PRIMARY_DEVICE_ID).unwrap();
        let device =
            AuthorizedEndpointDevice::authorize(&cert, &rig.alice, &registry, now_ms()).unwrap();
        let mut store = IndexedSessionStore::open(rig.a.path()).unwrap();
        let digest = scan_store(rig.a.path()).unwrap()[0].object_digest;
        store
            .retry_endpoint_outbound(
                &rig.key,
                &digest,
                &device,
                now_ms(),
                &mut |d: &[u8; 32], _: &[u8]| Ok(*d),
            )
            .unwrap();
        let tracked = rig.due();
        let ack = rig.bob_accepts(&bytes);
        store
            .accept_ack_envelope(&rig.key, &ack, &rig.b_bundle.cert, false, now_ms())
            .unwrap();
        drop(store);
        assert_eq!(rig.history(&mid).as_deref(), Some("queued"));
        let report = attempt_peer(&rig.ctx(), &rig.bob_pub, &tracked, &[]);
        assert_eq!(only(&report), Outcome::Delivered { carrier: None });
        assert_eq!(rig.history(&mid).as_deref(), Some("delivered"), "repaired");
    }

    /// Review C-time-deadlines-2: a tracked message that a prune settled as
    /// expired before destroying its session (history `expired`, no stage,
    /// no row) is finished as expired, with whether it ever left this
    /// computer, not as "gone".
    #[test]
    fn a_message_the_prune_settled_as_expired_is_reported_expired() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x65);
        let mid = rig.stage("pruned with its session", 1_500);
        let tracked = rig.due();
        std::thread::sleep(Duration::from_millis(1_600));
        // What the prune's settle and delete leave behind.
        let mut store = IndexedSessionStore::open(rig.a.path()).unwrap();
        let row = store.pending_endpoint_outbound().unwrap().remove(0);
        give_up_outbound(
            rig.a.path(),
            &mut store,
            &rig.key,
            &rig.bob_pub,
            &row.session_id,
            &row.object_digest,
            &row.message_id,
            HISTORY_EXPIRED,
        )
        .unwrap();
        drop(store);
        assert_eq!(rig.history(&mid).as_deref(), Some(HISTORY_EXPIRED));
        let report = attempt_peer(&rig.ctx(), &rig.bob_pub, &tracked, &[]);
        assert_eq!(only(&report), Outcome::Expired);
        assert_eq!(rig.dials(), 0);
        let (t0, wall) = (Instant::now(), now_ms());
        let mut entry = tracked[0].clone();
        apply_outcome(&mut entry, only(&report), t0, wall);
        let item = entry.item(t0, wall);
        assert_eq!(
            (item.state.as_str(), item.last_error_code.as_str()),
            ("expired", "EXPIRED")
        );
        assert!(item.never_sent, "it never left this computer");
    }

    /// D(b): a message the store refuses only because the clock stepped back
    /// (sealed "in the future") is held, not abandoned as expired.
    #[test]
    fn a_backward_clock_step_does_not_abandon_valid_messages() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x97);
        rig.set(UP);
        let mid = rig.stage_at("sealed with a fast clock", now_ms() + 10 * 60_000, DAY);
        assert_eq!(only(&rig.attempt()), Outcome::Held(code::CLOCK));
        assert_eq!(rig.dials(), 0);
        assert_eq!(rig.history(&mid).as_deref(), Some("queued"));
        assert_eq!(scan_store(rig.a.path()).unwrap().len(), 1, "not abandoned");
    }

    fn ack_envelope(id: u8, expires_at: u64) -> Vec<u8> {
        Envelope {
            env_type: EnvType::Ack as u8,
            flags: 0,
            message_id: [id; 16],
            routing_tag: [0x44; 16],
            dest_device_hint: 0,
            created_at: 1,
            expires_at,
            hop_limit: 4,
            replication_budget: 1,
            anti_replay_nonce: [id; 12],
            ratchet_header_ciphertext: vec![],
            message_ciphertext: vec![id; 8],
            sender_authentication: vec![0u8; 64],
        }
        .pack()
    }

    /// E: owed ACKs and the due message go in ONE dial (one per route), after
    /// the contact, block and revocation checks; a failed push backs off; one
    /// sender cannot fill everybody's slots.
    #[test]
    fn owed_acks_ride_one_dial_with_the_due_objects_after_the_checks() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x99);
        rig.stage("plus a message", DAY);
        let t = Instant::now();
        let owed: Vec<([u8; 32], UnsentAck)> = (0..6u8)
            .map(|i| {
                (
                    [i; 32],
                    UnsentAck {
                        peer: rig.bob_pub,
                        bytes: ack_envelope(i, now_ms() + 3_600_000),
                        expires_at_ms: now_ms() + 3_600_000,
                        failures: 0,
                        next_due: t,
                        durable: false,
                        session_id: None,
                        held_by: Vec::new(),
                        may_deposit: true,
                    },
                )
            })
            .collect();
        let report = attempt_peer(&rig.ctx(), &rig.bob_pub, &rig.due(), &owed);
        assert_eq!(rig.dials(), 1, "one dial for 6 owed ACKs and 1 message");
        assert_eq!(rig.net.log.lock().unwrap()[0].1, 7, "all in it");
        assert_eq!(report.acks_failed.len(), 6, "they back off together");
        // Not a contact any more: no dial, the ACKs are dropped.
        std::fs::write(rig.a.path().join("contacts.json"), "[]").unwrap();
        let report = attempt_peer(&rig.ctx(), &rig.bob_pub, &[], &owed);
        assert_eq!(rig.dials(), 1);
        assert_eq!(report.acks_done.len(), 6);
        // Revoked: no dial either.
        contacts(rig.a.path(), &rig.bob_pub, "127.0.0.1:9", "", false);
        let bob = Identity::from_seed(&[0x9a; 32]);
        let mut rev = raven_core::RevocationStore::load_checked(rig.a.path()).unwrap();
        assert!(rev
            .apply(
                raven_core::RevocationRecord::issue(&bob, PRIMARY_DEVICE_ID, 1, 10, "t").unwrap()
            )
            .unwrap());
        rev.save(rig.a.path()).unwrap();
        let report = attempt_peer(&rig.ctx(), &rig.bob_pub, &[], &owed);
        assert_eq!(rig.dials(), 1, "nothing to a revoked lineage");
        assert_eq!(report.acks_done.len(), 6);
        // Per-sender cap: one sender cannot push out another's owed ACKs.
        let mut inner = Inner::default();
        let carol = [0xC0; 32];
        inner.note_unsent_acks(&carol, &[ack_envelope(200, u64::MAX / 2)], t, now_ms());
        let flood: Vec<Vec<u8>> = (0..60u8).map(|i| ack_envelope(i, u64::MAX / 2)).collect();
        inner.note_unsent_acks(&rig.bob_pub, &flood, t, now_ms());
        let bobs = inner
            .unsent_acks
            .values()
            .filter(|a| a.peer == rig.bob_pub)
            .count();
        assert_eq!(bobs, MAX_UNSENT_ACKS_PER_PEER);
        assert_eq!(
            inner
                .unsent_acks
                .values()
                .filter(|a| a.peer == carol)
                .count(),
            1
        );
        // A failed push backs off at least 5 s.
        let digest = *inner.unsent_acks.keys().next().unwrap();
        let peer = inner.unsent_acks[&digest].peer;
        inner.apply(
            &peer,
            PeerReport {
                acks_failed: vec![digest],
                ..PeerReport::default()
            },
            t,
            now_ms(),
        );
        assert!(inner.unsent_acks[&digest].next_due >= t + MIN_RETRY);
    }

    /// J: an object sealed under an older session is given up as superseded
    /// only after repeated refusals spread over two minutes.
    #[test]
    fn a_superseded_session_is_given_up_only_after_repeated_refusals() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x9b);
        let mid = rig.stage("old session", DAY);
        // A newer confirmed session with Bob exists.
        let alice = Identity::from_seed(&[0x9b; 32]);
        let bob = Identity::from_seed(&[0x9c; 32]);
        let a_bundle = local_bundle(rig.a.path(), &alice).unwrap();
        pair(
            rig.a.path(),
            &alice,
            rig.b.path(),
            &bob,
            &a_bundle,
            &rig.b_bundle,
        );
        rig.set(REFUSE);
        let mut entry = rig.due().remove(0);
        // First refusal: never given up.
        let report = attempt_peer(&rig.ctx(), &rig.bob_pub, std::slice::from_ref(&entry), &[]);
        assert!(matches!(
            only(&report),
            Outcome::Unreachable {
                code: code::PEER_REFUSED,
                ..
            }
        ));
        // The third refusal within two minutes: still not.
        entry.refusals = 2;
        entry.first_refusal = Some(Instant::now());
        let report = attempt_peer(&rig.ctx(), &rig.bob_pub, std::slice::from_ref(&entry), &[]);
        assert!(matches!(
            only(&report),
            Outcome::Unreachable {
                code: code::PEER_REFUSED,
                ..
            }
        ));
        assert_eq!(rig.history(&mid).as_deref(), Some("queued"));
        // The third refusal over more than two minutes: superseded.
        let Some(long_ago) = Instant::now().checked_sub(SUPERSEDED_SPAN + Duration::from_secs(1))
        else {
            return;
        };
        entry.first_refusal = Some(long_ago);
        let report = attempt_peer(&rig.ctx(), &rig.bob_pub, std::slice::from_ref(&entry), &[]);
        assert_eq!(only(&report), Outcome::Failed(code::SUPERSEDED));
        assert_eq!(rig.history(&mid).as_deref(), Some(HISTORY_FAILED));
        // The refusal count follows the outcomes.
        let t = Instant::now();
        let mut e = Entry::from_row(&sched_row(1, 0xB0, u64::MAX), t);
        for _ in 0..3 {
            apply_outcome(
                &mut e,
                Outcome::Unreachable {
                    carrier: Some(OutboxCarrier::Lan),
                    code: code::PEER_REFUSED,
                },
                t,
                0,
            );
        }
        assert_eq!((e.refusals, e.first_refusal), (3, Some(t)));
        apply_outcome(&mut e, unreachable(), t, 0);
        assert_eq!((e.refusals, e.first_refusal), (0, None));
    }

    /// N: a route that answered with the wrong identity, or does not accept
    /// this node, is not retried for that object; with no route left it is
    /// held with that code until an explicit retry clears it.
    #[test]
    fn a_wrong_identity_or_refusing_route_is_blocked_until_an_explicit_retry() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x9d);
        rig.stage("to the right Bob only", DAY);
        for (mode, want) in [
            (WRONG_ID, code::WRONG_IDENTITY),
            (NOT_ACCEPTED, code::LINK_NOT_ACCEPTED),
        ] {
            rig.set(mode);
            let t = Instant::now();
            let mut inner = Inner {
                running: true,
                ..Inner::default()
            };
            inner.merge(scan_store(rig.a.path()).unwrap(), 0, t, now_ms());
            let work = inner.take_due(t).remove(0);
            let report = attempt_peer(&rig.ctx(), &rig.bob_pub, &work.entries, &[]);
            assert_eq!(only(&report), Outcome::Held(want), "no route left");
            inner.apply(&rig.bob_pub, report, t, now_ms());
            let entry = inner.entries.values().next().unwrap().clone();
            assert_eq!(entry.blocked_routes, vec![lan("127.0.0.1:9")]);
            let item = entry.item(t, now_ms());
            assert_eq!(
                (item.state.as_str(), item.last_error_code.as_str()),
                ("held", want)
            );
            // Retries leave that route alone: no dial at all.
            let dials = rig.dials();
            let report = attempt_peer(&rig.ctx(), &rig.bob_pub, &[entry], &[]);
            assert_eq!(only(&report), Outcome::Held(want));
            assert_eq!(rig.dials(), dials);
            // `raven outbox retry` (an explicit kick) clears it.
            inner.kick_now(Some(&rig.bob_pub), true, t);
            assert!(inner
                .entries
                .values()
                .next()
                .unwrap()
                .blocked_routes
                .is_empty());
        }
        rig.set(UP);
        assert!(matches!(only(&rig.attempt()), Outcome::Delivered { .. }));
    }

    /// M0: another key answered at Bob's address (a noise pin mismatch). The
    /// route is held as WRONG_IDENTITY but, unlike a bind mismatch, only
    /// until something says Bob may be back there: a network change, Bob's
    /// own authenticated link, his new route hints, or an explicit retry.
    /// Each clears it with no `raven outbox retry`, and Bob is reached at
    /// that very address.
    #[test]
    fn a_pin_mismatch_block_clears_on_a_network_change_and_on_the_contacts_inbound_link() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0xd1);
        rig.stage("to the right Bob only", DAY);
        rig.set(PIN_MISMATCH);
        let t = Instant::now();
        let mut inner = Inner {
            running: true,
            ..Inner::default()
        };
        inner.merge(scan_store(rig.a.path()).unwrap(), 0, t, now_ms());
        let blocked_now = |inner: &mut Inner| {
            let work = inner.take_due(t + RETRY_MAX).remove(0);
            let report = attempt_peer(&rig.ctx(), &rig.bob_pub, &work.entries, &[]);
            assert_eq!(only(&report), Outcome::Held(code::WRONG_IDENTITY));
            inner.apply(&rig.bob_pub, report, t, now_ms());
            let entry = inner.entries.values().next().unwrap().clone();
            assert_eq!(entry.pin_blocked, vec![lan("127.0.0.1:9")]);
            assert!(entry.blocked_routes.is_empty(), "not the lasting block");
            let item = entry.item(t, now_ms());
            assert_eq!(
                (item.state.as_str(), item.last_error_code.as_str()),
                ("held", code::WRONG_IDENTITY)
            );
            entry
        };
        type Clear = fn(&mut Inner, &[u8; 32], Instant);
        let clears: [(&str, Clear); 4] = [
            ("network change", |inner, _, t| {
                inner.network_changed(t);
            }),
            ("Bob's inbound link", |inner, bob, t| {
                inner.peer_seen_now(bob, t);
            }),
            ("Bob's new route hints", |inner, bob, t| {
                inner.routes_changed_now(bob, t);
            }),
            ("raven outbox retry", |inner, bob, t| {
                inner.kick_now(Some(bob), true, t);
            }),
        ];
        for (what, clear) in clears {
            let entry = blocked_now(&mut inner);
            // Until then: no dial at all.
            let dials = rig.dials();
            let report = attempt_peer(&rig.ctx(), &rig.bob_pub, &[entry], &[]);
            assert_eq!(only(&report), Outcome::Held(code::WRONG_IDENTITY), "{what}");
            assert_eq!(rig.dials(), dials, "{what}");
            // Bob's inbound link clears it even inside the dial-back window.
            inner.last_dialback.insert(rig.bob_pub, t);
            inner.last_routes_kick.remove(&rig.bob_pub);
            clear(&mut inner, &rig.bob_pub, t);
            let entry = inner.entries.values().next().unwrap();
            assert!(entry.pin_blocked.is_empty(), "{what}");
        }
        // Another contact's link leaves Bob's block alone.
        blocked_now(&mut inner);
        inner.peer_seen_now(&[0xEE; 32], t);
        assert!(!inner
            .entries
            .values()
            .next()
            .unwrap()
            .pin_blocked
            .is_empty());
        // Bob is back at that address: the next attempt reaches him.
        inner.peer_seen_now(&rig.bob_pub, t);
        rig.set(UP);
        let work = inner.take_due(t + RETRY_MAX).remove(0);
        let report = attempt_peer(&rig.ctx(), &rig.bob_pub, &work.entries, &[]);
        assert!(matches!(only(&report), Outcome::Delivered { .. }));
        assert_eq!(rig.bob_inbox(), vec!["to the right Bob only".to_string()]);
    }

    /// E-custody-harness-docs-8, as the LAN waiver amendment's §2.1 item 3
    /// says: a pin block belongs to the message that found it. A new message
    /// to the same contact plans that route again on its first attempt (one
    /// more dial, which stops at message 2 again), and a send's kick (every
    /// IPC OutboxKick is explicit) clears the older message's block too.
    #[test]
    fn a_pin_block_is_per_message_and_a_send_clears_it() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0xd8);
        rig.stage_queued("first", DAY);
        rig.set(PIN_MISMATCH);
        let t = Instant::now();
        let mut inner = Inner {
            running: true,
            ..Inner::default()
        };
        inner.merge(scan_store(rig.a.path()).unwrap(), 0, t, now_ms());
        let work = inner.take_due(t).remove(0);
        let report = attempt_peer(&rig.ctx(), &rig.bob_pub, &work.entries, &[]);
        assert_eq!(only(&report), Outcome::Held(code::WRONG_IDENTITY));
        inner.apply(&rig.bob_pub, report, t, now_ms());
        let first = *inner.entries.keys().next().unwrap();
        assert_eq!(inner.entries[&first].pin_blocked, vec![lan("127.0.0.1:9")]);

        // A second message: no block of its own, so its attempt dials there.
        rig.stage_queued("second", DAY);
        let seq = inner.scan_seq();
        inner.merge(scan_store(rig.a.path()).unwrap(), seq, t, now_ms());
        let second = *inner.entries.keys().find(|k| **k != first).unwrap();
        assert!(inner.entries[&second].pin_blocked.is_empty());
        let dials = rig.dials();
        let work = inner.take_due(t).remove(0);
        let report = attempt_peer(&rig.ctx(), &rig.bob_pub, &work.entries, &[]);
        assert_eq!(rig.dials(), dials + 1, "one more dial, at message 2");
        assert_eq!(
            report.outcomes.get(&second),
            Some(&Outcome::Held(code::WRONG_IDENTITY))
        );
        inner.apply(&rig.bob_pub, report, t, now_ms());
        assert_eq!(inner.entries[&second].pin_blocked, vec![lan("127.0.0.1:9")]);

        // A send to Bob (its OutboxKick): both blocks go.
        inner.kick_now(Some(&rig.bob_pub), true, t);
        assert!(inner.entries.values().all(|e| e.pin_blocked.is_empty()));
    }

    /// The same clears while an attempt to Bob is still in flight (a dial
    /// that found the mismatch on the old network and waits on his next
    /// route, the laptop asleep and woken on another network): the attempt
    /// ends after the clear, and what it found must not put the block back.
    /// Without a clear the block stays (the control).
    #[test]
    fn a_pin_mismatch_found_in_flight_does_not_outlive_a_clear() {
        if !lab_backends() {
            return;
        }
        type Clear = fn(&mut Inner, &[u8; 32], Instant);
        let clears: [(&str, Option<Clear>); 4] = [
            (
                "network change",
                Some(|inner, _, t| {
                    inner.network_changed(t);
                }),
            ),
            (
                "Bob's inbound link",
                Some(|inner, bob, t| {
                    inner.peer_seen_now(bob, t);
                }),
            ),
            (
                "Bob's new route hints",
                Some(|inner, bob, t| {
                    inner.routes_changed_now(bob, t);
                }),
            ),
            ("no clear", None),
        ];
        for (seed, (what, clear)) in (0xd4u8..).zip(clears) {
            let rig = Rig::new(seed);
            rig.stage("to Bob once he is back", DAY);
            rig.set(PIN_MISMATCH);
            let t = Instant::now();
            let mut inner = Inner {
                running: true,
                ..Inner::default()
            };
            inner.merge(scan_store(rig.a.path()).unwrap(), 0, t, now_ms());
            let work = inner.take_due(t).remove(0);
            assert!(inner.in_flight.contains(&rig.bob_pub), "{what}");
            let report = attempt_peer(&rig.ctx(), &rig.bob_pub, &work.entries, &[]);
            assert_eq!(
                report.pin_blocked.values().flatten().collect::<Vec<_>>(),
                [&lan("127.0.0.1:9")],
                "{what}"
            );
            if let Some(clear) = clear {
                clear(&mut inner, &rig.bob_pub, t);
            }
            inner.apply(&rig.bob_pub, report, t, now_ms());
            let entry = inner.entries.values().next().unwrap();
            if clear.is_none() {
                assert_eq!(entry.pin_blocked, vec![lan("127.0.0.1:9")], "{what}");
                continue;
            }
            assert!(entry.pin_blocked.is_empty(), "{what}: {entry:?}");
            // Bob is back at that address: the next attempt reaches him.
            rig.set(UP);
            let work = inner.take_due(t + RETRY_MAX).remove(0);
            let report = attempt_peer(&rig.ctx(), &rig.bob_pub, &work.entries, &[]);
            assert!(matches!(only(&report), Outcome::Delivered { .. }), "{what}");
            assert_eq!(
                rig.bob_inbox(),
                vec!["to Bob once he is back".to_string()],
                "{what}"
            );
            assert!(inner.clear_pins_after.is_empty(), "{what}: bounded");
        }
    }

    /// A-noise-pin-4: Alice's pin store exists but cannot be read (here a
    /// directory in its place), so no dial goes out to anyone. The object
    /// says so with its own code, not a generic DIAL_FAILED, blocks no
    /// route, and goes out by itself once the file is readable again.
    #[test]
    fn an_unreadable_pin_store_holds_with_its_own_code() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0xd8);
        rig.stage("after the pin store is fixed", DAY);
        rig.set(PIN_STORE);
        let pins = rig.a.path().join(raven_core::lan_noise_pin::NOISE_PIN_FILE);
        std::fs::create_dir(&pins).unwrap();
        let t = Instant::now();
        let mut inner = Inner {
            running: true,
            ..Inner::default()
        };
        inner.merge(scan_store(rig.a.path()).unwrap(), 0, t, now_ms());
        let work = inner.take_due(t).remove(0);
        let report = attempt_peer(&rig.ctx(), &rig.bob_pub, &work.entries, &[]);
        assert_eq!(
            only(&report),
            Outcome::Unreachable {
                carrier: Some(OutboxCarrier::Lan),
                code: code::PIN_STORE_UNREADABLE,
            }
        );
        inner.apply(&rig.bob_pub, report, t, now_ms());
        let entry = inner.entries.values().next().unwrap().clone();
        assert!(entry.blocked_routes.is_empty() && entry.pin_blocked.is_empty());
        assert_eq!(
            entry.item(t, now_ms()).last_error_code,
            code::PIN_STORE_UNREADABLE
        );
        assert!(rig.bob_inbox().is_empty());
        // Fixed (moved aside): the next attempt delivers it.
        std::fs::remove_dir(&pins).unwrap();
        let work = inner.take_due(t + RETRY_MAX).remove(0);
        let report = attempt_peer(&rig.ctx(), &rig.bob_pub, &work.entries, &[]);
        assert!(matches!(only(&report), Outcome::Delivered { .. }));
        assert_eq!(
            rig.bob_inbox(),
            vec!["after the pin store is fixed".to_string()]
        );
    }

    /// A bind mismatch (the key at that address proved it is someone else)
    /// keeps today's rule: blocked until an explicit retry, whatever the
    /// network or the contact does meanwhile.
    #[test]
    fn a_bind_mismatch_block_still_needs_an_explicit_retry() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0xd3);
        rig.stage("bind mismatch", DAY);
        rig.set(WRONG_ID);
        let t = Instant::now();
        let mut inner = Inner {
            running: true,
            ..Inner::default()
        };
        inner.merge(scan_store(rig.a.path()).unwrap(), 0, t, now_ms());
        let work = inner.take_due(t).remove(0);
        let report = attempt_peer(&rig.ctx(), &rig.bob_pub, &work.entries, &[]);
        assert_eq!(only(&report), Outcome::Held(code::WRONG_IDENTITY));
        inner.apply(&rig.bob_pub, report, t, now_ms());
        let blocked = |inner: &Inner| {
            let e = inner.entries.values().next().unwrap();
            (e.blocked_routes.clone(), e.pin_blocked.clone())
        };
        assert_eq!(blocked(&inner), (vec![lan("127.0.0.1:9")], Vec::new()));
        inner.network_changed(t);
        inner.peer_seen_now(&rig.bob_pub, t);
        inner.last_routes_kick.remove(&rig.bob_pub);
        inner.routes_changed_now(&rig.bob_pub, t);
        assert_eq!(blocked(&inner), (vec![lan("127.0.0.1:9")], Vec::new()));
        inner.kick_now(Some(&rig.bob_pub), true, t);
        assert_eq!(blocked(&inner), (Vec::new(), Vec::new()));
    }

    /// L: an unverified contact is dialled only at local-network addresses
    /// (names resolved first, dialled as the resolved literal); a verified one
    /// anywhere.
    #[test]
    fn an_unverified_contact_is_dialled_only_on_the_local_network() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x9f);
        rig.set(UP);
        let mid = rig.stage("only on the LAN", DAY);
        contacts(rig.a.path(), &rig.bob_pub, "203.0.113.7:7420", "", false);
        assert_eq!(only(&rig.attempt()), Outcome::Held(CONTACT_NOT_VERIFIED));
        assert_eq!(rig.dials(), 0);
        contacts(rig.a.path(), &rig.bob_pub, "100.64.0.9:7420", "", false);
        assert_eq!(only(&rig.attempt()), Outcome::Held(CONTACT_NOT_VERIFIED));
        assert_eq!(rig.dials(), 0, "carrier-grade NAT space is not local");
        contacts(rig.a.path(), &rig.bob_pub, "localhost:7420", "", false);
        assert!(matches!(only(&rig.attempt()), Outcome::Delivered { .. }));
        let (route, _) = rig.net.log.lock().unwrap()[0].clone();
        let addr: std::net::SocketAddr = route.dial.parse().expect("the resolved literal");
        assert!(addr.ip().is_loopback(), "{route:?}");
        assert_eq!(rig.history(&mid).as_deref(), Some("delivered"));
        // A verified contact's public LAN address from a card (nobody signs
        // a card's routes): still never dialled, and not "not verified".
        rig.stage("anywhere", DAY);
        contacts(rig.a.path(), &rig.bob_pub, "203.0.113.7:7420", "", true);
        assert!(rig
            .attempt()
            .outcomes
            .values()
            .all(|o| *o == Outcome::Held(code::NO_ROUTE)));
        assert_eq!(rig.net.log.lock().unwrap().len(), 1);
        // Typed on this computer (or learned after a delivery): dialled at
        // its public address as saved.
        contacts_typed(rig.a.path(), &rig.bob_pub, "203.0.113.7:7420", "", true);
        assert!(matches!(only(&rig.attempt()), Outcome::Delivered { .. }));
        assert_eq!(rig.net.log.lock().unwrap()[1].0, lan("203.0.113.7:7420"));
    }

    /// Cutoff F1 (CP.9; no worker change, so no gate here): what `raven send`
    /// queues for an unverified contact whose only LAN route is a name that
    /// does not resolve now waits like any unreachable message (held
    /// NOT_REACHABLE, backed off, retried), never as CONTACT_NOT_VERIFIED,
    /// and nothing is dialled. Once the name resolves to a local address the
    /// next attempt delivers it, once.
    #[test]
    fn an_unverified_name_route_waits_and_is_not_held_as_not_verified() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0xe5);
        rig.set(UP);
        let mid = rig.stage("while Bob is away", DAY);
        contacts(
            rig.a.path(),
            &rig.bob_pub,
            "no-such-host.invalid:7420",
            "",
            false,
        );
        rig.record(
            &mid,
            CarrierChoice::Auto,
            &[lan("no-such-host.invalid:7420")],
        );
        let t = Instant::now();
        let mut inner = Inner {
            running: true,
            ..Inner::default()
        };
        inner.merge(scan_store(rig.a.path()).unwrap(), 0, t, now_ms());
        for round in 0..2u32 {
            let now = t + RETRY_MAX * round;
            let work = inner.take_due(now).remove(0);
            let report = attempt_peer(&rig.ctx(), &rig.bob_pub, &work.entries, &[]);
            assert_eq!(only(&report), Outcome::Held(code::NOT_REACHABLE), "{round}");
            assert_eq!(rig.dials(), 0, "an unresolved name is never dialled");
            inner.apply(&rig.bob_pub, report, now, now_ms());
            let entry = inner.entries.values().next().unwrap();
            assert_eq!(entry.failures, round + 1, "backed off like any failure");
            assert!(entry.next_due > now && entry.next_due <= now + RETRY_MAX);
            let item = entry.item(now, now_ms());
            assert_eq!(item.state, "held");
            assert_eq!(item.last_error_code, code::NOT_REACHABLE);
            assert_ne!(item.last_error_code, CONTACT_NOT_VERIFIED);
        }
        assert_eq!(rig.history(&mid).as_deref(), Some("queued"));
        // The name now resolves, to this computer: delivered on the next
        // attempt, as the resolved literal.
        contacts(rig.a.path(), &rig.bob_pub, "localhost:7420", "", false);
        let work = inner.take_due(t + RETRY_MAX * 3).remove(0);
        let report = attempt_peer(&rig.ctx(), &rig.bob_pub, &work.entries, &[]);
        assert!(matches!(only(&report), Outcome::Delivered { .. }));
        let (route, _) = rig.net.log.lock().unwrap()[0].clone();
        let addr: std::net::SocketAddr = route.dial.parse().expect("the resolved literal");
        assert!(addr.ip().is_loopback(), "{route:?}");
        assert_eq!(rig.bob_inbox(), vec!["while Bob is away".to_string()]);
        assert_eq!(rig.history(&mid).as_deref(), Some("delivered"));
    }

    /// O: the contact's current addresses first; no record means LAN from the
    /// book only; a record is cleared once its object is delivered.
    #[test]
    fn routes_current_first_no_record_lan_only_and_cleared_on_delivery() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0xa1);
        let mid = rig.stage("route order", DAY);
        contacts(rig.a.path(), &rig.bob_pub, "127.0.0.2:7420", "", false);
        rig.record(&mid, CarrierChoice::Lan, &[lan("127.0.0.9:7420")]);
        let _ = rig.attempt();
        let dialled: Vec<String> = rig
            .net
            .log
            .lock()
            .unwrap()
            .iter()
            .map(|(r, _)| r.dial.clone())
            .collect();
        assert_eq!(
            dialled,
            vec!["127.0.0.2:7420", "127.0.0.9:7420"],
            "current first"
        );
        rig.set(UP);
        assert!(matches!(only(&rig.attempt()), Outcome::Delivered { .. }));
        let records = object_route_records(rig.a.path(), now_ms()).unwrap();
        assert!(!records.contains_key(&mid), "cleared on delivery");
        // No record: never the Internet, even for a verified contact.
        rig.stage("no record", DAY);
        contacts(rig.a.path(), &rig.bob_pub, "", "203.0.113.7:7422", true);
        assert_eq!(
            only(&rig.attempt_with(&rig.ctx_with(on, on))),
            Outcome::Held(code::NO_ROUTE)
        );
        assert_eq!(rig.net.internet_dials.load(Ordering::SeqCst), 0);
    }

    /// The rig's per-route modes: a SILENT route takes the frames and answers
    /// with the offer only, an ACK_LOST route lets Bob commit while his ACK is
    /// lost, and a route without its own mode follows `set`. Bob's dedup
    /// makes the later resend on another route a duplicate.
    #[test]
    fn per_route_modes_override_the_default_for_that_route_only() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0xad);
        let (l, i) = (lan("192.168.1.20:7420"), inet("203.0.113.7:7422"));
        contacts(rig.a.path(), &rig.bob_pub, &l.dial, &i.dial, true);
        let mid = rig.stage("per route", DAY);
        rig.record(&mid, CarrierChoice::Auto, &[]);
        rig.set(UP);
        let ctx = rig.ctx_with(on, on);
        let no_ack = Outcome::Sent {
            carrier: Some(OutboxCarrier::Lan),
            code: code::NO_ACK_YET,
        };
        rig.set_route(l.clone(), SILENT);
        assert_eq!(only(&rig.attempt_with(&ctx)), no_ack);
        assert!(rig.bob_inbox().is_empty(), "Bob never saw it");
        rig.set_route(l.clone(), ACK_LOST);
        assert_eq!(only(&rig.attempt_with(&ctx)), no_ack);
        assert_eq!(rig.bob_inbox(), ["per route"], "committed, the ACK lost");
        rig.set_route(l.clone(), DOWN);
        assert_eq!(
            only(&rig.attempt_with(&ctx)),
            Outcome::Delivered {
                carrier: Some(OutboxCarrier::Internet)
            },
            "the Internet route follows the default"
        );
        assert_eq!(rig.bob_inbox(), ["per route"], "the resend is a duplicate");
        assert_eq!(rig.dialled(), [l.clone(), l.clone(), l, i]);
        assert_eq!(rig.history(&mid).as_deref(), Some("delivered"));
    }

    /// The worker's schedule, rebuilt from A's store at `t`.
    fn schedule(rig: &Rig, t: Instant) -> Inner {
        let mut inner = Inner {
            running: true,
            ..Inner::default()
        };
        inner.merge(scan_store(rig.a.path()).unwrap(), 0, t, now_ms());
        inner
    }

    /// One worker attempt on the one peer `inner` tracks (Bob), with all it
    /// holds for him (the worker's own pick and write order, backoff waived),
    /// applied as the worker applies it: the outcomes, and the routes that
    /// took an object without an ACK.
    fn worker_round(
        ctx: &AttemptCtx,
        inner: &mut Inner,
    ) -> (HashMap<[u8; 32], Outcome>, HashMap<[u8; 32], OutboxRoute>) {
        let mut work = inner.take_due(Instant::now() + RETRY_MAX * 2);
        assert_eq!(work.len(), 1, "one peer");
        let work = work.remove(0);
        let report = attempt_peer(ctx, &work.peer, &work.entries, &work.acks);
        let seen = (report.outcomes.clone(), report.unacked.clone());
        inner.apply(&work.peer, report, Instant::now(), now_ms());
        seen
    }

    /// G3: the next attempt starts at the route after the one that took the
    /// frames silently and tries that one last, round the plan; a route that
    /// is not planned (any more) gives plan order. Nothing is added or
    /// dropped.
    #[test]
    fn the_next_attempt_starts_after_the_silent_route_and_drops_none() {
        let (l1, l2, i) = (
            lan("192.168.1.20:7420"),
            lan("192.168.1.21:7420"),
            inet("203.0.113.7:7422"),
        );
        let gone = lan("10.0.0.9:7420");
        let plan: Vec<(OutboxRoute, OutboxRoute)> = [&l1, &l2, &i]
            .into_iter()
            .map(|r| (r.clone(), r.clone()))
            .collect();
        let sorted = |routes: &[(OutboxRoute, OutboxRoute)]| {
            let mut v = routes.to_vec();
            v.sort_by_key(|(p, _)| (p.carrier, p.dial.clone()));
            v
        };
        for (unacked, want) in [
            (None, [&l1, &l2, &i]),
            (Some(&l1), [&l2, &i, &l1]),
            (Some(&l2), [&i, &l1, &l2]),
            // The last route: plan order again.
            (Some(&i), [&l1, &l2, &i]),
            // Not planned (blocked, or the contact moved): plan order.
            (Some(&gone), [&l1, &l2, &i]),
        ] {
            let mut routes = plan.clone();
            rotate_past(&mut routes, unacked);
            let got: Vec<&OutboxRoute> = routes.iter().map(|(p, _)| p).collect();
            assert_eq!(got, want, "after {unacked:?}");
            assert!(routes.iter().all(|(p, d)| p == d), "pairs kept together");
            assert_eq!(sorted(&routes), sorted(&plan), "none added or dropped");
        }
        let mut none: Vec<(OutboxRoute, OutboxRoute)> = Vec::new();
        rotate_past(&mut none, Some(&l1));
        assert!(none.is_empty());
    }

    /// G3: only a write without an ACK on that dial moves an object's start;
    /// a failed dial and a write whose ACKs were not checked (the send lock
    /// was busy) leave it, a rider's write counts (progress), and a rebuilt
    /// schedule (a restart) starts from plan order.
    #[test]
    fn only_a_write_without_an_ack_moves_the_start() {
        let t0 = Instant::now();
        let peer = [1; 32];
        let d = [0x31; 32];
        let (l20, l21) = (lan("192.168.1.20:7420"), lan("192.168.1.21:7420"));
        let mut inner = Inner::default();
        inner.merge(vec![sched_row(0x31, 1, u64::MAX)], 0, t0, 0);
        let no_ack = Outcome::Sent {
            carrier: Some(OutboxCarrier::Lan),
            code: code::NO_ACK_YET,
        };
        inner.apply(&peer, report_for(d, unreachable()), t0, 0);
        assert_eq!(inner.entries[&d].unacked_route, None, "a failed dial");
        let mut r = report_for(d, no_ack.clone());
        r.unacked.insert(d, l20.clone());
        inner.apply(&peer, r, t0, 0);
        assert_eq!(inner.entries[&d].unacked_route, Some(l20.clone()));
        inner.apply(&peer, report_for(d, unreachable()), t0, 0);
        let busy = Outcome::Sent {
            carrier: Some(OutboxCarrier::Lan),
            code: code::SEND_IN_PROGRESS,
        };
        inner.apply(&peer, report_for(d, busy), t0, 0);
        assert_eq!(
            inner.entries[&d].unacked_route,
            Some(l20),
            "a failure and an unchecked write leave it"
        );
        inner.riding.insert(d);
        let mut r = report_for(d, no_ack);
        r.unacked.insert(d, l21.clone());
        inner.apply(&peer, r, t0, 0);
        assert_eq!(inner.entries[&d].unacked_route, Some(l21), "a rider too");
        assert_eq!(
            Entry::from_row(&sched_row(0x31, 1, u64::MAX), t0).unacked_route,
            None,
            "rebuilt at start-up: plan order"
        );
    }

    /// G3: a route that took the frames and stayed silent goes last in that
    /// object's next attempt, which starts at the route after it; within one
    /// attempt the first route that takes it still settles it (no extra dial,
    /// no extra reply wait).
    #[test]
    fn a_route_that_takes_frames_without_an_ack_is_tried_last_next_time() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0xb1);
        let (l, i) = (lan("192.168.1.20:7420"), inet("203.0.113.7:7422"));
        contacts(rig.a.path(), &rig.bob_pub, &l.dial, &i.dial, true);
        let mid = rig.stage("rotate", DAY);
        rig.record(&mid, CarrierChoice::Auto, &[]);
        rig.set(UP);
        rig.set_route(l.clone(), SILENT);
        let ctx = rig.ctx_with(on, on);
        let mut inner = schedule(&rig, Instant::now());
        let digest = *inner.entries.keys().next().unwrap();
        let (outcomes, unacked) = worker_round(&ctx, &mut inner);
        assert_eq!(
            outcomes[&digest],
            Outcome::Sent {
                carrier: Some(OutboxCarrier::Lan),
                code: code::NO_ACK_YET
            }
        );
        assert_eq!(
            rig.net.internet_dials.load(Ordering::SeqCst),
            0,
            "the first route that took it settled the attempt"
        );
        assert_eq!(unacked.get(&digest), Some(&l));
        let entry = &inner.entries[&digest];
        assert_eq!(entry.state, EntryState::Sent);
        assert_eq!(entry.unacked_route, Some(l.clone()));
        let (outcomes, unacked) = worker_round(&ctx, &mut inner);
        assert_eq!(
            outcomes[&digest],
            Outcome::Delivered {
                carrier: Some(OutboxCarrier::Internet)
            }
        );
        assert!(unacked.is_empty());
        assert_eq!(rig.dialled(), [l, i], "the silent route was not needed");
        assert!(inner.entries.is_empty(), "off the schedule");
        assert_eq!(rig.history(&mid).as_deref(), Some("delivered"));
        assert_eq!(rig.bob_inbox(), ["rotate"]);
    }

    /// P6.13, Karn: the dial that resends an object which went silent on
    /// a route before tells the carrier so (`karn_exclude`), and its ACK
    /// gives learning a connect sample but no reply-time sample (it may
    /// answer the earlier copy); a first send's ACK gives both.
    #[test]
    fn karn_excluded_resends_take_no_reply_sample() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0xb3);
        let (l, i) = (lan("192.168.1.20:7420"), inet("203.0.113.7:7422"));
        contacts(rig.a.path(), &rig.bob_pub, &l.dial, &i.dial, true);
        let mut learning = crate::learning::TestService::loaded(rig.a.path(), Some("home"));
        *rig.net.timing.lock().unwrap() = Some(raven_core::learning::observe::DialTiming {
            connect_ms: Some(40),
            reply_ms: Some(90),
            total_ms: 150,
        });
        let arm = |learning: &crate::learning::TestService, carrier| {
            learning
                .model()
                .unwrap()
                .arm(&raven_core::learning::model::ArmKey {
                    contact: rig.bob_pub,
                    net: Some("home".into()),
                    carrier,
                })
                .copied()
                .unwrap()
        };
        let mid = rig.stage("silent first", DAY);
        rig.record(&mid, CarrierChoice::Auto, &[]);
        rig.set(UP);
        rig.set_route(l.clone(), SILENT);
        let ctx = rig.ctx_with(on, on);
        let mut inner = schedule(&rig, Instant::now());
        let digest = *inner.entries.keys().next().unwrap();
        worker_round(&ctx, &mut inner);
        assert_eq!(inner.entries[&digest].unacked_route, Some(l.clone()));
        // The resend over Internet: Karn-excluded.
        let (outcomes, _) = worker_round(&ctx, &mut inner);
        assert_eq!(
            outcomes[&digest],
            Outcome::Delivered {
                carrier: Some(OutboxCarrier::Internet)
            }
        );
        let karn = |k| crate::learning::DialMeta {
            karn_exclude: k,
            ..Default::default()
        };
        assert_eq!(
            *rig.net.metas.lock().unwrap(),
            [(l.clone(), karn(false)), (i.clone(), karn(true))]
        );
        learning.drain();
        let inet_arm = arm(&learning, OutboxCarrier::Internet);
        assert_eq!(
            (inet_arm.connect.n, inet_arm.reply.n),
            (1, 0),
            "no reply sample"
        );
        assert_eq!(
            arm(&learning, OutboxCarrier::Lan).reply.n,
            0,
            "silent: no reply"
        );
        // A first send over Internet (LAN down now): both samples.
        rig.set_route(l.clone(), DOWN);
        let mid = rig.stage("first send", DAY);
        rig.record(&mid, CarrierChoice::Auto, &[]);
        let mut inner = schedule(&rig, Instant::now());
        worker_round(&ctx, &mut inner);
        let metas = rig.net.metas.lock().unwrap().clone();
        assert_eq!(metas.last(), Some(&(i.clone(), karn(false))), "{metas:?}");
        learning.drain();
        let inet_arm = arm(&learning, OutboxCarrier::Internet);
        assert_eq!((inet_arm.connect.n, inet_arm.reply.n), (2, 1));
        assert_eq!(sorted(rig.bob_inbox()), ["first send", "silent first"]);
    }

    /// G3 relies on the receiver's dedup: Bob commits the message but his
    /// ACK is lost on one route; the next attempt resends the exact bytes on
    /// the next route, Bob sees a duplicate and answers with the same ACK.
    /// Delivered, and Bob still holds exactly one copy.
    #[test]
    fn an_ack_lost_on_one_route_comes_back_on_the_next_as_a_duplicate() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0xb3);
        let (l, i) = (lan("192.168.1.20:7420"), inet("203.0.113.7:7422"));
        contacts(rig.a.path(), &rig.bob_pub, &l.dial, &i.dial, true);
        let mid = rig.stage("once", DAY);
        rig.record(&mid, CarrierChoice::Auto, &[]);
        rig.set(UP);
        rig.set_route(l.clone(), ACK_LOST);
        let ctx = rig.ctx_with(on, on);
        let mut inner = schedule(&rig, Instant::now());
        let digest = *inner.entries.keys().next().unwrap();
        let (outcomes, _) = worker_round(&ctx, &mut inner);
        assert_eq!(
            outcomes[&digest],
            Outcome::Sent {
                carrier: Some(OutboxCarrier::Lan),
                code: code::NO_ACK_YET
            }
        );
        assert_eq!(rig.bob_inbox(), ["once"], "Bob committed it");
        let (outcomes, _) = worker_round(&ctx, &mut inner);
        assert_eq!(
            outcomes[&digest],
            Outcome::Delivered {
                carrier: Some(OutboxCarrier::Internet)
            }
        );
        assert_eq!(rig.bob_inbox(), ["once"], "a duplicate: no second row");
        assert_eq!(rig.dialled(), [l, i]);
        assert_eq!(rig.history(&mid).as_deref(), Some("delivered"));
    }

    /// B-3: `raven lan off` while an attempt runs (here: during its first
    /// LAN dial) leaves the LAN routes it planned after that one undialled.
    #[test]
    fn lan_off_during_an_attempt_dials_no_further_lan_route() {
        if !lab_backends() {
            return;
        }
        thread_local! {
            static LAN_LIVE: std::cell::Cell<bool> = const { std::cell::Cell::new(true) };
        }
        fn lan_live_here() -> bool {
            LAN_LIVE.with(std::cell::Cell::get)
        }
        /// Turns LAN off (on this thread) as it dials.
        struct LanOffWhileDialling(Arc<FakeNet>);
        impl Dialer for LanOffWhileDialling {
            fn dial(
                &self,
                data_dir: &Path,
                route: &OutboxRoute,
                expected: &str,
                frames: &[Vec<u8>],
            ) -> Result<Vec<Vec<u8>>, String> {
                LAN_LIVE.with(|live| live.set(false));
                self.0.dial(data_dir, route, expected, frames)
            }
        }
        let rig = Rig::new(0xb9);
        let (l20, l21) = (lan("192.168.1.20:7420"), lan("192.168.1.21:7420"));
        contacts(rig.a.path(), &rig.bob_pub, &l20.dial, "", false);
        let mid = rig.stage("lan off now", DAY);
        rig.record(&mid, CarrierChoice::Lan, std::slice::from_ref(&l21));
        rig.set(DOWN);
        // Both routes are dialled while LAN stays on.
        rig.attempt();
        assert_eq!(rig.dialled().len(), 2, "{:?}", rig.dialled());
        LAN_LIVE.with(|live| live.set(true));
        let ctx = AttemptCtx {
            dialer: Arc::new(LanOffWhileDialling(rig.net.clone())),
            lan_live: lan_live_here,
            ..rig.ctx()
        };
        rig.attempt_with(&ctx);
        assert_eq!(rig.dialled().len(), 3, "{:?}", rig.dialled());
        LAN_LIVE.with(|live| live.set(true));
    }

    /// G3 in the release shape (the LAN gate only): an object with a second
    /// LAN address goes there after the first one stayed silent; an object
    /// with one route is dialled exactly as before.
    #[test]
    fn lan_only_rotation_moves_to_the_other_lan_address_and_one_route_is_unchanged() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0xb5);
        let (l20, l21) = (lan("192.168.1.20:7420"), lan("192.168.1.21:7420"));
        contacts(rig.a.path(), &rig.bob_pub, &l20.dial, "", false);
        let mid = rig.stage("other lan", DAY);
        rig.record(&mid, CarrierChoice::Lan, std::slice::from_ref(&l21));
        rig.set(UP);
        rig.set_route(l20.clone(), SILENT);
        let ctx = rig.ctx();
        let no_ack = Outcome::Sent {
            carrier: Some(OutboxCarrier::Lan),
            code: code::NO_ACK_YET,
        };
        let mut inner = schedule(&rig, Instant::now());
        let (outcomes, _) = worker_round(&ctx, &mut inner);
        assert_eq!(outcomes.values().collect::<Vec<_>>(), [&no_ack]);
        assert_eq!(rig.dialled(), std::slice::from_ref(&l20));
        let (outcomes, _) = worker_round(&ctx, &mut inner);
        assert_eq!(
            outcomes.into_values().collect::<Vec<_>>(),
            [Outcome::Delivered {
                carrier: Some(OutboxCarrier::Lan)
            }]
        );
        assert_eq!(rig.dialled(), [l20.clone(), l21]);
        assert_eq!(rig.net.internet_dials.load(Ordering::SeqCst), 0);
        assert_eq!(rig.history(&mid).as_deref(), Some("delivered"));
        // No record: the book's one LAN route, silent every time.
        rig.stage("single", DAY);
        let mut inner = schedule(&rig, Instant::now());
        for _ in 0..2 {
            let (outcomes, unacked) = worker_round(&ctx, &mut inner);
            assert_eq!(outcomes.values().collect::<Vec<_>>(), [&no_ack]);
            assert_eq!(unacked.values().collect::<Vec<_>>(), [&l20]);
        }
        assert_eq!(rig.dialled()[2..], [l20.clone(), l20]);
        assert_eq!(rig.bob_inbox(), ["other lan"]);
    }

    /// G3 only reorders an object's own routes: in one dial, the object whose
    /// silent LAN route goes last is delivered over the Internet and not
    /// resent on the LAN, and a `lan` object never goes on the Internet.
    #[test]
    fn rotation_reorders_but_never_widens_an_objects_routes() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0xb7);
        let (l, i) = (lan("192.168.1.20:7420"), inet("203.0.113.7:7422"));
        contacts(rig.a.path(), &rig.bob_pub, &l.dial, &i.dial, true);
        let a = rig.stage_queued("one", DAY);
        let b = rig.stage_queued("two", DAY);
        rig.record(&a, CarrierChoice::Auto, &[]);
        rig.record(&b, CarrierChoice::Lan, &[]);
        rig.set(UP);
        let mut due = rig.due();
        assert_eq!(due.len(), 2);
        due.sort_by_key(|e| e.message_id != a);
        due[0].unacked_route = Some(l.clone());
        let report = attempt_peer(&rig.ctx_with(on, on), &rig.bob_pub, &due, &[]);
        let outcome = |mid: &[u8; 16]| {
            let e = due.iter().find(|e| e.message_id == *mid).unwrap();
            report.outcomes[&e.object_digest].clone()
        };
        assert_eq!(
            outcome(&a),
            Outcome::Delivered {
                carrier: Some(OutboxCarrier::Internet)
            }
        );
        assert_eq!(
            outcome(&b),
            Outcome::Delivered {
                carrier: Some(OutboxCarrier::Lan)
            }
        );
        assert_eq!(rig.net.log.lock().unwrap().clone(), [(i, 1), (l, 1)]);
        let mut inbox = rig.bob_inbox();
        inbox.sort();
        assert_eq!(inbox, ["one", "two"]);
    }

    /// G3 + G1: which route stayed silent is evidence from the old network:
    /// a change returns every object to plan order. An explicit retry
    /// (`raven outbox retry`) clears blocks, not the rotation.
    #[test]
    fn a_network_change_returns_rotation_to_plan_order() {
        let t0 = Instant::now();
        let wall = 1_000_000_000u64;
        let mut inner = Inner::default();
        inner.merge(
            vec![
                sched_row(1, 0xB0, wall + DAY),
                sched_row(2, 0xB1, wall + DAY),
            ],
            0,
            t0,
            wall,
        );
        for e in inner.entries.values_mut() {
            e.unacked_route = Some(lan("192.168.1.20:7420"));
        }
        inner.kick_now(None, true, t0);
        assert!(inner
            .entries
            .values()
            .all(|e| e.unacked_route == Some(lan("192.168.1.20:7420"))));
        assert_eq!(inner.network_changed(t0), 2);
        assert!(inner.entries.values().all(|e| e.unacked_route.is_none()));
    }

    /// G3 + G1: an attempt in flight when the network changed wrote on the
    /// old network; the route it found silent there is not recorded (the
    /// kicked retry starts in plan order). Its outcome still counts, and the
    /// next attempt's silent route is recorded again.
    #[test]
    fn a_silent_route_from_before_a_network_change_is_not_recorded() {
        let t0 = Instant::now();
        let wall = 1_000_000_000u64;
        let peer = [0xB0; 32];
        let d = [1; 32];
        let l20 = lan("192.168.1.20:7420");
        let no_ack = Outcome::Sent {
            carrier: Some(OutboxCarrier::Lan),
            code: code::NO_ACK_YET,
        };
        let mut inner = Inner::default();
        inner.merge(vec![sched_row(1, 0xB0, wall + DAY)], 0, t0, wall);
        assert_eq!(inner.take_due(t0).len(), 1, "in flight");
        assert_eq!(inner.network_changed(t0 + Duration::from_secs(1)), 1);
        let end = t0 + Duration::from_secs(2);
        let mut r = report_for(d, no_ack.clone());
        r.unacked.insert(d, l20.clone());
        inner.apply(&peer, r, end, wall);
        let e = &inner.entries[&d];
        assert_eq!(e.unacked_route, None, "old-network evidence");
        assert_eq!((e.state, e.next_due), (EntryState::Sent, end), "kicked");
        // The next attempt (on the new network) records it again.
        assert_eq!(inner.take_due(end).len(), 1);
        let mut r = report_for(d, no_ack);
        r.unacked.insert(d, l20.clone());
        inner.apply(&peer, r, end + Duration::from_secs(5), wall);
        assert_eq!(inner.entries[&d].unacked_route, Some(l20));
    }

    /// G4: a send that forced no carrier (an `auto` record, here with the one
    /// LAN route that send had) falls back to the contact's Internet address
    /// once its LAN route is down, but only behind the Internet gate and for
    /// a verified contact; a `lan` record never leaves the LAN.
    #[test]
    fn an_auto_record_falls_back_beyond_the_lan_only_behind_its_gates() {
        if !lab_backends() {
            return;
        }
        let lan_down = Outcome::Unreachable {
            carrier: Some(OutboxCarrier::Lan),
            code: code::NOT_LISTENING,
        };
        let delivered_inet = Outcome::Delivered {
            carrier: Some(OutboxCarrier::Internet),
        };
        // (seed, recorded choice, verified, Internet gate open, delivered
        // over the Internet)
        for (seed, choice, pinned, internet_open, over_internet) in [
            (0xa5, CarrierChoice::Auto, true, true, true),
            (0xa7, CarrierChoice::Lan, true, true, false),
            // The release gates: no Internet dial at all.
            (0xa9, CarrierChoice::Auto, true, false, false),
            // The verified-contact rule.
            (0xab, CarrierChoice::Auto, false, true, false),
        ] {
            let internet_live: fn() -> bool = if internet_open { on } else { off };
            let want = if over_internet {
                &delivered_inet
            } else {
                &lan_down
            };
            let rig = Rig::new(seed);
            contacts(
                rig.a.path(),
                &rig.bob_pub,
                "127.0.0.1:9",
                "203.0.113.7:7422",
                pinned,
            );
            rig.set(UP);
            rig.set_route(lan("127.0.0.1:9"), DOWN);
            let mid = rig.stage("auto means any carrier allowed", DAY);
            rig.record(&mid, choice, &[lan("127.0.0.1:9")]);
            let report = rig.attempt_with(&rig.ctx_with(on, internet_live));
            assert_eq!(&only(&report), want, "{seed:#x} {choice:?}");
            let internet_dials = rig.net.internet_dials.load(Ordering::SeqCst);
            if over_internet {
                assert_eq!(internet_dials, 1, "{seed:#x}");
                assert_eq!(rig.bob_inbox(), ["auto means any carrier allowed"]);
                assert_eq!(rig.history(&mid).as_deref(), Some("delivered"));
            } else {
                assert_eq!(internet_dials, 0, "{seed:#x} {choice:?}");
                assert!(rig.bob_inbox().is_empty(), "{seed:#x}");
                assert_eq!(rig.history(&mid).as_deref(), Some("queued"));
            }
            assert_eq!(rig.dialled()[0], lan("127.0.0.1:9"), "LAN first");
        }
    }

    /// G4: a contact edit (`contact set-dial`, `set-addr`, ...) clears an auto
    /// record's routes but not its choice, so the address added afterwards is
    /// used: the record no longer falls to the no-record LAN-only plan.
    #[test]
    fn an_auto_record_survives_a_contact_edit() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0xaf);
        let mid = rig.stage("after the edit", DAY);
        rig.record(&mid, CarrierChoice::Auto, &[lan("127.0.0.1:9")]);
        raven_core::outbox::clear_peer_routes(rig.a.path(), &rig.bob_pub).unwrap();
        let records = object_route_records(rig.a.path(), now_ms()).unwrap();
        assert_eq!(records[&mid].choice, CarrierChoice::Auto);
        assert!(records[&mid].routes.is_empty());
        contacts(
            rig.a.path(),
            &rig.bob_pub,
            "127.0.0.1:9",
            "203.0.113.7:7422",
            true,
        );
        rig.set(UP);
        rig.set_route(lan("127.0.0.1:9"), DOWN);
        assert_eq!(
            only(&rig.attempt_with(&rig.ctx_with(on, on))),
            Outcome::Delivered {
                carrier: Some(OutboxCarrier::Internet)
            }
        );
        assert_eq!(
            rig.dialled(),
            [lan("127.0.0.1:9"), inet("203.0.113.7:7422")]
        );
        assert_eq!(rig.bob_inbox(), ["after the edit"]);
        assert_eq!(rig.history(&mid).as_deref(), Some("delivered"));
    }

    /// P: an inbound link triggers at most one dial-back per minute per contact.
    #[test]
    fn dial_backs_from_inbound_links_are_rate_limited() {
        let t0 = Instant::now();
        let mut inner = Inner::default();
        let (bob, carol) = ([1u8; 32], [2u8; 32]);
        assert!(inner.dialback_allowed(&bob, t0));
        assert!(!inner.dialback_allowed(&bob, t0 + Duration::from_secs(30)));
        assert!(inner.dialback_allowed(&carol, t0 + Duration::from_secs(30)));
        assert!(inner.dialback_allowed(&bob, t0 + DIALBACK_INTERVAL));
    }

    /// S: one IPC answer loads the history at most once, and only when needed.
    #[test]
    fn an_outbox_list_loads_the_history_at_most_once() {
        let calls = std::cell::Cell::new(0);
        let gone = |i: u8| OutboxItem {
            message_id_hex: hex::encode([i; 16]),
            state: "gone".into(),
            ..OutboxItem::default()
        };
        let mut items = vec![gone(1), gone(2), gone(3)];
        resolve_from_history(&mut items, || {
            calls.set(calls.get() + 1);
            (1..=3u8)
                .map(|i| {
                    (
                        hex::encode([i; 16]),
                        (String::new(), "delivered".to_string()),
                    )
                })
                .collect()
        });
        assert_eq!(calls.get(), 1);
        assert!(items.iter().all(|i| i.state == "delivered"));
        let mut live = vec![OutboxItem {
            state: "queued".into(),
            ..OutboxItem::default()
        }];
        resolve_from_history(&mut live, || {
            calls.set(calls.get() + 1);
            HistoryStates::new()
        });
        assert_eq!(calls.get(), 1, "not loaded when no row needs it");
    }

    #[test]
    fn backoff_has_a_floor_and_never_waits_past_the_expiry() {
        let t = Instant::now();
        let wall = 1_000_000u64;
        let mut e = Entry::from_row(&sched_row(1, 0xB0, wall + 60_000), t);
        for _ in 0..20 {
            apply_outcome(&mut e, unreachable(), t, wall);
            assert!(
                e.next_due <= t + Duration::from_secs(60),
                "not past the expiry"
            );
            assert!(e.next_due >= t + MIN_RETRY);
        }
        assert_eq!(e.attempts, 20);
        apply_outcome(
            &mut e,
            Outcome::Delivered {
                carrier: Some(OutboxCarrier::Lan),
            },
            t,
            wall,
        );
        assert_eq!((e.attempts, e.state), (21, EntryState::Delivered));
        assert_eq!(e.item(t, wall).next_attempt_ms, 0);
        let mut e = Entry::from_row(&sched_row(1, 0xB0, wall + DAY), t);
        apply_outcome(&mut e, Outcome::Held(CONTACT_NOT_VERIFIED), t, wall);
        assert_eq!(e.item(t, wall).state, "held");
        assert_eq!(e.item(t, wall).last_error_code, CONTACT_NOT_VERIFIED);
        assert_eq!(
            retry_wait(0, 0, wall, 0.0),
            MIN_RETRY,
            "past expiry: the floor"
        );
    }

    #[test]
    fn dial_errors_map_to_fixed_codes_without_addresses() {
        let unavailable = raven_core::nearby_gate::nearby_dial_unavailable();
        for (text, want) in [
            (
                "ipc LAN_DIAL: lan connect: cannot connect to 10.0.0.5:7420 (Connection refused)",
                code::NOT_LISTENING,
            ),
            (
                "lan dial to x:1 timed out after 40s while connecting",
                code::NOT_REACHABLE,
            ),
            (
                "LAN_DIAL_PEER_CLOSED: the peer closed the connection without replying",
                code::PEER_REFUSED,
            ),
            (crate::netutil::LINK_NOT_ACCEPTED, code::LINK_NOT_ACCEPTED),
            (crate::internet_direct::HOLD, code::INTERNET_HOLD),
            (
                "CONTACT_NOT_VERIFIED: Internet delivery needs a verified contact",
                CONTACT_NOT_VERIFIED,
            ),
            ("rlb1 offer identity mismatch", code::WRONG_IDENTITY),
            (crate::lan_direct::NOISE_PIN_MISMATCH, code::WRONG_IDENTITY),
            (
                "ipc LAN_DIAL: lan noise pin mismatch: a different key answered",
                code::WRONG_IDENTITY,
            ),
            (
                crate::lan_direct::NOISE_PIN_UNAVAILABLE,
                code::PIN_STORE_UNREADABLE,
            ),
            (
                "ipc LAN_DIAL: lan noise pin unavailable: lan_noise_pins.json: permission denied",
                code::PIN_STORE_UNREADABLE,
            ),
            (raven_core::NEARBY_HOLD, code::NEARBY_HOLD),
            (
                crate::nearby::NEARBY_NOT_IN_RANGE,
                code::NEARBY_NOT_IN_RANGE,
            ),
            (crate::nearby::NEARBY_BUSY, code::NEARBY_BUSY),
            (
                "NEARBY_NOT_IN_RANGE: the contact's Bluetooth beacon is not seen now (no pipe \
                 within 12 s)",
                code::NEARBY_NOT_IN_RANGE,
            ),
            (crate::nearby::NEARBY_NOT_RUNNING, code::NEARBY_NOT_RUNNING),
            (
                unavailable.as_str(),
                if raven_core::nearby_live_enabled() {
                    code::NEARBY_NOT_RUNNING
                } else {
                    code::NEARBY_HOLD
                },
            ),
            ("something else", code::DIAL_FAILED),
        ] {
            assert_eq!(dial_error_code(text), want, "{text}");
        }
        assert!(blocks_route(code::WRONG_IDENTITY) && blocks_route(code::LINK_NOT_ACCEPTED));
        assert!(!blocks_route(code::NOT_REACHABLE) && !blocks_route(code::PEER_REFUSED));
        // Only a noise pin mismatch gets the scoped block.
        assert!(is_noise_pin_mismatch(crate::lan_direct::NOISE_PIN_MISMATCH));
        for other in [
            "rlb1 offer identity mismatch",
            "identity bind does not match expected pub",
            crate::netutil::LINK_NOT_ACCEPTED,
            crate::lan_direct::NOISE_PIN_UNAVAILABLE,
        ] {
            assert!(!is_noise_pin_mismatch(other), "{other}");
        }
    }

    /// Phase 6a (P6.4): every stable code has a row in the learning table
    /// (a failure weight or "not evidence"), so no code the worker records
    /// falls through to the unknown-code default.
    #[test]
    fn every_dial_code_has_a_learning_weight() {
        use raven_core::learning::observe::{known_code, weight_m, FULL_FAIL_W_M};
        let codes = [
            code::NOT_A_CONTACT,
            code::CONTACT_BLOCKED,
            code::CONTACTS_UNREADABLE,
            code::NO_ROUTE,
            code::DEFERRED,
            code::SEND_IN_PROGRESS,
            code::LOCK,
            code::LOCAL_DEVICE,
            code::LOCAL_DEVICE_REVOKED,
            code::PEER_REVOKED,
            code::NO_PEER_CERT,
            code::NO_LOCAL_BODY,
            code::HISTORY,
            code::CLOCK,
            code::STORE,
            code::NO_ACK_YET,
            code::STAGE,
            code::SUPERSEDED,
            code::EXPIRED,
            code::INTERNET_HOLD,
            code::P2P_HOLD,
            code::P2P_NOT_RUNNING,
            code::NEARBY_HOLD,
            code::NEARBY_NOT_RUNNING,
            code::NEARBY_NOT_IN_RANGE,
            code::NEARBY_BUSY,
            code::LINK_NOT_ACCEPTED,
            code::PEER_REFUSED,
            code::WRONG_IDENTITY,
            code::NOT_LISTENING,
            code::NOT_REACHABLE,
            code::CLOSED_EARLY,
            code::DIAL_FAILED,
            code::PIN_STORE_UNREADABLE,
            code::PEER_RESET,
            code::PEER_RESET_NO_BODY,
            code::RESEAL_CAP,
            code::IN_CUSTODY,
            code::NO_SHARED_CUSTODIAN,
            code::CUSTODIAN_NOT_OFFERING,
            code::MAILBOX_OFF,
            code::WAITING_FOR_CARRIER,
            code::CARRIER_FULL,
            code::NO_SHARED_CARRIER,
            code::SENDING_PAUSED,
            code::ONION_HOLD,
            code::ONION_NOT_READY,
            code::ONION_UNREACHABLE,
        ];
        // The list is every name `mod code` declares: a new code fails here
        // until it is listed above and has a learning row.
        let src = include_str!("outbox.rs");
        let start = src.find("pub(crate) mod code {").unwrap();
        let body = &src[start..start + src[start..].find("\n}\n").unwrap()];
        let mut declared = body
            .lines()
            .filter_map(|l| l.trim_start().strip_prefix("pub const "))
            .filter_map(|l| l.split(':').next())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        for line in body.lines().filter(|l| l.contains("pub use ")) {
            // `pub use path::{A, B};` or `pub use path::A;`.
            let names = match (line.find('{'), line.find('}')) {
                (Some(open), Some(close)) => &line[open + 1..close],
                _ => line
                    .trim_end()
                    .trim_end_matches(';')
                    .rsplit("::")
                    .next()
                    .unwrap(),
            };
            declared.extend(names.split(',').map(|n| n.trim().to_owned()));
        }
        assert_eq!(declared.len(), codes.len(), "{declared:?}");
        // Each listed constant's value is its name.
        let mut names = codes.to_vec();
        names.sort_unstable();
        declared.sort_unstable();
        assert_eq!(names, declared);
        // `dial_error_code` also returns CONTACT_NOT_VERIFIED.
        for c in codes.into_iter().chain([CONTACT_NOT_VERIFIED]) {
            assert!(known_code(c), "{c} has no learning row");
            let w = weight_m(c);
            assert!(w.is_none_or(|w| (1..=FULL_FAIL_W_M).contains(&w)), "{c}");
        }
        // A route that will not change by retrying counts in full, as does
        // a failure that says nothing more; a hold and a contact out of
        // range are never evidence.
        assert!(blocks_route(code::WRONG_IDENTITY) && blocks_route(code::LINK_NOT_ACCEPTED));
        for c in [
            code::WRONG_IDENTITY,
            code::LINK_NOT_ACCEPTED,
            code::DIAL_FAILED,
        ] {
            assert_eq!(weight_m(c), Some(FULL_FAIL_W_M), "{c}");
        }
        for c in [
            code::INTERNET_HOLD,
            code::P2P_HOLD,
            code::NEARBY_HOLD,
            code::NEARBY_NOT_IN_RANGE,
            code::NEARBY_BUSY,
            code::SEND_IN_PROGRESS,
            CONTACT_NOT_VERIFIED,
        ] {
            assert_eq!(weight_m(c), None, "{c}");
        }
    }

    /// Outbox IPC items carry identifiers, states and counts, never content.
    #[test]
    fn outbox_items_carry_no_plaintext() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0xa3);
        let secret = "the-secret-words-never-leave-the-store";
        rig.stage(secret, DAY);
        let item = rig.due().remove(0).item(Instant::now(), now_ms());
        let json = serde_json::to_string(&item).unwrap();
        assert!(
            !json.contains(secret) && !json.contains("the-secret"),
            "{json}"
        );
        assert_eq!(
            (item.kind.as_str(), item.state.as_str()),
            ("message", "queued")
        );
        assert_eq!(item.peer_pub_hex, hex::encode(rig.bob_pub));
    }

    // ---- session reset (lost-state recovery §12) ----

    struct ResetLab;
    impl ResetLab {
        fn on() -> Self {
            raven_core::session_reset::set_lab_session_reset_for_this_thread(Some(1));
            ResetLab
        }
    }
    impl Drop for ResetLab {
        fn drop(&mut self) {
            raven_core::session_reset::set_lab_session_reset_for_this_thread(None);
        }
    }

    fn texts(report: &PeerReport) -> Vec<Outcome> {
        let mut v: Vec<Outcome> = report.outcomes.values().cloned().collect();
        v.sort_by_key(|o| format!("{o:?}"));
        v
    }

    #[test]
    fn worker_recovers_wiped_peer_without_a_new_send() {
        if !lab_backends() {
            return;
        }
        let _lab = ResetLab::on();
        let rig = Rig::new(0xc1);
        let q1 = rig.stage_queued("q1", DAY);
        let q2 = rig.stage_queued("q2", DAY);
        rig.wipe_bob(false);
        rig.set(STRICT);
        let ctx = rig.ctx();
        // 1: the dial is refused; the query finds no session; retired.
        let report = rig.attempt_with(&ctx);
        assert!(
            report
                .outcomes
                .values()
                .all(|o| *o == Outcome::Held(code::PEER_RESET)),
            "{:?}",
            texts(&report)
        );
        // The query rode alone.
        assert!(rig.net.log.lock().unwrap().iter().any(|(_, n)| *n == 1));
        // 2: the reset step pairs again (LAN, local) and re-seals both.
        let report = rig.attempt_with(&ctx);
        assert!(
            report.outcomes.values().all(|o| *o == Outcome::Resealed),
            "{:?}",
            texts(&report)
        );
        // 3: the new copies go out and are delivered.
        let report = rig.attempt_with(&ctx);
        assert!(
            report
                .outcomes
                .values()
                .all(|o| matches!(o, Outcome::Delivered { .. })),
            "{:?}",
            texts(&report)
        );
        assert_eq!(rig.bob_inbox(), vec!["q1".to_string(), "q2".to_string()]);
        for mid in [q1, q2] {
            assert_eq!(rig.history(&mid).as_deref(), Some("delivered"));
        }
    }

    #[test]
    fn old_peer_refusal_keeps_superseded_rule() {
        if !lab_backends() {
            return;
        }
        let _lab = ResetLab::on();
        let rig = Rig::new(0xc3);
        rig.stage("to an old peer", DAY);
        rig.set(REFUSE);
        let report = rig.attempt();
        assert!(matches!(
            only(&report),
            Outcome::Unreachable {
                code: code::PEER_REFUSED,
                ..
            }
        ));
        // Nothing was retired: the old rules apply.
        assert!(IndexedSessionStore::open(rig.a.path())
            .unwrap()
            .find_sendable_session_for_peer(&rig.bob_pub)
            .unwrap()
            .is_some());
    }

    #[test]
    fn query_backoff_follows_unanswered_queries() {
        assert_eq!(reset_query_wait(0), Duration::ZERO);
        assert_eq!(reset_query_wait(1), Duration::from_secs(60));
        assert_eq!(reset_query_wait(4), Duration::from_secs(3_600));
        assert_eq!(reset_query_wait(40), Duration::from_secs(3_600));
    }

    #[test]
    fn send_lock_not_held_across_reset_dials() {
        if !lab_backends() {
            return;
        }
        let _lab = ResetLab::on();
        let rig = Rig::new(0xc5);
        rig.stage_queued("q1", DAY);
        rig.wipe_bob(false);
        rig.set(STRICT);
        let ctx = rig.ctx();
        // Every dial: the refused message, the query, the reset probe and the
        // PairInit.
        *rig.net.lock_probe.lock().unwrap() = Some((rig.a.path().to_path_buf(), rig.bob_pub));
        rig.attempt_with(&ctx);
        let report = rig.attempt_with(&ctx);
        assert!(report.outcomes.values().all(|o| *o == Outcome::Resealed));
        assert!(
            rig.net.rsr1_frames.load(Ordering::SeqCst) >= 1,
            "a query was dialled"
        );
        assert!(rig.net.probed_dials.load(Ordering::SeqCst) >= 4);
        assert_eq!(rig.net.dials_with_lock_held.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn resealed_entries_keep_route_records_and_status_shows_live_copy() {
        if !lab_backends() {
            return;
        }
        let _lab = ResetLab::on();
        let rig = Rig::new(0xc7);
        let mid = rig.stage_queued("q1", DAY);
        rig.record(&mid, CarrierChoice::Lan, &[lan("127.0.0.1:9")]);
        rig.wipe_bob(false);
        rig.set(STRICT);
        let ctx = rig.ctx();
        rig.attempt_with(&ctx);
        let report = rig.attempt_with(&ctx);
        assert!(report.outcomes.values().all(|o| *o == Outcome::Resealed));
        // The route record (keyed by message id) is shared by the new copy.
        let records = object_route_records(rig.a.path(), now_ms()).unwrap();
        assert!(records.contains_key(&mid));
        // Applying a Resealed outcome drops the old entry without finishing it.
        let mut inner = Inner::default();
        let t = Instant::now();
        let mut row = sched_row(7, 0xC8, u64::MAX);
        row.recipient = rig.bob_pub;
        inner.merge(vec![row.clone()], inner.scan_seq(), t, now_ms());
        inner.apply(
            &rig.bob_pub,
            report_for(row.object_digest, Outcome::Resealed),
            t,
            now_ms(),
        );
        assert!(inner.entries.is_empty());
        assert!(inner.done.is_empty());
        assert!(inner.refresh);
    }

    #[test]
    fn peer_reset_immediate_retry_happens_once_then_backs_off() {
        let t = Instant::now();
        let mut e = Entry::from_row(&sched_row(1, 0xB1, u64::MAX), t);
        apply_outcome(&mut e, Outcome::Held(code::PEER_RESET), t, 0);
        assert_eq!(e.next_due, t);
        assert_eq!(e.failures, 0);
        apply_outcome(&mut e, Outcome::Held(code::PEER_RESET), t, 0);
        assert!(e.next_due > t);
        assert_eq!(e.failures, 1);
    }

    #[test]
    fn worker_recovers_fresh_cert_peer_via_e2_without_any_rsr1() {
        if !lab_backends() {
            return;
        }
        let _lab = ResetLab::on();
        let rig = Rig::new(0xc9);
        let q1 = rig.stage_queued("q1", DAY);
        rig.wipe_bob(true);
        // Bob's new offer reached Alice first (he dialled her): cached.
        let b_new = local_bundle(rig.b.path(), &rig.net.bob).unwrap();
        assert_ne!(b_new.cert, rig.b_bundle.cert);
        cache_peer_bundle(rig.a.path(), &b_new).unwrap();
        rig.set(STRICT);
        let ctx = rig.ctx();
        // 1: no certificate bound to the session any more: the probe and E2
        //    retire it; the row waits for the reset step.
        let report = rig.attempt_with(&ctx);
        assert!(
            report
                .outcomes
                .values()
                .all(|o| *o == Outcome::Held(code::PEER_RESET)),
            "{:?}",
            texts(&report)
        );
        // 2: a new local session, re-seal; 3: delivered.
        let report = rig.attempt_with(&ctx);
        assert!(
            report.outcomes.values().all(|o| *o == Outcome::Resealed),
            "{:?}",
            texts(&report)
        );
        let report = rig.attempt_with(&ctx);
        assert!(
            report
                .outcomes
                .values()
                .all(|o| matches!(o, Outcome::Delivered { .. })),
            "{:?}",
            texts(&report)
        );
        assert_eq!(rig.bob_inbox(), vec!["q1".to_string()]);
        assert_eq!(rig.history(&q1).as_deref(), Some("delivered"));
        assert_eq!(
            rig.net.rsr1_frames.load(Ordering::SeqCst),
            0,
            "E2 needs no query"
        );
    }

    // ---- friend custody (§7.3) ----

    /// Alice's dials, routed by the expected key: Bob (maybe down) and Carol.
    struct ThreeNet {
        alice_bundle: LanBundle,
        alice_pub: [u8; 32],
        nodes: Vec<(String, PathBuf, Identity)>,
        bob_hex: String,
        bob_down: AtomicBool,
    }

    impl Dialer for ThreeNet {
        fn dial(
            &self,
            _data_dir: &Path,
            _route: &OutboxRoute,
            expected: &str,
            frames: &[Vec<u8>],
        ) -> Result<Vec<Vec<u8>>, String> {
            if expected == self.bob_hex && self.bob_down.load(Ordering::SeqCst) {
                return Err("lan connect: cannot connect (Connection refused)".into());
            }
            let (_, dir, id) = self
                .nodes
                .iter()
                .find(|(hex, _, _)| hex == expected)
                .ok_or("unknown peer")?;
            let mut replies = vec![raven_core::encode_local_offer(dir, id).unwrap()];
            for f in frames {
                replies.extend(raven_core::lan_dispatch::dispatch_frame_on(
                    dir,
                    id,
                    &self.alice_bundle,
                    &self.alice_pub,
                    f,
                    raven_core::friend_custody::InboundLink {
                        carrier: OutboxCarrier::Lan,
                        source: Some("192.168.1.40".parse().unwrap()),
                    },
                )?);
            }
            Ok(replies)
        }
    }

    #[test]
    fn worker_leaves_a_message_with_a_friend_while_the_contact_is_down() {
        if !lab_backends() {
            return;
        }
        // Custody routes and the custodian's links read `raven lan off`.
        let _lan = crate::lan_direct::lan_switch_untouched();
        raven_core::custody_gate::set_custody_gates_for_this_thread(Some(
            raven_core::custody_gate::CustodyGates {
                live: true,
                wan: false,
            },
        ));
        let rig = Rig::new(0xd1);
        let carol = Identity::from_seed(&[0xd9; 32]);
        let c_dir = tempfile::tempdir().unwrap();
        ensure_local_device_certificate(c_dir.path(), &carol, PRIMARY_DEVICE_ID).unwrap();
        raven_core::ensure_local_prekey(c_dir.path(), &carol).unwrap();
        let hexk = |k: &[u8; 32]| hex::encode(k);
        let (alice_pub, carol_pub) = (rig.alice.public_key_bytes(), carol.public_key_bytes());
        // Alice: Bob (pinned, custodian Carol) and Carol (pinned).
        std::fs::write(
            rig.a.path().join("contacts.json"),
            format!(
                r#"[{{"petname":"Bob","pub_hex":"{}","pinned":true,"lan_dial":"127.0.0.1:9","custodians":["{}"]}},
                   {{"petname":"Carol","pub_hex":"{}","pinned":true,"lan_dial":"192.168.1.50:7420"}}]"#,
                hexk(&rig.bob_pub),
                hexk(&carol_pub),
                hexk(&carol_pub)
            ),
        )
        .unwrap();
        // Carol: both pinned, custody on.
        std::fs::write(
            c_dir.path().join("contacts.json"),
            format!(
                r#"[{{"petname":"Alice","pub_hex":"{}","pinned":true}},{{"petname":"Bob","pub_hex":"{}","pinned":true}}]"#,
                hexk(&alice_pub),
                hexk(&rig.bob_pub)
            ),
        )
        .unwrap();
        raven_core::save_policy(
            c_dir.path(),
            &raven_core::NodePolicy {
                custody: true,
                ..Default::default()
            },
        )
        .unwrap();
        // Queued two minutes ago (the direct path had its chance).
        let mid = rig.stage_with("via carol", now_ms() - 120_000, DAY, true);
        rig.record(&mid, CarrierChoice::Auto, &[lan("127.0.0.1:9")]);
        raven_core::outbox::set_object_custody(rig.a.path(), &mid, now_ms()).unwrap();
        let net = Arc::new(ThreeNet {
            alice_bundle: local_bundle(rig.a.path(), &rig.alice).unwrap(),
            alice_pub,
            nodes: vec![
                (
                    hexk(&rig.bob_pub),
                    rig.b.path().to_path_buf(),
                    Identity::from_seed(&[0xd2; 32]),
                ),
                (hexk(&carol_pub), c_dir.path().to_path_buf(), carol),
            ],
            bob_hex: hexk(&rig.bob_pub),
            bob_down: AtomicBool::new(true),
        });
        let ctx = AttemptCtx {
            data_dir: rig.a.path().to_path_buf(),
            identity: Arc::clone(&rig.alice),
            dialer: net.clone(),
            lan_live: on,
            internet_live: off,
            p2p_live: off,
            nearby_live: off,
            nearby_available: no_nearby,
            onion_live: || false,
            onion_available: || false,
            onion_head_start: crate::onion::head_start,
            net_tag: no_net,
            on_link: unknown_link,
            connected: never_connected,
            lan_beacon_routes: no_finds,
            lan_want: no_want,
            lan_beacon_failed: no_find_failed,
            reset_backoff: Mutex::default(),
        };
        let report = rig.attempt_with(&ctx);
        assert_eq!(only(&report), Outcome::Deposited { held: 1 });
        let records = object_route_records(rig.a.path(), now_ms()).unwrap();
        assert_eq!(records[&mid].custodians_held, vec![hexk(&carol_pub)]);
        // The next attempt does not file it again, and stays IN_CUSTODY.
        let report = rig.attempt_with(&ctx);
        assert_eq!(only(&report), Outcome::Deposited { held: 1 });
        let held = raven_core::friend_custody::CustodyStore::open_existing(c_dir.path())
            .unwrap()
            .unwrap()
            .usage()
            .unwrap();
        assert_eq!(held.0, 1, "exactly one copy at Carol");
        // A deposit is never a delivery.
        assert_eq!(rig.history(&mid).as_deref(), Some("queued"));
        raven_core::custody_gate::set_custody_gates_for_this_thread(None);
    }

    /// [`ThreeNet`] that logs the custodian's routes and refuses its saved
    /// one and where the LAN beacon last found it (Carol moved).
    struct CustodianMoved {
        net: ThreeNet,
        carol_hex: String,
        saved: OutboxRoute,
        stale: OutboxRoute,
        carol_dials: Mutex<Vec<OutboxRoute>>,
    }

    impl Dialer for CustodianMoved {
        fn dial(
            &self,
            data_dir: &Path,
            route: &OutboxRoute,
            expected: &str,
            frames: &[Vec<u8>],
        ) -> Result<Vec<Vec<u8>>, String> {
            if expected == self.carol_hex {
                self.carol_dials.lock().unwrap().push(route.clone());
                if *route == self.saved || *route == self.stale {
                    return Err("lan connect: cannot connect (Connection refused)".into());
                }
            }
            self.net.dial(data_dir, route, expected, frames)
        }
    }

    /// The deposit plans the custodian through the worker's on-link filter:
    /// an address it last reached us from, on none of this computer's
    /// networks now, is not dialled (the signed bind would go to whoever
    /// holds it); on this network, or not known, it is.
    #[test]
    fn a_deposit_never_dials_a_custodian_address_off_this_network() {
        if !lab_backends() {
            return;
        }
        // Custody routes and the custodian's links read `raven lan off`.
        let _lan = crate::lan_direct::lan_switch_untouched();
        raven_core::custody_gate::set_custody_gates_for_this_thread(Some(
            raven_core::custody_gate::CustodyGates {
                live: true,
                wan: false,
            },
        ));
        let rig = Rig::new(0xe3);
        let carol = Identity::from_seed(&[0xe5; 32]);
        let c_dir = tempfile::tempdir().unwrap();
        ensure_local_device_certificate(c_dir.path(), &carol, PRIMARY_DEVICE_ID).unwrap();
        raven_core::ensure_local_prekey(c_dir.path(), &carol).unwrap();
        let hexk = |k: &[u8; 32]| hex::encode(k);
        let (alice_pub, carol_pub) = (rig.alice.public_key_bytes(), carol.public_key_bytes());
        std::fs::write(
            rig.a.path().join("contacts.json"),
            format!(
                r#"[{{"petname":"Bob","pub_hex":"{}","pinned":true,"lan_dial":"127.0.0.1:9","custodians":["{}"]}},
                   {{"petname":"Carol","pub_hex":"{}","pinned":true,"lan_dial":"192.168.1.50:7420"}}]"#,
                hexk(&rig.bob_pub),
                hexk(&carol_pub),
                hexk(&carol_pub)
            ),
        )
        .unwrap();
        std::fs::write(
            c_dir.path().join("contacts.json"),
            format!(
                r#"[{{"petname":"Alice","pub_hex":"{}","pinned":true}},{{"petname":"Bob","pub_hex":"{}","pinned":true}}]"#,
                hexk(&alice_pub),
                hexk(&rig.bob_pub)
            ),
        )
        .unwrap();
        raven_core::save_policy(
            c_dir.path(),
            &raven_core::NodePolicy {
                custody: true,
                ..Default::default()
            },
        )
        .unwrap();
        // Carol last reached Alice from another address.
        let seen: IpAddr = "192.168.1.60".parse().unwrap();
        raven_core::lan_seen::record_contact_seen(rig.a.path(), &carol_pub, seen, None, now_ms())
            .unwrap();
        let mid = rig.stage_with("via carol", now_ms() - 120_000, DAY, true);
        rig.record(&mid, CarrierChoice::Auto, &[lan("127.0.0.1:9")]);
        raven_core::outbox::set_object_custody(rig.a.path(), &mid, now_ms()).unwrap();
        let (saved, learned) = (lan("192.168.1.50:7420"), lan("192.168.1.60:7420"));
        let net = Arc::new(CustodianMoved {
            net: ThreeNet {
                alice_bundle: local_bundle(rig.a.path(), &rig.alice).unwrap(),
                alice_pub,
                nodes: vec![
                    (
                        hexk(&rig.bob_pub),
                        rig.b.path().to_path_buf(),
                        Identity::from_seed(&[0xe4; 32]),
                    ),
                    (hexk(&carol_pub), c_dir.path().to_path_buf(), carol),
                ],
                bob_hex: hexk(&rig.bob_pub),
                bob_down: AtomicBool::new(true),
            },
            carol_hex: hexk(&carol_pub),
            saved: saved.clone(),
            stale: lan("192.168.1.99:7420"),
            carol_dials: Mutex::new(Vec::new()),
        });
        let ctx = |on_link: fn(IpAddr) -> Option<bool>| AttemptCtx {
            data_dir: rig.a.path().to_path_buf(),
            identity: Arc::clone(&rig.alice),
            dialer: net.clone(),
            lan_live: on,
            internet_live: off,
            p2p_live: off,
            nearby_live: off,
            nearby_available: no_nearby,
            onion_live: || false,
            onion_available: || false,
            onion_head_start: crate::onion::head_start,
            net_tag: no_net,
            on_link,
            connected: never_connected,
            lan_beacon_routes: no_finds,
            lan_want: no_want,
            lan_beacon_failed: no_find_failed,
            reset_backoff: Mutex::default(),
        };
        // Review A-5: the LAN beacon found Carol where she no longer is. The
        // deposit dials that find first (no learned route then), and the
        // beacon is told to forget it, as a delivery dial tells it.
        fn carol_finds(peer: &[u8; 32]) -> Vec<String> {
            if *peer == Identity::from_seed(&[0xe5; 32]).public_key_bytes() {
                vec!["192.168.1.99:7420".into()]
            } else {
                Vec::new()
            }
        }
        let found = AttemptCtx {
            lan_beacon_routes: carol_finds,
            lan_beacon_failed: forgot,
            ..ctx(|_| Some(false))
        };
        let report = rig.attempt_with(&found);
        assert_ne!(only(&report), Outcome::Deposited { held: 1 });
        assert_eq!(
            *net.carol_dials.lock().unwrap(),
            [net.stale.clone(), saved.clone()]
        );
        assert_eq!(beacon_asked(), (Vec::new(), vec![net.stale.dial.clone()]));
        net.carol_dials.lock().unwrap().clear();
        let report = rig.attempt_with(&ctx(|_| Some(false)));
        assert_ne!(only(&report), Outcome::Deposited { held: 1 });
        assert_eq!(
            *net.carol_dials.lock().unwrap(),
            std::slice::from_ref(&saved)
        );
        net.carol_dials.lock().unwrap().clear();
        let report = rig.attempt_with(&ctx(unknown_link));
        raven_core::custody_gate::set_custody_gates_for_this_thread(None);
        assert_eq!(only(&report), Outcome::Deposited { held: 1 });
        assert_eq!(*net.carol_dials.lock().unwrap(), [saved, learned]);
    }

    #[test]
    fn a_message_left_with_a_friend_counts_as_written() {
        if !lab_backends() {
            return;
        }
        // Custody routes and the custodian's links read `raven lan off`.
        let _lan = crate::lan_direct::lan_switch_untouched();
        raven_core::custody_gate::set_custody_gates_for_this_thread(Some(
            raven_core::custody_gate::CustodyGates {
                live: true,
                wan: false,
            },
        ));
        let rig = Rig::new(0xe1);
        let carol = Identity::from_seed(&[0xd9; 32]);
        let c_dir = tempfile::tempdir().unwrap();
        ensure_local_device_certificate(c_dir.path(), &carol, PRIMARY_DEVICE_ID).unwrap();
        raven_core::ensure_local_prekey(c_dir.path(), &carol).unwrap();
        let hexk = |k: &[u8; 32]| hex::encode(k);
        let (alice_pub, carol_pub) = (rig.alice.public_key_bytes(), carol.public_key_bytes());
        // Alice: Bob (pinned, custodian Carol) and Carol (pinned).
        std::fs::write(
            rig.a.path().join("contacts.json"),
            format!(
                r#"[{{"petname":"Bob","pub_hex":"{}","pinned":true,"lan_dial":"127.0.0.1:9","custodians":["{}"]}},
                   {{"petname":"Carol","pub_hex":"{}","pinned":true,"lan_dial":"192.168.1.50:7420"}}]"#,
                hexk(&rig.bob_pub),
                hexk(&carol_pub),
                hexk(&carol_pub)
            ),
        )
        .unwrap();
        // Carol: both pinned, custody on.
        std::fs::write(
            c_dir.path().join("contacts.json"),
            format!(
                r#"[{{"petname":"Alice","pub_hex":"{}","pinned":true}},{{"petname":"Bob","pub_hex":"{}","pinned":true}}]"#,
                hexk(&alice_pub),
                hexk(&rig.bob_pub)
            ),
        )
        .unwrap();
        raven_core::save_policy(
            c_dir.path(),
            &raven_core::NodePolicy {
                custody: true,
                ..Default::default()
            },
        )
        .unwrap();
        // Queued two minutes ago (the direct path had its chance).
        let mid = rig.stage_with("via carol", now_ms() - 120_000, DAY, true);
        rig.record(&mid, CarrierChoice::Auto, &[lan("127.0.0.1:9")]);
        raven_core::outbox::set_object_custody(rig.a.path(), &mid, now_ms()).unwrap();
        // ash queued it while Bob was unreachable: nothing went on the wire.
        raven_core::outbox::set_object_unsent(rig.a.path(), &mid, true, now_ms()).unwrap();
        let net = Arc::new(ThreeNet {
            alice_bundle: local_bundle(rig.a.path(), &rig.alice).unwrap(),
            alice_pub,
            nodes: vec![
                (
                    hexk(&rig.bob_pub),
                    rig.b.path().to_path_buf(),
                    Identity::from_seed(&[0xd2; 32]),
                ),
                (hexk(&carol_pub), c_dir.path().to_path_buf(), carol),
            ],
            bob_hex: hexk(&rig.bob_pub),
            bob_down: AtomicBool::new(true),
        });
        let ctx = AttemptCtx {
            data_dir: rig.a.path().to_path_buf(),
            identity: Arc::clone(&rig.alice),
            dialer: net.clone(),
            lan_live: on,
            internet_live: off,
            p2p_live: off,
            nearby_live: off,
            nearby_available: no_nearby,
            onion_live: || false,
            onion_available: || false,
            onion_head_start: crate::onion::head_start,
            net_tag: no_net,
            on_link: unknown_link,
            connected: never_connected,
            lan_beacon_routes: no_finds,
            lan_want: no_want,
            lan_beacon_failed: no_find_failed,
            reset_backoff: Mutex::default(),
        };
        let report = rig.attempt_with(&ctx);
        assert_eq!(only(&report), Outcome::Deposited { held: 1 });
        let records = object_route_records(rig.a.path(), now_ms()).unwrap();
        assert_eq!(records[&mid].custodians_held, vec![hexk(&carol_pub)]);
        // Carol holds it (Bob will fetch it): it counts as written.
        assert!(!records[&mid].unsent, "a deposit is a write");
        let rows = scan_store(rig.a.path()).unwrap();
        let row = rows.iter().find(|r| r.message_id == mid).unwrap();
        assert_eq!(row.state, EntryState::Sent);
        // The next attempt does not file it again, and stays IN_CUSTODY.
        let report = rig.attempt_with(&ctx);
        assert_eq!(only(&report), Outcome::Deposited { held: 1 });
        let held = raven_core::friend_custody::CustodyStore::open_existing(c_dir.path())
            .unwrap()
            .unwrap()
            .usage()
            .unwrap();
        assert_eq!(held.0, 1, "exactly one copy at Carol");
        // A deposit is never a delivery.
        assert_eq!(rig.history(&mid).as_deref(), Some("queued"));
        raven_core::custody_gate::set_custody_gates_for_this_thread(None);
    }

    #[test]
    fn a_friends_copy_never_masks_the_superseded_give_up() {
        if !lab_backends() {
            return;
        }
        // Custody routes and the custodian's links read `raven lan off`.
        let _lan = crate::lan_direct::lan_switch_untouched();
        raven_core::custody_gate::set_custody_gates_for_this_thread(Some(
            raven_core::custody_gate::CustodyGates {
                live: true,
                wan: false,
            },
        ));
        let rig = Rig::new(0xeb);
        let mid = rig.stage("old session", DAY);
        rig.record(&mid, CarrierChoice::Auto, &[lan("127.0.0.1:9")]);
        // A friend holds a copy (an earlier deposit).
        raven_core::outbox::add_object_custodians(rig.a.path(), &mid, &[[0xC7; 32]], now_ms())
            .unwrap();
        let alice = Identity::from_seed(&[0xeb; 32]);
        let bob = Identity::from_seed(&[0xec; 32]);
        let a_bundle = local_bundle(rig.a.path(), &alice).unwrap();
        pair(
            rig.a.path(),
            &alice,
            rig.b.path(),
            &bob,
            &a_bundle,
            &rig.b_bundle,
        );
        rig.set(REFUSE);
        let mut entry = rig.due().remove(0);
        let Some(long_ago) = Instant::now().checked_sub(SUPERSEDED_SPAN + Duration::from_secs(1))
        else {
            return;
        };
        entry.refusals = 2;
        entry.first_refusal = Some(long_ago);
        let report = attempt_peer(&rig.ctx(), &rig.bob_pub, std::slice::from_ref(&entry), &[]);
        raven_core::custody_gate::set_custody_gates_for_this_thread(None);
        // The superseded rule decides, whoever holds a copy.
        assert_eq!(only(&report), Outcome::Failed(code::SUPERSEDED));
    }

    // ---- route memory (G2) ----

    /// What A's route memory holds for Bob on `test-net` now.
    fn remembered(rig: &Rig) -> Option<OutboxRoute> {
        raven_core::route_memory::preferred_route(
            rig.a.path(),
            &rig.bob_pub,
            test_net().as_deref(),
            now_ms(),
        )
    }

    /// `route` reached Bob on `net` right after a LAN route above it failed.
    fn remember_on(rig: &Rig, route: &OutboxRoute, net: &str) {
        // Qualified: this module's own `remember` takes the rig.
        super::test_rig::remember(rig.a.path(), &rig.bob_pub, route, net);
    }

    fn remember(rig: &Rig, route: &OutboxRoute) {
        remember_on(rig, route, "test-net");
        assert_eq!(remembered(rig).as_ref(), Some(route));
    }

    fn memory_file(rig: &Rig) -> PathBuf {
        rig.a
            .path()
            .join(raven_core::route_memory::ROUTE_MEMORY_FILE)
    }

    fn sorted(mut v: Vec<String>) -> Vec<String> {
        v.sort();
        v
    }

    /// G2: the contact's LAN address is dead and its Internet route delivers;
    /// the next attempt starts with the Internet route and never dials LAN.
    /// The memory holds the route, never a message id.
    #[test]
    fn the_route_that_delivered_after_a_dead_lan_is_dialled_first_next_time() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x41);
        let (l, i) = (lan("192.168.1.20:7420"), inet("203.0.113.7:7422"));
        contacts(rig.a.path(), &rig.bob_pub, &l.dial, &i.dial, true);
        rig.set(UP);
        rig.set_route(l.clone(), DOWN);
        let ctx = rig.ctx_net(on, on);
        let over_internet = Outcome::Delivered {
            carrier: Some(OutboxCarrier::Internet),
        };
        let first = rig.stage("first", DAY);
        rig.record(&first, CarrierChoice::Auto, &[]);
        assert_eq!(only(&rig.attempt_with(&ctx)), over_internet);
        assert_eq!(rig.dialled(), [l.clone(), i.clone()]);
        assert_eq!(remembered(&rig), Some(i.clone()));
        let second = rig.stage("second", DAY);
        rig.record(&second, CarrierChoice::Auto, &[]);
        assert_eq!(only(&rig.attempt_with(&ctx)), over_internet);
        assert_eq!(
            rig.dialled(),
            [l, i.clone(), i.clone()],
            "the Internet route first, the dead LAN never dialled"
        );
        assert_eq!(sorted(rig.bob_inbox()), ["first", "second"]);
        assert_eq!(remembered(&rig), Some(i), "using it changes nothing");
        let file = std::fs::read_to_string(memory_file(&rig)).unwrap();
        assert!(file.contains("internet"), "{file}");
        for mid in [first, second] {
            assert!(!file.contains(&hex::encode(mid)), "{file}");
        }
    }

    /// G2: a remembered Internet route is order only: an unverified contact,
    /// a closed Internet gate or a `--carrier lan` record still never dial
    /// it, and the outcome is the one without any memory.
    #[test]
    fn a_remembered_carrier_never_bypasses_a_gate_or_the_verified_contact_rule() {
        if !lab_backends() {
            return;
        }
        let (l, i) = (lan("192.168.1.20:7420"), inet("203.0.113.7:7422"));
        let lan_down = Outcome::Unreachable {
            carrier: Some(OutboxCarrier::Lan),
            code: code::NOT_LISTENING,
        };
        // (seed, verified, Internet gate open, recorded choice)
        for (seed, pinned, internet_open, choice) in [
            (0x43, false, true, CarrierChoice::Auto),
            (0x45, true, false, CarrierChoice::Auto),
            (0x47, true, true, CarrierChoice::Lan),
        ] {
            let rig = Rig::new(seed);
            contacts(rig.a.path(), &rig.bob_pub, &l.dial, &i.dial, pinned);
            rig.set(UP);
            rig.set_route(l.clone(), DOWN);
            remember(&rig, &i);
            let mid = rig.stage("never widened", DAY);
            rig.record(&mid, choice, &[]);
            let internet_live: fn() -> bool = if internet_open { on } else { off };
            let without = only(&rig.attempt_with(&rig.ctx_with(on, internet_live)));
            let with = only(&rig.attempt_with(&rig.ctx_net(on, internet_live)));
            assert_eq!(with, without, "{seed:#x}");
            assert_eq!(with, lan_down, "{seed:#x}");
            assert_eq!(
                rig.net.internet_dials.load(Ordering::SeqCst),
                0,
                "{seed:#x}"
            );
            assert_eq!(rig.dialled(), [l.clone(), l.clone()], "{seed:#x}");
            assert_eq!(
                remembered(&rig),
                Some(i.clone()),
                "{seed:#x}: never tried, so nothing says it is stale"
            );
            assert!(rig.bob_inbox().is_empty());
        }
    }

    /// G2: a remembered route that died costs one dial: LAN delivers in the
    /// same attempt, the entry is forgotten and the next attempt is LAN only.
    #[test]
    fn a_stale_remembered_route_costs_one_dial_and_is_forgotten() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x49);
        let (l, i) = (lan("192.168.1.20:7420"), inet("203.0.113.7:7422"));
        contacts(rig.a.path(), &rig.bob_pub, &l.dial, &i.dial, true);
        rig.set(UP);
        rig.set_route(i.clone(), DOWN);
        remember(&rig, &i);
        let ctx = rig.ctx_net(on, on);
        let over_lan = Outcome::Delivered {
            carrier: Some(OutboxCarrier::Lan),
        };
        let first = rig.stage("first", DAY);
        rig.record(&first, CarrierChoice::Auto, &[]);
        assert_eq!(only(&rig.attempt_with(&ctx)), over_lan);
        assert_eq!(rig.dialled(), [i.clone(), l.clone()]);
        assert_eq!(remembered(&rig), None);
        let second = rig.stage("second", DAY);
        rig.record(&second, CarrierChoice::Auto, &[]);
        assert_eq!(only(&rig.attempt_with(&ctx)), over_lan);
        assert_eq!(rig.dialled(), [i, l.clone(), l]);
        assert_eq!(sorted(rig.bob_inbox()), ["first", "second"]);
    }

    /// Phase 6a (P6.12): with learning on, the worker's plan follows the
    /// learned carrier order. LAN failed twice (nobody listening) while
    /// Internet delivered: the next plan is [internet, lan], so Internet
    /// takes the message and LAN is not dialled; that plan is counted as a
    /// reorder. A contact connected over p2p still goes first
    /// ([`connected_first`]).
    #[test]
    fn peer_plan_puts_the_learned_carrier_first_then_connected_first_wins() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x4d);
        let (l, i) = (lan("192.168.1.20:7420"), inet("203.0.113.7:7422"));
        let p = contacts_all(rig.a.path(), &rig.bob_pub, &l.dial, &i.dial);
        let mut learning = crate::learning::TestService::loaded(rig.a.path(), Some("home"));
        rig.set(UP);
        rig.set_route(l.clone(), DOWN);
        let over_inet = Outcome::Delivered {
            carrier: Some(OutboxCarrier::Internet),
        };
        let ctx = rig.ctx_with(on, on);
        for n in 0..2 {
            let mid = rig.stage(&format!("message {n}"), DAY);
            rig.record(&mid, CarrierChoice::Auto, &[]);
            assert_eq!(only(&rig.attempt_with(&ctx)), over_inet);
            learning.drain();
        }
        assert_eq!(rig.dialled(), [l.clone(), i.clone(), l.clone(), i.clone()]);
        assert_eq!(learning.status(&[rig.bob_pub]).would_reorder_24h, 0, "cold");
        let mid = rig.stage("learned", DAY);
        rig.record(&mid, CarrierChoice::Auto, &[]);
        assert_eq!(only(&rig.attempt_with(&ctx)), over_inet);
        assert_eq!(
            rig.dialled()[4..],
            *std::slice::from_ref(&i),
            "[internet, lan]: LAN not needed"
        );
        learning.drain();
        let st = learning.status(&[rig.bob_pub]);
        assert_eq!(st.would_reorder_24h, 1);
        assert_eq!(st.rows[0].order, ["internet_dial", "lan_dial"]);
        // p2p open and the contact connected: its route still goes first.
        let connected = AttemptCtx {
            p2p_live: on,
            connected: p2p_connected,
            ..rig.ctx_with(on, on)
        };
        let mid = rig.stage("connected", DAY);
        rig.record(&mid, CarrierChoice::Auto, &[]);
        assert_eq!(
            only(&rig.attempt_with(&connected)),
            Outcome::Delivered {
                carrier: Some(OutboxCarrier::P2p)
            }
        );
        assert_eq!(rig.dialled()[5..], [p]);
        assert_eq!(
            sorted(rig.bob_inbox()),
            ["connected", "learned", "message 0", "message 1"]
        );
    }

    /// Phase 6a (P6.12): G3 still wins per object. With Internet learned
    /// first and taking the frames silently, the object's next attempt
    /// starts at the route after it (LAN), whatever the learned order.
    #[test]
    fn silent_rotation_still_wins_per_object() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x43);
        let (l, i) = (lan("192.168.1.20:7420"), inet("203.0.113.7:7422"));
        contacts(rig.a.path(), &rig.bob_pub, &l.dial, &i.dial, true);
        let mut learning = crate::learning::TestService::loaded(rig.a.path(), Some("home"));
        learning.teach(&rig.bob_pub, OutboxCarrier::Lan, OutboxCarrier::Internet, 4);
        let statics = [OutboxCarrier::Lan, OutboxCarrier::Internet];
        let learned_first = || {
            crate::learning::plan(&rig.bob_pub, &statics)
                .unwrap()
                .0
                .carriers[0]
        };
        assert_eq!(learned_first(), OutboxCarrier::Internet);
        let mid = rig.stage("rotate", DAY);
        rig.record(&mid, CarrierChoice::Auto, &[]);
        rig.set(UP);
        rig.set_route(i.clone(), SILENT);
        let ctx = rig.ctx_with(on, on);
        let mut inner = schedule(&rig, Instant::now());
        let digest = *inner.entries.keys().next().unwrap();
        let (outcomes, unacked) = worker_round(&ctx, &mut inner);
        assert_eq!(
            outcomes[&digest],
            Outcome::Sent {
                carrier: Some(OutboxCarrier::Internet),
                code: code::NO_ACK_YET
            }
        );
        assert_eq!(unacked.get(&digest), Some(&i));
        // The model is unchanged (nothing drained): Internet still first.
        assert_eq!(learned_first(), OutboxCarrier::Internet);
        let (outcomes, _) = worker_round(&ctx, &mut inner);
        assert_eq!(
            outcomes[&digest],
            Outcome::Delivered {
                carrier: Some(OutboxCarrier::Lan)
            }
        );
        assert_eq!(rig.dialled(), [i, l], "the silent route went last");
        assert_eq!(rig.bob_inbox(), ["rotate"]);
    }

    /// Phase 6a (P6.12): learning reorders carriers only. A send forced to
    /// one carrier, and a typed LAN address (recorded as LAN only), dial
    /// exactly their static plan; an Auto send follows the learned order.
    #[test]
    fn a_forced_carrier_or_typed_peer_is_untouched() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x45);
        let (l, i) = (lan("192.168.1.20:7420"), inet("203.0.113.7:7422"));
        let typed = lan("192.168.1.30:7420");
        contacts(rig.a.path(), &rig.bob_pub, &l.dial, &i.dial, true);
        let mut learning = crate::learning::TestService::loaded(rig.a.path(), Some("home"));
        learning.teach(&rig.bob_pub, OutboxCarrier::Lan, OutboxCarrier::Internet, 4);
        rig.set(UP);
        let ctx = rig.ctx_with(on, on);
        // `raven send --peer <typed>`: LAN only, the book's LAN route first.
        rig.set_route(l.clone(), DOWN);
        let mid = rig.stage("typed", DAY);
        rig.record(&mid, CarrierChoice::Lan, std::slice::from_ref(&typed));
        assert_eq!(
            only(&rig.attempt_with(&ctx)),
            Outcome::Delivered {
                carrier: Some(OutboxCarrier::Lan)
            }
        );
        assert_eq!(rig.dialled(), [l.clone(), typed.clone()]);
        // `--carrier lan` with the book's route up: LAN, not Internet.
        rig.set_route(l.clone(), UP);
        let mid = rig.stage("forced lan", DAY);
        rig.record(&mid, CarrierChoice::Lan, &[]);
        assert_eq!(
            only(&rig.attempt_with(&ctx)),
            Outcome::Delivered {
                carrier: Some(OutboxCarrier::Lan)
            }
        );
        assert_eq!(rig.dialled()[2..], *std::slice::from_ref(&l));
        // Auto: the learned order.
        let mid = rig.stage("auto", DAY);
        rig.record(&mid, CarrierChoice::Auto, &[]);
        assert_eq!(
            only(&rig.attempt_with(&ctx)),
            Outcome::Delivered {
                carrier: Some(OutboxCarrier::Internet)
            }
        );
        assert_eq!(rig.dialled()[3..], [i]);
        assert_eq!(sorted(rig.bob_inbox()), ["auto", "forced lan", "typed"]);
    }

    /// Phase 6a (P6.12): learning never widens a plan. An unverified
    /// contact's plan is LAN only (Internet withheld), whatever the model
    /// says about its Internet route.
    #[test]
    fn unverified_contact_stays_lan_only() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x47);
        let (l, i) = (lan("127.0.0.1:9"), inet("203.0.113.7:7422"));
        contacts(rig.a.path(), &rig.bob_pub, &l.dial, &i.dial, false);
        let mut learning = crate::learning::TestService::loaded(rig.a.path(), Some("home"));
        learning.teach(&rig.bob_pub, OutboxCarrier::Lan, OutboxCarrier::Internet, 4);
        let all = [OutboxCarrier::Lan, OutboxCarrier::Internet];
        assert_eq!(
            crate::learning::plan(&rig.bob_pub, &all)
                .unwrap()
                .0
                .carriers[0],
            OutboxCarrier::Internet,
            "the model would put Internet first"
        );
        rig.set(UP);
        let mid = rig.stage("unverified", DAY);
        rig.record(&mid, CarrierChoice::Auto, &[]);
        assert_eq!(
            only(&rig.attempt_with(&rig.ctx_with(on, on))),
            Outcome::Delivered {
                carrier: Some(OutboxCarrier::Lan)
            }
        );
        assert_eq!(rig.dialled(), [l]);
        assert_eq!(rig.net.internet_dials.load(Ordering::SeqCst), 0);
        // Internet down too: still never dialled.
        rig.set(DOWN);
        let mid = rig.stage("held", DAY);
        rig.record(&mid, CarrierChoice::Auto, &[]);
        let _ = rig.attempt_with(&rig.ctx_with(on, on));
        assert_eq!(rig.net.internet_dials.load(Ordering::SeqCst), 0);
    }

    /// Phase 6a (P6.12): a learned order that is no pure reorder of a plan
    /// (here a carrier twice) gives the static plan, is counted once per
    /// resolve and pins the contact-network to the static order for an
    /// hour; after it the learned order is back.
    #[test]
    fn contradiction_pins_static_for_an_hour() {
        let dir = tempfile::tempdir().unwrap();
        let alice = Arc::new(Identity::from_seed(&[0x57; 32]));
        let bob = Identity::from_seed(&[0x58; 32]).public_key_bytes();
        let (l, i) = (lan("10.0.0.5:7420"), inet("203.0.113.9:7422"));
        contacts(dir.path(), &bob, &l.dial, &i.dial, true);
        let nodial = Arc::new(NoDial::default());
        let ctx = AttemptCtx {
            internet_live: on,
            ..test_ctx(dir.path(), Arc::clone(&alice), nodial.clone())
        };
        let mut learning = crate::learning::TestService::loaded(dir.path(), Some("home"));
        learning.teach(&bob, OutboxCarrier::Lan, OutboxCarrier::Internet, 4);
        let plan = || {
            let ContactAdmission::Allowed(c) = contact_admission(dir.path(), &bob) else {
                panic!("Bob is a contact");
            };
            peer_plan(&ctx, &bob, c, now_ms())
        };
        let dial_order = |p: &PeerPlan| -> Vec<OutboxRoute> {
            p.auto_dial(&bob, never_connected, &mut |r, _| Ok(r.clone()))
                .into_iter()
                .map(|(planned, _)| planned)
                .collect()
        };
        let mut resolved = plan();
        let order = resolved.learned.clone().expect("learning is on");
        assert_eq!(order.carriers[0], OutboxCarrier::Internet);
        assert_eq!(resolved.learned_net.as_deref(), Some("home"));
        assert!(resolved.preferred.is_none());
        assert_eq!(dial_order(&resolved), [i.clone(), l.clone()]);
        // A carrier twice: not a pure reorder.
        resolved.learned = Some(Order {
            carriers: vec![OutboxCarrier::Internet, OutboxCarrier::Internet],
            ..order.clone()
        });
        assert_eq!(dial_order(&resolved), [l.clone(), i.clone()], "static");
        let p = resolved.object_routes(&bob, None);
        assert!(p.learning_contradiction);
        assert_eq!(p.routes, std::slice::from_ref(&l));
        assert!(resolved.contradicted());
        let model = learning.model().unwrap();
        assert_eq!(model.counters().contradictions, 1, "once per resolve");
        // Pinned: the next resolve plans the static order.
        let pinned = plan();
        let fixed = pinned.learned.as_ref().unwrap();
        assert_eq!(fixed.why, raven_core::learning::explain::Why::Contradiction);
        assert_eq!(dial_order(&pinned), [l.clone(), i.clone()]);
        assert!(!pinned.contradicted());
        assert_eq!(learning.status(&[bob]).contradictions, 1);
        // An hour later the learned order is back.
        let statics = [OutboxCarrier::Lan, OutboxCarrier::Internet];
        let later = now_ms() + raven_core::learning::model::CONTRADICTION_PIN_MS + 1;
        let back =
            raven_core::learning::rank::order(&model, &bob, Some("home"), &statics, None, later);
        assert_eq!(back.carriers, [OutboxCarrier::Internet, OutboxCarrier::Lan]);
        assert_ne!(back.why, raven_core::learning::explain::Why::Contradiction);
        assert_eq!(nodial.dials(), 0);
    }

    /// Phase 6a (P6.12, OD6a-10): while learning is on the route memory is
    /// neither read (its route does not go first) nor taught (a LAN failure
    /// then an Internet delivery grants nothing, a LAN delivery forgets
    /// nothing); with learning off it is read again.
    #[test]
    fn route_memory_is_neither_read_nor_taught_while_on() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x59);
        let (l, i) = (lan("192.168.1.20:7420"), inet("203.0.113.7:7422"));
        contacts(rig.a.path(), &rig.bob_pub, &l.dial, &i.dial, true);
        let learning = crate::learning::TestService::loaded(rig.a.path(), Some("home"));
        let ctx = rig.ctx_net(on, on);
        rig.set(UP);
        rig.set_route(l.clone(), DOWN);
        let mid = rig.stage("not taught", DAY);
        rig.record(&mid, CarrierChoice::Auto, &[]);
        assert_eq!(
            only(&rig.attempt_with(&ctx)),
            Outcome::Delivered {
                carrier: Some(OutboxCarrier::Internet)
            }
        );
        assert_eq!(rig.dialled(), [l.clone(), i.clone()]);
        assert_eq!(remembered(&rig), None, "nothing granted");
        remember(&rig, &i);
        rig.set_route(l.clone(), UP);
        let mid = rig.stage("not read", DAY);
        rig.record(&mid, CarrierChoice::Auto, &[]);
        assert_eq!(
            only(&rig.attempt_with(&ctx)),
            Outcome::Delivered {
                carrier: Some(OutboxCarrier::Lan)
            }
        );
        assert_eq!(
            rig.dialled()[2..],
            *std::slice::from_ref(&l),
            "the memory's route not first"
        );
        assert_eq!(remembered(&rig), Some(i.clone()), "nothing forgotten");
        drop(learning);
        let mid = rig.stage("memory again", DAY);
        rig.record(&mid, CarrierChoice::Auto, &[]);
        assert_eq!(
            only(&rig.attempt_with(&ctx)),
            Outcome::Delivered {
                carrier: Some(OutboxCarrier::Internet)
            }
        );
        assert_eq!(rig.dialled()[3..], [i], "learning off: read again");
    }

    /// Phase 6a (P6.11): a dial whose every ACK the worker refuses (here
    /// its signature is broken) gave no receipt after all: learning takes
    /// it back; a good ACK's receipt stays.
    #[test]
    fn refused_acks_retract_the_receipt() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x4f);
        let mut learning = crate::learning::TestService::loaded(rig.a.path(), Some("home"));
        let lan_arm = |learning: &crate::learning::TestService| {
            learning
                .model()
                .unwrap()
                .arm(&raven_core::learning::model::ArmKey {
                    contact: rig.bob_pub,
                    net: Some("home".into()),
                    carrier: OutboxCarrier::Lan,
                })
                .copied()
                .unwrap()
        };
        rig.set(UP);
        rig.stage("acked", DAY);
        assert_eq!(
            only(&rig.attempt()),
            Outcome::Delivered {
                carrier: Some(OutboxCarrier::Lan)
            }
        );
        assert_eq!(learning.drain(), 1, "the observation only");
        assert_eq!(lan_arm(&learning).beta.a_m, 1_000);
        rig.set(BAD_ACK);
        rig.stage("forged ack", DAY);
        let outcome = only(&rig.attempt());
        assert!(!matches!(outcome, Outcome::Delivered { .. }), "{outcome:?}");
        assert_eq!(learning.drain(), 2, "the observation, then its retraction");
        let arm = lan_arm(&learning);
        assert_eq!((arm.beta.a_m, arm.beta.streak), (1_000, 0));
        assert_eq!(arm.tries(), (1, 2));
    }

    /// Phase 6a (P6.14): only a batch of owed ACKs explores. LAN delivered,
    /// then stopped answering while Internet delivered, so Internet leads
    /// and LAN is due for exploring half an hour later. A batch with a
    /// message keeps the learned order; an owed-ACK batch puts LAN first,
    /// once (one probe of the budget); the next owed-ACK batch is back on
    /// the learned order (LAN was explored just now).
    #[test]
    fn ack_only_batches_may_explore_message_batches_never() {
        if !lab_backends() {
            return;
        }
        if raven_core::learning::lab_tune().is_some() {
            eprintln!("skipped: RAVEN_LAB_LEARNING_TUNE replaces the exploration gaps");
            return;
        }
        let rig = Rig::new(0x5b);
        let (l, i) = (lan("192.168.1.20:7420"), inet("203.0.113.7:7422"));
        contacts(rig.a.path(), &rig.bob_pub, &l.dial, &i.dial, true);
        let mut learning = crate::learning::TestService::loaded(rig.a.path(), Some("home"));
        let t0 = now_ms();
        learning.set_now(t0);
        learning.wrote(&rig.bob_pub, OutboxCarrier::Lan, true);
        learning.teach(&rig.bob_pub, OutboxCarrier::Lan, OutboxCarrier::Internet, 4);
        learning.set_now(t0 + 31 * 60_000);
        rig.set(UP);
        let ctx = rig.ctx_with(on, on);
        let owed = vec![(
            [7u8; 32],
            UnsentAck {
                peer: rig.bob_pub,
                bytes: ack_envelope(7, now_ms() + 3_600_000),
                expires_at_ms: now_ms() + 3_600_000,
                failures: 0,
                next_due: Instant::now(),
                durable: false,
                session_id: None,
                held_by: Vec::new(),
                may_deposit: true,
            },
        )];
        let probes =
            |learning: &crate::learning::TestService| learning.status(&[rig.bob_pub]).probes_24h;
        // A message rides with the owed ACK: the learned order.
        let mid = rig.stage("with a message", DAY);
        rig.record(&mid, CarrierChoice::Auto, &[]);
        let report = attempt_peer(&ctx, &rig.bob_pub, &rig.due(), &owed);
        assert_eq!(
            only(&report),
            Outcome::Delivered {
                carrier: Some(OutboxCarrier::Internet)
            }
        );
        assert_eq!(report.acks_done, [[7u8; 32]]);
        assert_eq!(rig.dialled(), std::slice::from_ref(&i));
        learning.drain();
        assert_eq!(probes(&learning), 0);
        // Owed ACKs only: LAN, the due arm, goes first.
        let report = attempt_peer(&ctx, &rig.bob_pub, &[], &owed);
        assert_eq!(report.acks_done, [[7u8; 32]]);
        assert_eq!(rig.dialled()[1..], *std::slice::from_ref(&l));
        learning.drain();
        assert_eq!(probes(&learning), 1);
        // Explored just now: the learned order again.
        let report = attempt_peer(&ctx, &rig.bob_pub, &[], &owed);
        assert_eq!(report.acks_done, [[7u8; 32]]);
        assert_eq!(rig.dialled()[2..], [i]);
        learning.drain();
        assert_eq!(probes(&learning), 1);
        assert_eq!(rig.bob_inbox(), ["with a message"]);
    }

    /// G2: an entry learned on another network is not used here, and with no
    /// network tag (the memory off: release, or no default route) the plain
    /// plan is dialled and nothing is learned.
    #[test]
    fn route_memory_is_not_used_on_another_network_or_without_a_tag() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x4b);
        let (l, i) = (lan("192.168.1.20:7420"), inet("203.0.113.7:7422"));
        contacts(rig.a.path(), &rig.bob_pub, &l.dial, &i.dial, true);
        rig.set(UP);
        let over_lan = Outcome::Delivered {
            carrier: Some(OutboxCarrier::Lan),
        };
        remember_on(&rig, &i, "other");
        assert_eq!(remembered(&rig), None, "not on this network");
        let a = rig.stage("on this network", DAY);
        rig.record(&a, CarrierChoice::Auto, &[]);
        assert_eq!(only(&rig.attempt_with(&rig.ctx_net(on, on))), over_lan);
        assert_eq!(rig.dialled(), std::slice::from_ref(&l));
        remember(&rig, &i);
        let b = rig.stage("without a tag", DAY);
        rig.record(&b, CarrierChoice::Auto, &[]);
        assert_eq!(only(&rig.attempt_with(&rig.ctx_with(on, on))), over_lan);
        assert_eq!(rig.dialled(), [l.clone(), l]);
        assert_eq!(remembered(&rig), Some(i), "no tag: nothing learned either");
    }

    /// G2: only the contact's own dials teach the memory. A friend that took
    /// the message (custody) and the session-reset dials are not its routes.
    #[test]
    fn custody_and_reset_dials_never_teach_the_route_memory() {
        if !lab_backends() {
            return;
        }
        // Custody routes and the custodian's links read `raven lan off`.
        let _lan = crate::lan_direct::lan_switch_untouched();
        raven_core::custody_gate::set_custody_gates_for_this_thread(Some(
            raven_core::custody_gate::CustodyGates {
                live: true,
                wan: false,
            },
        ));
        let rig = Rig::new(0x51);
        let carol = Identity::from_seed(&[0x59; 32]);
        let c_dir = tempfile::tempdir().unwrap();
        ensure_local_device_certificate(c_dir.path(), &carol, PRIMARY_DEVICE_ID).unwrap();
        raven_core::ensure_local_prekey(c_dir.path(), &carol).unwrap();
        let hexk = |k: &[u8; 32]| hex::encode(k);
        let (alice_pub, carol_pub) = (rig.alice.public_key_bytes(), carol.public_key_bytes());
        std::fs::write(
            rig.a.path().join("contacts.json"),
            format!(
                r#"[{{"petname":"Bob","pub_hex":"{}","pinned":true,"lan_dial":"127.0.0.1:9","custodians":["{}"]}},
                   {{"petname":"Carol","pub_hex":"{}","pinned":true,"lan_dial":"192.168.1.50:7420"}}]"#,
                hexk(&rig.bob_pub),
                hexk(&carol_pub),
                hexk(&carol_pub)
            ),
        )
        .unwrap();
        std::fs::write(
            c_dir.path().join("contacts.json"),
            format!(
                r#"[{{"petname":"Alice","pub_hex":"{}","pinned":true}},{{"petname":"Bob","pub_hex":"{}","pinned":true}}]"#,
                hexk(&alice_pub),
                hexk(&rig.bob_pub)
            ),
        )
        .unwrap();
        raven_core::save_policy(
            c_dir.path(),
            &raven_core::NodePolicy {
                custody: true,
                ..Default::default()
            },
        )
        .unwrap();
        let mid = rig.stage_with("via carol", now_ms() - 120_000, DAY, true);
        rig.record(&mid, CarrierChoice::Auto, &[lan("127.0.0.1:9")]);
        raven_core::outbox::set_object_custody(rig.a.path(), &mid, now_ms()).unwrap();
        let net = Arc::new(ThreeNet {
            alice_bundle: local_bundle(rig.a.path(), &rig.alice).unwrap(),
            alice_pub,
            nodes: vec![
                (
                    hexk(&rig.bob_pub),
                    rig.b.path().to_path_buf(),
                    Identity::from_seed(&[0x52; 32]),
                ),
                (hexk(&carol_pub), c_dir.path().to_path_buf(), carol),
            ],
            bob_hex: hexk(&rig.bob_pub),
            bob_down: AtomicBool::new(true),
        });
        let ctx = AttemptCtx {
            data_dir: rig.a.path().to_path_buf(),
            identity: Arc::clone(&rig.alice),
            dialer: net,
            lan_live: on,
            internet_live: off,
            p2p_live: off,
            nearby_live: off,
            nearby_available: no_nearby,
            onion_live: || false,
            onion_available: || false,
            onion_head_start: crate::onion::head_start,
            net_tag: test_net,
            on_link: unknown_link,
            connected: never_connected,
            lan_beacon_routes: no_finds,
            lan_want: no_want,
            lan_beacon_failed: no_find_failed,
            reset_backoff: Mutex::default(),
        };
        let report = rig.attempt_with(&ctx);
        raven_core::custody_gate::set_custody_gates_for_this_thread(None);
        assert_eq!(only(&report), Outcome::Deposited { held: 1 });
        assert!(
            !memory_file(&rig).exists(),
            "Carol's answer says nothing about Bob's routes"
        );

        // The session-reset step: a query, a new pairing, the re-sealed copy.
        let _lab = ResetLab::on();
        let rig = Rig::new(0x53);
        rig.stage_queued("q1", DAY);
        rig.wipe_bob(false);
        rig.set(STRICT);
        let ctx = rig.ctx_net(on, off);
        for step in 0..3 {
            let report = rig.attempt_with(&ctx);
            assert!(
                !memory_file(&rig).exists(),
                "step {step}: {:?}",
                texts(&report)
            );
        }
        assert_eq!(rig.bob_inbox(), ["q1"]);
    }

    /// G2 with G3: a route that took the frames and sent no ACK back never
    /// earns the lead, even right after a route above it failed; the next
    /// attempt follows G3's rotation (the route after it first).
    #[test]
    fn a_silent_route_is_never_granted() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x55);
        let (l1, i, l2) = (
            lan("192.168.1.20:7420"),
            inet("203.0.113.7:7422"),
            lan("192.168.1.21:7420"),
        );
        contacts(rig.a.path(), &rig.bob_pub, &l1.dial, &i.dial, true);
        let mid = rig.stage("silent", DAY);
        // Planned: the contact's LAN and Internet routes, then the send's own.
        rig.record(&mid, CarrierChoice::Auto, std::slice::from_ref(&l2));
        rig.set(UP);
        rig.set_route(l1.clone(), DOWN);
        rig.set_route(i.clone(), SILENT);
        let ctx = rig.ctx_net(on, on);
        let mut inner = schedule(&rig, Instant::now());
        let digest = *inner.entries.keys().next().unwrap();
        let (outcomes, unacked) = worker_round(&ctx, &mut inner);
        assert_eq!(
            outcomes[&digest],
            Outcome::Sent {
                carrier: Some(OutboxCarrier::Internet),
                code: code::NO_ACK_YET
            },
            "the silent route reached Ok"
        );
        assert_eq!(unacked.get(&digest), Some(&i));
        assert!(!memory_file(&rig).exists(), "no lead for a silent route");
        let (outcomes, _) = worker_round(&ctx, &mut inner);
        assert_eq!(
            outcomes[&digest],
            Outcome::Delivered {
                carrier: Some(OutboxCarrier::Lan)
            }
        );
        assert_eq!(rig.dialled(), [l1, i, l2], "G3: the route after it first");
        assert!(!memory_file(&rig).exists());
        assert_eq!(rig.bob_inbox(), ["silent"]);
    }

    /// Phase 0b (lab): where the contact last reached us from is not dialled
    /// when it is on none of this computer's current networks (the one it
    /// just left); the saved address is, though it is on another network
    /// too. Not known or on link: the plan is today's.
    #[test]
    fn a_learned_lan_route_from_another_network_is_not_dialled() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x5b);
        let (saved, learned) = (lan("10.0.0.5:7420"), lan("192.168.1.20:7420"));
        contacts(rig.a.path(), &rig.bob_pub, &saved.dial, "", false);
        let seen_at: IpAddr = "192.168.1.20".parse().unwrap();
        raven_core::lan_seen::record_contact_seen(
            rig.a.path(),
            &rig.bob_pub,
            seen_at,
            None,
            now_ms(),
        )
        .unwrap();
        let mid = rig.stage("left behind", DAY);
        // Every route is down (the rig's default): each attempt dials its
        // whole plan.
        let off_link = AttemptCtx {
            on_link: |_| Some(false),
            ..rig.ctx()
        };
        assert!(!matches!(
            only(&rig.attempt_with(&off_link)),
            Outcome::Delivered { .. }
        ));
        assert_eq!(rig.dialled(), std::slice::from_ref(&saved));
        let on_link = AttemptCtx {
            on_link: |_| Some(true),
            ..rig.ctx()
        };
        let _ = rig.attempt_with(&on_link);
        assert_eq!(rig.dialled()[1..], [saved.clone(), learned.clone()]);
        let _ = rig.attempt(); // not known
        assert_eq!(rig.dialled()[3..], [saved.clone(), learned.clone()]);
        // Back on that network, the learned address delivers.
        rig.set_route(learned.clone(), UP);
        assert_eq!(
            only(&rig.attempt_with(&on_link)),
            Outcome::Delivered {
                carrier: Some(OutboxCarrier::Lan)
            }
        );
        assert_eq!(rig.dialled()[5..], [saved, learned]);
        assert_eq!(rig.history(&mid).as_deref(), Some("delivered"));
    }

    // ---- the LAN beacon's finds (Phase 3 P3.11, RAVEN_LAN_BEACON_V1 §7-§9) ----

    thread_local! {
        /// What this thread's LAN beacon found ([`finds_of`]).
        static FINDS: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
        /// Whom attempts asked it to look for ([`wanted`]).
        static WANTED: std::cell::RefCell<Vec<[u8; 32]>> = const { std::cell::RefCell::new(Vec::new()) };
        /// The finds a dial did not reach the contact at ([`forgot`]).
        static FORGOT: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
    }

    fn finds_of(_: &[u8; 32]) -> Vec<String> {
        FINDS.with(|f| f.borrow().clone())
    }

    fn wanted(peer: &[u8; 32]) {
        WANTED.with(|w| w.borrow_mut().push(*peer));
    }

    fn forgot(_: &[u8; 32], dial: &str) {
        FORGOT.with(|f| f.borrow_mut().push(dial.to_string()));
    }

    /// This thread's LAN beacon has found every contact at `found` (an
    /// attempt runs on its caller's thread).
    fn beacon_finds(found: &[&OutboxRoute]) {
        FINDS.with(|f| *f.borrow_mut() = found.iter().map(|r| r.dial.clone()).collect());
    }

    /// Whom attempts asked the beacon to look for, and the finds it was told
    /// to forget, since the last call.
    fn beacon_asked() -> (Vec<[u8; 32]>, Vec<String>) {
        (
            WANTED.with(|w| std::mem::take(&mut *w.borrow_mut())),
            FORGOT.with(|f| std::mem::take(&mut *f.borrow_mut())),
        )
    }

    /// `ctx` with this thread's LAN beacon.
    fn with_beacon(ctx: AttemptCtx) -> AttemptCtx {
        AttemptCtx {
            lan_beacon_routes: finds_of,
            lan_want: wanted,
            lan_beacon_failed: forgot,
            ..ctx
        }
    }

    /// An attempt for Bob asks the LAN beacon to look for him. Once it found
    /// him (which makes his waiting message due at once, backoff or not: the
    /// beacon calls `peer_routes_changed`), his finds are dialled first, IPv4
    /// first, before the saved address and with no learned LAN route (here
    /// where he last reached us from). A find that did not reach him is
    /// forgotten (§7); no find is taught to the route memory or written
    /// anywhere (§9).
    #[test]
    fn a_beacon_candidate_is_dialled_first_and_kicks_waiting_objects() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x5c);
        let (saved, learned) = (lan("10.0.0.5:7420"), lan("192.168.1.20:7420"));
        let (v4, v6) = (lan("192.168.1.77:7499"), lan("[fd00::77]:7499"));
        contacts(rig.a.path(), &rig.bob_pub, &saved.dial, "", false);
        let book = std::fs::read(rig.a.path().join("contacts.json")).unwrap();
        let seen_at: IpAddr = "192.168.1.20".parse().unwrap();
        raven_core::lan_seen::record_contact_seen(
            rig.a.path(),
            &rig.bob_pub,
            seen_at,
            None,
            now_ms(),
        )
        .unwrap();
        let mid = rig.stage("found nearby", DAY);
        // The route memory on: a find must not end up there either.
        let ctx = with_beacon(rig.ctx_net(on, off));
        beacon_finds(&[]);
        let mut inner = schedule(&rig, Instant::now());
        let (outcomes, _) = worker_round(&ctx, &mut inner);
        assert!(!outcomes
            .values()
            .any(|o| matches!(o, Outcome::Delivered { .. })));
        assert_eq!(
            rig.dialled(),
            [saved.clone(), learned.clone()],
            "today's plan"
        );
        assert_eq!(beacon_asked(), (vec![rig.bob_pub], Vec::new()));
        let now = Instant::now();
        assert!(inner.take_due(now).is_empty(), "backed off");

        // Found at two addresses (the IPv6 one listed first): due at once.
        beacon_finds(&[&v6, &v4]);
        assert!(inner.routes_changed_now(&rig.bob_pub, now));
        let mut work = inner.take_due(now);
        assert_eq!(work.len(), 1, "his message is due now");
        let work = work.remove(0);
        rig.set_route(v6.clone(), UP);
        let report = attempt_peer(&ctx, &work.peer, &work.entries, &work.acks);
        assert_eq!(
            only(&report),
            Outcome::Delivered {
                carrier: Some(OutboxCarrier::Lan)
            }
        );
        assert_eq!(rig.dialled()[2..], [v4.clone(), v6.clone()]);
        assert_eq!(
            beacon_asked(),
            (vec![rig.bob_pub], vec![v4.dial.clone()]),
            "the find nobody answered at is forgotten"
        );
        assert_eq!(rig.history(&mid).as_deref(), Some("delivered"));
        assert_eq!(rig.bob_inbox(), ["found nearby"]);
        assert!(!memory_file(&rig).exists(), "no find is remembered");
        assert_eq!(
            std::fs::read(rig.a.path().join("contacts.json")).unwrap(),
            book
        );
        assert_eq!(
            raven_core::lan_seen::seen_ip(rig.a.path(), &rig.bob_pub, now_ms()),
            Some(seen_at)
        );
        assert!(!rig
            .a
            .path()
            .join(raven_core::learned_routes::LEARNED_ROUTES_FILE)
            .exists());
    }

    /// The finds are LAN routes like any other. LAN off (`raven lan off`
    /// closes the worker's LAN gate): nobody is looked for, nothing is
    /// dialled. A message sent with `--carrier internet` asks for no find
    /// and takes none. Under `raven lan verified-only on` an unverified
    /// contact is dialled at no find (CONTACT_NOT_VERIFIED). A find off the
    /// local network is never planned for an unverified contact, and one
    /// where another key answers (M0) is blocked for that message like any
    /// route there, and forgotten.
    #[test]
    fn beacon_routes_never_bypass_gates_lan_off_or_the_contact_rule() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x5d);
        let saved = lan("10.0.0.5:7420");
        let found = lan("192.168.1.77:7499");
        contacts(rig.a.path(), &rig.bob_pub, &saved.dial, "", false);
        let mid = rig.stage("held back", DAY);
        rig.set_route(found.clone(), UP);
        beacon_finds(&[&found]);
        let not_delivered =
            |report: &PeerReport| !matches!(only(report), Outcome::Delivered { .. });

        // LAN off.
        let lan_off = with_beacon(rig.ctx_with(off, off));
        assert!(not_delivered(&rig.attempt_with(&lan_off)));
        assert!(rig.dialled().is_empty());
        assert_eq!(beacon_asked(), (Vec::new(), Vec::new()));

        // `--carrier internet`.
        rig.record(&mid, CarrierChoice::Internet, &[]);
        let ctx = with_beacon(rig.ctx_with(on, on));
        assert!(not_delivered(&rig.attempt_with(&ctx)));
        assert!(rig.dialled().is_empty());
        assert_eq!(beacon_asked(), (Vec::new(), Vec::new()));
        raven_core::outbox::clear_object_routes(rig.a.path(), &[mid]).unwrap();

        // `raven lan verified-only on`, Bob not verified.
        raven_core::node_policy::set_lan_verified_only(rig.a.path(), true).unwrap();
        assert_eq!(
            only(&rig.attempt_with(&ctx)),
            Outcome::Held(CONTACT_NOT_VERIFIED)
        );
        assert!(rig.dialled().is_empty());
        let _ = beacon_asked();
        raven_core::node_policy::set_lan_verified_only(rig.a.path(), false).unwrap();

        // Off the local network: not planned for him (the saved address is).
        let public = lan("203.0.113.9:7499");
        rig.set_route(public.clone(), UP);
        beacon_finds(&[&public]);
        assert!(not_delivered(&rig.attempt_with(&ctx)));
        assert_eq!(rig.dialled(), std::slice::from_ref(&saved));

        // Another key answers at the find (M0): blocked for this message,
        // forgotten by the beacon; the saved address is still tried.
        rig.set_route(found.clone(), PIN_MISMATCH);
        beacon_finds(&[&found]);
        let _ = beacon_asked();
        let report = rig.attempt_with(&ctx);
        assert!(not_delivered(&report));
        assert_eq!(rig.dialled()[1..], [found.clone(), saved.clone()]);
        assert_eq!(
            report.pin_blocked.values().next(),
            Some(&vec![found.clone()])
        );
        assert_eq!(
            beacon_asked(),
            (vec![rig.bob_pub], vec![found.dial.clone()])
        );
    }

    /// The outbox asks the LAN beacon to look for a contact only in an
    /// attempt in which LAN may carry something: a message whose send allows
    /// LAN (`auto`, `--carrier lan`, or no record: LAN only) or an owed ACK
    /// (any carrier), while the LAN gate is open, and for a current contact.
    #[test]
    fn want_is_raised_only_when_lan_is_allowed_for_a_due_object() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x5e);
        contacts(rig.a.path(), &rig.bob_pub, "10.0.0.5:7420", "", false);
        let mid = rig.stage("asked for", DAY);
        let ctx = with_beacon(rig.ctx_with(on, on));
        let bob = vec![rig.bob_pub];
        let asked = |ctx: &AttemptCtx, due: &[Entry], acks: &[([u8; 32], UnsentAck)]| {
            let _ = beacon_asked();
            let _ = attempt_peer(ctx, &rig.bob_pub, due, acks);
            beacon_asked().0
        };
        let due = rig.due();
        let ack = [(
            [0xAC; 32],
            owed(rig.bob_pub, 0, Instant::now(), now_ms() + DAY),
        )];
        // No record (LAN only), `auto` and `--carrier lan`: asked for.
        assert_eq!(asked(&ctx, &due, &[]), bob);
        for choice in [CarrierChoice::Auto, CarrierChoice::Lan] {
            raven_core::outbox::clear_object_routes(rig.a.path(), &[mid]).unwrap();
            rig.record(&mid, choice, &[]);
            assert_eq!(asked(&ctx, &due, &[]), bob, "{choice:?}");
        }
        // `--carrier internet` / `p2p`: not, unless an ACK is owed.
        for choice in [CarrierChoice::Internet, CarrierChoice::P2p] {
            raven_core::outbox::clear_object_routes(rig.a.path(), &[mid]).unwrap();
            rig.record(&mid, choice, &[]);
            assert!(asked(&ctx, &due, &[]).is_empty(), "{choice:?}");
            assert_eq!(asked(&ctx, &due, &ack), bob, "{choice:?} with an ACK owed");
        }
        // Only an ACK owed: asked for. Nothing due: not.
        assert_eq!(asked(&ctx, &[], &ack), bob);
        assert!(asked(&ctx, &[], &[]).is_empty());
        // LAN off: not.
        let lan_off = with_beacon(rig.ctx_with(off, on));
        assert!(asked(&lan_off, &due, &ack).is_empty());
        // Not a contact: not.
        contacts(rig.a.path(), &[0x99; 32], "10.0.0.5:7420", "", false);
        assert!(asked(&ctx, &due, &ack).is_empty());
    }

    // ---- route hints (RRH1): what contacts told us ----

    /// Bob's learned_routes.json entry (what his RRH1 said): `lan` his LAN
    /// port on the link's IP, `peer_id` his libp2p PeerId.
    fn learned_entry(
        rig: &Rig,
        lan: Option<(&str, u16)>,
        peer_id: Option<&str>,
    ) -> serde_json::Value {
        let now = now_ms();
        let mut entry = serde_json::json!({
            "pub_hex": hex::encode(rig.bob_pub),
            "generation": 7,
            "received_at_ms": now,
            "expires_at_ms": now + DAY,
            "via": "lan",
        });
        if let Some(peer_id) = peer_id {
            entry["peer_id"] = peer_id.into();
        }
        if let Some((ip, port)) = lan {
            entry["lan"] = serde_json::json!({
                "generation": 7,
                "received_at_ms": now,
                "expires_at_ms": now + DAY,
                "lan_port": port,
                "lan_ip": ip,
            });
        }
        entry
    }

    fn learn(rig: &Rig, entry: serde_json::Value) {
        std::fs::write(
            rig.a
                .path()
                .join(raven_core::learned_routes::LEARNED_ROUTES_FILE),
            serde_json::to_vec(&vec![entry]).unwrap(),
        )
        .unwrap();
    }

    /// The s04 unit: Bob's listener came back on another port and his RRH1
    /// said so. While route hints are live the worker dials the announced
    /// port after the saved route (an unverified contact on the local
    /// network too); with them off, exactly today's plan.
    #[test]
    fn a_learned_lan_port_is_dialled_after_the_saved_route() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x5d);
        let (saved, moved) = (lan("192.168.1.20:7420"), lan("192.168.1.20:7431"));
        contacts(rig.a.path(), &rig.bob_pub, &saved.dial, "", false);
        learn(
            &rig,
            learned_entry(&rig, Some(("192.168.1.20", 7431)), None),
        );
        let mid = rig.stage("moved port", DAY);
        let _ = rig.attempt();
        if !raven_core::route_hints::route_hints_live() {
            assert_eq!(rig.dialled(), std::slice::from_ref(&saved));
            return;
        }
        assert_eq!(rig.dialled(), [saved.clone(), moved.clone()]);
        rig.set_route(moved.clone(), UP);
        assert_eq!(
            only(&rig.attempt()),
            Outcome::Delivered {
                carrier: Some(OutboxCarrier::Lan)
            }
        );
        assert_eq!(rig.dialled()[2..], [saved, moved]);
        assert_eq!(rig.history(&mid).as_deref(), Some("delivered"));
    }

    /// A verified contact's RRH1 named its PeerId, which its book lacks:
    /// while route hints and p2p are live the worker plans `/p2p/<PeerId>`
    /// after its other routes and delivers over it.
    #[test]
    fn worker_plans_the_learned_p2p_route() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0x5f);
        let l = lan("192.168.1.20:7420");
        contacts(rig.a.path(), &rig.bob_pub, &l.dial, "", true);
        let peer_id = raven_core::p2p_route::local_peer_id(&Identity::from_seed(&[0x78; 32]));
        let p = OutboxRoute {
            carrier: OutboxCarrier::P2p,
            dial: raven_core::p2p_route::peer_route(&peer_id),
        };
        learn(&rig, learned_entry(&rig, None, Some(&peer_id)));
        rig.set(UP);
        rig.set_route(l.clone(), DOWN);
        let ctx = AttemptCtx {
            p2p_live: on,
            ..rig.ctx()
        };
        let mid = rig.stage("over the learned PeerId", DAY);
        rig.record(&mid, CarrierChoice::Auto, &[]);
        let report = rig.attempt_with(&ctx);
        if !raven_core::route_hints::route_hints_live() {
            assert_eq!(rig.dialled(), std::slice::from_ref(&l));
            assert!(!matches!(only(&report), Outcome::Delivered { .. }));
            return;
        }
        assert_eq!(rig.dialled(), [l, p]);
        assert_eq!(
            only(&report),
            Outcome::Delivered {
                carrier: Some(OutboxCarrier::P2p)
            }
        );
        assert_eq!(rig.history(&mid).as_deref(), Some("delivered"));
    }

    // ---- path labels and deliberate reversal (Phase 1 item 4) ----

    /// A p2p write records how its link travelled, shown by the outbox
    /// views and logged (counts only); a LAN one records nothing, even when
    /// its dialer says `direct`, so LAN views and logs are as they were.
    #[test]
    fn a_p2p_delivery_records_its_path_and_lan_records_none() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0xd1);
        let l = lan("192.168.1.20:7420");
        let p = contacts_p2p(rig.a.path(), &rig.bob_pub, &l.dial);
        rig.set(UP);
        rig.set_route(l.clone(), DOWN);
        rig.set_path(p.clone(), DeliveryPath::Relayed);
        rig.set_path(l.clone(), DeliveryPath::Direct);
        let ctx = AttemptCtx {
            p2p_live: on,
            ..rig.ctx()
        };
        let round = |inner: &mut Inner| {
            let mut work = inner.take_due(Instant::now() + RETRY_MAX * 2);
            let work = work.remove(0);
            let report = attempt_peer(&ctx, &work.peer, &work.entries, &work.acks);
            let lines = report.delivered_lines(&work.peer);
            let seen = (report.outcomes.clone(), report.paths.clone());
            inner.apply(&work.peer, report, Instant::now(), now_ms());
            (seen, lines)
        };
        let item = |inner: &Inner, mid: &[u8; 16]| {
            inner
                .done
                .iter()
                .find(|e| e.message_id == *mid)
                .expect("finished")
                .item(Instant::now(), now_ms())
        };

        let first = rig.stage("over p2p", DAY);
        rig.record(&first, CarrierChoice::Auto, &[]);
        let mut inner = schedule(&rig, Instant::now());
        let digest = *inner.entries.keys().next().unwrap();
        let ((outcomes, paths), lines) = round(&mut inner);
        assert_eq!(
            outcomes[&digest],
            Outcome::Delivered {
                carrier: Some(OutboxCarrier::P2p)
            }
        );
        assert_eq!(paths.get(&digest), Some(&DeliveryPath::Relayed));
        let tag = netutil::link_tag(&rig.bob_pub);
        assert_eq!(
            lines,
            [format!(
                "raven-node outbox: delivered 1 (p2p_dial, relayed); contact {tag}"
            )]
        );
        assert_eq!(rig.dialled(), [l.clone(), p.clone()]);
        let shown = item(&inner, &first);
        assert_eq!(
            (shown.carrier.as_str(), shown.path.as_str()),
            ("p2p_dial", "relayed")
        );

        rig.set_route(l.clone(), UP);
        let second = rig.stage("over lan", DAY);
        rig.record(&second, CarrierChoice::Auto, &[]);
        let mut inner = schedule(&rig, Instant::now());
        let ((outcomes, paths), lines) = round(&mut inner);
        assert_eq!(
            outcomes.values().next(),
            Some(&Outcome::Delivered {
                carrier: Some(OutboxCarrier::Lan)
            })
        );
        // A LAN delivery records no path, and its line names no address
        // (field test E3 round 2: it logged nothing at all).
        assert!(paths.is_empty(), "{paths:?}");
        assert_eq!(
            lines,
            [format!(
                "raven-node outbox: delivered 1 (lan_dial); contact {tag}"
            )]
        );
        assert!(!lines[0].contains("192.168"), "{lines:?}");
        let shown = item(&inner, &second);
        assert_eq!(
            (shown.carrier.as_str(), shown.path.as_str()),
            ("lan_dial", "")
        );
        assert_eq!(sorted(rig.bob_inbox()), ["over lan", "over p2p"]);
    }

    /// Deliberate reversal is order only: a connected contact's p2p route
    /// goes first and nothing is added; with the p2p gate closed nothing p2p
    /// is planned, so the plan is the same whatever is connected.
    #[test]
    fn connected_routes_go_first_but_order_only() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0xd3);
        let l = lan("192.168.1.20:7420");
        let p = contacts_p2p(rig.a.path(), &rig.bob_pub, &l.dial);
        let mid = rig.stage("reversal", DAY);
        rig.record(&mid, CarrierChoice::Auto, &[]);
        // Every route is down (the rig's default): each attempt dials its
        // whole plan.
        let plain = AttemptCtx {
            p2p_live: on,
            ..rig.ctx()
        };
        let connected = AttemptCtx {
            p2p_live: on,
            connected: p2p_connected,
            ..rig.ctx()
        };
        let _ = rig.attempt_with(&plain);
        assert_eq!(rig.dialled(), [l.clone(), p.clone()]);
        let _ = rig.attempt_with(&connected);
        assert_eq!(rig.dialled()[2..], [p.clone(), l.clone()]);
        // The p2p gate closed: identical, connected or not.
        let held = AttemptCtx {
            connected: p2p_connected,
            ..rig.ctx()
        };
        let _ = rig.attempt_with(&held);
        let _ = rig.attempt_with(&rig.ctx());
        assert_eq!(rig.dialled()[4..], [l.clone(), l.clone()]);
        // The connected route delivers; nothing else is dialled.
        rig.set_route(p.clone(), UP);
        rig.set_path(p.clone(), DeliveryPath::Reversed);
        let report = rig.attempt_with(&connected);
        assert_eq!(
            only(&report),
            Outcome::Delivered {
                carrier: Some(OutboxCarrier::P2p)
            }
        );
        assert_eq!(
            report.paths.values().copied().collect::<Vec<_>>(),
            [DeliveryPath::Reversed]
        );
        assert_eq!(rig.dialled()[6..], [p]);
        assert_eq!(rig.bob_inbox(), ["reversal"]);
    }

    /// Bob's nearby route (Phase 5): derived live, never stored.
    fn nearby_route(peer: &[u8; 32]) -> OutboxRoute {
        OutboxRoute {
            carrier: OutboxCarrier::Nearby,
            dial: raven_core::outbox::nearby_dial_for(peer),
        }
    }

    /// Phase 5 (owner decision O5-13): a verified contact's nearby route is
    /// tried last, and first only while its pipe is up; with the nearby gate
    /// closed, or no engine holding the contact's key, nothing nearby is
    /// dialled, pipe or not. A delivery over a pipe logs one counts-only
    /// line.
    #[test]
    fn worker_tries_nearby_last_unless_a_pipe_is_up() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0xe1);
        let l = lan("127.0.0.1:9");
        contacts(rig.a.path(), &rig.bob_pub, &l.dial, "", true);
        let n = nearby_route(&rig.bob_pub);
        let mid = rig.stage("nearby", DAY);
        rig.record(&mid, CarrierChoice::Auto, &[]);
        let plain = AttemptCtx {
            nearby_live: on,
            nearby_available: nearby_everyone,
            onion_live: || false,
            onion_available: || false,
            onion_head_start: crate::onion::head_start,
            ..rig.ctx()
        };
        let piped = AttemptCtx {
            nearby_live: on,
            nearby_available: nearby_everyone,
            onion_live: || false,
            onion_available: || false,
            onion_head_start: crate::onion::head_start,
            connected: nearby_connected,
            ..rig.ctx()
        };
        // Every route down: the whole plan, nearby last.
        let _ = rig.attempt_with(&plain);
        assert_eq!(rig.dialled(), [l.clone(), n.clone()]);
        let _ = rig.attempt_with(&piped);
        assert_eq!(rig.dialled()[2..], [n.clone(), l.clone()]);
        // The gate closed, or no key: the plan is the one before the
        // carrier existed, pipe or not.
        let closed = AttemptCtx {
            nearby_available: nearby_everyone,
            onion_live: || false,
            onion_available: || false,
            onion_head_start: crate::onion::head_start,
            connected: nearby_connected,
            ..rig.ctx()
        };
        let keyless = AttemptCtx {
            nearby_live: on,
            connected: nearby_connected,
            ..rig.ctx()
        };
        let _ = rig.attempt_with(&closed);
        let _ = rig.attempt_with(&keyless);
        assert_eq!(rig.dialled()[4..], [l.clone(), l.clone()]);
        // The pipe delivers; nothing else is dialled.
        rig.set_route(n.clone(), UP);
        let report = rig.attempt_with(&piped);
        assert_eq!(
            only(&report),
            Outcome::Delivered {
                carrier: Some(OutboxCarrier::Nearby)
            }
        );
        assert_eq!(
            report.delivered_lines(&rig.bob_pub),
            [format!(
                "raven-node outbox: delivered 1 (nearby_dial); contact {}",
                netutil::link_tag(&rig.bob_pub)
            )]
        );
        assert_eq!(rig.dialled()[6..], [n]);
        assert_eq!(rig.bob_inbox(), ["nearby"]);
    }

    /// NEARBY_NOT_IN_RANGE fails at once and stalls nothing: the next route
    /// in the same attempt carries the message, and the route is not
    /// blocked. Another carrier's reason stays the one shown. Nothing nearby
    /// teaches the route memory (not even a delivery after LAN failed).
    #[test]
    fn nearby_not_in_range_does_not_stall_other_routes() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0xe3);
        let l = lan("127.0.0.1:9");
        contacts(rig.a.path(), &rig.bob_pub, &l.dial, "", true);
        let n = nearby_route(&rig.bob_pub);
        let ctx = |connected: fn(&OutboxRoute) -> bool| AttemptCtx {
            nearby_live: on,
            nearby_available: nearby_everyone,
            onion_live: || false,
            onion_available: || false,
            onion_head_start: crate::onion::head_start,
            connected,
            ..rig.ctx_net(on, off)
        };
        let first = rig.stage("around", DAY);
        rig.record(&first, CarrierChoice::Auto, &[]);
        // Its pipe just went (still flagged up): out of range, LAN down.
        rig.set_route(n.clone(), NOT_IN_RANGE);
        let report = rig.attempt_with(&ctx(nearby_connected));
        assert_eq!(rig.dialled(), [n.clone(), l.clone()]);
        assert_eq!(
            only(&report),
            Outcome::Unreachable {
                carrier: Some(OutboxCarrier::Lan),
                code: code::NOT_LISTENING
            }
        );
        assert!(report.blocked.is_empty() && report.pin_blocked.is_empty());
        // Plan order (no pipe): LAN first, then nearby; LAN's reason stays.
        let report = rig.attempt_with(&ctx(never_connected));
        assert_eq!(rig.dialled()[2..], [l.clone(), n.clone()]);
        assert_eq!(
            only(&report),
            Outcome::Unreachable {
                carrier: Some(OutboxCarrier::Lan),
                code: code::NOT_LISTENING
            }
        );
        // LAN up: delivered in the same attempt, after the nearby try.
        rig.set_route(l.clone(), UP);
        let report = rig.attempt_with(&ctx(nearby_connected));
        assert_eq!(rig.dialled()[4..], [n.clone(), l.clone()]);
        assert_eq!(
            only(&report),
            Outcome::Delivered {
                carrier: Some(OutboxCarrier::Lan)
            }
        );
        // LAN down, the nearby pipe delivers: no route memory lead.
        let second = rig.stage("over the air", DAY);
        rig.record(&second, CarrierChoice::Auto, &[]);
        rig.set_route(l.clone(), DOWN);
        rig.set_route(n.clone(), UP);
        let report = rig.attempt_with(&ctx(never_connected));
        assert_eq!(rig.dialled()[6..], [l.clone(), n.clone()]);
        assert_eq!(
            only(&report),
            Outcome::Delivered {
                carrier: Some(OutboxCarrier::Nearby)
            }
        );
        assert_eq!(remembered(&rig), None, "nearby is never route evidence");
        // Nearby alone and out of range: its own code.
        contacts(rig.a.path(), &rig.bob_pub, "", "", true);
        let third = rig.stage("alone", DAY);
        rig.record(&third, CarrierChoice::Auto, &[]);
        rig.set_route(n.clone(), NOT_IN_RANGE);
        let report = rig.attempt_with(&ctx(never_connected));
        assert_eq!(
            only(&report),
            Outcome::Unreachable {
                carrier: Some(OutboxCarrier::Nearby),
                code: code::NEARBY_NOT_IN_RANGE
            }
        );
        assert_eq!(remembered(&rig), None);
    }

    /// A `--carrier nearby` object never widens: nothing else is dialled
    /// for it, and without a nearby route it is held.
    #[test]
    fn a_forced_nearby_object_never_widens() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0xe5);
        let l = lan("127.0.0.1:9");
        contacts(rig.a.path(), &rig.bob_pub, &l.dial, "", true);
        let n = nearby_route(&rig.bob_pub);
        rig.set(UP);
        let mid = rig.stage("by radio only", DAY);
        rig.record(&mid, CarrierChoice::Nearby, &[]);
        let report = rig.attempt_with(&AttemptCtx {
            nearby_live: on,
            ..rig.ctx()
        });
        assert_eq!(only(&report), Outcome::Held(code::NO_ROUTE));
        assert_eq!(rig.dials(), 0, "LAN is up but not this object's");
        let ctx = AttemptCtx {
            nearby_live: on,
            nearby_available: nearby_everyone,
            onion_live: || false,
            onion_available: || false,
            onion_head_start: crate::onion::head_start,
            ..rig.ctx()
        };
        rig.set_route(n.clone(), NOT_IN_RANGE);
        let report = rig.attempt_with(&ctx);
        assert_eq!(
            only(&report),
            Outcome::Unreachable {
                carrier: Some(OutboxCarrier::Nearby),
                code: code::NEARBY_NOT_IN_RANGE
            }
        );
        rig.set_route(n.clone(), UP);
        let report = rig.attempt_with(&ctx);
        assert_eq!(
            only(&report),
            Outcome::Delivered {
                carrier: Some(OutboxCarrier::Nearby)
            }
        );
        assert_eq!(rig.dialled(), [n.clone(), n]);
    }

    /// G3 wins: a connected route that took the object's frames without an
    /// ACK is not moved first again; the next attempt starts after it.
    #[test]
    fn a_silent_connected_route_is_not_moved_first() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0xd5);
        let l = lan("192.168.1.20:7420");
        let p = contacts_p2p(rig.a.path(), &rig.bob_pub, &l.dial);
        let mid = rig.stage("silent p2p", DAY);
        rig.record(&mid, CarrierChoice::Auto, &[]);
        rig.set(UP);
        rig.set_route(p.clone(), SILENT);
        let ctx = AttemptCtx {
            p2p_live: on,
            connected: p2p_connected,
            ..rig.ctx()
        };
        let mut inner = schedule(&rig, Instant::now());
        let digest = *inner.entries.keys().next().unwrap();
        let (outcomes, unacked) = worker_round(&ctx, &mut inner);
        assert_eq!(
            outcomes[&digest],
            Outcome::Sent {
                carrier: Some(OutboxCarrier::P2p),
                code: code::NO_ACK_YET
            }
        );
        assert_eq!(unacked.get(&digest), Some(&p));
        let (outcomes, _) = worker_round(&ctx, &mut inner);
        assert_eq!(
            outcomes[&digest],
            Outcome::Delivered {
                carrier: Some(OutboxCarrier::Lan)
            }
        );
        assert_eq!(
            rig.dialled(),
            [p, l],
            "connected first, then G3's rotation keeps it last"
        );
        assert_eq!(rig.bob_inbox(), ["silent p2p"]);
    }

    /// The ACKs we owe ride the contact's connection first too.
    #[test]
    fn owed_acks_ride_a_connected_route_first() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0xd7);
        let l = lan("192.168.1.20:7420");
        let p = contacts_p2p(rig.a.path(), &rig.bob_pub, &l.dial);
        let owed = vec![(
            [7u8; 32],
            UnsentAck {
                peer: rig.bob_pub,
                bytes: ack_envelope(7, now_ms() + 3_600_000),
                expires_at_ms: now_ms() + 3_600_000,
                failures: 0,
                next_due: Instant::now(),
                durable: false,
                session_id: None,
                held_by: Vec::new(),
                may_deposit: true,
            },
        )];
        let plain = AttemptCtx {
            p2p_live: on,
            ..rig.ctx()
        };
        let connected = AttemptCtx {
            p2p_live: on,
            connected: p2p_connected,
            ..rig.ctx()
        };
        let report = attempt_peer(&plain, &rig.bob_pub, &[], &owed);
        assert_eq!(report.acks_failed.len(), 1);
        assert_eq!(rig.dialled(), [l.clone(), p.clone()]);
        let report = attempt_peer(&connected, &rig.bob_pub, &[], &owed);
        assert_eq!(report.acks_failed.len(), 1);
        assert_eq!(rig.dialled()[2..], [p.clone(), l.clone()]);
        rig.set(UP);
        let report = attempt_peer(&connected, &rig.bob_pub, &[], &owed);
        assert_eq!(report.acks_done, [[7u8; 32]]);
        assert_eq!(rig.dialled()[4..], [p]);
    }

    /// G2: a delivery that only rode the contact's own connection (reversed)
    /// cannot be repeated on demand, so it never earns the lead; the same
    /// delivery through the relay does.
    #[test]
    fn a_reversed_delivery_never_earns_a_route_lease() {
        if !lab_backends() {
            return;
        }
        let rig = Rig::new(0xd9);
        let l = lan("192.168.1.20:7420");
        let p = contacts_p2p(rig.a.path(), &rig.bob_pub, &l.dial);
        rig.set(UP);
        rig.set_route(l.clone(), DOWN);
        rig.set_path(p.clone(), DeliveryPath::Reversed);
        let ctx = AttemptCtx {
            p2p_live: on,
            ..rig.ctx_net(on, off)
        };
        let over_p2p = Outcome::Delivered {
            carrier: Some(OutboxCarrier::P2p),
        };
        let first = rig.stage("reversed", DAY);
        rig.record(&first, CarrierChoice::Auto, &[]);
        assert_eq!(only(&rig.attempt_with(&ctx)), over_p2p);
        assert_eq!(rig.dialled(), [l.clone(), p.clone()]);
        assert!(
            !memory_file(&rig).exists(),
            "no lead for a reversed delivery"
        );
        // The control: through the relay, after the same dead LAN.
        rig.set_path(p.clone(), DeliveryPath::Relayed);
        let second = rig.stage("relayed", DAY);
        rig.record(&second, CarrierChoice::Auto, &[]);
        assert_eq!(only(&rig.attempt_with(&ctx)), over_p2p);
        assert_eq!(remembered(&rig), Some(p));
    }

    /// Plan step 1 is order only and leaves G3's silent route where it is.
    #[test]
    fn connected_first_moves_connected_p2p_routes_only() {
        let (l, i) = (lan("192.168.1.20:7420"), inet("203.0.113.7:7422"));
        let p = |n: u8| OutboxRoute {
            carrier: OutboxCarrier::P2p,
            dial: raven_core::p2p_route::peer_route(&raven_core::p2p_route::local_peer_id(
                &Identity::from_seed(&[n; 32]),
            )),
        };
        let (p1, p2) = (p(1), p(2));
        let pairs = |routes: &[&OutboxRoute]| -> Vec<(OutboxRoute, OutboxRoute)> {
            routes
                .iter()
                .map(|r| ((*r).clone(), (*r).clone()))
                .collect()
        };
        let mut routes = pairs(&[&l, &p1, &i, &p2]);
        connected_first(&mut routes, p2p_connected, None);
        assert_eq!(routes, pairs(&[&p1, &p2, &l, &i]));
        let mut routes = pairs(&[&l, &p1, &i, &p2]);
        connected_first(&mut routes, p2p_connected, Some(&p1));
        assert_eq!(routes, pairs(&[&p2, &l, &p1, &i]));
        let mut routes = pairs(&[&l, &p1, &i]);
        connected_first(&mut routes, never_connected, None);
        assert_eq!(routes, pairs(&[&l, &p1, &i]));
        let mut none = Vec::new();
        connected_first(&mut none, p2p_connected, None);
        assert!(none.is_empty());
    }

    /// Phase 6b R4 (design A, step P6.28): a Suspicious tag failure on a
    /// contact's LAN links puts its LAN route behind friend custody (set
    /// aside for the attempt, custody first) and behind its other carriers,
    /// for 10 minutes on that network only. With no other route and no
    /// custody the LAN route stays first; nothing is ever added; with the
    /// responses gate shut nothing moves.
    #[test]
    fn interference_puts_a_lan_route_behind_custody_for_ten_minutes() {
        use raven_core::route_memory::{note_interference, INTERFERENCE_MS};
        let (l, i) = (lan("192.168.1.20:7420"), inet("203.0.113.7:7422"));
        let pairs = |routes: &[&OutboxRoute]| -> Vec<(OutboxRoute, OutboxRoute)> {
            routes
                .iter()
                .map(|r| ((*r).clone(), (*r).clone()))
                .collect()
        };
        let peer = [0x8a; 32];
        let (here, there) = ([0x5a; 8], [0x5b; 8]);
        let now = now_ms();
        let hit = |at: u64, net: [u8; 8]| {
            raven_core::route_memory::interfered_carriers(&peer, Some(net), at)
        };
        // Shut (whatever a lab run's variables say): nothing is noted.
        {
            use raven_core::security_gate::{set_lab_for_this_thread, SecGate};
            set_lab_for_this_thread(SecGate::Responses, Some(false));
            note_interference(&peer, here, OutboxCarrier::Lan, now + INTERFERENCE_MS);
            assert!(hit(now, here).is_empty());
            set_lab_for_this_thread(SecGate::Responses, None);
        }
        let Some(_capture) = crate::security::tests::Capture::start() else {
            return;
        };
        let Some(_responding) = crate::security::tests::Responding::start() else {
            return;
        };
        assert!(hit(now, here).is_empty(), "nothing was noted while shut");
        note_interference(&peer, here, OutboxCarrier::Lan, now + INTERFERENCE_MS);
        let lan_hit = hit(now + 60_000, here);
        assert_eq!(lan_hit, [OutboxCarrier::Lan]);
        assert!(hit(now, there).is_empty(), "another network");
        // Custody may carry it: LAN waits behind custody this attempt.
        let mut routes = pairs(&[&l]);
        assert!(demote_interfered(&mut routes, &lan_hit, true));
        assert!(routes.is_empty());
        let mut routes = pairs(&[&l, &i]);
        assert!(demote_interfered(&mut routes, &lan_hit, true));
        assert_eq!(routes, pairs(&[&i]));
        // No custody: the other carrier first, LAN last.
        let mut routes = pairs(&[&l, &i]);
        assert!(!demote_interfered(&mut routes, &lan_hit, false));
        assert_eq!(routes, pairs(&[&i, &l]));
        // No other route, no custody: LAN stays first.
        let mut routes = pairs(&[&l]);
        assert!(!demote_interfered(&mut routes, &lan_hit, false));
        assert_eq!(routes, pairs(&[&l]));
        // Another carrier's interference leaves this plan as it is.
        let mut routes = pairs(&[&l, &i]);
        assert!(!demote_interfered(&mut routes, &[OutboxCarrier::P2p], true));
        assert_eq!(routes, pairs(&[&l, &i]));
        // Ten minutes later: LAN first again, custody or not.
        let later = hit(now + INTERFERENCE_MS, here);
        assert!(later.is_empty());
        let mut routes = pairs(&[&l, &i]);
        assert!(!demote_interfered(&mut routes, &later, true));
        assert_eq!(routes, pairs(&[&l, &i]));
    }

    /// The shared resolver ([`peer_plan`], the worker's, AppSubmit's and
    /// the announcer's): a connected contact's p2p route first, then the
    /// remembered route, then plan order. A learned LAN address on none of
    /// this computer's networks is left out; one on them follows the saved
    /// route. [`PeerPlan::plain`] ignores the memory. Nothing is dialled.
    #[test]
    fn peer_plan_orders_connected_then_remembered_then_plan() {
        let dir = tempfile::tempdir().unwrap();
        let alice = Arc::new(Identity::from_seed(&[0x5c; 32]));
        let bob = Identity::from_seed(&[0x5d; 32]).public_key_bytes();
        let (saved, learned) = (lan("10.0.0.5:7420"), lan("192.168.1.20:7420"));
        let i = inet("203.0.113.9:7422");
        let p = contacts_all(dir.path(), &bob, &saved.dial, &i.dial);
        let seen_at: IpAddr = "192.168.1.20".parse().unwrap();
        raven_core::lan_seen::record_contact_seen(dir.path(), &bob, seen_at, None, now_ms())
            .unwrap();
        super::test_rig::remember(dir.path(), &bob, &i, "test-net");
        let nodial = Arc::new(NoDial::default());
        let ctx =
            |on_link: fn(IpAddr) -> Option<bool>, connected: fn(&OutboxRoute) -> bool| AttemptCtx {
                internet_live: on,
                p2p_live: on,
                net_tag: test_net,
                on_link,
                connected,
                ..test_ctx(dir.path(), Arc::clone(&alice), nodial.clone())
            };
        let plan = |ctx: &AttemptCtx| {
            let ContactAdmission::Allowed(c) = contact_admission(dir.path(), &bob) else {
                panic!("Bob is a contact");
            };
            peer_plan(ctx, &bob, c, now_ms())
        };
        let dial_order = |ctx: &AttemptCtx| -> Vec<OutboxRoute> {
            plan(ctx)
                .auto_dial(&bob, ctx.connected, &mut |r, pinned| {
                    localize_lan_route(r, pinned, LOCALIZE_RESOLVE_TIMEOUT)
                })
                .into_iter()
                .map(|(planned, _)| planned)
                .collect()
        };
        assert_eq!(
            dial_order(&ctx(|_| Some(false), p2p_connected)),
            [p.clone(), i.clone(), saved.clone()]
        );
        assert_eq!(
            dial_order(&ctx(|_| Some(false), never_connected)),
            [i.clone(), saved.clone(), p.clone()]
        );
        assert_eq!(
            dial_order(&ctx(|_| Some(true), never_connected)),
            [i.clone(), saved.clone(), learned.clone(), p.clone()]
        );
        let on_link = plan(&ctx(|_| Some(true), p2p_connected));
        assert_eq!(on_link.net.as_deref(), Some("test-net"));
        assert_eq!(on_link.preferred.as_ref(), Some(&i));
        assert_eq!(on_link.plain(&bob), [saved, learned, i, p]);
        // The memory off: nothing remembered.
        assert_eq!(
            plan(&test_ctx(dir.path(), alice, nodial.clone())).preferred,
            None
        );
        assert_eq!(nodial.dials(), 0);
    }

    /// A card's LAN route (`lan=`: nobody signs a card's routes, and the
    /// security words cover the key only) keeps the local-network rule for a
    /// verified contact too: at a public address it is never dialled, by the
    /// worker, AppSubmit or the announcer ([`PeerPlan::auto_dial`]), session
    /// renewal and the horizon ([`PeerPlan::renewal_routes`]) or an
    /// exploration probe ([`explore_plan`]). At a local address it goes as
    /// before, and a LAN address typed on this computer or learned from the
    /// contact's authenticated link may lie beyond the local network.
    #[test]
    fn a_cards_lan_route_stays_on_the_local_network_for_a_verified_contact() {
        let dir = tempfile::tempdir().unwrap();
        let alice = Arc::new(Identity::from_seed(&[0x6e; 32]));
        let bob = Identity::from_seed(&[0x6f; 32]).public_key_bytes();
        let nodial = Arc::new(NoDial::default());
        let ctx = test_ctx(dir.path(), Arc::clone(&alice), nodial.clone());
        let plan = || {
            let ContactAdmission::Allowed(c) = contact_admission(dir.path(), &bob) else {
                panic!("Bob is a contact");
            };
            assert!(c.pinned, "Bob is verified");
            peer_plan(&ctx, &bob, c, now_ms())
        };
        let dialled = || -> Vec<OutboxRoute> {
            plan()
                .auto_dial(&bob, never_connected, &mut |r, pinned| {
                    localize_lan_route(r, pinned, LOCALIZE_RESOLVE_TIMEOUT)
                })
                .into_iter()
                .map(|(_, dialled)| dialled)
                .collect()
        };
        let book = |dial: &str, trusted: bool| {
            std::fs::write(
                dir.path().join("contacts.json"),
                format!(
                    r#"[{{"petname":"Bob","address":"","pub_hex":"{}","pinned":true,"lan_dial":"{dial}","lan_dial_trusted":{trusted}}}]"#,
                    hex::encode(bob)
                ),
            )
            .unwrap();
        };
        let public = lan("203.0.113.7:7420");
        // From a card (or a book from before the mark): not dialled.
        book(&public.dial, false);
        assert!(dialled().is_empty());
        assert!(plan().renewal_routes(&bob).is_empty());
        assert!(explore_plan(&ctx, &bob).is_some_and(|(routes, _)| routes.is_empty()));
        // A card's local address: as before.
        let local = lan("192.168.1.40:7420");
        book(&local.dial, false);
        assert_eq!(dialled(), std::slice::from_ref(&local));
        assert_eq!(plan().renewal_routes(&bob), [local]);
        // Typed here, or learned after an authenticated delivery.
        book(&public.dial, true);
        assert_eq!(dialled(), std::slice::from_ref(&public));
        assert_eq!(plan().renewal_routes(&bob), [public]);
        assert_eq!(nodial.dials(), 0);
    }

    /// P3.14: what a session renewal may dial ([`PeerPlan::renewal_routes`]
    /// after [`plan_inputs`]): any carrier behind its gate, the remembered
    /// route first. `raven lan off` (the LAN gate closed) leaves no LAN route,
    /// hide-IP no Internet route, and an unverified contact only its LAN
    /// routes; a key that is no contact is held. Nothing is dialled.
    #[test]
    fn renewal_routes_obey_gates_lan_off_hide_ip_and_pin() {
        let dir = tempfile::tempdir().unwrap();
        let alice = Arc::new(Identity::from_seed(&[0x6c; 32]));
        let bob = Identity::from_seed(&[0x6d; 32]).public_key_bytes();
        let saved = lan("10.0.0.5:7420");
        let i = inet("203.0.113.9:7422");
        let p = contacts_all(dir.path(), &bob, &saved.dial, &i.dial);
        super::test_rig::remember(dir.path(), &bob, &i, "test-net");
        let nodial = Arc::new(NoDial::default());
        let ctx = |lan_live: fn() -> bool| AttemptCtx {
            lan_live,
            internet_live: on,
            p2p_live: on,
            net_tag: test_net,
            ..test_ctx(dir.path(), Arc::clone(&alice), nodial.clone())
        };
        let plan = |ctx: &AttemptCtx| plan_inputs(ctx, &bob, now_ms(), true).unwrap();
        // Every gate open: the remembered route first, then plan order.
        assert_eq!(
            plan(&ctx(on)).renewal_routes(&bob),
            [i.clone(), saved.clone(), p.clone()]
        );
        // `raven lan off`: no LAN route.
        assert_eq!(plan(&ctx(off)).renewal_routes(&bob), [i.clone(), p.clone()]);
        // Today's gates (LAN only): LAN only.
        let lan_only = test_ctx(dir.path(), Arc::clone(&alice), nodial.clone());
        assert_eq!(
            plan(&lan_only).renewal_routes(&bob),
            std::slice::from_ref(&saved)
        );
        // Hide my IP from Bob: no Internet route.
        let mut hidden = plan(&ctx(on));
        hidden.contact.hide_ip = true;
        assert_eq!(hidden.renewal_routes(&bob), [saved.clone(), p]);
        // Not verified: LAN only, whatever the gates.
        let mut unverified = plan(&ctx(on));
        unverified.contact.pinned = false;
        assert_eq!(unverified.renewal_routes(&bob), [saved]);
        // No contact: held before anything is planned.
        assert_eq!(
            plan_inputs(&ctx(on), &[0x6e; 32], now_ms(), true).err(),
            Some(code::NOT_A_CONTACT)
        );
        assert_eq!(nodial.dials(), 0);
    }

    // ---- Phase 3 P3.20: learned custodians in the worker ----

    /// Phase 3 rig: Alice, Bob (down at 127.0.0.1:9, listing no custodian)
    /// and Carol (verified by both, holding mail); custody live, riding
    /// route hints, on this thread. Carol's row in Alice's book is
    /// `carol_route` (JSON fields). Carol's dials are logged.
    struct Learned {
        rig: Rig,
        net: Arc<CustodianMoved>,
        c_dir: tempfile::TempDir,
        carol: [u8; 32],
    }

    /// The overrides [`Learned`] sets on this thread; cleared on drop. The
    /// letters stay held: these tests check the base deposit, and with
    /// `RAVEN_LAB_LETTER` set a custodian key another test of this process
    /// noted as serving letters (the cache is process-wide, keyed by key:
    /// carry_tests' World(0x36) Dave is Learned(0x31)'s Carol) would take
    /// the letter path instead.
    struct LearnedGates;

    impl LearnedGates {
        fn on(wan: bool, p2p: bool) -> Self {
            raven_core::custody_gate::set_custody_gates_for_this_thread(Some(
                raven_core::custody_gate::CustodyGates { live: true, wan },
            ));
            raven_core::custody_gate::set_custody_hints_for_this_thread(Some(true));
            raven_core::custody_gate::set_carrier_gates_for_this_thread(Some(CarrierGates {
                lan: true,
                internet: false,
                p2p,
                nearby: false,
                onion: false,
            }));
            raven_core::horizon::set_lab_letter_for_this_thread(Some(false));
            Self
        }
    }

    impl Drop for LearnedGates {
        fn drop(&mut self) {
            raven_core::custody_gate::set_custody_gates_for_this_thread(None);
            raven_core::custody_gate::set_custody_hints_for_this_thread(None);
            raven_core::custody_gate::set_carrier_gates_for_this_thread(None);
            raven_core::horizon::set_lab_letter_for_this_thread(None);
        }
    }

    /// One sender's learned custody: its key, the custodian tags it
    /// announced, its custody offer.
    type ToldCustody = ([u8; 32], Vec<[u8; 32]>, Option<u8>);

    /// `dir`'s learned_routes.json: per sender, the custodian tags it
    /// announced and its custody offer.
    fn learned_custody(dir: &Path, entries: &[ToldCustody]) {
        let now = now_ms();
        let rows: Vec<serde_json::Value> = entries
            .iter()
            .map(|(sender, tags, offer)| {
                let mut row = serde_json::json!({
                    "pub_hex": hex::encode(sender),
                    "generation": now,
                    "received_at_ms": now,
                    "expires_at_ms": now + 600_000,
                    "via": "lan",
                });
                if !tags.is_empty() {
                    row["custodian_tags"] = tags.iter().map(hex::encode).collect();
                    row["custodian_tag_flags"] = vec![0u8; tags.len()].into();
                }
                if let Some(flags) = offer {
                    row["custody_offer"] = (*flags).into();
                }
                row
            })
            .collect();
        std::fs::write(
            dir.join(raven_core::learned_routes::LEARNED_ROUTES_FILE),
            serde_json::to_vec(&rows).unwrap(),
        )
        .unwrap();
    }

    fn uses_friends(dir: &Path, custody_use: Option<bool>) {
        raven_core::save_policy(
            dir,
            &raven_core::NodePolicy {
                custody_use,
                ..Default::default()
            },
        )
        .unwrap();
    }

    impl Learned {
        fn new(seed: u8, carol_route: &str, bob_lists_carol: bool) -> Self {
            let rig = Rig::new(seed);
            let carol = Identity::from_seed(&[seed.wrapping_add(8); 32]);
            let c_dir = tempfile::tempdir().unwrap();
            ensure_local_device_certificate(c_dir.path(), &carol, PRIMARY_DEVICE_ID).unwrap();
            raven_core::ensure_local_prekey(c_dir.path(), &carol).unwrap();
            let carol_pub = carol.public_key_bytes();
            let hexk = |k: &[u8; 32]| hex::encode(k);
            let listed = if bob_lists_carol {
                format!(r#","custodians":["{}"]"#, hexk(&carol_pub))
            } else {
                String::new()
            };
            std::fs::write(
                rig.a.path().join("contacts.json"),
                format!(
                    r#"[{{"petname":"Bob","pub_hex":"{}","pinned":true,"lan_dial":"127.0.0.1:9"{listed}}},
                       {{"petname":"Carol","pub_hex":"{}","pinned":true,{carol_route}}}]"#,
                    hexk(&rig.bob_pub),
                    hexk(&carol_pub),
                ),
            )
            .unwrap();
            std::fs::write(
                c_dir.path().join("contacts.json"),
                format!(
                    r#"[{{"petname":"Alice","pub_hex":"{}","pinned":true}},{{"petname":"Bob","pub_hex":"{}","pinned":true}}]"#,
                    hexk(&rig.alice.public_key_bytes()),
                    hexk(&rig.bob_pub)
                ),
            )
            .unwrap();
            raven_core::save_policy(
                c_dir.path(),
                &raven_core::NodePolicy {
                    custody: true,
                    ..Default::default()
                },
            )
            .unwrap();
            let net = Arc::new(CustodianMoved {
                net: ThreeNet {
                    alice_bundle: local_bundle(rig.a.path(), &rig.alice).unwrap(),
                    alice_pub: rig.alice.public_key_bytes(),
                    nodes: vec![
                        (
                            hexk(&rig.bob_pub),
                            rig.b.path().to_path_buf(),
                            Identity::from_seed(&[seed.wrapping_add(1); 32]),
                        ),
                        (hexk(&carol_pub), c_dir.path().to_path_buf(), carol),
                    ],
                    bob_hex: hexk(&rig.bob_pub),
                    bob_down: AtomicBool::new(true),
                },
                carol_hex: hexk(&carol_pub),
                saved: lan("10.255.255.1:1"),
                stale: lan("10.255.255.1:1"),
                carol_dials: Mutex::new(Vec::new()),
            });
            Self {
                rig,
                net,
                c_dir,
                carol: carol_pub,
            }
        }

        fn ctx(&self) -> AttemptCtx {
            AttemptCtx {
                data_dir: self.rig.a.path().to_path_buf(),
                identity: Arc::clone(&self.rig.alice),
                dialer: self.net.clone(),
                lan_live: on,
                internet_live: off,
                p2p_live: off,
                nearby_live: off,
                nearby_available: no_nearby,
                onion_live: || false,
                onion_available: || false,
                onion_head_start: crate::onion::head_start,
                net_tag: no_net,
                on_link: unknown_link,
                connected: never_connected,
                lan_beacon_routes: no_finds,
                lan_want: no_want,
                lan_beacon_failed: no_find_failed,
                reset_backoff: Mutex::default(),
            }
        }

        /// A message queued `age_ms` ago that friend custody may carry.
        fn message(&self, text: &str, age_ms: u64) -> [u8; 16] {
            let mid = self.rig.stage_with(text, now_ms() - age_ms, DAY, true);
            self.rig
                .record(&mid, CarrierChoice::Auto, &[lan("127.0.0.1:9")]);
            raven_core::outbox::set_object_custody(self.rig.a.path(), &mid, now_ms()).unwrap();
            mid
        }

        /// Bob announced `tags`; Carol offers custody with `offer`.
        fn told(&self, tags: Vec<[u8; 32]>, offer: Option<u8>) {
            learned_custody(
                self.rig.a.path(),
                &[
                    (self.rig.bob_pub, tags, None),
                    (self.carol, Vec::new(), offer),
                ],
            );
        }

        /// The tag Bob announces for Carol (Bob to Alice).
        fn tag(&self) -> [u8; 32] {
            raven_core::route_hints::custodian_tag(
                &self.rig.bob_pub,
                &self.rig.alice.public_key_bytes(),
                &self.carol,
            )
        }

        fn carol_dials(&self) -> usize {
            self.net.carol_dials.lock().unwrap().len()
        }

        fn carol_holds(&self) -> u64 {
            raven_core::friend_custody::CustodyStore::open_existing(self.c_dir.path())
                .unwrap()
                .map_or(0, |s| s.usage().unwrap().0 as u64)
        }
    }

    /// The code an attempt left on a message that was not carried.
    fn code_of(outcome: &Outcome) -> &'static str {
        match outcome {
            Outcome::Unreachable { code, .. } | Outcome::Held(code) => code,
            other => panic!("{other:?}"),
        }
    }

    const CAROL_LAN: &str = r#""lan_dial":"192.168.1.50:7420""#;

    #[test]
    fn w17_learned_custodian_without_static_config_deposits() {
        if !lab_backends() {
            return;
        }
        let _lan = crate::lan_direct::lan_switch_untouched();
        let _g = LearnedGates::on(false, false);
        let l = Learned::new(0x31, CAROL_LAN, false);
        uses_friends(l.rig.a.path(), Some(true));
        l.told(vec![l.tag()], Some(0));
        let mid = l.message("via a learned friend", 120_000);
        let report = l.rig.attempt_with(&l.ctx());
        assert_eq!(only(&report), Outcome::Deposited { held: 1 });
        assert!(l.carol_dials() > 0);
        assert_eq!(l.carol_holds(), 1);
        let records = object_route_records(l.rig.a.path(), now_ms()).unwrap();
        assert_eq!(records[&mid].custodians_held, vec![hex::encode(l.carol)]);
        let book = std::fs::read_to_string(l.rig.a.path().join("contacts.json")).unwrap();
        assert!(!book.contains(&format!(r#""custodians":["{}"]"#, hex::encode(l.carol))));
    }

    #[test]
    fn w18_consent_off_never_uses_learned_but_static_still_works() {
        if !lab_backends() {
            return;
        }
        let _lan = crate::lan_direct::lan_switch_untouched();
        let _g = LearnedGates::on(false, false);
        let l = Learned::new(0x34, CAROL_LAN, false);
        l.told(vec![l.tag()], Some(0));
        l.message("not without consent", 120_000);
        // Never asked: no deposit, and the status says why.
        uses_friends(l.rig.a.path(), None);
        let report = l.rig.attempt_with(&l.ctx());
        assert_eq!(code_of(&only(&report)), code::MAILBOX_OFF);
        // Said no: no deposit, no custody status.
        uses_friends(l.rig.a.path(), Some(false));
        let report = l.rig.attempt_with(&l.ctx());
        let code = code_of(&only(&report));
        assert!(
            ![
                code::MAILBOX_OFF,
                code::NO_SHARED_CUSTODIAN,
                code::CUSTODIAN_NOT_OFFERING
            ]
            .contains(&code),
            "{code}"
        );
        assert_eq!(l.carol_dials(), 0);
        // A custodian listed by hand still works without that consent.
        let l2 = Learned::new(0x37, CAROL_LAN, true);
        uses_friends(l2.rig.a.path(), Some(false));
        l2.told(vec![l2.tag()], Some(0));
        l2.message("listed by hand", 120_000);
        let report = l2.rig.attempt_with(&l2.ctx());
        assert_eq!(only(&report), Outcome::Deposited { held: 1 });
        assert_eq!(l2.carol_holds(), 1);
    }

    #[test]
    fn w19_unmatched_tags_give_no_shared_custodian_status_and_no_dial() {
        if !lab_backends() {
            return;
        }
        let _lan = crate::lan_direct::lan_switch_untouched();
        let _g = LearnedGates::on(false, false);
        let l = Learned::new(0x3a, CAROL_LAN, false);
        uses_friends(l.rig.a.path(), Some(true));
        // Bob collects mail from a friend Alice does not know.
        let stranger = Identity::from_seed(&[0x3f; 32]).public_key_bytes();
        let unknown = raven_core::route_hints::custodian_tag(
            &l.rig.bob_pub,
            &l.rig.alice.public_key_bytes(),
            &stranger,
        );
        l.told(vec![unknown], Some(0));
        l.message("nobody shared", 120_000);
        let report = l.rig.attempt_with(&l.ctx());
        let outcome = only(&report);
        assert!(
            matches!(outcome, Outcome::Unreachable { .. } | Outcome::Held(_)),
            "the outcome is unchanged: {outcome:?}"
        );
        assert_eq!(code_of(&outcome), code::NO_SHARED_CUSTODIAN);
        assert_eq!(l.carol_dials(), 0);
        assert_eq!(l.carol_holds(), 0);
    }

    #[test]
    fn w20_offer_without_wan_bit_and_only_p2p_routes_gives_custodian_not_offering_and_no_dial() {
        if !lab_backends() {
            return;
        }
        let _lan = crate::lan_direct::lan_switch_untouched();
        let _g = LearnedGates::on(true, true);
        let peer_id = raven_core::p2p_route::local_peer_id(&Identity::from_seed(&[0x78; 32]));
        let carol_p2p = format!(r#""p2p":"{peer_id}""#);
        let l = Learned::new(0x3d, &carol_p2p, false);
        uses_friends(l.rig.a.path(), Some(true));
        // Carol holds mail on LAN links only, and only p2p reaches her.
        l.told(
            vec![l.tag()],
            Some(raven_core::custody_gate::OFFER_REACHABLE),
        );
        l.message("lan only", 120_000);
        let report = l.rig.attempt_with(&l.ctx());
        assert_eq!(code_of(&only(&report)), code::CUSTODIAN_NOT_OFFERING);
        assert_eq!(l.carol_dials(), 0);
        // No offer at all: the same.
        l.told(vec![l.tag()], None);
        let report = l.rig.attempt_with(&l.ctx());
        assert_eq!(code_of(&only(&report)), code::CUSTODIAN_NOT_OFFERING);
        assert_eq!(l.carol_dials(), 0);
        // With the WAN bit her p2p route is dialled.
        l.told(vec![l.tag()], Some(raven_core::custody_gate::OFFER_WAN));
        l.rig.attempt_with(&l.ctx());
        let dials = l.net.carol_dials.lock().unwrap().clone();
        assert!(!dials.is_empty());
        assert!(dials.iter().all(|r| r.carrier == OutboxCarrier::P2p));
    }

    #[test]
    fn w21_deposits_split_by_bytes_into_two_dials() {
        if !lab_backends() {
            return;
        }
        let _lan = crate::lan_direct::lan_switch_untouched();
        let _g = LearnedGates::on(false, false);
        let l = Learned::new(0x40, CAROL_LAN, false);
        uses_friends(l.rig.a.path(), Some(true));
        l.told(vec![l.tag()], Some(0));
        // Eleven of the largest LAN messages: within 16 frames, past 512 KiB.
        let text = "x".repeat(raven_core::lan_noise::MAX_LAN_ENDPOINT_TEXT);
        for i in 0..11 {
            l.message(&format!("{i}{text}")[..text.len()], 120_000);
        }
        let report = l.rig.attempt_with(&l.ctx());
        assert_eq!(report.outcomes.len(), 11);
        assert!(report
            .outcomes
            .values()
            .all(|o| *o == Outcome::Deposited { held: 1 }));
        assert_eq!(l.carol_dials(), 2, "512 KiB per dial");
        assert_eq!(l.carol_holds(), 11);
    }

    #[test]
    fn w22_hand_off_skips_the_60s_wait_but_still_needs_a_failed_direct_try() {
        if !lab_backends() {
            return;
        }
        let _lan = crate::lan_direct::lan_switch_untouched();
        let _g = LearnedGates::on(false, false);
        let l = Learned::new(0x43, CAROL_LAN, false);
        uses_friends(l.rig.a.path(), Some(true));
        l.told(vec![l.tag()], Some(0));
        // Ten seconds old: the direct path is still having its chance.
        l.message("hand it off", 10_000);
        let report = l.rig.attempt_with(&l.ctx());
        assert!(
            matches!(only(&report), Outcome::Unreachable { .. }),
            "{report:?}"
        );
        assert_eq!(l.carol_dials(), 0);
        // `raven outbox hand-off`: no wait, Bob still tried first.
        crate::custody::hand_off(Some(l.rig.bob_pub));
        let report = l.rig.attempt_with(&l.ctx());
        assert_eq!(only(&report), Outcome::Deposited { held: 1 });
        assert_eq!(l.carol_holds(), 1);
        // With Bob up a hand-off changes nothing: he gets it himself.
        let m = Learned::new(0x46, CAROL_LAN, false);
        uses_friends(m.rig.a.path(), Some(true));
        m.told(vec![m.tag()], Some(0));
        m.net.net.bob_down.store(false, Ordering::SeqCst);
        m.message("direct", 10_000);
        crate::custody::hand_off(Some(m.rig.bob_pub));
        let report = m.rig.attempt_with(&m.ctx());
        assert!(
            !matches!(only(&report), Outcome::Deposited { .. }),
            "{report:?}"
        );
        assert_eq!(m.carol_dials(), 0);
    }

    #[test]
    fn w23_ack_goes_to_the_senders_announced_custodian() {
        if !lab_backends() {
            return;
        }
        let _lan = crate::lan_direct::lan_switch_untouched();
        let _g = LearnedGates::on(false, false);
        let seed = 0x49;
        let l = Learned::new(seed, CAROL_LAN, false);
        // Alice's message reached Bob; Bob owes her its ACK while she is
        // down, and she announced Carol (Alice to Bob).
        l.rig.stage_with("ack me", now_ms(), DAY, false);
        let ack = l.rig.bob_accepts(&l.rig.staged_bytes());
        let (b, alice_pub) = (l.rig.b.path(), l.rig.alice.public_key_bytes());
        let bob = Identity::from_seed(&[seed.wrapping_add(1); 32]);
        std::fs::write(
            b.join("contacts.json"),
            format!(
                r#"[{{"petname":"Alice","pub_hex":"{}","pinned":true,"lan_dial":"127.0.0.1:9"}},
                   {{"petname":"Carol","pub_hex":"{}","pinned":true,{CAROL_LAN}}}]"#,
                hex::encode(alice_pub),
                hex::encode(l.carol),
            ),
        )
        .unwrap();
        uses_friends(b, Some(true));
        let tag =
            raven_core::route_hints::custodian_tag(&alice_pub, &bob.public_key_bytes(), &l.carol);
        learned_custody(
            b,
            &[(alice_pub, vec![tag], None), (l.carol, Vec::new(), Some(0))],
        );
        let carol_id = Identity::from_seed(&[seed.wrapping_add(8); 32]);
        let net = Arc::new(ThreeNet {
            alice_bundle: local_bundle(b, &bob).unwrap(),
            alice_pub: bob.public_key_bytes(),
            nodes: vec![
                (
                    hex::encode(alice_pub),
                    l.rig.a.path().to_path_buf(),
                    Identity::from_seed(&[seed; 32]),
                ),
                (hex::encode(l.carol), l.c_dir.path().to_path_buf(), carol_id),
            ],
            bob_hex: hex::encode(alice_pub),
            bob_down: AtomicBool::new(true),
        });
        let ctx = AttemptCtx {
            data_dir: b.to_path_buf(),
            identity: Arc::new(bob),
            dialer: net,
            ..l.ctx()
        };
        let session_id = IndexedSessionStore::open(b)
            .unwrap()
            .session_id_for_record_key(&l.rig.key)
            .unwrap();
        let digest = raven_core::friend_custody::custody_digest(&ack);
        let owed = UnsentAck {
            peer: alice_pub,
            bytes: ack.clone(),
            expires_at_ms: Envelope::unpack(&ack).unwrap().expires_at,
            failures: 0,
            next_due: Instant::now(),
            durable: false,
            session_id: Some(session_id),
            held_by: Vec::new(),
            may_deposit: true,
        };
        let report = attempt_peer(&ctx, &alice_pub, &[], &[(digest, owed)]);
        assert_eq!(report.acks_failed, [digest], "still owed: pushes go on");
        assert_eq!(l.carol_holds(), 1, "left with Alice's friend");
        // Filed: the next attempt does not leave it there again.
        let (mut table, _) = raven_core::owed_acks::OwedAcks::open(b).unwrap();
        let listed = table.list(now_ms()).unwrap();
        assert_eq!(listed.len(), 1);
    }

    #[test]
    fn in_custody_reaches_outbox_item() {
        let now = Instant::now();
        let mut entry = Entry::from_row(&sched_row(7, 0xB1, now_ms() + DAY), now);
        assert_eq!(entry.item(now, now_ms()).in_custody, 0);
        apply_outcome(&mut entry, Outcome::Deposited { held: 2 }, now, now_ms());
        let item = entry.item(now, now_ms());
        assert_eq!(
            (item.in_custody, item.last_error_code.as_str()),
            (2, code::IN_CUSTODY)
        );
        let json = serde_json::to_string(&item).unwrap();
        assert!(json.contains(r#""in_custody":2"#), "{json}");
        assert!(!json.contains("custody_forwarded"), "{json}");
    }

    /// Review handoff-3: an attempt that reports its object held by a
    /// friend to pass on (custody handoff) marks the entry, and the finished
    /// item keeps it once time runs out (`custody_forwarded`: ash then says
    /// its delivery was not confirmed rather than not collected). A later
    /// `Deposited` outcome without it clears it (the holders were cleared
    /// by a re-seal).
    #[test]
    fn a_hold_to_pass_on_reaches_the_expired_item() {
        let (t0, wall) = (Instant::now(), now_ms());
        let (one, two) = (
            sched_row(8, 0xB2, wall + DAY),
            sched_row(9, 0xB2, wall + DAY),
        );
        let (peer, a, b) = (one.recipient, one.object_digest, two.object_digest);
        let mut inner = Inner::default();
        inner.merge(vec![one, two], 0, t0, wall);
        let mut report = PeerReport {
            attempted: vec![a, b],
            ..PeerReport::default()
        };
        report.outcomes.insert(a, Outcome::Deposited { held: 1 });
        report.outcomes.insert(b, Outcome::Deposited { held: 1 });
        report.custody_forwarded.insert(a);
        inner.apply(&peer, report, t0, wall);
        let item = inner.entries[&a].item(t0, wall);
        assert!(item.custody_forwarded && item.in_custody == 1, "{item:?}");
        assert!(!inner.entries[&b].item(t0, wall).custody_forwarded);
        // A ran out; B is now reported held to pass on too.
        let mut report = PeerReport {
            attempted: vec![a, b],
            ..PeerReport::default()
        };
        report.outcomes.insert(a, Outcome::Expired);
        report.outcomes.insert(b, Outcome::Deposited { held: 2 });
        report.custody_forwarded.insert(b);
        inner.apply(&peer, report, t0, wall);
        assert!(inner.entries[&b].item(t0, wall).custody_forwarded);
        let done = inner.done.iter().find(|e| e.object_digest == a).unwrap();
        let item = done.item(t0, wall);
        assert_eq!(item.state, "expired");
        assert!(item.custody_forwarded && item.in_custody == 1, "{item:?}");
        let json = serde_json::to_string(&item).unwrap();
        assert!(json.contains(r#""custody_forwarded":true"#), "{json}");
        // B held again without it.
        let mut report = PeerReport {
            attempted: vec![b],
            ..PeerReport::default()
        };
        report.outcomes.insert(b, Outcome::Deposited { held: 1 });
        inner.apply(&peer, report, t0, wall);
        assert!(!inner.entries[&b].item(t0, wall).custody_forwarded);
    }

    /// Review learning-8: an exploration probe whose carrier is still in its
    /// handshake when the probe's time runs out (a listener the kernel
    /// accepts for and that never answers) ends inside the carrier, so its
    /// hook tells learning: one LAN failure (NOT_REACHABLE) for the contact
    /// on this network, at the probe's 2 s, long before the handshake's own
    /// 30 s. Cut from outside, as before, the probe taught nothing.
    #[test]
    fn a_probe_that_runs_out_of_time_still_reaches_learning() {
        if !test_rig::lab_backends() {
            return;
        }
        let _lan = crate::lan_direct::lan_switch_untouched();
        let dir = tempfile::tempdir().unwrap();
        raven_core::load_or_create_identity(dir.path()).unwrap();
        let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let route = OutboxRoute {
            carrier: OutboxCarrier::Lan,
            dial: silent.local_addr().unwrap().to_string(),
        };
        let bob = [0xB7u8; 32];
        let mut learning = crate::learning::TestService::loaded(dir.path(), Some("home"));
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let dialer = NetDialer {
            handle: rt.handle().clone(),
        };
        let started = std::time::Instant::now();
        let err = dialer
            .probe_within(
                dir.path(),
                &route,
                &hex::encode(bob),
                Duration::from_secs(2),
            )
            .unwrap_err();
        let took = started.elapsed();
        assert!(took < Duration::from_secs(6), "{took:?}: {err}");
        assert_eq!(dial_error_code(&err), code::NOT_REACHABLE, "{err}");
        assert_eq!(learning.drain(), 1, "the probe was observed: {err}");
        let arm = learning
            .model()
            .unwrap()
            .arm(&raven_core::learning::model::ArmKey {
                contact: bob,
                net: Some("home".into()),
                carrier: OutboxCarrier::Lan,
            })
            .copied()
            .expect("the LAN arm");
        assert_eq!(arm.tries(), (0, 1), "one failure");
        drop(silent);
    }
}
