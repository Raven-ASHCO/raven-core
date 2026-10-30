//! How the last delivery to each contact travelled (any-network plan Phase 1
//! item 7), for `raven status`: in memory only (owner decision: it starts over
//! when raven-node restarts), bounded, the contact's key plus labels and when;
//! never an address.
//!
//! A dial counts only when its replies hold an ACK-type envelope from the
//! authenticated contact (a receipt; not verified here: this is a diagnostic,
//! never delivery state) and none of the frames it carried is a friend
//! custody (RFC1) request: a custody dial reaches the same carriers but is no
//! delivery to that contact.
//!
//! Beside it, why the last p2p dial to a contact could not reach it (the
//! "nobody reachable" diagnosis, [`raven_core::reach_diag`]: the reason
//! block, never an address) and when each contact was last heard from (a
//! receipt, or an authenticated link it opened to us). Both in memory and
//! bounded like the paths. A contact heard from loses its reason (it is
//! online); a network change clears every reason (evidence from the old
//! network), and a default route coming back clears the `no_route` ones.
//! A reason is served as it reads now: `heard=` aged by the reason's own
//! age, and `relay=mine<n>` naming the slot its relay (kept by PeerId) sits
//! in now, or no slot once that relay left our slots (automatic choice
//! replaced it): never another relay's owner.
//!
//! The outbox adds the local network's reasons (Phase 3, `lan_off` and
//! `lan_no_answer`, [`note_lan`]) for a contact no other carrier has a
//! route to; its next attempt keeps or drops them, and `raven lan on`
//! drops every `lan_off` one.
//!
//! Phase 6b (design A S21, R8; step P6.28): per relay, how many relayed
//! dials that carried a message went through it and how many brought a
//! receipt back ([`relayed_dial`]). A relayed dial without one, while the
//! same contact's receipt came over another path within an hour, is
//! `SEC_RELAY_NO_RECEIPT` about that relay; Suspicious when more than half
//! of its last 10 such dials went that way. Relays by PeerId only, in
//! memory, bounded, and only while the events gate is live.
//!
//! For `raven status`'s plain words about this network (Phase 3 P3.C6):
//! which contacts had an authenticated LAN link with this node lately, and
//! from where (only to tell whether that address is on one of this
//! computer's networks now: `Status` serves a count), and which contacts'
//! saved address answered with another key (M0), gone once the contact is
//! heard from or the network changes. In memory and bounded the same way.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use raven_core::arrivals::ArrivedVia;
use raven_core::envelope::{EnvType, Envelope};
use raven_core::friend_custody::is_rfc1;
use raven_core::ipc::{ContactPath, ContactWhy, OutboxItem};
use raven_core::outbox::{ack_frames, DeliveryPath};
use raven_core::reach_diag::{Diag, Why};
use raven_core::OutboxCarrier;

/// Contacts remembered; a new one beyond this drops the oldest.
const MAX_CONTACTS: usize = 256;
/// Rows `Status` lists, newest first.
pub(crate) const LIST_MAX: usize = 64;

/// Insert `value` for `contact`; a new contact beyond [`MAX_CONTACTS`] drops
/// the one with the oldest time (`at`).
fn insert_bounded<V>(
    map: &mut HashMap<[u8; 32], V>,
    contact: [u8; 32],
    value: V,
    at: impl Fn(&V) -> Instant,
) {
    if map.len() >= MAX_CONTACTS && !map.contains_key(&contact) {
        let oldest = map.iter().min_by_key(|(_, v)| at(v)).map(|(k, _)| *k);
        if let Some(oldest) = oldest {
            map.remove(&oldest);
        }
    }
    map.insert(contact, value);
}

/// The last delivery per contact key: carrier, path (when known), when.
#[derive(Default)]
struct LastPaths {
    by_contact: HashMap<[u8; 32], (OutboxCarrier, Option<DeliveryPath>, Instant)>,
}

impl LastPaths {
    fn record(
        &mut self,
        contact: [u8; 32],
        carrier: OutboxCarrier,
        path: Option<DeliveryPath>,
        at: Instant,
    ) {
        insert_bounded(&mut self.by_contact, contact, (carrier, path, at), |v| v.2);
    }

    /// Newest first, at most [`LIST_MAX`] rows, ages at `now`.
    fn list(&self, now: Instant) -> Vec<ContactPath> {
        let mut rows: Vec<_> = self.by_contact.iter().collect();
        rows.sort_by(|(ka, (_, _, a)), (kb, (_, _, b))| b.cmp(a).then(ka.cmp(kb)));
        rows.into_iter()
            .take(LIST_MAX)
            .map(|(key, (carrier, path, at))| ContactPath {
                peer_pub_hex: hex::encode(key),
                carrier: carrier.label().to_string(),
                path: path.map(|p| p.label().to_string()).unwrap_or_default(),
                age_s: now.saturating_duration_since(*at).as_secs(),
            })
            .collect()
    }
}

/// When a carrier last could not reach a contact, by (contact, carrier).
type LastFailed = HashMap<([u8; 32], OutboxCarrier), Instant>;

/// When `carrier` last could not reach each contact ([`failure_is_news`]).
static LAST_FAILED: Mutex<Option<LastFailed>> = Mutex::new(None);

/// `carrier` could not reach `contact` just now: is that news worth a log
/// line? Not when another carrier delivered to the contact since `carrier`
/// last could not reach it (E2 r9 #3: "p2p: a contact is unreachable
/// (direct_failed)" came every 30-40 s while Tor delivered to it). The
/// first failure always is (a contact that just went away: carrier matrix
/// C34), and so is every one while nothing else delivers.
pub(crate) fn failure_is_news(contact: &[u8; 32], carrier: OutboxCarrier) -> bool {
    let now = Instant::now();
    let before = {
        let mut held = LAST_FAILED.lock().unwrap_or_else(|e| e.into_inner());
        let map = held.get_or_insert_with(HashMap::new);
        if map.len() >= MAX_CONTACTS && !map.contains_key(&(*contact, carrier)) {
            map.clear();
        }
        map.insert((*contact, carrier), now)
    };
    let Some(before) = before else {
        return true;
    };
    let delivered_since = last().as_ref().is_some_and(|l| {
        l.by_contact
            .get(contact)
            .is_some_and(|(c, _, at)| *c != carrier && *at > before)
    });
    !delivered_since
}

static LAST: Mutex<Option<LastPaths>> = Mutex::new(None);

fn last() -> MutexGuard<'static, Option<LastPaths>> {
    LAST.lock().unwrap_or_else(|e| e.into_inner())
}

/// How far back `raven status` looks for contacts seen on this network and
/// for an answer from another key (P3.C6): ten minutes.
pub(crate) const HERE_SPAN: Duration = Duration::from_secs(10 * 60);
/// Contacts `Status.lan.pin_blocked` lists at most.
const PIN_BLOCKED_MAX: usize = 8;

/// Authenticated LAN links per contact (the address and when), and the
/// contacts whose saved address answered with another key (when).
#[derive(Default)]
struct Here {
    links: HashMap<[u8; 32], (IpAddr, Instant)>,
    pin: HashMap<[u8; 32], Instant>,
}

impl Here {
    fn link(&mut self, contact: [u8; 32], ip: IpAddr, at: Instant) {
        insert_bounded(&mut self.links, contact, (ip, at), |v| v.1);
    }

    fn pin_blocked(&mut self, contact: [u8; 32], at: Instant) {
        insert_bounded(&mut self.pin, contact, at, |t| *t);
    }

    /// The contact was heard from: its saved address answering with another
    /// key is no longer news.
    fn heard(&mut self, contact: &[u8; 32]) {
        self.pin.remove(contact);
    }

    /// The network changed: every pin block is the old network's.
    fn network_changed(&mut self) {
        self.pin.clear();
    }

    /// The contacts linked within [`HERE_SPAN`] of `now`, with the address.
    fn linked(&self, now: Instant) -> Vec<([u8; 32], IpAddr)> {
        self.links
            .iter()
            .filter(|(_, (_, at))| now.saturating_duration_since(*at) <= HERE_SPAN)
            .map(|(key, (ip, _))| (*key, *ip))
            .collect()
    }

    /// The pin blocks within [`HERE_SPAN`] of `now`, newest first, at most
    /// [`PIN_BLOCKED_MAX`] (hex keys).
    fn pin_list(&self, now: Instant) -> Vec<String> {
        let mut rows: Vec<_> = self
            .pin
            .iter()
            .filter(|(_, at)| now.saturating_duration_since(**at) <= HERE_SPAN)
            .collect();
        rows.sort_by(|(ka, a), (kb, b)| b.cmp(a).then(ka.cmp(kb)));
        rows.into_iter()
            .take(PIN_BLOCKED_MAX)
            .map(|(key, _)| hex::encode(key))
            .collect()
    }
}

static HERE: Mutex<Option<Here>> = Mutex::new(None);

fn with_here<T>(f: impl FnOnce(&mut Here) -> T) -> T {
    f(HERE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get_or_insert_with(Here::default))
}

/// An authenticated LAN link with `contact`, whose end is at `ip` (it
/// opened one to us, or our dial reached it).
pub(crate) fn lan_link(contact: &[u8; 32], ip: IpAddr) {
    with_here(|h| h.link(*contact, ip, Instant::now()));
}

/// `contact` told new routes over another carrier than the LAN: it moved
/// (E2 r40: a friend gone to another network still had its LAN sighting,
/// and the next send gave the LAN and p2p a head start over Tor).
pub(crate) fn forget_lan_sighting(contact: &[u8; 32]) {
    with_here(|h| {
        h.links.remove(contact);
    });
}

/// The contacts with an authenticated LAN link in the last [`HERE_SPAN`],
/// and the address each link came from or went to (P3.C6: the caller keeps
/// those on this computer's networks now, and serves a count).
#[cfg_attr(not(any(unix, windows)), allow(dead_code))]
pub(crate) fn lan_linked_lately() -> Vec<([u8; 32], IpAddr)> {
    with_here(|h| h.linked(Instant::now()))
}

/// Whether `contact` had an authenticated LAN link within [`HERE_SPAN`]
/// (the outbox tries it again sooner, E1).
pub(crate) fn lan_linked_within_span(contact: &[u8; 32]) -> bool {
    with_here(|h| {
        h.links
            .get(contact)
            .is_some_and(|(_, at)| Instant::now().saturating_duration_since(*at) <= HERE_SPAN)
    })
}

/// How long ago `contact` last had an authenticated LAN link with this node,
/// while that is remembered (E2 r9: `raven send` gives the LAN no head
/// start over Tor for a friend not seen on the LAN lately), and only while
/// that link's address is on one of this computer's networks now (links
/// are checked by address, P3.C6; E2 r40: after a network change the old
/// sighting still gave the LAN and p2p a head start over Tor).
pub(crate) fn lan_seen_age(contact: &[u8; 32]) -> Option<Duration> {
    lan_seen_age_with(contact, on_our_link)
}

/// [`lan_seen_age`] with "is this address on this computer's networks now"
/// passed in.
fn lan_seen_age_with(contact: &[u8; 32], here: impl Fn(IpAddr) -> bool) -> Option<Duration> {
    let (ip, at) = with_here(|h| h.links.get(contact).copied())?;
    (ip.is_loopback() || here(ip)).then(|| Instant::now().saturating_duration_since(at))
}

/// `ip` is on one of this computer's networks now (the LAN beacon's own
/// test).
fn on_our_link(ip: IpAddr) -> bool {
    #[cfg(any(unix, windows))]
    {
        crate::lan_ifaces::on_link(ip)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = ip;
        false
    }
}

/// The outbox found another key at one of `contact`'s saved addresses (M0,
/// a noise pin mismatch) on this network.
pub(crate) fn pin_blocked(contact: &[u8; 32]) {
    with_here(|h| h.pin_blocked(*contact, Instant::now()));
}

/// The rows for IPC `Status` (`lan.pin_blocked`): contacts whose address
/// answered with another key in the last [`HERE_SPAN`], newest first.
#[cfg_attr(not(any(unix, windows)), allow(dead_code))]
pub(crate) fn pin_blocked_snapshot() -> Vec<String> {
    with_here(|h| h.pin_list(Instant::now()))
}

/// Did this dial deliver to the contact: it carried a message of ours (a
/// chat message or a group copy), no custody (RFC1) frame, and a receipt
/// (ACK-type envelope) came back? A dial that carried no message (an
/// announce link, a probe, our receipts only) proves nothing about how our
/// messages travel, though the contact may hand its owed receipts over on
/// it (E2 r38: LAST DELIVERY said "direct over the internet" after a group
/// send that went over the LAN).
fn delivered(frames: &[Vec<u8>], replies: &[Vec<u8>]) -> bool {
    let carried_a_message = frames
        .iter()
        .any(|f| Envelope::unpack(f).is_some_and(|env| env.env_type == EnvType::Message as u8));
    carried_a_message && !frames.iter().any(|f| is_rfc1(f)) && !ack_frames(replies).is_empty()
}

/// A dial to `contact` over `carrier` returned `replies` for `frames`:
/// remembered as that contact's last delivery when it [`delivered`].
pub(crate) fn note(
    contact: &[u8; 32],
    carrier: OutboxCarrier,
    path: Option<DeliveryPath>,
    frames: &[Vec<u8>],
    replies: &[Vec<u8>],
) {
    if delivered(frames, replies) {
        last().get_or_insert_with(LastPaths::default).record(
            *contact,
            carrier,
            path,
            Instant::now(),
        );
        note_delivered_messages(frames, carrier, path);
        // A receipt: the contact is online, its reason is stale, and the
        // carrier that brought it works.
        heard(contact);
        carrier_worked(contact, carrier);
        // A receipt not through a relay (a relayed one is
        // [`relayed_dial`]'s, which knows the relay).
        if path != Some(DeliveryPath::Relayed) && events_live() {
            let lost = with_relays(|w| w.receipt(*contact, None, Instant::now()));
            note_lost(lost);
        }
    }
}

/// Our own messages a receipt confirmed, kept (the newest).
const DELIVERED_MAX: usize = 1024;

/// Our own messages a receipt confirmed since raven-node started, oldest
/// first: message id, how it went, when (wall clock). For the terminal
/// app's chat (field test E3: it showed the path of some of your messages
/// only, those its own send or the outbox delivered). In memory, bounded;
/// never an address.
static DELIVERED: Mutex<VecDeque<([u8; 16], ArrivedVia, u64)>> = Mutex::new(VecDeque::new());

/// The messages a dial that brought a receipt carried ([`delivered`]): how
/// each went, `carrier` and, for p2p, `path`.
fn note_delivered_messages(frames: &[Vec<u8>], carrier: OutboxCarrier, path: Option<DeliveryPath>) {
    let via = if path == Some(DeliveryPath::Relayed) {
        ArrivedVia::Relayed
    } else {
        ArrivedVia::of_carrier(carrier)
    };
    let at = raven_core::clock::now_ms();
    let mut kept = DELIVERED.lock().unwrap_or_else(|e| e.into_inner());
    for env in frames
        .iter()
        .filter_map(|f| Envelope::unpack(f))
        .filter(|env| env.env_type == EnvType::Message as u8)
    {
        kept.retain(|(id, _, _)| *id != env.message_id);
        if kept.len() >= DELIVERED_MAX {
            kept.pop_front();
        }
        kept.push_back((env.message_id, via, at));
    }
}

/// [`DELIVERED`], oldest first.
pub(crate) fn delivered_messages() -> Vec<([u8; 16], ArrivedVia, u64)> {
    DELIVERED
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .copied()
        .collect()
}

// ── Relays (Phase 6b design A S21, R8; step P6.28) ─────────────────────────

/// The relayed dials remembered per relay: the share of them that lost
/// their receipt decides SEC_RELAY_NO_RECEIPT's level.
const RELAY_WINDOW: usize = 10;
/// A relayed dial that brought no receipt counts against its relay when the
/// same contact's receipt came over another path this close to it (before
/// or after).
pub(crate) const RELAY_RECEIPT_SPAN: Duration = Duration::from_secs(60 * 60);
/// Relays remembered; a new one beyond this drops the one used longest ago.
const MAX_RELAYS: usize = 64;
/// Receipts remembered per contact (one per path: none or a relay).
const RECEIPT_PATHS: usize = 4;

/// What became of one relayed dial that carried a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RelayDialOutcome {
    Receipt,
    /// No receipt, and none over another path yet.
    Waiting,
    /// No receipt, while one came over another path within the span.
    Lost,
}

#[derive(Clone, Copy, Debug)]
struct RelayDial {
    contact: [u8; 32],
    at: Instant,
    outcome: RelayDialOutcome,
}

/// One relay's counters and its last [`RELAY_WINDOW`] relayed dials.
#[derive(Debug)]
struct RelayRow {
    dials: u64,
    receipts: u64,
    recent: VecDeque<RelayDial>,
    used: Instant,
}

impl RelayRow {
    /// More than half of its last [`RELAY_WINDOW`] dials lost their receipt.
    fn suspicious(&self) -> bool {
        let lost = self
            .recent
            .iter()
            .filter(|d| d.outcome == RelayDialOutcome::Lost)
            .count();
        lost * 2 > RELAY_WINDOW
    }
}

/// SEC_RELAY_NO_RECEIPT to note: the relay (PeerId bytes) and whether it is
/// Suspicious.
type Lost = Vec<(Vec<u8>, bool)>;

/// One contact's latest receipts: by path (`None`: not through a relay;
/// else the relay's PeerId bytes), when.
type Receipts = Vec<(Option<Vec<u8>>, Instant)>;

/// The relays' rows, and each contact's latest receipts.
#[derive(Default)]
struct RelayWatch {
    relays: HashMap<Vec<u8>, RelayRow>,
    receipts: HashMap<[u8; 32], Receipts>,
}

impl RelayWatch {
    /// A relayed dial through `relay` to `contact` that carried a message,
    /// at `now`; `receipt`: it brought one back.
    fn dial(&mut self, contact: [u8; 32], relay: &[u8], receipt: bool, now: Instant) -> Lost {
        let elsewhere = !receipt && self.receipt_elsewhere(&contact, relay, now);
        if self.relays.len() >= MAX_RELAYS && !self.relays.contains_key(relay) {
            let oldest = self
                .relays
                .iter()
                .min_by_key(|(_, r)| r.used)
                .map(|(k, _)| k.clone());
            if let Some(oldest) = oldest {
                self.relays.remove(&oldest);
            }
        }
        let row = self.relays.entry(relay.to_vec()).or_insert(RelayRow {
            dials: 0,
            receipts: 0,
            recent: VecDeque::new(),
            used: now,
        });
        row.dials = row.dials.saturating_add(1);
        row.used = now;
        let outcome = if receipt {
            row.receipts = row.receipts.saturating_add(1);
            RelayDialOutcome::Receipt
        } else if elsewhere {
            RelayDialOutcome::Lost
        } else {
            RelayDialOutcome::Waiting
        };
        if row.recent.len() >= RELAY_WINDOW {
            row.recent.pop_front();
        }
        row.recent.push_back(RelayDial {
            contact,
            at: now,
            outcome,
        });
        let mut lost = Lost::new();
        if outcome == RelayDialOutcome::Lost {
            lost.push((relay.to_vec(), row.suspicious()));
        }
        if receipt {
            lost.extend(self.receipt(contact, Some(relay), now));
        }
        lost
    }

    /// `contact`'s receipt came at `now` over `path` (`None`: not through a
    /// relay): the dials through other relays that brought it none within
    /// the span lost theirs.
    fn receipt(&mut self, contact: [u8; 32], path: Option<&[u8]>, now: Instant) -> Lost {
        if self.receipts.len() >= MAX_CONTACTS && !self.receipts.contains_key(&contact) {
            let oldest = self
                .receipts
                .iter()
                .min_by_key(|(_, v)| v.iter().map(|(_, at)| *at).max())
                .map(|(k, _)| *k);
            if let Some(oldest) = oldest {
                self.receipts.remove(&oldest);
            }
        }
        let paths = self.receipts.entry(contact).or_default();
        paths.retain(|(p, _)| p.as_deref() != path);
        if paths.len() >= RECEIPT_PATHS {
            paths.remove(0);
        }
        paths.push((path.map(<[u8]>::to_vec), now));
        let mut lost = Lost::new();
        for (relay, row) in &mut self.relays {
            if path == Some(relay.as_slice()) {
                continue;
            }
            let mut marked = 0;
            for d in &mut row.recent {
                if d.contact == contact
                    && d.outcome == RelayDialOutcome::Waiting
                    && now.saturating_duration_since(d.at) <= RELAY_RECEIPT_SPAN
                {
                    d.outcome = RelayDialOutcome::Lost;
                    marked += 1;
                }
            }
            for _ in 0..marked {
                lost.push((relay.clone(), row.suspicious()));
            }
        }
        lost
    }

    /// Did `contact`'s receipt come over a path other than `relay` within
    /// the span before `now`?
    fn receipt_elsewhere(&self, contact: &[u8; 32], relay: &[u8], now: Instant) -> bool {
        self.receipts.get(contact).is_some_and(|paths| {
            paths.iter().any(|(p, at)| {
                p.as_deref() != Some(relay)
                    && now.saturating_duration_since(*at) <= RELAY_RECEIPT_SPAN
            })
        })
    }

    /// `relay`'s (dials, receipts).
    fn counts(&self, relay: &[u8]) -> Option<(u64, u64)> {
        self.relays.get(relay).map(|r| (r.dials, r.receipts))
    }
}

static RELAYS: Mutex<Option<RelayWatch>> = Mutex::new(None);

fn with_relays<T>(f: impl FnOnce(&mut RelayWatch) -> T) -> T {
    f(RELAYS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get_or_insert_with(RelayWatch::default))
}

fn events_live() -> bool {
    raven_core::security_gate::live(raven_core::security_gate::SecGate::Events)
}

/// Note what lost its receipt (outside the watch's lock).
fn note_lost(lost: Lost) {
    for (relay, suspicious) in lost {
        crate::security::relay_no_receipt(&relay, suspicious);
    }
}

/// Does a dial that carried `frames` want a receipt back: a message among
/// them, and no custody (RFC1) frame (a custody dial is no delivery)?
fn wants_receipt(frames: &[Vec<u8>]) -> bool {
    !frames.iter().any(|f| is_rfc1(f))
        && frames
            .iter()
            .any(|f| Envelope::unpack(f).is_some_and(|env| env.env_type == EnvType::Message as u8))
}

/// A p2p dial to `contact` whose link went through a relay: `relays` the
/// relays of its relayed connections (PeerId bytes), `frames` what it
/// carried, `replies` what came back (`None`: it failed after the link
/// opened). Counted when it carried a message and one relay carried it
/// (with two, neither is blamed), while the events gate is live.
pub(crate) fn relayed_dial(
    contact: &[u8; 32],
    relays: &[Vec<u8>],
    frames: &[Vec<u8>],
    replies: Option<&[Vec<u8>]>,
) {
    let [relay] = relays else {
        return;
    };
    if !events_live() || !wants_receipt(frames) {
        return;
    }
    let receipt = replies.is_some_and(|r| !ack_frames(r).is_empty());
    let lost = with_relays(|w| w.dial(*contact, relay, receipt, Instant::now()));
    note_lost(lost);
}

/// `relay`'s counters since raven-node started: (relayed dials that carried
/// a message, those that brought a receipt). For `raven status` (P6.30).
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn relay_counts(relay: &[u8]) -> Option<(u64, u64)> {
    with_relays(|w| w.counts(relay))
}

/// The rows for IPC `Status` (`last_paths`), newest first.
#[cfg_attr(not(any(unix, windows)), allow(dead_code))]
pub(crate) fn snapshot() -> Vec<ContactPath> {
    last()
        .as_ref()
        .map(|l| l.list(Instant::now()))
        .unwrap_or_default()
}

/// One remembered reason: the diagnosis, when, and the relay (its PeerId)
/// that sat in the slot its `relay=mine<n>` names when it was made.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Noted {
    d: Diag,
    at: Instant,
    relay: Option<String>,
}

impl Noted {
    /// The reason as it reads at `now`, with `slots` the relays (PeerIds)
    /// of our slots now, in `Status` order: `heard=` aged by the reason's
    /// age; `relay=` the slot its relay sits in now, none once it left.
    fn current(&self, now: Instant, slots: &[Option<String>]) -> Diag {
        let age = now.saturating_duration_since(self.at).as_secs();
        let mut d = self.d.clone();
        d.heard_s = d.heard_s.map(|s| s.saturating_add(age));
        if d.relay.is_some() {
            d.relay = self
                .relay
                .as_deref()
                .and_then(|r| slots.iter().position(|s| s.as_deref() == Some(r)))
                .and_then(|i| u8::try_from(i + 1).ok())
                .filter(|slot| matches!(slot, 1 | 2));
        }
        d
    }
}

/// Why the last p2p dial to each contact failed, and when each contact was
/// last heard from (any carrier).
#[derive(Default)]
struct Reasons {
    why: HashMap<[u8; 32], Noted>,
    heard: HashMap<[u8; 32], Instant>,
    /// The last network change ([`Reasons::network_changed`]).
    changed_at: Option<Instant>,
}

impl Reasons {
    /// `relay`: the PeerId of the relay in the slot `d.relay` names.
    fn note(&mut self, contact: [u8; 32], d: Diag, relay: Option<String>, at: Instant) {
        insert_bounded(&mut self.why, contact, Noted { d, at, relay }, |v| v.at);
    }

    /// [`Reasons::note`] for a dial that began at `since` and whose reason
    /// was decided after it returned: kept only if nothing newer is known
    /// (no reason noted since, the contact not heard from since, the
    /// network unchanged since). Whether it was kept.
    fn note_after(
        &mut self,
        contact: [u8; 32],
        d: Diag,
        relay: Option<String>,
        since: Instant,
        at: Instant,
    ) -> bool {
        let newer = self.why.get(&contact).is_some_and(|n| n.at >= since)
            || self.heard.get(&contact).is_some_and(|h| *h >= since)
            || self.changed_at.is_some_and(|c| c >= since);
        if !newer {
            self.note(contact, d, relay, at);
        }
        !newer
    }

    /// The contact was heard from at `at`: online, so its reason goes.
    fn heard(&mut self, contact: [u8; 32], at: Instant) {
        insert_bounded(&mut self.heard, contact, at, |t| *t);
        self.why.remove(&contact);
    }

    fn heard_age(&self, contact: &[u8; 32], now: Instant) -> Option<Duration> {
        self.heard
            .get(contact)
            .map(|at| now.saturating_duration_since(*at))
    }

    /// The reason as it was noted, and its age.
    #[cfg(test)]
    fn why_for(&self, contact: &[u8; 32], now: Instant) -> Option<(Diag, Duration)> {
        self.why
            .get(contact)
            .map(|n| (n.d.clone(), now.saturating_duration_since(n.at)))
    }

    /// The reason as it reads now ([`Noted::current`]), and its age.
    fn current_for(
        &self,
        contact: &[u8; 32],
        now: Instant,
        slots: &[Option<String>],
    ) -> Option<(Diag, Duration)> {
        self.why
            .get(contact)
            .map(|n| (n.current(now, slots), now.saturating_duration_since(n.at)))
    }

    /// Newest first, at most [`LIST_MAX`] rows, ages at `now`, each reason
    /// as it reads now ([`Noted::current`]).
    fn list(&self, now: Instant, slots: &[Option<String>]) -> Vec<ContactWhy> {
        let mut rows: Vec<_> = self.why.iter().collect();
        rows.sort_by(|(ka, a), (kb, b)| b.at.cmp(&a.at).then(ka.cmp(kb)));
        rows.into_iter()
            .take(LIST_MAX)
            .map(|(key, n)| ContactWhy {
                peer_pub_hex: hex::encode(key),
                reason: n.current(now, slots).render(),
                age_s: now.saturating_duration_since(n.at).as_secs(),
            })
            .collect()
    }

    /// The network changed: every reason is evidence from the old one.
    fn network_changed(&mut self) {
        self.why.clear();
        self.changed_at = Some(Instant::now());
    }

    /// A default route is back: a `no_route` reason no longer holds.
    fn route_back(&mut self) {
        self.why.retain(|_, n| n.d.why != Why::NoRoute);
    }

    /// The outbox's last attempt for `contact`: the local network's reason
    /// (`Some`), or none any more (a p2p reason is left alone).
    fn note_lan(&mut self, contact: [u8; 32], d: Option<Diag>, at: Instant) {
        match d {
            Some(d) => self.note(contact, d, None, at),
            None => {
                if self.why.get(&contact).is_some_and(|n| n.d.why.is_lan()) {
                    self.why.remove(&contact);
                }
            }
        }
    }

    /// `raven lan on`: a `lan_off` reason no longer holds.
    fn lan_back(&mut self) {
        self.why.retain(|_, n| n.d.why != Why::LanOff);
    }
}

static REASONS: Mutex<Option<Reasons>> = Mutex::new(None);

fn with_reasons<T>(f: impl FnOnce(&mut Reasons) -> T) -> T {
    f(REASONS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get_or_insert_with(Reasons::default))
}

/// The last p2p dial to `contact` could not reach it, for reason `d`
/// (raven-node's p2p dial, `explain_unreachable`); `relay`: the PeerId of
/// the relay in the slot `d.relay` names.
pub(crate) fn note_unreachable(contact: &[u8; 32], d: &Diag, relay: Option<String>) {
    with_reasons(|r| r.note(*contact, d.clone(), relay, Instant::now()));
}

/// [`note_unreachable`] for a dial that began at `since` whose reason was
/// decided after it returned (`p2p` waited for a relay's answer): kept only
/// if nothing newer is known of the contact. Whether it was kept.
pub(crate) fn note_unreachable_after(
    contact: &[u8; 32],
    d: &Diag,
    relay: Option<String>,
    since: Instant,
) -> bool {
    with_reasons(|r| r.note_after(*contact, d.clone(), relay, since, Instant::now()))
}

/// `contact` was heard from now: a receipt came back, or it opened an
/// authenticated link to this node. Its reason is gone, and the LAN beacon
/// starts its query interval for it over (RAVEN_LAN_BEACON_V1 §8). Its
/// failed routes stay, route by route (E2 r40: one route answering said
/// nothing about another; each route is cleared by its own answer).
pub(crate) fn heard(contact: &[u8; 32]) {
    with_reasons(|r| r.heard(*contact, Instant::now()));
    with_here(|h| h.heard(contact));
    #[cfg(any(unix, windows))]
    crate::lan_beacon::linked(contact);
}

/// How long ago `contact` was last heard from, since raven-node started.
pub(crate) fn heard_age(contact: &[u8; 32]) -> Option<Duration> {
    with_reasons(|r| r.heard_age(contact, Instant::now()))
}

/// `contact`'s reason as it was noted, and how old it is (tests: what a
/// dial noted).
#[cfg(test)]
pub(crate) fn why_for(contact: &[u8; 32]) -> Option<(Diag, Duration)> {
    with_reasons(|r| r.why_for(contact, Instant::now()))
}

/// The rows for IPC `Status` (`unreachable`), newest first, each reason as
/// it reads now against our relay slots now ([`crate::p2p::slot_relay_ids`]).
#[cfg_attr(not(any(unix, windows)), allow(dead_code))]
pub(crate) fn unreachable_snapshot() -> Vec<ContactWhy> {
    let slots = crate::p2p::slot_relay_ids();
    with_reasons(|r| r.list(Instant::now(), &slots))
}

/// netwatch: the network changed; every reason goes.
#[cfg_attr(not(any(unix, windows)), allow(dead_code))]
pub(crate) fn network_changed() {
    with_reasons(Reasons::network_changed);
    with_here(Here::network_changed);
    with_fails(RouteFails::clear);
    with_tor_reached(TorReached::clear);
}

// ── Failed routes (E2 r9 #2) ───────────────────────────────────────────────

/// A failed route stays news this long: a `raven send` to a contact whose
/// every route failed within it queues at once instead of dialling them all
/// again (E2 r9: each of 10 sends to an unreachable friend waited 13 s).
pub(crate) const ROUTE_FAIL_FRESH: Duration = Duration::from_secs(120);
/// Routes remembered per contact (the newest).
const FAILED_ROUTES_MAX: usize = 8;

/// A send's Tor dial that failed this fast, Tor saying the friend's onion
/// service could not be reached, is a miss, not a sign that Tor cannot reach
/// the friend: the first one on a route is not news to the next send (field
/// test E3 round 2: a check that failed after 5.2 s made the next send, 5 s
/// later, queue without a dial, while the outbox's Tor dial seconds later
/// worked). A second one, or a slower one, is.
pub(crate) const ONION_SHORT_MISS: Duration = Duration::from_secs(12);

/// One route's last failed dial.
#[derive(Clone, Debug)]
struct FailedRoute {
    carrier: OutboxCarrier,
    dial: String,
    at: Instant,
    error: String,
    /// The route's only fresh failure, a short Tor miss
    /// ([`ONION_SHORT_MISS`]): kept, but no reason to leave Tor out.
    short_miss: bool,
}

/// Per contact, its routes whose last dial (a `raven send`'s, through IPC)
/// failed, newest last; dropped when the contact answers or is heard from,
/// and when the network changes. In memory, bounded; never logged (the
/// dial strings go to the local client only).
#[derive(Default)]
struct RouteFails {
    by: HashMap<[u8; 32], (Instant, Vec<FailedRoute>)>,
}

impl RouteFails {
    fn failed(&mut self, contact: [u8; 32], mut route: FailedRoute) {
        let at = route.at;
        let mut routes = self.by.remove(&contact).map(|(_, r)| r).unwrap_or_default();
        // A short Tor miss right after another failure of that route is a
        // second failure: news.
        let again = routes.iter().any(|r| {
            r.carrier == route.carrier
                && r.dial == route.dial
                && at.saturating_duration_since(r.at) <= ROUTE_FAIL_FRESH
        });
        route.short_miss &= !again;
        routes.retain(|r| !(r.carrier == route.carrier && r.dial == route.dial));
        routes.push(route);
        if routes.len() > FAILED_ROUTES_MAX {
            routes.remove(0);
        }
        insert_bounded(&mut self.by, contact, (at, routes), |v| v.0);
    }

    fn answered(&mut self, contact: &[u8; 32]) {
        self.by.remove(contact);
    }

    /// Forget `contact`'s failed routes on `carrier` (`dial`: only that
    /// one).
    fn answered_on(&mut self, contact: &[u8; 32], carrier: OutboxCarrier, dial: Option<&str>) {
        if let Some((_, routes)) = self.by.get_mut(contact) {
            routes.retain(|r| r.carrier != carrier || dial.is_some_and(|d| r.dial != d.trim()));
            if routes.is_empty() {
                self.by.remove(contact);
            }
        }
    }

    /// Forget every contact's failed routes on `carrier`.
    fn carrier_back(&mut self, carrier: OutboxCarrier) {
        for (_, routes) in self.by.values_mut() {
            routes.retain(|r| r.carrier != carrier);
        }
        self.by.retain(|_, (_, routes)| !routes.is_empty());
    }

    fn clear(&mut self) {
        self.by.clear();
    }

    /// `contact`'s failed routes within [`ROUTE_FAIL_FRESH`] of `now`.
    fn fresh(&self, contact: &[u8; 32], now: Instant) -> Vec<FreshFailure> {
        self.by
            .get(contact)
            .map(|(_, routes)| {
                routes
                    .iter()
                    .filter(|r| now.saturating_duration_since(r.at) <= ROUTE_FAIL_FRESH)
                    .map(|r| FreshFailure {
                        carrier: r.carrier.label().into(),
                        dial: r.dial.clone(),
                        age_s: now.saturating_duration_since(r.at).as_secs(),
                        error: r.error.clone(),
                        short_miss: r.short_miss,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

static FAILS: Mutex<Option<RouteFails>> = Mutex::new(None);

fn with_fails<T>(f: impl FnOnce(&mut RouteFails) -> T) -> T {
    f(FAILS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get_or_insert_with(RouteFails::default))
}

/// A send's dial (IPC) to `contact` over `carrier` at `dial` failed with
/// `error`.
pub(crate) fn route_failed(contact: &[u8; 32], carrier: OutboxCarrier, dial: &str, error: &str) {
    route_failed_after(contact, carrier, dial, error, Duration::MAX);
}

/// [`route_failed`] for a dial that ended after `took`: a Tor one that
/// failed within [`ONION_SHORT_MISS`], Tor saying the friend's onion
/// service could not be reached, is a short miss.
pub(crate) fn route_failed_after(
    contact: &[u8; 32],
    carrier: OutboxCarrier,
    dial: &str,
    error: &str,
    took: Duration,
) {
    let short_miss = carrier == OutboxCarrier::Onion
        && took < ONION_SHORT_MISS
        && crate::outbox::dial_error_code(error) == crate::outbox::code::ONION_UNREACHABLE;
    let route = FailedRoute {
        carrier,
        dial: dial.trim().to_string(),
        at: Instant::now(),
        error: error.chars().take(300).collect(),
        short_miss,
    };
    with_fails(|f| f.failed(*contact, route));
}

/// A send's dial to `contact` at `dial` over `carrier` answered: that
/// route's failure is news no more (E2 r40: a Tor answer cleared the LAN's
/// too, so the next send dialled the LAN again); a Tor answer is Tor
/// reaching the friend ([`tor_tried_lately`]).
pub(crate) fn route_answered(contact: &[u8; 32], carrier: OutboxCarrier, dial: &str) {
    with_fails(|f| f.answered_on(contact, carrier, Some(dial)));
    if carrier == OutboxCarrier::Onion {
        with_tor_reached(|r| r.reached(*contact, Instant::now()));
    }
}

/// A link with `contact` over `carrier` worked (in either direction): every
/// failed route of `contact` on that carrier is news no more (E2 r40: any
/// Tor link to the friend clears Tor's mark), and a Tor one is remembered
/// as Tor reaching the friend ([`tor_tried_lately`]).
pub(crate) fn carrier_worked(contact: &[u8; 32], carrier: OutboxCarrier) {
    with_fails(|f| f.answered_on(contact, carrier, None));
    if carrier == OutboxCarrier::Onion {
        with_tor_reached(|r| r.reached(*contact, Instant::now()));
    }
}

/// Our own Tor self-check reached our onion service: Tor works here, so no
/// friend's Tor route is remembered as failed (E2 r40).
pub(crate) fn tor_works_here() {
    with_fails(|f| f.carrier_back(OutboxCarrier::Onion));
}

/// Every route of `carriers` other than Tor failed for `contact` within
/// [`ROUTE_FAIL_FRESH`] (a send just tried them, or skipped them for that):
/// the outbox's next attempt starts Tor at once instead of after the direct
/// paths' head start (E2 r40: "the background retry should try Tor first,
/// promptly"). False when there is no direct route among them.
pub(crate) fn direct_routes_failed_lately(contact: &[u8; 32], carriers: &[OutboxCarrier]) -> bool {
    let fresh = failed_routes(contact);
    let mut direct = carriers
        .iter()
        .filter(|c| **c != OutboxCarrier::Onion)
        .peekable();
    direct.peek().is_some() && direct.all(|c| fresh.iter().any(|f| f.carrier == c.label()))
}

/// Tor dials to each contact running now (a send's or the outbox's).
static ONION_DIALS: Mutex<Option<HashMap<[u8; 32], u32>>> = Mutex::new(None);

fn with_onion_dials<T>(f: impl FnOnce(&mut HashMap<[u8; 32], u32>) -> T) -> T {
    f(ONION_DIALS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get_or_insert_with(HashMap::new))
}

/// A Tor dial to a contact, counted while it lives ([`onion_dial_started`]).
pub(crate) struct OnionDialMark([u8; 32]);

impl Drop for OnionDialMark {
    fn drop(&mut self) {
        with_onion_dials(|d| {
            if let Some(n) = d.get_mut(&self.0) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    d.remove(&self.0);
                }
            }
        });
    }
}

/// A Tor dial to `contact` starts; it counts as running until the mark
/// drops.
pub(crate) fn onion_dial_started(contact: &[u8; 32]) -> OnionDialMark {
    with_onion_dials(|d| *d.entry(*contact).or_insert(0) += 1);
    OnionDialMark(*contact)
}

/// Whether Tor is busy with `contact` without having reached it: its Tor
/// route failed within [`ROUTE_FAIL_FRESH`] (a Tor link that worked since
/// cleared that), or a Tor dial to it runs now while no Tor link with it
/// worked within [`ROUTE_FAIL_FRESH`] (E2 r40: a send then need not wait for
/// Tor again while the outbox carries a message to it, Tor first).
///
/// A running dial alone is no sign that Tor cannot reach the friend: the
/// outbox, a keeper's check or the friend's own messages keep Tor dials to
/// a friend Tor reaches every few seconds (field test E3: three sends right
/// after seven delivered over Tor, while the friend was writing to us, were
/// queued at once without a dial).
pub(crate) fn tor_tried_lately(contact: &[u8; 32]) -> bool {
    let failed = failed_routes(contact)
        .iter()
        .any(|f| f.carrier == OutboxCarrier::Onion.label() && !f.short_miss);
    failed
        || (with_onion_dials(|d| d.contains_key(contact))
            && !with_tor_reached(|r| r.within(contact, Instant::now(), ROUTE_FAIL_FRESH)))
}

/// When a Tor link with each contact last worked (a delivery over Tor, a
/// message that came over Tor): in memory, bounded like the failed routes,
/// cleared when the network changes.
#[derive(Default)]
struct TorReached {
    by: HashMap<[u8; 32], Instant>,
}

impl TorReached {
    fn reached(&mut self, contact: [u8; 32], at: Instant) {
        insert_bounded(&mut self.by, contact, at, |at| *at);
    }

    /// A Tor link with `contact` worked within `span` of `now`.
    fn within(&self, contact: &[u8; 32], now: Instant, span: Duration) -> bool {
        self.by
            .get(contact)
            .is_some_and(|at| now.saturating_duration_since(*at) <= span)
    }

    fn clear(&mut self) {
        self.by.clear();
    }
}

static TOR_REACHED: Mutex<Option<TorReached>> = Mutex::new(None);

fn with_tor_reached<T>(f: impl FnOnce(&mut TorReached) -> T) -> T {
    f(TOR_REACHED
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get_or_insert_with(TorReached::default))
}

/// `raven learning reset` (IPC `LearningReset`): what a send knows of failed
/// routes goes with what was learned, for `contact` or (`None`) everyone, so
/// the next send tries every route again.
pub(crate) fn forget_failed_routes(contact: Option<&[u8; 32]>) {
    with_fails(|f| match contact {
        Some(c) => f.answered(c),
        None => f.clear(),
    });
}

/// One of a contact's failed routes, as this process keeps it (its dial
/// never leaves it: [`reach_failures`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FreshFailure {
    pub(crate) carrier: String,
    pub(crate) dial: String,
    pub(crate) age_s: u64,
    pub(crate) error: String,
    /// A single short Tor miss ([`ONION_SHORT_MISS`]).
    pub(crate) short_miss: bool,
}

/// `contact`'s routes whose last dial failed within [`ROUTE_FAIL_FRESH`],
/// with no sign of the contact since.
pub(crate) fn failed_routes(contact: &[u8; 32]) -> Vec<FreshFailure> {
    with_fails(|f| f.fresh(contact, Instant::now()))
}

/// IPC `ContactReach`: `contact`'s failed routes among `routes` (the
/// send's, in its order), each named by its index there and its error
/// without any address. A failure on a route the send did not name is left
/// out.
pub(crate) fn reach_failures(
    contact: &[u8; 32],
    routes: &[raven_core::ipc::ReachRoute],
) -> Vec<raven_core::ipc::RouteFailure> {
    failures_by_index(failed_routes(contact), routes)
}

fn failures_by_index(
    fresh: Vec<FreshFailure>,
    routes: &[raven_core::ipc::ReachRoute],
) -> Vec<raven_core::ipc::RouteFailure> {
    fresh
        .into_iter()
        // A single short Tor miss is no reason for a send to leave Tor out.
        .filter(|f| !f.short_miss)
        .filter_map(|f| {
            let i = routes
                .iter()
                .position(|r| r.carrier == f.carrier && r.dial.trim() == f.dial)?;
            Some(raven_core::ipc::RouteFailure {
                carrier: f.carrier,
                route: u32::try_from(i).ok()?,
                age_s: f.age_s,
                error: raven_core::ipc::without_addresses(&f.error),
            })
        })
        .collect()
}

/// netwatch: the default route is back; the `no_route` reasons go.
#[cfg_attr(not(any(unix, windows)), allow(dead_code))]
pub(crate) fn route_back() {
    with_reasons(Reasons::route_back);
}

/// The outbox's attempt for `contact` left a message waiting: why the local
/// network could not carry it (`Some`: `lan_off` or `lan_no_answer`,
/// [`raven_core::reach_diag::diagnose_lan`]), or `None`: LAN is not why
/// (any earlier local network reason goes; a p2p one stays).
pub(crate) fn note_lan(contact: &[u8; 32], d: Option<Diag>) {
    with_reasons(|r| r.note_lan(*contact, d, Instant::now()));
}

/// `raven lan on` (IPC `SetLan`): the `lan_off` reasons go.
pub(crate) fn lan_back() {
    with_reasons(Reasons::lan_back);
}

/// For `OutboxList` / `OutboxStatus`: a live p2p object that failed as
/// NOT_REACHABLE carries its contact's reason (`why`) as it reads now, with
/// its age (`asof=`: it is a remembered check, not a current one); a live
/// object of any carrier carries its contact's local network reason
/// (`lan_off`, `lan_no_answer`); any other object is left as it is.
#[cfg_attr(not(any(unix, windows)), allow(dead_code))]
pub(crate) fn fill_why(item: &mut OutboxItem) {
    if !matches!(item.state.as_str(), "queued" | "held") {
        return;
    }
    let key = hex::decode(&item.peer_pub_hex)
        .ok()
        .and_then(|k| <[u8; 32]>::try_from(k).ok());
    let Some(key) = key else {
        return;
    };
    let slots = crate::p2p::slot_relay_ids();
    let current = with_reasons(|r| r.current_for(&key, Instant::now(), &slots));
    fill_why_with(item, current);
}

/// [`fill_why`] with its contact's reason as it reads now, and its age.
fn fill_why_with(item: &mut OutboxItem, current: Option<(Diag, Duration)>) {
    let live = matches!(item.state.as_str(), "queued" | "held");
    let p2p = item.carrier == OutboxCarrier::P2p.label()
        && item.last_error_code == crate::outbox::code::NOT_REACHABLE;
    if let Some((mut d, age)) = current.filter(|(d, _)| live && (p2p || d.why.is_lan())) {
        d.asof_s = Some(age.as_secs());
        item.why = d.render();
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// `ContactReach` names a failed route by its index in the send's routes,
    /// never by its dial (a LAN address, a multiaddr, an onion route), gives
    /// the error without addresses, and nothing for a route the send did not
    /// name.
    #[test]
    fn reach_failures_name_routes_by_index_and_carry_no_address() {
        let fresh = vec![
            FreshFailure {
                carrier: "lan_dial".into(),
                dial: "192.168.1.20:7420".into(),
                age_s: 4,
                error: "LAN dial to 192.168.1.20:7420 failed: connection refused".into(),
                short_miss: false,
            },
            FreshFailure {
                carrier: "onion".into(),
                dial: format!("onion:{}", "cd".repeat(32)),
                age_s: 9,
                error: "ONION_UNREACHABLE: the contact's onion service did not answer over Tor"
                    .into(),
                short_miss: false,
            },
            FreshFailure {
                carrier: "p2p_dial".into(),
                dial: "/ip4/203.0.113.9/tcp/7423".into(),
                age_s: 1,
                error: "unrelated".into(),
                short_miss: false,
            },
            // A single short Tor miss: not news to a send.
            FreshFailure {
                carrier: "onion".into(),
                dial: format!("onion:{}", "ef".repeat(32)),
                age_s: 2,
                error: "ONION_UNREACHABLE: the contact's onion service did not answer over Tor"
                    .into(),
                short_miss: true,
            },
        ];
        let routes = vec![
            raven_core::ipc::ReachRoute {
                carrier: "onion".into(),
                dial: format!("onion:{}", "cd".repeat(32)),
            },
            raven_core::ipc::ReachRoute {
                carrier: "lan_dial".into(),
                dial: " 192.168.1.20:7420 ".into(),
            },
            raven_core::ipc::ReachRoute {
                carrier: "onion".into(),
                dial: format!("onion:{}", "ef".repeat(32)),
            },
        ];
        let got = failures_by_index(fresh, &routes);
        assert_eq!(got.len(), 2);
        assert_eq!((got[0].carrier.as_str(), got[0].route), ("lan_dial", 1));
        assert_eq!(
            got[0].error,
            "LAN dial to <local address> failed: connection refused"
        );
        assert_eq!((got[1].carrier.as_str(), got[1].route), ("onion", 0));
        let text = serde_json::to_string(&got).unwrap();
        for leak in ["192.168", "203.0.113", "cdcdcd"] {
            assert!(!text.contains(leak), "{text}");
        }
    }
    use raven_core::envelope::{EnvType, Envelope};
    use std::time::Duration;

    pub(crate) fn envelope(kind: EnvType) -> Vec<u8> {
        Envelope {
            env_type: kind as u8,
            flags: 0,
            message_id: [3; 16],
            routing_tag: [4; 16],
            dest_device_hint: 0,
            created_at: 1,
            expires_at: u64::MAX / 2,
            hop_limit: 1,
            replication_budget: 1,
            anti_replay_nonce: [5; 12],
            ratchet_header_ciphertext: vec![],
            message_ciphertext: vec![1, 2, 3],
            sender_authentication: vec![0u8; 64],
        }
        .pack()
    }

    fn rfc1() -> Vec<u8> {
        let mut frame = raven_core::friend_custody::RFC1_MAGIC.to_vec();
        frame.extend_from_slice(&[1, 2, 0, 0]);
        frame
    }

    /// Only a dial that carried a message and whose replies hold a receipt
    /// counts: no reply, a reply that is no ACK, a custody (RFC1) exchange,
    /// or a dial with no message of ours is no delivery.
    /// Field test E3: the terminal app showed the path of some of your
    /// messages only. A dial that brought a receipt keeps how each of its
    /// messages went (by id: never an address); one without, nothing.
    #[test]
    fn a_delivered_message_keeps_how_it_went() {
        let mut message = Envelope::unpack(&envelope(EnvType::Message)).unwrap();
        message.message_id = [0xD7; 16];
        let message = message.pack();
        let ack = envelope(EnvType::Ack);
        let way = |id: [u8; 16]| {
            delivered_messages()
                .into_iter()
                .rev()
                .find(|(mid, _, _)| *mid == id)
                .map(|(_, via, _)| via)
        };
        note(
            &[0x5D; 32],
            OutboxCarrier::Onion,
            None,
            std::slice::from_ref(&message),
            &[],
        );
        assert_eq!(way([0xD7; 16]), None, "no receipt");
        note(
            &[0x5D; 32],
            OutboxCarrier::Onion,
            None,
            std::slice::from_ref(&message),
            std::slice::from_ref(&ack),
        );
        assert_eq!(way([0xD7; 16]), Some(ArrivedVia::Tor));
        // Through a relay: said so; once per message, the newest way.
        note(
            &[0x5D; 32],
            OutboxCarrier::P2p,
            Some(DeliveryPath::Relayed),
            std::slice::from_ref(&message),
            std::slice::from_ref(&ack),
        );
        assert_eq!(way([0xD7; 16]), Some(ArrivedVia::Relayed));
        assert_eq!(
            delivered_messages()
                .iter()
                .filter(|(mid, _, _)| *mid == [0xD7; 16])
                .count(),
            1
        );
        // IPC `Arrivals` names it by id and way.
        let raven_core::ipc::IpcResponse::Arrivals { delivered, .. } =
            crate::arrivals::ipc_rows(raven_core::ipc::IPC_VERSION)
        else {
            panic!("Arrivals");
        };
        assert!(delivered
            .iter()
            .any(|r| r.message_id_hex == hex::encode([0xD7; 16]) && r.via == "relayed"));
    }

    #[test]
    fn only_a_dial_that_brings_back_a_receipt_counts() {
        let message = envelope(EnvType::Message);
        let ack = envelope(EnvType::Ack);
        assert!(!delivered(std::slice::from_ref(&message), &[]));
        assert!(!delivered(
            std::slice::from_ref(&message),
            std::slice::from_ref(&message)
        ));
        assert!(!delivered(
            std::slice::from_ref(&message),
            &[b"RLB1".to_vec()]
        ));
        // Custody frames reach the same carriers: never a delivery, even
        // with an ACK-looking reply.
        assert!(!delivered(&[rfc1()], std::slice::from_ref(&ack)));
        assert!(!delivered(
            &[message.clone(), rfc1()],
            std::slice::from_ref(&ack)
        ));
        assert!(delivered(
            std::slice::from_ref(&message),
            &[b"RLB1".to_vec(), ack.clone()]
        ));
        // E2 r38: a dial that carried no message of ours (our receipts
        // only, or nothing: an announce link) is no delivery, though the
        // contact hands its owed receipts over on it: LAST DELIVERY said
        // "direct over the internet" after a group send that went over the
        // LAN.
        assert!(!delivered(
            std::slice::from_ref(&ack),
            std::slice::from_ref(&ack)
        ));
        assert!(!delivered(&[], std::slice::from_ref(&ack)));
        assert!(delivered(
            &[ack.clone(), message.clone()],
            std::slice::from_ref(&ack)
        ));

        // Through `note`: only the receipt is remembered.
        let key = [0xA7; 32];
        let hex_key = hex::encode(key);
        let listed = |k: &str| snapshot().into_iter().find(|r| r.peer_pub_hex == k);
        note(
            &key,
            OutboxCarrier::Lan,
            Some(DeliveryPath::Direct),
            &[rfc1()],
            std::slice::from_ref(&ack),
        );
        note(
            &key,
            OutboxCarrier::Lan,
            Some(DeliveryPath::Direct),
            std::slice::from_ref(&message),
            &[],
        );
        assert_eq!(listed(&hex_key), None);
        note(
            &key,
            OutboxCarrier::P2p,
            Some(DeliveryPath::Relayed),
            std::slice::from_ref(&message),
            std::slice::from_ref(&ack),
        );
        let row = listed(&hex_key).expect("a receipt is remembered");
        assert_eq!(
            (row.carrier.as_str(), row.path.as_str()),
            ("p2p_dial", "relayed")
        );
    }

    /// Newest first, at most LIST_MAX rows, at most MAX_CONTACTS contacts (the
    /// oldest goes), one row per contact (its latest), and only labels and a
    /// key: never an address.
    #[test]
    fn newest_first_bounded_labels_only() {
        let t0 = Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);
        let mut paths = LastPaths::default();
        paths.record(
            [1; 32],
            OutboxCarrier::Lan,
            Some(DeliveryPath::Direct),
            at(1),
        );
        paths.record(
            [2; 32],
            OutboxCarrier::Internet,
            Some(DeliveryPath::Direct),
            at(2),
        );
        paths.record([3; 32], OutboxCarrier::P2p, None, at(3));
        // A later delivery replaces that contact's row.
        paths.record(
            [1; 32],
            OutboxCarrier::P2p,
            Some(DeliveryPath::HolePunched),
            at(4),
        );
        let rows = paths.list(at(10));
        let got: Vec<(String, &str, &str, u64)> = rows
            .iter()
            .map(|r| {
                (
                    r.peer_pub_hex.clone(),
                    r.carrier.as_str(),
                    r.path.as_str(),
                    r.age_s,
                )
            })
            .collect();
        assert_eq!(
            got,
            vec![
                (hex::encode([1; 32]), "p2p_dial", "hole_punched", 6),
                (hex::encode([3; 32]), "p2p_dial", "", 7),
                (hex::encode([2; 32]), "internet_dial", "direct", 8),
            ]
        );
        // A key and labels: no field that could hold an address.
        for row in &rows {
            let json = serde_json::to_string(row).unwrap();
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&json)
                    .unwrap()
                    .as_object()
                    .unwrap()
                    .keys()
                    .filter(|k| !["peer_pub_hex", "carrier", "path", "age_s"].contains(&k.as_str()))
                    .count(),
                0,
                "{json}"
            );
        }

        // Bounded: MAX_CONTACTS kept (the oldest dropped), LIST_MAX listed.
        let mut many = LastPaths::default();
        for i in 0..=MAX_CONTACTS {
            let mut key = [0u8; 32];
            key[..8].copy_from_slice(&(i as u64).to_be_bytes());
            many.record(
                key,
                OutboxCarrier::Lan,
                Some(DeliveryPath::Direct),
                at(i as u64),
            );
        }
        assert_eq!(many.by_contact.len(), MAX_CONTACTS);
        assert!(!many.by_contact.contains_key(&[0u8; 32]), "the oldest goes");
        let listed = many.list(at(MAX_CONTACTS as u64 + 1));
        assert_eq!(listed.len(), LIST_MAX);
        let mut newest = [0u8; 32];
        newest[..8].copy_from_slice(&(MAX_CONTACTS as u64).to_be_bytes());
        assert_eq!(listed[0].peer_pub_hex, hex::encode(newest));
        assert!(listed.windows(2).all(|w| w[0].age_s <= w[1].age_s));
    }

    /// A reason as raven-node's p2p dial notes it.
    pub(crate) fn diag(why: Why) -> Diag {
        Diag {
            why,
            me: Some(raven_core::reach::ReachClass::Unreachable),
            relay: None,
            heard_s: None,
            stale: false,
            from_card: false,
            asof_s: None,
        }
    }

    /// A reason goes when the contact is heard from (a receipt, or a link it
    /// opened to us) and when the network changes; hearing from a contact is
    /// remembered with when.
    #[test]
    fn unreachable_is_cleared_by_receipt_heard_and_network_change() {
        let t0 = Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);
        let (bob, carol) = ([0xB1; 32], [0xC1; 32]);
        let mut r = Reasons::default();
        r.note(bob, diag(Why::BothNat), None, at(1));
        r.note(carol, diag(Why::ContactOffline), None, at(2));
        assert_eq!(r.why_for(&bob, at(5)), Some((diag(Why::BothNat), secs(4))));
        assert_eq!(r.heard_age(&bob, at(5)), None);
        // Bob reached us: online, his reason goes; Carol's stays.
        r.heard(bob, at(6));
        assert_eq!(r.why_for(&bob, at(7)), None);
        assert_eq!(r.heard_age(&bob, at(9)), Some(secs(3)));
        assert!(r.why_for(&carol, at(7)).is_some());
        // A network change: every reason goes, last heard stays.
        r.note(bob, diag(Why::RelayAsleep), None, at(10));
        r.network_changed();
        assert!(r.list(at(11), &[]).is_empty());
        assert_eq!(r.heard_age(&bob, at(11)), Some(secs(5)));

        // Through the module: a receipt clears it (`note` calls `heard`),
        // and so does a link the contact opened (`heard`).
        let message = envelope(EnvType::Message);
        let ack = envelope(EnvType::Ack);
        let (dave, erin) = ([0xD7; 32], [0xE7; 32]);
        note_unreachable(&dave, &diag(Why::RelayAsleep), None);
        note_unreachable(&erin, &diag(Why::ContactOffline), None);
        assert_eq!(why_for(&dave).map(|(d, _)| d.why), Some(Why::RelayAsleep));
        let listed = unreachable_snapshot();
        let row = listed
            .iter()
            .find(|r| r.peer_pub_hex == hex::encode(dave))
            .expect("listed");
        assert_eq!(row.reason, "reach: why=relay_asleep me=unreachable");
        // No receipt: nothing changes.
        note(
            &dave,
            OutboxCarrier::P2p,
            Some(DeliveryPath::Relayed),
            std::slice::from_ref(&message),
            &[],
        );
        assert!(why_for(&dave).is_some());
        assert_eq!(heard_age(&dave), None);
        note(
            &dave,
            OutboxCarrier::P2p,
            Some(DeliveryPath::Relayed),
            std::slice::from_ref(&message),
            std::slice::from_ref(&ack),
        );
        assert_eq!(why_for(&dave), None);
        assert!(heard_age(&dave).is_some_and(|a| a < secs(60)));
        heard(&erin);
        assert_eq!(why_for(&erin), None);
        assert!(!unreachable_snapshot()
            .iter()
            .any(|r| [hex::encode(dave), hex::encode(erin)].contains(&r.peer_pub_hex)));
    }

    /// A remembered reason is served as it reads now: `heard=` aged by the
    /// reason's own age, and `relay=mine<n>` following its relay (kept by
    /// PeerId) to the slot it sits in now, dropped once that relay left our
    /// slots (automatic choice replaced it), so the owner of the relay that
    /// took the slot is never named. `why_for` keeps what was noted.
    #[test]
    fn a_remembered_reason_follows_its_relay_and_ages() {
        let t0 = Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);
        let (r1, r2, r3) = (
            Some("relay-one".to_string()),
            Some("relay-two".to_string()),
            Some("relay-three".to_string()),
        );
        // Last heard 2.5 h before the diagnosis.
        let asleep = Diag {
            relay: Some(2),
            heard_s: Some(9_000),
            ..diag(Why::RelayAsleep)
        };
        let mut r = Reasons::default();
        r.note([1; 32], asleep.clone(), r2.clone(), at(0));
        let now = |r: &Reasons, slots: &[Option<String>]| {
            r.current_for(&[1; 32], at(3_600), slots).unwrap().0
        };
        // An hour later, the same slots: slot 2, last heard 3.5 h ago.
        let d = now(&r, &[r1.clone(), r2.clone()]);
        assert_eq!((d.relay, d.heard_s), (Some(2), Some(12_600)));
        let rows = r.list(at(3_600), &[r1.clone(), r2.clone()]);
        assert_eq!(
            (rows[0].reason.as_str(), rows[0].age_s),
            (
                "reach: why=relay_asleep me=unreachable relay=mine2 heard=3h",
                3_600
            )
        );
        // Its relay is in slot 1 now.
        assert_eq!(now(&r, &[r2.clone(), r3.clone()]).relay, Some(1));
        // Slot 2 holds another relay now: no slot is named.
        let d = now(&r, &[r1.clone(), r3.clone()]);
        assert_eq!((d.why, d.relay), (Why::RelayAsleep, None));
        assert_eq!(
            r.list(at(3_600), &[r1.clone(), r3.clone()])[0].reason,
            "reach: why=relay_asleep me=unreachable heard=3h"
        );
        // No host (no slots): none either.
        assert_eq!(now(&r, &[]).relay, None);
        // As it was noted.
        assert_eq!(r.why_for(&[1; 32], at(600)), Some((asleep, secs(600))));
        // A reason that names no relay never gains one; no heard stays none.
        r.note([2; 32], diag(Why::ContactOffline), r1.clone(), at(0));
        let (d, age) = r
            .current_for(&[2; 32], at(5), std::slice::from_ref(&r1))
            .unwrap();
        assert_eq!((d.relay, d.heard_s, age), (None, None, secs(5)));
    }

    /// A reason decided after its dial returned (the dial began at
    /// `since`) is kept only if nothing newer is known: no reason noted
    /// since, the contact not heard from since, the network unchanged
    /// since.
    #[test]
    fn a_late_reason_never_replaces_newer_knowledge() {
        let t0 = Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);
        let late = || diag(Why::ContactOffline);
        let (bob, carol, dave) = ([0xB2; 32], [0xC2; 32], [0xD2; 32]);
        let mut r = Reasons::default();
        // Nothing newer: kept, replacing an older reason.
        r.note(bob, diag(Why::RelayAsleep), None, at(1));
        assert!(r.note_after(bob, late(), None, at(5), at(20)));
        assert_eq!(r.why_for(&bob, at(20)), Some((late(), secs(0))));
        // A reason noted after the dial began wins.
        r.note(carol, diag(Why::BothNat), None, at(6));
        assert!(!r.note_after(carol, late(), None, at(5), at(20)));
        assert_eq!(
            r.why_for(&carol, at(20)).map(|(d, _)| d.why),
            Some(Why::BothNat)
        );
        // Heard from after the dial began: online, nothing kept.
        r.heard(dave, at(7));
        assert!(!r.note_after(dave, late(), None, at(5), at(20)));
        assert_eq!(r.why_for(&dave, at(20)), None);
        // A network change after the dial began: old evidence.
        let mut r = Reasons::default();
        let since = Instant::now();
        r.network_changed();
        assert!(!r.note_after(bob, late(), None, since, Instant::now()));
        assert!(r.why.is_empty());
    }

    /// F9: a default route coming back clears the `no_route` reasons only.
    /// Phase 3 (P3.23): the outbox's local network reasons. A new one
    /// replaces any reason; "LAN is not why" drops only a local network
    /// reason (a p2p one stays); `raven lan on` drops the `lan_off` ones; a
    /// contact heard from or a network change drops them like any reason.
    #[test]
    fn local_network_reasons_come_and_go_with_the_outbox_and_lan_on() {
        let mut r = Reasons::default();
        let t0 = Instant::now();
        let (bob, carol, dave) = ([1; 32], [2; 32], [3; 32]);
        r.note(bob, diag(Why::BothNat), None, t0);
        r.note_lan(bob, Some(diag(Why::LanOff)), t0);
        assert_eq!(r.why_for(&bob, t0).map(|(d, _)| d.why), Some(Why::LanOff));
        r.note_lan(carol, Some(diag(Why::LanNoAnswer)), t0);
        r.note(dave, diag(Why::ContactOffline), None, t0);
        // LAN is not why: only a local network reason goes.
        r.note_lan(dave, None, t0);
        assert!(r.why_for(&dave, t0).is_some());
        r.note_lan(carol, None, t0);
        assert_eq!(r.why_for(&carol, t0), None);
        r.note_lan(carol, Some(diag(Why::LanNoAnswer)), t0);
        // `raven lan on`.
        r.lan_back();
        assert_eq!(r.why_for(&bob, t0), None);
        assert_eq!(
            r.why_for(&carol, t0).map(|(d, _)| d.why),
            Some(Why::LanNoAnswer)
        );
        let rows = r.list(t0, &[]);
        assert_eq!(rows.len(), 2);
        assert!(rows
            .iter()
            .any(|row| row.reason == "reach: why=lan_no_answer me=unreachable"));
        r.heard(carol, t0);
        assert_eq!(r.why_for(&carol, t0), None);
        r.note_lan(bob, Some(diag(Why::LanOff)), t0);
        r.network_changed();
        assert!(r.why.is_empty());

        // fill_why: a live object of any carrier carries a local network
        // reason, whatever its code; a p2p one only on a p2p NOT_REACHABLE.
        let item = |carrier: OutboxCarrier, code: &str, state: &str| OutboxItem {
            peer_pub_hex: hex::encode([0xe7; 32]),
            carrier: carrier.label().into(),
            last_error_code: code.into(),
            state: state.into(),
            ..OutboxItem::default()
        };
        let silent = || Some((diag(Why::LanNoAnswer), secs(30)));
        for (carrier, code) in [
            (OutboxCarrier::Lan, crate::outbox::code::NOT_REACHABLE),
            (OutboxCarrier::Lan, crate::outbox::code::NO_ROUTE),
            (OutboxCarrier::P2p, crate::outbox::code::NOT_REACHABLE),
        ] {
            let mut i = item(carrier, code, "queued");
            fill_why_with(&mut i, silent());
            assert_eq!(i.why, "reach: why=lan_no_answer me=unreachable asof=30s");
            let mut done = item(carrier, code, "delivered");
            fill_why_with(&mut done, silent());
            assert!(done.why.is_empty());
            let mut none = item(carrier, code, "held");
            fill_why_with(&mut none, None);
            assert!(none.why.is_empty());
        }
        let offline = Some((diag(Why::ContactOffline), secs(5)));
        let mut lan = item(
            OutboxCarrier::Lan,
            crate::outbox::code::NOT_REACHABLE,
            "held",
        );
        fill_why_with(&mut lan, offline.clone());
        assert!(lan.why.is_empty(), "a p2p reason stays on p2p objects");
        let mut p2p = item(
            OutboxCarrier::P2p,
            crate::outbox::code::NOT_REACHABLE,
            "held",
        );
        fill_why_with(&mut p2p, offline);
        assert_eq!(p2p.why, "reach: why=contact_offline me=unreachable asof=5s");
    }

    #[test]
    fn a_route_coming_back_clears_only_no_route_reasons() {
        let t0 = Instant::now();
        let mut r = Reasons::default();
        r.note([1; 32], diag(Why::NoRoute), None, t0);
        r.note([2; 32], diag(Why::BothNat), None, t0);
        r.route_back();
        assert_eq!(r.why_for(&[1; 32], t0), None);
        assert_eq!(
            r.why_for(&[2; 32], t0).map(|(d, _)| d.why),
            Some(Why::BothNat)
        );
    }

    /// P3.C6: a link counts for ten minutes with its latest address; a pin
    /// block lists for ten minutes, newest first, at most 8, keys only, and
    /// goes once the contact is heard from or the network changes.
    #[test]
    fn links_and_pin_blocks_last_ten_minutes() {
        let t0 = Instant::now();
        let at = |s: u64| t0 + secs(s);
        let ip = |s: &str| -> IpAddr { s.parse().unwrap() };
        let mut h = Here::default();
        h.link([1; 32], ip("192.168.1.30"), at(0));
        h.link([2; 32], ip("10.0.0.2"), at(60));
        h.link([1; 32], ip("fe80::31"), at(120));
        let mut linked = h.linked(at(600));
        linked.sort_unstable();
        assert_eq!(
            linked,
            [([1; 32], ip("fe80::31")), ([2; 32], ip("10.0.0.2"))]
        );
        assert_eq!(h.linked(at(661)), [([1; 32], ip("fe80::31"))]);
        assert!(h.linked(at(721)).is_empty());
        for i in 0..10u8 {
            h.pin_blocked([i; 32], at(u64::from(i)));
        }
        let listed = h.pin_list(at(10));
        assert_eq!(listed.len(), PIN_BLOCKED_MAX);
        assert_eq!(listed[0], hex::encode([9; 32]));
        assert_eq!(listed[7], hex::encode([2; 32]));
        assert_eq!(
            h.pin_list(at(605)),
            (5..10u8)
                .rev()
                .map(|i| hex::encode([i; 32]))
                .collect::<Vec<_>>()
        );
        h.heard(&[9; 32]);
        assert_eq!(h.pin_list(at(10))[0], hex::encode([8; 32]));
        h.network_changed();
        assert!(h.pin_list(at(10)).is_empty());
        assert_eq!(h.linked(at(10)).len(), 2, "links are checked by address");
        // The process-wide calls, with a key no other test uses.
        let key = [0xE7; 32];
        pin_blocked(&key);
        assert!(pin_blocked_snapshot().contains(&hex::encode(key)));
        heard(&key);
        assert!(!pin_blocked_snapshot().contains(&hex::encode(key)));
        lan_link(&key, ip("192.168.7.7"));
        assert!(lan_linked_lately().contains(&(key, ip("192.168.7.7"))));
    }

    /// Newest first, at most LIST_MAX rows, at most MAX_CONTACTS contacts
    /// (the oldest goes, in both maps), one row per contact (its latest), and
    /// the reason block only: never an address.
    #[test]
    fn snapshot_newest_first_bounded() {
        let t0 = Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);
        let mut r = Reasons::default();
        r.note([1; 32], diag(Why::BothNat), None, at(1));
        r.note([2; 32], diag(Why::ContactOffline), None, at(2));
        r.note([1; 32], diag(Why::RelayRefused), None, at(3));
        let rows = r.list(at(10), &[]);
        let got: Vec<(String, &str, u64)> = rows
            .iter()
            .map(|r| (r.peer_pub_hex.clone(), r.reason.as_str(), r.age_s))
            .collect();
        assert_eq!(
            got,
            vec![
                (
                    hex::encode([1; 32]),
                    "reach: why=relay_refused me=unreachable",
                    7
                ),
                (
                    hex::encode([2; 32]),
                    "reach: why=contact_offline me=unreachable",
                    8
                ),
            ]
        );
        for row in &rows {
            let json = serde_json::to_string(row).unwrap();
            assert!(!json.contains('/') && !json.contains("12D3KooW"), "{json}");
        }

        let key = |i: usize| {
            let mut key = [0u8; 32];
            key[..8].copy_from_slice(&(i as u64).to_be_bytes());
            key
        };
        let mut many = Reasons::default();
        for i in 0..=MAX_CONTACTS {
            many.note(key(i), diag(Why::NoRelay), None, at(i as u64));
            many.heard(key(MAX_CONTACTS + 1 + i), at(i as u64));
        }
        assert_eq!(many.why.len(), MAX_CONTACTS);
        assert_eq!(many.heard.len(), MAX_CONTACTS);
        assert!(!many.why.contains_key(&key(0)), "the oldest goes");
        assert!(!many.heard.contains_key(&key(MAX_CONTACTS + 1)));
        let listed = many.list(at(MAX_CONTACTS as u64 + 1), &[]);
        assert_eq!(listed.len(), LIST_MAX);
        assert_eq!(listed[0].peer_pub_hex, hex::encode(key(MAX_CONTACTS)));
        assert!(listed.windows(2).all(|w| w[0].age_s <= w[1].age_s));
    }

    fn secs(s: u64) -> Duration {
        Duration::from_secs(s)
    }

    /// Phase 6b S21 (step P6.28): per relay, the relayed dials that carried
    /// a message and those that brought a receipt. One without, while the
    /// same contact's receipt came over another path within an hour (before
    /// or after it), is SEC_RELAY_NO_RECEIPT about that relay; more than half
    /// of its last 10 that way is Suspicious. A receipt through the same
    /// relay, another contact's, or one more than an hour away blames
    /// nothing.
    #[test]
    fn a_relay_that_loses_receipts_another_path_brings_is_noted() {
        let mut w = RelayWatch::default();
        let t = Instant::now();
        let min = |m: u64| t + secs(60 * m);
        let (alice, bob) = ([0xa1; 32], [0xb1; 32]);
        let (r1, r2) = (b"relay-one".as_slice(), b"relay-two".as_slice());
        let lost = |r: &[u8], suspicious| vec![(r.to_vec(), suspicious)];
        // A receipt through r1, then a dial through it without one: its own
        // receipt is no other path.
        assert!(w.dial(alice, r1, true, min(0)).is_empty());
        assert!(w.dial(alice, r1, false, min(1)).is_empty());
        assert_eq!(w.counts(r1), Some((2, 1)));
        // Bob's receipt says nothing about Alice's dial.
        assert!(w.receipt(bob, None, min(2)).is_empty());
        // Alice's over LAN half an hour later: that dial lost its receipt.
        assert_eq!(w.receipt(alice, None, min(31)), lost(r1, false));
        // Another without one right after: at once.
        assert_eq!(w.dial(alice, r1, false, min(32)), lost(r1, false));
        // More than an hour after the LAN one: it waits; a receipt through
        // r2 then counts against r1, never against r2.
        assert!(w.dial(alice, r1, false, min(92)).is_empty());
        assert_eq!(w.dial(alice, r2, true, min(93)), lost(r1, false));
        assert_eq!(w.counts(r2), Some((1, 1)));
        // A waiting dial more than an hour before a receipt stays as it was.
        assert!(w.dial(bob, r2, false, min(100)).is_empty());
        assert!(w.receipt(bob, None, min(161)).is_empty());
        assert!(w.receipt(alice, None, min(161)).is_empty());
        // Suspicious once more than half of r1's last 10 lost theirs: three
        // so far, two more are still a Notice, the sixth is Suspicious.
        for m in [162, 163] {
            assert_eq!(w.dial(alice, r1, false, min(m)), lost(r1, false));
        }
        assert_eq!(w.dial(alice, r1, false, min(164)), lost(r1, true));
        assert_eq!(w.counts(r1), Some((7, 1)));
        // Receipts through r1 push the old losses out of its window.
        for m in 165..170 {
            assert!(w.dial(alice, r1, true, min(m)).is_empty());
        }
        assert_eq!(w.dial(alice, r1, false, min(171)), lost(r1, false));
        // Bounded.
        for n in 0..=MAX_RELAYS as u16 {
            w.dial(alice, &n.to_be_bytes(), true, min(200));
        }
        assert!(w.relays.len() <= MAX_RELAYS);
    }

    /// Wired up: a relayed p2p dial with a message and no receipt, then the
    /// same contact's receipt over LAN, notes SEC_RELAY_NO_RECEIPT about the
    /// relay's digest (never its PeerId); a dial through two relays blames
    /// neither, one that carried no message is no evidence, and nothing is
    /// counted while the events gate is shut.
    #[test]
    fn a_relayed_dial_without_a_receipt_is_noted_about_its_relay() {
        use raven_core::security_events::{relay_subject, Attribution, CarrierRole, SecKind, Via};
        let (carol, relay) = ([0xc5; 32], b"relay-peer-id-c5".to_vec());
        let message = envelope(EnvType::Message);
        let ack = envelope(EnvType::Ack);
        {
            raven_core::security_gate::set_lab_for_this_thread(
                raven_core::security_gate::SecGate::Events,
                Some(false),
            );
            relayed_dial(
                &carol,
                std::slice::from_ref(&relay),
                std::slice::from_ref(&message),
                None,
            );
            raven_core::security_gate::set_lab_for_this_thread(
                raven_core::security_gate::SecGate::Events,
                None,
            );
        }
        let Some(capture) = crate::security::tests::Capture::start() else {
            return;
        };
        assert_eq!(relay_counts(&relay), None, "nothing while shut");
        let other = b"relay-peer-id-c6".to_vec();
        relayed_dial(
            &carol,
            &[relay.clone(), other],
            std::slice::from_ref(&message),
            None,
        );
        relayed_dial(
            &carol,
            std::slice::from_ref(&relay),
            std::slice::from_ref(&ack),
            None,
        );
        assert_eq!(relay_counts(&relay), None);
        let nothing: &[Vec<u8>] = &[];
        relayed_dial(
            &carol,
            std::slice::from_ref(&relay),
            std::slice::from_ref(&message),
            Some(nothing),
        );
        assert_eq!(relay_counts(&relay), Some((1, 0)));
        assert!(capture.events().is_empty());
        note(
            &carol,
            OutboxCarrier::Lan,
            Some(DeliveryPath::Direct),
            std::slice::from_ref(&message),
            std::slice::from_ref(&ack),
        );
        assert_eq!(
            capture.kinds(),
            [(
                SecKind::RelayNoReceipt,
                Attribution::Carrier {
                    carrier: relay_subject(&relay),
                    role: CarrierRole::Relay,
                },
                Via::Relay
            )]
        );
    }
}

#[cfg(test)]
mod failed_route_tests {
    use super::*;

    /// E2 r9 #2: a contact's failed routes are kept per route (the newest
    /// failure), served while fresh, and forgotten when the contact answers
    /// or is heard from; the LAN sighting has its own age.
    /// E2 r9 #3: a p2p failure is news the first time, and again while
    /// nothing else delivers; not after another carrier delivered since the
    /// last one (Tor carrying every message). A contact that went away after
    /// a LAN delivery still gets its first line (carrier matrix C34).
    #[test]
    fn a_delivery_over_another_carrier_quietens_p2p_failures() {
        let p2p = OutboxCarrier::P2p;
        let record = |who: [u8; 32], carrier| {
            last().get_or_insert_with(LastPaths::default).record(
                who,
                carrier,
                None,
                Instant::now(),
            );
        };
        // Tor delivers between p2p failures.
        let tor = [0xE1; 32];
        assert!(failure_is_news(&tor, p2p), "the first failure");
        std::thread::sleep(Duration::from_millis(5));
        record(tor, OutboxCarrier::Onion);
        assert!(!failure_is_news(&tor, p2p), "Tor delivered since");
        assert!(failure_is_news(&tor, p2p), "nothing delivered since");
        // A LAN delivery, then the contact goes away: its first p2p failure
        // is news.
        let away = [0xE2; 32];
        record(away, OutboxCarrier::Lan);
        std::thread::sleep(Duration::from_millis(5));
        assert!(failure_is_news(&away, p2p));
        assert!(failure_is_news(&away, p2p));
        // p2p's own delivery does not quieten p2p.
        let own = [0xE3; 32];
        assert!(failure_is_news(&own, p2p));
        std::thread::sleep(Duration::from_millis(5));
        record(own, p2p);
        assert!(failure_is_news(&own, p2p));
    }

    /// Field test E3 r1: seven sends over Tor were delivered, then three
    /// more were queued at once, without a dial, while the friend was
    /// writing to us: a Tor dial to the friend ran (the outbox's, a keeper's
    /// check) and counted as "Tor busy without reaching it". A running dial
    /// says nothing while Tor reached the friend lately; it still does when
    /// Tor did not, and a newer failure always does.
    #[test]
    fn a_running_tor_dial_is_not_busy_while_tor_reached_the_friend_lately() {
        let (tor, lan) = (OutboxCarrier::Onion, OutboxCarrier::Lan);
        // Reached by our own delivery over Tor.
        let friend = [0xF6; 32];
        carrier_worked(&friend, tor);
        let running = onion_dial_started(&friend);
        assert!(!tor_tried_lately(&friend), "Tor reached it just now");
        // A newer Tor failure: busy again, dial or not.
        route_failed(&friend, tor, "onion:f6", "ONION_UNREACHABLE");
        assert!(tor_tried_lately(&friend));
        drop(running);
        assert!(tor_tried_lately(&friend));
        // A message that came over Tor (arrivals.rs) clears it again.
        carrier_worked(&friend, tor);
        assert!(!tor_tried_lately(&friend));
        // Reached by a send's dial that Tor answered (no message yet).
        let answered = [0xF7; 32];
        let running = onion_dial_started(&answered);
        assert!(tor_tried_lately(&answered), "never reached: busy");
        route_answered(&answered, tor, "onion:f7");
        assert!(!tor_tried_lately(&answered));
        drop(running);
        // Another carrier working says nothing about Tor.
        let other = [0xF8; 32];
        carrier_worked(&other, lan);
        let running = onion_dial_started(&other);
        assert!(tor_tried_lately(&other));
        drop(running);
        // Reached long ago: a running dial counts again.
        let mut reached = TorReached::default();
        let now = Instant::now();
        reached.reached(friend, now - ROUTE_FAIL_FRESH - Duration::from_secs(1));
        assert!(!reached.within(&friend, now, ROUTE_FAIL_FRESH));
        reached.reached(friend, now);
        assert!(reached.within(&friend, now, ROUTE_FAIL_FRESH));
        reached.clear();
        assert!(!reached.within(&friend, now, ROUTE_FAIL_FRESH));
    }

    /// Field test E3 round 2: a send's Tor check failed after 5.2 s (Tor
    /// said the onion service could not be reached), and the next send, 5 s
    /// later, queued without a dial while the outbox's Tor dial seconds
    /// later worked. A single short Tor miss is kept but is no reason to
    /// leave Tor out; a second one, or a slow one, is.
    #[test]
    fn a_single_short_tor_miss_is_not_news_to_the_next_send() {
        let tor = OutboxCarrier::Onion;
        let miss = "ONION_UNREACHABLE: the contact's onion service did not answer over Tor \
                    (rendezvous failed)";
        let route = format!("onion:{}", "a1".repeat(32));
        let asked = [raven_core::ipc::ReachRoute {
            carrier: tor.label().into(),
            dial: route.clone(),
        }];
        // One short miss: kept, not reported, Tor not "tried lately".
        let friend = [0xA1; 32];
        route_failed_after(&friend, tor, &route, miss, Duration::from_millis(5_200));
        assert_eq!(failed_routes(&friend).len(), 1);
        assert!(failed_routes(&friend)[0].short_miss);
        assert!(reach_failures(&friend, &asked).is_empty());
        assert!(!tor_tried_lately(&friend));
        // A second one on that route: news.
        route_failed_after(&friend, tor, &route, miss, Duration::from_millis(4_000));
        assert!(!failed_routes(&friend)[0].short_miss);
        assert_eq!(reach_failures(&friend, &asked).len(), 1);
        assert!(tor_tried_lately(&friend));
        // A slow one (Tor's full wait), a timeout, or another error: news.
        for (who, error, took) in [
            (0xA2, miss, ONION_SHORT_MISS),
            (0xA3, "timed out", Duration::from_secs(1)),
            (
                0xA4,
                "ONION_NOT_READY: Tor is not ready",
                Duration::from_secs(1),
            ),
        ] {
            let contact = [who; 32];
            route_failed_after(&contact, tor, &route, error, took);
            assert!(!failed_routes(&contact)[0].short_miss, "{error}");
            assert_eq!(reach_failures(&contact, &asked).len(), 1, "{error}");
        }
        // Only Tor misses can be short.
        let lan = [0xA5; 32];
        route_failed_after(
            &lan,
            OutboxCarrier::Lan,
            "192.0.2.5:7420",
            miss,
            Duration::ZERO,
        );
        assert!(!failed_routes(&lan)[0].short_miss);
    }

    #[test]
    fn failed_routes_are_fresh_per_route_and_go_when_the_contact_answers() {
        let contact = [0xF1; 32];
        let other = [0xF2; 32];
        route_failed(
            &contact,
            OutboxCarrier::Lan,
            "192.0.2.7:7420",
            "no answer within 5.0s",
        );
        route_failed(
            &contact,
            OutboxCarrier::Onion,
            "onion:ab",
            "ONION_UNREACHABLE",
        );
        route_failed(
            &contact,
            OutboxCarrier::Lan,
            "192.0.2.7:7420",
            "connection refused",
        );
        route_failed(&other, OutboxCarrier::P2p, "/p2p/x", "P2P_UNREACHABLE");
        let rows = failed_routes(&contact);
        assert_eq!(rows.len(), 2, "{rows:?}");
        let lan = rows.iter().find(|r| r.carrier == "lan_dial").unwrap();
        assert_eq!(lan.error, "connection refused", "the newest failure");
        assert!(rows.iter().all(|r| r.age_s <= ROUTE_FAIL_FRESH.as_secs()));
        // E2 r40: an answer clears that route only.
        route_answered(&contact, OutboxCarrier::Onion, "onion:ab");
        let left: Vec<String> = failed_routes(&contact)
            .into_iter()
            .map(|r| r.carrier)
            .collect();
        assert_eq!(left, ["lan_dial"]);
        route_answered(&contact, OutboxCarrier::Lan, "192.0.2.7:7420");
        assert!(failed_routes(&contact).is_empty());
        // `raven learning reset` forgets them too, for one contact or all.
        route_failed(&contact, OutboxCarrier::Lan, "192.0.2.7:7420", "timed out");
        forget_failed_routes(Some(&contact));
        assert!(failed_routes(&contact).is_empty());
        assert_eq!(failed_routes(&other).len(), 1);
        // Hearing from the contact keeps them; a link on the carrier, or
        // (Tor) our own self-check, clears that carrier's.
        heard(&other);
        assert_eq!(failed_routes(&other).len(), 1);
        carrier_worked(&other, OutboxCarrier::P2p);
        assert!(failed_routes(&other).is_empty());
        route_failed(
            &other,
            OutboxCarrier::Onion,
            "onion:cd",
            "ONION_UNREACHABLE",
        );
        route_failed(&other, OutboxCarrier::Lan, "192.0.2.8:7420", "timed out");
        tor_works_here();
        let left: Vec<String> = failed_routes(&other)
            .into_iter()
            .map(|r| r.carrier)
            .collect();
        assert_eq!(left, ["lan_dial"]);
        // The outbox's next attempt starts Tor at once only when every
        // direct route of it failed lately (E2 r40).
        let direct = [0xF4; 32];
        let (lan, p2p, tor) = (OutboxCarrier::Lan, OutboxCarrier::P2p, OutboxCarrier::Onion);
        route_failed(&direct, lan, "192.0.2.10:7420", "no answer within 5.0s");
        assert!(direct_routes_failed_lately(&direct, &[lan, tor]));
        assert!(!direct_routes_failed_lately(&direct, &[lan, p2p, tor]));
        assert!(
            !direct_routes_failed_lately(&direct, &[tor]),
            "no direct route"
        );
        route_failed(&direct, p2p, "/p2p/y", "P2P_UNREACHABLE");
        assert!(direct_routes_failed_lately(&direct, &[lan, p2p, tor]));
        // Tor tried lately: while a dial runs, or after it failed.
        assert!(!tor_tried_lately(&direct));
        let mark = onion_dial_started(&direct);
        let second = onion_dial_started(&direct);
        assert!(tor_tried_lately(&direct));
        drop(mark);
        assert!(tor_tried_lately(&direct), "one still runs");
        drop(second);
        assert!(!tor_tried_lately(&direct));
        route_failed(&direct, tor, "onion:ef", "ONION_UNREACHABLE");
        assert!(tor_tried_lately(&direct));
        carrier_worked(&direct, tor);
        assert!(!tor_tried_lately(&direct));
        carrier_worked(&direct, lan);
        assert!(!direct_routes_failed_lately(&direct, &[lan, p2p, tor]));
        // Stale ones are not served.
        let mut fails = RouteFails::default();
        let long_ago = Instant::now() - ROUTE_FAIL_FRESH - Duration::from_secs(1);
        fails.failed(
            contact,
            FailedRoute {
                carrier: OutboxCarrier::Lan,
                dial: "x:1".into(),
                at: long_ago,
                error: String::new(),
                short_miss: false,
            },
        );
        assert!(fails.fresh(&contact, Instant::now()).is_empty());
        // The LAN sighting: only at an address on this computer's networks
        // now (ours moved: none; E2 r40), and gone when the contact told new
        // routes over another carrier (it moved).
        let seen = [0xF3; 32];
        let on = |_: IpAddr| true;
        assert_eq!(lan_seen_age_with(&seen, on), None);
        lan_link(&seen, "192.0.2.9".parse().unwrap());
        assert!(lan_seen_age_with(&seen, on).is_some_and(|age| age < Duration::from_secs(5)));
        assert_eq!(lan_seen_age_with(&seen, |_| false), None, "we moved");
        forget_lan_sighting(&seen);
        assert_eq!(lan_seen_age_with(&seen, on), None);
    }
}
