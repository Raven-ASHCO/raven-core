//! The LAN beacon task (Phase 3 item 2, `protocol/RAVEN_LAN_BEACON_V1.md`):
//! a contact-only, solicited query and answer over UDP that finds where a
//! contact's LAN listener is now, with no address typed. raven-core's
//! [`raven_core::lan_beacon`] makes and reads the datagrams (no I/O); this
//! task sends and receives them, keeps every limit and holds what it found.
//!
//! - **When (§13):** only while the beacon gate is live
//!   ([`raven_core::lan_beacon_live`], read once at start: never in a release
//!   build until the owner flips it; `RAVEN_LAB_LAN_BEACON=1` in a debug
//!   build), LAN is on ([`crate::lan_direct::lan_on`]: `raven lan off` and
//!   the end of a meeting time turn it off) and the LAN listener has loaded
//!   this profile's identity ([`crate::lan_direct::listener_identity`]).
//!   Otherwise no UDP socket is open; LAN turning off closes them, leaves the
//!   groups and forgets every candidate.
//! - **Sockets (§3):** `0.0.0.0:7420` and `[::]:7420` (IPv6 only) receive,
//!   with SO_REUSEADDR (and SO_REUSEPORT on macOS and the BSDs) so that
//!   several profiles on one computer each get every datagram, and join both
//!   groups on every interface [`crate::lan_ifaces`] selects (Linux:
//!   IP_MULTICAST_ALL off). Each interface sends from a socket bound to its
//!   IPv4 address or its IPv6 link-local address, TTL / hop limit 1, loop on:
//!   IPv4 to the group and the subnet broadcast address, IPv6 to the group.
//!   Every query and answer goes out twice, and a datagram seen again is
//!   handled once. Another program holding the port exclusively:
//!   `port-busy`, tried again at the next poll.
//! - **Shape (§3, Phase 6b W-B3, people study M13; the v1 amendment made
//!   before the beacon's production flip):** each query and answer gets a
//!   random tail ([`raven_core::lan_beacon::with_tail`]: 160..=191 and
//!   48..=63 bytes on the wire), its first copy goes out a random
//!   0..=[`SEND_DELAY_MAX`] after it was made and its second a random
//!   [`REPEAT_MIN`]..=[`REPEAT_MAX`] after the first ([`Shape`]), so neither
//!   the length nor the moment ties a datagram to its sender, its trigger or
//!   the query it answers. Receivers read any length of the two ranges.
//! - **Asking (§8):** a contact is wanted by the outbox, custody or a user
//!   send ([`want`]), by one join round per start and per interface or
//!   network change (at most [`JOIN_MAX`] contacts: while custody is live
//!   first the recipients this node holds custody mail for, then those seen
//!   on the LAN in the last 7 days,
//!   [`raven_core::lan_seen::recent_lan_contacts`]) and, after a
//!   change, for everything waiting ([`crate::outbox::waiting_peers`]). The
//!   join round goes only while something needs a contact found (owner
//!   decision OD-C7): deliveries or ACKs wait, custody rows wait for their
//!   recipients, or meeting mode is on; joining a network alone sends
//!   nothing. Wants within [`COALESCE`] share a round of at most 8 contacts,
//!   the oldest first; rounds come from a bucket of [`ROUND_BURST`] refilled
//!   one per [`ROUND_REFILL`]. Queries naming a contact are [`PEER_GAP_MIN`]
//!   apart, doubling while unanswered up to [`PEER_GAP_MAX`] ([`SEND_GAP`]
//!   for a user send), and none goes while it has a candidate younger than
//!   [`CANDIDATE_FRESH`]; a change or an authenticated link ([`linked`])
//!   starts its interval over. A join round asked for while the book cannot
//!   be read yet (the at-rest key is still loading) goes once it reads. A
//!   round goes out on every interface and family with a fresh nonce, naming
//!   the LAN listener's port where the listener accepts that family (else 0,
//!   §4 and §6); with no socket open, wants lapse. The interfaces are read
//!   again every [`POLL_BUSY`] while deliveries wait, else every
//!   [`POLL_IDLE`]: netwatch ignores a cable or a link-local-only network.
//! - **Answering (§6):** a query from a local source, within the rate limits
//!   ([`SOURCE_BURST`] per source, [`GLOBAL_BURST`] in all), not a replay of
//!   a matched nonce and not this node's own (its echo tells that multicast
//!   works here, `echo_ok`), is matched against the book: every current
//!   contact that is not blocked (pinned ones only under `raven lan
//!   verified-only`), at most [`BOOK_MAX`], read again when the contact
//!   book, block list or policy changes, its epoch keys kept per epoch. A
//!   match must pass the LAN link gate
//!   ([`raven_core::lan_dispatch::link_admission`]); then its port is a
//!   candidate, what waits for the contact is due now, and it is answered
//!   on the arrival interface when the LAN listener accepts that family
//!   there, at most once per contact per [`ANSWER_GAP`] (a change starts that
//!   over: an answer on the old network says nothing on the new one).
//!   Phase 6b (S22, R1; gated): a replay of a matched nonce and a query over
//!   its source's rate are noted and are strikes against the source in the
//!   stranger penalty box ([`crate::security::beacon_refused`]), and a source
//!   the box banned gets no answer at all
//!   ([`crate::security::beacon_banned`]).
//! - **Results (§7, §9):** an answer counts within [`ANSWER_WINDOW`] of a
//!   query of its family sent on its link (any interface on its IPv4
//!   source's subnet, or its IPv6 zone). A candidate (`ip:port` at a
//!   local-network address; a link-local address keeps its zone) lives in
//!   memory only, for [`CANDIDATE_TTL`], while its interface is one the
//!   task runs on, until the next network or interface change and until a
//!   dial to it fails ([`dial_failed`]: a delivery, custody fetch or
//!   deposit dial): never saved, announced or forwarded. [`candidates`]
//!   gives at most two, IPv4 first, for the outbox to dial first among the
//!   contact's LAN routes, and [`locate`] waits for one (IPC `LanLocate`, a
//!   user send).
//! - **Clocks (Phase 3 P3.C3, F11b):** a match says at which of this node's
//!   three epochs the contact's query was made, which bounds how far its
//!   clock is from ours by when in our epoch it matched. Matched
//!   [`SKEW_ROUNDS`] rounds in a row only at the epoch before ours, or only
//!   at the one after, one of them showing more than Raven's five-minute
//!   limit (a few seconds' skew matches next door at every epoch's edge),
//!   CP.7's clock notes say the contact's clock runs at least that much
//!   behind or ahead ([`crate::clock_notes`], `raven status`; review A-3).
//!   A contact two epochs or more off is never matched: when a
//!   want for it waits, it was seen on this network in the last 7 days and
//!   its last [`SILENT_ROUNDS`] rounds got no answer, `Status` names it
//!   (`no_answer`), and the nearby search row asks to check that both
//!   laptops show the same time.
//! - **Logs:** fixed words and counts only, never an address, a key or a
//!   name; IPC `Status` shows the state and the last ten minutes' counts
//!   ([`counts`]), and the contacts asked for in vain.
//!
//! **Lab (debug builds only; a release build never reads them):**
//! `RAVEN_LAB_LAN_BEACON_PORT=<port>` replaces UDP 7420,
//! `RAVEN_LAB_LAN_BEACON_FAMILY=v4|v6` keeps one address family, and
//! `RAVEN_LAB_LAN_BEACON_BUS=<file>` replaces the network with a bus on this
//! computer: the file's first line names a directory where each node
//! registers `<random>.port` and "sends to the group" by sending to every
//! 127.0.0.1 port listed there. The file is read again every [`BUS_POLL`];
//! another directory is a network change. The bus's one interface is
//! loopback, where a loopback LAN listener counts.

use std::collections::{HashMap, HashSet, VecDeque};
use std::convert::Infallible;
use std::hash::Hash;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::Duration;

use futures::future::BoxFuture;
use futures::FutureExt;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use raven_core::identity::Identity;
use raven_core::ipc::BeaconCounts;
use raven_core::lan_beacon::{
    self as codec, DatagramKind, EpochKeys, PairKeys, BEACON_PORT, GROUP_V4, GROUP_V6, SLOTS,
};
use raven_core::outbox::OutboxCarrier;
use raven_core::security_events::Via;
use serde::Deserialize;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch, Notify};
use tokio::time::Instant;

use crate::lan_ifaces::{on_link_in, BeaconIf};
use crate::netutil;
use crate::p2p::FileStamp;
use crate::pair_seed::KeyUse;

/// A candidate is dialled for this long after it was found (§7)...
const CANDIDATE_TTL: Duration = Duration::from_secs(10 * 60);
/// ...and while it is this young, its contact is not asked for (§8).
const CANDIDATE_FRESH: Duration = Duration::from_secs(2 * 60);
/// Candidates kept per contact: one per interface and family, the newest.
const CANDIDATES_PER_PEER: usize = 4;
/// Candidates [`candidates`] gives at most (§9).
const CANDIDATES_DIALLED: usize = 2;
/// An answer counts this long after its query went out (§7).
const ANSWER_WINDOW: Duration = Duration::from_secs(3);
/// A query's or answer's first copy goes out a random time up to this after
/// it was made (§3, Phase 6b W-B3)...
const SEND_DELAY_MAX: Duration = Duration::from_millis(500);
/// ...and its second copy a random time in this range after the first:
/// Wi-Fi does not acknowledge multicast (§3).
const REPEAT_MIN: Duration = Duration::from_millis(100);
const REPEAT_MAX: Duration = Duration::from_millis(400);
/// Queries naming one contact are at least this far apart, the gap doubling
/// while they go unanswered up to [`PEER_GAP_MAX`] (§8)...
const PEER_GAP_MIN: Duration = Duration::from_secs(15);
const PEER_GAP_MAX: Duration = Duration::from_secs(10 * 60);
/// ...and for a user send at least this far apart.
const SEND_GAP: Duration = Duration::from_secs(2);
/// Rounds come from a bucket of this many...
const ROUND_BURST: u32 = 4;
/// ...refilled one per this (§8).
const ROUND_REFILL: Duration = Duration::from_secs(3);
/// Wants this close together share one round (§8).
const COALESCE: Duration = Duration::from_millis(300);
/// A want older than this when the task reads it is dropped (its source
/// asks again).
const WANT_STALE: Duration = Duration::from_secs(30);
/// Wants queued for the task at most; a full queue drops new ones.
const WANT_QUEUE: usize = 256;
/// A contact is answered at most once per this (§6).
const ANSWER_GAP: Duration = Duration::from_secs(2);
/// Queries per source address: a bucket of this many...
const SOURCE_BURST: u32 = 4;
/// ...refilled one per this (§6)...
const SOURCE_REFILL: Duration = Duration::from_secs(2);
/// ...and from all sources together a bucket of this many, ten a second.
const GLOBAL_BURST: u32 = 20;
const GLOBAL_REFILL: Duration = Duration::from_millis(100);
/// Sources tracked at most: one whose bucket is full again is forgotten
/// first, and a new source past that is over the limit.
const SOURCES_MAX: usize = 1024;
/// Answers checked against this node's queries: a bucket of this many,
/// refilled about thirty a second. Not a wire rule: it bounds the HMACs a
/// flood of 48-byte datagrams costs while a query of ours waits (a round
/// names at most 8 contacts on at most 8 interfaces and two families).
const CHECK_BURST: u32 = 64;
const CHECK_REFILL: Duration = Duration::from_millis(31);
/// Matched query nonces kept: at most this many, for [`REPLAY_TTL`] (§6).
const REPLAY_MAX: usize = 4096;
const REPLAY_TTL: Duration = Duration::from_secs(30 * 60);
/// A datagram seen again from the same source within this is a repeat
/// (or IPv4's group and broadcast copies): handled once, at no cost (§3).
const SEEN_TTL: Duration = Duration::from_secs(5);
const SEEN_MAX: usize = 1024;
/// The book holds at most this many contacts (§6).
const BOOK_MAX: usize = 1024;
/// The book's files are looked at no more often than this...
const BOOK_CHECK: Duration = Duration::from_secs(1);
/// ...and a book that could not be read is read again after this, changed
/// or not.
const BOOK_RETRY: Duration = Duration::from_secs(30);
/// A join round names at most this many contacts...
const JOIN_MAX: usize = 8;
/// ...that had an authenticated LAN link within this (§8).
const JOIN_AGE_MS: u64 = 7 * 24 * 60 * 60 * 1000;
/// After a change, the contacts with waiting deliveries wanted, at most
/// (§8).
const WAITING_MAX: usize = 64;
/// The interfaces are read again this often while deliveries wait...
const POLL_BUSY: Duration = Duration::from_secs(15);
/// ...and this often otherwise (§8).
const POLL_IDLE: Duration = Duration::from_secs(60);
/// The lab bus's file is read this often.
const BUS_POLL: Duration = Duration::from_secs(1);
/// While LAN is on and the LAN listener has no identity yet, it is looked
/// for this often.
const IDENTITY_POLL: Duration = Duration::from_secs(1);
/// After a receive error the next receive waits this long (no busy loop).
const RECV_ERROR_PAUSE: Duration = Duration::from_millis(100);
/// [`locate`] waits at most this long (§8: a user send), the wait a send
/// asks for ([`raven_core::lan_beacon::LOCATE_SEND_WAIT_MS`]).
pub(crate) const LOCATE_MAX: Duration =
    Duration::from_millis(raven_core::lan_beacon::LOCATE_SEND_WAIT_MS as u64);
// A user send's search outlasts one find in the send shape's worst case
// (Phase 6 review traffic-3): the round's gathering, the query's first copy
// lost and its second at the latest, the answer's first copy at the latest,
// and 200 ms for the round trip.
const _: () = assert!(
    LOCATE_MAX.as_millis()
        >= COALESCE.as_millis()
            + SEND_DELAY_MAX.as_millis()
            + REPEAT_MAX.as_millis()
            + SEND_DELAY_MAX.as_millis()
            + 200
);
/// A contact's queries matched this close together are one of its rounds: a
/// round goes out on every interface and family at once, and rounds naming
/// one contact are at least [`SEND_GAP`] apart (F11b).
const ROUND_SPAN: Duration = Duration::from_secs(1);
/// Rounds in a row in which a contact's queries match only at the epoch
/// before ours, or only at the one after, before its clock may be noted as
/// that far off (F11b), when one of them shows that much (review A-3).
const SKEW_ROUNDS: u32 = 3;
/// One beacon epoch in ms ([`codec::EPOCH_SECS`]).
const EPOCH_MS: u64 = codec::EPOCH_SECS * 1000;
/// Rounds in a row naming a contact that got no answer before `Status` names
/// it (F11b)...
const SILENT_ROUNDS: u32 = 2;
/// ...while a want for it is this young: its sources ask again at least every
/// 10 min while they wait (the outbox's longest retry wait, and
/// [`PEER_GAP_MAX`]).
const WANT_HELD: Duration = Duration::from_secs(11 * 60);
/// Contacts `Status` names as asked for in vain, at most.
const NO_ANSWER_MAX: usize = 8;
/// The lab bus's interface indexes start here: no real interface has one.
const BUS_INDEX: u32 = 0x4000_0000;
/// Receive buffer: any UDP datagram fits, so a long one is read whole and
/// dropped by its length (on Windows a datagram longer than the buffer fails
/// the receive itself).
const RECV_BUF: usize = 64 * 1024;

/// `BeaconCounts.state` words.
const STATE_ON: &str = "on";
const STATE_HELD: &str = "held";
const STATE_OFF: &str = "off";
const STATE_STARTING: &str = "starting";
const STATE_NO_INTERFACES: &str = "no-interfaces";
const STATE_PORT_BUSY: &str = "port-busy";
const STATE_UNAVAILABLE: &str = "unavailable";

// ── What the rest of the node uses ─────────────────────────────────────────

/// Why a contact is wanted ([`want`]): RAVEN_LAN_BEACON_V1 §8's sources.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Want {
    /// An outbox attempt in which a due object may use LAN, or an ACK owed
    /// to the contact.
    Outbox,
    /// Custody with the contact, while custody is live (a due custodian,
    /// `crate::custody`).
    Custody,
    /// A user send (IPC LanLocate): its queries may be [`SEND_GAP`] apart.
    Send,
}

/// Look for `peer` on the local network soon: a round names it within
/// [`COALESCE`] unless its interval, a fresh candidate or the round bucket
/// holds it back. Nothing while the task does not run; a full queue drops
/// the want.
pub(crate) fn want(peer: &[u8; 32], w: Want) {
    shared().want(peer, w, Instant::now());
}

/// Where `peer`'s LAN listener was found (§9): at most two dial strings,
/// IPv4 first and the newest first within a family, found in the last
/// [`CANDIDATE_TTL`] on an interface the task runs on now; an IPv6
/// link-local address keeps its zone ([`netutil::scoped_dial`]). Untrusted:
/// Noise XX and the RLB1 bind decide who answers there. The outbox dials
/// them first among the contact's LAN routes.
pub(crate) fn candidates(peer: &[u8; 32]) -> Vec<String> {
    shared().candidates(peer, Instant::now())
}

/// A dial to `dial`, one of `peer`'s candidates as [`candidates`] wrote it,
/// did not reach the contact: it is a candidate no longer (§7, "until a dial
/// to it fails"). Any other dial string is left alone.
pub(crate) fn dial_failed(peer: &[u8; 32], dial: &str) {
    shared().dial_failed(peer, dial);
}

/// A user send's search (IPC LanLocate): `peer`'s candidates now, or
/// wanted ([`Want::Send`]) and waited for up to `wait` (at most
/// [`LOCATE_MAX`]). Empty at once while the task does not run (the gate is
/// closed, LAN is off), and without waiting when `wait` is zero.
pub(crate) async fn locate(peer: &[u8; 32], wait: Duration) -> Vec<String> {
    shared().locate(peer, wait).await
}

/// This machine's network changed, or every network is gone (netwatch): the
/// task reads the interfaces again, drops what it found on interfaces now
/// gone, starts every contact's query interval over and sends a join round
/// (§8). Nothing while it does not run.
pub(crate) fn network_changed() {
    shared().changed.notify_one();
}

/// An authenticated link with `peer` (or its receipt came back): its query
/// interval starts over (§8). Nothing while the task does not run.
pub(crate) fn linked(peer: &[u8; 32]) {
    let shared = shared();
    if shared.running.load(Ordering::Relaxed) {
        let _ = shared.tx.try_send(Msg::Linked(*peer));
    }
}

/// Is `peer` asked for in vain now (F11b, as `Status` names it in
/// `no_answer`, without its cap): a want for it holds, it was on this
/// network in the last 7 days and its last [`SILENT_ROUNDS`] rounds got no
/// answer. The outbox's `lan_no_answer` reason (Phase 3 P3.23). False while
/// the task does not run.
pub(crate) fn asked_in_vain(peer: &[u8; 32]) -> bool {
    shared().is_silent(peer, Instant::now())
}

/// The state and the last ten minutes' counts, for IPC `Status`: words and
/// numbers only.
pub(crate) fn counts() -> BeaconCounts {
    shared().snapshot(Instant::now())
}

/// How many contacts were seen on this network in the last ten minutes, for
/// IPC `Status` (`raven status`, Phase 3 P3.C6): a beacon find still live
/// (found within [`CANDIDATE_TTL`], ten minutes, on an interface the task
/// runs on now), or an authenticated LAN link within
/// [`crate::delivery_paths::HERE_SPAN`] from or to an address on one of this
/// computer's networks now (loopback included: this computer). Each contact
/// once; a count, never who or where.
pub(crate) fn friends_here_10m() -> u32 {
    let mut here = shared().found_lately(Instant::now());
    for (peer, ip) in crate::delivery_paths::lan_linked_lately() {
        if !here.contains(&peer) && (ip.is_loopback() || crate::lan_ifaces::on_link(ip)) {
            here.push(peer);
        }
    }
    u32::try_from(here.len()).unwrap_or(u32::MAX)
}

/// The supervised task (`raven-node service`): idle for the life of the
/// process when the gate is closed; else it waits for LAN and the LAN
/// listener's identity, runs until LAN turns off and waits again.
pub(crate) async fn run(data_dir: PathBuf) -> Result<(), String> {
    let host: Arc<dyn Host> = Arc::new(NodeHost { data_dir });
    match run_with(
        raven_core::lan_beacon_live(),
        Arc::clone(shared()),
        host,
        Net::from_env(),
        StdRng::from_entropy(),
    )
    .await {}
}

// ── Debug-only lab overrides ────────────────────────────────────────────────

/// `RAVEN_LAB_LAN_BEACON_PORT`: the UDP port instead of [`BEACON_PORT`]
/// (1-65535); debug builds only.
fn lab_port() -> Option<u16> {
    raven_core::p2p_gate::lab_switch("RAVEN_LAB_LAN_BEACON_PORT")
        .and_then(|v| v.trim().parse::<u16>().ok())
        .filter(|p| *p != 0)
}

/// `RAVEN_LAB_LAN_BEACON_FAMILY=v4|v6`: one address family only; debug
/// builds only.
fn lab_family() -> Option<Family> {
    match raven_core::p2p_gate::lab_switch("RAVEN_LAB_LAN_BEACON_FAMILY")?
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "v4" => Some(Family::V4),
        "v6" => Some(Family::V6),
        _ => None,
    }
}

/// `RAVEN_LAB_LAN_BEACON_BUS=<file>`: the lab bus instead of the network;
/// debug builds only.
fn lab_bus() -> Option<PathBuf> {
    raven_core::p2p_gate::lab_switch("RAVEN_LAB_LAN_BEACON_BUS").map(PathBuf::from)
}

// ── Shared state ────────────────────────────────────────────────────────────

/// What other tasks tell the beacon task.
#[derive(Debug)]
enum Msg {
    /// A contact is wanted (`true`: for a user send), since.
    Want([u8; 32], bool, Instant),
    /// An authenticated link with the contact.
    Linked([u8; 32]),
}

/// Where a contact's LAN listener was found: a dial candidate (§9).
#[derive(Clone, Debug, PartialEq, Eq)]
struct Candidate {
    addr: SocketAddr,
    /// The interface it was found on.
    iface: u32,
    at: Instant,
}

#[derive(Default)]
struct Found {
    candidates: HashMap<[u8; 32], Vec<Candidate>>,
    /// The interfaces the task runs on now: a candidate on another is gone.
    ifaces: Vec<u32>,
}

impl Found {
    fn live(&self, c: &Candidate, now: Instant, ttl: Duration) -> bool {
        self.ifaces.contains(&c.iface) && now < c.at + ttl
    }
}

/// A count per minute over the last ten minutes.
#[derive(Clone, Copy, Default)]
struct Window([(u64, u32); 10]);

impl Window {
    fn add(&mut self, minute: u64) {
        let slot = &mut self.0[(minute % 10) as usize];
        if slot.0 != minute {
            *slot = (minute, 0);
        }
        slot.1 = slot.1.saturating_add(1);
    }

    fn total(&self, minute: u64) -> u32 {
        self.0
            .iter()
            .filter(|(m, _)| *m <= minute && minute - *m < 10)
            .fold(0, |sum, (_, n)| sum.saturating_add(*n))
    }
}

/// What a count is of.
#[derive(Clone, Copy, Debug)]
enum Count {
    /// A query this node sent (one per round, interface and family).
    Query,
    /// One of those that a contact answered.
    Answered,
    /// An answer this node sent.
    AnswerSent,
    /// A datagram dropped: another length, a source that is not local or
    /// on no interface, over a limit, or a replay.
    Dropped,
}

struct Counts {
    state: &'static str,
    interfaces: u32,
    echo_ok: bool,
    queries: Window,
    answered: Window,
    answers_sent: Window,
    dropped: Window,
}

/// What the beacon task shares with the rest of the node (production's is
/// [`shared`]; each test has its own).
struct Shared {
    tx: mpsc::Sender<Msg>,
    /// The task holds it while it lives.
    rx: tokio::sync::Mutex<mpsc::Receiver<Msg>>,
    /// The task runs (LAN is on and it has the identity): wants are taken.
    running: AtomicBool,
    found: Mutex<Found>,
    /// [`locate`] waits on it: something was found, or the task stopped.
    news: Notify,
    /// netwatch's changes ([`network_changed`]).
    changed: Notify,
    counts: Mutex<Counts>,
    /// Minute 0 of the counts.
    base: Instant,
    /// Contacts asked for in vain (F11b): since when, and until when a want
    /// for them is held.
    silent: Mutex<HashMap<[u8; 32], (Instant, Instant)>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The process's beacon state: `held` while the gate is closed, else
/// `starting` until the task says more.
fn shared() -> &'static Arc<Shared> {
    static SHARED: OnceLock<Arc<Shared>> = OnceLock::new();
    SHARED.get_or_init(|| {
        Shared::new(if raven_core::lan_beacon_live() {
            STATE_STARTING
        } else {
            STATE_HELD
        })
    })
}

impl Shared {
    fn new(state: &'static str) -> Arc<Shared> {
        let (tx, rx) = mpsc::channel(WANT_QUEUE);
        Arc::new(Shared {
            tx,
            rx: tokio::sync::Mutex::new(rx),
            running: AtomicBool::new(false),
            found: Mutex::new(Found::default()),
            news: Notify::new(),
            changed: Notify::new(),
            counts: Mutex::new(Counts {
                state,
                interfaces: 0,
                echo_ok: false,
                queries: Window::default(),
                answered: Window::default(),
                answers_sent: Window::default(),
                dropped: Window::default(),
            }),
            base: Instant::now(),
            silent: Mutex::new(HashMap::new()),
        })
    }

    fn want(&self, peer: &[u8; 32], w: Want, now: Instant) {
        if self.running.load(Ordering::Relaxed) {
            let _ = self.tx.try_send(Msg::Want(*peer, w == Want::Send, now));
        }
    }

    /// Set the state; whether it changed.
    fn set_state(&self, state: &'static str) -> bool {
        let mut counts = lock(&self.counts);
        let changed = counts.state != state;
        counts.state = state;
        changed
    }

    fn set_interfaces(&self, n: usize) {
        lock(&self.counts).interfaces = u32::try_from(n).unwrap_or(u32::MAX);
    }

    fn set_echo_ok(&self, ok: bool) {
        lock(&self.counts).echo_ok = ok;
    }

    fn minute(&self, now: Instant) -> u64 {
        now.saturating_duration_since(self.base).as_secs() / 60
    }

    fn note(&self, what: Count, now: Instant) {
        let minute = self.minute(now);
        let mut counts = lock(&self.counts);
        match what {
            Count::Query => counts.queries.add(minute),
            Count::Answered => counts.answered.add(minute),
            Count::AnswerSent => counts.answers_sent.add(minute),
            Count::Dropped => counts.dropped.add(minute),
        }
    }

    fn snapshot(&self, now: Instant) -> BeaconCounts {
        let minute = self.minute(now);
        let no_answer = self.no_answer(now);
        let counts = lock(&self.counts);
        BeaconCounts {
            state: counts.state.to_owned(),
            interfaces: counts.interfaces,
            echo_ok: counts.echo_ok,
            queries_10m: counts.queries.total(minute),
            answered_10m: counts.answered.total(minute),
            answers_sent_10m: counts.answers_sent.total(minute),
            dropped_10m: counts.dropped.total(minute),
            no_answer,
        }
    }

    /// The contacts asked for in vain whose want still holds at `now`, the
    /// newest first, at most [`NO_ANSWER_MAX`] (hex keys).
    fn no_answer(&self, now: Instant) -> Vec<String> {
        let silent = lock(&self.silent);
        let mut rows: Vec<(&[u8; 32], Instant)> = silent
            .iter()
            .filter(|(_, (_, until))| now < *until)
            .map(|(peer, (since, _))| (peer, *since))
            .collect();
        rows.sort_by(|(ka, a), (kb, b)| b.cmp(a).then(ka.cmp(kb)));
        rows.into_iter()
            .take(NO_ANSWER_MAX)
            .map(|(peer, _)| hex::encode(peer))
            .collect()
    }

    /// Is `peer` asked for in vain at `now` (its want still holds)?
    fn is_silent(&self, peer: &[u8; 32], now: Instant) -> bool {
        lock(&self.silent)
            .get(peer)
            .is_some_and(|(_, until)| now < *until)
    }

    /// `peer`'s last rounds got no answer at `now`, while a want for it
    /// holds until `until` (F11b). Kept since the first such verdict.
    fn set_silent(&self, peer: [u8; 32], now: Instant, until: Instant) {
        let mut silent = lock(&self.silent);
        if silent.len() >= BOOK_MAX && !silent.contains_key(&peer) {
            silent.retain(|_, (_, held)| now < *held);
            if silent.len() >= BOOK_MAX {
                return;
            }
        }
        let since = silent.get(&peer).map_or(now, |(since, _)| *since);
        silent.insert(peer, (since, until));
    }

    /// A new want for `peer`: if it is asked for in vain, that holds until
    /// `until` now.
    fn hold_silent(&self, peer: &[u8; 32], until: Instant) {
        if let Some((_, held)) = lock(&self.silent).get_mut(peer) {
            *held = until;
        }
    }

    /// `peer` answered, was heard or linked: no longer asked for in vain.
    fn clear_silent(&self, peer: &[u8; 32]) {
        lock(&self.silent).remove(peer);
    }

    /// A network change: nobody is asked for in vain on the new network yet.
    fn clear_all_silent(&self) {
        lock(&self.silent).clear();
    }

    /// Keep `c` as one of `peer`'s candidates (the newest per interface and
    /// family) and wake [`locate`].
    /// Keep `c` as one of `peer`'s candidates: `true` when its address is
    /// new (no live candidate of `peer`'s had it).
    fn add_candidate(&self, peer: [u8; 32], c: Candidate) -> bool {
        let new;
        {
            let mut found = lock(&self.found);
            if found.candidates.len() >= BOOK_MAX && !found.candidates.contains_key(&peer) {
                let ifaces = found.ifaces.clone();
                found.candidates.retain(|_, list| {
                    list.retain(|old| ifaces.contains(&old.iface) && c.at < old.at + CANDIDATE_TTL);
                    !list.is_empty()
                });
            }
            let list = found.candidates.entry(peer).or_default();
            new = !list
                .iter()
                .any(|old| old.addr == c.addr && c.at < old.at + CANDIDATE_TTL);
            list.retain(|old| {
                !(old.iface == c.iface && old.addr.is_ipv6() == c.addr.is_ipv6())
                    && c.at < old.at + CANDIDATE_TTL
            });
            list.push(c);
            if list.len() > CANDIDATES_PER_PEER {
                list.remove(0);
            }
        }
        self.news.notify_waiters();
        new
    }

    fn candidates(&self, peer: &[u8; 32], now: Instant) -> Vec<String> {
        let found = lock(&self.found);
        let mut live: Vec<&Candidate> = found
            .candidates
            .get(peer)
            .map(|list| {
                list.iter()
                    .filter(|c| found.live(c, now, CANDIDATE_TTL))
                    .collect()
            })
            .unwrap_or_default();
        live.sort_by_key(|c| (c.addr.is_ipv6(), std::cmp::Reverse(c.at)));
        live.into_iter()
            .take(CANDIDATES_DIALLED)
            .map(|c| netutil::scoped_dial(c.addr))
            .collect()
    }

    /// The contacts with a live candidate at `now` (found within
    /// [`CANDIDATE_TTL`] on an interface the task runs on now).
    fn found_lately(&self, now: Instant) -> Vec<[u8; 32]> {
        let found = lock(&self.found);
        found
            .candidates
            .iter()
            .filter(|(_, list)| list.iter().any(|c| found.live(c, now, CANDIDATE_TTL)))
            .map(|(peer, _)| *peer)
            .collect()
    }

    /// Forget `peer`'s candidate that [`Self::candidates`] wrote as `dial`.
    fn dial_failed(&self, peer: &[u8; 32], dial: &str) {
        let mut found = lock(&self.found);
        if let Some(list) = found.candidates.get_mut(peer) {
            list.retain(|c| netutil::scoped_dial(c.addr) != dial);
            if list.is_empty() {
                found.candidates.remove(peer);
            }
        }
    }

    /// Has `peer` a candidate young enough that it is not asked for (§8)?
    fn fresh(&self, peer: &[u8; 32], now: Instant) -> bool {
        let found = lock(&self.found);
        found
            .candidates
            .get(peer)
            .is_some_and(|list| list.iter().any(|c| found.live(c, now, CANDIDATE_FRESH)))
    }

    /// The task runs on these interfaces now: candidates on others go.
    fn set_ifaces(&self, live: &[u32]) {
        let mut found = lock(&self.found);
        found.ifaces = live.to_vec();
        found.candidates.retain(|_, list| {
            list.retain(|c| live.contains(&c.iface));
            !list.is_empty()
        });
    }

    /// A network or interface change: everything found before it goes
    /// (review A-2), on every interface. The address may be another host's
    /// on the new network (one numbered the same included, which netwatch
    /// reports with the interfaces unchanged), and while it stood it held
    /// back the query that finds the contact here.
    fn forget_found(&self) {
        lock(&self.found).candidates.clear();
    }

    /// The task stopped: everything it found goes, and so does everything
    /// it asked for in vain.
    fn clear(&self) {
        {
            let mut found = lock(&self.found);
            found.candidates.clear();
            found.ifaces.clear();
        }
        lock(&self.silent).clear();
        self.news.notify_waiters();
    }

    async fn locate(&self, peer: &[u8; 32], wait: Duration) -> Vec<String> {
        let deadline = Instant::now() + wait.min(LOCATE_MAX);
        let news = self.news.notified();
        tokio::pin!(news);
        news.as_mut().enable();
        let found = self.candidates(peer, Instant::now());
        if !found.is_empty() || wait.is_zero() || !self.running.load(Ordering::Relaxed) {
            return found;
        }
        self.want(peer, Want::Send, Instant::now());
        loop {
            if tokio::time::timeout_at(deadline, news.as_mut())
                .await
                .is_err()
            {
                return self.candidates(peer, Instant::now());
            }
            news.set(self.news.notified());
            news.as_mut().enable();
            let found = self.candidates(peer, Instant::now());
            if !found.is_empty() || !self.running.load(Ordering::Relaxed) {
                return found;
            }
        }
    }
}

// ── The node, as the task sees it ───────────────────────────────────────────

/// What tells that the book must be read again: the contact book, the block
/// list, the node policy (`raven lan verified-only`) and the pair seeds
/// (Phase 6b, `crate::pair_seed`), the contact book's reload generation,
/// which moves when the at-rest key arrives (privacy pack PP.4), and while
/// pair seeds are live the hour (a retired seed leaves the book within it).
pub(crate) type BookStamp = ([Option<FileStamp>; 4], u64, u64);

/// What the task needs from the rest of the node; tests give their own.
trait Host: Send + Sync {
    /// The LAN switch to wait on ([`crate::lan_direct::lan_watch`]).
    fn lan(&self) -> watch::Receiver<bool>;
    /// Whether LAN is on now.
    fn lan_on(&self) -> bool;
    /// The identity the LAN listener loaded.
    fn identity(&self) -> Option<Arc<Identity>>;
    /// Where the LAN listener is bound now; empty while it is not.
    fn listeners(&self) -> Vec<SocketAddr>;
    /// Raven's clock, in ms since the epoch (a lab clock in a debug build).
    fn now_ms(&self) -> u64;
    /// Is a datagram from `ip` from the local network (§0's rule)?
    fn is_local(&self, ip: IpAddr) -> bool;
    fn book_stamp(&self) -> BookStamp;
    /// The book's pair keys ([`load_book`]): blocking work.
    fn load_book(
        &self,
        identity: Arc<Identity>,
    ) -> BoxFuture<'static, Result<Vec<(PairKeys, KeyUse)>, String>>;
    /// The LAN link gate's check for `peer` from `src` (§6).
    fn admit(&self, peer: [u8; 32], src: IpAddr) -> BoxFuture<'static, bool>;
    /// The join round's contacts (§8), newest first.
    fn recent(&self, now_ms: u64) -> BoxFuture<'static, Vec<[u8; 32]>>;
    /// The contacts with waiting deliveries, oldest first, at most `limit`.
    fn waiting(&self, limit: usize) -> Vec<[u8; 32]>;
    /// `peer` was found (`moved`: at an address it was not found at
    /// lately): what waits for it is due now, and when it `moved` its
    /// custody fetch too.
    fn found(&self, peer: &[u8; 32], moved: bool);
    /// Owner decision OD-C7: something needs a contact found, so a join
    /// round may go: deliveries or ACKs wait (the outbox), custody rows or
    /// sealed letters wait for their recipients, custody handoff rows for
    /// their next hops, or meeting mode is on.
    fn need(&self, now_ms: u64) -> BoxFuture<'static, bool>;
    /// Where `peer` reached this node over an authenticated LAN link in the
    /// last 7 days (lan_seen), if it did (F11b).
    fn sighting(&self, peer: [u8; 32], now_ms: u64) -> BoxFuture<'static, Option<IpAddr>>;
    /// `peer`'s clock runs at least `ahead_ms` ahead of ours (behind when
    /// negative), past Raven's five-minute limit (F11b, review A-3; CP.7's
    /// clock notes).
    fn clock_skew(&self, peer: &[u8; 32], ahead_ms: i64);
    /// Phase 6b R1: did the stranger penalty box ban `ip` (at `now`)? Its
    /// queries then go unanswered.
    fn source_banned(&self, ip: IpAddr, now: Instant) -> bool;
    /// Phase 6b S22, R1: a query from `ip` was dropped as a replay of a
    /// matched one (`replay`), or over its source's rate limit.
    fn source_refused(&self, ip: IpAddr, replay: bool, now: Instant);
}

/// `raven-node service`'s: its profile, the LAN listener and switch, the
/// outbox and custody.
struct NodeHost {
    data_dir: PathBuf,
}

impl Host for NodeHost {
    fn lan(&self) -> watch::Receiver<bool> {
        crate::lan_direct::lan_watch()
    }

    fn lan_on(&self) -> bool {
        crate::lan_direct::lan_on()
    }

    fn identity(&self) -> Option<Arc<Identity>> {
        crate::lan_direct::listener_identity()
    }

    fn listeners(&self) -> Vec<SocketAddr> {
        crate::lan_direct::listener_addrs()
    }

    fn now_ms(&self) -> u64 {
        raven_core::clock::now_ms()
    }

    fn is_local(&self, ip: IpAddr) -> bool {
        raven_core::paths::lan_source_is_local(ip, crate::lan_ifaces::on_link)
    }

    fn book_stamp(&self) -> BookStamp {
        book_stamp(&self.data_dir)
    }

    fn load_book(
        &self,
        identity: Arc<Identity>,
    ) -> BoxFuture<'static, Result<Vec<(PairKeys, KeyUse)>, String>> {
        let dd = self.data_dir.clone();
        let seeds = crate::pair_seed::live();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || load_book(&dd, &identity, seeds))
                .await
                .map_err(|e| e.to_string())?
        })
    }

    fn admit(&self, peer: [u8; 32], src: IpAddr) -> BoxFuture<'static, bool> {
        let dd = self.data_dir.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                raven_core::lan_dispatch::link_admission(
                    &dd,
                    &peer,
                    raven_core::outbox::OutboxCarrier::Lan,
                    Some(src),
                )
                .is_ok()
            })
            .await
            .unwrap_or(false)
        })
    }

    fn recent(&self, now_ms: u64) -> BoxFuture<'static, Vec<[u8; 32]>> {
        let dd = self.data_dir.clone();
        // The gates are read here, not in the blocking pool.
        let custody = raven_core::custody_gate::CustodyGates::current().live;
        let letters = raven_core::friend_custody::letter_ops_served();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                // While custody is live, a custodian's join round also names
                // the recipients it holds mail for: a waking recipient
                // learns where to fetch it (Phase 3).
                let held = if custody {
                    held_contacts(&dd, letters, now_ms)
                } else {
                    Vec::new()
                };
                let recent =
                    raven_core::lan_seen::recent_lan_contacts(&dd, JOIN_MAX, JOIN_AGE_MS, now_ms);
                join_set(&held, &recent)
            })
            .await
            .unwrap_or_default()
        })
    }

    fn waiting(&self, limit: usize) -> Vec<[u8; 32]> {
        crate::outbox::waiting_peers(limit)
    }

    fn found(&self, peer: &[u8; 32], moved: bool) {
        crate::outbox::peer_routes_changed(peer);
        // A custodian found where it was found before has nothing new for
        // the fetcher (E2: a find per query made its fetch due at once).
        if moved {
            crate::custody::routes_changed(peer);
        }
    }

    fn need(&self, now_ms: u64) -> BoxFuture<'static, bool> {
        let waiting = !crate::outbox::waiting_peers(1).is_empty();
        let meeting = crate::lan_meeting::meeting_on(now_ms);
        // Custody handoff rows waiting for their next hops are a need too
        // (review cross-3; the forwarder wants each next hop it dials).
        let forwarding = !crate::custody::forward_hops().is_empty();
        // The letter gate is read here, not in the blocking pool.
        let letters = raven_core::friend_custody::letter_ops_served();
        join_need(
            self.data_dir.clone(),
            now_ms,
            waiting || meeting || forwarding,
            letters,
        )
    }

    fn sighting(&self, peer: [u8; 32], now_ms: u64) -> BoxFuture<'static, Option<IpAddr>> {
        let dd = self.data_dir.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                raven_core::lan_seen::seen_within(&dd, &peer, JOIN_AGE_MS, now_ms).map(|s| s.ip())
            })
            .await
            .unwrap_or(None)
        })
    }

    fn clock_skew(&self, peer: &[u8; 32], ahead_ms: i64) {
        crate::clock_notes::beacon_skew(peer, ahead_ms);
    }

    fn source_banned(&self, ip: IpAddr, now: Instant) -> bool {
        crate::security::beacon_banned(ip, now.into_std())
    }

    fn source_refused(&self, ip: IpAddr, replay: bool, now: Instant) {
        crate::security::beacon_refused(ip, replay, now.into_std());
    }
}

/// Owner decision OD-C7 (§8; re-checked by Phase 6b W-B3, people study
/// M13): a join round may go when `local_need` (deliveries or ACKs wait in
/// the outbox, meeting mode is on, or custody handoff rows wait for their
/// next hops) or, else, when the profile at `dd` holds mail waiting for its
/// recipients ([`holds_mail`]: custody rows and, with `letters`, sealed
/// letters). No custody store is no row (nothing is created); one that
/// cannot be read is no need (nothing is announced).
fn join_need(
    dd: PathBuf,
    now_ms: u64,
    local_need: bool,
    letters: bool,
) -> BoxFuture<'static, bool> {
    if local_need {
        return Box::pin(std::future::ready(true));
    }
    Box::pin(async move {
        tokio::task::spawn_blocking(move || holds_mail(&dd, letters, now_ms))
            .await
            .unwrap_or(false)
    })
}

/// Blocking: the recipients this custodian holds custody mail for
/// ([`raven_core::friend_custody::held_recipients`]), then (`letters`: it
/// serves the letter ops) those it holds sealed letters for (review
/// cross-1: a letter waits up to 7 days, far longer than an object), newest
/// deposit first each.
fn held_mail_for(dd: &Path, letters: bool, now_ms: u64) -> Vec<[u8; 32]> {
    let mut held = raven_core::friend_custody::held_recipients(dd, now_ms).unwrap_or_default();
    if letters {
        held.extend(
            raven_core::friend_custody::held_letter_recipients(dd, now_ms).unwrap_or_default(),
        );
    }
    held
}

/// Blocking ([`Host::need`]): this custodian holds mail for someone
/// ([`held_mail_for`]). No custody store is no row (nothing is created); one
/// that cannot be read is no need (nothing is announced).
fn holds_mail(dd: &Path, letters: bool, now_ms: u64) -> bool {
    !held_mail_for(dd, letters, now_ms).is_empty()
}

/// Blocking: the recipients this custodian holds custody mail (and, with
/// `letters`, sealed letters) for that are verified, unblocked contacts,
/// newest deposit first ([`held_mail_for`]). No store, or one that cannot be
/// read, holds mail for nobody.
fn held_contacts(dd: &Path, letters: bool, now_ms: u64) -> Vec<[u8; 32]> {
    let held = held_mail_for(dd, letters, now_ms);
    if held.is_empty() {
        return held;
    }
    let Ok(book) = raven_core::outbox::pinned_unblocked_contacts(dd) else {
        return Vec::new();
    };
    held.into_iter().filter(|p| book.contains(p)).collect()
}

/// A join round's contacts (§8): the recipients this custodian holds mail
/// for (`held`), then the contacts seen on the LAN lately (`recent`), each
/// once, at most [`JOIN_MAX`] in all.
fn join_set(held: &[[u8; 32]], recent: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut out: Vec<[u8; 32]> = Vec::new();
    for peer in held.iter().chain(recent) {
        if out.len() == JOIN_MAX {
            break;
        }
        if !out.contains(peer) {
            out.push(*peer);
        }
    }
    out
}

/// The files [`load_book`] reads, as one stamp (the RLK1 link knock keeps
/// its own book by it too, `crate::link_knock`).
pub(crate) fn book_stamp(dd: &Path) -> BookStamp {
    use crate::p2p::file_stamp;
    let (seeds, hour) = crate::pair_seed::stamp(dd);
    (
        [
            file_stamp(&dd.join(raven_core::contact_book::CONTACTS_FILE)),
            file_stamp(&raven_core::chat_history::blocked_path(dd)),
            file_stamp(&raven_core::node_policy::policy_path(dd)),
            seeds,
        ],
        raven_core::contact_book::reload_generation(dd),
        if crate::pair_seed::live() { hour } else { 0 },
    )
}

/// The book (§6) from the profile: an unreadable contact book or block list
/// is an error (nobody is named or answered then), and an unreadable policy
/// is verified-only. Each contact's key sets come from its pair seeds while
/// they are live (`seeds`, Phase 6b): the one it is asked with and the
/// others it may ask with.
fn load_book(
    dd: &Path,
    identity: &Identity,
    seeds: bool,
) -> Result<Vec<(PairKeys, KeyUse)>, String> {
    let seeds = crate::pair_seed::book(dd, seeds);
    Ok(keys_of(identity, book_peers(dd)?, &seeds))
}

/// The contacts of the book (§6) in its order, before any key is made
/// ([`book_order`]); the RLK1 link knock tries the same contacts on a
/// connection from the local network (`crate::link_knock`, design B §3).
pub(crate) fn book_peers(dd: &Path) -> Result<Vec<[u8; 32]>, String> {
    book_peers_with(dd, false)
}

/// [`book_peers`], with the pinned (verified) contacts alone when
/// `pinned_only`: the RLK1 listener's book for a connection its contact gate
/// answers only for a verified contact (Internet direct, and LAN from beyond
/// the local network: `raven_core::lan_dispatch::link_admission`), so an
/// unverified contact's knock there is a stranger's (`crate::link_knock`).
pub(crate) fn book_peers_with(dd: &Path, pinned_only: bool) -> Result<Vec<[u8; 32]>, String> {
    #[derive(Deserialize)]
    struct Row {
        #[serde(default)]
        pub_hex: String,
        #[serde(default)]
        pinned: bool,
    }
    let rows: Vec<Row> = raven_core::contact_book::read_rows(dd)?.unwrap_or_default();
    let blocks = raven_core::chat_history::BlockList::load_checked(dd)?;
    let verified_only = raven_core::node_policy::lan_verified_only(dd);
    Ok(book_order(
        rows.iter().map(|r| (r.pub_hex.as_str(), r.pinned)),
        |key| blocks.is_blocked(key),
        verified_only || pinned_only,
    ))
}

/// The book's pair keys from the contact book's `(key, pinned)` rows
/// ([`book_order`]), at most [`BOOK_MAX`]. A key the beacon cannot use
/// ([`codec::pair_keys`]'s checks) is left out. The scripted hosts' book.
#[cfg(test)]
fn book_of<'a>(
    identity: &Identity,
    rows: impl Iterator<Item = (&'a str, bool)>,
    blocked: impl Fn(&str) -> bool,
    verified_only: bool,
) -> Vec<PairKeys> {
    keys_of(
        identity,
        book_order(rows, blocked, verified_only),
        &raven_core::pair_seed::SeedBook::default(),
    )
    .into_iter()
    .map(|(keys, _)| keys)
    .collect()
}

/// The key sets of `peers`, in order, at most [`BOOK_MAX`] contacts, from
/// their pair seeds in `seeds` (Phase 6b: up to three each; the root alone
/// without seeds); a key the beacon cannot use is left out.
fn keys_of(
    identity: &Identity,
    peers: Vec<[u8; 32]>,
    seeds: &raven_core::pair_seed::SeedBook,
) -> Vec<(PairKeys, KeyUse)> {
    peers
        .into_iter()
        .filter_map(|key| {
            crate::pair_seed::key_sets(identity, &key, seeds, codec::pair_keys_from).ok()
        })
        .take(BOOK_MAX)
        .flatten()
        .collect()
}

/// The book's contacts from the contact book's `(key, pinned)` rows: each
/// key once (pinned only if every row of it is, as the delivery planner
/// reads it), never a blocked one, pinned ones only while `verified_only`
/// holds, the pinned ones first.
fn book_order<'a>(
    rows: impl Iterator<Item = (&'a str, bool)>,
    blocked: impl Fn(&str) -> bool,
    verified_only: bool,
) -> Vec<[u8; 32]> {
    let mut keys: Vec<([u8; 32], bool)> = Vec::new();
    let mut at: HashMap<[u8; 32], usize> = HashMap::new();
    for (key_hex, pinned) in rows {
        let Some(key) = hex::decode(key_hex.trim())
            .ok()
            .and_then(|k| <[u8; 32]>::try_from(k).ok())
        else {
            continue;
        };
        match at.get(&key) {
            Some(&i) => keys[i].1 &= pinned,
            None => {
                at.insert(key, keys.len());
                keys.push((key, pinned));
            }
        }
    }
    keys.retain(|(key, pinned)| !blocked(&hex::encode(key)) && (*pinned || !verified_only));
    keys.sort_by_key(|(_, pinned)| !pinned);
    keys.into_iter().map(|(key, _)| key).collect()
}

// ── Sockets ─────────────────────────────────────────────────────────────────

/// One address family (the lab's `RAVEN_LAB_LAN_BEACON_FAMILY`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Family {
    V4,
    V6,
}

/// One datagram out on interface `index`: to the IPv4 group and the subnet
/// broadcast address, or (`v6`) to the IPv6 group.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Out {
    index: u32,
    v6: bool,
    bytes: Vec<u8>,
}

/// How a query or an answer goes out (§3; Phase 6b W-B3, people study M13):
/// with a random tail, its first copy a random delay after it was made and
/// its second a random gap after the first. The receiver's rules do not
/// depend on it.
#[derive(Clone, Copy, Debug)]
struct Shape {
    /// A random tail of 0..=31 bytes on a query, 0..=15 on an answer.
    tails: bool,
    /// The first copy's delay, drawn from this range (ms granularity).
    delay: (Duration, Duration),
    /// The second copy's gap after the first, drawn from this range.
    repeat: (Duration, Duration),
}

impl Shape {
    /// The amended v1: tails, 0-500 ms, then 100-400 ms.
    const V1: Shape = Shape {
        tails: true,
        delay: (Duration::ZERO, SEND_DELAY_MAX),
        repeat: (REPEAT_MIN, REPEAT_MAX),
    };
    /// Tests about rounds, limits and answers: the shape before the
    /// amendment (no tail, at once, the second copy 250 ms on), so their
    /// times stay exact. The V1 shape has tests of its own.
    #[cfg(test)]
    const FIXED: Shape = Shape {
        tails: false,
        delay: (Duration::ZERO, Duration::ZERO),
        repeat: (Duration::from_millis(250), Duration::from_millis(250)),
    };

    /// `datagram` as it goes on the wire.
    fn wire(&self, rng: &mut StdRng, datagram: &[u8]) -> Vec<u8> {
        if self.tails {
            codec::with_tail(rng, datagram)
        } else {
            datagram.to_vec()
        }
    }

    /// A first copy's delay.
    fn delay(&self, rng: &mut StdRng) -> Duration {
        draw(rng, self.delay)
    }

    /// A second copy's gap after the first.
    fn gap(&self, rng: &mut StdRng) -> Duration {
        draw(rng, self.repeat)
    }
}

/// A time in `(min, max)`, uniform at ms granularity (no draw when they are
/// equal).
fn draw(rng: &mut StdRng, (min, max): (Duration, Duration)) -> Duration {
    let (min_ms, max_ms) = (min.as_millis() as u64, max.as_millis() as u64);
    if max_ms <= min_ms {
        return min;
    }
    Duration::from_millis(rng.gen_range(min_ms..=max_ms))
}

/// A datagram due to go out at `at`: a first copy (`again`: its second
/// follows a [`Shape::gap`] later) or a second.
struct Due {
    at: Instant,
    out: Out,
    again: bool,
}

/// Where the datagrams go: UDP on this computer's interfaces, the lab bus,
/// or (tests) a fake.
enum Net {
    Udp {
        port: u16,
        family: Option<Family>,
    },
    Bus {
        file: PathBuf,
        /// The directory the file named at the last read, and how many
        /// times it changed (the bus interface's index moves with it).
        dir: Option<PathBuf>,
        generation: u32,
    },
    #[cfg(test)]
    Fake(FakeNet),
}

impl Net {
    /// The lab bus, or UDP on the lab port and family, in a debug build that
    /// sets them; else UDP on [`BEACON_PORT`], both families.
    fn from_env() -> Net {
        match lab_bus() {
            Some(file) => Net::Bus {
                file,
                dir: None,
                generation: 0,
            },
            None => Net::Udp {
                port: lab_port().unwrap_or(BEACON_PORT),
                family: lab_family(),
            },
        }
    }

    fn is_bus(&self) -> bool {
        matches!(self, Net::Bus { .. })
    }

    /// The interfaces to run on now ([`crate::lan_ifaces::refresh`]; the
    /// bus reads its file: another directory is another interface).
    fn ifaces(&mut self) -> Vec<BeaconIf> {
        match self {
            Net::Udp { family, .. } => keep_family(&crate::lan_ifaces::refresh(), *family),
            Net::Bus {
                file,
                dir,
                generation,
            } => {
                let named = std::fs::read_to_string(file).ok().and_then(|text| {
                    let first = text.lines().next()?.trim().to_owned();
                    (!first.is_empty()).then(|| PathBuf::from(first))
                });
                if named != *dir {
                    *dir = named;
                    *generation = generation.wrapping_add(1);
                }
                match dir {
                    Some(_) => vec![bus_iface(*generation)],
                    None => Vec::new(),
                }
            }
            #[cfg(test)]
            Net::Fake(fake) => lock(&fake.ifaces).clone(),
        }
    }

    /// The sockets for `ifaces` (none for none).
    fn open(&self, ifaces: &[BeaconIf]) -> io::Result<Io> {
        if ifaces.is_empty() {
            return Ok(Io::Closed);
        }
        match self {
            Net::Udp { port, .. } => UdpIo::open(ifaces, *port).map(Io::Udp),
            Net::Bus { dir: Some(dir), .. } => BusIo::open(dir).map(Io::Bus),
            Net::Bus { dir: None, .. } => Ok(Io::Closed),
            #[cfg(test)]
            Net::Fake(fake) => Ok(Io::Fake(fake.open())),
        }
    }

    /// How long until the interfaces are read again.
    fn poll_gap(&self, waiting: bool) -> Duration {
        match self {
            Net::Bus { .. } => BUS_POLL,
            _ if waiting => POLL_BUSY,
            _ => POLL_IDLE,
        }
    }
}

/// `ifaces` with one family only (the other's address left out), and those
/// left with none dropped.
fn keep_family(ifaces: &[BeaconIf], family: Option<Family>) -> Vec<BeaconIf> {
    ifaces
        .iter()
        .cloned()
        .filter_map(|mut i| {
            match family {
                Some(Family::V4) => i.v6_ll = None,
                Some(Family::V6) => i.v4 = None,
                None => {}
            }
            (i.v4.is_some() || i.v6_ll.is_some()).then_some(i)
        })
        .collect()
}

/// The lab bus's one interface: loopback, under an index that moves with
/// the bus directory (so what was found on the old bus goes).
fn bus_iface(generation: u32) -> BeaconIf {
    BeaconIf {
        index: BUS_INDEX + (generation & 0xffff),
        zone: "bus".into(),
        v4: Some((Ipv4Addr::LOCALHOST, 8, None)),
        v4_prefixes: vec![(Ipv4Addr::new(127, 0, 0, 0), 8)],
        v6_ll: None,
        v6_prefixes: Vec::new(),
    }
}

/// The open sockets.
enum Io {
    /// None: no interface, or they could not be opened.
    Closed,
    Udp(UdpIo),
    Bus(BusIo),
    #[cfg(test)]
    Fake(FakeIo),
}

impl Io {
    fn is_closed(&self) -> bool {
        matches!(self, Io::Closed)
    }

    /// Send `out` (best effort: UDP, a full buffer drops it).
    fn send(&self, out: &Out, ifaces: &[BeaconIf]) {
        match self {
            Io::Closed => {}
            Io::Udp(udp) => udp.send(out, ifaces),
            Io::Bus(bus) => bus.send(&out.bytes),
            #[cfg(test)]
            Io::Fake(fake) => fake.send(out),
        }
    }

    /// The next datagram and where it came from.
    async fn recv(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        match self {
            Io::Closed => std::future::pending().await,
            Io::Udp(udp) => udp.recv(buf).await,
            Io::Bus(bus) => bus.socket.recv_from(buf).await,
            #[cfg(test)]
            Io::Fake(fake) => fake.recv(buf).await,
        }
    }
}

/// The real sockets (§3).
struct UdpIo {
    port: u16,
    recv4: Option<UdpSocket>,
    recv6: Option<UdpSocket>,
    /// One per interface and family: (index, IPv6, socket).
    send: Vec<(u32, bool, UdpSocket)>,
}

impl UdpIo {
    /// Receive sockets for the families `ifaces` have, joined to the groups
    /// on each, and a send socket per interface and family. The IPv4 port
    /// held exclusively by another program is an error (`port-busy`); an
    /// IPv6 one that cannot be opened beside IPv4 leaves IPv4 alone, and an
    /// interface where a join or a send socket fails is skipped.
    fn open(ifaces: &[BeaconIf], port: u16) -> io::Result<UdpIo> {
        let recv4 = if ifaces.iter().any(|i| i.v4.is_some()) {
            Some(recv_socket(SocketAddr::from((
                Ipv4Addr::UNSPECIFIED,
                port,
            )))?)
        } else {
            None
        };
        let recv6 = if ifaces.iter().any(|i| i.v6_ll.is_some()) {
            match recv_socket(SocketAddr::from((Ipv6Addr::UNSPECIFIED, port))) {
                Ok(socket) => Some(socket),
                Err(_) if recv4.is_some() => None,
                Err(e) => return Err(e),
            }
        } else {
            None
        };
        let mut send = Vec::new();
        for i in ifaces {
            if let (Some(recv), Some((ip, _, _))) = (&recv4, i.v4) {
                if recv.join_multicast_v4(GROUP_V4, ip).is_ok() {
                    if let Ok(socket) = send_socket_v4(ip) {
                        send.push((i.index, false, socket));
                    }
                }
            }
            if let (Some(recv), Some(ll)) = (&recv6, i.v6_ll) {
                if recv.join_multicast_v6(&GROUP_V6, i.index).is_ok() {
                    if let Ok(socket) = send_socket_v6(ll, i.index) {
                        send.push((i.index, true, socket));
                    }
                }
            }
        }
        Ok(UdpIo {
            port,
            recv4,
            recv6,
            send,
        })
    }

    fn send(&self, out: &Out, ifaces: &[BeaconIf]) {
        let Some((_, _, socket)) = self
            .send
            .iter()
            .find(|(index, v6, _)| *index == out.index && *v6 == out.v6)
        else {
            return;
        };
        if out.v6 {
            let group = SocketAddrV6::new(GROUP_V6, self.port, 0, out.index);
            let _ = socket.try_send_to(&out.bytes, group.into());
            return;
        }
        let _ = socket.try_send_to(&out.bytes, SocketAddr::from((GROUP_V4, self.port)));
        let broadcast = ifaces
            .iter()
            .find(|i| i.index == out.index)
            .and_then(|i| i.v4)
            .and_then(|(_, _, broadcast)| broadcast);
        if let Some(broadcast) = broadcast {
            let _ = socket.try_send_to(&out.bytes, SocketAddr::from((broadcast, self.port)));
        }
    }

    async fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        loop {
            let socket = tokio::select! {
                ready = readable(&self.recv4) => { ready?; self.recv4.as_ref() }
                ready = readable(&self.recv6) => { ready?; self.recv6.as_ref() }
            };
            let Some(socket) = socket else { continue };
            match socket.try_recv_from(buf) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                got => return got,
            }
        }
    }
}

/// `socket` has a datagram; never for no socket.
async fn readable(socket: &Option<UdpSocket>) -> io::Result<()> {
    match socket {
        Some(socket) => socket.readable().await,
        None => std::future::pending().await,
    }
}

/// A receive socket on `at` (§3): IPv6 only for IPv6, SO_REUSEADDR (and
/// SO_REUSEPORT on macOS and the BSDs) so that every profile on this
/// computer gets every datagram, and on Linux only the groups it joins.
fn recv_socket(at: SocketAddr) -> io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(Domain::for_address(at), Type::DGRAM, Some(Protocol::UDP))?;
    if at.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_reuse_address(true)?;
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    socket.set_reuse_port(true)?;
    // Best effort: an older kernel without the IPv6 option still works,
    // with datagrams of other groups dropped by length or tag.
    #[cfg(target_os = "linux")]
    let _ = if at.is_ipv6() {
        socket.set_multicast_all_v6(false)
    } else {
        socket.set_multicast_all_v4(false)
    };
    socket.set_nonblocking(true)?;
    socket.bind(&at.into())?;
    UdpSocket::from_std(socket.into())
}

/// The IPv4 send socket of the interface with address `ip`.
fn send_socket_v4(ip: Ipv4Addr) -> io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_multicast_if_v4(&ip)?;
    socket.set_multicast_ttl_v4(1)?;
    socket.set_multicast_loop_v4(true)?;
    socket.set_broadcast(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&SocketAddr::from((ip, 0)).into())?;
    UdpSocket::from_std(socket.into())
}

/// The IPv6 send socket of the interface `index` with link-local address
/// `ll`.
fn send_socket_v6(ll: Ipv6Addr, index: u32) -> io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_only_v6(true)?;
    socket.set_multicast_if_v6(index)?;
    socket.set_multicast_hops_v6(1)?;
    socket.set_multicast_loop_v6(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&SocketAddr::V6(SocketAddrV6::new(ll, 0, 0, index)).into())?;
    UdpSocket::from_std(socket.into())
}

/// The lab bus (debug `RAVEN_LAB_LAN_BEACON_BUS`): one loopback socket,
/// registered in the bus directory while it is open.
struct BusIo {
    socket: UdpSocket,
    dir: PathBuf,
    /// This node's `<random>.port` in `dir`.
    entry: PathBuf,
}

impl BusIo {
    fn open(dir: &Path) -> io::Result<BusIo> {
        std::fs::create_dir_all(dir)?;
        let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        socket.set_nonblocking(true)?;
        let port = socket.local_addr()?.port();
        let entry = dir.join(format!("{:016x}.port", rand::random::<u64>()));
        std::fs::write(&entry, format!("{port}\n"))?;
        Ok(BusIo {
            socket: UdpSocket::from_std(socket)?,
            dir: dir.to_path_buf(),
            entry,
        })
    }

    /// "To the group": to every port registered on the bus, this node's own
    /// included (its echo).
    fn send(&self, bytes: &[u8]) {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_none_or(|e| e != "port") {
                continue;
            }
            let port = std::fs::read_to_string(&path)
                .ok()
                .and_then(|text| text.trim().parse::<u16>().ok());
            if let Some(port) = port.filter(|p| *p != 0) {
                let _ = self
                    .socket
                    .try_send_to(bytes, SocketAddr::from((Ipv4Addr::LOCALHOST, port)));
            }
        }
    }
}

impl Drop for BusIo {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.entry);
    }
}

/// Tests: a datagram for the fake receive side, and where it came from.
#[cfg(test)]
type Datagram = (Vec<u8>, SocketAddr);

/// Tests: the interfaces, what was sent and the open sockets of a fake
/// network.
#[cfg(test)]
#[derive(Clone, Default)]
struct FakeNet {
    ifaces: Arc<Mutex<Vec<BeaconIf>>>,
    sent: Arc<Mutex<Vec<Out>>>,
    /// Fakes open now, and opened in all.
    open: Arc<std::sync::atomic::AtomicUsize>,
    opened: Arc<std::sync::atomic::AtomicUsize>,
    /// Delivers to the open fake.
    inbox: Arc<Mutex<Option<mpsc::UnboundedSender<Datagram>>>>,
}

#[cfg(test)]
impl FakeNet {
    fn open(&self) -> FakeIo {
        let (tx, rx) = mpsc::unbounded_channel();
        *lock(&self.inbox) = Some(tx);
        self.open.fetch_add(1, Ordering::SeqCst);
        self.opened.fetch_add(1, Ordering::SeqCst);
        FakeIo {
            net: self.clone(),
            rx,
        }
    }
}

#[cfg(test)]
struct FakeIo {
    net: FakeNet,
    rx: mpsc::UnboundedReceiver<Datagram>,
}

#[cfg(test)]
impl FakeIo {
    fn send(&self, out: &Out) {
        lock(&self.net.sent).push(out.clone());
    }

    async fn recv(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        match self.rx.recv().await {
            Some((bytes, from)) => {
                let n = bytes.len().min(buf.len());
                buf[..n].copy_from_slice(&bytes[..n]);
                Ok((n, from))
            }
            None => std::future::pending().await,
        }
    }
}

#[cfg(test)]
impl Drop for FakeIo {
    fn drop(&mut self) {
        self.net.open.fetch_sub(1, Ordering::SeqCst);
    }
}

// ── The task ────────────────────────────────────────────────────────────────

/// The task with its gate (`live`), state, node, network and randomness.
async fn run_with(
    live: bool,
    shared: Arc<Shared>,
    host: Arc<dyn Host>,
    mut net: Net,
    mut rng: StdRng,
) -> Infallible {
    if !live {
        shared.set_state(STATE_HELD);
        return std::future::pending().await;
    }
    let mut wants = shared.rx.lock().await;
    let mut lan = host.lan();
    loop {
        let identity = wait_on(&shared, host.as_ref(), &mut lan).await;
        // A change noted before this start is part of it.
        let _ = shared.changed.notified().now_or_never();
        let now = Instant::now();
        let ifaces = net.ifaces();
        let mut io = open_io(&net, &ifaces, &shared);
        let mut st = State::new(
            Arc::clone(&host),
            Arc::clone(&shared),
            identity,
            net.is_bus(),
            StdRng::from_rng(&mut rng).unwrap_or_else(|_| StdRng::from_entropy()),
            Shape::V1,
            now,
        );
        shared.running.store(true, Ordering::Relaxed);
        st.start(ifaces, now).await;
        let mut poll_at = now + net.poll_gap(!host.waiting(1).is_empty());
        let mut buf = vec![0u8; RECV_BUF];
        loop {
            // A round or a second copy due (none: the branch is off).
            let timer = st.next_at();
            let due = timer.unwrap_or_else(Instant::now);
            tokio::select! {
                Some(msg) = wants.recv() => st.on_message(msg, Instant::now()).await,
                got = io.recv(&mut buf) => match got {
                    Ok((n, from)) => st.on_datagram(&buf[..n], from, &io, Instant::now()).await,
                    // Some systems report a send to a closed port on the next
                    // receive: nothing to do but not spin.
                    Err(_) => tokio::time::sleep(RECV_ERROR_PAUSE).await,
                },
                () = tokio::time::sleep_until(due), if timer.is_some() => {
                    st.on_timer(&io, Instant::now()).await;
                }
                () = tokio::time::sleep_until(poll_at) => {
                    let now = Instant::now();
                    let ifaces = net.ifaces();
                    if ifaces != st.ifaces {
                        drop(io);
                        io = open_io(&net, &ifaces, &shared);
                        st.changed(ifaces, now).await;
                    } else if io.is_closed() && !ifaces.is_empty() {
                        // The port was busy: once it opens, as at a start.
                        io = open_io(&net, &ifaces, &shared);
                        if !io.is_closed() {
                            st.start(ifaces, now).await;
                        }
                    }
                    poll_at = now + net.poll_gap(!host.waiting(1).is_empty());
                }
                () = shared.changed.notified() => {
                    let now = Instant::now();
                    let ifaces = net.ifaces();
                    if ifaces != st.ifaces || io.is_closed() {
                        drop(io);
                        io = open_io(&net, &ifaces, &shared);
                    }
                    st.changed(ifaces, now).await;
                    poll_at = now + net.poll_gap(!host.waiting(1).is_empty());
                }
                () = lan_off(&mut lan) => break,
            }
        }
        // LAN is off: the sockets close (the groups are left with them) and
        // what was found goes.
        shared.running.store(false, Ordering::Relaxed);
        drop(io);
        shared.clear();
        shared.set_echo_ok(false);
        shared.set_interfaces(0);
        if shared.set_state(STATE_OFF) {
            eprintln!("raven-node lan_beacon: off");
        }
    }
}

/// Until LAN is on and the LAN listener has loaded the identity (`off` and
/// `starting` meanwhile): that identity.
async fn wait_on(
    shared: &Shared,
    host: &dyn Host,
    lan: &mut watch::Receiver<bool>,
) -> Arc<Identity> {
    loop {
        if *lan.borrow_and_update() {
            if let Some(identity) = host.identity() {
                return identity;
            }
            shared.set_state(STATE_STARTING);
            tokio::select! {
                Ok(()) = lan.changed() => {}
                () = tokio::time::sleep(IDENTITY_POLL) => {}
            }
        } else {
            shared.set_state(STATE_OFF);
            if lan.changed().await.is_err() {
                // The switch is gone (a test's): it stays off.
                std::future::pending::<()>().await;
            }
        }
    }
}

/// Until LAN turns off; never when the switch is gone (a test's).
async fn lan_off(lan: &mut watch::Receiver<bool>) {
    if lan.wait_for(|on| !*on).await.is_err() {
        std::future::pending::<()>().await;
    }
}

/// The sockets for `ifaces`, and the state they give (one line when it
/// changes; counts and fixed words only).
fn open_io(net: &Net, ifaces: &[BeaconIf], shared: &Shared) -> Io {
    let (io, state) = match net.open(ifaces) {
        Ok(io) if io.is_closed() => (io, STATE_NO_INTERFACES),
        Ok(io) => (io, STATE_ON),
        Err(e) if e.kind() == io::ErrorKind::AddrInUse => (Io::Closed, STATE_PORT_BUSY),
        Err(e) => {
            if shared.set_state(STATE_UNAVAILABLE) {
                eprintln!(
                    "raven-node lan_beacon: sockets unavailable ({}); trying again",
                    e.kind()
                );
            }
            (Io::Closed, STATE_UNAVAILABLE)
        }
    };
    let changed = shared.set_state(state);
    shared.set_interfaces(if state == STATE_ON { ifaces.len() } else { 0 });
    match state {
        STATE_ON => eprintln!(
            "raven-node lan_beacon: on ({} {})",
            ifaces.len(),
            if ifaces.len() == 1 {
                "interface"
            } else {
                "interfaces"
            }
        ),
        STATE_NO_INTERFACES if changed => {
            eprintln!("raven-node lan_beacon: no LAN interface; waiting for one")
        }
        STATE_PORT_BUSY if changed => eprintln!(
            "raven-node lan_beacon: the UDP port is busy (another program holds it); trying again"
        ),
        _ => {}
    }
    io
}

/// A query this node sent, kept for [`ANSWER_WINDOW`] (§7).
struct Pending {
    nonce: [u8; 16],
    index: u32,
    v6: bool,
    /// The address it was sent from: an answer's `dst`.
    src: IpAddr,
    at: Instant,
    targets: Vec<[u8; 32]>,
    answered: bool,
}

/// One contact's query schedule (§8), and what its rounds got (F11b).
#[derive(Clone, Copy, Debug)]
struct PeerSched {
    last: Option<Instant>,
    gap: Duration,
    answered: bool,
    /// When a want for it last came from one of its sources (the outbox,
    /// custody, a user send; not a join round).
    wanted: Option<Instant>,
    /// When it last answered one of our rounds.
    answer_at: Option<Instant>,
    /// Rounds naming it in a row that got no answer within
    /// [`ANSWER_WINDOW`].
    misses: u32,
}

impl Default for PeerSched {
    fn default() -> Self {
        PeerSched {
            last: None,
            gap: PEER_GAP_MIN,
            answered: false,
            wanted: None,
            answer_at: None,
            misses: 0,
        }
    }
}

/// One contact's matched queries by epoch (F11b): the offset of the run of
/// rounds that matched at the same epoch next to ours (0: none), how many,
/// when its last round came, and the most skew one of them shows (ms,
/// review A-3).
#[derive(Clone, Copy, Debug, Default)]
struct ClockRun {
    offset: i8,
    rounds: u32,
    last: Option<Instant>,
    shown_ms: u64,
}

impl PeerSched {
    /// May a query name the contact at `now` (`send`: for a user send)?
    fn allows(&self, send: bool, now: Instant) -> bool {
        let gap = if send { SEND_GAP } else { self.gap };
        self.last.is_none_or(|last| now >= last + gap)
    }

    /// A query named the contact at `now`: the gap doubles when the one
    /// before went unanswered.
    fn queried(&mut self, now: Instant) {
        if self.last.is_some() && !self.answered {
            self.gap = (self.gap * 2).min(PEER_GAP_MAX);
        }
        self.answered = false;
        self.last = Some(now);
    }

    fn answered(&mut self) {
        self.answered = true;
        self.gap = PEER_GAP_MIN;
        self.misses = 0;
    }
}

/// A token bucket: `burst` tokens, one more per `every`.
#[derive(Clone, Copy, Debug)]
struct Bucket {
    burst: u32,
    every: Duration,
    tokens: u32,
    /// The time the tokens were counted for.
    at: Instant,
}

impl Bucket {
    fn new(burst: u32, every: Duration, now: Instant) -> Bucket {
        Bucket {
            burst,
            every,
            tokens: burst,
            at: now,
        }
    }

    fn refill(&mut self, now: Instant) {
        if self.tokens >= self.burst {
            self.at = now;
            return;
        }
        let gained =
            now.saturating_duration_since(self.at).as_nanos() / self.every.as_nanos().max(1);
        let room = u128::from(self.burst - self.tokens);
        if gained >= room {
            self.tokens = self.burst;
            self.at = now;
        } else if gained > 0 {
            let gained = gained as u32;
            self.tokens += gained;
            self.at += self.every * gained;
        }
    }

    fn take(&mut self, now: Instant) -> bool {
        self.refill(now);
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }

    /// When a token is there: `now`, or when the next one comes.
    fn ready_at(&mut self, now: Instant) -> Instant {
        self.refill(now);
        if self.tokens > 0 {
            now
        } else {
            self.at + self.every
        }
    }

    /// Full again: it may be forgotten (a new one starts full).
    fn full(&mut self, now: Instant) -> bool {
        self.refill(now);
        self.tokens >= self.burst
    }
}

/// Keys seen within `ttl`, at most `max` (the oldest go first).
struct Recent<K> {
    ttl: Duration,
    max: usize,
    order: VecDeque<(K, Instant)>,
    set: HashSet<K>,
}

impl<K: Copy + Eq + Hash> Recent<K> {
    fn new(ttl: Duration, max: usize) -> Recent<K> {
        Recent {
            ttl,
            max,
            order: VecDeque::new(),
            set: HashSet::new(),
        }
    }

    fn expire(&mut self, now: Instant) {
        while let Some(&(key, at)) = self.order.front() {
            if now < at + self.ttl {
                break;
            }
            self.order.pop_front();
            self.set.remove(&key);
        }
    }

    fn contains(&mut self, key: &K, now: Instant) -> bool {
        self.expire(now);
        self.set.contains(key)
    }

    /// Keep `key`; false when it was kept already.
    fn insert(&mut self, key: K, now: Instant) -> bool {
        self.expire(now);
        if !self.set.insert(key) {
            return false;
        }
        self.order.push_back((key, now));
        if self.order.len() > self.max {
            if let Some((old, _)) = self.order.pop_front() {
                self.set.remove(&old);
            }
        }
        true
    }
}

/// The book (§6) as the task keeps it.
#[derive(Default)]
struct Book {
    /// Every contact's key sets: one per contact without pair seeds, up to
    /// three with them (Phase 6b), all matched against.
    keys: Vec<PairKeys>,
    /// What each of `keys` is for.
    uses: Vec<KeyUse>,
    /// The key set each contact is asked with (and its answers made with).
    at: HashMap<[u8; 32], usize>,
    /// The epoch keys of `keys` for the epoch they name.
    epoch: Option<EpochKeys>,
    /// The files' stamp when it was read, and when they were looked at.
    stamp: Option<BookStamp>,
    checked: Option<Instant>,
    /// It could not be read then (empty meanwhile: fail closed).
    failed_at: Option<Instant>,
}

impl Book {
    fn set(&mut self, entries: Vec<(PairKeys, KeyUse)>) {
        let (keys, uses): (Vec<PairKeys>, Vec<KeyUse>) = entries.into_iter().unzip();
        self.at = keys
            .iter()
            .zip(&uses)
            .enumerate()
            .filter(|(_, (_, u))| u.send)
            .map(|(i, (k, _))| (k.peer, i))
            .collect();
        self.keys = keys;
        self.uses = uses;
        self.epoch = None;
    }

    /// The key set `peer` is asked with.
    fn get(&self, peer: &[u8; 32]) -> Option<&PairKeys> {
        self.at.get(peer).map(|&i| &self.keys[i])
    }

    /// Every key set of `peer`, the one it is asked with first: an answer
    /// to a query made before the book was read again opens with the one
    /// that query used.
    fn all_of<'a>(&'a self, peer: &'a [u8; 32]) -> impl Iterator<Item = &'a PairKeys> + 'a {
        self.get(peer)
            .into_iter()
            .chain(self.keys.iter().filter(move |k| k.peer == *peer))
    }

    fn has(&self, peer: &[u8; 32]) -> bool {
        self.at.contains_key(peer)
    }
}

/// The task's state while its sockets may be open.
struct State {
    host: Arc<dyn Host>,
    shared: Arc<Shared>,
    identity: Arc<Identity>,
    rng: StdRng,
    /// How datagrams go out ([`Shape::V1`]; tests of other things set
    /// theirs).
    shape: Shape,
    /// On the lab bus: its loopback listener counts.
    bus: bool,
    ifaces: Vec<BeaconIf>,
    book: Book,
    peers: HashMap<[u8; 32], PeerSched>,
    /// Wanted contacts the next rounds name, the oldest first.
    due: Vec<[u8; 32]>,
    round_at: Option<Instant>,
    rounds: Bucket,
    pending: VecDeque<Pending>,
    /// Datagrams not sent yet (first copies after their delay, second
    /// copies), in time order.
    outgoing: VecDeque<Due>,
    replay: Recent<[u8; 16]>,
    /// Datagrams handled lately: nonce, source and, for an answer from an
    /// IPv6 link-local source, the link it came in on (review A-1).
    seen: Recent<([u8; 16], IpAddr, u32)>,
    sources: HashMap<IpAddr, Bucket>,
    global: Bucket,
    checks: Bucket,
    /// When each contact was last answered.
    answered: HashMap<[u8; 32], Instant>,
    /// A join round waits for the book, which could not be read (the
    /// at-rest key is still loading): it goes once the book reads.
    join_owed: bool,
    /// Each contact's matched queries by epoch (F11b); book contacts only.
    clocks: HashMap<[u8; 32], ClockRun>,
    /// Rounds sent and the contacts they named, in time order, until their
    /// answer window ends (F11b).
    verdicts: VecDeque<(Instant, Vec<[u8; 32]>)>,
}

impl State {
    fn new(
        host: Arc<dyn Host>,
        shared: Arc<Shared>,
        identity: Arc<Identity>,
        bus: bool,
        rng: StdRng,
        shape: Shape,
        now: Instant,
    ) -> State {
        State {
            host,
            shared,
            identity,
            rng,
            shape,
            bus,
            ifaces: Vec::new(),
            book: Book::default(),
            peers: HashMap::new(),
            due: Vec::new(),
            round_at: None,
            rounds: Bucket::new(ROUND_BURST, ROUND_REFILL, now),
            pending: VecDeque::new(),
            outgoing: VecDeque::new(),
            replay: Recent::new(REPLAY_TTL, REPLAY_MAX),
            seen: Recent::new(SEEN_TTL, SEEN_MAX),
            sources: HashMap::new(),
            global: Bucket::new(GLOBAL_BURST, GLOBAL_REFILL, now),
            checks: Bucket::new(CHECK_BURST, CHECK_REFILL, now),
            answered: HashMap::new(),
            join_owed: false,
            clocks: HashMap::new(),
            verdicts: VecDeque::new(),
        }
    }

    /// The task (re)starts on `ifaces`: the book is read and one join round
    /// named (§8).
    async fn start(&mut self, ifaces: Vec<BeaconIf>, now: Instant) {
        self.set_ifaces(ifaces);
        self.join_round(now).await;
    }

    /// The interfaces to run on: what was found or asked on any other goes.
    fn set_ifaces(&mut self, ifaces: Vec<BeaconIf>) {
        let live: Vec<u32> = ifaces.iter().map(|i| i.index).collect();
        self.pending.retain(|p| live.contains(&p.index));
        // A datagram not sent yet goes out only on the interface it was
        // made for, as it was: never on another network (its address
        // changed), where it would say that a Raven node just arrived
        // (owner decision OD-C7, Phase 6b W-B3).
        let old = &self.ifaces;
        self.outgoing.retain(|d| {
            old.iter()
                .find(|i| i.index == d.out.index)
                .is_some_and(|made_for| ifaces.contains(made_for))
        });
        self.shared.set_ifaces(&live);
        self.ifaces = ifaces;
    }

    /// One join round (§8): the contacts seen on the LAN lately, at most
    /// [`JOIN_MAX`], and only while something needs a contact found (owner
    /// decision OD-C7: joining a network alone announces nothing). While the
    /// book cannot be read it is owed, and goes when the book reads
    /// ([`Self::on_timer`]).
    async fn join_round(&mut self, now: Instant) {
        self.refresh_book(now).await;
        self.join_owed = self.book.failed_at.is_some();
        if self.join_owed {
            return;
        }
        let now_ms = self.host.now_ms();
        if !self.host.need(now_ms).await {
            return;
        }
        let recent = self.host.recent(now_ms).await;
        for peer in recent.into_iter().take(JOIN_MAX) {
            self.add_want(peer, false, now);
        }
    }

    /// An interface or network change (§8): every contact's interval starts
    /// over, a join round, and the contacts with waiting deliveries wanted.
    /// An answer given on the old network does not hold back the first one
    /// on this network, rounds left unanswered there count for nothing
    /// here, and nothing found there is dialled or holds back a query here
    /// (review A-2).
    async fn changed(&mut self, ifaces: Vec<BeaconIf>, now: Instant) {
        self.set_ifaces(ifaces);
        self.shared.forget_found();
        self.peers.clear();
        self.answered.clear();
        self.verdicts.clear();
        self.shared.clear_all_silent();
        self.join_round(now).await;
        for peer in self.host.waiting(WAITING_MAX) {
            self.wanted(peer, now);
            self.add_want(peer, false, now);
        }
    }

    /// A message from the rest of the node. A want looks at the book first
    /// (read again when its files changed, at most once per [`BOOK_CHECK`]),
    /// so a contact added since the last look is asked for now, not only
    /// after the next change, query or round (found by the fault matrix's
    /// s83, Phase 3 P3.12).
    async fn on_message(&mut self, msg: Msg, now: Instant) {
        if matches!(msg, Msg::Want(..)) {
            self.refresh_book(now).await;
        }
        self.on_msg(msg, now);
    }

    fn on_msg(&mut self, msg: Msg, now: Instant) {
        match msg {
            Msg::Want(peer, send, at) => {
                if now.saturating_duration_since(at) <= WANT_STALE {
                    self.wanted(peer, now);
                    self.add_want(peer, send, now);
                }
            }
            Msg::Linked(peer) => {
                self.peers.remove(&peer);
                self.forget_rounds(&peer);
                self.shared.clear_silent(&peer);
            }
        }
    }

    /// `peer` is reachable (an authenticated link, or its query matched):
    /// the rounds that named it and are still in their answer window count
    /// no miss (F11b).
    fn forget_rounds(&mut self, peer: &[u8; 32]) {
        for (_, targets) in &mut self.verdicts {
            targets.retain(|p| p != peer);
        }
    }

    /// One of `peer`'s sources (the outbox, custody, a user send) wants it
    /// at `now` (F11b: a want is pending for [`WANT_HELD`]).
    fn wanted(&mut self, peer: [u8; 32], now: Instant) {
        if !self.book.has(&peer) {
            return;
        }
        self.peers.entry(peer).or_default().wanted = Some(now);
        self.shared.hold_silent(&peer, now + WANT_HELD);
    }

    /// `peer` is wanted at `now` (`send`: for a user send): named in the next
    /// round unless it is not in the book, has a fresh candidate or was
    /// named too recently (§8).
    fn add_want(&mut self, peer: [u8; 32], send: bool, now: Instant) {
        if !self.book.has(&peer) || self.due.contains(&peer) || self.shared.fresh(&peer, now) {
            return;
        }
        if !self.peers.get(&peer).is_none_or(|s| s.allows(send, now)) {
            return;
        }
        self.due.push(peer);
        self.round_at.get_or_insert(now + COALESCE);
    }

    /// When the timer is due next: a round, a datagram's first or second
    /// copy, the end of a round's answer window, or a look at the book for
    /// an owed join round.
    fn next_at(&self) -> Option<Instant> {
        let repeat = self.outgoing.front().map(|d| d.at);
        let verdict = self
            .verdicts
            .front()
            .map(|(sent, _)| self.verdict_at(*sent));
        let book = self
            .book
            .checked
            .filter(|_| self.join_owed)
            .map(|at| at + BOOK_CHECK);
        [self.round_at, repeat, verdict, book]
            .into_iter()
            .flatten()
            .min()
    }

    async fn on_timer(&mut self, io: &Io, now: Instant) {
        // Nothing made before LAN turned off goes out after it (§0).
        if !self.host.lan_on() {
            self.outgoing.clear();
        }
        while self.outgoing.front().is_some_and(|d| d.at <= now) {
            if let Some(d) = self.outgoing.pop_front() {
                io.send(&d.out, &self.ifaces);
                if d.again {
                    let gap = self.shape.gap(&mut self.rng);
                    self.queue(now + gap, d.out, false);
                }
            }
        }
        while self
            .verdicts
            .front()
            .is_some_and(|(sent, _)| self.verdict_at(*sent) <= now)
        {
            if let Some((sent, targets)) = self.verdicts.pop_front() {
                self.verdict(sent, &targets, now).await;
            }
        }
        if self.join_owed {
            self.join_round(now).await;
        }
        if self.round_at.is_some_and(|at| at <= now) {
            self.round_at = None;
            self.round(io, now).await;
        }
    }

    /// When the answer window of a round made at `sent` ends: its last
    /// query's delay, then [`ANSWER_WINDOW`].
    fn verdict_at(&self, sent: Instant) -> Instant {
        sent + self.shape.delay.1 + ANSWER_WINDOW
    }

    /// `datagram` (a query or an answer) goes out on interface `index`,
    /// family `v6`, shaped ([`Shape`]): its first copy now or after its
    /// delay, and a second a gap after that. When its first copy goes.
    fn send(&mut self, io: &Io, index: u32, v6: bool, datagram: &[u8], now: Instant) -> Instant {
        let out = Out {
            index,
            v6,
            bytes: self.shape.wire(&mut self.rng, datagram),
        };
        let delay = self.shape.delay(&mut self.rng);
        if delay.is_zero() {
            io.send(&out, &self.ifaces);
            let gap = self.shape.gap(&mut self.rng);
            self.queue(now + gap, out, false);
        } else {
            self.queue(now + delay, out, true);
        }
        now + delay
    }

    /// Keep `out` until `at`, in time order.
    fn queue(&mut self, at: Instant, out: Out, again: bool) {
        let i = self.outgoing.partition_point(|d| d.at <= at);
        self.outgoing.insert(i, Due { at, out, again });
    }

    /// The answer window of a round sent at `sent` naming `targets` has
    /// ended (F11b): a contact that gave no answer since has one more round
    /// without one. After [`SILENT_ROUNDS`] of them, while a want for it is
    /// pending and it reached this node on this network in the last 7 days
    /// (lan_seen, its address on one of these interfaces' networks), it is
    /// asked for in vain: as when the two clocks are too far apart for the
    /// beacon's epochs.
    async fn verdict(&mut self, sent: Instant, targets: &[[u8; 32]], now: Instant) {
        for peer in targets {
            let Some(s) = self.peers.get_mut(peer) else {
                continue;
            };
            if s.answer_at.is_some_and(|at| at >= sent) {
                continue;
            }
            s.misses = s.misses.saturating_add(1);
            let until = s
                .wanted
                .map(|at| at + WANT_HELD)
                .filter(|until| now < *until);
            let Some(until) = until.filter(|_| s.misses >= SILENT_ROUNDS) else {
                continue;
            };
            let seen = self.host.sighting(*peer, self.host.now_ms()).await;
            if seen.is_some_and(|ip| on_link_in(&self.ifaces, ip)) {
                self.shared.set_silent(*peer, now, until);
            }
        }
    }

    /// A round (§8): at most [`SLOTS`] wanted contacts, the oldest first; a
    /// contact found meanwhile or no longer in the book is left out, and the
    /// rest wait for the next round. Without a token from the bucket the
    /// round waits for one.
    async fn round(&mut self, io: &Io, now: Instant) {
        if io.is_closed() {
            // Nothing can go out (no interface, or the port is busy): the
            // wants lapse, and their sources ask again.
            self.due.clear();
            return;
        }
        self.refresh_book(now).await;
        let (mut targets, mut rest) = (Vec::new(), Vec::new());
        for peer in std::mem::take(&mut self.due) {
            if !self.book.has(&peer) || self.shared.fresh(&peer, now) {
                continue;
            }
            if targets.len() < SLOTS {
                targets.push(peer);
            } else {
                rest.push(peer);
            }
        }
        if targets.is_empty() {
            return;
        }
        if !self.rounds.take(now) {
            targets.append(&mut rest);
            self.due = targets;
            self.round_at = Some(self.rounds.ready_at(now));
            return;
        }
        self.due = rest;
        if !self.due.is_empty() {
            self.round_at = Some((now + COALESCE).max(self.rounds.ready_at(now)));
        }
        self.send_queries(io, &targets, now);
        for peer in &targets {
            self.peers.entry(*peer).or_default().queried(now);
        }
    }

    /// One round's queries naming `targets`: on every interface and family,
    /// a fresh nonce from that interface's address and the LAN listener's
    /// port where it accepts that family there (else 0, §4), each shaped
    /// ([`Self::send`]). Its answer window starts when it goes.
    fn send_queries(&mut self, io: &Io, targets: &[[u8; 32]], now: Instant) {
        let epoch = codec::epoch_at(self.host.now_ms() / 1000);
        let mut plan = Vec::new();
        for iface in &self.ifaces {
            for v6 in [false, true] {
                if let Some(src) = bound(iface, v6) {
                    let port = self.listener_port(iface, v6).unwrap_or(0);
                    plan.push((iface.index, v6, src, port));
                }
            }
        }
        let keys: Vec<&PairKeys> = targets.iter().filter_map(|p| self.book.get(p)).collect();
        let mut queries = Vec::with_capacity(plan.len());
        for (index, v6, src, port) in plan {
            let query = codec::build_query(&mut self.rng, epoch, src, port, &keys);
            queries.push((index, v6, src, query));
        }
        if !queries.is_empty() {
            self.verdicts.push_back((now, targets.to_vec()));
        }
        for (index, v6, src, query) in queries {
            let mut nonce = [0u8; 16];
            nonce.copy_from_slice(&query[..16]);
            let at = self.send(io, index, v6, &query, now);
            self.pending.retain(|p| now < p.at + ANSWER_WINDOW);
            self.pending.push_back(Pending {
                nonce,
                index,
                v6,
                src,
                at,
                targets: targets.to_vec(),
                answered: false,
            });
            self.shared.note(Count::Query, now);
        }
    }

    /// Read the book again when its files changed (looked at once per
    /// [`BOOK_CHECK`]), or [`BOOK_RETRY`] after it could not be read.
    async fn refresh_book(&mut self, now: Instant) {
        if self.book.checked.is_some_and(|at| now < at + BOOK_CHECK) {
            return;
        }
        self.book.checked = Some(now);
        let stamp = self.host.book_stamp();
        let retry = self.book.failed_at.is_some_and(|at| now >= at + BOOK_RETRY);
        if self.book.stamp.as_ref() == Some(&stamp) && !retry {
            return;
        }
        let loaded = self.host.load_book(Arc::clone(&self.identity)).await;
        self.book.stamp = Some(stamp);
        match loaded {
            Ok(keys) => {
                self.book.set(keys);
                self.book.failed_at = None;
            }
            // Fail closed: nobody is named or answered until it reads.
            Err(_) => {
                self.book.set(Vec::new());
                self.book.failed_at = Some(now);
            }
        }
    }

    /// The book's epoch keys for Raven's clock now, made once per epoch.
    fn epoch_keys(&mut self) -> &EpochKeys {
        let epoch = codec::epoch_at(self.host.now_ms() / 1000);
        let book = &mut self.book;
        if book.epoch.as_ref().is_none_or(|k| k.epoch() != epoch) {
            book.epoch = Some(EpochKeys::new(&book.keys, epoch));
        }
        book.epoch.as_ref().expect("made for this epoch above")
    }

    /// One datagram from `from`: a query (160..=191 bytes) or an answer
    /// (48..=63; Phase 6b W-B3), else dropped (§3).
    async fn on_datagram(&mut self, bytes: &[u8], from: SocketAddr, io: &Io, now: Instant) {
        let query = match codec::kind_of(bytes.len()) {
            Some(DatagramKind::Query) => true,
            Some(DatagramKind::Answer) => false,
            None => return self.dropped(now),
        };
        let ip = from.ip().to_canonical();
        if !self.host.is_local(ip) {
            return self.dropped(now);
        }
        let Some(at) = self.arrival(from) else {
            return self.dropped(now);
        };
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&bytes[..16]);
        // Its second copy, or IPv4's group and broadcast copies: once. An
        // answer that reaches this node on two links (Wi-Fi and a cable on
        // one network) is checked on each: it answers one of their queries
        // (review A-1).
        let link = match from {
            SocketAddr::V6(v6) if !query && is_link_local_v6(*v6.ip()) => v6.scope_id(),
            _ => 0,
        };
        if !self.seen.insert((nonce, ip, link), now) {
            return;
        }
        self.pending.retain(|p| now < p.at + ANSWER_WINDOW);
        if query {
            self.on_query(bytes, nonce, ip, at, io, now).await;
        } else {
            self.on_answer(bytes, ip, at, now);
        }
    }

    /// A query from `ip` on `self.ifaces[at]` (§6).
    async fn on_query(
        &mut self,
        query: &[u8],
        nonce: [u8; 16],
        ip: IpAddr,
        at: usize,
        io: &Io,
        now: Instant,
    ) {
        // This node's own: multicast works here. It costs no token.
        if self.pending.iter().any(|p| p.nonce == nonce && p.src == ip) {
            self.shared.set_echo_ok(true);
            return;
        }
        // A source the stranger penalty box banned gets nothing (Phase 6b R1).
        if self.host.source_banned(ip, now) {
            return self.dropped(now);
        }
        match self.source_allows(ip, now) {
            SourceLimit::Within => {}
            SourceLimit::Over => {
                self.host.source_refused(ip, false, now);
                return self.dropped(now);
            }
            SourceLimit::Crowded => return self.dropped(now),
        }
        if !self.global.take(now) {
            return self.dropped(now);
        }
        if self.replay.contains(&nonce, now) {
            self.host.source_refused(ip, true, now);
            return self.dropped(now);
        }
        self.refresh_book(now).await;
        let matches = codec::match_query_epochs(query, ip, self.epoch_keys());
        if matches.is_empty() {
            return;
        }
        self.replay.insert(nonce, now);
        let iface = self.ifaces[at].clone();
        for m in matches {
            let peer = self.book.keys[m.index].peer;
            // The LAN link gate's check: refused, nothing is kept or sent.
            if !self.host.admit(peer, ip).await {
                continue;
            }
            self.heard(peer, m.offset, now);
            // Phase 6b: only the pair's root matched, while a seed was
            // expected (a Notice; the root keeps friends from a lockout).
            crate::pair_seed::root_matched(
                &peer,
                self.book.uses[m.index],
                Via::DirectLink(OutboxCarrier::Lan),
            );
            if m.port != 0 {
                self.found(
                    peer,
                    candidate_addr(ip, m.port, iface.index),
                    iface.index,
                    now,
                );
            }
            self.answer(io, m.index, &nonce, ip, &iface, now);
        }
    }

    /// A query of `peer`'s matched at `offset` (its epoch less ours) and
    /// passed the link gate (F11b). It is here, and its epoch is within one
    /// of ours (so it can match ours too): the rounds it left unanswered
    /// count no more. Its rounds (matches [`ROUND_SPAN`] apart) are counted
    /// by epoch. A match at the epoch after ours, `p` ms into ours, shows
    /// that its clock runs more than one epoch less `p` ahead; at the one
    /// before, more than `p` behind (less a second for the way). A few
    /// seconds' skew matches next door at every epoch's edge, so only after
    /// [`SKEW_ROUNDS`] in a row only at the epoch before ours, or only at
    /// the one after, one of which shows more than Raven's five-minute
    /// limit, do CP.7's clock notes say so, with the most any of them shows
    /// (again at each such round; review A-3). A round at our own epoch ends
    /// the run.
    fn heard(&mut self, peer: [u8; 32], offset: i8, now: Instant) {
        if let Some(s) = self.peers.get_mut(&peer) {
            s.misses = 0;
        }
        self.forget_rounds(&peer);
        self.shared.clear_silent(&peer);
        if self.clocks.len() >= BOOK_MAX && !self.clocks.contains_key(&peer) {
            let book = &self.book;
            self.clocks.retain(|key, _| book.has(key));
            if self.clocks.len() >= BOOK_MAX {
                return;
            }
        }
        let run = self.clocks.entry(peer).or_default();
        if run.last.is_some_and(|last| now < last + ROUND_SPAN) {
            // The same round, on another interface or family.
            return;
        }
        run.last = Some(now);
        if offset == 0 {
            (run.offset, run.rounds, run.shown_ms) = (0, 0, 0);
            return;
        }
        let phase = self.host.now_ms() % EPOCH_MS;
        let shown = if offset > 0 {
            EPOCH_MS - phase
        } else {
            phase.saturating_sub(ROUND_SPAN.as_millis() as u64)
        };
        if run.offset == offset {
            run.rounds = run.rounds.saturating_add(1);
            run.shown_ms = run.shown_ms.max(shown);
        } else {
            (run.offset, run.rounds, run.shown_ms) = (offset, 1, shown);
        }
        if run.rounds >= SKEW_ROUNDS && run.shown_ms > raven_core::clock_skew::FUTURE_SKEW_MS {
            let ms = i64::try_from(run.shown_ms).unwrap_or(i64::MAX);
            self.host
                .clock_skew(&peer, if offset > 0 { ms } else { -ms });
        }
    }

    /// Answer the book's contact `i` (§5): its query had nonce `q_nonce` and
    /// came from `dst` on `iface`. Not while LAN is off or the LAN listener
    /// does not accept that family on `iface`, and once per contact per
    /// [`ANSWER_GAP`]; shaped as a query is ([`Self::send`]).
    fn answer(
        &mut self,
        io: &Io,
        i: usize,
        q_nonce: &[u8; 16],
        dst: IpAddr,
        iface: &BeaconIf,
        now: Instant,
    ) {
        let v6 = dst.is_ipv6();
        let Some(port) = self.listener_port(iface, v6) else {
            return;
        };
        let Some(src) = bound(iface, v6) else {
            return;
        };
        let peer = self.book.keys[i].peer;
        if self
            .answered
            .get(&peer)
            .is_some_and(|at| now < *at + ANSWER_GAP)
        {
            return;
        }
        let answer =
            codec::build_answer(&mut self.rng, &self.book.keys[i], q_nonce, src, dst, port);
        self.send(io, iface.index, v6, &answer, now);
        self.answered.retain(|_, at| now < *at + ANSWER_GAP);
        self.answered.insert(peer, now);
        self.shared.note(Count::AnswerSent, now);
    }

    /// An answer from `ip` on `self.ifaces[at]` (§7): it counts for a query
    /// of ours of that family on the same link ([`Self::answer_links`]) still
    /// in [`ANSWER_WINDOW`], when it opens with one of that query's contacts.
    fn on_answer(&mut self, answer: &[u8], ip: IpAddr, at: usize, now: Instant) {
        let links = self.answer_links(ip, at);
        let v6 = ip.is_ipv6();
        let ours = |p: &Pending| p.v6 == v6 && links.contains(&p.index);
        if !self.pending.iter().any(ours) {
            return;
        }
        if !self.checks.take(now) {
            return self.dropped(now);
        }
        let mut hit = None;
        'queries: for p in self.pending.iter_mut().filter(|p| ours(p)) {
            for peer in &p.targets {
                for keys in self.book.all_of(peer) {
                    if let Some(port) = codec::open_answer(answer, keys, &p.nonce, ip, p.src) {
                        hit = Some((*peer, port, !p.answered, p.index));
                        p.answered = true;
                        break 'queries;
                    }
                }
            }
        }
        let Some((peer, port, first, index)) = hit else {
            return;
        };
        if first {
            self.shared.note(Count::Answered, now);
        }
        let sched = self.peers.entry(peer).or_default();
        sched.answered();
        sched.answer_at = Some(now);
        self.shared.clear_silent(&peer);
        self.found(peer, candidate_addr(ip, port, index), index, now);
    }

    /// `peer`'s listener is at `addr`, found on interface `iface`: a
    /// candidate, and what waits for `peer` is due now. Not at an address
    /// the outbox and custody dial no find at
    /// ([`raven_core::outbox::beacon_lan_dials`]: a public IPv4 address on a
    /// public-numbered LAN, which the on-link rule lets in): kept, it would
    /// only hold back the next query and count the contact as here (review
    /// A-4).
    fn found(&self, peer: [u8; 32], addr: SocketAddr, iface: u32, now: Instant) {
        if raven_core::outbox::beacon_lan_dials(&[netutil::scoped_dial(addr)]).is_empty() {
            return;
        }
        let moved = self.shared.add_candidate(
            peer,
            Candidate {
                addr,
                iface,
                at: now,
            },
        );
        self.host.found(&peer, moved);
    }

    /// The interfaces whose queries an answer from `ip` that came in on
    /// `self.ifaces[at]` may answer (§7): that one for an IPv6 link-local
    /// source (its zone), else every interface on whose network `ip` is.
    /// Two interfaces on one subnet (Wi-Fi and a cable at a dock) each send
    /// their own query from their own address, and the contact answers the
    /// one that reached it first, while [`Self::arrival`] names the first
    /// of them (review A-1).
    fn answer_links(&self, ip: IpAddr, at: usize) -> Vec<u32> {
        match ip {
            IpAddr::V6(v6) if is_link_local_v6(v6) => vec![self.ifaces[at].index],
            _ => self
                .ifaces
                .iter()
                .filter(|i| on_link_in(std::slice::from_ref(i), ip))
                .map(|i| i.index)
                .collect(),
        }
    }

    /// The interface a datagram from `from` came in on: an IPv6 link-local
    /// source's scope, else the network its source is on.
    fn arrival(&self, from: SocketAddr) -> Option<usize> {
        if let SocketAddr::V6(v6) = from {
            if is_link_local_v6(*v6.ip()) && v6.scope_id() != 0 {
                return self
                    .ifaces
                    .iter()
                    .position(|i| i.index == v6.scope_id() && i.v6_ll.is_some());
            }
        }
        let ip = from.ip().to_canonical();
        self.ifaces
            .iter()
            .position(|i| on_link_in(std::slice::from_ref(i), ip))
    }

    /// The LAN listener's port that a connection of this family reaches on
    /// `iface` (§4 `P_X`, §6), or `None`: LAN off, no listener, or one that
    /// does not accept that family there ([`accepts`]).
    fn listener_port(&self, iface: &BeaconIf, v6: bool) -> Option<u16> {
        if !self.host.lan_on() {
            return None;
        }
        self.host
            .listeners()
            .into_iter()
            .find(|listen| accepts(*listen, iface, v6, self.bus))
            .map(|listen| listen.port())
    }

    /// Is a query from `ip` within its source's bucket (§6)?
    fn source_allows(&mut self, ip: IpAddr, now: Instant) -> SourceLimit {
        if !self.sources.contains_key(&ip) && self.sources.len() >= SOURCES_MAX {
            self.sources.retain(|_, bucket| !bucket.full(now));
            if self.sources.len() >= SOURCES_MAX {
                return SourceLimit::Crowded;
            }
        }
        let within = self
            .sources
            .entry(ip)
            .or_insert_with(|| Bucket::new(SOURCE_BURST, SOURCE_REFILL, now))
            .take(now);
        if within {
            SourceLimit::Within
        } else {
            SourceLimit::Over
        }
    }

    fn dropped(&self, now: Instant) {
        self.shared.note(Count::Dropped, now);
    }
}

/// What a source's bucket says about its query (§6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SourceLimit {
    Within,
    /// Over its own rate: the source's doing (a strike, Phase 6b R1).
    Over,
    /// Too many busy sources to track one more: not this source's doing.
    Crowded,
}

/// This interface's address of a family: its IPv4 address, or its IPv6
/// link-local one.
fn bound(iface: &BeaconIf, v6: bool) -> Option<IpAddr> {
    if v6 {
        iface.v6_ll.map(IpAddr::V6)
    } else {
        iface.v4.map(|(ip, _, _)| IpAddr::V4(ip))
    }
}

/// Does a LAN listener bound at `listen` accept a connection of this family
/// (`v6`) that comes in on `iface` (§6: one rule per family)? Its family's
/// unspecified address, or the address the beacon speaks from there
/// ([`bound`]: the interface's IPv4 address, its IPv6 link-local one), which
/// is where the contact dials; a loopback address only on the lab bus,
/// whose interface is loopback. A listener on another address of the
/// interface's networks (a second IPv4 address, a global or unique-local
/// IPv6 one) is not reached at that source (review A-6).
fn accepts(listen: SocketAddr, iface: &BeaconIf, v6: bool, bus: bool) -> bool {
    match listen {
        SocketAddr::V4(l) if !v6 => {
            let ip = *l.ip();
            if ip.is_unspecified() {
                return true;
            }
            if ip.is_loopback() {
                return bus;
            }
            iface.v4.is_some_and(|(own, _, _)| own == ip)
        }
        SocketAddr::V6(l) if v6 => {
            let ip = *l.ip();
            if ip.is_unspecified() {
                return true;
            }
            if ip.is_loopback() {
                return false;
            }
            iface.v6_ll == Some(ip) && (l.scope_id() == 0 || l.scope_id() == iface.index)
        }
        _ => false,
    }
}

/// Where a contact found at `ip` listens: `port` there, an IPv6 link-local
/// address scoped to the interface it was found on.
fn candidate_addr(ip: IpAddr, port: u16, iface: u32) -> SocketAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) if is_link_local_v6(v6) => {
            SocketAddr::V6(SocketAddrV6::new(v6, port, 0, iface))
        }
        ip => SocketAddr::new(ip, port),
    }
}

fn is_link_local_v6(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicU64;

    use raven_core::lan_beacon::{
        build_answer, build_query, kind_of, match_query, open_answer, pair_keys, ANSWER_LEN,
        ANSWER_MAX_LEN, QUERY_LEN, QUERY_MAX_LEN,
    };
    use raven_core::outbox::OutboxCarrier;
    use raven_core::security_events::{PenaltyBox, SourceKey};

    use super::*;

    /// Raven's clock here, and its beacon epoch.
    const NOW_MS: u64 = 1_700_000_000_000;
    const EPOCH: u64 = 2_833_333;
    /// This node's LAN listener port, and the contacts'.
    const PORT: u16 = 47531;
    const THEIR_PORT: u16 = 47532;
    /// Interface indexes no interface has here: a zone prints as the number.
    const EN0: u32 = 901;
    const EN5: u32 = 902;
    /// The second copy's gap in [`Shape::FIXED`], the shape most tests use.
    const REPEAT_GAP: Duration = Shape::FIXED.repeat.0;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn from(s: &str) -> SocketAddr {
        SocketAddr::new(ip(s), 50_000)
    }

    /// A link-local source on interface `index`.
    fn from_ll(s: &str, index: u32) -> SocketAddr {
        SocketAddr::V6(SocketAddrV6::new(s.parse().unwrap(), 50_000, 0, index))
    }

    fn me() -> Identity {
        Identity::from_seed(&[0x11; 32])
    }

    fn person(n: u8) -> Identity {
        Identity::from_seed(&[0x40 + n; 32])
    }

    fn key(p: &Identity) -> [u8; 32] {
        p.public_key_bytes()
    }

    /// A Wi-Fi: 192.168.1.20/24 (broadcast .255), fe80::20 and an on-link
    /// global /64.
    fn en0() -> BeaconIf {
        BeaconIf {
            index: EN0,
            zone: EN0.to_string(),
            v4: Some((
                Ipv4Addr::new(192, 168, 1, 20),
                24,
                Some(Ipv4Addr::new(192, 168, 1, 255)),
            )),
            v4_prefixes: vec![(Ipv4Addr::new(192, 168, 1, 0), 24)],
            v6_ll: Some("fe80::20".parse().unwrap()),
            v6_prefixes: vec![("2001:db8:1:2::".parse().unwrap(), 64)],
        }
    }

    /// A hotspot: 10.42.0.20/24, no IPv6.
    fn en5() -> BeaconIf {
        BeaconIf {
            index: EN5,
            zone: EN5.to_string(),
            v4: Some((
                Ipv4Addr::new(10, 42, 0, 20),
                24,
                Some(Ipv4Addr::new(10, 42, 0, 255)),
            )),
            v4_prefixes: vec![(Ipv4Addr::new(10, 42, 0, 0), 24)],
            v6_ll: None,
            v6_prefixes: Vec::new(),
        }
    }

    fn v4_only(i: BeaconIf) -> BeaconIf {
        BeaconIf { v6_ll: None, ..i }
    }

    /// The node as these tests set it: LAN on, the listener on
    /// `0.0.0.0:PORT`, the book as rows (or a profile's, with its link gate).
    struct TestHost {
        lan: watch::Sender<bool>,
        identity: Mutex<Option<Arc<Identity>>>,
        listeners: Mutex<Vec<SocketAddr>>,
        now_ms: AtomicU64,
        rows: Mutex<Vec<([u8; 32], bool)>>,
        profile: Option<PathBuf>,
        stamp: AtomicU64,
        /// The book cannot be read (the at-rest key is still loading).
        locked: AtomicBool,
        /// A profile's book takes its pair seeds (Phase 6b).
        seeds: AtomicBool,
        refused: Mutex<HashSet<[u8; 32]>>,
        /// Local besides the private ranges, as the on-link rule says.
        on_link: Mutex<Vec<IpAddr>>,
        recent: Mutex<Vec<[u8; 32]>>,
        waiting: Mutex<Vec<[u8; 32]>>,
        found: Mutex<Vec<[u8; 32]>>,
        /// OD-C7's need (on unless a test says otherwise)...
        need: AtomicBool,
        /// ...or, when set, [`join_need`] as the node asks it: what waits
        /// here, a meeting time of this test's own and the custody rows of
        /// a profile directory.
        meeting: Mutex<Option<(Arc<crate::lan_meeting::Meetings>, PathBuf)>>,
        /// Where each contact last reached this node within 7 days.
        sightings: Mutex<HashMap<[u8; 32], IpAddr>>,
        /// The clock notes made (ms ahead), in order.
        skews: Mutex<Vec<([u8; 32], i64)>>,
        /// The stranger penalty box (Phase 6b R1) on this rig's clock, and
        /// the refusals it was told of (source, replay), in order.
        penalty: Mutex<PenaltyBox>,
        refusals: Mutex<Vec<(IpAddr, bool)>>,
    }

    impl TestHost {
        fn new(identity: &Identity, rows: Vec<([u8; 32], bool)>) -> Arc<TestHost> {
            Self::with(identity, rows, None)
        }

        fn with_profile(identity: &Identity, profile: &Path) -> Arc<TestHost> {
            Self::with(identity, Vec::new(), Some(profile.to_path_buf()))
        }

        fn with(
            identity: &Identity,
            rows: Vec<([u8; 32], bool)>,
            profile: Option<PathBuf>,
        ) -> Arc<TestHost> {
            Arc::new(TestHost {
                lan: watch::Sender::new(true),
                identity: Mutex::new(Some(Arc::new(Identity::from_seed(&identity.seed_bytes())))),
                listeners: Mutex::new(vec!["0.0.0.0:47531".parse().unwrap()]),
                now_ms: AtomicU64::new(NOW_MS),
                rows: Mutex::new(rows),
                profile,
                stamp: AtomicU64::new(0),
                locked: AtomicBool::new(false),
                seeds: AtomicBool::new(false),
                refused: Mutex::new(HashSet::new()),
                on_link: Mutex::new(Vec::new()),
                recent: Mutex::new(Vec::new()),
                waiting: Mutex::new(Vec::new()),
                found: Mutex::new(Vec::new()),
                need: AtomicBool::new(true),
                meeting: Mutex::new(None),
                sightings: Mutex::new(HashMap::new()),
                skews: Mutex::new(Vec::new()),
                penalty: Mutex::new(PenaltyBox::new()),
                refusals: Mutex::new(Vec::new()),
            })
        }

        /// The penalty box's key for `ip`, as raven-node keys a LAN
        /// source (`security::penalty_key`) with this rig's networks.
        fn penalty_key(&self, ip: IpAddr) -> SourceKey {
            let on_link = lock(&self.on_link).clone();
            crate::security::penalty_key_with(ip, OutboxCarrier::Lan, |ip| on_link.contains(&ip))
        }

        fn set_listeners(&self, listeners: &[&str]) {
            *lock(&self.listeners) = listeners.iter().map(|l| l.parse().unwrap()).collect();
        }

        fn found(&self) -> Vec<[u8; 32]> {
            lock(&self.found).clone()
        }
    }

    impl Host for TestHost {
        fn lan(&self) -> watch::Receiver<bool> {
            self.lan.subscribe()
        }

        fn lan_on(&self) -> bool {
            *self.lan.borrow()
        }

        fn identity(&self) -> Option<Arc<Identity>> {
            lock(&self.identity).clone()
        }

        fn listeners(&self) -> Vec<SocketAddr> {
            lock(&self.listeners).clone()
        }

        fn now_ms(&self) -> u64 {
            self.now_ms.load(Ordering::SeqCst)
        }

        fn is_local(&self, ip: IpAddr) -> bool {
            raven_core::paths::lan_source_is_local(ip, |ip| lock(&self.on_link).contains(&ip))
        }

        fn book_stamp(&self) -> BookStamp {
            match &self.profile {
                Some(dd) => book_stamp(dd),
                None => ([None; 4], self.stamp.load(Ordering::SeqCst), 0),
            }
        }

        fn load_book(
            &self,
            identity: Arc<Identity>,
        ) -> BoxFuture<'static, Result<Vec<(PairKeys, KeyUse)>, String>> {
            let book = match &self.profile {
                _ if self.locked.load(Ordering::SeqCst) => Err("contacts.json: locked".into()),
                Some(dd) => load_book(dd, &identity, self.seeds.load(Ordering::SeqCst)),
                None => {
                    let rows: Vec<(String, bool)> = lock(&self.rows)
                        .iter()
                        .map(|(k, pinned)| (hex::encode(k), *pinned))
                        .collect();
                    Ok(book_of(
                        &identity,
                        rows.iter().map(|(k, p)| (k.as_str(), *p)),
                        |_| false,
                        false,
                    )
                    .into_iter()
                    .map(|k| (k, KeyUse::SEND))
                    .collect())
                }
            };
            Box::pin(std::future::ready(book))
        }

        fn admit(&self, peer: [u8; 32], src: IpAddr) -> BoxFuture<'static, bool> {
            let admitted = match &self.profile {
                Some(dd) => raven_core::lan_dispatch::link_admission(
                    dd,
                    &peer,
                    OutboxCarrier::Lan,
                    Some(src),
                )
                .is_ok(),
                None => !lock(&self.refused).contains(&peer),
            };
            Box::pin(std::future::ready(admitted))
        }

        fn recent(&self, _now_ms: u64) -> BoxFuture<'static, Vec<[u8; 32]>> {
            Box::pin(std::future::ready(lock(&self.recent).clone()))
        }

        fn waiting(&self, limit: usize) -> Vec<[u8; 32]> {
            lock(&self.waiting).iter().take(limit).copied().collect()
        }

        fn found(&self, peer: &[u8; 32], _moved: bool) {
            lock(&self.found).push(*peer);
        }

        fn need(&self, now_ms: u64) -> BoxFuture<'static, bool> {
            match &*lock(&self.meeting) {
                Some((meetings, dd)) => {
                    let waiting = !lock(&self.waiting).is_empty();
                    join_need(
                        dd.clone(),
                        now_ms,
                        waiting || meetings.meeting_on(now_ms),
                        false,
                    )
                }
                None => Box::pin(std::future::ready(self.need.load(Ordering::SeqCst))),
            }
        }

        fn sighting(&self, peer: [u8; 32], _now_ms: u64) -> BoxFuture<'static, Option<IpAddr>> {
            Box::pin(std::future::ready(
                lock(&self.sightings).get(&peer).copied(),
            ))
        }

        fn clock_skew(&self, peer: &[u8; 32], ahead_ms: i64) {
            lock(&self.skews).push((*peer, ahead_ms));
        }

        fn source_banned(&self, ip: IpAddr, now: Instant) -> bool {
            let key = self.penalty_key(ip);
            lock(&self.penalty).is_banned(key, now.into_std())
        }

        fn source_refused(&self, ip: IpAddr, replay: bool, now: Instant) {
            lock(&self.refusals).push((ip, replay));
            let weight = crate::security::beacon_strike_weight(replay);
            let key = self.penalty_key(ip);
            lock(&self.penalty).strike(key, weight, now.into_std());
        }
    }

    /// One node's task state over a fake network, driven by hand.
    struct Rig {
        host: Arc<TestHost>,
        shared: Arc<Shared>,
        net: FakeNet,
        io: Io,
        st: State,
        t0: Instant,
        /// Queries already sent (a second copy is not a new round).
        queries: HashSet<Vec<u8>>,
    }

    impl Rig {
        fn new(host: Arc<TestHost>, ifaces: Vec<BeaconIf>) -> Rig {
            Self::shaped(host, ifaces, Shape::FIXED)
        }

        fn shaped(host: Arc<TestHost>, ifaces: Vec<BeaconIf>, shape: Shape) -> Rig {
            let shared = Shared::new(STATE_ON);
            let net = FakeNet::default();
            *lock(&net.ifaces) = ifaces;
            let io = Io::Fake(net.open());
            let t0 = Instant::now();
            let identity = host.identity().unwrap();
            let st = State::new(
                Arc::clone(&host) as Arc<dyn Host>,
                Arc::clone(&shared),
                identity,
                false,
                StdRng::seed_from_u64(7),
                shape,
                t0,
            );
            Rig {
                host,
                shared,
                net,
                io,
                st,
                t0,
                queries: HashSet::new(),
            }
        }

        async fn start(&mut self) {
            let ifaces = lock(&self.net.ifaces).clone();
            self.st.start(ifaces, self.t0).await;
        }

        /// Everything sent since the last look.
        fn sent(&self) -> Vec<Out> {
            std::mem::take(&mut *lock(&self.net.sent))
        }

        async fn timer(&mut self, at: Instant) {
            self.st.on_timer(&self.io, at).await;
        }

        async fn deliver(&mut self, bytes: &[u8], from: SocketAddr, at: Instant) {
            self.st.on_datagram(bytes, from, &self.io, at).await;
        }

        /// The timer run at each time it is due up to `until`: the new
        /// queries (no second copies) with when they went out, and the
        /// answers sent meanwhile.
        async fn run_until(&mut self, until: Instant) -> Vec<(Instant, Out)> {
            let mut new = Vec::new();
            while let Some(at) = self.st.next_at().filter(|at| *at <= until) {
                self.timer(at).await;
                for out in self.sent() {
                    let query = kind_of(out.bytes.len()) == Some(DatagramKind::Query);
                    if !query || self.queries.insert(out.bytes.clone()) {
                        new.push((at, out));
                    }
                }
            }
            new
        }

        fn counts(&self, at: Instant) -> BeaconCounts {
            self.shared.snapshot(at)
        }

        /// Every datagram sent while the timer runs at each time it is due
        /// up to `until`, with when it went: first and second copies alike.
        async fn copies_until(&mut self, until: Instant) -> Vec<(Instant, Out)> {
            let mut all = Vec::new();
            while let Some(at) = self.st.next_at().filter(|at| *at <= until) {
                self.timer(at).await;
                all.extend(self.sent().into_iter().map(|out| (at, out)));
            }
            all
        }
    }

    /// A rig of this node with `people` as pinned contacts on `ifaces`.
    fn rig(people: &[Identity], ifaces: Vec<BeaconIf>) -> Rig {
        let rows = people.iter().map(|p| (key(p), true)).collect();
        Rig::new(TestHost::new(&me(), rows), ifaces)
    }

    /// Those of `people` that query `q` from `src` names, as (index, the
    /// port it carries for them).
    fn named(q: &[u8], src: IpAddr, people: &[Identity]) -> Vec<(usize, u16)> {
        let book: Vec<PairKeys> = people
            .iter()
            .map(|p| pair_keys(p, &key(&me())).unwrap())
            .collect();
        match_query(q, src, EPOCH, &book)
    }

    /// `c`'s query naming this node, from `src`, with `c`'s listener port.
    fn their_query(c: &Identity, src: &str, port: u16, seed: u64) -> Vec<u8> {
        let k = pair_keys(c, &key(&me())).unwrap();
        build_query(
            &mut StdRng::seed_from_u64(seed),
            EPOCH,
            ip(src),
            port,
            &[&k],
        )
        .to_vec()
    }

    /// The port this node's answer `a` to `c`'s query `q` (from `c_src`),
    /// sent from `our_src`, carries for `c`.
    fn opened(a: &[u8], c: &Identity, q: &[u8], our_src: &str, c_src: &str) -> Option<u16> {
        let k = pair_keys(c, &key(&me())).unwrap();
        let nonce: [u8; 16] = q[..16].try_into().unwrap();
        open_answer(a, &k, &nonce, ip(our_src), ip(c_src))
    }

    /// `c`'s answer to this node's query `q` (sent from `our_src`), from
    /// `c_src` with `c`'s port.
    fn their_answer(c: &Identity, q: &[u8], c_src: &str, our_src: &str, seed: u64) -> Vec<u8> {
        let k = pair_keys(c, &key(&me())).unwrap();
        let nonce: [u8; 16] = q[..16].try_into().unwrap();
        let mut rng = StdRng::seed_from_u64(seed);
        build_answer(&mut rng, &k, &nonce, ip(c_src), ip(our_src), THEIR_PORT).to_vec()
    }

    fn answers(sent: &[Out]) -> Vec<&Out> {
        sent.iter()
            .filter(|o| kind_of(o.bytes.len()) == Some(DatagramKind::Answer))
            .collect()
    }

    /// Wants within 300 ms share one round of at most eight, the oldest
    /// first; the rest go in the next round, and rounds come from a bucket
    /// of four refilled one per 3 s (§8).
    #[tokio::test(start_paused = true)]
    async fn rounds_coalesce_wants_up_to_eight_and_bucket_caps_rounds() {
        let people: Vec<Identity> = (0..41).map(person).collect();
        let src = ip("192.168.1.20");
        let mut rig = rig(&people, vec![v4_only(en0())]);
        rig.start().await;
        let t0 = rig.t0;
        assert_eq!(
            rig.st.next_at(),
            None,
            "no join round without recent contacts"
        );
        for (i, p) in people[..10].iter().enumerate() {
            rig.st.add_want(key(p), false, t0 + ms(20 * i as u64));
        }
        assert_eq!(rig.st.next_at(), Some(t0 + COALESCE));
        let first = rig.run_until(t0 + ms(400)).await;
        assert_eq!(first.len(), 1, "one interface, IPv4 only: {first:?}");
        let (at, q) = &first[0];
        assert_eq!((*at, q.index, q.v6), (t0 + COALESCE, EN0, false));
        let found = named(&q.bytes, src, &people);
        assert_eq!(
            found,
            (0..8).map(|i| (i, PORT)).collect::<Vec<_>>(),
            "the eight oldest, with this node's port"
        );
        // Its second copy 250 ms on; the other two 300 ms after the first.
        let next = rig.run_until(t0 + secs(1)).await;
        assert_eq!(next.len(), 1);
        assert_eq!(next[0].0, t0 + ms(600));
        let found = named(&next[0].1.bytes, src, &people);
        assert_eq!(found, vec![(8, PORT), (9, PORT)]);
        assert!(lock(&rig.net.sent).is_empty());

        // Forty wants at once: rounds of eight while the bucket lasts (4 at
        // first), then one per 3 s.
        let mut rig = rig_for(&people);
        rig.start().await;
        let t0 = rig.t0;
        for p in &people[..40] {
            rig.st.add_want(key(p), false, t0);
        }
        let rounds = rig.run_until(t0 + secs(20)).await;
        let at: Vec<Duration> = rounds.iter().map(|(at, _)| *at - t0).collect();
        assert_eq!(at, [ms(300), ms(600), ms(900), ms(1200), ms(3300)]);
        let mut all: Vec<usize> = rounds
            .iter()
            .flat_map(|(_, q)| named(&q.bytes, src, &people))
            .map(|(i, _)| i)
            .collect();
        assert!(rounds
            .iter()
            .all(|(_, q)| named(&q.bytes, src, &people).len() == 8));
        all.sort_unstable();
        assert_eq!(all, (0..40).collect::<Vec<_>>(), "each named once");
        // The bucket is empty now: a new want waits for the next token.
        rig.st.add_want(key(&people[40]), false, t0 + ms(3400));
        let late = rig.run_until(t0 + secs(20)).await;
        assert_eq!(late.len(), 1);
        assert_eq!(late[0].0, t0 + ms(6300));
    }

    /// A started rig of `people` on en0 (IPv4 only).
    fn rig_for(people: &[Identity]) -> Rig {
        rig(people, vec![v4_only(en0())])
    }

    /// [`rig_for`] with the shape a node uses ([`Shape::V1`]).
    fn jittered(people: &[Identity]) -> Rig {
        let rows = people.iter().map(|p| (key(p), true)).collect();
        Rig::shaped(TestHost::new(&me(), rows), vec![v4_only(en0())], Shape::V1)
    }

    /// Per contact, queries 15 s apart, the gap doubling while unanswered up
    /// to 10 min; a network change starts it over, and a user send may ask
    /// 2 s after the last query (§8).
    #[tokio::test(start_paused = true)]
    async fn per_peer_interval_doubles_and_resets_on_network_change() {
        let people = [person(1)];
        let bob = key(&people[0]);
        let mut rig = rig_for(&people);
        rig.start().await;
        let t0 = rig.t0;
        let mut asked = Vec::new();
        for s in 0..200u64 {
            let at = t0 + secs(s);
            if s == 150 {
                rig.st.changed(vec![v4_only(en0())], at).await;
            }
            rig.st.add_want(bob, false, at);
            for (when, out) in rig.run_until(at + ms(999)).await {
                assert_eq!(named(&out.bytes, ip("192.168.1.20"), &people), [(0, PORT)]);
                asked.push(when - t0);
            }
        }
        let expected: Vec<Duration> = [300, 16_300, 47_300, 108_300, 150_300, 166_300, 197_300]
            .into_iter()
            .map(ms)
            .collect();
        assert_eq!(asked, expected);
        // A user send: 2 s after the last query, not before.
        rig.st.add_want(bob, true, t0 + ms(199_200));
        assert!(rig.run_until(t0 + ms(199_299)).await.is_empty());
        rig.st.add_want(bob, true, t0 + ms(199_300));
        let sent = rig.run_until(t0 + secs(201)).await;
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, t0 + ms(199_600));
        // An answer brings the gap back to 15 s: no doubling after it.
        let mut sched = PeerSched::default();
        sched.queried(t0);
        sched.queried(t0 + secs(15));
        assert_eq!(sched.gap, secs(30));
        sched.answered();
        sched.queried(t0 + secs(45));
        assert_eq!(sched.gap, PEER_GAP_MIN);
        for _ in 0..10 {
            sched.queried(t0);
        }
        assert_eq!(sched.gap, PEER_GAP_MAX);
        // An authenticated link starts it over too.
        rig.st.peers.insert(bob, sched);
        rig.st.on_msg(Msg::Linked(bob), t0 + secs(201));
        assert!(!rig.st.peers.contains_key(&bob));
    }

    /// A contact found less than 2 min ago is not asked for; a want that a
    /// find overtakes is left out of its round, which then costs nothing
    /// (§8).
    #[tokio::test(start_paused = true)]
    async fn fresh_candidate_suppresses_a_query() {
        let people = [person(1), person(2)];
        let (bob, carol) = (key(&people[0]), key(&people[1]));
        let mut rig = rig_for(&people);
        rig.start().await;
        let t0 = rig.t0;
        let found = |at: Instant| Candidate {
            addr: "192.168.1.30:47532".parse().unwrap(),
            iface: EN0,
            at,
        };
        rig.shared.add_candidate(bob, found(t0));
        rig.st.add_want(bob, false, t0 + secs(1));
        rig.st.add_want(bob, true, t0 + secs(1));
        assert_eq!(rig.st.next_at(), None);
        // Carol is wanted, then found before her round.
        rig.st.add_want(carol, false, t0 + secs(3));
        rig.shared.add_candidate(carol, found(t0 + ms(3100)));
        assert!(rig.run_until(t0 + secs(4)).await.is_empty());
        assert_eq!(rig.st.rounds.tokens, ROUND_BURST, "no token used");
        // Older than two minutes: asked for again.
        rig.st.add_want(bob, false, t0 + secs(121));
        let sent = rig.run_until(t0 + secs(122)).await;
        assert_eq!(sent.len(), 1);
        assert_eq!(
            named(&sent[0].1.bytes, ip("192.168.1.20"), &people),
            [(0, PORT)]
        );
        // A candidate on an interface the task left holds nothing back.
        rig.shared.add_candidate(carol, found(t0 + secs(150)));
        rig.st.set_ifaces(vec![v4_only(en5())]);
        rig.st.add_want(carol, false, t0 + secs(151));
        assert!(rig.st.next_at().is_some());
    }

    /// A contact added after the task read the book is asked for at its
    /// first want: the want reads the book again first. Before, the book
    /// stayed as it was until a change, a query or a round came, so a
    /// contact added after the start was never named (the fault matrix's
    /// s83 found it).
    #[tokio::test(start_paused = true)]
    async fn a_contact_added_after_the_book_was_read_is_asked_for() {
        let people = [person(1)];
        let bob = key(&people[0]);
        let mut rig = rig_for(&[]);
        rig.start().await;
        let t0 = rig.t0;
        lock(&rig.host.rows).push((bob, true));
        rig.host.stamp.fetch_add(1, Ordering::SeqCst);
        let at = t0 + secs(2);
        rig.st.on_message(Msg::Want(bob, true, at), at).await;
        let sent = rig.run_until(t0 + secs(3)).await;
        assert_eq!(sent.len(), 1, "one query");
        assert_eq!(
            named(&sent[0].1.bytes, ip("192.168.1.20"), &people),
            [(0, PORT)]
        );
        // A link message reads nothing.
        rig.host.locked.store(true, Ordering::SeqCst);
        rig.host.stamp.fetch_add(1, Ordering::SeqCst);
        rig.st.on_message(Msg::Linked(bob), t0 + secs(5)).await;
        assert!(rig.st.book.has(&bob));
    }

    /// Phase 3: a custodian's join round names the recipients it holds
    /// mail for first, then the contacts seen on the LAN lately, each once,
    /// at most 8 in all.
    #[test]
    fn join_round_names_held_recipients_first_at_most_8() {
        let k = |n: u8| [n; 32];
        let held = [k(1), k(2)];
        let recent: Vec<[u8; 32]> = (2..12).map(k).collect();
        let set = join_set(&held, &recent);
        assert_eq!(set.len(), JOIN_MAX);
        assert_eq!(&set[..3], &[k(1), k(2), k(3)], "held first, once each");
        assert_eq!(join_set(&[], &recent), recent[..JOIN_MAX].to_vec());
        let many: Vec<[u8; 32]> = (20..40).map(k).collect();
        assert_eq!(join_set(&many, &recent), many[..JOIN_MAX].to_vec());
        assert!(join_set(&[], &[]).is_empty());
    }

    /// Reviews cross-1 and cross-3: the service's own host. A custodian
    /// that holds only a sealed letter needs a join round while it serves
    /// the letter ops, and its round names the letter's verified recipient
    /// first; with the letter gate closed the letter is no need and names
    /// nobody. One that holds only custody handoff rows needs a round too
    /// (their next hop is wanted by the forwarder).
    #[tokio::test]
    async fn held_letters_and_next_hops_need_a_join_round() {
        use raven_core::custody_gate::{
            set_custody_gates_for_this_thread, set_handoff_gate_for_this_thread, CustodyGates,
        };
        use raven_core::horizon::{
            set_lab_horizon_for_this_thread, set_lab_letter_for_this_thread,
        };
        // No meeting time is set while this runs: the one test that sets
        // one holds the LAN switch's write guard, and this its read guard.
        let _lan = crate::lan_direct::lan_switch_untouched();
        let (bob, carol, stranger, hop) = (person(1), person(2), person(3), [0xE3; 32]);
        let dir = profile(&[(&bob, true), (&carol, true)], &[]);
        let host = NodeHost {
            data_dir: dir.path().to_path_buf(),
        };
        let now = raven_core::clock::now_ms();
        let mut store =
            raven_core::friend_custody::CustodyStore::open_or_create(dir.path()).unwrap();
        for (digest, to) in [([0xD1; 32], key(&stranger)), ([0xD2; 32], key(&bob))] {
            store
                .deposit_letter(&digest, &to, &key(&carol), &[7; 900], now + 3_600_000, now)
                .unwrap();
        }
        drop(store);
        set_custody_gates_for_this_thread(Some(CustodyGates {
            live: true,
            wan: false,
        }));
        set_lab_horizon_for_this_thread(Some(true));
        set_handoff_gate_for_this_thread(Some(false));
        let mut seen = Vec::new();
        for letters in [true, false] {
            set_lab_letter_for_this_thread(Some(letters));
            seen.push((host.need(now).await, host.recent(now).await));
        }
        // No letter gate; a forward row's next hop.
        set_handoff_gate_for_this_thread(Some(true));
        let none = host.need(now).await;
        crate::custody::note_forward_hop_for_tests(&hop, true);
        let hop_need = host.need(now).await;
        crate::custody::note_forward_hop_for_tests(&hop, false);
        set_lab_letter_for_this_thread(None);
        set_handoff_gate_for_this_thread(None);
        set_lab_horizon_for_this_thread(None);
        set_custody_gates_for_this_thread(None);
        assert_eq!(
            seen[0],
            (true, vec![key(&bob)]),
            "the letter's recipient; the stranger is no contact"
        );
        assert_eq!(seen[1], (false, Vec::new()), "the letter gate closed");
        assert!(!none, "nothing else waits");
        assert!(hop_need, "a next hop waits");
    }

    /// One join round per start and per change: the contacts seen on the LAN
    /// lately, at most 8 of them, and only those in the book (§8).
    #[tokio::test(start_paused = true)]
    async fn join_round_once_per_change_from_recent_lan_contacts_at_most_8() {
        let people: Vec<Identity> = (0..10).map(person).collect();
        let stranger = person(30);
        let mut rig = rig_for(&people);
        let mut recent: Vec<[u8; 32]> = people.iter().map(key).collect();
        recent.insert(1, key(&stranger));
        *lock(&rig.host.recent) = recent;
        rig.start().await;
        let t0 = rig.t0;
        let src = ip("192.168.1.20");
        let joined = |rounds: &[(Instant, Out)]| -> Vec<usize> {
            rounds
                .iter()
                .flat_map(|(_, q)| named(&q.bytes, src, &people))
                .map(|(i, port)| {
                    assert_eq!(port, PORT, "its slots carry the listener port");
                    i
                })
                .collect()
        };
        let rounds = rig.run_until(t0 + secs(600)).await;
        assert_eq!(rounds.len(), 1, "{rounds:?}");
        assert_eq!(rounds[0].0, t0 + COALESCE);
        // The first eight of the list: the stranger is no contact.
        assert_eq!(joined(&rounds), (0..7).collect::<Vec<_>>());
        assert!(named(&rounds[0].1.bytes, src, &[stranger]).is_empty());
        // A change: one more round, and nothing after it.
        let t1 = t0 + secs(600);
        rig.st.changed(vec![v4_only(en0())], t1).await;
        let rounds = rig.run_until(t1 + secs(600)).await;
        assert_eq!(rounds.len(), 1);
        assert_eq!(joined(&rounds), (0..7).collect::<Vec<_>>());
    }

    /// A join round asked for while the book cannot be read (the at-rest
    /// key is still loading) is owed, and goes once the book reads; until
    /// then nobody is named (§8).
    #[tokio::test(start_paused = true)]
    async fn a_join_round_waits_for_a_book_that_cannot_be_read_yet() {
        let people = [person(1)];
        let mut rig = rig_for(&people);
        *lock(&rig.host.recent) = vec![key(&people[0])];
        rig.host.locked.store(true, Ordering::SeqCst);
        rig.start().await;
        let t0 = rig.t0;
        assert!(rig.st.join_owed);
        assert!(rig.run_until(t0 + secs(10)).await.is_empty());
        rig.st.add_want(key(&people[0]), false, t0 + secs(10));
        assert!(rig.st.due.is_empty(), "not in the book yet");
        // The key is here: the book's stamp moves, and it reads.
        rig.host.locked.store(false, Ordering::SeqCst);
        rig.host.stamp.fetch_add(1, Ordering::SeqCst);
        let rounds = rig.run_until(t0 + secs(20)).await;
        assert_eq!(rounds.len(), 1);
        assert_eq!(rounds[0].0, t0 + secs(11) + COALESCE);
        let src = ip("192.168.1.20");
        assert_eq!(named(&rounds[0].1.bytes, src, &people), [(0, PORT)]);
        assert!(!rig.st.join_owed);
    }

    /// A contact is answered at most once per 2 s; the answer goes to its
    /// interface, twice, and carries this node's port for it alone (§5,
    /// §6). Its own port makes it a candidate, and what waits for it due.
    #[tokio::test(start_paused = true)]
    async fn answer_limit_one_per_contact_per_2s() {
        let bob = person(1);
        let mut rig = rig_for(std::slice::from_ref(&bob));
        rig.start().await;
        let t0 = rig.t0;
        let q1 = their_query(&bob, "192.168.1.30", THEIR_PORT, 1);
        rig.deliver(&q1, from("192.168.1.30"), t0).await;
        let sent = rig.sent();
        assert_eq!(sent.len(), 1, "{sent:?}");
        assert_eq!(
            (sent[0].index, sent[0].v6, sent[0].bytes.len()),
            (EN0, false, ANSWER_LEN)
        );
        assert_eq!(
            opened(&sent[0].bytes, &bob, &q1, "192.168.1.20", "192.168.1.30"),
            Some(PORT)
        );
        assert_eq!(
            rig.shared.candidates(&key(&bob), t0),
            ["192.168.1.30:47532"]
        );
        assert_eq!(rig.host.found(), [key(&bob)]);
        // Its second copy.
        rig.timer(t0 + REPEAT_GAP).await;
        assert_eq!(rig.sent(), sent);
        // Another query a second later: not answered (but seen).
        let q2 = their_query(&bob, "192.168.1.30", THEIR_PORT, 2);
        rig.deliver(&q2, from("192.168.1.30"), t0 + secs(1)).await;
        assert!(rig.sent().is_empty());
        assert_eq!(rig.host.found().len(), 2);
        // 2.5 s after the first: answered.
        let q3 = their_query(&bob, "192.168.1.30", THEIR_PORT, 3);
        rig.deliver(&q3, from("192.168.1.30"), t0 + ms(2500)).await;
        let sent = rig.sent();
        assert_eq!(answers(&sent).len(), 1);
        assert_eq!(
            opened(&sent[0].bytes, &bob, &q3, "192.168.1.20", "192.168.1.30"),
            Some(PORT)
        );
        assert_eq!(rig.counts(t0 + secs(3)).answers_sent_10m, 2);
        // A network change: an answer on the old network holds none back.
        rig.st.changed(vec![v4_only(en0())], t0 + ms(2600)).await;
        let q4 = their_query(&bob, "192.168.1.30", THEIR_PORT, 4);
        rig.deliver(&q4, from("192.168.1.30"), t0 + ms(2700)).await;
        assert_eq!(answers(&rig.sent()).len(), 1);
    }

    /// A matched query seen again is a replay: no answer, a drop counted. Its
    /// second copy within seconds is no replay and no drop (§3, §6).
    #[tokio::test(start_paused = true)]
    async fn a_replayed_query_is_answered_once() {
        let bob = person(1);
        let mut rig = rig_for(std::slice::from_ref(&bob));
        rig.start().await;
        let t0 = rig.t0;
        let q = their_query(&bob, "192.168.1.30", THEIR_PORT, 1);
        rig.deliver(&q, from("192.168.1.30"), t0).await;
        assert_eq!(answers(&rig.sent()).len(), 1);
        rig.deliver(&q, from("192.168.1.30"), t0 + ms(250)).await;
        rig.deliver(&q, from("192.168.1.30"), t0 + ms(300)).await;
        assert!(rig.sent().is_empty());
        assert_eq!(rig.counts(t0 + secs(1)).dropped_10m, 0, "a second copy");
        rig.deliver(&q, from("192.168.1.30"), t0 + secs(10)).await;
        rig.deliver(&q, from("192.168.1.30"), t0 + secs(29 * 60))
            .await;
        assert!(rig.sent().is_empty());
        assert_eq!(rig.counts(t0 + secs(29 * 60)).dropped_10m, 1, "the replays");
        assert_eq!(rig.host.found(), [key(&bob)], "nothing kept again");
    }

    /// Phase 6b S22, R1 (P6.26): a replay of a matched query is a strike of
    /// 4 against the source that sent it, a query over its source's rate a
    /// strike of 1. A source the penalty box banned gets no answer at all,
    /// not even to a contact's genuine query, while every other source still
    /// does; once the ban ends it is answered again.
    #[tokio::test(start_paused = true)]
    async fn a_banned_source_is_not_answered_and_replays_and_floods_strike() {
        let bob = person(1);
        let mut rig = rig_for(std::slice::from_ref(&bob));
        rig.start().await;
        let t0 = rig.t0;
        let q = their_query(&bob, "192.168.1.30", THEIR_PORT, 1);
        rig.deliver(&q, from("192.168.1.30"), t0).await;
        assert_eq!(answers(&rig.sent()).len(), 1);
        // Someone else replays it, four times 10 s apart (past the repeat
        // filter, within its rate): 4 x 4 strikes ban its source.
        let replayer = "192.168.1.66";
        for n in 0..4 {
            assert!(!rig.host.source_banned(ip(replayer), t0 + secs(10 + 10 * n)));
            rig.deliver(&q, from(replayer), t0 + secs(10 + 10 * n))
                .await;
            assert!(rig.sent().is_empty());
        }
        let banned_at = t0 + secs(40);
        assert!(rig.host.source_banned(ip(replayer), banned_at));
        assert_eq!(*lock(&rig.host.refusals), [(ip(replayer), true); 4]);
        // Bob behind that address: not answered while the ban lasts.
        let from_there = their_query(&bob, replayer, THEIR_PORT, 2);
        rig.deliver(&from_there, from(replayer), banned_at + secs(5))
            .await;
        assert!(rig.sent().is_empty(), "a banned source gets nothing");
        // Bob from his own address still is.
        let q2 = their_query(&bob, "192.168.1.30", THEIR_PORT, 3);
        rig.deliver(&q2, from("192.168.1.30"), banned_at + secs(6))
            .await;
        assert_eq!(answers(&rig.sent()).len(), 1);
        // The ban (60 s) is over: answered again.
        let later = their_query(&bob, replayer, THEIR_PORT, 4);
        rig.deliver(&later, from(replayer), banned_at + secs(60))
            .await;
        assert_eq!(answers(&rig.sent()).len(), 1);
        // A flood from one source: its burst (4) is within its rate, the
        // other 16 are over it, a strike each: banned.
        let flooder = "192.168.1.77";
        let at = banned_at + secs(70);
        for n in 0..20 {
            let junk = their_query(&person(30), flooder, THEIR_PORT, 100 + n);
            rig.deliver(&junk, from(flooder), at).await;
        }
        assert!(rig.sent().is_empty());
        let floods: Vec<_> = lock(&rig.host.refusals)
            .iter()
            .filter(|(src, _)| *src == ip(flooder))
            .copied()
            .collect();
        assert_eq!(floods, [(ip(flooder), false); 16]);
        assert!(rig.host.source_banned(ip(flooder), at));
        assert!(!rig.host.source_banned(ip("192.168.1.30"), at));
    }

    /// A query from someone who is no contact, or naming someone else,
    /// gets nothing: no answer, no candidate, nothing made due (§6).
    #[tokio::test(start_paused = true)]
    async fn stranger_query_gets_no_answer_and_records_nothing() {
        let people = [person(1), person(2)];
        let (bob, carol, stranger) = (&people[0], &people[1], person(30));
        let mut rig = rig_for(&people);
        rig.start().await;
        let t0 = rig.t0;
        let q = their_query(&stranger, "192.168.1.40", THEIR_PORT, 1);
        rig.deliver(&q, from("192.168.1.40"), t0).await;
        // Bob asks for Carol, not for this node.
        let to_carol = pair_keys(bob, &key(carol)).unwrap();
        let q = build_query(
            &mut StdRng::seed_from_u64(2),
            EPOCH,
            ip("192.168.1.30"),
            THEIR_PORT,
            &[&to_carol],
        );
        rig.deliver(&q, from("192.168.1.30"), t0 + secs(1)).await;
        assert!(rig.sent().is_empty());
        assert!(rig.host.found().is_empty());
        for p in [bob, carol, &stranger] {
            assert!(rig.shared.candidates(&key(p), t0 + secs(1)).is_empty());
        }
        let counts = rig.counts(t0 + secs(1));
        assert_eq!((counts.answers_sent_10m, counts.dropped_10m), (0, 0));
    }

    /// A profile in a temp dir with these contacts (`pinned`) and blocks.
    fn profile(contacts: &[(&Identity, bool)], blocked: &[&Identity]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let rows: Vec<serde_json::Value> = contacts
            .iter()
            .map(
                |(p, pinned)| serde_json::json!({"pub_hex": hex::encode(key(p)), "pinned": pinned}),
            )
            .collect();
        std::fs::write(
            dir.path().join(raven_core::contact_book::CONTACTS_FILE),
            serde_json::to_vec(&rows).unwrap(),
        )
        .unwrap();
        block(dir.path(), blocked);
        dir
    }

    fn block(dd: &Path, blocked: &[&Identity]) {
        let mut blocks = raven_core::BlockList::default();
        for p in blocked {
            blocks.block(&hex::encode(key(p)));
        }
        blocks.save(dd).unwrap();
    }

    /// The pair seed `seed` (generation 1) as this node's profile `dd`
    /// keeps it for `peer` once both use it (P6.38).
    fn seeded(dd: &Path, peer: &[u8; 32], seed: [u8; 32]) {
        use raven_core::pair_seed::{incoming, is_leader, outgoing, SeedEntry};
        let mine = key(&me());
        let ack = SeedEntry::new(1, seed, 1);
        if is_leader(&mine, peer) {
            outgoing(dd, &mine, peer, NOW_MS, || seed).unwrap();
        }
        incoming(dd, &mine, peer, Some(&ack), NOW_MS).unwrap();
    }

    /// P6.38: while pair seeds are live the book holds a contact's key
    /// sets. A query made with the pair's seed is matched and answered with
    /// it (never with the root); one made with the root still is (the
    /// fallback: no lockout), and is `SEC_PAIR_SEED_ROOT` since the seed was
    /// expected; this node asks with its seed, and the contact's answer made
    /// with the seed opens. With the gate shut the book is the root's alone.
    #[tokio::test(start_paused = true)]
    async fn pair_seeds_match_with_the_seed_and_fall_back_to_the_root() {
        use raven_core::lan_beacon::pair_keys_from;
        use raven_core::security_events::{Attribution, SecKind};
        let bob = person(1);
        let dir = profile(&[(&bob, true)], &[]);
        let (mine, theirs) = (key(&me()), key(&bob));
        let seed = [0x38; 32];
        seeded(dir.path(), &theirs, seed);
        let root = raven_core::lan_beacon::pair_root(&bob, &mine).unwrap();
        let k_pair = raven_core::pair_seed::pair_key(&root, &seed);
        // Bob's keys as Bob holds them.
        let bob_seeded = pair_keys_from(&theirs, &mine, &k_pair);
        let bob_root = pair_keys(&bob, &mine).unwrap();
        // Shut: the root's set alone.
        let shut = TestHost::with_profile(&me(), dir.path());
        let mut rig = Rig::new(shut, vec![v4_only(en0())]);
        rig.start().await;
        assert_eq!(rig.st.book.keys.len(), 1);
        let host = TestHost::with_profile(&me(), dir.path());
        host.seeds.store(true, Ordering::SeqCst);
        let mut rig = Rig::new(host, vec![v4_only(en0())]);
        rig.start().await;
        let t0 = rig.t0;
        assert_eq!(rig.st.book.keys.len(), 2, "the seed's set and the root's");
        assert!(rig.st.book.uses[0].send && !rig.st.book.uses[0].notice);
        assert!(!rig.st.book.uses[1].send && rig.st.book.uses[1].notice);
        let bob_src = "192.168.1.30";
        // This node asks for Bob with its seed, and Bob's answer made with
        // the seed opens.
        rig.st.add_want(theirs, false, t0);
        let rounds = rig.run_until(t0 + secs(1)).await;
        assert_eq!(rounds.len(), 1);
        let q = rounds[0].1.bytes.clone();
        let here = ip("192.168.1.20");
        assert_eq!(
            match_query(&q, here, EPOCH, &[pair_keys_from(&theirs, &mine, &k_pair)]),
            vec![(0, PORT)]
        );
        assert!(match_query(&q, here, EPOCH, &[pair_keys(&bob, &mine).unwrap()]).is_empty());
        let nonce: [u8; 16] = q[..16].try_into().unwrap();
        let answer = build_answer(
            &mut StdRng::seed_from_u64(3),
            &bob_seeded,
            &nonce,
            ip(bob_src),
            here,
            THEIR_PORT,
        );
        rig.deliver(&answer, from(bob_src), t0 + secs(1)).await;
        assert_eq!(rig.host.found(), [theirs]);
        let capture = crate::security::tests::Capture::start();
        let ask = |k: &PairKeys, n: u64| {
            build_query(
                &mut StdRng::seed_from_u64(n),
                EPOCH,
                ip(bob_src),
                THEIR_PORT,
                &[k],
            )
            .to_vec()
        };
        let open = |a: &[u8], k: &PairKeys, q: &[u8]| {
            let nonce: [u8; 16] = q[..16].try_into().unwrap();
            open_answer(a, k, &nonce, here, ip(bob_src))
        };
        // Bob asks with the seed: answered with the seed's keys.
        let q = ask(&bob_seeded, 1);
        rig.deliver(&q, from(bob_src), t0 + secs(5)).await;
        let sent = rig.sent();
        let a = answers(&sent);
        assert_eq!(a.len(), 1);
        assert_eq!(open(&a[0].bytes, &bob_seeded, &q), Some(PORT));
        assert_eq!(open(&a[0].bytes, &bob_root, &q), None);
        if let Some(c) = &capture {
            assert!(c.events().is_empty(), "the seed is no notice");
        }
        // With the root: still answered (the fallback), with the root's.
        let q = ask(&bob_root, 2);
        rig.deliver(&q, from(bob_src), t0 + secs(9)).await;
        let sent = rig.sent();
        let a = answers(&sent);
        assert_eq!(a.len(), 1);
        assert_eq!(open(&a[0].bytes, &bob_root, &q), Some(PORT));
        if let Some(c) = &capture {
            assert_eq!(
                c.kinds(),
                [(
                    SecKind::PairSeedRoot,
                    Attribution::Contact { peer: theirs },
                    Via::DirectLink(OutboxCarrier::Lan),
                )]
            );
        }
    }

    /// A blocked contact is not in the book and gets no answer; one blocked
    /// after the book was read is refused by the link gate (§6).
    #[tokio::test(start_paused = true)]
    async fn blocked_contact_gets_no_answer() {
        let (bob, carol) = (person(1), person(2));
        let dir = profile(&[(&bob, true), (&carol, true)], &[&carol]);
        let mut rig = Rig::new(
            TestHost::with_profile(&me(), dir.path()),
            vec![v4_only(en0())],
        );
        rig.start().await;
        let t0 = rig.t0;
        assert!(!rig.st.book.has(&key(&carol)) && rig.st.book.has(&key(&bob)));
        let q = their_query(&carol, "192.168.1.31", THEIR_PORT, 1);
        rig.deliver(&q, from("192.168.1.31"), t0).await;
        assert!(rig.sent().is_empty());
        let q = their_query(&bob, "192.168.1.30", THEIR_PORT, 2);
        rig.deliver(&q, from("192.168.1.30"), t0 + secs(1)).await;
        assert_eq!(answers(&rig.sent()).len(), 1);
        // Bob is blocked now; the book is not read again yet.
        block(dir.path(), &[&carol, &bob]);
        rig.st.book.checked = Some(t0 + secs(5));
        let q = their_query(&bob, "192.168.1.30", THEIR_PORT, 3);
        rig.deliver(&q, from("192.168.1.30"), t0 + secs(5)).await;
        assert!(rig.sent().is_empty());
        assert_eq!(
            rig.host.found(),
            [key(&bob)],
            "nothing kept after the block"
        );
        assert!(rig.shared.candidates(&key(&carol), t0 + secs(5)).is_empty());
        // Read again, the book has no Bob: not even matched.
        rig.st.book.checked = None;
        let q = their_query(&bob, "192.168.1.30", THEIR_PORT, 4);
        rig.deliver(&q, from("192.168.1.30"), t0 + secs(9)).await;
        assert!(rig.sent().is_empty());
        assert!(!rig.st.book.has(&key(&bob)));
    }

    /// An unverified contact is answered from a private address, but not
    /// from an on-link global one (the link gate's local rule); a verified
    /// one is answered from both, and a source that is not local at all is
    /// dropped before anything (§6, owner decision: unverified contacts on
    /// the local network only).
    #[tokio::test(start_paused = true)]
    async fn unverified_contact_answered_only_from_a_local_source() {
        let (unverified, verified) = (person(1), person(2));
        let dir = profile(&[(&unverified, false), (&verified, true)], &[]);
        let host = TestHost::with_profile(&me(), dir.path());
        host.set_listeners(&["0.0.0.0:47531", "[::]:47531"]);
        *lock(&host.on_link) = vec![ip("2001:db8:1:2::31"), ip("2001:db8:1:2::32")];
        let mut rig = Rig::new(host, vec![en0()]);
        rig.start().await;
        let t0 = rig.t0;
        let q = their_query(&unverified, "192.168.1.31", THEIR_PORT, 1);
        rig.deliver(&q, from("192.168.1.31"), t0).await;
        let sent = rig.sent();
        assert_eq!(answers(&sent).len(), 1);
        assert_eq!(
            opened(
                &sent[0].bytes,
                &unverified,
                &q,
                "192.168.1.20",
                "192.168.1.31"
            ),
            Some(PORT)
        );
        let q = their_query(&unverified, "2001:db8:1:2::31", THEIR_PORT, 2);
        rig.deliver(&q, from("2001:db8:1:2::31"), t0 + secs(3))
            .await;
        assert!(rig.sent().is_empty());
        assert_eq!(rig.host.found(), [key(&unverified)]);
        let q = their_query(&verified, "2001:db8:1:2::32", THEIR_PORT, 3);
        rig.deliver(&q, from("2001:db8:1:2::32"), t0 + secs(4))
            .await;
        let sent = rig.sent();
        assert_eq!(answers(&sent).len(), 1);
        assert_eq!((sent[0].index, sent[0].v6), (EN0, true));
        assert_eq!(
            opened(
                &sent[0].bytes,
                &verified,
                &q,
                "fe80::20",
                "2001:db8:1:2::32"
            ),
            Some(PORT)
        );
        // Not local: dropped, verified or not.
        let q = their_query(&verified, "203.0.113.7", THEIR_PORT, 4);
        rig.deliver(&q, from("203.0.113.7"), t0 + secs(9)).await;
        assert!(rig.sent().is_empty());
        assert_eq!(rig.counts(t0 + secs(9)).dropped_10m, 1);
        // The verified one was answered, but its on-link global address is
        // no find the outbox dials: not kept (review A-4).
        assert_eq!(rig.host.found(), [key(&unverified)]);
    }

    /// Phase 3 P3.C2: under `raven lan verified-only on` the book holds the
    /// pinned contacts only, so an unpinned one is neither asked for nor
    /// answered; turned off, it is again (§6 "The book").
    #[tokio::test(start_paused = true)]
    async fn verified_only_answers_pinned_contacts_only() {
        let (unpinned, pinned) = (person(1), person(2));
        let dir = profile(&[(&unpinned, false), (&pinned, true)], &[]);
        raven_core::node_policy::set_lan_verified_only(dir.path(), true).unwrap();
        let mut rig = Rig::new(
            TestHost::with_profile(&me(), dir.path()),
            vec![v4_only(en0())],
        );
        rig.start().await;
        let t0 = rig.t0;
        let q = their_query(&unpinned, "192.168.1.31", THEIR_PORT, 1);
        rig.deliver(&q, from("192.168.1.31"), t0).await;
        assert!(rig.sent().is_empty());
        assert!(rig.host.found().is_empty());
        let q = their_query(&pinned, "192.168.1.32", THEIR_PORT, 2);
        rig.deliver(&q, from("192.168.1.32"), t0 + secs(1)).await;
        assert_eq!(answers(&rig.sent()).len(), 1);
        rig.st.add_want(key(&unpinned), false, t0 + secs(2));
        assert_eq!(
            rig.st.next_at(),
            Some(t0 + secs(1) + REPEAT_GAP),
            "only the repeat"
        );
        // Off again: the book is read again and the contact is answered.
        raven_core::node_policy::set_lan_verified_only(dir.path(), false).unwrap();
        rig.st.book.checked = None;
        rig.sent();
        let q = their_query(&unpinned, "192.168.1.31", THEIR_PORT, 3);
        rig.deliver(&q, from("192.168.1.31"), t0 + secs(4)).await;
        let sent = rig.sent();
        assert_eq!(answers(&sent).len(), 1);
        assert_eq!(
            opened(
                &sent[0].bytes,
                &unpinned,
                &q,
                "192.168.1.20",
                "192.168.1.31"
            ),
            Some(PORT)
        );
    }

    /// No answer while the LAN listener cannot be reached on that interface
    /// (loopback only, another interface's address) or LAN is off; a query
    /// still names this node with port 0 then (§4, §6).
    #[tokio::test(start_paused = true)]
    async fn no_answer_when_listener_is_loopback_only_or_lan_off() {
        let bob = person(1);
        let mut rig = rig_for(std::slice::from_ref(&bob));
        rig.start().await;
        let t0 = rig.t0;
        // This node's query names Bob with port 0: its listener is on
        // loopback only.
        rig.host.set_listeners(&["127.0.0.1:47531"]);
        rig.st.add_want(key(&bob), false, t0);
        let rounds = rig.run_until(t0 + ms(400)).await;
        let src = ip("192.168.1.20");
        let found = named(&rounds[0].1.bytes, src, std::slice::from_ref(&bob));
        assert_eq!(found, [(0, 0)]);
        let mut at = t0;
        let mut ask = |seed: u64| {
            at += secs(3);
            (their_query(&bob, "192.168.1.30", THEIR_PORT, seed), at)
        };
        let (q, when) = ask(1);
        rig.deliver(&q, from("192.168.1.30"), when).await;
        assert!(answers(&rig.sent()).is_empty());
        assert_eq!(rig.host.found(), [key(&bob)], "Bob's own port still counts");
        rig.host.set_listeners(&["10.9.9.9:47531"]);
        let (q, when) = ask(2);
        rig.deliver(&q, from("192.168.1.30"), when).await;
        assert!(answers(&rig.sent()).is_empty());
        rig.host.set_listeners(&["0.0.0.0:47531"]);
        rig.host.lan.send_replace(false);
        let (q, when) = ask(3);
        rig.deliver(&q, from("192.168.1.30"), when).await;
        assert!(answers(&rig.sent()).is_empty());
        rig.host.lan.send_replace(true);
        let (q, when) = ask(4);
        rig.deliver(&q, from("192.168.1.30"), when).await;
        assert_eq!(answers(&rig.sent()).len(), 1);
    }

    /// With an IPv4-only listener (`auto` with its gate closed is
    /// 0.0.0.0:7420), IPv6 queries are not answered and this node's IPv6
    /// slots carry port 0; with an IPv6 socket too, both are (§6: one rule
    /// per address family).
    #[tokio::test(start_paused = true)]
    async fn no_v6_answer_and_port_0_in_v6_slots_with_an_ipv4_only_listener() {
        let people = [person(1), person(2)];
        let (bob, carol) = (&people[0], &people[1]);
        let mut rig = rig(&people, vec![en0()]);
        rig.start().await;
        let t0 = rig.t0;
        let port_in = |rounds: &[(Instant, Out)], v6: bool, src: &str| {
            let (_, query) = rounds.iter().find(|(_, o)| o.v6 == v6).unwrap();
            named(&query.bytes, ip(src), &people)
        };
        rig.st.add_want(key(carol), false, t0);
        let rounds = rig.run_until(t0 + ms(400)).await;
        assert_eq!(rounds.len(), 2, "IPv4 and IPv6");
        assert_eq!(port_in(&rounds, false, "192.168.1.20"), [(1, PORT)]);
        assert_eq!(port_in(&rounds, true, "fe80::20"), [(1, 0)]);
        let q6 = their_query(bob, "fe80::30", THEIR_PORT, 1);
        rig.deliver(&q6, from_ll("fe80::30", EN0), t0 + secs(1))
            .await;
        assert!(answers(&rig.sent()).is_empty());
        assert_eq!(
            rig.shared.candidates(&key(bob), t0 + secs(1)),
            ["[fe80::30%901]:47532"],
            "its link-local address keeps the zone"
        );
        let q4 = their_query(bob, "192.168.1.30", THEIR_PORT, 2);
        rig.deliver(&q4, from("192.168.1.30"), t0 + secs(4)).await;
        assert_eq!(answers(&rig.sent()).len(), 1);
        // An IPv6 socket too: both families.
        rig.host.set_listeners(&["0.0.0.0:47531", "[::]:47531"]);
        rig.st.add_want(key(carol), false, t0 + secs(20));
        let rounds = rig.run_until(t0 + secs(21)).await;
        assert_eq!(port_in(&rounds, true, "fe80::20"), [(1, PORT)]);
        let q6 = their_query(bob, "fe80::30", THEIR_PORT, 3);
        rig.deliver(&q6, from_ll("fe80::30", EN0), t0 + secs(30))
            .await;
        let sent = rig.sent();
        let a = answers(&sent);
        assert_eq!(a.len(), 1);
        assert_eq!((a[0].index, a[0].v6), (EN0, true));
        assert_eq!(
            opened(&a[0].bytes, bob, &q6, "fe80::20", "fe80::30"),
            Some(PORT)
        );
    }

    /// An answer counts within 3 s of a query on its own interface: a late
    /// one, or one that comes in on another interface, is not opened (§7).
    #[tokio::test(start_paused = true)]
    async fn answer_after_3s_or_on_another_interface_is_ignored() {
        let bob = person(1);
        let mut rig = rig(std::slice::from_ref(&bob), vec![v4_only(en0()), en5()]);
        rig.start().await;
        let t0 = rig.t0;
        rig.st.add_want(key(&bob), false, t0);
        let rounds = rig.run_until(t0 + ms(400)).await;
        let sent_on = |index: u32| {
            let (_, query) = rounds.iter().find(|(_, o)| o.index == index).unwrap();
            query.bytes.clone()
        };
        let (q0, q5) = (sent_on(EN0), sent_on(EN5));
        let t = rounds[0].0;
        let a0 = their_answer(&bob, &q0, "192.168.1.30", "192.168.1.20", 1);
        // Bob's answer to the en0 query, but it comes in on the hotspot.
        rig.deliver(&a0, from("10.42.0.30"), t + secs(1)).await;
        assert!(rig.host.found().is_empty());
        assert_eq!(rig.counts(t + secs(1)).answered_10m, 0);
        // The hotspot's own answer, in time.
        let a5 = their_answer(&bob, &q5, "10.42.0.30", "10.42.0.20", 2);
        rig.deliver(&a5, from("10.42.0.30"), t + ms(2900)).await;
        assert_eq!(rig.host.found(), [key(&bob)]);
        assert_eq!(rig.counts(t + ms(2900)).answered_10m, 1);
        assert!(rig.st.peers[&key(&bob)].answered);
        // On en0, but late.
        rig.deliver(&a0, from("192.168.1.30"), t + ms(3100)).await;
        assert_eq!(rig.host.found(), [key(&bob)]);
        let found = rig.shared.candidates(&key(&bob), t + secs(4));
        assert_eq!(found, ["10.42.0.30:47532"]);
        assert_eq!(rig.counts(t + secs(4)).answered_10m, 1);
        // An answer to a query of nobody's here costs nothing.
        rig.deliver(&a5, from("10.42.0.31"), t + secs(9)).await;
        assert_eq!(rig.counts(t + secs(9)).dropped_10m, 0);
    }

    /// This node's own query coming back says multicast works here; it is
    /// not answered and not counted as dropped. The same bytes from another
    /// address are no echo (§6 item 4).
    #[tokio::test(start_paused = true)]
    async fn own_echo_sets_echo_ok() {
        let bob = person(1);
        let mut rig = rig_for(std::slice::from_ref(&bob));
        rig.start().await;
        let t0 = rig.t0;
        rig.st.add_want(key(&bob), false, t0);
        let rounds = rig.run_until(t0 + ms(400)).await;
        let q = rounds[0].1.bytes.clone();
        rig.deliver(&q, from("192.168.1.66"), t0 + ms(301)).await;
        assert!(!rig.counts(t0 + secs(1)).echo_ok);
        rig.deliver(&q, from("192.168.1.20"), t0 + ms(302)).await;
        let counts = rig.counts(t0 + secs(1));
        assert!(counts.echo_ok);
        assert_eq!((counts.dropped_10m, counts.answers_sent_10m), (0, 0));
        assert!(answers(&rig.sent()).is_empty());
    }

    /// A candidate is dialled for 10 min and while its interface is one the
    /// task runs on; at most two, IPv4 first, a link-local one with its
    /// zone; the newest per interface and family (§7, §9).
    #[tokio::test(start_paused = true)]
    async fn candidate_expires_after_10min_and_with_its_interface() {
        let shared = Shared::new(STATE_ON);
        shared.set_ifaces(&[EN0, EN5]);
        let t0 = Instant::now();
        let bob = [0xB0; 32];
        let add = |addr: SocketAddr, iface: u32, at: Instant| {
            shared.add_candidate(bob, Candidate { addr, iface, at });
        };
        add("192.168.1.30:47532".parse().unwrap(), EN0, t0);
        add(
            candidate_addr(ip("fe80::30"), THEIR_PORT, EN0),
            EN0,
            t0 + secs(1),
        );
        add("10.42.0.30:47532".parse().unwrap(), EN5, t0 + secs(2));
        assert_eq!(
            shared.candidates(&bob, t0 + secs(3)),
            ["10.42.0.30:47532", "192.168.1.30:47532"]
        );
        assert!(shared.fresh(&bob, t0 + secs(121)));
        shared.set_ifaces(&[EN0]);
        assert_eq!(
            shared.candidates(&bob, t0 + secs(3)),
            ["192.168.1.30:47532", "[fe80::30%901]:47532"]
        );
        assert_eq!(
            shared.candidates(&bob, t0 + secs(600)),
            ["[fe80::30%901]:47532"]
        );
        assert!(shared.candidates(&bob, t0 + secs(601)).is_empty());
        assert!(!shared.fresh(&bob, t0 + secs(122)));
        // A newer one on the same interface and family takes the place.
        add("192.168.1.31:47532".parse().unwrap(), EN0, t0 + secs(700));
        assert_eq!(
            shared.candidates(&bob, t0 + secs(701)),
            ["192.168.1.31:47532"]
        );
        assert_eq!(lock(&shared.found).candidates[&bob].len(), 1);
    }

    /// `raven status`'s friends seen here (P3.C6): each contact with a live
    /// candidate once, for ten minutes, and only while its interface is one
    /// the task runs on.
    #[tokio::test(start_paused = true)]
    async fn found_lately_counts_each_contact_once_for_10min_on_current_interfaces() {
        let shared = Shared::new(STATE_ON);
        shared.set_ifaces(&[EN0, EN5]);
        let t0 = Instant::now();
        let (bob, carol) = ([0xB0; 32], [0xC0; 32]);
        let at = |addr: &str, iface: u32, at: Instant| Candidate {
            addr: addr.parse().unwrap(),
            iface,
            at,
        };
        shared.add_candidate(bob, at("192.168.1.30:47532", EN0, t0));
        shared.add_candidate(bob, at("[fd00::30]:47532", EN0, t0));
        shared.add_candidate(carol, at("10.42.0.31:47533", EN5, t0 + secs(60)));
        let mut here = shared.found_lately(t0 + secs(1));
        here.sort_unstable();
        assert_eq!(here, [bob, carol]);
        assert_eq!(shared.found_lately(t0 + secs(601)), [carol]);
        shared.set_ifaces(&[EN0]);
        assert!(shared.found_lately(t0 + secs(601)).is_empty());
        assert_eq!(shared.found_lately(t0 + secs(1)), [bob]);
    }

    /// The task as it runs: sockets open once LAN is on and the LAN listener
    /// has the identity, and LAN off closes them and forgets every candidate
    /// at once; on again, they open again.
    #[tokio::test(start_paused = true)]
    async fn lan_off_closes_sockets_and_clears_candidates() {
        let bob = person(1);
        let host = TestHost::new(&me(), vec![(key(&bob), true)]);
        *lock(&host.identity) = None;
        let net = FakeNet::default();
        *lock(&net.ifaces) = vec![v4_only(en0())];
        let shared = Shared::new(STATE_STARTING);
        let task = tokio::spawn(run_with(
            true,
            Arc::clone(&shared),
            Arc::clone(&host) as Arc<dyn Host>,
            Net::Fake(net.clone()),
            StdRng::seed_from_u64(3),
        ));
        let opened = || net.opened.load(Ordering::SeqCst);
        let open = || net.open.load(Ordering::SeqCst);
        tokio::time::sleep(secs(5)).await;
        assert_eq!(opened(), 0, "no identity yet");
        assert_eq!(shared.snapshot(Instant::now()).state, STATE_STARTING);
        *lock(&host.identity) = Some(Arc::new(me()));
        tokio::time::sleep(secs(2)).await;
        assert_eq!((open(), opened()), (1, 1));
        let counts = shared.snapshot(Instant::now());
        assert_eq!((counts.state.as_str(), counts.interfaces), (STATE_ON, 1));
        let q = their_query(&bob, "192.168.1.30", THEIR_PORT, 1);
        let inbox = lock(&net.inbox).clone().unwrap();
        inbox.send((q, from("192.168.1.30"))).unwrap();
        tokio::time::sleep(ms(10)).await;
        assert_eq!(
            shared.candidates(&key(&bob), Instant::now()),
            ["192.168.1.30:47532"]
        );
        // The answer goes out within its delay, and again (Phase 6b W-B3).
        tokio::time::sleep(SEND_DELAY_MAX + REPEAT_MAX).await;
        assert_eq!(answers(&lock(&net.sent)).len(), 2);
        host.lan.send_replace(false);
        tokio::time::sleep(ms(10)).await;
        assert_eq!(open(), 0, "closed");
        assert!(shared.candidates(&key(&bob), Instant::now()).is_empty());
        assert!(lock(&shared.found).candidates.is_empty());
        let counts = shared.snapshot(Instant::now());
        assert_eq!((counts.state.as_str(), counts.interfaces), (STATE_OFF, 0));
        assert!(!shared.running.load(Ordering::SeqCst));
        tokio::time::sleep(secs(600)).await;
        assert_eq!(opened(), 1, "nothing opens while LAN is off");
        host.lan.send_replace(true);
        tokio::time::sleep(ms(10)).await;
        assert_eq!((open(), opened()), (1, 2));
        task.abort();
    }

    /// With the gate closed (release builds) the task opens nothing, takes
    /// no want and ignores network changes; its state is `held`.
    #[tokio::test(start_paused = true)]
    async fn gate_closed_binds_no_udp_socket() {
        let host = TestHost::new(&me(), vec![([0xB0; 32], true)]);
        let net = FakeNet::default();
        *lock(&net.ifaces) = vec![en0()];
        let shared = Shared::new(STATE_STARTING);
        let task = tokio::spawn(run_with(
            false,
            Arc::clone(&shared),
            Arc::clone(&host) as Arc<dyn Host>,
            Net::Fake(net.clone()),
            StdRng::seed_from_u64(4),
        ));
        tokio::time::sleep(secs(60)).await;
        shared.changed.notify_one();
        shared.want(&[0xB0; 32], Want::Send, Instant::now());
        tokio::time::sleep(secs(3600)).await;
        assert_eq!(net.opened.load(Ordering::SeqCst), 0);
        assert!(lock(&net.sent).is_empty());
        assert_eq!(shared.snapshot(Instant::now()).state, STATE_HELD);
        assert!(!shared.running.load(Ordering::SeqCst));
        assert!(
            shared.rx.try_lock().unwrap().try_recv().is_err(),
            "no want queued"
        );
        let asked = Instant::now();
        assert!(shared.locate(&[0xB0; 32], LOCATE_MAX).await.is_empty());
        assert_eq!(Instant::now(), asked, "at once");
        task.abort();
    }

    /// The lab overrides are read in a debug build only: a release build
    /// (whose test job sets them all) runs on UDP 7420, both families, on
    /// the network. Only this test sets these variables.
    #[test]
    fn lab_bus_port_and_family_overrides_are_inert_without_debug_assertions() {
        let names = [
            "RAVEN_LAB_LAN_BEACON_PORT",
            "RAVEN_LAB_LAN_BEACON_FAMILY",
            "RAVEN_LAB_LAN_BEACON_BUS",
        ];
        // Edition 2021: plain calls. The bus path is never opened here.
        let bus = "/tmp/raven-lab-beacon-bus";
        if !cfg!(debug_assertions) {
            std::env::set_var(names[0], "17421");
            std::env::set_var(names[1], "v6");
            std::env::set_var(names[2], bus);
            assert_eq!((lab_port(), lab_family(), lab_bus()), (None, None, None));
            assert!(matches!(
                Net::from_env(),
                Net::Udp {
                    port: BEACON_PORT,
                    family: None
                }
            ));
            return;
        }
        // A caller's own values (a lab run) come back at the end.
        let saved: Vec<Option<String>> = names.iter().map(|n| std::env::var(n).ok()).collect();
        std::env::remove_var(names[2]);
        for (value, port) in [
            ("17421", Some(17421)),
            (" 9 ", Some(9)),
            ("0", None),
            ("x", None),
        ] {
            std::env::set_var(names[0], value);
            assert_eq!(lab_port(), port, "{value}");
        }
        for (value, family) in [
            ("v4", Some(Family::V4)),
            ("V6", Some(Family::V6)),
            ("both", None),
        ] {
            std::env::set_var(names[1], value);
            assert_eq!(lab_family(), family, "{value}");
        }
        std::env::set_var(names[0], "9");
        assert!(matches!(
            Net::from_env(),
            Net::Udp {
                port: 9,
                family: None
            }
        ));
        std::env::set_var(names[2], bus);
        assert_eq!(lab_bus(), Some(PathBuf::from(bus)));
        assert!(Net::from_env().is_bus());
        for name in names {
            std::env::remove_var(name);
        }
        assert!(matches!(
            Net::from_env(),
            Net::Udp {
                port: BEACON_PORT,
                family: None
            }
        ));
        for (name, value) in names.iter().zip(saved) {
            if let Some(value) = value {
                std::env::set_var(name, value);
            }
        }
    }

    /// A user send's search: found, at once; else wanted and waited for at
    /// most 2 s (woken by a find); empty at once while the task does not
    /// run, and no want for a zero wait.
    #[tokio::test(start_paused = true)]
    async fn locate_waits_for_a_candidate_and_is_empty_while_off() {
        let shared = Shared::new(STATE_ON);
        let bob = [0xB0; 32];
        let started = Instant::now();
        assert!(shared.locate(&bob, LOCATE_MAX).await.is_empty());
        assert_eq!(Instant::now(), started);
        shared.running.store(true, Ordering::SeqCst);
        shared.set_ifaces(&[EN0]);
        assert!(shared.locate(&bob, secs(10)).await.is_empty());
        assert_eq!(Instant::now() - started, LOCATE_MAX);
        match shared.rx.try_lock().unwrap().try_recv() {
            Ok(Msg::Want(peer, true, _)) => assert_eq!(peer, bob),
            other => panic!("{other:?}"),
        }
        let waiting = Arc::clone(&shared);
        let waiter = tokio::spawn(async move { waiting.locate(&bob, secs(1)).await });
        tokio::time::sleep(ms(200)).await;
        shared.add_candidate(
            bob,
            Candidate {
                addr: "192.168.1.30:47532".parse().unwrap(),
                iface: EN0,
                at: Instant::now(),
            },
        );
        assert_eq!(waiter.await.unwrap(), ["192.168.1.30:47532"]);
        let _ = shared.rx.try_lock().unwrap().try_recv();
        assert_eq!(shared.locate(&bob, secs(1)).await, ["192.168.1.30:47532"]);
        assert!(shared.locate(&[0xB1; 32], Duration::ZERO).await.is_empty());
        assert!(shared.rx.try_lock().unwrap().try_recv().is_err(), "no want");
    }

    /// §7: a candidate is valid until a dial to it fails. That one goes (the
    /// contact's others stay; with none left it is no longer fresh, so it
    /// may be asked for again); another dial string or another contact's
    /// candidate changes nothing, and the process call is inert without a
    /// running task.
    #[tokio::test(start_paused = true)]
    async fn a_failed_dial_ends_that_candidate_only() {
        let shared = Shared::new(STATE_ON);
        shared.running.store(true, Ordering::SeqCst);
        shared.set_ifaces(&[EN0]);
        let (bob, carol) = ([0xB0; 32], [0xC0; 32]);
        let at = |addr: &str| Candidate {
            addr: addr.parse().unwrap(),
            iface: EN0,
            at: Instant::now(),
        };
        shared.add_candidate(bob, at("192.168.1.30:47532"));
        shared.add_candidate(bob, at("[fd00::30]:47532"));
        shared.add_candidate(carol, at("192.168.1.31:47533"));
        let now = Instant::now();
        assert_eq!(
            shared.candidates(&bob, now),
            ["192.168.1.30:47532", "[fd00::30]:47532"]
        );
        shared.dial_failed(&bob, "192.168.1.99:47532");
        shared.dial_failed(&carol, "192.168.1.30:47532");
        assert_eq!(shared.candidates(&bob, now).len(), 2);
        assert_eq!(shared.candidates(&carol, now), ["192.168.1.31:47533"]);
        shared.dial_failed(&bob, "192.168.1.30:47532");
        assert_eq!(shared.candidates(&bob, now), ["[fd00::30]:47532"]);
        assert!(shared.fresh(&bob, now));
        shared.dial_failed(&bob, "[fd00::30]:47532");
        assert!(shared.candidates(&bob, now).is_empty());
        assert!(!shared.fresh(&bob, now));
        assert!(!lock(&shared.found).candidates.contains_key(&bob));
        assert_eq!(shared.candidates(&carol, now), ["192.168.1.31:47533"]);
        dial_failed(&carol, "192.168.1.31:47533");
        assert!(candidates(&carol).is_empty());
    }

    /// The process-wide calls do nothing while no task runs in this process
    /// (the gate is closed, LAN is off, or `raven-node ipc`): no want is
    /// queued, nothing is found, and a search is empty at once.
    #[tokio::test(start_paused = true)]
    async fn the_process_calls_are_inert_without_a_running_task() {
        let bob = [0xB0; 32];
        for w in [Want::Outbox, Want::Custody, Want::Send] {
            want(&bob, w);
        }
        linked(&bob);
        assert!(candidates(&bob).is_empty());
        let asked = Instant::now();
        assert!(locate(&bob, LOCATE_MAX).await.is_empty());
        assert_eq!(Instant::now(), asked);
        let shared = shared();
        assert!(!shared.running.load(Ordering::SeqCst));
        assert!(shared.rx.try_lock().unwrap().try_recv().is_err());
        let state = counts().state;
        let gate = raven_core::lan_beacon_live();
        assert_eq!(state, if gate { STATE_STARTING } else { STATE_HELD });
    }

    /// Status counts: the last ten minutes, words and numbers only.
    #[tokio::test(start_paused = true)]
    async fn counts_are_the_last_ten_minutes() {
        let shared = Shared::new(STATE_ON);
        let t0 = shared.base;
        shared.note(Count::Query, t0);
        shared.note(Count::Query, t0 + secs(59));
        shared.note(Count::Answered, t0 + secs(61));
        shared.note(Count::Dropped, t0 + secs(300));
        shared.note(Count::AnswerSent, t0 + secs(540));
        let at = |s: u64| {
            let c = shared.snapshot(t0 + secs(s));
            (
                c.queries_10m,
                c.answered_10m,
                c.dropped_10m,
                c.answers_sent_10m,
            )
        };
        assert_eq!(at(599), (2, 1, 1, 1));
        assert_eq!(at(600), (0, 1, 1, 1));
        assert_eq!(at(660), (0, 0, 1, 1));
        assert_eq!(at(1200), (0, 0, 0, 0));
        let json = serde_json::to_value(shared.snapshot(t0)).unwrap();
        for (k, v) in json.as_object().unwrap() {
            assert!(v.is_number() || v.is_boolean() || k == "state", "{k}: {v}");
        }
    }

    /// The book: each unblocked contact once (verified only if every row of
    /// it is), the pinned ones first, pinned ones only under verified-only,
    /// unusable keys left out, at most 1024.
    #[test]
    fn the_book_is_every_unblocked_contact_pinned_first_each_once() {
        let me = me();
        let p: Vec<Identity> = (0..5).map(person).collect();
        let hex_of = |i: &Identity| hex::encode(key(i));
        let rows = [
            (hex_of(&p[0]), false),
            (hex_of(&p[1]), true),
            (hex_of(&p[2]), true),
            (hex_of(&p[3]), true),
            (hex_of(&p[3]).to_uppercase(), false),
            ("zz".into(), true),
            (hex_of(&me), true),
            (hex_of(&p[4]), true),
        ];
        let blocked = hex_of(&p[2]);
        let book = |verified_only: bool| -> Vec<[u8; 32]> {
            book_of(
                &me,
                rows.iter().map(|(k, pinned)| (k.as_str(), *pinned)),
                |k| k == blocked,
                verified_only,
            )
            .iter()
            .map(|k| k.peer)
            .collect()
        };
        assert_eq!(
            book(false),
            [key(&p[1]), key(&p[4]), key(&p[0]), key(&p[3])]
        );
        assert_eq!(book(true), [key(&p[1]), key(&p[4])]);
        let many: Vec<(String, bool)> = (0..1030u32)
            .map(|i| {
                let mut seed = [0x5A; 32];
                seed[..4].copy_from_slice(&i.to_be_bytes());
                (
                    hex::encode(Identity::from_seed(&seed).public_key_bytes()),
                    i % 2 == 0,
                )
            })
            .collect();
        let big = book_of(
            &me,
            many.iter().map(|(k, pinned)| (k.as_str(), *pinned)),
            |_| false,
            false,
        );
        assert_eq!(big.len(), BOOK_MAX);
    }

    /// The lab bus end to end on this computer's loopback (never UDP 7420):
    /// two nodes that are each other's contacts find each other's listener
    /// ports from a join round; another bus directory moves both.
    #[tokio::test]
    async fn the_lab_bus_finds_each_other_on_loopback() {
        let dir = tempfile::tempdir().unwrap();
        let (bus, bus2, file) = (
            dir.path().join("bus"),
            dir.path().join("bus2"),
            dir.path().join("bus.txt"),
        );
        std::fs::write(&file, format!("{}\n", bus.display())).unwrap();
        let (alice, bob) = (
            Identity::from_seed(&[0x21; 32]),
            Identity::from_seed(&[0x22; 32]),
        );
        let node = |own: &Identity, other: &Identity, port: &str| {
            let host = TestHost::new(own, vec![(key(other), true)]);
            host.set_listeners(&[port]);
            *lock(&host.recent) = vec![key(other)];
            let shared = Shared::new(STATE_STARTING);
            let net = Net::Bus {
                file: file.clone(),
                dir: None,
                generation: 0,
            };
            let task = tokio::spawn(run_with(
                true,
                Arc::clone(&shared),
                host as Arc<dyn Host>,
                net,
                StdRng::seed_from_u64(u64::from(own.public_key_bytes()[0])),
            ));
            (shared, task)
        };
        let (a, a_task) = node(&alice, &bob, "127.0.0.1:47541");
        let (b, b_task) = node(&bob, &alice, "127.0.0.1:47542");
        let both_found = || async {
            for _ in 0..100 {
                let now = Instant::now();
                if a.candidates(&key(&bob), now) == ["127.0.0.1:47542"]
                    && b.candidates(&key(&alice), now) == ["127.0.0.1:47541"]
                {
                    return true;
                }
                tokio::time::sleep(ms(100)).await;
            }
            false
        };
        assert!(both_found().await, "found on the bus");
        // The one that asked heard its own query (the other may have found
        // it from that query, and then had nobody left to ask for).
        let now = Instant::now();
        assert!(a.snapshot(now).echo_ok || b.snapshot(now).echo_ok);
        let ports = |d: &Path| {
            std::fs::read_dir(d)
                .map(|e| e.flatten().count())
                .unwrap_or(0)
        };
        assert_eq!(ports(&bus), 2);
        // Another directory: both move (a network change) and meet again.
        std::fs::write(&file, format!("{}\n", bus2.display())).unwrap();
        for _ in 0..100 {
            if (ports(&bus), ports(&bus2)) == (0, 2) {
                break;
            }
            tokio::time::sleep(ms(100)).await;
        }
        assert_eq!((ports(&bus), ports(&bus2)), (0, 2), "both moved");
        assert!(both_found().await, "found again on the new bus");
        a_task.abort();
        b_task.abort();
        let _ = (a_task.await, b_task.await);
        assert_eq!(ports(&bus2), 0, "unregistered when the task ends");
    }

    /// Owner decision OD-C7: the join round goes only while something needs
    /// a contact found (deliveries, owed ACKs or custody rows wait, or
    /// meeting mode is on): joining a network alone sends nothing, at start
    /// or after a change. A want still goes.
    #[tokio::test(start_paused = true)]
    async fn join_round_runs_only_with_a_need() {
        let people = [person(1), person(2)];
        let src = ip("192.168.1.20");
        let mut rig = rig_for(&people);
        *lock(&rig.host.recent) = people.iter().map(key).collect();
        rig.host.need.store(false, Ordering::SeqCst);
        rig.start().await;
        let t0 = rig.t0;
        assert!(rig.run_until(t0 + secs(60)).await.is_empty(), "at start");
        rig.st.changed(vec![v4_only(en0())], t0 + secs(60)).await;
        assert!(
            rig.run_until(t0 + secs(120)).await.is_empty(),
            "after a change"
        );
        rig.st.add_want(key(&people[0]), false, t0 + secs(120));
        let rounds = rig.run_until(t0 + secs(121)).await;
        assert_eq!(rounds.len(), 1);
        assert_eq!(named(&rounds[0].1.bytes, src, &people), [(0, PORT)]);
        // A need: the next change names the contacts seen lately.
        rig.host.need.store(true, Ordering::SeqCst);
        let t1 = t0 + secs(200);
        rig.st.changed(vec![v4_only(en0())], t1).await;
        let rounds = rig.run_until(t1 + secs(1)).await;
        assert_eq!(rounds.len(), 1);
        assert_eq!(
            named(&rounds[0].1.bytes, src, &people),
            [(0, PORT), (1, PORT)]
        );
    }

    /// Phase 3 P3.C3 (F11b): a contact whose queries match only at the
    /// epoch after ours three rounds in a row, 200 s into ours, runs at
    /// least 400 s ahead (noted again at each such round); only at the epoch
    /// before ours, 500 s into it: at least 499 s behind (review A-3: the
    /// bound shown, less a second for the way). Matches within a second are
    /// one round, a round at our own epoch ends the run and one at the other
    /// side starts a new run. A match the link gate refuses counts for
    /// nothing.
    #[tokio::test(start_paused = true)]
    async fn adjacent_epoch_only_matches_note_a_skew() {
        let people = [person(1), person(2)];
        let (bob, carol) = (&people[0], &people[1]);
        let mut rig = rig(&people, vec![v4_only(en0())]);
        lock(&rig.host.refused).insert(key(carol));
        rig.start().await;
        let t0 = rig.t0;
        let query = |who: &Identity, epoch: u64, seed: u64| {
            let k = pair_keys(who, &key(&me())).unwrap();
            let mut rng = StdRng::seed_from_u64(seed);
            build_query(&mut rng, epoch, ip("192.168.1.30"), THEIR_PORT, &[&k]).to_vec()
        };
        let skews = |rig: &Rig| lock(&rig.host.skews).clone();
        let mut seed = 0;
        let mut at = t0;
        // Bob three rounds ahead, a second copy on another interface's
        // nonce within the round, then a fourth round.
        for epoch in [EPOCH + 1, EPOCH + 1, EPOCH + 1] {
            seed += 1;
            rig.deliver(&query(bob, epoch, seed), from("192.168.1.30"), at)
                .await;
            assert_eq!(
                rig.host.found().last(),
                Some(&key(bob)),
                "matched at {epoch}"
            );
            at += secs(3);
        }
        assert_eq!(skews(&rig), [(key(bob), 400_000)]);
        rig.deliver(
            &query(bob, EPOCH + 1, 100),
            from("192.168.1.30"),
            at - secs(3) + ms(500),
        )
        .await;
        assert_eq!(skews(&rig).len(), 1, "the same round");
        rig.deliver(&query(bob, EPOCH + 1, 101), from("192.168.1.30"), at)
            .await;
        assert_eq!(skews(&rig), [(key(bob), 400_000), (key(bob), 400_000)]);
        // A round at our epoch ends the run: two more ahead say nothing.
        for epoch in [EPOCH, EPOCH + 1, EPOCH + 1] {
            at += secs(3);
            seed += 1;
            rig.deliver(&query(bob, epoch, seed), from("192.168.1.30"), at)
                .await;
        }
        assert_eq!(skews(&rig).len(), 2);
        // Behind: a new run at the epoch before ours, 500 s into ours.
        let epoch_start = EPOCH * codec::EPOCH_SECS * 1000;
        rig.host
            .now_ms
            .store(epoch_start + 500_000, Ordering::SeqCst);
        for _ in 0..3 {
            at += secs(3);
            seed += 1;
            rig.deliver(&query(bob, EPOCH - 1, seed), from("192.168.1.30"), at)
                .await;
        }
        assert_eq!(skews(&rig)[2..], [(key(bob), -499_000)]);
        // Ahead once more: a new run of one.
        at += secs(3);
        rig.deliver(&query(bob, EPOCH + 1, 200), from("192.168.1.30"), at)
            .await;
        assert_eq!(skews(&rig).len(), 3);
        // Carol is refused by the link gate: nothing counted.
        for n in 0..4 {
            at += secs(3);
            rig.deliver(&query(carol, EPOCH + 1, 300 + n), from("192.168.1.31"), at)
                .await;
        }
        assert_eq!(skews(&rig).len(), 3);
        assert!(!rig.st.clocks.contains_key(&key(carol)));
    }

    /// Bob in a rig of his own, asked for in two rounds that get no answer
    /// (at 0.3 s and 16.3 s): wanted by a source each time (`wanted`), or
    /// only named as a join round names him; `seen`: where lan_seen says he
    /// reached this node in the last 7 days. The rig at t0 + 20 s.
    async fn left_unanswered(seen: Option<&str>, wanted: bool) -> Rig {
        let bob = person(1);
        let mut rig = rig_for(std::slice::from_ref(&bob));
        if let Some(addr) = seen {
            lock(&rig.host.sightings).insert(key(&bob), ip(addr));
        }
        rig.start().await;
        let t0 = rig.t0;
        for at in [t0, t0 + secs(16)] {
            if wanted {
                rig.st.on_msg(Msg::Want(key(&bob), false, at), at);
            } else {
                rig.st.add_want(key(&bob), false, at);
            }
            assert_eq!(rig.run_until(at + secs(3)).await.len(), 1);
        }
        // The second round's answer window ends at 19.3 s.
        assert!(rig.counts(t0 + secs(19)).no_answer.is_empty());
        rig.run_until(t0 + secs(20)).await;
        rig
    }

    /// Phase 3 P3.C3 (F11b): `Status` names a contact asked for in vain once
    /// a want for it is pending, it was seen on this network in the last 7
    /// days and two rounds got no answer; as long as its want holds. An
    /// answer, a query of its that matches, an authenticated link, a network
    /// change or LAN off clear it. Without a pending want (join rounds
    /// only), without a sighting or with one on another network: never.
    #[tokio::test(start_paused = true)]
    async fn the_hint_row_needs_a_pending_want_and_a_recent_sighting() {
        let bob = person(1);
        let hex_bob = hex::encode(key(&bob));
        let mut rig = left_unanswered(Some("192.168.1.30"), true).await;
        let t0 = rig.t0;
        assert_eq!(rig.counts(t0 + secs(20)).no_answer, [hex_bob]);
        // The outbox's `lan_no_answer` reads the same (P3.23).
        assert!(rig.shared.is_silent(&key(&bob), t0 + secs(20)));
        assert!(!rig.shared.is_silent(&key(&person(2)), t0 + secs(20)));
        // Held while its want is: 11 min after the last one, or longer
        // after a new one (held back by the interval, but pending).
        let lapse = t0 + secs(16) + WANT_HELD;
        assert_eq!(rig.counts(lapse - ms(1)).no_answer.len(), 1);
        assert!(rig.counts(lapse).no_answer.is_empty());
        assert!(!rig.shared.is_silent(&key(&bob), lapse));
        rig.st
            .on_msg(Msg::Want(key(&bob), false, t0 + secs(30)), t0 + secs(30));
        assert_eq!(rig.counts(lapse).no_answer.len(), 1);
        // Its answer to the next round clears it, and that round's window
        // counts no miss.
        rig.st
            .on_msg(Msg::Want(key(&bob), false, t0 + secs(47)), t0 + secs(47));
        let rounds = rig.run_until(t0 + ms(47_400)).await;
        assert_eq!(rounds.len(), 1);
        let a = their_answer(&bob, &rounds[0].1.bytes, "192.168.1.30", "192.168.1.20", 9);
        rig.deliver(&a, from("192.168.1.30"), t0 + secs(48)).await;
        assert!(rig.counts(t0 + secs(48)).no_answer.is_empty());
        rig.run_until(t0 + secs(51)).await;
        assert_eq!(rig.st.peers[&key(&bob)].misses, 0);
        assert!(rig.counts(t0 + secs(51)).no_answer.is_empty());

        // A query of his that matches: he is here.
        let mut rig = left_unanswered(Some("192.168.1.30"), true).await;
        let t0 = rig.t0;
        let q = their_query(&bob, "192.168.1.30", THEIR_PORT, 5);
        rig.deliver(&q, from("192.168.1.30"), t0 + secs(21)).await;
        assert!(rig.counts(t0 + secs(21)).no_answer.is_empty());
        assert_eq!(rig.st.peers[&key(&bob)].misses, 0);
        // An authenticated link; a network change; LAN off.
        let mut rig = left_unanswered(Some("192.168.1.30"), true).await;
        let t0 = rig.t0;
        rig.st.on_msg(Msg::Linked(key(&bob)), t0 + secs(21));
        assert!(rig.counts(t0 + secs(21)).no_answer.is_empty());
        // A round still in its answer window at the link counts no miss.
        let want = |rig: &mut Rig, s: u64| {
            let at = rig.t0 + secs(s);
            rig.st.on_msg(Msg::Want(key(&bob), false, at), at);
        };
        want(&mut rig, 22);
        assert_eq!(rig.run_until(t0 + secs(23)).await.len(), 1);
        rig.st.on_msg(Msg::Linked(key(&bob)), t0 + secs(24));
        want(&mut rig, 24);
        assert_eq!(rig.run_until(t0 + secs(28)).await.len(), 1);
        assert_eq!(rig.st.peers[&key(&bob)].misses, 1);
        assert!(rig.counts(t0 + secs(28)).no_answer.is_empty());
        let mut rig = left_unanswered(Some("192.168.1.30"), true).await;
        let t0 = rig.t0;
        rig.st.changed(vec![v4_only(en0())], t0 + secs(21)).await;
        assert!(rig.counts(t0 + secs(21)).no_answer.is_empty());
        let rig = left_unanswered(Some("192.168.1.30"), true).await;
        rig.shared.clear();
        assert!(rig.counts(rig.t0 + secs(21)).no_answer.is_empty());
        // No pending want, no sighting, a sighting on another network.
        for (seen, wanted) in [
            (Some("192.168.1.30"), false),
            (None, true),
            (Some("10.9.0.5"), true),
        ] {
            let rig = left_unanswered(seen, wanted).await;
            assert!(
                rig.counts(rig.t0 + secs(20)).no_answer.is_empty(),
                "{seen:?} {wanted}"
            );
        }
        // At most eight, the newest first.
        let shared = Shared::new(STATE_ON);
        let t0 = Instant::now();
        for n in 0..10u8 {
            shared.set_silent([n; 32], t0 + secs(u64::from(n)), t0 + secs(600));
        }
        let listed = shared.snapshot(t0 + secs(20)).no_answer;
        let want: Vec<String> = (2..10u8).rev().map(|n| hex::encode([n; 32])).collect();
        assert_eq!(listed, want);
        // The outbox's reason is not capped: the oldest ones count too.
        assert!((0..10u8).all(|n| shared.is_silent(&[n; 32], t0 + secs(20))));
        assert!(!shared.is_silent(&[0; 32], t0 + secs(600)));
    }

    /// A cable on the Wi-Fi's subnet (a laptop at a dock): 192.168.1.21/24
    /// and fe80::21 under index [`EN5`].
    fn cable() -> BeaconIf {
        BeaconIf {
            index: EN5,
            zone: EN5.to_string(),
            v4: Some((
                Ipv4Addr::new(192, 168, 1, 21),
                24,
                Some(Ipv4Addr::new(192, 168, 1, 255)),
            )),
            v6_ll: Some("fe80::21".parse().unwrap()),
            ..en0()
        }
    }

    /// Review A-1: a laptop on Wi-Fi and a cable of one subnet sends one
    /// query from each address, and the contact answers only the one that
    /// reached it first (one answer per contact per 2 s). An IPv4 answer
    /// comes in as from the first interface of that subnet, so it is tried
    /// against the queries of every interface on it; an IPv6 copy that
    /// comes in on another link than the first is not taken for a repeat.
    /// Before, both were dropped and the round went unanswered.
    #[tokio::test(start_paused = true)]
    async fn a_dual_homed_querier_takes_the_answer_to_either_query() {
        let bob = person(1);
        for v6 in [false, true] {
            let mut rig = rig(std::slice::from_ref(&bob), vec![en0(), cable()]);
            rig.host.set_listeners(&["0.0.0.0:47531", "[::]:47531"]);
            rig.start().await;
            let t0 = rig.t0;
            rig.st.add_want(key(&bob), false, t0);
            let rounds = rig.run_until(t0 + ms(400)).await;
            assert_eq!(rounds.len(), 4, "two interfaces, two families");
            let (_, cable_query) = rounds
                .iter()
                .find(|(_, o)| o.index == EN5 && o.v6 == v6)
                .unwrap();
            let t = rounds[0].0 + ms(100);
            let (ours, theirs) = if v6 {
                ("fe80::21", "fe80::30")
            } else {
                ("192.168.1.21", "192.168.1.30")
            };
            let a = their_answer(&bob, &cable_query.bytes, theirs, ours, 1);
            if v6 {
                // One copy on each link, the Wi-Fi's first.
                rig.deliver(&a, from_ll(theirs, EN0), t).await;
                assert!(rig.host.found().is_empty());
                rig.deliver(&a, from_ll(theirs, EN5), t).await;
            } else {
                rig.deliver(&a, from(theirs), t).await;
            }
            assert_eq!(rig.host.found(), [key(&bob)], "v6 {v6}");
            let want = if v6 {
                "[fe80::30%902]:47532"
            } else {
                "192.168.1.30:47532"
            };
            assert_eq!(rig.shared.candidates(&key(&bob), t), [want]);
            assert_eq!(lock(&rig.shared.found).candidates[&key(&bob)][0].iface, EN5);
            assert_eq!(rig.counts(t).answered_10m, 1);
            assert!(rig.st.peers[&key(&bob)].answered);
        }
    }

    /// Review A-2: a network change forgets what was found before it, even
    /// on the same interface: the old network's address may be someone
    /// else's here (a same-numbered subnet included, which netwatch reports
    /// with the interfaces unchanged). A contact waiting for delivery is
    /// asked for at once on the new network, and `raven status` no longer
    /// counts it as here.
    #[tokio::test(start_paused = true)]
    async fn a_network_change_forgets_what_was_found_and_asks_again() {
        let bob = person(1);
        let people = std::slice::from_ref(&bob);
        let mut rig = rig_for(people);
        rig.start().await;
        let t0 = rig.t0;
        let q = their_query(&bob, "192.168.1.30", THEIR_PORT, 1);
        rig.deliver(&q, from("192.168.1.30"), t0).await;
        assert_eq!(
            rig.shared.candidates(&key(&bob), t0),
            ["192.168.1.30:47532"]
        );
        lock(&rig.host.waiting).push(key(&bob));
        // en0 now on another network.
        let moved = BeaconIf {
            v4: Some((
                Ipv4Addr::new(10, 7, 0, 5),
                24,
                Some(Ipv4Addr::new(10, 7, 0, 255)),
            )),
            v4_prefixes: vec![(Ipv4Addr::new(10, 7, 0, 0), 24)],
            ..v4_only(en0())
        };
        rig.st.changed(vec![moved.clone()], t0 + secs(5)).await;
        assert!(rig.shared.candidates(&key(&bob), t0 + secs(5)).is_empty());
        assert!(rig.shared.found_lately(t0 + secs(5)).is_empty());
        let sent = queries(rig.run_until(t0 + secs(6)).await);
        assert_eq!(sent.len(), 1, "Bob is asked for on the new network");
        assert_eq!(named(&sent[0], ip("10.7.0.5"), people), [(0, PORT)]);
        // Found there; a change that keeps the interfaces as they were
        // forgets it too.
        let q = their_query(&bob, "10.7.0.30", THEIR_PORT, 2);
        rig.deliver(&q, from("10.7.0.30"), t0 + secs(7)).await;
        assert!(rig.shared.fresh(&key(&bob), t0 + secs(7)));
        rig.st.changed(vec![moved], t0 + secs(8)).await;
        assert!(!rig.shared.fresh(&key(&bob), t0 + secs(8)));
        assert_eq!(queries(rig.run_until(t0 + secs(9)).await).len(), 1);
    }

    /// The queries among what [`Rig::run_until`] saw go out (no answers).
    fn queries(sent: Vec<(Instant, Out)>) -> Vec<Vec<u8>> {
        sent.into_iter()
            .map(|(_, o)| o.bytes)
            .filter(|b| kind_of(b.len()) == Some(DatagramKind::Query))
            .collect()
    }

    /// Review A-3: a match at the epoch next to ours shows only as much skew
    /// as lies between the match and that epoch's edge. A contact 10 s
    /// ahead matches at the next epoch in the last 10 s of each of ours, and
    /// one 10 s behind at the one before in the first 10 s: neither is
    /// noted as a clock too far off for Raven (five minutes), however many
    /// rounds in a row.
    #[tokio::test(start_paused = true)]
    async fn a_skew_of_seconds_near_an_epoch_edge_is_not_noted() {
        let bob = person(1);
        let mut rig = rig(std::slice::from_ref(&bob), vec![v4_only(en0())]);
        rig.start().await;
        let t0 = rig.t0;
        let query = |epoch: u64, seed: u64| {
            let k = pair_keys(&bob, &key(&me())).unwrap();
            let mut rng = StdRng::seed_from_u64(seed);
            build_query(&mut rng, epoch, ip("192.168.1.30"), THEIR_PORT, &[&k]).to_vec()
        };
        let epoch_ms = EPOCH * codec::EPOCH_SECS * 1000;
        let mut at = t0;
        for (phase_ms, epoch) in [(595_000, EPOCH + 1), (5_000, EPOCH - 1)] {
            rig.host.now_ms.store(epoch_ms + phase_ms, Ordering::SeqCst);
            for n in 0..4 {
                at += ms(1_500);
                rig.deliver(&query(epoch, 10 * epoch + n), from("192.168.1.30"), at)
                    .await;
                assert_eq!(rig.host.found().last(), Some(&key(&bob)));
            }
            at += secs(10);
        }
        assert!(lock(&rig.host.skews).is_empty());
    }

    /// Review A-4: on a LAN numbered with public IPv4 addresses (a campus,
    /// an old company network) a contact's query is local by the on-link
    /// rule and is answered, but the outbox dials no beacon find there. Such
    /// a find is not kept: it does not hold back the next query, wake
    /// anything or count the contact as here.
    #[tokio::test(start_paused = true)]
    async fn a_find_the_outbox_would_not_dial_is_not_kept() {
        let bob = person(1);
        let people = std::slice::from_ref(&bob);
        let campus = BeaconIf {
            v4: Some((
                Ipv4Addr::new(11, 237, 20, 20),
                24,
                Some(Ipv4Addr::new(11, 237, 20, 255)),
            )),
            v4_prefixes: vec![(Ipv4Addr::new(11, 237, 20, 0), 24)],
            ..v4_only(en0())
        };
        let mut rig = rig(people, vec![campus]);
        lock(&rig.host.on_link).push(ip("11.237.20.30"));
        rig.start().await;
        let t0 = rig.t0;
        let q = their_query(&bob, "11.237.20.30", THEIR_PORT, 1);
        rig.deliver(&q, from("11.237.20.30"), t0).await;
        assert_eq!(answers(&rig.sent()).len(), 1, "on this link: answered");
        assert!(rig.shared.candidates(&key(&bob), t0).is_empty());
        assert!(rig.shared.found_lately(t0).is_empty());
        assert!(rig.host.found().is_empty());
        rig.st.add_want(key(&bob), false, t0 + secs(1));
        let sent = queries(rig.run_until(t0 + secs(2)).await);
        assert_eq!(sent.len(), 1, "asked for");
    }

    /// Review A-6: the beacon speaks from an interface's IPv4 address and
    /// its IPv6 link-local one, and the contact dials the source it heard.
    /// A listener bound to another address of that interface's networks (a
    /// second IPv4 address, a global or unique-local IPv6 one) is not
    /// reached there: no port in the query slots, no answer.
    #[tokio::test(start_paused = true)]
    async fn a_listener_on_another_address_of_the_interface_is_not_advertised() {
        let i = en0();
        let ll = |scope: u32| {
            SocketAddr::V6(SocketAddrV6::new(
                "fe80::20".parse().unwrap(),
                7420,
                0,
                scope,
            ))
        };
        assert!(accepts(from("0.0.0.0"), &i, false, false));
        assert!(accepts(from("192.168.1.20"), &i, false, false));
        assert!(!accepts(from("192.168.1.50"), &i, false, false));
        assert!(accepts(from("::"), &i, true, false));
        assert!(accepts(ll(0), &i, true, false));
        assert!(accepts(ll(EN0), &i, true, false));
        assert!(!accepts(ll(EN5), &i, true, false));
        assert!(!accepts(from("2001:db8:1:2::5"), &i, true, false));
        let bob = person(1);
        let mut rig = rig_for(std::slice::from_ref(&bob));
        rig.host.set_listeners(&["192.168.1.50:47531"]);
        rig.start().await;
        let t0 = rig.t0;
        rig.st.add_want(key(&bob), false, t0);
        let rounds = rig.run_until(t0 + ms(400)).await;
        let src = ip("192.168.1.20");
        assert_eq!(
            named(&rounds[0].1.bytes, src, std::slice::from_ref(&bob)),
            [(0, 0)]
        );
        let q = their_query(&bob, "192.168.1.30", THEIR_PORT, 1);
        rig.deliver(&q, from("192.168.1.30"), t0 + secs(1)).await;
        assert!(answers(&rig.sent()).is_empty());
    }

    /// Phase 6b W-B3 (people study M13): every query goes out with a random
    /// tail (160..=191 bytes, found as the 160 it carries), its first copy
    /// 0-500 ms after its round and its second, byte for byte the same,
    /// 100-400 ms after the first. Over 100 rounds the delays, gaps and
    /// lengths spread over their ranges.
    #[tokio::test(start_paused = true)]
    async fn queries_go_out_with_a_tail_late_and_again_100_to_400ms_on() {
        let people = [person(1)];
        let bob = key(&people[0]);
        let src = ip("192.168.1.20");
        let mut rig = jittered(&people);
        rig.start().await;
        let t0 = rig.t0;
        let (mut delays, mut gaps, mut lens) = (Vec::new(), Vec::new(), HashSet::new());
        for n in 0..100u64 {
            // A user send each time: 2 s apart is enough (§8).
            let at = t0 + secs(5 * n);
            rig.st.add_want(bob, true, at);
            let copies = rig.copies_until(at + secs(2)).await;
            assert_eq!(copies.len(), 2, "round {n}: {copies:?}");
            let ((first, a), (second, b)) = (&copies[0], &copies[1]);
            assert_eq!(a.bytes, b.bytes, "the second copy is the first again");
            assert!((QUERY_LEN..=QUERY_MAX_LEN).contains(&a.bytes.len()));
            assert_eq!(named(&a.bytes, src, &people), [(0, PORT)]);
            let round = at + COALESCE;
            assert!(
                *first >= round && *first - round <= SEND_DELAY_MAX,
                "round {n}"
            );
            delays.push(*first - round);
            gaps.push(*second - *first);
            lens.insert(a.bytes.len());
        }
        assert!(
            gaps.iter().all(|g| (REPEAT_MIN..=REPEAT_MAX).contains(g)),
            "{gaps:?}"
        );
        let spread = |v: &[Duration], low: u64, high: u64| {
            v.iter().min() < Some(&ms(low)) && v.iter().max() > Some(&ms(high))
        };
        assert!(spread(&delays, 75, 425), "{delays:?}");
        assert!(spread(&gaps, 145, 355), "{gaps:?}");
        assert!(lens.len() >= 20, "{lens:?}");
    }

    /// Phase 6b W-B3: every answer goes out with a random tail (48..=63
    /// bytes, opened as the 48 it carries), its first copy 0-500 ms after
    /// the query came and its second, the same bytes, 100-400 ms after the
    /// first. Over 60 answers the delays and lengths spread.
    #[tokio::test(start_paused = true)]
    async fn answers_go_out_with_a_tail_late_and_again_100_to_400ms_on() {
        let bob = person(1);
        let mut rig = jittered(std::slice::from_ref(&bob));
        rig.start().await;
        let t0 = rig.t0;
        let (mut delays, mut lens) = (Vec::new(), HashSet::new());
        for n in 0..60u64 {
            // Within the source's rate (one per 2 s) and the answer gap.
            let at = t0 + secs(3 * n);
            let q = their_query(&bob, "192.168.1.30", THEIR_PORT, n + 1);
            rig.deliver(&q, from("192.168.1.30"), at).await;
            let mut copies: Vec<(Instant, Out)> =
                rig.sent().into_iter().map(|out| (at, out)).collect();
            copies.extend(rig.copies_until(at + secs(1)).await);
            assert_eq!(copies.len(), 2, "query {n}: {copies:?}");
            let ((first, a), (second, b)) = (&copies[0], &copies[1]);
            assert_eq!(a.bytes, b.bytes, "the second copy is the first again");
            assert!((ANSWER_LEN..=ANSWER_MAX_LEN).contains(&a.bytes.len()));
            assert_eq!(
                opened(&a.bytes, &bob, &q, "192.168.1.20", "192.168.1.30"),
                Some(PORT)
            );
            assert!(*first - at <= SEND_DELAY_MAX, "query {n}");
            assert!((REPEAT_MIN..=REPEAT_MAX).contains(&(*second - *first)));
            delays.push(*first - at);
            lens.insert(a.bytes.len());
        }
        assert!(
            delays.iter().min() < Some(&ms(75)) && delays.iter().max() > Some(&ms(425)),
            "{delays:?}"
        );
        assert!(lens.len() >= 10, "{lens:?}");
    }

    /// Phase 6 review (traffic-3): a user send's search (IPC `LanLocate`
    /// with the wait `raven send` and the terminal app ask for) outlasts one
    /// find with every delay of the send shape at its longest and the
    /// query's first copy lost: the round at 300 ms, the first copy at
    /// 800 ms (lost), the second at 1,200 ms, the answer's first copy at
    /// 1,700 ms and a 50 ms round trip. The 1 s wait sends asked for before
    /// gave up on it.
    #[tokio::test(start_paused = true)]
    async fn a_user_sends_search_outlasts_the_shapes_longest_find() {
        let bob = person(1);
        let longest = Shape {
            tails: true,
            delay: (SEND_DELAY_MAX, SEND_DELAY_MAX),
            repeat: (REPEAT_MAX, REPEAT_MAX),
        };
        let rows = vec![(key(&bob), true)];
        let mut rig = Rig::shaped(TestHost::new(&me(), rows), vec![v4_only(en0())], longest);
        rig.start().await;
        rig.shared.running.store(true, Ordering::SeqCst);
        let t0 = rig.t0;
        let wait = ms(u64::from(raven_core::lan_beacon::LOCATE_SEND_WAIT_MS));
        let shared = Arc::clone(&rig.shared);
        let search = tokio::spawn(async move { shared.locate(&key(&person(1)), wait).await });
        tokio::task::yield_now().await;
        // The search's want, as the task takes it.
        let want = rig.shared.rx.try_lock().unwrap().try_recv().unwrap();
        assert!(matches!(want, Msg::Want(_, true, _)), "a user send");
        rig.st.on_message(want, t0).await;
        let copies = rig.copies_until(t0 + secs(2)).await;
        let at: Vec<Duration> = copies.iter().map(|(at, _)| *at - t0).collect();
        assert_eq!(at, [ms(800), ms(1200)], "the query's two copies");
        // Bob hears the second copy only; his answer waits its longest.
        let a = their_answer(&bob, &copies[1].1.bytes, "192.168.1.30", "192.168.1.20", 3);
        let answered = copies[1].0 + SEND_DELAY_MAX + ms(50);
        assert!(answered - t0 > ms(1000), "past the old wait");
        tokio::time::sleep_until(answered).await;
        rig.deliver(&a, from("192.168.1.30"), answered).await;
        assert_eq!(search.await.unwrap(), ["192.168.1.30:47532"]);
    }

    /// No beacon while LAN is off (§0) holds for what the shape delays
    /// (Phase 6b W-B3): a query and an answer made before LAN turned off
    /// and due after it do not go out; with LAN on they go, each twice.
    #[tokio::test(start_paused = true)]
    async fn nothing_delayed_goes_out_after_lan_turned_off() {
        let (bob, carol) = (person(1), person(2));
        let late = Shape {
            delay: (ms(200), ms(200)),
            ..Shape::V1
        };
        for lan_off in [true, false] {
            let rows = vec![(key(&bob), true), (key(&carol), true)];
            let mut rig = Rig::shaped(TestHost::new(&me(), rows), vec![v4_only(en0())], late);
            rig.start().await;
            let t0 = rig.t0;
            // Carol is wanted; Bob asks for this node (and is found).
            rig.st.add_want(key(&carol), false, t0);
            let q = their_query(&bob, "192.168.1.30", THEIR_PORT, 1);
            rig.deliver(&q, from("192.168.1.30"), t0 + ms(150)).await;
            // The round at 300 ms: its query waits until 500, the answer
            // until 350.
            rig.timer(t0 + COALESCE).await;
            assert!(rig.sent().is_empty());
            assert_eq!(rig.st.outgoing.len(), 2, "the answer and the query wait");
            if lan_off {
                rig.host.lan.send_replace(false);
            }
            let sent = rig.copies_until(t0 + secs(5)).await;
            if lan_off {
                assert!(sent.is_empty(), "{sent:?}");
                assert!(rig.st.outgoing.is_empty());
            } else {
                let at: Vec<Instant> = sent.iter().map(|(at, _)| *at).collect();
                assert_eq!(&at[..2], [t0 + ms(350), t0 + ms(500)]);
                assert_eq!(sent.len(), 4, "each twice: {sent:?}");
            }
        }
    }

    /// What the shape delays goes out only on the network it was made for
    /// (owner decision OD-C7, Phase 6b W-B3): a query waiting for its delay
    /// when the interface moves to another network is dropped, so arriving
    /// there sends nothing; on an interface that did not change it still
    /// goes.
    #[tokio::test(start_paused = true)]
    async fn a_delayed_query_does_not_go_out_on_another_network() {
        let carol = person(2);
        let late = Shape {
            delay: (ms(200), ms(200)),
            ..Shape::V1
        };
        let rows = vec![(key(&carol), true)];
        let mut rig = Rig::shaped(TestHost::new(&me(), rows), vec![v4_only(en0())], late);
        rig.start().await;
        let t0 = rig.t0;
        rig.st.add_want(key(&carol), false, t0);
        rig.timer(t0 + COALESCE).await;
        assert_eq!(rig.st.outgoing.len(), 1, "the query waits");
        // The same interface and addresses (a route change): it still goes.
        rig.st
            .changed(vec![v4_only(en0())], t0 + COALESCE + ms(50))
            .await;
        assert_eq!(rig.st.outgoing.len(), 1);
        // en0 on another network before it went: dropped.
        let moved = BeaconIf {
            v4: Some((
                Ipv4Addr::new(10, 7, 0, 5),
                24,
                Some(Ipv4Addr::new(10, 7, 0, 255)),
            )),
            v4_prefixes: vec![(Ipv4Addr::new(10, 7, 0, 0), 24)],
            ..v4_only(en0())
        };
        rig.st.changed(vec![moved], t0 + COALESCE + ms(100)).await;
        assert!(rig.st.outgoing.is_empty());
        assert!(rig.copies_until(t0 + secs(5)).await.is_empty());
    }

    /// Owner decision OD-C7, re-checked for Phase 6b W-B3 (people study
    /// M13) with the node's own need ([`join_need`]): after a network change
    /// with nothing waiting, no custody row and no meeting, no join round
    /// goes; `raven lan on --for 1h` (meeting mode) makes the next change
    /// send one naming the contacts seen lately; once the meeting time has
    /// come, a change sends nothing again.
    #[tokio::test(start_paused = true)]
    async fn a_meeting_starts_a_join_round_and_nothing_waiting_starts_none() {
        let people = [person(1), person(2)];
        let src = ip("192.168.1.20");
        let dir = tempfile::tempdir().unwrap();
        let mut rig = rig_for(&people);
        *lock(&rig.host.recent) = people.iter().map(key).collect();
        let meetings = Arc::new(crate::lan_meeting::Meetings::new(|_| {}, || true));
        *lock(&rig.host.meeting) = Some((Arc::clone(&meetings), dir.path().to_path_buf()));
        rig.start().await;
        let t0 = rig.t0;
        assert!(rig.run_until(t0 + secs(60)).await.is_empty(), "at start");
        rig.st.changed(vec![v4_only(en0())], t0 + secs(60)).await;
        assert!(
            rig.run_until(t0 + secs(120)).await.is_empty(),
            "after a change with nothing waiting"
        );
        // Meeting mode for an hour: the next change sends a join round.
        meetings.apply(true, Some(NOW_MS + 3_600_000), NOW_MS);
        let t1 = t0 + secs(120);
        rig.st.changed(vec![v4_only(en0())], t1).await;
        let rounds = rig.run_until(t1 + secs(60)).await;
        assert_eq!(rounds.len(), 1, "{rounds:?}");
        assert_eq!(
            named(&rounds[0].1.bytes, src, &people),
            [(0, PORT), (1, PORT)]
        );
        // The meeting time has come: nothing again.
        rig.host.now_ms.store(NOW_MS + 3_600_000, Ordering::SeqCst);
        let t2 = t0 + secs(600);
        rig.st.changed(vec![v4_only(en0())], t2).await;
        assert!(
            rig.run_until(t2 + secs(60)).await.is_empty(),
            "after the meeting"
        );
    }
}
