//! The update exchange on Raven links (RUP1,
//! `protocol/RAVEN_UPDATE_EXCHANGE_V1.md`; `docs/roadmap/plans/phase6-design.json`
//! step P6.49, design D §6; owner decisions OD6b-23, OD6b-24, OD6b-25):
//! friends pass security notices, the release log and Raven releases to
//! each other over the links they already have, with no server.
//!
//! - **Negotiation** (spec §2). While the exchange is [`active`] (the
//!   `MESH_UPDATE` gate and release keys), this node's hello sets caps bit
//!   10 (`crate::link::offers`) and a LAN dial that reads puts it in its
//!   RLX1 (`crate::hints::lan_m3_payload_with`). [`UpdateLink`] runs one
//!   link's part: the listener sends its HAVE after its RLB1 and RRH1 when
//!   the dialer offered bit 10; the dialer sends its HAVE after the hellos
//!   (Internet direct, p2p, nearby) or after the listener's HAVE (LAN).
//!   Only to pinned contacts; an old peer never sets bit 10 and never gets
//!   a RUP1 frame.
//! - **Notices: automatic.** A pinned contact's HAVE naming a newer
//!   advisory, or a longer log (or as long with another root), makes it due
//!   ([`Node::take_have`]); the exchange task ([`run`]) dials it and asks
//!   (GET_ADVISORY, GET_LOG). The update state verifies and applies what
//!   comes, freezing on equivocation or a split view; the next HAVE offers
//!   it onward. A forged notice goes to quarantine and that friend is not
//!   asked again for a day. One under a key set this node never trusted (a
//!   rotation it missed) cannot be checked yet: the node asks that friend
//!   for the rotation away from its own set (GET_ROTATION), then again, at
//!   most [`MAX_CATCH_UPS_PER_DAY`] times a day. Still under an unknown set
//!   after a catch-up that took no rotation, or once the day's catch-ups
//!   with that friend are spent, it counts as forged (Phase 6 review
//!   re-verify, updates-protocol-3). Nothing is asked while frozen.
//! - **Releases: approved.** An offer for this computer's target with a
//!   newer build serial becomes a row of `updates/downloads`
//!   ([`raven_core::update_downloads`]) that waits for `raven update
//!   download`. An approved row is fetched manifest first (verified like a
//!   bundle up to its payload), then chunks from every friend offering the
//!   same digest, at most 8 a request and 16 a dial, into
//!   `updates/incoming/<digest>/` (resumable: a bitmap), each chunk checked
//!   by its audit path before it is written. A forged chunk goes to
//!   quarantine and that friend is not asked for this release again; the
//!   others carry on. Complete, the whole release is verified again and
//!   waits for the install approval, which only the CLI or the terminal app
//!   takes (they stage it; raven-node installs and runs nothing).
//! - **Serving** ([`Node::serve`]). The stored advisory and log, and the
//!   releases this node holds for its own platform (staged ones and complete
//!   downloads), to pinned contacts only (anyone else: POLICY_DENIED), at
//!   most 6 requests a minute and 128 MiB a day per friend (RATE_LIMITED)
//!   and 2 requests at a time overall (BUSY). Bluetooth (nearby) carries
//!   notices and logs only: its HAVE has no offers and bundle requests are
//!   POLICY_DENIED. Never through custody, letters or a relay's store.
//! - **Storage.** `incoming/` at most 256 MiB, a download untouched for 7
//!   days removed; `quarantine/` at most 64 MiB for 7 days, counted, never
//!   run or shown.
//!
//! With the gate shut nothing here runs: no bit 10, no HAVE, no task work,
//! and a RUP1 frame is not taken (the link handles it as before). A
//! security notice's hold on release bundles stops only the bundle part
//! (offers, GET_MANIFEST, GET_CHUNKS, downloads): notices still pass. The debug
//! lab switch [`LAB_CLAIM_NEWER`] makes this node a friend whose HAVE
//! claims a newer notice than it holds (the update harness, P6.51).

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use raven_core::ipc::UpdateStatus;
use raven_core::release_bundle::{
    verify_bundle, BundleError, ChunkTree, Manifest, Parts, CHUNK_SIZE, MAX_MANIFEST_LEN,
};
use raven_core::release_keys::SigError;
use raven_core::security_events::Via;
use raven_core::security_gate;
use raven_core::tlog::{leaf_hash, EntryType, Snapshot, MAX_SNAPSHOT_LEN};
use raven_core::update_downloads::{
    self as downloads, Row, RowState, INCOMING_CHUNKS, INCOMING_DIR, INCOMING_IDLE_MS,
    INCOMING_MANIFEST, INCOMING_PAYLOAD, INCOMING_SNAPSHOT, INCOMING_VERIFIED, MAX_INCOMING_BYTES,
    MAX_QUARANTINE_BYTES, QUARANTINE_AGE_MS, QUARANTINE_DIR,
};
use raven_core::update_exchange::{
    self as rup1, Chunk, ErrorCode, Have, ListenerDecode, Offer, Rup1Msg, MAX_CHUNKS_PER_DIAL,
    MAX_CHUNKS_PER_REQUEST, MAX_OFFERS, NO_REQ_ID, SERVE_AT_ONCE, SERVE_BYTES_PER_DAY,
    SERVE_REQUESTS_PER_MINUTE,
};
use raven_core::update_state::{
    self, Applied, Build, Origin, Refused, UpdateState, STAGED_DIR, STAGED_MANIFEST,
    STAGED_SNAPSHOT,
};
use raven_core::{OutboxCarrier, CAP_LINK_RUP1};
use tokio::sync::Notify;

/// A friend's HAVE counts this long for fetch decisions.
const HAVE_FRESH: Duration = Duration::from_secs(24 * 3_600);
/// The same claims of a friend are fetched again at most this often.
const NOTICE_REFETCH: Duration = Duration::from_secs(10 * 60);
/// A friend that passed on a forged notice is not asked again for this long.
const FORGED_PARK: Duration = Duration::from_secs(24 * 3_600);
/// A friend that sent a forged copy of a release, or does not serve it, is
/// not asked for that release again for this long.
const BAD_COPY_PARK: Duration = Duration::from_secs(24 * 3_600);
/// A dial that failed, or a BUSY: that friend waits this long.
const DIAL_RETRY: Duration = Duration::from_secs(30);
/// RATE_LIMITED: that friend waits this long.
const RATE_PARK: Duration = Duration::from_secs(60);
/// Download dials one pass makes at most, over every friend.
const MAX_DOWNLOAD_DIALS_PER_PASS: usize = 32;
/// Notice dials one pass makes to one friend at most: the notices, and one
/// more for each key rotation this node catches up with
/// ([`update_state::MAX_ROTATIONS`]).
const MAX_NOTICE_ROUNDS: usize = 2 + update_state::MAX_ROTATIONS;
/// Catch-up dials (GET_ROTATION) to one friend a day at most: enough to
/// take every rotation a friend keeps ([`update_state::MAX_ROTATIONS`]).
/// With them spent, a notice under a key set this node never trusted
/// counts as forged (Phase 6 review re-verify, updates-protocol-3).
const MAX_CATCH_UPS_PER_DAY: u32 = update_state::MAX_ROTATIONS as u32;
/// The task looks again this often without a kick.
const PASS_INTERVAL: Duration = Duration::from_secs(60);
/// ... and this soon while a download goes on.
const PASS_BUSY: Duration = Duration::from_secs(2);
/// Storage is pruned at most this often.
const PRUNE_INTERVAL: Duration = Duration::from_secs(3_600);
/// One follow-up dial's deadline.
const DIAL_DEADLINE: Duration = Duration::from_secs(45);
/// The reply budget of a follow-up dial (16 chunks and the replies around
/// them; `crate::netutil::INTERNAL_REPLY_BUDGET`): a node-internal dial, never an
/// IPC response.
pub(crate) const DIAL_REPLY_BUDGET: usize = 2 * 1024 * 1024;
/// Friends whose HAVE is kept at most.
const MAX_HAVES: usize = 256;
/// Chunk trees kept for serving at most.
const MAX_TREES: usize = 2;
/// An incoming folder without a row is removed after this (an interrupted
/// write, a row forgotten).
const ORPHAN_AGE_MS: u64 = 3_600_000;
const DAY: Duration = Duration::from_secs(86_400);
const MINUTE: Duration = Duration::from_secs(60);

// ── Gate and build ──────────────────────────────────────────────────────────

#[cfg(test)]
thread_local! {
    static BUILD_FOR_TEST: std::cell::RefCell<Option<Build>> = const { std::cell::RefCell::new(None) };
}

/// This build as the update state reads it (its key set, serial and
/// floor), read once. A test sets its own for its thread
/// ([`BuildForTest`]).
pub(crate) fn build() -> Build {
    #[cfg(test)]
    if let Some(build) = BUILD_FOR_TEST.with(|b| b.borrow().clone()) {
        return build;
    }
    static BUILD: OnceLock<Build> = OnceLock::new();
    BUILD.get_or_init(Build::this).clone()
}

/// [`build`] for the current thread until dropped (a `#[tokio::test]` runs
/// both ends of a scripted link on it).
#[cfg(all(test, debug_assertions))]
pub(crate) struct BuildForTest;

#[cfg(all(test, debug_assertions))]
impl BuildForTest {
    pub(crate) fn set(build: Build) -> Self {
        BUILD_FOR_TEST.with(|b| *b.borrow_mut() = Some(build));
        Self
    }
}

#[cfg(all(test, debug_assertions))]
impl Drop for BuildForTest {
    fn drop(&mut self) {
        BUILD_FOR_TEST.with(|b| *b.borrow_mut() = None);
    }
}

/// The exchange runs in this process: the gate for notices
/// ([`raven_core::update_exchange::notices_live`]: `MESH_UPDATE`, the release
/// bundle and advisory gates, no hold but one on release bundles) and a
/// release key set to check with. Bundles pass only while
/// [`bundles_live`] too.
pub(crate) fn active() -> bool {
    rup1::notices_live() && build().key_set.is_some()
}

/// Release bundles pass too ([`raven_core::update_exchange::live`]: no hold
/// on bundles either; Phase 6 review updates-protocol-4): offers in our
/// HAVE, GET_MANIFEST and GET_CHUNKS served, download rows fetched.
fn bundles_live() -> bool {
    rup1::live()
}

/// `=1` (debug builds with `RAVEN_LAB_TEST_A=1` only): this node's HAVE
/// claims one advisory serial more than its update state holds, with the
/// digest of the one it holds, so a friend holding the newer notice asks
/// and is answered with the older one. A friend stuck on an old notice that
/// says otherwise: the rolled-back notice of the update harness's C88
/// (P6.51), which an honest node never sends. A release build never reads
/// it.
pub(crate) const LAB_CLAIM_NEWER: &str = "RAVEN_LAB_UPDATE_CLAIM_NEWER";

#[cfg(test)]
thread_local! {
    static CLAIM_NEWER_FOR_TEST: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

/// [`LAB_CLAIM_NEWER`] is on (a test's own setting for its thread first;
/// either way never in a release build).
fn lab_claim_newer() -> bool {
    #[cfg(test)]
    if let Some(on) = CLAIM_NEWER_FOR_TEST.with(std::cell::Cell::get) {
        return cfg!(debug_assertions) && on;
    }
    raven_core::pair_init::lab_switch(LAB_CLAIM_NEWER)
}

/// [`lab_claim_newer`] for the current thread (`None`: the variable again).
#[cfg(test)]
pub(crate) fn set_lab_claim_newer_for_this_thread(on: Option<bool>) {
    CLAIM_NEWER_FOR_TEST.with(|c| c.set(on));
}

/// Run `work` on the blocking pool with this thread's gate overrides (an
/// in-process test's; none otherwise, and a release build ignores them):
/// `None` when it panicked.
async fn blocking<T, F>(work: F) -> Option<T>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let gates = security_gate::lab_overrides_for_this_thread();
    tokio::task::spawn_blocking(move || {
        let before = security_gate::set_lab_overrides_for_this_thread(gates);
        let out = work();
        security_gate::set_lab_overrides_for_this_thread(before);
        out
    })
    .await
    .ok()
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn pinned(data_dir: &Path, peer: &[u8; 32]) -> bool {
    raven_core::contact_is_pinned(data_dir, peer).unwrap_or(false)
}

// ── Shared state ────────────────────────────────────────────────────────────

/// A friend's last HAVE and when it came.
#[derive(Clone, Debug)]
struct PeerHave {
    have: Have,
    at: Instant,
}

/// What a friend's HAVE claimed when its notices were last fetched.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Claims {
    adv: (u64, [u8; 32]),
    log: (u32, [u8; 32]),
}

impl Claims {
    fn of(have: &Have) -> Self {
        Self {
            adv: (have.adv_serial, have.adv_digest),
            log: (have.log_size, have.log_root),
        }
    }
}

/// Serving quotas of one friend (spec §7).
#[derive(Debug, Default)]
struct Quota {
    requests: Vec<Instant>,
    day_start: Option<Instant>,
    day_bytes: u64,
}

impl Quota {
    /// One more request within [`SERVE_REQUESTS_PER_MINUTE`] a minute?
    fn admit_request(&mut self, now: Instant) -> bool {
        self.requests
            .retain(|at| now.saturating_duration_since(*at) < MINUTE);
        if self.requests.len() >= SERVE_REQUESTS_PER_MINUTE as usize {
            return false;
        }
        self.requests.push(now);
        true
    }

    /// `bytes` more within [`SERVE_BYTES_PER_DAY`] a day?
    fn admit_bytes(&mut self, bytes: u64, now: Instant) -> bool {
        let start = *self.day_start.get_or_insert(now);
        if now.saturating_duration_since(start) >= DAY {
            self.day_start = Some(now);
            self.day_bytes = 0;
        }
        if self.day_bytes.saturating_add(bytes) > SERVE_BYTES_PER_DAY {
            return false;
        }
        self.day_bytes += bytes;
        true
    }
}

/// What the exchange keeps in memory.
#[derive(Default)]
pub(crate) struct Shared {
    haves: HashMap<[u8; 32], PeerHave>,
    /// Friends whose HAVE wants a notice fetch.
    due: Vec<[u8; 32]>,
    /// The claims each friend's notices were last fetched for, and when.
    fetched: HashMap<[u8; 32], (Claims, Instant)>,
    /// Friends not asked for notices before (a forged one).
    notice_parked: HashMap<[u8; 32], Instant>,
    /// Catch-up dials (GET_ROTATION) to each friend today.
    catch_ups: HashMap<[u8; 32], CatchUps>,
    /// Friends not dialled before (a failed dial, BUSY, RATE_LIMITED).
    parked: HashMap<[u8; 32], Instant>,
    /// (friend, release) not asked before: a forged copy, or not served.
    bad_copy: HashMap<([u8; 32], [u8; 32]), Instant>,
    quotas: HashMap<[u8; 32], Quota>,
    /// Requests being served now, over every friend.
    serving: usize,
    /// Chunk trees of releases served lately (their root checked).
    trees: Vec<([u8; 32], Arc<ChunkTree>)>,
    next_prune: Option<Instant>,
    /// Counts since start (the tests read them).
    forged_chunks: u32,
    forged_notices: u32,
}

impl Shared {
    fn parked(&self, peer: &[u8; 32], now: Instant) -> bool {
        self.parked.get(peer).is_some_and(|until| *until > now)
    }

    fn park(&mut self, peer: &[u8; 32], until: Instant) {
        let at = self.parked.entry(*peer).or_insert(until);
        *at = (*at).max(until);
    }

    fn bad_copy(&self, peer: &[u8; 32], digest: &[u8; 32], now: Instant) -> bool {
        self.bad_copy
            .get(&(*peer, *digest))
            .is_some_and(|until| *until > now)
    }

    /// `peer`'s catch-ups of the day `now` is in (none: a new day).
    fn catch_ups(&self, peer: &[u8; 32], now: Instant) -> CatchUps {
        self.catch_ups
            .get(peer)
            .filter(|c| now.saturating_duration_since(c.since) < DAY)
            .copied()
            .unwrap_or(CatchUps {
                since: now,
                dials: 0,
                rotated: false,
            })
    }

    /// One catch-up dial to `peer` at `now`.
    fn count_catch_up(&mut self, peer: &[u8; 32], now: Instant) {
        let mut today = self.catch_ups(peer, now);
        today.dials += 1;
        if self.catch_ups.len() >= MAX_HAVES && !self.catch_ups.contains_key(peer) {
            // Bounded like the HAVEs: the oldest day goes.
            if let Some(oldest) = self
                .catch_ups
                .iter()
                .min_by_key(|(_, c)| c.since)
                .map(|(k, _)| *k)
            {
                self.catch_ups.remove(&oldest);
            }
        }
        self.catch_ups.insert(*peer, today);
    }

    /// `peer` brought a rotation today (`now`).
    fn note_rotation(&mut self, peer: &[u8; 32], now: Instant) {
        let mut today = self.catch_ups(peer, now);
        today.rotated = true;
        self.catch_ups.insert(*peer, today);
    }
}

/// One friend's catch-up dials (GET_ROTATION) of a day.
#[derive(Clone, Copy, Debug)]
struct CatchUps {
    /// When the day began.
    since: Instant,
    /// Dials made ([`MAX_CATCH_UPS_PER_DAY`] at most).
    dials: u32,
    /// The friend brought a rotation: a notice under a key set this node
    /// does not know yet may come right with its next one.
    rotated: bool,
}

impl CatchUps {
    fn left(&self) -> bool {
        self.dials < MAX_CATCH_UPS_PER_DAY
    }
}

fn shared() -> &'static Mutex<Shared> {
    static SHARED: OnceLock<Mutex<Shared>> = OnceLock::new();
    SHARED.get_or_init(Mutex::default)
}

fn kicked() -> &'static Notify {
    static KICK: OnceLock<Notify> = OnceLock::new();
    KICK.get_or_init(Notify::new)
}

/// Wake the exchange task now: an approval (IPC `UpdateKick`), or a HAVE
/// that wants a fetch.
pub(crate) fn kick() {
    kicked().notify_one();
}

// ── The node ────────────────────────────────────────────────────────────────

/// One profile's exchange: its folder, the build reading its update state
/// and its memory. Blocking (it reads and writes the profile).
pub(crate) struct Node<'a> {
    pub(crate) data_dir: &'a Path,
    pub(crate) build: &'a Build,
    pub(crate) shared: &'a Mutex<Shared>,
}

/// One follow-up dial: the friend, its frames and whether it fetches a
/// release (never over Bluetooth); the replies and the carrier that linked.
pub(crate) type DialFn<'a> =
    dyn FnMut(&[u8; 32], &[Vec<u8>], bool) -> Result<(Vec<Vec<u8>>, OutboxCarrier), String> + 'a;

/// The requests of one follow-up dial.
#[derive(Clone, Debug)]
pub(crate) struct Plan {
    reqs: Vec<([u8; 4], Rup1Msg)>,
}

impl Plan {
    fn of(msgs: Vec<Rup1Msg>) -> Self {
        Self {
            reqs: msgs
                .into_iter()
                .map(|m| (rand::random::<[u8; 4]>(), m))
                .collect(),
        }
    }

    pub(crate) fn frames(&self) -> Vec<Vec<u8>> {
        self.reqs
            .iter()
            .filter_map(|(id, m)| rup1::encode(id, m).ok())
            .collect()
    }

    /// The replies that answer request `at`, in order, up to its terminal
    /// one (spec §5): another op, another id or a chunk not asked for is
    /// ignored.
    fn answers(&self, at: usize, replies: &[Vec<u8>]) -> Vec<Rup1Msg> {
        let (id, request) = &self.reqs[at];
        let mut out = Vec::new();
        for frame in replies.iter().filter(|f| rup1::is_rup1(f)) {
            let Ok((rid, msg)) = rup1::decode(frame) else {
                continue;
            };
            if rid != *id || !request.answered_by(&msg) {
                continue;
            }
            let end = msg.is_terminal();
            out.push(msg);
            if end {
                break;
            }
        }
        out
    }
}

/// What one pass did (counts; the tests read them).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PassReport {
    pub(crate) dials: usize,
    pub(crate) notices: usize,
    pub(crate) chunks: usize,
    pub(crate) completed: usize,
    /// A download is under way: look again soon.
    pub(crate) busy: bool,
}

/// What a friend's notices did.
#[derive(Clone, Debug, Default)]
struct Noticed {
    /// Advisories and logs the update state stored.
    stored: usize,
    /// One of them applied a key rotation.
    rotated: bool,
    /// One was under a key set this node never trusted (it cannot be
    /// checked yet).
    unknown_keys: bool,
    /// Those notices' bytes, and whom they came from (they count as forged
    /// when no catch-up is left: [`MAX_CATCH_UPS_PER_DAY`]).
    unknown: Vec<Vec<u8>>,
    origin: Option<Origin>,
    /// The friend answered BUSY or RATE_LIMITED (a catch-up's rotation
    /// request included): nothing it sent then counts against it.
    busy: bool,
}

/// Why a friend's reply made no progress.
enum Took {
    Progress,
    Nothing,
}

impl<'a> Node<'a> {
    pub(crate) fn new(data_dir: &'a Path, build: &'a Build, shared: &'a Mutex<Shared>) -> Self {
        Self {
            data_dir,
            build,
            shared,
        }
    }

    fn state(&self) -> Option<UpdateState> {
        let state = update_state::load_with(self.data_dir, self.build).ok()?;
        state.key_set()?;
        Some(state)
    }

    fn origin(peer: &[u8; 32], carrier: OutboxCarrier, dialled: bool) -> Origin {
        Origin::friend(
            *peer,
            if dialled {
                Via::Dial(carrier)
            } else {
                Via::DirectLink(carrier)
            },
        )
    }

    // ── HAVE ──

    /// Our HAVE on a link of `carrier` (spec §3.1): the stored advisory and
    /// log, and up to 4 releases held for this platform (none over
    /// Bluetooth, none while serving is off).
    pub(crate) fn have(&self, carrier: OutboxCarrier) -> Have {
        let Some(state) = self.state() else {
            return Have::nothing();
        };
        let (adv_serial, adv_digest) = state
            .advisory()
            .map_or((0, [0; 32]), |a| (a.serial, a.digest()));
        // The lab's friend stuck on an old notice (C88): it claims the next
        // serial with the digest of the one it holds.
        let adv_serial = if adv_serial > 0 && lab_claim_newer() {
            adv_serial.saturating_add(1)
        } else {
            adv_serial
        };
        let (log_size, log_root) = state.log().map_or((0, [0; 32]), |l| {
            (
                u32::try_from(l.sth().tree_size).unwrap_or(0),
                l.sth().root_hash,
            )
        });
        let (log_size, log_root) = if log_size == 0 {
            (0, [0; 32])
        } else {
            (log_size, log_root)
        };
        let offers = if carrier != OutboxCarrier::Nearby && bundles_live() && self.serving_on() {
            held(self.data_dir)
                .iter()
                .take(MAX_OFFERS)
                .map(Held::offer)
                .collect()
        } else {
            Vec::new()
        };
        Have {
            adv_serial,
            adv_digest,
            log_size,
            log_root,
            offers,
        }
    }

    /// Our HAVE frame for a link with `peer`: `None` unless it is a pinned
    /// contact.
    pub(crate) fn have_frame(&self, peer: &[u8; 32], carrier: OutboxCarrier) -> Option<Vec<u8>> {
        if !pinned(self.data_dir, peer) {
            return None;
        }
        rup1::encode(&NO_REQ_ID, &Rup1Msg::Have(self.have(carrier))).ok()
    }

    fn serving_on(&self) -> bool {
        raven_core::node_policy::load_policy(self.data_dir).update_serve_on()
    }

    /// Take a pinned contact's HAVE (spec §7): kept for the pass; newer
    /// notices make it due, offers for this computer become download rows.
    /// `true`: the task has work now (kick it). Nothing is due while frozen.
    pub(crate) fn take_have(&self, peer: &[u8; 32], have: Have, now: Instant) -> bool {
        if !pinned(self.data_dir, peer) {
            return false;
        }
        let Some(state) = self.state() else {
            return false;
        };
        let installed = state.installed_serial();
        let offers: Vec<Offer> = have
            .offers
            .iter()
            .filter(|o| downloads::for_this_computer(o, installed))
            .cloned()
            .collect();
        let mut work = !offers.is_empty() && state.frozen().is_none();
        if work {
            let wall = raven_core::clock::now_ms();
            let wanted = downloads::change(self.data_dir, |rows| {
                for offer in &offers {
                    rows.note_offer(peer, offer, wall);
                }
                rows.forget_installed(installed);
                offers
                    .iter()
                    .any(|o| rows.row(&o.manifest_digest).is_some_and(Row::wanted))
            });
            work = wanted.unwrap_or(false);
        }
        let notices = state.frozen().is_none() && wants_notices(&state, &have);
        let mut s = lock(self.shared);
        if s.haves.len() >= MAX_HAVES && !s.haves.contains_key(peer) {
            if let Some(oldest) = s.haves.iter().min_by_key(|(_, h)| h.at).map(|(k, _)| *k) {
                s.haves.remove(&oldest);
            }
        }
        s.haves.insert(*peer, PeerHave { have, at: now });
        if notices {
            if !s.due.contains(peer) {
                s.due.push(*peer);
            }
            work = true;
        }
        work
    }

    // ── Serving (the listener) ──

    /// A frame the dialer `peer` sent on a link of `carrier` (spec §6): the
    /// replies to write. `first_have`: a HAVE is taken only once per link.
    pub(crate) fn listener_frame(
        &self,
        peer: &[u8; 32],
        carrier: OutboxCarrier,
        frame: &[u8],
        first_have: bool,
        now: Instant,
    ) -> (Vec<Vec<u8>>, bool) {
        match rup1::decode_for_listener(frame) {
            ListenerDecode::Drop => (Vec::new(), false),
            ListenerDecode::Have(have) => {
                let work = first_have && self.take_have(peer, have, now);
                (Vec::new(), work)
            }
            ListenerDecode::Refuse(id, code) => (error(&id, code), false),
            ListenerDecode::Request(id, msg) => (self.serve(peer, carrier, &id, &msg, now), false),
        }
    }

    /// Answer `peer`'s request (spec §7).
    pub(crate) fn serve(
        &self,
        peer: &[u8; 32],
        carrier: OutboxCarrier,
        id: &[u8; 4],
        msg: &Rup1Msg,
        now: Instant,
    ) -> Vec<Vec<u8>> {
        if !pinned(self.data_dir, peer) {
            return error(id, ErrorCode::PolicyDenied);
        }
        {
            let mut s = lock(self.shared);
            if !s.quotas.entry(*peer).or_default().admit_request(now) {
                return error(id, ErrorCode::RateLimited);
            }
            if s.serving >= SERVE_AT_ONCE {
                return error(id, ErrorCode::Busy);
            }
            s.serving += 1;
        }
        let out = self.answer(peer, carrier, id, msg, now);
        lock(self.shared).serving -= 1;
        out
    }

    fn answer(
        &self,
        peer: &[u8; 32],
        carrier: OutboxCarrier,
        id: &[u8; 4],
        msg: &Rup1Msg,
        now: Instant,
    ) -> Vec<Vec<u8>> {
        let Some(state) = self.state() else {
            return error(id, ErrorCode::NotFound);
        };
        let bundles = carrier != OutboxCarrier::Nearby && bundles_live() && self.serving_on();
        let reply = match msg {
            Rup1Msg::GetAdvisory => match (state.advisory(), state.log()) {
                (Some(advisory), Some(log)) => Rup1Msg::Advisory {
                    rad1: advisory.bytes().to_vec(),
                    snapshot: log.encode(),
                },
                _ => Rup1Msg::Error(ErrorCode::NotFound),
            },
            Rup1Msg::GetLog => match state.log() {
                Some(log) => Rup1Msg::Log {
                    snapshot: log.encode(),
                },
                None => Rup1Msg::Error(ErrorCode::NotFound),
            },
            // A friend still on an older key set (Phase 6 review
            // updates-protocol-3): the rotation away from it, with the log
            // it was accepted with, both of which that friend can check.
            Rup1Msg::GetRotation { key_set_digest } => match state.rotation_from(key_set_digest) {
                Some((advisory, log)) => Rup1Msg::Advisory {
                    rad1: advisory.bytes().to_vec(),
                    snapshot: log.encode(),
                },
                None => Rup1Msg::Error(ErrorCode::NotFound),
            },
            Rup1Msg::GetManifest { .. } | Rup1Msg::GetChunks { .. } if !bundles => {
                Rup1Msg::Error(ErrorCode::PolicyDenied)
            }
            Rup1Msg::GetManifest { manifest_digest } => {
                match find_held(self.data_dir, manifest_digest) {
                    Some(held) => {
                        // The stored log when it lists the release (it is the
                        // newest), else the one it came with.
                        let snapshot = state
                            .log()
                            .filter(|l| {
                                raven_core::tlog::contains(
                                    l.entries(),
                                    EntryType::Manifest,
                                    manifest_digest,
                                )
                            })
                            .map_or_else(|| held.snapshot.clone(), Snapshot::encode);
                        Rup1Msg::Manifest {
                            manifest: held.manifest.bytes().to_vec(),
                            snapshot,
                        }
                    }
                    None => Rup1Msg::Error(ErrorCode::NotFound),
                }
            }
            Rup1Msg::GetChunks {
                manifest_digest,
                first,
                count,
            } => return self.serve_chunks(peer, id, manifest_digest, *first, *count, now),
            // decode_for_listener hands requests only.
            _ => Rup1Msg::Error(ErrorCode::Unsupported),
        };
        match rup1::encode(id, &reply) {
            Ok(frame) => vec![frame],
            // An advisory and log that do not fit one frame (spec §8).
            Err(_) => error(id, ErrorCode::NotFound),
        }
    }

    fn serve_chunks(
        &self,
        peer: &[u8; 32],
        id: &[u8; 4],
        digest: &[u8; 32],
        first: u32,
        count: u8,
        now: Instant,
    ) -> Vec<Vec<u8>> {
        let Some(held) = find_held(self.data_dir, digest) else {
            return error(id, ErrorCode::NotFound);
        };
        let total = held.manifest.chunk_count();
        if u64::from(first) >= total {
            return error(id, ErrorCode::NotFound);
        }
        let Some(tree) = self.tree(&held) else {
            return error(id, ErrorCode::NotFound);
        };
        let mut out = Vec::new();
        let mut sent = 0u8;
        let mut stopped = None;
        let end = (u64::from(first) + u64::from(count)).min(total);
        for index in u64::from(first)..end {
            let len = held.manifest.chunk_len(index).unwrap_or(0);
            if !lock(self.shared)
                .quotas
                .entry(*peer)
                .or_default()
                .admit_bytes(len, now)
            {
                stopped = Some(ErrorCode::RateLimited);
                break;
            }
            let chunk = held
                .read(index * u64::from(CHUNK_SIZE), len as usize)
                .ok()
                .filter(|bytes| tree.leaf(index as usize) == Some(leaf_hash(bytes)))
                .and_then(|bytes| {
                    Some(Chunk {
                        index: index as u32,
                        bytes,
                        path: tree.chunk_path(index as usize)?,
                    })
                });
            let Some(frame) = chunk.and_then(|c| rup1::encode(id, &Rup1Msg::Chunk(c)).ok()) else {
                // The disk no longer holds what the tree says.
                stopped = Some(ErrorCode::NotFound);
                break;
            };
            out.push(frame);
            sent += 1;
        }
        if let Ok(end) = rup1::encode(id, &Rup1Msg::ChunksEnd { stopped, sent }) {
            out.push(end);
        }
        out
    }

    /// The chunk tree of a held release, its root checked against the
    /// manifest; cached for the next requests.
    fn tree(&self, held: &Held) -> Option<Arc<ChunkTree>> {
        let digest = held.manifest.digest();
        if let Some((_, tree)) = lock(self.shared).trees.iter().find(|(d, _)| *d == digest) {
            return Some(tree.clone());
        }
        let total = held.manifest.chunk_count();
        let mut leaves = Vec::with_capacity(total as usize);
        for index in 0..total {
            let len = held.manifest.chunk_len(index)? as usize;
            let bytes = held.read(index * u64::from(CHUNK_SIZE), len).ok()?;
            leaves.push(leaf_hash(&bytes));
        }
        let tree = ChunkTree::of_leaf_hashes(leaves);
        if tree.root() != held.manifest.payload_chunk_root {
            return None;
        }
        let tree = Arc::new(tree);
        let mut s = lock(self.shared);
        s.trees.insert(0, (digest, tree.clone()));
        s.trees.truncate(MAX_TREES);
        Some(tree)
    }

    // ── Fetching (the dialer) ──

    /// One pass of the task at `now`: the notices of due friends, then the
    /// approved downloads, through `dial`.
    pub(crate) fn pass(&self, now: Instant, dial: &mut DialFn<'_>) -> PassReport {
        let mut report = PassReport::default();
        let wall = raven_core::clock::now_ms();
        // Bundles held (a security notice's hold on release bundles): only
        // notices pass, and nothing of a download is touched.
        let bundles = bundles_live();
        let prune = bundles && {
            let mut s = lock(self.shared);
            let due = s.next_prune.is_none_or(|at| at <= now);
            if due {
                s.next_prune = Some(now + PRUNE_INTERVAL);
            }
            due
        };
        if prune {
            self.prune(wall);
        }
        let due = std::mem::take(&mut lock(self.shared).due);
        for peer in due {
            if !self.fetch_notices(&peer, now, dial, &mut report) {
                return report;
            }
        }
        if !bundles {
            return report;
        }
        // A notice taken may have frozen the state.
        let Some(state) = self.state() else {
            return report;
        };
        if state.frozen().is_some() {
            return report;
        }
        self.revive_not_logged(&state, now);
        let rows = downloads::load(self.data_dir).unwrap_or_default().rows;
        for row in rows.into_iter().filter(Row::wanted) {
            // Every chunk in but not checked yet (the check did not finish,
            // or raven-node stopped before it did): checked now, no dial.
            if self.finish_pending(&row, wall) {
                report.completed += 1;
                continue;
            }
            self.download(&row, now, dial, &mut report);
            if report.dials >= MAX_DOWNLOAD_DIALS_PER_PASS {
                report.busy = true;
                break;
            }
        }
        report
    }

    /// Ask `peer` for its notices (one dial, or a few to catch up with key
    /// rotations it took and this node missed: Phase 6 review
    /// updates-protocol-3). `false`: the update state cannot be read.
    fn fetch_notices(
        &self,
        peer: &[u8; 32],
        now: Instant,
        dial: &mut DialFn<'_>,
        report: &mut PassReport,
    ) -> bool {
        let mut catch_up = false;
        for _ in 0..MAX_NOTICE_ROUNDS {
            // Read again each round: what the last one took counts.
            let Some(state) = self.state() else {
                return false;
            };
            let plan = if catch_up {
                self.catch_up_plan(peer, &state, now)
            } else {
                self.notice_plan(peer, &state, now)
            };
            let Some(plan) = plan else {
                break;
            };
            if catch_up {
                lock(self.shared).count_catch_up(peer, now);
            }
            report.dials += 1;
            let took = match dial(peer, &plan.frames(), false) {
                Ok((replies, carrier)) => {
                    self.take_notices(peer, carrier, &plan, &replies, catch_up, now)
                }
                Err(_) => {
                    lock(self.shared).park(peer, now + DIAL_RETRY);
                    break;
                }
            };
            report.notices += took.stored;
            let today = {
                let mut s = lock(self.shared);
                if took.rotated {
                    s.note_rotation(peer, now);
                }
                s.catch_ups(peer, now)
            };
            if took.rotated {
                // A rotation taken: what that friend holds may check now,
                // or after its next rotation.
                lock(self.shared).fetched.remove(peer);
                if took.unknown_keys && !today.left() {
                    // Today's catch-ups are spent: the rest tomorrow, and
                    // no blame while that friend brings rotations.
                    break;
                }
                catch_up = took.unknown_keys;
            } else if took.unknown_keys && !catch_up {
                if today.left() {
                    // Under a key set this node does not know yet: ask for
                    // the rotation away from its own set first.
                    catch_up = true;
                } else {
                    // No catch-up left today: unless that friend brought a
                    // rotation today, what it sent counts as forged.
                    if !today.rotated {
                        if let Some(origin) = took.origin {
                            self.count_forged(peer, origin, &took.unknown, now);
                        }
                    }
                    break;
                }
            } else {
                break;
            }
        }
        true
    }

    /// `peer`'s notices under a key set this node never trusted, with no
    /// catch-up to explain them (the friend gave no rotation, or the day's
    /// catch-ups are spent): forged, as a notice that fails its check is
    /// (SEC_ADVISORY_FORGED, quarantine, that friend not asked for a day).
    fn count_forged(&self, peer: &[u8; 32], origin: Origin, notices: &[Vec<u8>], now: Instant) {
        if notices.is_empty() {
            return;
        }
        let wall = raven_core::clock::now_ms();
        for bytes in notices {
            quarantine(self.data_dir, "notice", bytes, wall);
            note_forged(origin);
        }
        let mut s = lock(self.shared);
        s.forged_notices += u32::try_from(notices.len()).unwrap_or(u32::MAX);
        s.notice_parked.insert(*peer, now + FORGED_PARK);
    }

    /// What to ask `peer` for its notices, from its last HAVE.
    fn notice_plan(&self, peer: &[u8; 32], state: &UpdateState, now: Instant) -> Option<Plan> {
        if !pinned(self.data_dir, peer) {
            return None;
        }
        // While frozen nothing is asked for: nothing new would be applied,
        // and no advisory lifts a freeze (only a release installed by hand
        // does; Phase 6 review updates-protocol-2).
        if state.frozen().is_some() {
            return None;
        }
        let mut s = lock(self.shared);
        if s.parked(peer, now) || s.notice_parked.get(peer).is_some_and(|until| *until > now) {
            return None;
        }
        let have = s
            .haves
            .get(peer)
            .filter(|h| now.saturating_duration_since(h.at) < HAVE_FRESH)?
            .have
            .clone();
        let claims = Claims::of(&have);
        if s.fetched.get(peer).is_some_and(|(c, at)| {
            *c == claims && now.saturating_duration_since(*at) < NOTICE_REFETCH
        }) {
            return None;
        }
        let ask = notice_request(state, &have)?;
        s.fetched.insert(*peer, (claims, now));
        Some(Plan::of(vec![ask]))
    }

    /// `peer`'s notices came under a key set this node never trusted: ask
    /// for the rotation away from this node's current set (GET_ROTATION,
    /// answered with the log it was accepted with), then the same notice
    /// again, in one dial.
    fn catch_up_plan(&self, peer: &[u8; 32], state: &UpdateState, now: Instant) -> Option<Plan> {
        if !pinned(self.data_dir, peer) || state.frozen().is_some() {
            return None;
        }
        let key_set_digest = state.key_set()?.digest();
        let s = lock(self.shared);
        if s.parked(peer, now) || s.notice_parked.get(peer).is_some_and(|until| *until > now) {
            return None;
        }
        let have = s
            .haves
            .get(peer)
            .filter(|h| now.saturating_duration_since(h.at) < HAVE_FRESH)?
            .have
            .clone();
        let ask = notice_request(state, &have)?;
        Some(Plan::of(vec![Rup1Msg::GetRotation { key_set_digest }, ask]))
    }

    /// Take the notices `peer` answered. In a catch-up dial (`catch_up`:
    /// GET_ROTATION first), a notice still under a key set this node never
    /// trusted after no rotation came (and no BUSY or RATE_LIMITED) is
    /// forged: the friend could not show how its key set follows from this
    /// node's.
    fn take_notices(
        &self,
        peer: &[u8; 32],
        carrier: OutboxCarrier,
        plan: &Plan,
        replies: &[Vec<u8>],
        catch_up: bool,
        now: Instant,
    ) -> Noticed {
        let origin = Self::origin(peer, carrier, true);
        let wall = raven_core::clock::now_ms();
        let mut took = Noticed {
            origin: Some(origin),
            ..Noticed::default()
        };
        for at in 0..plan.reqs.len() {
            let Some(answer) = plan.answers(at, replies).pop() else {
                continue;
            };
            let forged = match answer {
                Rup1Msg::Advisory { rad1, snapshot } => {
                    match update_state::accept_advisory_with(
                        self.data_dir,
                        self.build,
                        &rad1,
                        &snapshot,
                        origin,
                    ) {
                        Ok(Applied::Stored { rotated_to, .. }) => {
                            took.stored += 1;
                            took.rotated |= rotated_to.is_some();
                            None
                        }
                        Err(Refused::Forged(_) | Refused::Unlogged) => {
                            Some([rad1, snapshot].concat())
                        }
                        // The catch-up gave no rotation: forged.
                        Err(Refused::UnknownKeySet) if catch_up && !took.rotated && !took.busy => {
                            note_forged(origin);
                            Some([rad1, snapshot].concat())
                        }
                        // Not checkable yet: nothing kept, nobody blamed.
                        Err(Refused::UnknownKeySet) => {
                            took.unknown_keys = true;
                            took.unknown.push([rad1, snapshot].concat());
                            None
                        }
                        _ => None,
                    }
                }
                Rup1Msg::Log { snapshot } => {
                    match update_state::accept_log_with(
                        self.data_dir,
                        self.build,
                        &snapshot,
                        origin,
                    ) {
                        Ok(raven_core::tlog::Consistency::Extends) => {
                            took.stored += 1;
                            None
                        }
                        Err(Refused::Forged(_)) => Some(snapshot),
                        Err(Refused::UnknownKeySet) if catch_up && !took.rotated && !took.busy => {
                            note_forged(origin);
                            Some(snapshot)
                        }
                        Err(Refused::UnknownKeySet) => {
                            took.unknown_keys = true;
                            took.unknown.push(snapshot);
                            None
                        }
                        _ => None,
                    }
                }
                Rup1Msg::Error(ErrorCode::Busy | ErrorCode::RateLimited) => {
                    // Not answered now (a catch-up included): asked again,
                    // nobody blamed.
                    took.busy = true;
                    let mut s = lock(self.shared);
                    s.park(peer, now + RATE_PARK);
                    // Asked again once the park is over.
                    s.fetched.remove(peer);
                    if !s.due.contains(peer) {
                        s.due.push(*peer);
                    }
                    None
                }
                _ => None,
            };
            if let Some(bytes) = forged {
                quarantine(self.data_dir, "notice", &bytes, wall);
                let mut s = lock(self.shared);
                s.forged_notices += 1;
                s.notice_parked.insert(*peer, now + FORGED_PARK);
            }
        }
        took
    }

    /// Fetch an approved release: its manifest, then its chunks, from every
    /// friend that offered it, round and round while they give.
    fn download(&self, row: &Row, now: Instant, dial: &mut DialFn<'_>, report: &mut PassReport) {
        let digest = row.digest;
        loop {
            let friends: Vec<[u8; 32]> = {
                let s = lock(self.shared);
                row.from
                    .iter()
                    .filter(|f| !s.parked(f, now) && !s.bad_copy(f, &digest, now))
                    .copied()
                    .collect()
            };
            let friends: Vec<[u8; 32]> = friends
                .into_iter()
                .filter(|f| pinned(self.data_dir, f))
                .collect();
            if friends.is_empty() {
                return;
            }
            let mut progress = false;
            for friend in friends {
                let Some(plan) = self.download_plan(&digest) else {
                    return;
                };
                report.dials += 1;
                report.busy = true;
                let gave = match dial(&friend, &plan.frames(), true) {
                    Ok((replies, carrier)) => matches!(
                        self.take_download(&friend, carrier, row, &plan, &replies, now, report),
                        Took::Progress
                    ),
                    Err(_) => false,
                };
                if gave {
                    progress = true;
                } else {
                    // Nothing from this friend this time: the others first.
                    lock(self.shared).park(&friend, now + DIAL_RETRY);
                }
                if self.finished(&digest) {
                    report.busy = false;
                    return;
                }
                if report.dials >= MAX_DOWNLOAD_DIALS_PER_PASS {
                    return;
                }
            }
            if !progress {
                return;
            }
        }
    }

    /// The download of `digest` is no longer wanted (complete, failed or
    /// gone).
    fn finished(&self, digest: &[u8; 32]) -> bool {
        !downloads::load(self.data_dir)
            .ok()
            .and_then(|rows| rows.row(digest).map(Row::wanted))
            .unwrap_or(false)
    }

    /// What to ask for next: the manifest (also when the log kept with it
    /// was set aside: a fresh one comes with it), else up to 16 missing
    /// chunks in at most two requests.
    fn download_plan(&self, digest: &[u8; 32]) -> Option<Plan> {
        let manifest = || {
            Some(Plan::of(vec![Rup1Msg::GetManifest {
                manifest_digest: *digest,
            }]))
        };
        let Some(incoming) = Incoming::open(self.data_dir, digest) else {
            return manifest();
        };
        if !incoming.has_log() {
            return manifest();
        }
        let runs = incoming.missing_runs(MAX_CHUNKS_PER_DIAL, MAX_CHUNKS_PER_REQUEST);
        if runs.is_empty() {
            return None;
        }
        Some(Plan::of(
            runs.into_iter()
                .map(|(first, count)| Rup1Msg::GetChunks {
                    manifest_digest: *digest,
                    first,
                    count,
                })
                .collect(),
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn take_download(
        &self,
        friend: &[u8; 32],
        carrier: OutboxCarrier,
        row: &Row,
        plan: &Plan,
        replies: &[Vec<u8>],
        now: Instant,
        report: &mut PassReport,
    ) -> Took {
        let origin = Self::origin(friend, carrier, true);
        let wall = raven_core::clock::now_ms();
        let digest = row.digest;
        let mut took = Took::Nothing;
        let mut incoming = Incoming::open(self.data_dir, &digest);
        let mut forged = false;
        for at in 0..plan.reqs.len() {
            if forged {
                break;
            }
            for answer in plan.answers(at, replies) {
                match answer {
                    Rup1Msg::Manifest { manifest, snapshot } => {
                        if let Some(opened) =
                            self.take_manifest(friend, origin, row, &manifest, &snapshot, now)
                        {
                            incoming = Some(opened);
                            took = Took::Progress;
                        }
                    }
                    Rup1Msg::Chunk(chunk) => {
                        let Some(inc) = incoming.as_mut() else {
                            continue;
                        };
                        if inc.written(chunk.index) {
                            continue;
                        }
                        if !chunk.check(&inc.manifest) {
                            // A forged copy: kept aside, that friend is not
                            // asked for this release again; the others go on.
                            quarantine(self.data_dir, "chunk", &chunk.bytes, wall);
                            update_state::note_bundle_refusal(BundleError::BadChunkRoot, origin);
                            let mut s = lock(self.shared);
                            s.forged_chunks += 1;
                            s.bad_copy.insert((*friend, digest), now + BAD_COPY_PARK);
                            forged = true;
                            break;
                        }
                        if inc.write(chunk.index, &chunk.bytes).is_ok() {
                            report.chunks += 1;
                            took = Took::Progress;
                        }
                    }
                    Rup1Msg::ChunksEnd {
                        stopped: Some(ErrorCode::RateLimited | ErrorCode::Busy),
                        ..
                    }
                    | Rup1Msg::Error(ErrorCode::RateLimited | ErrorCode::Busy) => {
                        lock(self.shared).park(friend, now + RATE_PARK);
                    }
                    Rup1Msg::ChunksEnd {
                        stopped: Some(_), ..
                    }
                    | Rup1Msg::Error(_) => {
                        // NOT_FOUND, POLICY_DENIED and the like: this friend
                        // does not serve the release (any more).
                        lock(self.shared)
                            .bad_copy
                            .insert((*friend, digest), now + BAD_COPY_PARK);
                    }
                    _ => {}
                }
            }
        }
        if let Some(inc) = incoming.as_mut() {
            let _ = inc.flush();
            let have = inc.count();
            let _ = downloads::change(self.data_dir, |rows| {
                if let Some(r) = rows.row_mut(&digest) {
                    r.chunks_have = have;
                }
            });
            if inc.complete() && self.finish(Some(friend), origin, inc, wall) {
                report.completed += 1;
            }
        }
        took
    }

    /// Take a manifest `friend` sent for `row`: verified like a bundle up to
    /// its payload (spec RRB1 §7), its log first (a split view freezes),
    /// then its folder made (or, when the folder is there already, its log
    /// replaced and its chunks kept). `None`: nothing kept.
    fn take_manifest(
        &self,
        friend: &[u8; 32],
        origin: Origin,
        row: &Row,
        manifest_bytes: &[u8],
        snapshot_bytes: &[u8],
        now: Instant,
    ) -> Option<Incoming> {
        let wall = raven_core::clock::now_ms();
        let digest = row.digest;
        let bad_copy = |what: &str, bytes: &[u8]| {
            quarantine(self.data_dir, what, bytes, wall);
            lock(self.shared)
                .bad_copy
                .insert((*friend, digest), now + BAD_COPY_PARK);
        };
        let manifest = match Manifest::decode(manifest_bytes) {
            Ok(m) if m.digest() == digest => m,
            // Not the release asked for: that friend's copy is bad.
            _ => {
                bad_copy("manifest", manifest_bytes);
                return None;
            }
        };
        let Ok(snapshot) = Snapshot::decode(snapshot_bytes) else {
            bad_copy("log", snapshot_bytes);
            return None;
        };
        match update_state::accept_log_with(self.data_dir, self.build, snapshot_bytes, origin) {
            Ok(_) => {}
            Err(Refused::Forged(_)) => {
                bad_copy("log", snapshot_bytes);
                return None;
            }
            // Frozen now (a split view), under a key set this node does not
            // know yet (its notices catch up first), or the state cannot be
            // read.
            Err(_) => return None,
        }
        let state = self.state()?;
        if state.frozen().is_some() {
            return None;
        }
        // Checked against the friend's log when that lists the release, else
        // against the stored one when that does: a friend that sends an
        // older log does not fail a release the others offer (Phase 6
        // review updates-protocol-6).
        let snapshot = if lists_release(&snapshot, &digest) {
            snapshot
        } else {
            state
                .log()
                .filter(|log| lists_release(log, &digest))
                .cloned()
                .unwrap_or(snapshot)
        };
        let parts = Parts {
            manifest,
            snapshot,
            advisory: None,
            payload: Vec::new(),
        };
        // Every check before the payload's (spec §7): the payload is all
        // that is missing.
        let outcome = verify_bundle(&parts, &state.verify_ctx(false)).map(|_| ());
        match outcome {
            Err(BundleError::PayloadLength) => {}
            Err(e) if log_refusal(e) && self.others_to_ask(row, friend, now) => {
                // What this friend's log says, not the release's own bytes:
                // its copy is bad, and another friend's log may list it.
                update_state::note_bundle_refusal(e, origin);
                bad_copy("log", snapshot_bytes);
                return None;
            }
            Err(e) if log_refusal(e) => {
                // No log lists it (this friend's, nor the stored one), and
                // no other friend that offered it is left to ask: not used
                // now. That says nothing against the release's own bytes
                // (its log may be newer than any seen here): this friend's
                // copy is held back like a bad one, and the row waits for
                // a log that lists it ([`Node::revive_not_logged`]; Phase 6
                // review re-verify, updates-protocol-6).
                update_state::note_bundle_refusal(e, origin);
                bad_copy("log", snapshot_bytes);
                self.fail(&digest, downloads::FAILED_NOT_LOGGED);
                return None;
            }
            Err(e) => {
                // The release itself is refused: any friend's copy is the
                // same bytes.
                update_state::note_bundle_refusal(e, origin);
                if e.sec_kind().is_some() {
                    quarantine(self.data_dir, "manifest", manifest_bytes, wall);
                }
                self.fail(&digest, e.code());
                return None;
            }
            Ok(()) => return None,
        }
        let Parts {
            manifest, snapshot, ..
        } = parts;
        let snapshot_bytes = snapshot.encode();
        // Here already, its log set aside (it no longer checked when every
        // chunk was in): the chunks kept, the log replaced.
        if let Some(existing) = Incoming::open(self.data_dir, &digest) {
            raven_core::paths::atomic_write_private(
                &existing.dir.join(INCOMING_SNAPSHOT),
                &snapshot_bytes,
            )
            .ok()?;
            return Some(existing);
        }
        prune_incoming(self.data_dir, wall, Some(&digest));
        if incoming_bytes(self.data_dir) + manifest.payload_len > MAX_INCOMING_BYTES {
            self.fail(&digest, downloads::FAILED_NO_ROOM);
            return None;
        }
        let incoming = Incoming::create(self.data_dir, &manifest, &snapshot_bytes).ok()?;
        let total = u32::try_from(manifest.chunk_count()).unwrap_or(u32::MAX);
        let version = manifest.version.clone();
        let _ = downloads::change(self.data_dir, |rows| {
            if let Some(r) = rows.row_mut(&digest) {
                r.state = RowState::Downloading;
                r.version = Some(version);
                // The verified manifest's, not the friend's claims (Phase 6
                // review updates-protocol-7).
                r.build_serial = manifest.build_serial;
                r.payload_len = manifest.payload_len;
                r.chunks_total = total;
                r.chunks_have = 0;
            }
        });
        Some(incoming)
    }

    /// A release no log listed when it was checked
    /// ([`downloads::FAILED_NOT_LOGGED`]) is approved again, as the person
    /// approved it, once the stored log lists it (a notice brought a newer
    /// one) or a pinned friend that offered it may be asked (another
    /// friend's offer, or a day after the one whose log did not list it):
    /// that log may list it.
    fn revive_not_logged(&self, state: &UpdateState, now: Instant) {
        let rows = downloads::load(self.data_dir).unwrap_or_default().rows;
        let revive: Vec<[u8; 32]> = rows
            .iter()
            .filter(|r| {
                r.state == RowState::Failed
                    && r.failed.as_deref() == Some(downloads::FAILED_NOT_LOGGED)
            })
            .filter(|r| {
                state.log().is_some_and(|log| lists_release(log, &r.digest)) || {
                    let askable: Vec<[u8; 32]> = {
                        let s = lock(self.shared);
                        r.from
                            .iter()
                            .filter(|f| !s.parked(f, now) && !s.bad_copy(f, &r.digest, now))
                            .copied()
                            .collect()
                    };
                    askable.iter().any(|f| pinned(self.data_dir, f))
                }
            })
            .map(|r| r.digest)
            .collect();
        if revive.is_empty() {
            return;
        }
        let _ = downloads::change(self.data_dir, |rows| {
            for digest in &revive {
                if let Some(r) = rows.row_mut(digest) {
                    r.state = RowState::Approved;
                    r.failed = None;
                }
            }
        });
    }

    /// Another friend that offered `row`'s release is still to be asked
    /// (none sent a bad copy of it lately): a refusal that depends on
    /// `friend`'s log may not hold for theirs.
    fn others_to_ask(&self, row: &Row, friend: &[u8; 32], now: Instant) -> bool {
        let others: Vec<[u8; 32]> = {
            let s = lock(self.shared);
            row.from
                .iter()
                .filter(|f| *f != friend && !s.bad_copy(f, &row.digest, now))
                .copied()
                .collect()
        };
        others.iter().any(|f| pinned(self.data_dir, f))
    }

    /// Every chunk is in: the whole release verified again, against the
    /// stored log when it lists the release (the newest this node holds),
    /// else against the log kept with it; complete, or failed with its
    /// pieces in quarantine (a payload refusal: `from`, the friend that sent
    /// the last chunk, is not asked for it again). A log no longer checks
    /// (a key rotation since, say) is no friend's fault: it is set aside,
    /// nothing is noted, and a fresh one comes with the manifest (Phase 6
    /// review updates-protocol-5). `true`: complete.
    fn finish(&self, from: Option<&[u8; 32]>, origin: Origin, inc: &Incoming, wall: u64) -> bool {
        let digest = inc.manifest.digest();
        let Some(state) = self.state() else {
            return false;
        };
        if state.frozen().is_some() {
            return false;
        }
        let Ok(payload) = inc.read_payload() else {
            return false;
        };
        let kept = read_capped(&inc.dir.join(INCOMING_SNAPSHOT), MAX_SNAPSHOT_LEN)
            .and_then(|bytes| Snapshot::decode(&bytes).ok());
        let stored = state
            .log()
            .filter(|log| lists_release(log, &digest))
            .cloned();
        let mut logs = stored.into_iter().chain(kept);
        let Some(first) = logs.next() else {
            let _ = std::fs::remove_file(inc.dir.join(INCOMING_SNAPSHOT));
            return false;
        };
        let mut parts = Parts {
            manifest: inc.manifest.clone(),
            snapshot: first,
            advisory: None,
            payload,
        };
        loop {
            let outcome = verify_bundle(&parts, &state.verify_ctx(false)).map(|_| ());
            match outcome {
                Ok(()) => {
                    let _ = raven_core::paths::atomic_write_private(
                        &inc.dir.join(INCOMING_VERIFIED),
                        b"",
                    );
                    let _ = downloads::change(self.data_dir, |rows| {
                        if let Some(r) = rows.row_mut(&digest) {
                            r.state = RowState::Complete;
                            r.chunks_have = r.chunks_total;
                        }
                    });
                    eprintln!(
                        "raven-node updates: a release from a friend is downloaded and checked"
                    );
                    return true;
                }
                Err(e) if log_refusal(e) => match logs.next() {
                    Some(next) => parts.snapshot = next,
                    None => break,
                },
                Err(e) => {
                    update_state::note_bundle_refusal(e, origin);
                    quarantine(self.data_dir, "payload", &parts.payload, wall);
                    let _ = std::fs::remove_dir_all(&inc.dir);
                    if let Some(friend) = from {
                        lock(self.shared)
                            .bad_copy
                            .insert((*friend, digest), Instant::now() + BAD_COPY_PARK);
                    }
                    self.fail(&digest, e.code());
                    return false;
                }
            }
        }
        // No log this node holds checks it now: a fresh one is asked for.
        let _ = std::fs::remove_file(inc.dir.join(INCOMING_SNAPSHOT));
        false
    }

    /// A wanted row whose chunks are all in but whose check did not finish
    /// (raven-node stopped before it did, or its log no longer checked):
    /// checked now, with no dial. `true`: complete.
    fn finish_pending(&self, row: &Row, wall: u64) -> bool {
        let Some(inc) = Incoming::open(self.data_dir, &row.digest) else {
            return false;
        };
        if !inc.complete() || !inc.has_log() {
            return false;
        }
        let origin = Origin {
            passed_by: row.offered_by().copied(),
            via: Via::Local,
        };
        self.finish(None, origin, &inc, wall)
    }

    fn fail(&self, digest: &[u8; 32], code: &str) {
        let _ = downloads::change(self.data_dir, |rows| {
            if let Some(r) = rows.row_mut(digest) {
                r.state = RowState::Failed;
                r.failed = Some(code.to_owned());
            }
        });
        let _ = std::fs::remove_dir_all(downloads::incoming_dir(self.data_dir, digest));
    }

    // ── Storage and status ──

    /// Remove downloads idle for 7 days and orphans, quarantine past 7 days,
    /// and the rows the installed build no longer needs.
    pub(crate) fn prune(&self, wall: u64) {
        prune_incoming(self.data_dir, wall, None);
        prune_quarantine(self.data_dir, wall, 0);
        let installed = self.state().map_or(0, |s| s.installed_serial());
        let dd = self.data_dir;
        let staged = staged_serials(dd);
        let _ = downloads::change(dd, |rows| {
            rows.forget_installed(installed);
            for r in rows.rows.iter_mut() {
                let dir = downloads::incoming_dir(dd, &r.digest);
                match r.state {
                    // A download whose folder went (idle, removed by hand)
                    // starts again; a complete one is gone.
                    RowState::Downloading if !dir.join(INCOMING_MANIFEST).exists() => {
                        r.state = RowState::Approved;
                        r.chunks_have = 0;
                    }
                    // A complete one whose folder went: staged when its build
                    // is (the CLI or the app staged it), else removed after
                    // 7 idle days, so offered again for the person to
                    // approve (it was neither staged nor downloaded).
                    RowState::Complete if !dir.join(INCOMING_VERIFIED).exists() => {
                        r.state = if staged.contains(&r.build_serial) {
                            RowState::Staged
                        } else {
                            RowState::Offered
                        };
                        r.chunks_have = 0;
                    }
                    _ => {}
                }
            }
            rows.rows
                .retain(|r| r.state != RowState::Staged || r.build_serial > installed);
        });
    }

    /// `Status.updates` (counts only).
    pub(crate) fn status(&self) -> Option<UpdateStatus> {
        let state = self.state()?;
        let rows = downloads::load(self.data_dir).unwrap_or_default().rows;
        let count = |f: &dyn Fn(&Row) -> bool| {
            u16::try_from(rows.iter().filter(|r| f(r)).count()).unwrap_or(u16::MAX)
        };
        let now = raven_core::clock::now_ms();
        Some(UpdateStatus {
            advisory_serial: state.newest().map_or(0, |n| n.0),
            advisory_age_days: state.advisory().map(|a| {
                u32::try_from(now.saturating_sub(a.issued_at_ms) / 86_400_000).unwrap_or(u32::MAX)
            }),
            log_size: state
                .log()
                .map_or(0, |l| u32::try_from(l.sth().tree_size).unwrap_or(0)),
            offers: count(&|r| r.state == RowState::Offered),
            downloading: count(&Row::wanted),
            ready: count(&|r| r.state == RowState::Complete),
            staged: u16::try_from(staged_serials(self.data_dir).len()).unwrap_or(u16::MAX),
            frozen: state.frozen().is_some(),
            quarantined: u32::try_from(quarantine_items(self.data_dir).len()).unwrap_or(u32::MAX),
        })
    }

    #[cfg(all(test, debug_assertions))]
    pub(crate) fn forged_counts(&self) -> (u32, u32) {
        let s = lock(self.shared);
        (s.forged_notices, s.forged_chunks)
    }
}

/// Which of `have`'s claims are newer than `state` (spec §7): an advisory
/// with a higher serial, or the same serial with another digest (that is
/// equivocation, and the update state freezes on it); a longer log, or one
/// as long with another root.
fn newer(state: &UpdateState, have: &Have) -> (bool, bool) {
    let (serial, digest) = state.newest().unwrap_or((0, [0; 32]));
    let adv = have.adv_serial > serial
        || (have.adv_serial == serial && serial > 0 && have.adv_digest != digest);
    let (size, root) = state.log().map_or((0, [0; 32]), |l| {
        (
            u32::try_from(l.sth().tree_size).unwrap_or(u32::MAX),
            l.sth().root_hash,
        )
    });
    let log = have.log_size > size || (have.log_size == size && size > 0 && have.log_root != root);
    (adv, log)
}

fn wants_notices(state: &UpdateState, have: &Have) -> bool {
    let (adv, log) = newer(state, have);
    adv || log
}

/// Does `log` list the release of manifest digest `digest`?
fn lists_release(log: &Snapshot, digest: &[u8; 32]) -> bool {
    raven_core::tlog::contains(log.entries(), EntryType::Manifest, digest)
}

/// A bundle refusal that depends on the log it was checked against, not on
/// the release's own bytes: another friend's log (or the stored one) may
/// check it.
fn log_refusal(e: BundleError) -> bool {
    matches!(
        e,
        BundleError::Unlogged
            | BundleError::Log(_)
            | BundleError::SplitView
            | BundleError::ManifestSig(SigError::WrongKeySet)
    )
}

/// SEC_ADVISORY_FORGED about the friend that passed on a notice under a key
/// set this node never trusted and could not explain it (the same event
/// the update state notes for a notice that fails its check, through the
/// same sink).
fn note_forged(origin: Origin) {
    crate::security::note(raven_core::security_events::SecEvent::new(
        raven_core::security_events::SecKind::AdvisoryForged,
        raven_core::security_events::Attribution::Update {
            passed_by: origin.passed_by,
        },
        origin.via,
        raven_core::clock::now_ms(),
    ));
}

/// The request for what `have` claims newer than `state`: the advisory
/// first (it comes with its log), else the log.
fn notice_request(state: &UpdateState, have: &Have) -> Option<Rup1Msg> {
    match newer(state, have) {
        (true, _) => Some(Rup1Msg::GetAdvisory),
        (false, true) => Some(Rup1Msg::GetLog),
        (false, false) => None,
    }
}

fn error(id: &[u8; 4], code: ErrorCode) -> Vec<Vec<u8>> {
    rup1::encode(id, &Rup1Msg::Error(code))
        .map(|f| vec![f])
        .unwrap_or_default()
}

// ── Releases this node holds ────────────────────────────────────────────────

/// Where a held release's payload is.
#[derive(Clone, Debug)]
enum Source {
    /// A staged build: its files back to back (`staged_file_name`).
    Staged(PathBuf),
    /// A complete download: its payload file.
    Incoming(PathBuf),
}

/// A release this node holds for its own platform, verified when it came
/// (an import, or a complete download).
#[derive(Clone, Debug)]
struct Held {
    manifest: Manifest,
    snapshot: Vec<u8>,
    source: Source,
}

impl Held {
    fn offer(&self) -> Offer {
        Offer {
            build_serial: self.manifest.build_serial,
            target: self.manifest.target.clone(),
            manifest_digest: self.manifest.digest(),
            payload_len: self.manifest.payload_len,
        }
    }

    /// `len` payload bytes from `offset`.
    fn read(&self, offset: u64, len: usize) -> std::io::Result<Vec<u8>> {
        match &self.source {
            Source::Incoming(dir) => read_at(&dir.join(INCOMING_PAYLOAD), offset, len),
            Source::Staged(dir) => {
                let mut out = Vec::with_capacity(len);
                let end = offset + len as u64;
                for (i, f) in self.manifest.files.iter().enumerate() {
                    let (start, stop) = (f.offset, f.offset + f.size);
                    if stop <= offset || start >= end {
                        continue;
                    }
                    let from = offset.max(start);
                    let to = end.min(stop);
                    let path = dir.join(update_state::staged_file_name(i, &f.path));
                    out.extend(read_at(&path, from - start, (to - from) as usize)?);
                }
                if out.len() != len {
                    return Err(std::io::Error::other("short release"));
                }
                Ok(out)
            }
        }
    }
}

fn read_at(path: &Path, offset: u64, len: usize) -> std::io::Result<Vec<u8>> {
    let mut file = std::fs::File::open(path)?;
    file.seek(SeekFrom::Start(offset))?;
    let mut out = vec![0u8; len];
    file.read_exact(&mut out)?;
    Ok(out)
}

fn read_capped(path: &Path, cap: usize) -> Option<Vec<u8>> {
    let file = std::fs::File::open(path).ok()?;
    let mut out = Vec::new();
    file.take(cap as u64 + 1).read_to_end(&mut out).ok()?;
    (out.len() <= cap).then_some(out)
}

/// The staged builds' serials (`updates/staged/<serial>/`).
fn staged_serials(data_dir: &Path) -> Vec<u64> {
    std::fs::read_dir(data_dir.join(STAGED_DIR))
        .map(|list| {
            list.flatten()
                .filter_map(|e| e.file_name().to_str()?.parse::<u64>().ok())
                .collect()
        })
        .unwrap_or_default()
}

/// Every release held for this platform, newest first, each digest once.
fn held(data_dir: &Path) -> Vec<Held> {
    let mut out: Vec<Held> = Vec::new();
    for serial in staged_serials(data_dir) {
        let dir = data_dir.join(STAGED_DIR).join(serial.to_string());
        let Some(manifest) = read_capped(&dir.join(STAGED_MANIFEST), MAX_MANIFEST_LEN)
            .and_then(|b| Manifest::decode(&b).ok())
        else {
            continue;
        };
        let Some(snapshot) = read_capped(&dir.join(STAGED_SNAPSHOT), MAX_SNAPSHOT_LEN) else {
            continue;
        };
        let complete = manifest.files.iter().enumerate().all(|(i, f)| {
            std::fs::metadata(dir.join(update_state::staged_file_name(i, &f.path)))
                .is_ok_and(|m| m.len() == f.size)
        });
        if manifest.build_serial == serial && complete {
            out.push(Held {
                manifest,
                snapshot,
                source: Source::Staged(dir),
            });
        }
    }
    if let Ok(list) = std::fs::read_dir(data_dir.join(INCOMING_DIR)) {
        for entry in list.flatten() {
            let dir = entry.path();
            if !dir.join(INCOMING_VERIFIED).exists() {
                continue;
            }
            let Some(manifest) = read_capped(&dir.join(INCOMING_MANIFEST), MAX_MANIFEST_LEN)
                .and_then(|b| Manifest::decode(&b).ok())
            else {
                continue;
            };
            let Some(snapshot) = read_capped(&dir.join(INCOMING_SNAPSHOT), MAX_SNAPSHOT_LEN) else {
                continue;
            };
            let sized = std::fs::metadata(dir.join(INCOMING_PAYLOAD))
                .is_ok_and(|m| m.len() == manifest.payload_len);
            if sized && entry.file_name().to_str() == Some(&hex::encode(manifest.digest())) {
                out.push(Held {
                    manifest,
                    snapshot,
                    source: Source::Incoming(dir),
                });
            }
        }
    }
    out.retain(|h| h.manifest.target == raven_core::release_bundle::THIS_TARGET);
    out.sort_by_key(|h| std::cmp::Reverse(h.manifest.build_serial));
    let mut seen = Vec::new();
    out.retain(|h| {
        let d = h.manifest.digest();
        let new = !seen.contains(&d);
        seen.push(d);
        new
    });
    out
}

fn find_held(data_dir: &Path, digest: &[u8; 32]) -> Option<Held> {
    held(data_dir)
        .into_iter()
        .find(|h| h.manifest.digest() == *digest)
}

// ── A download on disk ──────────────────────────────────────────────────────

/// `updates/incoming/<digest>/`: the verified manifest, its log snapshot,
/// the payload as it arrives and the chunk bitmap.
struct Incoming {
    dir: PathBuf,
    manifest: Manifest,
    bitmap: Vec<u8>,
    payload: Option<std::fs::File>,
    dirty: bool,
}

impl Incoming {
    fn open(data_dir: &Path, digest: &[u8; 32]) -> Option<Self> {
        let dir = downloads::incoming_dir(data_dir, digest);
        let manifest = read_capped(&dir.join(INCOMING_MANIFEST), MAX_MANIFEST_LEN)
            .and_then(|b| Manifest::decode(&b).ok())
            .filter(|m| m.digest() == *digest)?;
        let len = downloads::bitmap_len(manifest.chunk_count());
        let bitmap = read_capped(&dir.join(INCOMING_CHUNKS), len)
            .filter(|b| b.len() == len)
            .unwrap_or_else(|| vec![0; len]);
        Some(Self {
            dir,
            manifest,
            bitmap,
            payload: None,
            dirty: false,
        })
    }

    fn create(data_dir: &Path, manifest: &Manifest, snapshot: &[u8]) -> Result<Self, String> {
        let dir = downloads::incoming_dir(data_dir, &manifest.digest());
        raven_core::paths::ensure_private_dir(&dir)?;
        raven_core::paths::atomic_write_private(&dir.join(INCOMING_SNAPSHOT), snapshot)?;
        let file = open_private(&dir.join(INCOMING_PAYLOAD)).map_err(|e| e.to_string())?;
        file.set_len(manifest.payload_len)
            .map_err(|e| e.to_string())?;
        let bitmap = vec![0; downloads::bitmap_len(manifest.chunk_count())];
        raven_core::paths::atomic_write_private(&dir.join(INCOMING_CHUNKS), &bitmap)?;
        // The manifest last: a folder without it is no download yet.
        raven_core::paths::atomic_write_private(&dir.join(INCOMING_MANIFEST), manifest.bytes())?;
        Ok(Self {
            dir,
            manifest: manifest.clone(),
            bitmap,
            payload: Some(file),
            dirty: false,
        })
    }

    /// Its log is there (it is set aside when it no longer checks).
    fn has_log(&self) -> bool {
        self.dir.join(INCOMING_SNAPSHOT).exists()
    }

    fn written(&self, index: u32) -> bool {
        downloads::chunk_written(&self.bitmap, u64::from(index))
    }

    fn count(&self) -> u32 {
        self.bitmap.iter().map(|b| b.count_ones()).sum()
    }

    fn complete(&self) -> bool {
        u64::from(self.count()) == self.manifest.chunk_count()
    }

    /// Runs of missing chunks, `(first, count)`: at most `per_dial` chunks
    /// in runs of at most `per_request`, the first missing ones first.
    fn missing_runs(&self, per_dial: usize, per_request: u8) -> Vec<(u32, u8)> {
        let max_runs = per_dial.div_ceil(usize::from(per_request));
        let mut runs: Vec<(u32, u8)> = Vec::new();
        let mut left = per_dial;
        for index in 0..self.manifest.chunk_count() {
            if left == 0 {
                break;
            }
            if downloads::chunk_written(&self.bitmap, index) {
                continue;
            }
            let index = index as u32;
            let extends = runs.last().is_some_and(|(first, count)| {
                first + u32::from(*count) == index && *count < per_request
            });
            if extends {
                if let Some(run) = runs.last_mut() {
                    run.1 += 1;
                }
            } else if runs.len() < max_runs {
                runs.push((index, 1));
            } else {
                break;
            }
            left -= 1;
        }
        runs
    }

    /// Write a checked chunk at its offset and mark it.
    fn write(&mut self, index: u32, bytes: &[u8]) -> std::io::Result<()> {
        if self.payload.is_none() {
            let file = std::fs::OpenOptions::new()
                .write(true)
                .open(self.dir.join(INCOMING_PAYLOAD))?;
            self.payload = Some(file);
        }
        let file = self.payload.as_mut().expect("opened above");
        file.seek(SeekFrom::Start(u64::from(index) * u64::from(CHUNK_SIZE)))?;
        file.write_all(bytes)?;
        downloads::mark_chunk(&mut self.bitmap, u64::from(index));
        self.dirty = true;
        Ok(())
    }

    /// The payload synced first, then the bitmap that names it.
    fn flush(&mut self) -> Result<(), String> {
        if !self.dirty {
            return Ok(());
        }
        if let Some(file) = &self.payload {
            file.sync_data().map_err(|e| e.to_string())?;
        }
        raven_core::paths::atomic_write_private(&self.dir.join(INCOMING_CHUNKS), &self.bitmap)?;
        self.dirty = false;
        Ok(())
    }

    fn read_payload(&self) -> std::io::Result<Vec<u8>> {
        let len = usize::try_from(self.manifest.payload_len).unwrap_or(usize::MAX);
        read_at(&self.dir.join(INCOMING_PAYLOAD), 0, len)
    }
}

/// A new file, owner only.
fn open_private(path: &Path) -> std::io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// Payload bytes the downloads in `incoming/` hold.
fn incoming_bytes(data_dir: &Path) -> u64 {
    std::fs::read_dir(data_dir.join(INCOMING_DIR))
        .map(|list| {
            list.flatten()
                .filter_map(|e| std::fs::metadata(e.path().join(INCOMING_PAYLOAD)).ok())
                .map(|m| m.len())
                .sum()
        })
        .unwrap_or(0)
}

/// When a download's folder last changed (its newest file), Unix ms.
fn touched_ms(dir: &Path) -> u64 {
    let newest = std::fs::read_dir(dir)
        .map(|list| {
            list.flatten()
                .filter_map(|e| e.metadata().ok()?.modified().ok())
                .max()
        })
        .ok()
        .flatten();
    newest
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_millis() as u64)
}

/// Remove downloads untouched for 7 days, and folders no row names once an
/// hour old (`keep`: never this one).
fn prune_incoming(data_dir: &Path, wall: u64, keep: Option<&[u8; 32]>) {
    let Ok(list) = std::fs::read_dir(data_dir.join(INCOMING_DIR)) else {
        return;
    };
    let rows = downloads::load(data_dir).ok();
    for entry in list.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if keep.is_some_and(|k| hex::encode(k) == name) {
            continue;
        }
        let age = wall.saturating_sub(touched_ms(&entry.path()));
        let rowed = rows
            .as_ref()
            .is_none_or(|r| r.rows.iter().any(|row| hex::encode(row.digest) == name));
        if age >= INCOMING_IDLE_MS || (!rowed && age >= ORPHAN_AGE_MS) {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

// ── Quarantine ──────────────────────────────────────────────────────────────

/// What quarantine holds: (path, written at Unix ms, bytes), oldest first.
fn quarantine_items(data_dir: &Path) -> Vec<(PathBuf, u64, u64)> {
    let mut items: Vec<(PathBuf, u64, u64)> = std::fs::read_dir(data_dir.join(QUARANTINE_DIR))
        .map(|list| {
            list.flatten()
                .filter_map(|e| {
                    let at = e.file_name().to_str()?.split('-').next()?.parse().ok()?;
                    Some((e.path(), at, e.metadata().ok()?.len()))
                })
                .collect()
        })
        .unwrap_or_default();
    items.sort_by_key(|i| i.1);
    items
}

/// Remove what is past 7 days, then the oldest until `room` more bytes fit
/// [`MAX_QUARANTINE_BYTES`].
fn prune_quarantine(data_dir: &Path, wall: u64, room: u64) {
    let mut total = 0;
    let mut kept = Vec::new();
    for (path, at, len) in quarantine_items(data_dir) {
        if wall.saturating_sub(at) >= QUARANTINE_AGE_MS {
            let _ = std::fs::remove_file(&path);
        } else {
            total += len;
            kept.push((path, len));
        }
    }
    for (path, len) in kept {
        if total + room <= MAX_QUARANTINE_BYTES {
            break;
        }
        let _ = std::fs::remove_file(&path);
        total -= len;
    }
}

/// Keep what failed its checks: `<ms>-<what>-<random>`, never the friend's
/// name, never run or shown. Nothing larger than the whole quarantine.
fn quarantine(data_dir: &Path, what: &str, bytes: &[u8], wall: u64) -> bool {
    let len = bytes.len() as u64;
    if len > MAX_QUARANTINE_BYTES {
        return false;
    }
    prune_quarantine(data_dir, wall, len);
    let path = data_dir.join(QUARANTINE_DIR).join(format!(
        "{wall}-{what}-{}",
        hex::encode(rand::random::<[u8; 4]>())
    ));
    raven_core::paths::atomic_write_private(&path, bytes).is_ok()
}

// ── One link ────────────────────────────────────────────────────────────────

/// The update exchange on one link (spec §2.2): our HAVE when it is due, the
/// peer's HAVE taken once, and on the listener its requests answered. Held
/// by the link's `crate::hints::LinkCtl` ([`crate::hints::LinkCtl::with_update`]).
#[derive(Debug)]
pub(crate) struct UpdateLink {
    /// This side runs the exchange on this link (it offered bit 10).
    live: bool,
    data_dir: PathBuf,
    build: Option<Build>,
    peer: [u8; 32],
    carrier: OutboxCarrier,
    listener: bool,
    /// The peer speaks RUP1 here: its hello's bit 10 (Internet direct, p2p,
    /// nearby), its message 3's (a LAN listener), its HAVE (a LAN dialer).
    peer_speaks: bool,
    sent: bool,
    received: u8,
}

impl UpdateLink {
    /// No exchange on this link (the gate shut, a test).
    pub(crate) fn off() -> Self {
        Self {
            live: false,
            data_dir: PathBuf::new(),
            build: None,
            peer: [0; 32],
            carrier: OutboxCarrier::Lan,
            listener: false,
            peer_speaks: false,
            sent: false,
            received: 0,
        }
    }

    fn on(data_dir: &Path, peer: [u8; 32], carrier: OutboxCarrier, listener: bool) -> Self {
        let build = build();
        Self {
            live: rup1::notices_live() && build.key_set.is_some(),
            data_dir: data_dir.to_path_buf(),
            build: Some(build),
            peer,
            carrier,
            listener,
            ..Self::off()
        }
    }

    /// The LAN listener of a dialer whose message 3 payload was `m3`.
    pub(crate) fn lan_listener(data_dir: &Path, peer: [u8; 32], m3: &[u8]) -> Self {
        Self {
            peer_speaks: raven_core::route_hints::rlx1_caps(m3) & CAP_LINK_RUP1 != 0,
            ..Self::on(data_dir, peer, OutboxCarrier::Lan, true)
        }
    }

    /// A LAN dial whose message 3 offered bit 10 (`asked`); the listener
    /// says it speaks RUP1 with its HAVE.
    pub(crate) fn lan_dialer(data_dir: &Path, peer: [u8; 32], asked: bool) -> Self {
        let mut link = Self::on(data_dir, peer, OutboxCarrier::Lan, false);
        link.live &= asked;
        link
    }

    /// Internet direct, p2p or nearby (`carrier`): `ours`, our hello set bit
    /// 10; `peer_caps`, the peer's verified hello caps.
    pub(crate) fn inet(
        data_dir: &Path,
        carrier: OutboxCarrier,
        listener: bool,
        peer: [u8; 32],
        ours: bool,
        peer_caps: u32,
    ) -> Self {
        let mut link = Self::on(data_dir, peer, carrier, listener);
        link.live &= ours;
        link.peer_speaks = peer_caps & CAP_LINK_RUP1 != 0;
        link
    }

    /// Our HAVE, once, when it is due (spec §2.2): a listener's when the
    /// dialer offered bit 10, an Internet, p2p or nearby dialer's when the
    /// listener's hello did, a LAN dialer's after the listener's HAVE. Only
    /// to a pinned contact.
    pub(crate) async fn outgoing(&mut self) -> Option<Vec<u8>> {
        let due = if self.listener || self.carrier != OutboxCarrier::Lan {
            self.peer_speaks
        } else {
            self.received > 0
        };
        if !self.live || self.sent || !due {
            return None;
        }
        self.sent = true;
        let (data_dir, build, peer, carrier) = (
            self.data_dir.clone(),
            self.build.clone()?,
            self.peer,
            self.carrier,
        );
        blocking(move || Node::new(&data_dir, &build, shared()).have_frame(&peer, carrier))
            .await
            .flatten()
    }

    /// May a dialer ask for anything here: does the peer speak RUP1 on this
    /// link as far as it knows (its hello; on LAN, once its HAVE came)?
    pub(crate) fn may_ask(&self) -> bool {
        self.live
            && !self.listener
            && (self.received > 0 || self.carrier != OutboxCarrier::Lan)
            && self.peer_speaks
    }

    /// Should a dialer wait for the listener's HAVE before it closes or
    /// asks: it offered bit 10 and none came yet (an Internet, p2p or
    /// nearby listener only when its hello set bit 10).
    pub(crate) fn expects_have(&self) -> bool {
        self.live
            && !self.listener
            && self.received == 0
            && (self.carrier == OutboxCarrier::Lan || self.peer_speaks)
    }

    /// The peer's HAVE: counted, and taken only the first time (one each
    /// way per link); a fetch it wants wakes the task.
    async fn take_have(&mut self, have: Have) {
        self.received = self.received.saturating_add(1);
        if self.received != 1 {
            return;
        }
        let Some(build) = self.build.clone() else {
            return;
        };
        let (data_dir, peer) = (self.data_dir.clone(), self.peer);
        let work = blocking(move || {
            Node::new(&data_dir, &build, shared()).take_have(&peer, have, Instant::now())
        })
        .await
        .unwrap_or(false);
        if work {
            kick();
        }
    }

    /// A dialer's frame: `None` when it is not this exchange's (a reply goes
    /// to the dial's collector); `Some(our HAVE to write, if now due)` for
    /// the listener's HAVE, taken once (one that breaks the rules is
    /// ignored). A dialer never answers anything else.
    pub(crate) async fn dialer_take(&mut self, frame: &[u8]) -> Option<Option<Vec<u8>>> {
        if !self.live || self.listener || !rup1::is_rup1(frame) {
            return None;
        }
        if frame.len() < rup1::HEADER_LEN || frame[5] != rup1::OP_HAVE {
            return None;
        }
        if let Ok((_, Rup1Msg::Have(have))) = rup1::decode(frame) {
            self.peer_speaks = true;
            self.take_have(have).await;
        }
        Some(self.outgoing().await)
    }

    /// A listener's frame: `None` when it is not this exchange's (dispatch
    /// it as before); the replies to write otherwise (spec §6: the dialer's
    /// HAVE taken once, requests served, refusals answered).
    pub(crate) async fn listener_take(&mut self, frame: &[u8]) -> Option<Vec<Vec<u8>>> {
        if !self.live || !self.listener || !rup1::is_rup1(frame) {
            return None;
        }
        if let ListenerDecode::Have(have) = rup1::decode_for_listener(frame) {
            self.take_have(have).await;
            return Some(Vec::new());
        }
        let (data_dir, build, peer, carrier, frame) = (
            self.data_dir.clone(),
            self.build.clone()?,
            self.peer,
            self.carrier,
            frame.to_vec(),
        );
        let (replies, _) = blocking(move || {
            Node::new(&data_dir, &build, shared()).listener_frame(
                &peer,
                carrier,
                &frame,
                false,
                Instant::now(),
            )
        })
        .await
        .unwrap_or_default();
        Some(replies)
    }
}

/// The link carries this exchange's feature: our hello's (or RLX1's) bit
/// 10 while the exchange is [`active`] (`crate::link::offers`).
pub(crate) fn offered() -> bool {
    active()
}

/// A follow-up dial may carry `frames` to this listener: RUP1 requests only
/// once it showed it speaks RUP1 ([`UpdateLink::may_ask`]); anything else
/// as before. `Err`: nothing may be sent.
pub(crate) fn check_requests(frames: &[Vec<u8>], link: &UpdateLink) -> Result<(), String> {
    if frames.iter().any(|f| rup1::is_rup1(f)) && !link.may_ask() {
        return Err(NOT_SPOKEN.into());
    }
    Ok(())
}

/// A follow-up dial reached a contact whose Raven does not take updates on
/// this link (no bit 10, no HAVE, or not pinned there): nothing was asked.
pub(crate) const NOT_SPOKEN: &str = "UPDATE_EXCHANGE_NOT_OFFERED: this contact's Raven does not \
     pass updates on this link; nothing was asked";

// ── The task ────────────────────────────────────────────────────────────────

/// One follow-up dial to `peer` from the blocking pool: its routes as the
/// outbox worker plans them (`crate::hints::announce_routes`), tried in
/// order, Bluetooth skipped for a release, each with the follow-up reply
/// budget and [`DIAL_DEADLINE`].
fn dial_peer(
    handle: &tokio::runtime::Handle,
    data_dir: &Path,
    peer: &[u8; 32],
    frames: &[Vec<u8>],
    bundle: bool,
) -> Result<(Vec<Vec<u8>>, OutboxCarrier), String> {
    let ctx = crate::outbox::attempt_ctx().ok_or("no outbox worker: no route plan")?;
    let routes = crate::hints::announce_routes(&ctx, peer, raven_core::clock::now_ms());
    let pub_hex = hex::encode(peer);
    let mut last = Err("no route to this contact".to_string());
    for (_, route) in routes {
        if bundle && route.carrier == OutboxCarrier::Nearby {
            continue;
        }
        let work = async {
            match route.carrier {
                OutboxCarrier::Lan => {
                    crate::lan_direct::dial(data_dir, &route.dial, &pub_hex, frames).await
                }
                OutboxCarrier::Internet => {
                    crate::internet_direct::dial(data_dir, &route.dial, &pub_hex, frames).await
                }
                OutboxCarrier::P2p => {
                    crate::p2p::dial_with_path(data_dir, &route.dial, &pub_hex, frames)
                        .await
                        .map(|(replies, _)| replies)
                }
                OutboxCarrier::Nearby => {
                    crate::nearby::dial(data_dir, &route.dial, &pub_hex, frames).await
                }
                OutboxCarrier::Onion => {
                    crate::onion::dial_with_meta(
                        data_dir,
                        &route.dial,
                        &pub_hex,
                        frames,
                        crate::learning::DialMeta::default(),
                    )
                    .await
                }
            }
        };
        let got = handle.block_on(crate::netutil::INTERNAL_REPLY_BUDGET.scope(
            DIAL_REPLY_BUDGET,
            async {
                tokio::time::timeout(DIAL_DEADLINE, work)
                    .await
                    .unwrap_or_else(|_| Err("update dial deadline".into()))
            },
        ));
        match got {
            Ok(replies) => return Ok((replies, route.carrier)),
            Err(e) => last = Err(e),
        }
    }
    last
}

/// The exchange task (`raven-node service`, supervised): idle while the
/// exchange is not [`active`]; otherwise a pass ([`Node::pass`]) after every
/// kick (a HAVE with work, an approval) and every minute, every 2 s while a
/// download goes on.
pub(crate) async fn run(data_dir: PathBuf) -> Result<(), String> {
    loop {
        let wait = if active() {
            let dd = data_dir.clone();
            let handle = tokio::runtime::Handle::current();
            let report = blocking(move || {
                let build = build();
                let node = Node::new(&dd, &build, shared());
                let mut dial = |peer: &[u8; 32], frames: &[Vec<u8>], bundle: bool| {
                    dial_peer(&handle, &dd, peer, frames, bundle)
                };
                node.pass(Instant::now(), &mut dial)
            })
            .await
            .unwrap_or_default();
            if report.notices > 0 || report.completed > 0 {
                // Counts only.
                eprintln!(
                    "raven-node updates: {} notice(s) taken, {} release(s) downloaded",
                    report.notices, report.completed
                );
            }
            if report.busy {
                PASS_BUSY
            } else {
                PASS_INTERVAL
            }
        } else {
            PASS_INTERVAL
        };
        tokio::select! {
            _ = kicked().notified() => {}
            _ = tokio::time::sleep(wait) => {}
        }
    }
}

/// Did a HAVE of `peer`'s reach this process's exchange (the link tests)?
#[cfg(all(test, debug_assertions))]
pub(crate) fn have_seen_for_test(peer: &[u8; 32]) -> bool {
    lock(shared()).haves.contains_key(peer)
}

/// The update gates for the current thread (`Some(on)`) or back to the
/// variables (`None`): the link tests of `lan_direct` and `internet_direct`.
#[cfg(all(test, debug_assertions))]
pub(crate) fn gates_for_test(on: Option<bool>) {
    use raven_core::security_gate::SecGate;
    for g in [
        SecGate::Advisory,
        SecGate::ReleaseBundle,
        SecGate::MeshUpdate,
    ] {
        security_gate::set_lab_for_this_thread(g, on);
    }
}

/// A build that trusts the published test keys (debug builds), at serial 1.
#[cfg(all(test, debug_assertions))]
pub(crate) fn test_build() -> Build {
    Build {
        key_set: Some(raven_core::release_keys::test_keys::key_set()),
        serial: 1,
        floor: (0, [0; 32]),
    }
}

/// IPC `Status.updates` (counts only): `None` while the exchange is not
/// [`active`]. Blocking (reads the profile).
pub(crate) fn status(data_dir: &Path) -> Option<UpdateStatus> {
    if !active() {
        return None;
    }
    let build = build();
    Node::new(data_dir, &build, shared()).status()
}

#[cfg(test)]
mod tests;
