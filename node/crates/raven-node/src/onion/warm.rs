//! W1 (Tor speed, Stage A; speed design M1): warm links on the dialer side.
//!
//! A program's send over Tor is two dials today: a check without frames (a
//! link of 3 round trips r: the stream, Noise messages 1 and 2, message 3
//! with our hello against the friend's hello and offer) and the message's
//! own link (4r), 7r in all. With the warm gate open
//! ([`raven_core::onion_gate::onion_warm_live`], false in release builds) a
//! link is kept after a batch that left it clean, and the next batch to the
//! same friend rides it: the message then rides its check's link (a first
//! send costs 4r), and a send within [`WARM_IDLE`] of the last batch costs
//! 1r, its check answered from the kept link with the friend's offer and no
//! traffic.
//!
//! The friend's listener is unchanged: it reads frame after frame on one
//! link as it always did, within its own limits (30 s without a frame, a
//! lifetime of 180 s, 64 frames), which [`WARM_IDLE`], [`WARM_AGE`] and
//! [`WARM_FRAMES`] stay below.
//!
//! **What may be kept.** Only a link whose batch read every frame it
//! waited for: a check's, or one whose chat messages and PairInits each got
//! their terminal reply ([`rides_warm`],
//! [`crate::netutil::ReplyCollector::all_answered`]). A wait that ran out,
//! a close or a failed write leaves it spent
//! ([`crate::internet_direct::DialIo::spent`]): on the link's own stream a
//! read under its deadline can stop part way through a frame, and on a kept
//! link a reply still on its way would be taken for the next batch's. A kept
//! link is written and read by a task of its own ([`pipe`]; its reads go
//! through [`WarmHalves`], whole frames only), so waits run out on a
//! channel, and a frame with no batch on the link or a close closes it.
//!
//! **Pipelining** (speed design M8, under the warm gate): up to
//! [`PIPELINE_DEPTH`] batches ride one kept link at once. Its task writes
//! each batch's frames as the batch hands them over, behind the batches
//! before it, and gives the replies first in, first out: the listener
//! answers frame after frame, each reply before it reads the next frame, so
//! the oldest batch on the link gets the replies until its last terminal
//! one. A burst's messages are then each answered about one round trip
//! after they were written, not one round trip after the message before. A
//! batch that ends any other way (its wait ran out, the link closed, its
//! dial was cut) closes the link, and a batch behind it sees it closed and
//! goes again on a fresh link: no reply is taken for another batch's (and
//! the ACK check of `raven send` takes an ACK only for the message it
//! names).
//!
//! **Before every batch** the dial's own checks run again (the carrier is
//! live, the contact verified and allowed on Tor), and the friend's block
//! is checked against its cached offer; a keeper looks at every kept link
//! each [`SWEEP`] and closes those of a contact blocked, removed or no
//! longer verified, and all of them once the gate is shut (a security
//! notice holds it). [`flush`] closes all of them on a lock, a network
//! change, the end of a Tor helper's life and the embedded node's pause.
//!
//! **Hedges** (speed design M5; the hedge gate
//! [`raven_core::onion_gate::onion_hedge_live`], false in release builds):
//! the pool also says which connect flags a dial asks the helper for
//! ([`WarmPool::connect_flags`]): a hedge, or fresh first when the last
//! link to that onion service failed a moment ago ([`WarmPool::link_failed`]).
//! And a batch on a kept link with no reply after
//! max([`BATCH_HEDGE_FLOOR`], 3 x the link's last round trip) closes the
//! link and goes again on a fresh one, fresh first (the batch hedge,
//! [`ride`]): the friend answers a copy it holds as the same message, with
//! the same ACK.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use raven_core::OutboxCarrier;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

use crate::internet_direct::{self, LinkState, OpenLink, WarmHalves};
use crate::netutil::{DialProgress, ReplyWait, PEER_CLOSED};

/// A kept link carries the next batch only within this of its last one:
/// the listener ends a link after 30 s without a frame (its read deadline,
/// `internet_direct` `IO_TIMEOUT`).
pub(crate) const WARM_IDLE: Duration = Duration::from_secs(20);
/// ... and within this of the moment its dial began: the onion listener's
/// link lifetime of 180 s (`netutil::ONION_INBOUND`), less its first reply
/// wait of 30 s and 30 s of margin.
pub(crate) const WARM_AGE: Duration = Duration::from_secs(120);
/// ... and while it carried at most this many frames after the offers: the
/// listener's budget of 64 per link counts every frame, route hints too,
/// so 8 are left for our RRH1, our HAVE and RUP1.
pub(crate) const WARM_FRAMES: u32 = 56;
/// Links kept at once, one per friend: 4, or 2 on the embedded node (the
/// iPhone app).
pub(crate) const WARM_POOL: usize = if cfg!(feature = "embedded") { 2 } else { 4 };
/// How often the keeper looks at the kept links.
const SWEEP: Duration = Duration::from_secs(1);
/// Batches riding one kept link at once (speed design M8).
pub(crate) const PIPELINE_DEPTH: usize = 3;
/// The batch hedge's shortest wait (speed design M5): a kept link's batch
/// with no reply after max(this, 3 x the link's last round trip) goes again
/// on a fresh link. A healthy reply takes one onion round trip.
pub(crate) const BATCH_HEDGE_FLOOR: Duration = Duration::from_secs(2);

/// A pool's limits ([`LIMITS`]; tests scale them down).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Limits {
    pub(crate) idle: Duration,
    pub(crate) age: Duration,
    pub(crate) frames: u32,
    pub(crate) cap: usize,
    pub(crate) sweep: Duration,
    /// Batches riding one link at once ([`PIPELINE_DEPTH`]).
    pub(crate) depth: usize,
}

/// The process pool's limits.
pub(crate) const LIMITS: Limits = Limits {
    idle: WARM_IDLE,
    age: WARM_AGE,
    frames: WARM_FRAMES,
    cap: WARM_POOL,
    sweep: SWEEP,
    depth: PIPELINE_DEPTH,
};

/// A gate a pool follows.
pub(crate) enum Gate {
    /// A release gate: [`raven_core::onion_gate::onion_warm_live`],
    /// [`raven_core::onion_gate::onion_hedge_live`].
    Live(fn() -> bool),
    /// A test's own switch.
    #[cfg(test)]
    Switch(&'static std::sync::atomic::AtomicBool),
}

impl Gate {
    fn open(&self) -> bool {
        match self {
            Gate::Live(live) => live(),
            #[cfg(test)]
            Gate::Switch(on) => on.load(Ordering::SeqCst),
        }
    }
}

/// How many onion services a pool remembers a failed link to (fresh first,
/// [`WarmPool::link_failed`]); past it the oldest is forgotten.
const FAILED_KEPT: usize = 64;

/// Whose a kept link is: this profile's link to `contact`'s onion service
/// `hs_id`, through the helper life whose token is `token` (a new life
/// brings a new token, and the links of the old one went with it).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WarmKey {
    data_dir: PathBuf,
    contact: [u8; 32],
    hs_id: [u8; 32],
    token: [u8; super::proto::TOKEN_LEN],
}

impl WarmKey {
    pub(crate) fn new(
        data_dir: &Path,
        contact: [u8; 32],
        hs_id: [u8; 32],
        token: [u8; super::proto::TOKEN_LEN],
    ) -> Self {
        Self {
            data_dir: data_dir.to_path_buf(),
            contact,
            hs_id,
            token,
        }
    }

    /// The same friend of the same profile (whatever its onion service or
    /// helper life): one kept link each.
    fn same_friend(&self, other: &Self) -> bool {
        self.contact == other.contact && self.data_dir == other.data_dir
    }
}

/// A kept link: its own task ([`pipe`], which holds its halves and state)
/// and what its limits count.
pub(crate) struct WarmLink {
    id: u64,
    key: WarmKey,
    /// Batches for its task.
    jobs: mpsc::UnboundedSender<Job>,
    task: tokio::task::JoinHandle<()>,
    /// The contact's verified offer (every batch's replies start with it).
    offer: Vec<u8>,
    /// When the dial that opened it began.
    opened: Instant,
    /// When its last batch ended (a check answered from it is none).
    last_batch: Instant,
    /// Frames its batches carried after the offers (the listener counts
    /// them; the few route hints and HAVE its task writes fit in the
    /// listener's margin, [`WARM_FRAMES`]).
    written: u32,
    /// Batches riding it now ([`Lease`]).
    in_flight: usize,
    /// Its last batch's round trip, from its frames written to its replies
    /// (the batch hedge's wait).
    trip: Option<Duration>,
}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

impl WarmLink {
    /// `link` after its first batch, which wrote `written` frames and, with
    /// frames, took `trip` from them to its reply; `opened`: when its dial
    /// began. Its task starts now.
    pub(crate) fn new(
        key: WarmKey,
        link: OpenLink<super::HelperStream>,
        opened: Instant,
        written: u32,
        trip: Option<Duration>,
    ) -> Self {
        let (jobs, next) = mpsc::unbounded_channel();
        let offer = link.state.peer_offer.clone();
        let task = tokio::spawn(pipe(WarmHalves::split(link.stream), link.state, next));
        Self {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            key,
            jobs,
            task,
            offer,
            opened,
            last_batch: Instant::now(),
            written,
            in_flight: 0,
            trip,
        }
    }

    /// Its task runs: no frame came with no batch on it, it did not close,
    /// and no write failed.
    fn alive(&self) -> bool {
        !self.task.is_finished()
    }

    /// May one more batch of `more` frames ride it at `now`: within its
    /// limits and its depth.
    fn may_take(&self, limits: &Limits, now: Instant, more: usize) -> bool {
        let more = u32::try_from(more).unwrap_or(u32::MAX);
        self.alive()
            && self.in_flight < limits.depth
            && (self.in_flight > 0 || now.saturating_duration_since(self.last_batch) < limits.idle)
            && now.saturating_duration_since(self.opened) < limits.age
            && self.written.saturating_add(more) <= limits.frames
    }

    /// Worth keeping at `now`: batches ride it, or another may.
    fn worth_keeping(&self, limits: &Limits, now: Instant) -> bool {
        self.alive()
            && (self.in_flight > 0
                || (self.may_take(limits, now, 0) && self.written < limits.frames))
    }
}

impl Drop for WarmLink {
    fn drop(&mut self) {
        // Its task holds the halves: aborted, it closes the link, and every
        // batch still on it sees it closed.
        self.task.abort();
    }
}

/// Kept links, one per friend, and the keeper that looks at them; and the
/// onion services whose last link failed (speed design M5).
pub(crate) struct WarmPool {
    limits: Limits,
    /// The warm gate (W1).
    gate: Gate,
    /// The hedge gate (M5).
    hedge: Gate,
    inner: Mutex<Inner>,
}

struct Inner {
    links: Vec<WarmLink>,
    /// The keeper task while it runs: it ends once no link is kept, or with
    /// the runtime it ran on (the embedded node's pause stops that one).
    keeper: Option<tokio::task::JoinHandle<()>>,
    /// Onion services whose last link failed, and when (hedge gate only).
    failed: Vec<([u8; 32], Instant)>,
}

impl WarmPool {
    /// A pool with `limits`, the warm `gate` and the `hedge` gate.
    pub(crate) const fn new(limits: Limits, gate: Gate, hedge: Gate) -> Self {
        Self {
            limits,
            gate,
            hedge,
            inner: Mutex::new(Inner {
                links: Vec::new(),
                keeper: None,
                failed: Vec::new(),
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The pool's gate is open.
    pub(crate) fn live(&self) -> bool {
        self.gate.open()
    }

    /// The connect flags of a dial to the onion service `hs_id`
    /// ([`super::proto::encode_connect`], speed design M5): none while the
    /// hedge gate is shut, as before; with it open a hedge, or fresh first
    /// when a link to it failed within [`super::proto::GROUP_KEPT`] and none
    /// worked since ([`Self::link_failed`]).
    pub(crate) fn connect_flags(&self, hs_id: &[u8; 32]) -> u8 {
        use super::proto::{CONNECT_FRESH_FIRST, CONNECT_HEDGE, GROUP_KEPT};
        if !self.hedge.open() {
            return 0;
        }
        let now = Instant::now();
        let mut inner = self.lock();
        inner
            .failed
            .retain(|(_, at)| now.saturating_duration_since(*at) < GROUP_KEPT);
        if inner.failed.iter().any(|(id, _)| id == hs_id) {
            CONNECT_FRESH_FIRST | CONNECT_HEDGE
        } else {
            CONNECT_HEDGE
        }
    }

    /// A link to `hs_id` failed where the helper cannot see it (no link, a
    /// batch left unanswered, a kept link dead): its next connect goes fresh
    /// first, in a new isolation group (W4). Nothing is noted while the
    /// hedge gate is shut.
    pub(crate) fn link_failed(&self, hs_id: [u8; 32]) {
        if !self.hedge.open() {
            return;
        }
        let mut inner = self.lock();
        inner.failed.retain(|(id, _)| *id != hs_id);
        if inner.failed.len() >= FAILED_KEPT {
            inner.failed.remove(0);
        }
        inner.failed.push((hs_id, Instant::now()));
    }

    /// A link to `hs_id` worked: its next connect goes in its friend's
    /// group again.
    pub(crate) fn link_worked(&self, hs_id: &[u8; 32]) {
        self.lock().failed.retain(|(id, _)| id != hs_id);
    }

    /// A share of `key`'s kept link for a batch of `more` frames, when one
    /// more may ride it now ([`Lease`]; the link stays in the pool). `None`:
    /// none is kept, or it takes no batch now: busy with
    /// [`Limits::depth`] of them, or past its limits (then it closes once no
    /// batch rides it). With the gate shut every link closes.
    pub(crate) fn checkout(&'static self, key: &WarmKey, more: usize) -> Option<Lease> {
        if !self.live() {
            self.flush();
            return None;
        }
        let now = Instant::now();
        let (lease, closed) = {
            let mut inner = self.lock();
            let at = inner.links.iter().position(|l| l.key == *key)?;
            let link = &mut inner.links[at];
            if link.may_take(&self.limits, now, more) {
                link.in_flight += 1;
                link.written = link
                    .written
                    .saturating_add(u32::try_from(more).unwrap_or(u32::MAX));
                let lease = Lease {
                    pool: self,
                    id: link.id,
                    data_dir: link.key.data_dir.clone(),
                    jobs: link.jobs.clone(),
                    offer: link.offer.clone(),
                    trip: link.trip,
                    ended: false,
                };
                (Some(lease), None)
            } else if link.in_flight > 0 && link.alive() {
                (None, None)
            } else {
                (None, Some(inner.links.swap_remove(at)))
            }
        };
        drop(closed);
        lease
    }

    /// A batch on the link `id` ended ([`Lease::end`]): a check, or one
    /// with every reply it waited for, leaves the link for the next one
    /// (unless it carried its frames and no batch rides it any more); any
    /// other end closes it, and every batch still on it sees it closed. A
    /// check put nothing on the link: its last batch stays the one before.
    fn end(&self, id: u64, how: Ended) {
        let closed = {
            let mut inner = self.lock();
            let Some(at) = inner.links.iter().position(|l| l.id == id) else {
                return;
            };
            let link = &mut inner.links[at];
            link.in_flight = link.in_flight.saturating_sub(1);
            if let Ended::Clean { trip } = how {
                link.last_batch = Instant::now();
                link.trip = Some(trip);
            }
            let keep = !matches!(how, Ended::Broken)
                && (link.written < self.limits.frames || link.in_flight > 0);
            (!keep).then(|| inner.links.swap_remove(at))
        };
        drop(closed);
    }

    /// Keep `link` for its friend's next batches: an older link of the same
    /// friend closes (unless batches ride it: then this one is not kept),
    /// and past the cap so does the one no batch rides whose last batch is
    /// oldest. Nothing is kept while the gate is shut, nor a link that
    /// carried its frames.
    pub(crate) fn checkin(&'static self, link: WarmLink) {
        if !self.live() || link.written >= self.limits.frames {
            return;
        }
        let mut closed = Vec::new();
        {
            let mut inner = self.lock();
            let busy = inner
                .links
                .iter()
                .any(|l| l.key.same_friend(&link.key) && l.in_flight > 0 && l.alive());
            if busy {
                closed.push(link);
            } else {
                let mut at = 0;
                while at < inner.links.len() {
                    if inner.links[at].key.same_friend(&link.key) {
                        closed.push(inner.links.swap_remove(at));
                    } else {
                        at += 1;
                    }
                }
                inner.links.push(link);
                while inner.links.len() > self.limits.cap {
                    let Some(oldest) = (0..inner.links.len())
                        .filter(|&i| inner.links[i].in_flight == 0)
                        .min_by_key(|&i| inner.links[i].last_batch)
                    else {
                        break;
                    };
                    closed.push(inner.links.swap_remove(oldest));
                }
                self.ensure_keeper(&mut inner);
            }
        }
        drop(closed);
    }

    /// Starts the keeper unless one runs (one that ended with its runtime
    /// does not). `true`: it started one.
    fn ensure_keeper(&'static self, inner: &mut Inner) -> bool {
        if inner.keeper.as_ref().is_some_and(|k| !k.is_finished()) {
            return false;
        }
        inner.keeper = Some(tokio::spawn(self.keep()));
        true
    }

    /// Close every kept link.
    pub(crate) fn flush(&self) {
        let closed = std::mem::take(&mut self.lock().links);
        drop(closed);
    }

    /// How many links are kept.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.lock().links.len()
    }

    /// The keeper: a sweep every `sweep` while any link is kept.
    async fn keep(&'static self) {
        loop {
            tokio::time::sleep(self.limits.sweep).await;
            if !self.sweep().await {
                return;
            }
        }
    }

    /// Close what may carry no batch now: every link while the gate is
    /// shut; one no batch rides that is idle, old or full, one whose task
    /// ended (a frame with no batch on it, a close), and one whose friend is
    /// blocked, removed or no longer verified (an unreadable store closes it
    /// too, batches on it or not). `false` once no link is kept: the keeper
    /// ends.
    async fn sweep(&'static self) -> bool {
        if !self.live() {
            self.flush();
        }
        let now = Instant::now();
        let (stale, look) = {
            let mut inner = self.lock();
            let mut stale = Vec::new();
            let mut at = 0;
            while at < inner.links.len() {
                if inner.links[at].worth_keeping(&self.limits, now) {
                    at += 1;
                } else {
                    stale.push(inner.links.swap_remove(at));
                }
            }
            let look: Vec<_> = inner
                .links
                .iter()
                .map(|l| {
                    let k = &l.key;
                    (l.id, k.data_dir.clone(), k.contact, l.offer.clone())
                })
                .collect();
            (stale, look)
        };
        drop(stale);
        if !look.is_empty() {
            let ids: Vec<u64> = look.iter().map(|(id, ..)| *id).collect();
            let gone = tokio::task::spawn_blocking(move || {
                look.into_iter()
                    .filter(|(_, dd, contact, offer)| !friend_still_ok(dd, contact, offer))
                    .map(|(id, ..)| id)
                    .collect::<Vec<u64>>()
            })
            .await
            .unwrap_or(ids);
            if !gone.is_empty() {
                let closed = {
                    let mut inner = self.lock();
                    let (closed, kept): (Vec<WarmLink>, Vec<WarmLink>) =
                        std::mem::take(&mut inner.links)
                            .into_iter()
                            .partition(|l| gone.contains(&l.id));
                    inner.links = kept;
                    closed
                };
                drop(closed);
            }
        }
        let mut inner = self.lock();
        if inner.links.is_empty() {
            inner.keeper = None;
            return false;
        }
        true
    }
}

/// Blocking: may this profile still send `contact` anything over Tor: a
/// verified contact (fingerprint pinned), blocked neither by its key nor
/// by its cached offer's. An unreadable store says no.
fn friend_still_ok(data_dir: &Path, contact: &[u8; 32], offer: &[u8]) -> bool {
    let pinned = raven_core::contact_is_pinned(data_dir, contact).unwrap_or(false);
    raven_core::carrier_allowed_for_contact(OutboxCarrier::Onion, pinned)
        && !blocked(data_dir, contact, offer).unwrap_or(true)
}

/// Blocking: is `contact` blocked, by its key or its cached offer's?
fn blocked(data_dir: &Path, contact: &[u8; 32], offer: &[u8]) -> Result<bool, String> {
    let peer = raven_core::lan_dispatch::parse_peer_offer(offer)?;
    raven_core::lan_dispatch::lan_peer_blocked(data_dir, &peer, contact)
}

/// The process's kept links: the sends programs make over Tor
/// (`crate::ipc_server`, [`crate::onion::dial_with_meta`]).
pub(crate) static WARM: WarmPool = WarmPool::new(
    LIMITS,
    Gate::Live(raven_core::onion_gate::onion_warm_live),
    Gate::Live(raven_core::onion_gate::onion_hedge_live),
);

/// Why every kept link closes ([`flush`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Flush {
    /// raven-node locks (`crate::lock`).
    Lock,
    /// This computer's network changed or it woke ([`super::network_changed`]).
    NetworkChanged,
    /// A Tor helper's life ended, or the onion task did.
    TorEnded,
    /// The embedded node pauses (`crate::embedded`).
    #[cfg_attr(not(all(unix, feature = "embedded")), allow(dead_code))]
    Pause,
}

#[cfg(test)]
static FLUSHES: [std::sync::atomic::AtomicU32; 4] =
    [const { std::sync::atomic::AtomicU32::new(0) }; 4];

/// Close every link of the process's pool ([`WARM`]).
pub(crate) fn flush(why: Flush) {
    #[cfg(test)]
    FLUSHES[why as usize].fetch_add(1, Ordering::SeqCst);
    let _ = why;
    WARM.flush();
}

/// How often [`flush`] ran for `why` in this process.
#[cfg(test)]
pub(crate) fn flushes_for_test(why: Flush) -> u32 {
    FLUSHES[why as usize].load(Ordering::SeqCst)
}

/// May a batch of `frames` ride a kept link, or leave its link kept: none
/// (a send's check), or chat messages and PairInits only, each answered by
/// one terminal reply at most (its ACK, its PairResponse). Anything else
/// (our ACKs, a session reset, custody, the update exchange) goes on a link
/// of its own, as before.
pub(crate) fn rides_warm(frames: &[Vec<u8>]) -> bool {
    use raven_core::envelope::{EnvType, Envelope};
    use raven_core::PairInitOobClassify;
    frames.iter().all(|f| {
        if raven_core::session_reset::is_rsr1(f)
            || raven_core::friend_custody::is_rfc1(f)
            || raven_core::update_exchange::is_rup1(f)
        {
            return false;
        }
        match raven_core::classify_packed_envelope(f) {
            PairInitOobClassify::PairInit(_) => true,
            PairInitOobClassify::PairResponse(_) => false,
            PairInitOobClassify::NotPairInitOob => {
                Envelope::unpack(f).is_some_and(|e| e.env_type == EnvType::Message as u8)
            }
        }
    })
}

/// Why a batch on a kept link did not end well ([`ride`]).
pub(crate) enum Rode {
    /// It may not go to the contact (blocked now): nothing was sent.
    Refused(String),
    /// The link failed before any reply came, or (the batch hedge, hedge
    /// gate only) no reply came within the hedge's wait: the batch goes on
    /// a fresh link (the contact takes a copy of what it holds as the same
    /// message, with the same ACK).
    Dead,
}

/// How a batch on a kept link ended ([`WarmPool::end`]).
#[derive(Clone, Copy, Debug)]
enum Ended {
    /// A send's check, answered with the link's offer: nothing was sent.
    Check,
    /// Every reply it waited for came, `trip` after its frames were
    /// written.
    Clean { trip: Duration },
    /// Any other way: a wait ran out, the link closed or failed, or the
    /// batch's dial was cut. The link may still bring a reply of its.
    Broken,
}

/// A batch's share of a kept link ([`WarmPool::checkout`]): the link stays
/// in the pool, and up to [`Limits::depth`] batches ride it at once. Ended
/// by [`Self::end`]; one dropped unended (its batch failed, or its dial was
/// cut) closes the link, whose replies to it would go unread.
pub(crate) struct Lease {
    pool: &'static WarmPool,
    id: u64,
    data_dir: PathBuf,
    jobs: mpsc::UnboundedSender<Job>,
    offer: Vec<u8>,
    trip: Option<Duration>,
    ended: bool,
}

impl Lease {
    /// Its batch ended ([`WarmPool::end`]).
    fn end(mut self, how: Ended) {
        self.ended = true;
        self.pool.end(self.id, how);
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        if !self.ended {
            self.pool.end(self.id, Ended::Broken);
        }
    }
}

/// One batch for a kept link's task ([`pipe`]).
struct Job {
    frames: Vec<Vec<u8>>,
    /// The terminal replies it waits for (one per frame that gets a reply,
    /// [`crate::netutil::expects_reply`]).
    expected: usize,
    /// Its frames were written, or why not.
    written: oneshot::Sender<Result<(), String>>,
    /// Its replies in the order they came; the channel ends after its last
    /// terminal reply, and with the link.
    replies: mpsc::UnboundedSender<ReplyWait>,
}

/// A batch whose frames were written, still owed terminal replies.
struct Flight {
    left: usize,
    replies: mpsc::UnboundedSender<ReplyWait>,
}

/// A kept link's own task (M8): it alone writes and reads the link
/// (`halves`, `state`). A batch's frames go out as the batch hands them
/// over, behind those of the batches before it (our route hints and HAVE
/// first when due, as a batch on a fresh link writes them). Replies go to
/// the oldest batch on the link until it had its last terminal reply (the
/// listener answers frame after frame, each reply before it reads the next
/// frame); the friend's HAVE and route hints are taken on the way, as a
/// batch's read takes them. A frame with no batch on the link, a close, an
/// unreadable frame or a failed write ends it, and every batch still on it
/// sees the link closed.
async fn pipe(
    mut halves: WarmHalves,
    mut state: LinkState,
    mut jobs: mpsc::UnboundedReceiver<Job>,
) {
    let mut flight: VecDeque<Flight> = VecDeque::new();
    let why = loop {
        tokio::select! {
            job = jobs.recv() => {
                let Some(job) = job else {
                    break PEER_CLOSED.to_string();
                };
                let wrote = write_batch(&mut halves, &mut state, &job.frames).await;
                let failed = wrote.as_ref().err().cloned();
                let _ = job.written.send(wrote);
                if let Some(why) = failed {
                    break why;
                }
                if job.expected > 0 {
                    flight.push_back(Flight {
                        left: job.expected,
                        replies: job.replies,
                    });
                }
            }
            sealed = halves.next_sealed() => {
                if let Err(why) = take_frame(&mut halves, &mut state, sealed, &mut flight).await {
                    break why;
                }
            }
        }
    };
    for batch in flight {
        let _ = batch.replies.send(ReplyWait::Closed(why.clone()));
    }
}

/// A batch's frames on a kept link: our route hints and HAVE first when
/// due, as `internet_direct`'s batch on a link's own stream writes them.
async fn write_batch(
    halves: &mut WarmHalves,
    state: &mut LinkState,
    frames: &[Vec<u8>],
) -> Result<(), String> {
    if let Some(ours) = state.hints.outgoing().await {
        halves.send(&mut state.cipher, &ours).await?;
        state.hints.written();
    }
    if let Some(have) = state.hints.update().outgoing().await {
        halves.send(&mut state.cipher, &have).await?;
    }
    for frame in frames {
        halves.send(&mut state.cipher, frame).await?;
    }
    Ok(())
}

/// What a kept link's reader read (`sealed`): opened, then the friend's
/// HAVE or route hints taken (as `internet_direct`'s read of a batch's
/// replies takes them), or a reply for the oldest batch on the link.
/// `Err`: why the link ends.
async fn take_frame(
    halves: &mut WarmHalves,
    state: &mut LinkState,
    sealed: Option<Result<Vec<u8>, String>>,
    flight: &mut VecDeque<Flight>,
) -> Result<(), String> {
    let got = match sealed {
        Some(Ok(ct)) => match state.cipher.open(&ct) {
            Ok(frame) => ReplyWait::Frame(frame),
            Err(why) => ReplyWait::Closed(why),
        },
        Some(Err(why)) => ReplyWait::Closed(why),
        None => ReplyWait::Closed(PEER_CLOSED.into()),
    };
    crate::security::dial_reply(&got, &state.hints);
    let frame = match got {
        ReplyWait::Frame(frame) => frame,
        ReplyWait::Closed(why) => return Err(why),
        ReplyWait::Idle => return Ok(()),
    };
    if let Some(answer) = state.hints.update().dialer_take(&frame).await {
        if let Some(ours) = answer {
            halves.send(&mut state.cipher, &ours).await?;
        }
        return Ok(());
    }
    if state.hints.take(&frame).await {
        if state.hints.flooded() {
            return Err("too many route hint frames".into());
        }
        if let Some(ours) = state.hints.outgoing().await {
            halves.send(&mut state.cipher, &ours).await?;
            state.hints.written();
        }
        return Ok(());
    }
    let Some(oldest) = flight.front_mut() else {
        return Err("a frame with no batch on the link".into());
    };
    let terminal = crate::netutil::is_terminal_reply(&frame);
    let _ = oldest.replies.send(ReplyWait::Frame(frame));
    if terminal {
        oldest.left -= 1;
        if oldest.left == 0 {
            flight.pop_front();
        }
    }
    Ok(())
}

/// A batch of `frames` for `expected` on its share of a kept link
/// (`lease`), with its replies into `progress`. A send's check (no frames)
/// is answered with the link's offer and no traffic. The batch's frames go
/// to the link's task ([`pipe`]), behind those of the batches already on
/// it, and its replies come back from it. With every reply it waited for
/// the link stays; any other end closes it. With the hedge gate open a
/// batch with no reply after max([`BATCH_HEDGE_FLOOR`], 3 x the link's last
/// round trip) closes the link and is [`Rode::Dead`] (the batch hedge, M5).
pub(crate) async fn ride(
    lease: Lease,
    expected: &[u8; 32],
    frames: &[Vec<u8>],
    progress: &mut DialProgress,
) -> Result<(), Rode> {
    // The contact's block, before anything is sent (the keeper looks too,
    // every sweep).
    let (dd, contact, offer) = (lease.data_dir.clone(), *expected, lease.offer.clone());
    match internet_direct::blocking(move || blocked(&dd, &contact, &offer)).await {
        Ok(false) => {}
        Ok(true) => return Err(Rode::Refused("blocked peer".into())),
        Err(e) => return Err(Rode::Refused(e)),
    }
    // A live link with the contact, as at its opening (the session
    // renewer).
    crate::renewal::note_live_link(expected, crate::renewal::LiveLink::Outbound);
    progress
        .collector
        .begin(lease.offer.clone(), frames)
        .map_err(Rode::Refused)?;
    if frames.is_empty() {
        lease.end(Ended::Check);
        return Ok(());
    }
    // It is reachable: what waits for it goes now (as a fresh link's
    // opening wakes it; never on a send's check).
    if !progress.send_check {
        internet_direct::wake_outbox_for(expected);
    }
    progress.stage = "sending frames";
    let (written, wrote) = oneshot::channel();
    let (replies_to, mut replies) = mpsc::unbounded_channel();
    let job = Job {
        frames: frames.to_vec(),
        expected: frames
            .iter()
            .filter(|f| crate::netutil::expects_reply(f))
            .count(),
        written,
        replies: replies_to,
    };
    if lease.jobs.send(job).is_err() || !matches!(wrote.await, Ok(Ok(()))) {
        return Err(Rode::Dead);
    }
    progress.frames_sent = true;
    progress.collector.mark_frames_sent();
    progress.stage = "waiting for a reply";
    let sent = Instant::now();
    let first_wait = progress.collector.first_wait();
    let hedge = lease
        .trip
        .filter(|_| lease.pool.hedge.open())
        .map(|trip| (trip * 3).max(BATCH_HEDGE_FLOOR))
        .filter(|hedge| *hedge < first_wait);
    let got = next_reply(&mut replies, hedge.unwrap_or(first_wait)).await;
    if hedge.is_some() && matches!(got, ReplyWait::Idle) {
        // The batch hedge: a silent link (its circuit may have died with
        // no word); the batch goes again on a fresh link.
        return Err(Rode::Dead);
    }
    let mut clean = matches!(got, ReplyWait::Frame(_));
    let mut more = match progress.collector.first(got) {
        Ok(more) => more,
        Err(e) => return Err(failed(progress, e)),
    };
    while more {
        let got = next_reply(&mut replies, progress.collector.idle_wait()).await;
        clean &= matches!(got, ReplyWait::Frame(_));
        more = match progress.collector.next(got) {
            Ok(more) => more,
            Err(e) => return Err(failed(progress, e)),
        };
    }
    lease.end(if clean && progress.collector.all_answered() {
        Ended::Clean {
            trip: sent.elapsed(),
        }
    } else {
        Ended::Broken
    });
    Ok(())
}

/// A batch on a kept link failed with `e`, as one on a link's own stream
/// ends: before any reply it goes again on a fresh link ([`Rode::Dead`]),
/// after one `e` is the dial's error.
fn failed(progress: &DialProgress, e: String) -> Rode {
    if progress.collector.answered_any() {
        Rode::Refused(e)
    } else {
        Rode::Dead
    }
}

/// A batch's next reply from its kept link's task within `wait`, as a read
/// on a link's own stream says it: a frame, nothing in time, or closed.
async fn next_reply(replies: &mut mpsc::UnboundedReceiver<ReplyWait>, wait: Duration) -> ReplyWait {
    match tokio::time::timeout(wait, replies.recv()).await {
        Ok(Some(got)) => got,
        Ok(None) => ReplyWait::Closed(PEER_CLOSED.into()),
        Err(_) => ReplyWait::Idle,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One keeper at a time; and one that went with its runtime (the
    /// embedded node's pause stops the runtime its tasks ran on) is not
    /// taken for one still running: the next kept link starts another, so
    /// kept links are still looked at after a resume.
    #[test]
    fn a_keeper_gone_with_its_runtime_is_started_again() {
        let gate = Box::leak(Box::new(std::sync::atomic::AtomicBool::new(true)));
        let hedge = Box::leak(Box::new(std::sync::atomic::AtomicBool::new(false)));
        let pool: &'static WarmPool = Box::leak(Box::new(WarmPool::new(
            LIMITS,
            Gate::Switch(gate),
            Gate::Switch(hedge),
        )));
        let runtime = || {
            tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .unwrap()
        };
        let first = runtime();
        first.block_on(async {
            assert!(pool.ensure_keeper(&mut pool.lock()), "the first keeper");
            assert!(!pool.ensure_keeper(&mut pool.lock()), "one at a time");
            tokio::task::yield_now().await;
        });
        drop(first);
        runtime().block_on(async {
            assert!(
                pool.ensure_keeper(&mut pool.lock()),
                "a keeper after its runtime stopped"
            );
        });
    }
}
