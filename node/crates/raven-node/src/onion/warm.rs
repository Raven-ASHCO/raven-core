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
//!
//! **Keep warm** (speed design M2 and M10, the warm gate): while a
//! conversation with a verified friend goes on, [`KeepWarm`] probes its
//! rendezvous circuit through the helper every 6 to 9 minutes
//! ([`super::probe_on`], a refused stream on the friend's Tor), so a send
//! after a pause longer than Arti's 10 minutes still rides it; once a new
//! Tor life is ready, the conversations going on are probed at once.

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

/// Blocking: may this profile warm its Tor path to `contact` (speed design
/// M2, M3): a verified contact (fingerprint pinned) not on the block list.
/// An unreadable store says no.
pub(crate) fn may_warm(data_dir: &Path, contact: &[u8; 32]) -> bool {
    warm_refusal(data_dir, contact).is_none()
}

/// Blocking: why this profile may not warm its Tor path to `contact`
/// ([`may_warm`]), in a word of `raven_core::ipc::WARM_SKIP_WORDS`:
/// `not_verified` (no pinned fingerprint, or the contact store unreadable)
/// or `blocked` (on the block list, or the list unreadable).
pub(crate) fn warm_refusal(data_dir: &Path, contact: &[u8; 32]) -> Option<Skip> {
    let pinned = raven_core::contact_is_pinned(data_dir, contact).unwrap_or(false);
    if !raven_core::carrier_allowed_for_contact(OutboxCarrier::Onion, pinned) {
        return Some("not_verified");
    }
    let unblocked = raven_core::chat_history::BlockList::load_checked(data_dir)
        .is_ok_and(|list| !list.is_blocked(&hex::encode(contact)));
    (!unblocked).then_some("blocked")
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

/// Close every link of the process's pool ([`WARM`]), and end keep warm
/// ([`KEEP`]; a lock forgets its conversations too).
pub(crate) fn flush(why: Flush) {
    #[cfg(test)]
    FLUSHES[why as usize].fetch_add(1, Ordering::SeqCst);
    WARM.flush();
    KEEP.stop(why);
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

// ── M2: keep warm (Tor speed Stage A, speed design M2 and M10) ─────────────

/// A conversation goes on this long after its last message either way over
/// Tor, or the app's last chat open or typing in it ([`KeepWarm`]).
pub(crate) const CONVERSATION_SPAN: Duration = Duration::from_secs(30 * 60);
/// Keep warm probes a friend's circuit this often, uniformly at random
/// between the two: under Arti's 10 minutes after a circuit's last use
/// ([`super::proto::GROUP_KEPT`]).
pub(crate) const KEEP_WARM_EVERY: (Duration, Duration) =
    (Duration::from_secs(6 * 60), Duration::from_secs(9 * 60));
/// Keep warm ends for a friend this long after it began for it, in one Tor
/// life and one conversation: Arti drops the circuit 10 minutes after its
/// last use, and the next use after that builds a new rendezvous.
pub(crate) const MAX_CIRCUIT_AGE: Duration = Duration::from_secs(60 * 60);
/// Friends kept warm at once: as many as kept links (4, or 2 on the
/// embedded node).
pub(crate) const KEEP_WARM_MAX: usize = WARM_POOL;
/// A chat open probes a friend's circuit at most once per this (speed
/// design M3); a probe of any kind, or a link of ours that worked, counts.
pub(crate) const OPEN_WARM_EVERY: Duration = Duration::from_secs(6 * 60);
/// Conversations remembered at most: past it the one quiet longest goes.
const TALKS_KEPT: usize = 64;

/// A [`KeepWarm`]'s limits ([`KEEP_LIMITS`]; tests scale them).
#[derive(Clone, Copy, Debug)]
pub(crate) struct KeepLimits {
    /// [`CONVERSATION_SPAN`].
    pub(crate) span: Duration,
    /// [`KEEP_WARM_EVERY`].
    pub(crate) every: (Duration, Duration),
    /// [`MAX_CIRCUIT_AGE`].
    pub(crate) age: Duration,
    /// [`KEEP_WARM_MAX`].
    pub(crate) cap: usize,
    /// [`OPEN_WARM_EVERY`].
    pub(crate) open_every: Duration,
    /// A typing warm up at most once per this ([`WARM_IDLE`]).
    pub(crate) typing_every: Duration,
}

/// The process's keep warm limits.
pub(crate) const KEEP_LIMITS: KeepLimits = KeepLimits {
    span: CONVERSATION_SPAN,
    every: KEEP_WARM_EVERY,
    age: MAX_CIRCUIT_AGE,
    cap: KEEP_WARM_MAX,
    open_every: OPEN_WARM_EVERY,
    typing_every: WARM_IDLE,
};

/// One conversation with a friend, in memory only: who and when, never
/// what.
struct Talk {
    data_dir: PathBuf,
    contact: [u8; 32],
    /// The friend's onion service as its last dial or warm-up named it
    /// (none yet: the contact book's binding is used).
    hs_id: Option<[u8; 32]>,
    /// Its last message either way over Tor, chat open or typing.
    active: Instant,
    /// When the friend's circuit was last in use: a probe of any kind, or
    /// a link of ours that worked.
    circuit_used: Option<Instant>,
    /// Its last typing warm-up.
    typed: Option<Instant>,
    /// Kept warm in this Tor life: since when, and when its next probe is
    /// due.
    kept: Option<(Instant, Instant)>,
    /// Its keep warm ran its age in this Tor life: not again in this
    /// conversation.
    aged: bool,
    /// Its last probe failed (or found no route): no keep warm until the
    /// conversation shows again.
    failed: bool,
}

impl Talk {
    fn same(&self, data_dir: &Path, contact: &[u8; 32]) -> bool {
        self.contact == *contact && self.data_dir == data_dir
    }

    fn going_on(&self, limits: &KeepLimits, now: Instant) -> bool {
        now.saturating_duration_since(self.active) < limits.span
    }

    /// Still worth remembering at `now`: its conversation goes on, or a
    /// rate limit of its warm-ups still runs.
    fn worth_keeping(&self, limits: &KeepLimits, now: Instant) -> bool {
        let within = |at: Option<Instant>, span: Duration| {
            at.is_some_and(|at| now.saturating_duration_since(at) < span)
        };
        self.going_on(limits, now)
            || within(self.circuit_used, limits.open_every)
            || within(self.typed, limits.typing_every)
    }
}

/// Speed design M2 (warm gate only): while a conversation with a verified
/// friend goes on (a message either way over Tor within
/// [`CONVERSATION_SPAN`], or the app's chat open or typing), its
/// rendezvous circuit is probed every [`KEEP_WARM_EVERY`] through the
/// helper ([`super::probe_on`]: a refused stream on the friend's Tor,
/// nothing on its raven-node), so a send after a pause longer than Arti's
/// 10 minutes still rides it. At most [`KEEP_WARM_MAX`] friends at once,
/// each for at most [`MAX_CIRCUIT_AGE`]; a lock, a pause, a network change
/// and the end of a Tor life end it ([`flush`]), and a new Tor life that is
/// ready starts it again for the conversations going on, each with a probe
/// at once (the resume warm-up, M10: [`Self::tor_ready`]). It also keeps
/// the rate limits of the app's warm-ups (M3, [`Self::warm_up`]).
pub(crate) struct KeepWarm {
    limits: KeepLimits,
    gate: Gate,
    /// The kept links whose gates and failed links the probes share.
    pool: &'static WarmPool,
    inner: Mutex<KeepInner>,
    /// Wakes the task when the conversations change.
    news: tokio::sync::Notify,
}

struct KeepInner {
    talks: Vec<Talk>,
    /// The task while it runs: it ends once no friend is kept warm, or with
    /// the runtime it ran on.
    task: Option<tokio::task::JoinHandle<()>>,
}

/// Why a warm-up warms nothing ([`KeepWarm::warm_up`], [`warm_refusal`]):
/// one of `raven_core::ipc::WARM_SKIP_WORDS`.
pub(crate) type Skip = &'static str;

impl KeepWarm {
    /// Keep warm with `limits`, its own `gate`, its probes sharing `pool`.
    pub(crate) const fn new(limits: KeepLimits, gate: Gate, pool: &'static WarmPool) -> Self {
        Self {
            limits,
            gate,
            pool,
            inner: Mutex::new(KeepInner {
                talks: Vec::new(),
                task: None,
            }),
            news: tokio::sync::Notify::const_new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, KeepInner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Its gate is open.
    pub(crate) fn live(&self) -> bool {
        self.gate.open()
    }

    /// The kept links its probes share.
    pub(crate) fn pool(&self) -> &'static WarmPool {
        self.pool
    }

    /// `contact`'s conversation shows now (a message either way over Tor,
    /// the app's chat open or typing; `hs_id`: its onion service, when the
    /// caller knows it): it goes on for [`CONVERSATION_SPAN`] more, and keep
    /// warm takes it up when it has room. Nothing while the gate is shut.
    pub(crate) fn talked(
        &'static self,
        data_dir: &Path,
        contact: &[u8; 32],
        hs_id: Option<[u8; 32]>,
    ) {
        if !self.live() {
            return;
        }
        let now = Instant::now();
        let mut inner = self.lock();
        let at = self.talk_at(&mut inner, data_dir, contact, now);
        let talk = &mut inner.talks[at];
        if !talk.going_on(&self.limits, now) {
            // A new conversation: its keep warm may run its age again.
            talk.aged = false;
        }
        talk.active = now;
        talk.failed = false;
        if hs_id.is_some() {
            talk.hs_id = hs_id;
        }
        self.ensure_task(&mut inner);
        drop(inner);
        self.news.notify_one();
    }

    /// Where `contact`'s conversation is in `inner` (a new one, when none:
    /// the one quiet longest goes first when [`TALKS_KEPT`] are kept).
    fn talk_at(
        &self,
        inner: &mut KeepInner,
        data_dir: &Path,
        contact: &[u8; 32],
        now: Instant,
    ) -> usize {
        if let Some(at) = inner.talks.iter().position(|t| t.same(data_dir, contact)) {
            return at;
        }
        if inner.talks.len() >= TALKS_KEPT {
            if let Some(oldest) = (0..inner.talks.len()).min_by_key(|&i| inner.talks[i].active) {
                inner.talks.swap_remove(oldest);
            }
        }
        inner.talks.push(Talk {
            data_dir: data_dir.to_path_buf(),
            contact: *contact,
            hs_id: None,
            active: now,
            circuit_used: None,
            typed: None,
            kept: None,
            aged: false,
            failed: false,
        });
        inner.talks.len() - 1
    }

    /// A dial of ours to `contact`'s onion service `hs_id` worked, with
    /// `frames` (none: a check): the friend's circuit was in use (for the
    /// first probe and the chat open's limit; a probe already planned stays
    /// as it is, since a batch on a kept link opens no stream and Arti
    /// counts streams), and a chat message in it shows the conversation.
    /// Nothing while the gate is shut.
    pub(crate) fn dialled(
        &'static self,
        data_dir: &Path,
        contact: &[u8; 32],
        hs_id: [u8; 32],
        frames: &[Vec<u8>],
    ) {
        if !self.live() {
            return;
        }
        if frames.iter().any(|f| is_chat(f)) {
            self.talked(data_dir, contact, Some(hs_id));
        }
        let now = Instant::now();
        let mut inner = self.lock();
        if let Some(talk) = inner.talks.iter_mut().find(|t| t.same(data_dir, contact)) {
            talk.circuit_used = Some(now);
            talk.hs_id = Some(hs_id);
        }
    }

    /// A frame from `contact` over Tor: a chat message in it shows the
    /// conversation. Nothing while the gate is shut.
    pub(crate) fn heard(&'static self, data_dir: &Path, contact: &[u8; 32], frame: &[u8]) {
        if self.live() && is_chat(frame) {
            self.talked(data_dir, contact, None);
        }
    }

    /// The app's warm-up of `level` for `contact` at its onion service
    /// `hs_id` (speed design M3), asked now: `Ok` when it may go ahead (it
    /// counts for its rate limit from now), else why not: the gate is shut
    /// (`off`), or the same warm-up ran for the friend within its limit
    /// (`soon`: a chat open once per [`OPEN_WARM_EVERY`], and not while its
    /// circuit was in use within that; typing once per [`WARM_IDLE`]).
    /// Either way the conversation shows ([`Self::talked`]).
    pub(crate) fn warm_up(
        &'static self,
        data_dir: &Path,
        contact: &[u8; 32],
        hs_id: [u8; 32],
        level: raven_core::ipc::WarmLevel,
    ) -> Result<(), Skip> {
        use raven_core::ipc::WarmLevel;
        if !self.live() {
            return Err("off");
        }
        self.talked(data_dir, contact, Some(hs_id));
        let now = Instant::now();
        let limits = self.limits;
        let mut inner = self.lock();
        let at = self.talk_at(&mut inner, data_dir, contact, now);
        let talk = &mut inner.talks[at];
        let (last, every) = match level {
            WarmLevel::Circuit => (&mut talk.circuit_used, limits.open_every),
            WarmLevel::Link => (&mut talk.typed, limits.typing_every),
        };
        if last.is_some_and(|at| now.saturating_duration_since(at) < every) {
            return Err("soon");
        }
        *last = Some(now);
        // Either opens a stream on the friend's circuit (a refused one, or
        // the link's).
        talk.circuit_used = Some(now);
        Ok(())
    }

    /// Why every kept link closes ([`flush`]): keep warm ends (its circuits
    /// went with Tor, or will); a lock also forgets every conversation, and
    /// the others keep them for the resume warm-up ([`Self::tor_ready`]).
    pub(crate) fn stop(&self, why: Flush) {
        let mut inner = self.lock();
        if why == Flush::Lock {
            inner.talks.clear();
        }
        for talk in &mut inner.talks {
            talk.kept = None;
            talk.aged = false;
        }
        if let Some(task) = inner.task.take() {
            task.abort();
        }
    }

    /// A new Tor life is ready (after a wake, an app resume, a network
    /// change or any other start; speed design M10): keep warm starts again
    /// for the conversations going on, the most recent first and up to its
    /// cap, each with a probe at once, unless its circuit was in use within
    /// [`OPEN_WARM_EVERY`] (the same limit as a chat open's). Nothing while
    /// the gate is shut.
    pub(crate) fn tor_ready(&'static self) {
        if !self.live() {
            return;
        }
        let now = Instant::now();
        let limits = self.limits;
        let mut inner = self.lock();
        let mut waiting: Vec<usize> = (0..inner.talks.len())
            .filter(|&i| {
                let t = &inner.talks[i];
                t.kept.is_none() && !t.aged && t.going_on(&limits, now)
            })
            .collect();
        waiting.sort_by_key(|&i| std::cmp::Reverse(inner.talks[i].active));
        let kept = inner.talks.iter().filter(|t| t.kept.is_some()).count();
        for i in waiting.into_iter().take(limits.cap.saturating_sub(kept)) {
            let talk = &mut inner.talks[i];
            let first = talk
                .circuit_used
                .map_or(now, |at| (at + limits.open_every).max(now));
            talk.kept = Some((now, first));
            talk.failed = false;
        }
        self.ensure_task(&mut inner);
        drop(inner);
        self.news.notify_one();
    }

    /// Starts the task unless one runs (one gone with its runtime does not),
    /// on this thread's runtime (none: the next note on one starts it).
    fn ensure_task(&'static self, inner: &mut KeepInner) {
        if inner.task.as_ref().is_some_and(|t| !t.is_finished()) {
            return;
        }
        if tokio::runtime::Handle::try_current().is_err() {
            return;
        }
        inner.task = Some(tokio::spawn(self.run()));
    }

    /// The task: the probes due, then a sleep until the next one (or news),
    /// while any friend is kept warm.
    async fn run(&'static self) {
        loop {
            let (due, next) = self.plan(Instant::now());
            for (data_dir, contact, hs_id) in due {
                self.probe(&data_dir, contact, hs_id).await;
            }
            let Some(next) = next else {
                return;
            };
            tokio::select! {
                () = tokio::time::sleep_until(next) => {}
                () = self.news.notified() => {}
            }
        }
    }

    /// One look at the conversations at `now`: keep warm ends for a friend
    /// whose conversation is over or whose keep warm ran its age, its room
    /// goes to a conversation going on (the most recent first; its first
    /// probe a full interval after its circuit's last use), the probes due
    /// now are taken, and conversations no longer worth keeping are
    /// forgotten. The probes to make (each friend's profile, key and onion
    /// service, when known) and when to look next: `None` once no friend
    /// is kept warm (the task ends; the next note starts another).
    #[allow(clippy::type_complexity)]
    fn plan(&self, now: Instant) -> (Vec<(PathBuf, [u8; 32], Option<[u8; 32]>)>, Option<Instant>) {
        let limits = self.limits;
        let mut inner = self.lock();
        if !self.live() {
            inner.talks.clear();
            inner.task = None;
            return (Vec::new(), None);
        }
        inner.talks.retain(|t| t.worth_keeping(&limits, now));
        let mut due = Vec::new();
        for talk in &mut inner.talks {
            let Some((since, next)) = talk.kept else {
                continue;
            };
            if !talk.going_on(&limits, now) {
                talk.kept = None;
            } else if now.saturating_duration_since(since) >= limits.age {
                talk.kept = None;
                talk.aged = true;
            } else if next <= now {
                due.push((talk.data_dir.clone(), talk.contact, talk.hs_id));
                talk.kept = Some((since, now + jitter(limits.every)));
            }
        }
        let mut waiting: Vec<usize> = (0..inner.talks.len())
            .filter(|&i| {
                let t = &inner.talks[i];
                t.kept.is_none() && !t.aged && !t.failed && t.going_on(&limits, now)
            })
            .collect();
        waiting.sort_by_key(|&i| std::cmp::Reverse(inner.talks[i].active));
        let kept = inner.talks.iter().filter(|t| t.kept.is_some()).count();
        for i in waiting.into_iter().take(limits.cap.saturating_sub(kept)) {
            let talk = &mut inner.talks[i];
            // From the circuit's last use while Arti may still keep it, else
            // from the conversation's last word (the probe then builds it).
            let from = match talk.circuit_used {
                Some(at) if now.saturating_duration_since(at) < super::proto::GROUP_KEPT => at,
                _ => talk.active,
            };
            talk.kept = Some((now, (from + jitter(limits.every)).max(now)));
        }
        let next = inner
            .talks
            .iter()
            .filter_map(|t| t.kept.map(|(_, next)| next))
            .min();
        if next.is_none() {
            inner.task = None;
        }
        (due, next)
    }

    /// One keep-warm probe of `contact`'s circuit at `hs_id` (none: the
    /// contact book's binding), [`super::probe_on`]. One that failed, or a
    /// friend with no onion route, ends keep warm for it until its
    /// conversation shows again.
    async fn probe(&'static self, data_dir: &Path, contact: [u8; 32], hs_id: Option<[u8; 32]>) {
        let hs_id = match hs_id {
            Some(hs_id) => Some(hs_id),
            None => {
                let dd = data_dir.to_path_buf();
                internet_direct::blocking(move || Ok(book_onion(&dd, &contact)))
                    .await
                    .ok()
                    .flatten()
            }
        };
        let probed = match hs_id {
            Some(hs_id) => super::probe_on(self.pool, data_dir, contact, hs_id).await,
            None => Err("no onion route".into()),
        };
        let mut inner = self.lock();
        let talk = inner.talks.iter_mut().find(|t| t.same(data_dir, &contact));
        match probed {
            Ok(()) => {
                if let Some(talk) = talk {
                    talk.circuit_used = Some(Instant::now());
                }
            }
            Err(e) => {
                if let Some(talk) = talk {
                    talk.kept = None;
                    talk.failed = true;
                }
                drop(inner);
                crate::netutil::log_limited(
                    &KEEP_LOG,
                    "raven-node onion",
                    format_args!("keep warm: a probe failed ({})", probe_failure_words(&e)),
                );
            }
        }
    }

    /// The friends kept warm now (tests).
    #[cfg(test)]
    pub(crate) fn kept_len(&self) -> usize {
        self.lock()
            .talks
            .iter()
            .filter(|t| t.kept.is_some())
            .count()
    }
}

/// Keep warm's log lines: at most one per 10 minutes, states only.
static KEEP_LOG: crate::netutil::LogLimiter =
    crate::netutil::LogLimiter::new(Duration::from_secs(600));

/// A probe's failure in a few fixed words for the log (never an address,
/// never Tor's own text).
fn probe_failure_words(e: &str) -> &'static str {
    if e.starts_with(super::ONION_NOT_READY) {
        "Tor not ready"
    } else if e.starts_with(super::ONION_UNREACHABLE) {
        "the friend's onion service did not answer"
    } else if e.starts_with(raven_core::CONTACT_NOT_VERIFIED) {
        "not a verified friend"
    } else {
        "other"
    }
}

/// Blocking: `contact`'s onion service from the contact book: the newest
/// binding its own key signed, for a verified contact only.
fn book_onion(data_dir: &Path, contact: &[u8; 32]) -> Option<[u8; 32]> {
    raven_core::outbox::contact_routes(data_dir, contact)
        .ok()
        .flatten()
        .filter(|routes| routes.pinned)
        .and_then(|routes| routes.onion)
        .map(|binding| binding.hs_id)
}

/// A chat message (not a PairInit, not a receipt): what shows a
/// conversation.
fn is_chat(frame: &[u8]) -> bool {
    use raven_core::envelope::{EnvType, Envelope};
    Envelope::unpack(frame).is_some_and(|e| e.env_type == EnvType::Message as u8)
        && matches!(
            raven_core::classify_packed_envelope(frame),
            raven_core::PairInitOobClassify::NotPairInitOob
        )
}

/// A time between the two of `every`, uniformly at random.
fn jitter((low, high): (Duration, Duration)) -> Duration {
    let span = u64::try_from(high.saturating_sub(low).as_millis()).unwrap_or(u64::MAX);
    if span == 0 {
        return low;
    }
    low + Duration::from_millis(rand::random::<u64>() % (span + 1))
}

/// The process's keep warm: the conversations of this process's profile,
/// its probes through [`WARM`]'s gates.
pub(crate) static KEEP: KeepWarm = KeepWarm::new(
    KEEP_LIMITS,
    Gate::Live(raven_core::onion_gate::onion_warm_live),
    &WARM,
);

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

    /// Speed design M2 and M10: keep warm takes at most its cap of friends
    /// at once (4, or 2 on the embedded node), first come while it has
    /// room; a new Tor life takes the conversations going on again, the
    /// most recent first, up to the same cap. On the paused clock, before
    /// any probe is due.
    #[tokio::test(start_paused = true)]
    async fn keep_warm_takes_its_cap_and_the_resume_the_most_recent_first() {
        let switch = |on: bool| -> &'static std::sync::atomic::AtomicBool {
            Box::leak(Box::new(std::sync::atomic::AtomicBool::new(on)))
        };
        let (gate, hedge) = (switch(true), switch(false));
        let pool: &'static WarmPool = Box::leak(Box::new(WarmPool::new(
            LIMITS,
            Gate::Switch(gate),
            Gate::Switch(hedge),
        )));
        let keep: &'static KeepWarm = Box::leak(Box::new(KeepWarm::new(
            KEEP_LIMITS,
            Gate::Switch(gate),
            pool,
        )));
        let kept = || -> Vec<u8> {
            let mut kept: Vec<u8> = keep
                .lock()
                .talks
                .iter()
                .filter(|t| t.kept.is_some())
                .map(|t| t.contact[0])
                .collect();
            kept.sort_unstable();
            kept
        };
        let dir = Path::new("/nonexistent/keep-warm-cap-test");
        let friends = u8::try_from(KEEP_LIMITS.cap + 2).unwrap();
        for n in 0..friends {
            keep.talked(dir, &[n; 32], None);
            tokio::task::yield_now().await;
            tokio::time::advance(Duration::from_secs(1)).await;
        }
        tokio::task::yield_now().await;
        let first_come: Vec<u8> = (0..friends - 2).collect();
        assert_eq!(kept(), first_come, "the first {} only", KEEP_LIMITS.cap);
        keep.stop(Flush::NetworkChanged);
        assert!(kept().is_empty());
        keep.tor_ready();
        let most_recent: Vec<u8> = (2..friends).collect();
        assert_eq!(kept(), most_recent, "the {} most recent", KEEP_LIMITS.cap);
    }
}
