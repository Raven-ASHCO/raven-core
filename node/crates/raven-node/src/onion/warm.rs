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
//! link reads through a task of its own ([`WarmHalves`]), so waits run out
//! on a channel, and a frame or a close between batches closes the link.
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

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use raven_core::OutboxCarrier;
use tokio::net::TcpStream;
use tokio::time::Instant;

use crate::internet_direct::{self, DialIo, LinkState, OpenLink, WarmHalves};
use crate::netutil::DialProgress;

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

/// A pool's limits ([`LIMITS`]; tests scale them down).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Limits {
    pub(crate) idle: Duration,
    pub(crate) age: Duration,
    pub(crate) frames: u32,
    pub(crate) cap: usize,
    pub(crate) sweep: Duration,
}

/// The process pool's limits.
pub(crate) const LIMITS: Limits = Limits {
    idle: WARM_IDLE,
    age: WARM_AGE,
    frames: WARM_FRAMES,
    cap: WARM_POOL,
    sweep: SWEEP,
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

/// A kept link: its halves, its state, and what its limits count.
pub(crate) struct WarmLink {
    id: u64,
    key: WarmKey,
    halves: WarmHalves,
    state: LinkState,
    /// When the dial that opened it began.
    opened: Instant,
    /// When its last batch ended (a check answered from it is none).
    last_batch: Instant,
    /// Frames it carried after the offers (the listener counts them).
    written: u32,
}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

impl WarmLink {
    /// `link` after its first batch, which wrote `written` frames; `opened`:
    /// when its dial began.
    pub(crate) fn new(
        key: WarmKey,
        link: OpenLink<TcpStream>,
        opened: Instant,
        written: u32,
    ) -> Self {
        Self {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            key,
            halves: WarmHalves::split(link.stream),
            state: link.state,
            opened,
            last_batch: Instant::now(),
            written,
        }
    }

    /// May it carry a batch of `more` frames at `now`: within its limits,
    /// and nothing came on it nor did it close since its last batch.
    fn usable(&mut self, limits: &Limits, now: Instant, more: usize) -> bool {
        let more = u32::try_from(more).unwrap_or(u32::MAX);
        now.saturating_duration_since(self.last_batch) < limits.idle
            && now.saturating_duration_since(self.opened) < limits.age
            && self.written.saturating_add(more) <= limits.frames
            && self.halves.idle_clean()
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

    /// The kept link of `key` when it may carry a batch of `more` frames
    /// now, taken out of the pool. `None`: none (one that may not is
    /// closed; with the gate shut, all are).
    pub(crate) fn checkout(&self, key: &WarmKey, more: usize) -> Option<WarmLink> {
        if !self.live() {
            self.flush();
            return None;
        }
        let mut link = {
            let mut inner = self.lock();
            let at = inner.links.iter().position(|l| l.key == *key)?;
            inner.links.swap_remove(at)
        };
        link.usable(&self.limits, Instant::now(), more)
            .then_some(link)
    }

    /// Keep `link` for its friend's next batch: an older link of the same
    /// friend closes, and past the cap so does the one whose last batch is
    /// oldest. Nothing is kept while the gate is shut, nor a link that
    /// carried its frames.
    pub(crate) fn checkin(&'static self, link: WarmLink) {
        if !self.live() || link.written >= self.limits.frames {
            return;
        }
        let mut closed = Vec::new();
        {
            let mut inner = self.lock();
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
                let Some(oldest) =
                    (0..inner.links.len()).min_by_key(|&i| inner.links[i].last_batch)
                else {
                    break;
                };
                closed.push(inner.links.swap_remove(oldest));
            }
            self.ensure_keeper(&mut inner);
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
    /// shut; one idle, old or full, one that got a frame or closed since
    /// its last batch, and one whose friend is blocked, removed or no
    /// longer verified (an unreadable store closes it too). `false` once
    /// no link is kept: the keeper ends.
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
                if inner.links[at].usable(&self.limits, now, 0) {
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
                    (
                        l.id,
                        k.data_dir.clone(),
                        k.contact,
                        l.state.peer_offer.clone(),
                    )
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
    /// The link failed before any reply came: the batch goes on a fresh
    /// link (the contact takes a copy of what it holds as the same
    /// message, with the same ACK).
    Dead,
}

/// A batch of `frames` on `link`, taken from `pool` for `expected`, with
/// its replies into `progress`. A send's check (no frames) is answered with
/// the link's offer and no traffic, and the link goes back unchanged; a
/// batch that leaves the link clean puts it back.
pub(crate) async fn ride(
    pool: &'static WarmPool,
    mut link: WarmLink,
    expected: &[u8; 32],
    frames: &[Vec<u8>],
    progress: &mut DialProgress,
) -> Result<(), Rode> {
    // The contact's block, before anything is sent (the keeper looks too,
    // every sweep).
    let (dd, contact, offer) = (
        link.key.data_dir.clone(),
        *expected,
        link.state.peer_offer.clone(),
    );
    match internet_direct::blocking(move || blocked(&dd, &contact, &offer)).await {
        Ok(false) => {}
        Ok(true) => return Err(Rode::Refused("blocked peer".into())),
        Err(e) => return Err(Rode::Refused(e)),
    }
    // A live link with the contact, as at its opening (the session
    // renewer).
    crate::renewal::note_live_link(expected, crate::renewal::LiveLink::Outbound);
    if frames.is_empty() {
        progress
            .collector
            .begin(link.state.peer_offer.clone(), frames)
            .map_err(Rode::Refused)?;
        pool.checkin(link);
        return Ok(());
    }
    // It is reachable: what waits for it goes now (as a fresh link's
    // opening wakes it; never on a send's check).
    if !progress.send_check {
        internet_direct::wake_outbox_for(expected);
    }
    let mut io = DialIo::warm(&mut link.halves);
    let ran = internet_direct::run_batch_on(&mut io, &mut link.state, frames, progress).await;
    let (spent, written) = (io.spent(), io.written());
    match ran {
        Ok(()) => {
            if !spent && progress.collector.all_answered() {
                link.last_batch = Instant::now();
                link.written = link.written.saturating_add(written);
                pool.checkin(link);
            }
            Ok(())
        }
        Err(_) if !progress.collector.answered_any() => Err(Rode::Dead),
        Err(e) => Err(Rode::Refused(e)),
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
