//! Attachments' chunks on Raven links (`RAX1`,
//! `docs/design/2026-11-attachments.md` §9, §10; the exchange itself is
//! `raven_core::attachment::exchange`).
//!
//! - **Negotiation.** While attachments are [`live`], this node's hello
//!   sets link caps bit 12 (`crate::link::offers`; never on Bluetooth) and
//!   a LAN dial that reads puts it in its RLX1. [`AttLink`] is one link's
//!   part: what the peer's caps showed is noted for a verified friend
//!   (`raven_core::attachment::peers`: the bit writes its record, caps
//!   without it clear it, a LAN listener shows none), and a listener takes
//!   `RAX1` frames only from a verified friend whose caps on this link
//!   showed the bit; anyone else gets a refusal for a request and nothing
//!   for the rest.
//! - **The task** ([`run`]). It asks the exchange what is due
//!   (`Exchange::plans`), makes each dial on the routes the outbox plans
//!   for a send to that friend (Tor too; never Bluetooth), and hands the
//!   replies back
//!   (`Exchange::took`). It looks again at once while there is more to do
//!   and when an offer is delivered in this process, a few times a second
//!   while something waits (for its time, for a friend, or for a delivery
//!   another program on this profile writes: found by its row, with no
//!   call from the app), and every few seconds otherwise. A friend whose
//!   link comes up is tried at once.
//! - A listener never speaks first; the dialer's `RAX1` frames are answered
//!   on the link and never dispatched.
//! - **An attachment goes with its message.** The task removes what the
//!   history no longer holds (`raven_core::attachment::sweep`) when it
//!   starts and every hour.
//!
//! With the gate shut nothing here runs: no bit 12, no task work, and a
//! `RAX1` frame is not taken (the link handles it as before: an unknown
//! frame).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use raven_core::attachment::exchange::{self, Exchange, Memory};
use raven_core::attachment::{link as rax1, peers};
use raven_core::{attachment_gate, security_gate, OutboxCarrier, CAP_LINK_ATT1};
use tokio::sync::Notify;

/// The task looks again this soon while something waits: for its time,
/// for a friend, or for its offer's delivery, which another program on
/// this profile may write (this node then finds it by its row, so this is
/// the longest a photo waits between its message and its chunks).
const PASS_WAITING: Duration = Duration::from_millis(300);
/// ... and this often with nothing to do.
const PASS_IDLE: Duration = Duration::from_secs(4);
/// ... and this often while attachments are off.
const PASS_OFF: Duration = Duration::from_secs(60);
/// Attachments whose message is gone are removed this often.
const SWEEP_INTERVAL: Duration = Duration::from_secs(3_600);
/// One dial's deadline: under the shortest life of a listener's link.
const DIAL_DEADLINE: Duration = Duration::from_secs(100);
/// The reply budget of a dial (16 chunks and the replies around them): a
/// node-internal dial, never an IPC response.
const DIAL_REPLY_BUDGET: usize = 2 * 1024 * 1024;

/// Why a dial of the task was not made or did not end, in its own words
/// (they hold no address and no key, so the log line says them whole).
const NO_WORKER: &str = "no outbox worker: no route plan";
const NO_ROUTE: &str = "no route to this contact";
const DEADLINE: &str = "attachment dial deadline";

/// What a failed dial's error says for the log: the task's own words, or
/// the error's leading code (`ONION_UNREACHABLE`); never the rest of a
/// dial's error, which may name an address.
fn failure_words(error: &str) -> &str {
    if [NO_WORKER, NO_ROUTE, DEADLINE, NOT_SPOKEN].contains(&error) {
        return error;
    }
    let code = error
        .split(|c: char| !(c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'))
        .next()
        .unwrap_or("");
    if code.len() >= 4 {
        code
    } else {
        "no code"
    }
}

/// A dial carried `RAX1` frames to a listener whose hello did not offer
/// them: nothing was sent.
pub(crate) const NOT_SPOKEN: &str = "ATTACHMENTS_NOT_OFFERED: this contact's Raven does not take \
     attachments on this link; nothing was sent";

/// Attachments are live in this process.
pub(crate) fn live() -> bool {
    attachment_gate::attachments_live()
}

/// Our hello (or RLX1) on a link of `carrier` carries bit 12: while
/// attachments are [`live`], on every carrier but Bluetooth.
pub(crate) fn offered(carrier: OutboxCarrier) -> bool {
    carrier != OutboxCarrier::Nearby && live()
}

fn memory() -> &'static Mutex<Memory> {
    static MEMORY: OnceLock<Mutex<Memory>> = OnceLock::new();
    MEMORY.get_or_init(Mutex::default)
}

fn kicked() -> &'static Notify {
    static KICK: OnceLock<Notify> = OnceLock::new();
    KICK.get_or_init(Notify::new)
}

/// Wake the task now.
pub(crate) fn kick() {
    kicked().notify_one();
}

/// Run `work` on the blocking pool with this thread's gate overrides (an
/// in-process test's; none otherwise, and a release build ignores them).
async fn blocking<T, F>(work: F) -> Option<T>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let gates = security_gate::lab_overrides_for_this_thread();
    let att = attachment_gate::lab_attachments_for_this_thread();
    tokio::task::spawn_blocking(move || {
        let before = security_gate::set_lab_overrides_for_this_thread(gates);
        let att_before = attachment_gate::lab_attachments_for_this_thread();
        attachment_gate::set_lab_attachments_for_this_thread(att);
        let out = work();
        attachment_gate::set_lab_attachments_for_this_thread(att_before);
        security_gate::set_lab_overrides_for_this_thread(before);
        out
    })
    .await
    .ok()
}

/// A verified contact that is not blocked (fail closed).
fn pinned(data_dir: &Path, peer: &[u8; 32]) -> bool {
    raven_core::attachment::flow::is_friend(data_dir, peer)
}

// ── One link ────────────────────────────────────────────────────────────────

/// The attachments' part of one link. Held by the link's
/// `crate::hints::LinkCtl` ([`crate::hints::LinkCtl::with_att`]).
#[derive(Debug)]
pub(crate) struct AttLink {
    /// Attachments are live and this side offered bit 12 on this link.
    live: bool,
    data_dir: PathBuf,
    peer: [u8; 32],
    listener: bool,
    /// What the peer's caps on this link showed: the bit, caps without it,
    /// or no caps at all (`None`: a LAN listener as its dialer sees it, a
    /// LAN dial that does not read).
    peer_speaks: Option<bool>,
    /// The peer is a verified friend; read once, when first needed.
    verified: Option<bool>,
}

impl AttLink {
    /// No attachments on this link (the gate shut, a test).
    pub(crate) fn off() -> Self {
        Self {
            live: false,
            data_dir: PathBuf::new(),
            peer: [0; 32],
            listener: false,
            peer_speaks: None,
            verified: None,
        }
    }

    fn on(data_dir: &Path, peer: [u8; 32], carrier: OutboxCarrier, listener: bool) -> Self {
        Self {
            live: offered(carrier),
            data_dir: data_dir.to_path_buf(),
            peer,
            listener,
            ..Self::off()
        }
    }

    /// The LAN listener of a dialer whose message 3 payload was `m3`: its
    /// RLX1 caps say whether it takes attachments; a message 3 without
    /// caps (a dial that does not read) says nothing.
    pub(crate) fn lan_listener(data_dir: &Path, peer: [u8; 32], m3: &[u8]) -> Self {
        let caps = raven_core::route_hints::rlx1_caps(m3);
        Self {
            peer_speaks: (caps != 0).then_some(caps & CAP_LINK_ATT1 != 0),
            ..Self::on(data_dir, peer, OutboxCarrier::Lan, true)
        }
    }

    /// A LAN dial: the listener sends no caps, so this node goes by the
    /// friend's record.
    pub(crate) fn lan_dialer(data_dir: &Path, peer: [u8; 32]) -> Self {
        Self::on(data_dir, peer, OutboxCarrier::Lan, false)
    }

    /// Internet direct, p2p, nearby or Tor (`carrier`): `peer_caps`, the
    /// peer's verified hello caps.
    pub(crate) fn inet(
        data_dir: &Path,
        carrier: OutboxCarrier,
        listener: bool,
        peer: [u8; 32],
        peer_caps: u32,
    ) -> Self {
        Self {
            // A Bluetooth link carries no attachments, whatever its hello
            // says, and says nothing about the friend's other links.
            peer_speaks: (carrier != OutboxCarrier::Nearby)
                .then_some(peer_caps & CAP_LINK_ATT1 != 0),
            ..Self::on(data_dir, peer, carrier, listener)
        }
    }

    /// The link is authenticated: note what the peer's caps showed when it
    /// is a verified friend, and try what waits for it.
    pub(crate) async fn seen(&mut self) {
        if !live() {
            return;
        }
        let (data_dir, peer, speaks) = (self.data_dir.clone(), self.peer, self.peer_speaks);
        let known = blocking(move || {
            if !pinned(&data_dir, &peer) {
                return (false, false);
            }
            if let Some(speaks) = speaks {
                let _ = peers::note(&data_dir, &peer, speaks, crate::now_ms());
            }
            (true, peers::speaks(&data_dir, &peer))
        })
        .await
        .unwrap_or((false, false));
        self.verified = Some(known.0);
        if known.1 {
            Exchange::new(&self.data_dir, memory()).peer_seen(&self.peer);
            kick();
        }
    }

    async fn verified(&mut self) -> bool {
        if let Some(verified) = self.verified {
            return verified;
        }
        let (data_dir, peer) = (self.data_dir.clone(), self.peer);
        let verified = blocking(move || pinned(&data_dir, &peer))
            .await
            .unwrap_or(false);
        self.verified = Some(verified);
        verified
    }

    /// May a dial carry `RAX1` frames on this link? Not to a listener whose
    /// hello showed caps without bit 12; a LAN listener shows none, and the
    /// task asked the friend's record before it dialled.
    pub(crate) fn may_send(&self) -> bool {
        self.live && !self.listener && self.peer_speaks != Some(false)
    }

    /// This dial's own frames were answered. When they carried a message
    /// and a send of an offer to this friend set out a moment ago: the
    /// chunks of that attachment and HAVE, to write on this link now
    /// (`Exchange::link_push`); the listener answers with a LACK. None:
    /// nothing rides this link.
    pub(crate) async fn plan_on_link(&mut self, frames: &[Vec<u8>]) -> Option<exchange::Plan> {
        if !self.live || self.listener {
            return None;
        }
        if !frames.iter().any(|f| crate::netutil::is_message_frame(f)) {
            return None;
        }
        let (data_dir, peer, shown) = (self.data_dir.clone(), self.peer, self.peer_speaks);
        let planned = blocking(move || {
            if !pinned(&data_dir, &peer) {
                return Err("");
            }
            // A LAN listener shows no caps: this node goes by the record.
            // A friend whose Raven did not say that it takes attachments
            // gets none on any link (the task says what waits for it).
            if !shown.unwrap_or_else(|| peers::speaks(&data_dir, &peer)) {
                return Err("");
            }
            Exchange::new(&data_dir, memory()).link_push_or_why(&peer, crate::now_ms())
        })
        .await
        .unwrap_or(Err("the look at the store did not end"));
        match planned {
            Ok(plan) => Some(plan),
            Err(why) => {
                // A photo that waits and does not ride this link says why
                // (a word; nothing for a link that has none to carry).
                if !why.is_empty() {
                    eprintln!(
                        "raven-node attachments: contact {}, nothing rides the message's link: {why}",
                        crate::netutil::link_tag(&self.peer)
                    );
                }
                None
            }
        }
    }

    /// The chunks of `plan` were written on this link: with the listener's
    /// answer (`replies`), or without one (the time ran out, the link was
    /// cut): the task then takes it up, asking first.
    pub(crate) async fn took_on_link(
        &self,
        plan: exchange::Plan,
        replies: Option<Vec<Vec<u8>>>,
        took: Duration,
    ) {
        note_on_link(&plan, replies.is_some(), took);
        let data_dir = self.data_dir.clone();
        let more = blocking(move || {
            Exchange::new(&data_dir, memory()).took(&plan, replies.as_deref(), crate::now_ms())
        })
        .await
        .unwrap_or(false);
        if more {
            kick();
        }
    }

    /// A listener's frame: `None` when it is not a `RAX1` frame or
    /// attachments are off here (dispatch it as before); the replies to
    /// write otherwise.
    pub(crate) async fn listener_take(&mut self, frame: &[u8]) -> Option<Vec<Vec<u8>>> {
        if !self.live || !self.listener || !rax1::is_rax1(frame) {
            return None;
        }
        if self.peer_speaks != Some(true) || !self.verified().await {
            return Some(exchange::refuse(frame));
        }
        let (data_dir, peer, bytes) = (self.data_dir.clone(), self.peer, frame.to_vec());
        let replies = blocking(move || {
            Exchange::new(&data_dir, memory()).listener_frame(&peer, &bytes, crate::now_ms())
        })
        .await
        .unwrap_or_default();
        // A HAVE ends a push, a DONE a pull: the task may have the next
        // thing to say (DONE for what just became complete).
        if frame.len() > 5 && matches!(frame[5], 0x01 | 0x03) {
            kick();
        }
        Some(replies)
    }
}

/// The longest the chunks of an offer may ride the link that carried it.
const ON_LINK_MAX: Duration = Duration::from_secs(20);
/// What is left of a dial for those chunks must leave this much for the
/// dial's own end (its replies go back to the program that sent).
const ON_LINK_MARGIN: Duration = Duration::from_secs(8);
/// ... and is not worth starting below this.
const ON_LINK_MIN: Duration = Duration::from_secs(3);

/// How long the chunks of an offer may ride this dial's link, `elapsed`
/// into the dial: what the dial's own deadline leaves (a program's dial
/// has 45 s, over Tor 75 s), [`ON_LINK_MAX`] at most. None: not enough is
/// left; the task sends them in a dial of its own.
pub(crate) fn on_link_budget(carrier: OutboxCarrier, elapsed: Duration) -> Option<Duration> {
    let limit = if carrier == OutboxCarrier::Onion {
        raven_core::onion::ONION_DIAL_DEADLINE
    } else {
        Duration::from_secs(45)
    };
    let left = limit.checked_sub(elapsed + ON_LINK_MARGIN)?;
    let budget = left.min(ON_LINK_MAX);
    (budget >= ON_LINK_MIN).then_some(budget)
}

/// How long the answer to chunks of `bytes` in all is waited for on a
/// link, within `budget`: the time a slow link takes to carry them (50
/// KB/s, a poor Tor circuit) and a few seconds for the listener's answer.
/// A link that died under the chunks is given up sooner than the whole
/// budget, so the message's own receipt is not held back by it.
pub(crate) fn on_link_wait(bytes: usize, budget: Duration) -> Duration {
    let carry = Duration::from_millis((bytes as u64).saturating_mul(1_000) / 50_000);
    (carry + Duration::from_secs(5)).min(budget)
}

/// [`AttLink::plan_on_link`] for a batch on a kept Tor link, which has no
/// link state at hand: by the friend's record. The link was opened by a
/// dial of ours to a verified friend, and a listener whose hello did not
/// offer attachments answers the HAVE with a refusal and takes no chunk.
pub(crate) async fn plan_for_kept_link(
    data_dir: &Path,
    peer: &[u8; 32],
    frames: &[Vec<u8>],
) -> Option<exchange::Plan> {
    if !live() || !frames.iter().any(|f| crate::netutil::is_message_frame(f)) {
        return None;
    }
    let (dd, friend) = (data_dir.to_path_buf(), *peer);
    let planned = blocking(move || {
        if !pinned(&dd, &friend) || !peers::speaks(&dd, &friend) {
            return Err("");
        }
        Exchange::new(&dd, memory()).link_push_or_why(&friend, crate::now_ms())
    })
    .await
    .unwrap_or(Err("the look at the store did not end"));
    match planned {
        Ok(plan) => Some(plan),
        Err(why) => {
            if !why.is_empty() {
                eprintln!(
                    "raven-node attachments: contact {}, nothing rides the message's link: {why}",
                    crate::netutil::link_tag(peer)
                );
            }
            None
        }
    }
}

/// [`AttLink::took_on_link`] for a batch on a kept Tor link.
pub(crate) async fn took_on_kept_link(
    data_dir: &Path,
    plan: exchange::Plan,
    replies: Option<Vec<Vec<u8>>>,
    took: Duration,
) {
    note_on_link(&plan, replies.is_some(), took);
    let dd = data_dir.to_path_buf();
    let more = blocking(move || {
        Exchange::new(&dd, memory()).took(&plan, replies.as_deref(), crate::now_ms())
    })
    .await
    .unwrap_or(false);
    if more {
        kick();
    }
}

/// One log line for chunks that rode a message's link (counts only).
fn note_on_link(plan: &exchange::Plan, answered: bool, took: Duration) {
    eprintln!(
        "raven-node attachments: contact {}, {} frame(s) on the message's own link, {} in {} ms",
        crate::netutil::link_tag(&plan.peer),
        plan.frames.len(),
        if answered { "answered" } else { "no answer" },
        took.as_millis()
    );
}

/// A dial may carry `frames` on this link: `RAX1` frames only to a
/// listener that may take them ([`AttLink::may_send`]); anything else as
/// before. `Err`: nothing may be sent.
pub(crate) fn check_frames(frames: &[Vec<u8>], link: &AttLink) -> Result<(), String> {
    if frames.iter().any(|f| rax1::is_rax1(f)) && !link.may_send() {
        return Err(NOT_SPOKEN.into());
    }
    Ok(())
}

// ── The task ────────────────────────────────────────────────────────────────

/// One dial to `peer` from the blocking pool: its routes as the outbox
/// worker plans a send's (`crate::hints::send_routes`: Tor too, last),
/// tried in order, never Bluetooth, each with the internal reply budget
/// and [`DIAL_DEADLINE`].
fn dial_peer(
    handle: &tokio::runtime::Handle,
    data_dir: &Path,
    peer: &[u8; 32],
    frames: &[Vec<u8>],
) -> Result<Vec<Vec<u8>>, String> {
    let ctx = crate::outbox::attempt_ctx().ok_or(NO_WORKER)?;
    // The routes a send to this friend takes, Tor last: two phones often
    // reach each other over Tor alone.
    let routes = crate::hints::send_routes(&ctx, peer, raven_core::clock::now_ms());
    let pub_hex = hex::encode(peer);
    let mut last = Err(NO_ROUTE.to_string());
    for (_, route) in routes {
        if route.carrier == OutboxCarrier::Nearby {
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
                OutboxCarrier::Nearby => Err("attachments do not travel over Bluetooth".into()),
            }
        };
        let got = handle.block_on(crate::netutil::INTERNAL_REPLY_BUDGET.scope(
            DIAL_REPLY_BUDGET,
            async {
                tokio::time::timeout(DIAL_DEADLINE, work)
                    .await
                    .unwrap_or_else(|_| Err(DEADLINE.into()))
            },
        ));
        match got {
            Ok(replies) => return Ok(replies),
            Err(e) => last = Err(e),
        }
    }
    last
}

/// One log line when what waits changes (counts only): a photo that does
/// not go says here what it waits for.
fn note_waits(waits: exchange::Waits) {
    static LAST: Mutex<Option<exchange::Waits>> = Mutex::new(None);
    let mut last = LAST.lock().unwrap_or_else(|e| e.into_inner());
    if *last == Some(waits) {
        return;
    }
    *last = Some(waits);
    if waits != exchange::Waits::default() {
        eprintln!(
            "raven-node attachments: waiting: {} for their message to arrive, {} for the next \
             try, {} for a friend's Raven that takes them, {} for their sender",
            waits.offer, waits.turn, waits.friend, waits.push
        );
    }
}

/// What one pass did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PassReport {
    pub(crate) dials: usize,
    /// A dial left more to do right now.
    pub(crate) again: bool,
    /// Something waits for its time or for a friend.
    pub(crate) waiting: bool,
}

/// One dial: the friend and the frames; the replies.
pub(crate) type DialFn<'a> = dyn FnMut(&[u8; 32], &[Vec<u8>]) -> Result<Vec<Vec<u8>>, String> + 'a;

/// One pass: the dials the exchange plans, through `dial`.
pub(crate) fn pass(data_dir: &Path, dial: &mut DialFn<'_>) -> PassReport {
    let exchange = Exchange::new(data_dir, memory());
    // Each friend's record is read once a pass.
    let known: Mutex<HashMap<[u8; 32], bool>> = Mutex::default();
    let speaks = |peer: &[u8; 32]| {
        *known
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(*peer)
            .or_insert_with(|| pinned(data_dir, peer) && peers::speaks(data_dir, peer))
    };
    let planned = exchange.plans(crate::now_ms(), &speaks);
    note_waits(planned.waits);
    let mut report = PassReport {
        waiting: planned.waiting,
        ..PassReport::default()
    };
    for plan in &planned.plans {
        report.dials += 1;
        let started = std::time::Instant::now();
        let got = dial(&plan.peer, &plan.frames);
        // One line a dial: the contact's tag, counts and a code, never an
        // address or a handle.
        let outcome = match &got {
            Ok(replies) => format!("answered ({} replies)", replies.len()),
            Err(e) => format!("failed ({})", failure_words(e)),
        };
        eprintln!(
            "raven-node attachments: contact {}, {} frame(s), {outcome} in {} ms",
            crate::netutil::link_tag(&plan.peer),
            plan.frames.len(),
            started.elapsed().as_millis()
        );
        report.again |= exchange.took(plan, got.as_deref().ok(), crate::now_ms());
    }
    report
}

/// The attachments task (`raven-node service`, supervised): idle while
/// attachments are off; otherwise a pass after every kick and at the
/// intervals above.
pub(crate) async fn run(data_dir: PathBuf) -> Result<(), String> {
    // An offer delivered by this process: its chunks go at once.
    raven_core::attachment::flow::set_delivered_hook(kick);
    if live() {
        eprintln!("raven-node attachments: on (lab)");
    }
    let mut adopted = false;
    let mut next_sweep = tokio::time::Instant::now();
    loop {
        let wait = if live() {
            if tokio::time::Instant::now() >= next_sweep {
                // An attachment goes with its message: what the history no
                // longer holds is removed, at the start and every hour.
                next_sweep = tokio::time::Instant::now() + SWEEP_INTERVAL;
                let dd = data_dir.clone();
                let swept =
                    blocking(move || raven_core::attachment::sweep::sweep(&dd, crate::now_ms()))
                        .await;
                if let Some(Ok(swept)) = swept.filter(|s| s.as_ref().is_ok_and(|s| s.any())) {
                    // Counts only.
                    eprintln!(
                        "raven-node attachments: removed {} with no message, {} unfinished",
                        swept.attachments,
                        swept.blobs + swept.staged
                    );
                }
            }
            if !adopted {
                // Offers a build before this one kept as they came.
                adopted = true;
                let dd = data_dir.clone();
                let rows = blocking(move || {
                    raven_core::attachment::flow::adopt_kept_offers(&dd, crate::now_ms())
                })
                .await;
                if let Some(Ok(rows)) = rows.filter(|r| !matches!(r, Ok(0))) {
                    eprintln!("raven-node attachments: {rows} kept offer(s) taken up");
                }
            }
            let dd = data_dir.clone();
            let handle = tokio::runtime::Handle::current();
            let report = blocking(move || {
                let mut dial =
                    |peer: &[u8; 32], frames: &[Vec<u8>]| dial_peer(&handle, &dd, peer, frames);
                pass(&dd, &mut dial)
            })
            .await
            .unwrap_or_default();
            if report.again {
                continue;
            }
            if report.waiting {
                PASS_WAITING
            } else {
                PASS_IDLE
            }
        } else {
            PASS_OFF
        };
        tokio::select! {
            _ = kicked().notified() => {}
            _ = tokio::time::sleep(wait) => {}
        }
    }
}
