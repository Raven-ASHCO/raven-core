//! The nearby engine (RNL1 §2-§5, §8; Nearby design step 5.5): the one owner
//! of the radio. One task holds every piece of state below; the rest of the
//! node talks to it through an [`EngineHandle`] (commands, and a snapshot for
//! the questions that must not wait: is a pipe up, does a contact have a pair
//! key, what is the status).
//!
//! - **Keys:** an RNB1 pair key ([`raven_core::nearby_link::pair_keys`]) for
//!   each verified, unblocked contact with a valid, non-revoked cached device
//!   certificate, at most [`MAX_KEYS`] ([`Host::load_keys`]). Read again when
//!   the files they come from change ([`Host::stamp`], checked every
//!   [`REFRESH_EVERY`]) and at every epoch. A contact that loses its key
//!   leaves the air and its pipe ends at that refresh.
//! - **Scan:** the tokens every keyed contact advertises for this node at the
//!   epochs next to ours ([`scan_epochs`]). A match is a contact that wants to
//!   deliver to us: the engine connects (at most once per [`CONNECT_GAP`] per
//!   contact), even with nothing to send, and knocks as the central.
//!   Continuous while something is in rotation, a pipe is up, a dial waits or
//!   background mail is on; otherwise [`SCAN_ON`] of every [`SCAN_CYCLE`].
//!   A token whose central knocks failed [`TOKEN_STRIKES`] times in a row
//!   (no CHALLENGE that verifies: a recorded token played back by someone
//!   who is not the contact) is not dialled again while it can match (its
//!   epoch and the next), so a replayer learns once, not again and again,
//!   that a device the token was meant for is in range (review nearby-4).
//!   The count is per token, not per advertising address: the address is
//!   the advertiser's free choice (a new one per advert, or the contact's
//!   own), so a count per address would hand the bound back to the
//!   replayer. A contact whose pipes are all taken answers anyway (see
//!   Pipes), so its knocks no longer count; a knock lost on a weak link
//!   still does.
//! - **Address (O5-12, review nearby-1):** a radio that would use its fixed
//!   public address neither advertises nor connects nor scans: a connect
//!   carries the initiator's address in the clear just as an advert does. A
//!   debug lab run may allow it ([`Host::allow_public_address`]).
//! - **Advertising (O5-12, cutoff addendum F11d):** the rotation is at most
//!   [`MAX_ROTATION`] contacts ([`rotation`]); exactly one of their tokens is
//!   on air, the next one every [`ADV_SLOT`]. A central-only radio publishes
//!   nothing and still dials and receives over the pipes it opens. The
//!   services of the rotation are published, and so is every service a knock
//!   or a pipe still uses (an epoch's service stays while its pipe lives).
//! - **Knock (RNK1, §5):** the central sends HELLO only on a link whose
//!   `max_tx` is at least [`MIN_FRAME`], and PROOF only for a CHALLENGE that
//!   verifies; the peripheral answers only a HELLO that verifies under the
//!   pair of the service it arrived on and is not a replay. Anything else is
//!   silence: [`STRIKES`] silenced frames and the connection is ignored and
//!   dropped. [`KNOCK_DEADLINE`] for each side; at most [`MAX_KNOCKS`]
//!   knocking connections. Only this side's own (central) knocks hold back
//!   a connect to a contact or keep a dial waiting: a peripheral knock is
//!   anyone's in radio range until its HELLO verifies (review nearby-5).
//! - **Pipes:** at most [`MAX_PIPES`], counting the knocks that may still
//!   bring one up (review nearby-6); one more that comes up anyway is reset
//!   with LIMIT. A contact's HELLO that verifies is answered even while the
//!   pipes are all taken, and its pipe is then reset with LIMIT: silence
//!   would count against this node's token at the contact. A dial to a
//!   contact in range that the pipes (this node's, or the contact's LIMIT)
//!   keep out fails `NEARBY_BUSY`, not `NEARBY_NOT_IN_RANGE`. A pipe that
//!   comes up kicks the outbox and tells custody
//!   ([`Host::pipe_up`]); the other side's channel goes to [`Host::inbound`]
//!   (the contact-gated responder). Two pipes for one contact: the one whose
//!   central has the lower identity key survives, and the other is reset
//!   with DUPLICATE.
//!
//! Every limit here bounds what a radio neighbour can make this node hold.
//! Nothing is written at rest; logs carry counts only.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::future::BoxFuture;
use rand::RngCore;
use raven_core::ipc::NearbyStatusInfo;
use raven_core::nearby_link::{
    decode, epoch_of, scan_epochs, CentralKnock, Frame, KnockReplay, PairKeys, PeripheralKnock,
    PipeError, Role, MIN_FRAME,
};
use tokio::io::DuplexStream;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{Instant, MissedTickBehavior};

use super::lock;
use super::pipe::{FrameSink, OnInbound, Pipe, PipeEnd};
use super::radio::{
    ConnId, ConnSink, Privacy, Radio, RadioAddr, RadioCaps, RadioEvent, RadioState, Sent,
    SharedRadio,
};
use super::{
    ADV_SLOT, KNOCK_DEADLINE, NEARBY_BUSY, NEARBY_NOT_IN_RANGE, NEARBY_NOT_RUNNING, SEEN_TTL,
};
use crate::pair_seed::KeyUse;

/// Pipes up at once (RNL1 §8).
pub(crate) const MAX_PIPES: usize = 4;
/// Knocking connections at once (RNL1 §8).
pub(crate) const MAX_KNOCKS: usize = 8;
/// Contacts with a pair key (RNL1 §8: the scan table holds three tokens
/// each).
pub(crate) const MAX_KEYS: usize = 512;
/// Contacts in the advertising rotation (RNL1 §3).
pub(crate) const MAX_ROTATION: usize = 2;
/// One connect per contact this often at most (RNL1 §3).
pub(crate) const CONNECT_GAP: Duration = Duration::from_secs(10);
/// Central knocks on one token that may fail in a row (a connect that never
/// came up, a link too small, a frame before our HELLO, no CHALLENGE that
/// verifies, the link gone) before that token is not dialled again while it
/// can match. The first failure is retried after [`CONNECT_GAP`] (a BlueZ
/// that remembers an ID its device no longer advertises fails once); the
/// contact itself answers. A success forgets the failures (review
/// nearby-4).
pub(crate) const TOKEN_STRIKES: u8 = 2;
/// A connect that has not completed after this is given up.
const CONNECT_WAIT: Duration = Duration::from_secs(10);
/// Silenced knock frames before a peripheral ignores the connection (§5).
pub(crate) const STRIKES: u8 = 3;
/// The engine's clock tick: timers, the advertising slot, the epoch.
const TICK: Duration = Duration::from_millis(500);
/// How often the key files are looked at ([`Host::stamp`]).
pub(crate) const REFRESH_EVERY: Duration = Duration::from_secs(5);
/// How often the contacts with mail waiting are asked for (background mail
/// only).
pub(crate) const WORK_EVERY: Duration = Duration::from_secs(30);
/// The scan duty cycle while nothing needs continuous scanning.
pub(crate) const SCAN_CYCLE: Duration = Duration::from_secs(30);
pub(crate) const SCAN_ON: Duration = Duration::from_secs(10);

/// What tells that the pair keys must be read again: stamps of the files
/// they come from, a generation (the contact book's reload generation) and
/// while pair seeds are live the hour (Phase 6b).
pub(crate) type KeyStamp = (Vec<Option<crate::p2p::FileStamp>>, u64, u64);

/// What the engine needs from the rest of the node; tests give their own.
pub(crate) trait Host: Send + Sync + 'static {
    /// Raven's clock in ms since the epoch (the lab clock in a debug lab
    /// run): the token epoch.
    fn now_ms(&self) -> u64;
    /// [`KeyStamp`] now (cheap: file stats).
    fn stamp(&self) -> KeyStamp;
    /// The pair keys (blocking work behind the future), each with what it
    /// is for: a contact with pair seeds (Phase 6b) has up to three key
    /// sets, one it is advertised for and knocked with. An error is no key
    /// at all: nobody is scanned for, advertised for or answered.
    fn load_keys(&self) -> BoxFuture<'static, Result<Vec<(PairKeys, KeyUse)>, String>>;
    /// The contacts something waits for (cutoff addendum F11d): outbox
    /// objects, owed ACKs, and on a custodian the recipients it holds mail
    /// (custody objects, letters) for and the next hops it holds handoff
    /// rows for. Asked only while background mail is on.
    fn has_work(&self) -> BoxFuture<'static, Vec<[u8; 32]>>;
    /// A pipe to `peer` came up: what waits for it is due now (and, with the
    /// custody gates live, custody on the encounter: a fetch from it, what
    /// it may carry for others, its handoff rows; P5.33).
    fn pipe_up(&self, peer: &[u8; 32]);
    /// The other side opened its channel on the pipe knocked for `peer`:
    /// serve the Raven link on `stream`. Must not wait.
    fn inbound(&self, peer: [u8; 32], stream: DuplexStream);
    /// A debug lab run may advertise and connect from a public address
    /// (`RAVEN_LAB_NEARBY_ALLOW_PUBLIC_ADDR=1`).
    fn allow_public_address(&self) -> bool;
}

enum Cmd {
    PipeFor([u8; 32], oneshot::Sender<Result<Pipe, String>>),
    Want([u8; 32]),
    Foreground([u8; 32], Duration),
    On([u8; 32], Option<Duration>),
    Off([u8; 32]),
    BackgroundMail(bool),
    Keys(KeyStamp, Result<Vec<(PairKeys, KeyUse)>, String>),
    Work(Vec<[u8; 32]>),
    PipeEnded(ConnId, PipeEnd),
    Stop,
}

/// What callers that must not wait read.
#[derive(Default)]
struct Snapshot {
    keyed: HashSet<[u8; 32]>,
    up: HashSet<[u8; 32]>,
    status: NearbyStatusInfo,
}

/// Frames and bytes the pipes sent (their sinks count them).
#[derive(Default)]
struct Counters {
    frames_tx: AtomicU64,
    bytes_tx: AtomicU64,
}

/// A running engine. Clones share it; [`EngineHandle::stop`] ends it.
#[derive(Clone)]
pub(crate) struct EngineHandle {
    cmd: mpsc::UnboundedSender<Cmd>,
    shared: Arc<Mutex<Snapshot>>,
    /// [`Engine::address_private`] at the start (the radio's address
    /// privacy is fixed for its life).
    on_air: bool,
}

impl EngineHandle {
    /// The engine still runs.
    pub(crate) fn is_running(&self) -> bool {
        !self.cmd.is_closed()
    }

    /// The engine's radio may go on the air as itself: it does not use the
    /// adapter's fixed public address, or a debug lab run allows that
    /// (owner decision O5-12, review nearby-1). One that may not neither
    /// advertises, scans nor connects, so it carries nothing: the planners
    /// and custody must not count it (offline mesh carry research, Phase 0:
    /// Windows today, Linux without `Privacy = device`).
    pub(crate) fn may_go_on_air(&self) -> bool {
        self.on_air
    }

    /// The pipe to `peer`: the one up now, else one the engine brings up
    /// within `budget` (a contact seen within [`SEEN_TTL`], or a knock for
    /// it already under way). Otherwise [`NEARBY_NOT_IN_RANGE`], at once.
    pub(crate) async fn pipe_for(&self, peer: [u8; 32], budget: Duration) -> Result<Pipe, String> {
        let (tx, rx) = oneshot::channel();
        self.cmd
            .send(Cmd::PipeFor(peer, tx))
            .map_err(|_| NEARBY_NOT_RUNNING.to_string())?;
        match tokio::time::timeout(budget, rx).await {
            Ok(Ok(found)) => found,
            Ok(Err(_)) => Err(NEARBY_NOT_RUNNING.into()),
            Err(_) => Err(format!(
                "{NEARBY_NOT_IN_RANGE} (no pipe within {} s)",
                budget.as_secs()
            )),
        }
    }

    /// Something is queued for `peer` that nearby could not carry now (RNL1
    /// §3 (a): "there is still queued work").
    pub(crate) fn want(&self, peer: [u8; 32]) {
        let _ = self.cmd.send(Cmd::Want(peer));
    }

    /// The user works with `peer` (a send, an open chat) for `ttl`.
    pub(crate) fn foreground(&self, peer: [u8; 32], ttl: Duration) {
        let _ = self.cmd.send(Cmd::Foreground(peer, ttl));
    }

    /// `raven nearby on`: advertise for `peer` for `ttl` (`None`: until
    /// [`Self::off`]).
    pub(crate) fn on(&self, peer: [u8; 32], ttl: Option<Duration>) {
        let _ = self.cmd.send(Cmd::On(peer, ttl));
    }

    /// `raven nearby off`: stop advertising for `peer` (its foreground and
    /// wants go too).
    pub(crate) fn off(&self, peer: [u8; 32]) {
        let _ = self.cmd.send(Cmd::Off(peer));
    }

    /// node_policy `nearby_background_mail` (cutoff addendum F11d).
    pub(crate) fn set_background_mail(&self, on: bool) {
        let _ = self.cmd.send(Cmd::BackgroundMail(on));
    }

    /// End the engine: every pipe is reset (SHUTDOWN), nothing stays
    /// published, scanning stops and the radio is dropped.
    pub(crate) fn stop(&self) {
        let _ = self.cmd.send(Cmd::Stop);
    }

    /// A pipe to `peer` is up now.
    pub(crate) fn has_pipe(&self, peer: &[u8; 32]) -> bool {
        lock(&self.shared).up.contains(peer)
    }

    /// The engine holds a pair key for `peer`.
    pub(crate) fn has_keys(&self, peer: &[u8; 32]) -> bool {
        lock(&self.shared).keyed.contains(peer)
    }

    /// Counts and states only (never a key, token or address).
    pub(crate) fn status(&self) -> NearbyStatusInfo {
        lock(&self.shared).status.clone()
    }
}

/// Start the engine on `radio` (whose events arrive on `events`) for this
/// node (`me`, its identity key).
pub(crate) fn spawn(
    radio: Box<dyn Radio>,
    events: mpsc::Receiver<RadioEvent>,
    host: Arc<dyn Host>,
    me: [u8; 32],
    background_mail: bool,
) -> (EngineHandle, JoinHandle<()>) {
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let shared = Arc::new(Mutex::new(Snapshot::default()));
    let caps = radio.caps();
    let handle = EngineHandle {
        cmd: cmd_tx.clone(),
        shared: Arc::clone(&shared),
        on_air: address_private(&caps, host.as_ref()),
    };
    let now = Instant::now();
    let epoch = epoch_of(host.now_ms());
    let engine = Engine {
        host,
        me,
        radio: Arc::new(Mutex::new(radio)),
        caps,
        state: RadioState::PoweredOff,
        cmd_tx,
        shared,
        counters: Arc::default(),
        keys: HashMap::new(),
        sets: HashMap::new(),
        stamp: None,
        loading: false,
        reload: false,
        epoch,
        scan: HashMap::new(),
        seen: HashMap::new(),
        fg: HashMap::new(),
        wants: HashMap::new(),
        explicit_on: HashMap::new(),
        background_mail,
        work: Vec::new(),
        work_loading: false,
        rotation: Vec::new(),
        services: HashMap::new(),
        published: None,
        scanning: None,
        knocking: HashMap::new(),
        pipes: HashMap::new(),
        conns: HashMap::new(),
        replay: KnockReplay::new(),
        last_connect: HashMap::new(),
        token_fails: HashMap::new(),
        limited: HashMap::new(),
        waiters: HashMap::new(),
        started: now,
        next_refresh: now + REFRESH_EVERY,
        next_work: now,
        frames_rx: 0,
        bytes_rx: 0,
        knock_silenced: 0,
        overflows: 0,
    };
    let task = tokio::spawn(engine.run(events, cmd_rx));
    (handle, task)
}

/// What the radio publishes: the services (sorted) and the one advert.
type Air = (Vec<[u8; 16]>, Option<[u8; 16]>);

/// One contact seen advertising for this node.
struct Sighting {
    addr: RadioAddr,
    token: [u8; 16],
    at: Instant,
    epoch: u64,
}

/// One knocking connection.
enum Knock {
    /// Central: connecting to `peer`'s service `t`.
    Dialing {
        peer: [u8; 32],
        t: [u8; 16],
        deadline: Instant,
    },
    /// Central: HELLO sent, waiting for the CHALLENGE.
    Hello {
        peer: [u8; 32],
        t: [u8; 16],
        knock: CentralKnock,
        max_tx: usize,
        max_rx: usize,
        deadline: Instant,
    },
    /// Peripheral: a central subscribed to `peer`'s service `t`; waiting
    /// for its HELLO.
    Await {
        peer: [u8; 32],
        t: [u8; 16],
        max_tx: usize,
        max_rx: usize,
        deadline: Instant,
        strikes: u8,
    },
    /// Peripheral: CHALLENGE sent, waiting for the PROOF.
    Challenged {
        peer: [u8; 32],
        t: [u8; 16],
        side: PeripheralKnock,
        max_tx: usize,
        max_rx: usize,
        deadline: Instant,
        strikes: u8,
    },
}

impl Knock {
    fn peer(&self) -> [u8; 32] {
        match self {
            Self::Dialing { peer, .. }
            | Self::Hello { peer, .. }
            | Self::Await { peer, .. }
            | Self::Challenged { peer, .. } => *peer,
        }
    }

    fn deadline(&self) -> Instant {
        match self {
            Self::Dialing { deadline, .. }
            | Self::Hello { deadline, .. }
            | Self::Await { deadline, .. }
            | Self::Challenged { deadline, .. } => *deadline,
        }
    }

    /// The service a peripheral knock runs on.
    fn hosted(&self) -> Option<[u8; 16]> {
        match self {
            Self::Await { t, .. } | Self::Challenged { t, .. } => Some(*t),
            Self::Dialing { .. } | Self::Hello { .. } => None,
        }
    }

    /// The token a central knock (this side's own) dials.
    fn dialled(&self) -> Option<[u8; 16]> {
        match self {
            Self::Dialing { t, .. } | Self::Hello { t, .. } => Some(*t),
            Self::Await { .. } | Self::Challenged { .. } => None,
        }
    }

    /// This side's own knock: it connected as the central.
    fn is_central(&self) -> bool {
        self.dialled().is_some()
    }

    /// A knock that may bring a pipe up without a stranger's help: this
    /// side's own, or a peripheral one whose HELLO verified. An `Await`
    /// (anyone in range can start one) is not.
    fn may_come_up(&self) -> bool {
        !matches!(self, Self::Await { .. })
    }
}

/// One pipe the engine started, and the service it runs on.
struct PipeSlot {
    pipe: Pipe,
    service: [u8; 16],
}

/// A pipe's sink: its connection, counting what it sends.
struct CountingSink {
    inner: ConnSink,
    counters: Arc<Counters>,
}

impl FrameSink for CountingSink {
    fn send(&mut self, frame: &[u8]) -> Result<Sent, String> {
        let sent = self.inner.send(frame);
        if matches!(sent, Ok(Sent::Queued)) {
            self.counters.frames_tx.fetch_add(1, Ordering::Relaxed);
            self.counters
                .bytes_tx
                .fetch_add(frame.len() as u64, Ordering::Relaxed);
        }
        sent
    }

    fn disconnect(&mut self) {
        self.inner.disconnect();
    }
}

/// A token scanned for: the contact advertising for us, its epoch, the key
/// set it is made with and what that set is for (pair seeds, Phase 6b).
type Scanned = ([u8; 32], u64, Arc<PairKeys>, KeyUse);

struct Engine {
    host: Arc<dyn Host>,
    me: [u8; 32],
    radio: SharedRadio,
    caps: RadioCaps,
    state: RadioState,
    cmd_tx: mpsc::UnboundedSender<Cmd>,
    shared: Arc<Mutex<Snapshot>>,
    counters: Arc<Counters>,
    /// Each contact's key set it is advertised for and knocked with.
    keys: HashMap<[u8; 32], Arc<PairKeys>>,
    /// Every key set of each contact, `keys`' included (pair seeds, Phase
    /// 6b: a token made with any of them is the contact's).
    sets: HashMap<[u8; 32], Vec<(Arc<PairKeys>, KeyUse)>>,
    stamp: Option<KeyStamp>,
    /// A key load runs; `reload`: another one is wanted after it.
    loading: bool,
    reload: bool,
    epoch: u64,
    /// Token -> (contact advertising for us, its epoch, the key set the
    /// token was made with and what that set is for).
    scan: HashMap<[u8; 16], Scanned>,
    seen: HashMap<[u8; 32], Sighting>,
    /// Foreground until (a send, an open chat).
    fg: HashMap<[u8; 32], Instant>,
    /// Queued work nearby could not carry yet, until.
    wants: HashMap<[u8; 32], Instant>,
    /// `raven nearby on`, until (`None`: until `off`).
    explicit_on: HashMap<[u8; 32], Option<Instant>>,
    background_mail: bool,
    /// The contacts something waits for (background mail only).
    work: Vec<[u8; 32]>,
    work_loading: bool,
    rotation: Vec<[u8; 32]>,
    /// Token -> (contact, epoch) of every service published now.
    services: HashMap<[u8; 16], ([u8; 32], u64)>,
    /// What the radio was last told.
    published: Option<Air>,
    scanning: Option<bool>,
    knocking: HashMap<ConnId, Knock>,
    /// Contact -> the connection of its pipe.
    pipes: HashMap<[u8; 32], ConnId>,
    /// Every pipe that runs, by connection (a losing duplicate until it
    /// ends too).
    conns: HashMap<ConnId, PipeSlot>,
    replay: KnockReplay,
    last_connect: HashMap<[u8; 32], Instant>,
    /// Token -> central knocks on it that failed in a row
    /// ([`TOKEN_STRIKES`]); only tokens in the scan table are kept.
    token_fails: HashMap<[u8; 16], u8>,
    /// Contacts whose side reset our pipe with LIMIT (its pipes were all
    /// taken), until: a dial to one is busy for [`CONNECT_GAP`], not out
    /// of range.
    limited: HashMap<[u8; 32], Instant>,
    waiters: HashMap<[u8; 32], Vec<oneshot::Sender<Result<Pipe, String>>>>,
    started: Instant,
    next_refresh: Instant,
    next_work: Instant,
    frames_rx: u64,
    bytes_rx: u64,
    knock_silenced: u64,
    /// Radio events dropped so far (a full event queue, RNL1 §8).
    overflows: u64,
}

/// Dropped radio events: one counts-only line per window.
static OVERFLOW_LOG: crate::netutil::LogLimiter =
    crate::netutil::LogLimiter::new(Duration::from_secs(60));

impl Engine {
    async fn run(
        mut self,
        mut events: mpsc::Receiver<RadioEvent>,
        mut cmds: mpsc::UnboundedReceiver<Cmd>,
    ) {
        self.request_keys();
        self.update_air(Instant::now());
        self.publish();
        let mut tick = tokio::time::interval(TICK);
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                cmd = cmds.recv() => match cmd {
                    Some(Cmd::Stop) | None => break,
                    Some(cmd) => self.on_cmd(cmd),
                },
                ev = events.recv() => match ev {
                    Some(ev) => self.on_event(ev),
                    // The radio is gone (its backend ended).
                    None => break,
                },
                _ = tick.tick() => self.on_tick(),
            }
            self.publish();
        }
        self.shutdown();
    }

    fn shutdown(&mut self) {
        for slot in self.conns.values() {
            slot.pipe.reset(PipeError::Shutdown);
        }
        for conn in self.knocking.keys() {
            lock(&self.radio).disconnect(*conn);
        }
        {
            let mut radio = lock(&self.radio);
            let _ = radio.set_services(&[], None);
            let _ = radio.set_scanning(false);
        }
        for (_, waiters) in self.waiters.drain() {
            for w in waiters {
                let _ = w.send(Err(NEARBY_NOT_RUNNING.into()));
            }
        }
        let mut shared = lock(&self.shared);
        shared.up.clear();
        shared.keyed.clear();
    }

    // ── Commands ────────────────────────────────────────────────────────

    fn on_cmd(&mut self, cmd: Cmd) {
        let now = Instant::now();
        match cmd {
            Cmd::PipeFor(peer, reply) => self.pipe_for(peer, reply, now),
            Cmd::Want(peer) => {
                if self.keys.contains_key(&peer) {
                    self.wants.insert(peer, now + super::foreground_ttl());
                }
            }
            Cmd::Foreground(peer, ttl) => {
                if self.keys.contains_key(&peer) {
                    self.fg.insert(peer, now + ttl);
                }
            }
            Cmd::On(peer, ttl) => {
                // Kept before the keys load too (a contact without a key is
                // never on air); bounded like the keys. A TTL past what the
                // clock holds is until `off`.
                if self.explicit_on.len() < MAX_KEYS || self.explicit_on.contains_key(&peer) {
                    self.explicit_on
                        .insert(peer, ttl.and_then(|t| now.checked_add(t)));
                }
            }
            Cmd::Off(peer) => {
                self.explicit_on.remove(&peer);
                self.fg.remove(&peer);
                self.wants.remove(&peer);
            }
            Cmd::BackgroundMail(on) => {
                if on != self.background_mail {
                    self.background_mail = on;
                    self.work.clear();
                    self.next_work = now;
                }
            }
            Cmd::Keys(stamp, keys) => self.keys_loaded(stamp, keys),
            Cmd::Work(work) => {
                self.work_loading = false;
                if self.background_mail {
                    self.work = work;
                }
            }
            Cmd::PipeEnded(conn, end) => self.pipe_ended(conn, end),
            Cmd::Stop => {}
        }
        self.update_air(now);
    }

    fn pipe_for(
        &mut self,
        peer: [u8; 32],
        reply: oneshot::Sender<Result<Pipe, String>>,
        now: Instant,
    ) {
        if let Some(slot) = self.pipes.get(&peer).and_then(|c| self.conns.get(c)) {
            if slot.pipe.is_up() {
                let _ = reply.send(Ok(slot.pipe.clone()));
                return;
            }
        }
        // Our own connect first: a peripheral knock for the contact (which
        // may be anyone's) never holds it back; the dial also waits for one
        // that runs, in case it is the contact's (review nearby-5).
        if self.connect(peer, now) || self.knocking.values().any(|k| k.peer() == peer) {
            self.waiters.entry(peer).or_default().push(reply);
        } else if self.busy(&peer, now) {
            let _ = reply.send(Err(NEARBY_BUSY.into()));
        } else {
            let _ = reply.send(Err(NEARBY_NOT_IN_RANGE.into()));
        }
    }

    /// `peer` is in range (seen within [`SEEN_TTL`]) but cannot be dialled
    /// now because the pipes are taken: this node's ([`MAX_PIPES`] with the
    /// knocks that may still come up, or [`MAX_KNOCKS`]), or the contact's
    /// (it reset our last pipe with LIMIT within [`CONNECT_GAP`]). A dial
    /// then says so rather than "not in range"; the outbox tries again on
    /// its backoff (re-verify of review nearby-6).
    fn busy(&self, peer: &[u8; 32], now: Instant) -> bool {
        let in_range = self
            .seen
            .get(peer)
            .is_some_and(|s| now.saturating_duration_since(s.at) <= SEEN_TTL);
        let ours = self.knocking.len() >= MAX_KNOCKS || self.pipes_and_coming() >= MAX_PIPES;
        let theirs = self.limited.get(peer).is_some_and(|until| *until > now);
        in_range && (ours || theirs)
    }

    /// This side runs a central knock for `peer`.
    fn dialling(&self, peer: &[u8; 32]) -> bool {
        self.knocking
            .values()
            .any(|k| k.is_central() && k.peer() == *peer)
    }

    /// The radio may go on the air as itself: its address is not the
    /// adapter's fixed public one, or a debug lab run allows that (owner
    /// decision O5-12). A connect's CONNECT_IND carries the initiator's
    /// address in the clear just as an advert carries the advertiser's, so
    /// this holds for advertising, connecting and scanning alike (review
    /// nearby-1).
    fn address_private(&self) -> bool {
        address_private(&self.caps, self.host.as_ref())
    }

    /// Pipes up, and knocks that may still bring one up
    /// ([`Knock::may_come_up`]): what [`MAX_PIPES`] bounds (review
    /// nearby-6).
    fn pipes_and_coming(&self) -> usize {
        self.pipes.len() + self.knocking.values().filter(|k| k.may_come_up()).count()
    }

    // ── Keys ────────────────────────────────────────────────────────────

    fn request_keys(&mut self) {
        if self.loading {
            self.reload = true;
            return;
        }
        self.loading = true;
        let stamp = self.host.stamp();
        let load = self.host.load_keys();
        let cmd = self.cmd_tx.clone();
        tokio::spawn(async move {
            let keys = load.await;
            let _ = cmd.send(Cmd::Keys(stamp, keys));
        });
    }

    fn keys_loaded(&mut self, stamp: KeyStamp, keys: Result<Vec<(PairKeys, KeyUse)>, String>) {
        self.loading = false;
        self.stamp = Some(stamp);
        // Fail closed: a book that cannot be read names nobody.
        let mut sets: HashMap<[u8; 32], Vec<(Arc<PairKeys>, KeyUse)>> = HashMap::new();
        for (k, used) in keys.unwrap_or_default() {
            if sets.len() >= MAX_KEYS && !sets.contains_key(&k.peer) {
                continue;
            }
            sets.entry(k.peer).or_default().push((Arc::new(k), used));
        }
        self.keys = sets
            .iter()
            .filter_map(|(peer, v)| {
                v.iter()
                    .find(|(_, used)| used.send)
                    .map(|(k, _)| (*peer, Arc::clone(k)))
            })
            .collect();
        self.sets = sets;
        let gone: Vec<[u8; 32]> = self
            .pipes
            .keys()
            .chain(self.waiters.keys())
            .filter(|p| !self.keys.contains_key(*p))
            .copied()
            .collect();
        for peer in gone {
            if let Some(slot) = self.pipes.remove(&peer).and_then(|c| self.conns.get(&c)) {
                slot.pipe.reset(PipeError::Shutdown);
            }
            self.fail_waiters(&peer);
        }
        let keys = &self.keys;
        self.seen.retain(|p, _| keys.contains_key(p));
        self.fg.retain(|p, _| keys.contains_key(p));
        self.wants.retain(|p, _| keys.contains_key(p));
        self.last_connect.retain(|p, _| keys.contains_key(p));
        // A knock for a contact that lost its key ends here.
        let doomed: Vec<ConnId> = self
            .knocking
            .iter()
            .filter(|(_, k)| !keys.contains_key(&k.peer()))
            .map(|(c, _)| *c)
            .collect();
        for conn in doomed {
            self.knocking.remove(&conn);
            lock(&self.radio).disconnect(conn);
        }
        self.rebuild_scan();
        lock(&self.shared).keyed = self.keys.keys().copied().collect();
        if std::mem::take(&mut self.reload) {
            self.request_keys();
        }
    }

    fn rebuild_scan(&mut self) {
        self.scan.clear();
        for (peer, sets) in &self.sets {
            for (k, used) in sets {
                for e in scan_epochs(self.epoch) {
                    self.scan
                        .insert(k.token_in(e), (*peer, e, Arc::clone(k), *used));
                }
            }
        }
        // A token that can no longer match needs no count.
        let scan = &self.scan;
        self.token_fails.retain(|t, _| scan.contains_key(t));
    }

    /// The key set `peer`'s token `t` was made with (Phase 6b: the contact
    /// may advertise with a set this node accepts but does not send with),
    /// and what it is for; the set `peer` is knocked with when `t` is no
    /// longer scanned for.
    fn keys_for(&self, peer: &[u8; 32], t: &[u8; 16]) -> Option<(Arc<PairKeys>, KeyUse)> {
        match self.scan.get(t) {
            Some((p, _, k, used)) if p == peer => Some((Arc::clone(k), *used)),
            _ => self.keys.get(peer).map(|k| (Arc::clone(k), KeyUse::SEND)),
        }
    }

    // ── Radio events ────────────────────────────────────────────────────

    fn on_event(&mut self, ev: RadioEvent) {
        let now = Instant::now();
        match ev {
            RadioEvent::State(state) => {
                let on = state == RadioState::PoweredOn;
                self.state = state;
                if on {
                    // Tell a radio that came back what it must do.
                    self.published = None;
                    self.scanning = None;
                }
            }
            RadioEvent::Seen { addr, uuids, .. } => {
                for uuid in uuids {
                    let Some(peer) = self.scan.get(&uuid).map(|(peer, ..)| *peer) else {
                        continue;
                    };
                    self.seen.insert(
                        peer,
                        Sighting {
                            addr: addr.clone(),
                            token: uuid,
                            at: now,
                            epoch: self.epoch,
                        },
                    );
                    // The contact wants to deliver to us: connect even with
                    // nothing to send.
                    self.connect(peer, now);
                }
            }
            RadioEvent::Connected {
                conn,
                role: Role::Central,
                max_tx,
                max_rx,
                ..
            } => self.central_connected(conn, max_tx, max_rx, now),
            RadioEvent::Connected {
                conn,
                role: Role::Peripheral,
                service,
                max_tx,
                max_rx,
            } => self.peripheral_connected(conn, service, max_tx, max_rx, now),
            RadioEvent::Frame { conn, bytes } => {
                self.frames_rx += 1;
                self.bytes_rx += bytes.len() as u64;
                if let Some(slot) = self.conns.get(&conn) {
                    // A full queue resets the pipe itself (LIMIT).
                    let _ = slot.pipe.rx(bytes);
                } else if self.knocking.contains_key(&conn) {
                    self.knock_frame(conn, &bytes, now);
                }
            }
            RadioEvent::Writable { conn } => {
                if let Some(slot) = self.conns.get(&conn) {
                    slot.pipe.writable();
                }
            }
            RadioEvent::Disconnected { conn } => {
                if let Some(slot) = self.conns.get(&conn) {
                    slot.pipe.down();
                }
                if let Some(knock) = self.knocking.remove(&conn) {
                    self.knock_ended(&knock, now);
                }
            }
        }
        self.update_air(now);
    }

    /// Connect to `peer` as the central, if it was seen lately and nothing
    /// holds us back (§3, §8). True when a connect for it runs now.
    fn connect(&mut self, peer: [u8; 32], now: Instant) -> bool {
        if self.dialling(&peer) {
            return true;
        }
        if self.pipes.contains_key(&peer)
            || !self.caps.central
            || !self.address_private()
            || self.state != RadioState::PoweredOn
            || !self.keys.contains_key(&peer)
            || self.knocking.len() >= MAX_KNOCKS
            || self.pipes_and_coming() >= MAX_PIPES
            || self
                .last_connect
                .get(&peer)
                .is_some_and(|at| now.saturating_duration_since(*at) < CONNECT_GAP)
        {
            return false;
        }
        let Some(s) = self
            .seen
            .get(&peer)
            .filter(|s| now.saturating_duration_since(s.at) <= SEEN_TTL)
        else {
            return false;
        };
        if self
            .token_fails
            .get(&s.token)
            .is_some_and(|n| *n >= TOKEN_STRIKES)
        {
            return false;
        }
        let (addr, t) = (s.addr.clone(), s.token);
        self.last_connect.insert(peer, now);
        match lock(&self.radio).connect(&addr, t) {
            Ok(conn) => {
                self.knocking.insert(
                    conn,
                    Knock::Dialing {
                        peer,
                        t,
                        deadline: now + CONNECT_WAIT,
                    },
                );
                true
            }
            Err(_) => false,
        }
    }

    fn central_connected(&mut self, conn: ConnId, max_tx: usize, max_rx: usize, now: Instant) {
        let Some(Knock::Dialing { peer, t, .. }) = self.knocking.remove(&conn) else {
            lock(&self.radio).disconnect(conn);
            return;
        };
        let Some((keys, _)) = self.keys_for(&peer, &t) else {
            lock(&self.radio).disconnect(conn);
            return;
        };
        // §4: a side whose max_tx is under 64 does not start the knock.
        if max_tx < MIN_FRAME {
            lock(&self.radio).disconnect(conn);
            self.token_failed(t);
            self.knock_failed(peer, now);
            return;
        }
        let knock = CentralKnock::new(t, nonce());
        if !self.send(conn, &knock.hello(&keys)) {
            lock(&self.radio).disconnect(conn);
            self.token_failed(t);
            self.knock_failed(peer, now);
            return;
        }
        self.knocking.insert(
            conn,
            Knock::Hello {
                peer,
                t,
                knock,
                max_tx,
                max_rx,
                deadline: now + KNOCK_DEADLINE,
            },
        );
    }

    fn peripheral_connected(
        &mut self,
        conn: ConnId,
        service: [u8; 16],
        max_tx: usize,
        max_rx: usize,
        now: Instant,
    ) {
        let Some(&(peer, _)) = self.services.get(&service) else {
            lock(&self.radio).disconnect(conn);
            return;
        };
        // §4: under 64 bytes the peripheral stays silent; §8: at most 8
        // knocking connections.
        if max_tx < MIN_FRAME || self.knocking.len() >= MAX_KNOCKS {
            lock(&self.radio).disconnect(conn);
            return;
        }
        self.knocking.insert(
            conn,
            Knock::Await {
                peer,
                t: service,
                max_tx,
                max_rx,
                deadline: now + KNOCK_DEADLINE,
                strikes: 0,
            },
        );
    }

    fn knock_frame(&mut self, conn: ConnId, bytes: &[u8], now: Instant) {
        let Some(knock) = self.knocking.remove(&conn) else {
            return;
        };
        let peer = knock.peer();
        // A central knocks with the set the contact's token was made with; a
        // peripheral answers with the set it advertises (pair seeds, Phase
        // 6b).
        let found = match &knock {
            Knock::Dialing { t, .. } | Knock::Hello { t, .. } => self.keys_for(&peer, t),
            Knock::Await { .. } | Knock::Challenged { .. } => {
                self.keys.get(&peer).map(|k| (Arc::clone(k), KeyUse::SEND))
            }
        };
        let Some((keys, used)) = found else {
            lock(&self.radio).disconnect(conn);
            return;
        };
        match knock {
            Knock::Dialing { t, .. } => {
                // A frame before our HELLO: not a peripheral that knows the
                // pair.
                lock(&self.radio).disconnect(conn);
                crate::security::knock_failed(super::admission_ip(&peer), true);
                self.token_failed(t);
                self.knock_failed(peer, now);
            }
            Knock::Hello {
                t,
                knock,
                max_tx,
                max_rx,
                ..
            } => {
                let proof = decode(bytes, max_rx)
                    .ok()
                    .and_then(|f| knock.proof(&keys, &f));
                match proof {
                    Some(proof) if self.send(conn, &proof) => {
                        // The CHALLENGE verified: the contact answered.
                        self.token_fails.remove(&t);
                        // The contact advertised with the pair's root while
                        // its seed was expected (a Notice).
                        crate::pair_seed::root_matched(
                            &peer,
                            used,
                            raven_core::security_events::Via::Dial(
                                raven_core::OutboxCarrier::Nearby,
                            ),
                        );
                        self.up(peer, conn, Role::Central, max_tx, max_rx, t);
                    }
                    other => {
                        lock(&self.radio).disconnect(conn);
                        if other.is_none() {
                            // The CHALLENGE did not prove the pair's key.
                            crate::security::knock_failed(super::admission_ip(&peer), true);
                        }
                        self.token_failed(t);
                        self.knock_failed(peer, now);
                    }
                }
            }
            Knock::Await {
                t,
                max_tx,
                max_rx,
                deadline,
                strikes,
                ..
            } => {
                // A HELLO that verifies is answered even while the pipes
                // fill the cap (§8): silence would read, at the contact, as
                // a failed knock against this node's token (review
                // nearby-4), so a full node would bar itself there. Its
                // pipe is reset with LIMIT as it comes up (`up`), which the
                // contact's dial reports as busy.
                let frame = decode(bytes, max_rx);
                let answer = match frame {
                    Ok(f @ Frame::Hello { .. }) => {
                        PeripheralKnock::answer(&keys, t, &f, nonce(), &mut self.replay)
                    }
                    _ => None,
                };
                // Silence for a knock that failed (garbage, another frame, a
                // HELLO that does not prove the pair's key), not for a
                // replayed HELLO or another version's (a full house answers
                // a HELLO that verifies, above).
                let failed = answer.is_none()
                    && match frame {
                        Ok(f @ Frame::Hello { version, .. }) => {
                            version == raven_core::nearby_link::VERSION
                                && !PeripheralKnock::hello_verifies(&keys, &t, &f)
                        }
                        Ok(_) | Err(_) => true,
                    };
                if failed {
                    crate::security::knock_failed(super::admission_ip(&peer), false);
                }
                match answer {
                    Some((side, challenge)) if self.send(conn, &challenge) => {
                        self.knocking.insert(
                            conn,
                            Knock::Challenged {
                                peer,
                                t,
                                side,
                                max_tx,
                                max_rx,
                                deadline: now + KNOCK_DEADLINE,
                                strikes,
                            },
                        );
                    }
                    Some(_) => lock(&self.radio).disconnect(conn),
                    None => self.strike(
                        conn,
                        Knock::Await {
                            peer,
                            t,
                            max_tx,
                            max_rx,
                            deadline,
                            strikes,
                        },
                    ),
                }
            }
            Knock::Challenged {
                t,
                side,
                max_tx,
                max_rx,
                deadline,
                strikes,
                ..
            } => {
                let proved = decode(bytes, max_rx).is_ok_and(|f| side.accepts_proof(&keys, &f));
                if proved {
                    self.up(peer, conn, Role::Peripheral, max_tx, max_rx, t);
                } else {
                    crate::security::knock_failed(super::admission_ip(&peer), false);
                    self.strike(
                        conn,
                        Knock::Challenged {
                            peer,
                            t,
                            side,
                            max_tx,
                            max_rx,
                            deadline,
                            strikes,
                        },
                    );
                }
            }
        }
    }

    /// The peripheral stays silent to a frame of `knock`'s connection; the
    /// third one ends it (§5).
    fn strike(&mut self, conn: ConnId, mut knock: Knock) {
        self.knock_silenced += 1;
        if let Knock::Await { strikes, .. } | Knock::Challenged { strikes, .. } = &mut knock {
            *strikes += 1;
            if *strikes >= STRIKES {
                lock(&self.radio).disconnect(conn);
                return;
            }
        }
        self.knocking.insert(conn, knock);
    }

    /// A central knock on `t` ended without a CHALLENGE that verifies
    /// ([`TOKEN_STRIKES`]).
    fn token_failed(&mut self, t: [u8; 16]) {
        if self.scan.contains_key(&t) {
            let fails = self.token_fails.entry(t).or_insert(0);
            *fails = fails.saturating_add(1);
        }
    }

    /// `knock` (taken out of `knocking`) ended without a pipe: a central
    /// one counts against its token, then [`Self::knock_failed`].
    fn knock_ended(&mut self, knock: &Knock, now: Instant) {
        if let Some(t) = knock.dialled() {
            self.token_failed(t);
        }
        self.knock_failed(knock.peer(), now);
    }

    /// A knock for `peer` ended without a pipe. Dials waiting for it hear
    /// so unless a pipe is up, this side still dials it, a fresh sighting
    /// can be dialled now, or another knock for it still runs (perhaps the
    /// contact's own). A stranger's knock that ends never fails a dial
    /// while the contact can still be reached (review nearby-5).
    fn knock_failed(&mut self, peer: [u8; 32], now: Instant) {
        if !self.waiters.contains_key(&peer)
            || self.pipes.contains_key(&peer)
            || self.connect(peer, now)
            || self.knocking.values().any(|k| k.peer() == peer)
        {
            return;
        }
        self.fail_waiters(&peer);
    }

    fn fail_waiters(&mut self, peer: &[u8; 32]) {
        let why = if self.busy(peer, Instant::now()) {
            NEARBY_BUSY
        } else {
            NEARBY_NOT_IN_RANGE
        };
        for w in self.waiters.remove(peer).unwrap_or_default() {
            let _ = w.send(Err(why.into()));
        }
    }

    /// One knock frame on `conn`; false when the radio did not take it.
    fn send(&mut self, conn: ConnId, frame: &[u8]) -> bool {
        let queued = matches!(lock(&self.radio).send(conn, frame), Ok(Sent::Queued));
        if queued {
            self.counters.frames_tx.fetch_add(1, Ordering::Relaxed);
            self.counters
                .bytes_tx
                .fetch_add(frame.len() as u64, Ordering::Relaxed);
        }
        queued
    }

    // ── Pipes ───────────────────────────────────────────────────────────

    /// The knock on `conn` for `peer` succeeded: the pipe is UP.
    fn up(
        &mut self,
        peer: [u8; 32],
        conn: ConnId,
        role: Role,
        max_tx: usize,
        max_rx: usize,
        service: [u8; 16],
    ) {
        let now = Instant::now();
        let sink = CountingSink {
            inner: ConnSink::new(Arc::clone(&self.radio), conn),
            counters: Arc::clone(&self.counters),
        };
        let host = Arc::clone(&self.host);
        let on_inbound: OnInbound = Box::new(move |_chan, stream| host.inbound(peer, stream));
        let Ok((pipe, task)) = Pipe::start(peer, role, max_tx, max_rx, Box::new(sink), on_inbound)
        else {
            lock(&self.radio).disconnect(conn);
            self.knock_failed(peer, now);
            return;
        };
        let cmd = self.cmd_tx.clone();
        tokio::spawn(async move {
            let end = task.await.unwrap_or(PipeEnd::LinkError);
            let _ = cmd.send(Cmd::PipeEnded(conn, end));
        });
        self.conns.insert(
            conn,
            PipeSlot {
                pipe: pipe.clone(),
                service,
            },
        );
        // §8: never more than MAX_PIPES contacts with a pipe. The knocks are
        // counted when they start; one that came up past the cap anyway
        // ends at once (LIMIT), and the central disconnects (review
        // nearby-6). A second pipe for a contact is the duplicate rule's.
        if !self.pipes.contains_key(&peer) && self.pipes.len() >= MAX_PIPES {
            pipe.reset(PipeError::Limit);
            self.knock_failed(peer, now);
            return;
        }
        // §5: two pipes for one pair: the one whose central has the lower
        // identity key survives; this side resets the other (DUPLICATE).
        if let Some(old) = self.pipes.get(&peer).copied() {
            let central_of = |r: Role| if r == Role::Central { self.me } else { peer };
            let old_role = self.conns.get(&old).map_or(role, |s| s.pipe.role());
            if central_of(role) < central_of(old_role) {
                if let Some(slot) = self.conns.get(&old) {
                    slot.pipe.reset(PipeError::Duplicate);
                }
            } else {
                pipe.reset(PipeError::Duplicate);
                return;
            }
        }
        self.pipes.insert(peer, conn);
        for w in self.waiters.remove(&peer).unwrap_or_default() {
            let _ = w.send(Ok(pipe.clone()));
        }
        // Delivered or not, the pipe now carries what waits: no more need
        // to advertise for it while the pipe lives.
        self.wants.remove(&peer);
        self.host.pipe_up(&peer);
    }

    fn pipe_ended(&mut self, conn: ConnId, end: PipeEnd) {
        let Some(slot) = self.conns.remove(&conn) else {
            return;
        };
        let peer = slot.pipe.peer();
        if self.pipes.get(&peer) == Some(&conn) {
            self.pipes.remove(&peer);
        }
        // The contact's pipes were all taken: dials to it are busy for a
        // while (its next knock is no sooner than CONNECT_GAP anyway).
        if end == PipeEnd::ResetReceived(PipeError::Limit.code()) {
            self.limited.insert(peer, Instant::now() + CONNECT_GAP);
        }
        if slot.pipe.role() == Role::Peripheral {
            // Where the OS lets a peripheral end it.
            lock(&self.radio).disconnect(conn);
        }
    }

    // ── Time ────────────────────────────────────────────────────────────

    fn on_tick(&mut self) {
        let now = Instant::now();
        let epoch = epoch_of(self.host.now_ms());
        if epoch != self.epoch {
            self.epoch = epoch;
            self.rebuild_scan();
            // §5: the replay cache covers the current and previous epoch.
            let keep: HashSet<[u8; 16]> = self
                .keys
                .values()
                .flat_map(|k| [k.token_out(epoch), k.token_out(epoch.saturating_sub(1))])
                .collect();
            self.replay.retain(|t| keep.contains(t));
            self.request_keys();
        } else if now >= self.next_refresh {
            self.next_refresh = now + REFRESH_EVERY;
            if self.stamp.as_ref() != Some(&self.host.stamp()) {
                self.request_keys();
            }
        }
        self.fg.retain(|_, until| *until > now);
        self.wants.retain(|_, until| *until > now);
        self.limited.retain(|_, until| *until > now);
        self.explicit_on
            .retain(|_, until| until.is_none_or(|u| u > now));
        let epoch = self.epoch;
        self.seen
            .retain(|_, s| s.epoch == epoch || now.saturating_duration_since(s.at) <= SEEN_TTL);
        let late: Vec<ConnId> = self
            .knocking
            .iter()
            .filter(|(_, k)| k.deadline() <= now)
            .map(|(c, _)| *c)
            .collect();
        for conn in late {
            if let Some(knock) = self.knocking.remove(&conn) {
                lock(&self.radio).disconnect(conn);
                self.knock_ended(&knock, now);
            }
        }
        self.waiters.retain(|_, ws| {
            ws.retain(|w| !w.is_closed());
            !ws.is_empty()
        });
        let overflows = lock(&self.radio).overflows();
        if overflows > self.overflows {
            crate::netutil::log_limited(
                &OVERFLOW_LOG,
                "raven-node nearby",
                format_args!(
                    "{} radio events dropped (queue full; their connections ended)",
                    overflows - self.overflows
                ),
            );
            self.overflows = overflows;
        }
        if self.background_mail && !self.work_loading && now >= self.next_work {
            self.next_work = now + WORK_EVERY;
            self.work_loading = true;
            let work = self.host.has_work();
            let cmd = self.cmd_tx.clone();
            tokio::spawn(async move {
                let _ = cmd.send(Cmd::Work(work.await));
            });
        }
        self.update_air(now);
    }

    /// Tell the radio what to publish, advertise and scan for now.
    fn update_air(&mut self, now: Instant) {
        let piped = |p: &[u8; 32]| self.pipes.contains_key(p);
        let background: &[[u8; 32]] = if self.background_mail {
            &self.work
        } else {
            &[]
        };
        self.rotation = rotation(
            now,
            self.epoch,
            |p| self.keys.contains_key(p) && !piped(p),
            &self.fg,
            &self.wants,
            &self.explicit_on,
            background,
        );
        // Services in use: a pipe's or a knock's, whatever its epoch (§4:
        // an epoch's service stays while its pipe lives).
        let in_use: HashSet<[u8; 16]> = self
            .conns
            .values()
            .filter(|s| s.pipe.role() == Role::Peripheral)
            .map(|s| s.service)
            .chain(self.knocking.values().filter_map(Knock::hosted))
            .collect();
        let mut services: HashMap<[u8; 16], ([u8; 32], u64)> = self
            .services
            .iter()
            .filter(|(t, _)| in_use.contains(*t))
            .map(|(t, v)| (*t, *v))
            .collect();
        let powered = self.state == RadioState::PoweredOn;
        let private = self.address_private();
        let may_advertise = self.caps.peripheral && powered && private;
        let mut advert = None;
        if may_advertise && !self.rotation.is_empty() {
            let tokens: Vec<[u8; 16]> = self
                .rotation
                .iter()
                .filter_map(|p| self.keys.get(p).map(|k| (p, k.token_out(self.epoch))))
                .map(|(p, t)| {
                    services.insert(t, (*p, self.epoch));
                    t
                })
                .collect();
            let slot = now.saturating_duration_since(self.started).as_secs() / ADV_SLOT.as_secs();
            advert = tokens.get(slot as usize % tokens.len().max(1)).copied();
        }
        if !self.caps.peripheral {
            services.clear();
        }
        let mut list: Vec<[u8; 16]> = services.keys().copied().collect();
        list.sort_unstable();
        self.services = services;
        let want = (list, advert);
        if powered && self.published.as_ref() != Some(&want) {
            let applied = lock(&self.radio).set_services(&want.0, want.1);
            if applied.is_ok() {
                self.published = Some(want);
            }
        }
        let continuous = !self.rotation.is_empty()
            || !self.pipes.is_empty()
            || !self.waiters.is_empty()
            || self.background_mail;
        let cycle = now.saturating_duration_since(self.started).as_secs() % SCAN_CYCLE.as_secs();
        // A radio that may not connect has nothing to scan for.
        let scan = powered
            && self.caps.central
            && private
            && !self.keys.is_empty()
            && (continuous || cycle < SCAN_ON.as_secs());
        if powered && self.scanning != Some(scan) && lock(&self.radio).set_scanning(scan).is_ok() {
            self.scanning = Some(scan);
        }
    }

    fn publish(&self) {
        let epoch = self.epoch;
        let on_air = self.published.as_ref().is_some_and(|p| p.1.is_some());
        let status = NearbyStatusInfo {
            enabled: true,
            gate_live: true,
            radio: state_name(&self.state).into(),
            roles: roles(&self.caps),
            address_privacy: privacy_name(self.caps.address_privacy).into(),
            advertising: u8::from(on_air),
            // What is on air rotates among them; nothing rotates otherwise.
            rotating: if on_air { self.rotation.len() as u8 } else { 0 },
            in_range: self.seen.values().filter(|s| s.epoch == epoch).count() as u32,
            pipes: self.pipes.len() as u32,
            frames_tx: self.counters.frames_tx.load(Ordering::Relaxed),
            frames_rx: self.frames_rx,
            bytes_tx: self.counters.bytes_tx.load(Ordering::Relaxed),
            bytes_rx: self.bytes_rx,
            knock_silenced: self.knock_silenced,
            background_mail: self.background_mail,
        };
        let mut shared = lock(&self.shared);
        shared.up = self.pipes.keys().copied().collect();
        shared.status = status;
    }
}

/// [`Engine::address_private`] for a radio with `caps` on `host`.
fn address_private(caps: &RadioCaps, host: &dyn Host) -> bool {
    caps.address_privacy != Privacy::Public || host.allow_public_address()
}

/// A fresh CSPRNG nonce (RNK1).
fn nonce() -> [u8; 16] {
    let mut n = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut n);
    n
}

/// The advertising rotation at `now` (RNL1 §3, cutoff addendum F11d): at
/// most [`MAX_ROTATION`] contacts that `eligible` admits.
/// 1. Foreground ones: user work (`fg`) while something is still queued
///    for them (`wants`), or `raven nearby on` (`explicit_on`); the most
///    recent first.
/// 2. Then, in the slots left, contacts with mail waiting (`background`,
///    empty unless background mail is on), round-robin by `epoch`: with
///    one slot free eight of them each get a slot within eight epochs (two
///    hours).
pub(crate) fn rotation(
    now: Instant,
    epoch: u64,
    eligible: impl Fn(&[u8; 32]) -> bool,
    fg: &HashMap<[u8; 32], Instant>,
    wants: &HashMap<[u8; 32], Instant>,
    explicit_on: &HashMap<[u8; 32], Option<Instant>>,
    background: &[[u8; 32]],
) -> Vec<[u8; 32]> {
    // (until, key): `None` (until `off`) is the most recent of all.
    let mut fore: Vec<(Option<Instant>, [u8; 32])> = Vec::new();
    let mut add = |peer: [u8; 32], until: Option<Instant>| {
        if !eligible(&peer) {
            return;
        }
        match fore.iter_mut().find(|(_, p)| *p == peer) {
            Some(entry) => {
                entry.0 = match (entry.0, until) {
                    (None, _) | (_, None) => None,
                    (Some(a), Some(b)) => Some(a.max(b)),
                }
            }
            None => fore.push((until, peer)),
        }
    };
    for (peer, until) in fg {
        if *until > now && wants.get(peer).is_some_and(|w| *w > now) {
            add(*peer, Some(*until));
        }
    }
    for (peer, until) in explicit_on {
        if until.is_none_or(|u| u > now) {
            add(*peer, *until);
        }
    }
    fore.sort_by(|a, b| match (a.0, b.0) {
        (None, None) => a.1.cmp(&b.1),
        (None, Some(_)) => std::cmp::Ordering::Less,
        (Some(_), None) => std::cmp::Ordering::Greater,
        (Some(x), Some(y)) => y.cmp(&x).then(a.1.cmp(&b.1)),
    });
    let mut out: Vec<[u8; 32]> = fore
        .into_iter()
        .map(|(_, p)| p)
        .take(MAX_ROTATION)
        .collect();
    let free = MAX_ROTATION - out.len();
    let mut bg: Vec<[u8; 32]> = background
        .iter()
        .filter(|p| eligible(p) && !out.contains(p))
        .copied()
        .collect();
    bg.sort_unstable();
    bg.dedup();
    if free > 0 && !bg.is_empty() {
        let n = bg.len();
        let start = (epoch as usize).wrapping_mul(free) % n;
        for i in 0..free.min(n) {
            out.push(bg[(start + i) % n]);
        }
    }
    out
}

/// [`NearbyStatusInfo::radio`] of a radio state
/// ([`raven_core::ipc::NEARBY_RADIO_STATES`]).
pub(crate) fn state_name(state: &RadioState) -> &'static str {
    match state {
        RadioState::PoweredOn => "powered_on",
        RadioState::PoweredOff => "off",
        RadioState::Unauthorized(_) => "unauthorized",
        RadioState::Unsupported(why) => super::radio::unsupported_kind(why),
    }
}

fn privacy_name(p: Privacy) -> &'static str {
    match p {
        Privacy::Random => "random",
        Privacy::Public => "public",
        Privacy::Unknown => "unknown",
    }
}

fn roles(caps: &RadioCaps) -> Vec<String> {
    let mut out = Vec::new();
    if caps.central {
        out.push("central".to_string());
    }
    if caps.peripheral {
        out.push("peripheral".to_string());
    }
    out
}

#[cfg(test)]
mod tests;
