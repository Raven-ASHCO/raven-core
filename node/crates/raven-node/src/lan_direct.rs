//! Direct LAN TCP: Noise XX + RLB1 + inbound PairInit/message/ACK dispatch.
//!
//! The dialer's signed bind comes first; the listener sends its own bind and
//! RLB1 only to a dialer whose bind names a local, unblocked contact, and
//! closes on anyone else before revealing its identity or prekey bundle.
//!
//! This path does not use `bridge_run` fanout. The listener loads the local
//! identity once at start; unauthenticated connections never touch the
//! identity lock / secret store, and all SQLite / file work for a connection
//! runs on the blocking pool. The pre-auth handshake has its own short
//! deadline, so an idle connection cannot sit on a slot for the session
//! lifetime.
//!
//! **Route hints** (RRH1, [`crate::hints`]; route hints live only): a dialer
//! that has frames to send asks for them with RLX1 as its Noise XX message 3
//! payload (m3 grows from 64 to 75 bytes; older listeners decrypt and drop
//! it). The listener parses it only after the contact gate and then sends its
//! RRH1 right after its RLB1; the dialer answers with its own as soon as that
//! arrives. Neither side ever sends one unasked, and an RRH1 is never a
//! reply: with the gate off it closes the link as any non-RVN1 frame does.
//!
//! **Link padding** (PAD1, [`crate::link`]; link padding live only): the
//! same dials (those that read) offer caps bit 9 in RLX1 too. The listener
//! pads every frame from its bind on when the dialer offered it; the dialer
//! reads padded frames from the start and pads its own once the listener's
//! first one arrived (its bind, 96 bytes, goes first and bare). With the gate
//! off every byte after the handshake is as before.
//!
//! **Noise pins** (M0, [`raven_core::lan_noise_pin`]; live only with
//! [`raven_core::lan_gate::lan_noise_pin_live`]): a dial that holds a pin for
//! its contact reads the responder's static after Noise message 2 and stops
//! before message 3 when another key answered ([`NOISE_PIN_MISMATCH`]), so
//! whatever answers at a friend's old address learns nothing but message 1.
//! A link that authenticated a contact records its static (the dialer after
//! the responder's bind, the listener for a contact's inbound link).
//!
//! **Listening** (Phase 3, D7; [`BindPlan`]): `--lan-listen auto` binds
//! `0.0.0.0` and `[::]` (a socket each) and admits local sources only while
//! its gate is live ([`raven_core::lan_auto_live`]); until then it is
//! `0.0.0.0:<port>` for any source, as before. A connection the source rule
//! refuses is closed before a byte and before admission. `raven lan off`
//! ([`set_lan_on`]) closes the port and its connections at once; `on` binds
//! again, and meeting mode (`raven lan on --for`, P3.C2) turns it off at
//! its time ([`crate::lan_meeting`]).
//!
//! **Verified friends only** (Phase 3 P3.C2, `raven lan verified-only on`,
//! read from node_policy.json at each link): the contact gate admits
//! verified (pinned) contacts only
//! ([`raven_core::lan_dispatch::LINK_REFUSED_VERIFIED_ONLY`]), and a dial to
//! an unverified contact is refused before it connects
//! ([`VERIFIED_ONLY_DIAL`]).

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::Duration;

use raven_core::identity::Identity;
use raven_core::lan_dispatch::{
    cache_peer_bundle, encode_local_offer, lan_peer_blocked, parse_peer_offer,
    remember_ephemeral_peer, rlb1_matches_noise_identity,
};
use raven_core::lan_noise::{
    build_initiator, build_responder, build_responder_with_static, derive_noise_static,
    encode_bind, get_remote_static, handshake_read, handshake_write, into_transport,
    noise_static_public, static_public, verify_bind, LanNoiseError, MAX_TRANSPORT_PLAINTEXT,
};
use raven_core::lan_noise_pin::{pin_digest, PinKey};
use raven_core::link_knock::DialerStep;
use raven_core::link_padding::PadState;
use raven_core::load_identity_required;
use raven_core::paths::LanListen;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

use crate::learning::DialMeta;
use crate::link::LinkCipher;
use crate::link_knock::{DialKnock, Ear, Knocked};
use crate::netutil::{
    self, AdmissionSlot, DialProgress, InboundLimits, ReplyWait, CONNECT_BUDGET, PEER_CLOSED,
};

/// One Noise message at most (snow rejects longer); checked before allocating.
const MAX_FRAME: usize = raven_core::lan_noise::MAX_NOISE_MSG;
const IO_TIMEOUT: Duration = Duration::from_secs(30);
/// The whole dial, below the 45 s IPC cap so the caller gets this module's
/// precise error (or the replies already collected) instead of a bare timeout.
const DIAL_DEADLINE: Duration = Duration::from_secs(40);
const READ_TIMEOUT: &str = "lan read timeout";
/// The security events classify these two texts (Phase 6b S2).
const HANDSHAKE_TIMEOUT: &str = raven_core::security_events::LAN_HANDSHAKE_TIMEOUT;
const FRAME_LENGTH: &str = raven_core::security_events::LAN_FRAME_LENGTH;

/// M0: another key answered a dial whose contact has a noise pin. The dial
/// ended after Noise message 2, before our static and our signed identity
/// bind. Never retried ([`netutil::with_handshake_retries`] retries only a
/// hang-up); no address or key in it.
pub(crate) const NOISE_PIN_MISMATCH: &str = "lan noise pin mismatch: a different key answered \
    at this address; RAVEN stopped before identifying this computer";
/// `raven lan verified-only on` (Phase 3 P3.C2) holds and the contact is not
/// verified: the dial was refused before connecting (the local code
/// `LAN_VERIFIED_ONLY` first; the outbox holds it as `CONTACT_NOT_VERIFIED`).
pub(crate) const VERIFIED_ONLY_DIAL: &str = "LAN_VERIFIED_ONLY: this contact is not verified, \
    and only verified contacts may link on the LAN (raven lan verified-only off allows every \
    contact); nothing was dialled";
/// M0: the pin store exists but cannot be read, so the route is not dialled.
/// [`NoisePins::load`] adds which file and the I/O kind (`: lan_noise_pins.json:
/// permission denied`); the outbox holds it as `PIN_STORE_UNREADABLE`.
pub(crate) const NOISE_PIN_UNAVAILABLE: &str = "lan noise pin unavailable";

/// Whether a link reads and writes noise pins (M0). Production passes
/// [`NoisePins::current`]; tests name the gate, so a gate-closed test stays
/// valid after the flip.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NoisePins {
    pub(crate) live: bool,
}

impl NoisePins {
    pub(crate) fn current() -> Self {
        Self {
            live: raven_core::lan_gate::lan_noise_pin_live(),
        }
    }

    /// Blocking: the pin a dial to `contact` checks (one small file read).
    /// Gate closed: nothing is read. An unreadable store ends the dial.
    pub(crate) fn load(
        self,
        data_dir: &Path,
        contact: &[u8; 32],
    ) -> Result<Option<[u8; 32]>, String> {
        if !self.live {
            return Ok(None);
        }
        raven_core::lan_noise_pin::load_pin(data_dir, contact)
            .map_err(|e| format!("{NOISE_PIN_UNAVAILABLE}: {e}"))
    }

    /// A link authenticated `contact` with `noise_static`: pin it under
    /// `identity`'s pin key on the blocking pool (best effort). Nothing when
    /// the gate is closed or when `pinned` (the pin the dial checked) already
    /// says so.
    pub(crate) async fn record(
        self,
        data_dir: &Path,
        identity: &Identity,
        contact: [u8; 32],
        noise_static: [u8; 32],
        pinned: Option<[u8; 32]>,
    ) {
        if !self.live {
            return;
        }
        let key = PinKey::derive(identity);
        if pinned == Some(pin_digest(&key, &contact, &noise_static)) {
            return;
        }
        let dd = data_dir.to_path_buf();
        let _ = blocking(move || {
            raven_core::lan_noise_pin::record(&dd, &key, &contact, &noise_static).map(drop)
        })
        .await;
    }
}

/// M0, between Noise messages 2 and 3: with a pin for `expected`, the
/// responder's static (known after message 2 of XX) must be the pinned one
/// (the pin is keyed by this computer's `identity`).
pub(crate) fn check_noise_pin(
    identity: &Identity,
    pinned: Option<&[u8; 32]>,
    expected: &[u8; 32],
    remote_static: &[u8; 32],
) -> Result<(), String> {
    match pinned {
        Some(pin) if *pin != pin_digest(&PinKey::derive(identity), expected, remote_static) => {
            Err(NOISE_PIN_MISMATCH.to_string())
        }
        _ => Ok(()),
    }
}

async fn blocking<T, F>(work: F) -> Result<T, String>
where
    F: FnOnce() -> Result<T, String> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|e| format!("lan_direct blocking join: {e}"))?
}

const PRODUCTION_LIMITS: InboundLimits = netutil::PRODUCTION_INBOUND;

fn frame_budget_allows(frames_seen: &mut u32, max_frames: u32) -> bool {
    *frames_seen = frames_seen.saturating_add(1);
    *frames_seen <= max_frames
}

fn locked<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

static LISTENER_UP: AtomicBool = AtomicBool::new(false);
/// Where the listener is bound while it is up, IPv4 first (the IPC `Status`
/// names them, so `ash listen` can tell this profile's port from another
/// profile's). `auto` binds one socket per address family.
static LISTEN_ADDR: Mutex<Vec<SocketAddr>> = Mutex::new(Vec::new());

pub fn listener_is_up() -> bool {
    LISTENER_UP.load(Ordering::Relaxed)
}

/// The address the LAN listener is bound to: its IPv4 one (a fixed IPv6
/// address has only that one); `None` while it is down or still starting.
/// `Status.lan_listen`, `ash listen` and the route hints' LAN_PORT read it.
pub fn listener_addr() -> Option<SocketAddr> {
    let addrs = locked(&LISTEN_ADDR);
    addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| addrs.first())
        .copied()
}

/// Every address the LAN listener is bound to, IPv4 first; empty while it
/// is down, still starting or off (`raven lan off`).
pub(crate) fn listener_addrs() -> Vec<SocketAddr> {
    locked(&LISTEN_ADDR).clone()
}

/// Why the last bind of the LAN listener failed, while it is down: the
/// address it is set to (`wanted`) and the kind, one of raven_core::ipc's
/// `LAN_BIND_*` tokens ([`bind_error_kind`]). The IPC `Status` names both,
/// so `ash status` can say "that address is not on this computer now"
/// instead of "busy port?". Cleared once a bind succeeds
/// ([`listeners_bound`]) and while LAN is off. One per address family: this
/// one is IPv4's (and a name's), [`LAN_BIND_V6`] IPv6's.
static LAN_BIND: Mutex<(Option<String>, Option<&'static str>)> = Mutex::new((None, None));
/// [`LAN_BIND`] for an IPv6 address: a fixed `[..]:port`, or `auto`'s
/// `[::]:port`, which it does without (IPv4 only) when that bind fails.
static LAN_BIND_V6: Mutex<(Option<String>, Option<&'static str>)> = Mutex::new((None, None));

/// The address the LAN listener could not bind and why (a `LAN_BIND_*`
/// token), IPv4's first: both `None` while it is up, before its first bind,
/// and once a bind succeeded.
pub fn bind_error() -> (Option<String>, Option<&'static str>) {
    let v4 = locked(&LAN_BIND).clone();
    if v4.1.is_some() {
        return v4;
    }
    locked(&LAN_BIND_V6).clone()
}

/// A failed bind's kind, as `Status.lan_bind_error` names it.
fn bind_error_kind(e: &std::io::Error) -> &'static str {
    use raven_core::ipc::{
        LAN_BIND_ADDR_NOT_HERE, LAN_BIND_DENIED, LAN_BIND_IN_USE, LAN_BIND_OTHER,
    };
    match e.kind() {
        std::io::ErrorKind::AddrNotAvailable => LAN_BIND_ADDR_NOT_HERE,
        std::io::ErrorKind::AddrInUse => LAN_BIND_IN_USE,
        std::io::ErrorKind::PermissionDenied => LAN_BIND_DENIED,
        _ => LAN_BIND_OTHER,
    }
}

/// Note that binding `wanted` failed, of `kind` (a `LAN_BIND_*` token), for
/// its address family: a bracketed address is IPv6, anything else (a name
/// too) IPv4.
pub(crate) fn record_bind_error(wanted: &str, kind: &'static str) {
    let family = if wanted.trim_start().starts_with('[') {
        &LAN_BIND_V6
    } else {
        &LAN_BIND
    };
    *locked(family) = (Some(wanted.to_owned()), Some(kind));
}

/// Forget why binds failed: the listener is up, or LAN is off.
fn clear_bind_errors() {
    for family in [&LAN_BIND, &LAN_BIND_V6] {
        *locked(family) = (None, None);
    }
}

/// Note why binding `lan_listen` failed ([`bind_error`]) and say it in the
/// words the service log has always had (the terminal app reads them).
fn bind_failed(lan_listen: &str, e: &std::io::Error) -> String {
    record_bind_error(lan_listen, bind_error_kind(e));
    format!("lan_direct bind {lan_listen}: {e}")
}

/// Bind the LAN listener on `lan_listen`, recording why it failed
/// ([`bind_error`]) until a later bind succeeds. A named IPv6 zone
/// (`[fe80::1%en0]:7420`) is bound by its interface's index (B-5: std reads
/// only a numeric one, and the text alone would go to the resolver).
async fn bind_listener(lan_listen: &str) -> Result<TcpListener, String> {
    let bound = match raven_core::netifs::scoped_v6_socket(lan_listen) {
        Some(Ok(addr)) => TcpListener::bind(addr).await,
        Some(Err(why)) => Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, why)),
        None => TcpListener::bind(lan_listen).await,
    };
    bound.map_err(|e| bind_failed(lan_listen, &e))
}

/// Record the listener as up on `addrs` (a plan's sockets: `auto` has an
/// IPv4 and an IPv6 one), IPv4 first, until the returned guard drops. Its
/// port is in this node's route hints: the announcer looks again
/// ([`crate::hints::own_changed`]), here and when the guard drops.
pub(crate) fn listeners_bound(mut addrs: Vec<SocketAddr>) -> ListenerGuard {
    addrs.sort_by_key(|a| !a.is_ipv4());
    clear_bind_errors();
    *locked(&LISTEN_ADDR) = addrs;
    LISTENER_UP.store(true, Ordering::Relaxed);
    crate::hints::own_changed();
    ListenerGuard
}

/// [`listeners_bound`] on one address (tests).
#[cfg(test)]
pub(crate) fn listener_bound(local: SocketAddr) -> ListenerGuard {
    listeners_bound(vec![local])
}

pub(crate) struct ListenerGuard;
impl Drop for ListenerGuard {
    fn drop(&mut self) {
        LISTENER_UP.store(false, Ordering::Relaxed);
        locked(&LISTEN_ADDR).clear();
        crate::hints::own_changed();
    }
}

/// The listener state above is process-wide: a test that starts a listener, or
/// asserts that none runs, holds this so parallel tests do not see each other's.
#[cfg(test)]
pub(crate) fn listener_state_test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

// ── `raven lan on|off` and `--lan-listen` (Phase 3, D7) ─────────────────────

/// `raven lan off|on` in this process ([`set_lan_on`]): the listener is bound
/// only while it is on, and the connections it accepted end when it turns
/// off. On until set, except in a debug lab run that carries over nearby
/// alone ([`raven_core::nearby_only`]): off from the start and for good.
static LAN_ON: OnceLock<watch::Sender<bool>> = OnceLock::new();

fn lan_switch() -> &'static watch::Sender<bool> {
    LAN_ON.get_or_init(|| watch::Sender::new(lan_on_allowed(true, raven_core::nearby_only())))
}

/// The LAN switch a request for `on` leaves: off whatever was asked while
/// this process carries over nearby alone (`nearby_only`, a debug lab
/// switch), so neither `raven lan on` nor a meeting time binds a LAN port
/// there.
fn lan_on_allowed(on: bool, nearby_only: bool) -> bool {
    on && !nearby_only
}

/// Turn the LAN carrier on or off in this process, at once: the listener
/// closes its port and its connections, or binds again; raven-core's switch
/// ([`raven_core::set_lan_user_off`]) holds LAN dials and custody links
/// over LAN. raven-node sets it from node_policy.json at start and on IPC
/// `SetLan` (ash writes the policy). Turned on, the outbox's `lan_off`
/// reasons go ([`crate::delivery_paths::lan_back`]).
pub(crate) fn set_lan_on(on: bool) {
    let on = lan_on_allowed(on, raven_core::nearby_only());
    raven_core::set_lan_user_off(!on);
    lan_switch().send_replace(on);
    if on {
        crate::delivery_paths::lan_back();
    }
}

/// Whether LAN is on in this process ([`set_lan_on`]).
pub(crate) fn lan_on() -> bool {
    *lan_switch().borrow()
}

/// The LAN switch ([`set_lan_on`]) to wait on: the LAN beacon
/// ([`crate::lan_beacon`]) opens its sockets while it is on and closes them
/// when it turns off.
#[cfg(any(unix, windows))]
pub(crate) fn lan_watch() -> watch::Receiver<bool> {
    lan_switch().subscribe()
}

/// What `--lan-listen` binds ([`BindPlan::of`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum BindPlan {
    /// `auto` while its gate is live ([`raven_core::lan_auto_live`]):
    /// `0.0.0.0:port` and `[::]:port`, one socket each
    /// ([`bind_auto_socket`]), local sources only.
    Auto { port: u16 },
    /// One address, any source: the `--lan-listen` value as given, or `auto`
    /// while its gate is closed (`0.0.0.0:port`, as before Phase 3).
    One { addr: String, auto: bool },
}

impl BindPlan {
    /// `--lan-listen` as this build binds it, `auto_live` being
    /// [`raven_core::lan_auto_live`]. Blank, or `auto:` without a port, is
    /// an error ([`raven_core::paths::parse_lan_listen`]).
    pub(crate) fn of(lan_listen: &str, auto_live: bool) -> Result<BindPlan, String> {
        Ok(match raven_core::paths::parse_lan_listen(lan_listen)? {
            LanListen::Auto { port } if auto_live => BindPlan::Auto { port },
            LanListen::Auto { port } => BindPlan::One {
                addr: format!("0.0.0.0:{port}"),
                auto: true,
            },
            LanListen::Fixed(addr) => BindPlan::One { addr, auto: false },
        })
    }

    /// Whom its sockets admit; `deny_loopback` is the debug lab switch
    /// ([`raven_core::lan_gate::lab_lan_source_deny_loopback`]).
    fn rule(&self, deny_loopback: bool) -> SourceRule {
        match self {
            BindPlan::Auto { .. } => SourceRule::LocalOnly { deny_loopback },
            BindPlan::One { .. } => SourceRule::Any,
        }
    }

    /// `Status.lan.mode` while LAN is on.
    fn mode(&self) -> &'static str {
        use raven_core::ipc::{LAN_MODE_FIXED, LAN_MODE_ON, LAN_MODE_THIS_COMPUTER};
        match self {
            BindPlan::Auto { .. } | BindPlan::One { auto: true, .. } => LAN_MODE_ON,
            BindPlan::One { addr, .. } if listen_is_loopback(addr) => LAN_MODE_THIS_COMPUTER,
            BindPlan::One { .. } => LAN_MODE_FIXED,
        }
    }
}

/// A fixed `--lan-listen` that only this computer reaches (CP.5's loopback
/// row): a loopback address, or `localhost`.
fn listen_is_loopback(addr: &str) -> bool {
    addr.parse::<SocketAddr>()
        .map(|a| a.ip().to_canonical().is_loopback())
        .unwrap_or_else(|_| addr.starts_with("localhost"))
}

/// Whom a LAN listener's sockets admit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SourceRule {
    /// Any source: a fixed `--lan-listen`, and `auto` while its gate is
    /// closed (as before Phase 3).
    Any,
    /// Local sources only ([`raven_core::paths::lan_source_is_local`]):
    /// loopback, private, link-local, unique-local, or on one of this
    /// computer's networks ([`on_link`]); 100.64.0.0/10 is not local (owner
    /// decision). `deny_loopback` (debug lab switch, harness case C27)
    /// counts loopback as not local.
    LocalOnly { deny_loopback: bool },
}

impl SourceRule {
    fn admits(self, ip: IpAddr) -> bool {
        match self {
            SourceRule::Any => true,
            SourceRule::LocalOnly { deny_loopback } => {
                !(deny_loopback && ip.to_canonical().is_loopback())
                    && raven_core::paths::lan_source_is_local(ip, on_link)
            }
        }
    }
}

/// Whether `ip` is on one of this computer's networks
/// ([`crate::lan_ifaces::on_link`]; also the penalty box's key rule,
/// `crate::security::penalty_key`).
pub(crate) fn on_link(ip: IpAddr) -> bool {
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

/// Connections a listener closed because their source is not local
/// ([`SourceRule::LocalOnly`]), since raven-node started.
static NON_LOCAL_REFUSED: AtomicU64 = AtomicU64::new(0);
/// At most one line an hour about them, with counts only: never the address
/// (any host that reaches the port could otherwise write to the service log,
/// which users back up and sync).
static NON_LOCAL_LOG: netutil::LogLimiter = netutil::LogLimiter::new(Duration::from_secs(3600));

/// The service log's words for [`NON_LOCAL_REFUSED`] (`total` so far).
fn non_local_note(total: u64) -> String {
    format!(
        "closed a connection from outside the local network before reading it \
         ({total} since start; `auto` admits local sources only)"
    )
}

fn note_non_local_refused() {
    let total = NON_LOCAL_REFUSED.fetch_add(1, Ordering::Relaxed) + 1;
    netutil::log_limited(&NON_LOCAL_LOG, "lan_direct", non_local_note(total));
}

/// A plan's bound sockets, IPv4 first, and whom they admit.
struct Listeners {
    sockets: Vec<TcpListener>,
    rule: SourceRule,
}

impl Listeners {
    /// The addresses its sockets are bound to, IPv4 first.
    fn local_addrs(&self) -> Vec<SocketAddr> {
        self.sockets
            .iter()
            .filter_map(|s| s.local_addr().ok())
            .collect()
    }

    /// The next connection the rule admits, from whichever socket has one.
    /// One it refuses is closed at once: before a byte is read or written
    /// and before admission ([`netutil::Admission`]), so it holds no slot.
    async fn accept(&self) -> std::io::Result<(TcpStream, SocketAddr)> {
        loop {
            let (stream, source) = match self.sockets.as_slice() {
                [only] => only.accept().await?,
                [v4, v6] => tokio::select! {
                    accepted = v4.accept() => accepted?,
                    accepted = v6.accept() => accepted?,
                },
                // Never: a plan binds one socket or two.
                _ => std::future::pending().await,
            };
            if self.rule.admits(source.ip()) {
                return Ok((stream, source));
            }
            drop(stream);
            note_non_local_refused();
        }
    }
}

/// The `auto` sockets' listen backlog.
const AUTO_BACKLOG: i32 = 128;

/// Logged once: `auto` runs on IPv4 only here.
static IPV6_UNAVAILABLE_SAID: AtomicBool = AtomicBool::new(false);

/// What the node log says of macOS refusing this process's LAN connections
/// (its Local Network permission, [`raven_core::outbox::local_network_refused`]).
static LOCAL_NETWORK: Mutex<LocalNetworkWatch> = Mutex::new(LocalNetworkWatch::new());

/// A refusal this quick is macOS's own, not a router's or a dead host's.
const REFUSED_AT_ONCE: Duration = Duration::from_secs(1);
/// Distinct addresses on this computer's own networks refused at once, with
/// no LAN connection through since, before the log says macOS refuses them.
const REFUSED_TO_SAY: usize = 2;
/// ... and for at least this long (E2, mac-b on a new build: macOS refused a
/// newly started raven-node's first LAN connections for some seconds, and
/// the log said so and took it back twice within 21 s, while `nc` went
/// through).
const REFUSED_FOR: Duration = Duration::from_secs(30);
/// For this long after raven-node started, a LAN connect macOS refuses at
/// once is tried again ([`REFUSED_RETRY_EVERY`]) instead of failing the
/// dial: macOS lets a new binary (each rebuild is a new ad-hoc signature)
/// onto the local network only after a few seconds.
const START_GRACE: Duration = Duration::from_secs(30);
/// The pause between those tries.
const REFUSED_RETRY_EVERY: Duration = Duration::from_secs(1);

/// When this raven-node started ([`note_process_start`]; first use
/// otherwise).
static PROCESS_START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();

/// `raven-node service` started now: the clock of [`START_GRACE`].
pub(crate) fn note_process_start() {
    let _ = PROCESS_START.set(std::time::Instant::now());
}

fn since_process_start() -> Duration {
    PROCESS_START.get_or_init(std::time::Instant::now).elapsed()
}

/// Whether a LAN connect that failed with `connect_error` after `took`, at
/// `uptime` since raven-node started, is tried again after
/// [`REFUSED_RETRY_EVERY`] (pure): macOS refused it at once ("No route to
/// host" for a local-network address within [`REFUSED_AT_ONCE`]) and the
/// node is inside [`START_GRACE`] still after that pause. Past it a refusal
/// fails the dial and counts for the warning, as before.
fn retry_refused_at_start(connect_error: &str, took: Duration, uptime: Duration) -> bool {
    took < REFUSED_AT_ONCE
        && uptime + REFUSED_RETRY_EVERY < START_GRACE
        && !raven_core::outbox::local_network_refused_at(connect_error).is_empty()
}

/// Whether macOS refuses this process's LAN connections, as the dials show
/// it (pure: the caller says whether a refusal came at once, whether an
/// address is on this computer's own networks, and the time). E1: one saved
/// address on another subnet (a friend's old one) was refused for real at
/// start, and the log said macOS refused every LAN connection while all of
/// them went through. Only refusals at once, of addresses on this computer's
/// own networks, count, from [`REFUSED_TO_SAY`] distinct ones on, and only
/// once they have lasted [`REFUSED_FOR`] with no LAN connection through (E2:
/// a new binary is refused for some seconds after it starts). A LAN
/// connection that goes through clears them, and takes back what was said:
/// one warning, one all-clear.
#[derive(Debug)]
struct LocalNetworkWatch {
    /// Refused at once since the last LAN connection went through (at most
    /// a few).
    refused: Vec<IpAddr>,
    /// The first of those refusals.
    since: Option<std::time::Instant>,
    /// The log said so, and has not taken it back.
    said: bool,
}

impl LocalNetworkWatch {
    const fn new() -> Self {
        Self {
            refused: Vec::new(),
            since: None,
            said: false,
        }
    }

    /// A LAN connect refused `ips` with "No route to host" at `now`;
    /// `at_once`: it failed within [`REFUSED_AT_ONCE`]. `true`: say it now.
    fn refused(
        &mut self,
        ips: &[IpAddr],
        at_once: bool,
        on_link: impl Fn(IpAddr) -> bool,
        now: std::time::Instant,
    ) -> bool {
        if !at_once {
            return false;
        }
        let mut counted = false;
        for ip in ips.iter().filter(|ip| on_link(**ip)) {
            counted = true;
            if !self.refused.contains(ip) && self.refused.len() < REFUSED_TO_SAY * 4 {
                self.refused.push(*ip);
            }
        }
        if !counted {
            return false;
        }
        let since = *self.since.get_or_insert(now);
        if self.said
            || self.refused.len() < REFUSED_TO_SAY
            || now.saturating_duration_since(since) < REFUSED_FOR
        {
            return false;
        }
        self.said = true;
        true
    }

    /// A LAN connection to a local-network address went through: macOS lets
    /// this process connect. `true`: take back what was said.
    fn connected(&mut self) -> bool {
        self.refused.clear();
        self.since = None;
        std::mem::take(&mut self.said)
    }
}

/// A LAN dial's connect failed with `connect_error` after `took`: say in the
/// node log when it shows that macOS refuses this process's LAN connections
/// ([`LocalNetworkWatch`]): every LAN dial of this process then fails the
/// same way until it is started again with the permission, and the dial
/// errors alone read like a contact who is away.
fn say_local_network_refused(connect_error: &str, took: Duration) {
    let ips = raven_core::outbox::local_network_refused_at(connect_error);
    if ips.is_empty() {
        return;
    }
    let say = locked(&LOCAL_NETWORK).refused(
        &ips,
        took < REFUSED_AT_ONCE,
        crate::lan_ifaces::on_link,
        std::time::Instant::now(),
    );
    if say {
        eprintln!(
            "raven-node lan_direct: macOS refuses this raven-node's connections on the local \
             network (No route to host at once for {}s, though contacts may be up): turn on \
             the app that started raven-node in System Settings > Privacy & Security > Local \
             Network, then restart raven-node",
            REFUSED_FOR.as_secs()
        );
    }
}

/// [`netutil::connect_dial_within`] for a LAN dial: a connect macOS refuses
/// at once while raven-node is new ([`retry_refused_at_start`]) is tried
/// again within seconds, quietly; a refusal that stands counts for the
/// warning ([`say_local_network_refused`]).
async fn connect_lan(
    lan_dial: &str,
    connect: &netutil::ConnectWait,
) -> Result<(tokio::net::TcpStream, SocketAddr), String> {
    connect_lan_with(
        || netutil::connect_dial_within(lan_dial, connect, CONNECT_BUDGET),
        since_process_start,
        REFUSED_RETRY_EVERY,
    )
    .await
}

/// [`connect_lan`] with the connect, the time since raven-node started and
/// the pause between tries as arguments.
async fn connect_lan_with<T, F, Fut>(
    mut dial: F,
    uptime: impl Fn() -> Duration,
    pause: Duration,
) -> Result<T, String>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, String>>,
{
    loop {
        let started = std::time::Instant::now();
        match dial().await {
            Ok(done) => return Ok(done),
            Err(e) if retry_refused_at_start(&e, started.elapsed(), uptime()) => {
                tokio::time::sleep(pause).await;
                lan_still_on()?;
            }
            Err(e) => {
                say_local_network_refused(&e, started.elapsed());
                return Err(format!("lan connect: {e}"));
            }
        }
    }
}

/// A LAN dial connected to `addr`: one on the local network (not this
/// computer itself) shows macOS lets this process connect there, and takes
/// back a warning that said otherwise.
fn local_network_connected(addr: SocketAddr) {
    let ip = addr.ip().to_canonical();
    if !raven_core::outbox::is_local_network_ip(ip) || ip.is_loopback() {
        return;
    }
    if locked(&LOCAL_NETWORK).connected() {
        eprintln!(
            "raven-node lan_direct: a connection on the local network went through: macOS does \
             not refuse this raven-node's connections (the warning before no longer holds)"
        );
    }
}

/// One `auto` socket on `addr` (socket2): IPv6 only on the IPv6 one, so each
/// family has its own socket; SO_REUSEADDR on Unix only, as tokio's own bind
/// sets it (on Windows it would let another program take the port); backlog
/// [`AUTO_BACKLOG`].
fn bind_auto_socket(addr: SocketAddr) -> std::io::Result<TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    #[cfg(unix)]
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(AUTO_BACKLOG)?;
    TcpListener::from_std(socket.into())
}

/// Bind `plan`'s sockets, recording why a bind failed ([`bind_error`]):
/// `auto` needs its IPv4 socket and takes the IPv6 one where it can (on the
/// IPv4 socket's port).
async fn bind_plan(plan: &BindPlan, rule: SourceRule) -> Result<Listeners, String> {
    let sockets = match plan {
        BindPlan::One { addr, .. } => vec![bind_listener(addr).await?],
        BindPlan::Auto { port } => {
            let at4 = SocketAddr::from((Ipv4Addr::UNSPECIFIED, *port));
            let v4 = bind_auto_socket(at4).map_err(|e| bind_failed(&at4.to_string(), &e))?;
            let port = v4.local_addr().map_err(|e| e.to_string())?.port();
            let at6 = SocketAddr::from((Ipv6Addr::UNSPECIFIED, port));
            match bind_auto_socket(at6) {
                Ok(v6) => vec![v4, v6],
                Err(e) => {
                    record_bind_error(&at6.to_string(), bind_error_kind(&e));
                    if !IPV6_UNAVAILABLE_SAID.swap(true, Ordering::Relaxed) {
                        eprintln!(
                            "raven-node lan_direct: IPv6 unavailable ({e}); listening on IPv4 only"
                        );
                    }
                    vec![v4]
                }
            }
        }
    };
    Ok(Listeners { sockets, rule })
}

/// The listener's plan once [`run_listener`] has read `--lan-listen`.
static PLAN: Mutex<Option<BindPlan>> = Mutex::new(None);

/// The LAN listener as `Status.lan` reports it: its mode (or `off`), the
/// addresses it is bound to and whom it admits. `None` while this process
/// runs no LAN listener (`raven-node ipc`, or a `--lan-listen` it cannot
/// read). IPC `Status` adds the beacon's counts
/// ([`crate::lan_beacon::counts`]), the contacts seen here and the pin
/// blocks (P3.C6).
pub(crate) fn lan_status() -> Option<raven_core::ipc::LanStatus> {
    let plan = locked(&PLAN).clone()?;
    let mode = if lan_on() {
        plan.mode()
    } else {
        raven_core::ipc::LAN_MODE_OFF
    };
    Some(raven_core::ipc::LanStatus {
        mode: mode.to_owned(),
        listen: listener_addrs().iter().map(ToString::to_string).collect(),
        local_only: matches!(plan, BindPlan::Auto { .. }),
        ..raven_core::ipc::LanStatus::default()
    })
}

/// The identity the listener loaded at its preflight ([`listener_identity`]).
static LISTENER_IDENTITY: Mutex<Option<Arc<Identity>>> = Mutex::new(None);

/// The identity the LAN listener loaded once at start, after its preflight:
/// the LAN beacon ([`crate::lan_beacon`]) answers with it and never opens
/// the keystore itself. `None` before that.
#[cfg_attr(not(any(unix, windows)), allow(dead_code))]
pub(crate) fn listener_identity() -> Option<Arc<Identity>> {
    locked(&LISTENER_IDENTITY).clone()
}

/// Lock v2 (P6.40): the listener's identity is no longer kept (the listener
/// task, which holds the other reference, stops with the lock).
pub(crate) fn forget_listener_identity() {
    *locked(&LISTENER_IDENTITY) = None;
}

/// Forgets the listener's identity when the listener ends or is dropped (a
/// lock, Lock v2): nothing keeps it past its listener.
struct ListenerIdentityHeld;

impl Drop for ListenerIdentityHeld {
    fn drop(&mut self) {
        forget_listener_identity();
    }
}

/// Test-only: the LAN switch ([`set_lan_on`]) is one per process and also
/// sets raven-core's (`raven_core::lan_usable_now`, which friend custody's
/// routes and links read). A test that changes it holds this for writing
/// ([`lan_switch_for_test`]); a test that needs LAN as the build sets it
/// holds it for reading ([`lan_switch_untouched`]). A thread takes it at
/// most once at a time, and last: after [`listener_state_test_lock`] or
/// any other test lock it holds too.
#[cfg(test)]
static LAN_SWITCH_TEST_LOCK: std::sync::RwLock<()> = std::sync::RwLock::new(());

/// Test-only: this test may turn LAN off ([`set_lan_on`]) while the guard
/// lives; dropping it turns LAN back on.
#[cfg(test)]
pub(crate) fn lan_switch_for_test() -> LanSwitchForTest {
    LanSwitchForTest {
        _lock: LAN_SWITCH_TEST_LOCK
            .write()
            .unwrap_or_else(PoisonError::into_inner),
    }
}

/// [`lan_switch_for_test`]'s guard.
#[cfg(test)]
pub(crate) struct LanSwitchForTest {
    _lock: std::sync::RwLockWriteGuard<'static, ()>,
}

#[cfg(test)]
impl Drop for LanSwitchForTest {
    fn drop(&mut self) {
        set_lan_on(true);
    }
}

/// Test-only: no test turns LAN off while the guard lives. Every test that
/// dials through [`dial_session`] (which refuses while LAN is off) holds it.
#[cfg(test)]
pub(crate) fn lan_switch_untouched() -> LanSwitchUntouched {
    LanSwitchUntouched {
        _lock: LAN_SWITCH_TEST_LOCK
            .read()
            .unwrap_or_else(PoisonError::into_inner),
    }
}

/// [`lan_switch_untouched`]'s guard. An async test holds it across its
/// awaits (its runtime runs on the test's own thread).
#[cfg(test)]
pub(crate) struct LanSwitchUntouched {
    _lock: std::sync::RwLockReadGuard<'static, ()>,
}

/// Test-only: `Status.lan` reports the plan of `lan_listen` (as
/// [`run_listener`] would have set it, `auto_live` being the gate) until the
/// guard drops. Under [`listener_state_test_lock`].
#[cfg(test)]
pub(crate) fn plan_for_test(lan_listen: &str, auto_live: bool) -> ListenerStateForTest {
    *locked(&PLAN) = Some(BindPlan::of(lan_listen, auto_live).expect("a plan"));
    ListenerStateForTest
}

/// Clears what [`run_listener`] sets (its plan and identity) when it drops.
#[cfg(test)]
pub(crate) struct ListenerStateForTest;

#[cfg(test)]
impl Drop for ListenerStateForTest {
    fn drop(&mut self) {
        *locked(&PLAN) = None;
        *locked(&LISTENER_IDENTITY) = None;
    }
}

fn parse_pub_hex(s: &str) -> Result<[u8; 32], String> {
    let h = s.trim().to_lowercase();
    if h.len() != 32 * 2 {
        return Err("expected_pub_hex must be 64 hex chars".into());
    }
    let v = hex::decode(&h).map_err(|_| "expected_pub_hex invalid hex".to_string())?;
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    Ok(a)
}

pub fn looks_like_lan_dial(s: &str) -> bool {
    let t = s.trim();
    if t.is_empty() || t.contains(' ') || t.starts_with("rvn1") {
        return false;
    }
    let Some((host, port)) = t.rsplit_once(':') else {
        return false;
    };
    !host.is_empty() && port.parse::<u16>().ok().is_some_and(|p| p != 0)
}

async fn write_raw<S: AsyncWrite + Unpin>(stream: &mut S, bytes: &[u8]) -> Result<(), String> {
    if bytes.len() > MAX_FRAME {
        return Err("lan frame too large".into());
    }
    // One write per frame: a separate 4-byte prefix segment would wait on the
    // peer's delayed ACK before the body goes out.
    let mut framed = Vec::with_capacity(4 + bytes.len());
    framed.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    framed.extend_from_slice(bytes);
    let write = async {
        stream
            .write_all(&framed)
            .await
            .map_err(|e| netutil::io_error_text(&e))?;
        stream
            .flush()
            .await
            .map_err(|e| netutil::io_error_text(&e))?;
        Ok::<(), String>(())
    };
    tokio::time::timeout(IO_TIMEOUT, write)
        .await
        .map_err(|_| "lan write timeout".to_string())?
}

/// One length-prefixed frame, with no deadline of its own (callers bound it).
async fn read_raw_untimed<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>, String> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| netutil::io_error_text(&e))?;
    let n = u32::from_be_bytes(len_buf) as usize;
    if n == 0 || n > MAX_FRAME {
        return Err(FRAME_LENGTH.into());
    }
    let mut buf = vec![0u8; n];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| netutil::io_error_text(&e))?;
    Ok(buf)
}

async fn read_raw<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>, String> {
    tokio::time::timeout(IO_TIMEOUT, read_raw_untimed(stream))
        .await
        .map_err(|_| READ_TIMEOUT.to_string())?
}

/// One link frame, padded when the link pads ([`LinkCipher::seal`]).
async fn write_cipher<S: AsyncWrite + Unpin>(
    stream: &mut S,
    cipher: &mut LinkCipher,
    plain: &[u8],
) -> Result<(), String> {
    if plain.len() > MAX_TRANSPORT_PLAINTEXT {
        return Err("lan payload exceeds Noise transport limit".into());
    }
    let ct = cipher.seal(plain)?;
    write_raw(stream, &ct).await
}

/// One link frame, unpadded when the peer padded it ([`LinkCipher::open`]).
async fn read_cipher<S: AsyncRead + Unpin>(
    stream: &mut S,
    cipher: &mut LinkCipher,
) -> Result<Vec<u8>, String> {
    let ct = read_raw(stream).await?;
    cipher.open(&ct)
}

/// Wait up to `wait` for the next reply frame and say what happened.
async fn read_reply<S: AsyncRead + Unpin>(
    stream: &mut S,
    cipher: &mut LinkCipher,
    wait: Duration,
) -> ReplyWait {
    let read = async {
        let ct = read_raw_untimed(stream).await?;
        cipher.open(&ct)
    };
    match tokio::time::timeout(wait, read).await {
        Ok(Ok(frame)) => ReplyWait::Frame(frame),
        Ok(Err(why)) => ReplyWait::Closed(why),
        Err(_) => ReplyWait::Idle,
    }
}

/// [`initiator_session_pinned`] without a noise pin or a knock (scripted
/// test dialers).
#[cfg(test)]
async fn initiator_session<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    identity: &Identity,
    expected: &[u8; 32],
    m3_payload: &[u8],
) -> Result<LinkCipher, String> {
    initiator_session_pinned(stream, identity, expected, m3_payload, None, None, None)
        .await
        .map(|(t, _, _)| t)
}

/// Dialer side: Noise XX with `m3_payload` as the message 3 payload (empty,
/// or RLX1: [`crate::hints::lan_m3_payload`]), then the signed binds. With
/// `pinned` (M0) another responder static ends it before message 3. Returns
/// the link's cipher, the responder's static and whether the link carried
/// the knock. `peer_ip`: the address dialled, for the security events
/// (Phase 6b R5 forgets a learned address another key answers at). PAD1
/// (P6.34): when the payload offered it, the dialer reads RPD1 from the
/// start (the listener's bind included) and pads once the listener did
/// ([`PadState::lan_dialer`]; its own bind is bare).
///
/// With `knock` (RLK1, P6.35, [`crate::link_knock`]) message 1 carries it,
/// and the listener's proof in message 2 decides: the proof lets the dial go
/// on with a fresh static of its own; without it the pin, then the
/// contact's capability floor, may end it before message 3 (the M0 text);
/// otherwise it goes on with its derived static, as today. Message 3's RLX1
/// then carries a `PAD` entry. The returned knock is `Some(proof)`; `None`
/// without `knock`.
async fn initiator_session_pinned<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    identity: &Identity,
    expected: &[u8; 32],
    m3_payload: &[u8],
    pinned: Option<&[u8; 32]>,
    peer_ip: Option<std::net::IpAddr>,
    knock: Option<&DialKnock>,
) -> Result<(LinkCipher, [u8; 32], Option<bool>), String> {
    // A security notice that marks a link suite BROKEN (P6.45): no link,
    // before anything is sent (the root fallback of a seeded knock asks
    // again).
    raven_core::suite_policy::check_link()?;
    let impostor =
        || crate::security::address_impostor(expected, raven_core::OutboxCarrier::Lan, peer_ip);
    let (mut hs, local_pub, remote_static, knocked, m3_payload) = match knock {
        None => {
            let secret = derive_noise_static(identity).map_err(|e| e.to_string())?;
            let local_pub = noise_static_public(&secret);
            let mut hs = build_initiator(&secret).map_err(|e| e.to_string())?;
            let m1 = handshake_write(&mut hs, &[]).map_err(|e| e.to_string())?;
            write_raw(stream, &m1).await?;
            let m2 = read_raw(stream).await?;
            handshake_read(&mut hs, &m2).map_err(|e| e.to_string())?;
            // XX: the responder's static came with message 2. Message 3
            // carries ours, and the bind after it our signed identity:
            // neither goes to a key that is not the one pinned for this
            // contact.
            let remote_static = get_remote_static(&hs).map_err(|e| e.to_string())?;
            check_noise_pin(identity, pinned, expected, &remote_static)
                .inspect_err(|_| impostor())?;
            (hs, local_pub, remote_static, None, m3_payload.to_vec())
        }
        Some(knock) => {
            let mut dial = knock.begin(identity, None)?;
            write_raw(stream, dial.m1()).await?;
            let m2 = read_raw(stream).await.map_err(|e| knock.m2_error(e))?;
            let (remote_static, proof) = knock.read_m2(&mut dial, &m2)?;
            // Neither our static nor our bind goes to a key that neither
            // proved itself nor is pinned, at a contact that knocked before.
            let step = knock.step(proof, identity, pinned, expected, &remote_static);
            // A seeded knock without a proof: the caller knocks once more
            // with the pair's root (Phase 6b P6.38) before this is an
            // impostor, or before a pin lets it go on without the knock.
            if knock.unproved(proof, step) {
                return Err(crate::link_knock::KNOCK_SEED_UNPROVED.to_string());
            }
            if matches!(step, DialerStep::StopPin | DialerStep::StopKnock) {
                impostor();
                return Err(NOISE_PIN_MISMATCH.to_string());
            }
            let (hs, local_pub) = dial
                .finish(
                    step == DialerStep::Fresh,
                    &m2,
                    &mut crate::link_knock::rng(),
                )
                .map_err(|e| e.to_string())?;
            let padded = crate::link_knock::m3_payload(m3_payload);
            (hs, local_pub, remote_static, Some(proof), padded)
        }
    };
    let m3 = handshake_write(&mut hs, &m3_payload).map_err(|e| e.to_string())?;
    write_raw(stream, &m3).await?;
    let offered = raven_core::route_hints::rlx1_caps(&m3_payload) & raven_core::CAP_LINK_PAD1 != 0;
    let mut t = LinkCipher::with_pad(
        into_transport(hs).map_err(|e| e.to_string())?,
        PadState::lan_dialer(offered),
    );
    write_cipher(stream, &mut t, &encode_bind(identity, &local_pub)).await?;
    // The responder answers only a dialer whose bind names one of its contacts;
    // anyone else sees the connection close here, before any identity of the
    // responder (see `responder_handshake`).
    let bind = read_cipher(stream, &mut t)
        .await
        .map_err(netutil::closed_before_peer_identity)?;
    verify_bind(&bind, &remote_static, Some(expected)).map_err(|e| {
        // Another identity bound at this contact's address (S13).
        if e == LanNoiseError::BindMismatch {
            impostor();
        }
        e.to_string()
    })?;
    Ok((t, remote_static, knocked))
}

/// Responder: Noise XX, then the dialer's signed bind, which always comes
/// first (bare). Returns the dialer's bound Ed25519 key, the link's cipher
/// (not padding yet: the caller decides once the dialer is a contact), our
/// own bind, which is **not** sent yet: the caller decides first whether the
/// dialer may learn who we are ([`raven_core::lan_dispatch::link_peer_admission`]),
/// the dialer's message 3 payload (RLX1, or empty), not parsed yet, the
/// dialer's Noise static (its bind signs it) and what the knock showed.
///
/// With `ear` (RLK1, P6.35, [`crate::link_knock`]) message 1 is read before
/// the responder is built, and the knock in it decides the static (a fresh
/// one for a contact that knocked; for anyone else the derived one, a fresh
/// one or no message 2 at all, by the mode) and message 2's payload (the
/// proof, or random bytes of the same lengths).
async fn responder_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    identity: &Identity,
    ear: Option<&Ear>,
) -> Result<([u8; 32], LinkCipher, Vec<u8>, Vec<u8>, [u8; 32], Knocked), String> {
    // A security notice that marks a link suite BROKEN (P6.45): no link,
    // before anything is read.
    raven_core::suite_policy::check_link()?;
    let (mut hs, local_pub, knocked) = match ear {
        None => {
            let secret = derive_noise_static(identity).map_err(|e| e.to_string())?;
            let local_pub = noise_static_public(&secret);
            let mut hs = build_responder(&secret).map_err(|e| e.to_string())?;
            let m1 = read_raw(stream).await?;
            handshake_read(&mut hs, &m1).map_err(|e| e.to_string())?;
            let m2 = handshake_write(&mut hs, &[]).map_err(|e| e.to_string())?;
            write_raw(stream, &m2).await?;
            (hs, local_pub, Knocked::Off)
        }
        Some(ear) => {
            let m1 = read_raw(stream).await?;
            let (reply, knocked) = crate::link_knock::hear(ear, &m1).await?;
            let mut hs = build_responder_with_static(&reply.static_secret, None)
                .map_err(|e| e.to_string())?;
            handshake_read(&mut hs, &m1).map_err(|e| e.to_string())?;
            let m2 = handshake_write(&mut hs, &reply.payload).map_err(|e| e.to_string())?;
            write_raw(stream, &m2).await?;
            (hs, static_public(&reply.static_secret), knocked)
        }
    };
    let m3 = read_raw(stream).await?;
    let mut extensions = handshake_read(&mut hs, &m3).map_err(|e| e.to_string())?;
    if extensions.len() > raven_core::route_hints::RLX1_MAX_LEN {
        extensions.clear();
    }
    let remote_static = get_remote_static(&hs).map_err(|e| e.to_string())?;
    let mut t = LinkCipher::new(into_transport(hs).map_err(|e| e.to_string())?);
    let bind = read_cipher(stream, &mut t).await?;
    let remote_ed = verify_bind(&bind, &remote_static, None).map_err(|e| e.to_string())?;
    Ok((
        remote_ed,
        t,
        encode_bind(identity, &local_pub).to_vec(),
        extensions,
        remote_static,
        knocked,
    ))
}

/// [`responder_handshake`] that answers every dialer (scripted test peers).
#[cfg(test)]
async fn responder_session<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    identity: &Identity,
) -> Result<([u8; 32], LinkCipher), String> {
    let (remote_ed, mut t, ours, _, _, _) = responder_handshake(stream, identity, None).await?;
    write_cipher(stream, &mut t, &ours).await?;
    Ok((remote_ed, t))
}

async fn handle_inbound<S: AsyncRead + AsyncWrite + Unpin>(
    data_dir: PathBuf,
    identity: Arc<Identity>,
    stream: S,
    limits: InboundLimits,
    slot: &mut AdmissionSlot,
    // The dialer's address: an unverified contact is answered only from the
    // local network (`None` counts as remote); an IPv6 link-local one is
    // remembered with its zone.
    source: Option<SocketAddr>,
) -> Result<(), String> {
    handle_inbound_with(
        data_dir,
        identity,
        stream,
        limits,
        slot,
        source,
        NoisePins::current(),
    )
    .await
}

/// [`handle_inbound`] with the noise pins (M0) named: a contact's inbound
/// link records its static.
async fn handle_inbound_with<S: AsyncRead + AsyncWrite + Unpin>(
    data_dir: PathBuf,
    identity: Arc<Identity>,
    mut stream: S,
    limits: InboundLimits,
    slot: &mut AdmissionSlot,
    source: Option<SocketAddr>,
    pins: NoisePins,
) -> Result<(), String> {
    let started = std::time::Instant::now();
    // From here on the source's IP. The zone of an IPv6 link-local one
    // (Phase 3 P3.4) is kept with its sighting and with the LAN part it tells
    // us, so it can be dialled back.
    let (source, zone) = (
        source.map(|a| a.ip()),
        source.and_then(netutil::link_local_zone),
    );
    // A contact book still held while its key loads (a start, an Unlock)
    // judges nobody: wait for it, else close before the handshake (E1).
    netutil::book_open_within(&data_dir, limits.book_wait).await?;
    // Identity comes from the listener (loaded once): an unauthenticated peer
    // must not be able to trigger identity-lock / secret-store work. The
    // network half of the handshake has its own short deadline; the local
    // blocking work below deliberately does not (a slow disk is not the
    // peer's fault), so the contact check's time is added back to it.
    let mut deadline = tokio::time::Instant::now() + limits.handshake_deadline;
    // RLK1 (P6.35): while the knock is live, message 1 is read for a knock.
    let ear = Ear::of(&data_dir, &identity, source, raven_core::OutboxCarrier::Lan);
    let (remote_ed, mut transport, our_bind, extensions, remote_static, knocked) =
        match tokio::time::timeout_at(
            deadline,
            responder_handshake(&mut stream, &identity, ear.as_ref()),
        )
        .await
        {
            Ok(done) => done?,
            Err(_) => return Err(HANDSHAKE_TIMEOUT.into()),
        };
    // Contact gate before anything identifying leaves this node: a stranger
    // (or a blocked key) gets the connection closed and nothing else, not our
    // bind (Raven identity) and not our RLB1 (certificate + prekey bundle).
    // An unverified contact dialling from outside the local network is
    // treated exactly like a stranger (owner decision 2026-10-08).
    let gate_started = tokio::time::Instant::now();
    {
        let dd = data_dir.clone();
        blocking(move || {
            raven_core::lan_dispatch::link_admission(
                &dd,
                &remote_ed,
                raven_core::OutboxCarrier::Lan,
                source,
            )
            .map_err(String::from)
        })
        .await?;
    }
    // A contact: what happens on this link from here on is about its path.
    slot.contact_admitted();
    deadline += gate_started.elapsed();
    // PAD1 (P6.34): from our bind on, when the dialer's message 3 offered it
    // and we pad. Its bind came bare; its next frames come padded.
    transport.pad = PadState::agreed(
        crate::link::padding_live()
            && raven_core::route_hints::rlx1_caps(&extensions) & raven_core::CAP_LINK_PAD1 != 0,
    );
    let offer = tokio::time::timeout_at(deadline, async {
        write_cipher(&mut stream, &mut transport, &our_bind).await?;
        read_cipher(&mut stream, &mut transport).await
    })
    .await;
    let peer_offer = match offer {
        Ok(done) => done.inspect_err(|e| {
            crate::security::inbound_link_error(&remote_ed, raven_core::OutboxCarrier::Lan, e);
        })?,
        Err(_) => return Err(HANDSHAKE_TIMEOUT.into()),
    };
    let (peer, local, trusted) = {
        let dd = data_dir.clone();
        let id = identity.clone();
        blocking(move || {
            let peer = parse_peer_offer(&peer_offer)?;
            if !rlb1_matches_noise_identity(&peer, &remote_ed) {
                return Err("rlb1/noise identity mismatch".into());
            }
            if lan_peer_blocked(&dd, &peer, &remote_ed)? {
                return Err("blocked peer".into());
            }
            // Unknown inbound peers stay ephemeral until PairInit confirms trust.
            // An offer dated in our future says how far that contact's clock
            // is ahead (CP.7); refused as before.
            remember_ephemeral_peer(&dd, &peer).inspect_err(|_| {
                crate::clock_notes::offer_refused(&remote_ed, &peer);
            })?;
            let local = encode_local_offer(&dd, &id)?;
            // Fail closed: an unreadable contact book trusts nobody.
            let trusted = raven_core::lan_dispatch::peer_is_trusted(&dd, &peer).unwrap_or(false);
            // Friend custody: a contact's mail may later come from a custodian
            // (best effort; gated, so nothing changes while custody is held).
            if trusted && raven_core::custody_gate::CustodyGates::current().live {
                let _ = raven_core::lan_dispatch::remember_inbound_contact(&dd, &peer);
            }
            Ok((peer, local, trusted))
        })
        .await?
    };
    // A bound RLB1 offer proves only that the peer holds *a* key: anyone can
    // generate an identity and self-sign a bundle. So only a local contact (the
    // sole kind of peer this node accepts PairInit, messages and ACKs from) moves
    // out of the pre-auth caps into a slot a newcomer cannot displace. A stranger
    // keeps a displaceable pre-auth slot, so a handful of sources cannot fill the
    // listener with throw-away identities and lock real contacts out.
    if trusted {
        slot.authenticated();
        // Remember where from first: a contact whose DHCP address changed is
        // reached again at `<this ip>:<saved port>` (raven_core::lan_seen), and
        // the dial-back below must already see it.
        if let Some(ip) = source {
            let dd = data_dir.clone();
            let peer = remote_ed;
            let zone = zone.clone();
            let moved_local = blocking(move || {
                let moved = raven_core::lan_seen::record_contact_seen(
                    &dd,
                    &peer,
                    ip,
                    zone.as_deref(),
                    crate::now_ms(),
                )?;
                // On our network now, from a new local address: a remembered
                // Internet or p2p route to it no longer goes first (LAN first
                // again, raven_core::route_memory). Only a new address: a
                // contact that reaches us while we cannot reach it (its
                // firewall) must not flap the memory.
                let moved_local = moved && raven_core::outbox::is_local_network_ip(ip);
                if moved_local {
                    let _ = raven_core::route_memory::forget_remote(&dd, &peer, crate::now_ms());
                }
                Ok(moved_local)
            })
            .await
            .unwrap_or(false);
            // Learning connectivity's analogue (Phase 6a, gated): its LAN
            // doubt on this network is halved.
            crate::learning::inbound(
                &remote_ed,
                raven_core::OutboxCarrier::Lan,
                None,
                moved_local,
            );
        }
        // M0: its inbound link authenticated its static (the bind signs it).
        // Before the dial-back below, so that dial checks this pin. A
        // dialer whose knock matched used a static of its own for this link
        // only: nothing to pin (RLK1).
        if !knocked.fresh_dialer() {
            pins.record(&data_dir, &identity, remote_ed, remote_static, None)
                .await;
        }
        // A contact that reaches us is online now: retry what we owe it.
        crate::outbox::peer_seen(&remote_ed);
        // From the local network it proves that network works: the other
        // contacts waiting there go now (cutoff pack F5, gated).
        if crate::outbox::inbound_proves_network(source) {
            crate::outbox::network_proven(&remote_ed);
        }
        crate::custody::peer_seen(&remote_ed);
        // A live link with a contact: renew the session soon if it ends
        // within 12 h (gated; a no-op while the renewer does not run).
        crate::renewal::note_live_link(&remote_ed, crate::renewal::LiveLink::Inbound);
        // Why it could not be reached no longer holds.
        crate::delivery_paths::heard(&remote_ed);
        // Seen on this network (`raven status`, P3.C6).
        if let Some(ip) = source {
            crate::delivery_paths::lan_link(&remote_ed, ip);
        }
    }
    write_cipher(&mut stream, &mut transport, &local).await?;
    // Route hints (RRH1): only to a dialer whose message 3 asked for them
    // (RLX1); one-way, never a reply.
    let keys = crate::hints::LinkKeys::new(remote_ed, &identity);
    let mut hints = crate::hints::LinkCtl::lan_listener(&data_dir, keys, source, &extensions)
        .with_peer_zone(zone)
        .with_knock(knocked.showed(&remote_ed))
        .with_update(crate::update_exchange::UpdateLink::lan_listener(
            &data_dir,
            remote_ed,
            &extensions,
        ));
    if trusted {
        if let Some(ours) = hints.outgoing().await {
            write_cipher(&mut stream, &mut transport, &ours).await?;
            hints.written();
        }
        // What its message 3 showed: its capability floor (P6.29).
        hints.note_features();
    }
    // RUP1 (P6.49): our HAVE, after RRH1, to a pinned contact whose message
    // 3 offered bit 10; one-way, never a reply.
    if let Some(have) = hints.update().outgoing().await {
        write_cipher(&mut stream, &mut transport, &have).await?;
    }

    let mut frames_seen = 0u32;
    loop {
        if started.elapsed() > limits.lifetime {
            return Err("lan connection lifetime exceeded".into());
        }
        let frame = match read_cipher(&mut stream, &mut transport).await {
            Ok(f) => f,
            // The dialer is done (it closes as soon as it has its replies) or
            // went quiet: normal ends, not events worth a log line.
            Err(e) if e == PEER_CLOSED || e == READ_TIMEOUT => break,
            Err(e) => {
                crate::security::inbound_link_error(&remote_ed, raven_core::OutboxCarrier::Lan, &e);
                netutil::log_inbound_failure(
                    "lan_direct inbound read",
                    format_args!("contact {}: {e}", netutil::link_tag(&remote_ed)),
                );
                break;
            }
        };
        if !frame_budget_allows(&mut frames_seen, limits.max_frames) {
            return Err("lan frame budget exceeded".into());
        }
        if hints.take(&frame).await {
            continue;
        }
        // RUP1 (P6.49): the dialer's HAVE and requests, answered here and
        // never dispatched.
        if let Some(replies) = hints.update().listener_take(&frame).await {
            for reply in &replies {
                write_cipher(&mut stream, &mut transport, reply).await?;
            }
            continue;
        }
        // A custody handoff FORWARD left here is handed on at once (P5.21).
        let handoff = raven_core::friend_custody::is_handoff_request(&frame);
        let dd = data_dir.clone();
        let id = identity.clone();
        let peer_c = peer.clone();
        let noise_ed = remote_ed;
        let replies = tokio::task::spawn_blocking(move || {
            if lan_peer_blocked(&dd, &peer_c, &noise_ed)? {
                return Ok(None);
            }
            // What the frame showed about the contact's clock (CP.7): kept
            // whether or not it was accepted.
            let mut clock = None;
            let replies = raven_core::lan_dispatch::dispatch_frame_clocked(
                &dd,
                &id,
                &peer_c,
                &noise_ed,
                &frame,
                raven_core::friend_custody::InboundLink {
                    carrier: raven_core::OutboxCarrier::Lan,
                    source,
                },
                &mut clock,
            );
            crate::clock_notes::seen(&noise_ed, clock);
            replies.map(Some)
        })
        .await
        .map_err(|e| format!("dispatch join: {e}"))?
        .map_err(|e| format!("dispatch: {e}"))?
        .ok_or_else(|| "blocked peer".to_string())?;
        if handoff {
            crate::custody::kick_forward();
        }
        for (i, reply) in replies.iter().enumerate() {
            if let Err(e) = write_cipher(&mut stream, &mut transport, reply).await {
                // The sealed ACK of a message we just accepted never left: the
                // outbox pushes it to the sender later (transports design F8).
                crate::outbox::note_unsent_replies(&remote_ed, &replies[i..]);
                return Err(e);
            }
        }
    }
    Ok(())
}

/// Blocking: loads the identity (the listener keeps it for its lifetime) and
/// readies durable LAN state, one durable pass at a time
/// ([`netutil::durable_pass`]).
fn preflight_lan_ready(data_dir: &Path) -> Result<Identity, String> {
    let _pass = netutil::durable_pass();
    let identity = load_identity_required(data_dir).map_err(|e| e.to_string())?;
    raven_core::ensure_local_prekey(data_dir, &identity)?;
    let _ = raven_core::IndexedSessionStore::open(data_dir).map_err(|e| e.redacted_display())?;
    let _ = raven_core::PrekeyLifecycleActor::open(data_dir).map_err(|e| e.to_string())?;
    raven_core::maintain_lan_durable_state(data_dir)?;
    Ok(identity)
}

/// Listen on `lan_listen` and dispatch inbound LAN-direct sessions.
pub async fn run_listener(data_dir: PathBuf, lan_listen: String) -> Result<(), String> {
    run_listener_with_limits(data_dir, lan_listen, PRODUCTION_LIMITS).await
}

async fn run_listener_with_limits(
    data_dir: PathBuf,
    lan_listen: String,
    limits: InboundLimits,
) -> Result<(), String> {
    // What `--lan-listen` asks for, read once. A value this build cannot
    // read fails like a bind that fails: logged, named in `Status`, and
    // tried again by the supervisor (before the preflight, so that is not
    // repeated).
    let plan = BindPlan::of(&lan_listen, raven_core::lan_auto_live()).inspect_err(|_| {
        record_bind_error(&lan_listen, raven_core::ipc::LAN_BIND_OTHER);
    })?;
    *locked(&PLAN) = Some(plan.clone());
    let rule = plan.rule(raven_core::lan_gate::lab_lan_source_deny_loopback());
    // Each start-up step is retried on its own (a busy port must not re-run
    // the preflight, which takes the data-dir locks `ash` sends need), and a
    // failure never ends the listener or the daemon around it.
    let identity = Arc::new(
        netutil::retry_until_ok("lan_direct", || {
            let dd = data_dir.clone();
            async move {
                netutil::with_slow_notice(
                    "lan_direct",
                    "local state preflight (identity, sessions, outbound stage)",
                    blocking(move || {
                        preflight_lan_ready(&dd)
                            .map_err(|e| raven_core::disk_space::with_disk_full_note(&dd, e))
                    }),
                )
                .await
            }
        })
        .await,
    );
    *locked(&LISTENER_IDENTITY) = Some(Arc::clone(&identity));
    let _held = ListenerIdentityHeld;
    let on = lan_switch().subscribe();
    match serve_while_on(&plan, rule, data_dir, identity, limits, on, || {
        // Back on the network: whatever the outbox holds is worth a try now.
        crate::outbox::listener_up();
        crate::custody::kick();
    })
    .await {}
}

/// Serve `plan` for as long as the task lives, while LAN is on (`on`): bound
/// when it turns on (`up` runs then), closed when it turns off (`raven lan
/// off`) together with every connection it accepted.
async fn serve_while_on(
    plan: &BindPlan,
    rule: SourceRule,
    data_dir: PathBuf,
    identity: Arc<Identity>,
    limits: InboundLimits,
    mut on: watch::Receiver<bool>,
    up: impl Fn(),
) -> Infallible {
    loop {
        let off = !*on.borrow_and_update();
        if off {
            // Nothing failed: there is nothing to bind while LAN is off.
            clear_bind_errors();
            if raven_core::nearby_only() {
                eprintln!("raven-node lan_direct: off in this lab run (nearby only)");
            } else {
                eprintln!("raven-node lan_direct: off (raven lan off)");
            }
            let _ = on.wait_for(|on| *on).await;
        }
        let bound = tokio::select! {
            bound = netutil::retry_until_ok("lan_direct", || bind_plan(plan, rule)) => Some(bound),
            _ = on.wait_for(|on| !*on) => None,
        };
        let Some(listeners) = bound else {
            continue;
        };
        let addrs = listeners.local_addrs();
        for local in &addrs {
            eprintln!("raven-node lan_direct: listen {local}");
        }
        let up_guard = listeners_bound(addrs);
        up();
        let conns = on.clone();
        tokio::select! {
            never = serve_listeners(&listeners, data_dir.clone(), identity.clone(), limits, conns) => {
                match never {}
            }
            _ = on.wait_for(|on| !*on) => {}
        }
        // LAN is off: the port closes, and its connections end on the same
        // switch.
        drop(listeners);
        drop(up_guard);
    }
}

/// Accept and serve inbound sessions on `listeners` for as long as the task
/// lives. Each connection also ends when LAN turns off (`on`).
async fn serve_listeners(
    listeners: &Listeners,
    data_dir: PathBuf,
    identity: Arc<Identity>,
    limits: InboundLimits,
    on: watch::Receiver<bool>,
) -> Infallible {
    netutil::serve_connections(
        "lan_direct",
        || listeners.accept(),
        limits,
        move |stream, mut slot| {
            let dd = data_dir.clone();
            let id = identity.clone();
            let mut on = on.clone();
            async move {
                let source = stream.peer_addr().ok();
                tokio::select! {
                    done = handle_inbound(dd, id, stream, limits, &mut slot, source) => done,
                    // `raven lan off`: the link ends with the listener.
                    _ = on.wait_for(|on| !*on) => Ok(()),
                }
            }
        },
    )
    .await
}

/// [`serve_listeners`] on one socket that admits any source, while LAN is on
/// in this process (tests).
#[cfg(test)]
async fn serve_listener(
    listener: TcpListener,
    data_dir: PathBuf,
    identity: Arc<Identity>,
    limits: InboundLimits,
) -> Infallible {
    let listeners = Listeners {
        sockets: vec![listener],
        rule: SourceRule::Any,
    };
    serve_listeners(
        &listeners,
        data_dir,
        identity,
        limits,
        lan_switch().subscribe(),
    )
    .await
}

/// How often the service prunes expired durable LAN state. Listener start-up
/// and each new PairInit prune too, but a node that keeps running and never
/// pairs again must still destroy an expired session's `K_root`, outbox
/// envelopes and inbox rows.
pub(crate) const DURABLE_PRUNE_INTERVAL: Duration = Duration::from_secs(10 * 60);

/// A prune that keeps failing does so every interval: log it once an hour.
static PRUNE_LOG: netutil::LogLimiter = netutil::LogLimiter::new(Duration::from_secs(3600));

/// Run `pass` once at start and then every `interval`, for ever. Each pass
/// runs on the blocking pool and takes and releases its SQLite / keystore
/// locks itself, so nothing is held across an await. A failed or panicking
/// pass is logged (rate limited) and the next tick simply tries again.
async fn run_periodic<F>(name: &'static str, interval: Duration, pass: F) -> Infallible
where
    F: Fn() -> Result<(), String> + Send + Sync + 'static,
{
    let pass = Arc::new(pass);
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        // The first tick completes at once: the pass at start.
        ticker.tick().await;
        let p = Arc::clone(&pass);
        let outcome = match tokio::task::spawn_blocking(move || p()).await {
            Ok(result) => result,
            Err(e) => Err(format!("pass ended abnormally: {e}")),
        };
        if let Err(e) = outcome {
            netutil::log_limited(&PRUNE_LOG, &format!("{name} failed"), e);
        }
    }
}

/// The service's periodic expiry prune (supervised in `main`).
pub async fn run_durable_prune(data_dir: PathBuf) -> Result<(), String> {
    match run_periodic("durable_prune", DURABLE_PRUNE_INTERVAL, move || {
        let _pass = netutil::durable_pass();
        raven_core::lan_dispatch::prune_expired_lan_durable_state(&data_dir)
            .map_err(|e| raven_core::disk_space::with_disk_full_note(&data_dir, e))
    })
    .await {}
}

/// Send `frames` and collect the replies into `progress`. Ends as soon as
/// every frame that gets a reply has had it; a peer that closes without
/// replying is an error rather than an empty success. The peer's RRH1 is
/// consumed by `hints` and never collected as a reply.
async fn exchange_frames<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    transport: &mut LinkCipher,
    frames: &[Vec<u8>],
    hints: &mut crate::hints::LinkCtl,
    progress: &mut DialProgress,
) -> Result<(), String> {
    progress.stage = "sending frames";
    // None on LAN here: the listener's RRH1 says whether it takes ours.
    if let Some(ours) = hints.outgoing().await {
        write_cipher(stream, transport, &ours).await?;
        hints.written();
    }
    // RUP1 requests (P6.49) only once the listener's HAVE came on this link.
    if frames
        .iter()
        .any(|f| raven_core::update_exchange::is_rup1(f))
    {
        read_peer_frames(stream, transport, hints, progress.collector.idle_wait()).await?;
        crate::update_exchange::check_requests(frames, hints.update())?;
    }
    for frame in frames {
        write_cipher(stream, transport, frame).await?;
    }
    if frames.is_empty() {
        // An announce link reads the listener's RRH1 (and answers it), and
        // its HAVE (RUP1, P6.49), before it closes.
        read_peer_frames(stream, transport, hints, progress.collector.idle_wait()).await?;
        return Ok(());
    }
    progress.frames_sent = true;
    progress.collector.mark_frames_sent();
    progress.stage = "waiting for a reply";
    let wait = progress.collector.first_wait();
    let mut more = progress
        .collector
        .first(read_reply_hints(stream, transport, wait, hints).await?)?;
    while more {
        let wait = progress.collector.idle_wait();
        more = progress
            .collector
            .next(read_reply_hints(stream, transport, wait, hints).await?)?;
    }
    Ok(())
}

/// [`read_reply`] that consumes the peer's RRH1 within the same wait and
/// answers the listener's with ours. The listener writes its RRH1 before any
/// reply, so ours leaves before the dialer reads its last reply and closes.
async fn read_reply_hints<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    transport: &mut LinkCipher,
    wait: Duration,
    hints: &mut crate::hints::LinkCtl,
) -> Result<ReplyWait, String> {
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        let got = read_reply(stream, transport, left).await;
        crate::security::dial_reply(&got, hints);
        let ReplyWait::Frame(frame) = &got else {
            return Ok(got);
        };
        // The listener's HAVE (RUP1, P6.49): taken and answered with ours,
        // never a reply.
        if let Some(answer) = hints.update().dialer_take(frame).await {
            if let Some(ours) = answer {
                write_cipher(stream, transport, &ours).await?;
            }
            continue;
        }
        if !hints.take(frame).await {
            return Ok(got);
        }
        if hints.flooded() {
            return Ok(ReplyWait::Closed("too many route hint frames".into()));
        }
        if let Some(ours) = hints.outgoing().await {
            write_cipher(stream, transport, &ours).await?;
            hints.written();
        }
    }
}

/// Before a dialer writes nothing more, or asks the update exchange
/// anything: read what the listener sends first (its RRH1, its HAVE) while
/// either is still expected, each within `wait`, and answer them with ours.
/// Without either expected it reads nothing, as before.
async fn read_peer_frames<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    transport: &mut LinkCipher,
    hints: &mut crate::hints::LinkCtl,
    wait: Duration,
) -> Result<(), String> {
    while hints.expects_peer_frame() || hints.update().expects_have() {
        let got = read_reply(stream, transport, wait).await;
        crate::security::dial_reply(&got, hints);
        let ReplyWait::Frame(frame) = got else {
            break;
        };
        if let Some(answer) = hints.update().dialer_take(&frame).await {
            if let Some(ours) = answer {
                write_cipher(stream, transport, &ours).await?;
            }
        } else if hints.take(&frame).await {
            if let Some(ours) = hints.outgoing().await {
                write_cipher(stream, transport, &ours).await?;
                hints.written();
            }
        } else {
            break;
        }
    }
    Ok(())
}

/// `raven lan off` (or the end of a meeting) after a dial was planned: it
/// connects nowhere (B-3; IPC `LanDial` refuses at its start in the same
/// words). Checked before the first connect and before each retry.
fn lan_still_on() -> Result<(), String> {
    if raven_core::lan_user_off() {
        return Err(format!(
            "{}: raven lan off is in effect (raven lan on)",
            raven_core::LAN_OFF
        ));
    }
    Ok(())
}

/// `announce`: a link that carries only route hints (it asks for the
/// listener's RRH1 although it has no frames, and waits for it). `pins`:
/// whether the contact's noise pin is checked and recorded (M0).
async fn dial_session(
    data_dir: &Path,
    lan_dial: &str,
    expected: &[u8; 32],
    frames: &[Vec<u8>],
    announce: bool,
    pins: NoisePins,
    progress: &mut DialProgress,
) -> Result<(), String> {
    progress.stage = "loading the local identity";
    lan_still_on()?;
    let knock_live = crate::link_knock::live();
    let knock_seeds = crate::pair_seed::live();
    let (identity, local, pinned, knock) = {
        let dd = data_dir.to_path_buf();
        let contact = *expected;
        blocking(move || {
            // `raven lan verified-only on` (P3.C2): no LAN link with an
            // unverified contact, so nothing is dialled at all.
            if raven_core::node_policy::lan_verified_only(&dd)
                && !raven_core::contact_is_pinned(&dd, &contact)?
            {
                return Err(VERIFIED_ONLY_DIAL.into());
            }
            let identity = load_identity_required(&dd).map_err(|e| e.to_string())?;
            let local = encode_local_offer(&dd, &identity)?;
            // Before connecting: an unreadable pin store dials nothing.
            let pinned = pins.load(&dd, &contact)?;
            // RLK1 (P6.35): the contact's knock keys and floor.
            let knock =
                crate::link_knock::for_dial(knock_live, knock_seeds, &dd, &identity, &contact);
            Ok((identity, local, pinned, knock))
        })
        .await?
    };
    // Route hints: asked for only on a dial that reads (a frame-less probe
    // closes right after RLB1 and would leave the listener's RRH1 unread).
    // PAD1 is offered on the same dials (P6.34): a probe's message 3 stays
    // what older builds send.
    // And only when this dial wants the contact's route hints or has news
    // for it (E2 night: every custody fetch told and learned them).
    let offers = crate::link::offers(raven_core::OutboxCarrier::Lan);
    let reads = announce || !frames.is_empty();
    let rrh1 = offers.contains(raven_core::internet::LinkFeatures::RRH1)
        && reads
        && crate::hints::lan_asks(
            data_dir,
            crate::hints::LinkKeys::new(*expected, &identity),
            announce,
        )
        .await;
    let m3_payload = crate::hints::lan_m3_payload_with(
        rrh1,
        offers.contains(raven_core::internet::LinkFeatures::PAD1),
        offers.contains(raven_core::internet::LinkFeatures::RUP1),
        reads,
    );
    let asked = raven_core::route_hints::rlx1_caps(&m3_payload) & raven_core::CAP_LINK_RRH1 != 0;
    let rup1_asked =
        raven_core::route_hints::rlx1_caps(&m3_payload) & raven_core::CAP_LINK_RUP1 != 0;
    progress.stage = "connecting and in the Noise handshake";
    let (mut stream, mut transport, local_addr, peer_addr, remote_static, knocked) = {
        let (identity, m3_payload, pinned) = (&identity, &m3_payload, pinned.as_ref());
        // Per address: today's, or learning connectivity's shorter wait.
        let connect = &progress.connect;
        // A knock with the pair's seed that got no proof (or whose listener
        // closed before message 2 every time) is made once more with the
        // pair's root (Phase 6b P6.38): a contact that lost its seed still
        // proves itself; anyone else is stopped there.
        crate::link_knock::dial_attempts(knock.as_ref(), move |k| async move {
            lan_still_on()?;
            let (mut stream, addr) = connect_lan(lan_dial, connect).await?;
            local_network_connected(addr);
            // The contact's LAN address answered: what waits for it goes
            // now, whatever this dial is for (E1; nothing while the outbox's
            // own attempt for it runs).
            crate::outbox::peer_back(expected);
            let here = stream.local_addr().ok();
            let (transport, remote_static, knocked) = initiator_session_pinned(
                &mut stream,
                identity,
                expected,
                m3_payload,
                pinned,
                Some(addr.ip()),
                k,
            )
            .await?;
            Ok((stream, transport, here, addr, remote_static, knocked))
        })
        .await?
    };
    // The responder's bind verified: its static is the contact's. A
    // listener that proved itself used a static for this link only: nothing
    // to pin (RLK1); the pins kept stay for listeners without the knock.
    if knocked != Some(true) {
        pins.record(data_dir, &identity, *expected, remote_static, pinned)
            .await;
    }
    let keys = crate::hints::LinkKeys::new(*expected, &identity);
    drop(identity);
    progress.stage = "exchanging RLB1 offers";
    write_cipher(&mut stream, &mut transport, &local).await?;
    let peer_offer = read_cipher(&mut stream, &mut transport)
        .await
        .inspect_err(|e| {
            crate::security::dial_link_error(expected, raven_core::OutboxCarrier::Lan, e)
        })?;
    let peer_offer = {
        let dd = data_dir.to_path_buf();
        let expected = *expected;
        blocking(move || {
            let peer = parse_peer_offer(&peer_offer)?;
            if peer.cert.device_ed_pub != expected && peer.cert.user_ed_pub != expected {
                return Err("rlb1 offer identity mismatch".into());
            }
            if lan_peer_blocked(&dd, &peer, &expected)? {
                return Err("blocked peer".into());
            }
            // An offer dated in our future (PREKEY_NOT_YET_VALID) says how
            // far the contact's clock is ahead (CP.7); refused as before.
            cache_peer_bundle(&dd, &peer).inspect_err(|_| {
                crate::clock_notes::offer_refused(&expected, &peer);
            })?;
            Ok(peer_offer)
        })
        .await?
    };
    // The contact's verified offer: a live link (the session renewer; a
    // no-op for its own dials and while it does not run).
    crate::renewal::note_live_link(expected, crate::renewal::LiveLink::Outbound);
    // Seen on this network (`raven status`, P3.C6).
    crate::delivery_paths::lan_link(expected, peer_addr.ip());
    // Its key answered at this address: if it was seen coming from there,
    // that is its own address, not a router's in front of it (E2).
    {
        let (dd, peer, ip) = (data_dir.to_path_buf(), *expected, peer_addr.ip());
        let zone = netutil::link_local_zone(peer_addr);
        let _ = blocking(move || {
            raven_core::lan_seen::note_reached(&dd, &peer, ip, zone.as_deref(), crate::now_ms())
        })
        .await;
    }
    progress.collector.begin(peer_offer, frames)?;
    let mut hints = crate::hints::LinkCtl::lan_dialer(
        data_dir,
        keys,
        local_addr,
        Some(peer_addr.ip()),
        asked,
        announce,
    )
    .with_purpose(crate::hints::dial_purpose(frames, announce))
    .with_peer_zone(netutil::link_local_zone(peer_addr))
    .with_update(crate::update_exchange::UpdateLink::lan_dialer(
        data_dir, *expected, rup1_asked,
    ));
    // Whether the listener proved the knock: its capability floor (P6.35).
    hints.knock_seen(knocked);
    // The listener padded its bind: its capability floor keeps that (P6.34).
    if transport.pad.peer_started() {
        hints.pad_seen();
    }
    exchange_frames(&mut stream, &mut transport, frames, &mut hints, progress).await
}

/// Dial `lan_dial` (`host:port`: an IP, a DNS / mDNS name, or `[v6%if]:port`),
/// complete Noise+RLB1, send `frames`, collect replies.
pub async fn dial(
    data_dir: &Path,
    lan_dial: &str,
    expected_pub_hex: &str,
    frames: &[Vec<u8>],
) -> Result<Vec<Vec<u8>>, String> {
    dial_with_meta(
        data_dir,
        lan_dial,
        expected_pub_hex,
        frames,
        DialMeta::default(),
    )
    .await
}

/// [`dial`] with the worker's facts about it ([`DialMeta`]: a resend of an
/// object that went silent gives learning no reply-time sample). Its waits
/// are `crate::learning::waits`' (today's while learning is off).
pub(crate) async fn dial_with_meta(
    data_dir: &Path,
    lan_dial: &str,
    expected_pub_hex: &str,
    frames: &[Vec<u8>],
    meta: DialMeta,
) -> Result<Vec<Vec<u8>>, String> {
    if !looks_like_lan_dial(lan_dial) {
        return Err(
            "lan_dial must be host:port (e.g. 192.168.1.20:7420 or mac-mini.local:7420)".into(),
        );
    }
    let expected = parse_pub_hex(expected_pub_hex)?;
    let net = crate::learning::net();
    let waits = crate::learning::waits(&expected, raven_core::OutboxCarrier::Lan);
    let mut progress = DialProgress::waiting("LAN", &waits);
    progress.collector.set_race(meta.race);
    // A probe's own bound (learning's exploration): it ends here, observed.
    let deadline = meta.deadline(DIAL_DEADLINE);
    let outcome = tokio::time::timeout(
        deadline,
        dial_session(
            data_dir,
            lan_dial,
            &expected,
            frames,
            false,
            NoisePins::current(),
            &mut progress,
        ),
    )
    .await;
    let timing = progress.timing();
    let expired = progress.expired();
    let dialled = progress.connecting_began();
    let replies = match outcome {
        Ok(Ok(())) => Ok(progress.collector.into_replies()),
        Ok(Err(e)) => Err(e),
        Err(_) => progress.on_deadline("lan", lan_dial, deadline),
    };
    crate::clock_notes::dialled(&expected, frames, &replies);
    // Learning connectivity (Phase 6a, gated): Ok and Err alike, once the
    // dial began connecting (before that nothing was dialled).
    if dialled {
        crate::learning::observe_dial(
            &expected,
            raven_core::OutboxCarrier::Lan,
            Some(raven_core::outbox::DeliveryPath::Direct),
            None,
            frames,
            &replies,
            &timing,
            expired,
            meta,
            net,
        );
    }
    let replies = replies?;
    crate::delivery_paths::note(
        &expected,
        raven_core::OutboxCarrier::Lan,
        Some(raven_core::outbox::DeliveryPath::Direct),
        frames,
        &replies,
    );
    Ok(replies)
}

/// An announce link to the contact at `lan_dial` (route hints spec §7): no
/// message frame; it asks for the listener's RRH1, waits for it and answers
/// it. `Ok` once the link completed, whether or not the listener sent one.
pub(crate) async fn dial_announce(
    data_dir: &Path,
    lan_dial: &str,
    expected_pub_hex: &str,
) -> Result<(), String> {
    if !looks_like_lan_dial(lan_dial) {
        return Err("lan_dial must be host:port".into());
    }
    let expected = parse_pub_hex(expected_pub_hex)?;
    let net = crate::learning::net();
    let waits = crate::learning::waits(&expected, raven_core::OutboxCarrier::Lan);
    let mut progress = DialProgress::waiting("LAN", &waits);
    let outcome = tokio::time::timeout(
        DIAL_DEADLINE,
        dial_session(
            data_dir,
            lan_dial,
            &expected,
            &[],
            true,
            NoisePins::current(),
            &mut progress,
        ),
    )
    .await;
    let timing = progress.timing();
    let expired = progress.expired();
    let dialled = progress.connecting_began();
    let result = match outcome {
        Ok(result) => result,
        Err(_) => progress
            .on_deadline("lan", lan_dial, DIAL_DEADLINE)
            .map(drop),
    };
    // Learning connectivity (Phase 6a, gated): a frame-less link is link
    // evidence for the route, its failure a failure.
    if dialled {
        crate::learning::observe_dial(
            &expected,
            raven_core::OutboxCarrier::Lan,
            Some(raven_core::outbox::DeliveryPath::Direct),
            None,
            &[],
            &result.as_ref().map(|_| Vec::new()).map_err(String::clone),
            &timing,
            expired,
            DialMeta::default(),
            net,
        );
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The source address the scripted dialers of these tests connect from.
    const LOOPBACK: Option<std::net::IpAddr> =
        Some(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    /// [`LOOPBACK`] with the dialer's port, as the listener sees it.
    const LOOPBACK_DIALER: Option<SocketAddr> = Some(SocketAddr::V4(std::net::SocketAddrV4::new(
        std::net::Ipv4Addr::LOCALHOST,
        50_123,
    )));
    use crate::netutil::{Admission, ReplyWaits, PRODUCTION_REPLY_WAITS};
    use raven_core::envelope::{EnvType, Envelope};
    use raven_core::lan_noise::transport_encrypt;
    use tokio::net::TcpStream;

    /// A debug lab run that carries over nearby alone keeps LAN off whatever
    /// is asked (`raven lan on`, a meeting time); otherwise the request
    /// stands.
    #[test]
    fn nearby_only_keeps_the_lan_switch_off() {
        assert!(lan_on_allowed(true, false));
        assert!(!lan_on_allowed(false, false));
        assert!(!lan_on_allowed(true, true));
        assert!(!lan_on_allowed(false, true));
    }

    /// The service prunes once at start and then every interval; a pass that
    /// fails or panics is only logged and the next tick runs again.
    #[tokio::test(start_paused = true)]
    async fn periodic_prune_runs_at_start_then_every_interval_despite_failures() {
        use std::sync::atomic::AtomicUsize;
        let passes = Arc::new(AtomicUsize::new(0));
        let p = Arc::clone(&passes);
        let task = tokio::spawn(run_periodic(
            "test_prune",
            DURABLE_PRUNE_INTERVAL,
            move || match p.fetch_add(1, Ordering::SeqCst) {
                0 => Err("store busy".into()),
                1 => panic!("prune bug (test)"),
                _ => Ok(()),
            },
        ));
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(passes.load(Ordering::SeqCst), 1, "one pass at start");
        tokio::time::sleep(DURABLE_PRUNE_INTERVAL * 3).await;
        assert_eq!(passes.load(Ordering::SeqCst), 4);
        assert!(!task.is_finished());
        task.abort();
    }

    #[test]
    fn preflight_fails_without_identity() {
        let _state = listener_state_test_lock();
        let dir = tempfile::tempdir().unwrap();
        let err = preflight_lan_ready(dir.path())
            .err()
            .expect("preflight must fail without identity");
        assert!(!err.is_empty());
        assert!(!listener_is_up());
    }

    /// E1 (Windows, after an unlock): the preflights and the prune all
    /// started at once over the same files. A preflight waits for the pass
    /// that runs.
    #[test]
    fn a_preflight_waits_for_the_durable_pass_that_runs() {
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path().to_path_buf();
        let pass = netutil::durable_pass();
        let (done_tx, done) = std::sync::mpsc::channel();
        let preflight = std::thread::spawn(move || {
            let _ = preflight_lan_ready(&dd);
            let _ = done_tx.send(());
        });
        assert!(
            done.recv_timeout(Duration::from_millis(200)).is_err(),
            "the preflight ran during another pass"
        );
        drop(pass);
        done.recv_timeout(Duration::from_secs(10))
            .expect("the preflight runs once the pass is over");
        preflight.join().unwrap();
    }

    /// The bound address is known while the listener serves and forgotten when
    /// its task ends (the IPC `Status` reports it as `lan_listen`).
    #[test]
    fn listener_addr_is_known_only_while_the_listener_serves() {
        let _state = listener_state_test_lock();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            assert_eq!(listener_addr(), None);
            let dir = tempfile::tempdir().unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let local = listener.local_addr().unwrap();
            let (data_dir, identity) = (
                dir.path().to_path_buf(),
                Arc::new(Identity::from_seed(&[0x61; 32])),
            );
            let (bound, is_bound) = tokio::sync::oneshot::channel();
            let task = tokio::spawn(async move {
                let _up = listener_bound(local);
                let _ = bound.send(());
                match serve_listener(listener, data_dir, identity, PRODUCTION_LIMITS).await {}
            });
            is_bound.await.unwrap();
            assert_eq!(listener_addr(), Some(local));
            assert!(listener_is_up());
            TcpStream::connect(local)
                .await
                .expect("the recorded address is the one serving");
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
            assert_eq!(listener_addr(), None);
            assert!(!listener_is_up());
        });
    }

    /// Why the listener could not bind is kept for the IPC `Status`
    /// (`lan_listen_wanted`, `lan_bind_error`) until a bind succeeds: an
    /// address that is not on this computer (TEST-NET-1 is on no
    /// interface; AddrNotAvailable on macOS, Linux and Windows), a port
    /// another socket holds, then a free loopback port that clears it.
    /// B-5: a `--lan-listen` with a named IPv6 zone (`[fe80::1%lo0]:7420`,
    /// as the docs and installers allow) binds, on that interface; an
    /// unknown interface is a bind error, never a resolver lookup.
    #[test]
    fn a_listen_address_with_a_named_zone_binds() {
        let _state = listener_state_test_lock();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        // A link-local address of this computer with its interface's name
        // (macOS: fe80::1 on lo0); none here (a Linux runner): nothing to bind.
        let Some(here) = raven_core::netifs::read()
            .unwrap_or_default()
            .into_iter()
            .filter(|a| a.ip.is_ipv6() && a.scope_id != 0 && a.up)
            .min_by_key(|a| !a.loopback)
        else {
            eprintln!("skipped: no IPv6 link-local address on this computer");
            return;
        };
        let wanted = format!("[{}%{}]:0", here.ip, zone_name_of(&here));
        rt.block_on(async {
            let listener = bind_listener(&wanted).await.unwrap();
            let local = listener.local_addr().unwrap();
            assert_eq!(local.ip(), here.ip, "{wanted}");
            assert!(
                matches!(local, SocketAddr::V6(v6) if v6.scope_id() == here.scope_id),
                "{local:?}"
            );
            let err = bind_listener("[fe80::1%no-such-if0]:0").await.unwrap_err();
            assert!(err.contains("unknown network interface"), "{err}");
        });
        *LAN_BIND_V6.lock().unwrap() = (None, None);
    }

    /// The name a zone gives `addr`'s interface by: the name the reader
    /// lists (`en0`, `lo0`). Windows lists the adapter's friendly name
    /// (`Ethernet 3`), and a zone names it by its system name
    /// (`ethernet_32769`, as `if_indextoname` gives it;
    /// `raven_core::netifs::interface_index`).
    #[cfg(not(windows))]
    fn zone_name_of(addr: &raven_core::netifs::LocalAddr) -> String {
        addr.ifname.clone()
    }

    #[cfg(windows)]
    fn zone_name_of(addr: &raven_core::netifs::LocalAddr) -> String {
        use windows_sys::Win32::NetworkManagement::IpHelper::if_indextoname;
        // IF_NAMESIZE (256) bytes and one more: a NUL always ends it.
        let mut buf = [0u8; 257];
        // SAFETY: `buf` holds IF_NAMESIZE bytes, as if_indextoname requires;
        // it writes a NUL-terminated name there or returns null.
        let named = unsafe { if_indextoname(addr.scope_id, buf.as_mut_ptr()) };
        assert!(!named.is_null(), "{addr:?}");
        std::ffi::CStr::from_bytes_until_nul(&buf)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned()
    }

    #[test]
    fn bind_error_kind_is_recorded_and_cleared() {
        use raven_core::ipc::{LAN_BIND_ADDR_NOT_HERE, LAN_BIND_IN_USE};
        let _state = listener_state_test_lock();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            *LAN_BIND.lock().unwrap() = (None, None);
            assert_eq!(bind_error(), (None, None));
            let err = bind_listener("192.0.2.10:0").await.unwrap_err();
            // The service log keeps its words (the app reads them).
            assert!(err.starts_with("lan_direct bind 192.0.2.10:0: "), "{err}");
            assert_eq!(
                bind_error(),
                (Some("192.0.2.10:0".into()), Some(LAN_BIND_ADDR_NOT_HERE))
            );
            let held = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let taken = held.local_addr().unwrap().to_string();
            bind_listener(&taken).await.unwrap_err();
            assert_eq!(bind_error(), (Some(taken.clone()), Some(LAN_BIND_IN_USE)));
            drop(held);
            // A bind that works says nothing new; the listener being up
            // clears the old word.
            let listener = bind_listener("127.0.0.1:0").await.unwrap();
            assert_eq!(bind_error().1, Some(LAN_BIND_IN_USE));
            let local = listener.local_addr().unwrap();
            let up = listener_bound(local);
            assert_eq!(bind_error(), (None, None));
            drop(up);
            assert_eq!(
                bind_error(),
                (None, None),
                "a listener that ends is no bind error"
            );
        });
        assert_eq!(
            bind_error_kind(&std::io::ErrorKind::PermissionDenied.into()),
            "denied"
        );
        assert_eq!(bind_error_kind(&std::io::ErrorKind::Other.into()), "other");
    }

    /// A current-thread runtime for a test that holds
    /// [`listener_state_test_lock`] (a std guard is never held across an
    /// await of a test's own runtime).
    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    /// Serve `listeners` on its own task with a fresh profile's directory
    /// and an in-memory identity (no keystore), ending connections when
    /// `on` turns false.
    fn serve_in_background(
        listeners: Listeners,
        on: watch::Receiver<bool>,
    ) -> (tokio::task::JoinHandle<()>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let (dd, id) = (
            dir.path().to_path_buf(),
            Arc::new(Identity::from_seed(&[0x64; 32])),
        );
        let task = tokio::spawn(async move {
            match serve_listeners(&listeners, dd, id, PRODUCTION_LIMITS, on).await {}
        });
        (task, dir)
    }

    /// The listener admitted `client`: it waits for Noise message 1 (its
    /// handshake deadline is 10 s), where a refused one is closed at once.
    async fn still_open(client: &mut TcpStream) -> bool {
        let mut buf = [0u8; 8];
        tokio::time::timeout(Duration::from_millis(300), client.read(&mut buf))
            .await
            .is_err()
    }

    /// Phase 3 P3.5: `auto` with its gate live (`RAVEN_LAB_LAN_AUTO=1` in a
    /// debug build; the plan is built here with the gate passed in, so no
    /// test touches the environment) binds `0.0.0.0` and `[::]` on one
    /// port, the IPv6 socket IPv6 only, admits local sources, and `Status`
    /// lists both, IPv4 first. On a host without IPv6 (no `::1`), IPv4
    /// alone.
    #[test]
    fn auto_binds_both_families_and_lists_both() {
        use raven_core::paths::DEFAULT_LAN_PORT;
        assert_eq!(
            BindPlan::of("auto", true),
            Ok(BindPlan::Auto {
                port: DEFAULT_LAN_PORT
            })
        );
        assert_eq!(
            BindPlan::of(" AUTO:7499 ", true),
            Ok(BindPlan::Auto { port: 7499 })
        );
        assert!(BindPlan::of("auto:0", true).is_err());
        assert!(BindPlan::of("  ", true).is_err());
        // An OS-chosen port: no test binds 7420.
        let plan = BindPlan::Auto { port: 0 };
        let rule = plan.rule(false);
        assert_eq!(
            rule,
            SourceRule::LocalOnly {
                deny_loopback: false
            }
        );
        assert_eq!(plan.mode(), raven_core::ipc::LAN_MODE_ON);
        let v6_here = std::net::TcpListener::bind("[::1]:0").is_ok();
        let _state = listener_state_test_lock();
        let _lan = lan_switch_untouched();
        runtime().block_on(async {
            let listeners = bind_plan(&plan, rule).await.expect("auto binds");
            let addrs = listeners.local_addrs();
            let port = addrs[0].port();
            assert_ne!(port, 0);
            assert_eq!(addrs[0], SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)));
            if v6_here {
                assert_eq!(
                    addrs,
                    [addrs[0], SocketAddr::from((Ipv6Addr::UNSPECIFIED, port))]
                );
                assert!(
                    socket2::SockRef::from(&listeners.sockets[1])
                        .only_v6()
                        .unwrap(),
                    "the IPv6 socket is IPv6 only"
                );
            } else {
                assert_eq!(addrs.len(), 1, "{addrs:?}");
            }
            // Listed IPv4 first, however the sockets are named.
            let _plan = plan_for_test("auto", true);
            let up = listeners_bound(addrs.iter().rev().copied().collect());
            assert_eq!(listener_addrs(), addrs);
            assert_eq!(listener_addr(), Some(addrs[0]));
            let row = lan_status().expect("a LAN row");
            assert_eq!(
                (row.mode.as_str(), row.local_only),
                (raven_core::ipc::LAN_MODE_ON, true)
            );
            assert_eq!(
                row.listen,
                addrs.iter().map(ToString::to_string).collect::<Vec<_>>()
            );
            // Each family is served on its own socket; loopback is local.
            let before = NON_LOCAL_REFUSED.load(Ordering::Relaxed);
            let (_switch, on) = watch::channel(true);
            let (server, _dir) = serve_in_background(listeners, on);
            let mut targets = vec![SocketAddr::from((Ipv4Addr::LOCALHOST, port))];
            if v6_here {
                targets.push(SocketAddr::from((Ipv6Addr::LOCALHOST, port)));
            }
            for target in targets {
                let mut client = TcpStream::connect(target).await.expect("connect");
                assert!(still_open(&mut client).await, "{target}: closed");
            }
            assert_eq!(NON_LOCAL_REFUSED.load(Ordering::Relaxed), before);
            server.abort();
            let _ = server.await;
            drop(up);
        });
    }

    /// `auto` while its gate is closed (every release build today): exactly
    /// the old `0.0.0.0:<port>`, one socket, any source (the switch that
    /// counts loopback as not local does not apply), and `Status` says `on`.
    #[test]
    fn auto_with_gate_closed_is_todays_single_0_0_0_0_any_source() {
        for (raw, addr) in [("auto", "0.0.0.0:7420"), ("auto:7499", "0.0.0.0:7499")] {
            let plan = BindPlan::of(raw, false).unwrap();
            assert_eq!(
                plan,
                BindPlan::One {
                    addr: addr.into(),
                    auto: true
                }
            );
            assert_eq!(plan.rule(true), SourceRule::Any);
            assert_eq!(plan.mode(), raven_core::ipc::LAN_MODE_ON);
        }
        for ip in [
            "127.0.0.1",
            "::1",
            "192.168.1.9",
            "198.51.100.7",
            "100.64.0.9",
            "2001:db8::7",
        ] {
            assert!(SourceRule::Any.admits(ip.parse().unwrap()), "{ip}");
        }
        // Bound as today (tokio's bind, one socket), on an OS-chosen port.
        let plan = BindPlan::One {
            addr: "0.0.0.0:0".into(),
            auto: true,
        };
        let _state = listener_state_test_lock();
        runtime().block_on(async {
            let listeners = bind_plan(&plan, plan.rule(true)).await.unwrap();
            let addrs = listeners.local_addrs();
            assert_eq!(addrs.len(), 1, "{addrs:?}");
            assert!(addrs[0].is_ipv4() && addrs[0].ip().is_unspecified());
            assert_ne!(addrs[0].port(), 0);
            assert_eq!(listeners.rule, SourceRule::Any);
        });
    }

    /// `auto`'s source rule with the debug switch that counts loopback as
    /// not local (harness case C27): a connection is closed before a byte
    /// (the dialer reads end of stream, so no Noise message 2) and before
    /// admission, and counted; the service log's line holds counts only.
    #[test]
    fn a_non_local_source_is_closed_before_any_byte() {
        // Local by range whatever the host: the switch alone refuses
        // loopback. Never local on any real network: TEST-NET and the
        // IPv6 documentation prefix.
        let rule = SourceRule::LocalOnly {
            deny_loopback: true,
        };
        for (ip, admitted) in [
            ("127.0.0.1", false),
            ("::1", false),
            ("::ffff:127.0.0.1", false),
            ("10.1.2.3", true),
            ("192.168.1.9", true),
            ("169.254.7.7", true),
            ("fe80::7", true),
            ("fd00::7", true),
            ("198.51.100.7", false),
            ("203.0.113.9", false),
            ("2001:db8::7", false),
        ] {
            assert_eq!(rule.admits(ip.parse().unwrap()), admitted, "{ip}");
        }
        let build = SourceRule::LocalOnly {
            deny_loopback: false,
        };
        assert!(build.admits("127.0.0.1".parse().unwrap()));
        assert!(!build.admits("198.51.100.7".parse().unwrap()));
        let _state = listener_state_test_lock();
        runtime().block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let local = listener.local_addr().unwrap();
            let before = NON_LOCAL_REFUSED.load(Ordering::Relaxed);
            let (_switch, on) = watch::channel(true);
            let listeners = Listeners {
                sockets: vec![listener],
                rule,
            };
            let (server, _dir) = serve_in_background(listeners, on);
            let mut client = TcpStream::connect(local).await.unwrap();
            let mut buf = [0u8; 64];
            let read = tokio::time::timeout(Duration::from_secs(10), client.read(&mut buf))
                .await
                .expect("closed at once");
            assert_eq!(read.ok(), Some(0), "end of stream, not a byte");
            assert_eq!(NON_LOCAL_REFUSED.load(Ordering::Relaxed), before + 1);
            // A dialer that sends Noise message 1 gets no message 2.
            let mut dialer = TcpStream::connect(local).await.unwrap();
            let initiator = Identity::from_seed(&[0x66; 32]);
            let expected = Identity::from_seed(&[0x64; 32]).public_key_bytes();
            let dial = tokio::time::timeout(
                Duration::from_secs(10),
                initiator_session(&mut dialer, &initiator, &expected, &[]),
            )
            .await
            .expect("the dial ends");
            assert!(dial.is_err());
            assert_eq!(NON_LOCAL_REFUSED.load(Ordering::Relaxed), before + 2);
            server.abort();
            let _ = server.await;
            let line = non_local_note(before + 2);
            for addr in [local.to_string(), local.ip().to_string()] {
                assert!(!line.contains(&addr), "{line}");
            }
            assert!(
                line.contains(&format!("{} since start", before + 2)),
                "{line}"
            );
        });
    }

    /// A fixed `--lan-listen` is bound as given whatever the gate, and
    /// admits any source (`auto`'s rule and its lab switch do not apply);
    /// `Status` calls a loopback one `this-computer` and any other `fixed`.
    #[test]
    fn fixed_listen_keeps_any_source() {
        use raven_core::ipc::{LAN_MODE_FIXED, LAN_MODE_THIS_COMPUTER};
        for (raw, mode) in [
            ("127.0.0.1:7420", LAN_MODE_THIS_COMPUTER),
            ("[::1]:7420", LAN_MODE_THIS_COMPUTER),
            ("localhost:7420", LAN_MODE_THIS_COMPUTER),
            ("0.0.0.0:7420", LAN_MODE_FIXED),
            ("[::]:7420", LAN_MODE_FIXED),
            ("192.168.1.20:7420", LAN_MODE_FIXED),
            ("[fe80::1%en0]:7420", LAN_MODE_FIXED),
        ] {
            for auto_live in [false, true] {
                let plan = BindPlan::of(raw, auto_live).unwrap();
                assert_eq!(
                    plan,
                    BindPlan::One {
                        addr: raw.into(),
                        auto: false
                    },
                    "{raw}"
                );
                assert_eq!(plan.rule(true), SourceRule::Any, "{raw}");
                assert_eq!(plan.mode(), mode, "{raw}");
            }
        }
        let _state = listener_state_test_lock();
        runtime().block_on(async {
            let plan = BindPlan::of("127.0.0.1:0", true).unwrap();
            let listeners = bind_plan(&plan, plan.rule(true)).await.unwrap();
            let local = listeners.local_addrs()[0];
            let before = NON_LOCAL_REFUSED.load(Ordering::Relaxed);
            let (_switch, on) = watch::channel(true);
            let (server, _dir) = serve_in_background(listeners, on);
            let mut client = TcpStream::connect(local).await.unwrap();
            assert!(still_open(&mut client).await, "a fixed listener admits it");
            assert_eq!(NON_LOCAL_REFUSED.load(Ordering::Relaxed), before);
            server.abort();
            let _ = server.await;
        });
    }

    /// `raven lan off` closes the port within a second, ends the connections
    /// it had accepted and lists nothing; `on` binds the same port again and
    /// tells the outbox (`up`) once more. Driven by a switch of the test's
    /// own, so no other test sees it.
    #[test]
    fn lan_off_closes_the_port_within_1s_and_on_reopens_it() {
        use std::sync::atomic::AtomicUsize;
        let _state = listener_state_test_lock();
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|l| l.local_addr())
            .unwrap()
            .port();
        let at = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let plan = BindPlan::of(&at.to_string(), false).unwrap();
        runtime().block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let (dd, id) = (
                dir.path().to_path_buf(),
                Arc::new(Identity::from_seed(&[0x67; 32])),
            );
            let ups = Arc::new(AtomicUsize::new(0));
            let (switch, on) = watch::channel(true);
            let told = Arc::clone(&ups);
            let server = tokio::spawn(async move {
                let up = move || {
                    told.fetch_add(1, Ordering::SeqCst);
                };
                match serve_while_on(&plan, SourceRule::Any, dd, id, PRODUCTION_LIMITS, on, up)
                    .await {}
            });
            let listed = || async {
                let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
                while listener_addrs() != [at] {
                    assert!(tokio::time::Instant::now() < deadline, "not listening");
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            };
            listed().await;
            assert!(listener_is_up());
            assert_eq!(ups.load(Ordering::SeqCst), 1, "back on the network");
            let mut held = TcpStream::connect(at).await.unwrap();
            assert!(still_open(&mut held).await);

            switch.send_replace(false);
            let off_at = std::time::Instant::now();
            loop {
                // Only an accepted connect says the port is open (a refused
                // one takes seconds on Windows).
                let accepted = matches!(
                    tokio::time::timeout(Duration::from_millis(200), TcpStream::connect(at)).await,
                    Ok(Ok(_))
                );
                if !accepted && listener_addrs().is_empty() && !listener_is_up() {
                    break;
                }
                assert!(
                    off_at.elapsed() < Duration::from_secs(1),
                    "still open 1 s after lan off"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            let mut buf = [0u8; 8];
            let ended = tokio::time::timeout(Duration::from_secs(1), held.read(&mut buf))
                .await
                .expect("its connection ended with it");
            assert!(matches!(ended, Ok(0) | Err(_)), "{ended:?}");
            assert_eq!(bind_error(), (None, None), "off is not a failed bind");
            assert_eq!(ups.load(Ordering::SeqCst), 1);

            switch.send_replace(true);
            listed().await;
            assert_eq!(ups.load(Ordering::SeqCst), 2, "back on the network again");
            let mut again = TcpStream::connect(at).await.expect("reopened");
            assert!(still_open(&mut again).await);
            server.abort();
            let _ = server.await;
            assert!(listener_addrs().is_empty());
        });
    }

    /// The service's listener reads `--lan-listen` and loads the identity
    /// once, after its preflight (the LAN beacon answers with that one and
    /// never opens the keystore); `Status.lan` reports its plan from then
    /// on. Needs the lab backend (a real preflight).
    #[test]
    fn the_listener_keeps_its_identity_for_the_beacon() {
        if !lab_backend_available() {
            return;
        }
        let _state = listener_state_test_lock();
        let _lan = lan_switch_untouched();
        let _cleared = ListenerStateForTest;
        runtime().block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let (identity, _) = raven_core::load_or_create_identity(dir.path()).unwrap();
            assert!(listener_identity().is_none());
            let task = tokio::spawn(run_listener_with_limits(
                dir.path().to_path_buf(),
                "127.0.0.1:0".into(),
                PRODUCTION_LIMITS,
            ));
            let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
            while !listener_is_up() {
                assert!(tokio::time::Instant::now() < deadline, "not listening");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            assert_eq!(
                listener_identity().map(|id| id.public_key_bytes()),
                Some(identity.public_key_bytes())
            );
            let row = lan_status().expect("a LAN row");
            assert_eq!(
                (row.mode.as_str(), row.local_only),
                (raven_core::ipc::LAN_MODE_THIS_COMPUTER, false)
            );
            assert_eq!(row.listen, vec![listener_addr().unwrap().to_string()]);
            task.abort();
            let _ = task.await;
            assert!(!listener_is_up());
        });
    }

    fn test_slot() -> AdmissionSlot {
        Admission::new(PRODUCTION_LIMITS)
            .try_admit("127.0.0.1".parse().unwrap())
            .expect("slot")
    }

    /// Regression: inbound connections used to call load_identity_required
    /// (exclusive SQLite lock + secret store, blocking) before the handshake.
    /// The listener's identity is now used; the data dir here has none at all.
    #[tokio::test]
    async fn inbound_handshake_uses_listener_identity_not_store() {
        let dir = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let responder = Arc::new(Identity::from_seed(&[0x51; 32]));
        let expected = responder.public_key_bytes();
        let data_dir = dir.path().to_path_buf();
        let initiator = Identity::from_seed(&[0x52; 32]);
        write_contacts(dir.path(), &[&initiator]);
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut slot = test_slot();
            handle_inbound(
                data_dir,
                responder,
                stream,
                PRODUCTION_LIMITS,
                &mut slot,
                LOOPBACK_DIALER,
            )
            .await
        });
        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut transport = initiator_session(&mut client, &initiator, &expected, &[])
            .await
            .expect("Noise XX + bind with the listener's in-memory identity");
        write_cipher(&mut client, &mut transport, b"not-an-rlb1-offer")
            .await
            .unwrap();
        let err = tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .expect("inbound handler finishes")
            .unwrap()
            .unwrap_err();
        assert!(!err.is_empty());
    }

    /// Real prekeys need the documented lab backend (debug builds only), which
    /// the Linux CI job exports for the whole run. Elsewhere the test is skipped
    /// rather than risk a keystore prompt.
    fn lab_backend_available() -> bool {
        let lab = ["RAVEN_PREKEY_BACKEND", "RAVEN_IDENTITY_BACKEND"]
            .iter()
            .any(|k| std::env::var(k).is_ok_and(|v| v == "locked-file"));
        if !(cfg!(debug_assertions) && lab) {
            eprintln!("skipped: needs a debug build and RAVEN_IDENTITY_BACKEND=locked-file");
            return false;
        }
        true
    }

    /// Admit from `ip` until the pre-auth cap says no; returns how many more
    /// pre-auth connections that source could still open.
    fn spare_preauth_slots(admission: &Arc<netutil::Admission>, ip: std::net::IpAddr) -> usize {
        let mut held = Vec::new();
        while let Some(s) = admission.try_admit(ip) {
            held.push(s);
        }
        held.len()
    }

    fn write_contacts(dir: &Path, contacts: &[&Identity]) {
        let rows: Vec<String> = contacts
            .iter()
            .map(|c| format!(r#"{{"pub_hex":"{}"}}"#, hex::encode(c.public_key_bytes())))
            .collect();
        std::fs::write(dir.join("contacts.json"), format!("[{}]", rows.join(","))).unwrap();
    }

    /// An RLB1 offer proves the peer holds *a* key, nothing more: anyone can
    /// generate an identity and self-sign a bundle. Only a local contact (the
    /// only peer whose PairInit / messages / ACKs are accepted) may therefore
    /// leave the pre-auth caps for a slot newcomers cannot displace. (A
    /// stranger never gets that far: see `stranger_learns_nothing_but_not_accepted`.)
    #[tokio::test]
    async fn only_a_local_contact_earns_a_protected_slot() {
        if !lab_backend_available() {
            return;
        }
        let ip: std::net::IpAddr = "10.9.8.7".parse().unwrap();
        let resp_dir = tempfile::tempdir().unwrap();
        let init_dir = tempfile::tempdir().unwrap();
        let responder = Arc::new(Identity::from_seed(&[0x71; 32]));
        let initiator = Identity::from_seed(&[0x72; 32]);
        write_contacts(resp_dir.path(), &[&initiator]);
        let admission = Admission::new(PRODUCTION_LIMITS);
        let mut slot = admission.try_admit(ip).expect("slot");
        let (mut client, server_side) = tokio::io::duplex(1 << 18);
        let (data_dir, resp) = (resp_dir.path().to_path_buf(), responder.clone());
        let server = tokio::spawn(async move {
            handle_inbound(
                data_dir,
                resp,
                server_side,
                PRODUCTION_LIMITS,
                &mut slot,
                LOOPBACK_DIALER,
            )
            .await
        });
        let mut t = initiator_session(&mut client, &initiator, &responder.public_key_bytes(), &[])
            .await
            .expect("Noise XX + bind");
        let offer = encode_local_offer(init_dir.path(), &initiator).unwrap();
        write_cipher(&mut client, &mut t, &offer).await.unwrap();
        // The responder's own offer is written after it decided.
        let theirs = read_cipher(&mut client, &mut t).await.unwrap();
        assert!(parse_peer_offer(&theirs).is_ok(), "a contact gets our RLB1");
        assert_eq!(
            spare_preauth_slots(&admission, ip),
            PRODUCTION_LIMITS.max_handshaking_per_ip,
            "a contact no longer counts as pre-auth"
        );
        drop(client);
        tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .expect("handler ends when the dialer hangs up")
            .unwrap()
            .unwrap();
    }

    /// Phase 6b S1 (P6.24): a contact's frame after RLB1 whose ciphertext
    /// changed on the way is one `SEC_LINK_TAG_FAIL` about that contact (its
    /// path on this network), and the link closes as before: the handler
    /// ends without an error, nothing more is written.
    #[tokio::test]
    async fn a_flipped_byte_after_rlb1_is_one_tag_failure_about_the_contact() {
        use crate::security::tests::Capture;
        use raven_core::security_events::{Attribution, SecKind, Via};
        if !lab_backend_available() {
            return;
        }
        let Some(capture) = Capture::start() else {
            return;
        };
        let resp_dir = tempfile::tempdir().unwrap();
        let init_dir = tempfile::tempdir().unwrap();
        let responder = Arc::new(Identity::from_seed(&[0x93; 32]));
        let initiator = Identity::from_seed(&[0x94; 32]);
        write_contacts(resp_dir.path(), &[&initiator]);
        let (mut client, server_side) = tokio::io::duplex(1 << 18);
        let (data_dir, resp) = (resp_dir.path().to_path_buf(), responder.clone());
        let server = tokio::spawn(async move {
            let mut slot = test_slot();
            handle_inbound(
                data_dir,
                resp,
                server_side,
                PRODUCTION_LIMITS,
                &mut slot,
                LOOPBACK_DIALER,
            )
            .await
        });
        let mut t = initiator_session(&mut client, &initiator, &responder.public_key_bytes(), &[])
            .await
            .expect("Noise XX + bind");
        let offer = encode_local_offer(init_dir.path(), &initiator).unwrap();
        write_cipher(&mut client, &mut t, &offer).await.unwrap();
        let theirs = read_cipher(&mut client, &mut t).await.unwrap();
        assert!(parse_peer_offer(&theirs).is_ok(), "a contact gets our RLB1");
        let mut ct = transport_encrypt(&mut t.transport, &message_frame(14)).unwrap();
        ct[0] ^= 0x01;
        write_raw(&mut client, &ct).await.unwrap();
        let ended = tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .expect("the link closes")
            .unwrap();
        assert_eq!(ended, Ok(()), "closed as before");
        let mut rest = Vec::new();
        assert_eq!(client.read_to_end(&mut rest).await.unwrap_or(0), 0);
        assert_eq!(
            capture.kinds(),
            [(
                SecKind::LinkTagFail,
                Attribution::Contact {
                    peer: initiator.public_key_bytes()
                },
                Via::DirectLink(raven_core::OutboxCarrier::Lan)
            )]
        );
    }

    /// Phase 6b S3 (P6.24): a stranger that completes the handshake at the
    /// listener is one network Notice, noted by the accept loop against its
    /// source (its throwaway key is never kept), and nothing is written (no
    /// ledger: the writer keeps network events in memory, see
    /// `security::tests`). The stranger sees what it saw before.
    #[tokio::test]
    async fn a_strangers_handshake_is_one_network_notice_and_no_write() {
        use crate::security::tests::Capture;
        use raven_core::security_events::{
            threshold, Attribution, SecKind, Severity, SourceKey, Via,
        };
        let Some(capture) = Capture::start() else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let responder = Arc::new(Identity::from_seed(&[0x98; 32]));
        let stranger = Identity::from_seed(&[0x99; 32]);
        let listener = Arc::new(TcpListener::bind("127.0.0.1:0").await.unwrap());
        let addr = listener.local_addr().unwrap();
        let (dd, resp) = (dir.path().to_path_buf(), responder.clone());
        let server = tokio::spawn(netutil::serve_connections(
            "lan_direct",
            move || {
                let listener = listener.clone();
                async move { listener.accept().await }
            },
            PRODUCTION_LIMITS,
            move |stream, mut slot| {
                let (dd, id) = (dd.clone(), resp.clone());
                async move {
                    let source = stream.peer_addr().ok();
                    handle_inbound(dd, id, stream, PRODUCTION_LIMITS, &mut slot, source).await
                }
            },
        ));
        let mut client = TcpStream::connect(addr).await.unwrap();
        let err = initiator_session(&mut client, &stranger, &responder.public_key_bytes(), &[])
            .await
            .err()
            .unwrap_or_else(|| panic!("a stranger gets no bind"));
        assert_eq!(err, netutil::LINK_NOT_ACCEPTED);
        let seen = capture.until(1).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(capture.events().len(), 1, "{seen:?}");
        assert_eq!(
            capture.kinds(),
            [(
                SecKind::StrangerRefused,
                Attribution::Network {
                    source: SourceKey::of("127.0.0.1".parse().unwrap())
                },
                Via::DirectLink(raven_core::OutboxCarrier::Lan)
            )]
        );
        let row = threshold(SecKind::StrangerRefused);
        assert_eq!(
            (row.base, row.suspicious, row.alert),
            (Severity::Notice, None, None),
            "a Notice, never more"
        );
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert!(
            !names
                .iter()
                .any(|n| n.to_string_lossy().starts_with("security")),
            "{names:?}"
        );
        server.abort();
    }

    /// One junk handshake to `addr` (a Noise message that does not parse);
    /// returns once the listener closed the connection.
    async fn junk_handshake(addr: SocketAddr) {
        let mut c = TcpStream::connect(addr).await.unwrap();
        let _ = c.write_all(&[0, 0, 0, 5, 1, 2, 3, 4, 5]).await;
        let mut rest = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(20), c.read_to_end(&mut rest)).await;
    }

    /// `contact`'s link to `addr` up to the listener's RLB1 offer (which
    /// comes only after the slot was authenticated).
    async fn contact_link(
        addr: SocketAddr,
        contact: &Identity,
        dir: &Path,
        listener_key: &[u8; 32],
    ) -> TcpStream {
        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut t = initiator_session(&mut client, contact, listener_key, &[])
            .await
            .expect("Noise XX + bind");
        let offer = encode_local_offer(dir, contact).unwrap();
        write_cipher(&mut client, &mut t, &offer).await.unwrap();
        let theirs = read_cipher(&mut client, &mut t).await.unwrap();
        assert!(parse_peer_offer(&theirs).is_ok(), "a contact gets our RLB1");
        client
    }

    /// Phase 6b R1 (P6.26), through the real accept loop and handler, each
    /// loopback socket stamped with a scripted source: 16 junk handshakes
    /// from 10.0.0.9 ban it (one SEC_PREAUTH_FLOOD); a contact at 10.0.0.10
    /// is unaffected; the contact connecting from the banned address gets
    /// the probation connection, completes RLB1 and clears the ban. Banned
    /// again, a junk connection takes the probation and the next one is
    /// closed at once, before any handshake (and noted nowhere).
    #[tokio::test]
    async fn junk_handshakes_ban_a_source_and_a_contact_still_gets_in() {
        use crate::security::tests::{Capture, Responding};
        use raven_core::security_events::SecKind;
        use std::net::IpAddr;
        if !lab_backend_available() {
            return;
        }
        let Some(capture) = Capture::start() else {
            return;
        };
        let Some(_responding) = Responding::start() else {
            return;
        };
        let resp_dir = tempfile::tempdir().unwrap();
        let init_dir = tempfile::tempdir().unwrap();
        let responder = Arc::new(Identity::from_seed(&[0x9a; 32]));
        let contact = Identity::from_seed(&[0x9b; 32]);
        write_contacts(resp_dir.path(), &[&contact]);
        let listener = Arc::new(TcpListener::bind("127.0.0.1:0").await.unwrap());
        let addr = listener.local_addr().unwrap();
        // The source the next accepted socket is stamped with.
        let next = Arc::new(std::sync::Mutex::new(IpAddr::from([10, 0, 0, 9])));
        let stamp = next.clone();
        let (dd, resp) = (resp_dir.path().to_path_buf(), responder.clone());
        let server = tokio::spawn(netutil::serve_connections(
            "lan_direct",
            move || {
                let (listener, stamp) = (listener.clone(), stamp.clone());
                async move {
                    let (stream, peer) = listener.accept().await?;
                    let ip = *stamp.lock().unwrap();
                    Ok((stream, SocketAddr::new(ip, peer.port())))
                }
            },
            PRODUCTION_LIMITS,
            move |stream, mut slot| {
                let (dd, id) = (dd.clone(), resp.clone());
                async move {
                    let source = stream.peer_addr().ok();
                    handle_inbound(dd, id, stream, PRODUCTION_LIMITS, &mut slot, source).await
                }
            },
        ));
        let (bad, friend) = (IpAddr::from([10, 0, 0, 9]), IpAddr::from([10, 0, 0, 10]));
        let count = |kind: SecKind| capture.events().iter().filter(|e| e.kind == kind).count();
        let key = responder.public_key_bytes();

        for n in 1..=16 {
            junk_handshake(addr).await;
            capture.until(n).await;
        }
        let seen = capture.until(17).await;
        assert_eq!(count(SecKind::HandshakeFail), 16, "{seen:?}");
        assert_eq!(count(SecKind::PreauthFlood), 1, "one per ban");
        assert!(crate::security::source_banned(bad));

        // A contact at another address: unaffected.
        *next.lock().unwrap() = friend;
        drop(contact_link(addr, &contact, init_dir.path(), &key).await);
        assert!(!crate::security::source_banned(friend));
        // The contact from the banned address: the probation connection,
        // and its authentication clears the source.
        *next.lock().unwrap() = bad;
        drop(contact_link(addr, &contact, init_dir.path(), &key).await);
        assert!(!crate::security::source_banned(bad), "cleared");
        assert_eq!(count(SecKind::HandshakeFail), 16, "no failure since");

        // Banned again; a junk connection takes the probation...
        for n in 1..=16 {
            junk_handshake(addr).await;
            capture.until(17 + n).await;
        }
        assert!(crate::security::source_banned(bad));
        assert_eq!(count(SecKind::PreauthFlood), 2);
        junk_handshake(addr).await;
        let noted = capture.until(35).await.len();
        assert_eq!(count(SecKind::HandshakeFail), 33);
        // ...and the next connection is closed before any handshake: no
        // bytes, no wait for the handshake deadline, nothing noted.
        let mut refused = TcpStream::connect(addr).await.unwrap();
        let mut rest = Vec::new();
        let closed = tokio::time::timeout(Duration::from_secs(5), refused.read_to_end(&mut rest))
            .await
            .expect("closed at once");
        assert!(matches!(closed, Ok(0) | Err(_)), "{closed:?}");
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(capture.events().len(), noted);
        crate::security::source_authenticated(bad, raven_core::OutboxCarrier::Lan);
        server.abort();
    }

    /// F4: a dialer that completes Noise XX with a key that is not a local
    /// contact (or is blocked) gets the connection closed right after its own
    /// bind. It never receives a single transport frame: not our bind (Raven
    /// identity), not our RLB1 (certificate + prekey bundle). Its error is the
    /// fixed `LINK_NOT_ACCEPTED`, never retried; the responder logs a fixed,
    /// key-free reason.
    #[tokio::test]
    async fn stranger_learns_nothing_but_not_accepted() {
        // P3.14: with the session renewer running, no refused key is queued.
        let _renewer = crate::renewal::RunningForTest::set();
        let responder = Arc::new(Identity::from_seed(&[0x75; 32]));
        let stranger = Identity::from_seed(&[0x76; 32]);
        let other = Identity::from_seed(&[0x77; 32]);
        for case in [
            "no contacts.json",
            "other contact",
            "blocked contact",
            "corrupt book",
            "unverified contact, verified-only",
        ] {
            let resp_dir = tempfile::tempdir().unwrap();
            match case {
                "other contact" => write_contacts(resp_dir.path(), &[&other]),
                "blocked contact" => {
                    write_contacts(resp_dir.path(), &[&stranger]);
                    let mut blocks = raven_core::BlockList::default();
                    blocks.block(&hex::encode(stranger.public_key_bytes()));
                    blocks.save(resp_dir.path()).unwrap();
                }
                "corrupt book" => {
                    std::fs::write(resp_dir.path().join("contacts.json"), "{not json").unwrap()
                }
                // Phase 3 P3.C2: a contact, but not verified, from this
                // computer (a local source) while `raven lan verified-only
                // on` holds.
                "unverified contact, verified-only" => {
                    write_contacts(resp_dir.path(), &[&stranger]);
                    raven_core::node_policy::set_lan_verified_only(resp_dir.path(), true).unwrap();
                }
                _ => {}
            }
            let (mut client, server_side) = tokio::io::duplex(1 << 18);
            let (data_dir, resp) = (resp_dir.path().to_path_buf(), responder.clone());
            let server = tokio::spawn(async move {
                let mut slot = test_slot();
                handle_inbound(
                    data_dir,
                    resp,
                    server_side,
                    PRODUCTION_LIMITS,
                    &mut slot,
                    LOOPBACK_DIALER,
                )
                .await
            });
            let err = initiator_session(&mut client, &stranger, &responder.public_key_bytes(), &[])
                .await
                .err()
                .unwrap_or_else(|| panic!("{case}: stranger must not get our bind"));
            assert_eq!(err, netutil::LINK_NOT_ACCEPTED, "{case}");
            let refusal = tokio::time::timeout(Duration::from_secs(10), server)
                .await
                .expect("handler ends")
                .unwrap()
                .unwrap_err();
            let want = match case {
                "blocked contact" => raven_core::lan_dispatch::LINK_REFUSED_BLOCKED,
                "unverified contact, verified-only" => {
                    raven_core::lan_dispatch::LINK_REFUSED_VERIFIED_ONLY
                }
                _ => raven_core::lan_dispatch::LINK_REFUSED_NOT_CONTACT,
            };
            assert_eq!(refusal, want, "{case}");
            assert!(!refusal.contains(&hex::encode(stranger.public_key_bytes())));
            assert!(
                !crate::renewal::queued_for_test(&stranger.public_key_bytes()),
                "{case}: no renewal for a refused key"
            );
            // Nothing but the close follows the handshake.
            let mut rest = Vec::new();
            let n = client.read_to_end(&mut rest).await.unwrap_or(0);
            assert_eq!(n, 0, "{case}: no byte after the stranger's bind");
        }
    }

    /// Phase 3 P3.C2 (cutoff M1): with `raven lan verified-only on` the
    /// listener refuses an unverified contact dialling from this computer (a
    /// local source, as every source is in a cutoff) right after its bind,
    /// exactly as a stranger, before our bind (the dialer's fixed
    /// `LINK_NOT_ACCEPTED`). A verified contact is admitted, and with the
    /// setting off again the unverified one is too. Read from
    /// node_policy.json at each link: no restart.
    #[tokio::test]
    async fn verified_only_refuses_an_unpinned_contact_before_our_bind() {
        let responder = Arc::new(Identity::from_seed(&[0x8a; 32]));
        let (plain, pinned) = (
            Identity::from_seed(&[0x8b; 32]),
            Identity::from_seed(&[0x8c; 32]),
        );
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        std::fs::write(
            dd.join("contacts.json"),
            format!(
                r#"[{{"pub_hex":"{}"}},{{"pub_hex":"{}","pinned":true}}]"#,
                hex::encode(plain.public_key_bytes()),
                hex::encode(pinned.public_key_bytes())
            ),
        )
        .unwrap();
        assert_eq!(dial_once(dd, &responder, &plain).await, Ok(()), "as before");
        raven_core::node_policy::set_lan_verified_only(dd, true).unwrap();
        let (dialer_err, refusal) = dial_once(dd, &responder, &plain).await.unwrap_err();
        assert_eq!(dialer_err, netutil::LINK_NOT_ACCEPTED);
        assert_eq!(
            refusal,
            raven_core::lan_dispatch::LINK_REFUSED_VERIFIED_ONLY
        );
        assert!(refusal.starts_with(raven_core::LAN_VERIFIED_ONLY));
        assert!(!refusal.contains(&hex::encode(plain.public_key_bytes())));
        // (No byte follows its bind: `stranger_learns_nothing_but_not_accepted`.)
        assert_eq!(dial_once(dd, &responder, &pinned).await, Ok(()));
        raven_core::node_policy::set_lan_verified_only(dd, false).unwrap();
        assert_eq!(dial_once(dd, &responder, &plain).await, Ok(()));
    }

    /// Phase 3 P3.C2: under `raven lan verified-only on` a LAN dial to an
    /// unverified contact is refused before it connects (the listener at
    /// its address never sees a connection), in the code the outbox holds it
    /// by; a verified contact's dial gets past that check.
    #[tokio::test]
    async fn a_dial_to_an_unverified_contact_under_verified_only_connects_nowhere() {
        let _lan = lan_switch_untouched();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let at = listener.local_addr().unwrap().to_string();
        let (plain, pinned) = ([0x8du8; 32], [0x8eu8; 32]);
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        std::fs::write(
            dd.join("contacts.json"),
            format!(
                r#"[{{"pub_hex":"{}"}},{{"pub_hex":"{}","pinned":true}}]"#,
                hex::encode(plain),
                hex::encode(pinned)
            ),
        )
        .unwrap();
        raven_core::node_policy::set_lan_verified_only(dd, true).unwrap();
        let err = dial(dd, &at, &hex::encode(plain), &[]).await.unwrap_err();
        assert_eq!(err, VERIFIED_ONLY_DIAL);
        assert!(err.starts_with(raven_core::LAN_VERIFIED_ONLY));
        assert_eq!(
            crate::outbox::dial_error_code(&err),
            raven_core::CONTACT_NOT_VERIFIED
        );
        assert!(
            matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock),
            "nothing connected"
        );
        // A verified contact's dial gets past the check (here it fails on
        // the missing identity, before it connects too).
        let err = dial(dd, &at, &hex::encode(pinned), &[]).await.unwrap_err();
        assert_ne!(err, VERIFIED_ONLY_DIAL);
    }

    /// B-3: a LAN dial planned before `raven lan off` (or before a meeting
    /// ended) connects nowhere once LAN is off: refused in IPC LanDial's
    /// words, the listener at its address sees nothing; announce links too.
    #[tokio::test]
    async fn a_dial_after_lan_off_connects_nowhere() {
        let _lan = lan_switch_for_test();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let at = listener.local_addr().unwrap().to_string();
        let contact = hex::encode([0x8fu8; 32]);
        let dir = tempfile::tempdir().unwrap();
        set_lan_on(false);
        let lan_off = format!(
            "{}: raven lan off is in effect (raven lan on)",
            raven_core::LAN_OFF
        );
        assert_eq!(
            dial(dir.path(), &at, &contact, &[]).await.unwrap_err(),
            lan_off
        );
        assert_eq!(
            dial_announce(dir.path(), &at, &contact).await.unwrap_err(),
            lan_off
        );
        assert!(
            matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock),
            "nothing connected"
        );
        // LAN on: the dial gets past the check (and fails later here, on
        // the missing identity).
        set_lan_on(true);
        let err = dial(dir.path(), &at, &contact, &[]).await.unwrap_err();
        assert_ne!(err, lan_off);
    }

    /// Learning connectivity (Phase 6a): a real LAN dial that connects
    /// nowhere (nobody listens) and an announce link are each observed once,
    /// on the LAN arm of the dial's network; a dial that fails before it
    /// connects (no identity here) says nothing about the route.
    #[tokio::test]
    async fn a_lan_dial_is_observed_once_it_connects() {
        if !crate::outbox::test_rig::lab_backends() {
            return;
        }
        let _lan = lan_switch_for_test();
        let free = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let at = free.local_addr().unwrap().to_string();
        drop(free);
        let contact = [0x8eu8; 32];
        let bare = tempfile::tempdir().unwrap();
        let mut learning = crate::learning::TestService::loaded(bare.path(), Some("home"));
        dial(bare.path(), &at, &hex::encode(contact), &[])
            .await
            .unwrap_err();
        assert_eq!(learning.drain(), 0, "no identity: nothing dialled");
        let dir = tempfile::tempdir().unwrap();
        let id = raven_core::load_or_create_identity(dir.path()).unwrap().0;
        raven_core::device_cert::ensure_local_device_certificate(
            dir.path(),
            &id,
            raven_core::paths::PRIMARY_DEVICE_ID,
        )
        .unwrap();
        raven_core::ensure_local_prekey(dir.path(), &id).unwrap();
        let err = dial(dir.path(), &at, &hex::encode(contact), &[])
            .await
            .unwrap_err();
        assert_eq!(
            crate::outbox::dial_error_code(&err),
            "NOT_LISTENING",
            "{err}"
        );
        dial_announce(dir.path(), &at, &hex::encode(contact))
            .await
            .unwrap_err();
        assert_eq!(learning.drain(), 2);
        let arm = learning
            .model()
            .unwrap()
            .arm(&raven_core::learning::model::ArmKey {
                contact,
                net: Some("home".into()),
                carrier: raven_core::OutboxCarrier::Lan,
            })
            .copied()
            .expect("the LAN arm");
        // Two NOT_LISTENING failures (250 each).
        assert_eq!((arm.beta.a_m, arm.beta.b_m, arm.tries()), (0, 500, (0, 2)));
    }

    /// Four LAN dials to `contact` on the current network that linked in
    /// `connect_ms` and got their ACK `reply_ms` after the frames, as the
    /// carrier hook posts them; applied (the arm is then warm).
    fn warm_lan_arm(
        learning: &mut crate::learning::TestService,
        contact: &[u8; 32],
        connect_ms: u32,
        reply_ms: u32,
    ) {
        let frames = vec![message_frame(1)];
        for _ in 0..4 {
            crate::learning::observe_dial(
                contact,
                raven_core::OutboxCarrier::Lan,
                Some(raven_core::outbox::DeliveryPath::Direct),
                None,
                &frames,
                &Ok(vec![ack_frame(1)]),
                &raven_core::learning::observe::DialTiming {
                    connect_ms: Some(connect_ms),
                    reply_ms: Some(reply_ms),
                    total_ms: connect_ms + reply_ms,
                },
                crate::learning::Expired::default(),
                DialMeta::default(),
                crate::learning::net(),
            );
        }
        assert_eq!(learning.drain(), 4);
    }

    /// The LAN arm of `contact` on network "home".
    fn lan_arm(
        learning: &crate::learning::TestService,
        contact: [u8; 32],
    ) -> raven_core::learning::model::Arm {
        learning
            .model()
            .unwrap()
            .arm(&raven_core::learning::model::ArmKey {
                contact,
                net: Some("home".into()),
                carrier: raven_core::OutboxCarrier::Lan,
            })
            .copied()
            .expect("the LAN arm")
    }

    /// P6.13: with a warm LAN arm (links in 20 ms) the per-address connect
    /// wait is the 1.5 s floor, not today's 5 s: a real dial to an address
    /// that never answers (a full listen queue on loopback) gives up after
    /// 1.5 s and within 3 s, names the wait it used, and that wait backs
    /// off. On tokio's paused clock: it moves only while nothing else can
    /// run (never during the identity load on the blocking pool), so the
    /// dial's time is its connect wait whatever the machine's load.
    #[tokio::test(start_paused = true)]
    async fn a_warm_lan_arm_gives_up_a_black_hole_after_1500ms() {
        if !file_backends() {
            return;
        }
        let _lan = lan_switch_untouched();
        let Some((hole, _listener, _queued)) = netutil::black_hole() else {
            return;
        };
        let contact = [0x8fu8; 32];
        let dir = tempfile::tempdir().unwrap();
        dialer_profile(dir.path());
        let mut learning = crate::learning::TestService::loaded(dir.path(), Some("home"));
        warm_lan_arm(&mut learning, &contact, 20, 50);
        let w = crate::learning::waits(&contact, raven_core::OutboxCarrier::Lan);
        assert_eq!(w.connect, Duration::from_millis(1_500));
        let started = tokio::time::Instant::now();
        let err = dial_with_meta(
            dir.path(),
            &hole.to_string(),
            &hex::encode(contact),
            &[message_frame(2)],
            DialMeta::default(),
        )
        .await
        .unwrap_err();
        let took = started.elapsed();
        assert!(took < Duration::from_secs(3), "{took:?}: {err}");
        assert!(took >= Duration::from_millis(1_500), "{took:?}: {err}");
        assert!(err.ends_with(": no answer within 1.5s)"), "{err}");
        assert_eq!(
            crate::outbox::dial_error_code(&err),
            "NOT_REACHABLE",
            "{err}"
        );
        assert_eq!(learning.drain(), 1);
        let arm = lan_arm(&learning, contact);
        assert_eq!((arm.connect.n, arm.connect.backoff), (4, 1), "backed off");
        assert_eq!(arm.tries(), (4, 5));
    }

    /// P6.13: a responder that completes Noise and RLB1, takes the message
    /// and never replies is left after the learned first-reply wait (the
    /// 6 s floor for 50 ms replies), not today's 30 s: the dial ends with
    /// the offer only (waiting for an ACK), and the reply wait backs off.
    #[tokio::test]
    async fn a_stalled_responder_is_left_after_the_learned_reply_wait_not_30s() {
        if !file_backends() {
            return;
        }
        let _lan = lan_switch_untouched();
        let (a_dir, b_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let alice = dialer_profile(a_dir.path());
        let bob = Identity::from_seed(&[0x9c; 32]);
        write_book(a_dir.path(), &[(&bob, true)]);
        let bob_offer = encode_local_offer(b_dir.path(), &bob).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let offer = bob_offer.clone();
        let stalled = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (dialer_ed, mut t) = responder_session(&mut stream, &bob).await.unwrap();
            let theirs = read_cipher(&mut stream, &mut t).await.unwrap();
            write_cipher(&mut stream, &mut t, &offer).await.unwrap();
            let mut got = Vec::new();
            // Reads everything, answers nothing, until the dialer leaves.
            while let Ok(frame) = read_cipher(&mut stream, &mut t).await {
                got.push(frame);
            }
            (dialer_ed, parse_peer_offer(&theirs).is_ok(), got)
        });
        let contact = Identity::from_seed(&[0x9c; 32]).public_key_bytes();
        let mut learning = crate::learning::TestService::loaded(a_dir.path(), Some("home"));
        warm_lan_arm(&mut learning, &contact, 20, 50);
        let w = crate::learning::waits(&contact, raven_core::OutboxCarrier::Lan);
        assert_eq!(w.reply_first, Duration::from_secs(6));
        let frame = message_frame(3);
        let started = std::time::Instant::now();
        let replies = dial_with_meta(
            a_dir.path(),
            &addr,
            &hex::encode(contact),
            std::slice::from_ref(&frame),
            DialMeta::default(),
        )
        .await
        .unwrap();
        let took = started.elapsed();
        assert!(took >= Duration::from_secs(6), "{took:?}");
        assert!(took < Duration::from_secs(20), "{took:?}");
        assert_eq!(replies, vec![bob_offer], "the offer only: no ACK yet");
        let (dialer_ed, offer_ok, got) = tokio::time::timeout(Duration::from_secs(10), stalled)
            .await
            .expect("the responder sees the dialer leave")
            .unwrap();
        assert_eq!(dialer_ed, alice.public_key_bytes());
        assert!(offer_ok);
        assert_eq!(got, vec![frame], "the message was written");
        assert_eq!(learning.drain(), 1);
        let arm = lan_arm(&learning, contact);
        assert_eq!((arm.reply.n, arm.reply.backoff), (4, 1), "backed off");
        assert_eq!(arm.connect.n, 5, "the link itself was a sample");
        // Silent: no receipt.
        assert_eq!(arm.tries(), (4, 5));
    }

    /// The Phase 3 re-verify's B-3 follow-on: [`dial_session`] refuses
    /// while the process-wide LAN switch is off, and other tests turn it off
    /// for a moment. Every test in this file that dials through it holds the
    /// switch untouched (or turns it itself), so none of them can see
    /// LAN_OFF. Read from this file: the race is too short to show itself.
    #[test]
    fn every_test_that_dials_holds_the_lan_switch() {
        const ME: &str = "every_test_that_dials_holds_the_lan_switch";
        let source = include_str!("lan_direct.rs");
        let tests = &source[source.find("\nmod tests {").expect("the tests")..];
        // A call of `name`, not of a longer name or a method.
        let calls = |body: &str, name: &str| {
            body.match_indices(&format!("{name}(")).any(|(at, _)| {
                !body[..at]
                    .chars()
                    .next_back()
                    .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
            })
        };
        let lines: Vec<&str> = tests.lines().collect();
        let mut dialing = Vec::new();
        for (at, line) in lines.iter().enumerate() {
            let line = line.trim();
            if !(line == "#[test]" || line.starts_with("#[tokio::test")) {
                continue;
            }
            let head = (at..lines.len())
                .find(|i| lines[*i].contains("fn "))
                .expect("a test function");
            let end = (head..lines.len())
                .find(|i| lines[*i] == "    }")
                .expect("its end");
            let name = lines[head].split("fn ").nth(1).unwrap_or_default();
            let name = &name[..name.find('(').unwrap_or(name.len())];
            if name == ME {
                continue;
            }
            let body = lines[head..end].join("\n");
            if [
                "dial",
                "dial_with_meta",
                "dial_announce",
                "full_dial",
                "dial_session",
            ]
            .iter()
            .any(|f| calls(&body, f))
            {
                assert!(
                    body.contains("lan_switch_untouched()")
                        || body.contains("lan_switch_for_test()"),
                    "{name} dials without holding the LAN switch"
                );
                dialing.push(name);
            }
        }
        assert!(dialing.len() >= 9, "{dialing:?}");
    }

    /// Phase 3 P3.C2 (cutoff M1), on a lab clock: `raven lan on --for 30m`
    /// opens the port; 31 minutes later on that clock (a jump, as the lab
    /// clock makes) the meeting watch closes it and its connections within a
    /// second, with no bind error. A restart after the meeting time (a new
    /// process: node_policy.json says on, the saved meeting time is past)
    /// keeps the port closed; `raven lan on` opens it again.
    #[test]
    fn meeting_deadline_closes_the_port_and_a_restart_after_it_stays_closed() {
        use crate::lan_meeting::{Meeting, Meetings};
        use std::sync::atomic::AtomicU64;
        const T0: u64 = 1_800_000_000_000;
        const MIN: u64 = 60_000;
        let _state = listener_state_test_lock();
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|l| l.local_addr())
            .unwrap()
            .port();
        let at = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let plan = BindPlan::of(&at.to_string(), false).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path().to_path_buf();
        std::fs::write(dd.join(raven_core::BACKEND_MARKER_NAME), b"locked-file\n").unwrap();
        // What `raven lan on --for 30m` saves (ash's side).
        raven_core::node_policy::set_lan_off(&dd, false, false).unwrap();
        raven_core::lan_meeting::save_until(&dd, T0 + 30 * MIN).unwrap();
        let clock = Arc::new(AtomicU64::new(T0));
        // One "process": its own LAN switch, meeting state and listener.
        let process = |clock: &Arc<AtomicU64>| {
            let (switch, on) = watch::channel(false);
            let switch = Arc::new(switch);
            let (set, get) = (Arc::clone(&switch), Arc::clone(&switch));
            let meetings = Arc::new(Meetings::new(
                move |on| {
                    set.send_replace(on);
                },
                move || *get.borrow(),
            ));
            let (m, c, d) = (Arc::clone(&meetings), Arc::clone(clock), dd.clone());
            let watch_task = tokio::spawn(async move {
                match m
                    .watch(
                        &d,
                        move || c.load(Ordering::SeqCst),
                        Duration::from_millis(50),
                    )
                    .await {}
            });
            let (plan, d, id) = (
                plan.clone(),
                dd.clone(),
                Arc::new(Identity::from_seed(&[0x8f; 32])),
            );
            let server = tokio::spawn(async move {
                match serve_while_on(&plan, SourceRule::Any, d, id, PRODUCTION_LIMITS, on, || {})
                    .await {}
            });
            (meetings, watch_task, server)
        };
        let listed = || async {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
            while listener_addrs() != [at] {
                assert!(tokio::time::Instant::now() < deadline, "not listening");
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        };
        let accepted = || async {
            matches!(
                tokio::time::timeout(Duration::from_millis(200), TcpStream::connect(at)).await,
                Ok(Ok(_))
            )
        };
        runtime().block_on(async {
            let (meetings, watch_task, server) = process(&clock);
            // ash's SetLan after it saved the time.
            meetings.apply(true, Some(T0 + 30 * MIN), clock.load(Ordering::SeqCst));
            listed().await;
            let mut held = TcpStream::connect(at).await.unwrap();
            assert!(still_open(&mut held).await);
            clock.store(T0 + 20 * MIN, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert!(accepted().await, "still before the meeting time");

            clock.store(T0 + 31 * MIN, Ordering::SeqCst);
            let moved = std::time::Instant::now();
            loop {
                if !accepted().await && listener_addrs().is_empty() && !listener_is_up() {
                    break;
                }
                assert!(
                    moved.elapsed() < Duration::from_secs(2),
                    "still open after the meeting time"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            let mut buf = [0u8; 8];
            let ended = tokio::time::timeout(Duration::from_secs(1), held.read(&mut buf))
                .await
                .expect("its connection ended with it");
            assert!(matches!(ended, Ok(0) | Err(_)), "{ended:?}");
            assert_eq!(bind_error(), (None, None), "closing is not a failed bind");
            assert_eq!(meetings.meeting(), Meeting::Until(T0 + 30 * MIN));
            server.abort();
            watch_task.abort();
            let _ = server.await;
            let _ = watch_task.await;

            // The restart: from what is saved, on the same clock.
            let (meetings, watch_task, server) = process(&clock);
            meetings.start(
                Ok(raven_core::node_policy::try_load_policy(&dd)
                    .unwrap()
                    .lan_off),
                || raven_core::lan_meeting::load_until(&dd),
                clock.load(Ordering::SeqCst),
            );
            assert_eq!(meetings.meeting(), Meeting::Until(T0 + 30 * MIN));
            tokio::time::sleep(Duration::from_millis(300)).await;
            assert!(
                !accepted().await,
                "a restart after the meeting time stays closed"
            );
            assert!(listener_addrs().is_empty());
            // `raven lan on`: ash removes the time, then SetLan.
            assert!(raven_core::lan_meeting::clear(&dd).unwrap());
            meetings.apply(true, None, clock.load(Ordering::SeqCst));
            listed().await;
            assert!(accepted().await, "open again");
            server.abort();
            watch_task.abort();
            let _ = server.await;
            let _ = watch_task.await;
            assert!(listener_addrs().is_empty());
        });
    }

    /// One dial of `dialer` at a responder serving `dd`: `Ok` once the
    /// responder answered with its own bind (it admitted the dialer), else
    /// the dialer's error and the responder's refusal.
    async fn dial_once(
        dd: &Path,
        responder: &Arc<Identity>,
        dialer: &Identity,
    ) -> Result<(), (String, String)> {
        dial_once_with(dd, responder, dialer, PRODUCTION_LIMITS).await
    }

    /// [`dial_once`] at a responder with `limits`.
    async fn dial_once_with(
        dd: &Path,
        responder: &Arc<Identity>,
        dialer: &Identity,
        limits: InboundLimits,
    ) -> Result<(), (String, String)> {
        let (mut client, server_side) = tokio::io::duplex(1 << 18);
        let (data_dir, resp) = (dd.to_path_buf(), responder.clone());
        let server = tokio::spawn(async move {
            let mut slot = test_slot();
            handle_inbound(
                data_dir,
                resp,
                server_side,
                limits,
                &mut slot,
                LOOPBACK_DIALER,
            )
            .await
        });
        let got = initiator_session(&mut client, dialer, &responder.public_key_bytes(), &[]).await;
        drop(client);
        let ended = tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .expect("handler ends when the dialer hangs up")
            .unwrap();
        match got {
            Ok(_) => Ok(()),
            Err(e) => Err((e, ended.err().unwrap_or_default())),
        }
    }

    /// Privacy pack PP.4: raven-node keeps the sealed book cached and reads
    /// it again when its file changes, before the next admission: a contact
    /// removed while the node runs is refused at its very next dial (the
    /// stranger's treatment), and admitted again once it is added back.
    #[tokio::test]
    async fn cached_book_reloads_on_stamp_change_before_the_next_admission() {
        use crate::at_rest_boot::tests::{lab_hist_key, profile_with, seal, serial, write_book};
        if !lab_hist_key() {
            return;
        }
        let responder = Arc::new(Identity::from_seed(&[0x7e; 32]));
        let dialer = Identity::from_seed(&[0x7f; 32]);
        let dir = profile_with(&[dialer.public_key_bytes()]);
        let dd = dir.path();
        {
            let _serial = serial();
            seal(dd);
        }
        raven_core::contact_book::enable_process_cache(dd);
        let book = || std::fs::read(dd.join(raven_core::contact_book::CONTACTS_FILE)).unwrap();
        assert!(raven_core::at_rest::is_sealed(&book()));
        assert_eq!(dial_once(dd, &responder, &dialer).await, Ok(()));
        // ash removes the contact (another process: the file changes).
        write_book(dd, &[]);
        assert!(raven_core::at_rest::is_sealed(&book()));
        assert_eq!(
            dial_once(dd, &responder, &dialer).await,
            Err((
                netutil::LINK_NOT_ACCEPTED.to_string(),
                raven_core::lan_dispatch::LINK_REFUSED_NOT_CONTACT.to_string()
            )),
            "a removed contact is refused at once"
        );
        write_book(dd, &[dialer.public_key_bytes()]);
        assert_eq!(dial_once(dd, &responder, &dialer).await, Ok(()));
    }

    /// E1 (three machines): right after an Unlock the at-rest key loader
    /// still held the contact book, and every link of a verified friend was
    /// refused as a stranger's: "inbound peer is not a local contact" in the
    /// log, SEC_STRANGER_REFUSED (`strangers_refused_1h`) and a strike
    /// against its address here, and LINK_NOT_ACCEPTED on its side, which
    /// holds that route until its user retries. A link that comes while the
    /// key loads waits for the book: once it opens, the friend is admitted on
    /// that very link. Still held after the wait, or held with no key load
    /// running, the link closes before Noise message 2: a hang-up the dialer
    /// retries and files as transient (CLOSED_EARLY), and nothing is noted
    /// here.
    #[tokio::test]
    async fn a_friend_is_no_stranger_while_the_book_is_held() {
        use crate::at_rest_boot::tests::{answered, key_loading_until_answered};
        use crate::security::tests::Capture;
        let capture = Capture::start();
        let responder = Arc::new(Identity::from_seed(&[0x5a; 32]));
        let friend = Identity::from_seed(&[0x5b; 32]);
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        write_book(dd, &[(&friend, true)]);
        // The key loads for a moment after the Unlock.
        let answer = key_loading_until_answered(dd);
        let opens = {
            let dd = dd.to_path_buf();
            tokio::task::spawn_blocking(move || {
                std::thread::sleep(Duration::from_millis(300));
                answered(&dd, answer);
            })
        };
        assert_eq!(
            dial_once(dd, &responder, &friend).await,
            Ok(()),
            "admitted once the book opened"
        );
        opens.await.unwrap();
        // The key does not come within the wait.
        let answer = key_loading_until_answered(dd);
        let limits = InboundLimits {
            book_wait: Duration::from_millis(200),
            ..PRODUCTION_LIMITS
        };
        let (dialer_err, refusal) = dial_once_with(dd, &responder, &friend, limits)
            .await
            .unwrap_err();
        assert_eq!(refusal, raven_core::lan_dispatch::LINK_REFUSED_NOT_READY);
        assert_eq!(dialer_err, netutil::PEER_CLOSED, "closed before message 2");
        // The dialer's view: a hang-up during the handshake, retried, then
        // transient; never this node refusing it.
        let retried =
            netutil::with_handshake_retries(|| async { Err::<(), _>(dialer_err.clone()) })
                .await
                .unwrap_err();
        let code = crate::outbox::dial_error_code(&retried);
        assert_eq!(code, crate::outbox::code::CLOSED_EARLY, "{retried}");
        assert_ne!(code, crate::outbox::code::LINK_NOT_ACCEPTED);
        // What the accept loop does with this refusal: no stranger noted,
        // no strike against the friend's address.
        let source = LOOPBACK_DIALER.unwrap().ip();
        crate::security::inbound_refused(source, raven_core::OutboxCarrier::Lan, &refusal);
        if let Some(capture) = &capture {
            assert!(capture.events().is_empty(), "{:?}", capture.kinds());
        }
        assert!(raven_core::security_events::classify_link_error(&refusal).is_none());
        tokio::task::spawn_blocking({
            let dd = dd.to_path_buf();
            move || answered(&dd, answer)
        })
        .await
        .unwrap();
        assert_eq!(dial_once(dd, &responder, &friend).await, Ok(()));
        // Held with no key load running (a failed one waits for its next
        // try): no wait, the same answer.
        raven_core::contact_book::hold(dd, "raven-node is waiting for the at-rest key");
        let started = std::time::Instant::now();
        let (_, refusal) = dial_once(dd, &responder, &friend).await.unwrap_err();
        assert_eq!(refusal, raven_core::lan_dispatch::LINK_REFUSED_NOT_READY);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
        raven_core::contact_book::enable_process_cache(dd);
    }

    /// E1 (three machines): mac-b's node said at start that macOS refuses
    /// its LAN connections, and then delivered every LAN send: one saved
    /// address of a friend was its old one on another subnet, refused for
    /// real. The true case (mac-a, before: every LAN dial refused at once)
    /// is still said, once it lasted [`REFUSED_FOR`]; a refusal off this
    /// computer's own networks, a slow one, or one dead address alone is
    /// not; a LAN connection that goes through takes it back.
    #[test]
    fn macos_refusing_the_local_network_is_said_only_when_it_is_so() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let t0 = std::time::Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);
        // This computer: 192.168.0.0/24 (cable and Wi-Fi).
        let on_link = |a: IpAddr| matches!(a, IpAddr::V4(v4) if v4.octets()[..3] == [192, 168, 0]);
        let (stale, friend, other) = (ip("192.168.1.146"), ip("192.168.0.25"), ip("192.168.0.31"));
        // mac-b: the stale address, refused at once at every try.
        let mut w = LocalNetworkWatch::new();
        for s in 0..60 {
            assert!(!w.refused(&[stale], true, on_link, at(s)), "another subnet");
        }
        // One dead address on this network (its ARP entry refuses at once
        // after the first try), or slow refusals: not said either.
        for s in 0..60 {
            assert!(
                !w.refused(&[friend], true, on_link, at(s)),
                "one address alone"
            );
        }
        assert!(!w.refused(&[other], false, on_link, at(61)), "not at once");
        // mac-a: every LAN dial refused at once: said once, after 30 s.
        let mut w = LocalNetworkWatch::new();
        assert!(!w.refused(&[friend], true, on_link, at(0)));
        assert!(!w.refused(&[other], true, on_link, at(1)), "not yet 30 s");
        assert!(!w.refused(&[friend], true, on_link, at(29)));
        assert!(
            w.refused(&[other], true, on_link, at(30)),
            "two of this network's"
        );
        assert!(
            !w.refused(&[friend, other, ip("192.168.0.40")], true, on_link, at(31)),
            "once"
        );
        // A LAN connection goes through: taken back once, and counted anew.
        assert!(w.connected());
        assert!(!w.connected());
        assert!(!w.refused(&[friend], true, on_link, at(32)));
        assert!(!w.connected(), "nothing said to take back");
        assert!(
            !w.refused(&[other], true, on_link, at(70)),
            "a connection in between"
        );
        // Both in one connect's error (a name with two addresses).
        let mut w = LocalNetworkWatch::new();
        assert!(!w.refused(&[friend, other], true, on_link, at(0)));
        assert!(w.refused(&[friend, other], true, on_link, at(40)));
    }

    /// E2 (mac-b, a new build): macOS refused the new raven-node's first
    /// LAN connections for some seconds after it started, and let them
    /// through in between: the log said "macOS refuses" at 08:14:05, took it
    /// back at :16, said it at :20 and took it back at :26. Refusals now
    /// count only once they lasted 30 s with nothing through in between:
    /// none of that is said, and so nothing is taken back.
    #[test]
    fn a_new_binary_refused_for_seconds_is_no_warning() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let t0 = std::time::Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);
        let on_link = |a: IpAddr| matches!(a, IpAddr::V4(v4) if v4.octets()[..3] == [192, 168, 0]);
        let (mac_a, win_c) = (ip("192.168.0.25"), ip("192.168.0.31"));
        let mut w = LocalNetworkWatch::new();
        let mut said = 0;
        let mut cleared = 0;
        for s in [0, 1, 3, 5, 8, 11] {
            said += usize::from(w.refused(&[mac_a, win_c], true, on_link, at(s)));
        }
        cleared += usize::from(w.connected());
        for s in [15, 17, 19] {
            said += usize::from(w.refused(&[mac_a, win_c], true, on_link, at(s)));
        }
        cleared += usize::from(w.connected());
        assert_eq!((said, cleared), (0, 0));
    }

    /// E2: while raven-node is new ([`START_GRACE`]) a LAN connect macOS
    /// refuses at once is tried again a second later instead of failing the
    /// send ("this Mac did not let RAVEN connect", then delivered by the
    /// retry); a slow refusal, another error, or one past the grace fails
    /// the dial as before.
    #[test]
    fn a_refusal_at_start_is_tried_again() {
        let refused = "cannot connect to 192.168.0.25:17420 (192.168.0.25:17420: No route to \
                       host (os error 65))";
        let s = Duration::from_secs;
        let quick = Duration::from_millis(20);
        assert!(retry_refused_at_start(refused, quick, s(0)));
        assert!(retry_refused_at_start(refused, quick, s(28)));
        assert!(
            !retry_refused_at_start(refused, quick, s(29)),
            "the grace ends"
        );
        assert!(!retry_refused_at_start(refused, quick, s(300)));
        assert!(!retry_refused_at_start(refused, s(2), s(0)), "not at once");
        for other in [
            "cannot connect to 192.168.0.25:17420 (192.168.0.25:17420: Connection refused (os \
             error 61))",
            "cannot connect to 203.0.113.9:17420 (203.0.113.9:17420: No route to host (os error \
             65))",
        ] {
            assert!(!retry_refused_at_start(other, quick, s(0)), "{other}");
        }
    }

    /// E2: a new raven-node's LAN connect that macOS refuses at once for a
    /// few seconds goes through on a later try inside the grace, and the
    /// send never sees the refusal; past the grace the first refusal fails
    /// the dial, worded as before.
    #[tokio::test]
    async fn a_new_nodes_refused_connect_goes_through_on_a_later_try() {
        let refused = "cannot connect to 192.168.0.25:17420 (192.168.0.25:17420: No route to \
                       host (os error 65))";
        let tries = std::cell::Cell::new(0u32);
        let dial = || {
            tries.set(tries.get() + 1);
            let n = tries.get();
            async move {
                if n < 4 {
                    Err(refused.to_string())
                } else {
                    Ok(n)
                }
            }
        };
        let pause = Duration::from_millis(5);
        let got = connect_lan_with(dial, || Duration::from_secs(3), pause).await;
        assert_eq!(got, Ok(4), "three refusals, then through");
        tries.set(0);
        let got = connect_lan_with(dial, || Duration::from_secs(45), pause).await;
        assert_eq!(got, Err(format!("lan connect: {refused}")));
        assert_eq!(tries.get(), 1, "past the grace: no second try");
    }

    /// Owner decision 2026-10-08: an unverified contact is answered on LAN
    /// direct only from a local-network address. From anywhere else (or an
    /// unknown source) it gets exactly the stranger's treatment: the link
    /// closes after its bind, before any byte of ours. A verified (pinned)
    /// contact is answered from anywhere.
    #[tokio::test]
    async fn an_unverified_contact_from_outside_the_local_network_is_a_stranger() {
        let responder = Arc::new(Identity::from_seed(&[0x7c; 32]));
        let dialer = Identity::from_seed(&[0x7d; 32]);
        let public: Option<SocketAddr> = Some("203.0.113.9:50123".parse().unwrap());
        let cgnat: Option<SocketAddr> = Some("100.64.3.4:50123".parse().unwrap());
        for (source, pinned, refused) in [
            (public, false, true),
            (cgnat, false, true),
            (None, false, true),
            (public, true, false),
        ] {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(
                dir.path().join("contacts.json"),
                format!(
                    r#"[{{"pub_hex":"{}","pinned":{pinned}}}]"#,
                    hex::encode(dialer.public_key_bytes())
                ),
            )
            .unwrap();
            let (mut client, server_side) = tokio::io::duplex(1 << 18);
            let (data_dir, resp) = (dir.path().to_path_buf(), responder.clone());
            let server = tokio::spawn(async move {
                let mut slot = test_slot();
                handle_inbound(
                    data_dir,
                    resp,
                    server_side,
                    PRODUCTION_LIMITS,
                    &mut slot,
                    source,
                )
                .await
            });
            let got =
                initiator_session(&mut client, &dialer, &responder.public_key_bytes(), &[]).await;
            let case = format!("{source:?} pinned={pinned}");
            if refused {
                assert_eq!(
                    got.err().as_deref(),
                    Some(netutil::LINK_NOT_ACCEPTED),
                    "{case}"
                );
                let refusal = tokio::time::timeout(Duration::from_secs(10), server)
                    .await
                    .expect("handler ends")
                    .unwrap()
                    .unwrap_err();
                assert_eq!(
                    refusal,
                    raven_core::lan_dispatch::LINK_REFUSED_NOT_VERIFIED,
                    "{case}"
                );
                let mut rest = Vec::new();
                assert_eq!(
                    client.read_to_end(&mut rest).await.unwrap_or(0),
                    0,
                    "{case}"
                );
            } else {
                assert!(got.is_ok(), "{case}: {:?}", got.err());
                server.abort();
            }
        }
    }

    /// The dialer authenticates first, so a contact that dials a responder
    /// which has *it* as a contact still verifies the responder's bind.
    #[tokio::test]
    async fn contact_dialer_still_authenticates_the_responder() {
        let resp_dir = tempfile::tempdir().unwrap();
        let responder = Arc::new(Identity::from_seed(&[0x78; 32]));
        let dialer = Identity::from_seed(&[0x79; 32]);
        let mallory = Identity::from_seed(&[0x7a; 32]);
        write_contacts(resp_dir.path(), &[&dialer]);
        let (mut client, server_side) = tokio::io::duplex(1 << 18);
        let (data_dir, resp) = (resp_dir.path().to_path_buf(), responder.clone());
        let _server = tokio::spawn(async move {
            let mut slot = test_slot();
            handle_inbound(
                data_dir,
                resp,
                server_side,
                PRODUCTION_LIMITS,
                &mut slot,
                LOOPBACK_DIALER,
            )
            .await
        });
        // Dialing the right listener but expecting someone else still fails on
        // the responder's (now disclosed) bind.
        let Err(err) =
            initiator_session(&mut client, &dialer, &mallory.public_key_bytes(), &[]).await
        else {
            panic!("wrong expected identity must fail");
        };
        assert_ne!(err, netutil::LINK_NOT_ACCEPTED, "{err}");
    }

    /// Regression: the pre-auth phase shared the 120 s session lifetime, so a
    /// connection that never sent anything held one of the 32 slots for two
    /// minutes. It now ends at the handshake deadline and frees its slot.
    #[tokio::test(start_paused = true)]
    async fn silent_connection_ends_at_handshake_deadline_and_frees_slot() {
        let dir = tempfile::tempdir().unwrap();
        let admission = Admission::new(PRODUCTION_LIMITS);
        let ip = "10.1.2.3".parse().unwrap();
        let mut slots = Vec::new();
        while let Some(s) = admission.try_admit(ip) {
            slots.push(s);
        }
        assert_eq!(slots.len(), PRODUCTION_LIMITS.max_handshaking_per_ip);
        let mut slot = slots.pop().unwrap();

        let (_silent_peer, server_side) = tokio::io::duplex(1024);
        let responder = Arc::new(Identity::from_seed(&[0x53; 32]));
        let started = tokio::time::Instant::now();
        let err = handle_inbound(
            dir.path().to_path_buf(),
            responder,
            server_side,
            PRODUCTION_LIMITS,
            &mut slot,
            LOOPBACK_DIALER,
        )
        .await
        .unwrap_err();
        assert_eq!(err, HANDSHAKE_TIMEOUT);
        let waited = started.elapsed();
        assert!(waited >= PRODUCTION_LIMITS.handshake_deadline, "{waited:?}");
        assert!(waited < PRODUCTION_LIMITS.lifetime, "{waited:?}");

        // Dropping the finished handler's slot makes room for the next dial.
        assert!(admission.try_admit(ip).is_none(), "still full");
        drop(slot);
        assert!(admission.try_admit(ip).is_some(), "slot freed");
    }

    fn message_frame(id: u8) -> Vec<u8> {
        envelope_frame(EnvType::Message, id)
    }

    fn ack_frame(id: u8) -> Vec<u8> {
        envelope_frame(EnvType::Ack, id)
    }

    fn envelope_frame(kind: EnvType, id: u8) -> Vec<u8> {
        Envelope {
            env_type: kind as u8,
            flags: 0,
            message_id: [id; 16],
            routing_tag: [0x44; 16],
            dest_device_hint: 0,
            created_at: 1,
            expires_at: u64::MAX / 2,
            hop_limit: 4,
            replication_budget: 1,
            anti_replay_nonce: [0x55; 12],
            ratchet_header_ciphertext: vec![],
            message_ciphertext: vec![id; 8],
            // Parsed only (never verified) by the reply classifier.
            sender_authentication: vec![0u8; 64],
        }
        .pack()
    }

    /// Dialer side of a duplex pipe after the Noise handshake, plus the
    /// responder's transport for the scripted peer.
    async fn noise_pair() -> (
        tokio::io::DuplexStream,
        LinkCipher,
        tokio::task::JoinHandle<(tokio::io::DuplexStream, LinkCipher)>,
    ) {
        let (mut dialer, mut listener) = tokio::io::duplex(1 << 18);
        let bob = Identity::from_seed(&[0x62; 32]);
        let expected = bob.public_key_bytes();
        let peer = tokio::spawn(async move {
            let (_, t) = responder_session(&mut listener, &bob).await.unwrap();
            (listener, t)
        });
        let alice = Identity::from_seed(&[0x61; 32]);
        let t = initiator_session(&mut dialer, &alice, &expected, &[])
            .await
            .unwrap();
        (dialer, t, peer)
    }

    const FAST: ReplyWaits = ReplyWaits {
        first: Duration::from_secs(60),
        idle: Duration::from_secs(60),
    };

    /// A dial without route hints (a gate-off build): nothing is sent or
    /// consumed, so the data dir is never read.
    fn no_hints() -> crate::hints::LinkCtl {
        let keys = crate::hints::LinkKeys {
            peer: [0x62; 32],
            local: [0x61; 32],
            local_p2p: [0x63; 32],
        };
        crate::hints::LinkCtl::lan_dialer(Path::new("unused"), keys, None, None, false, false)
    }

    /// A dial returns the moment its terminal reply arrives, without sitting
    /// out the idle wait (the peer keeps the connection open).
    #[tokio::test]
    async fn dial_returns_as_soon_as_the_ack_arrives() {
        let (mut dialer, mut t, peer) = noise_pair().await;
        let frames = vec![message_frame(1)];
        let (mut conn, mut peer_t) = peer.await.unwrap();
        let ack = ack_frame(2);
        let ack_c = ack.clone();
        let server = tokio::spawn(async move {
            let got = read_cipher(&mut conn, &mut peer_t).await.unwrap();
            write_cipher(&mut conn, &mut peer_t, &ack_c).await.unwrap();
            // Stay connected, like a real peer does after replying.
            let _keep = (conn, peer_t);
            std::future::pending::<()>().await;
            got
        });
        let mut progress = DialProgress::new("LAN", FAST);
        progress
            .collector
            .begin(b"peer-offer".to_vec(), &frames)
            .unwrap();
        tokio::time::timeout(
            Duration::from_secs(20),
            exchange_frames(&mut dialer, &mut t, &frames, &mut no_hints(), &mut progress),
        )
        .await
        .expect("must not wait for the idle timeout once the ACK is in")
        .unwrap();
        let replies = progress.collector.into_replies();
        assert_eq!(replies, vec![b"peer-offer".to_vec(), ack]);
        server.abort();
    }

    /// A peer that rejects the frame and hangs up used to yield a success
    /// holding only the RLB1 offer; it is now an explicit, retry-safe error.
    #[tokio::test]
    async fn peer_closing_without_a_reply_is_an_error() {
        let (mut dialer, mut t, peer) = noise_pair().await;
        let frames = vec![message_frame(3)];
        let (mut conn, mut peer_t) = peer.await.unwrap();
        let server = tokio::spawn(async move {
            let _ = read_cipher(&mut conn, &mut peer_t).await;
            drop(conn);
        });
        let mut progress = DialProgress::new("LAN", FAST);
        progress
            .collector
            .begin(b"offer".to_vec(), &frames)
            .unwrap();
        let err = exchange_frames(&mut dialer, &mut t, &frames, &mut no_hints(), &mut progress)
            .await
            .unwrap_err();
        assert!(err.starts_with("LAN_DIAL_PEER_CLOSED"), "{err}");
        assert!(err.contains("frames were sent"), "{err}");
        server.await.unwrap();
    }

    /// No reply within the first-reply wait is not an error: the caller sees
    /// only the offer and maps it to "waiting for ACK".
    #[tokio::test(start_paused = true)]
    async fn silent_peer_yields_offer_only() {
        let (mut dialer, mut t, peer) = noise_pair().await;
        let frames = vec![message_frame(4)];
        let (conn, peer_t) = peer.await.unwrap();
        let mut progress = DialProgress::new("LAN", PRODUCTION_REPLY_WAITS);
        progress
            .collector
            .begin(b"offer".to_vec(), &frames)
            .unwrap();
        exchange_frames(&mut dialer, &mut t, &frames, &mut no_hints(), &mut progress)
            .await
            .unwrap();
        assert_eq!(progress.collector.into_replies(), vec![b"offer".to_vec()]);
        drop((conn, peer_t));
    }

    /// Frames that get no reply (an ACK we forward, an RLB1 refresh) must not
    /// wait the patient first-reply time for nothing.
    #[tokio::test(start_paused = true)]
    async fn frames_without_replies_use_the_short_wait() {
        let (mut dialer, mut t, peer) = noise_pair().await;
        let frames = vec![ack_frame(5)];
        let (conn, peer_t) = peer.await.unwrap();
        let mut progress = DialProgress::new("LAN", PRODUCTION_REPLY_WAITS);
        progress
            .collector
            .begin(b"offer".to_vec(), &frames)
            .unwrap();
        let started = tokio::time::Instant::now();
        exchange_frames(&mut dialer, &mut t, &frames, &mut no_hints(), &mut progress)
            .await
            .unwrap();
        assert!(started.elapsed() < PRODUCTION_REPLY_WAITS.first);
        drop((conn, peer_t));
    }

    /// A peer that streams frames cannot grow the reply buffer past one IPC
    /// response, and the error says the frames were delivered.
    #[tokio::test]
    async fn reply_flood_hits_the_budget() {
        let (mut dialer, mut t, peer) = noise_pair().await;
        let frames = vec![message_frame(6)];
        let (mut conn, mut peer_t) = peer.await.unwrap();
        let server = tokio::spawn(async move {
            let _ = read_cipher(&mut conn, &mut peer_t).await;
            for _ in 0..200 {
                if write_cipher(&mut conn, &mut peer_t, b"not-terminal")
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        let mut progress = DialProgress::new("LAN", FAST);
        progress
            .collector
            .begin(b"offer".to_vec(), &frames)
            .unwrap();
        let err = exchange_frames(&mut dialer, &mut t, &frames, &mut no_hints(), &mut progress)
            .await
            .unwrap_err();
        assert!(err.starts_with("LAN_DIAL_REPLY_OVERFLOW"), "{err}");
        assert!(err.ends_with("(frames were sent)"), "{err}");
        drop(dialer);
        server.abort();
    }

    /// Phase 6b S1 (P6.24): a reply whose ciphertext changed on the way is
    /// one `SEC_LINK_TAG_FAIL` about the dialled contact's path, and that
    /// dial teaches learning nothing. The dial's error is the same byte for
    /// byte with the gate shut and open.
    #[tokio::test]
    async fn a_flipped_reply_is_one_tag_failure_about_the_dialled_contact() {
        use crate::security::tests::Capture;
        use raven_core::security_events::{Attribution, SecKind, Via};
        let bob = Identity::from_seed(&[0x62; 32]).public_key_bytes();
        let flipped_dial = || async move {
            let (mut dialer, mut t, peer) = noise_pair().await;
            let frames = vec![message_frame(12)];
            let (mut conn, mut peer_t) = peer.await.unwrap();
            let server = tokio::spawn(async move {
                let _ = read_cipher(&mut conn, &mut peer_t).await;
                let mut ct = transport_encrypt(&mut peer_t.transport, &ack_frame(13)).unwrap();
                ct[5] ^= 0x80;
                write_raw(&mut conn, &ct).await.unwrap();
                conn
            });
            let keys = crate::hints::LinkKeys::new(bob, &Identity::from_seed(&[0x61; 32]));
            let mut hints = crate::hints::LinkCtl::lan_dialer(
                Path::new("unused"),
                keys,
                None,
                None,
                false,
                false,
            );
            let mut progress = DialProgress::new("LAN", FAST);
            progress
                .collector
                .begin(b"offer".to_vec(), &frames)
                .unwrap();
            let err = exchange_frames(&mut dialer, &mut t, &frames, &mut hints, &mut progress)
                .await
                .unwrap_err();
            drop(server.await.unwrap());
            err
        };
        let shut = flipped_dial().await;
        assert_eq!(
            shut,
            "LAN_DIAL_BAD_REPLY: the peer's reply could not be read (noise transport failed); \
             the frames were sent, delivery is unconfirmed and a retry is safe"
        );
        assert!(crate::security::take_excluded_dial(
            &bob,
            raven_core::OutboxCarrier::Lan
        ));
        let Some(capture) = Capture::start() else {
            return;
        };
        assert_eq!(
            flipped_dial().await,
            shut,
            "the same error with the gate open"
        );
        assert_eq!(
            capture.kinds(),
            [(
                SecKind::LinkTagFail,
                Attribution::Contact { peer: bob },
                Via::Dial(raven_core::OutboxCarrier::Lan)
            )]
        );
        assert!(crate::security::take_excluded_dial(
            &bob,
            raven_core::OutboxCarrier::Lan
        ));
    }

    /// Phase 6b S13 (P6.24): another identity at the dialled address (a bind
    /// for someone else, or another static than the M0 pin) is
    /// `SEC_ADDRESS_IMPOSTOR` about the contact dialled; the dial ends as
    /// before.
    #[tokio::test]
    async fn another_identity_at_the_dialled_address_is_an_address_impostor() {
        use crate::security::tests::Capture;
        use raven_core::security_events::{Attribution, SecKind, Via};
        let Some(capture) = Capture::start() else {
            return;
        };
        let alice = Identity::from_seed(&[0x97; 32]);
        let bob = Identity::from_seed(&[0x95; 32]).public_key_bytes();
        let answered_by_mallory = |pin: Option<[u8; 32]>| {
            let alice = &alice;
            async move {
                let (mut dialer, mut listener) = tokio::io::duplex(1 << 18);
                let peer = tokio::spawn(async move {
                    let mallory = Identity::from_seed(&[0x96; 32]);
                    let _ = responder_session(&mut listener, &mallory).await;
                });
                let err = initiator_session_pinned(
                    &mut dialer,
                    alice,
                    &bob,
                    &[],
                    pin.as_ref(),
                    None,
                    None,
                )
                .await
                .err()
                .unwrap_or_else(|| panic!("not bob"));
                drop(dialer);
                peer.await.unwrap();
                err
            }
        };
        assert_eq!(
            answered_by_mallory(None).await,
            "identity bind does not match expected pub"
        );
        assert_eq!(answered_by_mallory(Some([0; 32])).await, NOISE_PIN_MISMATCH);
        let impostor = (
            SecKind::AddressImpostor,
            Attribution::Contact { peer: bob },
            Via::Dial(raven_core::OutboxCarrier::Lan),
        );
        assert_eq!(capture.kinds(), [impostor, impostor]);
    }

    /// The overall deadline reports what was in flight; once the frames are
    /// written the replies collected so far are the answer.
    #[test]
    fn deadline_reports_stage_or_returns_collected_replies() {
        let mut p = DialProgress::new("LAN", FAST);
        p.stage = "connecting";
        let err = p
            .on_deadline("lan", "bob.local:7420", DIAL_DEADLINE)
            .unwrap_err();
        assert!(err.contains("bob.local:7420"), "{err}");
        assert!(err.contains("while connecting"), "{err}");

        let mut p = DialProgress::new("LAN", FAST);
        p.stage = "sending frames";
        let err = p.on_deadline("lan", "x:1", DIAL_DEADLINE).unwrap_err();
        assert!(err.contains("may have been delivered"), "{err}");

        let mut p = DialProgress::new("LAN", FAST);
        p.collector.begin(b"offer".to_vec(), &[]).unwrap();
        p.frames_sent = true;
        assert_eq!(
            p.on_deadline("lan", "x:1", DIAL_DEADLINE).unwrap(),
            vec![b"offer".to_vec()]
        );
    }

    #[test]
    fn inbound_caps_are_bounded() {
        const {
            assert!(PRODUCTION_LIMITS.max_conns >= PRODUCTION_LIMITS.max_per_ip);
            assert!(PRODUCTION_LIMITS.max_per_ip >= PRODUCTION_LIMITS.max_handshaking_per_ip);
            assert!(PRODUCTION_LIMITS.max_handshaking_per_ip > 0);
            assert!(PRODUCTION_LIMITS.max_frames > 0);
        }
        assert!(PRODUCTION_LIMITS.lifetime.as_secs() >= 30);
        assert!(PRODUCTION_LIMITS.handshake_deadline < PRODUCTION_LIMITS.lifetime);
    }

    #[test]
    fn frame_budget_rejects_after_max() {
        let mut seen = 0u32;
        for _ in 0..3 {
            assert!(frame_budget_allows(&mut seen, 3));
        }
        assert!(!frame_budget_allows(&mut seen, 3));
        assert_eq!(seen, 4);
    }

    #[test]
    fn dial_string_accepts_names_and_scoped_v6() {
        assert!(looks_like_lan_dial("192.168.1.20:7420"));
        assert!(looks_like_lan_dial("mac-mini.local:7420"));
        assert!(looks_like_lan_dial("[fe80::1%en0]:7420"));
        assert!(!looks_like_lan_dial("192.168.1.20:0"));
        assert!(!looks_like_lan_dial("rvn1qabc"));
    }

    // ── Route hints (RRH1) ──────────────────────────────────────────────

    fn route_hint(generation: u64) -> Vec<u8> {
        raven_core::route_hints::encode(&raven_core::route_hints::RouteHints {
            generation,
            ttl_s: 3600,
            lan_port: Some(7431),
            ..Default::default()
        })
    }

    fn write_book(dir: &Path, rows: &[(&Identity, bool)]) {
        let rows: Vec<String> = rows
            .iter()
            .map(|(c, pinned)| {
                format!(
                    r#"{{"pub_hex":"{}","pinned":{pinned}}}"#,
                    hex::encode(c.public_key_bytes())
                )
            })
            .collect();
        std::fs::write(dir.join("contacts.json"), format!("[{}]", rows.join(","))).unwrap();
    }

    /// A real listener (`handle_inbound`) and a scripted dialer that sends
    /// `m3` as its message 3 payload and completes the RLB1 exchange. Returns
    /// the dialer's end after the listener's RLB1, and the listener task.
    async fn dial_listener(
        resp_dir: &Path,
        responder: &Arc<Identity>,
        dialer: &Identity,
        m3: &[u8],
        source: Option<SocketAddr>,
        limits: InboundLimits,
    ) -> (
        tokio::io::DuplexStream,
        LinkCipher,
        tokio::task::JoinHandle<Result<(), String>>,
    ) {
        dial_listener_with(
            resp_dir,
            responder,
            dialer,
            m3,
            source,
            limits,
            NoisePins::current(),
        )
        .await
    }

    /// [`dial_listener`] with the listener's noise pins (M0) named.
    async fn dial_listener_with(
        resp_dir: &Path,
        responder: &Arc<Identity>,
        dialer: &Identity,
        m3: &[u8],
        source: Option<SocketAddr>,
        limits: InboundLimits,
        pins: NoisePins,
    ) -> (
        tokio::io::DuplexStream,
        LinkCipher,
        tokio::task::JoinHandle<Result<(), String>>,
    ) {
        let init_dir = tempfile::tempdir().unwrap();
        let (mut client, server_side) = tokio::io::duplex(1 << 18);
        let (data_dir, resp) = (resp_dir.to_path_buf(), responder.clone());
        let server = tokio::spawn(async move {
            let mut slot = test_slot();
            handle_inbound_with(data_dir, resp, server_side, limits, &mut slot, source, pins).await
        });
        let mut t = initiator_session(&mut client, dialer, &responder.public_key_bytes(), m3)
            .await
            .expect("Noise XX + bind");
        let offer = encode_local_offer(init_dir.path(), dialer).unwrap();
        write_cipher(&mut client, &mut t, &offer).await.unwrap();
        let theirs = read_cipher(&mut client, &mut t).await.unwrap();
        assert!(parse_peer_offer(&theirs).is_ok(), "the listener's RLB1");
        (client, t, server)
    }

    /// Hang up (write side) and read what the listener still sends.
    async fn frames_until_close(
        client: &mut tokio::io::DuplexStream,
        t: &mut LinkCipher,
    ) -> Vec<Vec<u8>> {
        client.shutdown().await.unwrap();
        let mut got = Vec::new();
        while let Ok(frame) = read_cipher(client, t).await {
            got.push(frame);
        }
        got
    }

    async fn listener_result(
        server: tokio::task::JoinHandle<Result<(), String>>,
    ) -> Result<(), String> {
        tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .expect("listener ends")
            .unwrap()
    }

    /// Message 3 carries RLX1 only while route hints are live and only on a
    /// dial that reads; the responder gets exactly those bytes (and drops a
    /// payload longer than RLX1 allows).
    #[tokio::test]
    async fn rlx1_m3_only_when_live() {
        let too_long = vec![0x52; raven_core::route_hints::RLX1_MAX_LEN + 1];
        for (live, reads, m3) in [
            (false, false, None),
            (false, true, None),
            (true, false, None),
            (true, true, None),
            (true, true, Some(too_long)),
        ] {
            let m3 = m3.unwrap_or_else(|| crate::hints::lan_m3_payload(live, false, reads));
            let (mut dialer, mut listener) = tokio::io::duplex(1 << 18);
            let bob = Identity::from_seed(&[0x62; 32]);
            let expected = bob.public_key_bytes();
            let peer = tokio::spawn(async move {
                let (_, mut t, ours, ext, _, _) = responder_handshake(&mut listener, &bob, None)
                    .await
                    .unwrap();
                write_cipher(&mut listener, &mut t, &ours).await.unwrap();
                ext
            });
            let alice = Identity::from_seed(&[0x61; 32]);
            initiator_session(&mut dialer, &alice, &expected, &m3)
                .await
                .unwrap();
            let ext = peer.await.unwrap();
            if live && reads && m3.len() <= raven_core::route_hints::RLX1_MAX_LEN {
                assert_eq!(ext, m3);
                assert_eq!(ext.len(), 11);
                assert_eq!(
                    raven_core::route_hints::rlx1_caps(&ext),
                    raven_core::CAP_LINK_RRH1
                );
            } else {
                assert!(ext.is_empty(), "{live} {reads} {}", m3.len());
            }
        }
    }

    /// A security notice that marks a link suite BROKEN (P6.45): the dialer
    /// sends nothing and the listener reads nothing, each with the text
    /// that says why; lifted, the same two link again.
    #[tokio::test]
    async fn a_broken_link_suite_refuses_both_ends_with_the_text() {
        use raven_core::advisory::{Entry, EntryKind, Severity};
        use raven_core::security_gate::{self, SecGate};
        use raven_core::suite_policy::{link_refused_text, set_policy_for_this_thread, Policy};
        use raven_core::suite_registry::{NOISE_XX_25519_CHACHAPOLY_BLAKE2S, RLB1_V1};
        security_gate::set_lab_for_this_thread(SecGate::Advisory, Some(true));
        if !security_gate::live(SecGate::Advisory) {
            security_gate::set_lab_for_this_thread(SecGate::Advisory, None);
            return;
        }
        let alice = Identity::from_seed(&[0x63; 32]);
        let bob = Arc::new(Identity::from_seed(&[0x64; 32]));
        let expected = bob.public_key_bytes();
        // The knock (P6.35) open for this thread where it can be: a knocked
        // dial and a listener with its ear are refused the same way.
        let knock = knock_on();
        let (a_dir, b_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        write_contacts(b_dir.path(), &[&alice]);
        for id in [NOISE_XX_25519_CHACHAPOLY_BLAKE2S, RLB1_V1] {
            let broken = Entry {
                kind: EntryKind::SuiteStatus,
                severity: Severity::Broken,
                target: id.to_owned(),
                arg: Vec::new(),
                text_id: 0,
            };
            set_policy_for_this_thread(Some(Policy::of_entries(4, 0, &[broken], 0)));
            let (mut dialer, mut listener) = tokio::io::duplex(1 << 18);
            let err = initiator_session(&mut dialer, &alice, &expected, &[])
                .await
                .unwrap_err();
            assert_eq!(err, link_refused_text(id, 4));
            assert!(err.starts_with("SUITE_BROKEN: "), "{err}");
            let Err(err) = responder_handshake(&mut listener, &bob, None).await else {
                panic!("a listener takes no link either");
            };
            assert_eq!(err, link_refused_text(id, 4));
            // Nothing crossed either way.
            drop(dialer);
            let mut byte = [0u8; 1];
            assert_eq!(listener.read(&mut byte).await.unwrap(), 0);
            if knock.is_none() {
                continue;
            }
            let dial = crate::link_knock::for_dial(true, false, a_dir.path(), &alice, &expected)
                .expect("knock keys");
            let (mut dialer, mut listener) = tokio::io::duplex(1 << 18);
            let err = initiator_session_pinned(
                &mut dialer,
                &alice,
                &expected,
                &[],
                None,
                None,
                Some(&dial),
            )
            .await
            .unwrap_err();
            assert_eq!(err, link_refused_text(id, 4), "knocked");
            let ear = ear(b_dir.path(), &bob, HERE);
            let Err(err) = responder_handshake(&mut listener, &bob, Some(&ear)).await else {
                panic!("a listener with the knock takes no link either");
            };
            assert_eq!(err, link_refused_text(id, 4), "knocked");
            drop(dialer);
            assert_eq!(listener.read(&mut byte).await.unwrap(), 0, "knocked");
        }
        set_policy_for_this_thread(None);
        let (mut dialer, mut listener) = tokio::io::duplex(1 << 18);
        let bob_c = bob.clone();
        let peer = tokio::spawn(async move {
            let (_, mut t, ours, _, _, _) = responder_handshake(&mut listener, &bob_c, None)
                .await
                .unwrap();
            write_cipher(&mut listener, &mut t, &ours).await.unwrap();
        });
        initiator_session(&mut dialer, &alice, &expected, &[])
            .await
            .unwrap();
        peer.await.unwrap();
        // Lifted, a knocked link comes up again.
        if knock.is_some() {
            let dial = crate::link_knock::for_dial(true, false, a_dir.path(), &alice, &expected)
                .expect("knock keys");
            let (mut dialer, mut listener) = tokio::io::duplex(1 << 18);
            let (ear, bob_c) = (ear(b_dir.path(), &bob, HERE), bob.clone());
            let peer = tokio::spawn(async move {
                let (ed, mut t, ours, _, _, knocked) =
                    responder_handshake(&mut listener, &bob_c, Some(&ear))
                        .await
                        .unwrap();
                write_cipher(&mut listener, &mut t, &ours).await.unwrap();
                (ed, knocked)
            });
            let (_, _, knocked) = initiator_session_pinned(
                &mut dialer,
                &alice,
                &expected,
                &[],
                None,
                None,
                Some(&dial),
            )
            .await
            .unwrap();
            assert_eq!(knocked, Some(true));
            let (ed, heard) = peer.await.unwrap();
            assert_eq!(
                (ed, heard),
                (
                    alice.public_key_bytes(),
                    Knocked::Contact(alice.public_key_bytes())
                )
            );
        }
        security_gate::set_lab_for_this_thread(SecGate::Advisory, None);
    }

    /// A frame-less dial (ash's RLB1 probe) does not ask, so the listener
    /// sends nothing after its RLB1 and ends cleanly when the dialer hangs up
    /// (no unread RRH1, no reset, no log line).
    #[tokio::test]
    async fn a_frame_less_dial_sends_no_rlx1_and_the_listener_logs_nothing() {
        if !lab_backend_available() {
            return;
        }
        let _live = crate::hints::LiveForTest::set(true);
        // PAD1 (P6.34) live too: a probe offers it no more than RRH1, so the
        // listener sends its bind and RLB1 bare (`dial_listener` reads them).
        let _pad = crate::link::PaddingForTest::set(true);
        let m3 = crate::hints::lan_m3_payload(
            crate::hints::live_on(raven_core::OutboxCarrier::Lan),
            crate::link::padding_live(),
            false,
        );
        assert!(m3.is_empty());
        let resp_dir = tempfile::tempdir().unwrap();
        let responder = Arc::new(Identity::from_seed(&[0x81; 32]));
        let dialer = Identity::from_seed(&[0x82; 32]);
        write_book(resp_dir.path(), &[(&dialer, true)]);
        let (mut client, mut t, server) = dial_listener(
            resp_dir.path(),
            &responder,
            &dialer,
            &m3,
            LOOPBACK_DIALER,
            PRODUCTION_LIMITS,
        )
        .await;
        let mut progress = DialProgress::new("LAN", FAST);
        progress.collector.begin(b"offer".to_vec(), &[]).unwrap();
        let keys = crate::hints::LinkKeys::new(responder.public_key_bytes(), &dialer);
        let mut hints = crate::hints::LinkCtl::lan_dialer(
            Path::new("unused"),
            keys,
            None,
            LOOPBACK,
            !m3.is_empty(),
            false,
        );
        exchange_frames(&mut client, &mut t, &[], &mut hints, &mut progress)
            .await
            .unwrap();
        assert_eq!(hints.counts(), (false, 0));
        assert!(!t.pad.peer_started(), "no RPD1 frame to a probe");
        assert!(frames_until_close(&mut client, &mut t).await.is_empty());
        listener_result(server).await.expect("a clean end");
    }

    /// An older listener (or one with the gate off) drops RLX1: after the
    /// handshake the dialer sends and receives exactly what it does with an
    /// empty message 3.
    #[tokio::test]
    async fn new_dialer_old_listener_is_byte_identical_after_m3() {
        let mut runs = Vec::new();
        for asked in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let (mut dialer, mut listener) = tokio::io::duplex(1 << 18);
            let bob = Identity::from_seed(&[0x62; 32]);
            let alice = Identity::from_seed(&[0x61; 32]);
            write_book(dir.path(), &[(&bob, true)]);
            let expected = bob.public_key_bytes();
            let ack = ack_frame(9);
            let ack_c = ack.clone();
            let server = tokio::spawn(async move {
                let (_, mut t) = responder_session(&mut listener, &bob).await.unwrap();
                let mut got = Vec::new();
                while let Ok(frame) = read_cipher(&mut listener, &mut t).await {
                    if got.is_empty() {
                        write_cipher(&mut listener, &mut t, &ack_c).await.unwrap();
                    }
                    got.push(frame);
                }
                got
            });
            let m3 = crate::hints::lan_m3_payload(asked, false, true);
            let mut t = initiator_session(&mut dialer, &alice, &expected, &m3)
                .await
                .unwrap();
            let frames = vec![message_frame(8)];
            let mut progress = DialProgress::new("LAN", FAST);
            progress
                .collector
                .begin(b"peer-offer".to_vec(), &frames)
                .unwrap();
            let keys = crate::hints::LinkKeys::new(expected, &alice);
            let mut hints =
                crate::hints::LinkCtl::lan_dialer(dir.path(), keys, None, LOOPBACK, asked, false);
            exchange_frames(&mut dialer, &mut t, &frames, &mut hints, &mut progress)
                .await
                .unwrap();
            assert_eq!(hints.counts(), (false, 0), "asked={asked}");
            drop(dialer);
            runs.push((progress.collector.into_replies(), server.await.unwrap()));
        }
        assert_eq!(runs[0], runs[1]);
        assert_eq!(runs[1].1, vec![message_frame(8)], "no RRH1 either way");
    }

    /// An older dialer (empty message 3) never gets an RRH1 from a new
    /// listener; one that asks gets exactly one, right after the RLB1.
    #[tokio::test]
    async fn old_dialer_new_listener_gets_no_rrh1() {
        if !lab_backend_available() {
            return;
        }
        let _live = crate::hints::LiveForTest::set(true);
        let resp_dir = tempfile::tempdir().unwrap();
        let responder = Arc::new(Identity::from_seed(&[0x83; 32]));
        let dialer = Identity::from_seed(&[0x84; 32]);
        write_book(resp_dir.path(), &[(&dialer, true)]);
        for (m3, want) in [
            (Vec::new(), 0),
            (crate::hints::lan_m3_payload(true, false, true), 1),
        ] {
            let (mut client, mut t, server) = dial_listener(
                resp_dir.path(),
                &responder,
                &dialer,
                &m3,
                LOOPBACK_DIALER,
                PRODUCTION_LIMITS,
            )
            .await;
            let after = frames_until_close(&mut client, &mut t).await;
            assert_eq!(after.len(), want, "{m3:02x?}");
            assert!(after
                .iter()
                .all(|f| raven_core::route_hints::decode(f).is_some()));
            listener_result(server).await.unwrap();
        }
    }

    /// Two new ends: one RRH1 each way, consumed on both sides, and the
    /// message is still delivered and acknowledged (the RRH1 is no reply).
    #[tokio::test]
    async fn both_new_exchange_one_rrh1_each_way_and_still_deliver() {
        let _live = crate::hints::LiveForTest::set(true);
        let (dialer_dir, listener_dir) =
            (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let alice = Identity::from_seed(&[0x61; 32]);
        let bob = Identity::from_seed(&[0x62; 32]);
        write_book(dialer_dir.path(), &[(&bob, true)]);
        write_book(listener_dir.path(), &[(&alice, true)]);
        let (mut dialer, mut listener) = tokio::io::duplex(1 << 18);
        let ack = ack_frame(11);
        let ack_c = ack.clone();
        let (bob_c, alice_key, ldir) = (
            Identity::from_seed(&[0x62; 32]),
            alice.public_key_bytes(),
            listener_dir.path().to_path_buf(),
        );
        let server = tokio::spawn(async move {
            let (_, mut t, ours, m3, _, _) = responder_handshake(&mut listener, &bob_c, None)
                .await
                .unwrap();
            write_cipher(&mut listener, &mut t, &ours).await.unwrap();
            let keys = crate::hints::LinkKeys::new(alice_key, &bob_c);
            let mut hints = crate::hints::LinkCtl::lan_listener(&ldir, keys, LOOPBACK, &m3);
            let rrh1 = hints.outgoing().await.expect("the dialer asked");
            write_cipher(&mut listener, &mut t, &rrh1).await.unwrap();
            hints.written();
            let mut dispatched = Vec::new();
            while let Ok(frame) = read_cipher(&mut listener, &mut t).await {
                if hints.take(&frame).await {
                    continue;
                }
                write_cipher(&mut listener, &mut t, &ack_c).await.unwrap();
                dispatched.push(frame);
            }
            (dispatched, hints.counts())
        });
        let m3 = crate::hints::lan_m3_payload(true, false, true);
        let mut t = initiator_session(&mut dialer, &alice, &bob.public_key_bytes(), &m3)
            .await
            .unwrap();
        let frames = vec![message_frame(10)];
        let mut progress = DialProgress::new("LAN", FAST);
        progress
            .collector
            .begin(b"peer-offer".to_vec(), &frames)
            .unwrap();
        let keys = crate::hints::LinkKeys::new(bob.public_key_bytes(), &alice);
        let mut hints =
            crate::hints::LinkCtl::lan_dialer(dialer_dir.path(), keys, None, LOOPBACK, true, false);
        tokio::time::timeout(
            Duration::from_secs(20),
            exchange_frames(&mut dialer, &mut t, &frames, &mut hints, &mut progress),
        )
        .await
        .expect("ends at the ACK")
        .unwrap();
        assert_eq!(hints.counts(), (true, 1));
        assert_eq!(
            progress.collector.into_replies(),
            vec![b"peer-offer".to_vec(), ack],
            "the RRH1 is not a reply"
        );
        drop(dialer);
        let (dispatched, listener_counts) = server.await.unwrap();
        assert_eq!(dispatched, frames);
        assert_eq!(listener_counts, (true, 1));
        if raven_core::route_hints::route_hints_live() {
            let now = crate::now_ms();
            let at_listener = raven_core::learned_routes::learned(
                listener_dir.path(),
                &alice.public_key_bytes(),
                now,
            )
            .expect("the listener learned the dialer's");
            assert_eq!(at_listener.lan.unwrap().ip, LOOPBACK);
            assert!(raven_core::learned_routes::learned(
                dialer_dir.path(),
                &bob.public_key_bytes(),
                now
            )
            .is_some());
        }
    }

    /// A malformed RRH1 is ignored whole: the link stays up.
    #[tokio::test]
    async fn garbage_rrh1_does_not_close_the_link() {
        if !lab_backend_available() {
            return;
        }
        let _live = crate::hints::LiveForTest::set(true);
        let resp_dir = tempfile::tempdir().unwrap();
        let responder = Arc::new(Identity::from_seed(&[0x85; 32]));
        let dialer = Identity::from_seed(&[0x86; 32]);
        write_book(resp_dir.path(), &[(&dialer, true)]);
        let (mut client, mut t, server) = dial_listener(
            resp_dir.path(),
            &responder,
            &dialer,
            &[],
            LOOPBACK_DIALER,
            PRODUCTION_LIMITS,
        )
        .await;
        for frame in [b"RRH1".to_vec(), b"RRH1\x02garbage".to_vec(), route_hint(0)] {
            write_cipher(&mut client, &mut t, &frame).await.unwrap();
        }
        assert!(
            frames_until_close(&mut client, &mut t).await.is_empty(),
            "never a reply"
        );
        listener_result(server)
            .await
            .expect("not closed by the route hints");
        assert!(!resp_dir
            .path()
            .join(raven_core::learned_routes::LEARNED_ROUTES_FILE)
            .exists());
    }

    /// Phase 3 P3.4: a contact that reaches the listener from an IPv6
    /// link-local address is remembered with the zone it came in on and is
    /// dialled back with it (`[fe80::b%<zone>]:<saved port>`, read back to
    /// the same scope id); with route hints live, the LAN part it tells us
    /// keeps the zone too.
    #[tokio::test]
    async fn inbound_fe80_records_its_zone() {
        if !lab_backend_available() {
            return;
        }
        let _live = crate::hints::LiveForTest::set(true);
        let resp_dir = tempfile::tempdir().unwrap();
        let responder = Arc::new(Identity::from_seed(&[0xa1; 32]));
        let dialer = Identity::from_seed(&[0xa2; 32]);
        // Unverified: a link-local address is the local network.
        write_book(resp_dir.path(), &[(&dialer, false)]);
        // Index 1: the loopback interface on Unix (named), a number on Windows.
        let scope = 1;
        let zone = netutil::zone_name(scope);
        let source = SocketAddr::V6(std::net::SocketAddrV6::new(
            "fe80::b".parse().unwrap(),
            50_123,
            0,
            scope,
        ));
        let (mut client, mut t, server) = dial_listener(
            resp_dir.path(),
            &responder,
            &dialer,
            &[],
            Some(source),
            PRODUCTION_LIMITS,
        )
        .await;
        write_cipher(&mut client, &mut t, &route_hint(5))
            .await
            .unwrap();
        assert!(frames_until_close(&mut client, &mut t).await.is_empty());
        listener_result(server).await.expect("a clean end");

        let (dd, peer, now) = (resp_dir.path(), dialer.public_key_bytes(), crate::now_ms());
        let seen = raven_core::lan_seen::seen_addr(dd, &peer, now).expect("a sighting");
        assert_eq!(seen.to_string(), format!("fe80::b%{zone}"));
        let dial =
            raven_core::lan_seen::learned_lan_dial(dd, &peer, "192.168.1.20:7420", false, now)
                .expect("a learned route");
        assert_eq!(dial, format!("[fe80::b%{zone}]:7420"));
        match netutil::resolve_dial_target(&dial).await.unwrap()[..] {
            [SocketAddr::V6(v6)] => assert_eq!((v6.scope_id(), v6.port()), (scope, 7420)),
            ref other => panic!("{dial}: {other:?}"),
        }
        if raven_core::route_hints::route_hints_live() {
            let lan = raven_core::learned_routes::learned(dd, &peer, now)
                .and_then(|v| v.lan)
                .expect("the dialer's LAN part");
            assert_eq!(
                (lan.ip, lan.zone, lan.port),
                ("fe80::b".parse().ok(), Some(zone), Some(7431))
            );
        }
    }

    /// With the gate off an RRH1 is any other non-RVN1 frame: the listener
    /// closes, exactly as every older build does.
    #[tokio::test]
    async fn gate_off_listener_closes_on_rrh1_exactly_as_today() {
        if !lab_backend_available() {
            return;
        }
        let _off = crate::hints::LiveForTest::set(false);
        let resp_dir = tempfile::tempdir().unwrap();
        let responder = Arc::new(Identity::from_seed(&[0x87; 32]));
        let dialer = Identity::from_seed(&[0x88; 32]);
        write_book(resp_dir.path(), &[(&dialer, true)]);
        let asked = crate::hints::lan_m3_payload(true, false, true);
        let (mut client, mut t, server) = dial_listener(
            resp_dir.path(),
            &responder,
            &dialer,
            &asked,
            LOOPBACK_DIALER,
            PRODUCTION_LIMITS,
        )
        .await;
        write_cipher(&mut client, &mut t, &route_hint(5))
            .await
            .unwrap();
        assert_eq!(
            listener_result(server).await.unwrap_err(),
            "dispatch: lan frame is not RavenEnvelopeV1"
        );
    }

    /// RRH1 frames are bounded: a dialer stops reading at the third, and a
    /// listener counts them against its frame budget.
    #[tokio::test]
    async fn rrh1_flood_ends_the_dialer_read_and_hits_the_listener_budget() {
        // The dialer's side.
        let (mut dialer, mut t, peer) = noise_pair().await;
        let (mut conn, mut peer_t) = peer.await.unwrap();
        let server = tokio::spawn(async move {
            let _ = read_cipher(&mut conn, &mut peer_t).await;
            for g in 1..=5 {
                if write_cipher(&mut conn, &mut peer_t, &route_hint(g))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            let _keep = (conn, peer_t);
            std::future::pending::<()>().await;
        });
        let frames = vec![message_frame(12)];
        let mut progress = DialProgress::new("LAN", FAST);
        progress
            .collector
            .begin(b"offer".to_vec(), &frames)
            .unwrap();
        let keys = crate::hints::LinkKeys {
            peer: [0x62; 32],
            local: [0x61; 32],
            local_p2p: [0x63; 32],
        };
        let dir = tempfile::tempdir().unwrap();
        let mut hints =
            crate::hints::LinkCtl::lan_dialer(dir.path(), keys, None, LOOPBACK, true, false);
        let err = tokio::time::timeout(
            Duration::from_secs(20),
            exchange_frames(&mut dialer, &mut t, &frames, &mut hints, &mut progress),
        )
        .await
        .expect("does not wait for the ACK")
        .unwrap_err();
        assert!(err.contains("too many route hint frames"), "{err}");
        assert!(hints.flooded());
        server.abort();

        // The listener's side.
        if !lab_backend_available() {
            return;
        }
        let _live = crate::hints::LiveForTest::set(true);
        let resp_dir = tempfile::tempdir().unwrap();
        let responder = Arc::new(Identity::from_seed(&[0x89; 32]));
        let dialer = Identity::from_seed(&[0x8a; 32]);
        write_book(resp_dir.path(), &[(&dialer, true)]);
        let limits = InboundLimits {
            max_frames: 3,
            ..PRODUCTION_LIMITS
        };
        let (mut client, mut t, server) = dial_listener(
            resp_dir.path(),
            &responder,
            &dialer,
            &[],
            LOOPBACK_DIALER,
            limits,
        )
        .await;
        for g in 1..=4 {
            let _ = write_cipher(&mut client, &mut t, &route_hint(g)).await;
        }
        assert_eq!(
            listener_result(server).await.unwrap_err(),
            "lan frame budget exceeded"
        );
    }

    /// Owner decision 1: an unverified contact on the local network learns
    /// only the listener's port, as its card's `lan=` says; a verified one
    /// gets the same port plus whatever else this node has (no p2p host
    /// here, so nothing).
    #[test]
    fn unpinned_contact_gets_only_lan_port() {
        if !lab_backend_available() {
            return;
        }
        // The listener's address is process-wide: hold it for the whole
        // test, on a runtime of this thread (the route-hints switch is set
        // for this thread).
        let _state = listener_state_test_lock();
        let _up = listener_bound("0.0.0.0:7531".parse().unwrap());
        let _live = crate::hints::LiveForTest::set(true);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let responder = Arc::new(Identity::from_seed(&[0x8b; 32]));
            let dialer = Identity::from_seed(&[0x8c; 32]);
            let asked = crate::hints::lan_m3_payload(true, false, true);
            for pinned in [false, true] {
                let resp_dir = tempfile::tempdir().unwrap();
                write_book(resp_dir.path(), &[(&dialer, pinned)]);
                let (mut client, mut t, server) = dial_listener(
                    resp_dir.path(),
                    &responder,
                    &dialer,
                    &asked,
                    LOOPBACK_DIALER,
                    PRODUCTION_LIMITS,
                )
                .await;
                let after = frames_until_close(&mut client, &mut t).await;
                assert_eq!(after.len(), 1, "pinned={pinned}");
                let told = raven_core::route_hints::decode(&after[0]).unwrap();
                assert_eq!(told.lan_port, Some(7531), "pinned={pinned}");
                if !pinned {
                    assert_eq!(
                        told,
                        raven_core::route_hints::RouteHints {
                            generation: told.generation,
                            ttl_s: told.ttl_s,
                            lan_port: Some(7531),
                            ..Default::default()
                        }
                    );
                }
                listener_result(server).await.unwrap();
            }
        });
    }

    /// An announce link (route hints spec §7): no frame of its own; it asks
    /// for the listener's RRH1, reads it and answers it, so both ends learn
    /// (while the cache's switch is on), and nothing is collected as a
    /// reply. Against a listener that never sends one it ends after the idle
    /// wait, having sent nothing.
    #[tokio::test]
    async fn an_announce_link_trades_route_hints_and_waits_at_most_the_idle_wait() {
        if !lab_backend_available() {
            return;
        }
        let _live = crate::hints::LiveForTest::set(true);
        let (dialer_dir, resp_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let responder = Arc::new(Identity::from_seed(&[0x8d; 32]));
        let dialer = Identity::from_seed(&[0x8e; 32]);
        write_book(resp_dir.path(), &[(&dialer, true)]);
        write_book(dialer_dir.path(), &[(&responder, true)]);
        let keys = crate::hints::LinkKeys::new(responder.public_key_bytes(), &dialer);
        let quick = ReplyWaits {
            first: Duration::from_millis(500),
            idle: Duration::from_millis(500),
        };
        let asked = crate::hints::lan_m3_payload(true, false, true);

        // A new listener: one RRH1 each way.
        let (mut client, mut t, server) = dial_listener(
            resp_dir.path(),
            &responder,
            &dialer,
            &asked,
            LOOPBACK_DIALER,
            PRODUCTION_LIMITS,
        )
        .await;
        let mut hints =
            crate::hints::LinkCtl::lan_dialer(dialer_dir.path(), keys, None, LOOPBACK, true, true);
        let mut progress = DialProgress::new("LAN", FAST);
        progress.collector.begin(b"offer".to_vec(), &[]).unwrap();
        exchange_frames(&mut client, &mut t, &[], &mut hints, &mut progress)
            .await
            .unwrap();
        assert_eq!(hints.counts(), (true, 1), "theirs read, ours sent");
        assert_eq!(progress.collector.into_replies(), vec![b"offer".to_vec()]);
        assert!(frames_until_close(&mut client, &mut t).await.is_empty());
        listener_result(server).await.unwrap();
        if raven_core::route_hints::route_hints_live() {
            let now = crate::now_ms();
            let at_listener = raven_core::learned_routes::learned(
                resp_dir.path(),
                &dialer.public_key_bytes(),
                now,
            )
            .expect("the listener learned the announcer's");
            assert_eq!(at_listener.lan.unwrap().ip, LOOPBACK);
            assert!(raven_core::learned_routes::learned(
                dialer_dir.path(),
                &responder.public_key_bytes(),
                now
            )
            .is_some());
        }

        // An old listener (RLB1, then silence): the idle wait, nothing sent.
        let (mut client, mut listener) = tokio::io::duplex(1 << 18);
        let old = Arc::clone(&responder);
        let peer = tokio::spawn(async move {
            let (_, mut t, bind, _m3, _, _) = responder_handshake(&mut listener, &old, None)
                .await
                .unwrap();
            write_cipher(&mut listener, &mut t, &bind).await.unwrap();
            write_cipher(&mut listener, &mut t, b"offer").await.unwrap();
            let mut got = Vec::new();
            while let Ok(frame) = read_cipher(&mut listener, &mut t).await {
                got.push(frame);
            }
            got
        });
        let mut t = initiator_session(&mut client, &dialer, &responder.public_key_bytes(), &asked)
            .await
            .unwrap();
        let _offer = read_cipher(&mut client, &mut t).await.unwrap();
        let mut hints =
            crate::hints::LinkCtl::lan_dialer(dialer_dir.path(), keys, None, LOOPBACK, true, true);
        let mut progress = DialProgress::new("LAN", quick);
        progress.collector.begin(b"offer".to_vec(), &[]).unwrap();
        let started = std::time::Instant::now();
        tokio::time::timeout(
            Duration::from_secs(5),
            exchange_frames(&mut client, &mut t, &[], &mut hints, &mut progress),
        )
        .await
        .expect("bounded by the idle wait")
        .unwrap();
        assert!(started.elapsed() >= quick.idle);
        assert_eq!(hints.counts(), (false, 0));
        drop(client);
        assert!(
            peer.await.unwrap().is_empty(),
            "the old listener got nothing"
        );
    }

    // ── PAD1 link padding (Phase 6b P6.34) ─────────────────────────────

    type Tapped = crate::link::wire::Tap<tokio::io::DuplexStream>;

    /// [`dial_listener`] with the dialer's end tapped (what it writes and
    /// reads on the wire, `crate::link::wire`), from a loopback dialer;
    /// also returns the dialer's RLB1 offer.
    async fn tapped_dial_listener(
        resp_dir: &Path,
        responder: &Arc<Identity>,
        dialer: &Identity,
        m3: &[u8],
    ) -> (
        Tapped,
        LinkCipher,
        tokio::task::JoinHandle<Result<(), String>>,
        Vec<u8>,
    ) {
        let init_dir = tempfile::tempdir().unwrap();
        let (client, server_side) = tokio::io::duplex(1 << 18);
        let mut client = crate::link::wire::Tap::new(client);
        let (data_dir, resp) = (resp_dir.to_path_buf(), responder.clone());
        let server = tokio::spawn(async move {
            let mut slot = test_slot();
            handle_inbound(
                data_dir,
                resp,
                server_side,
                PRODUCTION_LIMITS,
                &mut slot,
                LOOPBACK_DIALER,
            )
            .await
        });
        let mut t = initiator_session(&mut client, dialer, &responder.public_key_bytes(), m3)
            .await
            .expect("Noise XX + bind");
        let offer = encode_local_offer(init_dir.path(), dialer).unwrap();
        write_cipher(&mut client, &mut t, &offer).await.unwrap();
        let theirs = read_cipher(&mut client, &mut t).await.unwrap();
        assert!(parse_peer_offer(&theirs).is_ok(), "the listener's RLB1");
        (client, t, server, offer)
    }

    /// [`frames_until_close`] on a tapped end.
    async fn tapped_until_close(client: &mut Tapped, t: &mut LinkCipher) -> Vec<Vec<u8>> {
        client.shutdown().await.unwrap();
        let mut got = Vec::new();
        while let Ok(frame) = read_cipher(client, t).await {
            got.push(frame);
        }
        got
    }

    /// P6.34, each order: old dialer and old listener (the baseline), old
    /// dialer and new listener, new and old, new and new. After the
    /// handshake every message on the wire is a PAD1 bucket plus the tag
    /// when both are new (but the dialer's 96-byte bind, which comes before
    /// it knows), and exactly the baseline's lengths otherwise: a new side
    /// whose peer did not offer PAD1 sends what it sent before. A frame
    /// after the RLB1 exchange (the dialer's RLB1 again) is read either way.
    #[tokio::test]
    async fn pad1_sizes_on_the_wire_for_each_order() {
        use crate::link::wire::is_padded;
        if !lab_backend_available() {
            return;
        }
        let _hints = crate::hints::LiveForTest::set(false);
        let resp_dir = tempfile::tempdir().unwrap();
        let responder = Arc::new(Identity::from_seed(&[0x8b; 32]));
        let dialer = Identity::from_seed(&[0x8c; 32]);
        write_book(resp_dir.path(), &[(&dialer, true)]);
        let mut baseline = None;
        for (dialer_new, listener_new) in
            [(false, false), (false, true), (true, false), (true, true)]
        {
            let _pad = crate::link::PaddingForTest::set(listener_new);
            if listener_new && !crate::link::padding_live() {
                return; // a release build: the gate cannot open
            }
            let m3 = crate::hints::lan_m3_payload(false, dialer_new, true);
            assert_eq!(m3.is_empty(), !dialer_new);
            let (mut client, mut t, server, offer) =
                tapped_dial_listener(resp_dir.path(), &responder, &dialer, &m3).await;
            write_cipher(&mut client, &mut t, &offer).await.unwrap();
            assert!(tapped_until_close(&mut client, &mut t).await.is_empty());
            listener_result(server).await.expect("a clean end");
            let (sent, received) = client.lengths();
            assert_eq!(
                (sent.len(), received.len()),
                (5, 3),
                "{sent:?} {received:?}"
            );
            let after = (sent[2..].to_vec(), received[1..].to_vec());
            let both = dialer_new && listener_new;
            assert_eq!(t.pad.peer_started(), both);
            assert_eq!(t.pad.negotiated(), both);
            if both {
                assert_eq!(sent[2], 96 + 16, "the dialer's bind is bare");
                assert!(sent[3..].iter().all(|&n| is_padded(n)), "{sent:?}");
                assert!(received[1..].iter().all(|&n| is_padded(n)), "{received:?}");
                assert_eq!(received[1], 512 + 16, "the listener's bind");
            } else if let Some(base) = &baseline {
                assert_eq!(
                    &after, base,
                    "dialer_new={dialer_new} listener_new={listener_new}"
                );
            } else {
                assert!(!after.0.iter().chain(&after.1).any(|&n| is_padded(n)));
                baseline = Some(after);
            }
        }
    }

    /// P6.34: a dialer that stops padding mid-link (a bare frame after its
    /// RPD1 ones) is closed, and that is `SEC_CONTACT_MALFORMED` about it.
    #[tokio::test]
    async fn a_dialer_that_stops_padding_is_closed_as_malformed() {
        use crate::security::tests::Capture;
        use raven_core::security_events::{Attribution, SecKind, Via};
        if !lab_backend_available() {
            return;
        }
        let _hints = crate::hints::LiveForTest::set(false);
        let _pad = crate::link::PaddingForTest::set(true);
        let Some(capture) = Capture::start() else {
            return;
        };
        if !crate::link::padding_live() {
            return;
        }
        let resp_dir = tempfile::tempdir().unwrap();
        let responder = Arc::new(Identity::from_seed(&[0x8f; 32]));
        let dialer = Identity::from_seed(&[0x90; 32]);
        write_book(resp_dir.path(), &[(&dialer, true)]);
        let m3 = crate::hints::lan_m3_payload(false, true, true);
        let (mut client, mut t, server, offer) =
            tapped_dial_listener(resp_dir.path(), &responder, &dialer, &m3).await;
        assert!(t.pad.peer_started());
        // Padded, as the link agreed: read as before.
        write_cipher(&mut client, &mut t, &offer).await.unwrap();
        t.pad = PadState::OFF;
        write_cipher(&mut client, &mut t, &offer).await.unwrap();
        assert_eq!(listener_result(server).await, Ok(()), "closed");
        assert!(tapped_until_close(&mut client, &mut t).await.is_empty());
        assert_eq!(
            capture.kinds(),
            [(
                SecKind::ContactMalformed,
                Attribution::Contact {
                    peer: dialer.public_key_bytes()
                },
                Via::DirectLink(raven_core::OutboxCarrier::Lan)
            )]
        );
    }

    /// P6.34: an announce link between two new ends (route hints and PAD1
    /// live): the RRH1 each way is padded and unwrapped and consumed as
    /// before, and nothing else crosses.
    #[tokio::test]
    async fn an_announce_link_pads_its_route_hints_both_ways() {
        use crate::link::wire::is_padded;
        if !lab_backend_available() {
            return;
        }
        let _hints = crate::hints::LiveForTest::set(true);
        let _pad = crate::link::PaddingForTest::set(true);
        if !crate::link::padding_live() {
            return;
        }
        let (dialer_dir, resp_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let responder = Arc::new(Identity::from_seed(&[0x87; 32]));
        let dialer = Identity::from_seed(&[0x88; 32]);
        write_book(resp_dir.path(), &[(&dialer, true)]);
        write_book(dialer_dir.path(), &[(&responder, true)]);
        let m3 = crate::hints::lan_m3_payload(true, true, true);
        let (mut client, mut t, server, _) =
            tapped_dial_listener(resp_dir.path(), &responder, &dialer, &m3).await;
        let keys = crate::hints::LinkKeys::new(responder.public_key_bytes(), &dialer);
        let mut hints =
            crate::hints::LinkCtl::lan_dialer(dialer_dir.path(), keys, None, LOOPBACK, true, true);
        let mut progress = DialProgress::new("LAN", FAST);
        progress.collector.begin(b"offer".to_vec(), &[]).unwrap();
        exchange_frames(&mut client, &mut t, &[], &mut hints, &mut progress)
            .await
            .unwrap();
        assert_eq!(hints.counts(), (true, 1), "theirs read, ours sent");
        assert_eq!(progress.collector.into_replies(), vec![b"offer".to_vec()]);
        assert!(tapped_until_close(&mut client, &mut t).await.is_empty());
        listener_result(server).await.unwrap();
        let (sent, received) = client.lengths();
        // m1, m3, bind, RLB1, RRH1 / m2, bind, RLB1, RRH1.
        assert_eq!(
            (sent.len(), received.len()),
            (5, 4),
            "{sent:?} {received:?}"
        );
        assert!(sent[3..].iter().all(|&n| is_padded(n)), "{sent:?}");
        assert!(received[1..].iter().all(|&n| is_padded(n)), "{received:?}");
    }

    /// P6.34 through `dial_session` itself: a real TCP dial to a real
    /// listener tapped on its side, route hints and PAD1 live. An announce
    /// dial (it reads) offers both: every message after the handshake is
    /// padded but the dialer's bind, the RRH1 each way included. A
    /// frame-less probe offers neither: nothing is padded, as before.
    #[tokio::test]
    async fn a_real_dial_pads_only_when_it_reads() {
        use crate::link::wire::{is_padded, lengths, Log, Tap};
        if !file_backends() {
            return;
        }
        let _lan = lan_switch_untouched();
        let _hints = crate::hints::LiveForTest::set(true);
        let _pad = crate::link::PaddingForTest::set(true);
        if !crate::link::padding_live() {
            return;
        }
        // The frames of PAD1 alone: RUP1 (P6.49) would add each side's HAVE
        // after RRH1 when a lab run opens the update gates.
        #[cfg(debug_assertions)]
        crate::update_exchange::gates_for_test(Some(false));
        let (a_dir, b_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let alice = dialer_profile(a_dir.path());
        let bob = Arc::new(Identity::from_seed(&[0x97; 32]));
        write_book(b_dir.path(), &[(&alice, true)]);
        write_book(a_dir.path(), &[(&bob, true)]);
        for announce in [true, false] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap().to_string();
            let (data_dir, resp) = (b_dir.path().to_path_buf(), bob.clone());
            let (wrote, read) = (Log::default(), Log::default());
            let logs = (wrote.clone(), read.clone());
            let server = tokio::spawn(async move {
                let (stream, from) = listener.accept().await.unwrap();
                let stream = Tap::with_logs(stream, logs.0, logs.1);
                let mut slot = test_slot();
                handle_inbound_with(
                    data_dir,
                    resp,
                    stream,
                    PRODUCTION_LIMITS,
                    &mut slot,
                    Some(from),
                    PINS_OFF,
                )
                .await
            });
            let mut progress = DialProgress::new("LAN", FAST);
            tokio::time::timeout(
                Duration::from_secs(20),
                dial_session(
                    a_dir.path(),
                    &addr,
                    &bob.public_key_bytes(),
                    &[],
                    announce,
                    PINS_OFF,
                    &mut progress,
                ),
            )
            .await
            .expect("the dial ends")
            .unwrap();
            listener_result(server).await.unwrap();
            let (from_dialer, from_listener) = (
                lengths(&read.lock().unwrap()),
                lengths(&wrote.lock().unwrap()),
            );
            if announce {
                // m1, m3, bind, RLB1, RRH1 / m2, bind, RLB1, RRH1.
                assert_eq!(from_dialer.len(), 5, "{from_dialer:?}");
                assert_eq!(from_listener.len(), 4, "{from_listener:?}");
                assert_eq!(from_dialer[2], 96 + 16, "the dialer's bind");
                assert!(
                    from_dialer[3..].iter().all(|&n| is_padded(n)),
                    "{from_dialer:?}"
                );
                assert!(
                    from_listener[1..].iter().all(|&n| is_padded(n)),
                    "{from_listener:?}"
                );
            } else {
                // m1, m3, bind, RLB1 / m2, bind, RLB1.
                assert_eq!((from_dialer.len(), from_listener.len()), (4, 3));
                assert!(!from_dialer
                    .iter()
                    .chain(&from_listener)
                    .any(|&n| is_padded(n)));
            }
        }
        #[cfg(debug_assertions)]
        crate::update_exchange::gates_for_test(None);
    }

    // ── Noise pins (M0) ─────────────────────────────────────────────────

    const PINS_ON: NoisePins = NoisePins { live: true };
    const PINS_OFF: NoisePins = NoisePins { live: false };

    fn noise_static_of(id: &Identity) -> [u8; 32] {
        noise_static_public(&derive_noise_static(id).unwrap())
    }

    /// The pin `holder` keeps for `contact` when its computer is `id`.
    fn pin_for(holder: &Identity, contact: &Identity, id: &Identity) -> [u8; 32] {
        pin_digest(
            &PinKey::derive(holder),
            &contact.public_key_bytes(),
            &noise_static_of(id),
        )
    }

    /// A scripted responder holding `id`'s static: reads message 1, answers
    /// message 2, then keeps everything the dialer sends until it closes.
    async fn scripted_responder<S: AsyncRead + AsyncWrite + Unpin>(
        mut stream: S,
        id: &Identity,
    ) -> Vec<u8> {
        let secret = derive_noise_static(id).unwrap();
        let mut hs = build_responder(&secret).unwrap();
        let m1 = read_raw(&mut stream).await.unwrap();
        handshake_read(&mut hs, &m1).unwrap();
        let m2 = handshake_write(&mut hs, &[]).unwrap();
        write_raw(&mut stream, &m2).await.unwrap();
        let mut rest = Vec::new();
        let _ = stream.read_to_end(&mut rest).await;
        rest
    }

    /// A full dial loads the dialer's identity from its data dir: only with
    /// the locked-file identity and prekey backends (never an OS keystore),
    /// in a debug build.
    fn file_backends() -> bool {
        let on = cfg!(debug_assertions)
            && ["RAVEN_IDENTITY_BACKEND", "RAVEN_PREKEY_BACKEND"]
                .iter()
                .all(|k| std::env::var(k).is_ok_and(|v| v == "locked-file"));
        if !on {
            eprintln!(
                "skipped: needs a debug build and the locked-file identity and prekey backends"
            );
        }
        on
    }

    /// A dialer profile in `dir`, as `raven init` leaves it (locked-file).
    fn dialer_profile(dir: &Path) -> Identity {
        raven_core::load_or_create_identity(dir).unwrap().0
    }

    /// A real listener (`handle_inbound_with`) on a loopback port for one
    /// connection: its address and task.
    async fn serve_one(
        resp_dir: &Path,
        responder: &Arc<Identity>,
        pins: NoisePins,
    ) -> (String, tokio::task::JoinHandle<Result<(), String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let (data_dir, resp) = (resp_dir.to_path_buf(), responder.clone());
        let task = tokio::spawn(async move {
            let (stream, from) = listener.accept().await.unwrap();
            let mut slot = test_slot();
            handle_inbound_with(
                data_dir,
                resp,
                stream,
                PRODUCTION_LIMITS,
                &mut slot,
                Some(from),
                pins,
            )
            .await
        });
        (addr, task)
    }

    /// A loopback port where `id`'s scripted responder answers every
    /// connection: its address, how many connected, and what each sent
    /// after message 2.
    async fn scripted_port(id: Identity) -> (String, Arc<Mutex<Vec<Vec<u8>>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let rest = scripted_responder(stream, &id).await;
                log.lock().unwrap().push(rest);
            }
        });
        (addr, seen)
    }

    async fn full_dial(
        dir: &Path,
        addr: &str,
        expected: &[u8; 32],
        frames: &[Vec<u8>],
        pins: NoisePins,
    ) -> Result<(), String> {
        let mut progress = DialProgress::new("LAN", FAST);
        tokio::time::timeout(
            Duration::from_secs(20),
            dial_session(dir, addr, expected, frames, false, pins, &mut progress),
        )
        .await
        .expect("the dial ends")
    }

    /// M0: Alice holds Bob's pin and dials his old address, where Mallory
    /// answers. The dial ends after message 2: Mallory never gets message 3
    /// (Alice's static) or the bind (her signed identity). Without a pin
    /// (today, or with the gate closed) the same responder gets both, and the
    /// bind names Alice: what the pin keeps back.
    #[tokio::test]
    async fn a_pinned_dial_stops_before_message_3_when_another_key_answers() {
        const MALLORY: [u8; 32] = [0x93; 32];
        let alice = Identity::from_seed(&[0x91; 32]);
        let bob = Identity::from_seed(&[0x92; 32]);
        let pin = pin_for(&alice, &bob, &bob);
        let (mut dialer, listener) = tokio::io::duplex(1 << 18);
        let peer = tokio::spawn(async move {
            scripted_responder(listener, &Identity::from_seed(&MALLORY)).await
        });
        let err = initiator_session_pinned(
            &mut dialer,
            &alice,
            &bob.public_key_bytes(),
            &[],
            Some(&pin),
            None,
            None,
        )
        .await
        .err();
        assert_eq!(err.as_deref(), Some(NOISE_PIN_MISMATCH));
        assert!(!NOISE_PIN_MISMATCH.contains("127.0.0.1"));
        drop(dialer);
        assert!(peer.await.unwrap().is_empty(), "no message 3, no bind");

        // No pin: message 3 and the bind go out, and the bind verifies as
        // Alice's under her static.
        let (mut dialer, mut listener) = tokio::io::duplex(1 << 18);
        let peer = tokio::spawn(async move {
            let secret = derive_noise_static(&Identity::from_seed(&MALLORY)).unwrap();
            let mut hs = build_responder(&secret).unwrap();
            let m1 = read_raw(&mut listener).await.unwrap();
            handshake_read(&mut hs, &m1).unwrap();
            let m2 = handshake_write(&mut hs, &[]).unwrap();
            write_raw(&mut listener, &m2).await.unwrap();
            let m3 = read_raw(&mut listener).await.unwrap();
            handshake_read(&mut hs, &m3).unwrap();
            let dialer_static = get_remote_static(&hs).unwrap();
            let mut t = LinkCipher::new(into_transport(hs).unwrap());
            let bind = read_cipher(&mut listener, &mut t).await.unwrap();
            verify_bind(&bind, &dialer_static, None).unwrap()
        });
        let err = initiator_session_pinned(
            &mut dialer,
            &alice,
            &bob.public_key_bytes(),
            &[],
            None,
            None,
            None,
        )
        .await
        .err();
        assert_eq!(err.as_deref(), Some(netutil::LINK_NOT_ACCEPTED));
        assert_eq!(peer.await.unwrap(), alice.public_key_bytes(), "the leak");
    }

    /// The pinned key answering completes as today, and the dial learns the
    /// responder's static.
    #[tokio::test]
    async fn a_matching_pin_completes() {
        const BOB: [u8; 32] = [0x95; 32];
        let alice = Identity::from_seed(&[0x94; 32]);
        let bob = Identity::from_seed(&BOB);
        let pin = pin_for(&alice, &bob, &bob);
        let (mut dialer, mut listener) = tokio::io::duplex(1 << 18);
        let peer = tokio::spawn(async move {
            let (dialer_ed, mut t) = responder_session(&mut listener, &Identity::from_seed(&BOB))
                .await
                .unwrap();
            let got = read_cipher(&mut listener, &mut t).await.unwrap();
            (dialer_ed, got)
        });
        let (mut t, remote_static, _) = initiator_session_pinned(
            &mut dialer,
            &alice,
            &bob.public_key_bytes(),
            &[],
            Some(&pin),
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(remote_static, noise_static_of(&bob));
        write_cipher(&mut dialer, &mut t, b"after the bind")
            .await
            .unwrap();
        assert_eq!(
            peer.await.unwrap(),
            (alice.public_key_bytes(), b"after the bind".to_vec())
        );
    }

    /// No pin yet: the dial runs as today against a real listener, and once
    /// the responder's bind verified the dialer pins its static; the
    /// listener pins the dialer's (a contact's inbound link). Without the
    /// RLK1 knock: a knocked link pins nothing
    /// (`a_knocked_link_pins_nothing_and_an_unknocked_one_still_does`).
    #[tokio::test]
    async fn no_pin_dials_as_today_and_records_after_the_link() {
        if !file_backends() {
            return;
        }
        let _lan = lan_switch_untouched();
        let _knock = crate::link_knock::KnockForTest::set(false);
        let (a_dir, b_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let alice = dialer_profile(a_dir.path());
        let bob = Arc::new(Identity::from_seed(&[0x96; 32]));
        write_book(b_dir.path(), &[(&alice, true)]);
        write_book(a_dir.path(), &[(&bob, true)]);
        let (addr, server) = serve_one(b_dir.path(), &bob, PINS_ON).await;
        full_dial(a_dir.path(), &addr, &bob.public_key_bytes(), &[], PINS_ON)
            .await
            .unwrap();
        assert_eq!(
            raven_core::lan_noise_pin::load_pin(a_dir.path(), &bob.public_key_bytes()),
            Ok(Some(pin_for(&alice, &bob, &bob)))
        );
        listener_result(server).await.unwrap();
        assert_eq!(
            raven_core::lan_noise_pin::load_pin(b_dir.path(), &alice.public_key_bytes()),
            Ok(Some(pin_for(&bob, &alice, &alice)))
        );
        // The pinned key again: the dial completes and writes nothing.
        let path = a_dir.path().join(raven_core::lan_noise_pin::NOISE_PIN_FILE);
        let before = std::fs::read(&path).unwrap();
        let (addr, server) = serve_one(b_dir.path(), &bob, PINS_ON).await;
        full_dial(a_dir.path(), &addr, &bob.public_key_bytes(), &[], PINS_ON)
            .await
            .unwrap();
        listener_result(server).await.unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    /// P3.14: with the session renewer running, a contact's link queues the
    /// contact for a renewal step at both ends: the listener notes the dialer
    /// (inbound, trusted branch), the dialer the listener once its verified
    /// RLB1 offer arrived (outbound).
    #[tokio::test]
    async fn a_contact_link_queues_both_ends_for_renewal() {
        if !file_backends() {
            return;
        }
        let _lan = lan_switch_untouched();
        let _renewer = crate::renewal::RunningForTest::set();
        let (a_dir, b_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let alice = dialer_profile(a_dir.path());
        let bob = Arc::new(Identity::from_seed(&[0x9e; 32]));
        write_book(b_dir.path(), &[(&alice, true)]);
        write_book(a_dir.path(), &[(&bob, true)]);
        let (addr, server) = serve_one(b_dir.path(), &bob, PINS_ON).await;
        full_dial(a_dir.path(), &addr, &bob.public_key_bytes(), &[], PINS_ON)
            .await
            .unwrap();
        listener_result(server).await.unwrap();
        assert!(
            crate::renewal::queued_for_test(&bob.public_key_bytes()),
            "the dialer queued the contact it reached"
        );
        assert!(
            crate::renewal::queued_for_test(&alice.public_key_bytes()),
            "the listener queued the contact that reached it"
        );
    }

    /// A contact's inbound link (its bind signs its static) replaces the pin
    /// held for it: a new static (Phase 6b rotation) is learned this way.
    #[tokio::test]
    async fn an_inbound_contact_link_refreshes_its_pin() {
        if !lab_backend_available() {
            return;
        }
        let resp_dir = tempfile::tempdir().unwrap();
        let responder = Arc::new(Identity::from_seed(&[0x97; 32]));
        let dialer = Identity::from_seed(&[0x98; 32]);
        let old_computer = Identity::from_seed(&[0x99; 32]);
        write_book(resp_dir.path(), &[(&dialer, true)]);
        raven_core::lan_noise_pin::record(
            resp_dir.path(),
            &PinKey::derive(&responder),
            &dialer.public_key_bytes(),
            &noise_static_of(&old_computer),
        )
        .unwrap();
        let (client, _t, server) = dial_listener_with(
            resp_dir.path(),
            &responder,
            &dialer,
            &[],
            LOOPBACK_DIALER,
            PRODUCTION_LIMITS,
            PINS_ON,
        )
        .await;
        drop(client);
        listener_result(server).await.unwrap();
        assert_eq!(
            raven_core::lan_noise_pin::load_pin(resp_dir.path(), &dialer.public_key_bytes()),
            Ok(Some(pin_for(&responder, &dialer, &dialer)))
        );
    }

    /// Strangers, blocked keys and an unverified contact from outside the
    /// local network are refused before anything else: none writes a pin.
    #[tokio::test]
    async fn a_stranger_inbound_writes_no_pin() {
        let responder = Arc::new(Identity::from_seed(&[0x9a; 32]));
        let dialer = Identity::from_seed(&[0x9b; 32]);
        let public: Option<SocketAddr> = Some("203.0.113.9:50123".parse().unwrap());
        for case in ["no contacts.json", "blocked contact", "unverified, remote"] {
            let resp_dir = tempfile::tempdir().unwrap();
            let source = match case {
                "blocked contact" => {
                    write_contacts(resp_dir.path(), &[&dialer]);
                    let mut blocks = raven_core::BlockList::default();
                    blocks.block(&hex::encode(dialer.public_key_bytes()));
                    blocks.save(resp_dir.path()).unwrap();
                    LOOPBACK_DIALER
                }
                "unverified, remote" => {
                    write_book(resp_dir.path(), &[(&dialer, false)]);
                    public
                }
                _ => LOOPBACK_DIALER,
            };
            let (mut client, server_side) = tokio::io::duplex(1 << 18);
            let (data_dir, resp) = (resp_dir.path().to_path_buf(), responder.clone());
            let server = tokio::spawn(async move {
                let mut slot = test_slot();
                handle_inbound_with(
                    data_dir,
                    resp,
                    server_side,
                    PRODUCTION_LIMITS,
                    &mut slot,
                    source,
                    PINS_ON,
                )
                .await
            });
            let got =
                initiator_session(&mut client, &dialer, &responder.public_key_bytes(), &[]).await;
            assert_eq!(
                got.err().as_deref(),
                Some(netutil::LINK_NOT_ACCEPTED),
                "{case}"
            );
            assert!(listener_result(server).await.is_err(), "{case}");
            assert!(
                !resp_dir
                    .path()
                    .join(raven_core::lan_noise_pin::NOISE_PIN_FILE)
                    .exists(),
                "{case}"
            );
        }
    }

    /// The gate closed (a release build until the flip, or `RAVEN_LAB_NOISE_PIN=0`
    /// after it): a full exchange reads and writes no pin on either side, and
    /// a pin already on disk is neither checked nor changed.
    #[tokio::test]
    async fn gate_closed_reads_and_writes_no_pin() {
        if !file_backends() {
            return;
        }
        let _lan = lan_switch_untouched();
        let (a_dir, b_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let alice = dialer_profile(a_dir.path());
        let bob = Arc::new(Identity::from_seed(&[0x9c; 32]));
        write_book(b_dir.path(), &[(&alice, true)]);
        write_book(a_dir.path(), &[(&bob, true)]);
        let (addr, server) = serve_one(b_dir.path(), &bob, PINS_OFF).await;
        full_dial(a_dir.path(), &addr, &bob.public_key_bytes(), &[], PINS_OFF)
            .await
            .unwrap();
        listener_result(server).await.unwrap();
        for dir in [a_dir.path(), b_dir.path()] {
            for name in [
                raven_core::lan_noise_pin::NOISE_PIN_FILE,
                ".lan_noise_pins.lock.sqlite",
            ] {
                assert!(!dir.join(name).exists(), "{name}");
            }
        }
        // A pin for another computer on disk: not read, so not refused, and
        // not rewritten.
        let other = Identity::from_seed(&[0x9d; 32]);
        raven_core::lan_noise_pin::record(
            a_dir.path(),
            &PinKey::derive(&alice),
            &bob.public_key_bytes(),
            &noise_static_of(&other),
        )
        .unwrap();
        let path = a_dir.path().join(raven_core::lan_noise_pin::NOISE_PIN_FILE);
        let before = std::fs::read(&path).unwrap();
        let (addr, server) = serve_one(b_dir.path(), &bob, PINS_OFF).await;
        full_dial(a_dir.path(), &addr, &bob.public_key_bytes(), &[], PINS_OFF)
            .await
            .unwrap();
        listener_result(server).await.unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    /// A pin mismatch is final for that dial: one connection, never a
    /// handshake retry (only a hang-up is retried), and the error is the
    /// fixed text.
    #[tokio::test]
    async fn a_pin_mismatch_is_not_retried() {
        let _lan = lan_switch_untouched();
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let err = netutil::with_handshake_retries(|| {
            calls.fetch_add(1, Ordering::SeqCst);
            async { Err::<(), _>(NOISE_PIN_MISMATCH.to_string()) }
        })
        .await
        .unwrap_err();
        assert_eq!((err.as_str(), calls.into_inner()), (NOISE_PIN_MISMATCH, 1));
        if !file_backends() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let alice = dialer_profile(dir.path());
        let bob = Identity::from_seed(&[0x9e; 32]);
        write_book(dir.path(), &[(&bob, true)]);
        raven_core::lan_noise_pin::record(
            dir.path(),
            &PinKey::derive(&alice),
            &bob.public_key_bytes(),
            &noise_static_of(&bob),
        )
        .unwrap();
        let (addr, seen) = scripted_port(Identity::from_seed(&[0x9f; 32])).await;
        let err = full_dial(
            dir.path(),
            &addr,
            &bob.public_key_bytes(),
            &[message_frame(1)],
            PINS_ON,
        )
        .await
        .unwrap_err();
        assert_eq!(err, NOISE_PIN_MISMATCH);
        let one = |seen: &Mutex<Vec<Vec<u8>>>| seen.lock().unwrap().clone();
        let done = std::time::Instant::now() + Duration::from_secs(5);
        while one(&seen).is_empty() && std::time::Instant::now() < done {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            one(&seen),
            vec![Vec::<u8>::new()],
            "one connection, nothing after m2"
        );
        assert_eq!(
            raven_core::lan_noise_pin::load_pin(dir.path(), &bob.public_key_bytes()),
            Ok(Some(pin_for(&alice, &bob, &bob))),
            "the pin stays"
        );
    }

    /// Privacy pack PP.5: a sealed profile keeps its pins in the sealed
    /// file (never the old plain name), and a pinned dial still stops after
    /// message 2 when another key answers: one connection, nothing sent
    /// after message 2, the pin kept. A sealed pin file that does not open
    /// (a changed byte) ends the dial before it connects.
    #[tokio::test]
    async fn a_sealed_pin_file_still_stops_the_dial_before_message_3() {
        use crate::at_rest_boot::tests::{lab_hist_key, seal, serial};
        use raven_core::lan_noise_pin::{NOISE_PIN_FILE, NOISE_PIN_SEALED_FILE};
        if !file_backends() || !lab_hist_key() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let alice = dialer_profile(dir.path());
        let bob = Identity::from_seed(&[0xb4; 32]);
        write_book(dir.path(), &[(&bob, true)]);
        {
            let _serial = serial();
            seal(dir.path());
        }
        // After `serial()`: the LAN switch lock is always taken last.
        let _lan = lan_switch_untouched();
        raven_core::lan_noise_pin::record(
            dir.path(),
            &PinKey::derive(&alice),
            &bob.public_key_bytes(),
            &noise_static_of(&bob),
        )
        .unwrap();
        let sealed = std::fs::read(dir.path().join(NOISE_PIN_SEALED_FILE)).unwrap();
        assert!(raven_core::at_rest::is_sealed(&sealed));
        assert!(!dir.path().join(NOISE_PIN_FILE).exists());
        let bob_hex = hex::encode(bob.public_key_bytes());
        assert!(!sealed
            .windows(bob_hex.len())
            .any(|w| w == bob_hex.as_bytes()));

        let (addr, seen) = scripted_port(Identity::from_seed(&[0xb5; 32])).await;
        let err = full_dial(
            dir.path(),
            &addr,
            &bob.public_key_bytes(),
            &[message_frame(3)],
            PINS_ON,
        )
        .await
        .unwrap_err();
        assert_eq!(err, NOISE_PIN_MISMATCH);
        let one = |seen: &Mutex<Vec<Vec<u8>>>| seen.lock().unwrap().clone();
        let done = std::time::Instant::now() + Duration::from_secs(5);
        while one(&seen).is_empty() && std::time::Instant::now() < done {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            one(&seen),
            vec![Vec::<u8>::new()],
            "one connection, nothing after m2"
        );
        assert_eq!(
            raven_core::lan_noise_pin::load_pin(dir.path(), &bob.public_key_bytes()),
            Ok(Some(pin_for(&alice, &bob, &bob))),
            "the pin stays"
        );

        // A changed byte: the store does not open, so no dial at all.
        let mut changed = sealed.clone();
        *changed.last_mut().unwrap() ^= 1;
        std::fs::write(dir.path().join(NOISE_PIN_SEALED_FILE), &changed).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let err = full_dial(
            dir.path(),
            &addr,
            &bob.public_key_bytes(),
            &[message_frame(4)],
            PINS_ON,
        )
        .await
        .unwrap_err();
        assert!(err.starts_with(NOISE_PIN_UNAVAILABLE), "{err}");
        assert!(err.contains(NOISE_PIN_SEALED_FILE), "{err}");
        let accepted = tokio::time::timeout(Duration::from_millis(300), listener.accept()).await;
        assert!(accepted.is_err(), "nothing connected");
    }

    /// The gate closed in a sealed profile: a full exchange reads and writes
    /// no pin file on either side, under either name.
    #[tokio::test]
    async fn gate_closed_reads_and_writes_no_pin_in_a_sealed_profile() {
        use crate::at_rest_boot::tests::{lab_hist_key, seal, serial};
        if !file_backends() || !lab_hist_key() {
            return;
        }
        let (a_dir, b_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let alice = dialer_profile(a_dir.path());
        let bob = Arc::new(Identity::from_seed(&[0xb6; 32]));
        write_book(b_dir.path(), &[(&alice, true)]);
        write_book(a_dir.path(), &[(&bob, true)]);
        {
            let _serial = serial();
            seal(a_dir.path());
        }
        // After `serial()`: the LAN switch lock is always taken last.
        let _lan = lan_switch_untouched();
        let (addr, server) = serve_one(b_dir.path(), &bob, PINS_OFF).await;
        full_dial(a_dir.path(), &addr, &bob.public_key_bytes(), &[], PINS_OFF)
            .await
            .unwrap();
        listener_result(server).await.unwrap();
        for dir in [a_dir.path(), b_dir.path()] {
            for name in [
                raven_core::lan_noise_pin::NOISE_PIN_FILE,
                raven_core::lan_noise_pin::NOISE_PIN_SEALED_FILE,
                ".lan_noise_pins.lock.sqlite",
            ] {
                assert!(!dir.join(name).exists(), "{name}");
            }
        }
    }

    /// A pin store that exists but cannot be read ends the dial before it
    /// connects (the privacy pack's locked store, here a directory in its
    /// place).
    #[tokio::test]
    async fn an_unreadable_pin_store_does_not_dial() {
        if !file_backends() {
            return;
        }
        let _lan = lan_switch_untouched();
        let dir = tempfile::tempdir().unwrap();
        dialer_profile(dir.path());
        std::fs::create_dir(dir.path().join(raven_core::lan_noise_pin::NOISE_PIN_FILE)).unwrap();
        let bob = Identity::from_seed(&[0xa0; 32]);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let err = full_dial(
            dir.path(),
            &addr,
            &bob.public_key_bytes(),
            &[message_frame(2)],
            PINS_ON,
        )
        .await
        .unwrap_err();
        // Which file and why (A-noise-pin-4), no address or key.
        assert!(err.starts_with(NOISE_PIN_UNAVAILABLE), "{err}");
        assert!(
            err.contains(raven_core::lan_noise_pin::NOISE_PIN_FILE),
            "{err}"
        );
        assert!(!err.contains(&addr) && !err.contains(&hex::encode(bob.public_key_bytes())));
        let accepted = tokio::time::timeout(Duration::from_millis(300), listener.accept()).await;
        assert!(accepted.is_err(), "nothing connected");
    }

    // ── RLK1 link knock (P6.35) ─────────────────────────────────────────

    /// The knock open for this thread; `None` in a release build (nothing
    /// to check there).
    fn knock_on() -> Option<crate::link_knock::KnockForTest> {
        let on = crate::link_knock::KnockForTest::set(true);
        crate::link_knock::live().then_some(on)
    }

    /// A dialer's address on the local network: its contact gate takes any
    /// contact from there, so its knock book holds every contact.
    const HERE: Option<std::net::IpAddr> = Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
        192, 168, 1, 20,
    )));

    /// `id`'s LAN ear on `dir` (the knock live), from `source`.
    fn ear(dir: &Path, id: &Arc<Identity>, source: Option<std::net::IpAddr>) -> Ear {
        Ear::of(dir, id, source, raven_core::OutboxCarrier::Lan).expect("the knock is live")
    }

    /// A dialer without the knock (any older build) against `ear`'s
    /// listener: the static message 2 carried, or the listener's error when
    /// it sent none.
    async fn unknocked_probe(
        ear: Ear,
        listener_id: Arc<Identity>,
        prober: &Identity,
    ) -> Result<[u8; 32], String> {
        let (mut client, mut listener) = tokio::io::duplex(1 << 18);
        let peer = tokio::spawn(async move {
            responder_handshake(&mut listener, &listener_id, Some(&ear))
                .await
                .map(drop)
        });
        let mut hs = build_initiator(&derive_noise_static(prober).unwrap()).unwrap();
        write_raw(&mut client, &handshake_write(&mut hs, &[]).unwrap())
            .await
            .unwrap();
        let seen = match read_raw(&mut client).await {
            Ok(m2) => {
                handshake_read(&mut hs, &m2).unwrap();
                Ok(get_remote_static(&hs).unwrap())
            }
            Err(_) => Err(String::new()),
        };
        drop(client);
        let ended = peer.await.unwrap();
        seen.map_err(|_| ended.unwrap_err())
    }

    /// RLK1: Alice knocks at Bob's listener twice. Each time Bob answers
    /// with a fresh static (never his derived one, and another each time)
    /// and the proof, Alice goes on with a fresh static of her own, both
    /// binds verify, and Bob learns that Alice knocked. The three handshake
    /// messages have jittered sizes within design B §3's ranges, and the
    /// RLX1 caps of message 3 read as before.
    #[tokio::test]
    async fn knocked_dials_get_a_fresh_listener_static_each_time() {
        use crate::link::wire::Tap;
        let Some(_knock) = knock_on() else {
            return;
        };
        let (b_dir, a_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let alice = Identity::from_seed(&[0xb1; 32]);
        let bob = Arc::new(Identity::from_seed(&[0xb2; 32]));
        write_contacts(b_dir.path(), &[&alice]);
        let knock =
            crate::link_knock::for_dial(true, false, a_dir.path(), &alice, &bob.public_key_bytes())
                .expect("knock keys");
        let asked = raven_core::route_hints::rlx1_payload(raven_core::CAP_LINK_RRH1);
        let mut statics = Vec::new();
        for _ in 0..2 {
            let (client, mut listener) = tokio::io::duplex(1 << 18);
            let mut client = Tap::new(client);
            let (ear, bob_c) = (ear(b_dir.path(), &bob, HERE), bob.clone());
            let peer = tokio::spawn(async move {
                let (ed, mut t, ours, m3, dialer_static, knocked) =
                    responder_handshake(&mut listener, &bob_c, Some(&ear))
                        .await
                        .unwrap();
                write_cipher(&mut listener, &mut t, &ours).await.unwrap();
                (ed, m3, dialer_static, knocked)
            });
            let (_, remote_static, knocked) = initiator_session_pinned(
                &mut client,
                &alice,
                &bob.public_key_bytes(),
                &asked,
                None,
                None,
                Some(&knock),
            )
            .await
            .expect("a knocked link");
            let (ed, m3, dialer_static, heard) = peer.await.unwrap();
            assert_eq!(knocked, Some(true));
            assert_eq!(ed, alice.public_key_bytes());
            assert_eq!(heard, Knocked::Contact(alice.public_key_bytes()));
            assert_eq!(heard.showed(&ed), Some(true));
            assert_ne!(remote_static, noise_static_of(&bob));
            assert_ne!(dialer_static, noise_static_of(&alice));
            assert_eq!(
                raven_core::route_hints::rlx1_caps(&m3),
                raven_core::CAP_LINK_RRH1
            );
            let (sent, got) = client.lengths();
            assert!((64..=95).contains(&sent[0]), "m1 {sent:?}");
            assert!((112..=143).contains(&got[0]), "m2 {got:?}");
            assert!((64..=128).contains(&sent[1]), "m3 {sent:?}");
            statics.push(remote_static);
        }
        assert_ne!(statics[0], statics[1], "a static per connection");
    }

    /// P6.38: Alice knocks with the pair's seed at Bob, who lost his (his
    /// book holds the root alone). No proof, and with the knock in Bob's
    /// floor that is no impostor yet: `KNOCK_SEED_UNPROVED`, nothing noted,
    /// nothing more sent. The dial's fallback knocks with the pair's root on
    /// a new connection: Bob proves himself and the link comes up. The
    /// fallback has no fallback of its own.
    #[tokio::test]
    async fn a_seeded_knock_without_a_proof_falls_back_to_the_root() {
        use raven_core::pair_seed::{incoming, is_leader, outgoing, SeedEntry};
        let Some(_knock) = knock_on() else {
            return;
        };
        let (b_dir, a_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let alice = Identity::from_seed(&[0xb6; 32]);
        let bob = Arc::new(Identity::from_seed(&[0xb7; 32]));
        let (a_pub, b_pub) = (alice.public_key_bytes(), bob.public_key_bytes());
        write_contacts(b_dir.path(), &[&alice]);
        if is_leader(&a_pub, &b_pub) {
            outgoing(a_dir.path(), &a_pub, &b_pub, 1, || [0x38; 32]).unwrap();
        }
        incoming(
            a_dir.path(),
            &a_pub,
            &b_pub,
            Some(&SeedEntry::new(1, [0x38; 32], 1)),
            1,
        )
        .unwrap();
        let knock = crate::link_knock::for_dial(true, true, a_dir.path(), &alice, &b_pub)
            .expect("knock keys")
            .with_floor(true);
        assert!(knock.seeded());
        let root = knock.fallback().expect("the root's knock");
        assert!(!root.seeded() && root.fallback().is_none());
        let capture = crate::security::tests::Capture::start();
        /// One dial of `alice` with `k` at `bob`'s listener (book in
        /// `b_dir`): the dial's knock result and what the listener got.
        async fn run(
            k: &crate::link_knock::DialKnock,
            alice: &Identity,
            bob: &Arc<Identity>,
            b_dir: &Path,
        ) -> (
            Result<Option<bool>, String>,
            Result<([u8; 32], Knocked), String>,
        ) {
            let (mut client, mut listener) = tokio::io::duplex(1 << 18);
            let (ear, bob_c) = (ear(b_dir, bob, HERE), bob.clone());
            let peer = tokio::spawn(async move {
                let (ed, mut t, ours, _, _, knocked) =
                    responder_handshake(&mut listener, &bob_c, Some(&ear)).await?;
                write_cipher(&mut listener, &mut t, &ours).await?;
                Ok::<_, String>((ed, knocked))
            });
            let b_pub = bob.public_key_bytes();
            let got =
                initiator_session_pinned(&mut client, alice, &b_pub, &[], None, None, Some(k))
                    .await
                    .map(|(_, _, knocked)| knocked);
            drop(client);
            (got, peer.await.unwrap())
        }
        let (seeded, heard) = run(&knock, &alice, &bob, b_dir.path()).await;
        assert_eq!(
            seeded,
            Err(crate::link_knock::KNOCK_SEED_UNPROVED.to_string())
        );
        assert!(heard.is_err(), "no message 3 for the listener");
        if let Some(c) = &capture {
            assert!(c.events().is_empty(), "no impostor: {:?}", c.kinds());
        }
        let (fallback, heard) = run(root, &alice, &bob, b_dir.path()).await;
        assert_eq!(fallback, Ok(Some(true)), "the root's knock is proved");
        assert_eq!(heard.unwrap(), (a_pub, Knocked::Contact(a_pub)));
    }

    /// Alice (0xb6) holding a pair seed with Bob (0xb7), who lost his: her
    /// seeded knock at Bob, with the root's to fall back on, as her floor
    /// does (`floor`) or does not show the knock. Bob's profile in `b_dir`
    /// has Alice as a contact and no seed.
    fn seeded_alice_and_bob(
        a_dir: &Path,
        b_dir: &Path,
        floor: bool,
    ) -> (Identity, Arc<Identity>, crate::link_knock::DialKnock) {
        use raven_core::pair_seed::{incoming, is_leader, outgoing, SeedEntry};
        let alice = Identity::from_seed(&[0xb6; 32]);
        let bob = Arc::new(Identity::from_seed(&[0xb7; 32]));
        let (a_pub, b_pub) = (alice.public_key_bytes(), bob.public_key_bytes());
        write_contacts(b_dir, &[&alice]);
        if is_leader(&a_pub, &b_pub) {
            outgoing(a_dir, &a_pub, &b_pub, 1, || [0x38; 32]).unwrap();
        }
        incoming(
            a_dir,
            &a_pub,
            &b_pub,
            Some(&SeedEntry::new(1, [0x38; 32], 1)),
            1,
        )
        .unwrap();
        let knock = crate::link_knock::for_dial(true, true, a_dir, &alice, &b_pub)
            .expect("knock keys")
            .with_floor(floor);
        assert!(knock.seeded());
        (alice, bob, knock)
    }

    /// One dial of `alice` (with the M0 pin `pinned`) at `bob`'s LAN
    /// listener (profile `b_dir`, from the local network) through
    /// `link_knock::dial_attempts`, as `dial_lan_session` makes it: the
    /// knock result, what the listener heard last and how many connections
    /// were made.
    async fn dial_bob(
        knock: &crate::link_knock::DialKnock,
        alice: &Identity,
        bob: &Arc<Identity>,
        b_dir: &Path,
        pinned: Option<&[u8; 32]>,
    ) -> (Result<Option<bool>, String>, Result<Knocked, String>, u32) {
        let connections = std::sync::atomic::AtomicU32::new(0);
        let heard = std::sync::Mutex::new(Err(String::from("no connection")));
        let b_pub = bob.public_key_bytes();
        let got = crate::link_knock::dial_attempts(Some(knock), |k| {
            connections.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let (ear, bob_c) = (ear(b_dir, bob, HERE), bob.clone());
            let heard = &heard;
            async move {
                let (mut client, mut listener) = tokio::io::duplex(1 << 18);
                let peer = tokio::spawn(async move {
                    let (_, mut t, ours, _, _, knocked) =
                        responder_handshake(&mut listener, &bob_c, Some(&ear)).await?;
                    write_cipher(&mut listener, &mut t, &ours).await?;
                    Ok::<_, String>(knocked)
                });
                let got =
                    initiator_session_pinned(&mut client, alice, &b_pub, &[], pinned, None, k)
                        .await
                        .map(|(_, _, knocked)| knocked);
                drop(client);
                *heard.lock().unwrap() = peer.await.unwrap();
                got
            }
        })
        .await;
        let heard = heard.into_inner().unwrap();
        (got, heard, connections.into_inner())
    }

    /// Phase 6 review (traffic-2): Alice holds an M0 pin of Bob's derived
    /// static (every pair that linked before the knock does) and her floor
    /// shows his knock. Bob lost his seed and is in legacy mode, so her
    /// seeded knock gets his derived static and no proof, and the pin
    /// matches. That is no reason to go on without the knock: the seeded
    /// knock leaves it to the root's (`KNOCK_SEED_UNPROVED`), which Bob
    /// proves, so both ends show the knock to their floors (no false
    /// Suspicious downgrade). With a floor that lacks the knock the pin lets
    /// the link go on as before, on one connection.
    #[tokio::test]
    async fn a_seeded_knock_with_a_matching_pin_still_falls_back_to_the_root() {
        let Some(_knock) = knock_on() else {
            return;
        };
        let (b_dir, a_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let (alice, bob, knock) = seeded_alice_and_bob(a_dir.path(), b_dir.path(), true);
        let a_pub = alice.public_key_bytes();
        let pin = pin_for(&alice, &bob, &bob);
        let capture = crate::security::tests::Capture::start();
        let (mut client, mut listener) = tokio::io::duplex(1 << 18);
        let (ear_b, bob_c) = (ear(b_dir.path(), &bob, HERE), bob.clone());
        let peer = tokio::spawn(async move {
            responder_handshake(&mut listener, &bob_c, Some(&ear_b))
                .await
                .map(drop)
        });
        let once = initiator_session_pinned(
            &mut client,
            &alice,
            &bob.public_key_bytes(),
            &[],
            Some(&pin),
            None,
            Some(&knock),
        )
        .await
        .map(|(_, _, knocked)| knocked);
        drop(client);
        assert_eq!(
            once,
            Err(crate::link_knock::KNOCK_SEED_UNPROVED.to_string())
        );
        assert!(peer.await.unwrap().is_err(), "no message 3 for Bob");
        let (got, heard, connections) =
            dial_bob(&knock, &alice, &bob, b_dir.path(), Some(&pin)).await;
        assert_eq!(got, Ok(Some(true)), "the root's knock is proved");
        assert_eq!(heard, Ok(Knocked::Contact(a_pub)));
        assert_eq!(heard.unwrap().showed(&a_pub), Some(true));
        assert_eq!(connections, 2);
        if let Some(c) = &capture {
            assert!(c.events().is_empty(), "nothing noted: {:?}", c.kinds());
        }
        // Her floor lacks the knock: the pin lets the link go on, unknocked.
        let knock = knock.with_floor(false);
        let (got, heard, connections) =
            dial_bob(&knock, &alice, &bob, b_dir.path(), Some(&pin)).await;
        assert_eq!(got, Ok(Some(false)));
        assert_eq!(heard, Ok(Knocked::Stranger));
        assert_eq!(connections, 1);
    }

    /// Phase 6 review (traffic-6): Bob is silent to strangers and lost his
    /// seed, so Alice's seeded knock matches nothing there and the
    /// connection closes before message 2, every attempt. The dial knocks
    /// once more with the pair's root on a new connection, which Bob
    /// proves. A listener that closes every connection after message 1
    /// gets that one root knock too, and the dial ends with the hang-up's
    /// text.
    #[tokio::test]
    async fn a_silent_listener_without_the_seed_gets_the_roots_knock() {
        let Some(_knock) = knock_on() else {
            return;
        };
        let (b_dir, a_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let (alice, bob, knock) = seeded_alice_and_bob(a_dir.path(), b_dir.path(), true);
        let a_pub = alice.public_key_bytes();
        let mut policy = raven_core::node_policy::load_policy(b_dir.path());
        policy.security_silent_to_strangers = raven_core::node_policy::SilentMode::On;
        raven_core::node_policy::save_policy(b_dir.path(), &policy).unwrap();
        let (got, heard, connections) = dial_bob(&knock, &alice, &bob, b_dir.path(), None).await;
        assert_eq!(got, Ok(Some(true)), "the root's knock is proved");
        assert_eq!(heard, Ok(Knocked::Contact(a_pub)));
        assert_eq!(connections, 4, "three seeded attempts, then the root");
        // Every connection closed after message 1, whatever it carried.
        let connections = std::sync::atomic::AtomicU32::new(0);
        let got: Result<(), String> = crate::link_knock::dial_attempts(Some(&knock), |k| {
            connections.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let alice = &alice;
            async move {
                let (mut client, mut listener) = tokio::io::duplex(1 << 18);
                tokio::spawn(async move {
                    let _ = read_raw(&mut listener).await;
                });
                initiator_session_pinned(&mut client, alice, &[0xb7; 32], &[], None, None, k)
                    .await
                    .map(drop)
            }
        })
        .await;
        let err = got.unwrap_err();
        assert!(
            err.starts_with(netutil::PEER_CLOSED) && err.contains("3 attempts"),
            "{err}"
        );
        assert_eq!(connections.into_inner(), 4);
    }

    /// Phase 6 review (traffic-4): a security notice holds the knock on Bob
    /// (`FEATURE_HOLD` BROKEN on `feature/link-knock`) and has not reached
    /// Alice yet. Her floor shows Bob's knock and she holds no pin (they
    /// met with the knock), so a Bob that gave no proof would be an
    /// impostor to her (`SEC_ADDRESS_IMPOSTOR`, R5 forgets his address).
    /// Bob knocks no more, but his listener still proves itself: her dial
    /// goes on, knocked, and nothing is noted.
    #[tokio::test]
    async fn a_listener_under_a_knock_hold_still_proves_itself_to_a_contact() {
        use raven_core::advisory::{Entry, EntryKind, Severity};
        use raven_core::security_gate::{self, SecGate};
        use raven_core::suite_policy::{set_policy_for_this_thread, Policy};
        let Some(_knock) = knock_on() else {
            return;
        };
        security_gate::set_lab_for_this_thread(SecGate::Advisory, Some(true));
        if !security_gate::live(SecGate::Advisory) {
            security_gate::set_lab_for_this_thread(SecGate::Advisory, None);
            return;
        }
        let (b_dir, a_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let alice = Identity::from_seed(&[0xc4; 32]);
        let bob = Arc::new(Identity::from_seed(&[0xc5; 32]));
        let (a_pub, b_pub) = (alice.public_key_bytes(), bob.public_key_bytes());
        write_contacts(b_dir.path(), &[&alice]);
        // Alice's knock, as her own (unheld) node makes it.
        let dial = crate::link_knock::for_dial(true, false, a_dir.path(), &alice, &b_pub)
            .expect("knock keys")
            .with_floor(true);
        let hold = Entry {
            kind: EntryKind::FeatureHold,
            severity: Severity::Broken,
            target: raven_core::suite_registry::FEATURE_LINK_KNOCK.to_owned(),
            arg: Vec::new(),
            text_id: 0,
        };
        set_policy_for_this_thread(Some(Policy::of_entries(6, 0, &[hold], 0)));
        assert!(!crate::link_knock::live(), "Bob knocks no more");
        assert!(crate::link_knock::for_dial(
            crate::link_knock::live(),
            false,
            b_dir.path(),
            &bob,
            &a_pub
        )
        .is_none());
        let capture = crate::security::tests::Capture::start();
        let (mut dialer, mut listener) = tokio::io::duplex(1 << 18);
        let (ear, bob_c) = (ear(b_dir.path(), &bob, HERE), bob.clone());
        let peer = tokio::spawn(async move {
            let (ed, mut t, ours, _, _, knocked) =
                responder_handshake(&mut listener, &bob_c, Some(&ear)).await?;
            write_cipher(&mut listener, &mut t, &ours).await?;
            Ok::<_, String>((ed, knocked))
        });
        let got =
            initiator_session_pinned(&mut dialer, &alice, &b_pub, &[], None, HERE, Some(&dial))
                .await
                .map(|(_, _, knocked)| knocked);
        let heard = peer.await.unwrap();
        let events = capture.as_ref().map(|c| c.kinds());
        drop(capture);
        set_policy_for_this_thread(None);
        security_gate::set_lab_for_this_thread(SecGate::Advisory, None);
        assert_eq!(got, Ok(Some(true)));
        assert_eq!(heard, Ok((a_pub, Knocked::Contact(a_pub))));
        if let Some(events) = events {
            assert!(events.is_empty(), "no impostor: {events:?}");
        }
    }

    /// RLK1: a dialer that does not knock (a stranger's probe, or any older
    /// build) sees Bob's derived static in legacy mode (a contact without
    /// the knock in its floor), a fresh static per connection in strict mode
    /// (here: nobody in the book to wait for), and nothing in silent mode:
    /// the connection closes before message 2.
    #[tokio::test]
    async fn an_unknocked_dialer_sees_the_derived_static_a_fresh_one_or_nothing() {
        let Some(_knock) = knock_on() else {
            return;
        };
        let bob = Arc::new(Identity::from_seed(&[0xb3; 32]));
        let stranger = Identity::from_seed(&[0xb4; 32]);
        let friend = Identity::from_seed(&[0xb5; 32]);
        let legacy = tempfile::tempdir().unwrap();
        write_contacts(legacy.path(), &[&friend]);
        let seen = unknocked_probe(ear(legacy.path(), &bob, HERE), bob.clone(), &stranger).await;
        assert_eq!(seen, Ok(noise_static_of(&bob)), "legacy");
        let strict = tempfile::tempdir().unwrap();
        let mut probes = Vec::new();
        for _ in 0..2 {
            let seen = unknocked_probe(ear(strict.path(), &bob, HERE), bob.clone(), &stranger);
            probes.push(seen.await.expect("strict still answers"));
        }
        assert_ne!(probes[0], probes[1]);
        assert!(!probes.contains(&noise_static_of(&bob)));
        let silent = tempfile::tempdir().unwrap();
        write_contacts(silent.path(), &[&friend]);
        let mut policy = raven_core::node_policy::load_policy(silent.path());
        policy.security_silent_to_strangers = raven_core::node_policy::SilentMode::On;
        raven_core::node_policy::save_policy(silent.path(), &policy).unwrap();
        let seen = unknocked_probe(ear(silent.path(), &bob, HERE), bob.clone(), &stranger).await;
        assert_eq!(seen, Err(crate::link_knock::KNOCK_SILENT.to_string()));
    }

    /// Phase 6 review (traffic-1): Alice is Bob's contact but not a verified
    /// one. Bob's LAN contact gate takes her from the local network only
    /// (`link_admission`), so his knock book tries her there only: from
    /// 192.168.1.20 her knock gets the proof; from 100.64.0.1 (carrier-grade
    /// NAT, a VPN) and from an unknown source it gets a stranger's answer
    /// (no proof; in silent mode no message 2), never
    /// the proof that would tell her whose address this is before the gate
    /// refuses her. A verified contact gets the proof from anywhere.
    #[tokio::test]
    async fn an_unverified_contact_beyond_the_local_network_gets_no_proof() {
        let Some(_knock) = knock_on() else {
            return;
        };
        let alice = Identity::from_seed(&[0xc1; 32]);
        let carol = Identity::from_seed(&[0xc2; 32]);
        let bob = Arc::new(Identity::from_seed(&[0xc3; 32]));
        let b_dir = tempfile::tempdir().unwrap();
        std::fs::write(
            b_dir.path().join("contacts.json"),
            format!(
                r#"[{{"pub_hex":"{}"}},{{"pub_hex":"{}","pinned":true}}]"#,
                hex::encode(alice.public_key_bytes()),
                hex::encode(carol.public_key_bytes())
            ),
        )
        .unwrap();
        /// `dialer`'s knock at Bob's listener from `source`: whether message
        /// 2 carried the proof (`Err`: none came), and what Bob heard.
        async fn knock_from(
            dialer: &Identity,
            bob: &Arc<Identity>,
            b_dir: &Path,
            source: Option<std::net::IpAddr>,
        ) -> (Result<bool, String>, Result<Knocked, String>) {
            let a_dir = tempfile::tempdir().unwrap();
            let k = crate::link_knock::for_dial(
                true,
                false,
                a_dir.path(),
                dialer,
                &bob.public_key_bytes(),
            )
            .expect("knock keys");
            let (mut client, mut listener) = tokio::io::duplex(1 << 18);
            let (ear, bob_c) = (ear(b_dir, bob, source), bob.clone());
            let peer = tokio::spawn(async move {
                responder_handshake(&mut listener, &bob_c, Some(&ear))
                    .await
                    .map(|(_, _, _, _, _, knocked)| knocked)
            });
            let mut dial = k.begin(dialer, None).unwrap();
            write_raw(&mut client, dial.m1()).await.unwrap();
            let proof = match read_raw(&mut client).await {
                Ok(m2) => Ok(k.read_m2(&mut dial, &m2).unwrap().1),
                Err(e) => Err(e),
            };
            drop(client);
            (proof, peer.await.unwrap())
        }
        let local = Some(std::net::IpAddr::from([192, 168, 1, 20]));
        let cgnat = Some(std::net::IpAddr::from([100, 64, 0, 1]));
        let (proof, heard) = knock_from(&alice, &bob, b_dir.path(), local).await;
        assert_eq!(proof, Ok(true), "from the local network");
        assert!(heard.is_err(), "no message 3 came");
        for source in [cgnat, None] {
            let (proof, heard) = knock_from(&alice, &bob, b_dir.path(), source).await;
            assert_eq!(proof, Ok(false), "{source:?}: a stranger's answer");
            assert!(heard.is_err());
            let (proof, _) = knock_from(&carol, &bob, b_dir.path(), source).await;
            assert_eq!(proof, Ok(true), "{source:?}: a verified contact");
        }
        // Silent to strangers: from beyond the local network an unverified
        // contact's knock gets no message 2 at all, as a stranger's.
        let mut policy = raven_core::node_policy::load_policy(b_dir.path());
        policy.security_silent_to_strangers = raven_core::node_policy::SilentMode::On;
        raven_core::node_policy::save_policy(b_dir.path(), &policy).unwrap();
        let (proof, heard) = knock_from(&alice, &bob, b_dir.path(), cgnat).await;
        assert!(proof.is_err());
        assert_eq!(heard, Err(crate::link_knock::KNOCK_SILENT.to_string()));
        let (proof, _) = knock_from(&alice, &bob, b_dir.path(), local).await;
        assert_eq!(proof, Ok(true));
    }

    /// RLK1: a knocking dialer at a listener without the knock (derived
    /// static, empty message 2 payload). Without a pin and without the knock
    /// in the contact's floor it goes on as today (its derived static); a
    /// pin that matches lets it go on whatever the floor says; with the
    /// floor and no pin it stops after message 2 (`SEC_ADDRESS_IMPOSTOR`, the
    /// M0 text): the listener gets neither message 3 nor the bind; another
    /// key than the pinned one stops it too.
    #[tokio::test]
    async fn a_knocking_dialer_at_a_listener_without_the_knock() {
        let Some(_knock) = knock_on() else {
            return;
        };
        let capture = crate::security::tests::Capture::start();
        let a_dir = tempfile::tempdir().unwrap();
        let alice = Identity::from_seed(&[0xb6; 32]);
        let bob = Identity::from_seed(&[0xb7; 32]);
        let bob_pub = bob.public_key_bytes();
        let pin = pin_for(&alice, &bob, &bob);
        let other_pin = pin_for(&alice, &bob, &alice);
        let cases = [
            (false, None, true),
            (true, Some(pin), true),
            (true, None, false),
            (false, Some(other_pin), false),
        ];
        for (floor, pinned, goes_on) in cases {
            let knock = crate::link_knock::for_dial(true, false, a_dir.path(), &alice, &bob_pub)
                .unwrap()
                .with_floor(floor);
            let case = format!("floor {floor}, pin {}", pinned.is_some());
            let (mut dialer, mut listener) = tokio::io::duplex(1 << 18);
            let old = Identity::from_seed(&[0xb7; 32]);
            if goes_on {
                // An older build's listener: the link completes as today.
                let peer = tokio::spawn(async move {
                    responder_session(&mut listener, &old)
                        .await
                        .map(|(ed, _)| ed)
                });
                let (_, remote_static, knocked) = initiator_session_pinned(
                    &mut dialer,
                    &alice,
                    &bob_pub,
                    &[],
                    pinned.as_ref(),
                    None,
                    Some(&knock),
                )
                .await
                .unwrap_or_else(|e| panic!("{case}: {e}"));
                assert_eq!(remote_static, noise_static_of(&bob), "{case}");
                assert_eq!(knocked, Some(false), "{case}");
                assert_eq!(peer.await.unwrap(), Ok(alice.public_key_bytes()), "{case}");
            } else {
                let peer = tokio::spawn(async move { scripted_responder(listener, &old).await });
                let err = initiator_session_pinned(
                    &mut dialer,
                    &alice,
                    &bob_pub,
                    &[],
                    pinned.as_ref(),
                    None,
                    Some(&knock),
                )
                .await
                .err();
                assert_eq!(err.as_deref(), Some(NOISE_PIN_MISMATCH), "{case}");
                drop(dialer);
                assert!(
                    peer.await.unwrap().is_empty(),
                    "{case}: nothing after message 2"
                );
            }
        }
        if let Some(capture) = capture {
            use raven_core::security_events::{Attribution, SecKind, Via};
            let impostor = (
                SecKind::AddressImpostor,
                Attribution::Contact { peer: bob_pub },
                Via::Dial(raven_core::OutboxCarrier::Lan),
            );
            assert_eq!(capture.kinds(), [impostor, impostor]);
        }
    }

    /// RLK1: Alice's message 1 recorded and sent again is a replay: one
    /// `SEC_KNOCK_REPLAY` about the source it came from, and a message 2
    /// that looks like a stranger's (Bob's derived static in legacy mode, a
    /// payload of the same lengths as a proof). The first one was matched
    /// and proved. Alice is a verified contact: from a source beyond the
    /// local network Bob's knock book holds verified contacts alone (Phase 6
    /// review traffic-1).
    #[tokio::test]
    async fn a_replayed_knock_is_noted_and_answered_like_a_stranger() {
        use raven_core::security_events::{Attribution, SecKind, SourceKey, Via};
        let Some(_knock) = knock_on() else {
            return;
        };
        let Some(capture) = crate::security::tests::Capture::start() else {
            return;
        };
        let (b_dir, a_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let alice = Identity::from_seed(&[0xb8; 32]);
        let bob = Arc::new(Identity::from_seed(&[0xb9; 32]));
        std::fs::write(
            b_dir.path().join("contacts.json"),
            format!(
                r#"[{{"pub_hex":"{}","pinned":true}}]"#,
                hex::encode(alice.public_key_bytes())
            ),
        )
        .unwrap();
        let knock =
            crate::link_knock::for_dial(true, false, a_dir.path(), &alice, &bob.public_key_bytes())
                .unwrap();
        let mut dial = knock.begin(&alice, None).unwrap();
        let m1 = dial.m1().to_vec();
        let from: std::net::IpAddr = "192.0.2.77".parse().unwrap();
        let mut answers = Vec::new();
        for _ in 0..2 {
            let (mut client, mut listener) = tokio::io::duplex(1 << 18);
            let (ear, bob_c) = (ear(b_dir.path(), &bob, Some(from)), bob.clone());
            let peer = tokio::spawn(async move {
                let _ = responder_handshake(&mut listener, &bob_c, Some(&ear)).await;
            });
            write_raw(&mut client, &m1).await.unwrap();
            answers.push(read_raw(&mut client).await.unwrap());
            drop(client);
            peer.await.unwrap();
        }
        assert!(answers.iter().all(|m2| (112..=143).contains(&m2.len())));
        let (remote, proof) = knock.read_m2(&mut dial, &answers[0]).unwrap();
        assert!(
            proof && remote != noise_static_of(&bob),
            "the first one matched"
        );
        assert_eq!(
            capture.kinds(),
            [(
                SecKind::KnockReplay,
                Attribution::Network {
                    source: SourceKey::of(from)
                },
                Via::DirectLink(raven_core::OutboxCarrier::Lan)
            )]
        );
    }

    /// RLK1 with M0 between two real nodes: a knocked link pins nothing at
    /// either end (both statics were for that link only), and a link
    /// without the knock afterwards pins as before, so pins stay the
    /// fallback for listeners without the knock.
    #[tokio::test]
    async fn a_knocked_link_pins_nothing_and_an_unknocked_one_still_does() {
        if !file_backends() {
            return;
        }
        let _lan = lan_switch_untouched();
        let (a_dir, b_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let alice = dialer_profile(a_dir.path());
        let bob = Arc::new(Identity::from_seed(&[0xba; 32]));
        write_book(b_dir.path(), &[(&alice, true)]);
        write_book(a_dir.path(), &[(&bob, true)]);
        {
            let Some(_knock) = knock_on() else {
                return;
            };
            let (addr, server) = serve_one(b_dir.path(), &bob, PINS_ON).await;
            full_dial(a_dir.path(), &addr, &bob.public_key_bytes(), &[], PINS_ON)
                .await
                .unwrap();
            listener_result(server).await.unwrap();
        }
        let pin = |dir: &Path, peer: &Identity| {
            raven_core::lan_noise_pin::load_pin(dir, &peer.public_key_bytes())
        };
        assert_eq!(pin(a_dir.path(), &bob), Ok(None));
        assert_eq!(pin(b_dir.path(), &alice), Ok(None));
        let _off = crate::link_knock::KnockForTest::set(false);
        let (addr, server) = serve_one(b_dir.path(), &bob, PINS_ON).await;
        full_dial(a_dir.path(), &addr, &bob.public_key_bytes(), &[], PINS_ON)
            .await
            .unwrap();
        listener_result(server).await.unwrap();
        assert_eq!(
            pin(a_dir.path(), &bob),
            Ok(Some(pin_for(&alice, &bob, &bob)))
        );
        assert_eq!(
            pin(b_dir.path(), &alice),
            Ok(Some(pin_for(&bob, &alice, &alice)))
        );
    }

    /// RUP1 on a LAN link (Phase 6b P6.49, spec §2): with the update
    /// exchange active, the listener sends its HAVE after RLB1 only to a
    /// pinned contact whose message 3 offered bit 10, takes the dialer's and
    /// answers its requests. A dialer without bit 10 (an older build) gets no
    /// RUP1 frame, and neither does any dialer while the gate is shut: the
    /// frames after RLB1 are exactly what they were.
    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn the_listener_sends_its_have_only_to_a_pinned_dialer_that_offered_bit_10() {
        use raven_core::update_exchange::{self as rup1, ErrorCode, Have, Rup1Msg};
        if !lab_backend_available() {
            return;
        }
        let _build =
            crate::update_exchange::BuildForTest::set(crate::update_exchange::test_build());
        // The last two cases knock (RLK1, P6.35): the dialer's padded
        // message 3 still offers bit 10, and the HAVE rides the knocked link.
        for (gate, bit10, pinned, have, knocks) in [
            (true, true, true, true, false),
            (true, false, true, false, false),
            (true, true, false, false, false),
            (false, true, true, false, false),
            (true, true, true, true, true),
            (false, true, true, false, true),
        ] {
            crate::update_exchange::gates_for_test(Some(gate));
            let _knock = crate::link_knock::KnockForTest::set(knocks);
            if knocks && !crate::link_knock::live() {
                continue;
            }
            let case = format!("gate {gate}, bit 10 {bit10}, pinned {pinned}, knocks {knocks}");
            let resp_dir = tempfile::tempdir().unwrap();
            let init_dir = tempfile::tempdir().unwrap();
            let responder = Arc::new(Identity::from_seed(&[0x91; 32]));
            let initiator = Identity::from_seed(&[0x92; 32]);
            std::fs::write(
                resp_dir.path().join("contacts.json"),
                format!(
                    r#"[{{"pub_hex":"{}","pinned":{pinned}}}]"#,
                    hex::encode(initiator.public_key_bytes())
                ),
            )
            .unwrap();
            let (mut client, server_side) = tokio::io::duplex(1 << 18);
            let (data_dir, resp) = (resp_dir.path().to_path_buf(), responder.clone());
            let server = tokio::spawn(async move {
                let mut slot = test_slot();
                handle_inbound(
                    data_dir,
                    resp,
                    server_side,
                    PRODUCTION_LIMITS,
                    &mut slot,
                    LOOPBACK_DIALER,
                )
                .await
            });
            let m3 = crate::hints::lan_m3_payload_with(false, false, bit10, true);
            let knock = knocks.then(|| {
                crate::link_knock::for_dial(
                    true,
                    false,
                    init_dir.path(),
                    &initiator,
                    &responder.public_key_bytes(),
                )
                .expect("knock keys")
            });
            let (mut t, _, knocked) = initiator_session_pinned(
                &mut client,
                &initiator,
                &responder.public_key_bytes(),
                &m3,
                None,
                None,
                knock.as_ref(),
            )
            .await
            .expect("Noise XX + bind");
            assert_eq!(
                knocked,
                knocks.then_some(true),
                "{case}: the listener proved the knock"
            );
            let offer = encode_local_offer(init_dir.path(), &initiator).unwrap();
            write_cipher(&mut client, &mut t, &offer).await.unwrap();
            let theirs = read_cipher(&mut client, &mut t).await.unwrap();
            assert!(parse_peer_offer(&theirs).is_ok(), "{case}");
            let next = tokio::time::timeout(
                Duration::from_millis(1_500),
                read_cipher(&mut client, &mut t),
            )
            .await;
            if have {
                let frame = next.expect("a HAVE").unwrap();
                assert_eq!(
                    rup1::decode(&frame),
                    Ok((rup1::NO_REQ_ID, Rup1Msg::Have(Have::nothing()))),
                    "{case}"
                );
                // Our HAVE, then a request: answered (no log here).
                let ours = rup1::encode(&rup1::NO_REQ_ID, &Rup1Msg::Have(Have::nothing())).unwrap();
                write_cipher(&mut client, &mut t, &ours).await.unwrap();
                let ask = rup1::encode(&[1, 2, 3, 4], &Rup1Msg::GetLog).unwrap();
                write_cipher(&mut client, &mut t, &ask).await.unwrap();
                let reply = read_cipher(&mut client, &mut t).await.unwrap();
                assert_eq!(
                    rup1::decode(&reply),
                    Ok(([1, 2, 3, 4], Rup1Msg::Error(ErrorCode::NotFound))),
                    "{case}"
                );
                assert!(crate::update_exchange::have_seen_for_test(
                    &initiator.public_key_bytes()
                ));
            } else {
                assert!(next.is_err(), "{case}: nothing after RLB1");
            }
            drop(client);
            let _ = tokio::time::timeout(Duration::from_secs(10), server)
                .await
                .expect("the listener ends");
        }
        crate::update_exchange::gates_for_test(None);
    }
}
