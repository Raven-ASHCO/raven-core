//! Raven local node — TCP framed RavenEnvelopeV1, persistent queue, ACK/dedup.
//! Bridge V1: opaque cross-transport forward (see `bridge_run`).
//! Frame: u32 BE length || envelope bytes. Never logs private keys or plaintext.

/// Every line raven-node writes to its log starts with its UTC time
/// ([`netutil::log_line`]): a failed delivery has to be matched to a
/// friend's report (E1). It shadows the standard `eprintln!` in every module
/// of this crate.
macro_rules! eprintln {
    () => {
        crate::netutil::log_line(format_args!(""))
    };
    ($($arg:tt)*) => {
        crate::netutil::log_line(format_args!($($arg)*))
    };
}

mod app_channel;
mod arrivals;
mod at_rest_boot;
mod autoreach;
mod bridge_run;
mod clock_notes;
mod custody;
mod delivery_paths;
mod friend_relay;
mod hints;
mod internet_direct;
#[cfg(any(unix, windows))]
mod ipc_server;
#[cfg(any(unix, windows))]
mod lan_beacon;
mod lan_direct;
#[cfg(any(unix, windows))]
mod lan_ifaces;
#[cfg(any(unix, windows))]
mod lan_meeting;
mod learning;
mod letters;
mod link;
mod link_knock;
mod lock;
mod nearby;
#[cfg(any(unix, windows))]
mod netwatch;
mod onion;
mod outbox;
mod p2p;
mod pair_seed;
mod proxy;
mod relay;
mod relay_probe;
mod renewal;
mod security;
mod update_exchange;

#[cfg(any(unix, windows))]
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
#[cfg(any(unix, windows))]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use rand::RngCore;
#[cfg(feature = "unsafe-demo-crypto")]
use raven_core::ack::{Ack, STATUS_DELIVERED};
use raven_core::clock::now_ms;
use raven_core::envelope::{EnvType, Envelope};
use raven_core::forward_queue::ForwardQueue;
use raven_core::identity::Identity;
use raven_core::node_policy::{load_policy, BridgeStatusSnapshot};
use raven_core::queue::{DeliveryState, OutgoingQueue, QueueItem};
#[cfg(feature = "unsafe-demo-crypto")]
use raven_core::routing_tag;
#[cfg(not(feature = "unsafe-demo-crypto"))]
use raven_core::seal::UNSAFE_INTERIM_DISABLED;
use raven_core::seal::{classify_sealed_body, rvna1_wire_plausible, SealClass};
#[cfg(feature = "unsafe-demo-crypto")]
use raven_core::seal::{derive_pairwise_key, seal_message, unseal_message};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Semaphore};
use tokio::task::JoinHandle;

const MAX_FRAME_BYTES: usize = 1024 * 1024;
const MAX_CONCURRENT_CONNECTION_HANDLERS: usize = 64;

#[derive(Clone, Copy, Debug)]
struct ConnectionLimits {
    /// Maximum wait for the next frame header. This also bounds idle peers.
    idle_timeout: Duration,
    /// Hard wall-clock budget from the start of a frame through its payload.
    frame_timeout: Duration,
    /// A peer that stops reading cannot retain a handler indefinitely.
    write_timeout: Duration,
    /// Hard lifetime for one TCP handler, including all frames and replies.
    lifetime: Duration,
}

const DEFAULT_CONNECTION_LIMITS: ConnectionLimits = ConnectionLimits {
    idle_timeout: Duration::from_secs(10),
    frame_timeout: Duration::from_secs(30),
    write_timeout: Duration::from_secs(30),
    lifetime: Duration::from_secs(120),
};

/// Longest `--timeout-secs` honoured (also keeps `Instant + Duration` from
/// overflowing on absurd values).
const MAX_RUN_SECS: u64 = 365 * 24 * 60 * 60;

/// Limits for a connection *we* dialed (`run --peer`): it has to survive for as
/// long as the user asked to wait, not the 10 s idle bound that protects the
/// accept side from slow-loris peers. The bridge keeps its side open for 600 s,
/// so a dialed node that stays connected is already supported.
fn client_limits(timeout_secs: u64) -> ConnectionLimits {
    let budget =
        Duration::from_secs(timeout_secs.min(MAX_RUN_SECS)).saturating_add(Duration::from_secs(5));
    ConnectionLimits {
        idle_timeout: budget,
        // The header wait is also capped by this (see read_frame_with_limits).
        frame_timeout: budget,
        write_timeout: DEFAULT_CONNECTION_LIMITS.write_timeout,
        lifetime: budget,
    }
}

/// Resolve and connect to `--peer` (an IP or a name) within a bounded time, or
/// print the reason and exit 1: a dead peer is an error, never a hang or panic.
async fn dial_peer_or_exit(peer: &str, timeout_secs: u64) -> (TcpStream, SocketAddr) {
    let per_addr = Duration::from_secs(timeout_secs.clamp(1, 10));
    netutil::connect_dial(peer, per_addr, per_addr * 2)
        .await
        .unwrap_or_else(|e| {
            eprintln!("connect: {e}");
            std::process::exit(1);
        })
}

/// `forward_queue.sqlite` counts for `status`. A profile without the file
/// reports 0/0 *without creating it*: `ForwardQueue::open` creates the file,
/// and one that exists before the identity breaks the first-install proof
/// (`require_proven_first_install`). Real open/count failures are errors, not
/// an empty queue.
fn forward_queue_counts(data_dir: &Path) -> Result<(usize, usize), String> {
    let path = bridge_run::forward_queue_path(data_dir);
    match path.try_exists() {
        Ok(true) => {}
        Ok(false) => return Ok((0, 0)),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    }
    let queue = ForwardQueue::open(&path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let pending = queue
        .count_pending()
        .map_err(|e| format!("count pending: {e}"))?;
    let total = queue.count_all().map_err(|e| format!("count total: {e}"))?;
    Ok((pending, total))
}

/// Accept errors are per-connection (ECONNABORTED, a pipe client that went
/// away) or resource pressure (EMFILE, ENFILE, ENOBUFS, ENOMEM). None of them
/// may terminate a listener — and with it the whole `service` process.
pub(crate) const ACCEPT_BACKOFF_MIN: Duration = Duration::from_millis(50);
pub(crate) const ACCEPT_BACKOFF_MAX: Duration = Duration::from_secs(1);

/// Delay before the next accept after `e`: zero for errors that belonged to a
/// single peer, exponential (capped) for resource exhaustion so in-flight
/// handlers can release descriptors.
pub(crate) fn accept_error_delay(e: &std::io::Error, previous: Duration) -> Duration {
    use std::io::ErrorKind;
    match e.kind() {
        ErrorKind::ConnectionAborted
        | ErrorKind::ConnectionReset
        | ErrorKind::ConnectionRefused
        | ErrorKind::Interrupted
        | ErrorKind::WouldBlock => Duration::ZERO,
        _ => (previous * 2).clamp(ACCEPT_BACKOFF_MIN, ACCEPT_BACKOFF_MAX),
    }
}

/// Run `accept` until it yields a connection. Errors are logged and backed off,
/// never returned: a listener only stops when its task is cancelled.
pub(crate) async fn accept_retrying<T, F, Fut>(what: &str, mut accept: F) -> T
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = std::io::Result<T>>,
{
    let mut delay = Duration::ZERO;
    loop {
        match accept().await {
            Ok(conn) => return conn,
            Err(e) => {
                delay = accept_error_delay(&e, delay);
                // Peer-caused errors (zero delay) are not logged: remote
                // peers must not get a log-amplification channel.
                if !delay.is_zero() {
                    eprintln!(
                        "{what}: accept error: {e} (retry in {}ms)",
                        delay.as_millis()
                    );
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }
}

/// Transport plumbing shared by the LAN-direct and internet-direct dialers and
/// listeners, so the two carriers cannot drift apart again.
pub(crate) mod netutil {
    use std::collections::BTreeMap;
    use std::convert::Infallible;
    use std::future::Future;
    use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use raven_core::envelope::{EnvType, Envelope};
    use raven_core::lan_noise::{transport_decrypt, LanNoiseError, NoiseTransport};
    use raven_core::outbox::OutboxCarrier;
    use raven_core::pair_init_lan_oob::{classify_packed_envelope, PairInitOobClassify};
    use raven_core::MAX_IPC_FRAME;
    use tokio::net::TcpStream;
    use tokio::sync::Notify;

    // ── Dialing ──────────────────────────────────────────────────────────

    /// One TCP connect attempt (one resolved address).
    pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
    /// All connect attempts of one dial together.
    pub(crate) const CONNECT_BUDGET: Duration = Duration::from_secs(20);
    /// Name resolution; mDNS `.local` lookups can be slow.
    const RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);
    /// Further candidates are never tried.
    const MAX_DIAL_ADDRS: usize = 8;

    // ── Supervision ──────────────────────────────────────────────────────

    /// First delay before a failed transport step is retried; doubles up to the cap.
    pub(crate) const RESTART_BACKOFF_MIN: Duration = Duration::from_secs(1);
    pub(crate) const RESTART_BACKOFF_MAX: Duration = Duration::from_secs(30);
    /// An attempt that stayed up this long resets the backoff.
    pub(crate) const RESTART_STABLE: Duration = Duration::from_secs(60);

    /// Right after an unlock a failed start-up step is tried again after
    /// this, with no line ([`retry_until_ok`]).
    pub(crate) const UNLOCK_RETRY: Duration = Duration::from_millis(200);

    /// Retry `op` until it succeeds, logging each failure (`<name> failed: …`,
    /// which the lab scripts grep for) and backing off up to
    /// [`RESTART_BACKOFF_MAX`]. A transport uses this for each *step* of its
    /// start-up (preflight, bind) so a failed bind retries only the bind:
    /// repeating the heavy preflight would keep re-taking the data-dir locks
    /// that `ash` sends need. In the seconds after an unlock
    /// ([`crate::lock::settling`]) a failure is tried again after
    /// [`UNLOCK_RETRY`] instead, quietly: one that still fails after them is
    /// logged as any other.
    pub(crate) async fn retry_until_ok<T, F, Fut>(name: &str, op: F) -> T
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<T, String>>,
    {
        retry_until_ok_as(name, op, crate::lock::settling, |line| eprintln!("{line}")).await
    }

    /// [`retry_until_ok`] with the unlock window (`settling`) and the log
    /// (`say`) passed in.
    async fn retry_until_ok_as<T, F, Fut>(
        name: &str,
        mut op: F,
        settling: impl Fn() -> bool,
        mut say: impl FnMut(String),
    ) -> T
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<T, String>>,
    {
        let mut backoff = RESTART_BACKOFF_MIN;
        loop {
            match op().await {
                Ok(v) => return v,
                Err(_) if settling() => tokio::time::sleep(UNLOCK_RETRY).await,
                Err(e) => {
                    say(format!("{name} failed: {e}"));
                    say(format!(
                        "{name}: unavailable; IPC and the other transports keep running; \
                         retrying in {}s",
                        backoff.as_secs()
                    ));
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(RESTART_BACKOFF_MAX);
                }
            }
        }
    }

    /// One pass over the profile's durable state at a time in this process,
    /// held for the whole pass on its blocking thread: the transports'
    /// preflights (LAN, Internet, nearby, p2p) and the expiry prune. At
    /// service start and after an unlock they all start at once, and each
    /// reads, rewrites and deletes the same session, stage, prekey and chat
    /// files; on Windows a file that another pass is replacing or deleting
    /// at that moment answers "Access is denied" (os error 5), where Unix
    /// lets both go on (E1: the LAN listener's first try after an unlock).
    pub(crate) fn durable_pass() -> std::sync::MutexGuard<'static, ()> {
        static PASS: Mutex<()> = Mutex::new(());
        PASS.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// A start-up step that runs this long without finishing is announced in
    /// the log (once) while it keeps running.
    pub(crate) const SLOW_STEP_NOTICE: Duration = Duration::from_secs(15);

    /// Await `step`. If it is still running after `after`, call `on_slow` once
    /// and keep waiting. The listener preflight reads the OS keystore, which
    /// can block for as long as an access prompt goes unanswered; without this
    /// the service log stays silent and the daemon looks dead.
    pub(crate) async fn with_slow_notice_then<T>(
        after: Duration,
        step: impl Future<Output = T>,
        on_slow: impl FnOnce(),
    ) -> T {
        tokio::pin!(step);
        tokio::select! {
            out = &mut step => out,
            () = tokio::time::sleep(after) => {
                on_slow();
                step.await
            }
        }
    }

    /// [`with_slow_notice_then`] that writes the standard log line for the
    /// start-up step `what` of transport `name`.
    pub(crate) async fn with_slow_notice<T>(
        name: &str,
        what: &str,
        step: impl Future<Output = T>,
    ) -> T {
        with_slow_notice_then(SLOW_STEP_NOTICE, step, || {
            eprintln!(
                "{name}: {what} is taking longer than {}s and is still running (if the OS \
                 keystore is asking for access, answer its prompt)",
                SLOW_STEP_NOTICE.as_secs()
            );
        })
        .await
    }

    /// What every "the other side hung up" I/O error is reported as: a clean
    /// EOF, a reset, an abort or a broken pipe.
    pub(crate) const PEER_CLOSED: &str = "peer closed the connection";

    /// The dialer's view of a contact-gated responder's refusal: the link closed
    /// after our signed bind/hello and before the peer identified itself. The
    /// responder sends nothing that names it or says why. Never retried: a
    /// refused dialer that repeats only repeats the refusal.
    pub(crate) const LINK_NOT_ACCEPTED: &str = "LINK_NOT_ACCEPTED: the peer closed the \
        connection after our signed hello, before identifying itself: it does not accept this \
        node (this identity is not one of its contacts, or it is blocked), or it is overloaded";

    /// A Noise transport frame whose tag did not verify on an established
    /// link (Phase 6b S1): the text of `LanNoiseError::Transport`, so every
    /// log line and error reads as before, and a caller can match it exactly
    /// (`crate::security`).
    pub(crate) use raven_core::security_events::LINK_TAG_FAILED;

    /// Open one Noise transport frame of a link: a tag that does not verify
    /// is [`LINK_TAG_FAILED`].
    pub(crate) fn decrypt(transport: &mut NoiseTransport, ct: &[u8]) -> Result<Vec<u8>, String> {
        transport_decrypt(transport, ct).map_err(|e| match e {
            LanNoiseError::Transport => LINK_TAG_FAILED.to_string(),
            other => other.to_string(),
        })
    }

    /// Map a hang-up while waiting for the peer's bind/hello to [`LINK_NOT_ACCEPTED`].
    pub(crate) fn closed_before_peer_identity(e: String) -> String {
        if e == PEER_CLOSED {
            LINK_NOT_ACCEPTED.to_string()
        } else {
            e
        }
    }

    pub(crate) fn io_error_text(e: &std::io::Error) -> String {
        use std::io::ErrorKind;
        match e.kind() {
            ErrorKind::UnexpectedEof
            | ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::BrokenPipe => PEER_CLOSED.to_string(),
            _ => e.to_string(),
        }
    }

    /// Attempts at connect + Noise handshake against a peer that hangs up
    /// during it.
    const HANDSHAKE_ATTEMPTS: u32 = 3;

    fn retry_delay() -> Duration {
        use rand::Rng;
        Duration::from_millis(rand::thread_rng().gen_range(100..300))
    }

    /// A listener over its connection cap accepts and immediately drops
    /// the socket, so a burst of dials from one host sees the hang-up in the
    /// middle of the handshake. Nothing but handshake bytes has been sent
    /// then, so retrying (after a short random delay) is always safe. Any other
    /// error, and a hang-up after the last attempt, is returned as is.
    pub(crate) async fn with_handshake_retries<T, F, Fut>(mut attempt: F) -> Result<T, String>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<T, String>>,
    {
        let mut n = 1;
        loop {
            match attempt().await {
                Err(e) if e == PEER_CLOSED && n < HANDSHAKE_ATTEMPTS => {
                    n += 1;
                    tokio::time::sleep(retry_delay()).await;
                }
                Err(e) if e == PEER_CLOSED => {
                    return Err(format!(
                        "{PEER_CLOSED} during the handshake ({n} attempts); the peer may be at \
                         its connection limit or may not be a RAVEN node"
                    ));
                }
                other => return other,
            }
        }
    }

    fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
        m.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// `host:port` / `[v6]:port` into the host (brackets removed) and port.
    fn split_host_port(target: &str) -> Result<(&str, u16), String> {
        let (host, port) = target
            .rsplit_once(':')
            .ok_or_else(|| format!("{target:?} is not host:port"))?;
        let port = port
            .parse::<u16>()
            .ok()
            .filter(|p| *p != 0)
            .ok_or_else(|| format!("{target:?} has no valid port"))?;
        let (host, bracketed) = match host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
            Some(inner) => (inner, true),
            None => (host, false),
        };
        if host.is_empty() || host.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Err(format!("{target:?} has an invalid host"));
        }
        if host.contains(':') && !bracketed {
            return Err(format!("{target:?}: an IPv6 address must be in [brackets]"));
        }
        Ok((host, port))
    }

    /// Syntax-only check of a dial target (no DNS).
    pub(crate) fn check_dial_syntax(target: &str) -> Result<(), String> {
        split_host_port(target.trim()).map(|_| ())
    }

    #[cfg(unix)]
    fn interface_index(name: &str) -> Option<u32> {
        let c = std::ffi::CString::new(name).ok()?;
        // SAFETY: `c` is a valid NUL-terminated string for the whole call.
        let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
        (idx != 0).then_some(idx)
    }

    /// Windows: the adapter's system name (`ethernet_32769`, `loopback_0`;
    /// not its friendly name, which may have spaces).
    #[cfg(windows)]
    fn interface_index(name: &str) -> Option<u32> {
        let c = std::ffi::CString::new(name).ok()?;
        // SAFETY: `c` is a valid NUL-terminated string for the whole call.
        let idx = unsafe {
            windows_sys::Win32::NetworkManagement::IpHelper::if_nametoindex(c.as_ptr().cast())
        };
        (idx != 0).then_some(idx)
    }

    #[cfg(not(any(unix, windows)))]
    fn interface_index(_name: &str) -> Option<u32> {
        None
    }

    // IPv6 zones in dial strings. A LAN link's peer address keeps its zone
    // ([`link_local_zone`], Phase 3 step 4), and so do the LAN beacon's
    // candidates ([`scoped_dial`], step 10).

    /// The name of the interface with index `index`; None when there is none.
    #[cfg(unix)]
    fn interface_name(index: u32) -> Option<String> {
        // One byte more than the system writes: a NUL always ends it.
        let mut buf: [libc::c_char; libc::IF_NAMESIZE + 1] = [0; libc::IF_NAMESIZE + 1];
        // SAFETY: `buf` holds IF_NAMESIZE bytes, as if_indextoname requires;
        // it writes a NUL-terminated name there or returns null.
        if unsafe { libc::if_indextoname(index, buf.as_mut_ptr()) }.is_null() {
            return None;
        }
        // SAFETY: `buf` is NUL-terminated (its last byte is never written).
        let name = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) };
        name.to_str().ok().map(str::to_owned)
    }

    /// Windows writes zones as numbers ([`zone_for`]): no name is looked up.
    #[cfg(not(unix))]
    fn interface_name(_index: u32) -> Option<String> {
        None
    }

    /// How the zone (scope id) of an IPv6 link-local address is written in a
    /// dial string ([`scoped_dial`]): the interface's name where it reads
    /// back as the same zone ([`zone_for`]), else the number.
    pub(crate) fn zone_name(scope_id: u32) -> String {
        zone_for(scope_id, interface_name(scope_id).as_deref())
    }

    /// [`zone_name`] for the interface `name` (pure). Unix: the name when
    /// [`parse_scoped_v6`] reads it back as that interface: not empty, no
    /// whitespace or control character, no `%` or `]`, and not a number (a
    /// number is read as an index). Windows: always the number; adapter
    /// names such as `Wi-Fi 2` have spaces, which [`split_host_port`]
    /// refuses, and [`interface_index`] knows the adapters' system names
    /// only.
    pub(crate) fn zone_for(scope_id: u32, name: Option<&str>) -> String {
        let fits = |n: &str| {
            !n.is_empty()
                && n.parse::<u32>().is_err()
                && !n
                    .chars()
                    .any(|c| c.is_whitespace() || c.is_control() || c == '%' || c == ']')
        };
        match name {
            Some(n) if !cfg!(windows) && fits(n) => n.to_string(),
            _ => scope_id.to_string(),
        }
    }

    /// The zone of `addr` when it is an IPv6 link-local address (fe80::/10)
    /// with a scope id, as dial strings write it ([`zone_name`]); `None` for
    /// any other address. A LAN link's peer address keeps it in `lan_seen`
    /// and in the learned LAN part (Phase 3 step 4).
    pub(crate) fn link_local_zone(addr: SocketAddr) -> Option<String> {
        match addr {
            SocketAddr::V6(v6)
                if v6.scope_id() != 0 && (v6.ip().segments()[0] & 0xffc0) == 0xfe80 =>
            {
                Some(zone_name(v6.scope_id()))
            }
            _ => None,
        }
    }

    /// `addr` as a dial string that keeps the zone of an IPv6 link-local
    /// address (fe80::/10 with a scope id): `[fe80::1%en0]:7420`
    /// ([`link_local_zone`]), which [`resolve_dial_target`] reads back to the
    /// same scope id. Anything else as `addr` prints.
    #[cfg_attr(not(any(unix, windows)), allow(dead_code))]
    pub(crate) fn scoped_dial(addr: SocketAddr) -> String {
        match link_local_zone(addr) {
            Some(zone) => format!("[{}%{zone}]:{}", addr.ip(), addr.port()),
            None => addr.to_string(),
        }
    }

    /// `fe80::1%en0` (interface name or numeric zone) as a scoped socket
    /// address. `None` when `host` has no zone; std's parser rejects zones.
    fn parse_scoped_v6(host: &str, port: u16) -> Option<Result<SocketAddr, String>> {
        let (ip, zone) = host.split_once('%')?;
        let ip: Ipv6Addr = match ip.parse() {
            Ok(ip) => ip,
            Err(_) => return Some(Err(format!("{host:?}: not an IPv6 address before %"))),
        };
        let scope = zone
            .parse::<u32>()
            .ok()
            .or_else(|| interface_index(zone))
            .ok_or_else(|| format!("{host:?}: unknown network interface {zone:?}"));
        Some(scope.map(|scope| SocketAddr::V6(SocketAddrV6::new(ip, port, 0, scope))))
    }

    /// Alternate address families, starting with the resolver's first choice,
    /// so a dead AAAA record cannot use up the whole connect budget.
    pub(crate) fn interleave_families(addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
        let first_is_v6 = addrs.first().is_some_and(SocketAddr::is_ipv6);
        let (lead, other): (Vec<_>, Vec<_>) =
            addrs.into_iter().partition(|a| a.is_ipv6() == first_is_v6);
        let mut out: Vec<SocketAddr> = Vec::new();
        let (mut lead, mut other) = (lead.into_iter(), other.into_iter());
        loop {
            let (a, b) = (lead.next(), other.next());
            if a.is_none() && b.is_none() {
                return out;
            }
            for addr in a.into_iter().chain(b) {
                if !out.contains(&addr) {
                    out.push(addr);
                }
            }
        }
    }

    /// Candidate socket addresses for `host:port`, `[v6]:port` or
    /// `[v6%zone]:port`. Literals never touch DNS; names go through the
    /// system resolver off the async workers.
    pub(crate) async fn resolve_dial_target(target: &str) -> Result<Vec<SocketAddr>, String> {
        let target = target.trim();
        if let Ok(addr) = target.parse::<SocketAddr>() {
            return Ok(vec![addr]);
        }
        let (host, port) = split_host_port(target)?;
        if let Some(scoped) = parse_scoped_v6(host, port) {
            return scoped.map(|a| vec![a]);
        }
        // Every failure starts "cannot resolve <host>": ash words them all as
        // a name not found on this network (its `Cause::NameNotFound`).
        raven_core::lab_audit::dns();
        let found = tokio::time::timeout(RESOLVE_TIMEOUT, tokio::net::lookup_host((host, port)))
            .await
            .map_err(|_| {
                format!(
                    "cannot resolve {host}: timed out after {}s",
                    RESOLVE_TIMEOUT.as_secs()
                )
            })?
            .map_err(|e| format!("cannot resolve {host}: {e}"))?;
        let addrs = interleave_families(found.collect());
        if addrs.is_empty() {
            return Err(format!("cannot resolve {host}: it has no address"));
        }
        Ok(addrs)
    }

    /// Resolve `target` and connect to the first address that answers, each
    /// attempt bounded by `per_addr` and all of them by `budget`. The stream
    /// has TCP_NODELAY set (frames are small and strictly request/response).
    pub(crate) async fn connect_dial(
        target: &str,
        per_addr: Duration,
        budget: Duration,
    ) -> Result<(TcpStream, SocketAddr), String> {
        connect_dial_within(target, &ConnectWait::new(per_addr), budget).await
    }

    /// One dial's connect wait (learning connectivity may shorten it, Phase
    /// 6a P6.13): per address for LAN and Internet ([`connect_dial_within`]),
    /// the whole connect for p2p. It remembers whether it ran out, also
    /// across a dial the overall deadline drops ([`DialProgress::expired`]).
    #[derive(Clone, Debug)]
    pub(crate) struct ConnectWait {
        pub(crate) within: Duration,
        expired: Arc<std::sync::atomic::AtomicBool>,
    }

    impl ConnectWait {
        pub(crate) fn new(within: Duration) -> Self {
            Self {
                within,
                expired: Arc::default(),
            }
        }

        /// The wait ran out.
        pub(crate) fn expire(&self) {
            self.expired
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }

        /// It ran out at least once.
        pub(crate) fn expired(&self) -> bool {
            self.expired.load(std::sync::atomic::Ordering::Relaxed)
        }
    }

    /// [`connect_dial`] with each attempt bounded by `connect`'s wait; an
    /// attempt that runs out of it marks `connect` expired.
    pub(crate) async fn connect_dial_within(
        target: &str,
        connect: &ConnectWait,
        budget: Duration,
    ) -> Result<(TcpStream, SocketAddr), String> {
        let per_addr = connect.within;
        let addrs = resolve_dial_target(target).await?;
        let deadline = tokio::time::Instant::now() + budget;
        let mut failures: Vec<String> = Vec::new();
        for addr in addrs.into_iter().take(MAX_DIAL_ADDRS) {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            if left.is_zero() {
                failures.push("connect budget exhausted".into());
                break;
            }
            let wait = per_addr.min(left);
            raven_core::lab_audit::connect(&addr);
            match tokio::time::timeout(wait, TcpStream::connect(addr)).await {
                Ok(Ok(stream)) => {
                    let _ = stream.set_nodelay(true);
                    return Ok((stream, addr));
                }
                Ok(Err(e)) => failures.push(format!("{addr}: {e}")),
                Err(_) => {
                    // Its own wait ran out, not the budget's rest.
                    if wait == per_addr {
                        connect.expire();
                    }
                    failures.push(format!(
                        "{addr}: no answer within {:.1}s",
                        wait.as_secs_f32()
                    ))
                }
            }
        }
        Err(format!(
            "cannot connect to {target} ({})",
            failures.join("; ")
        ))
    }

    // ── Reply collection ─────────────────────────────────────────────────

    /// `dial` replies go back to the IPC client in one `*DialResult` frame;
    /// stop reading once they could no longer fit instead of buffering
    /// without bound.
    const MAX_DIAL_REPLIES: usize = 64;
    /// Base64 bytes (plus per-item JSON quoting) available in one IPC
    /// response; the remainder of `MAX_IPC_FRAME` covers the JSON envelope.
    const DIAL_REPLY_B64_BUDGET: usize = MAX_IPC_FRAME - 1024;

    tokio::task_local! {
        /// The reply budget of a dial raven-node makes for itself, whose
        /// replies never go back in an IPC response (the update exchange's
        /// follow-up dials, Phase 6b P6.49: 16 chunks of up to 61,440
        /// bytes). Outside its scope a dial has [`DIAL_REPLY_B64_BUDGET`].
        pub(crate) static INTERNAL_REPLY_BUDGET: usize;
    }

    #[derive(Debug)]
    pub(crate) struct DialReplyBudget {
        carrier: &'static str,
        count: usize,
        b64_bytes: usize,
        /// Set once the caller's frames were written, so an overflow error
        /// tells the client whether they were delivered.
        frames_sent: bool,
        /// [`DIAL_REPLY_B64_BUDGET`], or [`INTERNAL_REPLY_BUDGET`]'s.
        limit: usize,
    }

    impl DialReplyBudget {
        pub(crate) fn new(carrier: &'static str) -> Self {
            Self {
                carrier,
                count: 0,
                b64_bytes: 0,
                frames_sent: false,
                limit: INTERNAL_REPLY_BUDGET
                    .try_with(|budget| *budget)
                    .unwrap_or(DIAL_REPLY_B64_BUDGET),
            }
        }

        pub(crate) fn mark_frames_sent(&mut self) {
            self.frames_sent = true;
        }

        pub(crate) fn admit(&mut self, reply: &[u8]) -> Result<(), String> {
            // Standard base64 plus `"` `"` `,` in the JSON array.
            let cost = reply.len().div_ceil(3) * 4 + 3;
            let total = self.b64_bytes.saturating_add(cost);
            if self.count >= MAX_DIAL_REPLIES || total > self.limit {
                let sent = if self.frames_sent {
                    "frames were sent"
                } else {
                    "no frames were sent"
                };
                return Err(format!(
                    "{}_DIAL_REPLY_OVERFLOW: peer replies exceed one IPC response ({sent})",
                    self.carrier
                ));
            }
            self.count += 1;
            self.b64_bytes = total;
            Ok(())
        }
    }

    /// Does the responder answer this frame? A PairInit gets a PairResponse
    /// and a Message gets a sealed ACK; RLB1 offers, ACKs and PairResponses
    /// get nothing.
    fn expects_reply(frame: &[u8]) -> bool {
        // Session reset requests (RSR1 SESSION_QUERY / PREKEY_STALE).
        if raven_core::session_reset::frame_expects_reply(frame)
            || raven_core::friend_custody::frame_expects_reply(frame)
            || raven_core::update_exchange::frame_expects_reply(frame)
        {
            return true;
        }
        match classify_packed_envelope(frame) {
            PairInitOobClassify::PairInit(_) => true,
            PairInitOobClassify::PairResponse(_) => false,
            PairInitOobClassify::NotPairInitOob => {
                Envelope::unpack(frame).is_some_and(|e| e.env_type == EnvType::Message as u8)
            }
        }
    }

    /// Is this the reply a dial was waiting for (PairResponse or sealed ACK)?
    fn is_terminal_reply(frame: &[u8]) -> bool {
        // Session reset replies (RSR1 SESSION_STATUS / PREKEY_STATUS).
        if raven_core::session_reset::frame_is_terminal_reply(frame)
            || raven_core::friend_custody::frame_is_terminal_reply(frame)
            || raven_core::update_exchange::frame_is_terminal_reply(frame)
        {
            return true;
        }
        match classify_packed_envelope(frame) {
            PairInitOobClassify::PairResponse(_) => true,
            PairInitOobClassify::PairInit(_) => false,
            PairInitOobClassify::NotPairInitOob => {
                Envelope::unpack(frame).is_some_and(|e| e.env_type == EnvType::Ack as u8)
            }
        }
    }

    /// Outcome of one wait for the next reply frame.
    #[derive(Debug)]
    pub(crate) enum ReplyWait {
        Frame(Vec<u8>),
        /// Nothing arrived in time.
        Idle,
        /// The peer closed the connection, or the frame was unreadable.
        Closed(String),
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) struct ReplyWaits {
        /// Patience for the first reply: the responder may be hitting
        /// Keychain / session persistence.
        pub first: Duration,
        /// Silence after which later replies are given up on.
        pub idle: Duration,
    }

    pub(crate) const PRODUCTION_REPLY_WAITS: ReplyWaits = ReplyWaits {
        first: Duration::from_secs(30),
        idle: Duration::from_secs(2),
    };

    /// Collects the replies of one dial. Ends as soon as every frame that
    /// gets a reply has had its terminal reply; the idle wait is only the
    /// fallback for replies that cannot be classified.
    #[derive(Debug)]
    pub(crate) struct ReplyCollector {
        carrier: &'static str,
        waits: ReplyWaits,
        budget: DialReplyBudget,
        replies: Vec<Vec<u8>>,
        expected: usize,
        seen: usize,
        /// When the peer's offer had been read (the link authenticated),
        /// the frames were written and the first terminal reply came: the
        /// dial's times for learning connectivity ([`DialProgress::timing`]).
        linked_at: Option<tokio::time::Instant>,
        sent_at: Option<tokio::time::Instant>,
        first_reply_at: Option<tokio::time::Instant>,
        /// The first-reply wait ran out on frames that get a reply
        /// ([`DialProgress::expired`]).
        first_expired: bool,
        /// The outbox race this dial is in, if any ([`crate::onion::race`]):
        /// [`Self::begin`] claims it before any frame is written.
        race: Option<crate::onion::race::RaceTicket>,
    }

    impl ReplyCollector {
        pub(crate) fn new(carrier: &'static str, waits: ReplyWaits) -> Self {
            Self {
                carrier,
                waits,
                budget: DialReplyBudget::new(carrier),
                replies: Vec::new(),
                expected: 0,
                seen: 0,
                linked_at: None,
                sent_at: None,
                first_reply_at: None,
                first_expired: false,
                race: None,
            }
        }

        /// Put this dial in an outbox race ([`crate::onion::race`]); `None`:
        /// in none.
        pub(crate) fn set_race(&mut self, race: Option<crate::onion::race::RaceTicket>) {
            self.race = race;
        }

        /// Record the peer's offer (already read) and the frames about to be
        /// sent. The link is authenticated here (the contact's offer was
        /// verified): a dial in an outbox race claims it now, before its
        /// first frame, and one whose other side already won writes nothing
        /// and ends with [`crate::onion::race::RACE_LOST`].
        pub(crate) fn begin(
            &mut self,
            peer_offer: Vec<u8>,
            frames: &[Vec<u8>],
        ) -> Result<(), String> {
            if let Some(ticket) = self.race.filter(|_| !frames.is_empty()) {
                if !crate::onion::race::claim(ticket) {
                    return Err(crate::onion::race::RACE_LOST.into());
                }
            }
            self.linked_at = Some(tokio::time::Instant::now());
            self.budget.admit(&peer_offer)?;
            self.replies.push(peer_offer);
            self.expected = frames.iter().filter(|f| expects_reply(f)).count();
            Ok(())
        }

        pub(crate) fn mark_frames_sent(&mut self) {
            self.sent_at = Some(tokio::time::Instant::now());
            self.budget.mark_frames_sent();
        }

        /// How long to wait for the first reply.
        pub(crate) fn first_wait(&self) -> Duration {
            if self.expected == 0 {
                self.waits.idle
            } else {
                self.waits.first
            }
        }

        pub(crate) fn idle_wait(&self) -> Duration {
            self.waits.idle
        }

        /// The reply waits it was made with.
        #[cfg(test)]
        pub(crate) fn waits(&self) -> ReplyWaits {
            self.waits
        }

        fn push(&mut self, frame: Vec<u8>) -> Result<bool, String> {
            self.budget.admit(&frame)?;
            if is_terminal_reply(&frame) {
                self.first_reply_at
                    .get_or_insert_with(tokio::time::Instant::now);
                self.seen += 1;
            }
            self.replies.push(frame);
            Ok(self.expected == 0 || self.seen < self.expected)
        }

        /// Feed the outcome of the first wait; `Ok(true)` = keep reading.
        pub(crate) fn first(&mut self, got: ReplyWait) -> Result<bool, String> {
            match got {
                ReplyWait::Frame(f) => self.push(f),
                // No answer yet: the caller sees only the offer and retries.
                ReplyWait::Idle => {
                    self.first_expired = self.expected > 0;
                    Ok(false)
                }
                ReplyWait::Closed(_) if self.expected == 0 => Ok(false),
                ReplyWait::Closed(why) => {
                    let (code, what) = if why == PEER_CLOSED {
                        (
                            "PEER_CLOSED",
                            "the peer closed the connection without replying".to_string(),
                        )
                    } else {
                        (
                            "BAD_REPLY",
                            format!("the peer's reply could not be read ({why})"),
                        )
                    };
                    Err(format!(
                        "{}_DIAL_{code}: {what}; the frames were sent, delivery is \
                         unconfirmed and a retry is safe",
                        self.carrier
                    ))
                }
            }
        }

        /// Feed a later wait; `Ok(true)` = keep reading. Silence or a close
        /// after at least one reply is a normal end.
        pub(crate) fn next(&mut self, got: ReplyWait) -> Result<bool, String> {
            match got {
                ReplyWait::Frame(f) => self.push(f),
                ReplyWait::Idle | ReplyWait::Closed(_) => Ok(false),
            }
        }

        pub(crate) fn into_replies(self) -> Vec<Vec<u8>> {
            self.replies
        }
    }

    /// What a dial has done so far, kept outside the dial future so the
    /// overall deadline can still report precisely.
    #[derive(Debug)]
    pub(crate) struct DialProgress {
        pub(crate) stage: &'static str,
        pub(crate) frames_sent: bool,
        pub(crate) collector: ReplyCollector,
        /// The dial's connect wait ([`connect_dial_within`]; the p2p
        /// connect).
        pub(crate) connect: ConnectWait,
        /// When the dial began ([`Self::timing`]).
        started: tokio::time::Instant,
    }

    impl DialProgress {
        /// A dial with today's connect wait per address
        /// ([`CONNECT_TIMEOUT`]) and the reply `waits`.
        pub(crate) fn new(carrier: &'static str, waits: ReplyWaits) -> Self {
            Self::with_connect(carrier, waits, CONNECT_TIMEOUT)
        }

        /// A dial with `waits` (`crate::learning::waits`: learning
        /// connectivity's, today's while it is off): its connect wait and
        /// its first-reply wait; the idle reply wait is always today's.
        pub(crate) fn waiting(
            carrier: &'static str,
            waits: &raven_core::learning::wait::Waits,
        ) -> Self {
            let replies = ReplyWaits {
                first: waits.reply_first.min(PRODUCTION_REPLY_WAITS.first),
                idle: PRODUCTION_REPLY_WAITS.idle,
            };
            Self::with_connect(carrier, replies, waits.connect)
        }

        pub(crate) fn with_connect(
            carrier: &'static str,
            waits: ReplyWaits,
            connect: Duration,
        ) -> Self {
            Self {
                stage: "starting",
                frames_sent: false,
                collector: ReplyCollector::new(carrier, waits),
                connect: ConnectWait::new(connect),
                started: tokio::time::Instant::now(),
            }
        }

        /// Which of the dial's waits ran out so far (learning connectivity
        /// backs them off, `crate::learning::observe_dial`). Read it before
        /// [`Self::on_deadline`] or [`ReplyCollector::into_replies`].
        pub(crate) fn expired(&self) -> crate::learning::Expired {
            crate::learning::Expired {
                connect: self.connect.expired(),
                reply: self.collector.first_expired,
            }
        }

        /// The dial got as far as connecting: what it says is about the
        /// route (learning connectivity, Phase 6a). Before that (this
        /// node's identity, pin store, `raven lan off`) nothing was dialled.
        pub(crate) fn connecting_began(&self) -> bool {
            !matches!(self.stage, "starting" | "loading the local identity")
        }

        /// The dial's times so far, for learning connectivity (Phase 6a,
        /// `crate::learning::observe_dial`): connect from the start until
        /// the peer's offer was read, reply from the frames being written
        /// until the first terminal reply, total until now. Read it before
        /// [`Self::on_deadline`] or [`ReplyCollector::into_replies`].
        pub(crate) fn timing(&self) -> raven_core::learning::observe::DialTiming {
            let ms = |d: Duration| u32::try_from(d.as_millis()).unwrap_or(u32::MAX);
            let c = &self.collector;
            raven_core::learning::observe::DialTiming {
                connect_ms: c.linked_at.map(|at| ms(at.duration_since(self.started))),
                reply_ms: c
                    .sent_at
                    .zip(c.first_reply_at)
                    .map(|(sent, first)| ms(first.saturating_duration_since(sent))),
                total_ms: ms(self.started.elapsed()),
            }
        }

        /// The overall dial deadline fired. Once the frames were written the
        /// replies collected so far are the answer (the caller maps a missing
        /// ACK to "waiting for ACK" and retries); before that it is an error.
        pub(crate) fn on_deadline(
            self,
            carrier: &str,
            target: &str,
            deadline: Duration,
        ) -> Result<Vec<Vec<u8>>, String> {
            if self.frames_sent {
                return Ok(self.collector.into_replies());
            }
            let sent = if self.stage == "sending frames" {
                "; the frames may have been delivered"
            } else {
                ""
            };
            Err(format!(
                "{carrier} dial to {target} timed out after {}s while {}{sent}",
                deadline.as_secs(),
                self.stage
            ))
        }
    }

    // ── Listening ────────────────────────────────────────────────────────

    #[derive(Debug, Clone, Copy)]
    pub(crate) struct InboundLimits {
        /// Concurrent connections, any phase.
        pub max_conns: usize,
        /// Concurrent connections from one source, handshaking or established.
        pub max_per_ip: usize,
        /// Pre-auth connections from one source. Small: an unauthenticated
        /// peer can hold these slots, nothing more.
        pub max_handshaking_per_ip: usize,
        pub max_frames: u32,
        /// Hard lifetime of one connection.
        pub lifetime: Duration,
        /// Noise handshake, bind and offer exchange: separate from (and much
        /// shorter than) `lifetime`, so an idle connection cannot sit on a slot.
        pub handshake_deadline: Duration,
        /// How long a link waits, before its handshake, for a contact book
        /// this process holds while its key loads ([`book_open_within`]).
        /// Well below a dialer's wait for Noise message 2 (30 s): a dialer
        /// tries 3 times ([`with_handshake_retries`]) within its dial.
        pub book_wait: Duration,
    }

    pub(crate) const PRODUCTION_INBOUND: InboundLimits = InboundLimits {
        max_conns: 32,
        max_per_ip: 8,
        max_handshaking_per_ip: 4,
        max_frames: 64,
        lifetime: Duration::from_secs(120),
        handshake_deadline: Duration::from_secs(10),
        book_wait: BOOK_WAIT,
    };

    /// The nearby carrier's inbound links (RNL1 §7-§8): at most 8, 2 per
    /// contact (each pipe's admission key is its contact's). The handshake
    /// deadline is longer than TCP's: RLB1 is about 3.4 KB each way at
    /// Bluetooth LE speed.
    pub(crate) const NEARBY_INBOUND: InboundLimits = InboundLimits {
        max_conns: 8,
        max_per_ip: 2,
        max_handshaking_per_ip: 2,
        max_frames: 64,
        lifetime: Duration::from_secs(300),
        handshake_deadline: Duration::from_secs(20),
        book_wait: BOOK_WAIT,
    };

    /// The Tor onion carrier's inbound links (RAVEN_ONION_CARRIER_V1 §5):
    /// every one arrives from the Tor helper on loopback, after its token,
    /// with the number of the rendezvous circuit it came on; the admission
    /// key is that circuit (`crate::onion`), so the per-source caps are per
    /// circuit and one client's circuit cannot hold every slot (a full
    /// listener displaces a pre-auth link of the busiest circuit; security
    /// review 2026-10-29 #1). The handshake deadline allows Tor round trips
    /// (`raven_core::onion::ONION_HANDSHAKE_DEADLINE`).
    pub(crate) const ONION_INBOUND: InboundLimits = InboundLimits {
        max_conns: 16,
        max_per_ip: 4,
        max_handshaking_per_ip: 2,
        max_frames: 64,
        lifetime: Duration::from_secs(180),
        handshake_deadline: raven_core::onion::ONION_HANDSHAKE_DEADLINE,
        book_wait: BOOK_WAIT,
    };

    /// [`InboundLimits::book_wait`] on every listener: right after a start
    /// or an Unlock the at-rest key loads in a moment or two; a dialer's
    /// three tries cover about three times this.
    const BOOK_WAIT: Duration = Duration::from_secs(3);
    /// How often a waiting link looks at the book's hold again.
    const BOOK_POLL: Duration = Duration::from_millis(50);

    /// Before an inbound link's handshake: while this process holds the
    /// contact book ([`raven_core::contact_book::hold`]), wait up to `wait`
    /// as long as its at-rest key is being loaded (at start or after an
    /// Unlock: [`crate::at_rest_boot::key_loading`]). A dialer cannot be
    /// judged against a book that cannot be read (E1: a verified friend was
    /// refused as a stranger right after an Unlock, its address struck, and
    /// its route held as refused until its user retried). A book still held
    /// then (or held with no key load running: a failed one waits for its
    /// next try) closes the link before Noise message 2
    /// ([`raven_core::lan_dispatch::LINK_REFUSED_NOT_READY`]): the dialer
    /// sees a hang-up during the handshake, which it retries
    /// ([`with_handshake_retries`]) and then files as transient
    /// (CLOSED_EARLY), never as this node refusing it (LINK_NOT_ACCEPTED);
    /// here it is no stranger's refusal (no security event, no strike). The
    /// same for whoever dials: nothing of theirs has been read yet.
    pub(crate) async fn book_open_within(data_dir: &Path, wait: Duration) -> Result<(), String> {
        let deadline = tokio::time::Instant::now() + wait;
        while raven_core::contact_book::is_held(data_dir) {
            if !crate::at_rest_boot::key_loading(data_dir)
                || tokio::time::Instant::now() >= deadline
            {
                return Err(raven_core::lan_dispatch::LINK_REFUSED_NOT_READY.into());
            }
            tokio::time::sleep(BOOK_POLL).await;
        }
        Ok(())
    }

    /// Per-source quota key: IPv4-mapped IPv6 folds to IPv4, a native IPv6
    /// address to its /64 (a host controls the whole /64).
    pub(crate) fn admission_key(ip: IpAddr) -> IpAddr {
        match ip {
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => IpAddr::V4(v4),
                None => {
                    let mut octets = v6.octets();
                    octets[8..].fill(0);
                    IpAddr::V6(Ipv6Addr::from(octets))
                }
            },
            v4 => v4,
        }
    }

    #[derive(Debug)]
    struct Conn {
        key: IpAddr,
        /// Still pre-auth: counts against the small per-source cap and may be
        /// displaced by a newcomer.
        handshaking: bool,
        displaced: Arc<Notify>,
    }

    #[derive(Debug, Default)]
    struct AdmissionState {
        next_id: u64,
        /// Live connections, oldest first (ids grow with admission order).
        /// At most `max_conns`, so counting by scan is cheap.
        conns: BTreeMap<u64, Conn>,
    }

    impl AdmissionState {
        /// The pre-auth connection to give up when the listener is full: the
        /// oldest one of the source holding the most pre-auth connections
        /// (a handshake that has had the longest to finish and has not is the
        /// most likely to be silent). `None` when there is no pre-auth
        /// connection, or when the newcomer's own source (`mine` pre-auth
        /// connections) already holds as many as that one: a source at its
        /// fair share cannot push anyone else out.
        fn displaceable(&self, mine: usize) -> Option<u64> {
            let mut best: Option<(u64, usize)> = None;
            for (&id, conn) in self.conns.iter().filter(|(_, c)| c.handshaking) {
                let n = self
                    .conns
                    .values()
                    .filter(|o| o.handshaking && o.key == conn.key)
                    .count();
                match best {
                    Some((_, most)) if n <= most => {}
                    _ => best = Some((id, n)),
                }
            }
            best.filter(|&(_, n)| n > mine).map(|(id, _)| id)
        }
    }

    /// Global and per-source admission for one listener. A slot is released
    /// by dropping it (also on panic or cancellation) and starts out as a
    /// pre-auth "handshaking" connection until [`AdmissionSlot::authenticated`].
    ///
    /// A full listener makes room for a newcomer by displacing a pre-auth
    /// connection of a busier source (see `AdmissionState::displaceable`), so a
    /// pool of silent sockets cannot lock real peers out. Authenticated
    /// sessions are never displaced, and a source over its own caps is simply
    /// refused.
    ///
    /// A listener whose sources are network addresses
    /// ([`Admission::for_addresses`]) also asks the process's penalty box
    /// first (Phase 6b R1, while the responses gate is live): a banned source
    /// is refused, save one probation connection per 10 s, and a contact that
    /// authenticates clears its source.
    #[derive(Debug)]
    pub(crate) struct Admission {
        state: Mutex<AdmissionState>,
        limits: InboundLimits,
        /// The sources are addresses met on this carrier: the penalty box
        /// applies, keyed as that carrier's sources are
        /// (`security::penalty_key`).
        addresses: Option<OutboxCarrier>,
    }

    /// Why [`Admission::admit`] refused a connection.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Refused {
        /// The source is banned (the penalty box, Phase 6b R1).
        Banned,
        /// The source is at its own caps.
        SourceCap,
        /// The listener is full, with nobody to displace.
        Full,
    }

    #[derive(Debug)]
    pub(crate) struct AdmissionSlot {
        admission: Arc<Admission>,
        id: u64,
        displaced: Arc<Notify>,
        /// The handler knows whom it serves ([`AdmissionSlot::authenticated`],
        /// [`AdmissionSlot::contact_admitted`]): from then on it reports the
        /// link's security events itself, and the accept loop notes none of
        /// its failures against the network source (Phase 6b S2).
        auth: Arc<AtomicBool>,
        /// The source's address and carrier, when the penalty box applies
        /// (it is told when the peer authenticates).
        source: Option<(IpAddr, OutboxCarrier)>,
    }

    impl Admission {
        /// Sources that are keys, not addresses (the p2p responder's, the
        /// radio pipes'): the penalty box never applies.
        pub(crate) fn new(limits: InboundLimits) -> Arc<Self> {
            Self::with(limits, None)
        }

        /// A listener on `carrier` whose sources are network addresses (LAN,
        /// Internet direct): the penalty box applies.
        pub(crate) fn for_addresses(limits: InboundLimits, carrier: OutboxCarrier) -> Arc<Self> {
            Self::with(limits, Some(carrier))
        }

        fn with(limits: InboundLimits, addresses: Option<OutboxCarrier>) -> Arc<Self> {
            Arc::new(Self {
                state: Mutex::new(AdmissionState::default()),
                limits,
                addresses,
            })
        }

        pub(crate) fn try_admit(self: &Arc<Self>, ip: IpAddr) -> Option<AdmissionSlot> {
            self.admit(ip).ok()
        }

        /// [`Self::try_admit`], saying why it refused.
        pub(crate) fn admit(self: &Arc<Self>, ip: IpAddr) -> Result<AdmissionSlot, Refused> {
            if let Some(carrier) = self.addresses {
                if crate::security::admit_source(ip, carrier)
                    == raven_core::security_events::Admit::Deny
                {
                    return Err(Refused::Banned);
                }
            }
            let key = admission_key(ip);
            let mut st = lock(&self.state);
            let (mut total, mut handshaking) = (0, 0);
            for c in st.conns.values().filter(|c| c.key == key) {
                total += 1;
                handshaking += usize::from(c.handshaking);
            }
            if total >= self.limits.max_per_ip || handshaking >= self.limits.max_handshaking_per_ip
            {
                return Err(Refused::SourceCap);
            }
            if st.conns.len() >= self.limits.max_conns {
                let victim = st.displaceable(handshaking).ok_or(Refused::Full)?;
                if let Some(conn) = st.conns.remove(&victim) {
                    // Stores a permit, so the wake-up is not lost if the
                    // victim's task has not polled yet.
                    conn.displaced.notify_one();
                }
            }
            let id = st.next_id;
            st.next_id += 1;
            let displaced = Arc::new(Notify::new());
            st.conns.insert(
                id,
                Conn {
                    key,
                    handshaking: true,
                    displaced: Arc::clone(&displaced),
                },
            );
            drop(st);
            Ok(AdmissionSlot {
                admission: Arc::clone(self),
                id,
                displaced,
                auth: Arc::new(AtomicBool::new(false)),
                source: self.addresses.map(|carrier| (ip, carrier)),
            })
        }
    }

    impl AdmissionSlot {
        /// The peer completed the handshake **and is trusted** (a local
        /// contact): stop counting it against the pre-auth caps and protect it
        /// from displacement. Possessing a key is not trust: anyone can
        /// self-sign an RLB1 bundle, so callers must not promote strangers.
        pub(crate) fn authenticated(&mut self) {
            if let Some(c) = lock(&self.admission.state).conns.get_mut(&self.id) {
                c.handshaking = false;
            }
            self.auth.store(true, Ordering::Relaxed);
            // A contact came from here: the source is no stranger's (a
            // friend behind an attacker's address clears its ban, Phase 6b
            // R1).
            if let Some((ip, carrier)) = self.source {
                crate::security::source_authenticated(ip, carrier);
            }
        }

        /// The dialer is a contact the gate admitted: the handler reports
        /// what happens on the link from here on (a contact's path, not a
        /// network source). The caps are unchanged until
        /// [`Self::authenticated`].
        pub(crate) fn contact_admitted(&self) {
            self.auth.store(true, Ordering::Relaxed);
        }

        /// Shared with the accept loop, which reads it once the handler ends.
        pub(crate) fn auth_flag(&self) -> Arc<AtomicBool> {
            Arc::clone(&self.auth)
        }

        /// Fires once a newcomer has taken this (pre-auth) slot over: the
        /// connection must then be dropped.
        pub(crate) fn displaced(&self) -> Arc<Notify> {
            Arc::clone(&self.displaced)
        }
    }

    impl Drop for AdmissionSlot {
        fn drop(&mut self) {
            // Already gone if it was displaced.
            lock(&self.admission.state).conns.remove(&self.id);
        }
    }

    /// At most one log line per window for events a remote peer can cause at
    /// will; the next line says how many were folded into it.
    pub(crate) struct LogLimiter {
        window: Duration,
        state: Mutex<(Option<Instant>, u64)>,
    }

    impl LogLimiter {
        pub(crate) const fn new(window: Duration) -> Self {
            Self {
                window,
                state: Mutex::new((None, 0)),
            }
        }

        /// Count one event. `Some(n)`: write a line now; `n` events happened
        /// since the previous line (this one included).
        pub(crate) fn hit_at(&self, now: Instant) -> Option<u64> {
            let mut st = lock(&self.state);
            st.1 += 1;
            match st.0 {
                Some(last) if now.saturating_duration_since(last) < self.window => None,
                _ => {
                    st.0 = Some(now);
                    Some(std::mem::take(&mut st.1))
                }
            }
        }
    }

    pub(crate) fn log_limited(limiter: &LogLimiter, what: &str, detail: impl std::fmt::Display) {
        match limiter.hit_at(Instant::now()) {
            None => {}
            Some(1) => eprintln!("{what}: {detail}"),
            Some(n) => eprintln!(
                "{what}: {detail} (and {} more like it in the last {}s)",
                n - 1,
                limiter.window.as_secs()
            ),
        }
    }

    static CAP_LOG: LogLimiter = LogLimiter::new(Duration::from_secs(10));
    static INBOUND_LOG: LogLimiter = LogLimiter::new(Duration::from_secs(10));

    /// One log line, after its UTC time (Raven's clock: the computer's, but
    /// for a lab offset in a debug build): what this crate's `eprintln!`
    /// writes.
    pub(crate) fn log_line(line: std::fmt::Arguments<'_>) {
        std::eprintln!("{}", stamped(line));
    }

    /// [`log_line`] that never panics: a write that fails (EPIPE once the
    /// log pipe's reader is gone) loses the line. The bridge's accept loops
    /// and poller log through it (`bridge_run`'s `blog!`), with the same
    /// UTC time first (E1: its lines had none).
    pub(crate) fn log_line_lossy(line: std::fmt::Arguments<'_>) {
        #[cfg(not(test))]
        {
            use std::io::Write as _;
            let _ = writeln!(std::io::stderr(), "{}", stamped(line));
        }
        // Tests: the harness captures it, as it does `eprintln!`.
        #[cfg(test)]
        std::eprintln!("{}", stamped(line));
    }

    fn stamped(line: std::fmt::Arguments<'_>) -> String {
        let ms = raven_core::clock::now_ms();
        format!("{} {line}", raven_core::local_time::utc_stamp(ms))
    }

    /// The other side of a link in a log line: a short tag, the same for the
    /// same contact key or source address while this raven-node runs (keyed
    /// with a secret made at start, which is never written), never the
    /// address, key or PeerId itself. The service log is plain and users back
    /// it up and sync it (docs/SAFETY_OFFLINE.md: counts and codes only).
    pub(crate) fn link_tag(id: &[u8]) -> String {
        use std::hash::{BuildHasher, Hasher};
        static KEYS: std::sync::OnceLock<std::collections::hash_map::RandomState> =
            std::sync::OnceLock::new();
        let mut h = KEYS
            .get_or_init(std::collections::hash_map::RandomState::new)
            .build_hasher();
        h.write(id);
        format!("#{:04x}", h.finish() & 0xffff)
    }

    /// [`link_tag`] of a source address.
    pub(crate) fn source_tag(ip: IpAddr) -> String {
        match ip.to_canonical() {
            IpAddr::V4(v4) => link_tag(&v4.octets()),
            IpAddr::V6(v6) => link_tag(&v6.octets()),
        }
    }

    /// Log a peer-caused per-connection failure (rate limited).
    pub(crate) fn log_inbound_failure(what: &str, detail: impl std::fmt::Display) {
        log_limited(&INBOUND_LOG, what, detail);
    }

    /// Accept connections for ever. Accept errors are retried
    /// ([`crate::accept_retrying`]), over-cap peers are dropped with a rate
    /// limited log line, and every admitted connection runs `handler` under
    /// `limits.lifetime`; its slot is released when the handler ends, however
    /// it ends (a pre-auth connection displaced by a newcomer ends early).
    pub(crate) async fn serve_connections<A, AFut, H, HFut>(
        name: &'static str,
        mut accept: A,
        limits: InboundLimits,
        handler: H,
    ) -> Infallible
    where
        A: FnMut() -> AFut,
        AFut: Future<Output = std::io::Result<(TcpStream, SocketAddr)>>,
        H: Fn(TcpStream, AdmissionSlot) -> HFut,
        HFut: Future<Output = Result<(), String>> + Send + 'static,
    {
        let admission = Admission::for_addresses(limits, crate::security::listener_carrier(name));
        loop {
            // EMFILE / ECONNABORTED etc. are logged and backed off, never fatal.
            let (stream, addr) = crate::accept_retrying(name, &mut accept).await;
            let slot = match admission.admit(addr.ip()) {
                Ok(slot) => slot,
                Err(refused) => {
                    if refused == Refused::SourceCap {
                        // Phase 6b R1: the source's own cap is a strike.
                        crate::security::cap_refused(
                            addr.ip(),
                            crate::security::listener_carrier(name),
                        );
                    }
                    log_limited(
                        &CAP_LOG,
                        name,
                        // No remote address: this line is persisted in the service log
                        // (`raven-node-service.log`), which users back up and sync, and
                        // any host that connects can trigger it.
                        match refused {
                            Refused::Banned => "a source that failed too often was refused",
                            Refused::SourceCap | Refused::Full => {
                                "connection cap reached; refused a connection"
                            }
                        },
                    );
                    continue;
                }
            };
            let _ = stream.set_nodelay(true);
            let displaced = slot.displaced();
            let auth = slot.auth_flag();
            let work = handler(stream, slot);
            let lifetime = limits.lifetime;
            tokio::spawn(async move {
                tokio::select! {
                    done = tokio::time::timeout(lifetime, work) => match done {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => {
                            // Before the handler knew whom it served: about
                            // the network source (Phase 6b S2, S3).
                            if !auth.load(Ordering::Relaxed) {
                                crate::security::inbound_refused(
                                    addr.ip(),
                                    crate::security::listener_carrier(name),
                                    &e,
                                );
                            }
                            log_inbound_failure(
                                &format!("{name} inbound"),
                                format_args!("from {}: {e}", source_tag(addr.ip())),
                            )
                        }
                        Err(_) => log_inbound_failure(
                            &format!("{name} inbound"),
                            format_args!(
                                "from {}: connection lifetime exceeded",
                                source_tag(addr.ip())
                            ),
                        ),
                    },
                    // Dropping `work` closes the socket.
                    () = displaced.notified() => log_inbound_failure(
                        &format!("{name} inbound"),
                        format_args!(
                            "from {}: unauthenticated connection displaced by a newcomer",
                            source_tag(addr.ip())
                        ),
                    ),
                    // Lock v2 (P6.40): every link ends when Raven locks, and
                    // the identity it held goes with it.
                    () = crate::lock::until_locked() => {}
                }
            });
        }
    }

    /// A loopback address whose connects get no answer, for tests of the
    /// connect waits: a listener with a backlog of one that never accepts,
    /// its queue filled (macOS and Linux then drop the SYN). Keep the
    /// returned sockets while dialling it. `None` where this computer
    /// refuses such a connect instead (Windows answers a full queue with a
    /// reset): the caller skips.
    #[cfg(test)]
    pub(crate) fn black_hole() -> Option<(SocketAddr, socket2::Socket, Vec<std::net::TcpStream>)> {
        use socket2::{Domain, Socket, Type};
        let listener = Socket::new(Domain::IPV4, Type::STREAM, None).ok()?;
        listener
            .bind(&SocketAddr::from(([127, 0, 0, 1], 0)).into())
            .ok()?;
        listener.listen(1).ok()?;
        let at = listener.local_addr().ok()?.as_socket()?;
        let mut queued = Vec::new();
        for _ in 0..8 {
            match std::net::TcpStream::connect_timeout(&at, Duration::from_millis(300)) {
                Ok(stream) => queued.push(stream),
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                    return Some((at, listener, queued))
                }
                Err(_) => break,
            }
        }
        eprintln!("skipped: this computer does not drop connects to a full listen queue");
        None
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use tokio::io::AsyncReadExt;
        use tokio::net::TcpListener;
        use tokio::sync::mpsc;

        fn sa(s: &str) -> SocketAddr {
            s.parse().unwrap()
        }

        /// E1 (three machines): a node log line had no time and nothing
        /// about the other side, so a failed delivery could not be matched
        /// to a friend's report. Every line starts with its UTC time; the
        /// other side is a short tag (never its address, key or PeerId: the
        /// log is plain).
        #[test]
        fn log_lines_carry_their_utc_time_and_links_a_tag_not_an_address() {
            let line = stamped(format_args!("lan_direct inbound: {}", PEER_CLOSED));
            let (stamp, rest) = line.split_once(' ').unwrap();
            assert_eq!(rest, "lan_direct inbound: peer closed the connection");
            assert_eq!(stamp.len(), "2026-10-25T12:43:10Z".len(), "{line}");
            assert!(stamp.starts_with("20") && stamp.ends_with('Z'), "{line}");
            assert_eq!(&stamp[10..11], "T", "{line}");
            let ip: IpAddr = "192.168.0.11".parse().unwrap();
            let tag = source_tag(ip);
            assert_eq!(tag, source_tag(ip), "the same source, the same tag");
            assert_eq!(tag, source_tag("::ffff:192.168.0.11".parse().unwrap()));
            assert_eq!(tag.len(), 5);
            assert!(tag.starts_with('#') && !tag.contains("192") && !tag.contains("168"));
            let key = [7u8; 32];
            assert_eq!(link_tag(&key), link_tag(&key));
            assert!(!link_tag(&key).contains("0707"));
        }

        /// E1 (win-c): the bridge's "raven-node: BRIDGE ..." lines had no
        /// time: its `blog!` wrote to stderr itself. No line of raven-node
        /// reaches stderr but through the stamp ([`log_line`], and
        /// [`log_line_lossy`], which `blog!` uses); the helper programs in
        /// `src/bin` are not raven-node's log.
        #[test]
        fn no_log_line_bypasses_the_stamp() {
            fn sources(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
                for entry in std::fs::read_dir(dir).unwrap() {
                    let path = entry.unwrap().path();
                    if path.is_dir() {
                        if !path.ends_with("bin") {
                            sources(&path, out);
                        }
                    } else if path.extension().is_some_and(|e| e == "rs") {
                        out.push(path);
                    }
                }
            }
            let mut files = Vec::new();
            sources(
                &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
                &mut files,
            );
            assert!(files.len() > 20, "{files:?}");
            let stamped_writes = [
                "std::eprintln!(\"{}\", stamped(line));",
                "let _ = writeln!(std::io::stderr(), \"{}\", stamped(line));",
            ];
            let mut bypass = Vec::new();
            for file in &files {
                let text = std::fs::read_to_string(file).unwrap();
                for (n, line) in text.lines().enumerate() {
                    let code = line.trim();
                    // In code, not in a string (this test's own texts).
                    let writes = ["io::stderr()", "std::eprintln!", "eprint!("]
                        .iter()
                        .any(|w| code.find(w).is_some_and(|at| !code[..at].contains('"')));
                    if writes && !code.starts_with("//") && !stamped_writes.contains(&code) {
                        bypass.push(format!("{}:{}: {code}", file.display(), n + 1));
                    }
                }
            }
            assert!(
                bypass.is_empty(),
                "unstamped log writes:\n{}",
                bypass.join("\n")
            );
            assert!(include_str!("bridge_run.rs")
                .contains("crate::netutil::log_line_lossy(format_args!($($arg)*))"));
            let line = stamped(format_args!("raven-node: BRIDGE lan listen 127.0.0.1:1"));
            assert!(
                line.ends_with("Z raven-node: BRIDGE lan listen 127.0.0.1:1"),
                "{line}"
            );
        }

        #[test]
        fn dial_syntax_accepts_names_and_bracketed_v6_only() {
            for ok in [
                "192.168.1.20:7420",
                "mac-mini.local:7420",
                "localhost:1",
                "[::1]:7420",
                "[fe80::1%en0]:7420",
            ] {
                assert!(check_dial_syntax(ok).is_ok(), "{ok}");
            }
            for bad in [
                "mac-mini.local",
                "host:0",
                "host:99999",
                ":7420",
                "ho st:1",
                "::1:7420", // ambiguous: a v6 literal needs brackets
                "bad\0host:1",
            ] {
                assert!(check_dial_syntax(bad).is_err(), "{bad:?}");
            }
        }

        #[tokio::test]
        async fn literals_and_zones_resolve_without_dns() {
            assert_eq!(
                resolve_dial_target(" 10.0.0.5:7420 ").await.unwrap(),
                vec![sa("10.0.0.5:7420")]
            );
            assert_eq!(
                resolve_dial_target("[::1]:7420").await.unwrap(),
                vec![sa("[::1]:7420")]
            );
            // std's parser rejects zones; a numeric one is carried as scope id.
            match resolve_dial_target("[fe80::1%7]:7420").await.unwrap()[..] {
                [SocketAddr::V6(v6)] => {
                    assert_eq!(v6.scope_id(), 7);
                    assert_eq!(v6.port(), 7420);
                    assert_eq!(v6.ip(), &"fe80::1".parse::<Ipv6Addr>().unwrap());
                }
                ref other => panic!("{other:?}"),
            }
            let err = resolve_dial_target("[fe80::1%no-such-if0]:7420")
                .await
                .unwrap_err();
            assert!(err.contains("unknown network interface"), "{err}");
            let err = resolve_dial_target("[not-an-ip%en0]:7420")
                .await
                .unwrap_err();
            assert!(err.contains("IPv6"), "{err}");
        }

        #[cfg(unix)]
        #[tokio::test]
        async fn interface_names_map_to_scope_ids() {
            let lo = if cfg!(target_os = "linux") {
                "lo"
            } else {
                "lo0"
            };
            match resolve_dial_target(&format!("[fe80::1%{lo}]:7420"))
                .await
                .unwrap()[..]
            {
                [SocketAddr::V6(v6)] => assert!(v6.scope_id() > 0),
                ref other => panic!("{other:?}"),
            }
        }

        /// The loopback interface's name and index on this host (Unix).
        #[cfg(unix)]
        fn loopback_interface() -> (&'static str, u32) {
            let lo = if cfg!(target_os = "linux") {
                "lo"
            } else {
                "lo0"
            };
            (lo, interface_index(lo).expect("the loopback interface"))
        }

        #[test]
        fn zone_names_read_back_as_the_same_zone_or_are_numbers() {
            // A Unix name is kept; Windows always writes the number.
            for name in ["en0", "bridge100", "eth0:1", "wlp2s0"] {
                let want = if cfg!(windows) { "4" } else { name };
                assert_eq!(zone_for(4, Some(name)), want, "{name}");
            }
            // A name a dial string can't carry, or one read back as another
            // zone, is written as the number.
            for name in [
                "Wi-Fi 2",
                "",
                "en0%1",
                "en0]",
                "tab\tname",
                "nul\0",
                "12",
                "+5",
            ] {
                assert_eq!(zone_for(9, Some(name)), "9", "{name:?}");
            }
            assert_eq!(zone_for(9, None), "9");
            // No interface has this index.
            assert_eq!(zone_name(u32::MAX), u32::MAX.to_string());
            #[cfg(unix)]
            {
                let (lo, index) = loopback_interface();
                assert_eq!(zone_name(index), lo);
            }
            #[cfg(windows)]
            assert_eq!(zone_name(1), "1");
        }

        #[tokio::test]
        async fn scoped_dial_reads_back_to_the_same_scope_id() {
            let link_local = |scope: u32| {
                SocketAddr::V6(SocketAddrV6::new(
                    "fe80::1".parse().unwrap(),
                    7420,
                    0,
                    scope,
                ))
            };
            #[cfg(unix)]
            let named = {
                let (lo, index) = loopback_interface();
                assert_eq!(
                    scoped_dial(link_local(index)),
                    format!("[fe80::1%{lo}]:7420")
                );
                Some(index)
            };
            #[cfg(not(unix))]
            let named = None;
            #[cfg(windows)]
            assert_eq!(scoped_dial(link_local(7)), "[fe80::1%7]:7420");
            // Indexes this host may or may not have: named zones and numbers
            // both read back.
            for scope in [1, 2, 7, 999_999].into_iter().chain(named) {
                let dial = scoped_dial(link_local(scope));
                match resolve_dial_target(&dial).await.unwrap()[..] {
                    [SocketAddr::V6(v6)] => {
                        assert_eq!(v6.scope_id(), scope, "{dial}");
                        assert_eq!(v6.port(), 7420, "{dial}");
                        assert_eq!(v6.ip(), &"fe80::1".parse::<Ipv6Addr>().unwrap());
                    }
                    ref other => panic!("{dial}: {other:?}"),
                }
            }
            // Anything else prints as itself.
            for plain in ["192.168.1.20:7420", "[2001:db8::1]:7420", "[fe80::1]:7420"] {
                assert_eq!(scoped_dial(sa(plain)), plain);
            }
            let global = SocketAddr::V6(SocketAddrV6::new(
                "2001:db8::1".parse().unwrap(),
                7420,
                0,
                3,
            ));
            assert_eq!(scoped_dial(global), global.to_string());
        }

        /// Phase 3 step 4: only an IPv6 link-local address with a scope id
        /// has a zone, written as [`zone_name`] writes it.
        #[test]
        fn only_a_scoped_link_local_address_has_a_zone() {
            let v6 = |ip: &str, scope: u32| {
                SocketAddr::V6(SocketAddrV6::new(ip.parse().unwrap(), 7420, 0, scope))
            };
            for (ip, scope) in [("fe80::1", 7), ("febf::1", u32::MAX)] {
                assert_eq!(link_local_zone(v6(ip, scope)), Some(zone_name(scope)));
            }
            #[cfg(unix)]
            {
                let (lo, index) = loopback_interface();
                assert_eq!(link_local_zone(v6("fe80::1", index)).as_deref(), Some(lo));
            }
            for none in [
                v6("fe80::1", 0),
                v6("fec0::1", 7),
                v6("fd00::1", 7),
                v6("::ffff:192.168.1.5", 7),
                sa("192.168.1.5:7420"),
            ] {
                assert_eq!(link_local_zone(none), None, "{none}");
            }
        }

        /// Windows: an adapter's system name (`loopback_0`, as
        /// `if_indextoname` gives it) resolves to its index.
        #[cfg(windows)]
        #[test]
        fn windows_resolves_the_loopback_adapters_name() {
            use windows_sys::Win32::NetworkManagement::IpHelper::if_indextoname;
            let lo = raven_core::netifs::read()
                .expect("this host's interfaces")
                .into_iter()
                .find(|a| a.ip.is_loopback())
                .expect("the loopback adapter");
            // IF_NAMESIZE (256) bytes and one more: a NUL always ends it.
            let mut buf = [0u8; 257];
            // SAFETY: `buf` holds IF_NAMESIZE bytes, as if_indextoname
            // requires; it writes a NUL-terminated name there or returns null.
            let named = unsafe { if_indextoname(lo.index, buf.as_mut_ptr()) };
            assert!(!named.is_null(), "{lo:?}");
            let name = std::ffi::CStr::from_bytes_until_nul(&buf)
                .unwrap()
                .to_str()
                .unwrap();
            assert_eq!(interface_index(name), Some(lo.index), "{name}");
            assert_eq!(interface_index("no_such_adapter_0"), None);
        }

        #[test]
        fn address_families_are_interleaved_and_deduplicated() {
            let (a, b) = (sa("[2001:db8::1]:1"), sa("[2001:db8::2]:1"));
            let (c, d) = (sa("192.0.2.1:1"), sa("192.0.2.2:1"));
            assert_eq!(
                interleave_families(vec![a, b, c, d, c]),
                vec![a, c, b, d],
                "a dead first family must not hold up the other"
            );
            assert_eq!(interleave_families(vec![c, a, d]), vec![c, a, d]);
            assert!(interleave_families(Vec::new()).is_empty());
        }

        #[tokio::test]
        async fn names_resolve_and_connect_with_fallback() {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            // `localhost` may list ::1 first; the v4-only listener must still
            // be reached through the fallback.
            let (stream, addr) = connect_dial(
                &format!("localhost:{port}"),
                Duration::from_secs(2),
                Duration::from_secs(5),
            )
            .await
            .expect("dial by name");
            assert!(addr.ip().is_loopback() && addr.port() == port);
            assert!(stream.nodelay().unwrap());
            drop(listener);
        }

        #[tokio::test]
        async fn refused_connect_names_the_address_and_returns_promptly() {
            let port = {
                let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
                l.local_addr().unwrap().port()
            };
            let target = format!("127.0.0.1:{port}");
            let err = connect_dial(&target, Duration::from_secs(2), Duration::from_secs(5))
                .await
                .unwrap_err();
            assert!(err.contains(&target), "{err}");
            assert!(err.contains("cannot connect"), "{err}");
            let err = connect_dial("no-such-host.invalid:1", CONNECT_TIMEOUT, CONNECT_BUDGET)
                .await
                .unwrap_err();
            assert!(err.contains("no-such-host.invalid"), "{err}");
        }

        #[test]
        fn log_limiter_folds_a_storm_into_one_line() {
            let limiter = LogLimiter::new(Duration::from_secs(10));
            let t0 = Instant::now();
            let mut lines = 0;
            for i in 0..50_000u32 {
                // 50k events spread over 9 s: still inside one window.
                if limiter
                    .hit_at(t0 + Duration::from_micros(u64::from(i) * 180))
                    .is_some()
                {
                    lines += 1;
                }
            }
            assert_eq!(lines, 1, "a connect/RST storm is one line, not 50k");
            // The next window reports how many were folded in.
            assert_eq!(limiter.hit_at(t0 + Duration::from_secs(11)), Some(50_000));
        }

        fn limits(max_conns: usize, per_ip: usize, hs_per_ip: usize) -> InboundLimits {
            InboundLimits {
                max_conns,
                max_per_ip: per_ip,
                max_handshaking_per_ip: hs_per_ip,
                ..PRODUCTION_INBOUND
            }
        }

        fn ip(s: &str) -> IpAddr {
            s.parse().unwrap()
        }

        impl AdmissionSlot {
            /// Not displaced, not dropped.
            fn is_live(&self) -> bool {
                lock(&self.admission.state).conns.contains_key(&self.id)
            }
        }

        #[test]
        fn admission_enforces_global_and_per_ip_caps() {
            let adm = Admission::new(limits(3, 2, 2));
            let (a, b) = (ip("192.0.2.1"), ip("192.0.2.2"));
            let mut s1 = adm.try_admit(a).expect("first");
            let mut s2 = adm.try_admit(a).expect("second from the same ip");
            assert!(adm.try_admit(a).is_none(), "per-ip cap");
            let mut s3 = adm.try_admit(b).expect("other ip");
            // Authenticated sessions are never displaced: full means full.
            for s in [&mut s1, &mut s2, &mut s3] {
                s.authenticated();
            }
            assert!(adm.try_admit(b).is_none(), "global cap");
            drop(s1);
            assert!(adm.try_admit(b).is_some(), "slot released by drop");
        }

        /// Regression: lingering connections kept the small per-IP cap full, so
        /// a burst of dials from one host (or one NAT) was refused. Only
        /// handshakes count against the small cap; an authenticated session
        /// makes room for the next dial.
        #[test]
        fn authenticated_sessions_do_not_hold_the_handshake_cap() {
            let adm = Admission::new(limits(32, 8, 4));
            let ip: IpAddr = "192.0.2.9".parse().unwrap();
            let mut held: Vec<AdmissionSlot> = (0..4).map(|_| adm.try_admit(ip).unwrap()).collect();
            assert!(adm.try_admit(ip).is_none(), "four handshakes in flight");
            held[0].authenticated();
            held[1].authenticated();
            // Two promoted: two more handshakes fit ...
            for _ in 0..2 {
                held.push(adm.try_admit(ip).expect("room after authentication"));
            }
            assert!(adm.try_admit(ip).is_none(), "handshake cap binds again");
            // ... and once everything is authenticated the total cap (8) is
            // the only limit left.
            for slot in &mut held {
                slot.authenticated();
                slot.authenticated(); // idempotent
            }
            for _ in 0..2 {
                held.push(adm.try_admit(ip).expect("handshake room"));
            }
            assert_eq!(held.len(), 8);
            assert!(adm.try_admit(ip).is_none(), "total per-ip cap still binds");
            // Dropping releases whatever is left.
            held.clear();
            assert!(adm.try_admit(ip).is_some());
        }

        /// Regression: silent pre-auth sockets from a few source addresses
        /// filled the listener and every real peer was refused until they
        /// timed out (and they re-opened at no cost). A newcomer now displaces
        /// the oldest pre-auth connection of the busiest source.
        #[test]
        fn a_pool_full_of_silent_handshakes_still_admits_a_newcomer() {
            // The production shape: 32 slots, 4 pre-auth per source, so 8
            // addresses fill it.
            let adm = Admission::new(limits(32, 8, 4));
            let mut silent: Vec<AdmissionSlot> = (1..=8)
                .flat_map(|host| {
                    let adm = &adm;
                    (0..4).map(move |_| adm.try_admit(ip(&format!("10.0.0.{host}"))).unwrap())
                })
                .collect();
            let stranger = ip("10.0.9.9");
            // A real peer gets in ... and took the oldest silent socket's place.
            let mut peer = adm.try_admit(stranger).expect("newcomer admitted");
            assert!(
                !silent[0].is_live(),
                "the oldest silent socket is displaced"
            );
            assert!(silent[1..].iter().all(AdmissionSlot::is_live));
            // It completes the handshake: its slot is now untouchable.
            peer.authenticated();
            // Silent sockets keep arriving from the attacker's addresses; each
            // one only ever displaces another silent socket.
            for round in 0..64 {
                let host = ip(&format!("10.0.0.{}", 1 + round % 8));
                if let Some(s) = adm.try_admit(host) {
                    silent.push(s);
                }
                assert!(peer.is_live(), "authenticated session survived {round}");
            }
            // And a second real peer is still admitted.
            assert!(adm.try_admit(ip("10.0.9.10")).is_some());
            assert!(peer.is_live());
        }

        /// The victim is the busiest source's oldest pre-auth connection, not
        /// the oldest overall: a lone slow handshake outlives a flood.
        #[test]
        fn displacement_prefers_the_busiest_source() {
            let adm = Admission::new(limits(4, 4, 4));
            let (lone, flood, newcomer) = (ip("192.0.2.1"), ip("192.0.2.2"), ip("192.0.2.3"));
            let first = adm.try_admit(lone).unwrap(); // oldest of all
            let f1 = adm.try_admit(flood).unwrap();
            let f2 = adm.try_admit(flood).unwrap();
            let f3 = adm.try_admit(flood).unwrap();
            let _new = adm.try_admit(newcomer).expect("admitted");
            assert!(first.is_live(), "the lone handshake is spared");
            assert!(!f1.is_live(), "the busiest source gives up its oldest");
            assert!(f2.is_live() && f3.is_live());
        }

        /// A source that already holds as many pre-auth connections as the
        /// busiest one cannot push anyone out, and authenticated sessions are
        /// never displaced.
        #[test]
        fn displacement_never_favours_a_greedy_source_or_touches_sessions() {
            let adm = Admission::new(limits(4, 4, 4));
            let (a, b) = (ip("192.0.2.1"), ip("192.0.2.2"));
            let (sa1, sa2) = (adm.try_admit(a).unwrap(), adm.try_admit(a).unwrap());
            let (sb1, sb2) = (adm.try_admit(b).unwrap(), adm.try_admit(b).unwrap());
            assert!(adm.try_admit(a).is_none(), "equally busy: refused");
            assert!(adm.try_admit(b).is_none(), "equally busy: refused");
            assert!(sa1.is_live() && sa2.is_live() && sb1.is_live() && sb2.is_live());
            // Promote everything: nothing is displaceable any more.
            let mut all = [sa1, sa2, sb1, sb2];
            for s in &mut all {
                s.authenticated();
            }
            assert!(
                adm.try_admit(ip("192.0.2.3")).is_none(),
                "only sessions left"
            );
            assert!(all.iter().all(AdmissionSlot::is_live));
        }

        /// A source over its own caps is refused outright; it never gets to
        /// displace connections of other sources, even when the pool is full.
        #[test]
        fn per_source_caps_refuse_instead_of_displacing() {
            let adm = Admission::new(limits(4, 4, 2));
            let (a, b) = (ip("192.0.2.1"), ip("192.0.2.2"));
            let from_b = [adm.try_admit(b).unwrap(), adm.try_admit(b).unwrap()];
            let from_a = [adm.try_admit(a).unwrap(), adm.try_admit(a).unwrap()];
            assert!(adm.try_admit(a).is_none());
            assert!(from_a.iter().chain(&from_b).all(AdmissionSlot::is_live));
        }

        #[test]
        fn admission_keys_fold_mapped_v4_and_v6_prefixes() {
            let k = |s: &str| admission_key(s.parse().unwrap());
            assert_eq!(k("::ffff:192.0.2.1"), k("192.0.2.1"));
            assert_eq!(k("2001:db8:1:2:aaaa::1"), k("2001:db8:1:2:bbbb::2"));
            assert_ne!(k("2001:db8:1:2::1"), k("2001:db8:1:3::1"));
            let adm = Admission::new(limits(32, 1, 1));
            let _s = adm.try_admit("2001:db8::1".parse().unwrap()).unwrap();
            assert!(
                adm.try_admit("2001:db8::2".parse().unwrap()).is_none(),
                "one host cannot dodge the cap with many addresses in its /64"
            );
        }

        #[test]
        fn dial_reply_budget_fits_one_ipc_response() {
            use raven_core::ipc::{encode_response, IpcResponse, IPC_VERSION};
            let mut budget = DialReplyBudget::new("LAN");
            let big = vec![0xA5u8; 40 * 1024];
            let mut admitted = Vec::new();
            while budget.admit(&big).is_ok() {
                admitted.push(big.clone());
            }
            assert!(!admitted.is_empty());
            let err = budget.admit(&big).unwrap_err();
            assert!(err.starts_with("LAN_DIAL_REPLY_OVERFLOW"));
            // Nothing was marked as sent: the error must not claim delivery
            // (e.g. an oversized RLB1 offer, read before any frame is written).
            assert!(err.contains("(no frames were sent)"), "{err}");
            budget.mark_frames_sent();
            let err = budget.admit(&big).unwrap_err();
            assert!(err.ends_with("(frames were sent)"), "{err}");
            // What the budget admitted is bounded by the IPC frame, not the peer.
            assert!(admitted.len() * big.len() < MAX_IPC_FRAME);
            use base64::Engine;
            let resp = IpcResponse::LanDialResult {
                v: IPC_VERSION,
                frames_b64: admitted
                    .iter()
                    .map(|f| base64::engine::general_purpose::STANDARD.encode(f))
                    .collect(),
            };
            assert!(
                encode_response(&resp).is_ok(),
                "admitted replies must encode"
            );

            let mut budget = DialReplyBudget::new("INTERNET");
            for _ in 0..MAX_DIAL_REPLIES {
                budget.admit(b"ack").unwrap();
            }
            let err = budget.admit(b"ack").unwrap_err();
            assert!(
                err.starts_with("INTERNET_DIAL_REPLY_OVERFLOW"),
                "reply count is capped: {err}"
            );
        }

        fn envelope(kind: EnvType) -> Vec<u8> {
            Envelope {
                env_type: kind as u8,
                flags: 0,
                message_id: [7; 16],
                routing_tag: [8; 16],
                dest_device_hint: 0,
                created_at: 1,
                expires_at: 2,
                hop_limit: 1,
                replication_budget: 1,
                anti_replay_nonce: [9; 12],
                ratchet_header_ciphertext: vec![],
                message_ciphertext: vec![1, 2, 3],
                sender_authentication: vec![0u8; 64],
            }
            .pack()
        }

        const WAITS: ReplyWaits = ReplyWaits {
            first: Duration::from_secs(30),
            idle: Duration::from_secs(2),
        };

        fn rsr1(kind: u8) -> Vec<u8> {
            let mut frame = b"RSR1".to_vec();
            frame.extend_from_slice(&[1, kind]);
            frame.resize(192, 0);
            frame
        }

        #[test]
        fn rsr1_query_and_prekey_stale_expect_a_reply() {
            assert!(expects_reply(&rsr1(1)));
            assert!(expects_reply(&rsr1(3)));
            assert!(!expects_reply(&rsr1(2)));
            assert!(!expects_reply(&rsr1(4)));
            // Unknown version or kind: not a request this build waits on.
            let mut v2 = rsr1(1);
            v2[4] = 2;
            assert!(!expects_reply(&v2));
            assert!(!expects_reply(&rsr1(9)));
        }

        #[test]
        fn rsr1_status_replies_are_terminal() {
            assert!(is_terminal_reply(&rsr1(2)));
            assert!(is_terminal_reply(&rsr1(4)));
            assert!(!is_terminal_reply(&rsr1(1)));
            let mut c = ReplyCollector::new("LAN", WAITS);
            c.begin(b"offer".to_vec(), &[rsr1(1)]).unwrap();
            assert!(!c.first(ReplyWait::Frame(rsr1(2))).unwrap());
            assert_eq!(c.into_replies().len(), 2);
        }

        /// RUP1 (Phase 6b P6.49): requests expect replies, a CHUNK ends none
        /// and CHUNKS_END does; 16 chunks overflow an IPC dial's reply budget
        /// but fit the update exchange's own follow-up dial.
        #[test]
        fn rup1_dials_end_on_their_terminals_and_16_chunks_fit_a_follow_up_dial() {
            use raven_core::update_exchange::{encode, Chunk, Rup1Msg};
            let ask = |first: u32| {
                encode(
                    &[1, 0, 0, first as u8],
                    &Rup1Msg::GetChunks {
                        manifest_digest: [7; 32],
                        first,
                        count: 8,
                    },
                )
                .unwrap()
            };
            let asks = [ask(0), ask(8)];
            assert!(asks.iter().all(|f| expects_reply(f)));
            let chunk = |id: u8, index: u32| {
                encode(
                    &[1, 0, 0, id],
                    &Rup1Msg::Chunk(Chunk {
                        index,
                        bytes: vec![0x5a; 61_440],
                        path: vec![[1; 32]; 11],
                    }),
                )
                .unwrap()
            };
            let end = |id: u8| {
                encode(
                    &[1, 0, 0, id],
                    &Rup1Msg::ChunksEnd {
                        stopped: None,
                        sent: 8,
                    },
                )
                .unwrap()
            };
            assert!(!expects_reply(&chunk(0, 0)) && !is_terminal_reply(&chunk(0, 0)));
            assert!(is_terminal_reply(&end(0)));
            let run = |c: &mut ReplyCollector| -> Result<bool, String> {
                c.begin(b"offer".to_vec(), &asks)?;
                let mut more = true;
                for (id, first) in [(0u8, 0u32), (8, 8)] {
                    for i in 0..8 {
                        more = c.next(ReplyWait::Frame(chunk(id, first + i)))?;
                        assert!(more);
                    }
                    more = c.next(ReplyWait::Frame(end(id)))?;
                }
                Ok(more)
            };
            let mut ipc = ReplyCollector::new("LAN", WAITS);
            assert!(run(&mut ipc)
                .unwrap_err()
                .starts_with("LAN_DIAL_REPLY_OVERFLOW"));
            let mut internal = INTERNAL_REPLY_BUDGET
                .sync_scope(crate::update_exchange::DIAL_REPLY_BUDGET, || {
                    ReplyCollector::new("LAN", WAITS)
                });
            assert!(
                !run(&mut internal).unwrap(),
                "the dial ends after the second CHUNKS_END"
            );
            assert_eq!(internal.into_replies().len(), 1 + 18);
        }

        /// Custody handoff (P5.21): a dial of 16 HANDOFF frames ends after
        /// the 16th HANDOFF_RESULT, not on the idle wait; TAGS + RELEASE +
        /// FETCH end after their three terminal replies (a FETCH_ITEM is
        /// not one); a full page with the TAGS and RELEASE answers fits one
        /// IPC response.
        #[test]
        fn collector_ends_after_handoff_and_tags_terminals() {
            use raven_core::custody_handoff::{Rhw1, TagsAction};
            use raven_core::friend_custody::{
                encode_reply, encode_request, CustodyCode, Rfc1Reply, Rfc1Request,
                MAX_FETCH_PAGE_BYTES, MAX_RFC1_RSO1,
            };
            let id = |salt: u8, i: u8| [salt, 0, 0, 0, 0, 0, 0, i];
            let handoffs: Vec<Vec<u8>> = (0..16u8)
                .map(|i| {
                    encode_request(
                        &id(0xB0, i),
                        &Rfc1Request::Handoff {
                            record: Rhw1::deliver(vec![0x5a; 300]),
                        },
                    )
                })
                .collect();
            assert!(handoffs.iter().all(|f| expects_reply(f)));
            let result = |i: u8| {
                encode_reply(
                    &id(0xB0, i),
                    &Rfc1Reply::HandoffResult {
                        code: CustodyCode::Ok,
                        digest: [i; 32],
                    },
                )
            };
            assert!(is_terminal_reply(&result(0)));
            let mut c = ReplyCollector::new("LAN", WAITS);
            c.begin(b"offer".to_vec(), &handoffs).unwrap();
            assert_eq!(c.first_wait(), WAITS.first);
            assert!(c.first(ReplyWait::Frame(result(0))).unwrap());
            for i in 1..15 {
                assert!(c.next(ReplyWait::Frame(result(i))).unwrap(), "{i}");
            }
            assert!(
                !c.next(ReplyWait::Frame(result(15))).unwrap(),
                "the 16th result ends the dial"
            );
            assert_eq!(c.into_replies().len(), 17);

            // TAGS + RELEASE + FETCH: three terminals.
            let tags = encode_request(
                &id(0xA0, 0),
                &Rfc1Request::Tags {
                    action: TagsAction::Register,
                    entries: vec![([7; 16], 1_000)],
                },
            );
            let release = encode_request(
                &id(0xE0, 0),
                &Rfc1Request::Release {
                    digests: vec![[2; 32]],
                },
            );
            let fetch = encode_request(
                &id(0xF0, 0),
                &Rfc1Request::Fetch {
                    tags: vec![[7; 16]],
                    after: None,
                    max_items: 16,
                },
            );
            let frames = [tags, release, fetch];
            assert!(frames.iter().all(|f| expects_reply(f)));
            let tags_result = encode_reply(
                &id(0xA0, 0),
                &Rfc1Reply::TagsResult {
                    code: CustodyCode::Ok,
                    accepted: 1,
                    conflicts: 0,
                },
            );
            let released = encode_reply(
                &id(0xE0, 0),
                &Rfc1Reply::ReleaseResult {
                    code: CustodyCode::Ok,
                    released: 1,
                },
            );
            let item = encode_reply(
                &id(0xF0, 0),
                &Rfc1Reply::FetchItem {
                    rso1: vec![0x33; 400],
                },
            );
            let end = encode_reply(
                &id(0xF0, 0),
                &Rfc1Reply::FetchEnd {
                    code: CustodyCode::Ok,
                    returned: 1,
                    next: None,
                },
            );
            assert!(!is_terminal_reply(&item));
            let mut c = ReplyCollector::new("LAN", WAITS);
            c.begin(b"offer".to_vec(), &frames).unwrap();
            assert!(c.first(ReplyWait::Frame(tags_result.clone())).unwrap());
            assert!(c.next(ReplyWait::Frame(released.clone())).unwrap());
            assert!(
                c.next(ReplyWait::Frame(item)).unwrap(),
                "an item keeps reading"
            );
            assert!(
                !c.next(ReplyWait::Frame(end.clone())).unwrap(),
                "FETCH_END ends it"
            );
            assert_eq!(c.into_replies().len(), 5);

            // A full page (items while they fit 128 KiB, at least one: here
            // the largest objects) with two TAGS answers, the RELEASE answer
            // and the end fits the reply budget.
            let mut budget = DialReplyBudget::new("LAN");
            budget.admit(b"offer").unwrap();
            for frame in [&tags_result, &tags_result, &released] {
                budget.admit(frame).unwrap();
            }
            let big = encode_reply(
                &id(0xF0, 0),
                &Rfc1Reply::FetchItem {
                    rso1: vec![0x44; MAX_RFC1_RSO1],
                },
            );
            let mut page = 0;
            loop {
                budget.admit(&big).unwrap();
                page += MAX_RFC1_RSO1;
                if page + MAX_RFC1_RSO1 > MAX_FETCH_PAGE_BYTES {
                    break;
                }
            }
            budget.admit(&end).unwrap();
        }

        #[test]
        fn old_collector_semantics_unchanged_for_rvn1() {
            for kind in [EnvType::Message, EnvType::Ack, EnvType::AliasGossip] {
                let frame = envelope(kind);
                assert_eq!(expects_reply(&frame), kind == EnvType::Message);
                assert_eq!(is_terminal_reply(&frame), kind == EnvType::Ack);
            }
        }

        #[test]
        fn collector_counts_only_frames_that_get_replies() {
            let message = envelope(EnvType::Message);
            let ack = envelope(EnvType::Ack);
            // A Message gets an ACK; an ACK or an RLB1 refresh gets nothing.
            assert!(expects_reply(&message));
            assert!(!expects_reply(&ack));
            assert!(!expects_reply(b"RLB1-refresh"));
            assert!(is_terminal_reply(&ack));
            assert!(!is_terminal_reply(&message));

            let mut c = ReplyCollector::new("LAN", WAITS);
            c.begin(b"offer".to_vec(), std::slice::from_ref(&message))
                .unwrap();
            assert_eq!(c.first_wait(), WAITS.first);
            // A non-terminal frame keeps the dial reading ...
            assert!(c.first(ReplyWait::Frame(b"noise".to_vec())).unwrap());
            // ... the ACK ends it.
            assert!(!c.next(ReplyWait::Frame(ack.clone())).unwrap());
            assert_eq!(c.into_replies().len(), 3);

            // Two frames that get replies need two terminal replies.
            let mut c = ReplyCollector::new("LAN", WAITS);
            c.begin(b"offer".to_vec(), &[message.clone(), message.clone()])
                .unwrap();
            assert!(c.first(ReplyWait::Frame(ack.clone())).unwrap());
            assert!(!c.next(ReplyWait::Frame(ack)).unwrap());

            // Nothing is answered: the short wait applies, not the patient one.
            let mut c = ReplyCollector::new("LAN", WAITS);
            c.begin(b"offer".to_vec(), &[b"RLB1-refresh".to_vec()])
                .unwrap();
            assert_eq!(c.first_wait(), WAITS.idle);
            assert!(!c.first(ReplyWait::Closed("eof".into())).unwrap());
        }

        #[test]
        fn collector_reports_closed_and_idle_distinctly() {
            let message = envelope(EnvType::Message);
            let mut c = ReplyCollector::new("INTERNET", WAITS);
            c.begin(b"offer".to_vec(), std::slice::from_ref(&message))
                .unwrap();
            c.mark_frames_sent();
            let err = c
                .first(ReplyWait::Closed("peer closed the connection".into()))
                .unwrap_err();
            assert!(err.starts_with("INTERNET_DIAL_PEER_CLOSED"), "{err}");
            assert!(err.contains("retry is safe"), "{err}");
            // An unreadable reply is not "closed".
            let mut c = ReplyCollector::new("LAN", WAITS);
            c.begin(b"offer".to_vec(), std::slice::from_ref(&message))
                .unwrap();
            let err = c
                .first(ReplyWait::Closed("aead: decryption failed".into()))
                .unwrap_err();
            assert!(err.starts_with("LAN_DIAL_BAD_REPLY"), "{err}");
            assert!(err.contains("aead: decryption failed"), "{err}");

            // Silence is "no reply yet", not a failure; after a reply it is a
            // normal end.
            let mut c = ReplyCollector::new("LAN", WAITS);
            c.begin(b"offer".to_vec(), &[message]).unwrap();
            assert!(!c.first(ReplyWait::Idle).unwrap());
            assert_eq!(c.into_replies(), vec![b"offer".to_vec()]);
        }

        #[tokio::test(start_paused = true)]
        async fn handshake_hang_ups_are_retried_but_other_errors_are_not() {
            use std::sync::atomic::{AtomicU32, Ordering};
            // Two hang-ups (a listener at its cap), then success.
            let calls = AtomicU32::new(0);
            let got = with_handshake_retries(|| {
                let n = calls.fetch_add(1, Ordering::SeqCst);
                async move {
                    if n < 2 {
                        Err(PEER_CLOSED.to_string())
                    } else {
                        Ok(n)
                    }
                }
            })
            .await;
            assert_eq!(got, Ok(2));

            // Always hanging up: bounded, and the error says what happened.
            let calls = AtomicU32::new(0);
            let err = with_handshake_retries(|| {
                calls.fetch_add(1, Ordering::SeqCst);
                async { Err::<(), _>(PEER_CLOSED.to_string()) }
            })
            .await
            .unwrap_err();
            assert_eq!(calls.load(Ordering::SeqCst), HANDSHAKE_ATTEMPTS);
            assert!(err.contains("3 attempts"), "{err}");
            assert!(err.contains("connection limit"), "{err}");

            // An authentication failure is final: no retry.
            let calls = AtomicU32::new(0);
            let err = with_handshake_retries(|| {
                calls.fetch_add(1, Ordering::SeqCst);
                async { Err::<(), _>("bind: identity mismatch".to_string()) }
            })
            .await
            .unwrap_err();
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert_eq!(err, "bind: identity mismatch");
        }

        /// Regression: the whole listener start-up was restarted after a bind
        /// failure, so a busy port made the daemon re-run the preflight (and
        /// re-take the chat-history / stage locks `ash` sends need) over and
        /// over. Steps are retried on their own: the preflight is not repeated
        /// for a bind that keeps failing.
        #[tokio::test(start_paused = true)]
        async fn each_startup_step_is_retried_on_its_own() {
            use std::sync::atomic::{AtomicU32, Ordering};
            let (preflights, binds) = (AtomicU32::new(0), AtomicU32::new(0));
            let identity = retry_until_ok("test", || {
                preflights.fetch_add(1, Ordering::SeqCst);
                async { Ok::<_, String>("identity") }
            })
            .await;
            let listener = retry_until_ok("test", || {
                let n = binds.fetch_add(1, Ordering::SeqCst);
                async move {
                    if n < 3 {
                        Err("bind: address in use".to_string())
                    } else {
                        Ok("listener")
                    }
                }
            })
            .await;
            assert_eq!((identity, listener), ("identity", "listener"));
            assert_eq!(preflights.load(Ordering::SeqCst), 1);
            assert_eq!(binds.load(Ordering::SeqCst), 4);
        }

        /// E1 (Windows, Lock v2): the LAN listener's first try after an
        /// unlock failed, "lan_direct failed: Access is denied. (os error
        /// 5)", and it came up a second later. In the seconds after an
        /// unlock a failed step is tried again after 200 ms with no line;
        /// one that still fails after them is logged as before.
        #[tokio::test(start_paused = true)]
        async fn a_step_failing_right_after_an_unlock_is_retried_quietly() {
            use std::sync::atomic::{AtomicU32, Ordering};
            use tokio::time::Instant;
            let unlocked = Instant::now();
            let settling = || unlocked.elapsed() < Duration::from_secs(5);
            let denied = || Err::<&str, _>("Access is denied. (os error 5)".to_string());
            let mut lines: Vec<(Duration, String)> = Vec::new();
            // Refused twice right after the unlock, then free: up at once,
            // and nothing said.
            let tries = AtomicU32::new(0);
            let up = retry_until_ok_as(
                "lan_direct",
                || {
                    let n = tries.fetch_add(1, Ordering::SeqCst);
                    async move {
                        if n < 2 {
                            denied()
                        } else {
                            Ok("listener")
                        }
                    }
                },
                settling,
                |line| lines.push((unlocked.elapsed(), line)),
            )
            .await;
            assert_eq!(up, "listener");
            assert_eq!(tries.load(Ordering::SeqCst), 3);
            assert_eq!(unlocked.elapsed(), UNLOCK_RETRY * 2);
            assert!(lines.is_empty(), "{lines:?}");
            // Still refused when the seconds are over: said then, and retried
            // with the backoff.
            let tries = AtomicU32::new(0);
            retry_until_ok_as(
                "lan_direct",
                || {
                    tries.fetch_add(1, Ordering::SeqCst);
                    async move {
                        if unlocked.elapsed() < Duration::from_secs(6) {
                            denied()
                        } else {
                            Ok("listener")
                        }
                    }
                },
                settling,
                |line| lines.push((unlocked.elapsed(), line)),
            )
            .await;
            let said: Vec<&str> = lines.iter().map(|(_, l)| l.as_str()).collect();
            assert_eq!(
                said,
                [
                    "lan_direct failed: Access is denied. (os error 5)",
                    "lan_direct: unavailable; IPC and the other transports keep running; \
                     retrying in 1s",
                ]
            );
            assert!(lines[0].0 >= Duration::from_secs(5), "{lines:?}");
            assert!(
                tries.load(Ordering::SeqCst) > 20,
                "quick tries in the window"
            );
        }

        #[tokio::test(start_paused = true)]
        async fn a_slow_startup_step_is_announced_once_and_still_awaited() {
            use std::sync::atomic::{AtomicU32, Ordering};
            let notices = AtomicU32::new(0);
            let slow = with_slow_notice_then(
                Duration::from_secs(15),
                async {
                    tokio::time::sleep(Duration::from_secs(40)).await;
                    7
                },
                || {
                    notices.fetch_add(1, Ordering::SeqCst);
                },
            )
            .await;
            assert_eq!(slow, 7, "the step's result is not lost");
            assert_eq!(notices.load(Ordering::SeqCst), 1);
            let fast = with_slow_notice_then(Duration::from_secs(15), async { 8 }, || {
                notices.fetch_add(1, Ordering::SeqCst);
            })
            .await;
            assert_eq!(fast, 8);
            assert_eq!(notices.load(Ordering::SeqCst), 1, "a fast step is silent");
        }

        #[test]
        fn hang_up_error_kinds_share_one_text() {
            use std::io::{Error, ErrorKind};
            for kind in [
                ErrorKind::UnexpectedEof,
                ErrorKind::ConnectionReset,
                ErrorKind::ConnectionAborted,
                ErrorKind::BrokenPipe,
            ] {
                assert_eq!(io_error_text(&Error::from(kind)), PEER_CLOSED);
            }
            assert_ne!(
                io_error_text(&Error::from(ErrorKind::PermissionDenied)),
                PEER_CLOSED
            );
        }

        /// A listener whose accept() fails (fd exhaustion, an aborted
        /// connection) keeps serving, caps what it admits, and gives a
        /// finished connection's slot back.
        #[tokio::test]
        async fn serve_connections_survives_accept_errors_and_recycles_slots() {
            use std::io::{Error, ErrorKind};
            let listener = Arc::new(TcpListener::bind("127.0.0.1:0").await.unwrap());
            let addr = listener.local_addr().unwrap();
            let mut script = vec![
                Err(Error::from_raw_os_error(24)), // EMFILE
                Err(Error::from(ErrorKind::ConnectionAborted)),
            ]
            .into_iter();
            let accept_from = listener.clone();
            let (started_tx, mut started_rx) = mpsc::unbounded_channel::<()>();
            let (done_tx, mut done_rx) = mpsc::unbounded_channel::<()>();
            let server = tokio::spawn(serve_connections(
                "test",
                move || {
                    let scripted = script.next();
                    let listener = accept_from.clone();
                    async move {
                        match scripted {
                            Some(err) => err,
                            None => listener.accept().await,
                        }
                    }
                },
                limits(2, 2, 2),
                move |mut stream, slot| {
                    let (started, done) = (started_tx.clone(), done_tx.clone());
                    async move {
                        started.send(()).unwrap();
                        // Hold the slot until the dialer hangs up.
                        let mut sink = Vec::new();
                        let _ = stream.read_to_end(&mut sink).await;
                        drop(slot);
                        done.send(()).unwrap();
                        Ok(())
                    }
                },
            ));

            let first = TcpStream::connect(addr).await.unwrap();
            let _second = TcpStream::connect(addr).await.unwrap();
            started_rx.recv().await.unwrap();
            started_rx.recv().await.unwrap();

            // Over the cap: accepted by the kernel, then dropped by the server.
            let mut third = TcpStream::connect(addr).await.unwrap();
            let mut buf = [0u8; 1];
            assert!(matches!(third.read(&mut buf).await, Ok(0) | Err(_)));

            // The dialer is done: its slot comes back and the next dial is served.
            drop(first);
            done_rx.recv().await.unwrap();
            let _fourth = TcpStream::connect(addr).await.unwrap();
            started_rx.recv().await.unwrap();
            assert!(!server.is_finished(), "the accept loop never ends");
            server.abort();
        }

        /// A pre-auth connection displaced by a newcomer is cut (its handler
        /// is dropped, the socket closes) and the newcomer is served.
        #[tokio::test]
        async fn serve_connections_cuts_a_displaced_pre_auth_connection() {
            use std::io::{Error, ErrorKind};
            let listener = Arc::new(TcpListener::bind("127.0.0.1:0").await.unwrap());
            let addr = listener.local_addr().unwrap();
            // Loopback is one source address and the quotas are per source, so
            // the accept side stamps each socket with a scripted one.
            let mut sources = ["192.0.2.1", "192.0.2.2", "192.0.2.3"]
                .into_iter()
                .map(|s| SocketAddr::new(ip(s), 4000));
            let (started_tx, mut started_rx) = mpsc::unbounded_channel::<()>();
            let server = tokio::spawn(serve_connections(
                "test",
                move || {
                    let (listener, source) = (listener.clone(), sources.next());
                    async move {
                        let (stream, _) = listener.accept().await?;
                        Ok((stream, source.ok_or_else(|| Error::from(ErrorKind::Other))?))
                    }
                },
                limits(2, 2, 2),
                move |mut stream, slot| {
                    let started = started_tx.clone();
                    async move {
                        // Never authenticates: waits for the peer to hang up.
                        let _slot = slot;
                        started.send(()).unwrap();
                        let mut sink = Vec::new();
                        let _ = stream.read_to_end(&mut sink).await;
                        Ok(())
                    }
                },
            ));

            let mut oldest = TcpStream::connect(addr).await.unwrap();
            started_rx.recv().await.unwrap();
            let _second = TcpStream::connect(addr).await.unwrap();
            started_rx.recv().await.unwrap();

            // Full of pre-auth connections: the third dial gets in, and the
            // oldest silent one is hung up on.
            let _third = TcpStream::connect(addr).await.unwrap();
            started_rx.recv().await.unwrap();
            let mut buf = [0u8; 1];
            let cut = tokio::time::timeout(Duration::from_secs(30), oldest.read(&mut buf))
                .await
                .expect("the displaced connection is closed");
            assert!(matches!(cut, Ok(0) | Err(_)), "{cut:?}");
            assert!(!server.is_finished(), "the accept loop never ends");
            server.abort();
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FrameReadError {
    Closed,
    Truncated,
    InvalidLength,
    IdleDeadline,
    FrameDeadline,
}

#[derive(Parser, Debug)]
#[command(name = "raven-node", about = "RAVEN serverless local node")]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Create a new identity in --data-dir (prints ADDRESS only, never the seed).
    Init {
        #[arg(long, default_value_os_t = raven_core::default_raven_data_dir())]
        data_dir: PathBuf,
    },
    /// Print public address for this data dir.
    Address {
        #[arg(long, default_value_os_t = raven_core::default_raven_data_dir())]
        data_dir: PathBuf,
    },
    /// Run listener; optionally send one message then wait for ACK.
    Run {
        #[arg(long, default_value_os_t = raven_core::default_raven_data_dir())]
        data_dir: PathBuf,
        #[arg(long, default_value = "127.0.0.1:0")]
        listen: String,
        /// Optional peer to dial (host:port).
        #[arg(long)]
        peer: Option<String>,
        /// Peer Ed25519 public key hex (32 bytes) for seal + verify.
        #[arg(long)]
        peer_pub_hex: Option<String>,
        /// REMOVED for security: plaintext on argv is refused. Use `--send-stdin`.
        #[arg(long, hide = true)]
        send: Option<String>,
        /// Read one plaintext line from stdin (secure). Never puts body on argv/`ps`.
        #[arg(long, default_value_t = false)]
        send_stdin: bool,
        /// Secure ATSAM session mode. The current daemon refuses origination
        /// until a persisted authenticated session is available. Lab builds
        /// may explicitly request `unsafe-interim`.
        #[arg(long, default_value = "atsam")]
        body_mode: String,
        /// Write bound listen address to this file (for demo scripts).
        #[arg(long)]
        write_addr: Option<PathBuf>,
        /// Write public key hex to this file (safe — public only).
        #[arg(long)]
        write_pub: Option<PathBuf>,
        /// Exit after successful send+ACK or after receiving N messages.
        #[arg(long, default_value_t = 0)]
        exit_after_recv: u32,
        #[arg(long, default_value_t = false)]
        exit_after_ack: bool,
        /// How long to run max (seconds).
        #[arg(long, default_value_t = 30)]
        timeout_secs: u64,
        /// Seal plaintext to this pub (A→C via bridge). Defaults to peer_pub_hex.
        #[arg(long)]
        seal_to_pub_hex: Option<String>,
        /// Verify inbound Message signatures with this pub (C verifies A).
        #[arg(long)]
        origin_pub_hex: Option<String>,
        /// Verify ACK signatures with this pub (A verifies C). Defaults to peer_pub_hex.
        #[arg(long)]
        ack_pub_hex: Option<String>,
    },
    /// Bridge daemon: LAN + mock-BLE opaque forward (survives ash exit).
    Bridge {
        #[arg(long, default_value_os_t = raven_core::default_raven_data_dir())]
        data_dir: PathBuf,
        #[arg(long, default_value = "127.0.0.1:0")]
        lan_listen: String,
        #[arg(long, default_value = "127.0.0.1:0")]
        ble_listen: String,
        #[arg(long)]
        write_lan_addr: Option<PathBuf>,
        #[arg(long)]
        write_ble_addr: Option<PathBuf>,
        #[arg(long)]
        write_status: Option<PathBuf>,
        /// 0 = run until killed (normal daemon).
        #[arg(long, default_value_t = 0)]
        timeout_secs: u64,
    },
    /// Print bridge/policy status (safe fields only).
    Status {
        #[arg(long, default_value_os_t = raven_core::default_raven_data_dir())]
        data_dir: PathBuf,
    },
    /// Replay pending queue items to peer (crash recovery).
    Flush {
        #[arg(long, default_value_os_t = raven_core::default_raven_data_dir())]
        data_dir: PathBuf,
        #[arg(long)]
        peer: String,
        #[arg(long)]
        peer_pub_hex: String,
        #[arg(long, default_value_t = 15)]
        timeout_secs: u64,
    },
    /// Always-on local IPC (UDS on Unix, named pipe on Windows) for ash ↔ raven-node.
    #[cfg(any(unix, windows))]
    Ipc {
        #[arg(long, default_value_os_t = raven_core::default_raven_data_dir())]
        data_dir: PathBuf,
        /// Optional forward queue path for status.pending.
        #[arg(long)]
        forward_db: Option<PathBuf>,
    },
    /// Always-on daemon: bridge + IPC together (launchd/systemd/Task Scheduler).
    #[cfg(any(unix, windows))]
    Service {
        #[arg(long, default_value_os_t = raven_core::default_raven_data_dir())]
        data_dir: PathBuf,
        /// LAN direct listen address: `auto` (every network of this
        /// computer, IPv4 and IPv6, local sources only, once its gate is
        /// live; until then 0.0.0.0:7420), `auto:PORT`, or IP:PORT (any
        /// source). A plain `auto` takes the port this profile picked, where
        /// it picked one (Phase 6b, random LAN port). `raven lan off` keeps
        /// it closed.
        #[arg(long, default_value = raven_core::LAN_LISTEN_AUTO)]
        lan_listen: String,
        #[arg(long, default_value = raven_core::DEFAULT_BLE_LISTEN)]
        ble_listen: String,
        /// Internet direct (RIH1) listen address, e.g. 0.0.0.0:7422 (a bare IP
        /// gets port 7422). Opt-in: without this flag RAVEN_INTERNET_LISTEN, then
        /// node_policy.json (`raven node internet on`) decide; an empty value is
        /// off. Needs INTERNET_DIRECT_PRODUCTION_ENABLED (or the debug lab unlock).
        #[arg(long)]
        internet_listen: Option<String>,
        /// libp2p carrier (P3): a port (every interface, IPv4 + IPv6, TCP +
        /// QUIC; default port 7423 with `on`), IP:PORT or `off`. `relay` is
        /// retired: it listens on 7423 anyway (test builds:
        /// RAVEN_LAB_P2P_RELAY_ONLY=1). Opt-in: without this flag
        /// RAVEN_P2P_LISTEN, then node_policy.json (`raven node p2p on`)
        /// decide. Needs P2P_PRODUCTION_ENABLED (or the debug lab unlock).
        #[arg(long, value_name = "PORT|IP:PORT|relay|off")]
        p2p_listen: Option<String>,
        /// A relay to keep a reservation on: its multiaddr ending in
        /// /p2p/<relay PeerId> (repeatable, at most 2 relay addresses; two
        /// addresses of one relay (TCP 7423 and TCP 443) are one relay with a
        /// fallback; else RAVEN_P2P_RELAYS, comma separated, then
        /// node_policy.json). None is compiled in.
        #[arg(long, value_name = "MULTIADDR")]
        p2p_relay: Vec<String>,
        /// HTTPS proxy for relay dials over WebSocket/TLS: `auto` (the
        /// environment's HTTPS_PROXY, then the system settings), `off`, or
        /// http://host:port; else RAVEN_P2P_PROXY, then node_policy.json. A
        /// user name and password go only in RAVEN_P2P_PROXY: other local
        /// users can read a command line. A bad value stops the p2p host.
        /// Needs WSS_PROXY_PRODUCTION_ENABLED (or the debug lab unlock).
        #[arg(long, value_name = "auto|off|URL")]
        p2p_proxy: Option<String>,
        /// Relay for your verified contacts with this profile's OWN relay key
        /// (folder friend_relay/, port 7427), like `raven relay offer on`;
        /// RAVEN_P2P_RELAY=1 likewise. A saved `raven relay offer off` wins
        /// over it, and hide my IP for every contact stops it. Never under
        /// your PeerId. Needs FRIEND_RELAY_PRODUCTION_ENABLED (or the debug
        /// lab unlock).
        #[arg(long, default_value_t = false)]
        relay: bool,
        /// Same as --relay (every verified contact may use it); an open relay
        /// for anyone must be a dedicated `raven-node relay --open`.
        #[arg(long, default_value_t = false)]
        relay_open: bool,
        #[arg(long, default_value_t = 0)]
        timeout_secs: u64,
    },
    /// Dedicated Circuit Relay v2 relay for friends (P3). Holds no Raven
    /// identity: only its libp2p key (relay_key.ed25519) in --data-dir, which
    /// must be a folder of its own. Only PeerIds in relay_allow.json may
    /// reserve (`raven --data-dir <dir> relay allow …`). Needs
    /// P2P_PRODUCTION_ENABLED (or the debug lab unlock). One command per OS:
    /// docs/RELAY_KIT.md.
    ///
    /// Exit codes: 0 stopped when asked (SIGTERM, Ctrl-C) or --check passed;
    /// 1 any other failure; 2 bad flags (also --wss while WSS is held:
    /// WSS_HOLD); 3 held (the P2P gate is closed); 4 a listen port is busy or
    /// needs a privilege; 5 the folder holds a Raven profile or another relay
    /// runs in it.
    Relay {
        /// The relay's own folder (not a Raven profile).
        #[arg(long)]
        data_dir: PathBuf,
        /// Port (every interface, IPv4 + IPv6, TCP + QUIC) or IP:PORT.
        #[arg(long, default_value = "7423", value_name = "PORT|IP:PORT")]
        listen: String,
        /// Serve anyone, not just the allow-list (stricter limits).
        #[arg(long, default_value_t = false)]
        open: bool,
        /// Also answer AutoNAT v2 reachability probes (it then learns the
        /// addresses it is asked to probe).
        #[arg(long, default_value_t = false)]
        autonat_server: bool,
        /// A public address to name in reservations besides the listeners,
        /// e.g. /ip4/203.0.113.7/tcp/7423 or /dns4/relay.example.com/tcp/7423.
        #[arg(long, value_name = "MULTIADDR")]
        external: Vec<String>,
        /// Also listen on this TCP port (repeatable, at most 2), e.g. 443 for
        /// networks that let only HTTPS out; LOCAL:PUBLIC when a router or
        /// firewall maps PUBLIC to LOCAL (7443:443). Ports below 1024 need a
        /// privilege on Linux (the relay kit's unit grants
        /// CAP_NET_BIND_SERVICE).
        #[arg(long, value_name = "LOCAL[:PUBLIC]")]
        also_tcp: Vec<String>,
        /// The public IP or DNS name friends reach this relay at: names it
        /// with every listening port (like --external) for reservations and
        /// `raven relay card`.
        #[arg(long, value_name = "HOST")]
        public_host: Option<String>,
        /// Also serve WebSocket over TLS on this TCP port (every interface)
        /// or IP:PORT, e.g. 443 for networks that let only web traffic out.
        /// The port takes raw libp2p too, so it replaces a raw TCP listener
        /// on the same port (--listen, --also-tcp). Lab-only in this build
        /// (WSS_PRODUCTION_ENABLED=false: exit 2, WSS_HOLD).
        #[arg(long, value_name = "PORT|IP:PORT")]
        wss: Option<String>,
        /// The certificate chain for --wss (PEM, leaf first), with
        /// --wss-key. Without them a self-signed certificate is made at each
        /// start.
        #[arg(long, value_name = "FULLCHAIN.PEM")]
        wss_cert: Option<PathBuf>,
        /// The private key of --wss-cert (PEM).
        #[arg(long, value_name = "PRIVKEY.PEM")]
        wss_key: Option<PathBuf>,
        /// A DNS name or IP address for the self-signed --wss certificate
        /// (repeatable).
        #[arg(long, value_name = "DNS")]
        wss_name: Vec<String>,
        /// Log the counts at most this often, in seconds (only when they
        /// changed).
        #[arg(
            long,
            value_name = "SECS",
            default_value_t = 30,
            value_parser = clap::value_parser!(u64).range(30..=3600)
        )]
        counts_every: u64,
        /// Check the gate, the folder and every listen port, create nothing,
        /// and exit (0 ok, 3 held, 4 a port problem, 5 the folder). Prints
        /// ports only, never an address.
        #[arg(long, default_value_t = false)]
        check: bool,
        /// Limits (each is capped at its hard maximum; see `raven relay status`).
        #[arg(long)]
        max_reservations: Option<usize>,
        #[arg(long)]
        max_circuits: Option<usize>,
        /// Bytes one circuit may carry (both directions).
        #[arg(long)]
        circuit_bytes: Option<u64>,
        #[arg(long)]
        circuit_secs: Option<u64>,
        #[arg(long)]
        reservation_secs: Option<u64>,
    },
    /// Check, from outside the relay's network, that each relay address
    /// answers as the relay its /p2p/ PeerId names (a port forward, a
    /// firewall, a stale card). It dials with a throwaway key: no Raven
    /// identity, nothing reserved. Prints `<tcp|quic>/<port>: <result>`,
    /// never an IP or PeerId. Exit 0 when every address answers, 1
    /// otherwise, 2 bad addresses, 3 held (the P2P gate is closed).
    RelayProbe {
        /// A relay address ending in /p2p/<relay PeerId> (1 to 6), e.g. the
        /// via= lines of `raven relay card`.
        #[arg(required = true, num_args = 1..=6, value_name = "VIA")]
        via: Vec<String>,
    },
    /// Report BLE adapter selection (mock vs platform) and the nearby
    /// carrier's gate and backend. Opens no radio. Safe fields only.
    BleStatus,
    /// Print the LAN listen address the installers give the service:
    /// `auto` once `--lan-listen auto` is live in this build, else
    /// 127.0.0.1:7420 (this computer only); with `--data-dir`, on the port
    /// that profile picked where it picked one (`auto:PORT`,
    /// 127.0.0.1:PORT). Opens and writes nothing; exits 0.
    #[command(hide = true)]
    LanDefault {
        /// The profile whose LAN port to use (read from its
        /// node_policy.json; a missing or unreadable one: the default port).
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },
    /// Lab only (debug builds, with RAVEN_LAB_TEST_A=1 and
    /// RAVEN_LAB_NEARBY=1): serve the fake Bluetooth radio (the nearby
    /// "ether") that lab raven-nodes started with
    /// RAVEN_LAB_NEARBY_ETHER=127.0.0.1:PORT share. Loopback only; runs
    /// until stopped. Not in release builds.
    #[cfg(debug_assertions)]
    #[command(hide = true)]
    NearbyEther {
        /// Loopback IP:PORT to listen on (port 0: the OS picks one).
        #[arg(long, default_value = "127.0.0.1:0")]
        listen: SocketAddr,
        /// Print the port on stdout (one line) once listening.
        #[arg(long)]
        print_port: bool,
        /// ATT MTU of every link, both ways (23 to 517; a frame is at most
        /// MTU - 3 bytes, and under 67 no knock starts).
        #[arg(long, default_value_t = nearby::fake::MAX_ATT_MTU)]
        mtu: usize,
        /// Air rate of each link direction in bytes per second (0: no
        /// limit).
        #[arg(long, default_value_t = 0)]
        rate: u32,
        /// Delay of every frame, in milliseconds.
        #[arg(long, default_value_t = 0)]
        latency_ms: u64,
        /// Lose the frame after this many crossed the ether (once).
        #[arg(long)]
        drop_after: Option<u64>,
        /// Cut the link carrying the frame after this many crossed the
        /// ether (once).
        #[arg(long)]
        disconnect_after: Option<u64>,
    },
    /// Lab only (debug builds): the Tor helper's local protocol with no Tor
    /// network (RAVEN_ONION_CARRIER_V1 §6). raven-node starts it instead of
    /// raven-tor-helper when RAVEN_LAB_TOR_LOOPBACK=<directory> is set; its
    /// "onion services" are loopback ports registered in that directory.
    /// Reads its config on stdin; exits when stdin closes. Not in release
    /// builds.
    #[cfg(debug_assertions)]
    #[command(hide = true)]
    TorLoopbackHelper {
        /// The directory the loopback helpers of one test share.
        #[arg(long)]
        registry: PathBuf,
    },
}

/// Milliseconds since the Unix epoch; a clock set before 1970 reads as 0
/// instead of panicking the daemon.
impl Commands {
    /// The profile directory a subcommand works in, if it takes one.
    fn data_dir(&self) -> Option<&Path> {
        match self {
            Commands::Init { data_dir }
            | Commands::Address { data_dir }
            | Commands::Status { data_dir }
            | Commands::Run { data_dir, .. }
            | Commands::Bridge { data_dir, .. }
            | Commands::Flush { data_dir, .. } => Some(data_dir),
            #[cfg(any(unix, windows))]
            Commands::Ipc { data_dir, .. } | Commands::Service { data_dir, .. } => Some(data_dir),
            Commands::Relay { data_dir, .. } => Some(data_dir),
            // `lan-default` only reads one setting of its profile, and
            // always answers.
            Commands::RelayProbe { .. } | Commands::BleStatus | Commands::LanDefault { .. } => None,
            #[cfg(debug_assertions)]
            Commands::NearbyEther { .. } | Commands::TorLoopbackHelper { .. } => None,
        }
    }
}

/// `raven lan off` (Phase 3) for this process from node_policy.json, and the
/// meeting time of `raven lan on --for` (P3.C2, [`lan_meeting`]): the LAN
/// listener, LAN dials and custody links over LAN follow them from the start,
/// IPC `SetLan` from then on, and the meeting watch (`watch_meeting`) closes
/// LAN when the meeting time comes. A policy that cannot be read keeps LAN
/// off (owner decision: fail closed; `raven lan on` repairs the file).
#[cfg(any(unix, windows))]
fn seed_lan_switch(data_dir: &Path) {
    lan_meeting::seed(data_dir);
}

/// The meeting watch ([`lan_meeting::run`]), supervised like a transport: it
/// opens no port and dials nothing, and the service never ends because of it.
#[cfg(any(unix, windows))]
fn watch_meeting(data_dir: &Path) -> tokio::task::JoinHandle<Infallible> {
    let data_dir = data_dir.to_path_buf();
    // It reads the sealed meeting time: not while Raven is locked.
    tokio::spawn(supervise_unlocked("lan_meeting", None, move || {
        lan_meeting::run(data_dir.clone())
    }))
}

/// What `raven-node lan-default` prints, `auto_live` being
/// [`raven_core::lan_auto_live`]: the installers stay on this computer
/// (127.0.0.1:7420) until the owner signs the Phase 3 LAN amendment and
/// `--lan-listen auto` goes live. `port`: the port the profile picked
/// (Phase 6b P6.36, [`raven_core::node_policy::profile_lan_port`]), in place
/// of the default one.
fn lan_default(auto_live: bool, port: Option<u16>) -> String {
    match (auto_live, port) {
        (true, None) => raven_core::LAN_LISTEN_AUTO.to_owned(),
        (true, Some(port)) => format!("{}:{port}", raven_core::LAN_LISTEN_AUTO),
        (false, port) => format!(
            "127.0.0.1:{}",
            port.unwrap_or(raven_core::paths::DEFAULT_LAN_PORT)
        ),
    }
}

/// `raven-node ble-status`'s nearby lines (they replace the retired
/// CoreBluetooth experiment's): the gate (`held` until the owner signs the
/// nearby waiver, `lab` in a debug lab run), the backend this build would use
/// (with `nearby-radio`: `bluez` on glibc Linux, `winrt` on Windows, `apple`
/// on macOS; else `none`) and that no radio was opened here.
fn ble_status_lines(gate_live: bool, backend: &str) -> Vec<String> {
    vec![
        format!("nearby_gate={}", if gate_live { "lab" } else { "held" }),
        format!("nearby_backend={backend}"),
        "nearby_radio=not_opened".to_owned(),
        "nearby_hint=the running service reports the radio, roles, address privacy and \
         counts (raven status); raven nearby enable turns it on"
            .to_owned(),
    ]
}

fn queue_path(data_dir: &Path) -> PathBuf {
    data_dir.join("queue.sqlite")
}

fn load_or_err(data_dir: &Path) -> Result<Identity, String> {
    raven_core::load_identity_required(data_dir).map_err(|e| e.to_string())
}

/// The profile's identity, created when it has none (`init`, `run` and the
/// service's start): a profile created here picks its random LAN port too
/// (Phase 6b P6.36, while that gate is live).
fn init_identity(data_dir: &Path) -> Result<Identity, String> {
    raven_core::load_or_create_profile_identity(data_dir)
        .map(|(id, _)| id)
        .map_err(|e| e.to_string())
}

async fn write_frame_with_timeout(
    stream: &mut TcpStream,
    bytes: &[u8],
    write_timeout: Duration,
) -> Result<(), String> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err("frame too large".into());
    }
    // One write per frame (a separate 4-byte prefix segment would wait on the
    // peer's delayed ACK).
    let mut framed = Vec::with_capacity(4 + bytes.len());
    framed.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    framed.extend_from_slice(bytes);
    let write = async {
        stream.write_all(&framed).await.map_err(|e| e.to_string())?;
        stream.flush().await.map_err(|e| e.to_string())?;
        Ok(())
    };
    tokio::time::timeout(write_timeout, write)
        .await
        .map_err(|_| "frame write deadline exceeded".to_string())?
}

async fn write_frame(stream: &mut TcpStream, bytes: &[u8]) -> Result<(), String> {
    write_frame_with_timeout(stream, bytes, DEFAULT_CONNECTION_LIMITS.write_timeout).await
}

async fn read_frame_with_limits<R: AsyncRead + Unpin>(
    stream: &mut R,
    limits: ConnectionLimits,
) -> Result<Vec<u8>, FrameReadError> {
    let started = tokio::time::Instant::now();
    let frame_deadline = started + limits.frame_timeout;
    let idle_deadline = started + limits.idle_timeout;
    let header_deadline = if idle_deadline < frame_deadline {
        idle_deadline
    } else {
        frame_deadline
    };

    let mut len_buf = [0u8; 4];
    tokio::time::timeout_at(header_deadline, stream.read_exact(&mut len_buf))
        .await
        .map_err(|_| FrameReadError::IdleDeadline)?
        .map_err(|_| FrameReadError::Closed)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    // Incremental: reject absurd sizes before alloc (DoS note from envelope spec).
    if len == 0 || len > MAX_FRAME_BYTES {
        return Err(FrameReadError::InvalidLength);
    }
    let mut buf = vec![0u8; len];
    tokio::time::timeout_at(frame_deadline, stream.read_exact(&mut buf))
        .await
        .map_err(|_| FrameReadError::FrameDeadline)?
        .map_err(|_| FrameReadError::Truncated)?;
    Ok(buf)
}

#[cfg(feature = "unsafe-demo-crypto")]
fn fingerprint_of(pub_bytes: &[u8]) -> String {
    let mut k = [0u8; 32];
    let n = pub_bytes.len().min(32);
    k[..n].copy_from_slice(&pub_bytes[..n]);
    raven_core::fingerprint::device_fingerprint_v1(&k)
}

fn parse_pub_hex(s: &str) -> Result<[u8; 32], String> {
    let v = hex::decode(s.trim()).map_err(|e| e.to_string())?;
    if v.len() != 32 {
        return Err("peer_pub_hex must be 32 bytes".into());
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    Ok(a)
}

/// A provided-but-malformed key flag is an error, never "not provided":
/// silently dropping `--origin-pub-hex` would verify against `--peer-pub-hex`.
fn parse_pub_flag(flag: &str, value: Option<&String>) -> Result<Option<[u8; 32]>, String> {
    value
        .map(|s| parse_pub_hex(s).map_err(|e| format!("--{flag}: {e}")))
        .transpose()
}

fn build_message_envelope(
    identity: &Identity,
    peer_pub: &[u8; 32],
    plaintext: &[u8],
    message_id: [u8; 16],
    body_mode: &str,
) -> Result<Envelope, String> {
    #[cfg(not(feature = "unsafe-demo-crypto"))]
    {
        let _ = (identity, peer_pub, plaintext, message_id, body_mode);
        Err("ATSAM_SESSION_REQUIRED: no authenticated persisted ATSAM session is available".into())
    }

    #[cfg(feature = "unsafe-demo-crypto")]
    {
        let my_pub = identity.public_key_bytes();
        let my_addr = identity.address();
        let peer_addr = raven_core::encode_address(peer_pub);
        let sealed =
            match body_mode {
                "unsafe-interim" => {
                    let key = derive_pairwise_key(&my_pub, peer_pub);
                    seal_message(&key, plaintext, &my_addr, &peer_addr, &message_id)?
                }
                "atsam" | "" => return Err(
                    "ATSAM_SESSION_REQUIRED: no authenticated persisted ATSAM session is available"
                        .into(),
                ),
                other => {
                    return Err(format!(
                        "unknown body_mode={other} (production: atsam; lab only: unsafe-interim)"
                    ))
                }
            };
        // Lab-only routing material. Production routing tags must be derived from
        // an authenticated session root, never public identity material.
        let k_route = derive_pairwise_key(&my_pub, peer_pub);
        let tag = routing_tag::derive(&k_route, now_ms() / 1000, 0);
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        let mut env = Envelope {
            env_type: EnvType::Message as u8,
            flags: 0,
            message_id,
            routing_tag: tag,
            dest_device_hint: 0,
            created_at: now_ms(),
            expires_at: now_ms() + 86_400_000,
            hop_limit: 8,
            replication_budget: 3,
            anti_replay_nonce: nonce,
            ratchet_header_ciphertext: vec![],
            message_ciphertext: sealed,
            sender_authentication: vec![],
        };
        env.sign_with(identity);
        Ok(env)
    }
}

#[cfg(feature = "unsafe-demo-crypto")]
fn build_ack_envelope(
    identity: &Identity,
    acked_message_id: [u8; 16],
    peer_pub: &[u8; 32],
) -> Envelope {
    let mut ack_nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut ack_nonce);
    let ack = Ack {
        acked_message_id,
        status: STATUS_DELIVERED,
        ack_nonce,
        created_at: now_ms(),
    };
    let sig = ack.sign(identity);
    let body = {
        let mut b = Vec::new();
        b.extend_from_slice(&ack.acked_message_id);
        b.push(ack.status);
        b.extend_from_slice(&ack.ack_nonce);
        b.extend_from_slice(&ack.created_at.to_be_bytes());
        b.extend_from_slice(&sig);
        b
    };
    let mut mid = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut mid);
    let k_route = derive_pairwise_key(&identity.public_key_bytes(), peer_pub);
    let tag = routing_tag::derive(&k_route, now_ms() / 1000, 1);
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let mut env = Envelope {
        env_type: EnvType::Ack as u8,
        flags: 0,
        message_id: mid,
        routing_tag: tag,
        dest_device_hint: 0,
        created_at: now_ms(),
        expires_at: now_ms() + 86_400_000,
        hop_limit: 8,
        replication_budget: 1,
        anti_replay_nonce: nonce,
        ratchet_header_ciphertext: vec![],
        message_ciphertext: body,
        sender_authentication: vec![],
    };
    env.sign_with(identity);
    env
}

struct NodeState {
    identity: Identity,
    queue: OutgoingQueue,
    /// Default peer pub (legacy two-node).
    peer_pub: Option<[u8; 32]>,
    /// Verify Message env signatures (origin A when C is recipient).
    origin_pub: Option<[u8; 32]>,
    /// Verify ACK signatures (C when A is sender).
    ack_pub: Option<[u8; 32]>,
    recv_count: u32,
    got_ack: bool,
}

/// Envelope verification keys. Immutable after startup, so a connection copies
/// them once and checks signatures (Ed25519 over up to 1 MiB) without holding
/// the `NodeState` lock.
#[derive(Clone, Copy, Debug)]
struct VerifyKeys {
    /// Message signatures: origin (A when C is recipient), else peer.
    msg: Option<[u8; 32]>,
    /// ACK signatures: ack key (C when A is sender), else peer.
    #[cfg_attr(not(feature = "unsafe-demo-crypto"), allow(dead_code))]
    ack: Option<[u8; 32]>,
}

/// Stateless half of inbound handling: parse, expiry and envelope signature.
/// Returns the envelope and the key that authenticated it; `Ok(None)` = ignore.
fn authenticate_inbound(
    raw: &[u8],
    keys: VerifyKeys,
) -> Result<Option<(Envelope, [u8; 32])>, String> {
    let env = Envelope::unpack(raw).ok_or_else(|| "malformed envelope".to_string())?;
    if now_ms() > env.expires_at {
        return Ok(None);
    }
    match env.env_type {
        x if x == EnvType::Message as u8 => {
            let peer_pub = keys
                .msg
                .ok_or_else(|| "origin/peer pub required to verify".to_string())?;
            if !env.verify(&peer_pub) {
                return Err("envelope auth failed".into());
            }
            Ok(Some((env, peer_pub)))
        }
        x if x == EnvType::Ack as u8 => {
            #[cfg(not(feature = "unsafe-demo-crypto"))]
            {
                let _ = env;
                Err("ATSAM_SESSION_REQUIRED: plaintext legacy ACK bodies are disabled".into())
            }

            #[cfg(feature = "unsafe-demo-crypto")]
            {
                let peer_pub = keys
                    .ack
                    .ok_or_else(|| "ack/peer pub required to verify".to_string())?;
                if !env.verify(&peer_pub) {
                    return Err("ack envelope auth failed".into());
                }
                Ok(Some((env, peer_pub)))
            }
        }
        _ => Ok(None),
    }
}

impl NodeState {
    fn verify_keys(&self) -> VerifyKeys {
        VerifyKeys {
            msg: self.origin_pub.or(self.peer_pub),
            ack: self.ack_pub.or(self.peer_pub),
        }
    }

    /// Both halves under one borrow (tests; connections split them so the
    /// signature check runs without the lock).
    #[cfg(test)]
    fn handle_inbound(&mut self, raw: &[u8]) -> Result<Option<Vec<u8>>, String> {
        match authenticate_inbound(raw, self.verify_keys())? {
            Some((env, peer_pub)) => self.handle_authenticated(env, peer_pub),
            None => Ok(None),
        }
    }

    /// Stateful half: queue/dedup work for an envelope that
    /// [`authenticate_inbound`] already verified against `peer_pub`.
    fn handle_authenticated(
        &mut self,
        env: Envelope,
        peer_pub: [u8; 32],
    ) -> Result<Option<Vec<u8>>, String> {
        #[cfg(not(feature = "unsafe-demo-crypto"))]
        let _ = peer_pub;
        match env.env_type {
            x if x == EnvType::Message as u8 => {
                match classify_sealed_body(&env.message_ciphertext) {
                    SealClass::InterimStub => {
                        #[cfg(not(feature = "unsafe-demo-crypto"))]
                        {
                            return Err(UNSAFE_INTERIM_DISABLED.into());
                        }

                        #[cfg(feature = "unsafe-demo-crypto")]
                        {
                            let my_addr = self.identity.address();
                            let peer_addr = raven_core::encode_address(&peer_pub);
                            let key =
                                derive_pairwise_key(&self.identity.public_key_bytes(), &peer_pub);
                            let plaintext = unseal_message(
                                &key,
                                &env.message_ciphertext,
                                &peer_addr,
                                &my_addr,
                                &env.message_id,
                            )?;
                            let dup = self
                                .queue
                                .dedup_check_and_insert(&env.message_id, now_ms())
                                .map_err(|e| e.to_string())?;
                            if dup {
                                return Ok(None);
                            }
                            self.recv_count += 1;
                            // Show the actual message to the human, plus who sent it.
                            let peer_fp = crate::fingerprint_of(&peer_pub);
                            let body = String::from_utf8_lossy(&plaintext);
                            let body = body.trim_end_matches(['\r', '\n']);
                            eprintln!("\n── INCOMING from {} ──", peer_fp);
                            for line in body.lines() {
                                eprintln!("│ {}", line);
                            }
                            eprintln!("────────────────────");
                            eprintln!("DELIVERED bytes={}", env.message_ciphertext.len());
                            let ack = build_ack_envelope(&self.identity, env.message_id, &peer_pub);
                            return Ok(Some(ack.pack()));
                        }
                    }
                    SealClass::OpaqueAtsam { proto } => {
                        if !rvna1_wire_plausible(&env.message_ciphertext) {
                            return Err(format!(
                                "opaque ATSAM proto={proto:#x} truncated or bad suite"
                            ));
                        }
                        return Err(format!(
                            "ATSAM_SESSION_REQUIRED: cannot authenticate/decrypt proto={proto:#x}; no delivery ACK emitted"
                        ));
                    }
                    SealClass::Other => {
                        return Err("unsupported message_ciphertext seal class".into());
                    }
                }
                #[allow(unreachable_code)]
                Ok(None)
            }
            x if x == EnvType::Ack as u8 => {
                #[cfg(not(feature = "unsafe-demo-crypto"))]
                {
                    // authenticate_inbound already refuses these; stay closed.
                    Err("ATSAM_SESSION_REQUIRED: plaintext legacy ACK bodies are disabled".into())
                }

                #[cfg(feature = "unsafe-demo-crypto")]
                {
                    if env.message_ciphertext.len() != 16 + 1 + 12 + 8 + 64 {
                        return Err("invalid ack body length".into());
                    }
                    let mut acked = [0u8; 16];
                    acked.copy_from_slice(&env.message_ciphertext[0..16]);
                    let status = env.message_ciphertext[16];
                    let mut ack_nonce = [0u8; 12];
                    ack_nonce.copy_from_slice(&env.message_ciphertext[17..29]);
                    let created_at = u64::from_be_bytes(
                        env.message_ciphertext[29..37]
                            .try_into()
                            .map_err(|_| "ack ts")?,
                    );
                    let mut sig = [0u8; 64];
                    sig.copy_from_slice(&env.message_ciphertext[37..101]);
                    let ack = Ack {
                        acked_message_id: acked,
                        status,
                        ack_nonce,
                        created_at,
                    };
                    if !ack.verify(&sig, &peer_pub) {
                        return Err("ack signature failed".into());
                    }
                    if status != STATUS_DELIVERED {
                        return Err("unsupported ack status for delivery queue".into());
                    }
                    if created_at > now_ms().saturating_add(5 * 60 * 1000)
                        || created_at > env.expires_at
                    {
                        return Err("ack timestamp outside accepted bounds".into());
                    }
                    let queued = self
                        .queue
                        .get(&acked)
                        .map_err(|e| e.to_string())?
                        .ok_or_else(|| {
                            "ack does not match a pending outbound message".to_string()
                        })?;
                    if queued.peer_addr != raven_core::encode_address(&peer_pub) {
                        return Err("ack signer is not the queued recipient".into());
                    }
                    if queued.state == DeliveryState::Delivered {
                        return Ok(None);
                    }
                    let dup = self
                        .queue
                        .dedup_check_and_insert(&env.message_id, now_ms())
                        .map_err(|e| e.to_string())?;
                    if dup {
                        return Ok(None);
                    }
                    self.queue
                        .mark_state(&acked, DeliveryState::Delivered)
                        .map_err(|e| e.to_string())?;
                    self.got_ack = true;
                    eprintln!("ACK delivered");
                    Ok(None)
                }
            }
            _ => Ok(None),
        }
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod security_tests {
    use super::*;
    #[cfg(not(feature = "unsafe-demo-crypto"))]
    use raven_core::seal::{ATSAM_PROTO_V2, SEAL_MAGIC_RVNA1, STUB_PROTO, STUB_SUITE};
    use tempfile::tempdir;

    fn signed_envelope(sender: &Identity, message_id: [u8; 16], body: Vec<u8>) -> Envelope {
        let mut env = Envelope {
            env_type: EnvType::Message as u8,
            flags: 0,
            message_id,
            routing_tag: [0x44; 16],
            dest_device_hint: 0,
            created_at: now_ms(),
            expires_at: now_ms() + 60_000,
            hop_limit: 4,
            replication_budget: 1,
            anti_replay_nonce: [0x55; 12],
            ratchet_header_ciphertext: vec![],
            message_ciphertext: body,
            sender_authentication: vec![],
        };
        env.sign_with(sender);
        env
    }

    fn node_state(path: &Path, recipient: Identity, sender: &Identity) -> NodeState {
        NodeState {
            identity: recipient,
            queue: OutgoingQueue::open(path).unwrap(),
            peer_pub: Some(sender.public_key_bytes()),
            origin_pub: None,
            ack_pub: None,
            recv_count: 0,
            got_ack: false,
        }
    }

    fn short_test_limits() -> ConnectionLimits {
        ConnectionLimits {
            idle_timeout: Duration::from_secs(2),
            frame_timeout: Duration::from_secs(5),
            write_timeout: Duration::from_secs(2),
            lifetime: Duration::from_secs(20),
        }
    }

    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (client, accepted) = tokio::join!(TcpStream::connect(address), listener.accept());
        (accepted.unwrap().0, client.unwrap())
    }

    #[cfg(not(feature = "unsafe-demo-crypto"))]
    fn stub_shaped_body() -> Vec<u8> {
        let mut body = SEAL_MAGIC_RVNA1.to_vec();
        body.extend_from_slice(&[STUB_PROTO, STUB_SUITE]);
        body.extend_from_slice(&[0u8; 28]);
        body
    }

    #[cfg(not(feature = "unsafe-demo-crypto"))]
    fn opaque_atsam_shaped_body() -> Vec<u8> {
        let mut body = SEAL_MAGIC_RVNA1.to_vec();
        body.extend_from_slice(&[ATSAM_PROTO_V2, STUB_SUITE]);
        body.extend_from_slice(&0u32.to_be_bytes());
        body.extend_from_slice(&[0u8; 28]);
        body
    }

    #[cfg(not(feature = "unsafe-demo-crypto"))]
    #[test]
    fn production_origination_requires_authenticated_session() {
        let sender = Identity::from_seed(&[1u8; 32]);
        let recipient = Identity::from_seed(&[2u8; 32]);
        let err = build_message_envelope(
            &sender,
            &recipient.public_key_bytes(),
            b"never queued",
            [3u8; 16],
            "atsam",
        )
        .unwrap_err();
        assert!(err.contains("ATSAM_SESSION_REQUIRED"));
    }

    #[cfg(not(feature = "unsafe-demo-crypto"))]
    #[test]
    fn signed_stub_and_opaque_atsam_get_no_ack_or_dedup_poison() {
        let dir = tempdir().unwrap();
        let sender = Identity::from_seed(&[4u8; 32]);
        let recipient = Identity::from_seed(&[5u8; 32]);
        let mut state = node_state(&dir.path().join("q.sqlite"), recipient, &sender);

        let stub = signed_envelope(&sender, [6u8; 16], stub_shaped_body()).pack();
        for _ in 0..2 {
            let err = state.handle_inbound(&stub).unwrap_err();
            assert!(err.contains("UNSAFE_INTERIM_DISABLED"));
        }

        let opaque = signed_envelope(&sender, [7u8; 16], opaque_atsam_shaped_body()).pack();
        for _ in 0..2 {
            let err = state.handle_inbound(&opaque).unwrap_err();
            assert!(err.contains("ATSAM_SESSION_REQUIRED"));
            assert!(err.contains("no delivery ACK"));
        }
        assert_eq!(state.recv_count, 0);
        assert!(!state.got_ack);
    }

    #[cfg(not(feature = "unsafe-demo-crypto"))]
    #[test]
    fn plaintext_ack_cannot_advance_queue() {
        let dir = tempdir().unwrap();
        let sender = Identity::from_seed(&[8u8; 32]);
        let recipient = Identity::from_seed(&[9u8; 32]);
        let acked = [0xAA; 16];
        let mut state = node_state(&dir.path().join("q.sqlite"), recipient, &sender);
        state
            .queue
            .enqueue(&QueueItem {
                message_id: acked,
                packed_envelope: vec![1],
                peer_addr: sender.address(),
                state: DeliveryState::Sent,
                created_at_ms: now_ms(),
            })
            .unwrap();

        let mut body = Vec::new();
        body.extend_from_slice(&acked);
        body.push(raven_core::ack::STATUS_DELIVERED);
        body.extend_from_slice(&[0x11; 12]);
        body.extend_from_slice(&now_ms().to_be_bytes());
        body.extend_from_slice(&[0u8; 64]);
        let mut ack_env = signed_envelope(&sender, [0xAB; 16], body);
        ack_env.env_type = EnvType::Ack as u8;
        ack_env.sign_with(&sender);

        let err = state.handle_inbound(&ack_env.pack()).unwrap_err();
        assert!(err.contains("plaintext legacy ACK bodies are disabled"));
        assert_eq!(
            state.queue.get(&acked).unwrap().unwrap().state,
            DeliveryState::Sent
        );
        assert!(!state.got_ack);
    }

    #[cfg(feature = "unsafe-demo-crypto")]
    #[test]
    fn lab_invalid_signature_cannot_poison_valid_message_id() {
        let dir = tempdir().unwrap();
        let sender = Identity::from_seed(&[10u8; 32]);
        let recipient = Identity::from_seed(&[11u8; 32]);
        let mid = [12u8; 16];
        let key = derive_pairwise_key(&sender.public_key_bytes(), &recipient.public_key_bytes());
        let wire = seal_message(
            &key,
            b"authenticated",
            &sender.address(),
            &recipient.address(),
            &mid,
        )
        .unwrap();
        let mut forged = signed_envelope(&sender, mid, wire.clone());
        forged.sender_authentication[0] ^= 0x80;

        let mut state = node_state(&dir.path().join("q.sqlite"), recipient, &sender);
        assert!(state
            .handle_inbound(&forged.pack())
            .unwrap_err()
            .contains("auth failed"));

        let valid = signed_envelope(&sender, mid, wire);
        assert!(state.handle_inbound(&valid.pack()).unwrap().is_some());
        assert_eq!(state.recv_count, 1);
    }

    #[tokio::test]
    async fn frame_reader_rejects_zero_and_oversized_lengths_before_payload() {
        let (mut writer, mut reader) = tokio::io::duplex(32);
        writer.write_all(&0u32.to_be_bytes()).await.unwrap();
        assert_eq!(
            read_frame_with_limits(&mut reader, short_test_limits()).await,
            Err(FrameReadError::InvalidLength)
        );

        let oversized = (MAX_FRAME_BYTES as u32) + 1;
        writer.write_all(&oversized.to_be_bytes()).await.unwrap();
        assert_eq!(
            read_frame_with_limits(&mut reader, short_test_limits()).await,
            Err(FrameReadError::InvalidLength)
        );
    }

    #[tokio::test]
    async fn frame_reader_is_exact_and_rejects_truncation() {
        let (mut writer, mut reader) = tokio::io::duplex(64);
        writer.write_all(&3u32.to_be_bytes()).await.unwrap();
        writer.write_all(b"one").await.unwrap();
        writer.write_all(&3u32.to_be_bytes()).await.unwrap();
        writer.write_all(b"two").await.unwrap();

        assert_eq!(
            read_frame_with_limits(&mut reader, short_test_limits())
                .await
                .unwrap(),
            b"one"
        );
        assert_eq!(
            read_frame_with_limits(&mut reader, short_test_limits())
                .await
                .unwrap(),
            b"two"
        );

        let (mut truncated_writer, mut truncated_reader) = tokio::io::duplex(32);
        truncated_writer
            .write_all(&4u32.to_be_bytes())
            .await
            .unwrap();
        truncated_writer.write_all(b"abc").await.unwrap();
        truncated_writer.shutdown().await.unwrap();
        assert_eq!(
            read_frame_with_limits(&mut truncated_reader, short_test_limits()).await,
            Err(FrameReadError::Truncated)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_frame_hits_hard_frame_deadline() {
        let (mut writer, mut reader) = tokio::io::duplex(32);
        writer.write_all(&8u32.to_be_bytes()).await.unwrap();
        writer.write_all(b"x").await.unwrap();

        let limits = ConnectionLimits {
            idle_timeout: Duration::from_secs(4),
            frame_timeout: Duration::from_secs(5),
            write_timeout: Duration::from_secs(2),
            lifetime: Duration::from_secs(20),
        };
        let read_task =
            tokio::spawn(async move { read_frame_with_limits(&mut reader, limits).await });
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(6)).await;
        assert_eq!(read_task.await.unwrap(), Err(FrameReadError::FrameDeadline));
    }

    #[tokio::test(start_paused = true)]
    async fn idle_connection_hits_header_deadline() {
        let (_writer, mut reader) = tokio::io::duplex(32);
        let limits = short_test_limits();
        let read_task =
            tokio::spawn(async move { read_frame_with_limits(&mut reader, limits).await });
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(3)).await;
        assert_eq!(read_task.await.unwrap(), Err(FrameReadError::IdleDeadline));
    }

    #[tokio::test]
    async fn connection_permit_is_reused_after_error_and_cancellation() {
        let dir = tempdir().unwrap();
        let sender = Identity::from_seed(&[0x31; 32]);
        let recipient = Identity::from_seed(&[0x32; 32]);
        let state = Arc::new(Mutex::new(node_state(
            &dir.path().join("permits.sqlite"),
            recipient,
            &sender,
        )));
        let limiter = Arc::new(Semaphore::new(1));

        let (server, mut client) = tcp_pair().await;
        let handle =
            spawn_connection_handler(server, state.clone(), limiter.clone(), short_test_limits())
                .unwrap();
        assert_eq!(limiter.available_permits(), 0);
        assert!(limiter.clone().try_acquire_owned().is_err());
        client.write_all(&0u32.to_be_bytes()).await.unwrap();
        client.shutdown().await.unwrap();
        assert!(handle.await.unwrap().unwrap_err().contains("invalid frame"));
        assert_eq!(limiter.available_permits(), 1);

        let (server, _client) = tcp_pair().await;
        let handle =
            spawn_connection_handler(server, state, limiter.clone(), short_test_limits()).unwrap();
        assert_eq!(limiter.available_permits(), 0);
        abort_handler(&handle);
        assert!(handle.await.unwrap_err().is_cancelled());
        assert_eq!(limiter.available_permits(), 1);
    }

    /// Regression: EMFILE / ECONNABORTED from accept() used to end the accept
    /// loop (and `service` then exited). They must be retried with backoff.
    #[tokio::test(start_paused = true)]
    async fn accept_errors_are_retried_not_fatal() {
        use std::io::{Error, ErrorKind};
        let started = tokio::time::Instant::now();
        let mut script = vec![
            Err(Error::from_raw_os_error(24)), // EMFILE
            Err(Error::from_raw_os_error(24)),
            Err(Error::from(ErrorKind::ConnectionAborted)),
            Err(Error::from(ErrorKind::OutOfMemory)),
            Ok(7u32),
        ]
        .into_iter();
        let got = accept_retrying("test", || {
            let next = script.next().expect("accept polled past script");
            async move { next }
        })
        .await;
        assert_eq!(got, 7);
        // Resource errors back off (50ms, 100ms; ECONNABORTED: none; then 50ms).
        assert!(started.elapsed() >= Duration::from_millis(200));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn accept_backoff_is_capped_and_zero_for_peer_errors() {
        use std::io::{Error, ErrorKind};
        let emfile = Error::from_raw_os_error(24);
        let mut d = Duration::ZERO;
        for _ in 0..20 {
            d = accept_error_delay(&emfile, d);
        }
        assert_eq!(d, ACCEPT_BACKOFF_MAX);
        assert_eq!(
            accept_error_delay(&emfile, Duration::ZERO),
            ACCEPT_BACKOFF_MIN
        );
        assert_eq!(
            accept_error_delay(&Error::from(ErrorKind::ConnectionAborted), d),
            Duration::ZERO
        );
    }

    /// Regression: a typo in a key flag silently became `None` and message
    /// verification fell back to a different key.
    #[test]
    fn malformed_pub_flags_are_errors() {
        let good = "ab".repeat(32);
        assert_eq!(parse_pub_flag("origin-pub-hex", None).unwrap(), None);
        assert_eq!(
            parse_pub_flag("origin-pub-hex", Some(&good)).unwrap(),
            Some([0xab; 32])
        );
        for bad in ["zz".repeat(32), "ab".repeat(31), String::new()] {
            let err = parse_pub_flag("origin-pub-hex", Some(&bad)).unwrap_err();
            assert!(err.starts_with("--origin-pub-hex"), "{err}");
        }
    }

    /// Regression: envelope signatures were verified while holding the global
    /// NodeState lock. A frame that fails authentication must be handled
    /// without taking the lock at all.
    #[tokio::test]
    async fn unauthenticated_frames_are_rejected_without_state_lock() {
        let dir = tempdir().unwrap();
        let sender = Identity::from_seed(&[0x61; 32]);
        let recipient = Identity::from_seed(&[0x62; 32]);
        let forger = Identity::from_seed(&[0x63; 32]);
        let state = Arc::new(Mutex::new(node_state(
            &dir.path().join("lockfree.sqlite"),
            recipient,
            &sender,
        )));
        let limiter = Arc::new(Semaphore::new(1));
        let (server, mut client) = tcp_pair().await;
        let handle =
            spawn_connection_handler(server, state.clone(), limiter, short_test_limits()).unwrap();
        // Let the handler copy its verification keys and block on the read.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _held = state.lock().await;
        let forged = signed_envelope(&forger, [0x64; 16], vec![1, 2, 3]).pack();
        write_frame(&mut client, &forged).await.unwrap();
        client.shutdown().await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("handler must not wait for the state lock")
            .unwrap()
            .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn connection_lifetime_timeout_releases_permit() {
        let dir = tempdir().unwrap();
        let sender = Identity::from_seed(&[0x41; 32]);
        let recipient = Identity::from_seed(&[0x42; 32]);
        let state = Arc::new(Mutex::new(node_state(
            &dir.path().join("lifetime.sqlite"),
            recipient,
            &sender,
        )));
        let limiter = Arc::new(Semaphore::new(1));
        let limits = ConnectionLimits {
            idle_timeout: Duration::from_secs(60),
            frame_timeout: Duration::from_secs(60),
            write_timeout: Duration::from_secs(2),
            lifetime: Duration::from_secs(5),
        };

        let (server, _client) = tcp_pair().await;
        let handle = spawn_connection_handler(server, state, limiter.clone(), limits).unwrap();
        assert_eq!(limiter.available_permits(), 0);
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(6)).await;
        assert!(handle
            .await
            .unwrap()
            .unwrap_err()
            .contains("connection lifetime"));
        assert_eq!(limiter.available_permits(), 1);
    }
}

async fn handle_connection_until(
    mut stream: TcpStream,
    state: Arc<Mutex<NodeState>>,
    limits: ConnectionLimits,
    lifetime_deadline: tokio::time::Instant,
) -> Result<(), String> {
    let connection = async {
        let keys = state.lock().await.verify_keys();
        loop {
            let frame = match read_frame_with_limits(&mut stream, limits).await {
                Ok(f) => f,
                Err(FrameReadError::Closed) => break,
                Err(FrameReadError::Truncated) => return Err("truncated frame".to_string()),
                Err(FrameReadError::InvalidLength) => {
                    return Err("invalid frame length".to_string())
                }
                Err(FrameReadError::IdleDeadline) => {
                    return Err("connection idle deadline exceeded".to_string())
                }
                Err(FrameReadError::FrameDeadline) => {
                    return Err("frame read deadline exceeded".to_string())
                }
            };
            // Detailed parser/authentication failures are deliberately not logged:
            // untrusted peers must not create a log-amplification channel.
            // Signatures are checked before (and without) taking the state lock.
            let reply = match authenticate_inbound(&frame, keys) {
                Ok(Some((env, peer_pub))) => {
                    let mut st = state.lock().await;
                    st.handle_authenticated(env, peer_pub).ok().flatten()
                }
                _ => None,
            };
            if let Some(ack_bytes) = reply {
                write_frame_with_timeout(&mut stream, &ack_bytes, limits.write_timeout).await?;
            }
        }
        Ok(())
    };

    tokio::time::timeout_at(lifetime_deadline, connection)
        .await
        .map_err(|_| "connection lifetime exceeded".to_string())?
}

fn spawn_connection_handler(
    stream: TcpStream,
    state: Arc<Mutex<NodeState>>,
    limiter: Arc<Semaphore>,
    limits: ConnectionLimits,
) -> Result<JoinHandle<Result<(), String>>, ()> {
    let permit = limiter.try_acquire_owned().map_err(|_| ())?;
    // Measure lifetime from admission, not from whenever the executor first
    // polls the spawned task.
    let lifetime_deadline = tokio::time::Instant::now() + limits.lifetime;
    Ok(tokio::spawn(async move {
        // The owned permit is released by RAII on normal return, timeout,
        // cancellation, or panic unwinding.
        let _permit = permit;
        handle_connection_until(stream, state, limits, lifetime_deadline).await
    }))
}

fn spawn_default_connection_handler(
    stream: TcpStream,
    state: Arc<Mutex<NodeState>>,
    limiter: Arc<Semaphore>,
) -> Result<JoinHandle<Result<(), String>>, ()> {
    spawn_connection_handler(stream, state, limiter, DEFAULT_CONNECTION_LIMITS)
}

fn abort_handler(handle: &JoinHandle<Result<(), String>>) {
    if !handle.is_finished() {
        handle.abort();
    }
}

/// Opt-in cap on the service's own log. `ash` sets it (to its 1 MiB cap) when
/// it redirected the daemon's stdout/stderr into `raven-node-service.log`, and
/// the macOS installers' launchd plists set it for the files launchd opens
/// (`macos_launchd.sh`, the relay kit's `macos_relay.sh`). A service run by
/// hand, under systemd (the journal), or redirected by the user is never
/// touched, and only a regular file opened with `O_APPEND` is ever truncated
/// ([`truncate_log_fd_if_over`]): whether launchd opens StandardOutPath that
/// way decides whether the plist's cap takes effect, never whether it is safe.
#[cfg(unix)]
const SERVICE_LOG_MAX_ENV: &str = "RAVEN_SERVICE_LOG_MAX_BYTES";
/// Lower bound for the cap, so a typo cannot make the service thrash its log.
#[cfg(unix)]
const SERVICE_LOG_MIN_BYTES: u64 = 64 * 1024;
#[cfg(unix)]
const SERVICE_LOG_CHECK_EVERY: Duration = Duration::from_secs(30);

/// Truncate the regular file behind `fd` to zero when it is larger than
/// `max_bytes` and `fd` was opened with `O_APPEND` (ash opens the log that
/// way), so the next write simply lands at the new end. A descriptor without
/// `O_APPEND` is left alone: its writer keeps its offset, so after a truncate
/// the next write would land far past the new end and leave a sparse,
/// NUL-filled file as large as before. Not a regular file (a terminal, a
/// pipe) or within the cap: nothing happens either. `true` when it truncated.
#[cfg(unix)]
fn truncate_log_fd_if_over(fd: std::os::fd::RawFd, max_bytes: u64) -> bool {
    // SAFETY: `fcntl(F_GETFL)` reads the descriptor's flags and takes no
    // memory; `fstat` only writes into the zeroed `stat` we own; `ftruncate`
    // takes no memory. All are plain syscalls on a descriptor number.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || flags & libc::O_APPEND == 0 {
        return false;
    }
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return false;
    }
    let regular = (st.st_mode & libc::S_IFMT) == libc::S_IFREG;
    if !regular || u64::try_from(st.st_size).unwrap_or(0) <= max_bytes {
        return false;
    }
    unsafe { libc::ftruncate(fd, 0) == 0 }
}

/// Keep the service log bounded while the daemon runs: `ash` only enforces its
/// cap when it next starts a service, and a detached daemon appends for weeks.
/// A no-op unless `ash` (or an installer's launchd plist) opted in through
/// [`SERVICE_LOG_MAX_ENV`]. Checked once right away, before this run writes
/// its first line: a process that fails at start and is restarted by its service
/// manager (launchd every 10 s) never lives the [`SERVICE_LOG_CHECK_EVERY`]
/// the loop waits, and its log would otherwise grow by a line per start.
#[cfg(unix)]
fn spawn_service_log_bound() {
    let Some(max) = std::env::var(SERVICE_LOG_MAX_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
    else {
        return;
    };
    let max = max.max(SERVICE_LOG_MIN_BYTES);
    // stdout and stderr normally share one file; either may be the log.
    for fd in [1, 2] {
        truncate_log_fd_if_over(fd, max);
    }
    let _ = std::thread::Builder::new()
        .name("service-log-bound".into())
        .spawn(move || loop {
            std::thread::sleep(SERVICE_LOG_CHECK_EVERY);
            // stdout and stderr normally share one file; either may be the log.
            let mut truncated = false;
            for fd in [1, 2] {
                truncated |= truncate_log_fd_if_over(fd, max);
            }
            if truncated {
                eprintln!("raven-node: service log truncated (it passed {max} bytes)");
            }
        });
}

/// Seconds `raven-node relay` waits before it exits with a lasting failure
/// (exit 2 bad flags, 3 the build holds p2p, 4 a listen port, 5 the relay
/// folder) when this is set: the relay kit's launchd plist sets it. launchd
/// restarts every non-zero exit after its ThrottleInterval (10 s) and has no
/// per-code exception like systemd's `RestartPreventExitStatus`, so without
/// the wait such a relay would start again 8640 times a day.
const RELAY_EXIT_PAUSE_ENV: &str = "RAVEN_RELAY_EXIT_PAUSE_SECS";
/// The longest pause [`RELAY_EXIT_PAUSE_ENV`] may ask for.
const RELAY_EXIT_PAUSE_MAX_SECS: u64 = 3600;

/// How long to wait before exiting with `code`, given the value of
/// [`RELAY_EXIT_PAUSE_ENV`]: only for exits 2 to 5, only for a whole number
/// of seconds (at most [`RELAY_EXIT_PAUSE_MAX_SECS`]), never for `--check`.
fn relay_exit_pause(code: i32, check: bool, env: Option<&str>) -> Option<Duration> {
    if check || !(2..=5).contains(&code) {
        return None;
    }
    let secs = env?.trim().parse::<u64>().ok()?;
    (secs > 0).then(|| Duration::from_secs(secs.min(RELAY_EXIT_PAUSE_MAX_SECS)))
}

/// Exit `raven-node relay` with `code`, after [`relay_exit_pause`] when one
/// applies (a stop request ends the wait).
async fn relay_exit(code: i32, check: bool) -> ! {
    let env = std::env::var(RELAY_EXIT_PAUSE_ENV).ok();
    if let Some(pause) = relay_exit_pause(code, check, env.as_deref()) {
        eprintln!(
            "relay: exiting ({code}) in {} s: the service manager starts it again then",
            pause.as_secs()
        );
        #[cfg(any(unix, windows))]
        let stop = stop_requested();
        #[cfg(not(any(unix, windows)))]
        let stop = std::future::pending::<()>();
        tokio::select! {
            _ = tokio::time::sleep(pause) => {}
            _ = stop => {}
        }
    }
    std::process::exit(code)
}

/// Set while the bridge could not start or keep running; `Status` stops
/// advertising bridge / store / relay then.
#[cfg(any(unix, windows))]
static BRIDGE_DEGRADED: AtomicBool = AtomicBool::new(false);

#[cfg(any(unix, windows))]
pub(crate) fn bridge_degraded() -> bool {
    BRIDGE_DEGRADED.load(Ordering::Relaxed)
}

/// Keep one transport running for the life of the process. Each attempt runs
/// in its own task, so a panic is a failed attempt rather than a dead
/// supervisor; failures are logged (`<name> failed: …`, which the lab scripts
/// grep for) and retried with capped exponential backoff. `degraded`, when
/// given, is true between a failure and the next attempt.
#[cfg(any(unix, windows))]
async fn supervise<F, Fut>(
    name: &'static str,
    degraded: Option<&'static AtomicBool>,
    mut start: F,
) -> Infallible
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<(), String>> + Send + 'static,
{
    let mut backoff = netutil::RESTART_BACKOFF_MIN;
    loop {
        if let Some(flag) = degraded {
            flag.store(false, Ordering::Relaxed);
        }
        let started = tokio::time::Instant::now();
        let attempt = tokio::spawn(start());
        // Dropping this future (a lock, Lock v2) ends the attempt with it.
        let _attempt = AbortOnDrop(attempt.abort_handle());
        match attempt.await {
            Ok(Ok(())) => eprintln!("{name} failed: exited unexpectedly"),
            Ok(Err(e)) => eprintln!("{name} failed: {e}"),
            Err(e) => eprintln!("{name} failed: task ended abnormally: {e}"),
        }
        if let Some(flag) = degraded {
            flag.store(true, Ordering::Relaxed);
        }
        if started.elapsed() >= netutil::RESTART_STABLE {
            backoff = netutil::RESTART_BACKOFF_MIN;
        }
        eprintln!(
            "{name}: unavailable; IPC and the other transports keep running; retrying in {}s",
            backoff.as_secs()
        );
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(netutil::RESTART_BACKOFF_MAX);
    }
}

/// Aborts a task when dropped ([`supervise`]'s attempt).
#[cfg(any(unix, windows))]
struct AbortOnDrop(tokio::task::AbortHandle);

#[cfg(any(unix, windows))]
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// [`supervise`] while Raven is unlocked (Lock v2, P6.40; [`lock`]): from
/// the start or an unlock to the next lock, which drops the task and the
/// attempt it runs (and with them its connections, keys and identity). The
/// next unlock starts it again as at service start. With the gate shut
/// nothing locks, so this is [`supervise`].
#[cfg(any(unix, windows))]
async fn supervise_unlocked<F, Fut>(
    name: &'static str,
    degraded: Option<&'static AtomicBool>,
    mut start: F,
) -> Infallible
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<(), String>> + Send + 'static,
{
    let mut locked = lock::subscribe();
    loop {
        if locked.wait_for(|locked| !*locked).await.is_err() {
            return std::future::pending().await;
        }
        tokio::select! {
            never = supervise(name, degraded, &mut start) => match never {},
            _ = locked.wait_for(|locked| *locked) => {
                eprintln!("{name}: stopped while Raven is locked");
            }
        }
    }
}

/// The service's Internet direct listen address and where it came from,
/// highest first: `--internet-listen` (an explicit empty value is off),
/// `RAVEN_INTERNET_LISTEN` (likewise), then `internet_listen` in
/// node_policy.json (`raven node internet on`). Unset everywhere is off:
/// Internet exposure is opt-in, like LAN exposure in the installers.
fn service_internet_listen(
    flag: Option<&str>,
    env: Option<&str>,
    policy: impl FnOnce() -> Result<String, String>,
) -> Result<Option<(String, &'static str)>, String> {
    let (raw, source) = match (flag, env) {
        (Some(f), _) => (f.to_string(), "--internet-listen"),
        (None, Some(e)) => (e.to_string(), "RAVEN_INTERNET_LISTEN"),
        (None, None) => (policy()?, "node_policy.json"),
    };
    raven_core::node_policy::normalize_internet_listen(&raw)
        .map(|addr| addr.map(|a| (a, source)))
        .map_err(|e| format!("{source}: {e}"))
}

/// The service's p2p host settings and where the listen setting came from,
/// highest first: `--p2p-listen` (an explicit empty value or `off` is off),
/// `RAVEN_P2P_LISTEN` (likewise), then `p2p_listen` in node_policy.json
/// (`raven node p2p on`). Unset everywhere is off: libp2p exposure is opt-in,
/// like Internet direct. The retired `relay` listens on 7423 anyway
/// ([`raven_core::p2p_route::P2pListen::effective`]; debug
/// `RAVEN_LAB_P2P_RELAY_ONLY=1` keeps it for tests). Relays: `--p2p-relay`
/// (any), else `RAVEN_P2P_RELAYS` (comma separated), else the policy's; at
/// most two, each a strict `/…/p2p/<relay PeerId>` multiaddr (a bad one is an
/// error: no host at all). `--relay`, `--relay-open` and `RAVEN_P2P_RELAY=1`
/// are consent for the friend relay ([`friend_relay`], its own relay key);
/// the retired relay role under the profile PeerId ([`profile_relay_role`])
/// is left only to the debug switch `RAVEN_LAB_P2P_PROFILE_RELAY=1`.
/// `peers_pending`: the policy's sealed sidecar (privacy pack PP.6) cannot be
/// read yet, so relays from the policy follow once the at-rest key is loaded
/// ([`p2p::P2pConfig::policy_relays_pending`]).
#[derive(Debug, PartialEq, Eq)]
enum P2pDecision {
    /// p2p is off; the source of the (empty / `off`) setting.
    Off(&'static str),
    On(p2p::P2pConfig, &'static str),
}

#[allow(clippy::too_many_arguments)]
fn service_p2p_config(
    flag: Option<&str>,
    env: Option<&str>,
    flag_relays: &[String],
    env_relays: Option<&str>,
    relay_flag: bool,
    env_relay: Option<&str>,
    relay_open: bool,
    peers_pending: bool,
    policy: impl FnOnce() -> Result<raven_core::NodePolicy, String>,
) -> Result<P2pDecision, String> {
    use raven_core::p2p_route::{normalize_p2p_listen, parse_via, MAX_VIA};
    // Read once; an unreadable policy only matters where its values are used
    // (then: no host, fail closed), and UPnP then stays off.
    let policy = policy();
    let policy_ref = || policy.as_ref().map_err(|e| e.clone());
    let (raw, source) = match (flag, env) {
        (Some(f), _) => (f.to_string(), "--p2p-listen"),
        (None, Some(e)) => (e.to_string(), "RAVEN_P2P_LISTEN"),
        (None, None) => (policy_ref()?.p2p_listen.clone(), "node_policy.json"),
    };
    let Some(listen) = normalize_p2p_listen(&raw).map_err(|e| format!("{source}: {e}"))? else {
        return Ok(P2pDecision::Off(source));
    };
    let (listen, retired_relay) = listen.effective(raven_core::p2p_relay_only_test_enabled());
    let (relays, relay_source): (Vec<String>, &str) = if !flag_relays.is_empty() {
        (flag_relays.to_vec(), "--p2p-relay")
    } else if let Some(env) = env_relays.filter(|e| !e.trim().is_empty()) {
        (
            env.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect(),
            "RAVEN_P2P_RELAYS",
        )
    } else {
        (policy_ref()?.p2p_relays.clone(), "node_policy.json")
    };
    if relays.len() > MAX_VIA {
        return Err(format!(
            "{relay_source}: at most {MAX_VIA} relay addresses (got {}); two addresses of one \
             relay (TCP 7423 and TCP 443) are one relay with a fallback",
            relays.len()
        ));
    }
    let relays = relays
        .iter()
        .map(|r| parse_via(r).map_err(|e| format!("{relay_source}: {e}")))
        .collect::<Result<Vec<_>, _>>()?;
    let relay_asked = relay_flag || relay_open || env_relay.is_some_and(|v| v.trim() == "1");
    let upnp = policy.as_ref().ok().and_then(|p| p.upnp);
    // Its own consent (O4-11): never implied by `upnp`.
    let v6_pinhole = policy.as_ref().ok().and_then(|p| p.v6_pinhole);
    Ok(P2pDecision::On(
        p2p::P2pConfig {
            listen,
            retired_relay,
            relays,
            relay_server: profile_relay_role(
                relay_asked,
                relay_open,
                raven_core::p2p_profile_relay_test_enabled(),
            ),
            upnp,
            v6_pinhole,
            // Automatic relay choice (C7) reads the relays contacts offer in
            // their route hints: only while those are live. An unreadable
            // policy starts it off.
            auto: raven_core::relay_offers_live()
                .then(|| policy.as_ref().is_ok_and(|p| p.relay_auto_on())),
            policy_relays_pending: peers_pending && relay_source == "node_policy.json",
            // Taken next ([`service_p2p_proxy`]).
            proxy: p2p::P2pProxy::default(),
        },
        source,
    ))
}

/// The p2p host's proxy setting for relay dials over WSS (RWS1 §8.2 source
/// 1), highest first: `--p2p-proxy`, `RAVEN_P2P_PROXY` (an empty value is
/// unset), then `p2p_proxy` in node_policy.json, read only when neither is
/// given. A bad value is an error: no host, as for a bad relay (the error
/// names the source, never the text); node_policy.json never holds a user
/// name or password. An unreadable policy is `off` (as for UPnP: off when
/// it is needed): WSS dials then go direct, never to a proxy the policy
/// may have turned off. `peers_pending`: the policy's sealed sidecar cannot
/// be read yet, so its value follows once the at-rest key is loaded
/// ([`p2p::P2pProxy::pending`]); until then an empty plain value is `off`
/// too (review B-5: the saved value may be `off`, so WSS dials go direct
/// rather than to the environment's or the system's proxy). A decision
/// without a host is returned as it is.
fn service_p2p_proxy(
    decision: P2pDecision,
    flag: Option<&str>,
    env: Option<&str>,
    peers_pending: bool,
    policy: impl FnOnce() -> Result<String, String>,
) -> Result<P2pDecision, String> {
    let P2pDecision::On(mut config, listen_source) = decision else {
        return Ok(decision);
    };
    let (text, source) = match (flag, env.filter(|e| !e.trim().is_empty())) {
        (Some(f), _) => (f.to_string(), "--p2p-proxy"),
        (None, Some(e)) => (e.to_string(), "RAVEN_P2P_PROXY"),
        (None, None) => (
            policy().unwrap_or_else(|_| "off".into()),
            proxy::POLICY_SOURCE,
        ),
    };
    let pending = peers_pending && source == proxy::POLICY_SOURCE;
    let text = if pending && text.trim().is_empty() {
        "off".to_string()
    } else {
        text
    };
    config.proxy = p2p::P2pProxy {
        setting: proxy::parse_explicit(&text, source)?,
        source,
        pending,
    };
    if let Some(note) = proxy::argv_credentials_note(&text, source) {
        eprintln!("{note}");
    }
    Ok(P2pDecision::On(config, listen_source))
}

/// `P2pConfig::relay_server`: relaying under the profile's own PeerId is
/// retired (owner decision 7: a relay never uses the profile identity). Only
/// the debug switch `RAVEN_LAB_P2P_PROFILE_RELAY=1` (`lab`) keeps it for
/// `--relay` (`Some(--relay-open)`), so a harness still covers that code.
fn profile_relay_role(asked: bool, open: bool, lab: bool) -> Option<bool> {
    (asked && lab).then_some(open)
}

/// Consent for the friend relay given at start: `--relay`, `--relay-open`
/// or `RAVEN_P2P_RELAY=1`, unless the debug switch
/// `RAVEN_LAB_P2P_PROFILE_RELAY=1` (`profile_lab`) keeps them for the retired
/// profile-key role ([`profile_relay_role`]).
fn friend_relay_flag(relay: bool, relay_open: bool, env: Option<&str>, profile_lab: bool) -> bool {
    !profile_lab && (relay || relay_open || env.is_some_and(|v| v.trim() == "1"))
}

/// Printed once when the service starts with `--relay-open`.
const RELAY_OPEN_NOTE: &str = "raven-node friend relay: --relay-open is the same as --relay \
    (every verified contact may use it); an open relay for anyone must be a dedicated \
    `raven-node relay --open`";

/// `raven-node relay` limit flags (each optional; capped by the hard max).
#[derive(Debug, Default, Clone, Copy)]
struct RelayLimitArgs {
    max_reservations: Option<usize>,
    max_circuits: Option<usize>,
    circuit_bytes: Option<u64>,
    circuit_secs: Option<u64>,
    reservation_secs: Option<u64>,
}

/// `raven-node relay`'s `--wss` flags, as given.
#[derive(Debug, Default, Clone, Copy)]
struct WssArgs<'a> {
    listen: Option<&'a str>,
    cert: Option<&'a Path>,
    key: Option<&'a Path>,
    names: &'a [String],
}

/// `raven-node relay`'s flags, as given.
#[derive(Debug, Clone, Copy)]
struct RelayFlags<'a> {
    listen: &'a str,
    open: bool,
    autonat_server: bool,
    external: &'a [String],
    also_tcp: &'a [String],
    public_host: Option<&'a str>,
    wss: WssArgs<'a>,
    counts_every: u64,
    limits: RelayLimitArgs,
}

/// The port of a listen setting (0 for the retired `relay`).
fn listen_port(listen: &raven_core::p2p_route::P2pListen) -> u16 {
    use raven_core::p2p_route::P2pListen;
    match listen {
        P2pListen::All(port) => *port,
        P2pListen::One(addr) => addr.port(),
        P2pListen::RelayOnly => 0,
    }
}

/// `raven-node relay --wss PORT|IP:PORT` (RWS1 §6), checked before any
/// other flag: refused with WSS_HOLD while `live` is false (the WSS gate is
/// closed). `--wss-cert` and `--wss-key` go together and replace the
/// self-signed certificate, whose names `--wss-name` gives (a DNS name or an
/// IP address each); none of them without `--wss`.
fn wss_listen(args: &WssArgs<'_>, live: bool) -> Result<Option<relay::WssListen>, String> {
    use raven_core::p2p_route::P2pListen;
    use relay::{WssCert, WssListen};
    let Some(text) = args.listen else {
        if args.cert.is_some() || args.key.is_some() || !args.names.is_empty() {
            return Err("--wss-cert, --wss-key and --wss-name need --wss".into());
        }
        return Ok(None);
    };
    if !live {
        return Err(raven_core::WSS_HOLD.into());
    }
    let s = text.trim();
    let listen = match s.parse::<u16>() {
        Ok(port) if s == port.to_string() => Some(P2pListen::All(port)),
        _ => s.parse::<std::net::SocketAddr>().ok().map(P2pListen::One),
    }
    .ok_or_else(|| {
        format!(
            "--wss must be a port (e.g. 443: every interface, IPv4 and IPv6) or IP:PORT (e.g. \
             127.0.0.1:443); got \"{}\"",
            raven_core::sanitize::sanitize_terminal_line(s)
        )
    })?;
    const TOGETHER: &str =
        "--wss-cert and --wss-key go together (the certificate chain and its private key)";
    const OWN_NAMES: &str =
        "--wss-name names the self-signed certificate; --wss-cert brings its own names";
    let cert = match (args.cert, args.key) {
        (Some(_), Some(_)) if !args.names.is_empty() => return Err(OWN_NAMES.into()),
        (Some(chain), Some(key)) => WssCert::Files(chain.to_path_buf(), key.to_path_buf()),
        (None, None) => WssCert::Ephemeral(wss_names(args.names)?),
        _ => return Err(TOGETHER.into()),
    };
    Ok(Some(WssListen { listen, cert }))
}

/// `--wss-name`s as the self-signed certificate takes them, once each: an
/// IP address bare (an IP SAN), a DNS name in lower case.
fn wss_names(names: &[String]) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    for name in names {
        // `/ip4/…`, `/ip6/…` or `/dns/…`, by `parse_via`'s host rule.
        let host =
            raven_core::p2p_route::host_prefix(name).map_err(|e| format!("--wss-name: {e}"))?;
        let bare = host.splitn(3, '/').nth(2).unwrap_or_default().to_string();
        if !out.contains(&bare) {
            out.push(bare);
        }
    }
    Ok(out)
}

/// [`relay_command_with`] with the WSS gate as this build has it.
fn relay_command(data_dir: PathBuf, flags: RelayFlags<'_>) -> Result<relay::RelayCmd, String> {
    relay_command_with(data_dir, flags, raven_core::wss_live_enabled())
}

/// The validated `raven-node relay` settings: `--open` picks the stricter
/// defaults, then each flag overrides one limit (refused above its hard
/// maximum: never silently clamped). `--also-tcp` adds at most 2 TCP
/// listeners on ports `--listen` does not use; `--wss` a WSS listener
/// ([`wss_listen`]; `wss_live`: the WSS gate is open), which replaces a raw
/// TCP listener on its port instead of being refused (relay.rs
/// `listen_plan`); `--public-host` names every listening port at that host
/// (fixed ports only), the WSS one without a WSS suffix, after `--external`.
fn relay_command_with(
    data_dir: PathBuf,
    flags: RelayFlags<'_>,
    wss_live: bool,
) -> Result<relay::RelayCmd, String> {
    use raven_core::p2p_route::{
        parse_extra_tcp, relay_listen_multiaddrs, relay_public_addrs, ExtraTcp, P2pListen,
    };
    use raven_swarm::host::RelayLimits;
    use raven_swarm::libp2p::Multiaddr;
    let wss = wss_listen(&flags.wss, wss_live)?;
    let listen = raven_core::p2p_route::normalize_p2p_listen(flags.listen)
        .map_err(|e| format!("--listen: {e}"))?
        .filter(|l| *l != P2pListen::RelayOnly)
        .ok_or("--listen needs a port or IP:PORT")?;
    let also_tcp = flags
        .also_tcp
        .iter()
        .map(|t| parse_extra_tcp(t))
        .collect::<Result<Vec<_>, _>>()?;
    relay_listen_multiaddrs(&listen, &also_tcp)?;
    let open = flags.open;
    let args = flags.limits;
    let mut limits = if open {
        RelayLimits::open()
    } else {
        RelayLimits::friends()
    };
    if let Some(n) = args.max_reservations {
        limits.max_reservations = n;
    }
    if let Some(n) = args.max_circuits {
        limits.max_circuits = n;
    }
    if let Some(n) = args.circuit_bytes {
        limits.max_circuit_bytes = n;
    }
    if let Some(n) = args.circuit_secs {
        limits.max_circuit_duration = Duration::from_secs(n);
    }
    if let Some(n) = args.reservation_secs {
        limits.reservation_duration = Duration::from_secs(n);
    }
    limits.validate().map_err(|e| e.to_string())?;
    let mut external = flags
        .external
        .iter()
        .map(|e| {
            e.parse::<Multiaddr>()
                .map_err(|err| format!("--external {e}: {err}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if let Some(host) = flags.public_host {
        let port = listen_port(&listen);
        // The WSS port takes raw libp2p too (RWS1 §6): a listening TCP port.
        let mut tcp = also_tcp.clone();
        if let Some(wss_port) = wss.as_ref().map(|w| listen_port(&w.listen)) {
            if wss_port != port && !tcp.iter().any(|e| e.local == wss_port) {
                tcp.push(ExtraTcp {
                    local: wss_port,
                    public: wss_port,
                });
            }
        }
        let named = relay_public_addrs(host, port, &tcp).map_err(|e| {
            if e.starts_with("--public-host") {
                e
            } else {
                format!("--public-host: {e}")
            }
        })?;
        for text in named {
            let addr = text
                .parse::<Multiaddr>()
                .map_err(|e| format!("--public-host: {e}"))?;
            if !external.contains(&addr) {
                external.push(addr);
            }
        }
    }
    Ok(relay::RelayCmd {
        data_dir,
        listen,
        open,
        autonat_server: flags.autonat_server,
        limits,
        external,
        also_tcp,
        extra_best_effort: false,
        wss,
        counts_every: Duration::from_secs(flags.counts_every),
        upnp: false,
        policy: relay::PolicySource::File,
        external_feed: None,
        status_sink: None,
        label: "raven-node relay",
    })
}

/// Why `service` is stopping.
#[cfg(any(unix, windows))]
#[derive(Debug, PartialEq, Eq)]
enum ServiceEnd {
    /// The IPC server ended: without it nothing can reach the daemon.
    IpcStopped,
    /// A transport supervisor itself died (it never returns on its own).
    SupervisorDied(&'static str),
    /// `--timeout-secs` elapsed (lab / CI runs).
    TimedOut,
    /// Asked to stop (SIGTERM / SIGINT, Ctrl-C on Windows): a normal stop or
    /// restart by launchd, systemd or the user.
    Stopped,
}

#[cfg(any(unix, windows))]
impl ServiceEnd {
    /// Non-zero for anything a supervisor (launchd, systemd) should restart.
    fn exit_code(&self) -> i32 {
        match self {
            Self::IpcStopped | Self::SupervisorDied(_) => 1,
            Self::TimedOut | Self::Stopped => 0,
        }
    }
}

/// Resolves when the service is asked to stop: SIGTERM or SIGINT on Unix,
/// Ctrl-C / console close on Windows. Never resolves when the handler cannot
/// be installed (the default action then stops the process as before).
#[cfg(any(unix, windows))]
async fn stop_requested() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match (
            signal(SignalKind::terminate()),
            signal(SignalKind::interrupt()),
        ) {
            (Ok(mut term), Ok(mut int)) => {
                tokio::select! {
                    _ = term.recv() => {}
                    _ = int.recv() => {}
                }
            }
            _ => std::future::pending::<()>().await,
        }
    }
    #[cfg(windows)]
    {
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

/// Wait until the service has to stop. Transport failures never get here:
/// their supervisors absorb them.
#[cfg(any(unix, windows))]
#[allow(clippy::too_many_arguments)]
async fn wait_service_end(
    ipc: &mut JoinHandle<()>,
    lan: &mut JoinHandle<Infallible>,
    inet: &mut JoinHandle<Infallible>,
    p2p: &mut JoinHandle<Infallible>,
    bridge: &mut JoinHandle<Infallible>,
    prune: &mut JoinHandle<Infallible>,
    outbox: &mut JoinHandle<Infallible>,
    timeout: Option<Duration>,
) -> ServiceEnd {
    let timer = async {
        match timeout {
            Some(d) => tokio::time::sleep(d).await,
            None => std::future::pending::<()>().await,
        }
    };
    tokio::select! {
        r = &mut *ipc => {
            if let Err(e) = r {
                eprintln!("ipc join: {e}");
            }
            ServiceEnd::IpcStopped
        }
        r = &mut *lan => {
            eprintln!("lan_direct supervisor ended: {r:?}");
            ServiceEnd::SupervisorDied("lan_direct")
        }
        r = &mut *inet => {
            eprintln!("internet_direct supervisor ended: {r:?}");
            ServiceEnd::SupervisorDied("internet_direct")
        }
        r = &mut *p2p => {
            eprintln!("p2p supervisor ended: {r:?}");
            ServiceEnd::SupervisorDied("p2p")
        }
        r = &mut *bridge => {
            eprintln!("bridge supervisor ended: {r:?}");
            ServiceEnd::SupervisorDied("bridge")
        }
        r = &mut *prune => {
            eprintln!("durable_prune supervisor ended: {r:?}");
            ServiceEnd::SupervisorDied("durable_prune")
        }
        r = &mut *outbox => {
            eprintln!("outbox supervisor ended: {r:?}");
            ServiceEnd::SupervisorDied("outbox")
        }
        _ = timer => {
            eprintln!("raven-node: service timeout");
            ServiceEnd::TimedOut
        }
        _ = stop_requested() => {
            eprintln!("raven-node: stop requested; shutting down");
            ServiceEnd::Stopped
        }
    }
}

#[tokio::main]
async fn main() {
    use raven_core::macos_keychain::{set_hint_mode, HintMode};
    let cli = Cli::parse();
    // A macOS Keychain dialog blocks the call it is raised from: besides the
    // human hint (without Ctrl-C advice: nothing can press it here), print one
    // BLOCKED_ON_KEYCHAIN line to stderr. That lands in raven-node-service.log
    // when `ash` started the service (where `ash` can find it), and in
    // raven-node.err under launchd. Set before any identity or session access.
    let _ = set_hint_mode(HintMode::Daemon);
    // No `--data-dir`, no override and no usable HOME: say so now instead of
    // letting the first store fail with an opaque "Not a directory".
    if let Some(dir) = cli.cmd.data_dir() {
        if let Err(e) = raven_core::paths::require_resolved_data_dir(dir) {
            eprintln!("{e}");
            std::process::exit(1);
        }
        // An unfinished `raven erase` (privacy pack PP.16) closed the
        // profile: no raven-node runs on it (a login item that starts it
        // anyway ends here), so nothing writes into it again.
        if let Err(e) = raven_core::erase::refuse_if_unfinished(dir) {
            eprintln!("{e}");
            std::process::exit(1);
        }
        // An unfinished `raven privacy rotate-meta` (PP.18): a store may
        // still be keyed under the old key, which no key file holds any
        // more; only that command finishes it.
        if let Err(e) = raven_core::privacy::refuse_if_meta_rotation_unfinished(dir) {
            eprintln!("{e}");
            std::process::exit(1);
        }
        // Security notices from the Raven project (Phase 6 P6.45, gated):
        // what this profile's applied advisory refuses or turns off applies
        // to every link and gate of this process.
        raven_core::suite_policy::attach(dir);
    }
    match cli.cmd {
        Commands::Init { data_dir } => match init_identity(&data_dir) {
            Ok(id) => {
                println!("address={}", id.address());
                println!("pub_hex={}", hex::encode(id.public_key_bytes()));
                // NEVER print seed.
            }
            Err(e) => {
                eprintln!("init failed: {e}");
                std::process::exit(1);
            }
        },
        Commands::Address { data_dir } => match load_or_err(&data_dir) {
            Ok(id) => {
                println!("address={}", id.address());
                println!("pub_hex={}", hex::encode(id.public_key_bytes()));
            }
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        },
        Commands::Run {
            data_dir,
            listen,
            peer,
            peer_pub_hex,
            send,
            send_stdin,
            body_mode,
            write_addr,
            write_pub,
            exit_after_recv,
            exit_after_ack,
            timeout_secs,
            seal_to_pub_hex,
            origin_pub_hex,
            ack_pub_hex,
        } => {
            let identity = init_identity(&data_dir).unwrap_or_else(|e| {
                eprintln!("{e}");
                std::process::exit(1);
            });
            if let Some(path) = write_pub {
                let _ = std::fs::write(path, hex::encode(identity.public_key_bytes()));
            }
            let queue = OutgoingQueue::open(&queue_path(&data_dir)).unwrap_or_else(|e| {
                eprintln!("queue: {e}");
                std::process::exit(1);
            });
            let pub_flag = |flag: &str, value: Option<&String>| {
                parse_pub_flag(flag, value).unwrap_or_else(|e| {
                    eprintln!("{e}");
                    std::process::exit(2);
                })
            };
            let peer_pub = pub_flag("peer-pub-hex", peer_pub_hex.as_ref());
            let origin_pub = pub_flag("origin-pub-hex", origin_pub_hex.as_ref());
            let ack_pub = pub_flag("ack-pub-hex", ack_pub_hex.as_ref());
            let seal_to = pub_flag("seal-to-pub-hex", seal_to_pub_hex.as_ref()).or(peer_pub);
            let state = Arc::new(Mutex::new(NodeState {
                identity,
                queue,
                peer_pub,
                origin_pub,
                ack_pub,
                recv_count: 0,
                got_ack: false,
            }));
            let connection_limiter = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTION_HANDLERS));

            let listener = TcpListener::bind(&listen).await.unwrap_or_else(|e| {
                eprintln!("bind: {e}");
                std::process::exit(1);
            });
            let local = listener.local_addr().unwrap();
            eprintln!("raven-node: listen {local}");
            if let Some(path) = write_addr {
                let _ = std::fs::write(path, local.to_string());
            }

            let state_accept = state.clone();
            let limiter_accept = connection_limiter.clone();
            tokio::spawn(async move {
                loop {
                    // Transient accept errors (EMFILE, ECONNABORTED, ...) are
                    // backed off inside accept_retrying; they never end the loop.
                    let (stream, _) = accept_retrying("raven-node", || listener.accept()).await;
                    let st = state_accept.clone();
                    // Admission is intentionally non-blocking. When full, the
                    // just-accepted socket is dropped without spawning work.
                    let _ = spawn_default_connection_handler(stream, st, limiter_accept.clone());
                }
            });

            let send_body: Option<String> = if send_stdin {
                use std::io::{self, BufRead};
                let mut line = String::new();
                if io::stdin().lock().read_line(&mut line).is_err() {
                    eprintln!("failed to read --send-stdin");
                    std::process::exit(1);
                }
                let t = line.trim_end_matches(['\r', '\n']).to_string();
                if t.is_empty() {
                    eprintln!("empty --send-stdin body");
                    std::process::exit(1);
                }
                Some(t)
            } else if send.is_some() {
                eprintln!(
                    "REFUSE: --send puts plaintext on argv (visible via ps). Use --send-stdin."
                );
                std::process::exit(2);
            } else {
                None
            };

            if let (Some(peer_s), Some(text), Some(pp)) =
                (peer.as_ref(), send_body.as_ref(), seal_to)
            {
                let mut mid = [0u8; 16];
                rand::thread_rng().fill_bytes(&mut mid);
                let env = {
                    let st = state.lock().await;
                    build_message_envelope(&st.identity, &pp, text.as_bytes(), mid, &body_mode)
                        .unwrap_or_else(|e| {
                            eprintln!("{e}");
                            std::process::exit(1);
                        })
                };
                eprintln!("ENVELOPE_FP mid={}", hex::encode(mid));
                let packed = env.pack();
                {
                    let st = state.lock().await;
                    st.queue
                        .enqueue(&QueueItem {
                            message_id: mid,
                            packed_envelope: packed.clone(),
                            peer_addr: raven_core::encode_address(&pp),
                            state: DeliveryState::Queued,
                            created_at_ms: now_ms(),
                        })
                        .unwrap_or_else(|e| {
                            eprintln!("queue: {e}");
                            std::process::exit(1);
                        });
                }
                let (mut stream, _) = dial_peer_or_exit(peer_s, timeout_secs).await;
                if let Err(e) = write_frame(&mut stream, &packed).await {
                    eprintln!("send: {e}");
                    std::process::exit(1);
                }
                {
                    let st = state.lock().await;
                    // The frame is already out; a failed state write must not
                    // abort the wait for the ACK.
                    if let Err(e) = st.queue.mark_state(&mid, DeliveryState::Sent) {
                        eprintln!("queue: mark sent: {e}");
                    }
                }
                let st = state.clone();
                if spawn_connection_handler(
                    stream,
                    st,
                    connection_limiter.clone(),
                    client_limits(timeout_secs),
                )
                .is_err()
                {
                    eprintln!("raven-node: connection handler capacity reached");
                }
            } else if let Some(peer_s) = peer.as_ref() {
                // Dial-only (e.g. C connects to B mock-BLE to receive).
                let (stream, _) = dial_peer_or_exit(peer_s, timeout_secs).await;
                let st = state.clone();
                if spawn_connection_handler(
                    stream,
                    st,
                    connection_limiter.clone(),
                    client_limits(timeout_secs),
                )
                .is_err()
                {
                    eprintln!("raven-node: connection handler capacity reached");
                }
            }

            let deadline = tokio::time::Instant::now()
                + std::time::Duration::from_secs(timeout_secs.min(MAX_RUN_SECS));
            loop {
                if tokio::time::Instant::now() > deadline {
                    eprintln!("raven-node: timeout");
                    break;
                }
                {
                    let st = state.lock().await;
                    if exit_after_ack && st.got_ack {
                        eprintln!("raven-node: exit_after_ack");
                        break;
                    }
                    if exit_after_recv > 0 && st.recv_count >= exit_after_recv {
                        eprintln!("raven-node: exit_after_recv");
                        break;
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
        Commands::Bridge {
            data_dir,
            lan_listen,
            ble_listen,
            write_lan_addr,
            write_ble_addr,
            write_status,
            timeout_secs,
        } => {
            if let Err(e) = bridge_run::run_bridge_daemon(
                data_dir,
                lan_listen,
                ble_listen,
                write_lan_addr,
                write_ble_addr,
                write_status,
                timeout_secs,
            )
            .await
            {
                eprintln!("bridge failed: {e}");
                std::process::exit(1);
            }
        }
        Commands::Status { data_dir } => {
            let policy = load_policy(&data_dir);
            let queue = forward_queue_counts(&data_dir);
            let (pending, total) = queue.as_ref().copied().unwrap_or((0, 0));
            let snap =
                BridgeStatusSnapshot::from_policy(&policy, &["lan", "mock_ble"], pending, total);
            println!("bridge={}", snap.bridge);
            println!("store={}", snap.store);
            println!("relay={}", snap.relay);
            println!("endpoint={}", snap.endpoint);
            println!("auto_policy={}", snap.auto_policy);
            println!("transports={}", snap.transports.join(","));
            match &queue {
                Ok(_) => {
                    println!("forward_queue_pending={}", snap.forward_queue_pending);
                    println!("forward_queue_total={}", snap.forward_queue_total);
                }
                // An unreadable queue is not an empty one: say so, and fail.
                Err(e) => {
                    println!("forward_queue_pending=unknown");
                    println!("forward_queue_total=unknown");
                    println!(
                        "forward_queue_error={}",
                        raven_core::sanitize::sanitize_terminal_line(e)
                    );
                }
            }
            println!("capabilities={}", snap.capabilities.join(","));
            if let Err(e) = queue {
                eprintln!("raven-node status: forward queue unavailable: {e}");
                std::process::exit(1);
            }
        }
        Commands::Flush {
            data_dir,
            peer,
            peer_pub_hex,
            timeout_secs,
        } => {
            let identity = load_or_err(&data_dir).unwrap_or_else(|e| {
                eprintln!("{e}");
                std::process::exit(1);
            });
            let queue = OutgoingQueue::open(&queue_path(&data_dir)).unwrap_or_else(|e| {
                eprintln!("queue: {e}");
                std::process::exit(1);
            });
            let peer_pub = parse_pub_hex(&peer_pub_hex).unwrap_or_else(|e| {
                eprintln!("--peer-pub-hex: {e}");
                std::process::exit(2);
            });
            if let Err(e) = netutil::check_dial_syntax(&peer) {
                eprintln!("--peer: {e}");
                std::process::exit(2);
            }
            let pending = queue.pending().unwrap_or_else(|e| {
                eprintln!("queue: {e}");
                std::process::exit(1);
            });
            eprintln!("raven-node: flushing {} pending", pending.len());
            let state = Arc::new(Mutex::new(NodeState {
                identity,
                queue,
                peer_pub: Some(peer_pub),
                origin_pub: None,
                ack_pub: None,
                recv_count: 0,
                got_ack: false,
            }));
            let connection_limiter = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTION_HANDLERS));
            // One dead connect or reset must not strand the items behind it:
            // every item is attempted, and the exit status says if any failed.
            let per_addr = Duration::from_secs(timeout_secs.clamp(1, 10));
            let mut failed = 0usize;
            for item in pending {
                let mid = hex::encode(&item.message_id[..4]);
                let mut stream = match netutil::connect_dial(&peer, per_addr, per_addr * 2).await {
                    Ok((stream, _)) => stream,
                    Err(e) => {
                        eprintln!("raven-node: flush {mid}…: connect: {e}");
                        failed += 1;
                        continue;
                    }
                };
                if let Err(e) = write_frame(&mut stream, &item.packed_envelope).await {
                    eprintln!("raven-node: flush {mid}…: send: {e}");
                    failed += 1;
                    continue;
                }
                {
                    let st = state.lock().await;
                    if let Err(e) = st.queue.mark_state(&item.message_id, DeliveryState::Sent) {
                        // Sent but not recorded: the next flush re-sends it
                        // and the peer's dedup absorbs the repeat.
                        eprintln!("raven-node: flush {mid}…: mark sent: {e}");
                        failed += 1;
                    }
                }
                let st = state.clone();
                let Ok(mut handle) =
                    spawn_default_connection_handler(stream, st, connection_limiter.clone())
                else {
                    eprintln!("raven-node: connection handler capacity reached");
                    continue;
                };
                if tokio::time::timeout(
                    std::time::Duration::from_secs(timeout_secs.min(MAX_RUN_SECS)),
                    &mut handle,
                )
                .await
                .is_err()
                {
                    // Dropping a JoinHandle detaches it. Explicit cancellation is
                    // required so a stalled peer cannot accumulate flush handlers.
                    abort_handler(&handle);
                    let _ = handle.await;
                }
            }
            let got_ack = state.lock().await.got_ack;
            if got_ack {
                eprintln!("raven-node: flush got ACK");
            } else {
                eprintln!("raven-node: flush done (check pending)");
            }
            if failed > 0 {
                eprintln!("raven-node: flush: {failed} item(s) not sent");
                std::process::exit(1);
            }
        }
        #[cfg(any(unix, windows))]
        Commands::Ipc {
            data_dir,
            forward_db,
        } => {
            let fwd = forward_db.or_else(|| {
                let p = bridge_run::forward_queue_path(&data_dir);
                if p.exists() {
                    Some(p)
                } else {
                    None
                }
            });
            // Its ops read the contact book too (privacy pack PP.4).
            at_rest_boot::start(&data_dir);
            // Its LAN dials follow `raven lan off` (and a meeting time) too.
            seed_lan_switch(&data_dir);
            let meeting_task = watch_meeting(&data_dir);
            let served = ipc_server::run_ipc_server(data_dir, fwd).await;
            meeting_task.abort();
            if let Err(e) = served {
                eprintln!("ipc failed: {e}");
                std::process::exit(1);
            }
        }
        #[cfg(any(unix, windows))]
        Commands::Service {
            data_dir,
            lan_listen,
            ble_listen,
            internet_listen,
            p2p_listen,
            p2p_relay,
            p2p_proxy,
            relay,
            relay_open,
            timeout_secs,
        } => {
            // A new binary's first LAN connects may be refused by macOS for
            // some seconds (E2): the LAN dials' start grace counts from here.
            lan_direct::note_process_start();
            #[cfg(unix)]
            spawn_service_log_bound();
            // Lock v2 (P6.40, gated): the profile the lock serves; a Raven
            // passphrase this process cannot read by itself starts it
            // locked, and then no key loads (the preflight and the at-rest
            // key wait for `Unlock`; it writes nothing). Every task below
            // that holds a key or the network runs only while unlocked
            // (`supervise_unlocked`).
            let locked_at_start = lock::start(&data_dir);
            if !locked_at_start {
                // Identity preflight runs before any other profile-state
                // creation. The first-install proof (raven-core
                // identity_store) tolerates an *empty* forward_queue.sqlite
                // and the IPC socket / instance lock, but nothing that holds
                // state: custody or rate-limit rows (and any other file) that
                // predate the identity would make a fresh profile fail
                // require_proven_first_install and wedge first install. Doing
                // the preflight first means none of that can exist yet.
                init_identity(&data_dir).unwrap_or_else(|e| {
                    eprintln!("service identity preflight failed: {e}");
                    std::process::exit(1);
                });
                // The at-rest key (privacy pack PP.4) loads on a thread of
                // its own; until it is here (and what is still plain is
                // sealed) the contact book is held, so the listeners below
                // start at once and admit nobody. Never a keystore call on
                // this thread.
                at_rest_boot::start(&data_dir);
            }
            // Security events (Phase 6b, gated): the ledger writer, which
            // opens the ledger once the key above is here and there is
            // something to write. Nothing starts while the gate is shut.
            security::start(&data_dir);
            // Pre-create WAL schema so IPC + bridge do not race on first open.
            let fq = bridge_run::forward_queue_path(&data_dir);
            let _warmup = ForwardQueue::open(&fq).map_err(|e| {
                eprintln!("service queue warmup failed: {e}");
                std::process::exit(1);
            });
            drop(_warmup);
            let fwd = Some(fq);
            let data_ipc = data_dir.clone();
            let mut ipc_task = tokio::spawn(async move {
                if let Err(e) = ipc_server::run_ipc_server(data_ipc, fwd).await {
                    eprintln!("ipc failed: {e}");
                }
            });
            // IPC is the one thing the service cannot run without. Every
            // transport is supervised on its own: a busy port, a slow or
            // failed preflight or a crash is logged, shown in Status (the
            // listener is simply not up) and retried with backoff; it never
            // takes IPC or the other transports down, and there is no
            // start-up wait that could mistake "slow" for "failed".
            seed_lan_switch(&data_dir);
            // The field test's Bluetooth-only node (debug lab switch
            // RAVEN_LAB_NEARBY_ONLY): said once, so its log shows that
            // nothing but nearby could carry (offline mesh carry research,
            // Phase 0).
            if raven_core::nearby_only() {
                eprintln!("raven-node: {}", raven_core::NEARBY_ONLY_NOTE);
            }
            let meeting_task = watch_meeting(&data_dir);
            // A plain `auto` listens on the port this profile picked (Phase
            // 6b P6.36), read once here: `raven lan port random` takes
            // effect at the next start.
            let lan_listen = raven_core::paths::profile_lan_listen(
                &lan_listen,
                raven_core::node_policy::profile_lan_port(&data_dir),
            );
            let data_lan = data_dir.clone();
            let mut lan_task = tokio::spawn(supervise_unlocked("lan_direct", None, move || {
                lan_direct::run_listener(data_lan.clone(), lan_listen.clone())
            }));
            let internet_listen = service_internet_listen(
                internet_listen.as_deref(),
                std::env::var("RAVEN_INTERNET_LISTEN").ok().as_deref(),
                || {
                    raven_core::node_policy::try_load_policy(&data_dir)
                        .map(|p| p.internet_listen)
                        .map_err(|e| {
                            format!("node_policy.json unreadable ({e}): no Internet listener")
                        })
                },
            );
            let mut inet_task = match internet_listen {
                Ok(None) => tokio::spawn(std::future::pending::<Infallible>()),
                // A nearby-only lab run: closed on purpose, said as such.
                Ok(Some((addr, source))) if raven_core::nearby_only() => {
                    eprintln!(
                        "raven-node internet_direct: off in this lab run (nearby only); {addr} \
                         from {source} stays closed"
                    );
                    tokio::spawn(std::future::pending::<Infallible>())
                }
                // Held in this build: say so once instead of retrying a listener
                // that can never start (the port stays closed).
                Ok(Some((addr, source))) if !raven_core::internet_direct_live_enabled() => {
                    eprintln!(
                        "internet_direct failed: {} ({addr} from {source} stays closed)",
                        internet_direct::HOLD
                    );
                    tokio::spawn(std::future::pending::<Infallible>())
                }
                Ok(Some((addr, source))) => {
                    eprintln!("raven-node internet_direct: configured {addr} ({source})");
                    // Auto-reach: route hints and the card may name its
                    // public address (gated, autoreach.rs).
                    autoreach::set_inet_listen(addr.parse().ok());
                    let data_inet = data_dir.clone();
                    tokio::spawn(supervise_unlocked("internet_direct", None, move || {
                        internet_direct::run_listener(data_inet.clone(), addr.clone())
                    }))
                }
                // A bad value or an unreadable policy: no public listener (fail
                // closed); IPC and LAN keep running.
                Err(e) => {
                    eprintln!("internet_direct failed: {e}");
                    tokio::spawn(std::future::pending::<Infallible>())
                }
            };
            // The libp2p carrier (P3): opt-in like Internet direct, and held
            // (nothing built, nothing listens or dials) while its gate is closed.
            // The key thread has just started: a sealed sidecar opens only
            // once it has loaded the at-rest key (privacy pack PP.6).
            let peers_pending = !raven_core::node_policy::peers_readable(&data_dir);
            let p2p_config = service_p2p_config(
                p2p_listen.as_deref(),
                std::env::var("RAVEN_P2P_LISTEN").ok().as_deref(),
                &p2p_relay,
                std::env::var("RAVEN_P2P_RELAYS").ok().as_deref(),
                relay,
                std::env::var("RAVEN_P2P_RELAY").ok().as_deref(),
                relay_open,
                peers_pending,
                || {
                    raven_core::node_policy::try_load_policy(&data_dir)
                        .map_err(|e| format!("node_policy.json unreadable ({e}): no libp2p host"))
                },
            )
            .and_then(|decision| {
                service_p2p_proxy(
                    decision,
                    p2p_proxy.as_deref(),
                    std::env::var("RAVEN_P2P_PROXY").ok().as_deref(),
                    peers_pending,
                    || {
                        raven_core::node_policy::try_load_policy(&data_dir)
                            .map(|p| p.p2p_proxy)
                            .map_err(|e| e.to_string())
                    },
                )
            });
            // IPC Status reports this decision (and its source) even while no
            // host runs, so `raven status` and `raven whoami --card` follow
            // what the service does, installer flags included.
            let mut p2p_task = match p2p_config {
                Ok(P2pDecision::Off(source)) => {
                    p2p::publish_service_config(p2p::ServiceP2p::Off { source });
                    tokio::spawn(std::future::pending::<Infallible>())
                }
                Ok(P2pDecision::On(config, source)) if !raven_core::p2p_live_enabled() => {
                    p2p::publish_service_config(p2p::ServiceP2p::Held {
                        config: &config,
                        source,
                    });
                    if raven_core::nearby_only() {
                        eprintln!(
                            "raven-node p2p: off in this lab run (nearby only); the p2p setting \
                             from {source} stays closed"
                        );
                    } else {
                        eprintln!(
                            "p2p failed: {} (the p2p setting from {source} stays closed)",
                            raven_core::P2P_HOLD
                        );
                    }
                    tokio::spawn(std::future::pending::<Infallible>())
                }
                Ok(P2pDecision::On(config, source)) => {
                    p2p::publish_service_config(p2p::ServiceP2p::Configured {
                        config: &config,
                        source,
                    });
                    eprintln!("raven-node p2p: configured ({source})");
                    let data_p2p = data_dir.clone();
                    tokio::spawn(supervise_unlocked("p2p", None, move || {
                        p2p::run_host(data_p2p.clone(), config.clone(), source.to_string())
                    }))
                }
                Err(e) => {
                    p2p::publish_service_config(p2p::ServiceP2p::Error);
                    eprintln!("p2p failed: {e}");
                    tokio::spawn(std::future::pending::<Infallible>())
                }
            };
            // The friend relay (Phase 2, gated): relays for this profile's
            // verified contacts under a relay key of its own (never the
            // profile PeerId) while consent is given, `raven relay offer on`
            // or `--relay`, applied live. It idles otherwise, and the service
            // never ends because of it.
            let profile_relay = raven_core::p2p_profile_relay_test_enabled();
            let relay_consent = friend_relay_flag(
                relay,
                relay_open,
                std::env::var("RAVEN_P2P_RELAY").ok().as_deref(),
                profile_relay,
            );
            if relay_open && !profile_relay {
                eprintln!("{RELAY_OPEN_NOTE}");
            }
            let data_friend = data_dir.clone();
            let friend_task = tokio::spawn(supervise_unlocked("friend_relay", None, move || {
                friend_relay::run(data_friend.clone(), relay_consent)
            }));
            // Auto-reach (gated; autoreach.rs): asks public STUN servers for
            // this computer's public address every 20 minutes while a p2p
            // host runs and the profile allows it (`raven node stun`); it
            // sends nothing otherwise, and the service never ends because of
            // it.
            let data_reach = data_dir.clone();
            let reach_task = tokio::spawn(supervise("autoreach", None, move || {
                autoreach::run(data_reach.clone())
            }));
            // Expired sessions (protected K_root, outbox envelopes, inbox
            // rows) are destroyed on a timer, not only when a listener starts
            // or the next PairInit arrives.
            let data_prune = data_dir.clone();
            let mut prune_task =
                tokio::spawn(supervise_unlocked("durable_prune", None, move || {
                    lan_direct::run_durable_prune(data_prune.clone())
                }));
            // Retries staged messages (and ACKs we owe) in the background until
            // the first verified ACK or expiry (transports design §2.4).
            let data_outbox = data_dir.clone();
            let mut outbox_task = tokio::spawn(supervise_unlocked("outbox", None, move || {
                outbox::run_worker(data_outbox.clone())
            }));
            // One line per received message and per hand-over as a keeper
            // (E2 r9): the hooks raven-core calls.
            arrivals::install();
            // Collects mail left for us with friends (friend custody, gated).
            let data_custody = data_dir.clone();
            let custody_task = tokio::spawn(supervise_unlocked("custody_fetch", None, move || {
                custody::run_fetcher(data_custody.clone())
            }));
            // Renews a contact's session on a live link when less than 12 h
            // remain (session renewal, Phase 3, gated; renewal.rs). Like
            // custody, the service never ends because of it.
            let renew_task = tokio::spawn(supervise_unlocked(
                "session_renewal",
                None,
                renewal::run_renewer,
            ));
            // Notices this machine's network changing (Wi-Fi to a hotspot, a
            // new DHCP lease, a cable) and retries what waits at once on a
            // fresh backoff (netwatch.rs). Not a transport: it opens no port
            // and dials nothing, and the service never ends because of it.
            let netwatch_task = tokio::spawn(supervise("netwatch", None, netwatch::run));
            // Learning connectivity (Phase 6a, gated; learning.rs): learns
            // from this node's own dial outcomes and ranks the carriers of
            // each contact's plan (order only).
            // It reads nothing and writes nothing while its gate is shut or
            // the user's switch is off; like netwatch, the service never
            // ends because of it.
            let data_learning = data_dir.clone();
            let learning_task = tokio::spawn(supervise("learning", None, move || {
                learning::run(data_learning.clone())
            }));
            // Finds contacts on the local network with no address typed, and
            // answers theirs (the LAN beacon, Phase 3, gated; lan_beacon.rs).
            // It opens UDP only while its gate is live, LAN is on and the LAN
            // listener has loaded the identity; like netwatch, the service
            // never ends because of it.
            let data_beacon = data_dir.clone();
            let beacon_task = tokio::spawn(supervise_unlocked("lan_beacon", None, move || {
                lan_beacon::run(data_beacon.clone())
            }));
            // The Bluetooth LE nearby carrier (Phase 5, gated; nearby/). It
            // creates no radio unless its gate is open and the user enabled
            // nearby; like netwatch, the service never ends because of it.
            let data_nearby = data_dir.clone();
            let nearby_task = tokio::spawn(supervise_unlocked("nearby", None, move || {
                nearby::run(data_nearby.clone())
            }));
            // The Tor onion carrier (lab, gated; onion/): its helper process
            // (Arti), the onion service and the forward listener. Nothing
            // unless its gate is open and a helper is built; a Tor failure
            // ends or hangs only the helper, which it restarts. Like
            // netwatch, the service never ends because of it.
            let data_onion = data_dir.clone();
            let onion_task = tokio::spawn(supervise_unlocked("onion", None, move || {
                onion::run(data_onion.clone())
            }));
            // Tells contacts this node's new routes when they change (route
            // hints announce links, gated; hints.rs). Like custody and
            // netwatch, the service never ends because of it.
            let data_hints = data_dir.clone();
            let hints_task = tokio::spawn(supervise_unlocked("route_hints", None, move || {
                hints::run_announcer(data_hints.clone())
            }));
            // Passes security notices, the release log and releases along
            // between pinned contacts (RUP1, Phase 6b P6.49, gated;
            // update_exchange.rs). It installs and runs nothing; like the
            // announcer, the service never ends because of it.
            let data_updates = data_dir.clone();
            let updates_task =
                tokio::spawn(supervise_unlocked("update_exchange", None, move || {
                    update_exchange::run(data_updates.clone())
                }));
            // Mock BLE stays on ble_listen. Do not fanout the production LAN port.
            // The service owns --timeout-secs; the bridge itself runs until stopped.
            let mut bridge_task = tokio::spawn(supervise_unlocked(
                "bridge",
                Some(&BRIDGE_DEGRADED),
                move || {
                    bridge_run::run_bridge_daemon(
                        data_dir.clone(),
                        "127.0.0.1:0".into(),
                        ble_listen.clone(),
                        None,
                        None,
                        None,
                        0,
                    )
                },
            ));
            let timeout =
                (timeout_secs > 0).then(|| Duration::from_secs(timeout_secs.min(MAX_RUN_SECS)));
            let end = wait_service_end(
                &mut ipc_task,
                &mut lan_task,
                &mut inet_task,
                &mut p2p_task,
                &mut bridge_task,
                &mut prune_task,
                &mut outbox_task,
                timeout,
            )
            .await;
            // A clean libp2p shutdown first: its connections are closed (QUIC
            // sends its close frame), so a relay frees our reservation at
            // once and a restart is not refused while it still holds it. The
            // friend relay likewise ends its members' reservations at once.
            tokio::join!(
                p2p::shutdown(p2p::SHUTDOWN_DRAIN + Duration::from_millis(500)),
                friend_relay::shutdown(relay::STOP_DRAIN + Duration::from_millis(500)),
                // What learning saw since its last save (best effort).
                learning::final_save(),
            );
            ipc_task.abort();
            lan_task.abort();
            inet_task.abort();
            p2p_task.abort();
            bridge_task.abort();
            prune_task.abort();
            outbox_task.abort();
            custody_task.abort();
            renew_task.abort();
            netwatch_task.abort();
            learning_task.abort();
            beacon_task.abort();
            nearby_task.abort();
            onion_task.abort();
            hints_task.abort();
            updates_task.abort();
            friend_task.abort();
            reach_task.abort();
            meeting_task.abort();
            // What the security ledger writer holds goes in (gated; at most
            // 2 s).
            let _ =
                tokio::task::spawn_blocking(|| security::shutdown(Duration::from_secs(2))).await;
            std::process::exit(end.exit_code());
        }
        Commands::Relay {
            data_dir,
            listen,
            open,
            autonat_server,
            external,
            also_tcp,
            public_host,
            wss,
            wss_cert,
            wss_key,
            wss_name,
            counts_every,
            check,
            max_reservations,
            max_circuits,
            circuit_bytes,
            circuit_secs,
            reservation_secs,
        } => {
            // Bounds the log under launchd (its plist sets the cap); a no-op
            // otherwise.
            #[cfg(unix)]
            spawn_service_log_bound();
            let cmd = relay_command(
                data_dir,
                RelayFlags {
                    listen: &listen,
                    open,
                    autonat_server,
                    external: &external,
                    also_tcp: &also_tcp,
                    public_host: public_host.as_deref(),
                    wss: WssArgs {
                        listen: wss.as_deref(),
                        cert: wss_cert.as_deref(),
                        key: wss_key.as_deref(),
                        names: &wss_name,
                    },
                    counts_every,
                    limits: RelayLimitArgs {
                        max_reservations,
                        max_circuits,
                        circuit_bytes,
                        circuit_secs,
                        reservation_secs,
                    },
                },
            );
            let cmd = match cmd {
                Ok(cmd) => cmd,
                Err(e) => {
                    eprintln!("relay: {e}");
                    relay_exit(2, check).await
                }
            };
            if check {
                let (lines, code) = relay::check(&cmd);
                for line in lines {
                    println!("relay check: {line}");
                }
                std::process::exit(code);
            }
            #[cfg(any(unix, windows))]
            let stop = stop_requested();
            #[cfg(not(any(unix, windows)))]
            let stop = std::future::pending::<()>();
            if let Err(e) = relay::run_relay(cmd, stop).await {
                eprintln!("relay failed: {e}");
                relay_exit(e.code(), false).await;
            }
        }
        Commands::RelayProbe { via } => {
            let vias = relay_probe::parse_args(&via).unwrap_or_else(|e| {
                eprintln!("relay-probe: {e}");
                std::process::exit(2);
            });
            match relay_probe::probe_all(&vias).await {
                Ok(results) => {
                    for (v, r) in vias.iter().zip(&results) {
                        println!("{}: {}", relay_probe::transport_label(v), r.text());
                    }
                    let all = results.iter().all(|r| *r == relay_probe::Probe::Reachable);
                    std::process::exit(if all { 0 } else { 1 });
                }
                Err(e) => {
                    eprintln!("relay-probe: {e}");
                    std::process::exit(e.code());
                }
            }
        }
        Commands::BleStatus => {
            let kind = raven_core::ble_adapter::select_ble_adapter_from_env();
            println!("ble_adapter={}", kind.as_str());
            println!("transport={:?}", kind.transport());
            println!(
                "hint=set RAVEN_BLE_PLATFORM=1 to prefer platform GATT; default mock_ble for CI"
            );
            // The nearby carrier (RNL1). Never creates a radio (no
            // Bluetooth prompt): the running service reports the radio, its
            // roles, address privacy and counts (`raven status`).
            for line in ble_status_lines(
                raven_core::nearby_live_enabled(),
                nearby::radio::backend_name(),
            ) {
                println!("{line}");
            }
        }
        Commands::LanDefault { data_dir } => println!(
            "{}",
            lan_default(
                raven_core::lan_auto_live(),
                data_dir
                    .as_deref()
                    .and_then(raven_core::node_policy::profile_lan_port),
            )
        ),
        #[cfg(debug_assertions)]
        Commands::NearbyEther {
            listen,
            print_port,
            mtu,
            rate,
            latency_ms,
            drop_after,
            disconnect_after,
        } => {
            let params = nearby::fake::EtherParams {
                mtu_c2p: mtu,
                mtu_p2c: mtu,
                latency: Duration::from_millis(latency_ms),
                bytes_per_sec: rate,
                drop_after_frames: drop_after,
                disconnect_after_frames: disconnect_after,
            };
            std::process::exit(nearby::ether_hub::run_cli(listen, print_port, params).await);
        }
        #[cfg(debug_assertions)]
        Commands::TorLoopbackHelper { registry } => {
            std::process::exit(onion::loopback::run_cli(registry).await);
        }
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    /// Phase 3 P3.5: `raven-node lan-default` (hidden) prints what the
    /// installers listen on: this computer only until `--lan-listen auto` is
    /// live. Runs in both builds: in the release job `RAVEN_LAB_LAN_AUTO=1`
    /// is set and the answer stays 127.0.0.1:7420 (the switch is never
    /// read); a debug build follows exactly the switch. The service itself
    /// defaults to `auto`.
    #[test]
    fn lan_default_lab_switch_is_inert_in_release() {
        use clap::CommandFactory;
        assert_eq!(lan_default(false, None), "127.0.0.1:7420");
        assert_eq!(lan_default(true, None), "auto");
        let lab =
            cfg!(debug_assertions) && std::env::var("RAVEN_LAB_LAN_AUTO").as_deref() == Ok("1");
        let want = if raven_core::lan_gate::LAN_AUTO_LISTEN_PRODUCTION_ENABLED || lab {
            "auto"
        } else {
            "127.0.0.1:7420"
        };
        assert_eq!(lan_default(raven_core::lan_auto_live(), None), want);
        assert!(matches!(
            Cli::try_parse_from(["raven-node", "lan-default"])
                .unwrap()
                .cmd,
            Commands::LanDefault { data_dir: None }
        ));
        assert!(Cli::try_parse_from(["raven-node", "lan-default", "x"]).is_err());
        let cli = Cli::command();
        assert!(cli.find_subcommand("lan-default").unwrap().is_hide_set());
        match Cli::try_parse_from(["raven-node", "service"]).unwrap().cmd {
            Commands::Service { lan_listen, .. } => assert_eq!(lan_listen, "auto"),
            _ => unreachable!(),
        }
    }

    /// Phase 6b P6.36: `raven-node lan-default --data-dir DIR` gives the
    /// installers the port that profile picked (`auto:PORT`, or
    /// 127.0.0.1:PORT while `auto` is held), in place of the default one; a
    /// profile without one (and every profile while the random-port gate is
    /// shut: raven-core's `profile_lan_port`) gets today's answer. The flag
    /// opens no profile (no data dir for the start-up checks).
    #[test]
    fn lan_default_takes_the_profiles_port() {
        assert_eq!(lan_default(true, Some(43_210)), "auto:43210");
        assert_eq!(lan_default(false, Some(43_210)), "127.0.0.1:43210");
        let cmd = Cli::try_parse_from(["raven-node", "lan-default", "--data-dir", "x"])
            .unwrap()
            .cmd;
        assert!(cmd.data_dir().is_none());
        match cmd {
            Commands::LanDefault { data_dir } => assert_eq!(data_dir, Some(PathBuf::from("x"))),
            _ => unreachable!(),
        }
        let fresh = tempfile::tempdir().unwrap();
        assert_eq!(
            lan_default(
                raven_core::lan_auto_live(),
                raven_core::node_policy::profile_lan_port(fresh.path())
            ),
            lan_default(raven_core::lan_auto_live(), None)
        );
        assert!(!raven_core::node_policy::policy_path(fresh.path()).exists());
    }

    /// P5.27: `ble-status` names the nearby gate and backend and says it
    /// opened no radio (the retired CoreBluetooth lines are gone).
    #[test]
    fn ble_status_names_the_gate_and_the_backend() {
        assert_eq!(
            ble_status_lines(false, "none")[..3],
            [
                "nearby_gate=held",
                "nearby_backend=none",
                "nearby_radio=not_opened"
            ]
        );
        assert_eq!(ble_status_lines(true, "ether_hub")[0], "nearby_gate=lab");
    }

    /// P5.26: `raven-node nearby-ether` (the lab Bluetooth ether hub) exists
    /// in debug builds only, hidden, with no profile; a release build does
    /// not know the word.
    #[test]
    fn nearby_ether_is_a_hidden_debug_only_command() {
        let parsed = Cli::try_parse_from([
            "raven-node",
            "nearby-ether",
            "--print-port",
            "--mtu",
            "185",
            "--rate",
            "20000",
            "--drop-after",
            "40",
        ]);
        #[cfg(debug_assertions)]
        {
            use clap::CommandFactory;
            let cmd = parsed.unwrap().cmd;
            assert!(cmd.data_dir().is_none());
            match cmd {
                Commands::NearbyEther {
                    listen,
                    print_port,
                    mtu,
                    rate,
                    latency_ms,
                    drop_after,
                    disconnect_after,
                } => {
                    assert_eq!(listen, "127.0.0.1:0".parse::<SocketAddr>().unwrap());
                    assert!(print_port);
                    assert_eq!((mtu, rate, latency_ms), (185, 20_000, 0));
                    assert_eq!((drop_after, disconnect_after), (Some(40), None));
                }
                _ => unreachable!(),
            }
            let cli = Cli::command();
            assert!(cli.find_subcommand("nearby-ether").unwrap().is_hide_set());
        }
        #[cfg(not(debug_assertions))]
        assert!(parsed.is_err());
    }

    fn relay_via(seed: u8) -> String {
        let peer = raven_core::p2p_route::local_peer_id(&Identity::from_seed(&[seed; 32]));
        format!("/ip4/198.51.100.{seed}/tcp/7423/p2p/{peer}")
    }

    /// Owner decision 7 (Phase 2): `--relay`, `--relay-open` and
    /// RAVEN_P2P_RELAY=1 are consent for the friend relay, which relays
    /// under its own key; relaying under the profile PeerId (`relay_server`)
    /// is left only to the debug switch RAVEN_LAB_P2P_PROFILE_RELAY=1, which
    /// keeps the flags for it. `--relay-open` is an alias with a note.
    #[test]
    fn relay_flags_are_friend_relay_consent_and_the_profile_relay_is_lab_only() {
        use clap::CommandFactory;
        let cli = Cli::command();
        let service = cli.find_subcommand("service").expect("service");
        let help = |id: &str| {
            service
                .get_arguments()
                .find(|a| a.get_id() == id)
                .and_then(|a| a.get_help())
                .map(|h| h.to_string())
                .unwrap_or_default()
        };
        let relay_help = help("relay");
        for words in [
            "OWN relay key",
            "friend_relay/",
            "7427",
            "raven relay offer on",
            "RAVEN_P2P_RELAY=1",
            "A saved `raven relay offer off` wins",
        ] {
            assert!(relay_help.contains(words), "{relay_help}");
        }
        let open = help("relay_open");
        assert!(
            open.contains("Same as --relay") && open.contains("`raven-node relay --open`"),
            "{open}"
        );
        assert!(RELAY_OPEN_NOTE.contains("same as --relay"));
        assert!(RELAY_OPEN_NOTE.contains("`raven-node relay --open`"));
        // An alias: `--relay-open` alone is accepted.
        assert!(Cli::try_parse_from(["raven-node", "service", "--relay-open"]).is_ok());
        // The profile-key role only under the debug switch.
        let lab = raven_core::p2p_profile_relay_test_enabled();
        for (relay, open) in [(true, true), (false, true), (true, false)] {
            let decision = service_p2p_config(
                Some("7423"),
                None,
                &[],
                None,
                relay,
                None,
                open,
                false,
                || Ok(raven_core::NodePolicy::default()),
            )
            .unwrap();
            match decision {
                P2pDecision::On(c, _) => assert_eq!(c.relay_server, lab.then_some(open)),
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(profile_relay_role(true, true, true), Some(true));
        assert_eq!(profile_relay_role(true, false, true), Some(false));
        assert_eq!(profile_relay_role(true, true, false), None);
        assert_eq!(profile_relay_role(false, false, true), None);
        // Friend relay consent: any of the three, unless the switch keeps
        // them for the profile-key role.
        for (relay, open, env, profile_lab, consent) in [
            (false, false, None, false, false),
            (true, false, None, false, true),
            (false, true, None, false, true),
            (false, false, Some("1"), false, true),
            (false, false, Some(" 1 "), false, true),
            (false, false, Some("0"), false, false),
            (false, false, Some("yes"), false, false),
            (true, true, Some("1"), true, false),
        ] {
            assert_eq!(
                friend_relay_flag(relay, open, env, profile_lab),
                consent,
                "{relay} {open} {env:?} {profile_lab}"
            );
        }
    }

    /// P3: the libp2p host is opt-in like Internet direct (flag, then env, then
    /// node_policy.json), relays are strict and at most two, the retired
    /// relay role (debug RAVEN_LAB_P2P_PROFILE_RELAY=1 only) needs `--relay`
    /// or RAVEN_P2P_RELAY=1, and UPnP comes from the policy.
    #[test]
    fn p2p_is_opt_in_strict_and_the_flag_wins() {
        use raven_core::p2p_route::P2pListen;
        let policy = |listen: &str, relays: Vec<String>, upnp: Option<bool>| {
            let p = raven_core::NodePolicy {
                p2p_listen: listen.into(),
                p2p_relays: relays,
                upnp,
                ..raven_core::NodePolicy::default()
            };
            move || Ok(p.clone())
        };
        type Got = Result<Option<(p2p::P2pConfig, &'static str)>, String>;
        fn cfg(
            flag: Option<&str>,
            env: Option<&str>,
            flag_relays: &[String],
            env_relays: Option<&str>,
            relay: bool,
            env_relay: Option<&str>,
            p: impl FnOnce() -> Result<raven_core::NodePolicy, String>,
        ) -> Got {
            service_p2p_config(
                flag,
                env,
                flag_relays,
                env_relays,
                relay,
                env_relay,
                false,
                false,
                p,
            )
            .map(|d| match d {
                P2pDecision::Off(_) => None,
                P2pDecision::On(c, source) => Some((c, source)),
            })
        }
        // Nothing configured anywhere: no host at all.
        assert_eq!(
            cfg(None, None, &[], None, false, None, policy("", vec![], None)).unwrap(),
            None
        );
        // Privacy pack PP.6: relays from the policy wait for the at-rest
        // key only while its sealed sidecar cannot be read; relays from a
        // flag or the environment never do.
        let pending = |flag_relays: &[String], peers_pending: bool| match service_p2p_config(
            Some("7423"),
            None,
            flag_relays,
            None,
            false,
            None,
            false,
            peers_pending,
            policy("", vec![relay_via(1)], None),
        )
        .unwrap()
        {
            P2pDecision::On(c, _) => c.policy_relays_pending,
            other => panic!("{other:?}"),
        };
        assert!(pending(&[], true));
        assert!(!pending(&[], false));
        assert!(!pending(&[relay_via(2)], true));
        // The policy (`raven node p2p on`), with its relays and UPnP choice.
        let (c, source) = cfg(
            None,
            None,
            &[],
            None,
            false,
            None,
            policy("7423", vec![relay_via(1)], Some(true)),
        )
        .unwrap()
        .unwrap();
        assert_eq!(source, "node_policy.json");
        assert_eq!(c.listen, P2pListen::All(7423));
        assert!(!c.retired_relay);
        assert_eq!(c.relays.len(), 1);
        assert_eq!(c.upnp, Some(true));
        assert_eq!(c.relay_server, None);
        // Automatic relay choice (C7) only while relay offers are live, then
        // as node policy says (on unless turned off).
        let offers_live = raven_core::relay_offers_live();
        assert_eq!(c.auto, offers_live.then_some(true));
        let off = raven_core::NodePolicy {
            p2p_listen: "7423".into(),
            relay_auto: Some(false),
            ..raven_core::NodePolicy::default()
        };
        let (c, _) = cfg(None, None, &[], None, false, None, move || Ok(off.clone()))
            .unwrap()
            .unwrap();
        assert_eq!(c.auto, offers_live.then_some(false));
        // The env beats the policy, the flag beats both; empty or off is off.
        // The retired `relay` listens on 7423 (unless the debug test switch).
        let (c, source) = cfg(
            None,
            Some("relay"),
            &[],
            None,
            false,
            None,
            policy("7423", vec![], None),
        )
        .unwrap()
        .unwrap();
        let relay_only = raven_core::p2p_relay_only_test_enabled();
        assert_eq!(
            (c.listen, c.retired_relay, source),
            if relay_only {
                (P2pListen::RelayOnly, false, "RAVEN_P2P_LISTEN")
            } else {
                (P2pListen::All(7423), true, "RAVEN_P2P_LISTEN")
            }
        );
        let (c, _) = cfg(
            Some("relay"),
            None,
            &[],
            None,
            false,
            None,
            policy("", vec![], None),
        )
        .unwrap()
        .unwrap();
        assert_eq!(c.retired_relay, !relay_only, "--p2p-listen relay");
        assert_eq!(c.listen.multiaddrs().is_empty(), relay_only);
        assert_eq!(
            cfg(
                Some("off"),
                Some("7423"),
                &[],
                None,
                false,
                None,
                policy("7423", vec![], None)
            )
            .unwrap(),
            None
        );
        // "Off" says where it came from: `raven status` shows that the running
        // service has p2p off because of a flag or env var (review item 8).
        for (flag, env, listen, source) in [
            (Some("off"), Some("7423"), "7423", "--p2p-listen"),
            (None, Some("off"), "7423", "RAVEN_P2P_LISTEN"),
            (None, None, "", "node_policy.json"),
        ] {
            assert_eq!(
                service_p2p_config(
                    flag,
                    env,
                    &[],
                    None,
                    false,
                    None,
                    false,
                    false,
                    policy(listen, vec![], None)
                )
                .unwrap(),
                P2pDecision::Off(source)
            );
        }
        // Relays: flag, then RAVEN_P2P_RELAYS (comma separated), then policy.
        let env = format!("{} , {}", relay_via(2), relay_via(3));
        let (c, _) = cfg(
            Some("127.0.0.1:0"),
            None,
            &[],
            Some(&env),
            false,
            None,
            policy("", vec![relay_via(1)], None),
        )
        .unwrap()
        .unwrap();
        assert_eq!(c.relays.len(), 2);
        let flag = vec![relay_via(4)];
        let (c, _) = cfg(
            Some("7423"),
            None,
            &flag,
            Some(&env),
            true,
            None,
            policy("", vec![], None),
        )
        .unwrap()
        .unwrap();
        assert_eq!(c.relays.len(), 1);
        let profile_lab = raven_core::p2p_profile_relay_test_enabled();
        assert_eq!(c.relay_server, profile_lab.then_some(false), "--relay");
        let (c, _) = cfg(
            Some("7423"),
            None,
            &[],
            None,
            false,
            Some("1"),
            policy("", vec![], None),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            c.relay_server,
            profile_lab.then_some(false),
            "RAVEN_P2P_RELAY=1"
        );
        // Junk or too many relays: no host (fail closed), with the source named.
        let three = vec![relay_via(1), relay_via(2), relay_via(3)];
        assert!(cfg(
            Some("7423"),
            None,
            &three,
            None,
            false,
            None,
            policy("", vec![], None)
        )
        .unwrap_err()
        .starts_with("--p2p-relay: at most 2"));
        let bad = vec!["/ip4/198.51.100.1/tcp/7423".to_string()];
        assert!(cfg(
            Some("7423"),
            None,
            &bad,
            None,
            false,
            None,
            policy("", vec![], None)
        )
        .is_err());
        assert!(cfg(
            Some("example.com:7423"),
            None,
            &[],
            None,
            false,
            None,
            policy("", vec![], None)
        )
        .unwrap_err()
        .starts_with("--p2p-listen: "));
        // An unreadable policy: off when it is needed, irrelevant when not.
        let broken = || Err("node_policy.json unreadable".to_string());
        assert!(cfg(None, None, &[], None, false, None, broken).is_err());
        let (c, _) = cfg(Some("7423"), None, &flag, None, false, None, broken)
            .unwrap()
            .unwrap();
        assert_eq!(c.upnp, None, "UPnP stays off");
    }

    /// Phase 4 (RWS1 §8.2): the proxy setting of relay dials over WSS comes
    /// from `--p2p-proxy`, then `RAVEN_P2P_PROXY` (empty is unset), then
    /// node_policy.json, read only when neither is given; only the policy's
    /// may wait for the sealed sidecar. A bad value stops the p2p host like
    /// a bad relay, naming the source and never the text; node_policy.json
    /// never holds credentials; an unreadable policy is `off`. With p2p off
    /// nothing is looked at.
    #[test]
    fn a_bad_p2p_proxy_value_stops_the_p2p_host_like_a_bad_relay() {
        use raven_core::net_proxy::{parse_setting, ProxySetting};
        let on = || {
            service_p2p_config(
                Some("7423"),
                None,
                &[],
                None,
                false,
                None,
                false,
                false,
                || Ok(raven_core::NodePolicy::default()),
            )
            .unwrap()
        };
        let proxy = |flag: Option<&str>,
                     env: Option<&str>,
                     pending: bool,
                     policy: Result<&str, &str>|
         -> Result<p2p::P2pProxy, String> {
            let read = std::cell::Cell::new(false);
            let got = service_p2p_proxy(on(), flag, env, pending, || {
                read.set(true);
                policy.map(String::from).map_err(String::from)
            });
            assert_eq!(
                read.get(),
                flag.is_none() && env.is_none_or(|e| e.trim().is_empty())
            );
            match got? {
                P2pDecision::On(config, source) => {
                    assert_eq!(source, "--p2p-listen");
                    Ok(config.proxy)
                }
                other => panic!("{other:?}"),
            }
        };
        let url = |text: &str| parse_setting(text).unwrap();
        let p = proxy(None, None, false, Ok("")).unwrap();
        assert_eq!(
            (p.setting, p.source, p.pending),
            (ProxySetting::Auto, "node_policy.json", false)
        );
        // Review B-5: the sealed sidecar not read yet and nothing in the
        // plain file: off (direct) until the saved value arrives, never the
        // environment's or the system's proxy the policy may have turned off.
        let p = proxy(None, None, true, Ok("")).unwrap();
        assert_eq!(
            (p.setting, p.source, p.pending),
            (ProxySetting::Off, "node_policy.json", true)
        );
        let p = proxy(None, Some(" "), true, Ok(" ")).unwrap();
        assert_eq!((p.setting, p.pending), (ProxySetting::Off, true));
        let p = proxy(None, Some("  "), true, Ok("http://policy.example:3128")).unwrap();
        assert_eq!(p.setting, url("http://policy.example:3128"));
        assert!(p.pending, "the policy's may wait for the sealed sidecar");
        let p = proxy(None, Some("off"), true, Ok("http://policy.example:3128")).unwrap();
        assert_eq!(
            (p.setting, p.source, p.pending),
            (ProxySetting::Off, "RAVEN_P2P_PROXY", false)
        );
        let p = proxy(Some("auto"), Some("off"), true, Ok("off")).unwrap();
        assert_eq!(
            (p.setting, p.source, p.pending),
            (ProxySetting::Auto, "--p2p-proxy", false)
        );
        // Credentials: in the environment, never in the policy; the flag
        // still takes them, with a note that other local users can read
        // them (review B-7), which never repeats them.
        let secret = "http://user:hunter2@proxy.example:3128";
        assert!(proxy(Some(secret), None, false, Ok("")).unwrap().setting != ProxySetting::Auto);
        assert!(proxy(None, Some(secret), false, Ok("")).is_ok());
        let note = proxy::argv_credentials_note(secret, "--p2p-proxy").unwrap();
        assert!(note.contains("give them only in RAVEN_P2P_PROXY"), "{note}");
        assert!(!note.contains("hunter2") && !note.contains("proxy.example"));
        assert_eq!(
            proxy::argv_credentials_note(secret, "RAVEN_P2P_PROXY"),
            None
        );
        assert_eq!(
            proxy::argv_credentials_note("http://proxy.example:3128", "--p2p-proxy"),
            None
        );
        let refused = proxy(None, None, false, Ok(secret)).unwrap_err();
        assert!(
            refused.contains("only in RAVEN_P2P_PROXY") && !refused.contains("--p2p-proxy"),
            "{refused}"
        );
        assert!(!raven_core::node_policy::PolicyError::ProxyCredentials
            .to_string()
            .contains("--p2p-proxy"));
        let help = {
            use clap::CommandFactory;
            let mut cmd = Cli::command();
            cmd.build();
            cmd.find_subcommand("service")
                .and_then(|s| s.get_arguments().find(|a| a.get_id() == "p2p_proxy"))
                .map(|a| a.get_help().map(|h| h.to_string()).unwrap_or_default())
                .unwrap()
        };
        assert!(!help.contains("user:pass@"), "{help}");
        // Bad values: an error (main prints `p2p failed: …`, no host), like a
        // bad relay; the text is never repeated.
        for (flag, env, policy, source) in [
            (
                Some("socks5://proxy.example:1080"),
                None,
                "",
                "--p2p-proxy: ",
            ),
            (None, Some("https://proxy.example"), "", "RAVEN_P2P_PROXY: "),
            (None, None, "http://proxy.example:0", "node_policy.json: "),
            (None, None, secret, "node_policy.json: "),
        ] {
            let err = proxy(flag, env, false, Ok(policy)).unwrap_err();
            assert!(err.starts_with(source), "{err}");
            assert!(
                !err.contains("proxy.example") && !err.contains("hunter2"),
                "{err}"
            );
        }
        let bad_relay = service_p2p_config(
            Some("7423"),
            None,
            &["/ip4/203.0.113.7/tcp/7423".to_string()],
            None,
            false,
            None,
            false,
            false,
            || Ok(raven_core::NodePolicy::default()),
        )
        .unwrap_err();
        assert!(bad_relay.starts_with("--p2p-relay: "), "{bad_relay}");
        // An unreadable policy: off when it is needed.
        let p = proxy(None, None, false, Err("node_policy.json unreadable")).unwrap();
        assert_eq!(p.setting, ProxySetting::Off);
        // p2p off: the proxy is not looked at, a bad one included.
        let off = service_p2p_proxy(
            P2pDecision::Off("--p2p-listen"),
            Some("socks5://proxy.example:1080"),
            None,
            false,
            || unreachable!(),
        );
        assert_eq!(off, Ok(P2pDecision::Off("--p2p-listen")));
        assert!(Cli::try_parse_from(["raven-node", "service", "--p2p-proxy", "off"]).is_ok());
    }

    /// Phase 1 item 2: `relay` (no listener: it can never hole-punch) is
    /// retired. It still parses, so an old node_policy.json or env value is
    /// no config error, but the host listens on 7423 like `on` and says so;
    /// only the debug test switch keeps the old no-listener mode (C6).
    /// Written against `effective`, so the environment is never touched.
    #[test]
    fn relay_listen_is_retired_unless_the_test_switch() {
        use clap::CommandFactory;
        use raven_core::p2p_route::{normalize_p2p_listen, P2pListen, DEFAULT_P2P_PORT};
        for raw in ["relay", " Relay "] {
            let parsed = normalize_p2p_listen(raw).unwrap().unwrap();
            assert_eq!(parsed, P2pListen::RelayOnly);
            let (listen, retired) = parsed.effective(false);
            assert_eq!((listen, retired), (P2pListen::All(DEFAULT_P2P_PORT), true));
            assert_eq!(
                listen.multiaddrs(),
                P2pListen::All(DEFAULT_P2P_PORT).multiaddrs()
            );
            assert_eq!(parsed.effective(true), (P2pListen::RelayOnly, false));
        }
        for raw in ["on", "7423", "127.0.0.1:0", "[::1]:7423"] {
            let parsed = normalize_p2p_listen(raw).unwrap().unwrap();
            assert_eq!(parsed.effective(false), (parsed, false), "{raw}");
        }
        // The switch is debug only: a release build never keeps `relay`.
        if !cfg!(debug_assertions) {
            assert!(!raven_core::p2p_relay_only_test_enabled());
        }
        // The help says so and still names `relay`, so scripts keep parsing.
        let cli = Cli::command();
        let arg = cli
            .find_subcommand("service")
            .and_then(|s| s.get_arguments().find(|a| a.get_id() == "p2p_listen"))
            .expect("--p2p-listen")
            .clone();
        let help = arg.get_help().map(|h| h.to_string()).unwrap_or_default();
        assert!(
            help.contains("`relay` is retired") && help.contains("RAVEN_LAB_P2P_RELAY_ONLY=1"),
            "{help}"
        );
        let names: Vec<String> = arg
            .get_value_names()
            .unwrap_or_default()
            .iter()
            .map(|n| n.to_string())
            .collect();
        assert_eq!(names, ["PORT|IP:PORT|relay|off"]);
    }

    /// `raven-node relay --listen <listen>` with every other flag at its
    /// default.
    fn relay_flags(listen: &str) -> RelayFlags<'_> {
        RelayFlags {
            listen,
            open: false,
            autonat_server: false,
            external: &[],
            also_tcp: &[],
            public_host: None,
            wss: WssArgs::default(),
            counts_every: 30,
            limits: RelayLimitArgs::default(),
        }
    }

    #[test]
    fn relay_limits_flags_are_validated_never_clamped() {
        let dir = PathBuf::from("relay-dir");
        let ok = relay_command(dir.clone(), relay_flags("7423")).unwrap();
        assert_eq!(ok.limits, raven_swarm::host::RelayLimits::friends());
        assert_eq!(ok.label, "raven-node relay");
        assert!(matches!(ok.policy, relay::PolicySource::File));
        assert!(!ok.upnp && !ok.extra_best_effort && ok.status_sink.is_none());
        assert_eq!(ok.counts_every, Duration::from_secs(30));
        let open = relay_command(
            dir.clone(),
            RelayFlags {
                open: true,
                ..relay_flags("7423")
            },
        )
        .unwrap();
        assert_eq!(open.limits, raven_swarm::host::RelayLimits::open());
        let external = ["/ip4/203.0.113.7/tcp/7423".to_string()];
        let tuned = relay_command(
            dir.clone(),
            RelayFlags {
                autonat_server: true,
                external: &external,
                limits: RelayLimitArgs {
                    max_reservations: Some(10),
                    circuit_bytes: Some(1 << 20),
                    circuit_secs: Some(60),
                    ..RelayLimitArgs::default()
                },
                ..relay_flags("127.0.0.1:0")
            },
        )
        .unwrap();
        assert_eq!(tuned.limits.max_reservations, 10);
        assert_eq!(tuned.limits.max_circuit_bytes, 1 << 20);
        assert_eq!(tuned.external.len(), 1);
        for args in [
            RelayLimitArgs {
                circuit_bytes: Some(17 << 20),
                ..RelayLimitArgs::default()
            },
            RelayLimitArgs {
                max_circuits: Some(0),
                ..RelayLimitArgs::default()
            },
            RelayLimitArgs {
                reservation_secs: Some(3 * 3600),
                ..RelayLimitArgs::default()
            },
        ] {
            let flags = RelayFlags {
                limits: args,
                ..relay_flags("7423")
            };
            assert!(relay_command(dir.clone(), flags).is_err());
        }
        assert!(relay_command(dir.clone(), relay_flags("relay")).is_err());
        let bad = ["not a multiaddr".to_string()];
        let flags = RelayFlags {
            external: &bad,
            ..relay_flags("7423")
        };
        assert!(relay_command(dir, flags).is_err());
    }

    #[test]
    fn relay_counts_every_is_bounded_by_the_flag() {
        let parse = |extra: &[&str]| {
            let mut args = vec!["raven-node", "relay", "--data-dir", "r"];
            args.extend_from_slice(extra);
            Cli::try_parse_from(args)
        };
        match parse(&[]).unwrap().cmd {
            Commands::Relay {
                counts_every,
                check,
                ..
            } => assert_eq!((counts_every, check), (30, false)),
            _ => unreachable!(),
        }
        assert!(parse(&["--counts-every", "3600", "--check"]).is_ok());
        assert!(parse(&["--counts-every", "29"]).is_err());
        assert!(parse(&["--counts-every", "3601"]).is_err());
    }

    #[test]
    fn relay_extra_tcp_and_public_host_rules() {
        let dir = PathBuf::from("relay-dir");
        let run = |listen: &str, also: &[&str], host: Option<&str>| {
            let also: Vec<String> = also.iter().map(|s| s.to_string()).collect();
            relay_command(
                dir.clone(),
                RelayFlags {
                    also_tcp: &also,
                    public_host: host,
                    ..relay_flags(listen)
                },
            )
        };
        use raven_core::p2p_route::ExtraTcp;
        let tcp = |local, public| ExtraTcp { local, public };
        // Accepted.
        assert_eq!(
            run("7423", &["443"], None).unwrap().also_tcp,
            [tcp(443, 443)]
        );
        assert_eq!(
            run("7423", &["7443:443"], None).unwrap().also_tcp,
            [tcp(7443, 443)]
        );
        assert_eq!(
            run("127.0.0.1:0", &["0"], None).unwrap().also_tcp,
            [tcp(0, 0)]
        );
        assert_eq!(
            run("7423", &["443", "7443:8443"], None)
                .unwrap()
                .also_tcp
                .len(),
            2
        );
        // Refused.
        for (listen, also, host) in [
            ("7423", &["abc"][..], None),
            ("7423", &["1:2:3"][..], None),
            ("7423", &["7423"][..], None),
            ("127.0.0.1:7423", &["7423"][..], None),
            ("7423", &["443", "8443", "9443"][..], None),
            ("127.0.0.1:0", &[][..], Some("127.0.0.1")),
            ("7423", &["0"][..], Some("relay.example.org")),
            ("7423", &[][..], Some("0.0.0.0")),
            ("7423", &[][..], Some("not a host")),
        ] {
            let err = run(listen, also, host).unwrap_err();
            assert!(!err.is_empty(), "{listen} {also:?} {host:?}");
        }
        assert!(run("127.0.0.1:0", &[], Some("127.0.0.1"))
            .unwrap_err()
            .contains("--public-host needs fixed ports"));
        assert!(run("7423", &[], Some("0.0.0.0"))
            .unwrap_err()
            .starts_with("--public-host: "));
        // `--public-host` names every listening port, in that order, after
        // `--external`.
        let named = |cmd: relay::RelayCmd| -> Vec<String> {
            cmd.external.iter().map(|a| a.to_string()).collect()
        };
        assert_eq!(
            named(run("7423", &["443"], Some("relay.example.org")).unwrap()),
            [
                "/dns/relay.example.org/tcp/7423",
                "/dns/relay.example.org/udp/7423/quic-v1",
                "/dns/relay.example.org/tcp/443",
            ]
        );
        assert_eq!(
            named(run("0.0.0.0:7423", &["7443:443"], Some("[2001:db8::7]")).unwrap()),
            [
                "/ip6/2001:db8::7/tcp/7423",
                "/ip6/2001:db8::7/udp/7423/quic-v1",
                "/ip6/2001:db8::7/tcp/443",
            ]
        );
        let external = ["/ip4/203.0.113.7/tcp/7423".to_string()];
        let both = relay_command(
            dir.clone(),
            RelayFlags {
                external: &external,
                public_host: Some("203.0.113.7"),
                ..relay_flags("7423")
            },
        )
        .unwrap();
        assert_eq!(
            named(both),
            [
                "/ip4/203.0.113.7/tcp/7423",
                "/ip4/203.0.113.7/udp/7423/quic-v1",
            ],
            "no duplicate"
        );
    }

    /// `raven-node relay --wss` (RWS1 §6), the relay_command table:
    /// - refused with WSS_HOLD (main.rs exits 2 on any relay_command error)
    ///   while the WSS gate is closed, before any other flag;
    /// - a WSS port equal to a raw TCP listen port (Phase 2's raw 443, or
    ///   `--listen`'s) is not refused: the raw listener on that port is
    ///   dropped and the port is never bound twice;
    /// - `--wss-cert` and `--wss-key` only together, `--wss-name` only for
    ///   the self-signed certificate, none of them without `--wss`;
    /// - `--public-host` names the WSS port without a WSS suffix.
    #[test]
    fn relay_wss_flags_table() {
        use raven_core::p2p_route::P2pListen;
        use relay::{WssCert, WssListen};
        fn run(
            listen: &str,
            also: &[&str],
            host: Option<&str>,
            wss: WssArgs<'_>,
            live: bool,
        ) -> Result<relay::RelayCmd, String> {
            let also: Vec<String> = also.iter().map(|s| s.to_string()).collect();
            relay_command_with(
                PathBuf::from("relay-dir"),
                RelayFlags {
                    also_tcp: &also,
                    public_host: host,
                    wss,
                    ..relay_flags(listen)
                },
                live,
            )
        }
        let wss = |listen| WssArgs {
            listen: Some(listen),
            ..WssArgs::default()
        };
        let (cert, key) = (Path::new("fullchain.pem"), Path::new("privkey.pem"));
        let names = ["relay.example.org".to_string()];

        // Held: WSS_HOLD before anything else is looked at.
        for args in [
            wss("443"),
            wss("not a port"),
            WssArgs {
                cert: Some(cert),
                ..wss("443")
            },
        ] {
            let err = run("not a port", &[], None, args, false).unwrap_err();
            assert_eq!(err, raven_core::WSS_HOLD);
        }
        let built = relay_command(
            PathBuf::from("relay-dir"),
            RelayFlags {
                wss: wss("443"),
                ..relay_flags("7423")
            },
        );
        if raven_core::wss_live_enabled() {
            assert!(built.unwrap().wss.is_some());
        } else {
            assert_eq!(built.unwrap_err(), raven_core::WSS_HOLD);
        }
        // Without --wss nothing changes, held or not.
        for live in [false, true] {
            assert!(run("7423", &[], None, WssArgs::default(), live)
                .unwrap()
                .wss
                .is_none());
        }

        // Live: PORT (every interface) or IP:PORT, self-signed by default.
        assert_eq!(
            run("7423", &[], None, wss(" 443 "), true).unwrap().wss,
            Some(WssListen {
                listen: P2pListen::All(443),
                cert: WssCert::Ephemeral(Vec::new()),
            })
        );
        for (text, at) in [("127.0.0.1:0", "127.0.0.1:0"), ("[::1]:8443", "[::1]:8443")] {
            assert_eq!(
                run("7423", &[], None, wss(text), true)
                    .unwrap()
                    .wss
                    .unwrap()
                    .listen,
                P2pListen::One(at.parse().unwrap())
            );
        }
        for bad in [
            "",
            "on",
            "off",
            "relay",
            "0443",
            "+443",
            "65536",
            "443:443",
            "abc",
            "relay.example.org:443",
        ] {
            let err = run("7423", &[], None, wss(bad), true).unwrap_err();
            assert!(err.starts_with("--wss must be a port"), "{bad}: {err}");
        }

        // A WSS port equal to a raw listen port is converted, never shared.
        for (listen, also, at, shared) in [
            ("7423", &["443"][..], "443", 443),
            ("443", &[][..], "443", 443),
            ("7423", &["7443:443"][..], "7443", 7443),
            ("127.0.0.1:7423", &[][..], "127.0.0.1:7423", 7423),
        ] {
            let cmd = run(listen, also, None, wss(at), true).unwrap();
            assert_eq!(cmd.also_tcp.len(), also.len(), "the mapping is kept");
            let plan = relay::listen_plan(&cmd).unwrap();
            assert_eq!(plan.shared, [shared], "{listen} {also:?} {at}");
            let raw = plan
                .addrs
                .iter()
                .map(|a| a.to_string())
                .filter(|a| a.ends_with(&format!("/tcp/{shared}")))
                .collect::<Vec<_>>();
            assert!(raw.is_empty(), "a raw listener beside WSS: {raw:?}");
            let wss_forms = plan
                .addrs
                .iter()
                .filter(|a| a.to_string().ends_with(&format!("/tcp/{shared}/tls/ws")))
                .count();
            assert!(wss_forms >= 1);
        }

        // --wss-cert and --wss-key only together.
        for args in [
            WssArgs {
                cert: Some(cert),
                ..wss("443")
            },
            WssArgs {
                key: Some(key),
                ..wss("443")
            },
        ] {
            let err = run("7423", &[], None, args, true).unwrap_err();
            assert_eq!(
                err,
                "--wss-cert and --wss-key go together (the certificate chain and its private key)"
            );
        }
        let files = WssArgs {
            cert: Some(cert),
            key: Some(key),
            ..wss("443")
        };
        assert_eq!(
            run("7423", &[], None, files, true)
                .unwrap()
                .wss
                .unwrap()
                .cert,
            WssCert::Files(cert.into(), key.into())
        );
        let err = run(
            "7423",
            &[],
            None,
            WssArgs {
                names: &names,
                ..files
            },
            true,
        )
        .unwrap_err();
        assert!(err.starts_with("--wss-name names the self-signed"), "{err}");
        // None of them without --wss, held or not.
        for live in [false, true] {
            for args in [
                WssArgs {
                    cert: Some(cert),
                    ..WssArgs::default()
                },
                WssArgs {
                    key: Some(key),
                    ..WssArgs::default()
                },
                WssArgs {
                    names: &names,
                    ..WssArgs::default()
                },
            ] {
                assert_eq!(
                    run("7423", &[], None, args, live).unwrap_err(),
                    "--wss-cert, --wss-key and --wss-name need --wss"
                );
            }
        }

        // The self-signed certificate's names: a DNS name (lower case) or
        // an IP address, once each.
        let given: Vec<String> = [
            "Relay.Example.ORG",
            "203.0.113.7",
            "[2001:DB8::7]",
            "relay.example.org",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(
            run(
                "7423",
                &[],
                None,
                WssArgs {
                    names: &given,
                    ..wss("443")
                },
                true
            )
            .unwrap()
            .wss
            .unwrap()
            .cert,
            WssCert::Ephemeral(vec![
                "relay.example.org".into(),
                "203.0.113.7".into(),
                "2001:db8::7".into()
            ])
        );
        for bad in ["not a name", "0.0.0.0", "-relay.example.org", "a..b"] {
            let one = [bad.to_string()];
            let err = run(
                "7423",
                &[],
                None,
                WssArgs {
                    names: &one,
                    ..wss("443")
                },
                true,
            )
            .unwrap_err();
            assert!(err.starts_with("--wss-name: "), "{bad}: {err}");
        }

        // --public-host names the WSS port, plain (RWS1 §2.2), once.
        let named = |cmd: relay::RelayCmd| -> Vec<String> {
            cmd.external.iter().map(|a| a.to_string()).collect()
        };
        let host = Some("relay.example.org");
        let want = [
            "/dns/relay.example.org/tcp/7423",
            "/dns/relay.example.org/udp/7423/quic-v1",
            "/dns/relay.example.org/tcp/443",
        ];
        assert_eq!(
            named(run("7423", &[], host, wss("443"), true).unwrap()),
            want
        );
        assert_eq!(
            named(run("7423", &["443"], host, wss("443"), true).unwrap()),
            want
        );
        assert_eq!(
            named(run("7423", &["7443:443"], host, wss("7443"), true).unwrap()),
            want
        );
        assert_eq!(
            named(run("443", &[], host, wss("443"), true).unwrap()),
            [
                "/dns/relay.example.org/tcp/443",
                "/dns/relay.example.org/udp/443/quic-v1"
            ]
        );
        assert!(run(
            "127.0.0.1:7423",
            &[],
            Some("127.0.0.1"),
            wss("127.0.0.1:0"),
            true
        )
        .unwrap_err()
        .contains("--public-host needs fixed ports"));

        // The flags as clap reads them.
        let cli = Cli::try_parse_from([
            "raven-node",
            "relay",
            "--data-dir",
            "r",
            "--wss",
            "443",
            "--wss-name",
            "a.example.org",
            "--wss-name",
            "203.0.113.7",
        ])
        .unwrap();
        match cli.cmd {
            Commands::Relay {
                wss,
                wss_cert,
                wss_key,
                wss_name,
                ..
            } => {
                assert_eq!(wss.as_deref(), Some("443"));
                assert!(wss_cert.is_none() && wss_key.is_none());
                assert_eq!(wss_name, ["a.example.org", "203.0.113.7"]);
            }
            _ => unreachable!(),
        }
    }

    /// The repository root (docs/, node/scripts/install/).
    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
    }

    /// The code of a Markdown text: every line of a fenced block, and every
    /// `inline span` of the other lines.
    fn markdown_code(doc: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut fenced = false;
        for line in doc.lines() {
            if line.trim_start().starts_with("```") {
                fenced = !fenced;
                continue;
            }
            if fenced {
                out.push(line.to_string());
            } else {
                out.extend(line.split('`').skip(1).step_by(2).map(String::from));
            }
        }
        out
    }

    /// The words after each `program` in `code` that runs it (first in its
    /// segment, or after sudo, env, a separator or a VAR=value), up to a
    /// shell separator or a comment.
    fn invocations(code: &[String], program: &str) -> Vec<Vec<String>> {
        let mut out = Vec::new();
        for segment in code {
            let words: Vec<&str> = segment.split_whitespace().collect();
            for (i, w) in words.iter().enumerate() {
                let runs = i == 0
                    || matches!(words[i - 1], "sudo" | "env" | "|" | "||" | "&&" | ";")
                    || words[i - 1].starts_with(|c: char| c.is_ascii_uppercase())
                        && words[i - 1].contains('=');
                if *w != program || !runs {
                    continue;
                }
                let args: Vec<String> = words[i + 1..]
                    .iter()
                    .take_while(|a| {
                        !matches!(**a, "|" | "||" | "&&" | ";" | ">") && !a.starts_with('#')
                    })
                    .map(|a| a.trim_end_matches(';').to_string())
                    .collect();
                out.push(args);
            }
        }
        out
    }

    /// The deepest subcommand `words` name, and the words after it.
    fn walk<'a>(cli: &'a clap::Command, words: &'a [String]) -> (&'a clap::Command, &'a [String]) {
        let mut cmd = cli;
        let mut rest = words;
        while let Some((w, tail)) = rest.split_first() {
            match cmd.find_subcommand(w.as_str()) {
                Some(sub) => {
                    cmd = sub;
                    rest = tail;
                }
                None => break,
            }
        }
        (cmd, rest)
    }

    fn has_long(cmd: &clap::Command, flag: &str) -> bool {
        let name = flag.split('=').next().unwrap_or(flag);
        name == "help" || cmd.get_arguments().any(|a| a.get_long() == Some(name))
    }

    /// docs/RELAY_KIT.md names only `raven-node` subcommands and flags that
    /// exist (every `raven-node …` in its code, and every `--flag` in its
    /// tables, which are the relay's), and only install scripts that exist.
    #[test]
    fn relay_kit_doc_names_only_real_flags() {
        use clap::CommandFactory;
        let root = repo_root();
        let doc = std::fs::read_to_string(root.join("docs/RELAY_KIT.md")).expect("RELAY_KIT.md");
        let cli = Cli::command();
        let code = markdown_code(&doc);
        let mut flags = 0;
        let mut commands = 0;
        for words in invocations(&code, "raven-node") {
            if words.is_empty() {
                continue;
            }
            let (cmd, rest) = walk(&cli, &words);
            let stray = rest
                .first()
                .filter(|w| !w.starts_with('-') && cmd.has_subcommands())
                .filter(|_| cmd.get_positionals().next().is_none());
            assert!(
                !std::ptr::eq(cmd, &cli) && stray.is_none(),
                "RELAY_KIT.md: `raven-node {}` is no subcommand",
                words.join(" ")
            );
            commands += 1;
            for w in rest {
                if let Some(flag) = w.strip_prefix("--") {
                    assert!(
                        has_long(cmd, flag),
                        "RELAY_KIT.md: `raven-node {}` has no --{flag}",
                        cmd.get_name()
                    );
                    flags += 1;
                }
            }
        }
        // The tables (limits, what a relay learns) name `raven-node relay`
        // flags on their own.
        let relay = cli.find_subcommand("relay").expect("relay");
        for line in doc.lines().filter(|l| l.starts_with('|')) {
            for span in line.split('`').skip(1).step_by(2) {
                if let Some(flag) = span.strip_prefix("--") {
                    assert!(
                        has_long(relay, flag),
                        "RELAY_KIT.md table: no relay --{flag}"
                    );
                    flags += 1;
                }
            }
        }
        assert!(
            commands >= 3 && flags >= 6,
            "{commands} commands, {flags} flags"
        );
        // Every installer the guide names exists.
        let mut scripts = 0;
        for (i, _) in doc.match_indices("node/scripts/install/") {
            let name: String = doc[i + "node/scripts/install/".len()..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
                .collect();
            let name = name.trim_end_matches('.');
            assert!(
                root.join("node/scripts/install").join(name).is_file(),
                "RELAY_KIT.md names node/scripts/install/{name}, which does not exist"
            );
            scripts += 1;
        }
        assert!(scripts >= 5, "{scripts}");
    }

    /// The relay kit never runs an open relay: no kit script names that flag
    /// (nor the profile relay's), the shared settings refuse
    /// RAVEN_RELAY_OPEN, and every flag the kit passes to `raven-node relay`
    /// exists.
    #[test]
    fn relay_kit_scripts_never_pass_open() {
        use clap::CommandFactory;
        let dir = repo_root().join("node/scripts/install");
        let mut kit: Vec<String> = std::fs::read_dir(&dir)
            .expect("install dir")
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains("relay"))
            .collect();
        kit.sort();
        assert_eq!(
            kit,
            [
                "linux_relay.sh",
                "macos_relay.sh",
                "raven-relay.sh",
                "relay_common.sh",
                "windows_relay.ps1"
            ]
        );
        let read = |name: &str| std::fs::read_to_string(dir.join(name)).expect(name);
        for name in &kit {
            let text = read(name);
            for banned in ["--open", "relay-open", "relay_open"] {
                assert!(!text.contains(banned), "{name} names {banned}");
            }
        }
        let common = read("relay_common.sh");
        assert!(common.contains("RAVEN_RELAY_OPEN is refused"));
        let cli = Cli::command();
        let relay = cli.find_subcommand("relay").expect("relay");
        // relay_common.sh's relay_args, and the PowerShell $relayArgs.
        let body = common
            .split("\nrelay_args() {\n")
            .nth(1)
            .and_then(|b| b.split("\n}\n").next())
            .expect("relay_args");
        let ps = read("windows_relay.ps1");
        let ps_args: Vec<&str> = ps.lines().filter(|l| l.contains("$relayArgs")).collect();
        let mut passed = std::collections::BTreeSet::new();
        for text in std::iter::once(body).chain(ps_args) {
            for word in text.split(|c: char| c.is_whitespace() || "()\"@,".contains(c)) {
                if let Some(flag) = word.strip_prefix("--") {
                    assert!(has_long(relay, flag), "the kit passes relay --{flag}");
                    passed.insert(flag.to_string());
                }
            }
        }
        for want in [
            "listen",
            "also-tcp",
            "public-host",
            "autonat-server",
            "counts-every",
        ] {
            assert!(passed.contains(want), "{want}: {passed:?}");
        }
        // The installers' check is `raven-node relay --check --data-dir`.
        for name in ["linux_relay.sh", "macos_relay.sh"] {
            assert!(read(name).contains("relay --check --data-dir"), "{name}");
        }
        assert!(ps.contains("relay --check --data-dir"));
        assert!(has_long(relay, "check") && has_long(relay, "data-dir"));
    }

    /// The relay kit says what `raven-relay status` prints: the allow-list
    /// (friends' PeerIds and the operator's labels) and the relay's own
    /// addresses. "Counts only" is the logs' promise, never the status
    /// command's.
    #[test]
    fn relay_kit_never_calls_status_counts_only() {
        let root = repo_root();
        let read = |rel: &str| std::fs::read_to_string(root.join(rel)).expect(rel);
        for rel in [
            "node/scripts/install/linux_relay.sh",
            "node/scripts/install/macos_relay.sh",
            "node/scripts/install/raven-relay.sh",
            "node/scripts/install/relay_common.sh",
            "node/scripts/install/windows_relay.ps1",
            "docs/RELAY_KIT.md",
        ] {
            for (i, line) in read(rel).lines().enumerate() {
                let line = line.to_lowercase();
                assert!(
                    !(line.contains("status") && line.contains("counts only")),
                    "{rel}:{}: status is not counts only: {line}",
                    i + 1
                );
            }
        }
        let words = |rel: &str| read(rel).split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(words("docs/RELAY_KIT.md").contains("so replace those before you share its output"));
    }

    /// The relay kit never offers `RAVEN_RELAY_TCP443=7443` for a 443 that
    /// a web server holds: on one IP a redirect of 443 takes the website
    /// down, and without one the cards' 443 line reaches the web server.
    /// The installers' busy-port advice offers `off`; wherever the guides
    /// pair a web server with 7443 they also say who maps the public 443 (a
    /// router or a second IP) and offer `off`.
    #[test]
    fn relay_kit_never_offers_7443_for_a_web_servers_443() {
        let root = repo_root();
        let read = |rel: &str| std::fs::read_to_string(root.join(rel)).expect(rel);
        let common = read("node/scripts/install/relay_common.sh");
        let check_failed = common
            .split("\nrelay_check_failed() {\n")
            .nth(1)
            .and_then(|b| b.split("\n}\n").next())
            .expect("relay_check_failed");
        let ps = read("node/scripts/install/windows_relay.ps1");
        let mut busy = 0;
        for (what, text, seven) in [
            ("relay_common.sh", check_failed, "RAVEN_RELAY_TCP443=7443"),
            ("windows_relay.ps1", ps.as_str(), "-Tcp443 7443"),
        ] {
            let said = |l: &&str| l.contains("echo ") || l.contains("Write-Host ");
            for line in text.lines().filter(said).filter(|l| l.contains("is busy")) {
                assert!(
                    !line.contains(seven),
                    "{what}: a busy port is offered 7443: {line}"
                );
                assert!(line.contains("off"), "{what}: {line}");
                busy += 1;
            }
        }
        assert_eq!(busy, 2, "one busy-port line in each installer");
        // Markdown blocks: paragraphs and list items.
        let blocks = |text: &str| {
            let mut out: Vec<String> = Vec::new();
            let mut cur = String::new();
            for line in text.lines() {
                let t = line.trim_start();
                let item = t.starts_with("- ")
                    || t.split_once(". ").is_some_and(|(n, _)| {
                        (1..=2).contains(&n.len()) && n.bytes().all(|b| b.is_ascii_digit())
                    });
                if t.is_empty() || item {
                    out.push(std::mem::take(&mut cur));
                }
                cur.push(' ');
                cur.push_str(t);
            }
            out.push(cur);
            out
        };
        let mut paired = 0;
        for (rel, seven, off) in [
            (
                "docs/RELAY_KIT.md",
                "RAVEN_RELAY_TCP443=7443",
                "RAVEN_RELAY_TCP443=off",
            ),
            ("docs/INSTALL_Windows.md", "-Tcp443 7443", "-Tcp443 off"),
        ] {
            for b in blocks(&read(rel)) {
                if (b.contains("web server") || b.contains("IIS")) && b.contains(seven) {
                    assert!(
                        (b.contains("router") || b.contains("second")) && b.contains(off),
                        "{rel}: 7443 for a web server's 443:{b}"
                    );
                    paired += 1;
                }
            }
        }
        assert!(paired >= 4, "{paired}");
    }

    /// The installers' firewall advice in `RAVEN_RELAY_TCP443=7443` mode:
    /// the box allows 7443 (where the router or a redirect delivers), and a
    /// VPS provider's firewall opens the public 443, not 7443.
    #[cfg(unix)]
    #[test]
    fn relay_kit_firewall_advice_names_the_public_443_in_7443_mode() {
        let dir = repo_root().join("node/scripts/install");
        let run = |tcp443: &str| {
            let out = std::process::Command::new("bash")
                .arg("-c")
                .arg(
                    "set -euo pipefail; . \"$RELAY_KIT_DIR/relay_common.sh\"; \
                     RAVEN_RELAY_PORT=7423 RAVEN_RELAY_BIN_DIR=/opt/raven-relay \
                     relay_print_firewall linux",
                )
                .env("RELAY_KIT_DIR", &dir)
                .env("RAVEN_RELAY_TCP443", tcp443)
                .output()
                .expect("bash");
            assert!(out.status.success(), "{out:?}");
            String::from_utf8(out.stdout).unwrap()
        };
        let mapped = run("7443");
        assert!(mapped.contains("sudo ufw allow 7443/tcp"), "{mapped}");
        assert!(
            mapped.contains(
                "A VPS: in the provider's firewall / security group open TCP+UDP 7423 \
                 and TCP 443 (the public port, mapped to 7443 on the box), not 7443."
            ),
            "{mapped}"
        );
        let direct = run("direct");
        assert!(direct.contains("sudo ufw allow 443/tcp"), "{direct}");
        assert!(
            direct.contains("A VPS: open the same ports in the provider's firewall"),
            "{direct}"
        );
    }

    /// A relay that cannot start for a lasting reason waits before it
    /// exits when its service manager would restart it at once (launchd):
    /// exits 2 to 5 only, a whole number of seconds capped at an hour,
    /// never `--check`. The kit's macOS plist asks for it, and bounds the
    /// log the same way.
    #[test]
    fn a_lasting_relay_failure_waits_before_it_exits_under_launchd() {
        let five_min = Some(Duration::from_secs(300));
        for code in 2..=5 {
            assert_eq!(
                relay_exit_pause(code, false, Some("300")),
                five_min,
                "{code}"
            );
            assert_eq!(relay_exit_pause(code, true, Some("300")), None, "--check");
            assert_eq!(relay_exit_pause(code, false, None), None, "not asked");
        }
        for code in [0, 1, 6, 101] {
            assert_eq!(relay_exit_pause(code, false, Some("300")), None, "{code}");
        }
        for bad in ["", "0", "-5", "5m", "1.5"] {
            assert_eq!(relay_exit_pause(4, false, Some(bad)), None, "{bad:?}");
        }
        assert_eq!(
            relay_exit_pause(4, false, Some(" 99999 ")),
            Some(Duration::from_secs(RELAY_EXIT_PAUSE_MAX_SECS))
        );
        let plist =
            std::fs::read_to_string(repo_root().join("node/scripts/install/macos_relay.sh"))
                .expect("macos_relay.sh");
        for key in [RELAY_EXIT_PAUSE_ENV, "RAVEN_SERVICE_LOG_MAX_BYTES"] {
            assert!(
                plist.contains(&format!("<key>{key}</key><string>")),
                "the kit's plist sets {key}"
            );
        }
    }

    #[test]
    fn internet_listen_is_opt_in_and_the_flag_wins() {
        let none = || Ok(String::new());
        let policy = || Ok("0.0.0.0".to_string());
        let broken = || Err("node_policy.json unreadable".to_string());
        // Nothing configured anywhere: off.
        assert_eq!(service_internet_listen(None, None, none).unwrap(), None);
        // The policy (`raven node internet on`) fills in the default port.
        assert_eq!(
            service_internet_listen(None, None, policy).unwrap(),
            Some(("0.0.0.0:7422".into(), "node_policy.json"))
        );
        // The environment beats the policy; an empty value turns it off.
        assert_eq!(
            service_internet_listen(None, Some("127.0.0.1:0"), policy).unwrap(),
            Some(("127.0.0.1:0".into(), "RAVEN_INTERNET_LISTEN"))
        );
        assert_eq!(
            service_internet_listen(None, Some(""), policy).unwrap(),
            None
        );
        // The flag beats both, and an explicit empty flag is off.
        assert_eq!(
            service_internet_listen(Some("[::1]:0"), Some("127.0.0.1:0"), policy).unwrap(),
            Some(("[::1]:0".into(), "--internet-listen"))
        );
        assert_eq!(
            service_internet_listen(Some(""), None, policy).unwrap(),
            None
        );
        // An unreadable policy or a bad value is an error (no listener), and a
        // flag or env value never needs the policy at all.
        assert!(service_internet_listen(None, None, broken).is_err());
        assert!(service_internet_listen(Some("0.0.0.0:7422"), None, broken).is_ok());
        let bad = service_internet_listen(Some("example.com:7422"), None, none).unwrap_err();
        assert!(bad.starts_with("--internet-listen: "), "{bad}");
    }

    /// Regression: `unwrap()` on `duration_since(UNIX_EPOCH)` panicked the
    /// daemon on a clock set before 1970. The daemon's clock is
    /// `raven_core::clock::now_ms`, which reads such a clock as 0 (raven-core's
    /// `a_clock_before_1970_reads_as_zero`).
    #[test]
    fn pre_epoch_clock_reads_as_zero() {
        assert!(now_ms() > 0);
    }

    /// The daemon bounds its own (append-mode) log in place: past the cap the
    /// file is truncated and later writes land at the new end; a file within the
    /// cap, and anything that is not a regular file, is left alone.
    #[cfg(unix)]
    #[test]
    fn service_log_is_truncated_in_place_only_past_the_cap() {
        use std::io::{Read, Write};
        use std::os::fd::AsRawFd;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("raven-node-service.log");
        // Same flags ash opens the log with.
        let mut log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .unwrap();
        log.write_all(&[b'x'; 100]).unwrap();
        assert!(!truncate_log_fd_if_over(log.as_raw_fd(), 100), "at the cap");
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 100);
        log.write_all(b"y").unwrap();
        assert!(
            truncate_log_fd_if_over(log.as_raw_fd(), 100),
            "past the cap"
        );
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
        // The same descriptor keeps working: the next line is at the new start.
        log.write_all(b"after\n").unwrap();
        let mut text = String::new();
        std::fs::File::open(&path)
            .unwrap()
            .read_to_string(&mut text)
            .unwrap();
        assert_eq!(text, "after\n");
        // A pipe (or terminal) is never truncated.
        let (reader, writer) = std::io::pipe().unwrap();
        assert!(!truncate_log_fd_if_over(writer.as_raw_fd(), 0));
        drop((reader, writer));
        // A bad descriptor is not a panic.
        assert!(!truncate_log_fd_if_over(-1, 0));
    }

    /// CP.8: a log descriptor opened without `O_APPEND` (as a service manager
    /// may open StandardOutPath) is never truncated: its writer keeps its
    /// offset, so the next line would land past the new end and leave a
    /// sparse, NUL-filled file. Two temp files, one with and one without
    /// `O_APPEND`; no launchd involved.
    #[cfg(unix)]
    #[test]
    fn truncate_skips_a_descriptor_without_o_append() {
        use std::io::Write;
        use std::os::fd::AsRawFd;
        let dir = tempfile::tempdir().unwrap();
        let plain_path = dir.path().join("plain.log");
        let mut plain = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&plain_path)
            .unwrap();
        plain.write_all(&[b'x'; 200]).unwrap();
        assert!(
            !truncate_log_fd_if_over(plain.as_raw_fd(), 100),
            "no O_APPEND"
        );
        assert_eq!(std::fs::metadata(&plain_path).unwrap().len(), 200);
        // The writer goes on at its own offset: the file holds every byte
        // written and no hole.
        plain.write_all(b"after\n").unwrap();
        let bytes = std::fs::read(&plain_path).unwrap();
        assert_eq!(bytes.len(), 206);
        assert!(!bytes.contains(&0), "no NUL-filled gap");

        let append_path = dir.path().join("append.log");
        let mut append = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&append_path)
            .unwrap();
        append.write_all(&[b'x'; 200]).unwrap();
        assert!(truncate_log_fd_if_over(append.as_raw_fd(), 100), "O_APPEND");
        append.write_all(b"after\n").unwrap();
        assert_eq!(std::fs::read(&append_path).unwrap(), b"after\n");
    }

    /// CP.8: the launchd agent's plist opts in to the log cap (its
    /// StandardOutPath / StandardErrorPath files would otherwise grow for
    /// good). Safe whether or not launchd opens them with `O_APPEND`
    /// ([`truncate_skips_a_descriptor_without_o_append`]).
    #[test]
    fn the_launchd_agent_plist_caps_its_logs() {
        let script =
            std::fs::read_to_string(repo_root().join("node/scripts/install/macos_launchd.sh"))
                .expect("macos_launchd.sh");
        assert!(
            script.contains("<key>RAVEN_SERVICE_LOG_MAX_BYTES</key><string>1048576</string>"),
            "the agent's plist sets the 1 MiB cap"
        );
        let env = script
            .find("<key>EnvironmentVariables</key>")
            .expect("an EnvironmentVariables dict");
        let cap = script
            .find("<key>RAVEN_SERVICE_LOG_MAX_BYTES</key>")
            .unwrap();
        assert!(env < cap, "the cap is inside EnvironmentVariables");
    }

    /// Regression: `raven-node status` opened (and so created)
    /// forward_queue.sqlite on a fresh profile, which made the next
    /// `init`/`service` fail require_proven_first_install.
    #[test]
    fn status_never_creates_the_forward_queue() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(forward_queue_counts(dir.path()), Ok((0, 0)));
        assert!(
            !bridge_run::forward_queue_path(dir.path()).exists(),
            "status must not touch a profile that has no queue"
        );
    }

    /// Regression: open / count errors were reported as an empty queue.
    #[test]
    fn status_reports_an_unreadable_queue_instead_of_zero() {
        let dir = tempfile::tempdir().unwrap();
        let path = bridge_run::forward_queue_path(dir.path());
        std::fs::write(&path, b"this is not a sqlite database, just 100 bytes of text....................................").unwrap();
        let err = forward_queue_counts(dir.path()).unwrap_err();
        assert!(err.contains("forward_queue.sqlite"), "{err}");

        // A queue that works reports its real counts.
        let ok_dir = tempfile::tempdir().unwrap();
        drop(ForwardQueue::open(&bridge_run::forward_queue_path(ok_dir.path())).unwrap());
        assert_eq!(forward_queue_counts(ok_dir.path()), Ok((0, 0)));
    }

    /// Regression: a dialed `run --peer` connection inherited the accept-side
    /// 10 s idle bound (and the 30 s frame bound caps the header wait), so a
    /// receiver told to wait 35 s was dropped long before. Client limits
    /// cover the whole `--timeout-secs`.
    #[test]
    fn client_limits_cover_the_requested_wait() {
        for secs in [0, 1, 30, 35, 40, 600] {
            let l = client_limits(secs);
            let want = Duration::from_secs(secs);
            assert!(l.idle_timeout >= want, "{secs}: idle {:?}", l.idle_timeout);
            assert!(
                l.frame_timeout >= want,
                "{secs}: frame {:?}",
                l.frame_timeout
            );
            assert!(l.lifetime >= want, "{secs}: lifetime {:?}", l.lifetime);
        }
        // Absurd values are clamped, not an Instant overflow.
        assert!(client_limits(u64::MAX).lifetime <= Duration::from_secs(MAX_RUN_SECS + 5));
        // The accept side keeps its slow-loris bound.
        assert_eq!(
            DEFAULT_CONNECTION_LIMITS.idle_timeout,
            Duration::from_secs(10)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_dialed_connection_survives_a_late_frame_that_default_limits_drop() {
        let late = Duration::from_secs(25);
        let (mut peer, mut mine) = tokio::io::duplex(1 << 12);
        let send = tokio::spawn(async move {
            tokio::time::sleep(late).await;
            peer.write_all(&3u32.to_be_bytes()).await.unwrap();
            peer.write_all(b"abc").await.unwrap();
            peer
        });
        assert_eq!(
            read_frame_with_limits(&mut mine, client_limits(35)).await,
            Ok(b"abc".to_vec()),
            "a frame 25 s into a 35 s wait must arrive"
        );
        let _peer = send.await.unwrap();

        let (_peer2, mut mine2) = tokio::io::duplex(1 << 12);
        assert_eq!(
            read_frame_with_limits(&mut mine2, DEFAULT_CONNECTION_LIMITS).await,
            Err(FrameReadError::IdleDeadline),
            "the accept-side default still idles out at 10 s"
        );
    }

    #[cfg(any(unix, windows))]
    fn counting_failures(
        attempts: Arc<AtomicUsize>,
        err: &'static str,
    ) -> impl FnMut() -> std::future::Ready<Result<(), String>> {
        move || {
            attempts.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Err(err.to_string()))
        }
    }

    /// Regression: a busy LAN port (or any listener failure) ended the whole
    /// `service` process. The listener is now retried with backoff and
    /// nothing else notices.
    #[cfg(any(unix, windows))]
    #[tokio::test(start_paused = true)]
    async fn failing_listener_is_retried_and_never_ends_the_service() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let mut ipc = tokio::spawn(std::future::pending::<()>());
        let mut lan = tokio::spawn(supervise(
            "test_lan",
            None,
            counting_failures(attempts.clone(), "bind: address in use"),
        ));
        let mut inet = tokio::spawn(std::future::pending::<Infallible>());
        let mut p2p = tokio::spawn(std::future::pending::<Infallible>());
        let mut bridge = tokio::spawn(std::future::pending::<Infallible>());
        let mut prune = tokio::spawn(std::future::pending::<Infallible>());
        let mut outbox = tokio::spawn(std::future::pending::<Infallible>());
        let outcome = tokio::time::timeout(
            Duration::from_secs(3600),
            wait_service_end(
                &mut ipc,
                &mut lan,
                &mut inet,
                &mut p2p,
                &mut bridge,
                &mut prune,
                &mut outbox,
                None,
            ),
        )
        .await;
        assert!(
            outcome.is_err(),
            "service must still be running: {outcome:?}"
        );
        // 1 + 2 + 4 + 8 + 16 s, then 30 s steps: well past a handful of tries.
        assert!(attempts.load(Ordering::SeqCst) >= 10);
        assert!(!ipc.is_finished(), "IPC untouched by the listener failure");
        ipc.abort();
        inet.abort();
        p2p.abort();
        bridge.abort();
        prune.abort();
        outbox.abort();
        lan.abort();
    }

    #[cfg(any(unix, windows))]
    #[tokio::test(start_paused = true)]
    async fn retry_backoff_is_capped_and_a_panic_is_just_a_failed_attempt() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let a = attempts.clone();
        let task = tokio::spawn(supervise("test_panic", None, move || {
            let n = a.fetch_add(1, Ordering::SeqCst);
            async move {
                if n == 0 {
                    panic!("listener bug");
                }
                Err("still down".to_string())
            }
        }));
        // Attempts at 0 (the panic), 1, 3, 7, 15, 31, 61 and 91 s: the delay
        // stops doubling at 30 s (an uncapped 32 s would push the 8th past 93 s).
        tokio::time::sleep(Duration::from_millis(91_500)).await;
        assert_eq!(attempts.load(Ordering::SeqCst), 8);
        assert!(!task.is_finished());
        task.abort();
    }

    /// The bridge flag is up while an attempt is failing and clear again when
    /// the next one starts (`Status` stops advertising bridge capabilities).
    #[cfg(any(unix, windows))]
    #[tokio::test(start_paused = true)]
    async fn bridge_degraded_flag_follows_the_attempts() {
        static FLAG: AtomicBool = AtomicBool::new(false);
        let attempts = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(supervise(
            "test_bridge",
            Some(&FLAG),
            counting_failures(attempts.clone(), "ble bind: address in use"),
        ));
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(FLAG.load(Ordering::Relaxed), "degraded while retrying");
        task.abort();
    }

    /// Regression: `service` awaited the listener task during start-up, so a
    /// preflight slower than 1 s parked it for ever and the bridge never
    /// started. There is no start-up wait now: a listener that is slow to come
    /// up (here: 120 s) changes nothing, and only IPC ending (or the
    /// timeout) stops the service.
    #[cfg(any(unix, windows))]
    #[tokio::test(start_paused = true)]
    async fn slow_listener_start_does_not_block_or_end_the_service() {
        let mut ipc = tokio::spawn(std::future::pending::<()>());
        let mut lan = tokio::spawn(supervise("slow_lan", None, || async {
            tokio::time::sleep(Duration::from_secs(120)).await;
            std::future::pending::<Result<(), String>>().await
        }));
        let mut inet = tokio::spawn(std::future::pending::<Infallible>());
        let mut p2p = tokio::spawn(std::future::pending::<Infallible>());
        let mut bridge = tokio::spawn(std::future::pending::<Infallible>());
        let mut prune = tokio::spawn(std::future::pending::<Infallible>());
        let mut outbox = tokio::spawn(std::future::pending::<Infallible>());
        let end = wait_service_end(
            &mut ipc,
            &mut lan,
            &mut inet,
            &mut p2p,
            &mut bridge,
            &mut prune,
            &mut outbox,
            Some(Duration::from_secs(300)),
        )
        .await;
        assert_eq!(end, ServiceEnd::TimedOut);
        assert_eq!(end.exit_code(), 0);
        ipc.abort();
        lan.abort();
        inet.abort();
        p2p.abort();
        bridge.abort();
        prune.abort();
        outbox.abort();
    }

    /// IPC is the one task whose end stops the service, with a non-zero
    /// status so launchd / systemd restart it.
    #[cfg(any(unix, windows))]
    #[tokio::test(start_paused = true)]
    async fn ipc_ending_stops_the_service_with_a_failure_status() {
        let mut ipc = tokio::spawn(async {});
        let mut lan = tokio::spawn(std::future::pending::<Infallible>());
        let mut inet = tokio::spawn(std::future::pending::<Infallible>());
        let mut p2p = tokio::spawn(std::future::pending::<Infallible>());
        let mut bridge = tokio::spawn(std::future::pending::<Infallible>());
        let mut prune = tokio::spawn(std::future::pending::<Infallible>());
        let mut outbox = tokio::spawn(std::future::pending::<Infallible>());
        let end = wait_service_end(
            &mut ipc,
            &mut lan,
            &mut inet,
            &mut p2p,
            &mut bridge,
            &mut prune,
            &mut outbox,
            None,
        )
        .await;
        assert_eq!(end, ServiceEnd::IpcStopped);
        assert_eq!(end.exit_code(), 1);
        assert_eq!(ServiceEnd::SupervisorDied("bridge").exit_code(), 1);
        lan.abort();
        inet.abort();
        p2p.abort();
        bridge.abort();
        prune.abort();
        outbox.abort();
    }

    /// The outbox worker is the sixth supervised task: should its supervisor
    /// itself ever end, the service stops with a failure status (restarted by
    /// launchd / systemd), like for every other transport.
    #[cfg(any(unix, windows))]
    #[tokio::test(start_paused = true)]
    async fn the_outbox_supervisor_is_waited_for_like_the_transports() {
        let mut ipc = tokio::spawn(std::future::pending::<()>());
        let mut lan = tokio::spawn(std::future::pending::<Infallible>());
        let mut inet = tokio::spawn(std::future::pending::<Infallible>());
        let mut p2p = tokio::spawn(std::future::pending::<Infallible>());
        let mut bridge = tokio::spawn(std::future::pending::<Infallible>());
        let mut prune = tokio::spawn(std::future::pending::<Infallible>());
        let mut outbox: JoinHandle<Infallible> =
            tokio::spawn(async { panic!("outbox supervisor bug (test)") });
        let end = wait_service_end(
            &mut ipc,
            &mut lan,
            &mut inet,
            &mut p2p,
            &mut bridge,
            &mut prune,
            &mut outbox,
            None,
        )
        .await;
        assert_eq!(end, ServiceEnd::SupervisorDied("outbox"));
        assert_eq!(end.exit_code(), 1);
        ipc.abort();
        lan.abort();
        inet.abort();
        p2p.abort();
        bridge.abort();
        prune.abort();
    }
}
