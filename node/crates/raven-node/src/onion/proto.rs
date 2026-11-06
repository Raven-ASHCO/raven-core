//! The local protocol between raven-node and its Tor helper
//! (`protocol/RAVEN_ONION_CARRIER_V1.md` §6). Shared, file for file, by
//! raven-node (`crate::onion`) and the helpers (`raven-tor-helper` and the
//! debug loopback helper): it depends on nothing of either.
//!
//! - **Control:** the helper's stdin and stdout, one JSON object per line.
//!   raven-node writes [`Config`] first, then [`Command`]s; the helper writes
//!   [`Event`]s. The helper exits when its stdin closes.
//! - **Outbound:** raven-node connects to the helper's connect address
//!   ([`Event::Ready`]), writes [`encode_connect`] (the token, the onion
//!   key, the port) and reads one [`ConnectReply`]; on
//!   [`ConnectReply::Ok`] the stream carries the bytes.
//! - **Inbound:** for every accepted onion stream the helper connects to
//!   raven-node's forward address ([`Config::forward`]) and writes
//!   [`encode_forward`] first (the token, then an opaque number for the
//!   rendezvous circuit the stream came on); then the stream carries the
//!   bytes.
//! - **Version 4** (security review 2026-11, TOR-4): the streams ride the
//!   helper channel (`channel.rs`): a socket pair on macOS and Linux, the
//!   loopback ports on Windows; on every stream the helper proves the token
//!   first, by challenge and response, and a proof rides where the token
//!   did above. The token itself never travels on a stream.
//!
//! Nothing here ever carries an onion address of a friend in a log or an
//! event: the onion key travels only inside the connect request.
//!
//! Items only a helper uses are marked
//! `#[cfg_attr(not(debug_assertions), allow(dead_code))]`: a release
//! raven-node has no loopback helper, and raven-tor-helper allows dead code
//! in its copy of this file.

use std::future::Future;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// This protocol's version ([`Config::v`]).
///
/// 2: an inbound stream's header carries its circuit number after the token
/// ([`encode_forward`]).
/// 3: a connect request ends with a flags byte ([`encode_connect`],
/// [`CONNECT_FLAGS`]; Tor speed Stage A, speed design M5).
/// 4: the helper channel and its hellos (`channel.rs`, TOR-4); the
/// requests are those of version 3.
pub const PROTO_VERSION: u32 = 4;

/// The shared secret of one helper's life: 32 random bytes, hex in
/// [`Config::token`], raw on the loopback streams.
pub const TOKEN_LEN: usize = 32;

/// The longest control line either side accepts.
pub const MAX_LINE: usize = 4096;

/// A connect request: token, onion key, port, flags.
pub const CONNECT_REQUEST_LEN: usize = TOKEN_LEN + 32 + 2 + 1;

/// Connect flag: fresh first (speed design M5, W4). The first try goes in a
/// new isolation group (fresh circuits; Arti fetches the descriptor again),
/// not in the friend's: raven-node's last link to that friend failed a
/// moment ago, past a point the helper did not see (the stream opened, and
/// then the link died or went silent). Hedge gate only
/// (`onion_gate::onion_hedge_live`).
pub const CONNECT_FRESH_FIRST: u8 = 1 << 0;
/// Connect flag: probe (speed design M2 and M3). One try in the friend's
/// isolation group to [`SELF_CHECK_PORT`], whatever port the request
/// names, which the friend's onion service refuses (END, DONE): that answer
/// proves the rendezvous circuit works and keeps it in use (Arti's last
/// use, the group's kept time), and nothing reaches the friend's
/// raven-node. The reply says whether it was answered and the helper then
/// closes the connection: no stream follows. A probe that failed moves the
/// friend to a new group, so the next connect builds fresh circuits; with
/// [`CONNECT_FRESH_FIRST`] the try goes in a new group, which becomes the
/// friend's once answered. No hedge and no second try. Warm gate only
/// (`onion_gate::onion_warm_live`; [`probe_in_groups`]).
pub const CONNECT_PROBE: u8 = 1 << 1;
/// Connect flag: hedge (speed design M5). A first try in the friend's group
/// that has no stream after [`CONNECT_HEDGE_AFTER`] gets a fresh try in a
/// new group beside it; the first stream wins, and the other try is dropped
/// (Arti ends its stream). Hedge gate only.
pub const CONNECT_HEDGE: u8 = 1 << 3;
/// The flags this version knows. Bit 2 is kept for optimistic data (speed
/// design M6); a helper refuses a request with a bit it does not know
/// ([`unknown_flags`]).
pub const CONNECT_FLAGS: u8 = CONNECT_FRESH_FIRST | CONNECT_PROBE | CONNECT_HEDGE;
/// How long a hedged connect waits for a stream in the friend's group before
/// a fresh try starts beside it: a healthy BEGIN is one onion round trip
/// (under a second, typically), and Arti gives up one on a dead circuit only
/// after 6 s (the Arti helper's `STREAM_CONNECT_TIMEOUT`).
pub const CONNECT_HEDGE_AFTER: Duration = Duration::from_secs(2);
/// The reason a helper gives for a request with flags it does not know.
#[cfg_attr(not(debug_assertions), allow(dead_code))]
pub const UNKNOWN_FLAGS: &str = "unknown connect flags";

/// Bits of `flags` this version does not know ([`CONNECT_FLAGS`]): such a
/// request is refused, never served as if the bit were clear.
#[cfg_attr(not(debug_assertions), allow(dead_code))]
pub fn unknown_flags(flags: u8) -> bool {
    flags & !CONNECT_FLAGS != 0
}

/// An inbound stream's header: token, circuit number (u64 BE).
pub const FORWARD_HEADER_LEN: usize = TOKEN_LEN + 8;

/// The longest reason a connect reply carries.
pub const MAX_REASON: usize = 120;

/// The first control line raven-node writes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    /// [`PROTO_VERSION`].
    pub v: u32,
    /// Where the helper keeps Tor's state, cache and keys
    /// (`<profile>/tor`).
    pub state_dir: String,
    /// [`TOKEN_LEN`] bytes in lowercase hex.
    pub token: String,
    /// raven-node's forward listener (`127.0.0.1:<port>`); version 4 on
    /// macOS and Linux: the helper channel instead (`fd:<n>`, or `conduit`
    /// in raven-node's own process).
    pub forward: String,
    /// The onion service's virtual port: the only one the helper accepts
    /// streams on.
    pub port: u16,
    /// Start with a fresh guard state (the old one set aside): asked after
    /// repeated bootstraps that ended blocked (Arti issue #2534).
    #[serde(default)]
    pub fresh_state: bool,
}

/// raven-node to the helper, after [`Config`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Command {
    /// Answer with [`Event::Pong`] carrying `n` (the liveness watchdog).
    Ping { n: u64 },
    /// Reach our own onion service as a friend would (a fresh isolation
    /// group: a fresh descriptor, new circuits) on [`SELF_CHECK_PORT`], and
    /// answer with [`Event::SelfCheck`] carrying `n`.
    SelfCheck { n: u64 },
    /// Close everything and exit.
    Stop,
}

/// The helper to raven-node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "ev", rename_all = "snake_case")]
pub enum Event {
    /// Bootstrap progress, 0-100, and Tor's own word for why it is stuck
    /// ([`blockage_word`]), if it says it is.
    Progress {
        pct: u8,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        blocked: Option<String>,
        /// Where the bootstrap is, as one fixed word ([`stage_word`]).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        stage: Option<String>,
    },
    /// The client is bootstrapped and takes connect requests at `connect`
    /// (`127.0.0.1:<port>`).
    Ready { connect: String },
    /// The onion service runs under this key (64 lowercase hex). Said once
    /// per helper life.
    Onion { hs_id: String },
    /// The onion service's state ([`ServiceState::word`]), and Arti's
    /// current problem as one fixed phrase ([`SERVICE_REASONS`]), if any.
    Service {
        state: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    /// The answer to [`Command::Ping`].
    Pong { n: u64 },
    /// Something failed; `what` is a short fixed text, never an address.
    /// `local`: the cause is on this computer (its folder, its clock, the
    /// helper itself), not the network.
    Error {
        what: String,
        #[serde(default)]
        local: bool,
    },
    /// One descriptor upload round of the onion service ended: `ok` of
    /// `of` HSDirs took it (the HSDirs that needed it this round; counts
    /// only, never which).
    Uploads { ok: u32, of: u32 },
    /// The answer to [`Command::SelfCheck`]: whether our own onion service
    /// answered (it refuses [`SELF_CHECK_PORT`], which proves it reachable),
    /// else a fixed reason ([`ConnectReply`]'s).
    SelfCheck {
        n: u64,
        reached: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
}

/// The reasons a failed connect or self-check carries (the helper's fixed
/// phrases, [`ConnectReply`]).
pub const CONNECT_REASONS: [&str; 7] = [
    "not bootstrapped",
    "tor timeout",
    "no descriptor",
    "service not running",
    "rendezvous failed",
    "tor connect failed",
    "no circuit in time",
];

/// A received connect reason as its fixed phrase (anything else: `other`).
pub fn known_connect_reason(text: &str) -> &'static str {
    CONNECT_REASONS
        .into_iter()
        .find(|r| *r == text)
        .unwrap_or("other")
}

/// The virtual port a self-check asks our own onion service for. The
/// service refuses every port but the Raven one with END (DONE): that
/// answer means the descriptor, an introduction point and a rendezvous all
/// worked, and nothing reaches raven-node.
/// (raven-tor-helper's; the loopback helper has no ports to ask.)
#[allow(dead_code)]
pub const SELF_CHECK_PORT: u16 = 9;

/// Arti's debug line for one descriptor upload round
/// (`tor-hsservice` publish/reactor.rs: "descriptor uploaded successfully
/// to N/M HSDirs") as (N, M); anything else `None`. Only the numbers are
/// kept. (raven-tor-helper's.)
#[cfg_attr(not(test), allow(dead_code))]
pub fn upload_round(message: &str) -> Option<(u32, u32)> {
    let rest = message.strip_prefix("descriptor uploaded successfully to ")?;
    let (counts, tail) = rest.split_once(' ')?;
    if tail != "HSDirs" {
        return None;
    }
    let (ok, of) = counts.split_once('/')?;
    let (ok, of) = (ok.parse().ok()?, of.parse().ok()?);
    (ok <= of).then_some((ok, of))
}

/// The pause before a second Tor connect after a first try that failed
/// without timing out: no descriptor, an introduction or a rendezvous that
/// failed ([`connect_with_retry`]). After a timeout there is none: that try
/// has waited already (audit T6: a BEGIN on a dead shared circuit), and a
/// pause would only add to it.
#[cfg_attr(not(debug_assertions), allow(dead_code))]
pub const CONNECT_RETRY_PAUSE: Duration = Duration::from_secs(2);
/// A second Tor connect is made only with at least this much of the
/// connect budget left after the pause (a rendezvous over a fresh
/// descriptor takes several seconds).
#[cfg_attr(not(debug_assertions), allow(dead_code))]
pub const CONNECT_RETRY_MIN_LEFT: Duration = Duration::from_secs(12);

/// A failed connect worth one more try with a fresh descriptor and fresh
/// circuits: the service was not found or not running, its introduction or
/// rendezvous failed, or Tor timed out. Field test round 8: right after a
/// friend's node restarted, the first connects failed on what the client
/// had cached of the old service (its descriptor, its introduction points).
#[cfg_attr(not(debug_assertions), allow(dead_code))]
pub fn worth_another_connect(reply: &ConnectReply) -> bool {
    matches!(
        reply,
        ConnectReply::Unreachable(_) | ConnectReply::Timeout(_)
    )
}

/// One Tor connect within `budget`: first with the shared circuits
/// (`connect(false, within)`), and after a failure worth it
/// ([`worth_another_connect`]) one more with fresh ones (`connect(true,
/// within)`: the helper uses a new isolation group, so Arti fetches the
/// descriptor again and builds new circuits) when [`CONNECT_RETRY_MIN_LEFT`]
/// is left for it: at once after a timeout, [`CONNECT_RETRY_PAUSE`] after
/// any other failure. Each try is bounded by what is left of `budget`; the
/// error is the last try's. (The Arti helper's self-check; a friend's
/// connect is [`connect_in_groups`].)
#[cfg_attr(not(feature = "tor-embedded"), allow(dead_code))]
pub async fn connect_with_retry<T, F, Fut>(budget: Duration, connect: F) -> Result<T, ConnectReply>
where
    F: FnMut(bool, Duration) -> Fut,
    Fut: Future<Output = Result<T, ConnectReply>>,
{
    tries(budget, None, connect).await.got
}

/// How [`tries`] went.
#[cfg_attr(not(debug_assertions), allow(dead_code))]
struct Tries<T> {
    got: Result<T, ConnectReply>,
    /// The first try's error, if it failed.
    first: Option<ConnectReply>,
    /// A fresh try was made.
    fresh: bool,
}

/// [`connect_with_retry`], and how its tries went. A first try that timed
/// out is followed by the fresh one at once: on a dead shared circuit
/// (audit T6) the first message to a friend already paid Arti's BEGIN
/// timeout. One that failed otherwise is followed after
/// [`CONNECT_RETRY_PAUSE`]: a quick failure is not tried again at once.
///
/// With `hedge` (speed design M5, [`CONNECT_HEDGE`]): a first try with no
/// stream after that long gets the fresh try beside it, when
/// [`CONNECT_RETRY_MIN_LEFT`] is left for it ([`hedged`]); a first try that
/// ends before then goes on as without a hedge.
#[cfg_attr(not(debug_assertions), allow(dead_code))]
async fn tries<T, F, Fut>(budget: Duration, hedge: Option<Duration>, mut connect: F) -> Tries<T>
where
    F: FnMut(bool, Duration) -> Fut,
    Fut: Future<Output = Result<T, ConnectReply>>,
{
    let start = tokio::time::Instant::now();
    let bounded = |within: Duration, fut: Fut| async move {
        tokio::time::timeout(within, fut)
            .await
            .unwrap_or_else(|_| Err(ConnectReply::Timeout("no circuit in time".into())))
    };
    let first = bounded(budget, connect(false, budget));
    tokio::pin!(first);
    let got = match hedge {
        None => first.await,
        Some(after) => match tokio::time::timeout(after, &mut first).await {
            Ok(got) => got,
            // No time for a fresh try: the first alone, as without a hedge.
            Err(_) if budget.saturating_sub(start.elapsed()) < CONNECT_RETRY_MIN_LEFT => {
                first.await
            }
            Err(_) => {
                let left = budget.saturating_sub(start.elapsed());
                return hedged(first, bounded(left, connect(true, left))).await;
            }
        },
    };
    let err = match got {
        Ok(t) => {
            return Tries {
                got: Ok(t),
                first: None,
                fresh: false,
            }
        }
        Err(e) => e,
    };
    let pause = if matches!(err, ConnectReply::Timeout(_)) {
        Duration::ZERO
    } else {
        CONNECT_RETRY_PAUSE
    };
    let left = budget.saturating_sub(start.elapsed());
    if !worth_another_connect(&err) || left < pause + CONNECT_RETRY_MIN_LEFT {
        return Tries {
            got: Err(err.clone()),
            first: Some(err),
            fresh: false,
        };
    }
    if !pause.is_zero() {
        tokio::time::sleep(pause).await;
    }
    let left = budget.saturating_sub(start.elapsed());
    Tries {
        got: bounded(left, connect(true, left)).await,
        first: Some(err),
        fresh: true,
    }
}

/// A hedged connect's two tries side by side ([`tries`]): the first try in
/// the friend's group, still without a stream, and the fresh one. The first
/// stream wins, and the other try is dropped (a stream it opened ends, END).
/// A try that fails leaves the other to finish: a slow circuit may still
/// answer, and a dead one times out. Both failed: the fresh try's error.
#[cfg_attr(not(debug_assertions), allow(dead_code))]
async fn hedged<T, A, B>(mut first: std::pin::Pin<&mut A>, second: B) -> Tries<T>
where
    A: Future<Output = Result<T, ConnectReply>>,
    B: Future<Output = Result<T, ConnectReply>>,
{
    tokio::pin!(second);
    let (mut first_err, mut second_err) = (None, None);
    loop {
        tokio::select! {
            got = &mut first, if first_err.is_none() => match got {
                Ok(t) => {
                    return Tries {
                        got: Ok(t),
                        first: None,
                        fresh: false,
                    }
                }
                Err(e) => first_err = Some(e),
            },
            got = &mut second, if second_err.is_none() => match got {
                Ok(t) => {
                    return Tries {
                        got: Ok(t),
                        first: first_err,
                        fresh: true,
                    }
                }
                Err(e) => second_err = Some(e),
            },
        }
        if let (Some(_), Some(e)) = (&first_err, &second_err) {
            return Tries {
                got: Err(e.clone()),
                first: first_err,
                fresh: true,
            };
        }
    }
}

/// How long a friend's isolation group is kept after its last use
/// ([`IsolationBook`]): as long as Arti keeps an onion service circuit
/// nobody uses (tor-hsclient's `RETAIN_CIRCUIT_AFTER_LAST_USE`).
#[cfg_attr(not(debug_assertions), allow(dead_code))]
pub const GROUP_KEPT: Duration = Duration::from_secs(10 * 60);

/// The isolation group each friend's first connect try goes in, for one
/// helper life (audit T6). Arti hands every connect of one group to one
/// onion service the same rendezvous circuit while it looks open, and a
/// circuit whose far end vanished with no DESTROY back still looks open.
/// Every first try in the default group met it again and timed out, and
/// only the fresh try (a new group) got through, in a group nobody used
/// again. Now a fresh try that works makes its group the friend's, and a
/// first try that timed out is never made in its group again.
///
/// Keyed by the friend's onion key. `G` is the helper's isolation token
/// (Arti's `IsolationToken`; a number in the loopback helper); `None` is
/// the default group. A friend unused for [`GROUP_KEPT`] is back in the
/// default group (Arti dropped what it kept for it by then).
#[cfg_attr(not(debug_assertions), allow(dead_code))]
pub struct IsolationBook<G> {
    groups: std::collections::HashMap<[u8; 32], (G, tokio::time::Instant)>,
    new_group: fn() -> G,
}

#[cfg_attr(not(debug_assertions), allow(dead_code))]
impl<G: Clone + PartialEq> IsolationBook<G> {
    /// An empty book; `new_group` makes a group no connect used yet.
    pub fn new(new_group: fn() -> G) -> Self {
        Self {
            groups: std::collections::HashMap::new(),
            new_group,
        }
    }

    /// The group of a first try to `key` (`None`: the default group).
    pub fn first_try(&mut self, key: &[u8; 32]) -> Option<G> {
        let now = tokio::time::Instant::now();
        self.groups
            .retain(|_, (_, used)| now.saturating_duration_since(*used) < GROUP_KEPT);
        self.groups.get_mut(key).map(|(group, used)| {
            *used = now;
            group.clone()
        })
    }

    /// A group no connect used yet, for a fresh try.
    pub fn new_group(&self) -> G {
        (self.new_group)()
    }

    /// A fresh try to `key` in `group` opened a stream: later first tries
    /// go in that group.
    pub fn fresh_succeeded(&mut self, key: [u8; 32], group: G) {
        self.groups
            .insert(key, (group, tokio::time::Instant::now()));
    }

    /// A first try to `key` in `used` timed out: no later first try goes in
    /// that group (nothing changes when another connect already moved the
    /// friend on).
    pub fn first_timed_out(&mut self, key: [u8; 32], used: Option<G>) {
        if self.groups.get(&key).map(|(group, _)| group) == used.as_ref() {
            let group = self.new_group();
            self.groups
                .insert(key, (group, tokio::time::Instant::now()));
        }
    }
}

/// [`connect_with_retry`] to the onion service `key`, its isolation groups
/// from `book` (audit T6): the first try goes in the friend's group
/// (`connect(Some(group), within)`, or `None`: the default group), the fresh
/// one in a new group. A fresh try that works makes its group the friend's;
/// a first try that timed out moves the friend to a new group whatever
/// happens next. The book is shared by the helper's connects (its lock is
/// never held across a try).
///
/// `flags` (version 3, speed design M5; 0 is the above): with
/// [`CONNECT_FRESH_FIRST`] the first try goes in a new group too, which
/// becomes the friend's when it works; with [`CONNECT_HEDGE`] (and not
/// fresh first) a first try with no stream after [`CONNECT_HEDGE_AFTER`]
/// gets the fresh try beside it ([`tries`]).
#[cfg_attr(not(debug_assertions), allow(dead_code))]
pub async fn connect_in_groups<G, T, F, Fut>(
    budget: Duration,
    book: &std::sync::Mutex<IsolationBook<G>>,
    key: [u8; 32],
    flags: u8,
    mut connect: F,
) -> Result<T, ConnectReply>
where
    G: Clone + PartialEq,
    F: FnMut(Option<G>, Duration) -> Fut,
    Fut: Future<Output = Result<T, ConnectReply>>,
{
    let lock = || {
        book.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    };
    let fresh_first = flags & CONNECT_FRESH_FIRST != 0;
    let (first, fresh) = {
        let mut book = lock();
        let kept = book.first_try(&key);
        // Fresh first (W4): a new group instead of the friend's.
        let first = if fresh_first {
            Some(book.new_group())
        } else {
            kept
        };
        (first, book.new_group())
    };
    let hedge = (flags & CONNECT_HEDGE != 0 && !fresh_first).then_some(CONNECT_HEDGE_AFTER);
    let tried = tries(budget, hedge, |is_fresh, within| {
        let group = if is_fresh {
            Some(fresh.clone())
        } else {
            first.clone()
        };
        connect(group, within)
    })
    .await;
    let mut book = lock();
    if matches!(tried.first, Some(ConnectReply::Timeout(_))) {
        book.first_timed_out(key, first.clone());
    }
    if tried.got.is_ok() {
        if tried.fresh {
            book.fresh_succeeded(key, fresh);
        } else if let Some(group) = first.filter(|_| fresh_first) {
            book.fresh_succeeded(key, group);
        }
    }
    tried.got
}

/// A probe ([`CONNECT_PROBE`], speed design M2 and M3) of the onion service
/// `key` within `budget`: one try, `probe(group)`, in the friend's group
/// from `book` (`None`: the default group), or in a new one with
/// [`CONNECT_FRESH_FIRST`] in `flags`, which becomes the friend's once the
/// probe was answered. `Ok`: the service answered (its refusal of the
/// probe's port counts). A probe that failed or ran out of time moves the
/// friend to a new group (nothing changes when another connect already
/// moved it on), so the next connect builds fresh circuits instead of
/// meeting a dead one. The hedge flag is not used: a probe asks only
/// whether the friend's circuit still works.
#[cfg_attr(not(debug_assertions), allow(dead_code))]
pub async fn probe_in_groups<G, F, Fut>(
    budget: Duration,
    book: &std::sync::Mutex<IsolationBook<G>>,
    key: [u8; 32],
    flags: u8,
    probe: F,
) -> Result<(), ConnectReply>
where
    G: Clone + PartialEq,
    F: FnOnce(Option<G>) -> Fut,
    Fut: Future<Output = Result<(), ConnectReply>>,
{
    let lock = || {
        book.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    };
    let fresh_first = flags & CONNECT_FRESH_FIRST != 0;
    let group = {
        let mut book = lock();
        let kept = book.first_try(&key);
        if fresh_first {
            Some(book.new_group())
        } else {
            kept
        }
    };
    let got = tokio::time::timeout(budget, probe(group.clone()))
        .await
        .unwrap_or_else(|_| Err(ConnectReply::Timeout("no circuit in time".into())));
    let mut book = lock();
    match (&got, group) {
        (Ok(()), Some(group)) if fresh_first => book.fresh_succeeded(key, group),
        (Ok(()), _) => {}
        (Err(_), used) => book.first_timed_out(key, used),
    }
    got
}

/// The reasons an onion service state may carry ([`Event::Service`]):
/// Arti's current problem (`tor_hsservice::status::Problem`) as a fixed
/// phrase, never its text (which may name a relay).
pub const SERVICE_REASONS: [&str; 7] = [
    "descriptor upload failed",
    "descriptor upload timed out",
    "descriptor upload retries ran out",
    "intro point failed",
    "intro point stopped answering",
    "intro point left the directory",
    "service error",
];

/// A received reason as its fixed phrase (anything else: `other problem`).
pub fn known_reason(text: &str) -> &'static str {
    SERVICE_REASONS
        .into_iter()
        .find(|r| *r == text)
        .unwrap_or("other problem")
}

/// The onion service's states, as Arti names them (`tor_hsservice::status`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceState {
    Shutdown,
    Bootstrapping,
    DegradedReachable,
    DegradedUnreachable,
    Running,
    Recovering,
    Broken,
}

impl ServiceState {
    pub const ALL: [Self; 7] = [
        Self::Shutdown,
        Self::Bootstrapping,
        Self::DegradedReachable,
        Self::DegradedUnreachable,
        Self::Running,
        Self::Recovering,
        Self::Broken,
    ];

    /// The event's word.
    pub fn word(self) -> &'static str {
        match self {
            Self::Shutdown => "shutdown",
            Self::Bootstrapping => "bootstrapping",
            Self::DegradedReachable => "degraded_reachable",
            Self::DegradedUnreachable => "degraded_unreachable",
            Self::Running => "running",
            Self::Recovering => "recovering",
            Self::Broken => "broken",
        }
    }

    /// The exact word only.
    pub fn parse(word: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.word() == word)
    }

    /// Friends can reach the service in this state (Arti's own reading:
    /// running, or degraded with working introduction points).
    pub fn reachable(self) -> bool {
        matches!(self, Self::Running | Self::DegradedReachable)
    }
}

/// The helper's answer to a connect request: one status byte, then a
/// reason (a length byte and at most [`MAX_REASON`] printable ASCII bytes;
/// never an address).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnectReply {
    /// The Tor stream to the friend's onion service is open.
    Ok,
    /// The client is not bootstrapped (any more).
    NotReady(String),
    /// The onion service did not answer (no descriptor, introduction or
    /// rendezvous failed, the service refused the port).
    Unreachable(String),
    /// Tor gave up within its own time.
    Timeout(String),
    /// Anything else.
    Failed(String),
}

impl ConnectReply {
    #[cfg_attr(not(debug_assertions), allow(dead_code))]
    fn code(&self) -> u8 {
        match self {
            Self::Ok => 0,
            Self::NotReady(_) => 1,
            Self::Unreachable(_) => 2,
            Self::Timeout(_) => 3,
            Self::Failed(_) => 4,
        }
    }

    /// The reason text (a fixed phrase; empty for [`Self::Ok`]).
    #[cfg_attr(not(debug_assertions), allow(dead_code))]
    pub fn reason(&self) -> &str {
        match self {
            Self::Ok => "",
            Self::NotReady(r) | Self::Unreachable(r) | Self::Timeout(r) | Self::Failed(r) => r,
        }
    }

    /// The reply bytes: status, reason length, reason (cut to
    /// [`MAX_REASON`], non-printable bytes as `?`).
    #[cfg_attr(not(debug_assertions), allow(dead_code))]
    pub fn encode(&self) -> Vec<u8> {
        let reason: Vec<u8> = self
            .reason()
            .bytes()
            .take(MAX_REASON)
            .map(|b| {
                if b.is_ascii_graphic() || b == b' ' {
                    b
                } else {
                    b'?'
                }
            })
            .collect();
        let mut out = Vec::with_capacity(2 + reason.len());
        out.push(self.code());
        out.push(reason.len() as u8);
        out.extend_from_slice(&reason);
        out
    }

    /// From the status byte and the reason bytes; an unknown status is
    /// [`ConnectReply::Failed`].
    pub fn decode(status: u8, reason: &[u8]) -> Self {
        let reason: String = reason
            .iter()
            .take(MAX_REASON)
            .map(|&b| {
                if b.is_ascii_graphic() || b == b' ' {
                    b as char
                } else {
                    '?'
                }
            })
            .collect();
        match status {
            0 => Self::Ok,
            1 => Self::NotReady(reason),
            2 => Self::Unreachable(reason),
            3 => Self::Timeout(reason),
            _ => Self::Failed(reason),
        }
    }
}

/// A connect request's bytes: token, onion key, port (u16 BE), flags
/// ([`CONNECT_FLAGS`]; 0 asks what version 2 asked).
pub fn encode_connect(
    token: &[u8; TOKEN_LEN],
    hs_id: &[u8; 32],
    port: u16,
    flags: u8,
) -> [u8; CONNECT_REQUEST_LEN] {
    let mut out = [0u8; CONNECT_REQUEST_LEN];
    out[..TOKEN_LEN].copy_from_slice(token);
    out[TOKEN_LEN..TOKEN_LEN + 32].copy_from_slice(hs_id);
    out[TOKEN_LEN + 32..TOKEN_LEN + 34].copy_from_slice(&port.to_be_bytes());
    out[TOKEN_LEN + 34] = flags;
    out
}

/// A connect request's parts (onion key, port, flags), the token checked
/// against `token` first ([`token_eq`]); `None` on a wrong token. Flags this
/// version does not know are the caller's to refuse ([`unknown_flags`]).
#[cfg_attr(not(debug_assertions), allow(dead_code))]
pub fn decode_connect(
    req: &[u8; CONNECT_REQUEST_LEN],
    token: &[u8; TOKEN_LEN],
) -> Option<([u8; 32], u16, u8)> {
    let got: [u8; TOKEN_LEN] = req[..TOKEN_LEN].try_into().ok()?;
    if !token_eq(&got, token) {
        return None;
    }
    let hs_id: [u8; 32] = req[TOKEN_LEN..TOKEN_LEN + 32].try_into().ok()?;
    let port = u16::from_be_bytes(req[TOKEN_LEN + 32..TOKEN_LEN + 34].try_into().ok()?);
    Some((hs_id, port, req[TOKEN_LEN + 34]))
}

/// An inbound stream's header: the token, then `circuit`, an opaque number
/// the helper gives each rendezvous circuit of its onion service (the same
/// for every stream on one circuit, never reused in one helper life). It
/// says nothing about who dialled; raven-node counts its slots per circuit.
#[cfg_attr(not(debug_assertions), allow(dead_code))]
pub fn encode_forward(token: &[u8; TOKEN_LEN], circuit: u64) -> [u8; FORWARD_HEADER_LEN] {
    let mut out = [0u8; FORWARD_HEADER_LEN];
    out[..TOKEN_LEN].copy_from_slice(token);
    out[TOKEN_LEN..].copy_from_slice(&circuit.to_be_bytes());
    out
}

/// An inbound stream header's circuit number, the token checked against
/// `token` first ([`token_eq`]); `None` on a wrong token.
pub fn decode_forward(head: &[u8; FORWARD_HEADER_LEN], token: &[u8; TOKEN_LEN]) -> Option<u64> {
    let got: [u8; TOKEN_LEN] = head[..TOKEN_LEN].try_into().ok()?;
    if !token_eq(&got, token) {
        return None;
    }
    Some(u64::from_be_bytes(head[TOKEN_LEN..].try_into().ok()?))
}

/// Constant-time token comparison (no early exit on the first difference).
pub fn token_eq(a: &[u8; TOKEN_LEN], b: &[u8; TOKEN_LEN]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    // Keep the compiler from turning the loop into an early exit.
    std::hint::black_box(diff) == 0
}

/// The token from [`Config::token`]: exactly 64 lowercase hex digits.
pub fn parse_token(hex_text: &str) -> Option<[u8; TOKEN_LEN]> {
    if hex_text.len() != TOKEN_LEN * 2
        || !hex_text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    hex::decode(hex_text).ok()?.try_into().ok()
}

/// An onion key from [`Event::Onion`]: exactly 64 lowercase hex digits.
pub fn parse_hs_id(hex_text: &str) -> Option<[u8; 32]> {
    parse_token(hex_text)
}

/// A control line: one JSON object and a newline.
pub fn line<T: Serialize>(value: &T) -> String {
    let mut text = serde_json::to_string(value).unwrap_or_else(|_| "{}".into());
    text.push('\n');
    text
}

/// The bootstrap stages [`stage_word`] names, in order. The first four:
/// no Tor relay has completed a handshake yet; the rest: relays answer and
/// the directory is being loaded.
pub const STAGES: [&str; 10] = [
    "connecting",
    "no_internet",
    "handshaking",
    "no_handshake",
    "waiting",
    "consensus",
    "certificates",
    "microdescriptors",
    "usable",
    "stuck",
];

/// Whether `stage` ([`STAGES`]) says Tor relays answered handshakes.
pub fn relays_reached(stage: &str) -> bool {
    matches!(
        stage,
        "waiting" | "consensus" | "certificates" | "microdescriptors" | "usable"
    )
}

/// Arti's bootstrap status (its display text: `N%: <connection>;
/// <directory>` or `Stuck at N%: <problem>`) as one fixed word of
/// [`STAGES`], or `other`. Never the text itself: the directory part names
/// times, the problem may name a relay. (raven-tor-helper's; raven-node
/// reads the word with [`known_stage`].)
#[cfg_attr(not(test), allow(dead_code))]
pub fn stage_word(display: &str) -> &'static str {
    let s = display.to_ascii_lowercase();
    if s.starts_with("stuck") {
        return "stuck";
    }
    let (conn, dir) = s.split_once("; ").unwrap_or((s.as_str(), ""));
    if conn.contains("unable to connect") {
        "no_internet"
    } else if conn.contains("unable to handshake") {
        "no_handshake"
    } else if conn.contains("connecting to the internet") {
        "connecting"
    } else if conn.contains("handshaking") {
        "handshaking"
    } else if !conn.contains("connecting successfully") {
        "other"
    } else if dir.contains("fetching a consensus") {
        "consensus"
    } else if dir.contains("authority certificates") {
        "certificates"
    } else if dir.contains("microdescriptors") {
        "microdescriptors"
    } else if dir.contains("usable") {
        "usable"
    } else {
        "waiting"
    }
}

/// A received stage as its fixed word (anything else is `other`).
pub fn known_stage(word: &str) -> &'static str {
    STAGES.into_iter().find(|s| *s == word).unwrap_or("other")
}

/// Tor's reason for being stuck as one fixed word (Arti's `BlockageKind`
/// display texts, mapped; anything else is `other`). Never Arti's free-text
/// message, which may name a relay.
pub fn blockage_word(kind_display: &str) -> &'static str {
    let k = kind_display.to_ascii_lowercase();
    if k.contains("offline") {
        "offline"
    } else if k.contains("filter") || k.contains("firewall") {
        "filtered"
    } else if k.contains("clock") {
        "clock_skewed"
    } else if k.contains("can't reach") || k.contains("cannot reach") || k.contains("reach tor") {
        "cant_reach_tor"
    } else if k.contains("directory") {
        "directory"
    } else if k.contains("disabled") {
        "disabled"
    } else {
        "other"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_lines_round_trip_and_stay_one_line() {
        let config = Config {
            v: PROTO_VERSION,
            state_dir: "/tmp/x/tor".into(),
            token: "ab".repeat(32),
            forward: "127.0.0.1:5000".into(),
            port: 7422,
            fresh_state: false,
        };
        let text = line(&config);
        assert_eq!(text.matches('\n').count(), 1);
        assert_eq!(
            serde_json::from_str::<Config>(text.trim_end()).unwrap(),
            config
        );
        // An older config line without fresh_state still reads.
        let old = r#"{"v":1,"state_dir":"s","token":"t","forward":"f","port":1}"#;
        assert!(!serde_json::from_str::<Config>(old).unwrap().fresh_state);
        for ev in [
            Event::Progress {
                pct: 45,
                blocked: None,
                stage: None,
            },
            Event::Progress {
                pct: 15,
                blocked: Some("offline".into()),
                stage: Some("consensus".into()),
            },
            Event::Ready {
                connect: "127.0.0.1:1".into(),
            },
            Event::Onion {
                hs_id: "00".repeat(32),
            },
            Event::Service {
                state: "running".into(),
                reason: None,
            },
            Event::Service {
                state: "bootstrapping".into(),
                reason: Some("intro point stopped answering".into()),
            },
            Event::Pong { n: 7 },
            Event::Uploads { ok: 1, of: 2 },
            Event::SelfCheck {
                n: 3,
                reached: true,
                reason: None,
            },
            Event::SelfCheck {
                n: 4,
                reached: false,
                reason: Some("no descriptor".into()),
            },
            Event::Error {
                what: "bootstrap failed".into(),
                local: false,
            },
            Event::Error {
                what: "folder permissions".into(),
                local: true,
            },
        ] {
            let text = line(&ev);
            assert_eq!(serde_json::from_str::<Event>(text.trim_end()).unwrap(), ev);
        }
        for cmd in [
            Command::Ping { n: 3 },
            Command::SelfCheck { n: 5 },
            Command::Stop,
        ] {
            let text = line(&cmd);
            assert_eq!(
                serde_json::from_str::<Command>(text.trim_end()).unwrap(),
                cmd
            );
        }
    }

    #[test]
    fn connect_requests_need_the_token() {
        let token = [7u8; TOKEN_LEN];
        let hs = [9u8; 32];
        let req = encode_connect(&token, &hs, 7422, 0);
        assert_eq!(decode_connect(&req, &token), Some((hs, 7422, 0)));
        let mut wrong = token;
        wrong[31] ^= 1;
        assert_eq!(decode_connect(&req, &wrong), None);
        assert!(token_eq(&token, &token));
        assert!(!token_eq(&token, &wrong));
    }

    #[test]
    fn forward_headers_need_the_token_and_carry_the_circuit() {
        let token = [7u8; TOKEN_LEN];
        let head = encode_forward(&token, 0x0102_0304_0506_0708);
        assert_eq!(&head[..TOKEN_LEN], &token);
        assert_eq!(decode_forward(&head, &token), Some(0x0102_0304_0506_0708));
        let mut wrong = token;
        wrong[0] ^= 1;
        assert_eq!(decode_forward(&head, &wrong), None);
    }

    #[test]
    fn connect_replies_round_trip_and_stay_printable() {
        for reply in [
            ConnectReply::Ok,
            ConnectReply::NotReady("bootstrapping".into()),
            ConnectReply::Unreachable("no descriptor".into()),
            ConnectReply::Timeout("rendezvous".into()),
            ConnectReply::Failed("x".into()),
        ] {
            let bytes = reply.encode();
            assert_eq!(ConnectReply::decode(bytes[0], &bytes[2..]), reply);
            assert_eq!(bytes[1] as usize, bytes.len() - 2);
        }
        let long = ConnectReply::Failed("a\nb".repeat(100)).encode();
        assert_eq!(long[1] as usize, MAX_REASON);
        assert!(long[2..].iter().all(|b| b.is_ascii_graphic() || *b == b' '));
        assert!(matches!(
            ConnectReply::decode(99, b""),
            ConnectReply::Failed(_)
        ));
    }

    #[test]
    fn tokens_and_keys_are_strict_hex() {
        let hex_text = "0f".repeat(32);
        assert_eq!(parse_token(&hex_text), Some([0x0f; 32]));
        assert!(parse_token(&hex_text.to_uppercase()).is_none());
        assert!(parse_token(&hex_text[2..]).is_none());
        assert!(parse_hs_id(&format!("{hex_text}0")).is_none());
    }

    #[test]
    fn service_states_have_exact_words() {
        for s in ServiceState::ALL {
            assert_eq!(ServiceState::parse(s.word()), Some(s));
        }
        assert!(ServiceState::parse("Running").is_none());
        assert!(ServiceState::Running.reachable());
        assert!(ServiceState::DegradedReachable.reachable());
        assert!(!ServiceState::Bootstrapping.reachable());
    }

    #[test]
    fn blockage_words_are_fixed() {
        assert_eq!(blockage_word("We seem to be offline"), "offline");
        assert_eq!(
            blockage_word("Can't reach the Tor network"),
            "cant_reach_tor"
        );
        assert_eq!(blockage_word("Clock is skewed"), "clock_skewed");
        assert_eq!(blockage_word("relay 192.0.2.1 said no"), "other");
    }

    /// Field test round 8: the first connects to a friend whose node just
    /// restarted failed on stale cached state. One more try with fresh
    /// circuits, within the budget, after a failure worth it.
    #[tokio::test(start_paused = true)]
    async fn a_failed_connect_is_tried_once_more_with_fresh_circuits() {
        use std::sync::{Arc, Mutex};
        let budget = Duration::from_secs(44);
        let run = |plan: Vec<(u64, Result<u8, ConnectReply>)>| {
            let tries: Arc<Mutex<Vec<(bool, u64)>>> = Arc::default();
            let log = tries.clone();
            let plan = Arc::new(Mutex::new(plan.into_iter()));
            let fut = connect_with_retry(budget, move |fresh, within| {
                log.lock().unwrap().push((fresh, within.as_secs()));
                let (secs, got) = plan.lock().unwrap().next().expect("a planned try");
                async move {
                    tokio::time::sleep(Duration::from_secs(secs)).await;
                    got
                }
            });
            async move {
                let t = tokio::time::Instant::now();
                let got = fut.await;
                let tries = tries.lock().unwrap().clone();
                (got, tries, t.elapsed().as_secs())
            }
        };
        let gone = || Err(ConnectReply::Unreachable("rendezvous failed".into()));
        // The stale try fails in 15 s; the fresh one 2 s later works.
        let (got, tries, took) = run(vec![(15, gone()), (6, Ok(1))]).await;
        assert_eq!(got, Ok(1));
        assert_eq!(tries, [(false, 44), (true, 27)]);
        assert_eq!(took, 23);
        // A first try that works: no second.
        let (got, tries, _) = run(vec![(3, Ok(7))]).await;
        assert_eq!((got, tries.len()), (Ok(7), 1));
        // Not worth it (not bootstrapped, a local failure): no second.
        for e in [
            ConnectReply::NotReady("x".into()),
            ConnectReply::Failed("x".into()),
        ] {
            let (got, tries, _) = run(vec![(1, Err(e.clone()))]).await;
            assert_eq!((got, tries.len()), (Err(e), 1));
        }
        // Too little left after the first: its error, no second.
        let (got, tries, _) = run(vec![(31, gone())]).await;
        assert_eq!((got, tries.len()), (gone(), 1));
        // The second is cut at what is left of the budget.
        let (got, tries, took) = run(vec![(10, gone()), (60, Ok(2))]).await;
        assert_eq!(got, Err(ConnectReply::Timeout("no circuit in time".into())));
        assert_eq!(tries, [(false, 44), (true, 32)]);
        assert_eq!(took, 44);
        // A first try that hangs is cut at the budget: no time for another.
        let (got, tries, took) = run(vec![(100, Ok(3))]).await;
        assert!(matches!(got, Err(ConnectReply::Timeout(_))));
        assert_eq!((tries.len(), took), (1, 44));
    }

    /// Audit T6: a first try that timed out (the Arti helper gives up a
    /// BEGIN on a dead shared circuit after 6 s) is followed by the fresh
    /// one at once, with [`CONNECT_RETRY_MIN_LEFT`] left; the pause comes
    /// only after any other failure.
    #[tokio::test(start_paused = true)]
    async fn a_timed_out_first_try_is_followed_at_once() {
        use std::sync::{Arc, Mutex};
        let budget = Duration::from_secs(44);
        let run = |plan: Vec<(u64, Result<u8, ConnectReply>)>| {
            let tries: Arc<Mutex<Vec<(bool, u64)>>> = Arc::default();
            let log = tries.clone();
            let plan = Arc::new(Mutex::new(plan.into_iter()));
            let fut = connect_with_retry(budget, move |fresh, within| {
                log.lock().unwrap().push((fresh, within.as_secs()));
                let (secs, got) = plan.lock().unwrap().next().expect("a planned try");
                async move {
                    tokio::time::sleep(Duration::from_secs(secs)).await;
                    got
                }
            });
            async move {
                let t = tokio::time::Instant::now();
                let got = fut.await;
                let tries = tries.lock().unwrap().clone();
                (got, tries, t.elapsed().as_secs())
            }
        };
        let timeout = || Err(ConnectReply::Timeout("tor timeout".into()));
        let gone = || Err(ConnectReply::Unreachable("rendezvous failed".into()));
        // The BEGIN times out after 6 s; the fresh try starts at once and
        // works in 3 s.
        let (got, tries, took) = run(vec![(6, timeout()), (3, Ok(1))]).await;
        assert_eq!(got, Ok(1));
        assert_eq!(tries, [(false, 44), (true, 38)]);
        assert_eq!(took, 9);
        // A rendezvous that failed after 6 s: the fresh try 2 s later.
        let (got, tries, took) = run(vec![(6, gone()), (3, Ok(2))]).await;
        assert_eq!(got, Ok(2));
        assert_eq!(tries, [(false, 44), (true, 36)]);
        assert_eq!(took, 11);
        // Timed out after 31 s: the 13 s left are enough for a fresh try.
        let (got, tries, took) = run(vec![(31, timeout()), (3, Ok(3))]).await;
        assert_eq!(got, Ok(3));
        assert_eq!(tries, [(false, 44), (true, 13)]);
        assert_eq!(took, 34);
        // Timed out after 33 s: 11 s left, no fresh try; the first's error.
        let (got, tries, took) = run(vec![(33, timeout())]).await;
        assert_eq!((got, tries.len(), took), (timeout(), 1, 33));
    }

    /// A new group number for the tests' isolation books.
    fn next_group() -> u32 {
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    /// Audit T6: a fresh try that worked is the friend's group from then
    /// on; a first try that timed out is never made in its group again,
    /// unless another dial already moved the friend on; each friend has its
    /// own; one unused for [`GROUP_KEPT`] is back in the default group.
    #[tokio::test(start_paused = true)]
    async fn the_isolation_book_keeps_the_group_that_worked() {
        let mut book = IsolationBook::new(next_group);
        let (a, b) = ([1u8; 32], [2u8; 32]);
        // Nothing known yet: the default group.
        assert_eq!(book.first_try(&a), None);
        // Its first try timed out: a new group from then on.
        book.first_timed_out(a, None);
        let moved = book.first_try(&a);
        assert!(moved.is_some());
        assert_eq!(book.first_try(&a), moved);
        // A fresh try that worked: its group is the friend's.
        let fresh = book.new_group();
        assert_ne!(Some(fresh), moved);
        book.fresh_succeeded(a, fresh);
        assert_eq!(book.first_try(&a), Some(fresh));
        // That group timed out too: a new one again.
        book.first_timed_out(a, Some(fresh));
        let again = book.first_try(&a);
        assert!(again.is_some() && again != Some(fresh), "{again:?}");
        // A timeout in a group the friend already left changes nothing.
        book.first_timed_out(a, Some(fresh));
        book.first_timed_out(a, None);
        assert_eq!(book.first_try(&a), again);
        // Another friend: its own (still the default group).
        assert_eq!(book.first_try(&b), None);
        // Kept while used; after GROUP_KEPT unused, the default group.
        tokio::time::advance(GROUP_KEPT - Duration::from_secs(1)).await;
        assert_eq!(book.first_try(&a), again);
        tokio::time::advance(GROUP_KEPT).await;
        assert_eq!(book.first_try(&a), None);
    }

    /// Audit T6 as the helpers connect: the circuit the default group
    /// shares is dead (each try in it times out after 10 s, as a BEGIN that
    /// gets no CONNECTED with Arti's default timeout). The first connect
    /// pays for it once: 10 s, then the fresh try at once (no pause after a
    /// timeout). The next ones go in that fresh group at once. Without the
    /// book, each one would meet the dead circuit again (13 s each).
    #[tokio::test(start_paused = true)]
    async fn connects_after_a_dead_shared_circuit_reuse_the_fresh_group() {
        use std::sync::{Arc, Mutex};
        let book = Mutex::new(IsolationBook::new(next_group));
        let key = [7u8; 32];
        let tries: Arc<Mutex<Vec<Option<u32>>>> = Arc::default();
        let connect = || {
            let tries = tries.clone();
            connect_in_groups(
                Duration::from_secs(44),
                &book,
                key,
                0,
                move |group, _within| {
                    tries.lock().unwrap().push(group);
                    async move {
                        if group.is_none() {
                            tokio::time::sleep(Duration::from_secs(10)).await;
                            return Err(ConnectReply::Timeout("tor timeout".into()));
                        }
                        tokio::time::sleep(Duration::from_secs(3)).await;
                        Ok(group)
                    }
                },
            )
        };
        let mut took = Vec::new();
        let mut used = Vec::new();
        for _ in 0..3 {
            let t = tokio::time::Instant::now();
            used.push(connect().await.expect("connected"));
            took.push(t.elapsed().as_secs());
        }
        assert_eq!(took, [13, 3, 3]);
        let fresh = used[0];
        assert!(fresh.is_some());
        assert_eq!(used, [fresh, fresh, fresh]);
        assert_eq!(*tries.lock().unwrap(), [None, fresh, fresh, fresh]);
    }

    /// The other ways a first try ends: one that timed out with no time
    /// left for a fresh try still moves the friend to a new group; one that
    /// failed otherwise (here a stale descriptor) keeps the friend's group
    /// unless the fresh try works, which then becomes it.
    #[tokio::test(start_paused = true)]
    async fn a_first_try_that_failed_moves_the_friend_only_when_it_should() {
        use std::sync::Mutex;
        let book = Mutex::new(IsolationBook::new(next_group));
        let key = [8u8; 32];
        let fail = |e: ConnectReply, secs: u64| {
            move |_group: Option<u32>, _within: Duration| {
                let e = e.clone();
                async move {
                    tokio::time::sleep(Duration::from_secs(secs)).await;
                    Err::<(), _>(e)
                }
            }
        };
        let timeout = ConnectReply::Timeout("tor timeout".into());
        let gone = ConnectReply::Unreachable("rendezvous failed".into());
        // Timed out after 35 s: no fresh try, but a new group next time.
        let got =
            connect_in_groups(Duration::from_secs(44), &book, key, 0, fail(timeout, 35)).await;
        assert!(matches!(got, Err(ConnectReply::Timeout(_))));
        let moved = book.lock().unwrap().first_try(&key);
        assert!(moved.is_some());
        // Unreachable, and the fresh try failed too: the group stays.
        let got = connect_in_groups(
            Duration::from_secs(44),
            &book,
            key,
            0,
            fail(gone.clone(), 1),
        )
        .await;
        assert_eq!(got, Err(gone.clone()));
        assert_eq!(book.lock().unwrap().first_try(&key), moved);
        // Unreachable, then the fresh try worked: its group is the friend's.
        let got = connect_in_groups(Duration::from_secs(44), &book, key, 0, |group, _| {
            let gone = gone.clone();
            async move {
                if group == moved {
                    Err(gone)
                } else {
                    Ok(group)
                }
            }
        })
        .await;
        let fresh = got.expect("the fresh try");
        assert!(fresh.is_some() && fresh != moved);
        assert_eq!(book.lock().unwrap().first_try(&key), fresh);
    }

    /// Version 3: the flags byte rides after the port, both ways; a bit this
    /// version does not know is refused (bits 1 and 2 are kept for the probe
    /// and optimistic data), and 0 asks what version 2 asked.
    #[test]
    fn connect_request_v3_round_trips_flags() {
        // Version 4 (the helper channel) keeps this layout.
        const { assert!(PROTO_VERSION >= 3) };
        assert_eq!(CONNECT_REQUEST_LEN, TOKEN_LEN + 32 + 2 + 1);
        let (token, hs) = ([3u8; TOKEN_LEN], [4u8; 32]);
        // Bit 1 is the probe (speed design M2, M3).
        assert_eq!(CONNECT_PROBE, 1 << 1);
        for flags in [
            0,
            CONNECT_FRESH_FIRST,
            CONNECT_PROBE,
            CONNECT_PROBE | CONNECT_FRESH_FIRST,
            CONNECT_HEDGE,
            CONNECT_FLAGS,
        ] {
            let req = encode_connect(&token, &hs, 7422, flags);
            assert_eq!(req[CONNECT_REQUEST_LEN - 1], flags);
            assert_eq!(decode_connect(&req, &token), Some((hs, 7422, flags)));
            assert!(!unknown_flags(flags), "{flags:#x}");
        }
        for bit in [1u8 << 2, 1 << 4, 1 << 7] {
            assert!(unknown_flags(bit), "{bit:#x}");
            assert!(unknown_flags(bit | CONNECT_HEDGE), "{bit:#x}");
            assert!(unknown_flags(bit | CONNECT_PROBE), "{bit:#x}");
        }
    }

    /// A probe (speed design M2): one try, in the friend's group, and no
    /// second one after a failure. One answered keeps the friend's group;
    /// one that failed or ran out of time moves the friend to a new group
    /// (the next first try builds fresh circuits). With fresh first the try
    /// goes in a new group, the friend's once answered.
    #[tokio::test(start_paused = true)]
    async fn a_probe_tries_once_and_a_failed_one_moves_the_friend() {
        /// One probe that takes `secs` and is answered when `ok`: what it
        /// gave and the groups it tried.
        async fn probe(
            book: &std::sync::Mutex<IsolationBook<u32>>,
            flags: u8,
            secs: u64,
            ok: bool,
        ) -> (Result<(), ConnectReply>, Vec<Option<u32>>) {
            let tried: Arc<std::sync::Mutex<Vec<Option<u32>>>> = Arc::default();
            let log = tried.clone();
            let got = probe_in_groups(Duration::from_secs(44), book, [13u8; 32], flags, |g| {
                log.lock().unwrap().push(g);
                async move {
                    tokio::time::sleep(Duration::from_secs(secs)).await;
                    if ok {
                        Ok(())
                    } else {
                        Err(ConnectReply::Timeout("tor timeout".into()))
                    }
                }
            })
            .await;
            let tried = tried.lock().unwrap().clone();
            (got, tried)
        }
        let key = [13u8; 32];
        let book = std::sync::Mutex::new(IsolationBook::new(next_group));
        // Answered in the default group: the friend stays there.
        let (got, tried) = probe(&book, CONNECT_PROBE, 1, true).await;
        assert_eq!((got, tried), (Ok(()), vec![None]));
        assert_eq!(book.lock().unwrap().first_try(&key), None);
        // A dead circuit: one try, 6 s, no fresh try; the friend moves on.
        let t = tokio::time::Instant::now();
        let (got, tried) = probe(&book, CONNECT_PROBE, 6, false).await;
        assert!(got.is_err());
        assert_eq!(tried, vec![None], "one try");
        assert_eq!(t.elapsed().as_secs(), 6);
        let moved = book.lock().unwrap().first_try(&key);
        assert!(moved.is_some(), "a new group for the next connect");
        // Out of time: the same.
        let (got, _) = probe(&book, CONNECT_PROBE, 60, true).await;
        assert_eq!(got, Err(ConnectReply::Timeout("no circuit in time".into())));
        let again = book.lock().unwrap().first_try(&key);
        assert!(again.is_some() && again != moved);
        // Fresh first: a new group, the friend's once answered.
        let (got, tried) = probe(&book, CONNECT_PROBE | CONNECT_FRESH_FIRST, 1, true).await;
        assert_eq!(got, Ok(()));
        assert!(tried[0].is_some() && tried[0] != again, "{tried:?}");
        assert_eq!(book.lock().unwrap().first_try(&key), tried[0]);
    }

    /// One planned try of the hedge tests: where it went, how long it takes,
    /// what it gives, and whether it ran to its end (a dropped try did not).
    type Plan = Arc<std::sync::Mutex<Vec<(Option<u32>, u64, bool)>>>;

    use std::sync::Arc;

    /// A try that takes `secs` in `group` and gives `got`, logged in `plan`
    /// (its last field set once it ran to its end).
    fn planned<T>(
        plan: &Plan,
        group: Option<u32>,
        secs: u64,
        got: Result<T, ConnectReply>,
    ) -> impl Future<Output = Result<T, ConnectReply>> {
        let plan = plan.clone();
        let at = {
            let mut p = plan.lock().unwrap();
            p.push((group, secs, false));
            p.len() - 1
        };
        async move {
            tokio::time::sleep(Duration::from_secs(secs)).await;
            plan.lock().unwrap()[at].2 = true;
            got
        }
    }

    /// Speed design M5: the friend's kept circuit is dead (a try in it
    /// times out after 6 s, as Arti gives up a BEGIN that gets no
    /// CONNECTED), a fresh group connects in 1 s. Hedged, the fresh try
    /// starts after 2 s without a stream and the connect takes 3 s, not 7;
    /// the dead try is dropped, and the fresh group is the friend's from
    /// then on (the next connect takes 1 s, with no hedge). Unhedged (flags
    /// 0) it is as before: 6 s, then the fresh try.
    #[tokio::test(start_paused = true)]
    async fn a_stalled_kept_circuit_is_hedged_after_two_seconds() {
        for (flags, took_first, ran_out) in [(CONNECT_HEDGE, 3, false), (0, 7, true)] {
            let book = std::sync::Mutex::new(IsolationBook::new(next_group));
            let key = [11u8; 32];
            let plan: Plan = Arc::default();
            let mut took = Vec::new();
            for _ in 0..2 {
                let t = tokio::time::Instant::now();
                let got = connect_in_groups(Duration::from_secs(44), &book, key, flags, |g, _| {
                    let dead = g.is_none();
                    planned(
                        &plan,
                        g,
                        if dead { 6 } else { 1 },
                        if dead {
                            Err(ConnectReply::Timeout("tor timeout".into()))
                        } else {
                            Ok(g)
                        },
                    )
                })
                .await;
                assert!(got.expect("connected").is_some(), "{flags}");
                took.push(t.elapsed().as_secs());
            }
            assert_eq!(took, [took_first, 1], "flags {flags}");
            let plan = plan.lock().unwrap().clone();
            assert_eq!(plan.len(), 3, "{plan:?}");
            assert_eq!((plan[0].0, plan[0].2), (None, ran_out), "{plan:?}");
            let fresh = plan[1].0;
            assert!(fresh.is_some(), "{plan:?}");
            assert_eq!(plan[2].0, fresh, "the next connect in the fresh group");
        }
    }

    /// The hedge's two tries: the first stream wins and the other try is
    /// dropped before its end. A slow but working first try that connects
    /// before the fresh one keeps the friend's group; a fresh try that
    /// wins makes its group the friend's. A first try that fails after the
    /// hedge started starts no third try: the fresh one's answer counts. A
    /// first try that ends before the hedge goes on as before (a quick
    /// failure: the fresh try 2 s later), and with too little budget left
    /// there is no hedge.
    #[tokio::test(start_paused = true)]
    async fn the_hedge_loser_is_ended() {
        let key = [12u8; 32];
        let gone = || Err::<Option<u32>, _>(ConnectReply::Unreachable("rendezvous failed".into()));
        let timeout = || Err::<Option<u32>, _>(ConnectReply::Timeout("tor timeout".into()));
        // (first try: secs, result; fresh try: secs, result) -> took, winner,
        // whether each ran to its end, the friend's group after.
        let run = |first: (u64, bool), fresh: (u64, Result<(), ConnectReply>), budget: u64| {
            let book = std::sync::Mutex::new(IsolationBook::new(next_group));
            async move {
                let plan: Plan = Arc::default();
                let t = tokio::time::Instant::now();
                let got = connect_in_groups(
                    Duration::from_secs(budget),
                    &book,
                    key,
                    CONNECT_HEDGE,
                    |g, _| {
                        let (secs, got) = if g.is_none() {
                            (first.0, if first.1 { Ok(g) } else { timeout() })
                        } else {
                            (fresh.0, fresh.1.clone().map(|()| g))
                        };
                        planned(&plan, g, secs, got)
                    },
                )
                .await;
                let took = t.elapsed().as_secs();
                let plan = plan.lock().unwrap().clone();
                let after = book.lock().unwrap().first_try(&key);
                (got, took, plan, after)
            }
        };
        // The first connects at 4 s, the fresh one (from 2 s) at 3 s: the
        // fresh one wins, the first is dropped.
        let (got, took, plan, after) = run((4, true), (1, Ok(())), 44).await;
        assert_eq!((took, plan.len()), (3, 2), "{plan:?}");
        assert_eq!(got.unwrap(), plan[1].0);
        assert!(!plan[0].2 && plan[1].2, "{plan:?}");
        assert_eq!(after, plan[1].0, "the fresh group is the friend's");
        // The first connects at 3 s, the fresh one (from 2 s) would at 5 s:
        // the first wins, the fresh try is dropped, the group stays.
        let (got, took, plan, after) = run((3, true), (3, Ok(())), 44).await;
        assert_eq!((got, took), (Ok(None), 3), "{plan:?}");
        assert!(plan[0].2 && !plan[1].2, "{plan:?}");
        assert_eq!(after, None, "the friend's group stays");
        // The first times out at 6 s while the fresh one (from 2 s) takes 5:
        // no third try; the fresh one connects at 7 s and is the friend's.
        let (got, took, plan, after) = run((6, false), (5, Ok(())), 44).await;
        assert_eq!((took, plan.len()), (7, 2), "{plan:?}");
        assert_eq!(got.unwrap(), plan[1].0);
        assert_eq!(after, plan[1].0);
        // Both fail: the fresh one's error, no third try.
        let (got, _, plan, _) = run((6, false), (1, gone().map(|_| ())), 44).await;
        assert_eq!((got, plan.len()), (gone(), 2), "{plan:?}");
        // Too little budget left at 2 s for a fresh try (12 s): no hedge.
        let (got, took, plan, _) = run((4, true), (1, Ok(())), 13).await;
        assert_eq!((got, took, plan.len()), (Ok(None), 4, 1), "{plan:?}");
    }

    /// Fresh first (W4): raven-node's last link to the friend failed past
    /// the stream, so the first try goes in a new group and never in the
    /// friend's kept one (whose circuit may be the dead one), with no hedge
    /// beside it; the group that worked is the friend's from then on.
    #[tokio::test(start_paused = true)]
    async fn fresh_first_skips_the_kept_group() {
        let book = std::sync::Mutex::new(IsolationBook::new(next_group));
        let key = [13u8; 32];
        let kept = book.lock().unwrap().new_group();
        book.lock().unwrap().fresh_succeeded(key, kept);
        let plan: Plan = Arc::default();
        let got = connect_in_groups(
            Duration::from_secs(44),
            &book,
            key,
            CONNECT_FRESH_FIRST | CONNECT_HEDGE,
            |g, _| {
                let stale = g == Some(kept);
                planned(
                    &plan,
                    g,
                    if stale { 6 } else { 3 },
                    if stale {
                        Err(ConnectReply::Timeout("tor timeout".into()))
                    } else {
                        Ok(g)
                    },
                )
            },
        )
        .await;
        let plan = plan.lock().unwrap().clone();
        assert_eq!(plan.len(), 1, "one try, no hedge: {plan:?}");
        let used = got.expect("connected");
        assert!(used.is_some() && used != Some(kept), "{plan:?}");
        assert_eq!(book.lock().unwrap().first_try(&key), used);
        // Without it, the first try goes in the friend's group.
        let plan: Plan = Arc::default();
        let got = connect_in_groups(Duration::from_secs(44), &book, key, 0, |g, _| {
            planned(&plan, g, 1, Ok(g))
        })
        .await;
        assert_eq!(got, Ok(used));
    }

    #[test]
    fn upload_rounds_are_read_from_one_arti_line_only() {
        assert_eq!(
            upload_round("descriptor uploaded successfully to 7/8 HSDirs"),
            Some((7, 8))
        );
        assert_eq!(
            upload_round("descriptor uploaded successfully to 0/1 HSDirs"),
            Some((0, 1))
        );
        for other in [
            "descriptor uploaded successfully to 9/8 HSDirs",
            "descriptor uploaded successfully to x/8 HSDirs",
            "descriptor uploaded successfully to 7/8 relays",
            "reuploading descriptor in 1h 3m",
            "",
        ] {
            assert_eq!(upload_round(other), None, "{other}");
        }
    }

    #[test]
    fn service_reasons_are_fixed() {
        for r in SERVICE_REASONS {
            assert_eq!(known_reason(r), r);
            assert!(!r
                .chars()
                .any(|c| c.is_ascii_digit() || c == '.' || c == ':'));
        }
        assert_eq!(known_reason("relay 192.0.2.1 closed"), "other problem");
        for r in CONNECT_REASONS {
            assert_eq!(known_connect_reason(r), r);
        }
        assert_eq!(known_connect_reason("192.0.2.1"), "other");
    }

    #[test]
    fn older_helper_lines_still_read() {
        // A progress line without a stage, an error without `local`.
        assert_eq!(
            serde_json::from_str::<Event>(r#"{"ev":"progress","pct":15}"#).unwrap(),
            Event::Progress {
                pct: 15,
                blocked: None,
                stage: None
            }
        );
        assert_eq!(
            serde_json::from_str::<Event>(r#"{"ev":"service","state":"running"}"#).unwrap(),
            Event::Service {
                state: "running".into(),
                reason: None
            }
        );
        assert_eq!(
            serde_json::from_str::<Event>(r#"{"ev":"error","what":"x"}"#).unwrap(),
            Event::Error {
                what: "x".into(),
                local: false
            }
        );
    }

    #[test]
    fn stage_words_are_fixed_and_say_whether_relays_answered() {
        // Arti 0.47's display texts (arti-client status.rs, tor-chanmgr and
        // tor-dirmgr event.rs).
        let cases = [
            (
                "0%: connecting to the internet; not downloading",
                "connecting",
            ),
            (
                "0%: unable to connect to the internet; not downloading",
                "no_internet",
            ),
            (
                "7%: handshaking with Tor relays; not downloading",
                "handshaking",
            ),
            (
                "7%: unable to handshake with Tor relays, possibly due to clock skew; x",
                "no_handshake",
            ),
            ("15%: connecting successfully; not downloading", "waiting"),
            (
                "15%: connecting successfully; directory is fetching a consensus",
                "consensus",
            ),
            (
                "30%: connecting successfully; directory is fetching authority certificates (3/9)",
                "certificates",
            ),
            (
                "60%: connecting successfully; directory is fetching microdescriptors (10/90)",
                "microdescriptors",
            ),
            (
                "100%: connecting successfully; directory is usable, fresh until 2026-10-28 \
                 12:00:00 UTC, and valid until 2026-10-28 14:00:00 UTC",
                "usable",
            ),
            (
                "Stuck at 15%: Can't reach the Tor network (relay 192.0.2.1)",
                "stuck",
            ),
            ("something new", "other"),
        ];
        for (display, word) in cases {
            assert_eq!(stage_word(display), word, "{display}");
            assert_eq!(known_stage(word), word);
        }
        assert_eq!(known_stage("192.0.2.1"), "other");
        assert!(!relays_reached("handshaking"));
        assert!(!relays_reached("stuck"));
        assert!(relays_reached("consensus"));
        assert!(relays_reached("microdescriptors"));
    }
}
