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
//!
//! Nothing here ever carries an onion address of a friend in a log or an
//! event: the onion key travels only inside the connect request.

use std::future::Future;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// This protocol's version ([`Config::v`]).
///
/// 2: an inbound stream's header carries its circuit number after the token
/// ([`encode_forward`]).
pub const PROTO_VERSION: u32 = 2;

/// The shared secret of one helper's life: 32 random bytes, hex in
/// [`Config::token`], raw on the loopback streams.
pub const TOKEN_LEN: usize = 32;

/// The longest control line either side accepts.
pub const MAX_LINE: usize = 4096;

/// A connect request: token, onion key, port.
pub const CONNECT_REQUEST_LEN: usize = TOKEN_LEN + 32 + 2;

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
    /// raven-node's forward listener (`127.0.0.1:<port>`).
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

/// The pause before a second Tor connect ([`connect_with_retry`]).
pub const CONNECT_RETRY_PAUSE: Duration = Duration::from_secs(2);
/// A second Tor connect is made only with at least this much of the
/// connect budget left after the pause (a rendezvous over a fresh
/// descriptor takes several seconds).
pub const CONNECT_RETRY_MIN_LEFT: Duration = Duration::from_secs(12);

/// A failed connect worth one more try with a fresh descriptor and fresh
/// circuits: the service was not found or not running, its introduction or
/// rendezvous failed, or Tor timed out. Field test round 8: right after a
/// friend's node restarted, the first connects failed on what the client
/// had cached of the old service (its descriptor, its introduction points).
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
/// is left after [`CONNECT_RETRY_PAUSE`]. Each try is bounded by what is
/// left of `budget`; the error is the last try's.
pub async fn connect_with_retry<T, F, Fut>(
    budget: Duration,
    mut connect: F,
) -> Result<T, ConnectReply>
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
    let first = bounded(budget, connect(false, budget)).await;
    let err = match first {
        Ok(t) => return Ok(t),
        Err(e) => e,
    };
    let left = budget.saturating_sub(start.elapsed());
    if !worth_another_connect(&err) || left < CONNECT_RETRY_PAUSE + CONNECT_RETRY_MIN_LEFT {
        return Err(err);
    }
    tokio::time::sleep(CONNECT_RETRY_PAUSE).await;
    let left = budget.saturating_sub(start.elapsed());
    bounded(left, connect(true, left)).await
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
    pub fn reason(&self) -> &str {
        match self {
            Self::Ok => "",
            Self::NotReady(r) | Self::Unreachable(r) | Self::Timeout(r) | Self::Failed(r) => r,
        }
    }

    /// The reply bytes: status, reason length, reason (cut to
    /// [`MAX_REASON`], non-printable bytes as `?`).
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

/// A connect request's bytes: token, onion key, port (u16 BE).
pub fn encode_connect(
    token: &[u8; TOKEN_LEN],
    hs_id: &[u8; 32],
    port: u16,
) -> [u8; CONNECT_REQUEST_LEN] {
    let mut out = [0u8; CONNECT_REQUEST_LEN];
    out[..TOKEN_LEN].copy_from_slice(token);
    out[TOKEN_LEN..TOKEN_LEN + 32].copy_from_slice(hs_id);
    out[TOKEN_LEN + 32..].copy_from_slice(&port.to_be_bytes());
    out
}

/// A connect request's parts, the token checked against `token` first
/// ([`token_eq`]); `None` on a wrong token.
pub fn decode_connect(
    req: &[u8; CONNECT_REQUEST_LEN],
    token: &[u8; TOKEN_LEN],
) -> Option<([u8; 32], u16)> {
    let got: [u8; TOKEN_LEN] = req[..TOKEN_LEN].try_into().ok()?;
    if !token_eq(&got, token) {
        return None;
    }
    let hs_id: [u8; 32] = req[TOKEN_LEN..TOKEN_LEN + 32].try_into().ok()?;
    let port = u16::from_be_bytes(req[TOKEN_LEN + 32..].try_into().ok()?);
    Some((hs_id, port))
}

/// An inbound stream's header: the token, then `circuit`, an opaque number
/// the helper gives each rendezvous circuit of its onion service (the same
/// for every stream on one circuit, never reused in one helper life). It
/// says nothing about who dialled; raven-node counts its slots per circuit.
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
        let req = encode_connect(&token, &hs, 7422);
        assert_eq!(decode_connect(&req, &token), Some((hs, 7422)));
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
