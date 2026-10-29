//! Local IPC framing for ash/raven ↔ raven-node (UDS / named pipe payload).
//!
//! Versioned length-prefixed JSON requests. Private keys MUST NOT appear in
//! request/response bodies. Auth is peer-cred at the socket layer (OS-specific).

use serde::{Deserialize, Serialize};

pub const IPC_VERSION: u16 = 1;
pub const MAX_IPC_FRAME: usize = 256 * 1024;

fn is_false(value: &bool) -> bool {
    !*value
}

fn is_zero_u8(value: &u8) -> bool {
    *value == 0
}

fn is_zero_u32(value: &u32) -> bool {
    *value == 0
}

fn is_zero_u64(value: &u64) -> bool {
    *value == 0
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum IpcRequest {
    Ping {
        v: u16,
    },
    Status {
        v: u16,
        /// The user asks raven-node to try its at-rest key again now, if the
        /// last try ended 30 s ago or more (`raven status`; privacy pack
        /// PP.4, review B-sealed-stores-6). The terminal app's periodic poll
        /// never sets it: the retries then keep their backoff. Not sent when
        /// false, so the request is the same bytes as before; an older
        /// raven-node ignores it.
        #[serde(default, skip_serializing_if = "is_false")]
        retry_key: bool,
    },
    /// Policy toggle — no secrets.
    SetPolicy {
        v: u16,
        bridge: Option<bool>,
        store: Option<bool>,
        relay: Option<bool>,
    },
    /// Enqueue already-sealed RavenEnvelopeV1 (base64). Daemon never seals here.
    EnqueueSealed {
        v: u16,
        envelope_b64: String,
        peer_hint: Option<String>,
    },
    /// Seal application payload bytes inside the daemon under a persisted ATSAM
    /// session (ADR 0004 D4 / M2). NON-RELEASE: does not lift RVN1 HOLD, and is
    /// not O6 E2E / confidential-delivery Proven. Field names must not include
    /// the substring `plaintext` (decode denylist).
    SealUnderSession {
        v: u16,
        /// Peer device Ed25519 as 64 hex chars (same plane as LanDial expected_pub_hex).
        peer_hint: String,
        /// Application payload bytes (standard or URL-safe base64). Not a field
        /// named with substring `plaintext`.
        app_payload_b64: String,
    },
    /// Direct-dial a LAN peer over Noise XX and exchange already-sealed frames.
    LanDial {
        v: u16,
        lan_dial: String,
        expected_pub_hex: String,
        frames_b64: Vec<String>,
    },
    /// Direct-dial an InternetTransport peer (RIH1 hello + framed envelopes).
    /// Lab-only until INTERNET_DIRECT_PRODUCTION_ENABLED. Not a WAN claim.
    InternetDial {
        v: u16,
        internet_dial: String,
        expected_pub_hex: String,
        frames_b64: Vec<String>,
    },
    /// Dial a peer over the libp2p carrier (P3: direct, then a Circuit Relay
    /// v2 circuit, DCUtR upgrade by libp2p) and run the Raven Noise link
    /// (`raven/p2p-link/v1` + RIH1 bind) inside a `/raven/link/1.0.0` stream.
    /// `multiaddr` ends in the target's `/p2p/<PeerId>`: `/p2p/<PeerId>` alone
    /// means "every address the contact book has". Verified contacts only.
    /// Lab-only until P2P_PRODUCTION_ENABLED. Not a WAN claim.
    P2pDial {
        v: u16,
        multiaddr: String,
        expected_pub_hex: String,
        frames_b64: Vec<String>,
    },
    /// Dial a verified contact over the Bluetooth nearby carrier (Phase 5,
    /// `protocol/RAVEN_NEARBY_LINK_V1.md`) and run the Raven Noise link
    /// (`raven/nearby-link/v1`) over its pipe. `nearby_dial` is the route's
    /// dial string, `nearby:<64 lowercase hex>`
    /// ([`crate::outbox::nearby_dial_for`]): a name, never an address.
    /// Lab-only until NEARBY_PRODUCTION_ENABLED. An older daemon answers
    /// `IPC_FRAME`.
    NearbyDial {
        v: u16,
        nearby_dial: String,
        expected_pub_hex: String,
        frames_b64: Vec<String>,
    },
    /// Dial a verified contact over the Tor onion carrier (lab,
    /// `protocol/RAVEN_ONION_CARRIER_V1.md`) and run the Raven Noise link
    /// (`raven/onion-link/v1`) inside the Tor stream. `onion_dial` is the
    /// route's dial string, `onion:<64 lowercase hex>`
    /// ([`crate::onion::dial_for`]): the onion key, never a `.onion` text.
    /// Lab-only until ONION_PRODUCTION_ENABLED. An older daemon answers
    /// `IPC_FRAME`.
    OnionDial {
        v: u16,
        onion_dial: String,
        expected_pub_hex: String,
        frames_b64: Vec<String>,
    },
    /// Wake the background outbox worker (`raven-node service`): retry the
    /// staged objects to one peer (64 hex Ed25519), or to every peer, now.
    /// Carries no content; answered `Accepted`. A daemon without a worker (or
    /// an older one, which answers `IPC_FRAME`) does not retry in the
    /// background, and the client must say so.
    OutboxKick {
        v: u16,
        #[serde(default)]
        peer_pub_hex: Option<String>,
        /// `raven outbox retry` (not a send's own kick): also lifts parks
        /// that only an explicit retry may lift (friend custody).
        #[serde(default)]
        retry: bool,
        /// `raven outbox hand-off` (friend custody, Phase 3): leave what
        /// waits with friends now, without the 60 s wait (a failed direct
        /// try is still needed). Absent (false) from older clients.
        #[serde(default, skip_serializing_if = "is_false")]
        custody_now: bool,
    },
    /// Delivery state of one of our outbound messages (32 hex message id).
    /// Metadata only, never content.
    OutboxStatus {
        v: u16,
        message_id_hex: String,
    },
    /// Our outbound objects the outbox still tracks, oldest first: at most
    /// `limit` rows ([`MAX_OUTBOX_LIST`] at most; default 50).
    OutboxList {
        v: u16,
        #[serde(default)]
        peer_pub_hex: Option<String>,
        #[serde(default)]
        limit: Option<u16>,
    },
    /// App channel (`docs/design/2026-10-rdap-app-channel.md` §8): seal an
    /// agent payload for a contact's node and queue it for the outbox worker.
    /// Idempotent on `(peer_identity_hex, client_ref)`. Gated
    /// (`APP_CHANNEL_HOLD`); a forerunner of IPC v2 `SubmitMessage`.
    AppSubmit {
        v: u16,
        peer_identity_hex: String,
        content_type: String,
        client_ref: String,
        body_b64: String,
        #[serde(default)]
        ttl_ms: Option<u64>,
        #[serde(default)]
        resend: bool,
    },
    /// App channel: one page of received agent payloads for the bound
    /// consumer (long-poll up to `wait_ms`, at most 20 s).
    AppInboxPage {
        v: u16,
        consumer: String,
        #[serde(default)]
        takeover: bool,
        #[serde(default)]
        content_type: Option<String>,
        #[serde(default)]
        after: Option<String>,
        #[serde(default)]
        limit: Option<u16>,
        #[serde(default)]
        wait_ms: Option<u32>,
    },
    /// App channel: the bound consumer is done with these items.
    AppInboxAck {
        v: u16,
        consumer: String,
        items: Vec<AppInboxRef>,
        disposition: String,
    },
    /// App channel identity bridge (design §4.2): sign one RDAP delegation
    /// statement with this node's identity. The node builds the exact bytes;
    /// one context only; the text never reaches the node (only its digest).
    AgentSign {
        v: u16,
        statement: crate::agent_sign::AgentDelegationStatement,
    },
    /// `raven lan on|off` (Phase 3, D7): the running node turns the LAN
    /// carrier on or off at once (its listener, LAN dials, custody links over
    /// LAN). ash has already written `lan_off` to node_policy.json; the node
    /// only applies it. Answered `LanSet`; an older daemon answers
    /// `IPC_FRAME` (it applies the policy at its next start).
    SetLan {
        v: u16,
        on: bool,
        /// `raven lan on --for <time>` (Phase 3 P3.C2): LAN turns off by
        /// itself at this time (ms since the epoch on Raven's clock); ash
        /// has saved it in `lan_meeting.json`. `None` (omitted): no meeting
        /// time, and any earlier one is dropped. A node before P3.C2 ignores
        /// it and answers `LanSet` without one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        until_ms: Option<u64>,
    },
    /// `raven send`'s nearby search (Phase 3 P3.11): where the LAN beacon
    /// (`protocol/RAVEN_LAN_BEACON_V1.md` §8) found the contact's LAN
    /// listener. The node answers at once with what it found, else looks for
    /// the contact and waits up to `wait_ms` (at most 2 s,
    /// [`crate::lan_beacon::LOCATE_SEND_WAIT_MS`]) for an answer.
    /// Answered `LanLocated`; an older daemon answers `IPC_FRAME`, which
    /// means nothing was found.
    LanLocate {
        v: u16,
        /// The contact's device key, 64 hex chars.
        peer_pub_hex: String,
        wait_ms: u32,
    },
    /// `raven nearby …` (Phase 5): `action` is one of
    /// [`NEARBY_CONTROL_ACTIONS`]: `enable` / `disable` (the ask-once
    /// consent, node_policy `nearby`), `on` / `off` (advertise for one
    /// contact, `peer_pub_hex`, for `ttl_secs`), `foreground` (a send or open
    /// chat for that contact), `status`, and `background_on` /
    /// `background_off` (`raven nearby background-mail on|off`, its own
    /// consent, owner decision OD-C8: node_policy `nearby_background_mail`,
    /// applied at once). (Not `op`: that is the request's own tag.) Answered
    /// `NearbyControlResult`; an older daemon answers `IPC_FRAME` (too old
    /// for nearby), and one older than background mail's actions
    /// `NEARBY_BAD_REQUEST`.
    NearbyControl {
        v: u16,
        action: String,
        /// The contact's device key, 64 hex chars (`on`, `off`,
        /// `foreground`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        peer_pub_hex: Option<String>,
        /// How long `on` advertises for the contact, in seconds.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ttl_secs: Option<u32>,
    },
    /// Phase 6a: the carrier order learning connectivity would use for one
    /// contact on the current network now ([`crate::learning`]), and why.
    /// Answered `LearningPlan`; `LEARNING_HOLD` while the learning gate is
    /// shut, and `IPC_FRAME` from an older daemon: either way the client
    /// keeps today's static order.
    LearningPlan {
        v: u16,
        /// The contact's device key, 64 hex chars.
        peer_pub_hex: String,
    },
    /// `raven learning reset` (Phase 6a): forget what was learned about one
    /// contact (`peer_pub_hex`), or about everyone (`None`). Answered
    /// `LearningReset`; `LEARNING_HOLD` while the gate is shut, and
    /// `IPC_FRAME` from an older daemon.
    LearningReset {
        v: u16,
        /// The contact's device key, 64 hex chars; absent: every contact.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        peer_pub_hex: Option<String>,
    },
    /// Lock v2 (Phase 6 P6.40, gate `LOCAL_PROTECTION`): raven-node drops
    /// every key it holds, stops its listeners and network tasks, and until
    /// `Unlock` answers only `Ping`, `Status` (`locked: true`), `Lock` and
    /// `Unlock` ([`LOCKED`] to anything else). Answered `LockState`. An
    /// older raven-node answers `IPC_FRAME` and one whose gate is shut
    /// [`LOCK_V2_HELD`]: `raven lock` then stops Raven instead (Lock now
    /// v1).
    Lock {
        v: u16,
    },
    /// Lock v2's unlock. `passphrase_b64` is the Raven passphrase (base64 of
    /// its bytes) of a profile that has one: never logged, never in a decode
    /// error, zeroized when dropped ([`IpcSecret`]). Absent for a keychain
    /// profile: a plain resume. Answered `LockState`, else
    /// [`UNLOCK_WRONG_PASSPHRASE`], [`UNLOCK_WAIT`] (the back-off after a
    /// wrong one) or [`UNLOCK_PASSPHRASE_REQUIRED`].
    Unlock {
        v: u16,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        passphrase_b64: Option<IpcSecret>,
    },
    /// Wake raven-node's update exchange (Phase 6b P6.49, RUP1 spec §7):
    /// `raven update download` approved a download (written to
    /// `updates/downloads` first), so it is fetched now rather than at the
    /// next pass. Carries no content; answered `Accepted`. An older daemon
    /// answers `IPC_FRAME` (it fetches nothing from friends).
    UpdateKick {
        v: u16,
    },
    /// How the messages raven-node received since it started came (E2 r9:
    /// `raven inbox` showed no path): message id, carrier and age, never an
    /// address. Answered `Arrivals`; `IPC_FRAME` from an older daemon (the
    /// inbox then shows no path).
    Arrivals {
        v: u16,
    },
    /// What raven-node saw of one contact lately, for `raven send` (E2 r9):
    /// how long ago it last had an authenticated LAN link with the contact
    /// (no LAN head start in the race without one), and the contact's
    /// routes whose last dial failed with no sign of the contact since (a
    /// send whose every route just failed queues at once). Answered
    /// `ContactReach`; `IPC_FRAME` from an older daemon (the send then
    /// probes as before).
    ContactReach {
        v: u16,
        /// The contact's device key, 64 hex chars.
        peer_pub_hex: String,
        /// The routes the send is about to try, in its order: the answer
        /// names a failed route by its index here, never by its address
        /// (security review 2026-10-29 #11). Empty from an older client
        /// (the answer then names no route).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        routes: Vec<ReachRoute>,
    },
}

/// One route a send asks about in [`IpcRequest::ContactReach`]: its carrier
/// label (`lan_dial`, ...) and its dial as the client will send it.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct ReachRoute {
    pub carrier: String,
    pub dial: String,
}

/// One received message in [`IpcResponse::Arrivals`]: its id (hex), how it
/// came ([`crate::arrivals::ArrivedVia::token`]) and how long ago.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct ArrivalRow {
    pub message_id_hex: String,
    pub via: String,
    pub age_s: u64,
}

/// One route of a contact whose last dial failed ([`IpcResponse::ContactReach`]):
/// the carrier label (`lan_dial`, ...), the route's index in the request's
/// `routes`, how long ago, and the dial's error text with every address in
/// it replaced by [`ADDRESS_PLACEHOLDER`] ([`without_addresses`]). No
/// address, multiaddr or onion address of a friend is ever in an IPC answer
/// (security review 2026-10-29 #11); the client knows its own routes.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct RouteFailure {
    pub carrier: String,
    pub route: u32,
    pub age_s: u64,
    pub error: String,
}

/// What [`without_addresses`] puts where an address was.
pub const ADDRESS_PLACEHOLDER: &str = "<address>";
/// What [`without_addresses`] puts where a local-network address was
/// ([`crate::outbox::is_local_network_ip`]): a text still says that macOS
/// refused a connection on the local network
/// ([`crate::outbox::local_network_refused`]).
pub const LOCAL_ADDRESS_PLACEHOLDER: &str = "<local address>";

/// The placeholder for the address `word`: a local-network one keeps that
/// fact.
fn placeholder_for(word: &str) -> &'static str {
    let ip = word
        .parse::<std::net::IpAddr>()
        .ok()
        .or_else(|| word.parse::<std::net::SocketAddr>().ok().map(|a| a.ip()))
        .or_else(|| {
            word.rsplit_once(':')
                .and_then(|(host, _)| host.parse::<std::net::IpAddr>().ok())
        });
    match ip {
        Some(ip) if crate::outbox::is_local_network_ip(ip) => LOCAL_ADDRESS_PLACEHOLDER,
        _ => ADDRESS_PLACEHOLDER,
    }
}

/// `text` with every address in it replaced by [`ADDRESS_PLACEHOLDER`]: IP
/// addresses (with or without a port, IPv6 in brackets or not), multiaddrs
/// (`/ip4/...`, `/p2p/...`), onion routes (`onion:<hex>`, `*.onion`) and
/// long hex or base32 runs (keys, onion addresses). The words around them
/// stay, so a text still says what happened.
pub fn without_addresses(text: &str) -> String {
    fn is_address(word: &str) -> bool {
        let lower = word.to_ascii_lowercase();
        if word.parse::<std::net::IpAddr>().is_ok()
            || word.parse::<std::net::SocketAddr>().is_ok()
            || lower.starts_with("onion:")
            || lower.ends_with(".onion")
            || lower.contains(".onion:")
            || ["/ip4/", "/ip6/", "/dns", "/p2p/", "/onion"]
                .iter()
                .any(|m| lower.contains(m))
        {
            return true;
        }
        // host:port with an IPv4 host and a trailing word char cut off.
        if let Some((host, port)) = word.rsplit_once(':') {
            if host.parse::<std::net::IpAddr>().is_ok() && port.chars().all(|c| c.is_ascii_digit())
            {
                return true;
            }
        }
        // A key or onion address: 40+ hex or base32 characters.
        word.len() >= 40 && word.chars().all(|c| c.is_ascii_alphanumeric())
    }
    let mut out = String::with_capacity(text.len());
    for (i, piece) in text.split(' ').enumerate() {
        if i > 0 {
            out.push(' ');
        }
        let start = piece
            .find(|c: char| !matches!(c, '(' | '[' | '"' | '\'' | '<' | '`'))
            .unwrap_or(piece.len());
        let lead = &piece[..start];
        let rest = &piece[start..];
        // Try the word without any trailing punctuation first (an address
        // before ':' or ')'), then as it is, then trimmed one mark at a time
        // (an IPv6 address may end in ':').
        const TRAILING: [char; 10] = [')', ']', ',', ';', ':', '.', '"', '\'', '>', '`'];
        let bare = rest.trim_end_matches(TRAILING);
        let mut core = if !bare.is_empty() && is_address(bare) {
            bare
        } else {
            rest
        };
        let mut hit = !core.is_empty() && is_address(core);
        while !hit && !core.is_empty() {
            let Some(last) = core.chars().last() else {
                break;
            };
            if !TRAILING.contains(&last) {
                break;
            }
            core = &core[..core.len() - last.len_utf8()];
            hit = !core.is_empty() && is_address(core);
        }
        // `[v6]:port` keeps its bracket in `lead`; try it whole too.
        if !hit && lead.ends_with('[') {
            let whole = format!("[{rest}");
            let trimmed = whole.trim_end_matches([')', ',', ';', '.']);
            if trimmed.parse::<std::net::SocketAddr>().is_ok() {
                out.push_str(&lead[..lead.len() - 1]);
                out.push_str(placeholder_for(trimmed));
                out.push_str(&whole[trimmed.len()..]);
                continue;
            }
        }
        if hit {
            out.push_str(lead);
            out.push_str(placeholder_for(core));
            out.push_str(&rest[core.len()..]);
        } else {
            out.push_str(piece);
        }
    }
    out
}

/// A secret one IPC request carries (Lock v2's passphrase, P6.40): `Debug`
/// never shows it and it is zeroized when dropped. On the wire it is a plain
/// JSON string.
#[derive(Clone, PartialEq, Eq)]
pub struct IpcSecret(zeroize::Zeroizing<String>);

/// Secret bytes that are wiped when dropped (Lock v2's passphrase, P6.40).
pub type SecretBytes = zeroize::Zeroizing<Vec<u8>>;

impl IpcSecret {
    pub fn new(text: String) -> Self {
        Self(zeroize::Zeroizing::new(text))
    }

    /// The base64 (standard or URL-safe) of `bytes`, as `Unlock` carries a
    /// passphrase.
    pub fn of_bytes(bytes: &[u8]) -> Self {
        use base64::Engine;
        Self::new(base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    /// The secret itself, for the one place that uses it.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// The bytes the base64 stands for, wiped when dropped; `None` when it
    /// is not base64 (said without the value).
    pub fn decode_b64(&self) -> Option<SecretBytes> {
        use base64::Engine;
        let text = self.0.trim();
        let mut out = zeroize::Zeroizing::new(Vec::with_capacity(text.len()));
        let standard = base64::engine::general_purpose::STANDARD.decode_vec(text, &mut out);
        if standard.is_ok() {
            return Some(out);
        }
        out.clear();
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode_vec(text, &mut out)
            .ok()
            .map(|()| out)
    }
}

/// Wipe a request frame that may have held Lock v2's passphrase (P6.40),
/// once it was answered.
pub fn wipe_frame(frame: &mut Vec<u8>) {
    zeroize::Zeroize::zeroize(frame);
}

impl std::fmt::Debug for IpcSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("IpcSecret(<redacted>)")
    }
}

impl Serialize for IpcSecret {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for IpcSecret {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(IpcSecret::new)
    }
}

/// Lock v2 (P6.40): what raven-node answers, while it is locked, to any
/// request but `Ping`, `Status`, `Lock` and `Unlock`.
pub const LOCKED: &str = "LOCKED";
/// `UpdateKick` to a raven-node whose update exchange is not active (the
/// mesh-update gate shut, or no release keys; Phase 6b P6.49).
pub const UPDATE_EXCHANGE_OFF: &str = "UPDATE_EXCHANGE_OFF";
/// Lock v2: `Lock` or `Unlock` to a raven-node whose local-protection gate
/// is shut (`raven lock` stops Raven instead, Lock now v1).
pub const LOCK_V2_HELD: &str = "LOCK_V2_HELD";
/// Lock v2: `Unlock` with a passphrase that does not open the profile.
pub const UNLOCK_WRONG_PASSPHRASE: &str = "UNLOCK_WRONG_PASSPHRASE";
/// Lock v2: `Unlock` sooner than the back-off after a wrong passphrase
/// allows (1 s, doubling to 60 s); the message says how long to wait.
pub const UNLOCK_WAIT: &str = "UNLOCK_WAIT";
/// Lock v2: `Unlock` without a passphrase for a profile that has one.
pub const UNLOCK_PASSPHRASE_REQUIRED: &str = "UNLOCK_PASSPHRASE_REQUIRED";

/// [`IpcRequest::NearbyControl`]'s actions.
pub const NEARBY_CONTROL_ACTIONS: [&str; 8] = [
    "enable",
    "disable",
    "on",
    "off",
    "foreground",
    "status",
    "background_on",
    "background_off",
];

impl IpcRequest {
    /// `Status`, as every reader of it but `raven status` sends it.
    pub fn status() -> Self {
        IpcRequest::Status {
            v: IPC_VERSION,
            retry_key: false,
        }
    }

    /// `raven status`'s `Status`: it also asks raven-node to try its at-rest
    /// key again now ([`IpcRequest::Status`]'s `retry_key`).
    pub fn status_retrying_key() -> Self {
        IpcRequest::Status {
            v: IPC_VERSION,
            retry_key: true,
        }
    }
}

/// One received agent payload, named for `AppInboxAck`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppInboxRef {
    pub sender_device_hex: String,
    pub message_id_hex: String,
}

/// One received agent payload as `AppInboxPage` serves it. The sender fields
/// come from the session-bound certificate the node verified.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppInboxEntry {
    pub sender_identity_hex: String,
    pub sender_device_hex: String,
    pub sender_address: String,
    pub sender_verified: bool,
    pub message_id_hex: String,
    pub app_id_hex: String,
    pub content_type: String,
    pub created_at_ms: u64,
    pub received_at_ms: u64,
    pub expires_at_ms: u64,
    pub body_b64: String,
}

/// Hard cap on `OutboxList` rows.
pub const MAX_OUTBOX_LIST: u16 = 200;

/// The libp2p host as `Status` reports it (P3). Public facts about this node
/// only: its own PeerId and listen addresses, counts and states; never a
/// peer's address, a message id or content.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct P2pStatusInfo {
    /// The host is running (listening, or at least dialling out).
    pub up: bool,
    /// This node's libp2p PeerId (the `p2p=` of its card).
    pub peer_id: String,
    /// The addresses the host listens on (and any UPnP / relay addresses).
    pub listen_addrs: Vec<String>,
    /// AutoNAT v2 verdict ([`crate::reach::NatVerdict`]): `public` (2
    /// independent servers reached us), `unconfirmed` (1), `private` or
    /// `unknown`. An older raven-node says `public` after one server.
    pub nat: String,
    /// One per relay that holds an active reservation: the address it is
    /// held on (`/…/p2p/<relay>`; a DNS name's resolved address).
    pub reservations: Vec<String>,
    /// How many relays are set by hand (at most 2): two addresses of one
    /// relay (TCP 7423 and TCP 443) are one relay with a fallback. Relays
    /// picked from contacts' offers are not counted here.
    pub relays_configured: u32,
    /// UPnP-IGD (IPv4): `unset` (never asked: off), `off`, `on` (trying),
    /// `mapped <port>` or `failed`.
    pub upnp: String,
    /// Present while this node also relays for others under its own PeerId
    /// (the retired `service --relay` role: debug
    /// `RAVEN_LAB_P2P_PROFILE_RELAY=1` only). Never the friend relay's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<RelayCounts>,
    /// The p2p listen setting the service runs with (`7423`, `IP:PORT`;
    /// `relay` only under the debug test switch; empty: p2p is off),
    /// whatever its `source`. Reported even while the host is held or not
    /// up, so `raven status` and `raven whoami --card` follow what the
    /// service really does (an installer flag beats node_policy.json).
    #[serde(default)]
    pub listen_setting: String,
    /// The listen setting the service was given but no longer honours
    /// (`relay`: it listens on 7423 instead); empty otherwise and from an
    /// older raven-node.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub retired_listen: String,
    /// Where it came from: `--p2p-listen`, `RAVEN_P2P_LISTEN` or
    /// `node_policy.json`.
    #[serde(default)]
    pub source: String,
    /// The relays the service keeps (or tries to keep) a reservation on:
    /// every address of each, in slot order: the relays set by hand first,
    /// then the ones picked from contacts' offers. While no host runs, the
    /// relays set by hand.
    #[serde(default)]
    pub relays: Vec<String>,
    /// The retired relay role under this node's own PeerId is on (`service
    /// --relay` with the debug switch `RAVEN_LAB_P2P_PROFILE_RELAY=1`;
    /// without it `--relay` is consent for the friend relay).
    #[serde(default)]
    pub relay_role: bool,
    /// The p2p gate is closed in this build (`P2P_HOLD`): nothing runs.
    #[serde(default)]
    pub held: bool,
    /// The p2p settings could not be used (bad value, unreadable policy):
    /// no host. Fixed text, no addresses.
    #[serde(default)]
    pub config_error: String,
    /// Listen addresses not open yet: a busy port (retried), or a specific
    /// address on no interface of this host (opened once it is there).
    #[serde(default)]
    pub listen_retrying: u32,
    /// Reachability class ([`crate::reach::ReachClass`]): `public`, `mapped`,
    /// `relayed`, `unreachable` or `unknown`. Empty while no host runs, and
    /// from an older raven-node.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reach: String,
    /// The AutoNAT results behind `nat`: those that count (independent
    /// servers) and those that do not. Counts only.
    #[serde(default)]
    pub nat_checks: NatChecks,
    /// One row per relay slot of the running host, in the order of
    /// [`Self::relays`] (empty while no host runs, and from an older
    /// raven-node).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relay_health: Vec<RelayHealth>,
    /// The running host's peer gate (counts only). `None` while no host
    /// runs, and from an older raven-node. Boxed: it keeps `Status` within
    /// the size of the other responses (the JSON is the same).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gate: Option<Box<P2pGateStatus>>,
    /// Raven links and hole punches since raven-node started (counts only;
    /// they survive a re-home). `None` while no host runs, and from an
    /// older raven-node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paths: Option<P2pPathCounts>,
    /// The friend relay of this profile ([`FriendRelayInfo`]): present
    /// while its gate is open (state `off` until consent is given), and
    /// while consent is given or the relay runs, whether or not the p2p host
    /// is up. `None` from an older raven-node. Its counts are never in [`Self::relay`] (that row is the
    /// retired relay role under this node's own PeerId).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub friend_relay: Option<FriendRelayInfo>,
    /// Automatic relay choice from the relays contacts offer is on (any-
    /// network plan C7: the friend relay gate, route hints and node policy
    /// `relay_auto`). `false` from an older raven-node.
    #[serde(default)]
    pub relay_auto: bool,
    /// Offered relays automatic choice could take now beside the ones it
    /// holds (used when one stops answering). Counts only.
    #[serde(default)]
    pub relay_standby: u32,
    /// Phase 4 (RWS1): how each relay slot's reservation travels, in the
    /// order of [`Self::relay_health`]: `tcp`, `quic`, `wss` (WebSocket over
    /// TLS), `wss-proxy` (the same through the HTTPS proxy), or empty while
    /// the slot holds none. Fixed words only. Empty while no host runs, and
    /// from an older raven-node.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relay_paths: Vec<String>,
    /// Phase 4 (RWS1 §8): where the proxy of WSS relay dials comes from:
    /// `setting`, `env`, `system`, `unsupported: <kind>` (one Raven cannot
    /// use: dials go direct), `held` (the proxy gate is closed), or empty
    /// (no proxy). Fixed words only: never a proxy host or a credential.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub proxy: String,
    /// Phase 4 (RWS1 §9): a relay reservation rides a proxied WSS
    /// connection, so this node offers no hole-punch or AutoNAT candidates
    /// and dials no direct contact address.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub restricted: bool,
    /// Phase 4 (RWS1 §8.2, P4.16): where the service's explicit proxy
    /// setting came from, as [`Self::source`] for the listen setting:
    /// `--p2p-proxy`, `RAVEN_P2P_PROXY` or `node_policy.json` (`raven node
    /// proxy`). Reported whether or not a host runs; empty while p2p is
    /// off, and from an older raven-node. Never the setting itself.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub proxy_source: String,
    /// Phase 4 (RWS1 §7, P4.16): the HTTPS proxy answered this host's last
    /// failed dial through it with a 407: `unsupported` (it offers no Basic:
    /// NTLM or Negotiate, Windows sign-in), `other` (no Basic and neither of
    /// those: Digest, Bearer, or no scheme named), `basic` (it wants a user name and
    /// password and none was given) or `refused` (it refused the ones
    /// given). Cleared by any reservation accepted. Fixed words only;
    /// empty otherwise, and from an older raven-node.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub proxy_auth: String,
    /// Phase 4 (RAVEN Port Mapping V1, P4.20): router port mapping as the
    /// running host sees it. Present while the PORT_MAP gate is open
    /// (debug lab only); `None` otherwise and from an older raven-node,
    /// whose [`Self::upnp`] says the same in its own words (`mapped <port>`
    /// for PCP and NAT-PMP too). Words and counts only, never an address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port_map: Option<PortMapStatus>,
    /// Phase 4 (P4.24): this host's NAT mapping classes and the hole-punch
    /// policy. Present while the NAT_CLASS gate is open (debug lab only);
    /// `None` otherwise and from an older raven-node. Words and counts only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nat_mapping: Option<NatMappingStatus>,
    /// Phase 4 (P4.28): PeerId rotation as the running host applies it.
    /// Present while the PEER_ROTATION gate is open (debug lab only); `None`
    /// otherwise and from an older raven-node. [`Self::peer_id`] is always
    /// the key in use. Words, counts and epoch numbers only, never a PeerId.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation: Option<RotationStatus>,
    /// Auto-reach (`docs/design/2026-10-auto-reach.md`): what STUN discovery
    /// found and what serverless punching did. Present while the STUN
    /// discovery gate is open (debug lab only); `None` otherwise and from an
    /// older raven-node. Words and counts only: no address (owner rule
    /// 2026-10-28: a public address travels only inside authenticated,
    /// encrypted links between verified friends, never in a card).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_reach: Option<AutoReachStatus>,
}

/// Auto-reach as the running node applies it (`P2pStatusInfo::auto_reach`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AutoReachStatus {
    /// `on` (STUN servers are asked), `off` (`raven node stun off`) or
    /// `hidden` (hide my IP for everyone stops the queries).
    #[serde(default)]
    pub state: String,
    /// `found` (a public IPv4 address is known and fresh), `none` (the
    /// servers asked last did not agree on one, or none answered) or
    /// `waiting` (not asked yet on this network).
    #[serde(default)]
    pub public: String,
    /// The NAT mapping class STUN saw for the p2p port (the Phase 4 words:
    /// `unknown`, `no_nat`, `stable_kept`, `stable_shifted`, `varies`).
    #[serde(default)]
    pub class: String,
    /// The p2p QUIC endpoint is exact (asked from the p2p port itself)
    /// rather than inferred from port preservation.
    #[serde(default)]
    pub anchored: bool,
    /// Servers asked and answers counted in the last probe.
    #[serde(default)]
    pub asked: u32,
    #[serde(default)]
    pub answered: u32,
    /// Seconds since the last answer; `None` before any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub age_s: Option<u64>,
    /// Which of this node's ports a contact reached from outside in the last
    /// 24 h (confirmed): `tcp`, `quic` (p2p) and `inet` (Internet direct).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reached: Vec<String>,
    /// Serverless punching (design §5), while its gate is open.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub punch: Option<PunchStatus>,
}

/// Serverless punching's counts since the node started (design §5). Counts
/// only: no contact is named.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PunchStatus {
    /// Contacts that are punch targets now.
    #[serde(default)]
    pub targets: u32,
    /// Attempts made, and those that ended in a connection.
    #[serde(default)]
    pub tried: u64,
    #[serde(default)]
    pub connected: u64,
    /// Contacts skipped now because a NAT class says a punch cannot work
    /// (`varies` or `unknown` on either side).
    #[serde(default)]
    pub skipped_class: u32,
    /// Attempts left for a later slot by the per-slot or daily limits.
    #[serde(default)]
    pub deferred: u64,
}

/// PeerId rotation (Phase 4, `protocol/RAVEN_P2P_PEER_ROTATION_V1.md`) as the
/// running host applies it.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RotationStatus {
    /// `off` (the profile's setting is off: the fixed network ID),
    /// `waiting` (on, but [`Self::waiting_on`] verified contacts cannot
    /// follow yet: the fixed ID), `starting` (contacts are told the coming
    /// IDs; the fixed ID until the next epoch), `on` (the ID of the current
    /// epoch) or
    /// `postponed` (a relay refused the new ID: the earlier one until the
    /// next epoch or a retry).
    #[serde(default)]
    pub state: String,
    /// Verified contacts with a p2p route that have not said they can follow
    /// a rotating ID (`waiting`).
    #[serde(default)]
    pub waiting_on: u32,
    /// The epoch whose key is in use; `None` with the fixed key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
    /// The epoch length in seconds.
    #[serde(default)]
    pub epoch_len_s: u64,
    /// Seconds until the next change of ID (an epoch boundary or a retry);
    /// `None` while the ID is fixed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_change_s: Option<u64>,
}

/// Router port mapping (Phase 4, RAVEN Port Mapping V1) as the running host
/// sees it: fixed words, the mapped port and counts. Never an address.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PortMapStatus {
    /// IPv4: `pcp`, `nat-pmp` or `upnp` (the router forwards
    /// [`Self::v4_port`]), `asking`, `none` (no router answered in any of
    /// the three), `behind_another_nat` (carrier NAT: nothing to map),
    /// `double_nat` (the router sits behind another router of the site),
    /// `off_path` (the Internet path bypasses the router, a VPN: not
    /// asked), `refused` (the router said no), or `off` (no consent:
    /// `raven node upnp on`).
    #[serde(default)]
    pub v4: String,
    /// The port the router forwards while [`Self::v4`] names a protocol; 0
    /// otherwise.
    #[serde(default)]
    pub v4_port: u16,
    /// The IPv6 pinhole: `open` (PCP), `asking`, `none` (no PCP answer, or
    /// no global IPv6 address), `refused`, or `not_asked` (no consent:
    /// `raven node ipv6-pinhole on`, or its gate is closed).
    #[serde(default)]
    pub v6: String,
    /// Mappings the router granted again after the first: a moved port or
    /// external address, or after a lease ran out. Counts only.
    #[serde(default)]
    pub renewals: u32,
    /// Times the router lost its mappings (a router restart) and was asked
    /// again.
    #[serde(default)]
    pub server_restarts: u32,
}

/// What this host knows of its NAT's outbound mappings (Phase 4, P4.24),
/// and what the hole-punch policy did with it. It starts over whenever the
/// endpoint is rebuilt (a network change). Words and counts only.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NatMappingStatus {
    /// The IPv4 TCP mapping: `unknown` (fewer than two networks observed
    /// this host together), `no_nat`, `stable_kept`, `stable_shifted` or
    /// `varies` (the outside port depends on the destination: no hole
    /// punch can guess it).
    #[serde(default)]
    pub tcp: String,
    /// The IPv4 QUIC mapping, in the same words.
    #[serde(default)]
    pub quic: String,
    /// The networks (/24 or /48) whose observations count now.
    #[serde(default)]
    pub observers: u32,
    /// Hole punches skipped as hopeless (both mappings vary, or two
    /// attempts failed on this network).
    #[serde(default)]
    pub punch_skipped: u64,
    /// Hole punches that failed on this network.
    #[serde(default)]
    pub punch_failed: u64,
}

/// The AutoNAT v2 results this host holds (they start over whenever the
/// endpoint is rebuilt). A result counts only from an independent server: one
/// we dialled directly at a global address, in a network (/24 or /48) other
/// than the tested address's own. Counts only.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NatChecks {
    /// The most independent servers that reached one IP of ours (`public`
    /// needs 2).
    #[serde(default)]
    pub reached: u32,
    /// Independent servers whose checks all failed.
    #[serde(default)]
    pub failed: u32,
    /// Results that did not count (a server on our own network, or one
    /// reached through a relay, on loopback or a LAN).
    #[serde(default)]
    pub not_counted: u32,
}

/// One relay slot as the running host sees it: state, times and counts,
/// never a peer's address beyond the relay's own address in use.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayHealth {
    /// The address in use (the one the reservation is asked or held on; a
    /// DNS name's resolved address), else as configured (one of
    /// `P2pStatusInfo.relays`).
    pub relay: String,
    /// `reserved`, `asking` (a reservation request in flight), `resolving`
    /// (its DNS name), `retrying` (after a refusal or a loss) or `waiting`
    /// (not tried yet).
    pub state: String,
    /// `reserved`: held for this long; `retrying`: lost this long ago
    /// (absent when it never held one in this endpoint).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub for_s: Option<u64>,
    /// The last successful ping's round trip, and how long ago it was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ping_ms: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ping_age_s: Option<u64>,
    /// `retrying`: the next attempt is due in this long.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_in_s: Option<u64>,
    /// Attempts that failed in a row.
    #[serde(default)]
    pub tries: u32,
    /// This relay's own AutoNAT check of us: `reached`, `failed`,
    /// `not_counted` (see [`NatChecks`]), or empty (none yet: a relay without
    /// `--autonat-server` never checks).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub check: String,
    /// `manual` (set by hand) or `offer` (picked from a contact's offer);
    /// empty from an older raven-node.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source: String,
    /// For an offered relay: the device key (hex) of the contact that
    /// offered it (ash shows that contact's name). Empty otherwise.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub operator_pub_hex: String,
}

/// Raven links per [`crate::outbox::DeliveryPath`]: counts only.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PathCounts {
    pub direct: u64,
    pub reversed: u64,
    pub relayed: u64,
    pub hole_punched: u64,
}

impl PathCounts {
    pub fn add(&mut self, path: crate::outbox::DeliveryPath) {
        use crate::outbox::DeliveryPath as P;
        let n = match path {
            P::Direct => &mut self.direct,
            P::Reversed => &mut self.reversed,
            P::Relayed => &mut self.relayed,
            P::HolePunched => &mut self.hole_punched,
        };
        *n = n.saturating_add(1);
    }
}

/// How this node's p2p links travelled since raven-node started: links it
/// started that carried a delivery (`sent`), links a peer started that it
/// served (`received`), and DCUtR's verdicts. Counts only.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct P2pPathCounts {
    pub sent: PathCounts,
    pub received: PathCounts,
    /// Relayed connections DCUtR upgraded to a direct one.
    pub upgrades: u64,
    /// Hole punches that failed (the link stays on the relay).
    pub upgrade_failures: u64,
}

/// Who the p2p host admits, as `Status` reports it: counts only, never a
/// PeerId or an address. The refusal counts start over whenever the
/// endpoint is rebuilt (raven-node starts, or the network changed).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct P2pGateStatus {
    /// Verified contacts with a `p2p=` PeerId: they may connect.
    pub contacts: u32,
    /// Relays it may connect to: its own, and those its contacts' `via=`
    /// lines name.
    pub relays: u32,
    /// contacts.json or blocked_pubs.json cannot be read: no contact is
    /// admitted until it is fixed (the relays still are).
    #[serde(default)]
    pub unreadable: bool,
    /// Connections refused: peers that are none of the above.
    pub refused: u64,
    /// Hole-punch dials refused because an address was not globally
    /// routable.
    #[serde(default)]
    pub refused_hole_punch: u64,
}

/// Route hints (RRH1, [`crate::route_hints`]) as `Status` reports them:
/// counts and flags only, never a key, a PeerId or an address. raven-node
/// fills it while route hints are live; the counters start over when it
/// restarts.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct RouteHintsStatus {
    /// Route hints are on ([`crate::route_hints::route_hints_live`]).
    pub live: bool,
    /// Contacts this node sent its route hints to.
    pub told: u32,
    /// Contacts whose route hints this node holds (not expired).
    pub learned: u32,
    /// RRH1 frames received and not used (malformed, stale or unasked).
    pub ignored: u64,
    /// Seconds since this node's own route hints last changed.
    pub generation_age_s: u64,
    /// This node hides its IP from every contact (node policy `hide_ip`).
    pub hide_ip: bool,
    /// Contacts it hides its IP from one by one (`contacts.json` `hide_ip`).
    pub hidden_contacts: u32,
}

/// The LAN listener as `Status` reports it (Phase 3, D7): how it is set,
/// where it is bound and whom it admits. Fixed words, listen addresses and
/// counts: never a contact's address, and contact keys only in
/// `pin_blocked` (and the beacon's `no_answer`), as `Status.clock_skew` has
/// them. raven-node fills it while it runs a LAN listener (`raven-node
/// service`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct LanStatus {
    /// [`LAN_MODE_ON`] (`--lan-listen auto`), [`LAN_MODE_OFF`] (`raven lan
    /// off`, or an unreadable node_policy.json), [`LAN_MODE_THIS_COMPUTER`]
    /// (a loopback address) or [`LAN_MODE_FIXED`] (any other address given
    /// with `--lan-listen`).
    pub mode: String,
    /// The addresses it is bound to now, IPv4 first (`0.0.0.0:7420`,
    /// `[::]:7420`); empty while it is down or off.
    pub listen: Vec<String>,
    /// It admits local sources only (loopback, private, link-local,
    /// unique-local or on one of this computer's networks): `auto` while
    /// its gate is live.
    pub local_only: bool,
    /// The LAN beacon (Phase 3): counts only. Absent while it does not run.
    /// Boxed: it keeps `Status` within the size of the other responses (the
    /// JSON is the same).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub beacon: Option<Box<BeaconCounts>>,
    /// How many contacts were seen on this network in the last 10 minutes
    /// (Phase 3 P3.C6): a fresh beacon find, or an authenticated LAN link
    /// from an address on one of this computer's networks now. A count
    /// only, never who or where. Absent from raven-node before P3.C6.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub friends_here_10m: Option<u32>,
    /// Contacts (keys, hex) whose saved address answered with another key
    /// in the last 10 minutes (M0, a noise pin mismatch: RAVEN stopped
    /// before identifying this computer), newest first, at most 8. Gone
    /// once the contact is heard from or the network changes. Absent when
    /// there is none, and from raven-node before P3.C6.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub pin_blocked: Vec<String>,
}

/// `LanStatus.mode`: `--lan-listen auto`, on.
pub const LAN_MODE_ON: &str = "on";
/// `LanStatus.mode`: `raven lan off` is in effect.
pub const LAN_MODE_OFF: &str = "off";
/// `LanStatus.mode`: a loopback address, reachable from this computer only.
pub const LAN_MODE_THIS_COMPUTER: &str = "this-computer";
/// `LanStatus.mode`: an address given with `--lan-listen`.
pub const LAN_MODE_FIXED: &str = "fixed";

/// The LAN beacon's counts as `Status` reports them (Phase 3): the last ten
/// minutes, never an address; contact keys only in `no_answer`, as
/// `Status.clock_skew` has them.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct BeaconCounts {
    /// `on`, `held` (its gate is closed), `off` (`raven lan off`, or the
    /// meeting time is over), `starting` (the LAN listener has not loaded
    /// the identity yet), `no-interfaces`, `port-busy` (another program
    /// holds the UDP port) or `unavailable` (its sockets could not be
    /// opened otherwise).
    pub state: String,
    /// Interfaces it runs on.
    pub interfaces: u32,
    /// Its own query came back to it, so this computer's multicast works.
    pub echo_ok: bool,
    /// Queries it sent.
    pub queries_10m: u32,
    /// Of those, the ones a contact answered.
    pub answered_10m: u32,
    /// Answers it sent to contacts' queries.
    pub answers_sent_10m: u32,
    /// Datagrams it dropped (malformed, over a limit, replayed).
    pub dropped_10m: u32,
    /// Contacts (keys, hex) it asked for in vain (Phase 3 P3.C3, F11b):
    /// something still waits for each, it was seen on this network in the
    /// last 7 days, and its last two rounds or more got no answer, as when
    /// the two clocks are too far apart for the beacon. At most 8, newest
    /// first. Absent when there is none, and from raven-node before P3.C3.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub no_answer: Vec<String>,
}

/// The profile's at-rest state as raven-node reports it (privacy pack PP.4):
/// fixed words and counts only, never a file name, a key or a friend. Every
/// build of the pack sends it, so its absence tells ash that an older
/// raven-node answers (the upgrade interlock,
/// [`crate::privacy::node_is_older`]).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct AtRestStatus {
    /// `sealed`, `waiting_for_keychain`, `key_unavailable`, `key_lost`,
    /// `migrating`, `plain`, `unsealed_by_user` or `needs_disk_space`
    /// ([`crate::privacy::STATE_SEALED`], ...).
    pub state: String,
    /// Registered files this build seals that are sealed, and that are plain.
    pub sealed_files: u16,
    pub plain_files: u16,
    /// Fixed tokens: `older_build_wrote_plain`, `scrub_pending`,
    /// `older_node_running`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

/// `Status.updates` (Phase 6b P6.49, design D W-D5): the update exchange's
/// counts and states, never a friend, a key or an address. Absent while the
/// mesh-update gate is shut and from older daemons; a field an older
/// raven-node lacks reads as its default.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct UpdateStatus {
    /// The newest security notice's serial (0: none).
    pub advisory_serial: u64,
    /// How many days old it is (by its issue time), when there is one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advisory_age_days: Option<u32>,
    /// The release log's size (0: none stored).
    pub log_size: u32,
    /// Releases friends offered this computer that wait for the person's
    /// approval.
    pub offers: u16,
    /// Approved downloads not finished yet.
    pub downloading: u16,
    /// Downloads complete and verified, waiting for the install approval.
    pub ready: u16,
    /// Builds staged (`updates/staged/`).
    pub staged: u16,
    /// Updates are frozen (equivocation or a split view).
    pub frozen: bool,
    /// What friends passed on that failed its checks, kept in quarantine.
    pub quarantined: u32,
}

/// raven-node's security events as `Status` reports them (Phase 6b design
/// A, step P6.24): counts kept in memory since raven-node started, never an
/// address, a key or a time of day. raven-node fills it while the security
/// events gate is live ([`crate::security_gate::SecGate::Events`]); the
/// alerts themselves are in the profile's security ledger. A field an older
/// raven-node lacks reads as its default.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct SecurityStatus {
    /// Connections the contact gates refused in the last hour (strangers,
    /// blocked keys, unverified contacts from outside the local network,
    /// the p2p peer gate).
    pub strangers_refused_1h: u32,
    /// Connections that failed before they authenticated in the last hour
    /// (a handshake that did not finish or did not parse, garbage).
    pub preauth_failures_1h: u32,
    /// Network sources the penalty box bans now (design A R1).
    pub bans_active: u16,
    /// Authenticated links to a contact whose data was changed on the way
    /// in the last 24 hours (`SEC_LINK_TAG_FAIL`).
    pub link_tag_failures_24h: u32,
    /// Alerts open in the ledger (new or seen).
    pub alerts_open: u16,
    /// The automatic responses are live
    /// ([`crate::security_gate::SecGate::Responses`]).
    pub responses_live: bool,
    /// Events dropped before they reached the ledger (a full queue).
    pub dropped: u32,
}

/// How the last delivery to one contact travelled since raven-node started
/// (any-network plan Phase 1 item 7): the contact's key and labels only,
/// never an address. Kept in memory by raven-node, so it starts over when
/// raven-node restarts.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContactPath {
    /// The contact's key (hex), as `contacts.json` holds it.
    pub peer_pub_hex: String,
    /// `lan_dial`, `internet_dial` or `p2p_dial`
    /// ([`crate::outbox::OutboxCarrier::label`]).
    pub carrier: String,
    /// [`crate::outbox::DeliveryPath`] (`direct`, `reversed`, `relayed` or
    /// `hole_punched`); empty when it is not known.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
    /// Seconds since that delivery.
    #[serde(default)]
    pub age_s: u64,
}

/// A contact the last p2p dial could not reach, and why
/// ([`crate::reach_diag`]: the reason block `reach: why=…`). Since raven-node
/// started; cleared by a receipt, an inbound link from the contact or a
/// network change. Never an address.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct ContactWhy {
    /// The contact's key (hex), as `contacts.json` holds it.
    pub peer_pub_hex: String,
    /// The reason block ([`crate::reach_diag::Diag::render`]), without the
    /// "; " that joins it to an error text.
    pub reason: String,
    /// Seconds since that dial.
    pub age_s: u64,
}

/// A contact whose clock runs ahead of ours (cutoff pack CP.7): something it
/// sent was refused as dated in our future. Or (Phase 3 P3.C3, F11b) the LAN
/// beacon matched its queries only at the epoch next to ours, round after
/// round, at a time in our epoch that shows a skew past the five minutes
/// Raven tolerates: its clock is at least that much ahead or behind. Kept in
/// memory by raven-node; never an address, never a time of day.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct ContactSkew {
    /// The contact's key (hex), as `contacts.json` holds it.
    pub peer_pub_hex: String,
    /// How far its clock is ahead of ours, in whole minutes (+ = ahead; at
    /// least 5, the window Raven tolerates, when measured from a refusal;
    /// negative = behind, which only the LAN beacon tells).
    pub minutes: i32,
    /// The LAN beacon's estimate: about this much or more (the bound its
    /// matches show). Absent (false) for a skew measured from a refusal, and
    /// from raven-node before P3.C3.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub at_least: bool,
}

/// A contact that took our PairInit or message and gave no answer
/// (`times` in a row since raven-node started, cleared by an answer): a hint
/// that the two clocks may differ when nothing measured a skew (CP.7).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct ContactUnanswered {
    /// The contact's key (hex), as `contacts.json` holds it.
    pub peer_pub_hex: String,
    pub times: u32,
}

/// What a relay reports about itself: counts only (NAT spec §5), shared by
/// `service --relay` (IPC `Status`) and `raven-node relay` (relay_status.json).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayCounts {
    /// `--open`: anyone may reserve (stricter limits).
    pub open: bool,
    /// PeerIds on the allow-list (0 with `open`).
    pub allowed_peers: u32,
    /// The allow-list could not be read: nobody may reserve (fail closed).
    #[serde(default)]
    pub allow_list_unreadable: bool,
    pub reservations: u32,
    pub circuits: u32,
    pub reservations_refused: u64,
    pub circuits_refused: u64,
    /// Connections the peer gate refused (a peer that may not use the relay
    /// never reaches the relay protocol). 0 from an older relay.
    #[serde(default)]
    pub connections_refused: u64,
}

/// The friend relay of `raven-node service` (any-network plan C6): a relay
/// for the profile's verified contacts under a relay key of its own, never
/// the profile PeerId. Counts and labels only: no address and no PeerId.
/// Every field is serde-default (local IPC only).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct FriendRelayInfo {
    /// `off` (its gate is open and consent is not given: see `consent`),
    /// `held` (consent is given but the friend relay gate is closed:
    /// `FRIEND_RELAY_HOLD`), `hidden` (consent is given but this node hides
    /// its IP from every contact: stopped until that is off), `starting`,
    /// `up` or `failed` (retried with backoff).
    #[serde(default)]
    pub state: String,
    /// `unset`, `no` or `yes` (node_policy.json `relay_offer`), or `flag`
    /// (`raven-node service --relay`, `RAVEN_P2P_RELAY=1`).
    #[serde(default)]
    pub consent: String,
    /// Its TCP and UDP (QUIC) port.
    #[serde(default)]
    pub port: u16,
    /// It is set to listen on TCP 443 too (best effort: a port this user may
    /// not open is skipped).
    #[serde(default)]
    pub also_443: bool,
    /// With `also_443`, once the relay reported its listeners: whether its
    /// TCP 443 listener is open (`false`: skipped, e.g. a Linux user
    /// service without CAP_NET_BIND_SERVICE). `None` before that, without
    /// `also_443`, and from an older raven-node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port_443_open: Option<bool>,
    /// PeerIds it admits: verified, unblocked contacts with a PeerId that
    /// this node may show its IP to, plus the manual allow-list, minus the
    /// deny list and blocked contacts.
    #[serde(default)]
    pub members: u32,
    /// PeerIds on the profile's manual allow-list (`relay_allow.json`).
    #[serde(default)]
    pub manual: u32,
    /// PeerIds on its deny list.
    #[serde(default)]
    pub denied: u32,
    #[serde(default)]
    pub counts: RelayCounts,
    /// `confirmed` (a member reserved from a globally routable IP within 24
    /// hours, or UPnP mapped its port), `unconfirmed` (it names addresses
    /// nobody has proved yet) or `no_address`.
    #[serde(default)]
    pub reachable: String,
    /// How long ago it was last confirmed, in seconds.
    #[serde(default)]
    pub confirmed_age_s: Option<u64>,
    /// It has an address worth offering to its members (route hints).
    #[serde(default)]
    pub offering: bool,
    /// Members its offer goes to.
    #[serde(default)]
    pub offered_to: u32,
}

/// One outbound object as the outbox sees it. Identifiers, states and counts
/// only: no plaintext, preview or ciphertext ever travels in it.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutboxItem {
    pub message_id_hex: String,
    pub peer_pub_hex: String,
    /// `message` or `ack`.
    pub kind: String,
    /// `queued` (not yet handed to a carrier), `sent` (written, no ACK yet),
    /// `held` (not tried: see `last_error_code`), `delivered`, `expired`,
    /// `failed` or `cancelled`; `waiting` (the long message horizon, Phase
    /// 5a: its envelope ran out and it waits for a new session, until its
    /// deadline in `expires_at_ms`). Additive: an older ash prints the word.
    pub state: String,
    /// The carrier of the last attempt (`lan_dial` / `internet_dial` /
    /// `p2p_dial`), or "".
    pub carrier: String,
    pub attempts: u32,
    /// Unix ms of the next scheduled attempt; 0 when none is scheduled.
    pub next_attempt_ms: u64,
    /// Stable code of the last failure (`NOT_REACHABLE`,
    /// `CONTACT_NOT_VERIFIED`, ...), or "".
    pub last_error_code: String,
    /// Unix ms when the sealed envelope stops being valid (0 = unknown); for
    /// a `waiting` message, its deadline.
    pub expires_at_ms: u64,
    /// Unix ms when raven-node's outbox saw it delivered (its verified
    /// receipt came back on an attempt of its own); 0 otherwise, and from an
    /// older raven-node.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub delivered_at_ms: u64,
    /// How the last write travelled (`direct` | `reversed` | `relayed` |
    /// `hole_punched`); recorded for p2p only, so empty when unknown, for
    /// LAN and Internet direct, and from an older raven-node.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
    /// Why the contact could not be reached: the reason block
    /// ([`crate::reach_diag`]), filled only for a live p2p object whose last
    /// error is `NOT_REACHABLE`, with its age (`asof=`: a remembered check).
    /// Empty otherwise, and from an older raven-node.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub why: String,
    /// No carrier ever wrote it and no friend holds a copy: it never left
    /// this computer (cutoff pack CP.6). Kept by a finished (`expired`) row,
    /// so its view can say "time ran out before they could be reached".
    /// Absent (false) from an older raven-node.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub never_sent: bool,
    /// Friends that hold a sealed copy (`IN_CUSTODY`, friend custody); 0 =
    /// none. Absent (0) from an older raven-node.
    #[serde(default, skip_serializing_if = "is_zero_u8")]
    pub in_custody: u8,
    /// One of those friends took it to pass on to the contact's own friend
    /// (custody handoff, Phase 5): the contact's receipt comes back through
    /// friends only if the contact verified this node's friend too, so a
    /// message that ran out was not confirmed rather than not collected
    /// (review handoff-3). Absent (false) from an older raven-node.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub custody_forwarded: bool,
    /// The ways its last attempt dialled, in plan order (carrier labels:
    /// `lan_dial`, `p2p_dial`, `onion_dial`, ...; E2 r40: its waiting
    /// reason names them all, not whichever dial ended last). Empty before
    /// the first dial, and from an older raven-node.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tried: Vec<String>,
    /// Its attempts by how they ended, in the order each first happened
    /// (E2 r40: `raven outbox status` said only "queued" after 10
    /// attempts). Empty from an older raven-node.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outcomes: Vec<AttemptCount>,
}

/// How many attempts of one outbox object ended one way
/// ([`OutboxItem::outcomes`]): `code` is an outbox error code
/// (`NOT_REACHABLE`, `NO_ACK_YET`, ...) or `DELIVERED`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct AttemptCount {
    pub code: String,
    pub count: u32,
}

/// The Bluetooth nearby carrier as `Status` and `NearbyControlResult`
/// report it (Phase 5, `protocol/RAVEN_NEARBY_LINK_V1.md`): counts and
/// states only, never a contact key, token, Bluetooth address or device
/// name. A field an older raven-node lacks reads as its default.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct NearbyStatusInfo {
    /// The user turned nearby on (node_policy `nearby`).
    pub enabled: bool,
    /// The nearby gate is open in this raven-node.
    pub gate_live: bool,
    /// The radio: one of [`NEARBY_RADIO_STATES`].
    pub radio: String,
    /// The roles this computer's radio takes: `central`, `peripheral`.
    pub roles: Vec<String>,
    /// The address this computer advertises from: `random` | `public` |
    /// `unknown`.
    pub address_privacy: String,
    /// Tokens on the air now (0 or 1).
    pub advertising: u8,
    /// Contacts the advertising rotates among now (at most 2).
    pub rotating: u8,
    /// Contacts seen in range in the current epoch.
    pub in_range: u32,
    /// Pipes up now.
    pub pipes: u32,
    pub frames_tx: u64,
    pub frames_rx: u64,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
    /// Knocks this node stayed silent to (strangers, replays).
    pub knock_silenced: u64,
    /// Background mail (owner decision OD-C8, node_policy
    /// `nearby_background_mail`): nearby also advertises for the contacts
    /// this node holds or has mail waiting for. An older raven-node lacks
    /// it (off).
    pub background_mail: bool,
}

/// [`NearbyStatusInfo::radio`]'s values: powered on, powered off, refused
/// by the OS (permission), no Bluetooth LE here, no backend in this build;
/// and why a radio did not start that the user can fix (review nearby-3):
/// the macOS RavenNearby helper missing, outdated or not running, the
/// Bluetooth service (BlueZ, the system bus) not running, this profile's own
/// state (identity, sessions, disk) not ready. An older ash shows a value
/// it does not know as it is.
pub const NEARBY_RADIO_STATES: [&str; 8] = [
    "powered_on",
    "off",
    "unauthorized",
    "unsupported",
    "no_backend",
    "helper_unavailable",
    "service_down",
    "local_state",
];

/// Learning connectivity (Phase 6a, [`crate::learning`]) as `Status`
/// reports it: its state, counts and, for the current network only, the
/// learned order per contact. Contact keys as `Status.last_paths` has them,
/// carrier labels and reason blocks: never an address, a network name, a
/// relay or a time of day. raven-node fills it while the learning gate is
/// live; a field an older raven-node lacks reads as its default.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct LearningStatus {
    /// `on`, `shadow`, `off`, `memory_only` or `reset_after_unreadable`
    /// ([`crate::learning::explain::State::token`]).
    pub state: String,
    /// Contacts, networks and relays the model holds, and its carry rows
    /// (custodian, recipient: carry choice, P6.16).
    pub contacts: u32,
    pub networks: u32,
    pub relays: u32,
    pub carriers: u32,
    /// Dials observed, probes sent and observations dropped (over a cap or
    /// not evidence) in the last 24 hours.
    pub observations_24h: u32,
    pub probes_24h: u32,
    pub dropped_24h: u32,
    /// Learned orders held back because the evidence contradicted itself.
    pub contradictions: u32,
    /// Worker plans whose learned order differed from the static one, in
    /// the last 24 hours (in shadow mode, P6.11, the order was not used).
    pub would_reorder_24h: u32,
    /// Seconds since the learning store was last saved; absent before the
    /// first save and while it is memory only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub saved_age_s: Option<u64>,
    /// At most [`MAX_LEARNING_ROWS`], current network only, newest first.
    pub rows: Vec<LearningRow>,
}

/// One contact's learned order in [`LearningStatus`].
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct LearningRow {
    /// The contact's key (hex), as `contacts.json` holds it.
    pub peer_pub_hex: String,
    /// Carrier labels, first tried first: `lan_dial`, `internet_dial`,
    /// `p2p_dial` ([`crate::outbox::OutboxCarrier::label`]).
    pub order: Vec<String>,
    /// The reason block (`learn: state=… order=… why=…`,
    /// [`crate::learning::explain`]).
    pub why: String,
}

/// Cap on [`LearningStatus::rows`].
pub const MAX_LEARNING_ROWS: usize = 16;

/// One custodian of carry choice's pick for a contact in
/// [`IpcResponse::LearningPlan`] (Phase 6a P6.16), first left with first:
/// what ash words as "left with Carol first (you meet often; delivered 3 of
/// 4 before)". Counts and fixed words only.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct LearningCarry {
    /// The custodian's key (hex), as `contacts.json` holds it.
    pub peer_pub_hex: String,
    /// How often this node meets it: `often`, `sometimes`, `rarely` or
    /// `never` ([`crate::learning::carry::met_word`]).
    pub met: String,
    /// Objects for this contact it held that were delivered, of all with
    /// an outcome, in whole outcomes as learning keeps them
    /// ([`crate::learning::model::Model::carry_record`]).
    pub delivered: u32,
    pub outcomes: u32,
}

// `Status` boxes its large optional rows (`p2p`, `nearby`, `learning`,
// `security`). With `learning` and `security` it is over clippy's 200-byte
// gap to the next variant: boxing one more existing field would change every
// reader of it in three crates, for a value that lives for one request.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "ok", rename_all = "snake_case")]
pub enum IpcResponse {
    Pong {
        v: u16,
    },
    Status {
        v: u16,
        bridge: bool,
        store: bool,
        relay: bool,
        forward_pending: u64,
        capabilities: Vec<String>,
        /// The libp2p host (P3): `nat`, `reservations`, `listen_addrs`, …
        /// Absent from older daemons and while the host does not run. Boxed:
        /// it keeps `Status` within the size of the other responses (the
        /// JSON is the same).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        p2p: Option<Box<P2pStatusInfo>>,
        /// This raven-node's process id, so a client names the one process to
        /// stop (`kill <pid>`), never a pattern that matches every profile's
        /// service. Absent from older daemons.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pid: Option<u32>,
        /// Where the LAN listener is bound while it is up (e.g. `0.0.0.0:7424`).
        /// Absent from older daemons and while it is down.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        lan_listen: Option<String>,
        /// How the last delivery to each contact travelled since raven-node
        /// started, newest first (bounded). Absent when there is none, and
        /// from older daemons.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        last_paths: Vec<ContactPath>,
        /// Route hints (RRH1): counts only. Absent while they are off, and
        /// from older daemons.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        route_hints: Option<RouteHintsStatus>,
        /// Contacts the last p2p dial could not reach, and why
        /// ([`ContactWhy`]), newest first (bounded). Absent when there is
        /// none, and from older daemons.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        unreachable: Vec<ContactWhy>,
        /// This computer's default route as raven-node last read it (a local
        /// fact; nothing is probed): `Some(false)` none, so only peers on its
        /// own networks can be reached; `Some(true)` one; `None` not read
        /// (no p2p host, or an older daemon).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        egress: Option<bool>,
        /// The LAN listen address raven-node is set to (`192.0.2.10:7499`)
        /// while binding it fails: the address `lan_bind_error` is about.
        /// Absent while the listener is up or has not tried yet, and from
        /// older daemons.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        lan_listen_wanted: Option<String>,
        /// Why that bind failed, as a token (`LAN_BIND_*`): the address is
        /// not on this computer now, another program has the port, the OS
        /// refused it, or another reason. Never the OS's own text (the
        /// service log has it).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        lan_bind_error: Option<String>,
        /// Contacts whose clock runs ahead of ours past the five minutes
        /// Raven tolerates, so what they send is refused ([`ContactSkew`],
        /// cutoff pack CP.7), newest first (bounded). Since raven-node
        /// started; cleared by the next envelope from that contact dated in
        /// time. Absent when there is none, and from older daemons.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        clock_skew: Vec<ContactSkew>,
        /// Contacts that took our PairInit or message on a link they
        /// accepted and gave no answer, and how many times in a row
        /// ([`ContactUnanswered`], CP.7), newest first (bounded). Since
        /// raven-node started; cleared by an answer. Absent when there is
        /// none, and from older daemons.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        unanswered: Vec<ContactUnanswered>,
        /// The profile's at-rest state ([`AtRestStatus`], privacy pack
        /// PP.4). Every build of the pack sends it; absent from older
        /// daemons, which is how ash tells that an older raven-node still
        /// runs for the profile.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        at_rest: Option<AtRestStatus>,
        /// The LAN listener ([`LanStatus`], Phase 3): its mode, where it is
        /// bound and whom it admits. Absent from older daemons and from a
        /// raven-node that runs no LAN listener (`raven-node ipc`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        lan: Option<LanStatus>,
        /// Security events ([`SecurityStatus`], Phase 6b): raven-node's
        /// memory-only counts. Absent while the security events gate is
        /// shut, and from older daemons; an older ash ignores it. Boxed like
        /// `p2p`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        security: Option<Box<SecurityStatus>>,
        /// The Bluetooth nearby carrier ([`NearbyStatusInfo`], Phase 5):
        /// counts and states only. Absent from older daemons and from a
        /// raven-node that runs no nearby engine. Boxed like `p2p`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        nearby: Option<Box<NearbyStatusInfo>>,
        /// Learning connectivity ([`LearningStatus`], Phase 6a): state,
        /// counts and the current network's learned orders. Absent while
        /// the learning gate is shut, and from older daemons. Boxed like
        /// `p2p`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        learning: Option<Box<LearningStatus>>,
        /// Lock v2 (P6.40): raven-node is locked (`IpcRequest::Lock`).
        /// Absent while the local-protection gate is shut, and from older
        /// daemons. While locked every other field is empty.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        locked: Option<bool>,
        /// The update exchange ([`UpdateStatus`], Phase 6b P6.49): counts
        /// only. Absent while the mesh-update gate is shut (a release
        /// build's Status is what it was), and from older daemons.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        updates: Option<UpdateStatus>,
        /// The Tor onion carrier's status line (lab, design
        /// 2026-10-tor-fallback §3.7): `Tor: starting (45 %)`, `Tor: ready`,
        /// `Tor: blocked on this network (...)`; states only. Absent while
        /// its gate is closed (a release build's Status is what it was), and
        /// from older daemons.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tor: Option<String>,
    },
    Accepted {
        v: u16,
    },
    /// `Lock` / `Unlock`'s answer (Lock v2, P6.40): raven-node is `locked`
    /// now. `passphrase`: this profile has a Raven passphrase, so its keys
    /// open with nothing else; without one they stay in the login keychain
    /// (DPAPI, the desktop keyring) while Raven is locked. `failed_unlocks`:
    /// wrong passphrases typed since the last unlock, said once by the
    /// `Unlock` that ends the lock.
    LockState {
        v: u16,
        locked: bool,
        passphrase: bool,
        #[serde(default, skip_serializing_if = "is_zero_u32")]
        failed_unlocks: u32,
    },
    /// `SetLan` is in effect: LAN is `on` (or off) in the running node now.
    LanSet {
        v: u16,
        on: bool,
        applied: bool,
        /// The meeting time the node now holds (`SetLan.until_ms`, Phase 3
        /// P3.C2); absent from a node before P3.C2, which holds none.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        until_ms: Option<u64>,
    },
    /// `LanLocate`'s answer: at most two dial strings, IPv4 first (an IPv6
    /// link-local one with its `%zone`), found in the last ten minutes on the
    /// local network; empty when nothing was found, while LAN is off, or
    /// while the beacon does not run. For this send only: never saved.
    LanLocated {
        v: u16,
        dials: Vec<String>,
    },
    LanDialResult {
        v: u16,
        frames_b64: Vec<String>,
    },
    InternetDialResult {
        v: u16,
        frames_b64: Vec<String>,
    },
    P2pDialResult {
        v: u16,
        frames_b64: Vec<String>,
        /// How the link travelled (`direct` | `reversed` | `relayed` |
        /// `hole_punched`); absent from older daemons.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        path: Option<String>,
    },
    NearbyDialResult {
        v: u16,
        frames_b64: Vec<String>,
    },
    OnionDialResult {
        v: u16,
        frames_b64: Vec<String>,
    },
    /// `NearbyControl`'s answer: the nearby carrier after the operation.
    NearbyControlResult {
        v: u16,
        status: Box<NearbyStatusInfo>,
    },
    /// Packed RavenEnvelopeV1 produced by in-daemon ATSAM seal (base64).
    SealUnderSessionResult {
        v: u16,
        envelope_b64: String,
    },
    OutboxStatusResult {
        v: u16,
        item: OutboxItem,
    },
    OutboxListResult {
        v: u16,
        /// False when this daemon runs no outbox worker (nothing is retried
        /// in the background); the items then come from the store alone.
        worker_running: bool,
        items: Vec<OutboxItem>,
    },
    AppSubmitResult {
        v: u16,
        message_id_hex: String,
        app_id_hex: String,
        /// `queued` for a fresh seal; the record's state for a duplicate.
        state: String,
        expires_at_ms: u64,
        duplicate: bool,
        attempt_seq: u32,
    },
    AppInboxPageResult {
        v: u16,
        items: Vec<AppInboxEntry>,
        next: Option<String>,
        more: bool,
        pending: u32,
    },
    AppInboxAckResult {
        v: u16,
        removed: u32,
    },
    AgentSignResult {
        v: u16,
        signer_address: String,
        signer_pub_hex: String,
        signature_b64: String,
    },
    /// `LearningPlan`'s answer: the carrier labels to try, first tried
    /// first (`lan_dial`, `internet_dial`, `p2p_dial`), the reason block
    /// (`learn: …`, [`crate::learning::explain`]) and the learning state
    /// ([`LearningStatus::state`]'s words). Only `on` asks the client to
    /// use the order.
    LearningPlan {
        v: u16,
        order: Vec<String>,
        why: String,
        state: String,
        /// Carry choice (P6.16): the custodians raven-node leaves this
        /// contact's mail with, in its order, while carry choice is live and
        /// learned something about them (`carry=ranked`); empty otherwise,
        /// and from an older raven-node (not written while empty).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        carry: Vec<LearningCarry>,
    },
    /// `LearningReset`'s answer: how many contacts' rows were forgotten.
    LearningReset {
        v: u16,
        cleared: u32,
    },
    /// `Arrivals`' answer, oldest first.
    Arrivals {
        v: u16,
        rows: Vec<ArrivalRow>,
    },
    /// `ContactReach`'s answer.
    ContactReach {
        v: u16,
        /// Seconds since raven-node's last authenticated LAN link with the
        /// contact, while it remembers one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        lan_seen_s: Option<u64>,
        /// The routes whose last dial failed, with no sign of the contact
        /// since.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        failed: Vec<RouteFailure>,
        /// Tor did not reach the contact lately (or is still dialling it),
        /// and raven-node's outbox already carries a message to it, Tor
        /// first: a send need not wait for Tor again (E2 r40). Absent
        /// (false) from an older raven-node.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        tor_busy: bool,
    },
    Error {
        v: u16,
        code: String,
        message: String,
    },
}

/// `Status.lan_bind_error`: the LAN listen address is not on this computer
/// now (`AddrNotAvailable`: macOS 49, Linux 99, Windows 10049), so the
/// listener binds once it is back (a network change, a cable).
pub const LAN_BIND_ADDR_NOT_HERE: &str = "addr_not_here";
/// `Status.lan_bind_error`: another program on this computer has the port
/// (`AddrInUse`).
pub const LAN_BIND_IN_USE: &str = "in_use";
/// `Status.lan_bind_error`: the OS refused the bind (`PermissionDenied`).
pub const LAN_BIND_DENIED: &str = "denied";
/// `Status.lan_bind_error`: any other bind failure.
pub const LAN_BIND_OTHER: &str = "other";

pub fn encode_request(req: &IpcRequest) -> Result<Vec<u8>, String> {
    let body = serde_json::to_vec(req).map_err(|e| e.to_string())?;
    if body.len() > MAX_IPC_FRAME {
        return Err("ipc request too large".into());
    }
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Substrings refused in JSON object *keys* (never in values: base64 ciphertext
/// and dial strings are opaque data and may contain any of these by chance).
pub const FORBIDDEN_FIELD_TOKENS: [&str; 4] = ["seed", "private_key", "plaintext", "recovery"];

/// Why [`decode_request_checked`] refused a frame. `code` is the stable
/// `IPC_*` error code for the response; `message` is diagnostic text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpcDecodeError {
    pub code: &'static str,
    pub message: String,
}

impl IpcDecodeError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

fn json_has_forbidden_key(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(map) => map.iter().any(|(key, v)| {
            let key = key.to_ascii_lowercase();
            FORBIDDEN_FIELD_TOKENS.iter().any(|bad| key.contains(bad)) || json_has_forbidden_key(v)
        }),
        serde_json::Value::Array(items) => items.iter().any(json_has_forbidden_key),
        _ => false,
    }
}

pub fn decode_request(frame: &[u8]) -> Result<IpcRequest, String> {
    decode_request_checked(frame).map_err(|e| e.message)
}

/// A refused request that may carry a passphrase is described with this
/// fixed text (Lock v2, P6.40), never serde's.
pub const PASSPHRASE_DECODE_ERROR: &str = "malformed request (its details are not shown)";

/// The body names a passphrase anywhere (any case): `Unlock`, or a request
/// that only looks like one.
fn mentions_passphrase(body: &[u8]) -> bool {
    body.windows(b"passphrase".len())
        .any(|w| w.eq_ignore_ascii_case(b"passphrase"))
}

/// [`decode_request`] with a typed error code (no substring classification).
pub fn decode_request_checked(frame: &[u8]) -> Result<IpcRequest, IpcDecodeError> {
    if frame.len() < 4 {
        return Err(IpcDecodeError::new("IPC_FRAME", "short frame"));
    }
    let n = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
    if n > MAX_IPC_FRAME || frame.len() < 4 + n {
        return Err(IpcDecodeError::new("IPC_FRAME", "bad length"));
    }
    let body = &frame[4..4 + n];
    let secret = mentions_passphrase(body);
    // serde's text can quote a value it refused: never for a request that
    // may carry Lock v2's passphrase (P6.40).
    let refused = |e: serde_json::Error| {
        let message = if secret {
            PASSPHRASE_DECODE_ERROR.to_owned()
        } else {
            e.to_string()
        };
        IpcDecodeError::new("IPC_FRAME", message)
    };
    let req: IpcRequest = serde_json::from_slice(body).map_err(refused)?;
    match &req {
        IpcRequest::Ping { v }
        | IpcRequest::Status { v, .. }
        | IpcRequest::SetPolicy { v, .. }
        | IpcRequest::EnqueueSealed { v, .. }
        | IpcRequest::SealUnderSession { v, .. }
        | IpcRequest::LanDial { v, .. }
        | IpcRequest::InternetDial { v, .. }
        | IpcRequest::P2pDial { v, .. }
        | IpcRequest::NearbyDial { v, .. }
        | IpcRequest::OnionDial { v, .. }
        | IpcRequest::OutboxKick { v, .. }
        | IpcRequest::OutboxStatus { v, .. }
        | IpcRequest::OutboxList { v, .. }
        | IpcRequest::AppSubmit { v, .. }
        | IpcRequest::AppInboxPage { v, .. }
        | IpcRequest::AppInboxAck { v, .. }
        | IpcRequest::AgentSign { v, .. }
        | IpcRequest::SetLan { v, .. }
        | IpcRequest::LanLocate { v, .. }
        | IpcRequest::NearbyControl { v, .. }
        | IpcRequest::LearningPlan { v, .. }
        | IpcRequest::LearningReset { v, .. }
        | IpcRequest::Lock { v }
        | IpcRequest::Unlock { v, .. }
        | IpcRequest::UpdateKick { v }
        | IpcRequest::Arrivals { v }
        | IpcRequest::ContactReach { v, .. } => {
            if *v != IPC_VERSION {
                return Err(IpcDecodeError::new("IPC_VERSION", "ipc version"));
            }
        }
    }
    // Refuse accidental secret field names in JSON (defense in depth). Only
    // object keys are inspected (after JSON unescaping); scanning the raw body
    // would randomly reject base64 payloads (~2^-20 per character for "seed").
    let mut tree: serde_json::Value = serde_json::from_slice(body).map_err(refused)?;
    let forbidden = json_has_forbidden_key(&tree);
    if secret {
        wipe_json_strings(&mut tree);
    }
    if forbidden {
        return Err(IpcDecodeError::new(
            "IPC_FORBIDDEN_FIELD",
            "forbidden field",
        ));
    }
    Ok(req)
}

/// Wipe every string of a JSON tree that may hold Lock v2's passphrase
/// before it drops (P6.40).
fn wipe_json_strings(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(text) => zeroize::Zeroize::zeroize(text),
        serde_json::Value::Array(items) => items.iter_mut().for_each(wipe_json_strings),
        serde_json::Value::Object(map) => map.values_mut().for_each(wipe_json_strings),
        _ => {}
    }
}

pub fn encode_response(resp: &IpcResponse) -> Result<Vec<u8>, String> {
    let body = serde_json::to_vec(resp).map_err(|e| e.to_string())?;
    if body.len() > MAX_IPC_FRAME {
        return Err("ipc response too large".into());
    }
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

pub fn decode_response(frame: &[u8]) -> Result<IpcResponse, String> {
    if frame.len() < 4 {
        return Err("short frame".into());
    }
    let n = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
    if n > MAX_IPC_FRAME || frame.len() < 4 + n {
        return Err("bad length".into());
    }
    serde_json::from_slice(&frame[4..4 + n]).map_err(|e| e.to_string())
}

pub(crate) const SOCKET_FILE_NAME: &str = "raven-node.sock";

/// Longest path `bind`/`connect` accept for an `AF_UNIX` socket: `sizeof
/// (sun_path)` minus the NUL (104 on macOS/BSD, 108 elsewhere).
#[cfg(unix)]
const UNIX_SOCKET_PATH_MAX: usize = if cfg!(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
)) {
    103
} else {
    107
};

/// Default Unix domain socket path (mode 0600 expected at bind): the daemon
/// and every client call this, so they always agree.
///
/// Normally `<data_dir>/raven-node.sock`. When that would not fit `sun_path`
/// (long `RAVEN_DATA_DIR`, sandbox or CI temp paths) `bind` would fail and the
/// service could never start, so a short deterministic per-user path is used
/// instead: `/tmp/raven-<euid>/raven-<hash of data dir>.sock` in a verified
/// owner-only directory. If no such directory can be made safely the direct
/// path is returned unchanged and bind fails loudly as before.
///
/// Every decision (direct or fallback, the direct path itself, the hash) is a
/// function of one normalized spelling of the data dir ([`normalized_data_dir`]:
/// absolute, symlinks resolved), never of how the caller happened to write it.
/// Otherwise a daemon started with one spelling (a launchd/systemd absolute or
/// symlinked `HOME`, `/tmp/x` vs `/private/tmp/x`, `./data`) and a client using
/// another that falls on the other side of the length limit would talk to
/// different sockets, and to different instance locks (`<sock>.lock`). A
/// consequence: a data dir spelled through a symlink such as macOS `/tmp` or
/// `/var` is measured by its longer canonical form, so it reaches the short
/// fallback a few bytes earlier. Tools should ask [`ipc_endpoint`] (`raven
/// doctor` prints it) instead of assuming `<data_dir>/raven-node.sock`.
///
/// Windows callers must not use this alone — the daemon binds
/// [`WINDOWS_NAMED_PIPE`], not a `.sock` file. Use [`ipc_endpoint`].
pub fn default_socket_path(data_dir: &std::path::Path) -> std::path::PathBuf {
    #[cfg(unix)]
    {
        let base = normalized_data_dir(data_dir);
        let direct = base.join(SOCKET_FILE_NAME);
        if direct.as_os_str().len() > UNIX_SOCKET_PATH_MAX {
            if let Some(short) = short_socket_path(&base) {
                return short;
            }
        }
        direct
    }
    #[cfg(not(unix))]
    {
        data_dir.join(SOCKET_FILE_NAME)
    }
}

/// The single-instance lock file of the IPC server listening on `socket`: the
/// socket path plus `.lock`. `raven-node` takes an exclusive `flock` on it for as
/// long as it serves, and clients (`ash`) probe it to tell a live service that is
/// not answering apart from no service at all. Both sides derive it here so they
/// cannot disagree.
pub fn instance_lock_path(socket: &std::path::Path) -> std::path::PathBuf {
    let mut path = socket.as_os_str().to_owned();
    path.push(".lock");
    std::path::PathBuf::from(path)
}

/// One spelling-independent form of `data_dir`: absolute, with symlinks
/// resolved. A directory that does not exist yet resolves its longest existing
/// ancestor and re-appends the rest, so the answer does not change when the
/// daemon creates the directory afterwards. Falls back to the absolute (then
/// the raw) spelling only when nothing can be resolved.
#[cfg(unix)]
fn normalized_data_dir(data_dir: &std::path::Path) -> std::path::PathBuf {
    if let Ok(canonical) = std::fs::canonicalize(data_dir) {
        return canonical;
    }
    let absolute = std::path::absolute(data_dir).unwrap_or_else(|_| data_dir.to_path_buf());
    let mut missing = Vec::new();
    let mut cursor = absolute.as_path();
    while let (Some(name), Some(parent)) = (cursor.file_name(), cursor.parent()) {
        missing.push(name.to_os_string());
        cursor = parent;
        if let Ok(mut resolved) = std::fs::canonicalize(cursor) {
            resolved.extend(missing.iter().rev());
            return resolved;
        }
    }
    absolute
}

#[cfg(unix)]
pub(crate) fn current_euid() -> u32 {
    extern "C" {
        fn geteuid() -> u32;
    }
    // SAFETY: `geteuid` takes no arguments, cannot fail and touches no memory.
    unsafe { geteuid() }
}

/// `/tmp/raven-<euid>`, created 0700 and verified: a symlink or a directory
/// owned by someone else in the shared `/tmp` (a squatted name) is never used,
/// since the socket's parent decides who can swap the endpoint under us.
#[cfg(unix)]
fn private_short_socket_dir() -> Option<std::path::PathBuf> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    let uid = current_euid();
    let dir = std::path::PathBuf::from(format!("/tmp/raven-{uid}"));
    match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return None,
    }
    let meta = std::fs::symlink_metadata(&dir).ok()?;
    if !meta.is_dir() || meta.uid() != uid {
        return None;
    }
    if meta.mode() & 0o077 != 0 {
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).ok()?;
    }
    Some(dir)
}

/// `base` must already be [`normalized_data_dir`]: daemon and clients then hash
/// the same bytes whatever spelling they were given.
#[cfg(unix)]
fn short_socket_path(base: &std::path::Path) -> Option<std::path::PathBuf> {
    use sha2::{Digest, Sha256};
    use std::os::unix::ffi::OsStrExt;
    let dir = private_short_socket_dir()?;
    let mut hasher = Sha256::new();
    hasher.update(b"raven/ipc-socket/v1\0");
    hasher.update(base.as_os_str().as_bytes());
    let digest = hasher.finalize();
    let path = dir.join(format!("raven-{}.sock", hex::encode(&digest[..8])));
    (path.as_os_str().len() <= UNIX_SOCKET_PATH_MAX).then_some(path)
}

/// Prefix of the Windows named pipe. The pipe namespace is machine-wide, so the
/// daemon binds (and clients connect to) the per-user name
/// `{WINDOWS_NAMED_PIPE}-{user SID}` ([`windows_pipe_name_for_sid`]) with a
/// current-user DACL. Clients must also verify the server process owner
/// (`verify_named_pipe_server_is_current_user`) — the name alone is not auth.
pub const WINDOWS_NAMED_PIPE: &str = r"\\.\pipe\raven-node";

/// Alias for [`WINDOWS_NAMED_PIPE`] (per-user pipe name prefix).
pub fn default_pipe_name() -> &'static str {
    WINDOWS_NAMED_PIPE
}

/// Per-user pipe name for a canonical string SID (`S-1-...`). `None` for
/// anything that is not a plain SID string, so it can never inject pipe path
/// components.
pub fn windows_pipe_name_for_sid(sid: &str) -> Option<String> {
    let mut parts = sid.split('-');
    let well_formed =
        sid.len() <= 184 && parts.next() == Some("S") && parts.next() == Some("1") && {
            let rest: Vec<&str> = parts.collect();
            !rest.is_empty()
                && rest
                    .iter()
                    .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
        };
    well_formed.then(|| format!("{WINDOWS_NAMED_PIPE}-{sid}"))
}

/// Debug-build lab override: `RAVEN_LAB_IPC_PIPE_SUFFIX=<1-32 of [A-Za-z0-9_-]>`
/// appends `-<suffix>` to this process's per-user pipe name. The Windows pipe
/// is per user, not per data dir (Unix sockets live in the data dir), so
/// without it two `raven-node service` profiles of one account (the portable
/// carrier harness on a CI runner) would share one pipe. Release builds ignore
/// it; a malformed value yields no name at all (fail closed, never the shared
/// default).
pub const LAB_IPC_PIPE_SUFFIX_ENV: &str = "RAVEN_LAB_IPC_PIPE_SUFFIX";

/// Apply [`LAB_IPC_PIPE_SUFFIX_ENV`] to a per-user pipe name (pure, testable
/// on every OS).
pub fn with_lab_pipe_suffix(
    user_pipe: String,
    suffix: Option<&str>,
    lab_build: bool,
) -> Option<String> {
    match suffix {
        Some(s) if lab_build => {
            let ok = (1..=32).contains(&s.len())
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
            ok.then(|| format!("{user_pipe}-{s}"))
        }
        _ => Some(user_pipe),
    }
}

/// Per-user pipe name for the current process token user (cached).
/// `None` if the SID cannot be read — callers fail closed.
#[cfg(windows)]
pub fn windows_user_pipe_name() -> Option<&'static str> {
    static NAME: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    NAME.get_or_init(|| {
        let suffix = std::env::var(LAB_IPC_PIPE_SUFFIX_ENV).ok();
        win_pipe::current_user_sid()
            .ok()
            .and_then(|sid| windows_pipe_name_for_sid(&sid))
            .and_then(|name| with_lab_pipe_suffix(name, suffix.as_deref(), cfg!(debug_assertions)))
    })
    .as_deref()
}

/// Refuse a connected pipe whose server process runs as a different user
/// (pipe squatting). Call before writing any request bytes.
#[cfg(windows)]
pub fn verify_named_pipe_server_is_current_user(
    pipe: std::os::windows::io::RawHandle,
) -> Result<(), String> {
    let me = win_pipe::current_user_sid()?;
    let server = win_pipe::pipe_server_user_sid(pipe as windows_sys::Win32::Foundation::HANDLE)?;
    if server != me {
        return Err("named pipe server runs as a different user; refusing (squatted pipe?)".into());
    }
    Ok(())
}

#[cfg(windows)]
pub(crate) mod win_pipe {
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
    use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    struct OwnedHandle(HANDLE);

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
    }

    unsafe fn token_user_sid(token: HANDLE) -> Result<String, String> {
        let mut needed = 0u32;
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed);
        if needed == 0 {
            return Err("GetTokenInformation(TokenUser) size failed".into());
        }
        // u64 backing keeps TOKEN_USER (pointer-bearing) suitably aligned.
        let mut buf = vec![0u64; (needed as usize).div_ceil(8)];
        if GetTokenInformation(
            token,
            TokenUser,
            buf.as_mut_ptr().cast(),
            needed,
            &mut needed,
        ) == 0
        {
            return Err("GetTokenInformation(TokenUser) failed".into());
        }
        let sid = (*(buf.as_ptr() as *const TOKEN_USER)).User.Sid;
        if sid.is_null() {
            return Err("TOKEN_USER SID is null".into());
        }
        let mut wide: windows_sys::core::PWSTR = std::ptr::null_mut();
        if ConvertSidToStringSidW(sid, &mut wide) == 0 || wide.is_null() {
            return Err("ConvertSidToStringSidW failed".into());
        }
        let mut len = 0usize;
        while *wide.add(len) != 0 {
            len += 1;
        }
        let out = String::from_utf16_lossy(std::slice::from_raw_parts(wide, len));
        LocalFree(wide as _);
        Ok(out)
    }

    pub(crate) fn current_user_sid() -> Result<String, String> {
        unsafe {
            let mut token: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return Err("OpenProcessToken(self) failed".into());
            }
            let token = OwnedHandle(token);
            token_user_sid(token.0)
        }
    }

    pub(super) fn pipe_server_user_sid(pipe: HANDLE) -> Result<String, String> {
        unsafe {
            let mut pid = 0u32;
            if GetNamedPipeServerProcessId(pipe, &mut pid) == 0 || pid == 0 {
                return Err("GetNamedPipeServerProcessId failed".into());
            }
            let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if process.is_null() {
                return Err("OpenProcess(pipe server) failed".into());
            }
            let process = OwnedHandle(process);
            let mut token: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(process.0, TOKEN_QUERY, &mut token) == 0 {
                let os = std::io::Error::last_os_error();
                // Typical cause: the daemon runs elevated and this client does
                // not. Fail closed; the fix is running both at one elevation.
                return Err(format!(
                    "OpenProcessToken(pipe server) failed: {os}; cannot verify the pipe owner \
                     (run raven-node and ash at the same elevation)"
                ));
            }
            let token = OwnedHandle(token);
            token_user_sid(token.0)
        }
    }
}

/// Platform-local IPC connect target.
///
/// Callers must obtain this from [`ipc_endpoint`] so Windows never looks for a
/// UDS path under `data_dir`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcEndpoint {
    /// Unix domain socket (`<data_dir>/raven-node.sock`, or the short
    /// per-user fallback of [`default_socket_path`] for long data dirs).
    UnixSocket(std::path::PathBuf),
    /// Per-user Windows named pipe (`{WINDOWS_NAMED_PIPE}-{user SID}`).
    NamedPipe(&'static str),
    /// No local IPC transport on this OS. Clients/doctor must fail closed
    /// (`ipc_transport_missing`) — never treat as a pass.
    Unsupported,
}

impl std::fmt::Display for IpcEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpcEndpoint::UnixSocket(p) => write!(f, "{}", p.display()),
            IpcEndpoint::NamedPipe(n) => write!(f, "{n}"),
            IpcEndpoint::Unsupported => write!(f, "ipc_transport_missing"),
        }
    }
}

impl IpcEndpoint {
    /// False when this OS has no ash↔raven-node IPC transport.
    pub fn transport_available(&self) -> bool {
        !matches!(self, IpcEndpoint::Unsupported)
    }
}

/// Unix socket path vs Windows named-pipe name.
///
/// Never returns a UDS path on Windows.
pub fn ipc_endpoint(data_dir: &std::path::Path) -> IpcEndpoint {
    #[cfg(unix)]
    {
        IpcEndpoint::UnixSocket(default_socket_path(data_dir))
    }
    #[cfg(windows)]
    {
        let _ = data_dir;
        match windows_user_pipe_name() {
            Some(name) => IpcEndpoint::NamedPipe(name),
            // No user SID → no safe per-user name. Fail closed.
            None => IpcEndpoint::Unsupported,
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = data_dir;
        IpcEndpoint::Unsupported
    }
}

/// Alias for [`ipc_endpoint`].
pub fn default_ipc_endpoint(data_dir: &std::path::Path) -> IpcEndpoint {
    ipc_endpoint(data_dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Security review 2026-10-29 #11: no address of a friend in an IPC
    /// answer or a send's technical text; the words stay.
    #[test]
    fn without_addresses_keeps_the_words_and_drops_every_address() {
        let onion = format!("did not answer at onion:{}", "ab".repeat(32));
        let cases = [
            (
                "LAN dial to 192.168.1.20:7420 failed: Connection refused (os error 61)",
                "LAN dial to <local address> failed: Connection refused (os error 61)",
            ),
            (
                "lan_dial 192.168.1.20:7420: no route to host",
                "lan_dial <local address>: no route to host",
            ),
            ("cannot connect to [fe80::1]:7422.", "cannot connect to <local address>."),
            ("cannot connect to [2001:db8::1]:7422.", "cannot connect to <address>."),
            ("internet connect (203.0.113.9) timed out", "internet connect (<address>) timed out"),
            (
                "p2p_dial /ip4/203.0.113.9/tcp/7423/p2p/12D3KooWAbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcd: P2P_UNREACHABLE",
                "p2p_dial <address>: P2P_UNREACHABLE",
            ),
            (onion.as_str(), "did not answer at <address>"),
            ("host 2001:db8::7 is down", "host <address> is down"),
            (
                "ONION_UNREACHABLE: the contact's onion service did not answer over Tor",
                "ONION_UNREACHABLE: the contact's onion service did not answer over Tor",
            ),
        ];
        for (raw, want) in cases {
            assert_eq!(without_addresses(raw), want, "{raw}");
        }
        // macOS refusing a local-network dial is still recognised.
        let refused = "lan connect: cannot connect to 192.168.0.25:17420 (192.168.0.25:17420: No \
                       route to host (os error 65))";
        assert!(crate::outbox::local_network_refused(refused));
        assert!(crate::outbox::local_network_refused(&without_addresses(
            refused
        )));
        assert!(!crate::outbox::local_network_refused(&without_addresses(
            "cannot connect to 203.0.113.9:7420 (No route to host (os error 65))"
        )));
    }

    #[test]
    fn contact_reach_answers_name_routes_by_index_only() {
        let answer = IpcResponse::ContactReach {
            v: IPC_VERSION,
            lan_seen_s: None,
            failed: vec![RouteFailure {
                carrier: "lan_dial".into(),
                route: 1,
                age_s: 3,
                error: without_addresses("dial 192.168.1.20:7420: connection refused"),
            }],
            tor_busy: false,
        };
        let text = serde_json::to_string(&answer).unwrap();
        assert!(!text.contains("192.168"), "{text}");
        assert!(!text.contains("\"dial\""), "{text}");
        assert!(text.contains("\"route\":1"), "{text}");
    }

    /// Auto-reach (owner rule 2026-10-28): the status names no address,
    /// only words and counts, so nothing a status or doctor prints (or a
    /// card built from it) can carry the public IP.
    #[test]
    fn auto_reach_status_has_no_address_field() {
        let full = AutoReachStatus {
            state: "on".into(),
            public: "found".into(),
            class: "stable_kept".into(),
            anchored: true,
            asked: 2,
            answered: 2,
            age_s: Some(5),
            reached: vec!["quic".into()],
            punch: Some(PunchStatus {
                targets: 1,
                ..PunchStatus::default()
            }),
        };
        let v = serde_json::to_value(&full).unwrap();
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "age_s", "anchored", "answered", "asked", "class", "public", "punch", "reached",
                "state"
            ]
        );
    }

    #[test]
    fn roundtrip_ping() {
        let req = IpcRequest::Ping { v: IPC_VERSION };
        let f = encode_request(&req).unwrap();
        assert_eq!(decode_request(&f).unwrap(), req);
        let resp = IpcResponse::Pong { v: IPC_VERSION };
        let rf = encode_response(&resp).unwrap();
        assert_eq!(decode_response(&rf).unwrap(), resp);
    }

    #[test]
    fn rejects_secret_token_in_json() {
        let body = br#"{"op":"ping","v":1,"seed":"nope"}"#;
        let mut frame = Vec::new();
        frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
        frame.extend_from_slice(body);
        assert!(decode_request(&frame).is_err());
    }

    #[test]
    fn rejects_oversized() {
        let huge = vec![b'a'; MAX_IPC_FRAME + 10];
        let mut frame = Vec::new();
        frame.extend_from_slice(&(huge.len() as u32).to_be_bytes());
        frame.extend_from_slice(&huge);
        assert!(decode_request(&frame).is_err());
    }

    #[test]
    fn roundtrip_internet_dial() {
        let req = IpcRequest::InternetDial {
            v: IPC_VERSION,
            internet_dial: "127.0.0.1:7421".into(),
            expected_pub_hex: "ab".repeat(32),
            frames_b64: vec!["QUJD".into()],
        };
        let f = encode_request(&req).unwrap();
        assert_eq!(decode_request(&f).unwrap(), req);
        let resp = IpcResponse::InternetDialResult {
            v: IPC_VERSION,
            frames_b64: vec!["ZGVm".into()],
        };
        let rf = encode_response(&resp).unwrap();
        assert_eq!(decode_response(&rf).unwrap(), resp);
        let raw = std::str::from_utf8(&f[4..]).unwrap().to_ascii_lowercase();
        for bad in ["seed", "private_key", "plaintext", "recovery"] {
            assert!(!raw.contains(bad), "{bad} leaked into InternetDial JSON");
        }
    }

    #[test]
    fn roundtrip_p2p_dial_and_status_have_no_secret_fields() {
        let req = IpcRequest::P2pDial {
            v: IPC_VERSION,
            multiaddr: "/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN".into(),
            expected_pub_hex: "ab".repeat(32),
            frames_b64: vec!["QUJD".into()],
        };
        let f = encode_request(&req).unwrap();
        assert_eq!(decode_request(&f).unwrap(), req);
        let raw = std::str::from_utf8(&f[4..]).unwrap();
        assert!(raw.contains("\"op\":\"p2p_dial\""), "{raw}");
        assert_json_has_no_secret_tokens(raw);
        let resp = IpcResponse::P2pDialResult {
            v: IPC_VERSION,
            frames_b64: vec!["ZGVm".into()],
            path: None,
        };
        assert_eq!(
            decode_response(&encode_response(&resp).unwrap()).unwrap(),
            resp
        );
        let status = IpcResponse::Status {
            v: IPC_VERSION,
            bridge: true,
            store: true,
            relay: false,
            forward_pending: 0,
            capabilities: vec!["ipc".into(), "p2p".into()],
            p2p: Some(Box::new(P2pStatusInfo {
                up: true,
                peer_id: "12D3KooW".into(),
                listen_addrs: vec!["/ip4/127.0.0.1/tcp/7423".into()],
                nat: "private".into(),
                reservations: vec!["/ip4/203.0.113.7/tcp/7423/p2p/x".into()],
                relays_configured: 1,
                upnp: "unset".into(),
                relay: Some(RelayCounts::default()),
                listen_setting: "7423".into(),
                source: "--p2p-listen".into(),
                relays: vec!["/ip4/203.0.113.7/tcp/7423/p2p/x".into()],
                relay_role: true,
                ..P2pStatusInfo::default()
            })),
            pid: Some(4242),
            lan_listen: Some("0.0.0.0:7424".into()),
            last_paths: vec![
                ContactPath {
                    peer_pub_hex: "ab".repeat(32),
                    carrier: "p2p_dial".into(),
                    path: "hole_punched".into(),
                    age_s: 3,
                },
                ContactPath {
                    peer_pub_hex: "cd".repeat(32),
                    carrier: "lan_dial".into(),
                    path: "direct".into(),
                    age_s: 70,
                },
            ],
            route_hints: None,
            unreachable: Vec::new(),
            egress: None,
            lan_listen_wanted: None,
            lan_bind_error: None,
            clock_skew: Vec::new(),
            unanswered: Vec::new(),
            at_rest: None,
            lan: None,
            security: None,
            nearby: None,
            tor: None,
            learning: None,
            locked: None,
            updates: None,
        };
        let f = encode_response(&status).unwrap();
        let json = std::str::from_utf8(&f[4..]).unwrap();
        assert_json_has_no_secret_tokens(json);
        assert!(
            json.contains(&format!(
                r#""last_paths":[{{"peer_pub_hex":"{}","carrier":"p2p_dial","path":"hole_punched","age_s":3}}"#,
                "ab".repeat(32)
            )),
            "{json}"
        );
        assert_eq!(decode_response(&f).unwrap(), status);
        // Nothing delivered yet: no field at all, and an unknown path is not
        // written either.
        let mut quiet = status.clone();
        if let IpcResponse::Status { last_paths, .. } = &mut quiet {
            last_paths.clear();
        }
        let quiet_json = String::from_utf8(encode_response(&quiet).unwrap()[4..].to_vec()).unwrap();
        assert!(!quiet_json.contains("last_paths"), "{quiet_json}");
        let unknown = serde_json::to_string(&ContactPath {
            carrier: "p2p_dial".into(),
            ..ContactPath::default()
        })
        .unwrap();
        assert!(!unknown.contains("\"path\""), "{unknown}");
        let raw = |json: &[u8]| {
            let mut frame = (json.len() as u32).to_be_bytes().to_vec();
            frame.extend_from_slice(json);
            decode_response(&frame).unwrap()
        };
        // An older daemon's Status (no p2p, pid, lan_listen or last_paths)
        // still decodes.
        match raw(br#"{"ok":"status","v":1,"bridge":true,"store":true,"relay":false,"forward_pending":0,"capabilities":["ipc"]}"#) {
            IpcResponse::Status {
                p2p,
                pid,
                lan_listen,
                last_paths,
                ..
            } => {
                assert_eq!((p2p, pid, lan_listen), (None, None, None));
                assert!(last_paths.is_empty());
            }
            other => panic!("{other:?}"),
        }
        // A newer daemon's extra fields, in Status and in each row, do not
        // break an older client.
        match raw(br#"{"ok":"status","v":1,"bridge":false,"store":false,"relay":false,"forward_pending":0,"capabilities":["ipc"],"pid":7,"lan_listen":"127.0.0.1:7420","last_paths":[{"peer_pub_hex":"ab","carrier":"lan_dial","future":2}],"future":1}"#) {
            IpcResponse::Status {
                pid, lan_listen, last_paths, ..
            } => {
                assert_eq!((pid, lan_listen.as_deref()), (Some(7), Some("127.0.0.1:7420")));
                assert_eq!(
                    last_paths,
                    vec![ContactPath {
                        peer_pub_hex: "ab".into(),
                        carrier: "lan_dial".into(),
                        path: String::new(),
                        age_s: 0,
                    }]
                );
            }
            other => panic!("{other:?}"),
        }
        assert!(FORBIDDEN_FIELD_TOKENS.iter().all(|bad| [
            "last_paths",
            "peer_pub_hex",
            "carrier",
            "path",
            "age_s"
        ]
        .iter()
        .all(|key| !key.contains(bad))));
    }

    /// Route hints in `Status`: counts and flags only, both ways through the
    /// codec, absent while off, and an older daemon's (or a newer one's
    /// extra fields) still decode.
    #[test]
    fn status_route_hints_are_optional_and_round_trip() {
        let hints = RouteHintsStatus {
            live: true,
            told: 3,
            learned: 2,
            ignored: 5,
            generation_age_s: 61,
            hide_ip: false,
            hidden_contacts: 1,
        };
        let status = IpcResponse::Status {
            v: IPC_VERSION,
            bridge: false,
            store: false,
            relay: false,
            forward_pending: 0,
            capabilities: vec!["ipc".into()],
            p2p: None,
            pid: Some(7),
            lan_listen: None,
            last_paths: Vec::new(),
            route_hints: Some(hints.clone()),
            unreachable: Vec::new(),
            egress: None,
            lan_listen_wanted: None,
            lan_bind_error: None,
            clock_skew: Vec::new(),
            unanswered: Vec::new(),
            at_rest: None,
            lan: None,
            security: None,
            nearby: None,
            tor: None,
            learning: None,
            locked: None,
            updates: None,
        };
        let f = encode_response(&status).unwrap();
        let json = std::str::from_utf8(&f[4..]).unwrap();
        assert_json_has_no_secret_tokens(json);
        assert!(
            json.contains(
                r#""route_hints":{"live":true,"told":3,"learned":2,"ignored":5,"generation_age_s":61,"hide_ip":false,"hidden_contacts":1}"#
            ),
            "{json}"
        );
        assert_eq!(decode_response(&f).unwrap(), status);
        // Off: no field at all.
        let mut off = status.clone();
        if let IpcResponse::Status { route_hints, .. } = &mut off {
            *route_hints = None;
        }
        let off_json = String::from_utf8(encode_response(&off).unwrap()[4..].to_vec()).unwrap();
        assert!(!off_json.contains("route_hints"), "{off_json}");
        assert_eq!(
            decode_response(&encode_response(&off).unwrap()).unwrap(),
            off
        );
        let raw = |json: &[u8]| {
            let mut frame = (json.len() as u32).to_be_bytes().to_vec();
            frame.extend_from_slice(json);
            decode_response(&frame).unwrap()
        };
        // An older daemon: no route hints.
        match raw(br#"{"ok":"status","v":1,"bridge":true,"store":true,"relay":false,"forward_pending":0,"capabilities":["ipc"]}"#) {
            IpcResponse::Status { route_hints, .. } => assert_eq!(route_hints, None),
            other => panic!("{other:?}"),
        }
        // A newer daemon's extra and missing fields.
        match raw(br#"{"ok":"status","v":1,"bridge":true,"store":true,"relay":false,"forward_pending":0,"capabilities":["ipc"],"route_hints":{"live":true,"told":4,"future":9}}"#) {
            IpcResponse::Status { route_hints, .. } => assert_eq!(
                route_hints,
                Some(RouteHintsStatus {
                    live: true,
                    told: 4,
                    ..RouteHintsStatus::default()
                })
            ),
            other => panic!("{other:?}"),
        }
        assert!(FORBIDDEN_FIELD_TOKENS.iter().all(|bad| [
            "route_hints",
            "live",
            "told",
            "learned",
            "ignored",
            "generation_age_s",
            "hide_ip",
            "hidden_contacts"
        ]
        .iter()
        .all(|key| !key.contains(bad))));
    }

    /// Privacy pack PP.4: `Status.at_rest` is fixed words and counts, both
    /// ways through the codec; absent from an older daemon (which is how
    /// ash tells one: [`crate::privacy::node_is_older`]); a newer one's
    /// extra fields are ignored; no field name holds a forbidden token.
    #[test]
    fn status_at_rest_is_optional_and_names_no_secret() {
        let at_rest = AtRestStatus {
            state: "sealed".into(),
            sealed_files: 1,
            plain_files: 0,
            notes: Vec::new(),
        };
        let status = IpcResponse::Status {
            v: IPC_VERSION,
            bridge: false,
            store: false,
            relay: false,
            forward_pending: 0,
            capabilities: vec!["ipc".into()],
            p2p: None,
            pid: Some(7),
            lan_listen: None,
            last_paths: Vec::new(),
            route_hints: None,
            unreachable: Vec::new(),
            egress: None,
            lan_listen_wanted: None,
            lan_bind_error: None,
            clock_skew: Vec::new(),
            unanswered: Vec::new(),
            at_rest: Some(at_rest.clone()),
            lan: None,
            security: None,
            nearby: None,
            tor: None,
            learning: None,
            locked: None,
            updates: None,
        };
        let f = encode_response(&status).unwrap();
        let json = std::str::from_utf8(&f[4..]).unwrap();
        assert_json_has_no_secret_tokens(json);
        assert!(
            json.ends_with(r#""at_rest":{"state":"sealed","sealed_files":1,"plain_files":0}}"#),
            "{json}"
        );
        assert_eq!(decode_response(&f).unwrap(), status);
        assert!(!crate::privacy::node_is_older(&status));
        let raw = |json: &[u8]| {
            let mut frame = (json.len() as u32).to_be_bytes().to_vec();
            frame.extend_from_slice(json);
            decode_response(&frame).unwrap()
        };
        let older = raw(br#"{"ok":"status","v":1,"bridge":true,"store":true,"relay":false,"forward_pending":0,"capabilities":["ipc"]}"#);
        match &older {
            IpcResponse::Status { at_rest, .. } => assert_eq!(*at_rest, None),
            other => panic!("{other:?}"),
        }
        assert!(crate::privacy::node_is_older(&older));
        match raw(br#"{"ok":"status","v":1,"bridge":true,"store":true,"relay":false,"forward_pending":0,"capabilities":["ipc"],"at_rest":{"state":"key_unavailable","notes":["scrub_pending"],"future":3}}"#) {
            IpcResponse::Status { at_rest, .. } => assert_eq!(
                at_rest,
                Some(AtRestStatus {
                    state: "key_unavailable".into(),
                    notes: vec!["scrub_pending".into()],
                    ..AtRestStatus::default()
                })
            ),
            other => panic!("{other:?}"),
        }
        assert!(FORBIDDEN_FIELD_TOKENS.iter().all(|bad| [
            "at_rest",
            "state",
            "sealed_files",
            "plain_files",
            "notes"
        ]
        .iter()
        .all(|key| !key.contains(bad))));
    }

    /// An older daemon's Status, and a newer one's with extra fields in it
    /// and in its rows.
    fn status_from(json: &[u8]) -> IpcResponse {
        let mut frame = (json.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(json);
        decode_response(&frame).unwrap()
    }

    /// The diagnosis in `Status` (`unreachable`, `egress`) and in an outbox
    /// item (`why`): both ways through the codec, absent while empty, keys
    /// and reasons only (no address, no secret field name).
    #[test]
    fn contact_why_and_outbox_why_round_trip() {
        let reason = "reach: why=both_nat me=unreachable src=card";
        let why = ContactWhy {
            peer_pub_hex: "ab".repeat(32),
            reason: reason.into(),
            age_s: 30,
        };
        let status = IpcResponse::Status {
            v: IPC_VERSION,
            bridge: false,
            store: false,
            relay: false,
            forward_pending: 0,
            capabilities: vec!["ipc".into(), "p2p".into()],
            p2p: None,
            pid: Some(7),
            lan_listen: None,
            last_paths: Vec::new(),
            route_hints: None,
            unreachable: vec![
                why.clone(),
                ContactWhy {
                    peer_pub_hex: "cd".repeat(32),
                    reason: "reach: why=no_route me=unknown".into(),
                    age_s: 5,
                },
            ],
            egress: Some(false),
            lan_listen_wanted: None,
            lan_bind_error: None,
            clock_skew: Vec::new(),
            unanswered: Vec::new(),
            at_rest: None,
            lan: None,
            security: None,
            nearby: None,
            tor: None,
            learning: None,
            locked: None,
            updates: None,
        };
        let f = encode_response(&status).unwrap();
        let json = std::str::from_utf8(&f[4..]).unwrap();
        assert_json_has_no_secret_tokens(json);
        assert!(
            json.contains(&format!(
                r#""unreachable":[{{"peer_pub_hex":"{}","reason":"{reason}","age_s":30}}"#,
                "ab".repeat(32)
            )) && json.contains(r#""egress":false"#),
            "{json}"
        );
        assert_eq!(decode_response(&f).unwrap(), status);
        // A route: `egress` true. Nothing unreachable and not read: no field.
        let mut quiet = status.clone();
        if let IpcResponse::Status {
            unreachable,
            egress,
            ..
        } = &mut quiet
        {
            unreachable.clear();
            *egress = Some(true);
        }
        let quiet_json = String::from_utf8(encode_response(&quiet).unwrap()[4..].to_vec()).unwrap();
        assert!(
            !quiet_json.contains("unreachable") && quiet_json.contains(r#""egress":true"#),
            "{quiet_json}"
        );
        assert_eq!(
            decode_response(&encode_response(&quiet).unwrap()).unwrap(),
            quiet
        );
        if let IpcResponse::Status { egress, .. } = &mut quiet {
            *egress = None;
        }
        let none_json = String::from_utf8(encode_response(&quiet).unwrap()[4..].to_vec()).unwrap();
        assert!(!none_json.contains("egress"), "{none_json}");

        // The outbox item's reason block.
        let item = OutboxItem {
            message_id_hex: "ef".repeat(16),
            peer_pub_hex: "ab".repeat(32),
            kind: "message".into(),
            state: "queued".into(),
            carrier: "p2p_dial".into(),
            attempts: 2,
            next_attempt_ms: 1_700_000_000_000,
            last_error_code: "NOT_REACHABLE".into(),
            expires_at_ms: 1_700_000_086_400,
            delivered_at_ms: 0,
            path: String::new(),
            why: reason.into(),
            never_sent: false,
            in_custody: 0,
            custody_forwarded: false,
            tried: Vec::new(),
            outcomes: Vec::new(),
        };
        let resp = IpcResponse::OutboxStatusResult {
            v: IPC_VERSION,
            item: item.clone(),
        };
        let f = encode_response(&resp).unwrap();
        let json = std::str::from_utf8(&f[4..]).unwrap();
        assert_json_has_no_secret_tokens(json);
        assert!(json.contains(&format!(r#""why":"{reason}""#)), "{json}");
        assert_eq!(decode_response(&f).unwrap(), resp);
        let plain = serde_json::to_string(&OutboxItem {
            why: String::new(),
            ..item
        })
        .unwrap();
        assert!(!plain.contains("\"why\""), "{plain}");
        // An older daemon's item (no why) decodes with an empty one.
        let old: OutboxItem = serde_json::from_str(
            r#"{"message_id_hex":"ab","peer_pub_hex":"cd","kind":"message","state":"queued","carrier":"","attempts":0,"next_attempt_ms":0,"last_error_code":"","expires_at_ms":0}"#,
        )
        .unwrap();
        assert_eq!(old.why, "");
        // When it was delivered (E1): only once it was, and an older
        // daemon's item reads 0.
        assert!(!plain.contains("delivered_at_ms"), "{plain}");
        assert_eq!(old.delivered_at_ms, 0);
        let delivered = OutboxItem {
            state: "delivered".into(),
            delivered_at_ms: 1_700_000_000_500,
            ..old.clone()
        };
        let json = serde_json::to_string(&delivered).unwrap();
        assert!(
            json.contains(r#""delivered_at_ms":1700000000500"#),
            "{json}"
        );
        assert_eq!(
            serde_json::from_str::<OutboxItem>(&json).unwrap(),
            delivered
        );
        assert!(FORBIDDEN_FIELD_TOKENS.iter().all(|bad| [
            "unreachable",
            "peer_pub_hex",
            "reason",
            "age_s",
            "egress",
            "why"
        ]
        .iter()
        .all(|key| !key.contains(bad))));
    }

    #[test]
    fn old_status_json_decodes_with_empty_unreachable() {
        match status_from(br#"{"ok":"status","v":1,"bridge":true,"store":true,"relay":false,"forward_pending":0,"capabilities":["ipc"],"last_paths":[]}"#) {
            IpcResponse::Status { unreachable, .. } => assert!(unreachable.is_empty()),
            other => panic!("{other:?}"),
        }
        // A newer daemon's extra fields, in Status and in each row, and a
        // row missing some, still decode.
        match status_from(br#"{"ok":"status","v":1,"bridge":true,"store":true,"relay":false,"forward_pending":0,"capabilities":["ipc"],"unreachable":[{"peer_pub_hex":"ab","reason":"reach: why=relay_busy","age_s":4,"future":1},{"peer_pub_hex":"cd"}],"future":2}"#) {
            IpcResponse::Status { unreachable, .. } => assert_eq!(
                unreachable,
                vec![
                    ContactWhy {
                        peer_pub_hex: "ab".into(),
                        reason: "reach: why=relay_busy".into(),
                        age_s: 4,
                    },
                    ContactWhy {
                        peer_pub_hex: "cd".into(),
                        ..ContactWhy::default()
                    },
                ]
            ),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn old_status_json_decodes_with_egress_none() {
        match status_from(br#"{"ok":"status","v":1,"bridge":true,"store":true,"relay":false,"forward_pending":0,"capabilities":["ipc"]}"#) {
            IpcResponse::Status { egress, .. } => assert_eq!(egress, None),
            other => panic!("{other:?}"),
        }
        for (raw, want) in [
            (&br#"{"ok":"status","v":1,"bridge":true,"store":true,"relay":false,"forward_pending":0,"capabilities":["ipc"],"egress":false}"#[..], Some(false)),
            (br#"{"ok":"status","v":1,"bridge":true,"store":true,"relay":false,"forward_pending":0,"capabilities":["ipc"],"egress":true}"#, Some(true)),
            (br#"{"ok":"status","v":1,"bridge":true,"store":true,"relay":false,"forward_pending":0,"capabilities":["ipc"],"egress":null}"#, None),
        ] {
            match status_from(raw) {
                IpcResponse::Status { egress, .. } => assert_eq!(egress, want),
                other => panic!("{other:?}"),
            }
        }
    }

    /// Why the LAN listener could not bind (CP.5): absent from an older
    /// daemon's Status, and not written while there is nothing to say, so
    /// an older client reads a newer daemon's Status as before.
    #[test]
    fn old_status_json_decodes_without_bind_fields() {
        match status_from(br#"{"ok":"status","v":1,"bridge":true,"store":true,"relay":false,"forward_pending":0,"capabilities":["ipc"],"lan_listen":"127.0.0.1:7420"}"#) {
            IpcResponse::Status {
                lan_listen_wanted,
                lan_bind_error,
                ..
            } => assert_eq!((lan_listen_wanted, lan_bind_error), (None, None)),
            other => panic!("{other:?}"),
        }
        let told = br#"{"ok":"status","v":1,"bridge":true,"store":true,"relay":false,"forward_pending":0,"capabilities":["ipc"],"lan_listen_wanted":"192.0.2.10:7499","lan_bind_error":"addr_not_here"}"#;
        let status = status_from(told);
        match &status {
            IpcResponse::Status {
                lan_listen,
                lan_listen_wanted,
                lan_bind_error,
                ..
            } => {
                assert_eq!(lan_listen, &None);
                assert_eq!(lan_listen_wanted.as_deref(), Some("192.0.2.10:7499"));
                assert_eq!(lan_bind_error.as_deref(), Some(LAN_BIND_ADDR_NOT_HERE));
            }
            other => panic!("{other:?}"),
        }
        let f = encode_response(&status).unwrap();
        let json = std::str::from_utf8(&f[4..]).unwrap();
        assert!(
            json.contains(
                r#""lan_listen_wanted":"192.0.2.10:7499","lan_bind_error":"addr_not_here""#
            ),
            "{json}"
        );
        assert_eq!(decode_response(&f).unwrap(), status);
        // Nothing to say: neither field is written.
        let mut bound = status;
        if let IpcResponse::Status {
            lan_listen,
            lan_listen_wanted,
            lan_bind_error,
            ..
        } = &mut bound
        {
            *lan_listen = Some("0.0.0.0:7420".into());
            *lan_listen_wanted = None;
            *lan_bind_error = None;
        }
        let quiet = String::from_utf8(encode_response(&bound).unwrap()[4..].to_vec()).unwrap();
        assert!(
            !quiet.contains("lan_listen_wanted") && !quiet.contains("lan_bind_error"),
            "{quiet}"
        );
        // The tokens are plain words, distinct, and no field name holds a
        // forbidden token.
        let tokens = [
            LAN_BIND_ADDR_NOT_HERE,
            LAN_BIND_IN_USE,
            LAN_BIND_DENIED,
            LAN_BIND_OTHER,
        ];
        let distinct: std::collections::BTreeSet<&str> = tokens.into_iter().collect();
        assert_eq!(distinct.len(), tokens.len());
        assert!(tokens
            .iter()
            .all(|t| t.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')));
        assert!(FORBIDDEN_FIELD_TOKENS
            .iter()
            .all(|bad| ["lan_listen_wanted", "lan_bind_error"]
                .iter()
                .all(|key| !key.contains(bad))));
    }

    /// Phase 6b (P6.24): `Status.security` is optional both ways (absent
    /// from an older daemon, not written while there is none), holds counts
    /// and a flag only, and a newer daemon's extra fields in it are ignored.
    /// An older ash, whose decoder does not know the field, reads a Status
    /// that carries it as before.
    #[test]
    fn status_security_is_optional_and_an_older_ash_ignores_it() {
        match status_from(br#"{"ok":"status","v":1,"bridge":true,"store":true,"relay":false,"forward_pending":0,"capabilities":["ipc"]}"#) {
            IpcResponse::Status { security, .. } => assert_eq!(security, None),
            other => panic!("{other:?}"),
        }
        let newer = br#"{"ok":"status","v":1,"bridge":true,"store":true,"relay":false,"forward_pending":0,"capabilities":["ipc"],"security":{"strangers_refused_1h":37,"bans_active":2,"link_tag_failures_24h":1,"alerts_open":1,"responses_live":false,"dropped":3,"future":9}}"#;
        let status = status_from(newer);
        match &status {
            IpcResponse::Status {
                security: Some(security),
                ..
            } => assert_eq!(
                **security,
                SecurityStatus {
                    strangers_refused_1h: 37,
                    preauth_failures_1h: 0,
                    bans_active: 2,
                    link_tag_failures_24h: 1,
                    alerts_open: 1,
                    responses_live: false,
                    dropped: 3,
                }
            ),
            other => panic!("{other:?}"),
        }
        let frame = encode_response(&status).unwrap();
        assert_eq!(decode_response(&frame).unwrap(), status);
        let json = std::str::from_utf8(&frame[4..]).unwrap();
        assert!(
            json.contains(r#""security":{"strangers_refused_1h":37,"#),
            "{json}"
        );

        // An older ash: a Status decoder with no `security` field.
        #[derive(Deserialize, Debug)]
        #[serde(tag = "ok", rename_all = "snake_case")]
        enum OlderAsh {
            Status {
                v: u16,
                bridge: bool,
                forward_pending: u64,
                capabilities: Vec<String>,
            },
        }
        let OlderAsh::Status {
            v,
            bridge,
            forward_pending,
            capabilities,
        } = serde_json::from_str(json).unwrap();
        assert_eq!(
            (v, bridge, forward_pending, capabilities),
            (IPC_VERSION, true, 0, vec!["ipc".to_string()])
        );

        // Nothing to say (the gate shut): not written.
        let mut quiet = status;
        if let IpcResponse::Status { security, .. } = &mut quiet {
            *security = None;
        }
        let quiet = String::from_utf8(encode_response(&quiet).unwrap()[4..].to_vec()).unwrap();
        assert!(!quiet.contains("security"), "{quiet}");
        let keys = [
            "security",
            "strangers_refused_1h",
            "preauth_failures_1h",
            "bans_active",
            "link_tag_failures_24h",
            "alerts_open",
            "responses_live",
            "dropped",
        ];
        assert!(FORBIDDEN_FIELD_TOKENS
            .iter()
            .all(|bad| keys.iter().all(|key| !key.contains(bad))));
    }

    /// Phase 3 (P3.5): `SetLan` and `LanSet` round-trip and name nothing
    /// secret, and a wrong version is refused like every other op.
    /// `Status.lan` is optional both ways (absent from an older daemon, not
    /// written while there is none), holds fixed words, listen addresses
    /// and counts, and a newer daemon's extra fields are ignored.
    #[test]
    fn set_lan_and_status_lan_round_trip() {
        for on in [false, true] {
            let req = IpcRequest::SetLan {
                v: IPC_VERSION,
                on,
                until_ms: None,
            };
            let f = encode_request(&req).unwrap();
            assert_eq!(decode_request(&f).unwrap(), req);
            let raw = std::str::from_utf8(&f[4..]).unwrap();
            assert_eq!(raw, format!(r#"{{"op":"set_lan","v":1,"on":{on}}}"#));
            assert_json_has_no_secret_tokens(raw);
            let resp = IpcResponse::LanSet {
                v: IPC_VERSION,
                on,
                applied: true,
                until_ms: None,
            };
            let rf = encode_response(&resp).unwrap();
            assert_eq!(decode_response(&rf).unwrap(), resp);
            let raw = std::str::from_utf8(&rf[4..]).unwrap();
            assert_eq!(
                raw,
                format!(r#"{{"ok":"lan_set","v":1,"on":{on},"applied":true}}"#)
            );
            assert_json_has_no_secret_tokens(raw);
        }
        let err =
            decode_request_checked(&frame_of(br#"{"op":"set_lan","v":2,"on":false}"#)).unwrap_err();
        assert_eq!(err.code, "IPC_VERSION");
        // A SetLan that does not say which is no request.
        let err = decode_request_checked(&frame_of(br#"{"op":"set_lan","v":1}"#)).unwrap_err();
        assert_eq!(err.code, "IPC_FRAME");

        // An older daemon: no LAN row.
        let old = br#"{"ok":"status","v":1,"bridge":true,"store":true,"relay":false,"forward_pending":0,"capabilities":["ipc"],"lan_listen":"0.0.0.0:7420"}"#;
        match status_from(old) {
            IpcResponse::Status { lan, .. } => assert_eq!(lan, None),
            other => panic!("{other:?}"),
        }
        // A newer daemon's row, with fields this build does not know.
        let told = br#"{"ok":"status","v":1,"bridge":true,"store":true,"relay":false,"forward_pending":0,"capabilities":["ipc"],"lan":{"mode":"on","listen":["0.0.0.0:7420","[::]:7420"],"local_only":true,"beacon":{"state":"held","interfaces":2,"future":1},"future":2}}"#;
        let status = status_from(told);
        let want = LanStatus {
            mode: LAN_MODE_ON.into(),
            listen: vec!["0.0.0.0:7420".into(), "[::]:7420".into()],
            local_only: true,
            beacon: Some(Box::new(BeaconCounts {
                state: "held".into(),
                interfaces: 2,
                ..BeaconCounts::default()
            })),
            ..LanStatus::default()
        };
        match &status {
            IpcResponse::Status { lan, .. } => assert_eq!(lan.as_ref(), Some(&want)),
            other => panic!("{other:?}"),
        }
        let f = encode_response(&status).unwrap();
        let json = std::str::from_utf8(&f[4..]).unwrap();
        assert_json_has_no_secret_tokens(json);
        assert!(
            json.contains(
                r#""lan":{"mode":"on","listen":["0.0.0.0:7420","[::]:7420"],"local_only":true,"beacon":{"state":"held","interfaces":2,"echo_ok":false,"queries_10m":0,"answered_10m":0,"answers_sent_10m":0,"dropped_10m":0}}"#
            ),
            "{json}"
        );
        assert_eq!(decode_response(&f).unwrap(), status);
        // No beacon yet: no beacon field. No LAN listener: no LAN row.
        let mut quiet = status;
        if let IpcResponse::Status { lan, .. } = &mut quiet {
            lan.as_mut().unwrap().beacon = None;
        }
        let json = String::from_utf8(encode_response(&quiet).unwrap()[4..].to_vec()).unwrap();
        assert!(
            json.contains(
                r#""lan":{"mode":"on","listen":["0.0.0.0:7420","[::]:7420"],"local_only":true}"#
            ),
            "{json}"
        );
        assert_eq!(
            decode_response(&encode_response(&quiet).unwrap()).unwrap(),
            quiet
        );
        // P3.C6: the friends seen here and the pin blocks, after the
        // beacon; absent above (an older raven-node's row reads the same).
        if let IpcResponse::Status { lan, .. } = &mut quiet {
            let lan = lan.as_mut().unwrap();
            lan.friends_here_10m = Some(2);
            lan.pin_blocked = vec!["ab".repeat(32)];
        }
        let json = String::from_utf8(encode_response(&quiet).unwrap()[4..].to_vec()).unwrap();
        assert!(
            json.contains(&format!(
                r#""local_only":true,"friends_here_10m":2,"pin_blocked":["{}"]}}"#,
                "ab".repeat(32)
            )),
            "{json}"
        );
        assert_eq!(
            decode_response(&encode_response(&quiet).unwrap()).unwrap(),
            quiet
        );
        if let IpcResponse::Status { lan, .. } = &mut quiet {
            *lan = None;
        }
        let json = String::from_utf8(encode_response(&quiet).unwrap()[4..].to_vec()).unwrap();
        assert!(!json.contains(r#""lan":"#), "{json}");
        // The mode words are distinct, and no field name holds a forbidden
        // token.
        let modes = [
            LAN_MODE_ON,
            LAN_MODE_OFF,
            LAN_MODE_THIS_COMPUTER,
            LAN_MODE_FIXED,
        ];
        let distinct: std::collections::BTreeSet<&str> = modes.into_iter().collect();
        assert_eq!(distinct.len(), modes.len());
        assert!(FORBIDDEN_FIELD_TOKENS.iter().all(|bad| [
            "set_lan",
            "lan_set",
            "on",
            "applied",
            "lan",
            "mode",
            "listen",
            "local_only",
            "beacon",
            "state",
            "interfaces",
            "echo_ok",
            "queries_10m",
            "answered_10m",
            "answers_sent_10m",
            "dropped_10m",
            "friends_here_10m",
            "pin_blocked"
        ]
        .iter()
        .all(|key| !key.contains(bad))));
    }

    /// Phase 3 P3.C2: `SetLan` with a meeting time (`raven lan on --for`)
    /// and without one (exactly P3.5's bytes, which an older node reads);
    /// an older ash's `SetLan` reads as one without; `LanSet` echoes the time
    /// it holds, and an older node's `LanSet` (no time) still decodes.
    #[test]
    fn set_lan_with_and_without_until_ms() {
        let until = 1_800_000_000_000u64;
        let req = IpcRequest::SetLan {
            v: IPC_VERSION,
            on: true,
            until_ms: Some(until),
        };
        let f = encode_request(&req).unwrap();
        let raw = std::str::from_utf8(&f[4..]).unwrap();
        assert_eq!(
            raw,
            format!(r#"{{"op":"set_lan","v":1,"on":true,"until_ms":{until}}}"#)
        );
        assert_json_has_no_secret_tokens(raw);
        assert_eq!(decode_request(&f).unwrap(), req);
        let older = decode_request(&frame_of(br#"{"op":"set_lan","v":1,"on":true}"#)).unwrap();
        assert_eq!(
            older,
            IpcRequest::SetLan {
                v: IPC_VERSION,
                on: true,
                until_ms: None
            }
        );
        // A meeting time is a number of ms; anything else is no request.
        let err = decode_request_checked(&frame_of(
            br#"{"op":"set_lan","v":1,"on":true,"until_ms":"soon"}"#,
        ))
        .unwrap_err();
        assert_eq!(err.code, "IPC_FRAME");
        let resp = IpcResponse::LanSet {
            v: IPC_VERSION,
            on: true,
            applied: true,
            until_ms: Some(until),
        };
        let rf = encode_response(&resp).unwrap();
        let raw = std::str::from_utf8(&rf[4..]).unwrap();
        assert_eq!(
            raw,
            format!(r#"{{"ok":"lan_set","v":1,"on":true,"applied":true,"until_ms":{until}}}"#)
        );
        assert_eq!(decode_response(&rf).unwrap(), resp);
        let older = br#"{"ok":"lan_set","v":1,"on":true,"applied":true}"#;
        assert_eq!(
            decode_response(&frame_of(older)).unwrap(),
            IpcResponse::LanSet {
                v: IPC_VERSION,
                on: true,
                applied: true,
                until_ms: None
            }
        );
        assert!(!FORBIDDEN_FIELD_TOKENS
            .iter()
            .any(|bad| "until_ms".contains(bad)));
    }

    /// Phase 3 P3.11: `LanLocate` and `LanLocated` round-trip and name
    /// nothing secret, a wrong version is refused like every other op, and
    /// a request without a key or a wait is no request. The answer holds
    /// dial strings only, a zoned one as it is written.
    #[test]
    fn lan_locate_and_lan_located_round_trip() {
        let key = "ab".repeat(32);
        let req = IpcRequest::LanLocate {
            v: IPC_VERSION,
            peer_pub_hex: key.clone(),
            wait_ms: 1_000,
        };
        let f = encode_request(&req).unwrap();
        assert_eq!(decode_request(&f).unwrap(), req);
        let raw = std::str::from_utf8(&f[4..]).unwrap();
        assert_eq!(
            raw,
            format!(r#"{{"op":"lan_locate","v":1,"peer_pub_hex":"{key}","wait_ms":1000}}"#)
        );
        assert_json_has_no_secret_tokens(raw);
        let err = decode_request_checked(&frame_of(
            format!(r#"{{"op":"lan_locate","v":2,"peer_pub_hex":"{key}","wait_ms":0}}"#).as_bytes(),
        ))
        .unwrap_err();
        assert_eq!(err.code, "IPC_VERSION");
        for partial in [
            r#"{"op":"lan_locate","v":1,"wait_ms":0}"#.to_string(),
            format!(r#"{{"op":"lan_locate","v":1,"peer_pub_hex":"{key}"}}"#),
            format!(r#"{{"op":"lan_locate","v":1,"peer_pub_hex":"{key}","wait_ms":-1}}"#),
        ] {
            let err = decode_request_checked(&frame_of(partial.as_bytes())).unwrap_err();
            assert_eq!(err.code, "IPC_FRAME", "{partial}");
        }
        for dials in [
            Vec::new(),
            vec![
                "192.168.1.30:47532".to_string(),
                "[fe80::1%en0]:47532".to_string(),
            ],
        ] {
            let resp = IpcResponse::LanLocated {
                v: IPC_VERSION,
                dials: dials.clone(),
            };
            let rf = encode_response(&resp).unwrap();
            assert_eq!(decode_response(&rf).unwrap(), resp);
            let raw = std::str::from_utf8(&rf[4..]).unwrap();
            assert_eq!(
                raw,
                format!(
                    r#"{{"ok":"lan_located","v":1,"dials":{}}}"#,
                    serde_json::to_string(&dials).unwrap()
                )
            );
            assert_json_has_no_secret_tokens(raw);
        }
        assert!(FORBIDDEN_FIELD_TOKENS.iter().all(|bad| [
            "lan_locate",
            "lan_located",
            "peer_pub_hex",
            "wait_ms",
            "dials"
        ]
        .iter()
        .all(|key| !key.contains(bad))));
    }

    /// Phase 5 (P5.25): the nearby ops and the Status field round-trip,
    /// an older daemon's Status (no `nearby`) decodes as before and a Status
    /// without it is written as before, and nothing in them names a secret,
    /// a contact key beyond the dial's own, a token or a Bluetooth address.
    #[test]
    fn nearby_ops_and_status_round_trip_without_secrets() {
        let key = "ab".repeat(32);
        let dial = crate::outbox::nearby_dial_for(&[0xab; 32]);
        let req = IpcRequest::NearbyDial {
            v: IPC_VERSION,
            nearby_dial: dial.clone(),
            expected_pub_hex: key.clone(),
            frames_b64: vec!["QUJD".into()],
        };
        let f = encode_request(&req).unwrap();
        assert_eq!(decode_request(&f).unwrap(), req);
        let raw = std::str::from_utf8(&f[4..]).unwrap();
        assert_eq!(
            raw,
            format!(
                r#"{{"op":"nearby_dial","v":1,"nearby_dial":"{dial}","expected_pub_hex":"{key}","frames_b64":["QUJD"]}}"#
            )
        );
        assert_json_has_no_secret_tokens(raw);
        for action in NEARBY_CONTROL_ACTIONS {
            for (peer, ttl) in [(None, None), (Some(key.clone()), Some(900))] {
                let req = IpcRequest::NearbyControl {
                    v: IPC_VERSION,
                    action: action.into(),
                    peer_pub_hex: peer.clone(),
                    ttl_secs: ttl,
                };
                let f = encode_request(&req).unwrap();
                assert_eq!(decode_request(&f).unwrap(), req);
                let raw = std::str::from_utf8(&f[4..]).unwrap();
                assert_json_has_no_secret_tokens(raw);
                assert_eq!(raw.contains("peer_pub_hex"), peer.is_some(), "{raw}");
                assert_eq!(raw.contains("ttl_secs"), ttl.is_some(), "{raw}");
            }
        }
        assert_eq!(
            serde_json::to_string(&IpcRequest::NearbyControl {
                v: IPC_VERSION,
                action: "status".into(),
                peer_pub_hex: None,
                ttl_secs: None,
            })
            .unwrap(),
            r#"{"op":"nearby_control","v":1,"action":"status"}"#
        );
        // Another IPC version is refused, as for every op.
        for body in [
            format!(
                r#"{{"op":"nearby_dial","v":2,"nearby_dial":"{dial}","expected_pub_hex":"{key}","frames_b64":[]}}"#
            ),
            r#"{"op":"nearby_control","v":2,"action":"status"}"#.to_string(),
        ] {
            let err = decode_request_checked(&frame_of(body.as_bytes())).unwrap_err();
            assert_eq!(err.code, "IPC_VERSION", "{body}");
        }
        let status = NearbyStatusInfo {
            enabled: true,
            gate_live: true,
            radio: "powered_on".into(),
            roles: vec!["central".into(), "peripheral".into()],
            address_privacy: "random".into(),
            advertising: 1,
            rotating: 2,
            in_range: 3,
            pipes: 1,
            frames_tx: 10,
            frames_rx: 11,
            bytes_tx: 1_000,
            bytes_rx: 1_100,
            knock_silenced: 4,
            background_mail: true,
        };
        assert!(NEARBY_RADIO_STATES.contains(&status.radio.as_str()));
        for resp in [
            IpcResponse::NearbyDialResult {
                v: IPC_VERSION,
                frames_b64: vec!["QUJD".into()],
            },
            IpcResponse::NearbyControlResult {
                v: IPC_VERSION,
                status: Box::new(status.clone()),
            },
            IpcResponse::NearbyControlResult {
                v: IPC_VERSION,
                status: Box::default(),
            },
        ] {
            let rf = encode_response(&resp).unwrap();
            assert_eq!(decode_response(&rf).unwrap(), resp);
            let raw = std::str::from_utf8(&rf[4..]).unwrap();
            assert_json_has_no_secret_tokens(raw);
            assert!(!raw.contains(&key), "{raw}");
        }
        // A field an older raven-node lacks reads as its default.
        let partial: NearbyStatusInfo =
            serde_json::from_str(r#"{"enabled":true,"radio":"off"}"#).unwrap();
        assert_eq!(
            partial,
            NearbyStatusInfo {
                enabled: true,
                radio: "off".into(),
                ..NearbyStatusInfo::default()
            }
        );
        // Status: absent while None (an older client reads it as before),
        // and round-trips when set.
        let quiet = status_from(br#"{"ok":"status","v":1,"bridge":true,"store":true,"relay":false,"forward_pending":0,"capabilities":[]}"#);
        let IpcResponse::Status { nearby, .. } = &quiet else {
            panic!("not a Status: {quiet:?}");
        };
        assert!(nearby.is_none());
        let rf = encode_response(&quiet).unwrap();
        assert!(!std::str::from_utf8(&rf[4..]).unwrap().contains("nearby"));
        let mut loud = quiet.clone();
        if let IpcResponse::Status { nearby, .. } = &mut loud {
            *nearby = Some(Box::new(status));
        }
        let rf = encode_response(&loud).unwrap();
        assert_eq!(decode_response(&rf).unwrap(), loud);
        let raw = std::str::from_utf8(&rf[4..]).unwrap();
        assert!(raw.contains(r#""nearby":{"enabled":true"#), "{raw}");
        assert_json_has_no_secret_tokens(raw);
        assert!(FORBIDDEN_FIELD_TOKENS.iter().all(|bad| [
            "nearby_dial",
            "nearby_control",
            "nearby_dial_result",
            "nearby_control_result",
            "action",
            "ttl_secs",
            "gate_live",
            "address_privacy",
            "knock_silenced",
        ]
        .iter()
        .all(|key| !key.contains(bad))));
    }

    /// Contacts whose clock runs ahead and contacts that gave no answer
    /// (CP.7): absent from an older daemon's Status, not written while
    /// empty (an older client reads a newer daemon's Status as before), keys
    /// and counts only both ways through the codec.
    #[test]
    fn status_clock_rows_are_optional_both_ways() {
        let old = br#"{"ok":"status","v":1,"bridge":true,"store":true,"relay":false,"forward_pending":0,"capabilities":["ipc"]}"#;
        match status_from(old) {
            IpcResponse::Status {
                clock_skew,
                unanswered,
                ..
            } => assert!(clock_skew.is_empty() && unanswered.is_empty()),
            other => panic!("{other:?}"),
        }
        let key = "ab".repeat(32);
        let told = format!(
            r#"{{"ok":"status","v":1,"bridge":true,"store":true,"relay":false,"forward_pending":0,"capabilities":["ipc"],"clock_skew":[{{"peer_pub_hex":"{key}","minutes":10}}],"unanswered":[{{"peer_pub_hex":"{key}","times":2}}],"from_a_newer_daemon":1}}"#
        );
        let status = status_from(told.as_bytes());
        match &status {
            IpcResponse::Status {
                clock_skew,
                unanswered,
                ..
            } => {
                assert_eq!(
                    clock_skew,
                    &vec![ContactSkew {
                        peer_pub_hex: key.clone(),
                        minutes: 10,
                        at_least: false,
                    }]
                );
                assert_eq!(
                    unanswered,
                    &vec![ContactUnanswered {
                        peer_pub_hex: key.clone(),
                        times: 2,
                    }]
                );
            }
            other => panic!("{other:?}"),
        }
        let f = encode_response(&status).unwrap();
        let json = std::str::from_utf8(&f[4..]).unwrap();
        assert_json_has_no_secret_tokens(json);
        assert!(
            json.contains(&format!(
                r#""clock_skew":[{{"peer_pub_hex":"{key}","minutes":10}}],"unanswered":[{{"peer_pub_hex":"{key}","times":2}}]"#
            )),
            "{json}"
        );
        assert_eq!(decode_response(&f).unwrap(), status);
        let mut quiet = status;
        if let IpcResponse::Status {
            clock_skew,
            unanswered,
            ..
        } = &mut quiet
        {
            clock_skew.clear();
            unanswered.clear();
        }
        let json = String::from_utf8(encode_response(&quiet).unwrap()[4..].to_vec()).unwrap();
        assert!(
            !json.contains("clock_skew") && !json.contains("unanswered"),
            "{json}"
        );
        assert!(FORBIDDEN_FIELD_TOKENS.iter().all(|bad| {
            ["clock_skew", "unanswered", "minutes", "times"]
                .iter()
                .all(|k| !k.contains(bad))
        }));
    }

    /// Phase 3 P3.C3 (F11b): the LAN beacon's clock estimate (`at_least`,
    /// behind as negative minutes) and the contacts it asked for in vain
    /// (`no_answer`) go both ways through the codec, are absent from an
    /// older daemon's Status and are not written while unset, so an older
    /// client reads the rest as before.
    #[test]
    fn status_beacon_clock_rows_and_no_answer_are_optional_both_ways() {
        let key = "cd".repeat(32);
        let told = format!(
            r#"{{"ok":"status","v":1,"bridge":true,"store":true,"relay":false,"forward_pending":0,"capabilities":["ipc"],"clock_skew":[{{"peer_pub_hex":"{key}","minutes":-10,"at_least":true}}],"lan":{{"mode":"on","listen":[],"local_only":true,"beacon":{{"state":"on","no_answer":["{key}"]}}}}}}"#
        );
        let status = status_from(told.as_bytes());
        match &status {
            IpcResponse::Status {
                clock_skew, lan, ..
            } => {
                assert_eq!(
                    clock_skew,
                    &vec![ContactSkew {
                        peer_pub_hex: key.clone(),
                        minutes: -10,
                        at_least: true,
                    }]
                );
                let beacon = lan.as_ref().and_then(|l| l.beacon.as_ref()).unwrap();
                assert_eq!(beacon.no_answer, vec![key.clone()]);
            }
            other => panic!("{other:?}"),
        }
        let f = encode_response(&status).unwrap();
        let json = std::str::from_utf8(&f[4..]).unwrap();
        assert_json_has_no_secret_tokens(json);
        assert!(
            json.contains(&format!(
                r#""clock_skew":[{{"peer_pub_hex":"{key}","minutes":-10,"at_least":true}}]"#
            )),
            "{json}"
        );
        assert!(
            json.contains(&format!(r#""dropped_10m":0,"no_answer":["{key}"]}}"#)),
            "{json}"
        );
        assert_eq!(decode_response(&f).unwrap(), status);
        // An older daemon's rows: measured, and nobody unanswered.
        let old = format!(
            r#"{{"ok":"status","v":1,"bridge":true,"store":true,"relay":false,"forward_pending":0,"capabilities":["ipc"],"clock_skew":[{{"peer_pub_hex":"{key}","minutes":7}}],"lan":{{"mode":"on","listen":[],"local_only":true,"beacon":{{"state":"on"}}}}}}"#
        );
        match status_from(old.as_bytes()) {
            IpcResponse::Status {
                clock_skew, lan, ..
            } => {
                assert!(!clock_skew[0].at_least);
                assert!(lan.unwrap().beacon.unwrap().no_answer.is_empty());
            }
            other => panic!("{other:?}"),
        }
        assert!(FORBIDDEN_FIELD_TOKENS
            .iter()
            .all(|bad| ["at_least", "no_answer"].iter().all(|k| !k.contains(bad))));
    }

    /// The peer gate's row and the relay's refused connections: counts
    /// only, both ways through the codec, and absent from an older daemon.
    #[test]
    fn p2p_gate_status_and_refused_connections_round_trip() {
        let info = P2pStatusInfo {
            up: true,
            peer_id: "12D3KooW".into(),
            relay: Some(RelayCounts {
                allowed_peers: 3,
                connections_refused: 7,
                ..RelayCounts::default()
            }),
            gate: Some(Box::new(P2pGateStatus {
                contacts: 2,
                relays: 1,
                unreadable: false,
                refused: 5,
                refused_hole_punch: 1,
            })),
            ..P2pStatusInfo::default()
        };
        let status = IpcResponse::Status {
            v: IPC_VERSION,
            bridge: false,
            store: false,
            relay: true,
            forward_pending: 0,
            capabilities: vec!["ipc".into(), "p2p".into()],
            p2p: Some(Box::new(info.clone())),
            pid: None,
            lan_listen: None,
            last_paths: Vec::new(),
            route_hints: None,
            unreachable: Vec::new(),
            egress: None,
            lan_listen_wanted: None,
            lan_bind_error: None,
            clock_skew: Vec::new(),
            unanswered: Vec::new(),
            at_rest: None,
            lan: None,
            security: None,
            nearby: None,
            tor: None,
            learning: None,
            locked: None,
            updates: None,
        };
        let f = encode_response(&status).unwrap();
        let json = std::str::from_utf8(&f[4..]).unwrap();
        assert_json_has_no_secret_tokens(json);
        assert!(
            json.contains(r#""gate":{"contacts":2,"relays":1,"unreadable":false,"refused":5,"refused_hole_punch":1}"#)
                && json.contains(r#""connections_refused":7"#),
            "{json}"
        );
        assert_eq!(decode_response(&f).unwrap(), status);
        // No host: no gate field at all.
        let none = serde_json::to_string(&P2pStatusInfo::default()).unwrap();
        assert!(!none.contains("\"gate\""), "{none}");
        // An older daemon's p2p status and relay counts still decode.
        let old: P2pStatusInfo = serde_json::from_str(
            r#"{"up":true,"peer_id":"12D3KooW","listen_addrs":[],"nat":"unknown","reservations":[],"relays_configured":1,"upnp":"unset","relay":{"open":false,"allowed_peers":2,"reservations":1,"circuits":0,"reservations_refused":0,"circuits_refused":0}}"#,
        )
        .unwrap();
        assert_eq!(old.gate, None);
        assert_eq!(old.relay.unwrap().connections_refused, 0);
        // A gate status without the optional counts.
        let gate: P2pGateStatus =
            serde_json::from_str(r#"{"contacts":0,"relays":2,"refused":0}"#).unwrap();
        assert!(!gate.unreadable && gate.refused_hole_punch == 0);
    }

    /// The retired `relay` listen setting: said only when it applies, and
    /// absent from (and harmless to) an older daemon or client.
    #[test]
    fn p2p_status_says_a_retired_listen_setting() {
        let info = P2pStatusInfo {
            up: true,
            listen_setting: "7423".into(),
            retired_listen: "relay".into(),
            ..P2pStatusInfo::default()
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains(r#""retired_listen":"relay""#), "{json}");
        assert_eq!(serde_json::from_str::<P2pStatusInfo>(&json).unwrap(), info);
        let plain = serde_json::to_string(&P2pStatusInfo::default()).unwrap();
        assert!(!plain.contains("retired_listen"), "{plain}");
        let old: P2pStatusInfo = serde_json::from_str(
            r#"{"up":true,"peer_id":"12D3KooW","listen_addrs":[],"nat":"unknown","reservations":[],"relays_configured":0,"upnp":"unset","listen_setting":"relay"}"#,
        )
        .unwrap();
        assert!(old.retired_listen.is_empty());
        assert!(FORBIDDEN_FIELD_TOKENS
            .iter()
            .all(|bad| !"retired_listen".contains(bad)));
    }

    /// The p2p dial reply names how the link travelled; an older daemon's
    /// reply (no `path`) and a newer one's extra field both still decode.
    #[test]
    fn p2p_dial_result_carries_an_optional_path() {
        for path in [None, Some("reversed".to_string())] {
            let resp = IpcResponse::P2pDialResult {
                v: IPC_VERSION,
                frames_b64: vec!["ZGVm".into()],
                path: path.clone(),
            };
            let f = encode_response(&resp).unwrap();
            let json = std::str::from_utf8(&f[4..]).unwrap();
            assert_json_has_no_secret_tokens(json);
            assert_eq!(json.contains("\"path\""), path.is_some(), "{json}");
            assert_eq!(decode_response(&f).unwrap(), resp);
        }
        let old = decode_response(&frame_of(
            br#"{"ok":"p2p_dial_result","v":1,"frames_b64":[]}"#,
        ))
        .unwrap();
        assert_eq!(
            old,
            IpcResponse::P2pDialResult {
                v: 1,
                frames_b64: vec![],
                path: None,
            }
        );
        let newer = decode_response(&frame_of(
            br#"{"ok":"p2p_dial_result","v":1,"frames_b64":[],"path":"hole_punched","future":1}"#,
        ))
        .unwrap();
        match newer {
            IpcResponse::P2pDialResult { path, .. } => {
                assert_eq!(path.as_deref(), Some("hole_punched"))
            }
            other => panic!("{other:?}"),
        }
        assert!(FORBIDDEN_FIELD_TOKENS
            .iter()
            .all(|bad| !"path".contains(bad)));
    }

    /// `OutboxItem.path` is written only when known, and an older daemon's
    /// item (or a newer one's extra field) still decodes.
    #[test]
    fn outbox_item_path_is_optional() {
        let plain = OutboxItem {
            message_id_hex: "ab".repeat(16),
            state: "delivered".into(),
            carrier: "lan_dial".into(),
            ..OutboxItem::default()
        };
        let json = serde_json::to_string(&plain).unwrap();
        assert!(!json.contains("\"path\""), "{json}");
        assert_eq!(serde_json::from_str::<OutboxItem>(&json).unwrap(), plain);
        let p2p = OutboxItem {
            carrier: "p2p_dial".into(),
            path: "relayed".into(),
            ..plain.clone()
        };
        let json = serde_json::to_string(&p2p).unwrap();
        assert!(json.contains(r#""path":"relayed""#), "{json}");
        assert_json_has_no_secret_tokens(&json);
        assert_eq!(serde_json::from_str::<OutboxItem>(&json).unwrap(), p2p);
        let old: OutboxItem = serde_json::from_str(
            r#"{"message_id_hex":"ab","peer_pub_hex":"cd","kind":"message","state":"sent","carrier":"p2p_dial","attempts":1,"next_attempt_ms":0,"last_error_code":"","expires_at_ms":0}"#,
        )
        .unwrap();
        assert!(old.path.is_empty());
        let newer: OutboxItem = serde_json::from_str(
            r#"{"message_id_hex":"ab","peer_pub_hex":"cd","kind":"message","state":"sent","carrier":"p2p_dial","attempts":1,"next_attempt_ms":0,"last_error_code":"","expires_at_ms":0,"path":"direct","future":2}"#,
        )
        .unwrap();
        assert_eq!(newer.path, "direct");
    }

    /// Phase 3 friend custody: `OutboxKick.custody_now` and
    /// `OutboxItem.in_custody` are written only when set, an older client's
    /// kick and an older daemon's item still decode, and neither carries a
    /// secret token.
    #[test]
    fn outbox_kick_custody_now_and_outbox_item_in_custody_are_optional_and_old_json_decodes() {
        let kick = IpcRequest::OutboxKick {
            v: IPC_VERSION,
            peer_pub_hex: Some("cd".repeat(32)),
            retry: true,
            custody_now: true,
        };
        let f = encode_request(&kick).unwrap();
        let json = std::str::from_utf8(&f[4..]).unwrap();
        assert!(json.contains(r#""custody_now":true"#), "{json}");
        assert_json_has_no_secret_tokens(json);
        assert_eq!(decode_request(&f).unwrap(), kick);
        let plain = IpcRequest::OutboxKick {
            v: IPC_VERSION,
            peer_pub_hex: None,
            retry: true,
            custody_now: false,
        };
        let f = encode_request(&plain).unwrap();
        let json = std::str::from_utf8(&f[4..]).unwrap();
        assert!(!json.contains("custody_now"), "{json}");
        // An older client's kick: no custody_now, so no hand-off.
        let old = decode_request(&frame_of(br#"{"op":"outbox_kick","v":1,"retry":true}"#)).unwrap();
        assert_eq!(old, plain);

        let item = OutboxItem {
            message_id_hex: "ab".repeat(16),
            state: "sent".into(),
            last_error_code: "IN_CUSTODY".into(),
            in_custody: 2,
            ..OutboxItem::default()
        };
        let json = serde_json::to_string(&item).unwrap();
        assert!(json.contains(r#""in_custody":2"#), "{json}");
        assert_json_has_no_secret_tokens(&json);
        assert_eq!(serde_json::from_str::<OutboxItem>(&json).unwrap(), item);
        let none = OutboxItem {
            in_custody: 0,
            ..item
        };
        let json = serde_json::to_string(&none).unwrap();
        assert!(!json.contains("in_custody"), "{json}");
        assert!(!json.contains("custody_forwarded"), "{json}");
        // Review handoff-3: a friend took it to pass on (custody handoff).
        let forwarded = OutboxItem {
            in_custody: 1,
            custody_forwarded: true,
            ..none
        };
        let json = serde_json::to_string(&forwarded).unwrap();
        assert!(json.contains(r#""custody_forwarded":true"#), "{json}");
        assert_eq!(
            serde_json::from_str::<OutboxItem>(&json).unwrap(),
            forwarded
        );
        let old: OutboxItem = serde_json::from_str(
            r#"{"message_id_hex":"ab","peer_pub_hex":"cd","kind":"message","state":"sent","carrier":"","attempts":1,"next_attempt_ms":0,"last_error_code":"IN_CUSTODY","expires_at_ms":0}"#,
        )
        .unwrap();
        assert_eq!(old.in_custody, 0);
        assert!(!old.custody_forwarded);
        for field in ["custody_now", "in_custody", "custody_forwarded"] {
            assert!(FORBIDDEN_FIELD_TOKENS
                .iter()
                .all(|bad| !field.contains(bad)));
        }
    }

    /// The path counts: counts only, absent while no host runs and from an
    /// older daemon, and harmless next to a newer daemon's extra field.
    #[test]
    fn p2p_status_paths_is_optional() {
        let mut sent = PathCounts::default();
        for p in [
            crate::outbox::DeliveryPath::Relayed,
            crate::outbox::DeliveryPath::Relayed,
            crate::outbox::DeliveryPath::Reversed,
        ] {
            sent.add(p);
        }
        let mut received = PathCounts::default();
        received.add(crate::outbox::DeliveryPath::HolePunched);
        received.add(crate::outbox::DeliveryPath::Direct);
        let info = P2pStatusInfo {
            up: true,
            paths: Some(P2pPathCounts {
                sent,
                received,
                upgrades: 1,
                upgrade_failures: 2,
            }),
            ..P2pStatusInfo::default()
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(
            json.contains(r#""paths":{"sent":{"direct":0,"reversed":1,"relayed":2,"hole_punched":0},"received":{"direct":1,"reversed":0,"relayed":0,"hole_punched":1},"upgrades":1,"upgrade_failures":2}"#),
            "{json}"
        );
        assert_json_has_no_secret_tokens(&json);
        assert_eq!(serde_json::from_str::<P2pStatusInfo>(&json).unwrap(), info);
        let none = serde_json::to_string(&P2pStatusInfo::default()).unwrap();
        assert!(!none.contains("\"paths\""), "{none}");
        let old: P2pStatusInfo = serde_json::from_str(
            r#"{"up":true,"peer_id":"12D3KooW","listen_addrs":[],"nat":"unknown","reservations":[],"relays_configured":0,"upnp":"unset"}"#,
        )
        .unwrap();
        assert_eq!(old.paths, None);
        let newer: P2pStatusInfo = serde_json::from_str(
            r#"{"up":true,"peer_id":"12D3KooW","listen_addrs":[],"nat":"unknown","reservations":[],"relays_configured":0,"upnp":"unset","paths":{"sent":{"direct":1,"reversed":0,"relayed":0,"hole_punched":0},"received":{"direct":0,"reversed":0,"relayed":0,"hole_punched":0},"upgrades":0,"upgrade_failures":0,"future":3},"future":4}"#,
        )
        .unwrap();
        assert_eq!(newer.paths.unwrap().sent.direct, 1);
        let mut full = PathCounts {
            relayed: u64::MAX,
            ..PathCounts::default()
        };
        full.add(crate::outbox::DeliveryPath::Relayed);
        assert_eq!(full.relayed, u64::MAX);
        assert!(FORBIDDEN_FIELD_TOKENS.iter().all(|bad| [
            "paths",
            "sent",
            "received",
            "upgrades",
            "upgrade_failures",
            "hole_punched"
        ]
        .iter()
        .all(|key| !key.contains(bad))));
    }

    /// The reachability class, the AutoNAT check counts and the per-relay
    /// health rows: both ways through the codec, counts and states only, and
    /// defaults from an older daemon (or a newer one's extra fields).
    #[test]
    fn p2p_status_reach_fields_round_trip() {
        let info = P2pStatusInfo {
            up: true,
            peer_id: "12D3KooW".into(),
            nat: "unconfirmed".into(),
            reach: "relayed".into(),
            nat_checks: NatChecks {
                reached: 1,
                failed: 0,
                not_counted: 2,
            },
            relay_health: vec![
                RelayHealth {
                    relay: "/ip4/203.0.113.7/tcp/7423/p2p/x".into(),
                    state: "reserved".into(),
                    for_s: Some(120),
                    ping_ms: Some(31),
                    ping_age_s: Some(4),
                    check: "reached".into(),
                    ..RelayHealth::default()
                },
                RelayHealth {
                    relay: "/dns4/relay.example.org/tcp/7423/p2p/y".into(),
                    state: "retrying".into(),
                    retry_in_s: Some(9),
                    tries: 3,
                    ..RelayHealth::default()
                },
            ],
            ..P2pStatusInfo::default()
        };
        let status = IpcResponse::Status {
            v: IPC_VERSION,
            bridge: false,
            store: false,
            relay: false,
            forward_pending: 0,
            capabilities: vec!["ipc".into(), "p2p".into()],
            p2p: Some(Box::new(info.clone())),
            pid: None,
            lan_listen: None,
            last_paths: Vec::new(),
            route_hints: None,
            unreachable: Vec::new(),
            egress: None,
            lan_listen_wanted: None,
            lan_bind_error: None,
            clock_skew: Vec::new(),
            unanswered: Vec::new(),
            at_rest: None,
            lan: None,
            security: None,
            nearby: None,
            tor: None,
            learning: None,
            locked: None,
            updates: None,
        };
        let f = encode_response(&status).unwrap();
        let json = std::str::from_utf8(&f[4..]).unwrap();
        assert_json_has_no_secret_tokens(json);
        assert!(
            json.contains(r#""reach":"relayed""#)
                && json.contains(r#""nat_checks":{"reached":1,"failed":0,"not_counted":2}"#)
                && json.contains(r#"{"relay":"/dns4/relay.example.org/tcp/7423/p2p/y","state":"retrying","retry_in_s":9,"tries":3}"#)
                && json.contains(r#""for_s":120,"ping_ms":31,"ping_age_s":4,"tries":0,"check":"reached""#),
            "{json}"
        );
        assert_eq!(decode_response(&f).unwrap(), status);
        // No host: no class and no relay rows written.
        let none = serde_json::to_string(&P2pStatusInfo::default()).unwrap();
        assert!(
            !none.contains("\"reach\"") && !none.contains("relay_health"),
            "{none}"
        );
        // An older daemon's p2p status: an empty class, no counts, no rows.
        let old: P2pStatusInfo = serde_json::from_str(
            r#"{"up":true,"peer_id":"12D3KooW","listen_addrs":[],"nat":"public","reservations":[],"relays_configured":1,"upnp":"unset"}"#,
        )
        .unwrap();
        assert!(old.reach.is_empty() && old.relay_health.is_empty());
        assert_eq!(old.nat_checks, NatChecks::default());
        // A newer daemon's extra fields, at every level, still decode.
        let newer: P2pStatusInfo = serde_json::from_str(
            r#"{"up":true,"peer_id":"12D3KooW","listen_addrs":[],"nat":"public","reservations":[],"relays_configured":2,"upnp":"unset","reach":"public","nat_checks":{"reached":2,"future":1},"relay_health":[{"relay":"r","state":"reserved","future":2}],"future":3}"#,
        )
        .unwrap();
        assert_eq!(newer.reach, "public");
        assert_eq!(newer.nat_checks.reached, 2);
        assert_eq!(newer.relay_health[0].state, "reserved");
        assert_eq!(newer.relay_health[0].for_s, None);
        assert!(FORBIDDEN_FIELD_TOKENS.iter().all(|bad| [
            "reach",
            "nat_checks",
            "reached",
            "failed",
            "not_counted",
            "relay_health",
            "relay",
            "state",
            "for_s",
            "ping_ms",
            "ping_age_s",
            "retry_in_s",
            "tries",
            "check"
        ]
        .iter()
        .all(|key| !key.contains(bad))));
    }

    /// Phase 2 (P2.21): a status with the friend relay, automatic relay
    /// choice and a relay row of each source.
    fn friend_relay_status() -> IpcResponse {
        let info = P2pStatusInfo {
            up: true,
            peer_id: "12D3KooW".into(),
            relays_configured: 1,
            relays: vec!["/ip4/203.0.113.7/tcp/7423/p2p/m".into()],
            relay_health: vec![
                RelayHealth {
                    relay: "/ip4/203.0.113.7/tcp/7423/p2p/m".into(),
                    state: "reserved".into(),
                    source: "manual".into(),
                    ..RelayHealth::default()
                },
                RelayHealth {
                    relay: "/ip4/198.51.100.9/tcp/7427/p2p/o".into(),
                    state: "asking".into(),
                    source: "offer".into(),
                    operator_pub_hex: "ab".repeat(32),
                    ..RelayHealth::default()
                },
            ],
            friend_relay: Some(FriendRelayInfo {
                state: "up".into(),
                consent: "yes".into(),
                port: 7427,
                also_443: true,
                port_443_open: Some(true),
                members: 3,
                manual: 1,
                denied: 1,
                counts: RelayCounts {
                    reservations: 2,
                    circuits: 1,
                    ..RelayCounts::default()
                },
                reachable: "confirmed".into(),
                confirmed_age_s: Some(60),
                offering: true,
                offered_to: 3,
            }),
            relay_auto: true,
            relay_standby: 2,
            ..P2pStatusInfo::default()
        };
        IpcResponse::Status {
            v: IPC_VERSION,
            bridge: false,
            store: false,
            relay: false,
            forward_pending: 0,
            capabilities: vec!["ipc".into(), "p2p".into(), "p2p_friend_relay".into()],
            p2p: Some(Box::new(info)),
            pid: None,
            lan_listen: None,
            last_paths: Vec::new(),
            route_hints: None,
            unreachable: Vec::new(),
            egress: None,
            lan_listen_wanted: None,
            lan_bind_error: None,
            clock_skew: Vec::new(),
            unanswered: Vec::new(),
            at_rest: None,
            lan: None,
            security: None,
            nearby: None,
            tor: None,
            learning: None,
            locked: None,
            updates: None,
        }
    }

    /// Phase 2 (P2.21): the friend relay row, automatic relay choice and
    /// each relay row's source and operator go both ways through the codec;
    /// a manual row writes no operator, and with no friend relay and no
    /// offered relay nothing new is written.
    #[test]
    fn friend_relay_and_relay_health_source_round_trip() {
        let status = friend_relay_status();
        let f = encode_response(&status).unwrap();
        let json = std::str::from_utf8(&f[4..]).unwrap();
        assert_eq!(decode_response(&f).unwrap(), status);
        assert!(
            json.contains(r#""relay_auto":true,"relay_standby":2"#)
                && json.contains(r#""state":"up","consent":"yes","port":7427,"also_443":true"#)
                && json.contains(r#""offering":true,"offered_to":3"#)
                && json.contains(r#""state":"reserved","tries":0,"source":"manual"}"#)
                && json.contains(&format!(
                    r#""source":"offer","operator_pub_hex":"{}""#,
                    "ab".repeat(32)
                )),
            "{json}"
        );
        let none = serde_json::to_string(&P2pStatusInfo::default()).unwrap();
        assert!(
            !none.contains("friend_relay") && !none.contains("operator_pub_hex"),
            "{none}"
        );
        let row = serde_json::to_string(&RelayHealth::default()).unwrap();
        assert!(
            !row.contains("source") && !row.contains("operator"),
            "{row}"
        );
    }

    /// Phase 2 (P2.21): an older daemon's status (no friend relay, no
    /// automatic choice, rows without a source) decodes to the defaults, and
    /// a newer one's unknown fields are ignored at every level.
    #[test]
    fn old_json_decodes_to_defaults() {
        let old: P2pStatusInfo = serde_json::from_str(
            r#"{"up":true,"peer_id":"12D3KooW","listen_addrs":[],"nat":"public","reservations":[],"relays_configured":1,"upnp":"unset","relay_health":[{"relay":"r","state":"reserved"}]}"#,
        )
        .unwrap();
        assert_eq!(old.friend_relay, None);
        assert!(!old.relay_auto);
        assert_eq!(old.relay_standby, 0);
        let row = &old.relay_health[0];
        assert!(row.source.is_empty() && row.operator_pub_hex.is_empty());
        let newer: P2pStatusInfo = serde_json::from_str(
            r#"{"up":false,"peer_id":"","listen_addrs":[],"nat":"unknown","reservations":[],"relays_configured":0,"upnp":"off","friend_relay":{"state":"held","future":1},"relay_auto":true,"future":2}"#,
        )
        .unwrap();
        let friend = newer.friend_relay.unwrap();
        assert_eq!(friend.state, "held");
        assert_eq!(friend.counts, RelayCounts::default());
        assert!(friend.consent.is_empty() && !friend.offering);
        assert!(newer.relay_auto);
    }

    /// Phase 4 (P4.15): the relay paths, the proxy word and the restricted
    /// flag go both ways through the codec as fixed words; nothing new is
    /// written while they are empty, and an older raven-node's status
    /// decodes to the defaults (IPC_VERSION stays 1).
    #[test]
    fn relay_paths_proxy_and_restricted_round_trip() {
        let IpcResponse::Status { p2p, .. } = friend_relay_status() else {
            unreachable!()
        };
        let mut info = *p2p.unwrap();
        info.relay_paths = vec!["wss-proxy".into(), String::new()];
        info.proxy = "env".into();
        info.restricted = true;
        let status = IpcResponse::Status {
            v: IPC_VERSION,
            bridge: false,
            store: false,
            relay: false,
            forward_pending: 0,
            capabilities: vec!["ipc".into(), "p2p".into()],
            p2p: Some(Box::new(info)),
            pid: None,
            lan_listen: None,
            last_paths: Vec::new(),
            route_hints: None,
            unreachable: Vec::new(),
            egress: None,
            lan_listen_wanted: None,
            lan_bind_error: None,
            clock_skew: Vec::new(),
            unanswered: Vec::new(),
            at_rest: None,
            lan: None,
            security: None,
            nearby: None,
            tor: None,
            learning: None,
            locked: None,
            updates: None,
        };
        let f = encode_response(&status).unwrap();
        let json = std::str::from_utf8(&f[4..]).unwrap();
        assert_eq!(decode_response(&f).unwrap(), status);
        assert!(
            json.contains(r#""relay_paths":["wss-proxy",""],"proxy":"env","restricted":true"#),
            "{json}"
        );
        assert_json_has_no_secret_tokens(json);
        // Words, never a proxy: no URL, port or credential.
        for bad in ["http", "://", "@", "3128", "proxy.", "basic"] {
            assert!(!json.to_ascii_lowercase().contains(bad), "{bad}: {json}");
        }
        assert!(FORBIDDEN_FIELD_TOKENS
            .iter()
            .all(|bad| ["relay_paths", "proxy", "restricted"]
                .iter()
                .all(|key| !key.contains(bad))));
        let none = serde_json::to_string(&P2pStatusInfo::default()).unwrap();
        for key in ["relay_paths", "\"proxy\"", "restricted"] {
            assert!(!none.contains(key), "{key}: {none}");
        }
        let old: P2pStatusInfo = serde_json::from_str(
            r#"{"up":true,"peer_id":"12D3KooW","listen_addrs":[],"nat":"unknown","reservations":[],"relays_configured":1,"upnp":"unset"}"#,
        )
        .unwrap();
        assert!(old.relay_paths.is_empty() && old.proxy.is_empty() && !old.restricted);
    }

    /// Phase 4 (P4.16): the proxy setting's source and the proxy's 407 word
    /// go both ways as fixed words, are absent while empty, and an older
    /// raven-node's status decodes to empty ones.
    #[test]
    fn proxy_source_and_auth_round_trip() {
        for (source, auth) in [
            ("--p2p-proxy", "unsupported"),
            ("RAVEN_P2P_PROXY", "basic"),
            ("node_policy.json", "refused"),
        ] {
            let info = P2pStatusInfo {
                up: true,
                proxy: "setting".into(),
                proxy_source: source.into(),
                proxy_auth: auth.into(),
                ..P2pStatusInfo::default()
            };
            let json = serde_json::to_string(&info).unwrap();
            assert!(
                json.contains(&format!(
                    r#""proxy":"setting","proxy_source":"{source}","proxy_auth":"{auth}""#
                )),
                "{json}"
            );
            assert_json_has_no_secret_tokens(&json);
            for bad in ["://", "@", "3128"] {
                assert!(!json.contains(bad), "{bad}: {json}");
            }
            let back: P2pStatusInfo = serde_json::from_str(&json).unwrap();
            assert_eq!(back, info);
        }
        assert!(FORBIDDEN_FIELD_TOKENS
            .iter()
            .all(|bad| ["proxy_source", "proxy_auth"]
                .iter()
                .all(|key| !key.contains(bad))));
        let none = serde_json::to_string(&P2pStatusInfo::default()).unwrap();
        for key in ["proxy_source", "proxy_auth"] {
            assert!(!none.contains(key), "{key}: {none}");
        }
        let old: P2pStatusInfo = serde_json::from_str(
            r#"{"up":true,"peer_id":"12D3KooW","listen_addrs":[],"nat":"unknown","reservations":[],"relays_configured":1,"upnp":"unset","proxy":"env"}"#,
        )
        .unwrap();
        assert!(old.proxy_source.is_empty() && old.proxy_auth.is_empty());
    }

    /// Phase 4 (P4.20): router port mapping goes both ways as words and
    /// counts, is absent while unset, an older raven-node's status decodes
    /// to `None`, and an older reader of a newer one's ignores it. No
    /// address is ever in it.
    #[test]
    fn port_map_round_trip_old_json_and_no_addresses() {
        for (v4, v4_port, v6) in [
            ("pcp", 41000, "open"),
            ("nat-pmp", 7423, "not_asked"),
            ("upnp", 7423, "none"),
            ("behind_another_nat", 0, "refused"),
            ("double_nat", 0, "none"),
            ("off_path", 0, "not_asked"),
            ("none", 0, "asking"),
            ("off", 0, "not_asked"),
        ] {
            let info = P2pStatusInfo {
                up: true,
                upnp: if v4_port == 0 {
                    "failed".into()
                } else {
                    format!("mapped {v4_port}")
                },
                port_map: Some(PortMapStatus {
                    v4: v4.into(),
                    v4_port,
                    v6: v6.into(),
                    renewals: 2,
                    server_restarts: 1,
                }),
                ..P2pStatusInfo::default()
            };
            let json = serde_json::to_string(&info).unwrap();
            assert!(
                json.contains(&format!(
                    r#""port_map":{{"v4":"{v4}","v4_port":{v4_port},"v6":"{v6}","renewals":2,"server_restarts":1}}"#
                )),
                "{json}"
            );
            assert_json_has_no_secret_tokens(&json);
            let map = serde_json::to_string(&info.port_map).unwrap();
            for bad in [".", "/", "@", "::"] {
                assert!(!map.contains(bad), "{bad}: {map}");
            }
            let back: P2pStatusInfo = serde_json::from_str(&json).unwrap();
            assert_eq!(back, info);
        }
        assert!(FORBIDDEN_FIELD_TOKENS.iter().all(|bad| [
            "port_map",
            "v4",
            "v4_port",
            "v6",
            "renewals",
            "server_restarts"
        ]
        .iter()
        .all(|key| !key.contains(bad))));
        let none = serde_json::to_string(&P2pStatusInfo::default()).unwrap();
        assert!(!none.contains("port_map"), "{none}");
        let old: P2pStatusInfo = serde_json::from_str(
            r#"{"up":true,"peer_id":"12D3KooW","listen_addrs":[],"nat":"unknown","reservations":[],"relays_configured":1,"upnp":"mapped 7423"}"#,
        )
        .unwrap();
        assert_eq!((old.port_map, old.upnp.as_str()), (None, "mapped 7423"));
        // A newer raven-node's fields a reader does not know yet default.
        let newer: P2pStatusInfo = serde_json::from_str(
            r#"{"up":true,"peer_id":"12D3KooW","listen_addrs":[],"nat":"unknown","reservations":[],"relays_configured":0,"upnp":"on","port_map":{"v4":"asking","future":1}}"#,
        )
        .unwrap();
        assert_eq!(
            newer.port_map,
            Some(PortMapStatus {
                v4: "asking".into(),
                ..PortMapStatus::default()
            })
        );
    }

    /// Phase 4 (P4.24): the NAT mapping goes both ways as words and counts,
    /// is absent while unset, an older raven-node's status decodes to
    /// `None`, and an older reader of a newer one's ignores it.
    #[test]
    fn nat_mapping_round_trip_old_json_and_no_addresses() {
        for (tcp, quic) in [
            ("varies", "unknown"),
            ("stable_kept", "stable_shifted"),
            ("no_nat", "varies"),
        ] {
            let info = P2pStatusInfo {
                up: true,
                nat_mapping: Some(NatMappingStatus {
                    tcp: tcp.into(),
                    quic: quic.into(),
                    observers: 2,
                    punch_skipped: 3,
                    punch_failed: 1,
                }),
                ..P2pStatusInfo::default()
            };
            let json = serde_json::to_string(&info).unwrap();
            assert!(
                json.contains(&format!(
                    r#""nat_mapping":{{"tcp":"{tcp}","quic":"{quic}","observers":2,"punch_skipped":3,"punch_failed":1}}"#
                )),
                "{json}"
            );
            assert_json_has_no_secret_tokens(&json);
            let map = serde_json::to_string(&info.nat_mapping).unwrap();
            for bad in [".", "/", "@", "::"] {
                assert!(!map.contains(bad), "{bad}: {map}");
            }
            let back: P2pStatusInfo = serde_json::from_str(&json).unwrap();
            assert_eq!(back, info);
        }
        assert!(FORBIDDEN_FIELD_TOKENS.iter().all(|bad| [
            "nat_mapping",
            "tcp",
            "quic",
            "observers",
            "punch_skipped",
            "punch_failed"
        ]
        .iter()
        .all(|key| !key.contains(bad))));
        let none = serde_json::to_string(&P2pStatusInfo::default()).unwrap();
        assert!(!none.contains("nat_mapping"), "{none}");
        let old: P2pStatusInfo = serde_json::from_str(
            r#"{"up":true,"peer_id":"12D3KooW","listen_addrs":[],"nat":"unknown","reservations":[],"relays_configured":1,"upnp":"on"}"#,
        )
        .unwrap();
        assert_eq!(old.nat_mapping, None);
        let newer: P2pStatusInfo = serde_json::from_str(
            r#"{"up":true,"peer_id":"12D3KooW","listen_addrs":[],"nat":"unknown","reservations":[],"relays_configured":0,"upnp":"on","nat_mapping":{"tcp":"varies","future":1}}"#,
        )
        .unwrap();
        assert_eq!(
            newer.nat_mapping,
            Some(NatMappingStatus {
                tcp: "varies".into(),
                ..NatMappingStatus::default()
            })
        );
    }

    /// Phase 4 (P4.28): the rotation row round-trips, is absent while the
    /// gate is closed and from an older raven-node, and holds no PeerId,
    /// address or secret.
    #[test]
    fn rotation_round_trip_old_json_and_no_peer_id() {
        let info = P2pStatusInfo {
            up: true,
            peer_id: "12D3KooW".into(),
            rotation: Some(RotationStatus {
                state: "waiting".into(),
                waiting_on: 1,
                epoch: Some(7),
                epoch_len_s: 2_419_200,
                next_change_s: Some(30),
            }),
            ..P2pStatusInfo::default()
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(
            json.contains(
                r#""rotation":{"state":"waiting","waiting_on":1,"epoch":7,"epoch_len_s":2419200,"next_change_s":30}"#
            ),
            "{json}"
        );
        assert_json_has_no_secret_tokens(&json);
        let row = serde_json::to_string(&info.rotation).unwrap();
        for bad in ["12D3", ".", "/", "@"] {
            assert!(!row.contains(bad), "{bad}: {row}");
        }
        assert_eq!(serde_json::from_str::<P2pStatusInfo>(&json).unwrap(), info);
        let fixed = RotationStatus {
            state: "off".into(),
            ..RotationStatus::default()
        };
        let text = serde_json::to_string(&fixed).unwrap();
        assert!(
            !text.contains("epoch\"") && !text.contains("next_change_s"),
            "{text}"
        );
        let none = serde_json::to_string(&P2pStatusInfo::default()).unwrap();
        assert!(!none.contains("rotation"), "{none}");
        let old: P2pStatusInfo = serde_json::from_str(
            r#"{"up":true,"peer_id":"12D3KooW","listen_addrs":[],"nat":"unknown","reservations":[],"relays_configured":1,"upnp":"on"}"#,
        )
        .unwrap();
        assert_eq!(old.rotation, None);
    }

    /// Cutoff pack CP.6: an expired row that never left this computer says
    /// so; the field is absent when false and from an older raven-node.
    #[test]
    fn never_sent_round_trip_and_old_json() {
        let item = OutboxItem {
            message_id_hex: "ab".repeat(16),
            peer_pub_hex: "cd".repeat(32),
            kind: "message".into(),
            state: "expired".into(),
            last_error_code: "EXPIRED".into(),
            expires_at_ms: 1_700_000_086_400,
            never_sent: true,
            ..OutboxItem::default()
        };
        let resp = IpcResponse::OutboxStatusResult {
            v: IPC_VERSION,
            item: item.clone(),
        };
        let f = encode_response(&resp).unwrap();
        let json = std::str::from_utf8(&f[4..]).unwrap();
        assert!(json.contains(r#""never_sent":true"#), "{json}");
        assert_json_has_no_secret_tokens(json);
        assert_eq!(decode_response(&f).unwrap(), resp);
        let sent = serde_json::to_string(&OutboxItem {
            never_sent: false,
            ..item
        })
        .unwrap();
        assert!(!sent.contains("never_sent"), "{sent}");
        let old: OutboxItem = serde_json::from_str(
            r#"{"message_id_hex":"ab","peer_pub_hex":"cd","kind":"message","state":"expired","carrier":"","attempts":0,"next_attempt_ms":0,"last_error_code":"EXPIRED","expires_at_ms":0}"#,
        )
        .unwrap();
        assert!(!old.never_sent);
        assert!(!FORBIDDEN_FIELD_TOKENS
            .iter()
            .any(|bad| "never_sent".contains(bad)));
    }

    /// Phase 2 (P2.21): the new fields carry counts, labels and a contact's
    /// public device key only: no secret token in the JSON, and no new field
    /// name holds a token the IPC refuses.
    #[test]
    fn no_secret_tokens() {
        let f = encode_response(&friend_relay_status()).unwrap();
        assert_json_has_no_secret_tokens(std::str::from_utf8(&f[4..]).unwrap());
        assert!(FORBIDDEN_FIELD_TOKENS.iter().all(|bad| [
            "friend_relay",
            "relay_auto",
            "relay_standby",
            "source",
            "operator_pub_hex",
            "consent",
            "members",
            "offered_to",
            "confirmed_age_s"
        ]
        .iter()
        .all(|key| !key.contains(bad))));
    }

    #[test]
    fn roundtrip_lan_dial() {
        let req = IpcRequest::LanDial {
            v: IPC_VERSION,
            lan_dial: "192.168.1.20:7420".into(),
            expected_pub_hex: "ab".repeat(32),
            frames_b64: vec!["QUJD".into()],
        };
        let f = encode_request(&req).unwrap();
        assert_eq!(decode_request(&f).unwrap(), req);
        let resp = IpcResponse::LanDialResult {
            v: IPC_VERSION,
            frames_b64: vec!["ZGVm".into()],
        };
        let rf = encode_response(&resp).unwrap();
        assert_eq!(decode_response(&rf).unwrap(), resp);
    }

    #[test]
    fn windows_named_pipe_is_canonical_bind_name() {
        assert_eq!(WINDOWS_NAMED_PIPE, r"\\.\pipe\raven-node");
        assert_eq!(default_pipe_name(), WINDOWS_NAMED_PIPE);
    }

    /// The lab pipe suffix separates two profiles of one Windows account in a
    /// debug build only, and a malformed one fails closed (no shared default).
    #[test]
    fn lab_pipe_suffix_is_debug_only_and_strict() {
        let user = windows_pipe_name_for_sid("S-1-5-21-1-2-3-1001").unwrap();
        assert_eq!(
            with_lab_pipe_suffix(user.clone(), None, true),
            Some(user.clone())
        );
        assert_eq!(
            with_lab_pipe_suffix(user.clone(), Some("alice-1_2"), true),
            Some(format!("{user}-alice-1_2"))
        );
        assert_eq!(
            with_lab_pipe_suffix(user.clone(), Some("alice"), false),
            Some(user.clone()),
            "release ignores the lab override"
        );
        for bad in ["", "a\\b", "../x", "a b", &"x".repeat(33)] {
            assert_eq!(with_lab_pipe_suffix(user.clone(), Some(bad), true), None);
        }
    }

    #[cfg(unix)]
    #[test]
    fn ipc_endpoint_selects_unix_socket() {
        let tmp = tempfile::tempdir().unwrap();
        // Canonical spelling: macOS `/var` and `/tmp` are symlinks.
        let dir = std::fs::canonicalize(tmp.path())
            .unwrap()
            .join("raven-data");
        let ep = ipc_endpoint(&dir);
        assert_eq!(default_ipc_endpoint(&dir), ep);
        assert_eq!(ep, IpcEndpoint::UnixSocket(default_socket_path(&dir)));
        assert_eq!(
            ep.to_string(),
            dir.join("raven-node.sock").display().to_string()
        );
        assert!(ep.transport_available());
        assert!(!matches!(ep, IpcEndpoint::NamedPipe(_)));
        assert!(!matches!(ep, IpcEndpoint::Unsupported));
    }

    #[cfg(unix)]
    #[test]
    fn long_data_dir_gets_short_deterministic_private_socket_path() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        // A short canonical data dir keeps `<dir>/raven-node.sock`.
        let tmp = tempfile::tempdir().unwrap();
        let tmp_path = std::fs::canonicalize(tmp.path()).unwrap();
        let short = tmp_path.join("raven-data");
        assert_eq!(default_socket_path(&short), short.join("raven-node.sock"));

        // A data dir whose `<dir>/raven-node.sock` cannot fit sun_path.
        let long_a = tmp_path.join("a".repeat(120));
        let long_b = tmp_path.join("b".repeat(120));
        assert!(long_a.join(SOCKET_FILE_NAME).as_os_str().len() > UNIX_SOCKET_PATH_MAX);
        let sock_a = default_socket_path(&long_a);
        assert_ne!(sock_a, long_a.join(SOCKET_FILE_NAME));
        assert!(sock_a.as_os_str().len() <= UNIX_SOCKET_PATH_MAX);
        // Daemon and clients call the same function: stable per data dir, and
        // distinct data dirs never share an endpoint.
        assert_eq!(default_socket_path(&long_a), sock_a);
        assert_ne!(default_socket_path(&long_b), sock_a);
        assert_eq!(
            ipc_endpoint(&long_a),
            IpcEndpoint::UnixSocket(sock_a.clone())
        );

        // It lives in a verified owner-only directory.
        let parent = sock_a.parent().unwrap();
        let meta = std::fs::symlink_metadata(parent).unwrap();
        assert!(meta.is_dir());
        assert_eq!(meta.uid(), current_euid());
        assert_eq!(meta.permissions().mode() & 0o077, 0);

        // And it really binds and connects, which the long path cannot.
        let _ = std::fs::remove_file(&sock_a);
        assert!(std::os::unix::net::UnixListener::bind(long_a.join(SOCKET_FILE_NAME)).is_err());
        let listener = std::os::unix::net::UnixListener::bind(&sock_a).unwrap();
        let client = std::os::unix::net::UnixStream::connect(&sock_a).unwrap();
        drop((listener, client));
        std::fs::remove_file(&sock_a).unwrap();
    }

    /// One data dir, several spellings (symlink, `..`, not yet created): the
    /// daemon and a client must reach the same socket, and therefore the same
    /// `<sock>.lock`, even when the spellings fall on different sides of the
    /// `sun_path` limit. The raw-length decision used to give the short
    /// symlink spelling its own direct socket while the long real spelling got
    /// the hashed fallback, so a second daemon could start on one profile.
    #[cfg(unix)]
    #[test]
    fn every_spelling_of_one_data_dir_gets_the_same_socket() {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let real = root.join("r".repeat(100));
        std::fs::create_dir(&real).unwrap();
        let link = root.join("l");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        // The two spellings are on opposite sides of the limit.
        assert!(link.join(SOCKET_FILE_NAME).as_os_str().len() <= UNIX_SOCKET_PATH_MAX);
        assert!(real.join(SOCKET_FILE_NAME).as_os_str().len() > UNIX_SOCKET_PATH_MAX);

        let via_real = default_socket_path(&real);
        let via_link = default_socket_path(&link);
        assert_eq!(via_link, via_real, "spelling must not pick the socket");
        assert!(via_real.as_os_str().len() <= UNIX_SOCKET_PATH_MAX);
        assert_ne!(via_real, real.join(SOCKET_FILE_NAME));
        // `..` and `.` do not change it either.
        assert_eq!(default_socket_path(&real.join("..").join("l")), via_real);
        assert_eq!(default_socket_path(&real.join(".")), via_real);
        // Nor does the instance lock derived from it.
        let lock = |sock: &std::path::Path| {
            let mut p = sock.as_os_str().to_os_string();
            p.push(".lock");
            std::path::PathBuf::from(p)
        };
        assert_eq!(lock(&via_link), lock(&via_real));

        // A short symlinked spelling of a short dir: also one answer, and a
        // direct socket inside the (resolved) directory.
        let short_real = root.join("s");
        std::fs::create_dir(&short_real).unwrap();
        let short_link = root.join("sl");
        std::os::unix::fs::symlink(&short_real, &short_link).unwrap();
        assert_eq!(
            default_socket_path(&short_link),
            short_real.join(SOCKET_FILE_NAME)
        );
        assert_eq!(
            default_socket_path(&short_link),
            default_socket_path(&short_real)
        );
    }

    #[test]
    fn instance_lock_sits_next_to_the_socket() {
        let sock = std::path::Path::new("/some/dir/raven-node.sock");
        assert_eq!(
            instance_lock_path(sock),
            std::path::PathBuf::from("/some/dir/raven-node.sock.lock")
        );
    }

    /// The answer must not change when the daemon creates the directory after
    /// a client (`ash doctor`, a launcher) already asked for its endpoint.
    #[cfg(unix)]
    #[test]
    fn socket_path_is_stable_across_creation_of_the_data_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let real = root.join("r".repeat(60));
        std::fs::create_dir(&real).unwrap();
        let link = root.join("l");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        // `<link>/p/q` does not exist yet; its resolved spelling is under `real`.
        let future_via_link = link.join("p").join("q");
        let future_real = real.join("p").join("q");
        assert!(!future_real.exists());
        assert_eq!(normalized_data_dir(&future_via_link), future_real);
        let before = default_socket_path(&future_via_link);
        assert_eq!(before, default_socket_path(&future_real));
        std::fs::create_dir_all(&future_real).unwrap();
        assert_eq!(default_socket_path(&future_via_link), before);
        assert_eq!(default_socket_path(&future_real), before);
    }

    /// A relative data dir resolves against the working directory (read, never
    /// changed, so this cannot race other tests).
    #[cfg(unix)]
    #[test]
    fn relative_data_dir_is_resolved_against_the_working_directory() {
        let cwd = std::fs::canonicalize(std::env::current_dir().unwrap()).unwrap();
        let rel = std::path::Path::new("raven-ipc-test-no-such-dir-42");
        assert!(!cwd.join(rel).exists());
        assert_eq!(normalized_data_dir(rel), cwd.join(rel));
        assert_eq!(
            default_socket_path(rel),
            default_socket_path(&cwd.join(rel)),
            "relative and absolute spellings share one endpoint"
        );
        // `.` is the working directory itself.
        assert_eq!(
            default_socket_path(std::path::Path::new(".")),
            default_socket_path(&cwd)
        );
    }

    #[cfg(windows)]
    #[test]
    fn ipc_endpoint_selects_windows_named_pipe() {
        let dir = std::path::Path::new(r"C:\raven-data");
        let ep = ipc_endpoint(dir);
        assert_eq!(default_ipc_endpoint(dir), ep);
        let name = windows_user_pipe_name().expect("current user SID");
        assert_eq!(ep, IpcEndpoint::NamedPipe(name));
        assert!(ep.to_string().starts_with(r"\\.\pipe\raven-node-S-1-"));
        assert_eq!(default_pipe_name(), r"\\.\pipe\raven-node");
        assert!(ep.transport_available());
        assert!(!matches!(ep, IpcEndpoint::UnixSocket(_)));
        assert!(!matches!(ep, IpcEndpoint::Unsupported));
    }

    #[test]
    fn windows_pipe_name_is_per_user_and_injection_safe() {
        assert_eq!(
            windows_pipe_name_for_sid("S-1-5-21-1004336348-1177238915-682003330-1001").as_deref(),
            Some(r"\\.\pipe\raven-node-S-1-5-21-1004336348-1177238915-682003330-1001")
        );
        assert_ne!(
            windows_pipe_name_for_sid("S-1-5-21-1-2-3-1001"),
            windows_pipe_name_for_sid("S-1-5-21-1-2-3-1002")
        );
        for bad in [
            "",
            "S-1",
            "S-1-",
            "S-1-5-",
            "S-1-5--21",
            "S-2-5-21",
            "s-1-5-21",
            "S-1-5-21-a",
            r"S-1-5\..\raven-node",
            "S-1-5-21-1 ",
        ] {
            assert_eq!(windows_pipe_name_for_sid(bad), None, "{bad:?}");
        }
    }

    fn frame_of(body: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
        frame.extend_from_slice(body);
        frame
    }

    /// Regression: the denylist used to scan the whole body, so base64
    /// ciphertext or a dial host containing e.g. "seed" was refused.
    #[test]
    fn forbidden_tokens_inside_values_are_accepted() {
        let envelope_b64 = format!("QUJD{}c2VlZA==", "seedPlainTextRECOVERYprivate_key");
        let req = IpcRequest::EnqueueSealed {
            v: IPC_VERSION,
            envelope_b64,
            peer_hint: Some("seedbox".into()),
        };
        assert_eq!(decode_request(&encode_request(&req).unwrap()).unwrap(), req);
        let req = IpcRequest::LanDial {
            v: IPC_VERSION,
            lan_dial: "seed.local:7420".into(),
            expected_pub_hex: "ab".repeat(32),
            frames_b64: vec!["xxSEEDxx".into(), "plaintext".into()],
        };
        assert_eq!(decode_request(&encode_request(&req).unwrap()).unwrap(), req);
        let req = IpcRequest::SealUnderSession {
            v: IPC_VERSION,
            peer_hint: "cd".repeat(32),
            app_payload_b64: "cmVjb3Zlcnk=Recovery".into(),
        };
        assert_eq!(decode_request(&encode_request(&req).unwrap()).unwrap(), req);
    }

    /// Lock v2 (P6.40): Lock and Unlock round-trip, and the passphrase never
    /// shows: not in `Debug`, not in any decode error (serde's own text
    /// would quote a value it refused) and not past the secret-name
    /// denylist, which refuses with fixed words. An older daemon's Status
    /// (no `locked`) reads as `None`.
    #[test]
    fn lock_v2_ops_roundtrip_and_never_show_the_passphrase() {
        const SECRET: &str = "aHVudGVyMi1jb3JyZWN0LWhvcnNl";
        let lock = IpcRequest::Lock { v: IPC_VERSION };
        let f = encode_request(&lock).unwrap();
        assert_eq!(
            std::str::from_utf8(&f[4..]).unwrap(),
            r#"{"op":"lock","v":1}"#
        );
        assert_eq!(decode_request(&f).unwrap(), lock);
        let unlock = IpcRequest::Unlock {
            v: IPC_VERSION,
            passphrase_b64: Some(IpcSecret::new(SECRET.into())),
        };
        let f = encode_request(&unlock).unwrap();
        let json = std::str::from_utf8(&f[4..]).unwrap();
        assert!(json.contains("passphrase_b64") && json.contains(SECRET));
        assert_json_has_no_secret_tokens(json);
        assert_eq!(decode_request(&f).unwrap(), unlock);
        assert!(!format!("{unlock:?}").contains(SECRET), "Debug redacts it");
        let plain = IpcRequest::Unlock {
            v: IPC_VERSION,
            passphrase_b64: None,
        };
        let f = encode_request(&plain).unwrap();
        assert_eq!(
            std::str::from_utf8(&f[4..]).unwrap(),
            r#"{"op":"unlock","v":1}"#
        );
        assert_eq!(decode_request(&f).unwrap(), plain);
        for (body, code) in [
            (
                format!(r#"{{"op":"unlock","v":1,"passphrase_b64":["{SECRET}"]}}"#),
                "IPC_FRAME",
            ),
            (
                format!(r#"{{"op":"unlock","v":1,"passphrase_b64":"{SECRET}","#),
                "IPC_FRAME",
            ),
            (
                format!(r#"{{"op":"unlock","v":"{SECRET}","passphrase_b64":"x"}}"#),
                "IPC_FRAME",
            ),
            (
                format!(r#"{{"op":"unlock","v":2,"passphrase_b64":"{SECRET}"}}"#),
                "IPC_VERSION",
            ),
            (
                format!(r#"{{"op":"unlock","v":1,"passphrase_b64":"{SECRET}","seed":"{SECRET}"}}"#),
                "IPC_FORBIDDEN_FIELD",
            ),
        ] {
            let err = decode_request_checked(&frame_of(body.as_bytes())).unwrap_err();
            assert_eq!(err.code, code, "{body}");
            assert!(!err.message.contains(SECRET), "{body}: {}", err.message);
            assert!(!format!("{err:?}").contains(SECRET), "{body}");
        }
        // An unknown field is ignored, as everywhere: no passphrase came.
        let odd = format!(r#"{{"op":"unlock","v":1,"Passphrase":"{SECRET}"}}"#);
        assert_eq!(decode_request(&frame_of(odd.as_bytes())).unwrap(), plain);
        // The fixed text replaces serde's for a body that names a
        // passphrase; any other body keeps serde's words.
        let err = decode_request_checked(&frame_of(
            format!(r#"{{"op":"unlock","v":1,"passphrase_b64":7{SECRET}}}"#).as_bytes(),
        ))
        .unwrap_err();
        assert_eq!(err.message, PASSPHRASE_DECODE_ERROR);
        let err = decode_request_checked(&frame_of(br#"{"op":"ping","v":true}"#)).unwrap_err();
        assert_ne!(err.message, PASSPHRASE_DECODE_ERROR);
        // LockState: `failed_unlocks` only when there were any.
        let state = IpcResponse::LockState {
            v: IPC_VERSION,
            locked: true,
            passphrase: false,
            failed_unlocks: 0,
        };
        let f = encode_response(&state).unwrap();
        assert_eq!(
            std::str::from_utf8(&f[4..]).unwrap(),
            r#"{"ok":"lock_state","v":1,"locked":true,"passphrase":false}"#
        );
        assert_eq!(decode_response(&f).unwrap(), state);
        let after = IpcResponse::LockState {
            v: IPC_VERSION,
            locked: false,
            passphrase: true,
            failed_unlocks: 3,
        };
        assert_eq!(
            decode_response(&encode_response(&after).unwrap()).unwrap(),
            after
        );
        let old = decode_response(&frame_of(
            br#"{"ok":"status","v":1,"bridge":true,"store":true,"relay":false,"forward_pending":0,"capabilities":["ipc"]}"#,
        ))
        .unwrap();
        assert!(
            matches!(old, IpcResponse::Status { locked: None, .. }),
            "{old:?}"
        );
    }

    #[test]
    fn forbidden_keys_are_refused_when_nested_escaped_or_cased() {
        for body in [
            r#"{"op":"ping","v":1,"Seed_Hex":"x"}"#,
            r#"{"op":"ping","v":1,"s\u0065ed":"x"}"#,
            r#"{"op":"ping","v":1,"meta":{"inner":{"recovery_phrase":1}}}"#,
            r#"{"op":"ping","v":1,"list":[{"PRIVATE_KEY":0}]}"#,
            r#"{"op":"enqueue_sealed","v":1,"envelope_b64":"QUJD","plaintext_b64":"eA=="}"#,
            // Lock v2 (P6.40): an Unlock with a secret-named field is refused
            // too, and its passphrase never shows in the refusal.
            r#"{"op":"unlock","v":1,"passphrase_b64":"aHVudGVyMg==","meta":{"Seed":1}}"#,
        ] {
            let err = decode_request_checked(&frame_of(body.as_bytes())).unwrap_err();
            assert_eq!(err.code, "IPC_FORBIDDEN_FIELD", "{body}");
            assert!(!format!("{err:?} {}", err.message).contains("aHVudGVyMg=="));
            assert!(decode_request(&frame_of(body.as_bytes())).is_err());
        }
    }

    #[test]
    fn decode_errors_carry_typed_codes() {
        let err = decode_request_checked(&frame_of(br#"{"op":"ping","v":2}"#)).unwrap_err();
        assert_eq!(err.code, "IPC_VERSION");
        let err = decode_request_checked(&frame_of(b"{not json")).unwrap_err();
        assert_eq!(err.code, "IPC_FRAME");
        let err = decode_request_checked(&[0, 0]).unwrap_err();
        assert_eq!(err.code, "IPC_FRAME");
    }

    fn assert_json_has_no_secret_tokens(raw: &str) {
        let lower = raw.to_ascii_lowercase();
        for bad in ["seed", "private_key", "plaintext", "recovery"] {
            assert!(!lower.contains(bad), "{bad} leaked into IPC JSON: {raw}");
        }
    }

    /// Review B-sealed-stores-6: the Status every reader but `raven status`
    /// sends is the same bytes as before (so an older raven-node reads it
    /// as before, and an older client's Status asks for no key try);
    /// `raven status` adds `retry_key`, which an older raven-node ignores.
    #[test]
    fn status_asks_for_a_key_try_only_from_raven_status() {
        let plain = serde_json::to_string(&IpcRequest::status()).unwrap();
        assert_eq!(plain, r#"{"op":"status","v":1}"#);
        let asking = serde_json::to_string(&IpcRequest::status_retrying_key()).unwrap();
        assert_eq!(asking, r#"{"op":"status","v":1,"retry_key":true}"#);
        let frame = |json: &str| {
            let mut out = (json.len() as u32).to_be_bytes().to_vec();
            out.extend_from_slice(json.as_bytes());
            out
        };
        assert_eq!(
            decode_request(&frame(&plain)).unwrap(),
            IpcRequest::Status {
                v: IPC_VERSION,
                retry_key: false
            }
        );
        assert_eq!(
            decode_request(&frame(&asking)).unwrap(),
            IpcRequest::status_retrying_key()
        );
    }

    #[test]
    fn status_json_has_no_private_key_material() {
        let req = IpcRequest::status();
        let resp = IpcResponse::Status {
            v: IPC_VERSION,
            bridge: false,
            store: false,
            relay: false,
            forward_pending: 0,
            capabilities: vec!["ipc".into()],
            p2p: None,
            pid: None,
            lan_listen: None,
            last_paths: Vec::new(),
            route_hints: None,
            unreachable: Vec::new(),
            egress: None,
            lan_listen_wanted: None,
            lan_bind_error: None,
            clock_skew: Vec::new(),
            unanswered: Vec::new(),
            at_rest: None,
            lan: None,
            security: None,
            nearby: None,
            tor: None,
            learning: None,
            locked: None,
            updates: None,
        };
        let rf = encode_request(&req).unwrap();
        let sf = encode_response(&resp).unwrap();
        let req_json = std::str::from_utf8(&rf[4..]).unwrap();
        let resp_json = std::str::from_utf8(&sf[4..]).unwrap();
        assert_json_has_no_secret_tokens(req_json);
        assert_json_has_no_secret_tokens(resp_json);
        assert!(resp_json.contains("\"ok\":\"status\""));
        assert!(
            !resp_json.contains("rvn1"),
            "Status stays policy-only; whoami is ash CLI"
        );
    }

    /// Serialize existing ops to prove no secret field names.
    /// Encode/decode only — not an O6 E2E / HOLD-lift claim.
    #[test]
    fn all_ipc_variants_json_have_no_private_key_material() {
        let reqs = [
            IpcRequest::Ping { v: IPC_VERSION },
            IpcRequest::status(),
            IpcRequest::SetPolicy {
                v: IPC_VERSION,
                bridge: Some(false),
                store: None,
                relay: None,
            },
            IpcRequest::EnqueueSealed {
                v: IPC_VERSION,
                envelope_b64: "QUJD".into(),
                peer_hint: Some("peer".into()),
            },
            IpcRequest::SealUnderSession {
                v: IPC_VERSION,
                peer_hint: "ab".repeat(32),
                app_payload_b64: "aGVsbG8=".into(),
            },
            IpcRequest::LanDial {
                v: IPC_VERSION,
                lan_dial: "127.0.0.1:1".into(),
                expected_pub_hex: "ab".repeat(32),
                frames_b64: vec!["QUJD".into()],
            },
            IpcRequest::InternetDial {
                v: IPC_VERSION,
                internet_dial: "127.0.0.1:1".into(),
                expected_pub_hex: "ab".repeat(32),
                frames_b64: vec!["QUJD".into()],
            },
        ];
        let resps = [
            IpcResponse::Pong { v: IPC_VERSION },
            IpcResponse::Status {
                v: IPC_VERSION,
                bridge: false,
                store: false,
                relay: false,
                forward_pending: 0,
                capabilities: vec!["ipc".into()],
                p2p: None,
                pid: None,
                lan_listen: None,
                last_paths: Vec::new(),
                route_hints: None,
                unreachable: Vec::new(),
                egress: None,
                lan_listen_wanted: None,
                lan_bind_error: None,
                clock_skew: Vec::new(),
                unanswered: Vec::new(),
                at_rest: None,
                lan: None,
                security: None,
                nearby: None,
                tor: None,
                learning: None,
                locked: None,
                updates: None,
            },
            IpcResponse::Accepted { v: IPC_VERSION },
            IpcResponse::LanDialResult {
                v: IPC_VERSION,
                frames_b64: vec!["QUJD".into()],
            },
            IpcResponse::InternetDialResult {
                v: IPC_VERSION,
                frames_b64: vec!["QUJD".into()],
            },
            IpcResponse::SealUnderSessionResult {
                v: IPC_VERSION,
                envelope_b64: "QUJD".into(),
            },
            IpcResponse::Error {
                v: IPC_VERSION,
                code: "X".into(),
                message: "no".into(),
            },
        ];
        for req in &reqs {
            let f = encode_request(req).unwrap();
            assert_json_has_no_secret_tokens(std::str::from_utf8(&f[4..]).unwrap());
        }
        for resp in &resps {
            let f = encode_response(resp).unwrap();
            assert_json_has_no_secret_tokens(std::str::from_utf8(&f[4..]).unwrap());
        }
    }

    #[test]
    fn seal_under_session_roundtrip_has_no_secret_fields() {
        let req = IpcRequest::SealUnderSession {
            v: IPC_VERSION,
            peer_hint: "cd".repeat(32),
            app_payload_b64: "aGVsbG8=".into(),
        };
        let f = encode_request(&req).unwrap();
        assert_eq!(decode_request(&f).unwrap(), req);
        let raw = std::str::from_utf8(&f[4..]).unwrap();
        assert_json_has_no_secret_tokens(raw);
        assert!(raw.contains("\"op\":\"seal_under_session\""));
        assert!(raw.contains("app_payload_b64"));
        assert!(!raw.to_ascii_lowercase().contains("plaintext"));
        let resp = IpcResponse::SealUnderSessionResult {
            v: IPC_VERSION,
            envelope_b64: "QkFTRTY0".into(),
        };
        let rf = encode_response(&resp).unwrap();
        assert_eq!(decode_response(&rf).unwrap(), resp);
        assert_json_has_no_secret_tokens(std::str::from_utf8(&rf[4..]).unwrap());
    }

    #[test]
    fn enqueue_sealed_roundtrip_has_no_secret_fields() {
        let req = IpcRequest::EnqueueSealed {
            v: IPC_VERSION,
            envelope_b64: "QUJD".into(),
            peer_hint: Some("peer".into()),
        };
        let f = encode_request(&req).unwrap();
        assert_eq!(decode_request(&f).unwrap(), req);
        let raw = std::str::from_utf8(&f[4..]).unwrap().to_ascii_lowercase();
        for bad in ["seed", "private_key", "plaintext", "recovery"] {
            assert!(!raw.contains(bad), "{bad} leaked into EnqueueSealed JSON");
        }
    }

    /// The outbox ops carry identifiers, states and counts only: no field
    /// (and so no value) can hold message content, and the JSON keys pass the
    /// secret-name denylist both ways.
    #[test]
    fn outbox_ops_roundtrip_and_carry_no_content() {
        let item = OutboxItem {
            message_id_hex: "ab".repeat(16),
            peer_pub_hex: "cd".repeat(32),
            kind: "message".into(),
            state: "queued".into(),
            carrier: "lan_dial".into(),
            attempts: 3,
            next_attempt_ms: 1_700_000_000_000,
            last_error_code: "NOT_REACHABLE".into(),
            expires_at_ms: 1_700_000_086_400,
            delivered_at_ms: 0,
            path: String::new(),
            why: String::new(),
            never_sent: false,
            in_custody: 0,
            custody_forwarded: false,
            tried: Vec::new(),
            outcomes: Vec::new(),
        };
        let reqs = [
            IpcRequest::OutboxKick {
                v: IPC_VERSION,
                peer_pub_hex: Some("cd".repeat(32)),
                retry: false,
                custody_now: false,
            },
            IpcRequest::OutboxKick {
                v: IPC_VERSION,
                peer_pub_hex: None,
                retry: true,
                custody_now: false,
            },
            IpcRequest::OutboxStatus {
                v: IPC_VERSION,
                message_id_hex: "ab".repeat(16),
            },
            IpcRequest::OutboxList {
                v: IPC_VERSION,
                peer_pub_hex: None,
                limit: Some(MAX_OUTBOX_LIST),
            },
        ];
        for req in &reqs {
            let f = encode_request(req).unwrap();
            assert_eq!(&decode_request(&f).unwrap(), req);
            assert_json_has_no_secret_tokens(std::str::from_utf8(&f[4..]).unwrap());
        }
        // Optional fields may be absent (and a minimal kick is just the op).
        let kick = decode_request(&frame_of(br#"{"op":"outbox_kick","v":1}"#)).unwrap();
        assert_eq!(
            kick,
            IpcRequest::OutboxKick {
                v: IPC_VERSION,
                peer_pub_hex: None,
                retry: false,
                custody_now: false,
            }
        );
        let resps = [
            IpcResponse::OutboxStatusResult {
                v: IPC_VERSION,
                item: item.clone(),
            },
            IpcResponse::OutboxListResult {
                v: IPC_VERSION,
                worker_running: true,
                items: vec![item.clone()],
            },
        ];
        for resp in &resps {
            let f = encode_response(resp).unwrap();
            assert_eq!(&decode_response(&f).unwrap(), resp);
            let json = std::str::from_utf8(&f[4..]).unwrap();
            assert_json_has_no_secret_tokens(json);
            for word in ["body", "preview", "text", "envelope", "frames"] {
                assert!(!json.contains(word), "{word} in outbox IPC JSON: {json}");
            }
        }
        // The item has exactly these fields: adding one is a reviewed change.
        let value = serde_json::to_value(&item).unwrap();
        let mut keys: Vec<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "attempts",
                "carrier",
                "expires_at_ms",
                "kind",
                "last_error_code",
                "message_id_hex",
                "next_attempt_ms",
                "peer_pub_hex",
                "state"
            ]
        );
        // E2 r40: the ways the last attempt tried and the attempts by how
        // they ended: carrier labels, codes and counts only.
        let counted = OutboxItem {
            tried: vec!["lan_dial".into(), "onion_dial".into()],
            outcomes: vec![AttemptCount {
                code: "NOT_REACHABLE".into(),
                count: 9,
            }],
            ..item.clone()
        };
        let resp = IpcResponse::OutboxStatusResult {
            v: IPC_VERSION,
            item: counted,
        };
        let f = encode_response(&resp).unwrap();
        let json = std::str::from_utf8(&f[4..]).unwrap();
        assert!(
            json.contains(r#""tried":["lan_dial","onion_dial"]"#),
            "{json}"
        );
        assert!(
            json.contains(r#""outcomes":[{"code":"NOT_REACHABLE","count":9}]"#),
            "{json}"
        );
        assert_eq!(decode_response(&f).unwrap(), resp);
        // A wrong version is refused like every other op.
        let err = decode_request_checked(&frame_of(br#"{"op":"outbox_list","v":2}"#)).unwrap_err();
        assert_eq!(err.code, "IPC_VERSION");
    }

    /// An op this build does not know (a newer client talking to an older
    /// daemon) is the typed `IPC_FRAME` refusal, never a crash or a guess.
    #[test]
    fn unknown_ops_are_a_typed_frame_error() {
        let err =
            decode_request_checked(&frame_of(br#"{"op":"outbox_frobnicate","v":1}"#)).unwrap_err();
        assert_eq!(err.code, "IPC_FRAME");
    }

    #[test]
    fn rejects_all_secret_field_names() {
        for bad in ["seed", "private_key", "plaintext", "recovery"] {
            let body = format!(r#"{{"op":"ping","v":1,"{bad}":"nope"}}"#);
            let mut frame = Vec::new();
            frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
            frame.extend_from_slice(body.as_bytes());
            assert!(decode_request(&frame).is_err(), "expected refuse for {bad}");
        }
    }

    #[test]
    fn app_channel_ops_roundtrip_without_forbidden_keys() {
        let reqs = [
            IpcRequest::AppSubmit {
                v: IPC_VERSION,
                peer_identity_hex: "ab".repeat(32),
                content_type: "a2a-request/1".into(),
                client_ref: "rdap-task:0123".into(),
                body_b64: "e30=".into(),
                ttl_ms: Some(14_400_000),
                resend: false,
            },
            IpcRequest::AppInboxPage {
                v: IPC_VERSION,
                consumer: "rdap:9f2c".into(),
                takeover: false,
                content_type: Some("a2a-response/1".into()),
                after: None,
                limit: Some(4),
                wait_ms: Some(20_000),
            },
            IpcRequest::AppInboxAck {
                v: IPC_VERSION,
                consumer: "rdap:9f2c".into(),
                items: vec![AppInboxRef {
                    sender_device_hex: "cd".repeat(32),
                    message_id_hex: "ef".repeat(16),
                }],
                disposition: "done".into(),
            },
            IpcRequest::AgentSign {
                v: IPC_VERSION,
                statement: crate::agent_sign::AgentDelegationStatement {
                    context: crate::agent_sign::AGENT_DELEGATION_CONTEXT.into(),
                    sender: "rvn1q".into(),
                    recipient: "rvn1q".into(),
                    task_id: "t".into(),
                    kind: "task".into(),
                    issued_at: 1,
                    expires_at: 2,
                    payload_sha256_hex: "00".repeat(32),
                    nonce_hex: "00".repeat(16),
                },
            },
        ];
        for req in &reqs {
            let f = encode_request(req).unwrap();
            assert_eq!(&decode_request(&f).unwrap(), req);
            assert_json_has_no_secret_tokens(std::str::from_utf8(&f[4..]).unwrap());
        }
        // Minimal requests decode with their defaults.
        let page = decode_request(&frame_of(
            br#"{"op":"app_inbox_page","v":1,"consumer":"rdap:x"}"#,
        ))
        .unwrap();
        assert!(matches!(
            page,
            IpcRequest::AppInboxPage {
                takeover: false,
                content_type: None,
                limit: None,
                wait_ms: None,
                ..
            }
        ));
        let resps = [
            IpcResponse::AppSubmitResult {
                v: IPC_VERSION,
                message_id_hex: "ab".repeat(16),
                app_id_hex: "cd".repeat(16),
                state: "queued".into(),
                expires_at_ms: 1,
                duplicate: false,
                attempt_seq: 0,
            },
            IpcResponse::AgentSignResult {
                v: IPC_VERSION,
                signer_address: "rvn1q".into(),
                signer_pub_hex: "ab".repeat(32),
                signature_b64: "AA==".into(),
            },
        ];
        for resp in &resps {
            let json = serde_json::to_string(resp).unwrap();
            assert_json_has_no_secret_tokens(&json);
            assert_eq!(&serde_json::from_str::<IpcResponse>(&json).unwrap(), resp);
        }
    }

    /// A full [`LearningStatus`] with one row, every field set.
    fn learning_status_sample() -> LearningStatus {
        LearningStatus {
            state: "shadow".into(),
            contacts: 3,
            networks: 2,
            relays: 1,
            carriers: 7,
            observations_24h: 40,
            probes_24h: 4,
            dropped_24h: 1,
            contradictions: 0,
            would_reorder_24h: 2,
            saved_age_s: Some(120),
            rows: vec![LearningRow {
                peer_pub_hex: "ab".repeat(32),
                order: vec!["internet_dial".into(), "lan_dial".into(), "p2p_dial".into()],
                why: "learn: state=shadow order=internet,lan,p2p why=shadow".into(),
            }],
        }
    }

    /// The learning ops (P6.10): both requests and both answers round-trip
    /// as the exact JSON below, an optional key is not written while unset,
    /// another IPC version is refused as for every op, and a `LearningPlan`
    /// without its key is no request.
    #[test]
    fn learning_ops_round_trip() {
        let key = "ab".repeat(32);
        for (req, want) in [
            (
                IpcRequest::LearningPlan {
                    v: IPC_VERSION,
                    peer_pub_hex: key.clone(),
                },
                format!(r#"{{"op":"learning_plan","v":1,"peer_pub_hex":"{key}"}}"#),
            ),
            (
                IpcRequest::LearningReset {
                    v: IPC_VERSION,
                    peer_pub_hex: Some(key.clone()),
                },
                format!(r#"{{"op":"learning_reset","v":1,"peer_pub_hex":"{key}"}}"#),
            ),
            (
                IpcRequest::LearningReset {
                    v: IPC_VERSION,
                    peer_pub_hex: None,
                },
                r#"{"op":"learning_reset","v":1}"#.to_string(),
            ),
        ] {
            let f = encode_request(&req).unwrap();
            let raw = std::str::from_utf8(&f[4..]).unwrap();
            assert_eq!(raw, want);
            assert_json_has_no_secret_tokens(raw);
            assert_eq!(decode_request_checked(&f).unwrap(), req);
        }
        for body in [
            format!(r#"{{"op":"learning_plan","v":2,"peer_pub_hex":"{key}"}}"#),
            r#"{"op":"learning_reset","v":2}"#.to_string(),
        ] {
            let err = decode_request_checked(&frame_of(body.as_bytes())).unwrap_err();
            assert_eq!(err.code, "IPC_VERSION", "{body}");
        }
        let err =
            decode_request_checked(&frame_of(br#"{"op":"learning_plan","v":1}"#)).unwrap_err();
        assert_eq!(err.code, "IPC_FRAME");
        for (resp, want) in [
            (
                IpcResponse::LearningPlan {
                    v: IPC_VERSION,
                    order: vec!["lan_dial".into(), "internet_dial".into()],
                    why: "learn: state=on order=lan,internet why=kept".into(),
                    state: "on".into(),
                    carry: Vec::new(),
                },
                r#"{"ok":"learning_plan","v":1,"order":["lan_dial","internet_dial"],"why":"learn: state=on order=lan,internet why=kept","state":"on"}"#.to_string(),
            ),
            (
                IpcResponse::LearningPlan {
                    v: IPC_VERSION,
                    order: vec!["lan_dial".into()],
                    why: "learn: state=on order=lan why=cold".into(),
                    state: "on".into(),
                    carry: vec![LearningCarry {
                        peer_pub_hex: key.clone(),
                        met: "often".into(),
                        delivered: 3,
                        outcomes: 4,
                    }],
                },
                format!(
                    r#"{{"ok":"learning_plan","v":1,"order":["lan_dial"],"why":"learn: state=on order=lan why=cold","state":"on","carry":[{{"peer_pub_hex":"{key}","met":"often","delivered":3,"outcomes":4}}]}}"#
                ),
            ),
            (
                IpcResponse::LearningReset {
                    v: IPC_VERSION,
                    cleared: 2,
                },
                r#"{"ok":"learning_reset","v":1,"cleared":2}"#.to_string(),
            ),
        ] {
            let rf = encode_response(&resp).unwrap();
            let raw = std::str::from_utf8(&rf[4..]).unwrap();
            assert_eq!(raw, want);
            assert_json_has_no_secret_tokens(raw);
            assert_eq!(decode_response(&rf).unwrap(), resp);
        }
        // P6.16: an ash from before carry choice reads a newer answer (its
        // `carry` ignored), and an older raven-node's answer has none.
        #[derive(Deserialize)]
        #[serde(tag = "ok", rename_all = "snake_case")]
        enum OlderAnswer {
            LearningPlan { order: Vec<String>, state: String },
        }
        let newer = format!(
            r#"{{"ok":"learning_plan","v":1,"order":["lan_dial"],"why":"","state":"on","carry":[{{"peer_pub_hex":"{key}","met":"often","delivered":1,"outcomes":1,"later":7}}]}}"#
        );
        let OlderAnswer::LearningPlan { order, state } = serde_json::from_str(&newer).unwrap();
        assert_eq!((order.len(), state.as_str()), (1, "on"));
        match decode_response(&frame_of(newer.as_bytes())).unwrap() {
            IpcResponse::LearningPlan { carry, .. } => assert_eq!(carry[0].delivered, 1),
            other => panic!("{other:?}"),
        }
        let older = br#"{"ok":"learning_plan","v":1,"order":[],"why":"","state":"off"}"#;
        match decode_response(&frame_of(older)).unwrap() {
            IpcResponse::LearningPlan { carry, .. } => assert!(carry.is_empty()),
            other => panic!("{other:?}"),
        }
        // The state words are the learning store's own.
        for state in crate::learning::explain::State::ALL {
            let resp = IpcResponse::LearningPlan {
                v: IPC_VERSION,
                order: Vec::new(),
                why: String::new(),
                state: state.token().into(),
                carry: Vec::new(),
            };
            assert_eq!(
                decode_response(&encode_response(&resp).unwrap()).unwrap(),
                resp
            );
        }
    }

    /// `Status.learning` (P6.10), modelled on route hints: state, counts
    /// and rows both ways through the codec, absent while the gate is shut,
    /// and a newer daemon's extra or missing fields still decode.
    #[test]
    fn status_learning_is_optional_and_round_trips() {
        let learning = learning_status_sample();
        let status = IpcResponse::Status {
            v: IPC_VERSION,
            bridge: false,
            store: false,
            relay: false,
            forward_pending: 0,
            capabilities: vec!["ipc".into()],
            p2p: None,
            pid: Some(7),
            lan_listen: None,
            last_paths: Vec::new(),
            route_hints: None,
            unreachable: Vec::new(),
            egress: None,
            lan_listen_wanted: None,
            lan_bind_error: None,
            clock_skew: Vec::new(),
            unanswered: Vec::new(),
            at_rest: None,
            lan: None,
            security: None,
            nearby: None,
            tor: None,
            learning: Some(Box::new(learning.clone())),
            locked: None,
            updates: None,
        };
        let f = encode_response(&status).unwrap();
        let json = std::str::from_utf8(&f[4..]).unwrap();
        assert_json_has_no_secret_tokens(json);
        assert!(
            json.ends_with(&format!(
                r#""learning":{{"state":"shadow","contacts":3,"networks":2,"relays":1,"carriers":7,"observations_24h":40,"probes_24h":4,"dropped_24h":1,"contradictions":0,"would_reorder_24h":2,"saved_age_s":120,"rows":[{{"peer_pub_hex":"{}","order":["internet_dial","lan_dial","p2p_dial"],"why":"learn: state=shadow order=internet,lan,p2p why=shadow"}}]}}}}"#,
                "ab".repeat(32)
            )),
            "{json}"
        );
        assert_eq!(decode_response(&f).unwrap(), status);
        // Never saved: no `saved_age_s`; no rows: an empty list.
        let fresh = LearningStatus {
            saved_age_s: None,
            rows: Vec::new(),
            ..learning
        };
        let fresh_json = serde_json::to_string(&fresh).unwrap();
        assert!(!fresh_json.contains("saved_age_s"), "{fresh_json}");
        assert!(fresh_json.ends_with(r#""rows":[]}"#), "{fresh_json}");
        assert_eq!(
            serde_json::from_str::<LearningStatus>(&fresh_json).unwrap(),
            fresh
        );
        // Gate shut: no field at all.
        let mut off = status.clone();
        if let IpcResponse::Status { learning, .. } = &mut off {
            *learning = None;
        }
        let off_json = String::from_utf8(encode_response(&off).unwrap()[4..].to_vec()).unwrap();
        assert!(!off_json.contains("learning"), "{off_json}");
        assert_eq!(
            decode_response(&encode_response(&off).unwrap()).unwrap(),
            off
        );
        // A newer daemon's extra fields, in the status and in a row, and
        // missing ones.
        match status_from(br#"{"ok":"status","v":1,"bridge":true,"store":true,"relay":false,"forward_pending":0,"capabilities":["ipc"],"learning":{"state":"on","contacts":2,"future":9,"rows":[{"peer_pub_hex":"ab","future":1}]}}"#) {
            IpcResponse::Status { learning, .. } => assert_eq!(
                learning.as_deref(),
                Some(&LearningStatus {
                    state: "on".into(),
                    contacts: 2,
                    rows: vec![LearningRow {
                        peer_pub_hex: "ab".into(),
                        ..LearningRow::default()
                    }],
                    ..LearningStatus::default()
                })
            ),
            other => panic!("{other:?}"),
        }
        assert_eq!(MAX_LEARNING_ROWS, 16);
    }

    /// An older daemon's Status (no `learning`) decodes with `None`, and a
    /// Status without it is written exactly as before.
    #[test]
    fn old_daemon_json_decodes_learning_none() {
        let old = br#"{"ok":"status","v":1,"bridge":true,"store":true,"relay":false,"forward_pending":0,"capabilities":["ipc"]}"#;
        let status = status_from(old);
        let IpcResponse::Status { learning, .. } = &status else {
            panic!("not a Status: {status:?}");
        };
        assert!(learning.is_none());
        let rf = encode_response(&status).unwrap();
        let raw = std::str::from_utf8(&rf[4..]).unwrap();
        assert!(!raw.contains("learning"), "{raw}");
        // `null` reads as absent too.
        match status_from(br#"{"ok":"status","v":1,"bridge":true,"store":true,"relay":false,"forward_pending":0,"capabilities":["ipc"],"learning":null}"#) {
            IpcResponse::Status { learning, .. } => assert!(learning.is_none()),
            other => panic!("{other:?}"),
        }
    }

    /// A daemon from before P6.10 decodes requests with an `IpcRequest`
    /// that has no learning ops: `decode_request_checked` maps the serde
    /// refusal of an unknown `op` to `IPC_FRAME`, which raven-node sends
    /// back as `Error { code: "IPC_FRAME" }`. The client reads that as
    /// "no learning here" (ash `ipc_client::learning_plan`).
    #[test]
    fn an_old_daemon_answers_learning_ops_with_ipc_frame() {
        /// The pre-P6.10 op set, as far as the decision goes: an internally
        /// tagged enum refuses any `op` it does not list.
        #[derive(Debug, Deserialize)]
        #[serde(tag = "op", rename_all = "snake_case")]
        #[allow(dead_code)]
        enum Older {
            Ping { v: u16 },
            Status { v: u16 },
            NearbyControl { v: u16, action: String },
        }
        /// The older daemon's decode, mapped as `decode_request_checked`
        /// maps a serde error.
        fn older_decode(frame: &[u8]) -> Result<Older, IpcDecodeError> {
            serde_json::from_slice::<Older>(&frame[4..])
                .map_err(|e| IpcDecodeError::new("IPC_FRAME", e.to_string()))
        }
        assert!(older_decode(&encode_request(&IpcRequest::status()).unwrap()).is_ok());
        for req in [
            IpcRequest::LearningPlan {
                v: IPC_VERSION,
                peer_pub_hex: "ab".repeat(32),
            },
            IpcRequest::LearningReset {
                v: IPC_VERSION,
                peer_pub_hex: None,
            },
        ] {
            let f = encode_request(&req).unwrap();
            let err = older_decode(&f).unwrap_err();
            assert_eq!(err.code, "IPC_FRAME", "{req:?}");
            assert!(err.message.contains("unknown variant"), "{}", err.message);
            // This build accepts the same bytes.
            assert_eq!(decode_request_checked(&f).unwrap(), req);
        }
        // The same path in this build, for an op it does not know.
        let err = decode_request_checked(&frame_of(br#"{"op":"learning_frobnicate","v":1}"#))
            .unwrap_err();
        assert_eq!(err.code, "IPC_FRAME");
        // The answer the client gets, through the codec.
        let resp = IpcResponse::Error {
            v: IPC_VERSION,
            code: "IPC_FRAME".into(),
            message: "unknown variant `learning_plan`".into(),
        };
        assert_eq!(
            decode_response(&encode_response(&resp).unwrap()).unwrap(),
            resp
        );
    }

    /// Every JSON key the learning ops and `Status.learning` write passes
    /// the secret-name denylist: collected from fully populated values, so
    /// a field added later is checked too.
    #[test]
    fn learning_fields_have_no_forbidden_tokens() {
        fn keys(value: &serde_json::Value, out: &mut Vec<String>) {
            match value {
                serde_json::Value::Object(map) => {
                    for (key, v) in map {
                        out.push(key.clone());
                        keys(v, out);
                    }
                }
                serde_json::Value::Array(items) => items.iter().for_each(|v| keys(v, out)),
                _ => {}
            }
        }
        let mut all = Vec::new();
        for value in [
            serde_json::to_value(IpcRequest::LearningPlan {
                v: IPC_VERSION,
                peer_pub_hex: "ab".repeat(32),
            }),
            serde_json::to_value(IpcRequest::LearningReset {
                v: IPC_VERSION,
                peer_pub_hex: Some("ab".repeat(32)),
            }),
            serde_json::to_value(IpcResponse::LearningPlan {
                v: IPC_VERSION,
                order: vec!["lan_dial".into()],
                why: "learn: state=on order=lan why=kept".into(),
                state: "on".into(),
                carry: vec![LearningCarry {
                    peer_pub_hex: "ab".repeat(32),
                    met: "often".into(),
                    delivered: 1,
                    outcomes: 1,
                }],
            }),
            serde_json::to_value(IpcResponse::LearningReset {
                v: IPC_VERSION,
                cleared: 1,
            }),
            serde_json::to_value(learning_status_sample()),
        ] {
            keys(&value.unwrap(), &mut all);
        }
        all.extend(["learning_plan", "learning_reset", "learning"].map(String::from));
        for key in [
            "op",
            "ok",
            "peer_pub_hex",
            "order",
            "why",
            "state",
            "cleared",
            "contacts",
            "networks",
            "relays",
            "carriers",
            "observations_24h",
            "probes_24h",
            "dropped_24h",
            "contradictions",
            "saved_age_s",
            "rows",
            "carry",
            "met",
            "delivered",
            "outcomes",
        ] {
            assert!(all.iter().any(|k| k == key), "{key} not written");
        }
        for key in &all {
            let lower = key.to_ascii_lowercase();
            assert!(
                !FORBIDDEN_FIELD_TOKENS.iter().any(|bad| lower.contains(bad)),
                "{key}"
            );
        }
    }
}
