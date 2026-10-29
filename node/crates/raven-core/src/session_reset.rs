//! Automatic recovery when a contact lost its Raven session state (RSR1).
//!
//! Design: `docs/design/2026-10-lost-state-recovery.md` (phase 2a). Normative
//! wire format: `protocol/RAVEN_SESSION_RESET_V1.md`.
//!
//! RSR1 is a raw Noise-transport plaintext frame, like RLB1. It rides only an
//! endpoint-authenticated Raven link (LAN direct, Internet direct, p2p direct)
//! and is never wrapped in RVN1, stored or forwarded. Requests travel alone in
//! a dedicated dial; replies only answer them.
//!
//! Everything here is behind [`session_reset_live_enabled`] (off in production;
//! `RAVEN_LAB_SESSION_RESET=1` unlocks it in debug builds).
//!
//! Proactive renewal ([`crate::session_renewal`]) shares [`ResetIo`] and
//! [`bound_offer`], never retires a session, and yields while retired rows exist.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::bridge::authenticated_object_digest;
use crate::clock::now_ms;
use crate::device_cert::DeviceCertificate;
use crate::envelope::{EnvType, Envelope};
use crate::identity::Identity;
use crate::indexed_session_store::{
    endpoint_device_hint, EndpointDeliveryState, InboundSessionMatch, IndexedSessionStore,
    IndexedSessionStoreError, SessionRetireCause,
};
use crate::lan_rlb1::LanBundle;

/// Phase 2a production gate (RSR1 kinds 1 and 2, retirement, re-seal).
pub const SESSION_RESET_PRODUCTION_ENABLED: bool = false;
/// Phase 2b production gate (restore from an older backup).
pub const SESSION_RESET_RESTORE_PRODUCTION_ENABLED: bool = false;
const _: () =
    assert!(!SESSION_RESET_RESTORE_PRODUCTION_ENABLED || SESSION_RESET_PRODUCTION_ENABLED);

/// `RAVEN_LAB_SESSION_RESET` = 1 (2a) | 2 (2a + 2b). Debug builds only; release
/// binaries always read 0. Independent of `RAVEN_LAB_TEST_A`.
fn lab_session_reset_level() -> u8 {
    if !cfg!(debug_assertions) {
        return 0;
    }
    if let Some(level) = LAB_OVERRIDE.with(std::cell::Cell::get) {
        return level;
    }
    lab_level_from(std::env::var("RAVEN_LAB_SESSION_RESET").ok().as_deref())
}

thread_local! {
    static LAB_OVERRIDE: std::cell::Cell<Option<u8>> = const { std::cell::Cell::new(None) };
}

/// In-process tests switch the lab level for the current thread only (the
/// environment variable would leak into every other test of the binary).
/// Ignored in release builds, like the variable.
#[doc(hidden)]
pub fn set_lab_session_reset_for_this_thread(level: Option<u8>) {
    LAB_OVERRIDE.with(|cell| cell.set(level));
}

fn lab_level_from(value: Option<&str>) -> u8 {
    match value.map(str::trim) {
        Some("1") => 1,
        Some("2") => 2,
        _ => 0,
    }
}

/// Session reset is live: the gate or the lab level, unless a security
/// notice holds it or marks `rsr1/1` BROKEN (P6.45, close-only).
pub fn session_reset_live_enabled() -> bool {
    (SESSION_RESET_PRODUCTION_ENABLED || lab_session_reset_level() >= 1)
        && crate::suite_policy::hold_allows(crate::suite_registry::FEATURE_SESSION_RESET)
}

/// Restore on top of a live session reset, unless a security notice holds
/// it (P6.45).
pub fn session_reset_restore_live_enabled() -> bool {
    session_reset_live_enabled()
        && (SESSION_RESET_RESTORE_PRODUCTION_ENABLED || lab_session_reset_level() >= 2)
        && crate::suite_policy::hold_allows(crate::suite_registry::FEATURE_SESSION_RESET_RESTORE)
}

// ---------------------------------------------------------------------------
// Constants (design §20)
// ---------------------------------------------------------------------------

/// Race with a peer-initiated session the peer has not yet confirmed.
pub const RESET_NO_SESSION_MIN_AGE_MS: u64 = 60_000;
/// In-flight traffic around a retirement before fork evidence counts.
pub const RESET_FORK_GRACE_MS: u64 = 60_000;
/// Fork evidence counts only an object made at least this long after the
/// retirement, by its own `created_at` (the clock skew an endpoint object
/// is accepted with: its sender's clock may run that far ahead of ours).
/// One made before, and delivered late (through a friend's custody, or an
/// ACK still owed), proves nothing: a contact whose early security re-key
/// closed a session answers NO_SESSION about it while its earlier ACKs and
/// messages in it may still be on their way (Phase 6 review sensing-1).
pub const RESET_FORK_MADE_AFTER_MS: u64 = crate::indexed_session_store::MAX_ENDPOINT_FUTURE_SKEW_MS;
/// How long fork evidence holds automatic handling.
pub const RESET_FORK_HOLD_MS: u64 = 86_400_000;
/// Automatic PairInit + re-seal rounds per peer per 24 h.
pub const RESET_MAX_AUTO_ROUNDS_PER_DAY: usize = 3;
/// Re-seals of one message (at most 4 copies ever exist).
pub const RESET_MAX_RESEALS_PER_MESSAGE: u8 = 3;
/// Crossed or duplicate rounds.
pub const RESET_PAIRINIT_COOLDOWN_MS: u64 = 60_000;
/// Re-seal targets about to expire are not used.
pub const RESET_TARGET_MIN_REMAINING_MS: u64 = 600_000;
/// Copies that could not be delivered in time end `expired`.
pub const RESET_RESEAL_MIN_REMAINING_MS: u64 = 30_000;
/// One day, the window of the automatic round cap.
pub const RESET_DAY_MS: u64 = 86_400_000;

// ---------------------------------------------------------------------------
// RSR1 v1 codec (design §6)
// ---------------------------------------------------------------------------

pub const RSR1_MAGIC: [u8; 4] = *b"RSR1";
pub const RSR1_VERSION: u8 = 1;
pub const RSR1_HEADER_LEN: usize = 78;
pub const RSR1_SIGNATURE_LEN: usize = 64;
pub const RSR1_MAX_FRAME: usize = crate::lan_noise::MAX_TRANSPORT_PLAINTEXT;
pub const RSR1_MAX_PINNED_JSON: usize = 8_192;
const SIGNING_DOMAIN: &[u8] = b"rvn1/session-reset/v1\0";

const QUERY_FIXED_LEN: usize = RSR1_HEADER_LEN + 4 + RSR1_SIGNATURE_LEN; // 146
const STATUS_FRAME_LEN: usize = RSR1_HEADER_LEN + 1 + 1 + 32 + 16 + RSR1_SIGNATURE_LEN; // 192
const PREKEY_STALE_FIXED_LEN: usize = RSR1_HEADER_LEN + 32 + 4 + RSR1_SIGNATURE_LEN; // 178
const PREKEY_STATUS_FRAME_LEN: usize = RSR1_HEADER_LEN + 1 + 32 + 4 + RSR1_SIGNATURE_LEN; // 179
/// Smallest canonical RVN1 envelope (`envelope::PREFIX_LEN`).
const MIN_QUERIED_ENVELOPE: usize = crate::envelope::PREFIX_LEN;
pub const RSR1_MAX_QUERIED_ENVELOPE: usize = RSR1_MAX_FRAME - QUERY_FIXED_LEN;

pub const RSR1_MALFORMED: &str = "RSR1_MALFORMED";
pub const RSR1_WRONG_SIGNER: &str = "RSR1_WRONG_SIGNER";
pub const RSR1_WRONG_SUBJECT: &str = "RSR1_WRONG_SUBJECT";
pub const RSR1_BAD_SIGNATURE: &str = "RSR1_BAD_SIGNATURE";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Rsr1Kind {
    SessionQuery = 1,
    SessionStatus = 2,
    PrekeyStale = 3,
    PrekeyStatus = 4,
}

impl Rsr1Kind {
    fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::SessionQuery),
            2 => Some(Self::SessionStatus),
            3 => Some(Self::PrekeyStale),
            4 => Some(Self::PrekeyStatus),
            _ => None,
        }
    }
}

/// SESSION_STATUS answer. 3 and 4 are phase 2b reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SessionStatusCode {
    Present = 1,
    NoSession = 2,
    SenderStateStale = 3,
    ReceiverStateStale = 4,
}

impl SessionStatusCode {
    fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Present),
            2 => Some(Self::NoSession),
            3 => Some(Self::SenderStateStale),
            4 => Some(Self::ReceiverStateStale),
            _ => None,
        }
    }
}

/// PREKEY_STATUS result (phase 2b).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PrekeyStatusCode {
    Renewed = 1,
    NoChangeNeeded = 2,
    GenerationCap = 3,
    ClockBehind = 4,
    StaleOffer = 5,
    InvalidProof = 6,
}

impl PrekeyStatusCode {
    fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Renewed),
            2 => Some(Self::NoChangeNeeded),
            3 => Some(Self::GenerationCap),
            4 => Some(Self::ClockBehind),
            5 => Some(Self::StaleOffer),
            6 => Some(Self::InvalidProof),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rsr1Body {
    SessionQuery {
        envelope: Vec<u8>,
    },
    SessionStatus {
        status: SessionStatusCode,
        echoed_env_type: u8,
        echoed_object: [u8; 32],
        echoed_mid: [u8; 16],
    },
    PrekeyStale {
        offered_bundle_hash: [u8; 32],
        pinned_bundle: Vec<u8>,
    },
    PrekeyStatus {
        result: PrekeyStatusCode,
        echoed_pinned: [u8; 32],
        current_id: u32,
    },
}

impl Rsr1Body {
    pub fn kind(&self) -> Rsr1Kind {
        match self {
            Self::SessionQuery { .. } => Rsr1Kind::SessionQuery,
            Self::SessionStatus { .. } => Rsr1Kind::SessionStatus,
            Self::PrekeyStale { .. } => Rsr1Kind::PrekeyStale,
            Self::PrekeyStatus { .. } => Rsr1Kind::PrekeyStatus,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rsr1Frame {
    pub signer_device: [u8; 32],
    pub subject_device: [u8; 32],
    /// Signer's clock. Signed, for logs only; never a validity check.
    pub created_at_ms: u64,
    pub body: Rsr1Body,
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rsr1Decode {
    /// Not an RSR1 frame (fewer than 4 bytes or another magic).
    NotRsr1,
    /// A version or kind this build does not know: dropped without a reply.
    Unsupported,
    Frame(Rsr1Frame),
}

pub fn is_rsr1(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && bytes[..4] == RSR1_MAGIC
}

fn be_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn arr<const N: usize>(bytes: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes[..N]);
    out
}

/// Strict decoder. Signature and binding checks are [`verify`]'s job.
pub fn decode(bytes: &[u8]) -> Result<Rsr1Decode, &'static str> {
    if !is_rsr1(bytes) {
        return Ok(Rsr1Decode::NotRsr1);
    }
    if bytes.len() < 6 {
        return Err(RSR1_MALFORMED);
    }
    if bytes[4] != RSR1_VERSION {
        return Ok(Rsr1Decode::Unsupported);
    }
    let Some(kind) = Rsr1Kind::from_u8(bytes[5]) else {
        return Ok(Rsr1Decode::Unsupported);
    };
    if bytes.len() < RSR1_HEADER_LEN + RSR1_SIGNATURE_LEN || bytes.len() > RSR1_MAX_FRAME {
        return Err(RSR1_MALFORMED);
    }
    let signer_device = arr::<32>(&bytes[6..38]);
    let subject_device = arr::<32>(&bytes[38..70]);
    let created_at_ms = u64::from_be_bytes(arr::<8>(&bytes[70..78]));
    let body_end = bytes.len() - RSR1_SIGNATURE_LEN;
    let body_bytes = &bytes[RSR1_HEADER_LEN..body_end];
    let body = match kind {
        Rsr1Kind::SessionQuery => {
            if body_bytes.len() < 4 {
                return Err(RSR1_MALFORMED);
            }
            let n = be_u32(&body_bytes[..4]) as usize;
            if !(MIN_QUERIED_ENVELOPE..=RSR1_MAX_QUERIED_ENVELOPE).contains(&n)
                || bytes.len() != QUERY_FIXED_LEN + n
            {
                return Err(RSR1_MALFORMED);
            }
            Rsr1Body::SessionQuery {
                envelope: body_bytes[4..].to_vec(),
            }
        }
        Rsr1Kind::SessionStatus => {
            if bytes.len() != STATUS_FRAME_LEN {
                return Err(RSR1_MALFORMED);
            }
            let status = SessionStatusCode::from_u8(body_bytes[0]).ok_or(RSR1_MALFORMED)?;
            let echoed_env_type = body_bytes[1];
            if echoed_env_type != EnvType::Message as u8 && echoed_env_type != EnvType::Ack as u8 {
                return Err(RSR1_MALFORMED);
            }
            Rsr1Body::SessionStatus {
                status,
                echoed_env_type,
                echoed_object: arr::<32>(&body_bytes[2..34]),
                echoed_mid: arr::<16>(&body_bytes[34..50]),
            }
        }
        Rsr1Kind::PrekeyStale => {
            if body_bytes.len() < 36 {
                return Err(RSR1_MALFORMED);
            }
            let n = be_u32(&body_bytes[32..36]) as usize;
            if !(1..=RSR1_MAX_PINNED_JSON).contains(&n) || bytes.len() != PREKEY_STALE_FIXED_LEN + n
            {
                return Err(RSR1_MALFORMED);
            }
            let pinned_bundle = body_bytes[36..].to_vec();
            if serde_json::from_slice::<serde_json::Value>(&pinned_bundle).is_err() {
                return Err(RSR1_MALFORMED);
            }
            Rsr1Body::PrekeyStale {
                offered_bundle_hash: arr::<32>(&body_bytes[..32]),
                pinned_bundle,
            }
        }
        Rsr1Kind::PrekeyStatus => {
            if bytes.len() != PREKEY_STATUS_FRAME_LEN {
                return Err(RSR1_MALFORMED);
            }
            Rsr1Body::PrekeyStatus {
                result: PrekeyStatusCode::from_u8(body_bytes[0]).ok_or(RSR1_MALFORMED)?,
                echoed_pinned: arr::<32>(&body_bytes[1..33]),
                current_id: be_u32(&body_bytes[33..37]),
            }
        }
    };
    Ok(Rsr1Decode::Frame(Rsr1Frame {
        signer_device,
        subject_device,
        created_at_ms,
        body,
        signature: arr::<64>(&bytes[body_end..]),
    }))
}

/// Binding and signature checks with fixed, redacted codes (design §6).
pub fn verify(
    bytes: &[u8],
    frame: &Rsr1Frame,
    expected_signer: &[u8; 32],
    local_device: &[u8; 32],
) -> Result<(), &'static str> {
    if frame.signer_device != *expected_signer {
        return Err(RSR1_WRONG_SIGNER);
    }
    if frame.subject_device != *local_device {
        return Err(RSR1_WRONG_SUBJECT);
    }
    if bytes.len() < RSR1_SIGNATURE_LEN {
        return Err(RSR1_MALFORMED);
    }
    let signed = signing_bytes(&bytes[..bytes.len() - RSR1_SIGNATURE_LEN]);
    if !Identity::verify(&frame.signer_device, &signed, &frame.signature) {
        return Err(RSR1_BAD_SIGNATURE);
    }
    Ok(())
}

fn signing_bytes(unsigned: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(SIGNING_DOMAIN.len() + unsigned.len());
    out.extend_from_slice(SIGNING_DOMAIN);
    out.extend_from_slice(unsigned);
    out
}

/// Encode and sign a frame from `signer` to `subject`.
pub fn encode_signed(
    signer: &Identity,
    subject_device: &[u8; 32],
    created_at_ms: u64,
    body: &Rsr1Body,
) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(STATUS_FRAME_LEN);
    out.extend_from_slice(&RSR1_MAGIC);
    out.push(RSR1_VERSION);
    out.push(body.kind() as u8);
    out.extend_from_slice(&signer.public_key_bytes());
    out.extend_from_slice(subject_device);
    out.extend_from_slice(&created_at_ms.to_be_bytes());
    match body {
        Rsr1Body::SessionQuery { envelope } => {
            if !(MIN_QUERIED_ENVELOPE..=RSR1_MAX_QUERIED_ENVELOPE).contains(&envelope.len()) {
                return Err(format!("{RSR1_MALFORMED}: queried envelope size"));
            }
            out.extend_from_slice(&(envelope.len() as u32).to_be_bytes());
            out.extend_from_slice(envelope);
        }
        Rsr1Body::SessionStatus {
            status,
            echoed_env_type,
            echoed_object,
            echoed_mid,
        } => {
            out.push(*status as u8);
            out.push(*echoed_env_type);
            out.extend_from_slice(echoed_object);
            out.extend_from_slice(echoed_mid);
        }
        Rsr1Body::PrekeyStale {
            offered_bundle_hash,
            pinned_bundle,
        } => {
            if !(1..=RSR1_MAX_PINNED_JSON).contains(&pinned_bundle.len()) {
                return Err(format!("{RSR1_MALFORMED}: pinned bundle size"));
            }
            out.extend_from_slice(offered_bundle_hash);
            out.extend_from_slice(&(pinned_bundle.len() as u32).to_be_bytes());
            out.extend_from_slice(pinned_bundle);
        }
        Rsr1Body::PrekeyStatus {
            result,
            echoed_pinned,
            current_id,
        } => {
            out.push(*result as u8);
            out.extend_from_slice(echoed_pinned);
            out.extend_from_slice(&current_id.to_be_bytes());
        }
    }
    let signature = signer.sign(&signing_bytes(&out));
    out.extend_from_slice(&signature);
    if out.len() > RSR1_MAX_FRAME {
        return Err(format!("{RSR1_MALFORMED}: frame too large"));
    }
    Ok(out)
}

/// The SESSION_QUERY a sealer sends alone, in a dedicated dial, for one of its
/// outstanding objects `envelope` (exact packed RVN1) to `peer`.
pub fn session_query_frame(
    identity: &Identity,
    peer: &[u8; 32],
    envelope: &[u8],
    now_ms: u64,
) -> Result<Vec<u8>, String> {
    let env = Envelope::unpack(envelope).ok_or_else(|| "queried object is not RVN1".to_string())?;
    if env.env_type != EnvType::Message as u8 && env.env_type != EnvType::Ack as u8 {
        return Err("only Message or Ack objects are queried".into());
    }
    encode_signed(
        identity,
        peer,
        now_ms,
        &Rsr1Body::SessionQuery {
            envelope: envelope.to_vec(),
        },
    )
}

/// Request kinds expect a reply in the same dial (raven-node dial classifier).
pub fn frame_expects_reply(frame: &[u8]) -> bool {
    is_rsr1(frame)
        && frame.len() >= 6
        && frame[4] == RSR1_VERSION
        && matches!(
            Rsr1Kind::from_u8(frame[5]),
            Some(Rsr1Kind::SessionQuery | Rsr1Kind::PrekeyStale)
        )
}

/// Reply kinds end a dial's collection (raven-node dial classifier).
pub fn frame_is_terminal_reply(frame: &[u8]) -> bool {
    is_rsr1(frame)
        && frame.len() >= 6
        && frame[4] == RSR1_VERSION
        && matches!(
            Rsr1Kind::from_u8(frame[5]),
            Some(Rsr1Kind::SessionStatus | Rsr1Kind::PrekeyStatus)
        )
}

// ---------------------------------------------------------------------------
// Receiver: answering SESSION_QUERY (design §7). Read-only.
// ---------------------------------------------------------------------------

/// At most one line per key per hour (receiver, worker and subject logs).
fn log_once_per_hour(key: [u8; 32], line: &str) {
    static LAST: Mutex<Option<HashMap<[u8; 32], Instant>>> = Mutex::new(None);
    let mut guard = LAST.lock().unwrap_or_else(|e| e.into_inner());
    let map = guard.get_or_insert_with(HashMap::new);
    let now = Instant::now();
    if map
        .get(&key)
        .is_some_and(|at| now.saturating_duration_since(*at) < Duration::from_secs(3600))
    {
        return;
    }
    if map.len() >= 1024 {
        map.clear();
    }
    map.insert(key, now);
    eprintln!("{line}");
}

/// The local device key (`ensure_local_device_certificate`'s device).
fn local_device_key(data_dir: &Path, identity: &Identity) -> Result<[u8; 32], String> {
    let (cert, _) = crate::device_cert::ensure_local_device_certificate(
        data_dir,
        identity,
        crate::paths::PRIMARY_DEVICE_ID,
    )?;
    Ok(cert.device_ed_pub)
}

/// Handle one inbound RSR1 frame on an authenticated link (called by
/// `dispatch_frame` with the gate on). `Err` closes the link, as for any
/// refused frame; `Ok(vec![])` drops the frame without a reply.
pub fn handle_inbound_rsr1(
    data_dir: &Path,
    identity: &Identity,
    peer: &LanBundle,
    noise_ed: &[u8; 32],
    frame: &[u8],
) -> Result<Vec<Vec<u8>>, String> {
    if !crate::lan_dispatch::peer_is_trusted(data_dir, peer)? {
        return Err("rsr1 refused: peer is not a local contact".into());
    }
    let decoded = match decode(frame).map_err(str::to_string)? {
        Rsr1Decode::Frame(decoded) => decoded,
        Rsr1Decode::NotRsr1 | Rsr1Decode::Unsupported => return Ok(Vec::new()),
    };
    let local_device = local_device_key(data_dir, identity)?;
    verify(frame, &decoded, noise_ed, &local_device).map_err(str::to_string)?;
    let Rsr1Body::SessionQuery { envelope } = &decoded.body else {
        // Replies never arrive as frames; kind 3 is phase 2b.
        return Ok(Vec::new());
    };
    let env = Envelope::unpack(envelope).ok_or_else(|| RSR1_MALFORMED.to_string())?;
    if env.env_type != EnvType::Message as u8 && env.env_type != EnvType::Ack as u8 {
        return Err(RSR1_MALFORMED.into());
    }
    // The queried object must be the asking contact's own (outer signature).
    if !env.verify(&peer.cert.device_ed_pub) {
        return Err("rsr1 refused: queried object is not signed by the contact".into());
    }
    if env.dest_device_hint != 0 && env.dest_device_hint != endpoint_device_hint(&local_device) {
        return Err("rsr1 refused: queried object is for another device".into());
    }
    let now = now_ms();
    let mut store = IndexedSessionStore::open(data_dir).map_err(|e| e.redacted_display())?;
    let found = store
        .match_inbound_session_detail(&peer.cert.device_ed_pub, envelope, now)
        .map_err(|e| e.redacted_display())?;
    let status = match found {
        InboundSessionMatch::Matched(_) => SessionStatusCode::Present,
        InboundSessionMatch::ClosedByRekey | InboundSessionMatch::NoMatch => {
            SessionStatusCode::NoSession
        }
    };
    let reply = encode_signed(
        identity,
        &peer.cert.device_ed_pub,
        now,
        &Rsr1Body::SessionStatus {
            status,
            echoed_env_type: env.env_type,
            echoed_object: authenticated_object_digest(&env),
            echoed_mid: env.message_id,
        },
    )?;
    if status == SessionStatusCode::NoSession {
        log_once_per_hour(
            peer.cert.device_ed_pub,
            no_session_note(found == InboundSessionMatch::ClosedByRekey),
        );
    }
    Ok(vec![reply])
}

/// The service log's line after a SESSION_QUERY answered NO_SESSION:
/// `closed_by_rekey` when the object was sealed in a session this node
/// closed itself after an early security re-key (it set up a new one with
/// the contact first), else when no session here matched (RAVEN lost it:
/// reinstalled, or restored from a backup). Phase 6 review re-verify,
/// sensing-1.
pub fn no_session_note(closed_by_rekey: bool) -> &'static str {
    if closed_by_rekey {
        "raven-node lan_direct: answered a contact's session check: no session (this computer \
         replaced that secure connection with a new one in a security re-key; the contact \
         sends what waited in it again; nothing needs doing here)"
    } else {
        "raven-node lan_direct: answered a contact's session check: no session (RAVEN was \
         reset here; the contact sets up a new secure connection)"
    }
}

// ---------------------------------------------------------------------------
// Sealer: applying the answer (design §8) and certificate renewal (§5.2)
// ---------------------------------------------------------------------------

pub const PEER_HAS_SESSION: &str = "PEER_HAS_SESSION";
pub const RESET_ECHO_MISMATCH: &str = "RESET_ECHO_MISMATCH";
pub const RESET_UNKNOWN_ECHO: &str = "RESET_UNKNOWN_ECHO";
pub const RESET_ALREADY_DELIVERED: &str = "RESET_ALREADY_DELIVERED";
pub const RESET_TRANSIENT_YOUNG_SESSION: &str = "RESET_TRANSIENT_YOUNG_SESSION";
pub const RESET_STALE_NEEDS_RESTORE_GATE: &str = "RESET_STALE_NEEDS_RESTORE_GATE";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryOutcome {
    Retired {
        session_id: [u8; 32],
        cause: SessionRetireCause,
    },
    Transient(&'static str),
    /// Closed, malformed, or an old peer: never a version verdict.
    NoAnswer,
}

/// Apply the replies of a dedicated SESSION_QUERY dial for `queried_envelope`
/// (one of our outstanding objects to `peer`). Run under the peer's send lock.
pub fn apply_query_replies(
    store: &mut IndexedSessionStore,
    local_device: &[u8; 32],
    peer: &[u8; 32],
    queried_envelope: &[u8],
    replies: &[Vec<u8>],
    now_ms: u64,
) -> Result<QueryOutcome, String> {
    let Some((bytes, frame)) = replies.iter().find_map(|reply| match decode(reply) {
        Ok(Rsr1Decode::Frame(frame)) if matches!(frame.body, Rsr1Body::SessionStatus { .. }) => {
            Some((reply, frame))
        }
        _ => None,
    }) else {
        return Ok(QueryOutcome::NoAnswer);
    };
    if verify(bytes, &frame, peer, local_device).is_err() {
        return Ok(QueryOutcome::NoAnswer);
    }
    let Rsr1Body::SessionStatus {
        status,
        echoed_env_type,
        echoed_object,
        echoed_mid,
    } = frame.body
    else {
        return Ok(QueryOutcome::NoAnswer);
    };
    let env = Envelope::unpack(queried_envelope)
        .ok_or_else(|| "queried object is not RVN1".to_string())?;
    let digest = authenticated_object_digest(&env);
    if echoed_env_type != env.env_type || echoed_object != digest || echoed_mid != env.message_id {
        return Ok(QueryOutcome::Transient(RESET_ECHO_MISMATCH));
    }
    let map = |e: IndexedSessionStoreError| e.redacted_display();
    let Some((row, delivery)) = store
        .outbound_by_digest_for_recipient(&digest, peer)
        .map_err(map)?
    else {
        return Ok(QueryOutcome::Transient(RESET_UNKNOWN_ECHO));
    };
    if matches!(
        delivery,
        Some(EndpointDeliveryState::Delivered | EndpointDeliveryState::Read)
    ) {
        return Ok(QueryOutcome::Transient(RESET_ALREADY_DELIVERED));
    }
    let Some(key) = store
        .record_key_for_session_id(&row.session_id)
        .map_err(map)?
    else {
        return Ok(QueryOutcome::Transient(RESET_UNKNOWN_ECHO));
    };
    let local_is_initiator = key.initiator_device_ed25519 == *local_device;
    let remote = if local_is_initiator {
        key.responder_device_ed25519
    } else {
        key.initiator_device_ed25519
    };
    if remote != *peer {
        return Ok(QueryOutcome::Transient(RESET_UNKNOWN_ECHO));
    }
    let cause = match status {
        SessionStatusCode::Present => return Ok(QueryOutcome::Transient(PEER_HAS_SESSION)),
        SessionStatusCode::NoSession => {
            if !local_is_initiator {
                // As responder we confirmed before the contact did: it confirms
                // only once it reads our PairResponse. A young session may just
                // not be confirmed there yet.
                let confirmed = match store
                    .session_reset_info(&row.session_id)
                    .map_err(map)?
                    .and_then(|info| info.confirmed_at_ms)
                {
                    Some(at) => at,
                    None => store
                        .session_created_at_ms(&row.session_id)
                        .map_err(map)?
                        .unwrap_or(now_ms)
                        .saturating_add(crate::prekey_lifecycle::MAX_PREKEY_FUTURE_SKEW_MS),
                };
                if now_ms < confirmed.saturating_add(RESET_NO_SESSION_MIN_AGE_MS) {
                    return Ok(QueryOutcome::Transient(RESET_TRANSIENT_YOUNG_SESSION));
                }
            }
            SessionRetireCause::PeerNoSession
        }
        SessionStatusCode::SenderStateStale | SessionStatusCode::ReceiverStateStale
            if !session_reset_restore_live_enabled() =>
        {
            return Ok(QueryOutcome::Transient(RESET_STALE_NEEDS_RESTORE_GATE));
        }
        SessionStatusCode::SenderStateStale => SessionRetireCause::PeerSaysOurSendStale,
        SessionStatusCode::ReceiverStateStale => SessionRetireCause::PeerReceiveStale,
    };
    store
        .retire_session(&key, peer, cause, now_ms)
        .map_err(map)?;
    Ok(QueryOutcome::Retired {
        session_id: row.session_id,
        cause,
    })
}

/// E2: the contact presented (on a Noise-bound offer) a valid certificate for
/// its own key that differs from the one bound into our sessions with it. It
/// can neither seal nor ACK under those sessions any more: retire them for
/// sending. Returns how many were retired. A denied lineage takes the
/// revocation path instead and retires nothing.
pub fn note_presented_cert(
    data_dir: &Path,
    store: &mut IndexedSessionStore,
    peer: &[u8; 32],
    presented: &DeviceCertificate,
    now_ms: u64,
) -> Result<usize, String> {
    if presented.device_ed_pub != *peer || presented.user_ed_pub != *peer {
        return Ok(0);
    }
    if presented.verify(now_ms).is_err() {
        return Ok(0);
    }
    if crate::outbox::peer_lineage_denied(data_dir, presented)? {
        return Ok(0);
    }
    // A revoked device of this key (legacy records match by device id only):
    // a new certificate never retires its sessions; revocation decides.
    if identity_revoked(data_dir, peer)? {
        return Ok(0);
    }
    let presented_hash =
        crate::pair_init::device_certificate_hash(presented).map_err(|e| e.to_string())?;
    let map = |e: IndexedSessionStoreError| e.redacted_display();
    let mut retired = 0;
    for key in store
        .unretired_sessions_for_peer_at(peer, now_ms)
        .map_err(map)?
    {
        if store.remote_certificate_digest(&key).map_err(map)? != presented_hash
            && store
                .retire_session(&key, peer, SessionRetireCause::PeerCertRenewed, now_ms)
                .map_err(map)?
        {
            retired += 1;
        }
    }
    Ok(retired)
}

/// The contact's own offer on a probe dial: `replies[0]` parses as RLB1,
/// verifies, and is the contact's key as both device and user.
pub fn bound_offer(replies: &[Vec<u8>], peer: &[u8; 32], now_ms: u64) -> Option<LanBundle> {
    let first = replies.first()?;
    let offer = crate::lan_rlb1::decode_offer(first).ok()?;
    crate::lan_dispatch::verify_lan_bundle(&offer, now_ms).ok()?;
    (offer.cert.device_ed_pub == *peer && offer.cert.user_ed_pub == *peer).then_some(offer)
}

/// FE1 (design §10): traffic made at `made_at_ms` (its envelope's
/// `created_at`) was committed on `key`. When the gate is on and we retired
/// that session because the contact said it had none, and the object was
/// made after that ([`RESET_FORK_MADE_AFTER_MS`]), someone still holds the
/// contact's state: record fork evidence. Best effort.
pub fn note_inbound_on_session(
    store: &mut IndexedSessionStore,
    key: &crate::indexed_session_store::IndexedSessionRecordKey,
    local_device: &[u8; 32],
    made_at_ms: u64,
    now_ms: u64,
) {
    if !session_reset_live_enabled() {
        return;
    }
    let Ok(sid) = store.session_id_for_record_key(key) else {
        return;
    };
    let local_is_initiator = key.initiator_device_ed25519 == *local_device;
    if let Ok(true) = store.note_inbound_on_retired(&sid, local_is_initiator, made_at_ms, now_ms) {
        log_once_per_hour(
            sid,
            "raven: a contact that said it lost your secure connection is still using it; \
             earlier messages to it are on hold (technical: PEER_IDENTITY_FORK)",
        );
    }
}

// ---------------------------------------------------------------------------
// Reset step: policy, target, PairInit, re-seal (design §9)
// ---------------------------------------------------------------------------

/// Outbox / ash codes (design §23). Stable strings.
pub mod code {
    /// Session retired; re-seal pending (transitional).
    pub const PEER_RESET: &str = "PEER_RESET";
    /// Held: no local-network route for automatic re-seal.
    pub const PEER_RESET_CONFIRM: &str = "PEER_RESET_CONFIRM";
    /// Held: 3 automatic rounds in 24 h.
    pub const PEER_RESET_LOOP: &str = "PEER_RESET_LOOP";
    /// Held: fork evidence (the contact's identity may be in use twice).
    pub const PEER_IDENTITY_FORK: &str = "PEER_IDENTITY_FORK";
    /// Pin refuses the contact's bundle; no renewal possible.
    pub const PEER_PREKEY_RESET: &str = crate::lan_dispatch::PEER_PREKEY_RESET;
    /// NOT SENT: every session retired and the contact is unreachable.
    pub const PEER_RESET_UNREACHABLE: &str = "PEER_RESET_UNREACHABLE";
    /// Body-less (RDAP) row in a retired session.
    pub const PEER_RESET_NO_BODY: &str = "PEER_RESET_NO_BODY";
    /// Per-message re-seal cap.
    pub const RESEAL_CAP: &str = "RESEAL_CAP";
}

/// Inputs of one reset step for one contact.
pub struct ResetEnv<'a> {
    pub data_dir: &'a Path,
    pub identity: &'a Identity,
    pub peer: [u8; 32],
    /// The contact's planned routes, preference order.
    pub routes: &'a [crate::outbox::OutboxRoute],
    /// `raven outbox resend`: the user confirmed the contact reset RAVEN.
    pub user_confirmed: bool,
    pub now_ms: u64,
}

/// How a caller runs store work and dials. ash holds the send lock for the
/// whole send (runs `f` inline); the worker takes the peer's lock per call and
/// never holds it across a dial.
pub trait ResetIo {
    fn locked(
        &mut self,
        f: &mut dyn FnMut(&mut IndexedSessionStore) -> Result<(), String>,
    ) -> Result<(), String>;
    fn dial(
        &mut self,
        route: &crate::outbox::OutboxRoute,
        frames: &[Vec<u8>],
    ) -> Result<Vec<Vec<u8>>, String>;
}

#[derive(Debug, Clone)]
pub struct Resealed {
    pub message_id: [u8; 16],
    pub old_session: [u8; 32],
    pub old_digest: [u8; 32],
    pub new: crate::indexed_session_store::EndpointOutbound,
}

#[derive(Debug, Clone, Default)]
pub struct ResealReport {
    pub resealed: Vec<Resealed>,
    pub delivered: Vec<[u8; 16]>,
    pub expired: Vec<[u8; 16]>,
    pub capped: Vec<[u8; 16]>,
    pub no_body: Vec<[u8; 16]>,
    /// Abandoned because the target lineage is revoked.
    pub revoked: Vec<[u8; 16]>,
    /// At the per-message cap: held until the user confirms.
    pub held_at_cap: Vec<[u8; 16]>,
    /// Ran out before its deadline: parked for the horizon step (the long
    /// message horizon's gate on; with it off these are `expired`).
    pub parked: Vec<[u8; 16]>,
}

impl ResealReport {
    pub fn is_empty(&self) -> bool {
        self.resealed.is_empty()
            && self.delivered.is_empty()
            && self.expired.is_empty()
            && self.capped.is_empty()
            && self.no_body.is_empty()
            && self.revoked.is_empty()
            && self.held_at_cap.is_empty()
            && self.parked.is_empty()
    }

    fn absorb(&mut self, other: ResealReport) {
        self.resealed.extend(other.resealed);
        self.delivered.extend(other.delivered);
        self.expired.extend(other.expired);
        self.capped.extend(other.capped);
        self.no_body.extend(other.no_body);
        self.revoked.extend(other.revoked);
        self.held_at_cap.extend(other.held_at_cap);
        self.parked.extend(other.parked);
    }
}

#[derive(Debug, Clone)]
pub enum ResetStep {
    /// No retired undelivered rows.
    Nothing,
    Resealed(ResealReport),
    Held {
        code: &'static str,
        rows: usize,
    },
    /// The probe or the PairInit dial failed: the caller backs off.
    Unreachable(String),
}

pub(crate) fn store_err(e: IndexedSessionStoreError) -> String {
    e.redacted_display()
}

/// The out body of `mid` to `peer`: the stage bound to `(session, digest)`, or
/// the ChatHistory row. `(body, created_at_ms)`.
pub(crate) fn outbound_body(
    data_dir: &Path,
    peer: &[u8; 32],
    session_id: &[u8; 32],
    digest: &[u8; 32],
    mid: &[u8; 16],
) -> Result<Option<(String, u64)>, String> {
    if let Some(staged) =
        crate::chat_history::load_staged_outbound_body(data_dir, mid).map_err(|e| e.to_string())?
    {
        let bound = staged.peer_pub_hex.eq_ignore_ascii_case(&hex::encode(peer))
            && staged
                .session_id_hex
                .eq_ignore_ascii_case(&hex::encode(session_id))
            && staged
                .object_digest_hex
                .eq_ignore_ascii_case(&hex::encode(digest));
        if bound {
            return Ok(Some((staged.body, staged.created_at_ms)));
        }
    }
    let history = crate::chat_history::ChatHistory::load(data_dir).map_err(|e| e.to_string())?;
    let mid_hex = hex::encode(mid);
    Ok(history
        .for_peer(&hex::encode(peer))
        .into_iter()
        .find(|e| {
            e.direction == "out"
                && e.message_id_hex.eq_ignore_ascii_case(&mid_hex)
                && !e.body.is_empty()
        })
        .map(|e| (e.body.clone(), e.created_at_ms)))
}

/// History `delivered` for `mid` (stage body first when present), stage cleared.
pub(crate) fn settle_history_delivered(
    data_dir: &Path,
    peer: &[u8; 32],
    mid: &[u8; 16],
) -> Result<(), String> {
    settle_history(data_dir, peer, mid, "delivered")
}

/// History `delivery` for `mid` (stage body first when present, whatever copy
/// the stage is bound to), stage cleared.
pub(crate) fn settle_history(
    data_dir: &Path,
    peer: &[u8; 32],
    mid: &[u8; 16],
    delivery: &str,
) -> Result<(), String> {
    match crate::chat_history::load_staged_outbound_body(data_dir, mid)
        .map_err(|e| e.to_string())?
    {
        Some(staged) if staged.peer_pub_hex.eq_ignore_ascii_case(&hex::encode(peer)) => {
            crate::lan_dispatch::persist_lan_chat_history(
                data_dir,
                "out",
                peer,
                mid,
                staged.created_at_ms,
                delivery,
                staged.body.as_bytes(),
            )?;
            crate::chat_history::clear_staged_outbound_body(data_dir, mid)
                .map_err(|e| e.to_string())
        }
        _ => {
            // A row the history never had is repaired by the stage reconcile.
            let _ = crate::lan_dispatch::mark_lan_chat_history_delivery(
                data_dir, "out", peer, mid, delivery,
            );
            Ok(())
        }
    }
}

pub(crate) fn authorized_local<'a>(
    identity: &'a Identity,
    cert: &'a DeviceCertificate,
    registry: &'a crate::device_cert::DeviceRegistry,
    now_ms: u64,
) -> Result<crate::indexed_session_store::AuthorizedEndpointDevice<'a>, String> {
    crate::indexed_session_store::AuthorizedEndpointDevice::authorize(
        cert, identity, registry, now_ms,
    )
    .map_err(store_err)
}

/// Hand a leftover Prepared Message row of `key` to the queue (history first).
pub(crate) fn hand_off_prepared(
    data_dir: &Path,
    store: &mut IndexedSessionStore,
    key: &crate::indexed_session_store::IndexedSessionRecordKey,
    peer: &[u8; 32],
    row: &crate::indexed_session_store::EndpointOutbound,
    local_device: &crate::indexed_session_store::AuthorizedEndpointDevice<'_>,
    now_ms: u64,
) -> Result<(), String> {
    let created = Envelope::unpack(&row.immutable_envelope_bytes)
        .map(|e| e.created_at)
        .unwrap_or(now_ms);
    let (sid, mid) = (row.session_id, row.message_id);
    let mut cb = |digest: &[u8; 32], _bytes: &[u8]| -> Result<[u8; 32], ()> {
        crate::lan_dispatch::ensure_outbound_queued_history(
            data_dir, peer, &sid, digest, &mid, created, None,
        )
        .map_err(|_| ())?;
        Ok(*digest)
    };
    store
        .retry_endpoint_outbound(key, &row.object_digest, local_device, now_ms, &mut cb)
        .map_err(store_err)?;
    Ok(())
}

/// Any revocation recorded for `peer`'s identity (see
/// `RevocationStore::identity_has_revocation`). Unreadable store: an error.
pub(crate) fn identity_revoked(data_dir: &Path, peer: &[u8; 32]) -> Result<bool, String> {
    Ok(crate::device_sync::RevocationStore::load_checked(data_dir)?.identity_has_revocation(peer))
}

/// A revoked identity's backlog in retired sessions is never sealed again:
/// give it up (history `failed`), as the revocation path does.
fn give_up_retired_for_revoked(
    data_dir: &Path,
    store: &mut IndexedSessionStore,
    peer: &[u8; 32],
    report: &mut ResealReport,
) -> Result<(), String> {
    for row in store
        .retired_undelivered_messages_for_recipient(peer)
        .map_err(store_err)?
    {
        let Some(key) = store
            .record_key_for_session_id(&row.session_id)
            .map_err(store_err)?
        else {
            continue;
        };
        crate::outbox::give_up_outbound(
            data_dir,
            store,
            &key,
            peer,
            &row.session_id,
            &row.object_digest,
            &row.message_id,
            crate::outbox::HISTORY_FAILED,
        )?;
        report.revoked.push(row.message_id);
    }
    Ok(())
}

/// Crash repair for re-sealed messages to `peer` (design §9.5). Idempotent;
/// run under the peer's lock before every attempt. Returns repairs made.
pub fn reconcile_resealed_outbound(
    data_dir: &Path,
    identity: &Identity,
    store: &mut IndexedSessionStore,
    peer: &[u8; 32],
    now_ms: u64,
) -> Result<usize, String> {
    let mut repaired = 0;
    for mid in store.resealed_message_ids(peer).map_err(store_err)? {
        let copies = store
            .message_copies_for_recipient(peer, &mid)
            .map_err(store_err)?;
        let delivered = copies.iter().any(|c| {
            matches!(
                c.delivery_state,
                Some(EndpointDeliveryState::Delivered | EndpointDeliveryState::Read)
            )
        });
        if delivered {
            // Sibling settlement: the other copies are never sent again.
            let mut changed = false;
            for copy in &copies {
                if copy.has_outbox_row
                    && !matches!(
                        copy.delivery_state,
                        Some(EndpointDeliveryState::Delivered | EndpointDeliveryState::Read)
                    )
                {
                    if let (Some(key), Some(digest)) = (
                        store
                            .record_key_for_session_id(&copy.session_id)
                            .map_err(store_err)?,
                        copy.object_digest,
                    ) {
                        changed |= store
                            .retire_outbound_copy(&key, &digest)
                            .map_err(store_err)?;
                    }
                }
            }
            let staged = crate::chat_history::load_staged_outbound_body(data_dir, &mid)
                .map_err(|e| e.to_string())?
                .is_some();
            if changed || staged {
                settle_history_delivered(data_dir, peer, &mid)?;
                repaired += 1;
            }
            continue;
        }
        let old = copies.iter().find(|c| c.retired && c.has_outbox_row);
        let live = copies.iter().find(|c| !c.retired && c.has_outbox_row);
        let (Some(old), Some(live)) = (old, live) else {
            continue;
        };
        let (Some(old_digest), Some(live_digest)) = (old.object_digest, live.object_digest) else {
            continue;
        };
        let (Some(old_key), Some(live_key)) = (
            store
                .record_key_for_session_id(&old.session_id)
                .map_err(store_err)?,
            store
                .record_key_for_session_id(&live.session_id)
                .map_err(store_err)?,
        ) else {
            continue;
        };
        // (a) Stage still bound to the old copy: re-bind it to the live one.
        if let Some(staged) = crate::chat_history::load_staged_outbound_body(data_dir, &mid)
            .map_err(|e| e.to_string())?
        {
            if staged
                .object_digest_hex
                .eq_ignore_ascii_case(&hex::encode(old_digest))
            {
                crate::chat_history::stage_outbound_body(
                    data_dir,
                    peer,
                    &live.session_id,
                    &live_digest,
                    &mid,
                    staged.created_at_ms,
                    &staged.body,
                )
                .map_err(|e| e.to_string())?;
            }
        }
        // (b) Live copy still Prepared: hand it to the queue.
        if let Some(row) = store
            .pending_endpoint_outbound_for_recipient(Some(peer))
            .map_err(store_err)?
            .into_iter()
            .find(|r| r.session_id == live.session_id && r.message_id == mid)
        {
            let (cert, registry) = crate::device_cert::ensure_local_device_certificate(
                data_dir,
                identity,
                crate::paths::PRIMARY_DEVICE_ID,
            )?;
            let local = authorized_local(identity, &cert, &registry, now_ms)?;
            hand_off_prepared(data_dir, store, &live_key, peer, &row, &local, now_ms)?;
        }
        // (c) The old copy is never sent again.
        store
            .retire_outbound_copy(&old_key, &old_digest)
            .map_err(store_err)?;
        repaired += 1;
    }
    Ok(repaired + reconcile_parked_outbound(data_dir, store, peer)?)
}

/// The long message horizon's part of [`reconcile_resealed_outbound`]
/// ([`crate::horizon`]): a parked message to `peer` that a late ACK settled
/// under another copy is delivered (row dropped, history `delivered`); one
/// with a live copy elsewhere is no longer parked; and a stage that still
/// names no copy ([`crate::horizon::SENTINEL_BINDING`]) or another one while
/// a live copy exists is bound to that copy. Follows the store, not the gate.
fn reconcile_parked_outbound(
    data_dir: &Path,
    store: &mut IndexedSessionStore,
    peer: &[u8; 32],
) -> Result<usize, String> {
    let mut repaired = 0;
    for row in store.parked_for_recipient(peer).map_err(store_err)? {
        let mid = row.message_id;
        let copies = store
            .message_copies_for_recipient(peer, &mid)
            .map_err(store_err)?;
        let delivered = copies.iter().any(|c| {
            matches!(
                c.delivery_state,
                Some(EndpointDeliveryState::Delivered | EndpointDeliveryState::Read)
            )
        });
        if delivered {
            settle_history_delivered(data_dir, peer, &mid)?;
            store.give_up_parked(peer, &mid).map_err(store_err)?;
            repaired += 1;
            continue;
        }
        if let Some(live) = copies.iter().find(|c| !c.retired && c.has_outbox_row) {
            rebind_stage_to_copy(data_dir, peer, &mid, live)?;
            store.give_up_parked(peer, &mid).map_err(store_err)?;
            repaired += 1;
        }
    }
    let peer_hex = hex::encode(peer);
    for staged in crate::chat_history::list_staged_outbound_bodies(data_dir)
        .map_err(|e| e.to_string())?
        .into_iter()
        .filter(|s| {
            s.peer_pub_hex.eq_ignore_ascii_case(&peer_hex) && crate::horizon::is_sentinel_stage(s)
        })
    {
        let Some(mid) = hex::decode(&staged.message_id_hex)
            .ok()
            .and_then(|raw| <[u8; 16]>::try_from(raw).ok())
        else {
            continue;
        };
        let copies = store
            .message_copies_for_recipient(peer, &mid)
            .map_err(store_err)?;
        if let Some(live) = copies.iter().find(|c| !c.retired && c.has_outbox_row) {
            rebind_stage_to_copy(data_dir, peer, &mid, live)?;
            repaired += 1;
        }
    }
    Ok(repaired)
}

/// Bind `mid`'s stage (when it names another copy, or none) to `live`.
fn rebind_stage_to_copy(
    data_dir: &Path,
    peer: &[u8; 32],
    mid: &[u8; 16],
    live: &crate::indexed_session_store::MessageCopy,
) -> Result<(), String> {
    let Some(digest) = live.object_digest else {
        return Ok(());
    };
    let Some(staged) =
        crate::chat_history::load_staged_outbound_body(data_dir, mid).map_err(|e| e.to_string())?
    else {
        return Ok(());
    };
    let bound = staged
        .session_id_hex
        .eq_ignore_ascii_case(&hex::encode(live.session_id))
        && staged
            .object_digest_hex
            .eq_ignore_ascii_case(&hex::encode(digest));
    if bound || !staged.peer_pub_hex.eq_ignore_ascii_case(&hex::encode(peer)) {
        return Ok(());
    }
    crate::chat_history::stage_outbound_body(
        data_dir,
        peer,
        &live.session_id,
        &digest,
        mid,
        staged.created_at_ms,
        &staged.body,
    )
    .map_err(|e| e.to_string())
}

/// A retired row whose envelope runs out: parked until its deadline with
/// the long message horizon's gate on ([`crate::outbox::park_or_give_up_expired`]),
/// otherwise given up as `expired` exactly as before.
fn expire_retired_row(
    data_dir: &Path,
    store: &mut IndexedSessionStore,
    old_key: &crate::indexed_session_store::IndexedSessionRecordKey,
    peer: &[u8; 32],
    row: &crate::indexed_session_store::EndpointOutbound,
    now_ms: u64,
    report: &mut ResealReport,
) -> Result<(), String> {
    match crate::outbox::park_or_give_up_expired(
        data_dir,
        store,
        old_key,
        peer,
        &row.session_id,
        &row.object_digest,
        &row.message_id,
        false,
        now_ms,
    )? {
        crate::outbox::ExpiredMessage::Parked { .. } => report.parked.push(row.message_id),
        crate::outbox::ExpiredMessage::GaveUp(_) => report.expired.push(row.message_id),
    }
    Ok(())
}

/// Terminal checks that need no target (design §9.4 steps 1, 3, 4 and the
/// original deadline): delivered siblings, body-less rows, the per-message cap
/// and messages whose own deadline is too close. Returns the remaining rows.
fn settle_terminal_rows(
    data_dir: &Path,
    store: &mut IndexedSessionStore,
    peer: &[u8; 32],
    user_confirmed: bool,
    now_ms: u64,
    report: &mut ResealReport,
) -> Result<usize, String> {
    let mut remaining = 0;
    for row in store
        .retired_undelivered_messages_for_recipient(peer)
        .map_err(store_err)?
    {
        let Some(old_key) = store
            .record_key_for_session_id(&row.session_id)
            .map_err(store_err)?
        else {
            continue;
        };
        let mid = row.message_id;
        let copies = store
            .message_copies_for_recipient(peer, &mid)
            .map_err(store_err)?;
        if let Some(delivered) = copies.iter().find(|c| {
            matches!(
                c.delivery_state,
                Some(EndpointDeliveryState::Delivered | EndpointDeliveryState::Read)
            )
        }) {
            crate::outbox::record_outbound_delivered(
                data_dir,
                store,
                peer,
                &delivered.session_id,
                &mid,
            )?;
            store
                .retire_outbound_copy(&old_key, &row.object_digest)
                .map_err(store_err)?;
            report.delivered.push(mid);
            continue;
        }
        if copies
            .iter()
            .any(|c| c.session_id != row.session_id && !c.retired)
        {
            // Already re-sealed; reconcile owns it.
            continue;
        }
        if outbound_body(data_dir, peer, &row.session_id, &row.object_digest, &mid)?.is_none() {
            store
                .abandon_undelivered_outbound(&old_key, &row.object_digest)
                .map_err(store_err)?;
            report.no_body.push(mid);
            continue;
        }
        if user_confirmed
            && store.reseal_count(peer, &mid).map_err(store_err)? >= RESET_MAX_RESEALS_PER_MESSAGE
        {
            crate::outbox::give_up_outbound(
                data_dir,
                store,
                &old_key,
                peer,
                &row.session_id,
                &row.object_digest,
                &mid,
                crate::outbox::HISTORY_FAILED,
            )?;
            report.capped.push(mid);
            continue;
        }
        let orig = Envelope::unpack(&row.immutable_envelope_bytes)
            .map(|e| e.expires_at)
            .unwrap_or(0);
        if orig <= now_ms.saturating_add(RESET_RESEAL_MIN_REMAINING_MS) {
            expire_retired_row(data_dir, store, &old_key, peer, &row, now_ms, report)?;
            continue;
        }
        remaining += 1;
    }
    Ok(remaining)
}

/// Re-seal every retired undelivered Message to `peer` into `target`, in the
/// original send order (design §9.4). Run under the peer's lock.
pub fn reseal_retired_outbound(
    data_dir: &Path,
    identity: &Identity,
    store: &mut IndexedSessionStore,
    peer: &[u8; 32],
    target: &crate::indexed_session_store::IndexedSessionRecordKey,
    user_confirmed: bool,
    now_ms: u64,
) -> Result<ResealReport, String> {
    let mut report = ResealReport::default();
    if identity_revoked(data_dir, peer)? {
        give_up_retired_for_revoked(data_dir, store, peer, &mut report)?;
        return Ok(report);
    }
    settle_terminal_rows(data_dir, store, peer, user_confirmed, now_ms, &mut report)?;
    let rows = store
        .retired_undelivered_messages_for_recipient(peer)
        .map_err(store_err)?;
    if rows.is_empty() {
        return Ok(report);
    }
    let (cert, registry) = crate::device_cert::ensure_local_device_certificate(
        data_dir,
        identity,
        crate::paths::PRIMARY_DEVICE_ID,
    )?;
    // Revocation, once: the lineage bound into the target session.
    let peer_cert =
        crate::lan_dispatch::session_bound_peer_certificate(data_dir, store, target, peer)?
            .ok_or_else(|| "no certificate is bound to the new session".to_string())?;
    match crate::lan_dispatch::refuse_if_session_lineage_revoked(data_dir, &cert, &peer_cert) {
        Ok(()) => {}
        Err(e) if e == crate::lan_dispatch::ATSAM_LINEAGE_REVOKED => {
            report.revoked = rows.iter().map(|r| r.message_id).collect();
            crate::outbox::abandon_undelivered_to_peer(data_dir, store, peer)?;
            return Ok(report);
        }
        // An unreadable revocation store decides nothing: try again later.
        Err(e) => return Err(e),
    }
    let local = authorized_local(identity, &cert, &registry, now_ms)?;
    let target_sid = store.session_id_for_record_key(target).map_err(store_err)?;
    let target_expires = store.session_expires_at(target).map_err(store_err)?;
    // Lane free, once: a leftover Prepared Message in the target blocks a seal.
    if let Some(row) = store
        .pending_endpoint_outbound_for_recipient(Some(peer))
        .map_err(store_err)?
        .into_iter()
        .find(|r| {
            r.session_id == target_sid
                && r.kind == crate::indexed_session_store::EndpointOutboundKind::Message
        })
    {
        hand_off_prepared(data_dir, store, target, peer, &row, &local, now_ms)?;
    }
    let mut rng = rand::rngs::OsRng;
    for row in rows {
        let Some(old_key) = store
            .record_key_for_session_id(&row.session_id)
            .map_err(store_err)?
        else {
            continue;
        };
        let mid = row.message_id;
        if store
            .live_copy_elsewhere(peer, &mid, &row.session_id)
            .map_err(store_err)?
        {
            continue;
        }
        // The lineage the row was sealed to: a backlog for a revoked lineage
        // never flows to the same key re-certified under another device id.
        if let Some(old_cert) =
            crate::lan_dispatch::session_bound_peer_certificate(data_dir, store, &old_key, peer)?
        {
            match crate::lan_dispatch::refuse_if_session_lineage_revoked(data_dir, &cert, &old_cert)
            {
                Ok(()) => {}
                Err(e) if e == crate::lan_dispatch::ATSAM_LINEAGE_REVOKED => {
                    crate::outbox::give_up_outbound(
                        data_dir,
                        store,
                        &old_key,
                        peer,
                        &row.session_id,
                        &row.object_digest,
                        &mid,
                        crate::outbox::HISTORY_FAILED,
                    )?;
                    report.revoked.push(mid);
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
        let Some((body, created)) =
            outbound_body(data_dir, peer, &row.session_id, &row.object_digest, &mid)?
        else {
            continue;
        };
        // Per-message cap: a row at the cap stays held until the user
        // confirms (with confirmation it was given up in settle_terminal_rows).
        if store.reseal_count(peer, &mid).map_err(store_err)? >= RESET_MAX_RESEALS_PER_MESSAGE {
            report.held_at_cap.push(mid);
            continue;
        }
        let orig = Envelope::unpack(&row.immutable_envelope_bytes)
            .map(|e| e.expires_at)
            .unwrap_or(0);
        let expires = orig.min(target_expires);
        if expires <= now_ms.saturating_add(RESET_RESEAL_MIN_REMAINING_MS) {
            expire_retired_row(data_dir, store, &old_key, peer, &row, now_ms, &mut report)?;
            continue;
        }
        store
            .bump_reseal_ledger(peer, &mid, orig, now_ms)
            .map_err(store_err)?;
        #[cfg(test)]
        fault::hit(fault::ResealFault::AfterLedger)?;
        let mut cb = |digest: &[u8; 32], _bytes: &[u8]| -> Result<[u8; 32], ()> {
            #[cfg(test)]
            fault::hit(fault::ResealFault::AfterW1).map_err(|_| ())?;
            crate::lan_dispatch::ensure_outbound_queued_history(
                data_dir,
                peer,
                &target_sid,
                digest,
                &mid,
                created,
                Some(&body),
            )
            .map_err(|_| ())?;
            Ok(*digest)
        };
        let new = store
            .reseal_message_envelope(
                target, &body, &mid, &local, now_ms, expires, now_ms, &mut rng, &mut cb,
            )
            .map_err(store_err)?;
        #[cfg(test)]
        fault::hit(fault::ResealFault::AfterW2)?;
        store
            .retire_outbound_copy(&old_key, &row.object_digest)
            .map_err(store_err)?;
        // Friends hold only the old copy: the new one is left again.
        let _ = crate::outbox::clear_object_custodians(data_dir, &mid, now_ms);
        report.resealed.push(Resealed {
            message_id: mid,
            old_session: row.session_id,
            old_digest: row.object_digest,
            new,
        });
    }
    Ok(report)
}

#[cfg(test)]
pub(crate) mod fault {
    use std::cell::Cell;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ResealFault {
        AfterLedger,
        AfterW1,
        AfterW2,
    }

    thread_local! {
        static ARMED: Cell<Option<ResealFault>> = const { Cell::new(None) };
    }

    pub fn arm(point: Option<ResealFault>) {
        ARMED.with(|cell| cell.set(point));
    }

    pub fn hit(point: ResealFault) -> Result<(), String> {
        if ARMED.with(Cell::get) == Some(point) {
            ARMED.with(|cell| cell.set(None));
            return Err(format!("injected crash at {point:?}"));
        }
        Ok(())
    }
}

pub(crate) fn first_pair_response(frames: &[Vec<u8>]) -> Option<crate::pair_init::PairResponse> {
    frames.iter().find_map(|packed| {
        match crate::pair_init_lan_oob::classify_packed_envelope(packed) {
            crate::pair_init_lan_oob::PairInitOobClassify::PairResponse(wire) => {
                crate::pair_init::decode_response(&wire).ok()
            }
            _ => None,
        }
    })
}

/// PairInit with the contact over `route`, from the contact's own Noise-bound
/// `offer`. Creates the session (recording `local_route` and `reset_round` at
/// creation, so failed rounds count too), dials without the lock, confirms.
pub fn pair_with_peer(
    data_dir: &Path,
    identity: &Identity,
    offer: &LanBundle,
    route: &crate::outbox::OutboxRoute,
    local_route: bool,
    reset_round: bool,
    io: &mut dyn ResetIo,
) -> Result<crate::indexed_session_store::IndexedSessionRecordKey, String> {
    let peer = offer.cert.device_ed_pub;
    let mut created = None;
    io.locked(&mut |store| {
        let (init, key) =
            crate::lan_dispatch::create_initiator_pair_init(data_dir, identity, offer)?;
        store
            .mark_session_initiated(&key, &peer, local_route, reset_round, now_ms())
            .map_err(store_err)?;
        created = Some((init, key));
        Ok(())
    })?;
    let (init, key) = created.ok_or_else(|| "pair init not created".to_string())?;
    let frame = crate::lan_dispatch::wrap_pair_init(identity, &init)?;
    let replies = io.dial(route, &[frame])?;
    let response = first_pair_response(&replies)
        .ok_or_else(|| "WAITING_FOR_PAIR_RESPONSE: no PairResponse".to_string())?;
    io.locked(&mut |store| {
        store
            .confirm_verified_pair_response(&key, &init, &response, now_ms())
            .map_err(store_err)
    })?;
    Ok(key)
}

/// Phase 6b S17: the daily round cap holding a contact's resets
/// (`SEC_RESET_LOOP`), noted once per hold (the contact and the round that
/// reached the cap), however often a step finds it held.
fn note_reset_loop(peer: &[u8; 32], last_round: Option<u64>) {
    /// Holds noted, newest last (at most this many contacts).
    const KEPT: usize = 256;
    static NOTED: Mutex<Vec<([u8; 32], Option<u64>)>> = Mutex::new(Vec::new());
    if !crate::security_sense::live() {
        return;
    }
    {
        let mut noted = NOTED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if noted.contains(&(*peer, last_round)) {
            return;
        }
        noted.retain(|(p, _)| p != peer);
        if noted.len() >= KEPT {
            noted.remove(0);
        }
        noted.push((*peer, last_round));
    }
    crate::security_sense::contact(
        crate::security_events::SecKind::ResetLoop,
        peer,
        crate::security_events::Via::Local,
    );
}

/// One reset step for `env.peer` (design §9.1): re-seal retired rows into a
/// session we may use, setting one up over a local-network route when needed.
pub fn run_reset_step(env: &ResetEnv, io: &mut dyn ResetIo) -> Result<ResetStep, String> {
    if !session_reset_live_enabled() {
        return Ok(ResetStep::Nothing);
    }
    let peer = env.peer;
    let (data_dir, identity, now) = (env.data_dir, env.identity, env.now_ms);
    let mut report = ResealReport::default();
    let mut remaining = 0usize;
    let mut fork_hold = false;
    let mut target = None;
    let mut rounds = 0usize;
    let mut last_round = None;
    let mut loop_hold = false;
    io.locked(&mut |store| {
        reconcile_resealed_outbound(data_dir, identity, store, &peer, now)?;
        if identity_revoked(data_dir, &peer)? {
            // Never PairInit or re-seal for a revoked identity.
            give_up_retired_for_revoked(data_dir, store, &peer, &mut report)?;
            remaining = 0;
            return Ok(());
        }
        remaining =
            settle_terminal_rows(data_dir, store, &peer, env.user_confirmed, now, &mut report)?;
        if remaining == 0 {
            return Ok(());
        }
        let state = store.peer_reset_state(&peer).map_err(store_err)?;
        let since = now
            .saturating_sub(RESET_DAY_MS)
            .max(state.user_confirmed_at_ms.unwrap_or(0));
        fork_hold = !env.user_confirmed && state.fork_evidence_at_ms.is_some_and(|at| at > since);
        if fork_hold {
            return Ok(());
        }
        // P4 before any target: after three rounds today the backlog waits for
        // the user, even when some other session (an ordinary send's, say)
        // could carry it.
        rounds = store.reset_rounds_since(&peer, since).map_err(store_err)?;
        last_round = store.last_reset_round_at(&peer).map_err(store_err)?;
        loop_hold = !env.user_confirmed && rounds >= RESET_MAX_AUTO_ROUNDS_PER_DAY;
        if loop_hold {
            return Ok(());
        }
        target = store
            .reseal_target_for_peer(&peer, env.user_confirmed, now)
            .map_err(store_err)?;
        if let Some(target) = &target {
            report.absorb(reseal_retired_outbound(
                data_dir,
                identity,
                store,
                &peer,
                target,
                env.user_confirmed,
                now,
            )?);
        }
        Ok(())
    })?;
    if remaining == 0 {
        return Ok(if report.is_empty() {
            ResetStep::Nothing
        } else {
            ResetStep::Resealed(report)
        });
    }
    if fork_hold {
        return Ok(ResetStep::Held {
            code: code::PEER_IDENTITY_FORK,
            rows: remaining,
        });
    }
    if loop_hold {
        note_reset_loop(&peer, last_round);
        return Ok(ResetStep::Held {
            code: code::PEER_RESET_LOOP,
            rows: remaining,
        });
    }
    if target.is_some() {
        // Rows at the per-message cap wait for the user: say so instead of
        // reporting an empty re-seal.
        if report.resealed.is_empty() && !report.held_at_cap.is_empty() {
            return Ok(ResetStep::Held {
                code: code::PEER_RESET_LOOP,
                rows: report.held_at_cap.len(),
            });
        }
        return Ok(ResetStep::Resealed(report));
    }
    if last_round.is_some_and(|at| now < at.saturating_add(RESET_PAIRINIT_COOLDOWN_MS)) {
        return Ok(ResetStep::Held {
            code: code::PEER_RESET,
            rows: remaining,
        });
    }
    // P2, locality: automatic re-seal only into a session we set up over a
    // local-network route; anything else waits for the user.
    let local = env.routes.iter().find_map(|r| {
        (r.carrier == crate::outbox::OutboxCarrier::Lan)
            .then(|| {
                crate::outbox::localize_lan_route(r, false, crate::outbox::LOCALIZE_RESOLVE_TIMEOUT)
                    .ok()
            })
            .flatten()
    });
    let (route, local_route) = match (local, env.user_confirmed, env.routes.first()) {
        (Some(route), _, _) => (route, true),
        (None, true, Some(first)) => (first.clone(), false),
        (None, true, None) => return Ok(ResetStep::Unreachable("no route to the contact".into())),
        (None, false, _) => {
            return Ok(ResetStep::Held {
                code: code::PEER_RESET_CONFIRM,
                rows: remaining,
            })
        }
    };
    let replies = match io.dial(&route, &[]) {
        Ok(replies) => replies,
        Err(e) => return Ok(ResetStep::Unreachable(e)),
    };
    let Some(offer) = bound_offer(&replies, &peer, now) else {
        return Ok(ResetStep::Unreachable(
            "the contact's offer did not verify".into(),
        ));
    };
    crate::lan_dispatch::cache_peer_bundle(data_dir, &offer)?;
    io.locked(&mut |store| {
        note_presented_cert(data_dir, store, &peer, &offer.cert, now).map(|_| ())
    })?;
    if let Err(e) = pair_with_peer(data_dir, identity, &offer, &route, local_route, true, io) {
        if e.starts_with(code::PEER_PREKEY_RESET) {
            return Ok(ResetStep::Held {
                code: code::PEER_PREKEY_RESET,
                rows: remaining,
            });
        }
        return Ok(ResetStep::Unreachable(e));
    }
    let mut target = None;
    io.locked(&mut |store| {
        target = store
            .reseal_target_for_peer(&peer, env.user_confirmed, now)
            .map_err(store_err)?;
        if let Some(target) = &target {
            report.absorb(reseal_retired_outbound(
                data_dir,
                identity,
                store,
                &peer,
                target,
                env.user_confirmed,
                now,
            )?);
        }
        Ok(())
    })?;
    Ok(match target {
        Some(_) if report.resealed.is_empty() && !report.held_at_cap.is_empty() => {
            ResetStep::Held {
                code: code::PEER_RESET_LOOP,
                rows: report.held_at_cap.len(),
            }
        }
        Some(_) => ResetStep::Resealed(report),
        None => ResetStep::Held {
            code: code::PEER_RESET,
            rows: remaining,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alice() -> Identity {
        Identity::from_seed(&[0x51; 32])
    }

    fn bob() -> Identity {
        Identity::from_seed(&[0x52; 32])
    }

    fn sample_envelope(signer: &Identity) -> Vec<u8> {
        let mut env = Envelope {
            env_type: EnvType::Message as u8,
            flags: 0,
            message_id: [0x11; 16],
            routing_tag: [0x22; 16],
            dest_device_hint: 0,
            created_at: 1_760_000_000_000,
            expires_at: 1_760_086_400_000,
            hop_limit: 0,
            replication_budget: 0,
            anti_replay_nonce: [0x33; 12],
            ratchet_header_ciphertext: vec![],
            message_ciphertext: vec![0x44; 40],
            sender_authentication: vec![],
        };
        env.sign_with(signer);
        env.try_pack().unwrap()
    }

    fn status_body() -> Rsr1Body {
        Rsr1Body::SessionStatus {
            status: SessionStatusCode::NoSession,
            echoed_env_type: 1,
            echoed_object: [0x77; 32],
            echoed_mid: [0x11; 16],
        }
    }

    fn frame_of(bytes: &[u8]) -> Rsr1Frame {
        match decode(bytes).unwrap() {
            Rsr1Decode::Frame(frame) => frame,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn query_and_status_roundtrip_and_verify() {
        let (a, b) = (alice(), bob());
        let env = sample_envelope(&a);
        let query = session_query_frame(&a, &b.public_key_bytes(), &env, 7).unwrap();
        assert_eq!(query.len(), 146 + env.len());
        let frame = frame_of(&query);
        assert_eq!(frame.body, Rsr1Body::SessionQuery { envelope: env });
        assert_eq!(frame.created_at_ms, 7);
        verify(&query, &frame, &a.public_key_bytes(), &b.public_key_bytes()).unwrap();

        let status = encode_signed(&b, &a.public_key_bytes(), 9, &status_body()).unwrap();
        assert_eq!(status.len(), 192);
        let frame = frame_of(&status);
        assert_eq!(frame.body, status_body());
        verify(
            &status,
            &frame,
            &b.public_key_bytes(),
            &a.public_key_bytes(),
        )
        .unwrap();
        assert!(frame_expects_reply(&query) && !frame_is_terminal_reply(&query));
        assert!(frame_is_terminal_reply(&status) && !frame_expects_reply(&status));
    }

    #[test]
    fn prekey_kinds_roundtrip() {
        let (a, b) = (alice(), bob());
        let stale = Rsr1Body::PrekeyStale {
            offered_bundle_hash: [0x09; 32],
            pinned_bundle: br#"{"v":1}"#.to_vec(),
        };
        let bytes = encode_signed(&a, &b.public_key_bytes(), 1, &stale).unwrap();
        assert_eq!(bytes.len(), 178 + 7);
        assert_eq!(frame_of(&bytes).body, stale);
        let status = Rsr1Body::PrekeyStatus {
            result: PrekeyStatusCode::Renewed,
            echoed_pinned: [0x0a; 32],
            current_id: 0x0102_0304,
        };
        let bytes = encode_signed(&b, &a.public_key_bytes(), 1, &status).unwrap();
        assert_eq!(bytes.len(), 179);
        assert_eq!(frame_of(&bytes).body, status);
    }

    #[test]
    fn negatives_are_typed() {
        let (a, b) = (alice(), bob());
        let status = encode_signed(&b, &a.public_key_bytes(), 9, &status_body()).unwrap();
        // Wrong magic → not RSR1 at all.
        let mut other = status.clone();
        other[0] = b'X';
        assert_eq!(decode(&other).unwrap(), Rsr1Decode::NotRsr1);
        assert_eq!(decode(b"RS").unwrap(), Rsr1Decode::NotRsr1);
        // Version 2 and kind 9 are dropped without closing.
        let mut v2 = status.clone();
        v2[4] = 2;
        assert_eq!(decode(&v2).unwrap(), Rsr1Decode::Unsupported);
        let mut k9 = status.clone();
        k9[5] = 9;
        assert_eq!(decode(&k9).unwrap(), Rsr1Decode::Unsupported);
        // Truncated and one trailing byte.
        assert_eq!(decode(&status[..191]).unwrap_err(), RSR1_MALFORMED);
        let mut long = status.clone();
        long.push(0);
        assert_eq!(decode(&long).unwrap_err(), RSR1_MALFORMED);
        assert_eq!(decode(b"RSR1\x01").unwrap_err(), RSR1_MALFORMED);
        // Status 0 and 5.
        for bad in [0u8, 5] {
            let mut s = status.clone();
            s[78] = bad;
            assert_eq!(decode(&s).unwrap_err(), RSR1_MALFORMED);
        }
        // Echoed env_type other than Message/Ack.
        let mut s = status.clone();
        s[79] = 3;
        assert_eq!(decode(&s).unwrap_err(), RSR1_MALFORMED);
        // envelope_len 85 and too large.
        let env = sample_envelope(&a);
        let query = session_query_frame(&a, &b.public_key_bytes(), &env, 7).unwrap();
        let mut short = query.clone();
        short[78..82].copy_from_slice(&85u32.to_be_bytes());
        assert_eq!(decode(&short).unwrap_err(), RSR1_MALFORMED);
        let mut huge = query.clone();
        huge[78..82].copy_from_slice(&(RSR1_MAX_QUERIED_ENVELOPE as u32 + 1).to_be_bytes());
        assert_eq!(decode(&huge).unwrap_err(), RSR1_MALFORMED);
        assert!(encode_signed(
            &a,
            &b.public_key_bytes(),
            0,
            &Rsr1Body::SessionQuery {
                envelope: vec![0; 85]
            }
        )
        .is_err());
        // Kind 3 with invalid JSON.
        let mut stale = encode_signed(
            &a,
            &b.public_key_bytes(),
            1,
            &Rsr1Body::PrekeyStale {
                offered_bundle_hash: [0; 32],
                pinned_bundle: b"{}".to_vec(),
            },
        )
        .unwrap();
        stale[114] = b'x';
        assert_eq!(decode(&stale).unwrap_err(), RSR1_MALFORMED);
    }

    #[test]
    fn bad_signature_wrong_signer_and_wrong_subject() {
        let (a, b) = (alice(), bob());
        let c = Identity::from_seed(&[0x53; 32]);
        let status = encode_signed(&b, &a.public_key_bytes(), 9, &status_body()).unwrap();
        let frame = frame_of(&status);
        assert_eq!(
            verify(
                &status,
                &frame,
                &c.public_key_bytes(),
                &a.public_key_bytes()
            ),
            Err(RSR1_WRONG_SIGNER)
        );
        assert_eq!(
            verify(
                &status,
                &frame,
                &b.public_key_bytes(),
                &c.public_key_bytes()
            ),
            Err(RSR1_WRONG_SUBJECT)
        );
        let mut tampered = status.clone();
        tampered[80] ^= 1;
        let frame = frame_of(&tampered);
        assert_eq!(
            verify(
                &tampered,
                &frame,
                &b.public_key_bytes(),
                &a.public_key_bytes()
            ),
            Err(RSR1_BAD_SIGNATURE)
        );
        // A frame signed by C claiming to be B fails the signature check.
        let mut forged = encode_signed(&c, &a.public_key_bytes(), 9, &status_body()).unwrap();
        forged[6..38].copy_from_slice(&b.public_key_bytes());
        let frame = frame_of(&forged);
        assert_eq!(
            verify(
                &forged,
                &frame,
                &b.public_key_bytes(),
                &a.public_key_bytes()
            ),
            Err(RSR1_BAD_SIGNATURE)
        );
    }

    #[test]
    fn created_at_years_off_is_still_accepted() {
        let (a, b) = (alice(), bob());
        for at in [0u64, u64::MAX, 4_000_000_000_000] {
            let status = encode_signed(&b, &a.public_key_bytes(), at, &status_body()).unwrap();
            let frame = frame_of(&status);
            verify(
                &status,
                &frame,
                &b.public_key_bytes(),
                &a.public_key_bytes(),
            )
            .unwrap();
        }
    }

    /// Domain separation: a signature over the same bytes under another Raven
    /// domain, or with no domain, never verifies as RSR1.
    #[test]
    fn signatures_from_other_domains_do_not_verify() {
        let (a, b) = (alice(), bob());
        let status = encode_signed(&b, &a.public_key_bytes(), 9, &status_body()).unwrap();
        let unsigned = &status[..status.len() - 64];
        for domain in [
            &b""[..],
            b"RVN1",
            b"rvn1/pair-response",
            b"rvn1/ack",
            b"rvn1/session-reset/v1",
        ] {
            let mut msg = domain.to_vec();
            msg.extend_from_slice(unsigned);
            let mut forged = unsigned.to_vec();
            forged.extend_from_slice(&b.sign(&msg));
            let frame = frame_of(&forged);
            assert_eq!(
                verify(
                    &forged,
                    &frame,
                    &b.public_key_bytes(),
                    &a.public_key_bytes()
                ),
                Err(RSR1_BAD_SIGNATURE),
                "{}",
                String::from_utf8_lossy(domain)
            );
        }
        assert!(!b"rvn1/session-reset/v1\0".starts_with(b"RVN1"));
    }

    #[test]
    fn lab_switch_parses_only_known_levels() {
        assert_eq!(lab_level_from(None), 0);
        assert_eq!(lab_level_from(Some("1")), 1);
        assert_eq!(lab_level_from(Some(" 2 ")), 2);
        assert_eq!(lab_level_from(Some("3")), 0);
        assert_eq!(lab_level_from(Some("yes")), 0);
    }

    #[test]
    fn session_reset_lab_switch_is_inert_without_debug_assertions() {
        if cfg!(debug_assertions) {
            return;
        }
        // SAFETY: release test job; no other test reads this variable.
        unsafe { std::env::set_var("RAVEN_LAB_SESSION_RESET", "2") };
        assert_eq!(lab_session_reset_level(), 0);
        assert!(!session_reset_live_enabled());
        assert!(!session_reset_restore_live_enabled());
    }

    fn vectors_dir() -> std::path::PathBuf {
        let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.pop();
        p.pop();
        p.pop();
        p.join("shared-vectors/rvn1/session_reset")
    }

    /// KATs: fixed seeds, exact signing bytes and signature. Regenerate with
    /// `RAVEN_REGEN_RSR1_VECTORS=1` only when the wire format changes on purpose.
    #[test]
    fn rsr1_known_answer_vectors() {
        let a_seed = [0x51u8; 32];
        let b_seed = [0x52u8; 32];
        let (a, b) = (Identity::from_seed(&a_seed), Identity::from_seed(&b_seed));
        let env = sample_envelope(&a);
        let query =
            session_query_frame(&a, &b.public_key_bytes(), &env, 1_760_000_000_123).unwrap();
        let status =
            encode_signed(&b, &a.public_key_bytes(), 1_760_000_000_456, &status_body()).unwrap();
        let cases = [
            (
                "rsr1_session_query_001.json",
                "SESSION_QUERY (kind 1) from A to B",
                &a_seed,
                &b,
                &query,
            ),
            (
                "rsr1_session_status_001.json",
                "SESSION_STATUS NO_SESSION (kind 2) from B to A",
                &b_seed,
                &a,
                &status,
            ),
        ];
        for (name, what, signer_seed, subject, bytes) in cases {
            let unsigned = &bytes[..bytes.len() - 64];
            let expected = serde_json::json!({
                "name": what,
                "protocol_version": "rvn1",
                "deterministic": true,
                "description": "RSR1 v1 frame; signature = Ed25519(signer, domain || bytes[0..end-64])",
                "inputs": {
                    "signer_seed_hex": hex::encode(signer_seed),
                    "subject_device_hex": hex::encode(subject.public_key_bytes()),
                    "signing_domain": "rvn1/session-reset/v1\\0",
                },
                "expected": {
                    "signing_bytes_hex": hex::encode(signing_bytes(unsigned)),
                    "signature_hex": hex::encode(&bytes[bytes.len() - 64..]),
                    "frame_hex": hex::encode(bytes),
                    "frame_len": bytes.len(),
                },
            });
            let path = vectors_dir().join(name);
            if std::env::var("RAVEN_REGEN_RSR1_VECTORS").as_deref() == Ok("1") {
                std::fs::create_dir_all(vectors_dir()).unwrap();
                std::fs::write(
                    &path,
                    serde_json::to_string_pretty(&expected).unwrap() + "\n",
                )
                .unwrap();
            }
            let stored: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            assert_eq!(stored, expected, "{name}");
            let frame = frame_of(bytes);
            verify(
                bytes,
                &frame,
                &frame.signer_device,
                &subject.public_key_bytes(),
            )
            .unwrap();
        }
    }
}
