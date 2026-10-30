//! Indexed send: LanDial (Noise XX) or InternetDial (RIH1) + PairInit + ACK.
//!
//! Never uses `unsafe-demo-crypto` / public-key-derived `seal_message`.
//! Lab import files are optional leftovers; the live path uses RLB1 on the socket.
//! InternetDial is lab-gated and is not a WAN claim.

use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant};

use raven_core::device_cert::{ensure_local_device_certificate, DeviceCertificate, DeviceRegistry};
use raven_core::envelope::Envelope;
use raven_core::identity::Identity;
use raven_core::indexed_session_store::{
    AuthorizedEndpointDevice, EndpointOutboundKind, IndexedSessionRecordKey, IndexedSessionStore,
};
use raven_core::ipc::{ipc_endpoint, IpcRequest, IpcResponse, IPC_VERSION};
use raven_core::lan_dispatch::{
    cache_peer_bundle, create_initiator_pair_init, find_confirmed_peer_session,
    find_sendable_peer_session, load_cached_peer_bundle, parse_peer_offer, wrap_pair_init,
};
use raven_core::outbox::{
    abandon_undelivered_to_peer, clear_object_routes, envelope_expires_at,
    finish_outbound_delivered, first_ack_frame, give_up_outbound, outbound_already_delivered,
    park_or_give_up_expired, peer_lineage_denied, record_object_routes, record_outbound_delivered,
    send_lock_busy, CarrierChoice, DeliveryPath, ExpiredMessage, GiveUp, OutboxCarrier,
    OutboxRoute, PeerSendLock, ACK_FOR_ANOTHER_MESSAGE, CONTACT_NOT_VERIFIED, HISTORY_FAILED,
};
use raven_core::pair_init_lan_oob::{classify_packed_envelope, PairInitOobClassify};
use raven_core::paths::PRIMARY_DEVICE_ID;
use raven_core::route_memory;
use raven_core::sanitize::sanitize_terminal_line;
use raven_core::session_reset::{
    apply_query_replies, note_presented_cert, run_reset_step, session_query_frame,
    session_reset_live_enabled, QueryOutcome, ResetEnv, ResetIo, ResetStep,
};

use super::ext::{
    earlier_unconfirmed_text, earlier_undelivered_text, friendly_send_error, not_sent_text,
    offline_stage_full_text, parked_text, peer_reset_unreachable_text, queue_full_text,
    queued_text, quoted_preview, recorded_locally_failed_text, unconfirmed_text, ResetWhy,
    RetryNote, SendCtx,
};
use super::trace_delivery;

// Shared palette (NO_COLOR / non-TTY aware), clock and strict pub_hex parser.
use super::{now_ms, parse_pub_hex_strict as parse_pub_hex, C_BOLD, C_DIM, C_GREEN, C_RESET};

const DEVICE_ID: &str = PRIMARY_DEVICE_ID;
const PEER_CERT_CACHE: &str = "peer_device_certs.json";
/// Mirrors raven-core `lan_dispatch::MAX_TRUSTED_PEER_CERT_KEYS`: the lab
/// import must not grow the shared peer cert cache past the production cap.
const MAX_PEER_CERT_CACHE_KEYS: usize = 256;
/// Longest one `ash send` waits for another send from this profile to the same
/// peer (another `ash send`, or raven-node's outbox retrying it; see
/// [`acquire_send_lock`]).
const PEER_SEND_LOCK_WAIT: Duration = Duration::from_secs(120);
/// Messages that may wait for one unreachable peer at once (queued or sent
/// without an ACK). Well inside the receiver's skipped-key window
/// (`MAX_SKIPPED_KEYS`) and the shared outbound stage (`MAX_STAGE_ENTRIES`).
const MAX_QUEUED_PER_PEER: usize = 32;
/// Offline queueing (to any peer) stops this short of the shared outbound stage
/// (`MAX_STAGE_ENTRIES` = 256 bodies, about 4 MiB), so queues for unreachable
/// contacts can never block sends to reachable ones.
const OFFLINE_STAGE_MAX_ENTRIES: usize = 192;
const OFFLINE_STAGE_MAX_BYTES: usize = 3 * 1024 * 1024;
/// Bindings and JSON framing of one stage entry beside its body (generous).
const STAGE_ENTRY_OVERHEAD: usize = 512;

/// The per-peer send lock shared with raven-node's outbox worker
/// ([`raven_core::outbox::PeerSendLock`]): pairing (first contact), the retry
/// of an earlier queued message, staging the new one and its dial run under it.
/// Without it, concurrent senders interleave in ways the store can only refuse
/// (two first-contact sends each ran PairInit; a burst lost texts to the single
/// outstanding-message slot). Under the lock the second sender finds the first
/// one's confirmed session and reuses it, and a burst goes out one by one.
///
/// It is taken *after* the RLB1 probe, so waiting on an unreachable peer is not
/// serialised, and an offline send (stage only, no dial) holds it just briefly.
/// Held per peer, so sends to different peers never wait on each other.
pub(crate) fn acquire_send_lock(
    data_dir: &Path,
    peer_device: &[u8; 32],
) -> Result<PeerSendLock, String> {
    acquire_send_lock_within(data_dir, peer_device, PEER_SEND_LOCK_WAIT)
}

/// [`acquire_send_lock`] for a send to `who`: when the lock is not free at
/// once, say so on stderr (one plain line) before the bounded wait, so a send
/// that waits behind raven-node's background retry (or another terminal) does
/// not look frozen.
fn acquire_send_lock_noting(
    data_dir: &Path,
    peer_device: &[u8; 32],
    who: &str,
) -> Result<PeerSendLock, String> {
    acquire_send_lock_noting_within(data_dir, peer_device, who, PEER_SEND_LOCK_WAIT, &mut |l| {
        eprintln!("{C_DIM}{l}{C_RESET}")
    })
}

fn acquire_send_lock_noting_within(
    data_dir: &Path,
    peer_device: &[u8; 32],
    who: &str,
    wait: Duration,
    note: &mut dyn FnMut(&str),
) -> Result<PeerSendLock, String> {
    match PeerSendLock::acquire_within(data_dir, peer_device, Duration::ZERO) {
        Ok(lock) => return Ok(lock),
        Err(e) if !send_lock_busy(&e) => {
            return Err(format!("NOT SENT, nothing queued: send lock: {e}"));
        }
        Err(_) => {}
    }
    note(&send_lock_waiting_text(who, wait));
    acquire_send_lock_within(data_dir, peer_device, wait)
}

/// The one line a send prints while it waits for the per-peer send lock.
fn send_lock_waiting_text(who: &str, wait: Duration) -> String {
    format!(
        "waiting: another send to {who} is in progress (raven-node retrying an earlier \
         message, or another terminal); this waits at most {}s",
        wait.as_secs()
    )
}

fn acquire_send_lock_within(
    data_dir: &Path,
    peer_device: &[u8; 32],
    wait: Duration,
) -> Result<PeerSendLock, String> {
    PeerSendLock::acquire_within(data_dir, peer_device, wait).map_err(|e| {
        if send_lock_busy(&e) {
            format!(
                "NOT SENT, nothing queued: another `ash send` to this peer from this \
                 profile (or raven-node's outbox retrying an earlier message) was still \
                 running after {}s; try again shortly",
                wait.as_secs()
            )
        } else {
            format!("NOT SENT, nothing queued: send lock: {e}")
        }
    })
}

/// How long a send waits for raven-node's `ContactReach` (it answers from
/// memory); an older or busy one: the send probes as before.
const CONTACT_REACH_WAIT: Duration = Duration::from_millis(700);

/// How long the RLB1 probe may take when the message can be queued anyway (a
/// confirmed session exists): `raven send` then ends within about 10 s and
/// raven-node's outbox keeps trying. A first message still waits for the
/// full dial, since it cannot be queued.
const QUEUEABLE_PROBE_TIMEOUT: Duration = Duration::from_secs(7);
/// The IPC wait of every other dial (just above the daemon's 45 s dial cap).
const DIAL_IPC_TIMEOUT: Duration = Duration::from_secs(50);
/// Probe rounds a first message gets when the friend's computer answered
/// and closed the link ([`probe_again`]), and the pause between them.
const FIRST_MESSAGE_PROBES: usize = 3;
const FIRST_MESSAGE_PROBE_PAUSE: Duration = Duration::from_secs(1);

/// Whether a first message (`first_message`: no session to queue it under,
/// so a failed probe is NOT SENT) probes its routes again after `errors`:
/// only when one of them shows that the friend's computer answered and then
/// closed the link (it refused us for now, as a contact book still held
/// while its key loads after a start or an unlock does, or the link closed
/// early). Nobody listening, no route, a silent address or a wrong identity
/// would only fail again (E1).
fn probe_again(first_message: bool, errors: &[String]) -> bool {
    use super::ext::{classify_cause, Cause};
    first_message
        && errors
            .iter()
            .any(|e| matches!(classify_cause(e), Cause::PeerRefused | Cause::ClosedEarly))
}

/// How long `raven send` waits for raven-node to accept an `OutboxKick`.
const OUTBOX_KICK_TIMEOUT: Duration = Duration::from_secs(2);
/// How long `raven send` waits for raven-node's learned probe order
/// (`LearningPlan`, Phase 6a); past it, today's order.
const LEARNING_PLAN_TIMEOUT: Duration = Duration::from_secs(2);

/// Refusal while the Internet carrier is closed (on in release builds since
/// 2026-10; a debug build closes it with `RAVEN_LAB_TEST_A=0`). Shared with
/// ext.rs, which refuses with it before it would start a daemon.
pub const INTERNET_DIRECT_HOLD: &str =
    "INTERNET_DIRECT_HOLD: Internet direct is closed in this process (a debug build with \
     RAVEN_LAB_TEST_A=0 or RAVEN_LAB_NEARBY_ONLY=1, or a security notice); release builds have \
     it on (INTERNET_DIRECT_PRODUCTION_ENABLED=true)";

/// Carrier for one indexed send. `Internet` and `P2p` are lab-only (not WAN
/// Proven).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DialCarrier {
    Lan,
    Internet,
    /// The libp2p carrier (P3): the dial is a p2p dial string such as
    /// `/p2p/<PeerId>` (raven-node dials the contact's addresses).
    P2p,
    /// Bluetooth nearby (Phase 5, RNL1): the dial is the contact's nearby
    /// route, `nearby:<64 hex>` (a name, never an address; raven-node
    /// finds the contact in radio range).
    Nearby,
    /// The Tor onion carrier (lab, RAVEN_ONION_CARRIER_V1): the dial is the
    /// contact's onion route, `onion:<64 hex>` (its onion key; raven-node's
    /// Tor helper turns it into an address).
    Onion,
}

impl DialCarrier {
    pub(crate) fn label(self) -> &'static str {
        self.outbox().label()
    }

    /// The same carrier in the shared outbox / route policy.
    pub(crate) fn outbox(self) -> OutboxCarrier {
        match self {
            Self::Lan => OutboxCarrier::Lan,
            Self::Internet => OutboxCarrier::Internet,
            Self::P2p => OutboxCarrier::P2p,
            Self::Nearby => OutboxCarrier::Nearby,
            Self::Onion => OutboxCarrier::Onion,
        }
    }

    /// Is `dial` a dial string this carrier can use (never the "local
    /// listen" placeholder)?
    pub(crate) fn plausible(self, dial: &str) -> bool {
        raven_core::outbox::plausible_route(&raven_core::OutboxRoute {
            carrier: self.outbox(),
            dial: dial.to_string(),
        })
    }

    /// This carrier's gate refusal, when its gate is closed.
    pub(crate) fn hold(self) -> Option<&'static str> {
        match self {
            Self::Lan => None,
            Self::Internet if !raven_core::internet_direct_live_enabled() => {
                Some(INTERNET_DIRECT_HOLD)
            }
            Self::P2p if !raven_core::p2p_live_enabled() => Some(raven_core::P2P_HOLD),
            Self::Nearby if !raven_core::nearby_live_enabled() => Some(raven_core::NEARBY_HOLD),
            Self::Onion if !raven_core::onion_live_enabled() => Some(raven_core::ONION_HOLD),
            _ => None,
        }
    }
}

/// Refusal for an Internet or p2p send to a contact that is not verified
/// (owner decision 2026-10-08: delivery beyond the LAN only for pinned
/// contacts). Nothing was dialled. `carrier`: `Internet` or `p2p`.
pub(crate) fn unverified_carrier_text(
    who: &str,
    carrier: &str,
    verify_cmd: &str,
    pin_cmd: &str,
) -> String {
    format!(
        "NOT SENT: {who} is not verified: {carrier} delivery needs the fingerprint checked \
         first. Compare it with {who} by phone or in person (run: {verify_cmd}), then pin it: \
         {pin_cmd}. Nothing was dialled. ({CONTACT_NOT_VERIFIED})"
    )
}

/// The word for `carrier` in user sentences.
pub(crate) fn carrier_word(carrier: DialCarrier) -> &'static str {
    match carrier {
        DialCarrier::Lan => "LAN",
        DialCarrier::Internet => "Internet",
        DialCarrier::P2p => "p2p",
        DialCarrier::Nearby => "nearby",
        DialCarrier::Onion => "Tor",
    }
}

/// What a send says it dials: the route's address, or for a nearby route
/// (a contact's key, not an address) `Bluetooth nearby`. Safe for the
/// terminal.
pub(crate) fn dial_shown(route: &DialRoute) -> String {
    match route.carrier {
        DialCarrier::Nearby => "Bluetooth nearby".into(),
        DialCarrier::Onion => "Tor".into(),
        _ => sanitize_terminal_line(&route.dial),
    }
}

/// The address a send's texts name for `route` (`SendCtx::dial`): none for
/// a nearby route, which has no address.
pub(crate) fn ctx_dial(route: &DialRoute) -> String {
    match route.carrier {
        DialCarrier::Nearby | DialCarrier::Onion => String::new(),
        _ => route.dial.trim().to_string(),
    }
}

/// What an older raven-node (`IPC_FRAME`) means for a nearby dial.
pub(crate) const NEARBY_TOO_OLD: &str = "raven-node is too old for nearby: update it";

/// What an older raven-node (`IPC_FRAME`) means for a Tor dial.
pub(crate) const ONION_TOO_OLD: &str = "raven-node is too old for Tor: update it";

/// The IPC wait of a Tor dial: raven-node's own (75 s) and a little more.
const ONION_IPC_TIMEOUT: Duration = Duration::from_secs(85);

/// How long ash waits for raven-node's answer to a dial asked to take
/// `timeout`: a Tor dial has Tor's waits (a first circuit takes 10-30 s);
/// the probe of a send that can queue (shorter than a dial, no frame) has
/// the send's Tor budget instead ([`ONION_SEND_BUDGET`]; E2 r40: a friend
/// that was offline cost 75 s per message; the outbox keeps Tor's full
/// wait).
fn ipc_dial_wait(carrier: DialCarrier, timeout: Duration, frameless: bool) -> Duration {
    match carrier {
        DialCarrier::Onion if timeout < DIAL_IPC_TIMEOUT && frameless => {
            timeout.max(ONION_SEND_BUDGET)
        }
        DialCarrier::Onion => timeout.max(ONION_IPC_TIMEOUT),
        _ => timeout,
    }
}

/// How long a send that can queue its message waits for Tor's check (E2
/// r40: a first Tor connect takes 6-12 s in the field, and a friend that
/// was offline cost 75 s per message). Past it the message is queued and
/// raven-node's outbox tries Tor first, with Tor's full wait.
pub(crate) const ONION_SEND_BUDGET: Duration = Duration::from_secs(25);

fn ensure_local_device_cert(
    data_dir: &Path,
    id: &Identity,
) -> Result<(DeviceCertificate, DeviceRegistry), String> {
    ensure_local_device_certificate(data_dir, id, DEVICE_ID)
}

/// Lab-only cert import write. Runs under raven-core's shared peer-cache lock
/// (which also recovers any staged cert+prekey commit first) and refuses to
/// rewrite a cache it cannot parse instead of silently dropping trusted certs.
fn cache_peer_cert(
    data_dir: &Path,
    peer_pub: &[u8; 32],
    cert: &DeviceCertificate,
) -> Result<(), String> {
    use raven_core::at_rest::{self, Kind};
    raven_core::with_prekey_store_lock(data_dir, || {
        let path = data_dir.join(PEER_CERT_CACHE);
        // Sealed (RMS1) in a sealed profile (privacy pack PP.5).
        let mut map: HashMap<String, DeviceCertificate> =
            match at_rest::load_bytes(data_dir, &path, Kind::PeerDeviceCerts) {
                Ok(Some(raw)) => serde_json::from_slice(&raw)
                    .map_err(|e| format!("peer cert cache corrupt — refusing overwrite: {e}"))?,
                Ok(None) => HashMap::new(),
                Err(e) if e.is_unavailable() => return Err(format!("peer cert cache read: {e}")),
                Err(e) => return Err(format!("peer cert cache corrupt — refusing overwrite: {e}")),
            };
        map.insert(hex::encode(peer_pub), cert.clone());
        if map.len() > MAX_PEER_CERT_CACHE_KEYS {
            return Err(format!(
                "peer cert cache full ({MAX_PEER_CERT_CACHE_KEYS} keys) — refusing lab import"
            ));
        }
        let out = serde_json::to_string_pretty(&map).map_err(|e| e.to_string())?;
        // The shared peer-cache lock is held: the file's writer lock.
        at_rest::write_held(data_dir, &path, Kind::PeerDeviceCerts, out.as_bytes())
            .map_err(|e| e.to_string())
    })
}

fn ipc_carrier_dial(
    data_dir: &Path,
    carrier: DialCarrier,
    dial: &str,
    expected_pub_hex: &str,
    frames: &[Vec<u8>],
) -> Result<Vec<Vec<u8>>, String> {
    ipc_carrier_dial_within(
        data_dir,
        carrier,
        dial,
        expected_pub_hex,
        frames,
        DIAL_IPC_TIMEOUT,
    )
}

/// [`ipc_carrier_dial`] that waits at most `timeout` for the daemon's answer.
/// Only for frame-less probes when shorter than the daemon's own dial cap: the
/// daemon may still finish such a dial, which sends nothing.
fn ipc_carrier_dial_within(
    data_dir: &Path,
    carrier: DialCarrier,
    dial: &str,
    expected_pub_hex: &str,
    frames: &[Vec<u8>],
    timeout: Duration,
) -> Result<Vec<Vec<u8>>, String> {
    ipc_carrier_dial_reply_within(data_dir, carrier, dial, expected_pub_hex, frames, timeout)
        .map(|r| r.frames)
}

/// A daemon dial's replies and how the link travelled (p2p: from the daemon,
/// absent from an older one; LAN and Internet direct are always direct).
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct DialReply {
    pub frames: Vec<Vec<u8>>,
    pub path: Option<DeliveryPath>,
}

/// [`ipc_carrier_dial_within`] with the reply's path ([`DialReply`]).
fn ipc_carrier_dial_reply_within(
    data_dir: &Path,
    carrier: DialCarrier,
    dial: &str,
    expected_pub_hex: &str,
    frames: &[Vec<u8>],
    timeout: Duration,
) -> Result<DialReply, String> {
    let req = dial_request(data_dir, carrier, dial, expected_pub_hex, frames)?;
    let wait = ipc_dial_wait(carrier, timeout, frames.is_empty());
    ipc_dial_answer(data_dir, carrier, dial, &req, wait, frames.is_empty())
}

/// The IPC dial request for raven-node, or why there is none (no IPC on this
/// computer, a route that is not one).
fn dial_request(
    data_dir: &Path,
    carrier: DialCarrier,
    dial: &str,
    expected_pub_hex: &str,
    frames: &[Vec<u8>],
) -> Result<IpcRequest, String> {
    use base64::Engine;
    let ep = ipc_endpoint(data_dir);
    if !ep.transport_available() {
        return Err("ipc_transport_missing".into());
    }
    if dial.trim().is_empty()
        || dial.eq_ignore_ascii_case("local-listen")
        || dial.eq_ignore_ascii_case("local")
        || (matches!(
            carrier,
            DialCarrier::P2p | DialCarrier::Nearby | DialCarrier::Onion
        ) && !carrier.plausible(dial))
    {
        return Err(format!(
            "valid {} {} required (LocalListenQueue is disabled)",
            carrier.label(),
            match carrier {
                DialCarrier::P2p => "/p2p/<PeerId> address",
                DialCarrier::Nearby => "nearby:<contact key> route",
                DialCarrier::Onion => "onion:<onion key> route",
                _ => "host:port",
            }
        ));
    }
    let frames_b64 = frames
        .iter()
        .map(|f| base64::engine::general_purpose::STANDARD.encode(f))
        .collect();
    Ok(match carrier {
        DialCarrier::Lan => IpcRequest::LanDial {
            v: IPC_VERSION,
            lan_dial: dial.to_string(),
            expected_pub_hex: expected_pub_hex.to_string(),
            frames_b64,
        },
        DialCarrier::Internet => IpcRequest::InternetDial {
            v: IPC_VERSION,
            internet_dial: dial.to_string(),
            expected_pub_hex: expected_pub_hex.to_string(),
            frames_b64,
        },
        DialCarrier::P2p => IpcRequest::P2pDial {
            v: IPC_VERSION,
            multiaddr: dial.to_string(),
            expected_pub_hex: expected_pub_hex.to_string(),
            frames_b64,
        },
        DialCarrier::Nearby => IpcRequest::NearbyDial {
            v: IPC_VERSION,
            nearby_dial: dial.to_string(),
            expected_pub_hex: expected_pub_hex.to_string(),
            frames_b64,
        },
        DialCarrier::Onion => IpcRequest::OnionDial {
            v: IPC_VERSION,
            onion_dial: dial.to_string(),
            expected_pub_hex: expected_pub_hex.to_string(),
            frames_b64,
        },
    })
}

/// [`ipc_carrier_dial_reply_within`]'s request `req`, answered within
/// `timeout` (the IPC wait itself: [`ipc_dial_wait`] or what is left of
/// it); `probe`: a frame-less check, whose cut-short wait says so.
fn ipc_dial_answer(
    data_dir: &Path,
    carrier: DialCarrier,
    dial: &str,
    req: &IpcRequest,
    timeout: Duration,
    probe: bool,
) -> Result<DialReply, String> {
    // Retry only the connect (daemon just auto-started / restarting); a request
    // that was written is never replayed.
    let answer = super::ipc_client::ipc_request_retrying_connect(data_dir, req, timeout);
    if timeout < DIAL_IPC_TIMEOUT && probe {
        if let Err(e) = &answer {
            if super::ipc_client::error_means_no_answer(e) {
                return Err(format!(
                    "{} {}: no answer within {}s (the probe was cut short; nothing was sent)",
                    carrier.label(),
                    dial_shown(&DialRoute {
                        carrier,
                        dial: dial.to_string()
                    }),
                    timeout.as_secs()
                ));
            }
        }
    }
    dial_reply(carrier, answer)
}

/// How old raven-node's last reason for a contact may be to explain a probe
/// that was cut short.
const LAST_CHECK_MAX_AGE_S: u64 = 600;

/// raven-node's last p2p reason why `peer_pub_hex` could not be reached (at
/// most [`LAST_CHECK_MAX_AGE_S`] old), marked with its age (`asof`). ash's
/// probe of a contact it can queue for ends after 7 s, before raven-node's
/// own dial does; this costs one `Status` (2 s at most), only then. A local
/// network reason (Phase 3, `lan_off`, `lan_no_answer`) says nothing about
/// a p2p probe and is left out.
fn last_check(data_dir: &Path, peer_pub_hex: &str) -> Option<raven_core::reach_diag::Diag> {
    let Ok(IpcResponse::Status { unreachable, .. }) = super::ipc_client::ipc_request_timeout(
        data_dir,
        &IpcRequest::status(),
        Duration::from_secs(2),
    ) else {
        return None;
    };
    let row = unreachable.iter().find(|r| {
        r.peer_pub_hex
            .trim()
            .eq_ignore_ascii_case(peer_pub_hex.trim())
            && r.age_s <= LAST_CHECK_MAX_AGE_S
    })?;
    let mut d = raven_core::reach_diag::Diag::find(&row.reason).filter(|d| !d.why.is_lan())?;
    d.asof_s = Some(row.age_s);
    Some(d)
}

/// The daemon's answer to a dial on `carrier`: the replies, decoded, and the
/// path. A p2p answer names it (`path`, absent from an older raven-node:
/// unknown); LAN and Internet direct links are always `direct`.
fn dial_reply(
    carrier: DialCarrier,
    answer: Result<IpcResponse, String>,
) -> Result<DialReply, String> {
    use base64::Engine;
    let decode = |frames_b64: &[String]| -> Result<Vec<Vec<u8>>, String> {
        frames_b64
            .iter()
            .map(|s| {
                base64::engine::general_purpose::STANDARD
                    .decode(s.trim())
                    .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s.trim()))
                    .map_err(|e| e.to_string())
            })
            .collect()
    };
    match answer {
        Ok(IpcResponse::LanDialResult { frames_b64, .. }) if carrier == DialCarrier::Lan => {
            Ok(DialReply {
                frames: decode(&frames_b64)?,
                path: Some(DeliveryPath::Direct),
            })
        }
        Ok(IpcResponse::InternetDialResult { frames_b64, .. })
            if carrier == DialCarrier::Internet =>
        {
            Ok(DialReply {
                frames: decode(&frames_b64)?,
                path: Some(DeliveryPath::Direct),
            })
        }
        Ok(IpcResponse::P2pDialResult {
            frames_b64, path, ..
        }) if carrier == DialCarrier::P2p => Ok(DialReply {
            frames: decode(&frames_b64)?,
            path: path.as_deref().and_then(DeliveryPath::parse),
        }),
        // A nearby link is one radio hop: always direct.
        Ok(IpcResponse::NearbyDialResult { frames_b64, .. }) if carrier == DialCarrier::Nearby => {
            Ok(DialReply {
                frames: decode(&frames_b64)?,
                path: Some(DeliveryPath::Direct),
            })
        }
        // Its path is Tor (the carrier says it).
        Ok(IpcResponse::OnionDialResult { frames_b64, .. }) if carrier == DialCarrier::Onion => {
            Ok(DialReply {
                frames: decode(&frames_b64)?,
                path: None,
            })
        }
        // An older raven-node does not know the request.
        Ok(IpcResponse::Error { code, .. })
            if carrier == DialCarrier::Nearby && code == "IPC_FRAME" =>
        {
            Err(NEARBY_TOO_OLD.into())
        }
        Ok(IpcResponse::Error { code, .. })
            if carrier == DialCarrier::Onion && code == "IPC_FRAME" =>
        {
            Err(ONION_TOO_OLD.into())
        }
        Ok(IpcResponse::Error { code, message, .. }) => Err(format!("ipc {code}: {message}")),
        Ok(other) => Err(format!("unexpected ipc: {other:?}")),
        Err(e) => Err(e),
    }
}

/// [`ipc_carrier_dial`], repeated while the peer's listener sheds load. A refusal
/// *during the handshake* means none of our frames reached the peer, so the dial
/// is safe to repeat; a burst of concurrent sends from one profile otherwise
/// overflowed the listener's small per-source handshake cap and read as an
/// unreachable peer or a failed dial.
fn ipc_carrier_dial_patient(
    data_dir: &Path,
    carrier: DialCarrier,
    dial: &str,
    expected_pub_hex: &str,
    frames: &[Vec<u8>],
) -> Result<Vec<Vec<u8>>, String> {
    ipc_carrier_dial_patient_within(
        data_dir,
        carrier,
        dial,
        expected_pub_hex,
        frames,
        DIAL_IPC_TIMEOUT,
    )
}

fn ipc_carrier_dial_patient_within(
    data_dir: &Path,
    carrier: DialCarrier,
    dial: &str,
    expected_pub_hex: &str,
    frames: &[Vec<u8>],
    timeout: Duration,
) -> Result<Vec<Vec<u8>>, String> {
    retry_while_peer_sheds_load(PROBE_ATTEMPTS, PROBE_BACKOFF, std::thread::sleep, || {
        ipc_carrier_dial_within(data_dir, carrier, dial, expected_pub_hex, frames, timeout)
    })
}

/// [`ipc_carrier_dial_patient`] with the reply's path: the message dial,
/// whose `status delivered` says how it travelled.
fn ipc_carrier_dial_reply_patient(
    data_dir: &Path,
    carrier: DialCarrier,
    dial: &str,
    expected_pub_hex: &str,
    frames: &[Vec<u8>],
) -> Result<DialReply, String> {
    retry_while_peer_sheds_load(PROBE_ATTEMPTS, PROBE_BACKOFF, std::thread::sleep, || {
        ipc_carrier_dial_reply_within(
            data_dir,
            carrier,
            dial,
            expected_pub_hex,
            frames,
            DIAL_IPC_TIMEOUT,
        )
    })
}

fn first_pair_response(frames: &[Vec<u8>]) -> Option<raven_core::PairResponse> {
    for packed in frames {
        if let PairInitOobClassify::PairResponse(wire) = classify_packed_envelope(packed) {
            if let Ok(response) = raven_core::pair_init::decode_response(&wire) {
                return Some(response);
            }
        }
    }
    None
}

/// Message ids of the app channel objects to `peer` (raven-node's worker owns
/// them). `None`: the app store cannot be read.
fn app_message_ids(
    data_dir: &Path,
    peer: &[u8; 32],
) -> Option<std::collections::HashSet<[u8; 16]>> {
    use raven_core::app_store::{app_store_path, AppStore, MetadataOnly};
    if !app_store_path(data_dir).exists() {
        return Some(std::collections::HashSet::new());
    }
    AppStore::open(data_dir, &MetadataOnly)
        .and_then(|s| s.message_ids_for_device(peer))
        .ok()
}

/// An earlier row this send must leave alone: an app object, or (when the
/// app store cannot be read) any row without a staged chat body.
fn worker_owned(
    data_dir: &Path,
    app_rows: &Option<std::collections::HashSet<[u8; 16]>>,
    message_id: &[u8; 16],
) -> bool {
    match app_rows {
        Some(rows) => rows.contains(message_id),
        None => raven_core::load_staged_outbound_body(data_dir, message_id)
            .ok()
            .flatten()
            .is_none(),
    }
}

pub fn ensure_lab_local_material(data_dir: &Path, id: &Identity) -> Result<(), String> {
    let (_cert, _reg) = ensure_local_device_cert(data_dir, id)?;
    raven_core::ensure_local_prekey(data_dir, id)
}

/// One way to dial a peer for one send: a carrier and its `host:port`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DialRoute {
    pub carrier: DialCarrier,
    pub dial: String,
}

/// Session reset state of one `ash send` (lost-state recovery §11).
#[derive(Debug, Default)]
struct SendReset {
    enabled: bool,
    /// At most one SESSION_QUERY per send.
    queried: bool,
    /// A query retired a session: run the reset step and send again, once.
    restart: bool,
    /// The new message itself was refused and is re-sealed by that step: it is
    /// reported as the new message, and not sealed a second time.
    own_mid: Option<[u8; 16]>,
}

/// The dial carrier for a route's carrier.
fn dial_carrier_of(carrier: OutboxCarrier) -> DialCarrier {
    match carrier {
        OutboxCarrier::Lan => DialCarrier::Lan,
        OutboxCarrier::Internet => DialCarrier::Internet,
        OutboxCarrier::P2p => DialCarrier::P2p,
        OutboxCarrier::Nearby => DialCarrier::Nearby,
        OutboxCarrier::Onion => DialCarrier::Onion,
    }
}

/// `ash send`'s side of a reset step: the send lock is already held for the
/// whole send, so store work runs inline; dials go through raven-node.
struct AshIo<'a> {
    data_dir: &'a Path,
    peer_pub_hex: &'a str,
}

impl ResetIo for AshIo<'_> {
    fn locked(
        &mut self,
        f: &mut dyn FnMut(&mut IndexedSessionStore) -> Result<(), String>,
    ) -> Result<(), String> {
        let mut store =
            IndexedSessionStore::open(self.data_dir).map_err(|e| e.redacted_display())?;
        f(&mut store)
    }

    fn dial(&mut self, route: &OutboxRoute, frames: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, String> {
        ipc_carrier_dial_patient(
            self.data_dir,
            dial_carrier_of(route.carrier),
            &route.dial,
            self.peer_pub_hex,
            frames,
        )
    }
}

/// One reset step for `peer` over this send's route, and what it printed.
fn run_reset_and_report(
    data_dir: &Path,
    id: &Identity,
    peer: &[u8; 32],
    route: &DialRoute,
    peer_pub_hex: &str,
    ctx: &SendCtx,
    // Rows of this send itself (its own message): not "earlier" messages.
    own_rows: usize,
) -> Option<ResetStep> {
    let routes = [OutboxRoute {
        carrier: route.carrier.outbox(),
        dial: route.dial.trim().to_string(),
    }];
    let env = ResetEnv {
        data_dir,
        identity: id,
        peer: *peer,
        routes: &routes,
        user_confirmed: false,
        now_ms: now_ms(),
    };
    let mut io = AshIo {
        data_dir,
        peer_pub_hex,
    };
    let step = run_reset_step(&env, &mut io).ok()?;
    match &step {
        ResetStep::Resealed(report) => {
            // Parked ones (the long message horizon) are sealed into the new
            // session by this send right after, ahead of its own message.
            ctx.say_peer_reset(
                report.resealed.len() + report.parked.len(),
                ResetWhy::of(data_dir, peer),
            );
            // Reported here: not again as a background note.
            if let Ok(mut store) = IndexedSessionStore::open(data_dir) {
                let _ = store.take_unnotified_reseals(peer);
            }
        }
        ResetStep::Held { code, rows } => {
            let today = IndexedSessionStore::open(data_dir)
                .ok()
                .and_then(|s| {
                    s.reset_rounds_since(peer, now_ms().saturating_sub(24 * 3_600_000))
                        .ok()
                })
                .unwrap_or(0);
            ctx.say_reset_held(
                code,
                rows.saturating_sub(own_rows),
                today,
                ResetWhy::of(data_dir, peer),
            );
        }
        ResetStep::Nothing | ResetStep::Unreachable(_) => {}
    }
    Some(step)
}

/// The pre-pass after the probe (gate on, send lock held): a renewed
/// certificate retires the sessions bound to the old one (E2), background
/// re-seals are reported once, and retired rows are re-sealed when possible.
/// Returns whether a renewed certificate retired any session.
fn reset_prepass(
    data_dir: &Path,
    id: &Identity,
    peer_bundle: &raven_core::LanBundle,
    route: &DialRoute,
    peer_pub_hex: &str,
    ctx: &SendCtx,
) -> bool {
    let peer = peer_bundle.cert.device_ed_pub;
    let mut renewed = false;
    if let Ok(mut store) = IndexedSessionStore::open(data_dir) {
        renewed = note_presented_cert(data_dir, &mut store, &peer, &peer_bundle.cert, now_ms())
            .is_ok_and(|n| n > 0);
        if let Ok((n, at)) = store.take_unnotified_reseals(&peer) {
            let replaced = n > 0
                && store
                    .contact_replaced_retired_session(&peer, now_ms())
                    .unwrap_or(false);
            let why = if replaced {
                ResetWhy::Replaced
            } else {
                ResetWhy::Lost
            };
            ctx.say_unnotified_reseals(n, at, why);
        }
    }
    let _ = run_reset_and_report(data_dir, id, &peer, route, peer_pub_hex, ctx, 0);
    renewed
}

/// SESSION_QUERY for `queried` (bytes the peer just refused), alone in its own
/// dial over the same carrier and route. True when the answer retired its
/// session.
#[allow(clippy::too_many_arguments)]
fn query_retires_session(
    data_dir: &Path,
    id: &Identity,
    local_device: &[u8; 32],
    peer: &[u8; 32],
    carrier: DialCarrier,
    dial: &str,
    peer_pub_hex: &str,
    store: &mut IndexedSessionStore,
    queried: &[u8],
) -> bool {
    let Ok(frame) = session_query_frame(id, peer, queried, now_ms()) else {
        return false;
    };
    let replies = ipc_carrier_dial_patient(data_dir, carrier, dial, peer_pub_hex, &[frame])
        .unwrap_or_default();
    matches!(
        apply_query_replies(store, local_device, peer, queried, &replies, now_ms()),
        Ok(QueryOutcome::Retired { .. })
    )
}

/// `raven outbox resend --contact X` (design §11.5): the user confirmed the
/// contact reinstalled or restored RAVEN. Held rows are re-sealed into a new
/// session, over the contact's own routes, and handed to raven-node.
pub(crate) fn resend_after_reset(
    data_dir: &Path,
    peer: &[u8; 32],
    who: &str,
) -> Result<(), String> {
    if !session_reset_live_enabled() {
        return Err("raven outbox resend: not available in this build".into());
    }
    let id = raven_core::load_identity_required(data_dir).map_err(|e| e.to_string())?;
    let mut contact = match raven_core::outbox::contact_admission(data_dir, peer) {
        raven_core::outbox::ContactAdmission::Allowed(c) => c,
        _ => return Err(format!("{who} is not a current, unblocked contact")),
    };
    // `raven lan verified-only on` (Phase 3 P3.C2): no LAN route for an
    // unverified contact here either.
    contact.lan_verified_only = raven_core::node_policy::lan_verified_only(data_dir);
    let gates = raven_core::outbox::CarrierGates {
        lan: raven_core::lan_usable_now(),
        internet: raven_core::internet_direct_live_enabled(),
        p2p: raven_core::p2p_live_enabled(),
        nearby: raven_core::nearby_live_enabled(),
        onion: false,
    };
    let routes: Vec<OutboxRoute> = raven_core::outbox::plan_object_routes(
        Some(&raven_core::outbox::ObjectRoutes {
            peer_pub_hex: hex::encode(peer),
            choice: CarrierChoice::Auto,
            routes: Vec::new(),
            expires_at_ms: u64::MAX,
            unsent: false,
            written: false,
            custodians_held: Vec::new(),
            custody_forwarded: false,
            custody: false,
        }),
        &contact,
        gates,
    )
    .routes
    .into_iter()
    .filter(|r| r.carrier.confidential_to_endpoint())
    // An unverified contact is reached only on the local network, here too.
    .filter_map(|r| {
        raven_core::outbox::localize_lan_route(
            &r,
            contact.localize_pinned(&r),
            raven_core::outbox::LOCALIZE_RESOLVE_TIMEOUT,
        )
        .ok()
    })
    .collect();
    let _lock = acquire_send_lock(data_dir, peer)?;
    IndexedSessionStore::open(data_dir)
        .and_then(|mut store| store.confirm_peer_reset(peer, now_ms()))
        .map_err(|e| e.redacted_display())?;
    let env = ResetEnv {
        data_dir,
        identity: &id,
        peer: *peer,
        routes: &routes,
        user_confirmed: true,
        now_ms: now_ms(),
    };
    let peer_hex = hex::encode(peer);
    let mut io = AshIo {
        data_dir,
        peer_pub_hex: &peer_hex,
    };
    let step = run_reset_step(&env, &mut io)?;
    let _ = outbox_kick(data_dir, Some(peer));
    match step {
        ResetStep::Resealed(report) => {
            if let Ok(mut store) = IndexedSessionStore::open(data_dir) {
                let _ = store.take_unnotified_reseals(peer);
            }
            println!(
                "{} message(s) to {who} were sealed again and handed to raven-node.",
                report.resealed.len()
            );
            if !report.parked.is_empty() {
                // The long message horizon: raven-node's next attempt seals
                // them into the new session.
                println!(
                    "{} more message(s) to {who} ran out of time under the old connection; \
                     raven-node sends them under the new one.",
                    report.parked.len()
                );
            }
            Ok(())
        }
        ResetStep::Nothing => {
            println!("Nothing to send again: no message to {who} is on hold.");
            Ok(())
        }
        ResetStep::Held { code, rows } => Err(format!(
            "{rows} message(s) to {who} are still on hold (technical: {code})"
        )),
        ResetStep::Unreachable(detail) => Err(format!(
            "{who} could not be reached to set up a new secure connection; the messages stay \
             on hold and you can run this again later (technical: {})",
            sanitize_terminal_line(&detail)
        )),
    }
}

/// After a restart, what the user's own (re-sealed) message is: delivered
/// (Ok), or queued for raven-node, whatever went wrong with other rows.
fn own_message_outcome(
    data_dir: &Path,
    peer: &[u8; 32],
    mid: &[u8; 16],
    error: &str,
    text: &str,
    ctx: &SendCtx,
    handoff: &OutboxHandoff<'_>,
) -> Result<(), String> {
    let Ok(store) = IndexedSessionStore::open(data_dir) else {
        return Err(error.to_string());
    };
    let copies = store
        .message_copies_for_recipient(peer, mid)
        .unwrap_or_default();
    if copies.iter().any(|c| {
        matches!(
            c.delivery_state,
            Some(
                raven_core::indexed_session_store::EndpointDeliveryState::Delivered
                    | raven_core::indexed_session_store::EndpointDeliveryState::Read
            )
        )
    }) {
        return Ok(());
    }
    if error.starts_with(super::ext::QUEUED_PREFIX)
        || error.starts_with(super::ext::UNCONFIRMED_PREFIX)
    {
        return Err(error.to_string());
    }
    let live = copies.iter().find(|c| !c.retired && c.has_outbox_row);
    let expires = live
        .and_then(|c| c.object_digest)
        .and_then(|d| {
            store
                .outbound_by_digest_for_recipient(&d, peer)
                .ok()
                .flatten()
        })
        .map(|(row, _)| envelope_expiry(&row.immutable_envelope_bytes))
        .unwrap_or_else(|| now_ms() + 24 * 3_600_000);
    Err(queued_text(
        ctx,
        &format!(
            "{}; mid={}…",
            raven_core::session_reset::code::PEER_RESET,
            hex::encode(&mid[..4])
        ),
        &quoted_preview(text),
        &handoff.note_own(mid, expires),
    ))
}

/// Is `route` a local-network route (a session set up over it may receive
/// re-sealed messages automatically)?
/// Only an IP literal counts: a host name would need a second resolution,
/// which may differ from the address raven-node actually dialled, and costs
/// time under the send lock.
fn local_network_route(route: &DialRoute) -> bool {
    route.carrier == DialCarrier::Lan
        && route
            .dial
            .trim()
            .parse::<std::net::SocketAddr>()
            .is_ok_and(|addr| raven_core::outbox::is_local_network_ip(addr.ip()))
}

/// PairInit + indexed send over one-connection LanDial or InternetDial, on a
/// named carrier. `ctx` names the recipient for every line this prints (see
/// `ext::SendCtx`): success lines go to stdout, and every `Err` is already the
/// user's sentence (queued / not sent / unconfirmed). Production sends go
/// through [`run_pair_init_and_send_routes`]; this single-route form is kept
/// for the tests (Unix-only ones).
#[cfg(test)]
#[cfg_attr(not(unix), allow(dead_code))]
pub fn run_pair_init_and_send_on(
    data_dir: &Path,
    id: &Identity,
    peer: &str,
    peer_pub_hex: &str,
    text: &str,
    carrier: DialCarrier,
    ctx: &SendCtx,
) -> Result<(), String> {
    let route = DialRoute {
        carrier,
        dial: peer.to_string(),
    };
    run_pair_init_and_send_routes(
        data_dir,
        id,
        &[route],
        &ProbePlan::in_order(1),
        peer_pub_hex,
        text,
        ctx,
    )
    .map(|_| ())
}

/// [`run_pair_init_and_send_on`] over the first of `routes` (in order: LAN,
/// then Internet) whose RLB1 probe answers, and returns the route it used.
/// `probe_plan` may put the contact's remembered route first
/// (`raven_core::route_memory`, lab only) and learns from the probes; a
/// route whose error it already knows ([`ProbePlan::with_unresolved`]) is
/// not probed and fails with that error.
///
/// Only the probe moves on to the next route. It carries no message frame and
/// stages nothing, so trying another route can never send or queue a second
/// copy. Everything stateful (pairing, the retry of an earlier queued message,
/// staging and dialing this one) runs once, on the chosen route. When no route
/// answers, the send behaves exactly like a single-route send on the first
/// route (queued for retry if a confirmed session exists, else NOT SENT).
/// A frame-less RLB1 probe of route `i` (its known error, or raven-node's
/// dial), owned so it can run on its own thread ([`probe_round`]).
type Prober<B> = std::sync::Arc<dyn Fn(usize) -> Result<B, String> + Send + Sync>;

/// [`Prober`] of `routes` for [`run_pair_init_and_send_routes`].
fn route_prober(
    data_dir: &Path,
    routes: &[DialRoute],
    known: &ProbePlan,
    peer_pub_hex: &str,
    probe_timeout: Duration,
) -> Prober<raven_core::LanBundle> {
    let data_dir = data_dir.to_path_buf();
    let routes = routes.to_vec();
    let peer_pub_hex = peer_pub_hex.to_string();
    let known: Vec<Option<String>> = (0..routes.len())
        .map(|i| known.known_error(i).map(str::to_string))
        .collect();
    std::sync::Arc::new(move |i: usize| {
        // F1: an unverified contact's name that does not resolve now.
        // Nothing to ask raven-node: it fails as a name not found, and the
        // unreachable path queues or refuses as for any route.
        if let Some(e) = known.get(i).cloned().flatten() {
            return Err(e);
        }
        let route = routes.get(i).ok_or("no such route")?;
        let check = |wait: Duration| {
            let req = dial_request(&data_dir, route.carrier, &route.dial, &peer_pub_hex, &[])?;
            retry_while_peer_sheds_load(PROBE_ATTEMPTS, PROBE_BACKOFF, std::thread::sleep, || {
                ipc_dial_answer(&data_dir, route.carrier, &route.dial, &req, wait, true)
            })
            .map(|r| r.frames)
        };
        let wait = ipc_dial_wait(route.carrier, probe_timeout, true);
        let checked = if route.carrier == DialCarrier::Onion {
            onion_check_again(wait, ONION_CHECK_AGAIN_WITHIN, check)
        } else {
            check(wait)
        };
        checked.and_then(|replies| {
            replies
                .iter()
                .find_map(|f| parse_peer_offer(f).ok())
                .ok_or_else(|| "peer did not return an RLB1 bundle".to_string())
        })
    })
}

/// A send's Tor check that Tor answered "unreachable" this fast gets one
/// more try within the send's Tor wait (field test E3 round 2: a check
/// ended after 5.2 s, both of the Tor helper's connects having failed at
/// once, and the message was queued with 20 s of the send's 25 s Tor wait
/// left; raven-node's outbox reached the friend over Tor seconds later).
const ONION_CHECK_AGAIN_WITHIN: Duration = Duration::from_secs(12);
/// The least of the send's Tor wait a second check needs (a rendezvous over
/// a fresh descriptor takes several seconds).
const ONION_CHECK_AGAIN_MIN_LEFT: Duration = Duration::from_secs(10);

/// A Tor check (`check(wait)`: raven-node's frame-less dial, answered
/// within `wait`) that failed within `again_within` with Tor's
/// "unreachable" is made once more with what is left of `wait`. Any other
/// failure (a refusal, Tor not ready on this computer, the wait cut short)
/// is final; so is one with less than [`ONION_CHECK_AGAIN_MIN_LEFT`] left.
fn onion_check_again<T>(
    wait: Duration,
    again_within: Duration,
    mut check: impl FnMut(Duration) -> Result<T, String>,
) -> Result<T, String> {
    let started = Instant::now();
    match check(wait) {
        Err(e) if tor_missed(&e) && started.elapsed() < again_within => {
            let left = wait.saturating_sub(started.elapsed());
            if left < ONION_CHECK_AGAIN_MIN_LEFT {
                return Err(e);
            }
            if super::ext::verbose() {
                eprintln!(
                    "{C_DIM}Tor did not reach them at the first try ({:.1} s); trying once \
                     more{C_RESET}",
                    started.elapsed().as_secs_f64()
                );
            }
            check(left)
        }
        other => other,
    }
}

/// Tor said the friend's onion service could not be reached (not a
/// refusal, not Tor missing here, not a send's own short wait).
fn tor_missed(e: &str) -> bool {
    e.contains("ONION_UNREACHABLE") && !e.starts_with(TOR_BUSY) && !is_peer_refusal(e)
}

/// How long each direct route of a send's race waits after the one before
/// it in plan order (happy eyeballs), unless that one failed sooner.
const DIRECT_STAGGER: Duration = Duration::from_millis(300);

/// The same while the plan's first route is the one that carried the last
/// message on this network (route memory or learning): it gets the head
/// start Tor gets, so a route that just worked is not raced for nothing.
const REMEMBERED_STAGGER: Duration = raven_core::onion::ONION_HEAD_START;

/// One finished probe of a [`probe_round`]: the route index, its answer,
/// and when it finished (since the round began).
type Probed<B> = (usize, Result<B, String>, Duration);

/// What a [`probe_round`] did: the finished probes in the order they
/// finished (an answer last), and the routes whose probe had started but
/// not finished when the round ended (another answered first).
struct RoundOutcome<B> {
    done: Vec<Probed<B>>,
    running: Vec<usize>,
    /// When each probe that started did (since the round began).
    started: Vec<(usize, Duration)>,
}

impl<B> RoundOutcome<B> {
    /// When route `i`'s probe started, since the round began.
    fn started_at(&self, i: usize) -> Duration {
        self.started
            .iter()
            .find(|(j, _)| *j == i)
            .map_or(Duration::ZERO, |(_, at)| *at)
    }
}

/// A verbose race line (E2 r38: the lines said when each route ended, not
/// when it started): "p2p_dial /p2p/... started +0.3 s, did not answer
/// (4.6 s)".
fn race_line(route: &DialRoute, started: Duration, what: &str, ended: Duration) -> String {
    format!(
        "{} {} started +{:.1} s, {what} ({:.1} s)",
        route.carrier.label(),
        dial_shown(route),
        started.as_secs_f64(),
        ended.as_secs_f64()
    )
}

/// One round of probes over `order` (route indices, plan order), the
/// finished ones in the order they finished; the round ends at the first
/// that answers (`Ok`, last). Every route races (E2 r9 #1: the direct ones
/// were probed one after the other, so a stale LAN address and a p2p dial
/// cost 5 s + 7 s before anything else): the direct routes start
/// `stagger` apart in plan order, each at once when every one before it
/// failed; Tor's (`onion`) after `head_start`, or at once when every direct
/// one failed (the outbox's race). A probe still running when another
/// answered is not waited for (it finishes on its own, frame-less: two at
/// once never send anything twice), and no new one starts.
fn probe_round<B: Send + 'static>(
    order: &[usize],
    onion: Option<usize>,
    head_start: Duration,
    stagger: Duration,
    probe: Prober<B>,
) -> RoundOutcome<B> {
    use std::sync::{Arc, Condvar, Mutex};
    struct Round<B> {
        done: Vec<Probed<B>>,
        started: Vec<(usize, Duration)>,
        answered: bool,
    }
    let tor = onion.filter(|t| order.contains(t));
    let direct: Vec<usize> = order.iter().copied().filter(|&i| Some(i) != tor).collect();
    let total = direct.len() + usize::from(tor.is_some());
    let t0 = std::time::Instant::now();
    let state = Arc::new((
        Mutex::new(Round::<B> {
            done: Vec::new(),
            started: Vec::new(),
            answered: false,
        }),
        Condvar::new(),
    ));
    // (route, its delay, the routes that must all have failed for it to go
    // at once).
    let mut slots: Vec<(usize, Duration, Vec<usize>)> = direct
        .iter()
        .enumerate()
        .map(|(k, &i)| {
            let delay = stagger.saturating_mul(u32::try_from(k).unwrap_or(u32::MAX));
            (i, delay, direct[..k].to_vec())
        })
        .collect();
    if let Some(t) = tor {
        let delay = if direct.is_empty() {
            Duration::ZERO
        } else {
            head_start
        };
        slots.push((t, delay, direct.clone()));
    }
    for (i, delay, before) in slots {
        let (state, probe) = (Arc::clone(&state), Arc::clone(&probe));
        std::thread::spawn(move || {
            let (lock, ready) = &*state;
            {
                let mut round = lock.lock().unwrap_or_else(|e| e.into_inner());
                loop {
                    if round.answered {
                        return;
                    }
                    let failed =
                        |j: &usize| round.done.iter().any(|(k, r, _)| k == j && r.is_err());
                    let left = delay.saturating_sub(t0.elapsed());
                    if left.is_zero() || before.iter().all(failed) {
                        break;
                    }
                    round = ready
                        .wait_timeout(round, left)
                        .unwrap_or_else(|e| e.into_inner())
                        .0;
                }
                round.started.push((i, t0.elapsed()));
            }
            let got = probe(i);
            let mut round = lock.lock().unwrap_or_else(|e| e.into_inner());
            if round.answered {
                return;
            }
            round.answered = got.is_ok();
            round.done.push((i, got, t0.elapsed()));
            ready.notify_all();
        });
    }
    let (lock, ready) = &*state;
    let mut round = lock.lock().unwrap_or_else(|e| e.into_inner());
    while !round.answered && round.done.len() < total {
        round = ready.wait(round).unwrap_or_else(|e| e.into_inner());
    }
    // Late probes see `answered` (or nothing left to wait for) and stop.
    round.answered = true;
    ready.notify_all();
    let done = std::mem::take(&mut round.done);
    let started = std::mem::take(&mut round.started);
    let running = started
        .iter()
        .map(|(i, _)| *i)
        .filter(|i| !done.iter().any(|(j, _, _)| j == i))
        .collect();
    RoundOutcome {
        done,
        running,
        started,
    }
}

/// Tor's head start in a send's race (E2 r9 #1): the direct routes get
/// [`raven_core::onion::ONION_HEAD_START`] only while one of them is likely
/// to answer: the friend was on an authenticated LAN link with raven-node
/// lately (`lan_seen_s`: `Some(Some(s))` with `s` within
/// [`LAN_SEEN_SPAN_S`]), the send plans a LAN address the beacon found or
/// the friend told this computer (`lan_found`), or the plan tries a p2p or
/// Internet route first because it carried the last message on this
/// network (`direct_first`). A friend not seen on the LAN lately gets no
/// LAN head start: Tor goes at once with the others (mac-b dialled a stale
/// saved LAN address of a friend on another network first on every send).
/// An older raven-node that cannot say (`lan_seen_s` `None`) keeps it.
fn tor_head_start(
    has_lan: bool,
    lan_seen_s: Option<Option<u64>>,
    lan_found: bool,
    direct_first: bool,
) -> Duration {
    let lan_likely = has_lan
        && (lan_found
            || match lan_seen_s {
                None => true,
                Some(seen) => seen.is_some_and(|s| s <= LAN_SEEN_SPAN_S),
            });
    if lan_likely || direct_first {
        raven_core::onion::ONION_HEAD_START
    } else {
        Duration::ZERO
    }
}

/// How recent a LAN link with the friend must be for its LAN route to get a
/// head start over Tor (raven-node's own "seen here" span).
const LAN_SEEN_SPAN_S: u64 = 10 * 60;

/// E2 r9 #2: what raven-node saw of `routes` lately (`failed`, IPC
/// `ContactReach`), route by route: the probe's error for each route whose
/// last dial failed lately, with how long ago (`None` for a route with no
/// recent failure: new, changed, or not tried). `known`: routes the probe
/// would not dial (their error is known; age 0).
///
/// Tor is the one route that reaches a friend on another network, and its
/// circuits fail now and then (E2 r40: one slow Tor dial left Tor out of
/// the next eight sends, and only the background retry delivered them):
/// its failure counts only while the friend's own Raven is known to be
/// stopped (its computer refused the LAN dial at an address on this
/// computer's network: [`friend_raven_stopped`]), when Tor cannot reach it
/// either (field K4), or while Tor is busy with the friend
/// (`ContactReach::tor_busy`: it did not reach it lately, and raven-node's
/// outbox already carries a message to it, Tor first, with Tor's full
/// wait): the send queues for that attempt instead of waiting for Tor
/// again (E2 r40: the user never waits twice).
fn recent_failures(
    routes: &[DialRoute],
    reach: &super::ipc_client::ContactReach,
    known: &ProbePlan,
) -> Vec<Option<(String, u64)>> {
    recent_failures_with(
        routes,
        &reach.failed,
        reach.tor_busy,
        reach.lan_seen_s,
        known,
        super::ext::on_our_network,
    )
}

/// What a send says of a Tor route it leaves to raven-node's outbox
/// ([`recent_failures`], `tor_busy`) when Tor's own failure is not known
/// (its dial still runs).
pub(crate) const TOR_BUSY: &str =
    "ONION_UNREACHABLE: Tor has not reached them yet; raven-node's outbox keeps trying over Tor";

/// [`recent_failures`] with "is this address on this computer's network"
/// passed in (tests).
fn recent_failures_with(
    routes: &[DialRoute],
    failed: &[super::ipc_client::RouteFailure],
    tor_busy: bool,
    lan_seen_s: Option<u64>,
    known: &ProbePlan,
    on_net: impl Fn(std::net::IpAddr) -> bool,
) -> Vec<Option<(String, u64)>> {
    // A refusal at a LAN address says the friend's Raven stopped only while
    // raven-node also had a LAN link with the friend lately (`lan_seen_s`,
    // within [`LAN_SEEN_SPAN_S`]); otherwise the address may be an old one
    // that another computer has now, and Tor stays in the race.
    let seen_here = lan_seen_s.is_some_and(|s| s <= LAN_SEEN_SPAN_S);
    let stopped = seen_here && friend_raven_stopped(failed, on_net);
    let failure_of = |route: &DialRoute| {
        failed
            .iter()
            .find(|f| {
                f.carrier == route.carrier.outbox().label() && f.dial.trim() == route.dial.trim()
            })
            .map(|f| (f.error.clone(), f.age_s))
    };
    routes
        .iter()
        .enumerate()
        .map(|(i, route)| match known.known_error(i) {
            Some(e) => Some((e.to_string(), 0)),
            // The outbox carries an earlier message to the friend over Tor:
            // this one waits with it, whatever Tor's last failure said (field
            // test E3 round 2: "every way failed 5 s ago" while the outbox
            // was delivering over Tor).
            None if route.carrier == DialCarrier::Onion && tor_busy && !stopped => Some((
                TOR_BUSY.to_string(),
                failure_of(route).map_or(0, |(_, age)| age),
            )),
            None if route.carrier == DialCarrier::Onion && !stopped => None,
            None => failed
                .iter()
                .find(|f| {
                    f.carrier == route.carrier.outbox().label()
                        && f.dial.trim() == route.dial.trim()
                })
                .map(|f| (f.error.clone(), f.age_s)),
        })
        .collect()
}

/// The friend's Raven is stopped though its computer is here: a LAN dial
/// to an address on this computer's network (`on_net`) was refused lately
/// (nothing listening). Its onion service is that same Raven, so Tor fails
/// too (field K4); anywhere else Tor is the way to try.
fn friend_raven_stopped(
    failed: &[super::ipc_client::RouteFailure],
    on_net: impl Fn(std::net::IpAddr) -> bool,
) -> bool {
    failed.iter().any(|f| {
        let refused = {
            let e = f.error.to_ascii_lowercase();
            e.contains("connection refused") || e.contains("actively refused")
        };
        f.carrier == DialCarrier::Lan.outbox().label()
            && refused
            && f.dial
                .trim()
                .parse::<std::net::SocketAddr>()
                .is_ok_and(|a| on_net(a.ip()))
    })
}

/// What a send does with [`recent_failures`] (E2 r9 #2, r38 K4): every
/// route failed lately, at least one of them dialled (not only a known
/// error): queue at once, with these errors as the probe's, and the oldest
/// failure's age. Otherwise `None`.
fn every_route_failed(
    routes: &[DialRoute],
    recent: &[Option<(String, u64)>],
    known: &ProbePlan,
) -> Option<(Vec<String>, u64)> {
    let dialled = (0..routes.len()).any(|i| known.known_error(i).is_none());
    // Nothing known (a first message, an older raven-node): no row at all.
    if routes.is_empty()
        || recent.len() != routes.len()
        || !dialled
        || recent.iter().any(Option::is_none)
    {
        return None;
    }
    let oldest = recent
        .iter()
        .flatten()
        .map(|(_, age)| *age)
        .max()
        .unwrap_or(0);
    let errors = routes
        .iter()
        .zip(recent.iter().flatten())
        .map(|(route, (e, _))| {
            if routes.len() > 1 {
                format!("{} {}: {e}", route.carrier.label(), dial_shown(route))
            } else {
                e.clone()
            }
        })
        .collect();
    Some((errors, oldest))
}

/// Why a send queued without dialling ([`every_route_failed`]), in one
/// line: Tor left to raven-node's outbox, which is already trying it for
/// an earlier message ([`TOR_BUSY`]: nothing failed), or every way failed
/// `age_s` seconds ago.
fn not_dialled_line(who: &str, recent: &[Option<(String, u64)>], age_s: u64) -> String {
    if recent.iter().flatten().any(|(e, _)| e == TOR_BUSY) {
        format!(
            "Raven is already trying to reach {who} over Tor with an earlier message; this one \
             waits with it"
        )
    } else {
        format!("every way to {who} failed {age_s} s ago; not tried again now")
    }
}

/// The routes a send leaves out of its race because they failed lately
/// (E2 r38 K4: "only re-probe the routes that have not failed lately"):
/// (route index, the error its probe reports, said as not tried again).
/// Routes whose error is known already are not repeated.
fn skipped_routes(recent: &[Option<(String, u64)>], known: &ProbePlan) -> Vec<(usize, String)> {
    recent
        .iter()
        .enumerate()
        .filter(|(i, _)| known.known_error(*i).is_none())
        .filter_map(|(i, r)| {
            r.as_ref().map(|(e, age)| {
                if e == TOR_BUSY {
                    (i, format!("{e} (not tried again now)"))
                } else {
                    (i, format!("{e} (failed {age} s ago; not tried again now)"))
                }
            })
        })
        .collect()
}

/// A message dial over Tor that did not get through right after Tor
/// answered the send's check (E2 r40): its words say so
/// (`ext::cause_sentence`), never "did not answer at onion:...".
pub(crate) const ONION_CHECKED_THEN_LOST: &str = "ONION_CHECKED_THEN_LOST";

/// A message dial over Tor that failed within this gets a second try in the
/// same send (a slower failure goes to raven-node's queue, which tries Tor
/// again at once: the send never waits two full Tor deadlines).
const ONION_SECOND_TRY_WITHIN: Duration = Duration::from_secs(30);

/// The message dial over Tor after Tor answered this send's check (E2 r40:
/// "onion_dial Tor answered first (21.7 s)", then the message's own Tor
/// connection failed and the words blamed the address). The check's link
/// is closed once it answers, so the message makes a connection of its
/// own: one that fails within `second_within` gets one more try at once
/// (the same sealed envelope; a copy that did arrive is answered as a
/// duplicate, never shown twice), and a failure says that Tor answered
/// ([`ONION_CHECKED_THEN_LOST`]). A refusal is the friend's answer: as it
/// came.
fn dial_after_tor_check<T>(
    second_within: Duration,
    mut dial: impl FnMut() -> Result<T, String>,
) -> Result<T, String> {
    let started = Instant::now();
    match dial() {
        Err(e) if !is_peer_refusal(&e) => {
            let again = if started.elapsed() < second_within {
                if super::ext::verbose() {
                    eprintln!(
                        "{C_DIM}Tor answered the check, but the message's own Tor connection \
                         failed; trying it once more{C_RESET}"
                    );
                }
                dial()
            } else {
                Err(e)
            };
            again.map_err(|e| {
                if is_peer_refusal(&e) {
                    e
                } else {
                    format!("{ONION_CHECKED_THEN_LOST}: {e}")
                }
            })
        }
        other => other,
    }
}

/// Refusal for chat text that starts with the app channel's reserved prefix.
pub(crate) const RESERVED_PREFIX_REFUSAL: &str =
    "NOT SENT: messages may not start with the reserved prefix RVNAPP/ or RVNGRP/";

pub fn run_pair_init_and_send_routes(
    data_dir: &Path,
    id: &Identity,
    routes: &[DialRoute],
    probe_plan: &ProbePlan,
    peer_pub_hex: &str,
    text: &str,
    ctx: &SendCtx,
) -> Result<DialRoute, String> {
    // Agent payloads (`RVNAPP/…`) travel only through raven-node's app
    // channel; chat text never starts with the reserved prefix.
    if !raven_core::app_channel::chat_text_allowed(text) {
        return Err(RESERVED_PREFIX_REFUSAL.into());
    }
    if !trace_delivery::live_pair_init_outbound_ready() {
        return Err(trace_delivery::production_gate_status().into());
    }
    let first = routes
        .first()
        .ok_or_else(|| "no host:port to dial — refusing LocalListenQueue fallback".to_string())?;
    for route in routes {
        if let Some(hold) = route.carrier.hold() {
            return Err(hold.into());
        }
        let peer = route.dial.as_str();
        if matches!(
            route.carrier,
            DialCarrier::P2p | DialCarrier::Nearby | DialCarrier::Onion
        ) {
            if !route.carrier.plausible(peer) {
                return Err(format!(
                    "valid {} {} required",
                    route.carrier.label(),
                    match route.carrier {
                        DialCarrier::P2p => "/p2p/<PeerId> address",
                        DialCarrier::Onion => "onion:<onion key> route",
                        _ => "nearby:<contact key> route",
                    }
                ));
            }
        } else if !peer.contains(':')
            || peer.eq_ignore_ascii_case("local-listen")
            || peer.eq_ignore_ascii_case("local")
        {
            return Err(format!(
                "valid {} host:port required — refusing LocalListenQueue fallback",
                route.carrier.label()
            ));
        }
    }
    let peer_pub = parse_pub_hex(peer_pub_hex)?;
    // Internet and p2p delivery only for a verified (pinned) contact: refuse
    // before anything is dialled (`--peer … --carrier internet` included).
    if let Some(route) = routes.iter().find(|r| r.carrier != DialCarrier::Lan) {
        let pinned = raven_core::contact_is_pinned(data_dir, &peer_pub)?;
        if routes.iter().any(|r| {
            r.carrier != DialCarrier::Lan
                && !raven_core::carrier_allowed_for_contact(r.carrier.outbox(), pinned)
        }) {
            return Err(unverified_carrier_text(
                &ctx.display_name(),
                carrier_word(route.carrier),
                &format!(
                    "raven contact verify --address {}",
                    raven_core::encode_address(&peer_pub)
                ),
                &pin_command_hint(&peer_pub),
            ));
        }
    }
    ensure_lab_local_material(data_dir, id)?;
    let (local_cert, registry) = ensure_local_device_cert(data_dir, id)?;
    let handoff = OutboxHandoff::new(data_dir, routes, peer_pub, ctx.choice)
        .with_custody(ctx.custody_ok)
        .with_local(id.public_key_bytes())
        .leaving_out(&ctx.unrecorded);
    // With a confirmed session the message can be queued for raven-node's
    // outbox whatever the probe says, so an unreachable peer costs ~10 s here,
    // not a full dial timeout. A first message needs the probe's answer.
    let first_message = !matches!(offline_send_target(data_dir, &peer_pub), Ok(Some(_)));
    let probe_timeout = if first_message {
        DIAL_IPC_TIMEOUT
    } else {
        QUEUEABLE_PROBE_TIMEOUT
    };

    // Routes not to probe keep their known error whatever the order.
    let known = probe_plan;
    // A plan that does not match these routes is plan order, nothing taught.
    let in_order;
    let probe_plan = if probe_plan.order.len() == routes.len() {
        probe_plan
    } else {
        in_order = ProbePlan::in_order(routes.len());
        &in_order
    };
    let probes_started = now_ms();
    // (index into `routes`, reached the contact) per probe, for the memory.
    let mut probed: Vec<(usize, bool)> = Vec::new();
    let mut probe_errors: Vec<String> = Vec::new();
    let mut answered: Option<(DialRoute, raven_core::LanBundle)> = None;
    // What raven-node saw of the contact lately (E2 r9 #1, #2): its LAN
    // sightings for Tor's head start, and the routes that just failed.
    let asked: Vec<(String, String)> = routes
        .iter()
        .map(|r| {
            (
                r.carrier.outbox().label().to_string(),
                r.dial.trim().to_string(),
            )
        })
        .collect();
    let reach =
        super::ipc_client::contact_reach_within(data_dir, peer_pub_hex, &asked, CONTACT_REACH_WAIT);
    // E2 r9 #2: every route of a message that can be queued failed moments
    // ago, with no sign of the contact since and no new route: queued at
    // once ("Raven keeps trying"), not dialled again (10 sends to an
    // unreachable friend took 13 s each).
    let recent = reach
        .as_ref()
        .filter(|_| !first_message)
        .map(|r| recent_failures(routes, r, known))
        .unwrap_or_default();
    let skip = every_route_failed(routes, &recent, known);
    // Some routes failed lately, not all: the race leaves those out (r38
    // K4); a first message always tries every route.
    let partial;
    let known = match skipped_routes(&recent, known) {
        left_out if skip.is_none() && !left_out.is_empty() && left_out.len() < routes.len() => {
            partial = known.with_known(left_out);
            &partial
        }
        _ => known,
    };
    if let Some((errors, age_s)) = skip {
        if !ctx.chat {
            eprintln!(
                "{C_DIM}{}{C_RESET}",
                not_dialled_line(&ctx.display_name(), &recent, age_s)
            );
        }
        probe_errors = errors;
    }
    let head_start = tor_head_start(
        routes.iter().any(|r| r.carrier == DialCarrier::Lan),
        reach.as_ref().map(|r| r.lan_seen_s),
        !ctx.unrecorded.is_empty(),
        probe_plan
            .order
            .first()
            .and_then(|&i| routes.get(i))
            .is_some_and(|r| matches!(r.carrier, DialCarrier::P2p | DialCarrier::Internet))
            && probe_plan.remembers_a_route(),
    );
    // A first message probes again (up to FIRST_MESSAGE_PROBES rounds) while
    // the friend's computer answers and closes the link: one refusal for
    // now was final before, and only a retyped message went out (E1).
    for round in 0..FIRST_MESSAGE_PROBES {
        if !probe_errors.is_empty() && round == 0 {
            // Every route failed just now (#2): nothing to probe.
            break;
        }
        if round > 0 {
            if answered.is_some() || !probe_again(first_message, &probe_errors) {
                break;
            }
            std::thread::sleep(FIRST_MESSAGE_PROBE_PAUSE);
            probed.clear();
            probe_errors.clear();
        }
        let order: Vec<usize> = probe_plan
            .order
            .iter()
            .copied()
            .filter(|&i| i < routes.len())
            .collect();
        // The race (design 2026-10-tor-fallback §2; E2 r9 #1): every route
        // at once, the direct ones a moment apart, Tor after its head start
        // (none for a friend not seen on the LAN lately) or as soon as the
        // direct ones failed. Probes carry no message, so two at once can
        // send nothing twice.
        let onion = routes.iter().position(|r| r.carrier == DialCarrier::Onion);
        let probe = route_prober(data_dir, routes, known, peer_pub_hex, probe_timeout);
        let stagger = if probe_plan.remembers_a_route() {
            REMEMBERED_STAGGER
        } else {
            DIRECT_STAGGER
        };
        let outcome = probe_round(&order, onion, head_start, stagger, probe);
        let ended = outcome.done.last().map(|(_, _, at)| *at);
        // A route still running when another answered lost the race: for
        // the route memory it did not answer (a black-holed LAN address is
        // otherwise never seen to fail, and stays first).
        let lost = outcome.running.clone();
        for &i in &outcome.running {
            if let Some(route) = routes.get(i).filter(|_| super::ext::verbose()) {
                eprintln!(
                    "{C_DIM}{}{C_RESET}",
                    race_line(
                        route,
                        outcome.started_at(i),
                        "did not answer before another way did",
                        ended.unwrap_or_default()
                    )
                );
            }
        }
        let started: Vec<Duration> = outcome
            .done
            .iter()
            .map(|(i, _, _)| outcome.started_at(*i))
            .collect();
        for ((i, probe, took), started) in outcome.done.into_iter().zip(started) {
            let route = &routes[i];
            // Technical details on demand: what each route did, in the order
            // they finished, when it started and when it ended.
            if super::ext::verbose() {
                let what = match &probe {
                    Ok(_) => "answered first",
                    Err(e) if e.starts_with(TOR_BUSY) => {
                        "not tried again (raven-node's outbox is trying Tor)"
                    }
                    Err(e) if e.ends_with("not tried again now)") => {
                        "not tried again (it failed lately)"
                    }
                    Err(_) => "did not answer",
                };
                eprintln!("{C_DIM}{}{C_RESET}", race_line(route, started, what, took));
            }
            match probe {
                Ok(bundle) => {
                    // Evidence only when it is the contact's own bundle (checked
                    // again below, where a mismatch refuses the send).
                    let ok = bundle.cert.user_ed_pub == peer_pub
                        || bundle.cert.device_ed_pub == peer_pub;
                    probed.push((i, ok));
                    answered = Some((route.clone(), bundle));
                    break;
                }
                Err(mut e) => {
                    probed.push((i, false));
                    // The probe ended before raven-node's own dial: its last check
                    // of this contact may already say why.
                    if route.carrier == DialCarrier::P2p
                        && e.contains("the probe was cut short")
                        && !e.contains(raven_core::reach_diag::REACH_TAG)
                    {
                        if let Some(d) = last_check(data_dir, peer_pub_hex) {
                            e = format!("{e}; {}", d.render());
                        }
                    }
                    probe_errors.push(if routes.len() > 1 {
                        format!("{} {}: {e}", route.carrier.label(), dial_shown(route))
                    } else {
                        e
                    });
                }
            }
        }
        if answered.is_some() {
            probed.extend(lost.into_iter().map(|i| (i, false)));
        }
    }
    // Outside the send lock (the memory has its own).
    probe_plan.teach(data_dir, &peer_pub, &probed, probes_started);
    // From here on the send reads and writes per-peer session state: serialise it
    // with every other `ash send` to this peer (see `PeerSendLock`). After the
    // probe, so an unreachable peer's timeouts are not serialised.
    let _send_lock = acquire_send_lock_noting(data_dir, &peer_pub, &ctx.display_name())?;
    let (route, peer_bundle) = match answered {
        Some(hit) => hit,
        // Peer asleep / unreachable on every route: the RLB1 probe is not needed
        // to stage a message into an already-confirmed session, so do that (on
        // the first route) instead of dropping the text.
        None => {
            let ctx = SendCtx {
                dial: ctx_dial(first),
                ..ctx.clone()
            };
            return send_when_peer_unreachable(
                data_dir,
                id,
                &registry,
                &local_cert,
                &first.dial,
                peer_pub_hex,
                &peer_pub,
                text,
                first.carrier,
                probe_errors.join("; "),
                &ctx,
                &handoff,
            )
            .map(|()| first.clone());
        }
    };
    // The address the texts name: none for Tor (never an onion address in
    // a send's words; E2 r40 said "did not answer at onion:...").
    let ctx = &SendCtx {
        dial: ctx_dial(&route),
        ..ctx.clone()
    };
    let (peer, carrier) = (route.dial.as_str(), route.carrier);
    if peer_bundle.cert.user_ed_pub != peer_pub && peer_bundle.cert.device_ed_pub != peer_pub {
        return Err("RLB1 identity does not match --peer-pub-hex / contact".into());
    }
    cache_peer_bundle(data_dir, &peer_bundle)?;

    let reset_live = session_reset_live_enabled();
    let cert_renewed =
        reset_live && reset_prepass(data_dir, id, &peer_bundle, &route, peer_pub_hex, ctx);
    let existing = if reset_live {
        find_sendable_peer_session(data_dir, &peer_bundle.cert.device_ed_pub)?
    } else {
        find_confirmed_peer_session(data_dir, &peer_bundle.cert.device_ed_pub)?
    };
    let record_key = if let Some(existing) = existing {
        existing
    } else {
        // Before a new session exists: was there one with this contact?
        let remembered = super::ext::session_remembered(data_dir, &peer_bundle.cert.device_ed_pub);
        // PairInit (addresses and trust material in clear, PairInit V1 §7) only
        // rides a carrier whose Raven Noise session ends at the contact.
        if !carrier.outbox().confidential_to_endpoint() {
            return Err(not_sent_text(
                ctx,
                &format!(
                    "{} is not confidential to the endpoint; no PairInit on it",
                    carrier.label()
                ),
                true,
            ));
        }
        let (init, key) = create_initiator_pair_init(data_dir, id, &peer_bundle)?;
        let init_frame = wrap_pair_init(id, &init)?;
        // A responder that does not list us as a contact already closed the RLB1
        // probe above after our hello (`LINK_NOT_ACCEPTED`). Should it refuse the
        // PairInit itself ("pair init refused: peer is not a local contact"), it
        // says nothing on the wire, so the dial ends in a silent close;
        // `not_sent_text` names the likely cause (and nothing was queued).
        let replies =
            ipc_carrier_dial_patient(data_dir, carrier, peer, peer_pub_hex, &[init_frame])
                .map_err(|e| not_sent_text(ctx, &e, true))?;
        let response = first_pair_response(&replies).ok_or_else(|| {
            let kinds: Vec<String> = replies
                .iter()
                .map(|f| {
                    if parse_peer_offer(f).is_ok() {
                        "rlb1".into()
                    } else {
                        format!("{:?}", classify_packed_envelope(f))
                    }
                })
                .collect();
            not_sent_text(
                ctx,
                &format!(
                    "WAITING_FOR_PAIR_RESPONSE: no PairResponse on {} ({} frames: {})",
                    carrier.label(),
                    replies.len(),
                    kinds.join(",")
                ),
                true,
            )
        })?;
        let mut store = IndexedSessionStore::open(data_dir).map_err(|e| e.redacted_display())?;
        let now = now_ms();
        store
            .confirm_verified_pair_response(&key, &init, &response, now)
            .map_err(|e| {
                // Dated in our future (cutoff pack CP.7): the contact's clock
                // runs ahead, which raven-node noted from this reply, so the
                // outcome can say so (the refusal itself is unchanged).
                let raw = e.redacted_display();
                if raven_core::clock_skew::future_by_ms(response.created_at_ms, now).is_some() {
                    not_sent_text(ctx, &raw, true)
                } else {
                    raw
                }
            })?;
        // Session-reset metadata: we initiated it, over a local route or not.
        let _ = store.mark_session_initiated(
            &key,
            &peer_bundle.cert.device_ed_pub,
            local_network_route(&route),
            false,
            now_ms(),
        );
        trace_delivery::trace_event(
            "ash/pair_init_lab.rs:run_pair_init_and_send",
            "TRACE_PAIR_RESPONSE_CONFIRMED",
            "SESSION_CONFIRMED",
            Some(&hex::encode(&init.init_id[..4])),
            Some(carrier.label()),
        );
        if cert_renewed {
            ctx.say_new_connection_after_reset();
        } else {
            ctx.say_connection_set_up(super::ext::talked_before(remembered, || {
                super::ext::history_with(data_dir, peer_pub_hex)
            }));
        }
        key
    };

    let mut reset = SendReset {
        enabled: reset_live,
        ..SendReset::default()
    };
    let first = send_indexed_text(
        data_dir,
        id,
        &registry,
        &local_cert,
        &record_key,
        text,
        peer,
        peer_pub_hex,
        &peer_bundle.cert,
        carrier,
        None,
        ctx,
        &handoff,
        &mut reset,
    );
    let error = match first {
        Err(error) if reset.restart => error,
        other => return other.map(|()| route.clone()),
    };
    // The contact said it no longer holds the session (design §11.3): set up a
    // new one and send again, once. Its waiting messages, possibly including
    // this one, were re-sealed by the step.
    let peer_dev = peer_bundle.cert.device_ed_pub;
    let step = run_reset_and_report(
        data_dir,
        id,
        &peer_dev,
        &route,
        peer_pub_hex,
        ctx,
        usize::from(reset.own_mid.is_some()),
    );
    let resealed = matches!(step, Some(ResetStep::Resealed(_)));
    match find_sendable_peer_session(data_dir, &peer_dev)? {
        Some(key) if resealed || reset.own_mid.is_none() => {
            let mut again = SendReset {
                enabled: true,
                queried: true,
                restart: false,
                own_mid: reset.own_mid,
            };
            let result = send_indexed_text(
                data_dir,
                id,
                &registry,
                &local_cert,
                &key,
                text,
                peer,
                peer_pub_hex,
                &peer_bundle.cert,
                carrier,
                None,
                ctx,
                &handoff,
                &mut again,
            );
            match (result, reset.own_mid) {
                (Ok(()), _) => Ok(route.clone()),
                // The user's own text is durably queued as its re-sealed copy
                // (or already delivered): never "not sent, send it again".
                (Err(error), Some(mid)) => {
                    own_message_outcome(data_dir, &peer_dev, &mid, &error, text, ctx, &handoff)
                        .map(|()| route.clone())
                }
                (Err(error), None) => Err(error),
            }
        }
        _ => match reset.own_mid {
            // Safe in the retired session; raven-node keeps working on it.
            Some(mid) => {
                let code = match &step {
                    Some(ResetStep::Held { code, .. }) => *code,
                    _ => raven_core::session_reset::code::PEER_RESET,
                };
                let expires = IndexedSessionStore::open(data_dir)
                    .ok()
                    .and_then(|s| s.retired_undelivered_messages_for_recipient(&peer_dev).ok())
                    .and_then(|rows| {
                        rows.into_iter()
                            .find(|r| r.message_id == mid)
                            .map(|r| envelope_expiry(&r.immutable_envelope_bytes))
                    })
                    .unwrap_or_else(|| now_ms() + 24 * 3_600_000);
                Err(queued_text(
                    ctx,
                    &format!("{code}; mid={}…", hex::encode(&mid[..4])),
                    &quoted_preview(text),
                    &handoff.note_own(&mid, expires),
                ))
            }
            None => Err(error),
        },
    }
}

/// Refusal for a LAN send to an unverified contact at an address that is not
/// on the local network (owner decision 2026-10-08: unverified contacts are
/// LAN only). Nothing was dialled.
pub(crate) fn unverified_remote_lan_text(
    who: &str,
    reason: &str,
    verify_cmd: &str,
    pin_cmd: &str,
) -> String {
    format!(
        "NOT SENT: {who} is not verified, and {reason}: an unverified contact is reached only \
         at addresses on your local network. Compare the fingerprint with {who} by phone or in \
         person (run: {verify_cmd}), then pin it: {pin_cmd}. Nothing was dialled. \
         ({CONTACT_NOT_VERIFIED})"
    )
}

/// `raven contact add …` that pins the contact whose key is `peer`, for the
/// verified-contact refusal (the existing verify command only shows the
/// fingerprint; adding again with `--verify-fp` pins it).
pub(crate) fn pin_command_hint(peer: &[u8; 32]) -> String {
    format!(
        "raven contact add --address {} --pub-hex {} --verify-fp <the fingerprint they read out>",
        raven_core::encode_address(peer),
        hex::encode(peer)
    )
}

/// The order the RLB1 probe tries a send's routes in, and what it teaches
/// (`raven_core::route_memory`, lab only). `planned`: the routes as planned
/// (saved / learned / env addresses, before an unverified contact's LAN name
/// is resolved), index-aligned with the routes dialled.
pub(crate) struct ProbePlan {
    planned: Vec<OutboxRoute>,
    order: Vec<usize>,
    preferred: Option<OutboxRoute>,
    net: Option<String>,
    /// (route index, probe error): routes the probe does not ask raven-node
    /// about, because that error is already known (cutoff F1: an unverified
    /// contact's saved name that does not resolve now).
    unresolved: Vec<(usize, String)>,
    /// The order is learning connectivity's (Phase 6a): the route memory is
    /// neither read nor taught (OD6a-10).
    learned: bool,
}

impl ProbePlan {
    /// Learning connectivity's carrier order when raven-node uses one for
    /// this contact (Phase 6a: IPC `LearningPlan` answers `state=on`, within
    /// [`LEARNING_PLAN_TIMEOUT`]); otherwise (an older raven-node, the hold,
    /// learning off, no answer in time) the contact's remembered route
    /// first, when this network has one. With learning and the memory off
    /// (release) nothing is read and no socket is opened: plan order.
    pub(crate) fn remembered(data_dir: &Path, peer: &[u8; 32], planned: Vec<OutboxRoute>) -> Self {
        // The learning gate is the same in ash and the raven-node it starts.
        let asked = raven_core::learning::learning_live().then(|| {
            super::ipc_client::learning_plan_within(
                data_dir,
                &hex::encode(peer),
                LEARNING_PLAN_TIMEOUT,
            )
        });
        Self::planned_on(data_dir, peer, planned, route_memory::network_tag(), asked)
    }

    /// [`Self::remembered`] on network `net`, with raven-node's answer to
    /// `LearningPlan` (`None`: not asked).
    fn planned_on(
        data_dir: &Path,
        peer: &[u8; 32],
        planned: Vec<OutboxRoute>,
        net: Option<String>,
        asked: Option<Result<Option<super::ipc_client::LearningPlan>, String>>,
    ) -> Self {
        match asked.and_then(|a| learned_order(&planned, a)) {
            Some(order) => Self {
                planned,
                order,
                preferred: None,
                net: None,
                unresolved: Vec::new(),
                learned: true,
            },
            None => Self::remembered_on(data_dir, peer, planned, net),
        }
    }

    /// [`Self::remembered`] on network `net`.
    fn remembered_on(
        data_dir: &Path,
        peer: &[u8; 32],
        planned: Vec<OutboxRoute>,
        net: Option<String>,
    ) -> Self {
        let preferred = route_memory::preferred_route(data_dir, peer, net.as_deref(), now_ms());
        let order = route_memory::probe_order(&planned, preferred.as_ref());
        Self {
            planned,
            order,
            preferred,
            net,
            unresolved: Vec::new(),
            learned: false,
        }
    }

    /// Plan order, nothing read or taught.
    pub(crate) fn in_order(n: usize) -> Self {
        Self {
            planned: Vec::new(),
            order: (0..n).collect(),
            preferred: None,
            net: None,
            unresolved: Vec::new(),
            learned: false,
        }
    }

    #[cfg(test)]
    fn with(planned: Vec<OutboxRoute>, preferred: Option<OutboxRoute>, net: Option<&str>) -> Self {
        let order = route_memory::probe_order(&planned, preferred.as_ref());
        Self {
            planned,
            order,
            preferred,
            net: net.map(str::to_string),
            unresolved: Vec::new(),
            learned: false,
        }
    }

    /// This plan, with (route index, probe error) for each route whose
    /// probe error is already known: such a route is not probed, it fails
    /// with that error.
    pub(crate) fn with_unresolved(mut self, unresolved: Vec<(usize, String)>) -> Self {
        self.unresolved = unresolved;
        self
    }

    /// The known probe error of route `i`, when it is not to be probed.
    fn known_error(&self, i: usize) -> Option<&str> {
        self.unresolved
            .iter()
            .find(|(j, _)| *j == i)
            .map(|(_, e)| e.as_str())
    }

    /// This plan with `more` routes whose error is known (not dialled).
    fn with_known(&self, more: Vec<(usize, String)>) -> ProbePlan {
        ProbePlan {
            planned: self.planned.clone(),
            order: self.order.clone(),
            preferred: self.preferred.clone(),
            net: self.net.clone(),
            unresolved: self.unresolved.iter().cloned().chain(more).collect(),
            learned: self.learned,
        }
    }

    /// The order comes from learning connectivity or the route memory (a
    /// route that carried the last message on this network goes first), not
    /// plan order alone.
    fn remembers_a_route(&self) -> bool {
        let reordered = self.order.iter().enumerate().any(|(n, &i)| n != i);
        self.preferred.is_some() || (self.learned && reordered)
    }

    /// The index of the route tried first.
    pub(crate) fn first(&self) -> usize {
        self.order.first().copied().unwrap_or(0)
    }

    /// Teach the memory what the probes saw: `probed` holds (index, reached)
    /// in probe order, mapped back to the planned routes (a resolved LAN
    /// literal is never stored).
    fn teach(&self, data_dir: &Path, peer: &[u8; 32], probed: &[(usize, bool)], started_ms: u64) {
        // A learned order supersedes the memory: nothing is taught.
        if self.planned.is_empty() || self.learned {
            return;
        }
        // A nearby route is derived live and is never route evidence
        // (Phase 5): what it did teaches nothing, and it is not planned here.
        let dialled: Vec<(OutboxRoute, bool)> = probed
            .iter()
            .filter_map(|(i, ok)| Some((self.planned.get(*i)?.clone(), *ok)))
            .filter(|(r, _)| r.carrier != OutboxCarrier::Nearby)
            .collect();
        let planned: Vec<OutboxRoute> = self
            .planned
            .iter()
            .filter(|r| r.carrier != OutboxCarrier::Nearby)
            .cloned()
            .collect();
        let _ = route_memory::learn(
            data_dir,
            peer,
            &planned,
            self.preferred.as_ref(),
            &dialled,
            self.net.as_deref(),
            started_ms,
            now_ms(),
        );
    }
}

/// The probe order of `planned` (as indices) by raven-node's learned
/// carrier order, when its answer asks for it (`state=on`): a stable sort
/// by each route's carrier label in `order`; a carrier it does not name goes
/// after the named ones, and a nearby route keeps its slot (learning never
/// ranks nearby). `None`: no such answer (an error, an older raven-node or
/// the hold, learning shadowed or off), so today's order.
fn learned_order(
    planned: &[OutboxRoute],
    asked: Result<Option<super::ipc_client::LearningPlan>, String>,
) -> Option<Vec<usize>> {
    let plan = asked.ok().flatten().filter(|p| p.state == "on")?;
    let rank = |c: OutboxCarrier| {
        plan.order
            .iter()
            .position(|label| label == c.label())
            .unwrap_or(plan.order.len())
    };
    let slots: Vec<usize> = (0..planned.len())
        .filter(|i| planned[*i].carrier != OutboxCarrier::Nearby)
        .collect();
    let mut ranked = slots.clone();
    ranked.sort_by_key(|i| rank(planned[*i].carrier));
    let mut order: Vec<usize> = (0..planned.len()).collect();
    for (slot, i) in slots.into_iter().zip(ranked) {
        order[slot] = i;
    }
    Some(order)
}

/// The friends a queued message may be left with, as labels (`label`), and
/// why the first goes first: carry choice's pick in its order when
/// raven-node named one (`carry`, its `LearningPlan` carry rows; a row
/// without a valid key is skipped), else `set`
/// (`deposit_custodians`) with no reason. Pure.
fn custodian_words(
    set: &[([u8; 32], Option<u8>)],
    carry: &[raven_core::ipc::LearningCarry],
    label: impl Fn(&[u8; 32]) -> String,
) -> (Vec<String>, Option<String>) {
    let picked: Vec<([u8; 32], &raven_core::ipc::LearningCarry)> = carry
        .iter()
        .filter_map(|row| {
            let key = <[u8; 32]>::try_from(hex::decode(row.peer_pub_hex.trim()).ok()?).ok()?;
            Some((key, row))
        })
        .collect();
    match picked.first() {
        Some((first, row)) => {
            let words =
                super::ext::carry_first_words(&label(first), &row.met, row.delivered, row.outcomes);
            (picked.iter().map(|(c, _)| label(c)).collect(), Some(words))
        }
        None => (set.iter().map(|(c, _)| label(c)).collect(), None),
    }
}

/// Hands a message this send left undelivered to raven-node's background
/// outbox: records, for that object, the carrier choice and the routes this
/// send planned (so the worker never widens them; the record expires with the
/// envelope) and kicks the worker once per send.
pub(crate) struct OutboxHandoff<'a> {
    data_dir: &'a Path,
    routes: &'a [DialRoute],
    peer: [u8; 32],
    choice: CarrierChoice,
    taken: std::cell::Cell<Option<bool>>,
    custody_ok: bool,
    /// LAN dials never recorded ([`Self::leaving_out`]).
    unrecorded: Vec<String>,
    /// This node's key ([`Self::with_local`]): what names the friends a
    /// queued message may be left with.
    local: Option<[u8; 32]>,
}

impl<'a> OutboxHandoff<'a> {
    /// `choice`: what the send asked for (`SendCtx::choice`); `None` derives
    /// the narrowest choice the routes allow (several carriers: auto; one:
    /// that one), for tests and `run_send_secure_on`.
    pub(crate) fn new(
        data_dir: &'a Path,
        routes: &'a [DialRoute],
        peer: [u8; 32],
        choice: Option<CarrierChoice>,
    ) -> Self {
        let has = |c: DialCarrier| routes.iter().any(|r| r.carrier == c);
        let kinds = [
            DialCarrier::Lan,
            DialCarrier::Internet,
            DialCarrier::P2p,
            DialCarrier::Nearby,
            DialCarrier::Onion,
        ]
        .into_iter()
        .filter(|c| has(*c))
        .count();
        let derived = if kinds > 1 {
            CarrierChoice::Auto
        } else if has(DialCarrier::Internet) {
            CarrierChoice::Internet
        } else if has(DialCarrier::P2p) {
            CarrierChoice::P2p
        } else if has(DialCarrier::Nearby) {
            CarrierChoice::Nearby
        } else if has(DialCarrier::Onion) {
            CarrierChoice::Onion
        } else {
            CarrierChoice::Lan
        };
        Self {
            data_dir,
            routes,
            peer,
            choice: choice.unwrap_or(derived),
            taken: std::cell::Cell::new(None),
            custody_ok: false,
            unrecorded: Vec::new(),
            local: None,
        }
    }

    /// This node's key, so the retry promise can name the friends a queued
    /// message may be left with ([`RetryNote::custodians`]).
    pub(crate) fn with_local(mut self, local: [u8; 32]) -> Self {
        self.local = Some(local);
        self
    }

    /// The learned LAN dials among the routes (`SendCtx::unrecorded`) stay
    /// out of the record: the worker plans what was learned again at every
    /// attempt, through its own on-link filter, so a learned address of a
    /// network this computer has left is never retried from a record
    /// (any-network plan P2.R1, as AppSubmit records none).
    pub(crate) fn leaving_out(mut self, dials: &[String]) -> Self {
        self.unrecorded = dials.to_vec();
        self
    }

    /// Friend custody may carry this send's own message when the send forced
    /// no carrier (`--carrier` absent or `auto`).
    pub(crate) fn with_custody(mut self, custody_ok: bool) -> Self {
        // Nothing is recorded for friend custody while its gate is closed.
        self.custody_ok = custody_ok && raven_core::custody_gate::CustodyGates::current().live;
        self
    }

    /// `record` for this send's own message: the only object a send may mark
    /// for friend custody (an earlier row keeps whatever its own send chose:
    /// its carrier choice, see `record_object_routes`, and its custody).
    pub(crate) fn record_own(&self, message_id: &[u8; 16], expires_at_ms: u64) {
        self.record(message_id, expires_at_ms);
        if self.custody_ok {
            let _ = raven_core::outbox::set_object_custody(self.data_dir, message_id, now_ms());
        }
    }

    /// `note` for this send's own message (see `record_own`).
    pub(crate) fn note_own(&self, message_id: &[u8; 16], expires_at_ms: u64) -> RetryNote {
        // Marked before the kick, so the worker sees it on its first pass.
        self.record_own(message_id, expires_at_ms);
        let (custodians, carry_first) = self.custodian_labels();
        RetryNote {
            expires_at_ms: self.can_wait_until(message_id, expires_at_ms),
            copy_expires_at_ms: expires_at_ms,
            background: self.kicked(),
            custodians,
            carry_first,
        }
    }

    /// The friends (labels) raven-node may leave this send's message with
    /// (`deposit_custodians`): none unless friend custody may carry it.
    /// While raven-node's carry choice has learned about them (Phase 6a
    /// P6.16, its `LearningPlan` carry rows), the ones it picks in its
    /// order, with why the first goes first.
    fn custodian_labels(&self) -> (Vec<String>, Option<String>) {
        let Some(local) = self.local.filter(|_| self.custody_ok) else {
            return (Vec::new(), None);
        };
        let set = raven_core::custody_client::deposit_custodians(
            self.data_dir,
            &local,
            &self.peer,
            now_ms(),
        );
        if set.is_empty() {
            return (Vec::new(), None);
        }
        let contacts = super::load_contacts(self.data_dir).unwrap_or_default();
        let label = |c: &[u8; 32]| {
            let key = hex::encode(c);
            contacts
                .iter()
                .find(|k| k.pub_hex.trim().eq_ignore_ascii_case(&key))
                .map_or_else(|| "a friend".to_string(), |k| k.primary_label())
        };
        custodian_words(&set, &self.carry_rows(), label)
    }

    /// raven-node's carry choice for this contact (IPC `LearningPlan`'s
    /// carry rows, within [`LEARNING_PLAN_TIMEOUT`]), asked only while the
    /// learning gate is live: empty when it learned nothing about them, or
    /// does not answer.
    fn carry_rows(&self) -> Vec<raven_core::ipc::LearningCarry> {
        if !raven_core::learning::learning_live() {
            return Vec::new();
        }
        match super::ipc_client::learning_plan_within(
            self.data_dir,
            &hex::encode(self.peer),
            LEARNING_PLAN_TIMEOUT,
        ) {
            Ok(Some(plan)) if plan.state == "on" => plan.carry,
            _ => Vec::new(),
        }
    }

    /// Did raven-node's outbox take it (its `OutboxKick` was accepted)? An
    /// older service answers with an error: nothing retries it then.
    fn kicked(&self) -> bool {
        if let Some(taken) = self.taken.get() {
            return taken;
        }
        let taken = outbox_kick(self.data_dir, Some(&self.peer));
        self.taken.set(Some(taken));
        taken
    }

    /// Write `message_id`'s route record only (no kick): for an object already
    /// queued whose record was lost.
    pub(crate) fn record(&self, message_id: &[u8; 16], expires_at_ms: u64) {
        let routes: Vec<OutboxRoute> = self
            .routes
            .iter()
            .filter(|r| !(r.carrier == DialCarrier::Lan && self.unrecorded.contains(&r.dial)))
            .map(|r| OutboxRoute {
                carrier: r.carrier.outbox(),
                dial: r.dial.clone(),
            })
            .collect();
        // Best effort: without the record the worker plans LAN from the book.
        let _ = record_object_routes(
            self.data_dir,
            message_id,
            &self.peer,
            self.choice,
            &routes,
            expires_at_ms,
            now_ms(),
        );
    }

    /// Record `message_id` for the worker and return the retry promise for its
    /// envelope, which expires at `expires_at_ms`.
    pub(crate) fn note(&self, message_id: &[u8; 16], expires_at_ms: u64) -> RetryNote {
        self.record(message_id, expires_at_ms);
        RetryNote {
            expires_at_ms: self.can_wait_until(message_id, expires_at_ms),
            copy_expires_at_ms: expires_at_ms,
            background: self.kicked(),
            custodians: Vec::new(),
            carry_first: None,
        }
    }

    /// Until when the message `message_id`, whose envelope expires at
    /// `expires_at_ms`, can still go out: that expiry, or with the long
    /// message horizon live (P5.8) its message's deadline, from its staged
    /// write time, as the worker parks it and seals it again until then.
    fn can_wait_until(&self, message_id: &[u8; 16], expires_at_ms: u64) -> u64 {
        if !raven_core::horizon::horizon_live_enabled() {
            return expires_at_ms;
        }
        raven_core::load_staged_outbound_body(self.data_dir, message_id)
            .ok()
            .flatten()
            .filter(|staged| staged.created_at_ms > 0)
            .map_or(expires_at_ms, |staged| {
                raven_core::horizon::message_deadline(staged.created_at_ms).max(expires_at_ms)
            })
    }
}

/// Ask raven-node's outbox to retry the objects to `peer` (or all) now.
/// `true` only when a worker accepted it.
pub(crate) fn outbox_kick(data_dir: &Path, peer: Option<&[u8; 32]>) -> bool {
    outbox_kick_with(data_dir, peer, false, false)
}

/// `raven outbox retry`: the kick that also lifts friend-custody parks.
pub(crate) fn outbox_retry_kick(data_dir: &Path, peer: Option<&[u8; 32]>) -> bool {
    outbox_kick_with(data_dir, peer, true, false)
}

/// `raven outbox hand-off`: the retry kick that also leaves the messages
/// with a friend now (Phase 3 P3.21).
pub(crate) fn outbox_hand_off_kick(data_dir: &Path, peer: Option<&[u8; 32]>) -> bool {
    outbox_kick_with(data_dir, peer, true, true)
}

fn outbox_kick_with(
    data_dir: &Path,
    peer: Option<&[u8; 32]>,
    retry: bool,
    custody_now: bool,
) -> bool {
    let req = IpcRequest::OutboxKick {
        v: IPC_VERSION,
        peer_pub_hex: peer.map(hex::encode),
        retry,
        custody_now,
    };
    matches!(
        super::ipc_client::ipc_request_timeout(data_dir, &req, OUTBOX_KICK_TIMEOUT),
        Ok(IpcResponse::Accepted { .. })
    )
}

/// Did an earlier message never leave this computer, as its route record
/// (read past its deadline too, `object_route_evidence`) tells? Queued
/// (`resend`): when it was handed to the queue while the peer could not be
/// reached (`unsent`, cutoff pack CP.6). Prepared: unless a contact read it
/// and refused it (`written`, review C-time-deadlines-1). No record: a
/// queued one was written, a prepared one was not.
fn never_left_computer(resend: bool, record: Option<&raven_core::outbox::RouteEvidence>) -> bool {
    if resend {
        record.is_some_and(|r| r.unsent)
    } else {
        !record.is_some_and(|r| r.written)
    }
}

/// When the sealed envelope `bytes` stops being valid (0 if unreadable).
fn envelope_expiry(bytes: &[u8]) -> u64 {
    Envelope::unpack(bytes).map(|e| e.expires_at).unwrap_or(0)
}

/// Attempts at a dial the peer shed at the handshake, and the first back-off
/// between them (doubling).
const PROBE_ATTEMPTS: u32 = 5;
const PROBE_BACKOFF: Duration = Duration::from_millis(150);

/// The daemon's text when the peer's listener closed the connection *during the
/// handshake*: it is at its connection limit (or not a RAVEN node), and nothing
/// of ours was sent.
fn peer_shed_the_connection(err: &str) -> bool {
    err.contains("closed the connection during the handshake")
}

/// Run `attempt`, retrying (with doubling back-off plus a little jitter) while the
/// peer's listener sheds load. Only for dials, whose refusal *during the
/// handshake* proves no frame reached the peer, so repeating them cannot
/// duplicate anything: a burst of concurrent `ash send`s all dial at once, and the
/// listener's small per-source handshake cap used to turn the overflow into "peer
/// unreachable" or a queued message. Any other error, and the last attempt's, is
/// returned as is.
fn retry_while_peer_sheds_load<T>(
    attempts: u32,
    first_backoff: Duration,
    mut sleep: impl FnMut(Duration),
    mut attempt: impl FnMut() -> Result<T, String>,
) -> Result<T, String> {
    use rand::Rng;
    let mut backoff = first_backoff;
    let mut n = 1;
    loop {
        match attempt() {
            Err(e) if peer_shed_the_connection(&e) && n < attempts => {
                let jitter = rand::thread_rng().gen_range(0..=backoff.as_millis() as u64 / 2);
                sleep(backoff + Duration::from_millis(jitter));
                backoff *= 2;
                n += 1;
            }
            other => return other,
        }
    }
}

/// The peer's cached (re-verified) certificate and the confirmed session with
/// it, if both exist. First contact has neither: the peer's RLB1 bundle is
/// needed to seal the PairInit, so it cannot be staged offline.
fn offline_send_target(
    data_dir: &Path,
    peer_pub: &[u8; 32],
) -> Result<Option<(DeviceCertificate, IndexedSessionRecordKey)>, String> {
    let Some(bundle) = load_cached_peer_bundle(data_dir, peer_pub)? else {
        return Ok(None);
    };
    if bundle.cert.user_ed_pub != *peer_pub && bundle.cert.device_ed_pub != *peer_pub {
        return Ok(None);
    }
    let found = if session_reset_live_enabled() {
        find_sendable_peer_session(data_dir, &bundle.cert.device_ed_pub)?
    } else {
        find_confirmed_peer_session(data_dir, &bundle.cert.device_ed_pub)?
    };
    let Some(record_key) = found else {
        return Ok(None);
    };
    Ok(Some((bundle.cert, record_key)))
}

/// Confirmed sessions with the contact exist, but every one was retired by a
/// session reset: nothing to queue a message under.
fn every_session_retired(data_dir: &Path, peer_pub: &[u8; 32]) -> bool {
    let Ok(Some(bundle)) = load_cached_peer_bundle(data_dir, peer_pub) else {
        return false;
    };
    let dev = bundle.cert.device_ed_pub;
    matches!(find_sendable_peer_session(data_dir, &dev), Ok(None))
        && matches!(find_confirmed_peer_session(data_dir, &dev), Ok(Some(_)))
}

/// The RLB1 probe could not reach the peer. With a confirmed session the send
/// path stages the message durably before dialing, so run it: the message is
/// then queued and retried on the next send. Without one, say plainly that
/// nothing was queued (a first message cannot wait for the peer to come online).
#[allow(clippy::too_many_arguments)]
fn send_when_peer_unreachable(
    data_dir: &Path,
    id: &Identity,
    registry: &DeviceRegistry,
    local_cert: &DeviceCertificate,
    peer: &str,
    peer_pub_hex: &str,
    peer_pub: &[u8; 32],
    text: &str,
    carrier: DialCarrier,
    probe_err: String,
    ctx: &SendCtx,
    handoff: &OutboxHandoff<'_>,
) -> Result<(), String> {
    let (peer_cert, record_key) = match offline_send_target(data_dir, peer_pub) {
        Ok(Some(target)) => target,
        Ok(None) => {
            // The long message horizon: it waits for a new session instead.
            if let Some(parked) = park_new_message(
                data_dir, id, peer_pub, text, carrier, &probe_err, ctx, handoff,
            ) {
                return parked;
            }
            if session_reset_live_enabled() && every_session_retired(data_dir, peer_pub) {
                return Err(peer_reset_unreachable_text(ctx));
            }
            return Err(not_sent_text(ctx, &probe_err, true));
        }
        Err(e) => {
            return Err(not_sent_text(
                ctx,
                &format!("{probe_err}; cached peer state is unavailable: {e}"),
                false,
            ));
        }
    };
    // The probe just failed: stage (and keep ordering behind any earlier queued
    // message) without dialing a second time, so an asleep peer costs one
    // timeout, not two.
    send_indexed_text(
        data_dir,
        id,
        registry,
        local_cert,
        &record_key,
        text,
        peer,
        peer_pub_hex,
        &peer_cert,
        carrier,
        Some(&probe_err),
        ctx,
        handoff,
        &mut SendReset::default(),
    )
}

/// A message that will only be queued (the contact cannot be reached): keep
/// room in the shared stage for sends to contacts that can be reached.
/// Measured as the stage measures itself (serialized entries), and fail
/// closed: a stage we cannot read has no known room.
fn offline_stage_room(data_dir: &Path, text: &str, ctx: &SendCtx) -> Result<(), String> {
    let staged = raven_core::list_staged_outbound_bodies(data_dir)
        .map_err(|e| not_sent_nothing_queued(ctx, &format!("outbound stage unreadable: {e}")))?;
    let bytes: usize = staged
        .iter()
        .map(|b| serde_json::to_vec(b).map_or(usize::MAX / 512, |v| v.len()))
        .sum::<usize>()
        + serde_json::to_vec(text).map_or(text.len() * 6, |v| v.len())
        + STAGE_ENTRY_OVERHEAD;
    if staged.len() >= OFFLINE_STAGE_MAX_ENTRIES || bytes > OFFLINE_STAGE_MAX_BYTES {
        return Err(offline_stage_full_text(ctx));
    }
    Ok(())
}

/// Messages to `recipient` that wait (prepared, queued or sent without an
/// ACK, and parked for the long message horizon), bounded by
/// [`MAX_QUEUED_PER_PEER`]. Agent payloads are raven-node's and not counted.
fn waiting_for_peer(
    data_dir: &Path,
    store: &IndexedSessionStore,
    recipient: &[u8; 32],
) -> Result<usize, String> {
    let app_rows = app_message_ids(data_dir, recipient);
    let queued = store
        .pending_endpoint_outbound_for_recipient(Some(recipient))
        .map_err(|e| e.redacted_display())?
        .into_iter()
        .chain(
            store
                .awaiting_ack_endpoint_outbound_for_recipient(Some(recipient))
                .map_err(|e| e.redacted_display())?,
        )
        .filter(|row| row.kind == EndpointOutboundKind::Message)
        .filter(|row| !worker_owned(data_dir, &app_rows, &row.message_id))
        .count();
    let parked = store
        .parked_for_recipient(recipient)
        .map_err(|e| e.redacted_display())?
        .len();
    Ok(queued + parked)
}

/// What a horizon re-seal or settle in this send did to the contact's parked
/// messages, in the send's words: those past their deadline ran out
/// (`previews`: their text, read before they went).
fn say_parked_settled(
    ctx: &SendCtx,
    previews: &HashMap<[u8; 16], String>,
    report: &raven_core::horizon::HorizonReport,
) {
    let preview = |mid: &[u8; 16]| previews.get(mid).cloned().unwrap_or_default();
    for (mid, never_sent) in &report.expired {
        if *never_sent {
            ctx.say_earlier_ran_out(&preview(mid));
        } else {
            ctx.say_earlier_failed(&preview(mid), EXPIRED_BEFORE_DELIVERY);
        }
    }
    for mid in &report.delivered {
        ctx.say_earlier_delivered(&preview(mid));
    }
}

/// The text of each of `peer`'s parked messages (for [`say_parked_settled`]).
fn parked_previews(
    data_dir: &Path,
    store: &IndexedSessionStore,
    peer: &[u8; 32],
) -> HashMap<[u8; 16], String> {
    store
        .parked_for_recipient(peer)
        .unwrap_or_default()
        .into_iter()
        .map(|row| (row.message_id, staged_preview(data_dir, &row.message_id)))
        .collect()
}

/// The long message horizon (Phase 5a, P5.8): `text` to the contact
/// `peer_pub`, unreachable now and with no session to queue it under, is
/// parked until its deadline (`now + MESSAGE_HORIZON_MS`) instead of NOT
/// SENT: its body is staged with the zero sentinel binding
/// ([`raven_core::horizon::SENTINEL_BINDING`]: no sealed copy exists yet),
/// a parked row holds its deadline, and raven-node's outbox is kicked; it
/// (or the next send that reaches the contact) sets up a new session, then
/// seals it. Under the peer's send lock. `None`: not parked, the caller says
/// NOT SENT as before: the gate is closed, the key is no current contact
/// (nothing would ever plan a route to it), or its identity or lineage is
/// revoked. Parked rows count toward [`MAX_QUEUED_PER_PEER`].
#[allow(clippy::too_many_arguments)]
fn park_new_message(
    data_dir: &Path,
    id: &Identity,
    peer_pub: &[u8; 32],
    text: &str,
    carrier: DialCarrier,
    probe_err: &str,
    ctx: &SendCtx,
    handoff: &OutboxHandoff<'_>,
) -> Option<Result<(), String>> {
    if !raven_core::horizon::horizon_live_enabled() {
        return None;
    }
    // The contact's device key: its cached certificate's (checked against
    // the contact), else the contact's own key, a primary device's.
    let bundle = load_cached_peer_bundle(data_dir, peer_pub)
        .ok()
        .flatten()
        .filter(|b| b.cert.user_ed_pub == *peer_pub || b.cert.device_ed_pub == *peer_pub);
    let device = bundle.as_ref().map_or(*peer_pub, |b| b.cert.device_ed_pub);
    if !matches!(
        raven_core::outbox::contact_admission(data_dir, &device),
        raven_core::outbox::ContactAdmission::Allowed(_)
    ) {
        return None;
    }
    let revoked = raven_core::device_sync::RevocationStore::load_checked(data_dir)
        .map(|r| r.identity_has_revocation(&device) || r.identity_has_revocation(peer_pub))
        .unwrap_or(true)
        || bundle
            .as_ref()
            .is_some_and(|b| peer_lineage_denied(data_dir, &b.cert).unwrap_or(true));
    if revoked {
        return None;
    }
    Some(park_new_message_for(
        data_dir, id, &device, text, carrier, probe_err, ctx, handoff,
    ))
}

#[allow(clippy::too_many_arguments)]
fn park_new_message_for(
    data_dir: &Path,
    id: &Identity,
    device: &[u8; 32],
    text: &str,
    carrier: DialCarrier,
    probe_err: &str,
    ctx: &SendCtx,
    handoff: &OutboxHandoff<'_>,
) -> Result<(), String> {
    use rand::RngCore;
    use raven_core::horizon::{message_deadline, settle_parked, HorizonReport, SENTINEL_BINDING};
    let max_text = raven_core::lan_noise::MAX_LAN_ENDPOINT_TEXT;
    if text.len() > max_text {
        return Err(format!(
            "message too large for {} (max {} bytes)",
            carrier.label(),
            max_text
        ));
    }
    let now = now_ms();
    let mut store = IndexedSessionStore::open(data_dir).map_err(|e| e.redacted_display())?;
    // What already ran out goes first, so it neither counts nor waits.
    let previews = parked_previews(data_dir, &store, device);
    let mut settled = HorizonReport::default();
    settle_parked(data_dir, id, &mut store, device, now, &mut settled)
        .map_err(|e| not_sent_nothing_queued(ctx, &e))?;
    for mid in settled.finished() {
        let _ = clear_object_routes(data_dir, &[mid]);
    }
    say_parked_settled(ctx, &previews, &settled);
    let waiting = waiting_for_peer(data_dir, &store, device)?;
    if waiting >= MAX_QUEUED_PER_PEER {
        return Err(queue_full_text(ctx, waiting));
    }
    offline_stage_room(data_dir, text, ctx)?;
    // Lock and capacity held from here until the body is staged.
    let guard =
        raven_core::OutboundStageSendGuard::acquire(data_dir, text, now).map_err(|e| match e {
            raven_core::ChatHistoryError::TooLarge => {
                not_sent_nothing_queued(ctx, "outbound stage capacity exceeded")
            }
            other => not_sent_nothing_queued(ctx, &other.to_string()),
        })?;
    let mut mid = [0u8; 16];
    while mid == [0u8; 16] {
        rand::rngs::OsRng.fill_bytes(&mut mid);
    }
    let deadline = message_deadline(now);
    // The row first: a crash before the body is staged leaves a parked row
    // with no body, which the next horizon step gives up, never a stage
    // nothing would ever send.
    match store.park_outbound(device, &mid, None, now, deadline, now) {
        Ok(true) => {}
        Ok(false) => {
            return Err(not_sent_nothing_queued(
                ctx,
                "the message could not be parked",
            ))
        }
        Err(e) => return Err(not_sent_nothing_queued(ctx, &e.redacted_display())),
    }
    if let Err(e) = raven_core::ensure_outbound_queued_history_under_send_guard(
        &guard,
        device,
        &SENTINEL_BINDING,
        &SENTINEL_BINDING,
        &mid,
        now,
        Some(text),
    ) {
        drop(guard);
        // The stage goes before the row, as it came after it: a crash in
        // between leaves a parked row with no body (given up by the next
        // step), never a sentinel stage with no row.
        let _ = raven_core::clear_staged_outbound_body(data_dir, &mid);
        let _ = store.give_up_parked(device, &mid);
        return Err(not_sent_nothing_queued(ctx, &e));
    }
    drop(guard);
    trace_delivery::trace_event(
        "ash/pair_init_lab.rs:park_new_message",
        "TRACE_HORIZON_PARKED",
        "PARKED",
        Some(&hex::encode(&mid[..4])),
        Some(carrier.label()),
    );
    // Never written by a carrier: if it runs out, it never left this
    // computer (CP.6). Recorded before the kick.
    handoff.record_own(&mid, deadline);
    let _ = raven_core::outbox::set_object_unsent(data_dir, &mid, true, now);
    let note = handoff.note_own(&mid, deadline);
    Err(parked_text(
        ctx,
        &format!(
            "{probe_err}; HORIZON_PARKED; mid={}…",
            hex::encode(&mid[..4])
        ),
        &quoted_preview(text),
        &note,
    ))
}

/// One line for a failed `ash send`. The outcomes differ, and one blanket
/// "send refused:" prefix misreported two of them:
/// - the text is **queued** locally (the carrier dial failed after staging):
///   `not delivered yet: ... queued locally ...`;
/// - the frames were **sent** and only the ACK is missing: `sent, delivery
///   unconfirmed ...` (the peer may already hold the message, so a script must not
///   read it as "not sent" and blindly send the text again);
/// - nothing of the message was queued: `NOT SENT: ...`, or the old
///   `send refused: ...` for text no sentence covers.
///
/// The send path already returns these sentences; this only turns text from
/// elsewhere into one (see `ext::friendly_send_error`, which takes the contact's
/// name for a more personal sentence).
pub(crate) fn send_failure_line(error: &str) -> String {
    friendly_send_error(error, "")
}

/// Why an earlier queued message was given up: it outlived its envelope validity
/// before it could be (re)delivered; the retry paths abandon it, and this says so.
const EXPIRED_BEFORE_DELIVERY: &str = "it expired before delivery was confirmed and was marked \
     expired (not delivered); send it again if you still need it";

/// Why a queued message was abandoned: it was sealed under a session the peer no
/// longer accepts while a newer confirmed session exists, so it can never be
/// delivered.
const SUPERSEDED_SESSION: &str = "it was sealed under an older connection that the other side \
     no longer accepts (a newer one exists) and was marked failed; send it again if you still \
     need it";

/// The daemon's error code for "the peer completed the handshake, took the
/// frames, and closed the connection without answering": a refusal it gave no
/// reason for (not a contact, no session with us, a session it no longer holds).
const PEER_REFUSED_CODE: &str = "_DIAL_PEER_CLOSED";

fn is_peer_refusal(detail: &str) -> bool {
    detail.contains(PEER_REFUSED_CODE)
}

/// The new message was refused before anything of it was staged.
fn not_sent_nothing_queued(ctx: &SendCtx, detail: &str) -> String {
    if detail.starts_with("NOT SENT") {
        detail.to_string()
    } else {
        not_sent_text(ctx, detail, false)
    }
}

/// `"first words..."` of a message that is still staged for retry, so a line about
/// an earlier message shows the user's own words instead of a hex id. Empty once
/// the staged body is gone (or cannot be read).
fn staged_preview(data_dir: &Path, message_id: &[u8; 16]) -> String {
    raven_core::load_staged_outbound_body(data_dir, message_id)
        .ok()
        .flatten()
        .map(|staged| quoted_preview(&staged.body))
        .unwrap_or_default()
}

/// Whether a failed retry of a queued row proves the row can never be delivered:
/// the peer is reachable (the RLB1 probe worked), it refused the frames, and the
/// row is sealed under a session other than the one this send uses, i.e. one a
/// newer confirmed session has superseded. A row on the *current* session is
/// kept (the refusal may be transient, and a duplicate must stay deduplicated).
fn superseded_row_was_refused(
    peer_unreachable: Option<&str>,
    row_key: &IndexedSessionRecordKey,
    selected: &IndexedSessionRecordKey,
    detail: &str,
) -> bool {
    peer_unreachable.is_none() && row_key != selected && is_peer_refusal(detail)
}

/// Daemon parity (`load_session_bound_peer_cert`): revocation is decided
/// against the certificate bound into the confirmed session at PairInit, never
/// against whatever certificate the peer presents now (RLB1 reply or cache). A
/// holder of a revoked device key can re-certify the same key under a new
/// `device_id`, which a legacy `(user, device_id)` revocation record does not
/// match. Such a certificate never hashes to the session's remote digest, so it
/// is refused here, before any seal or dial, instead of the message being
/// delivered and only the ACK acceptance failing.
fn require_session_bound_peer_cert(
    peer_cert: &DeviceCertificate,
    bound_digest: &[u8; 32],
) -> Result<(), String> {
    let presented = raven_core::device_certificate_hash(peer_cert)
        .map_err(|e| format!("peer device cert hash: {e}"))?;
    if presented != *bound_digest {
        return Err(format!(
            "{}: the peer's certificate is not the one bound into the confirmed session \
             (renewed or re-certified); nothing was sent",
            raven_core::ATSAM_SESSION_REQUIRED
        ));
    }
    Ok(())
}

/// Daemon parity (`seal_app_payload_under_session`): never seal to, retry
/// toward or resend to a revoked peer lineage, and refuse a retired local one.
/// Only the session-bound peer certificate is evaluated
/// (`require_session_bound_peer_cert`). Undelivered messages for a revoked peer
/// are abandoned (marked failed) so they are not retried on every later send.
fn refuse_revoked_peer(
    data_dir: &Path,
    store: &mut IndexedSessionStore,
    local_cert: &DeviceCertificate,
    peer_cert: &DeviceCertificate,
    bound_digest: &[u8; 32],
) -> Result<(), String> {
    require_session_bound_peer_cert(peer_cert, bound_digest)?;
    let peer_revoked = peer_lineage_denied(data_dir, peer_cert)?;
    if peer_revoked {
        abandon_undelivered_to_peer(data_dir, store, &peer_cert.device_ed_pub)?;
    }
    raven_core::refuse_if_session_lineage_revoked(data_dir, local_cert, peer_cert).map_err(|e| {
        if peer_revoked {
            format!("{e}: peer device lineage is revoked; nothing was sent; any queued messages for it were abandoned")
        } else {
            e
        }
    })
}

#[allow(clippy::too_many_arguments)]
fn send_indexed_text(
    data_dir: &Path,
    id: &Identity,
    registry: &DeviceRegistry,
    local_cert: &DeviceCertificate,
    record_key: &IndexedSessionRecordKey,
    text: &str,
    lan_dial: &str,
    peer_pub_hex: &str,
    peer_cert: &DeviceCertificate,
    carrier: DialCarrier,
    // `Some(reason)`: the peer is already known unreachable (failed RLB1 probe).
    // Stage and queue as usual but skip the network, failing with `reason`.
    peer_unreachable: Option<&str>,
    ctx: &SendCtx,
    // Where a message this send leaves undelivered goes: raven-node's outbox.
    handoff: &OutboxHandoff<'_>,
    // Session reset: query a refusal once, restart once (see `SendReset`).
    reset: &mut SendReset,
) -> Result<(), String> {
    // LAN and Internet both carry each envelope as one Noise transport message.
    let max_text = raven_core::lan_noise::MAX_LAN_ENDPOINT_TEXT;
    if text.len() > max_text {
        return Err(format!(
            "message too large for {} (max {} bytes)",
            carrier.label(),
            max_text
        ));
    }
    let now = now_ms();
    let local_device = AuthorizedEndpointDevice::authorize(local_cert, id, registry, now)
        .map_err(|e| e.redacted_display())?;
    let mut store = IndexedSessionStore::open(data_dir).map_err(|e| e.redacted_display())?;
    // Before any retry, resend or seal: an existing confirmed session skips the
    // PairInit-time revocation check, so enforce it here, on the cert the
    // session is bound to.
    let bound_digest = store
        .remote_certificate_digest(record_key)
        .map_err(|e| e.redacted_display())?;
    refuse_revoked_peer(data_dir, &mut store, local_cert, peer_cert, &bound_digest)?;
    let session_expires = store
        .session_expires_at(record_key)
        .map_err(|e| e.redacted_display())?;
    // The shared validity policy (min(session end, now + 24 h)).
    let expires = envelope_expires_at(now, session_expires)?;
    let mut rng = rand::rngs::OsRng;
    let replies = std::cell::RefCell::new(Vec::<Vec<u8>>::new());
    // How the message dial's link travelled (`status delivered` says so).
    let dial_path = std::cell::Cell::new(None::<DeliveryPath>);
    let dial_err = std::cell::RefCell::new(None::<String>);
    let recipient = &peer_cert.device_ed_pub;
    raven_core::reconcile_outbound_stage_history(data_dir)?;
    // Crash leftovers of a re-seal are repaired before any row is retried
    // (on every path, the unreachable one included).
    if session_reset_live_enabled() {
        let _ = raven_core::session_reset::reconcile_resealed_outbound(
            data_dir, id, &mut store, recipient, now,
        );
    }
    let session_id = store
        .session_id_for_record_key(record_key)
        .map_err(|e| e.redacted_display())?;
    // Compose text is only set for the *new* send. Retries reload body from the
    // protected outbound stage written before ChatHistory on the first dial attempt.
    let history_queue_text = std::cell::RefCell::new(None::<String>);
    let dial_session = std::cell::RefCell::new(session_id);
    let dial_expected_digest = std::cell::RefCell::new(None::<[u8; 32]>);
    // Held from capacity preflight until stage write succeeds; dropped before network.
    let stage_guard = std::cell::RefCell::new(None::<raven_core::OutboundStageSendGuard>);
    // Exact binding observed in the dial callback when handoff fails.
    let failed_binding = std::cell::RefCell::new(None::<([u8; 32], [u8; 32], [u8; 16])>);
    // True once the new message body is durably staged, i.e. a failed dial left
    // it queued for retry (a staging failure did not).
    let staged_for_retry = std::cell::Cell::new(false);
    // True when the staged object of the current dial was handed to the outbox
    // queue instead of a carrier (see the dial closure).
    let queued_offline = std::cell::Cell::new(false);
    // The link to the peer is down for the rest of this send: the probe failed
    // (`peer_unreachable`), or a dial failed at the transport. Every later
    // object of this send then goes to the outbox queue without a dial, in
    // order, instead of one timeout per queued message.
    let link_down = std::cell::RefCell::new(peer_unreachable.map(str::to_string));
    // This one object goes to the outbox queue without a dial (an earlier
    // prepared row whose own `--carrier` excludes this send's carrier): the
    // worker sends it over its own carrier, and its lane is free meanwhile.
    let handoff_only = std::cell::Cell::new(false);
    // The message id of the object the closure is handling (for `unsent`),
    // and when its envelope runs out.
    let dial_mid = std::cell::Cell::new(None::<[u8; 16]>);
    let dial_expiry = std::cell::Cell::new(0u64);
    // The exact Message bytes of the current dial (a session reset query
    // carries them when the peer refuses).
    let dial_bytes = std::cell::RefCell::new(None::<Vec<u8>>);
    let mut dial = |digest: &[u8; 32], bytes: &[u8]| {
        let oversize = bytes.len() > raven_core::lan_noise::MAX_TRANSPORT_PLAINTEXT;
        if oversize {
            *dial_err.borrow_mut() = Some(format!(
                "packed envelope exceeds {} transport limit",
                carrier.label()
            ));
            return Err(());
        }
        if let Some(expected) = *dial_expected_digest.borrow() {
            if expected != *digest {
                *dial_err.borrow_mut() = Some("outbound object digest mismatch".into());
                return Err(());
            }
        }
        if let Some(env) = raven_core::Envelope::unpack(bytes) {
            if env.env_type == raven_core::EnvType::Message as u8 {
                dial_mid.set(Some(env.message_id));
                dial_expiry.set(env.expires_at);
                *dial_bytes.borrow_mut() = Some(bytes.to_vec());
                let compose = history_queue_text.borrow();
                let session = *dial_session.borrow();
                *failed_binding.borrow_mut() = Some((session, *digest, env.message_id));
                let stage_result = match stage_guard.borrow().as_ref() {
                    Some(guard) => raven_core::ensure_outbound_queued_history_under_send_guard(
                        guard,
                        &peer_cert.device_ed_pub,
                        &session,
                        digest,
                        &env.message_id,
                        now,
                        compose.as_deref(),
                    ),
                    None => raven_core::ensure_outbound_queued_history(
                        data_dir,
                        &peer_cert.device_ed_pub,
                        &session,
                        digest,
                        &env.message_id,
                        now,
                        compose.as_deref(),
                    ),
                };
                if let Err(e) = stage_result {
                    *dial_err.borrow_mut() = Some(e);
                    return Err(());
                }
                staged_for_retry.set(true);
                // Never hold BEGIN EXCLUSIVE across carrier dial (up to ~45s).
                let _ = stage_guard.borrow_mut().take();
            }
        }
        let skip_dial = link_down.borrow().clone().or_else(|| {
            handoff_only
                .get()
                .then(|| "its own carrier choice excludes this one".to_string())
        });
        if let Some(reason) = skip_dial {
            *dial_err.borrow_mut() = Some(reason);
            if staged_for_retry.get() {
                // The body is durably staged and the sealed bytes are in the
                // store: hand the object to the outbox queue (raven-node resends
                // queued objects from those exact bytes until the ACK) instead
                // of leaving it prepared, which would block every later message
                // to this peer until it is delivered.
                queued_offline.set(true);
                return Ok(*digest);
            }
            return Err(());
        }
        let dial_once = || {
            ipc_carrier_dial_reply_patient(
                data_dir,
                carrier,
                lan_dial,
                peer_pub_hex,
                &[bytes.to_vec()],
            )
        };
        let tor_checked = carrier == DialCarrier::Onion && peer_unreachable.is_none();
        let dialled = if tor_checked {
            dial_after_tor_check(ONION_SECOND_TRY_WITHIN, dial_once)
        } else {
            dial_once()
        };
        match dialled {
            Ok(reply) => {
                *replies.borrow_mut() = reply.frames;
                dial_path.set(reply.path);
                if let Some(mid) = dial_mid.get() {
                    let _ = raven_core::outbox::set_object_unsent(data_dir, &mid, false, now);
                }
                Ok(*digest)
            }
            Err(e) => {
                let refused = is_peer_refusal(&e);
                if refused {
                    // The peer took the frames, then refused them: written. A
                    // prepared row stays prepared, so its route record says
                    // so (made with this send's carrier choice when it has
                    // none): its expiry must not read "it never left this
                    // computer" (review C-time-deadlines-1).
                    if let Some(mid) = dial_mid.get() {
                        let _ = raven_core::outbox::set_object_unsent(data_dir, &mid, false, now);
                        handoff.record(&mid, dial_expiry.get());
                        let _ = raven_core::outbox::set_object_written(
                            data_dir,
                            &mid,
                            &peer_cert.device_ed_pub,
                            dial_expiry.get(),
                            now,
                        );
                    }
                } else {
                    *link_down.borrow_mut() = Some(e.clone());
                }
                *dial_err.borrow_mut() = Some(e);
                if staged_for_retry.get() && !refused {
                    // A transport failure (refused connection, timeout, reset):
                    // hand the staged object to the outbox queue as above, so a
                    // flaky link does not block the next message either. A
                    // peer that took the frames and refused them keeps the old
                    // path (it may not accept us at all).
                    queued_offline.set(true);
                    return Ok(*digest);
                }
                Err(())
            }
        }
    };
    // The long message horizon (P5.8): the contact's parked messages are
    // sealed again into this session first, under this send's lock, so this
    // message never overtakes them; they then go out below as queued rows,
    // in order. Best effort: what stays parked waits for raven-node.
    if raven_core::horizon::horizon_live_enabled() {
        let previews = parked_previews(data_dir, &store, recipient);
        if let Ok(report) = raven_core::horizon::reseal_parked_before_send(
            data_dir, id, &mut store, recipient, record_key, now,
        ) {
            let _ = clear_object_routes(data_dir, &report.finished());
            say_parked_settled(ctx, &previews, &report);
        }
    }
    // Earlier messages to this peer go first (queued, then sent without an ACK),
    // in order. When the probe already found the peer unreachable they are not
    // dialled again (that only adds a timeout), and one whose dial fails at the
    // transport goes back to the outbox queue: either way they stay queued for
    // raven-node's outbox and this message is queued behind them, up to
    // MAX_QUEUED_PER_PEER waiting messages per peer.
    let mut earlier: Vec<(raven_core::EndpointOutbound, bool)> = store
        .pending_endpoint_outbound_for_recipient(Some(recipient))
        .map_err(|e| e.redacted_display())?
        .into_iter()
        .map(|row| (row, false))
        .collect();
    earlier.extend(
        store
            .awaiting_ack_endpoint_outbound_for_recipient(Some(recipient))
            .map_err(|e| e.redacted_display())?
            .into_iter()
            .map(|row| (row, true)),
    );
    // Each queued object's own route record (its `--carrier` choice and
    // routes): read once. Best effort, like the records themselves. Whether
    // it ever left this computer is read past its deadline too.
    let records = raven_core::outbox::object_route_records(data_dir, now).unwrap_or_default();
    let evidence = raven_core::outbox::object_route_evidence(data_dir, now).unwrap_or_default();
    // A restarted send whose own message was re-sealed: did it get through?
    let mut own_delivered = false;
    // Agent payloads (app channel) belong to raven-node's worker: never
    // dialled, abandoned or counted here (design §8.7).
    let app_rows = app_message_ids(data_dir, recipient);
    for (earlier_row, resend) in earlier {
        if earlier_row.kind != EndpointOutboundKind::Message {
            continue;
        }
        if worker_owned(data_dir, &app_rows, &earlier_row.message_id) {
            continue;
        }
        // Held in a session the contact lost: the reset step re-seals it; it
        // never blocks this send (on any path, gate or not: the store refuses
        // to retry it anyway).
        if store
            .session_is_retired(&earlier_row.session_id)
            .unwrap_or(false)
        {
            continue;
        }
        let own = reset.own_mid == Some(earlier_row.message_id);
        let Some(row_key) = store
            .record_key_for_session_id(&earlier_row.session_id)
            .map_err(|e| e.redacted_display())?
        else {
            continue;
        };
        let preview = staged_preview(data_dir, &earlier_row.message_id);
        let note = || {
            handoff.note(
                &earlier_row.message_id,
                envelope_expiry(&earlier_row.immutable_envelope_bytes),
            )
        };
        // An ACK that came back another way (pushed by the peer's outbox, or
        // seen by raven-node) already delivered it: record that, never dial it.
        if outbound_already_delivered(
            &store,
            &earlier_row.session_id,
            &earlier_row.message_id,
            recipient,
        )? {
            record_outbound_delivered(
                data_dir,
                &mut store,
                recipient,
                &earlier_row.session_id,
                &earlier_row.message_id,
            )?;
            let _ = clear_object_routes(data_dir, &[earlier_row.message_id]);
            ctx.say_earlier_delivered(&preview);
            continue;
        }
        let expiry = envelope_expiry(&earlier_row.immutable_envelope_bytes);
        let record = records.get(&earlier_row.message_id);
        let never_left = never_left_computer(resend, evidence.get(&earlier_row.message_id));
        let say_expired = |ctx: &SendCtx| {
            if never_left {
                ctx.say_earlier_ran_out(&preview);
            } else {
                ctx.say_earlier_failed(&preview, EXPIRED_BEFORE_DELIVERY);
            }
        };
        if link_down.borrow().is_some() && expiry <= now {
            // Never deliverable any more: give it up instead of letting it
            // take a place in the queue (the store refuses to retry it), or
            // park it until its deadline (the long message horizon).
            match expire_row(
                data_dir,
                &mut store,
                &row_key,
                recipient,
                &earlier_row,
                never_left,
                now,
            )? {
                Some(GiveUp::Abandoned) => say_expired(ctx),
                Some(GiveUp::Delivered) => ctx.say_earlier_delivered(&preview),
                None => {}
            }
            continue;
        }
        if link_down.borrow().is_some() && resend {
            // Queued, ahead of this message: raven-node's outbox retries it.
            // Do not `note()` it: the handoff kicks the worker once per send,
            // and that kick must come after this send's own message is in the
            // store. Only restore a lost route record (crash, failed write).
            if record.is_none() {
                handoff.record(&earlier_row.message_id, expiry);
            }
            continue;
        }
        // Never redial an object over a carrier its own `--carrier` excludes:
        // the worker plans it from its record. A queued one simply waits for
        // it; a prepared one is handed to the queue (no dial) so it does not
        // block this lane.
        let excluded = record.is_some_and(|r| !r.choice.allows(carrier.outbox()));
        if excluded && resend {
            continue;
        }
        handoff_only.set(excluded);
        dial_mid.set(None);
        *dial_session.borrow_mut() = earlier_row.session_id;
        *dial_expected_digest.borrow_mut() = Some(earlier_row.object_digest);
        replies.borrow_mut().clear();
        let result = if resend {
            store.resend_queued_endpoint_outbound(
                &row_key,
                &earlier_row.object_digest,
                &local_device,
                now,
                &mut dial,
            )
        } else {
            store.retry_endpoint_outbound(
                &row_key,
                &earlier_row.object_digest,
                &local_device,
                now,
                &mut dial,
            )
        };
        match result {
            Ok(row) => {
                if queued_offline.replace(false) {
                    // Handed (back) to the outbox queue, nothing taken on the
                    // wire: it stays queued, ahead of this message. A prepared
                    // row was never written by a carrier at all: say so.
                    if !resend {
                        if record.is_none() {
                            handoff.record(&row.message_id, expiry);
                        }
                        let _ = raven_core::outbox::set_object_unsent(
                            data_dir,
                            &row.message_id,
                            true,
                            now,
                        );
                    }
                    continue;
                }
                let frames = replies.borrow();
                if let Some(ack) = first_ack_frame(&frames) {
                    let ack = ack.to_vec();
                    drop(frames);
                    finish_outbound_delivered(
                        data_dir,
                        &mut store,
                        &row_key,
                        peer_cert,
                        &earlier_row.session_id,
                        &earlier_row.object_digest,
                        &row.message_id,
                        &ack,
                        now,
                        carrier.outbox(),
                    )
                    .map_err(|e| finish_failure_text(ctx, &e, &preview, &note()))?;
                    let _ = clear_object_routes(data_dir, &[row.message_id]);
                    if own {
                        own_delivered = true;
                        ctx.say_delivered(carrier.label(), dial_path.get(), &row.message_id);
                    } else {
                        ctx.say_earlier_delivered(&preview);
                    }
                } else if own {
                    return Err(unconfirmed_text(
                        ctx,
                        &format!(
                            "WAITING_FOR_ENDPOINT_ACK: no sealed ACK came back; mid={}…",
                            hex::encode(&row.message_id[..4])
                        ),
                        &quoted_preview(text),
                        &note(),
                    ));
                } else {
                    // Sent again, no ACK yet: the outbox keeps resending it.
                    let _ = note();
                    return Err(earlier_unconfirmed_text(ctx, &preview));
                }
            }
            Err(raven_core::IndexedSessionStoreError::NotFound)
            | Err(raven_core::IndexedSessionStoreError::BindingConflict) => continue,
            Err(raven_core::IndexedSessionStoreError::EndpointNotCurrentlyValid) => {
                // Expired by its own clock: give it up. Otherwise the clock
                // moved (a step backwards): keep it, raven-node retries it.
                if envelope_expiry(&earlier_row.immutable_envelope_bytes) <= now {
                    match expire_row(
                        data_dir,
                        &mut store,
                        &row_key,
                        recipient,
                        &earlier_row,
                        never_left,
                        now,
                    )? {
                        Some(GiveUp::Abandoned) => say_expired(ctx),
                        Some(GiveUp::Delivered) => ctx.say_earlier_delivered(&preview),
                        None => {}
                    }
                    continue;
                }
                if resend {
                    continue;
                }
                return Err(earlier_undelivered_text(
                    ctx,
                    CLOCK_MOVED,
                    &preview,
                    &note(),
                ));
            }
            Err(e) => {
                let detail = dial_err
                    .borrow()
                    .clone()
                    .unwrap_or_else(|| e.redacted_display());
                if stage_or_body_handoff_failure(&detail) {
                    give_up_row(
                        data_dir,
                        &mut store,
                        &row_key,
                        recipient,
                        &earlier_row,
                        HISTORY_FAILED,
                    )?;
                    return Err(detail);
                }
                if reset.enabled && !reset.queried && is_peer_refusal(&detail) {
                    // The contact took the frames and closed: ask, once, whether
                    // it still holds that session.
                    reset.queried = true;
                    if query_retires_session(
                        data_dir,
                        id,
                        &local_cert.device_ed_pub,
                        recipient,
                        carrier,
                        lan_dial,
                        peer_pub_hex,
                        &mut store,
                        &earlier_row.immutable_envelope_bytes,
                    ) {
                        reset.restart = true;
                        return Err(detail);
                    }
                }
                if superseded_row_was_refused(peer_unreachable, &row_key, record_key, &detail) {
                    // Sealed under a session the (reachable) peer refuses while a
                    // newer one exists: it can never be accepted, and left alone it
                    // would block every later send until its envelope expires.
                    match give_up_row(
                        data_dir,
                        &mut store,
                        &row_key,
                        recipient,
                        &earlier_row,
                        HISTORY_FAILED,
                    )? {
                        GiveUp::Abandoned => ctx.say_earlier_failed(&preview, SUPERSEDED_SESSION),
                        GiveUp::Delivered => ctx.say_earlier_delivered(&preview),
                    }
                    continue;
                }
                return Err(earlier_undelivered_text(ctx, &detail, &preview, &note()));
            }
        }
    }
    // The loops above ran the shared `dial` for *earlier* messages and left their
    // binding and staged flag behind. They describe someone else's message: reset
    // them so the new send's own dial is the only thing that can say "queued".
    // (A stale binding made a send that failed at key reservation report that its
    // text was queued under the *earlier* message's id; it was never staged.)
    *failed_binding.borrow_mut() = None;
    staged_for_retry.set(false);
    queued_offline.set(false);
    handoff_only.set(false);
    dial_mid.set(None);
    *dial_err.borrow_mut() = None;
    if let Some(mid) = reset.own_mid {
        // This text already went out above as its re-sealed copy: never seal
        // it a second time.
        if own_delivered {
            return Ok(());
        }
        return Err(queued_text(
            ctx,
            &format!(
                "{}; mid={}…",
                raven_core::session_reset::code::PEER_RESET,
                hex::encode(&mid[..4])
            ),
            &quoted_preview(text),
            &handoff.note_own(&mid, expires),
        ));
    }
    // Whatever the loop above could not deliver still waits, ahead of this
    // message (parked ones too): bound how many may wait for one peer.
    let waiting = waiting_for_peer(data_dir, &store, recipient)?;
    if waiting >= MAX_QUEUED_PER_PEER {
        return Err(queue_full_text(ctx, waiting));
    }
    if link_down.borrow().is_some() {
        // This message will only be queued.
        offline_stage_room(data_dir, text, ctx)?;
    }
    *history_queue_text.borrow_mut() = Some(text.to_string());
    *dial_session.borrow_mut() = session_id;
    *dial_expected_digest.borrow_mut() = None;
    // Lock+capacity held until stage write inside dial (or send fails).
    *stage_guard.borrow_mut() = Some(
        raven_core::OutboundStageSendGuard::acquire(data_dir, text, now).map_err(|e| match e {
            raven_core::ChatHistoryError::TooLarge => {
                "outbound stage capacity exceeded".to_string()
            }
            other => other.to_string(),
        })?,
    );
    let outbound = match store.send_message_envelope(
        record_key,
        text,
        &local_device,
        now,
        expires,
        now,
        &mut rng,
        &mut dial,
    ) {
        Ok(row) => {
            let _ = stage_guard.borrow_mut().take();
            row
        }
        Err(e) => {
            let detail = dial_err
                .borrow()
                .clone()
                .unwrap_or_else(|| e.redacted_display());
            let binding = failed_binding.borrow_mut().take();
            let _ = stage_guard.borrow_mut().take();
            // A binding that was prepared but never staged means the staging step
            // itself failed (chat history unreadable, Keychain denied, history locked,
            // ...). The body and the reserved outbound row may be half-written, and a
            // row left pending would be delivered silently by the NEXT send, so a user
            // who retypes the text as advised would send it twice. Abandon it, so that
            // "nothing was queued" is true.
            if stage_or_body_handoff_failure(&detail)
                || (binding.is_some() && !staged_for_retry.get())
            {
                if let Some((sid, digest, mid)) = binding {
                    abandon_prepared_binding(
                        data_dir,
                        &mut store,
                        &peer_cert.device_ed_pub,
                        &sid,
                        &digest,
                        &mid,
                    )?;
                }
                return Err(detail);
            }
            if let (true, false, Some((_, _, mid)), Some(bytes)) = (
                reset.enabled,
                reset.queried,
                binding,
                dial_bytes.borrow().clone(),
            ) {
                if staged_for_retry.get() && is_peer_refusal(&detail) {
                    reset.queried = true;
                    if query_retires_session(
                        data_dir,
                        id,
                        &local_cert.device_ed_pub,
                        recipient,
                        carrier,
                        lan_dial,
                        peer_pub_hex,
                        &mut store,
                        &bytes,
                    ) {
                        reset.restart = true;
                        reset.own_mid = Some(mid);
                        return Err(detail);
                    }
                }
            }
            return Err(match binding {
                // Only this call's own dial can have staged this message.
                Some((_, _, mid)) if staged_for_retry.get() => queued_text(
                    ctx,
                    &format!("{detail}; mid={}…", hex::encode(&mid[..4])),
                    &quoted_preview(text),
                    &handoff.note_own(&mid, expires),
                ),
                _ => not_sent_nothing_queued(ctx, &detail),
            });
        }
    };

    let mid = hex::encode(&outbound.message_id[..4]);
    if queued_offline.get() {
        // Nothing went on the wire: queued for raven-node's outbox, behind any
        // earlier message to this peer. Marked unsent before the kick, so the
        // worker never lists it as sent.
        let detail = dial_err.borrow().clone().unwrap_or_default();
        handoff.record_own(&outbound.message_id, expires);
        let _ = raven_core::outbox::set_object_unsent(data_dir, &outbound.message_id, true, now);
        return Err(queued_text(
            ctx,
            &format!("{detail}; mid={mid}…"),
            &quoted_preview(text),
            &handoff.note_own(&outbound.message_id, expires),
        ));
    }
    trace_delivery::trace_event(
        "ash/pair_init_lab.rs:send_indexed_text",
        "TRACE_INDEXED_MESSAGE_DIALED",
        "WAITING_FOR_ENDPOINT_ACK",
        Some(&mid),
        Some(carrier.label()),
    );
    if let Some(ack) = first_ack_frame(&replies.borrow()) {
        finish_outbound_delivered(
            data_dir,
            &mut store,
            record_key,
            peer_cert,
            &session_id,
            &outbound.object_digest,
            &outbound.message_id,
            ack,
            now,
            carrier.outbox(),
        )
        .map_err(|e| {
            finish_failure_text(
                ctx,
                &e,
                &quoted_preview(text),
                &handoff.note_own(&outbound.message_id, expires),
            )
        })?;
        // Only a verified ACK gets here: "delivered" means the receiver confirmed.
        ctx.say_delivered(carrier.label(), dial_path.get(), &outbound.message_id);
        trace_delivery::trace_event(
            "ash/pair_init_lab.rs:send_indexed_text",
            "TRACE_ENDPOINT_ACK_ACCEPTED",
            "DELIVERED",
            Some(&mid),
            Some("accept_ack_envelope"),
        );
    } else {
        return Err(unconfirmed_text(
            ctx,
            &format!("WAITING_FOR_ENDPOINT_ACK: no sealed ACK came back; mid={mid}…"),
            &quoted_preview(text),
            &handoff.note_own(&outbound.message_id, expires),
        ));
    }
    Ok(())
}

/// The detail of an earlier message the store refuses although its envelope
/// has not expired: the computer's clock moved back past its creation time.
const CLOCK_MOVED: &str = "ENDPOINT_NOT_CURRENTLY_VALID: the earlier message is dated ahead of \
     this computer's clock (did the clock change?); it is kept, not given up, and raven-node \
     tries it again";

/// [`give_up_outbound`] for one outbox row; its route record goes too.
fn give_up_row(
    data_dir: &Path,
    store: &mut IndexedSessionStore,
    key: &IndexedSessionRecordKey,
    peer: &[u8; 32],
    row: &raven_core::EndpointOutbound,
    delivery: &str,
) -> Result<GiveUp, String> {
    let outcome = give_up_outbound(
        data_dir,
        store,
        key,
        peer,
        &row.session_id,
        &row.object_digest,
        &row.message_id,
        delivery,
    )?;
    let _ = clear_object_routes(data_dir, &[row.message_id]);
    Ok(outcome)
}

/// An earlier message whose envelope expired: given up as before (its route
/// record cleared), or, with the long message horizon on and before its
/// deadline, parked for raven-node's outbox to seal again into a new
/// session (`None`: it waits, its route record kept). `never_left`: no
/// carrier ever wrote it.
fn expire_row(
    data_dir: &Path,
    store: &mut IndexedSessionStore,
    key: &IndexedSessionRecordKey,
    peer: &[u8; 32],
    row: &raven_core::EndpointOutbound,
    never_left: bool,
    now: u64,
) -> Result<Option<GiveUp>, String> {
    match park_or_give_up_expired(
        data_dir,
        store,
        key,
        peer,
        &row.session_id,
        &row.object_digest,
        &row.message_id,
        never_left,
        now,
    )? {
        ExpiredMessage::Parked { .. } => Ok(None),
        ExpiredMessage::GaveUp(outcome) => {
            let _ = clear_object_routes(data_dir, &[row.message_id]);
            Ok(Some(outcome))
        }
    }
}

fn stage_or_body_handoff_failure(detail: &str) -> bool {
    detail.contains("outbound body unavailable")
        || detail.contains("binding mismatch")
        || detail.contains("outbound stage capacity exceeded")
}

fn abandon_prepared_binding(
    data_dir: &Path,
    store: &mut IndexedSessionStore,
    peer_pub: &[u8; 32],
    session_id: &[u8; 32],
    object_digest: &[u8; 32],
    message_id: &[u8; 16],
) -> Result<(), String> {
    let Some(pending_key) = store
        .record_key_for_session_id(session_id)
        .map_err(|e| e.redacted_display())?
    else {
        return Ok(());
    };
    let pending = store
        .pending_endpoint_outbound_for_recipient(Some(peer_pub))
        .map_err(|e| e.redacted_display())?
        .into_iter()
        .find(|row| {
            row.kind == EndpointOutboundKind::Message
                && row.session_id == *session_id
                && row.object_digest == *object_digest
                && row.message_id == *message_id
        });
    let Some(pending) = pending else {
        return Ok(());
    };
    give_up_row(
        data_dir,
        store,
        &pending_key,
        peer_pub,
        &pending,
        HISTORY_FAILED,
    )?;
    Ok(())
}

/// How a failure of [`finish_outbound_delivered`] is told: an ACK for another
/// message leaves this one unconfirmed; anything else happened after the peer
/// acknowledged this message, so it must not be retyped.
fn finish_failure_text(ctx: &SendCtx, raw: &str, preview: &str, retry: &RetryNote) -> String {
    if raw.starts_with(ACK_FOR_ANOTHER_MESSAGE) {
        unconfirmed_text(ctx, raw, preview, retry)
    } else {
        recorded_locally_failed_text(ctx, raw, preview, retry)
    }
}

pub fn export_lab_device_cert(data_dir: &Path, id: &Identity) -> Result<(), String> {
    let (cert, _) = ensure_local_device_cert(data_dir, id)?;
    let path = data_dir.join("lab_device_cert.json");
    let json = serde_json::to_string_pretty(&cert).map_err(|e| e.to_string())?;
    raven_core::atomic_write_private(&path, json.as_bytes())?;
    println!(
        "{C_BOLD}lab device cert{C_RESET} → {} (give peer; map key = your pub_hex)",
        path.display()
    );
    println!(
        "{C_DIM}peer_device_certs.json entry key{C_RESET} {}",
        hex::encode(id.public_key_bytes())
    );
    Ok(())
}

/// Decode an already-sealed RavenEnvelopeV1. Does not seal (O6 M3 lab).
pub fn decode_already_sealed_envelope_b64(envelope_b64: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    let raw = envelope_b64.trim();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(raw)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(raw))
        .map_err(|e| format!("envelope_b64: {e}"))?;
    if Envelope::unpack(&bytes).is_none() {
        return Err("not a packed RavenEnvelopeV1 (already-sealed LanDial only)".into());
    }
    if bytes.len() < 4 || &bytes[..4] != b"RVN1" {
        return Err("envelope magic is not RVN1 (already-sealed LanDial only)".into());
    }
    Ok(bytes)
}

/// Forward an already-sealed RavenEnvelopeV1 over LanDial. Lab-only. Not WAN.
pub fn lan_dial_already_sealed(
    data_dir: &Path,
    lan_dial: &str,
    expected_pub_hex: &str,
    envelope: &[u8],
) -> Result<Vec<Vec<u8>>, String> {
    if Envelope::unpack(envelope).is_none() || envelope.len() < 4 || &envelope[..4] != b"RVN1" {
        return Err("not a packed RavenEnvelopeV1 (already-sealed LanDial only)".into());
    }
    ipc_carrier_dial(
        data_dir,
        DialCarrier::Lan,
        lan_dial,
        expected_pub_hex,
        &[envelope.to_vec()],
    )
}

/// Friend custody frames (RFC1) to a custodian over LanDial, through this
/// profile's raven-node, which takes them only in a lab run. Lab-only (`ash
/// lab custody-deposit`). Not WAN.
pub fn lan_dial_custody_frames(
    data_dir: &Path,
    lan_dial: &str,
    expected_pub_hex: &str,
    frames: &[Vec<u8>],
) -> Result<Vec<Vec<u8>>, String> {
    if frames.is_empty()
        || !frames
            .iter()
            .all(|f| raven_core::friend_custody::is_rfc1(f))
    {
        return Err("not friend custody frames (RFC1 only)".into());
    }
    ipc_carrier_dial(
        data_dir,
        DialCarrier::Lan,
        lan_dial,
        expected_pub_hex,
        frames,
    )
}

/// `ash lab import-peer-cert`: Test A lab only (debug + `RAVEN_LAB_TEST_A=1`).
/// The live LAN path learns certs from RLB1 on the socket instead.
pub fn import_peer_device_cert(
    data_dir: &Path,
    peer_pub_hex: &str,
    cert_json_path: &Path,
) -> Result<(), String> {
    if !raven_core::pair_init::lab_test_a_enabled() {
        return Err(
            "lab import-peer-cert requires a debug build with RAVEN_LAB_TEST_A=1 \
             (live LAN pairing learns the peer cert from RLB1)"
                .into(),
        );
    }
    let peer = parse_pub_hex(peer_pub_hex)?;
    let raw = std::fs::read_to_string(cert_json_path).map_err(|e| e.to_string())?;
    let cert: DeviceCertificate =
        serde_json::from_str(&raw).map_err(|e| format!("cert json: {e}"))?;
    verify_imported_peer_cert(&cert, &peer, now_ms())?;
    cache_peer_cert(data_dir, &peer, &cert)?;
    println!(
        "{C_GREEN}peer cert cached{C_RESET} for {}",
        hex::encode(peer)
    );
    Ok(())
}

/// Signature + validity window + key binding for a hand-imported device cert.
fn verify_imported_peer_cert(
    cert: &DeviceCertificate,
    peer: &[u8; 32],
    now: u64,
) -> Result<(), String> {
    if cert.user_ed_pub != *peer && cert.device_ed_pub != *peer {
        return Err("cert does not match peer_pub_hex".into());
    }
    cert.verify(now)?;
    if cert.device_id.trim().is_empty() || cert.device_id != sanitize_terminal_line(&cert.device_id)
    {
        return Err("cert device_id is empty or contains control characters".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// E1 (three machines): a first message (no secure connection yet) was
    /// NOT SENT within about a second while the friend's port answered; the
    /// same text typed again went out. A probe the friend's computer
    /// answered and then closed (it refused us for now: its contact book
    /// still loading after a start or an unlock, or the link closed early) is
    /// tried again before a first message is given up; one that found nobody
    /// listening, no route or a wrong identity is not (s93's dead address
    /// stays NOT SENT within seconds).
    #[test]
    fn a_first_message_probes_again_only_when_the_friend_answered() {
        let refused = format!(
            "LAN 192.168.0.11:17420: ipc LAN_DIAL: {}",
            "LINK_NOT_ACCEPTED: \
            the peer closed the connection after our signed hello, before identifying itself"
        );
        let closed = "ipc LAN_DIAL: LAN_DIAL_PEER_CLOSED: the peer closed the connection \
            without replying"
            .to_string();
        let early = "ipc LAN_DIAL: lan handshake: early eof".to_string();
        let dead = "ipc LAN_DIAL: lan connect 192.168.0.11:17420: Connection refused (os error \
            61)"
        .to_string();
        let silent = "ipc LAN_DIAL: lan connect: timed out".to_string();
        let wrong = "ipc LAN_DIAL: RLB1 identity does not match".to_string();
        for answered in [&refused, &closed, &early] {
            assert!(
                probe_again(true, &[dead.clone(), answered.clone()]),
                "{answered}"
            );
            assert!(
                !probe_again(false, std::slice::from_ref(answered)),
                "queueable: {answered}"
            );
        }
        for nobody in [&dead, &silent, &wrong] {
            assert!(!probe_again(true, std::slice::from_ref(nobody)), "{nobody}");
        }
        assert!(!probe_again(true, &[]));
        const { assert!(FIRST_MESSAGE_PROBES >= 2) };
    }

    /// The daemon's dial answer carries the p2p path; an older daemon's
    /// answer (no `path`) is still a delivery, of unknown path; LAN and
    /// Internet direct are always direct; an answer for another carrier is
    /// refused.
    #[test]
    fn dial_reply_reads_the_path_and_tolerates_an_old_daemon() {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(b"ack");
        let p2p = |path: Option<&str>| {
            Ok(IpcResponse::P2pDialResult {
                v: IPC_VERSION,
                frames_b64: vec![b64.clone()],
                path: path.map(str::to_string),
            })
        };
        let reply = |path| DialReply {
            frames: vec![b"ack".to_vec()],
            path,
        };
        assert_eq!(
            dial_reply(DialCarrier::P2p, p2p(Some("reversed"))).unwrap(),
            reply(Some(DeliveryPath::Reversed))
        );
        assert_eq!(
            dial_reply(DialCarrier::P2p, p2p(Some("hole_punched"))).unwrap(),
            reply(Some(DeliveryPath::HolePunched))
        );
        // An older daemon, or a token this ash does not know: unknown.
        assert_eq!(
            dial_reply(DialCarrier::P2p, p2p(None)).unwrap(),
            reply(None)
        );
        assert_eq!(
            dial_reply(DialCarrier::P2p, p2p(Some("warp"))).unwrap(),
            reply(None)
        );
        let lan = Ok(IpcResponse::LanDialResult {
            v: IPC_VERSION,
            frames_b64: vec![b64.clone()],
        });
        assert_eq!(
            dial_reply(DialCarrier::Lan, lan.clone()).unwrap(),
            reply(Some(DeliveryPath::Direct))
        );
        let inet = Ok(IpcResponse::InternetDialResult {
            v: IPC_VERSION,
            frames_b64: vec![b64.clone()],
        });
        assert_eq!(
            dial_reply(DialCarrier::Internet, inet).unwrap(),
            reply(Some(DeliveryPath::Direct))
        );
        assert!(dial_reply(DialCarrier::P2p, lan).is_err());
        assert!(dial_reply(DialCarrier::Lan, p2p(Some("direct"))).is_err());
        let err = dial_reply(
            DialCarrier::P2p,
            Ok(IpcResponse::Error {
                v: IPC_VERSION,
                code: "P2P_DIAL".into(),
                message: "P2P_UNREACHABLE".into(),
            }),
        )
        .unwrap_err();
        assert_eq!(err, "ipc P2P_DIAL: P2P_UNREACHABLE");
        // Phase 5 (P5.28): a nearby link is one radio hop (direct); an
        // older raven-node does not know NearbyDial: too old for nearby.
        let near = Ok(IpcResponse::NearbyDialResult {
            v: IPC_VERSION,
            frames_b64: vec![b64.clone()],
        });
        assert_eq!(
            dial_reply(DialCarrier::Nearby, near.clone()).unwrap(),
            reply(Some(DeliveryPath::Direct))
        );
        assert!(dial_reply(DialCarrier::Lan, near).is_err());
        let old = |carrier| {
            dial_reply(
                carrier,
                Ok(IpcResponse::Error {
                    v: IPC_VERSION,
                    code: "IPC_FRAME".into(),
                    message: "unknown variant `nearby_dial`".into(),
                }),
            )
            .unwrap_err()
        };
        assert_eq!(old(DialCarrier::Nearby), NEARBY_TOO_OLD);
        assert_eq!(
            NEARBY_TOO_OLD,
            "raven-node is too old for nearby: update it"
        );
        assert!(old(DialCarrier::P2p).starts_with("ipc IPC_FRAME"));
    }

    /// Phase 5 (P5.28): the nearby dial carrier is the outbox's nearby
    /// carrier, held with its gate, plausible only as the contact's
    /// `nearby:<64 hex>` route, and never shown as an address.
    #[test]
    fn the_nearby_dial_carrier_is_held_named_and_never_an_address() {
        let key = [0x5c; 32];
        let route = DialRoute {
            carrier: DialCarrier::Nearby,
            dial: raven_core::outbox::nearby_dial_for(&key),
        };
        assert_eq!(DialCarrier::Nearby.outbox(), OutboxCarrier::Nearby);
        assert_eq!(dial_carrier_of(OutboxCarrier::Nearby), DialCarrier::Nearby);
        assert_eq!(dial_carrier_of(OutboxCarrier::Onion), DialCarrier::Onion);
        assert_eq!(DialCarrier::Nearby.label(), "nearby_dial");
        assert_eq!(carrier_word(DialCarrier::Nearby), "nearby");
        assert!(DialCarrier::Nearby.plausible(&route.dial));
        for bad in ["127.0.0.1:7420", "nearby:", "nearby:zz", "/p2p/12D3KooW"] {
            assert!(!DialCarrier::Nearby.plausible(bad), "{bad}");
        }
        assert_eq!(
            DialCarrier::Nearby.hold().is_some(),
            !raven_core::nearby_live_enabled()
        );
        assert_eq!(dial_shown(&route), "Bluetooth nearby");
        assert_eq!(ctx_dial(&route), "");
        let lan = DialRoute {
            carrier: DialCarrier::Lan,
            dial: " 192.168.1.20:7420 ".into(),
        };
        assert_eq!(ctx_dial(&lan), "192.168.1.20:7420");
        assert_eq!(
            dial_shown(&lan),
            " 192.168.1.20:7420 ",
            "as it was shown before"
        );
        let handoff = OutboxHandoff::new(
            Path::new("/nonexistent"),
            std::slice::from_ref(&route),
            key,
            None,
        );
        assert_eq!(handoff.choice, CarrierChoice::Nearby);
    }

    /// G2: the probe tries the remembered route first, and what it saw is
    /// learned by the routes as planned (the index of a dialled route maps
    /// back to its planned form; a resolved LAN literal is never stored).
    /// A probe that answers (`Ok(i)`) or fails after `ms`, per route, and
    /// counts the probes that started.
    fn timed_prober(
        plan: &'static [(u64, bool)],
        started: std::sync::Arc<std::sync::Mutex<Vec<usize>>>,
    ) -> Prober<usize> {
        std::sync::Arc::new(move |i: usize| {
            started.lock().unwrap().push(i);
            let (ms, ok) = plan[i];
            std::thread::sleep(Duration::from_millis(ms));
            if ok {
                Ok(i)
            } else {
                Err(format!("route {i} did not answer"))
            }
        })
    }

    fn round(
        plan: &'static [(u64, bool)],
        onion: Option<usize>,
        head_ms: u64,
    ) -> (Vec<(usize, bool)>, Vec<usize>, Duration) {
        let started = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let t = std::time::Instant::now();
        let order: Vec<usize> = (0..plan.len()).collect();
        let done = probe_round(
            &order,
            onion,
            Duration::from_millis(head_ms),
            Duration::from_millis(200),
            timed_prober(plan, started.clone()),
        );
        let took = t.elapsed();
        let done = done
            .done
            .into_iter()
            .map(|(i, r, _)| (i, r.is_ok()))
            .collect();
        let started = started.lock().unwrap().clone();
        (done, started, took)
    }

    /// A direct route that fails at once lets the next go at once; one
    /// that answers keeps the rest from starting; Tor alone goes at once.
    #[test]
    fn probes_without_a_tor_route_go_one_after_the_other() {
        let (done, started, _) = round(&[(10, false), (10, true), (10, true)], None, 1_500);
        assert_eq!(done, [(0, false), (1, true)]);
        assert_eq!(started, [0, 1]);
        let (done, _, _) = round(&[(10, true)], Some(0), 1_500);
        assert_eq!(done, [(0, true)]);
    }

    /// The routes still running when another answered are reported apart
    /// (verbose mode names them), and every probe says when it started (E2
    /// r38).
    #[test]
    fn a_round_reports_the_probes_still_running() {
        let started = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let outcome = probe_round(
            &[0, 1],
            None,
            Duration::from_millis(1_500),
            Duration::from_millis(100),
            timed_prober(&[(2_000, false), (20, true)], started),
        );
        assert_eq!(outcome.running, [0]);
        assert!(matches!(outcome.done[..], [(1, Ok(1), _)]));
        assert!(outcome.started_at(0) < Duration::from_millis(50));
        let second = outcome.started_at(1);
        assert!(
            (Duration::from_millis(90)..Duration::from_millis(600)).contains(&second),
            "the stagger: {second:?}"
        );
        let route = DialRoute {
            carrier: DialCarrier::P2p,
            dial: "/p2p/12D3KooWExample".into(),
        };
        assert_eq!(
            race_line(
                &route,
                Duration::from_millis(300),
                "did not answer before another way did",
                Duration::from_millis(400)
            ),
            "p2p_dial /p2p/12D3KooWExample started +0.3 s, did not answer before another way \
             did (0.4 s)"
        );
    }

    /// E2 r9 #1: the direct routes race too. A stale LAN address that
    /// hangs no longer holds the next route back: it starts after the
    /// stagger and its answer carries the send.
    #[test]
    fn a_hanging_lan_route_does_not_hold_the_next_direct_route_back() {
        let (done, started, took) = round(&[(3_000, false), (50, true)], None, 1_500);
        assert_eq!(done, [(1, true)]);
        assert_eq!(started, [0, 1]);
        assert!(took < Duration::from_millis(1_000), "{took:?}");
        // Nobody answers: every failure is reported, and the round lasts as
        // long as the slowest probe, not their sum.
        let (mut done, _, took) = round(&[(600, false), (600, false)], None, 1_500);
        done.sort_unstable();
        assert_eq!(done, [(0, false), (1, false)]);
        assert!(took < Duration::from_millis(1_150), "{took:?}");
    }

    /// E2 r9 #1: Tor's head start only for a friend seen on the LAN lately
    /// (or a remembered p2p/Internet route first); an older raven-node that
    /// cannot say keeps it.
    #[test]
    fn tor_gets_no_head_start_for_a_friend_not_seen_on_the_lan_lately() {
        let head = raven_core::onion::ONION_HEAD_START;
        let zero = Duration::ZERO;
        assert_eq!(tor_head_start(true, Some(Some(30)), false, false), head);
        assert_eq!(tor_head_start(true, Some(Some(3_600)), false, false), zero);
        assert_eq!(tor_head_start(true, Some(None), false, false), zero);
        // A LAN address the beacon found, or the friend told, just now.
        assert_eq!(tor_head_start(true, Some(None), true, false), head);
        // An older raven-node.
        assert_eq!(tor_head_start(true, None, false, false), head);
        assert_eq!(tor_head_start(false, Some(Some(30)), false, false), zero);
        assert_eq!(tor_head_start(false, Some(None), false, true), head);
    }

    /// E2 r40 (A): a send that can queue waits for Tor's check
    /// ONION_SEND_BUDGET, not Tor's full dial; a first message's probe and
    /// every message dial keep Tor's full wait; other carriers as asked.
    #[test]
    fn a_queueable_send_waits_for_tor_its_own_budget() {
        let tor = DialCarrier::Onion;
        assert_eq!(
            ipc_dial_wait(tor, QUEUEABLE_PROBE_TIMEOUT, true),
            ONION_SEND_BUDGET
        );
        assert_eq!(
            ipc_dial_wait(tor, DIAL_IPC_TIMEOUT, true),
            ONION_IPC_TIMEOUT
        );
        assert_eq!(
            ipc_dial_wait(tor, QUEUEABLE_PROBE_TIMEOUT, false),
            ONION_IPC_TIMEOUT
        );
        assert_eq!(
            ipc_dial_wait(DialCarrier::Lan, QUEUEABLE_PROBE_TIMEOUT, true),
            QUEUEABLE_PROBE_TIMEOUT
        );
    }

    /// E2 r40 #2: the message dial after Tor answered the check: one more
    /// try at once after a quick failure, none after a slow one or a
    /// refusal, and a failure says Tor answered.
    #[test]
    fn a_tor_message_dial_after_the_check_gets_one_more_try() {
        let run = |plan: Vec<Result<u8, &str>>, within: Duration| {
            let mut plan = plan.into_iter();
            let mut tries = 0;
            let got = dial_after_tor_check(within, || {
                tries += 1;
                plan.next().expect("a planned try").map_err(str::to_string)
            });
            (got, tries)
        };
        let lost = "ONION_UNREACHABLE (rendezvous failed)";
        let soon = Duration::from_secs(30);
        assert_eq!(run(vec![Ok(1)], soon), (Ok(1), 1));
        assert_eq!(run(vec![Err(lost), Ok(2)], soon), (Ok(2), 2));
        let (got, tries) = run(vec![Err(lost), Err(lost)], soon);
        assert_eq!(tries, 2);
        let e = got.unwrap_err();
        assert!(e.starts_with(ONION_CHECKED_THEN_LOST), "{e}");
        assert!(e.ends_with(lost), "{e}");
        // A slow failure: no second try (the queue tries Tor at once).
        let (got, tries) = run(vec![Err(lost)], Duration::ZERO);
        assert_eq!(tries, 1);
        assert!(got.unwrap_err().starts_with(ONION_CHECKED_THEN_LOST));
        // The friend refused: its answer as it came, no second try.
        let refused = format!("ipc: {PEER_REFUSED_CODE}: closed");
        let (got, tries) = run(vec![Err(refused.as_str())], soon);
        assert_eq!((got, tries), (Err(refused.clone()), 1));
        let (got, tries) = run(vec![Err(lost), Err(refused.as_str())], soon);
        assert_eq!((got, tries), (Err(refused), 2));
    }

    /// Field test E3 round 2: a send's Tor check ended after 5.2 s with
    /// Tor's "unreachable" and the message was queued, with 20 s of the
    /// send's Tor wait left; the outbox reached the friend over Tor seconds
    /// later. A quick miss is checked once more with what is left of the
    /// wait; a slow one, a refusal, Tor not ready here or a short wait left
    /// is final.
    #[test]
    fn a_quick_tor_miss_is_checked_once_more_within_the_send_wait() {
        let run = |plan: Vec<Result<u8, &str>>, wait: Duration, within: Duration| {
            let mut plan = plan.into_iter();
            let mut waits = Vec::new();
            let got = onion_check_again(wait, within, |w| {
                waits.push(w);
                plan.next()
                    .expect("a planned check")
                    .map_err(str::to_string)
            });
            (got, waits)
        };
        let miss = "ONION_UNREACHABLE: the contact's onion service did not answer over Tor \
                    (rendezvous failed)";
        let wait = ONION_SEND_BUDGET;
        let soon = ONION_CHECK_AGAIN_WITHIN;
        assert_eq!(run(vec![Ok(1)], wait, soon), (Ok(1), vec![wait]));
        let (got, waits) = run(vec![Err(miss), Ok(2)], wait, soon);
        assert_eq!(got, Ok(2));
        assert_eq!(waits.len(), 2);
        assert!(waits[1] <= wait && waits[1] + Duration::from_secs(1) > wait);
        let (got, waits) = run(vec![Err(miss), Err(miss)], wait, soon);
        assert_eq!((got, waits.len()), (Err(miss.to_string()), 2));
        // A slow miss: final.
        let (_, waits) = run(vec![Err(miss)], wait, Duration::ZERO);
        assert_eq!(waits.len(), 1);
        // Too little of the wait left for another rendezvous: final.
        let (_, waits) = run(vec![Err(miss)], ONION_CHECK_AGAIN_MIN_LEFT, soon);
        assert_eq!(waits.len(), 1);
        // Not a miss: a refusal, Tor not ready here, the wait cut short, the
        // outbox already on Tor.
        let refused = format!("ipc: {PEER_REFUSED_CODE}: closed");
        for other in [
            refused.as_str(),
            "ONION_NOT_READY: Tor is not ready on this computer yet",
            "onion_dial Tor: no answer within 25s (the probe was cut short; nothing was sent)",
            TOR_BUSY,
        ] {
            let (got, waits) = run(vec![Err(other)], wait, soon);
            assert_eq!((got, waits.len()), (Err(other.to_string()), 1), "{other}");
        }
    }

    /// E2 r9 #2: a queueable send skips its probes only when every one of
    /// its routes failed lately (the dial as sent); a new route, or one
    /// without a failure, probes them all.
    #[test]
    fn recent_failures_cover_every_route_or_nothing() {
        let lan = DialRoute {
            carrier: DialCarrier::Lan,
            dial: "192.168.0.16:17420".into(),
        };
        let p2p = DialRoute {
            carrier: DialCarrier::P2p,
            dial: "/p2p/12D3KooWExample".into(),
        };
        let tor = DialRoute {
            carrier: DialCarrier::Onion,
            dial: format!("onion:{}", "ab".repeat(32)),
        };
        let fail = |carrier: &str, dial: &str, age_s, error: &str| {
            super::super::ipc_client::RouteFailure {
                carrier: carrier.into(),
                dial: dial.into(),
                age_s,
                error: error.into(),
            }
        };
        // E2 r38 K4: the LAN refused (its Raven stopped), p2p and Tor did not
        // answer: the next send queues at once.
        let all = [
            fail("lan_dial", &lan.dial, 20, "connection refused"),
            fail("p2p_dial", &p2p.dial, 15, "no answer"),
            fail("onion_dial", &tor.dial, 4, "no answer"),
        ];
        let routes = [lan.clone(), p2p.clone(), tor.clone()];
        let plan = ProbePlan::in_order(3);
        let here = |_: std::net::IpAddr| true;
        let recent = recent_failures_with(&routes, &all, false, Some(30), &plan, here);
        let (errors, age) = every_route_failed(&routes, &recent, &plan).unwrap();
        assert_eq!(
            errors,
            [
                "lan_dial 192.168.0.16:17420: connection refused",
                "p2p_dial /p2p/12D3KooWExample: no answer",
                "onion_dial Tor: no answer"
            ]
        );
        assert_eq!(age, 20);
        assert!(skipped_routes(&recent, &plan).len() == 3);
        // E2 r40: the friend on another network. One Tor dial failed, the LAN
        // address (an old one) did not answer, p2p did not: Tor stays in the
        // race (the one route that can work), the others are left out.
        let away = [
            fail("lan_dial", &lan.dial, 20, "no answer within 5.0s"),
            fail("p2p_dial", &p2p.dial, 15, "no answer"),
            fail("onion_dial", &tor.dial, 4, "no answer"),
        ];
        let recent = recent_failures_with(&routes, &away, false, Some(30), &plan, here);
        assert!(every_route_failed(&routes, &recent, &plan).is_none());
        assert_eq!(
            skipped_routes(&recent, &plan)
                .iter()
                .map(|(i, _)| *i)
                .collect::<Vec<_>>(),
            [0, 1]
        );
        // E2 r40 (A): Tor busy with the friend (it did not reach it lately
        // or still dials, and the outbox carries a message to it, Tor
        // first): left out of this send's race, with its failure or, while
        // its dial still runs, as busy; quick queue when the rest failed.
        let busy = recent_failures_with(&routes, &away, true, Some(30), &plan, here);
        assert_eq!(busy[2], Some((TOR_BUSY.to_string(), 4)));
        assert!(every_route_failed(&routes, &busy, &plan).is_some());
        let running = recent_failures_with(&routes, &away[..2], true, Some(30), &plan, here);
        assert_eq!(running[2], Some((TOR_BUSY.to_string(), 0)));
        let skipped = skipped_routes(&running, &plan);
        assert!(
            skipped[2].1.ends_with("Tor (not tried again now)"),
            "{skipped:?}"
        );
        // What the send says when it queues without a dial (field test E3:
        // "failed 0 s ago" while nothing had failed): Tor left to the
        // outbox's earlier message, or every way failed that long ago.
        assert_eq!(
            not_dialled_line("Bob", &running, 0),
            "Raven is already trying to reach Bob over Tor with an earlier message; this one \
             waits with it"
        );
        // Field test E3 round 2: the outbox was delivering the earlier
        // message over Tor; the send said "every way failed 5 s ago".
        assert_eq!(
            not_dialled_line("Bob", &busy, 20),
            "Raven is already trying to reach Bob over Tor with an earlier message; this one \
             waits with it"
        );
        let idle_all = recent_failures_with(&routes, &all, false, Some(30), &plan, here);
        assert_eq!(
            not_dialled_line("Bob", &idle_all, 20),
            "every way to Bob failed 20 s ago; not tried again now"
        );
        // Not busy: Tor is probed whatever failed.
        let idle = recent_failures_with(&routes, &away[..2], false, Some(30), &plan, here);
        assert_eq!(idle[2], None);
        // A refusal at an address not on this network (another computer
        // took the old address) is no sign the friend's Raven stopped.
        let elsewhere = recent_failures_with(&routes, &all, false, Some(30), &plan, |_| false);
        assert!(elsewhere[2].is_none(), "Tor stays in the race");
        // A refusal at an address on this network, but the friend not seen
        // on this LAN lately (an old address another computer took): Tor
        // stays in the race, no quick queue.
        for unseen in [None, Some(LAN_SEEN_SPAN_S + 1)] {
            let old_address = recent_failures_with(&routes, &all, false, unseen, &plan, here);
            assert!(old_address[2].is_none(), "Tor stays in the race");
            assert!(every_route_failed(&routes, &old_address, &plan).is_none());
        }
        // Only two failed lately: no quick queue; those two are left out of
        // the race, the third is probed.
        let recent = recent_failures_with(&routes, &all[..2], false, Some(30), &plan, here);
        assert!(every_route_failed(&routes, &recent, &plan).is_none());
        let left_out = skipped_routes(&recent, &plan);
        assert_eq!(left_out.iter().map(|(i, _)| *i).collect::<Vec<_>>(), [0, 1]);
        assert!(left_out[0]
            .1
            .ends_with("(failed 20 s ago; not tried again now)"));
        let partial = plan.with_known(left_out);
        assert!(partial.known_error(0).is_some() && partial.known_error(2).is_none());
        // A route with another address (it moved): probe it.
        let moved = DialRoute {
            dial: "192.168.0.99:17420".into(),
            ..lan.clone()
        };
        let recent = recent_failures_with(
            &[moved.clone(), p2p.clone(), tor.clone()],
            &all,
            false,
            Some(30),
            &plan,
            here,
        );
        assert!(every_route_failed(&[moved, p2p, tor], &recent, &plan).is_none());
        assert!(recent[0].is_none());
        // Nothing known at all (a first message, an older raven-node): no
        // quick queue.
        assert!(every_route_failed(&routes, &[], &plan).is_none());
        // Nothing failed lately: nothing left out.
        let none = recent_failures(
            std::slice::from_ref(&lan),
            &super::super::ipc_client::ContactReach::default(),
            &ProbePlan::in_order(1),
        );
        assert!(every_route_failed(&[lan], &none, &ProbePlan::in_order(1)).is_none());
        assert!(skipped_routes(&none, &ProbePlan::in_order(1)).is_empty());
    }

    /// A direct route that answers within the head start: Tor is never
    /// probed.
    #[test]
    fn a_quick_direct_answer_keeps_tor_from_starting() {
        let started = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let done = probe_round(
            &[0, 1],
            Some(1),
            Duration::from_millis(400),
            Duration::from_millis(200),
            timed_prober(&[(20, true), (10, true)], started.clone()),
        );
        assert!(done.running.is_empty());
        let done = done.done;
        assert_eq!(done.len(), 1);
        assert!(matches!(done[0], (0, Ok(0), _)));
        // Past the head start: Tor's probe never started.
        std::thread::sleep(Duration::from_millis(600));
        assert_eq!(*started.lock().unwrap(), [0]);
    }

    /// Field test S15 (mac-b): a stale LAN address takes 8 s to fail. Tor
    /// starts after its head start and answers; the send does not wait for
    /// the LAN probe.
    #[test]
    fn tor_answers_after_its_head_start_while_a_stale_lan_route_hangs() {
        let (done, started, took) = round(&[(3_000, false), (50, true)], Some(1), 200);
        assert_eq!(done, [(1, true)]);
        assert_eq!(started, [0, 1]);
        assert!(took < Duration::from_millis(1_500), "{took:?}");
    }

    /// Every direct route failed before the head start ran out: Tor goes at
    /// once; and a round where nothing answers reports every probe.
    #[test]
    fn tor_goes_at_once_when_the_direct_routes_failed_and_all_failures_are_kept() {
        let (done, _, took) = round(&[(10, false), (10, false), (20, true)], Some(2), 2_000);
        assert_eq!(done, [(0, false), (1, false), (2, true)]);
        assert!(took < Duration::from_millis(1_000), "{took:?}");
        let (mut done, _, _) = round(&[(10, false), (30, false)], Some(1), 50);
        done.sort_unstable();
        assert_eq!(done, [(0, false), (1, false)]);
    }

    #[test]
    fn probe_plan_orders_and_teaches_by_planned_route() {
        let route = |carrier, dial: &str| OutboxRoute {
            carrier,
            dial: dial.into(),
        };
        let saved = route(OutboxCarrier::Lan, "bob-mac.local:7420");
        let learned = route(OutboxCarrier::Lan, "192.168.1.37:7420");
        let inet = route(OutboxCarrier::Internet, "203.0.113.7:7422");
        let planned = vec![saved.clone(), learned.clone(), inet.clone()];
        let plan = ProbePlan::with(planned.clone(), Some(inet.clone()), Some("n1"));
        assert_eq!(plan.first(), 2);
        assert_eq!(plan.order, [2, 0, 1]);
        let plain = ProbePlan::with(planned.clone(), None, Some("n1"));
        assert_eq!((plain.first(), plain.order.clone()), (0, vec![0, 1, 2]));
        assert_eq!(ProbePlan::in_order(2).order, [0, 1]);

        let dir = tempfile::tempdir().unwrap();
        let peer = [7u8; 32];
        let now = now_ms();
        let memory = dir.path().join(route_memory::ROUTE_MEMORY_FILE);
        // Plan order and no tag: nothing is taught.
        ProbePlan::in_order(3).teach(dir.path(), &peer, &[(0, false), (1, true)], now);
        ProbePlan::with(planned.clone(), None, None).teach(
            dir.path(),
            &peer,
            &[(0, false), (1, true)],
            now,
        );
        assert!(!memory.exists());
        // The saved name failed (it was dialled as its resolved literal), the
        // learned address answered: the planned form is remembered.
        plain.teach(dir.path(), &peer, &[(0, false), (1, true), (9, true)], now);
        assert_eq!(
            route_memory::preferred_route(dir.path(), &peer, Some("n1"), now),
            Some(learned.clone())
        );
        // Next time it goes first; it failed then, and the saved name
        // answered: forgotten, nothing new granted.
        let next = ProbePlan::remembered_on(dir.path(), &peer, planned, Some("n1".into()));
        assert_eq!(next.order, [1, 0, 2]);
        next.teach(dir.path(), &peer, &[(1, false), (0, true)], now_ms());
        assert_eq!(
            route_memory::preferred_route(dir.path(), &peer, Some("n1"), now_ms()),
            None
        );
    }

    /// Phase 5 (P5.28): a nearby route is derived live and is never route
    /// evidence: a nearby delivery after a dead LAN address grants nothing
    /// (the LAN route is not taught into an Internet-style preference
    /// either), and nothing remembered ever names nearby.
    #[test]
    fn a_nearby_probe_teaches_the_route_memory_nothing() {
        let lan = OutboxRoute {
            carrier: OutboxCarrier::Lan,
            dial: "192.168.1.37:7420".into(),
        };
        let near = OutboxRoute {
            carrier: OutboxCarrier::Nearby,
            dial: raven_core::outbox::nearby_dial_for(&[3; 32]),
        };
        let dir = tempfile::tempdir().unwrap();
        let peer = [3u8; 32];
        let plan = ProbePlan::with(vec![lan, near], None, Some("n1"));
        plan.teach(dir.path(), &peer, &[(0, false), (1, true)], now_ms());
        assert_eq!(
            route_memory::preferred_route(dir.path(), &peer, Some("n1"), now_ms()),
            None
        );
    }

    fn learning_answer(order: &[&str], state: &str) -> super::super::ipc_client::LearningPlan {
        super::super::ipc_client::LearningPlan {
            order: order.iter().map(|s| (*s).to_string()).collect(),
            why: format!("learn: state={state} order=internet,lan why=failing"),
            state: state.into(),
            carry: Vec::new(),
        }
    }

    /// Phase 6a (P6.16): the queued text names raven-node's carry pick in
    /// its order, with why the first goes first; without carry rows (cold,
    /// off, an older raven-node) today's `deposit_custodians` labels and no
    /// reason. A row without a valid key is skipped.
    #[test]
    fn custodian_words_follow_the_carry_pick() {
        let (carol, dave) = ([0xCA; 32], [0xDA; 32]);
        let label = |k: &[u8; 32]| match k[0] {
            0xCA => "Carol".to_string(),
            0xDA => "Dave".to_string(),
            _ => "a friend".to_string(),
        };
        let set = [(carol, None), (dave, Some(1))];
        assert_eq!(
            custodian_words(&set, &[], label),
            (vec!["Carol".to_string(), "Dave".to_string()], None)
        );
        let row = |key: &[u8; 32], met: &str, delivered, outcomes| raven_core::ipc::LearningCarry {
            peer_pub_hex: hex::encode(key),
            met: met.into(),
            delivered,
            outcomes,
        };
        let bad = raven_core::ipc::LearningCarry {
            peer_pub_hex: "zz".into(),
            ..row(&carol, "often", 0, 0)
        };
        let carry = [bad, row(&dave, "often", 3, 4), row(&carol, "never", 0, 0)];
        assert_eq!(
            custodian_words(&set, &carry, label),
            (
                vec!["Dave".to_string(), "Carol".to_string()],
                Some("Dave first (you meet often; delivered 3 of 4 before)".to_string())
            )
        );
    }

    /// Phase 6a (P6.12): when raven-node uses a learned carrier order for
    /// the contact (`LearningPlan` says `on`), the probe follows it: a
    /// stable sort of the planned routes by carrier, a carrier it does not
    /// name after the named ones, nearby in its slot. The route memory is
    /// neither read (its route does not go first) nor taught.
    #[test]
    fn probe_plan_uses_the_learned_order() {
        let route = |carrier, dial: &str| OutboxRoute {
            carrier,
            dial: dial.into(),
        };
        let saved = route(OutboxCarrier::Lan, "bob-mac.local:7420");
        let learned = route(OutboxCarrier::Lan, "192.168.1.37:7420");
        let inet = route(OutboxCarrier::Internet, "203.0.113.7:7422");
        let near = route(
            OutboxCarrier::Nearby,
            &raven_core::outbox::nearby_dial_for(&[7; 32]),
        );
        let planned = vec![saved.clone(), learned.clone(), inet.clone(), near];
        let dir = tempfile::tempdir().unwrap();
        let peer = [7u8; 32];
        // The memory holds the learned LAN address.
        ProbePlan::with(planned[..3].to_vec(), None, Some("n1")).teach(
            dir.path(),
            &peer,
            &[(0, false), (1, true)],
            now_ms(),
        );
        assert_eq!(
            route_memory::preferred_route(dir.path(), &peer, Some("n1"), now_ms()),
            Some(learned)
        );
        let memory = dir.path().join(route_memory::ROUTE_MEMORY_FILE);
        let before = std::fs::read(&memory).unwrap();
        let answer = learning_answer(&["internet_dial", "lan_dial", "p2p_dial"], "on");
        let plan = ProbePlan::planned_on(
            dir.path(),
            &peer,
            planned.clone(),
            Some("n1".into()),
            Some(Ok(Some(answer))),
        );
        assert_eq!(plan.order, [2, 0, 1, 3]);
        assert_eq!(plan.first(), 2);
        assert!(plan.learned && plan.preferred.is_none() && plan.net.is_none());
        // Learning supersedes the memory: nothing is taught.
        plan.teach(dir.path(), &peer, &[(2, false), (0, true)], now_ms());
        assert_eq!(std::fs::read(&memory).unwrap(), before, "not taught");
        // An order that names only Internet: the LAN routes follow it in
        // plan order.
        let only = learning_answer(&["internet_dial"], "on");
        let plan = ProbePlan::planned_on(dir.path(), &peer, planned, None, Some(Ok(Some(only))));
        assert_eq!(plan.order, [2, 0, 1, 3]);
        // The static order as learned (cold): plan order.
        let cold = learning_answer(&["lan_dial", "internet_dial"], "on");
        let plan = ProbePlan::planned_on(
            dir.path(),
            &peer,
            vec![saved, inet],
            None,
            Some(Ok(Some(cold))),
        );
        assert_eq!(plan.order, [0, 1]);
    }

    /// Phase 6a (P6.12): an older raven-node (`IPC_FRAME`), the learning
    /// hold, an answer that is not `on`, a service that does not answer
    /// within the budget, no service, or not asked at all: today's order,
    /// the remembered route first, and the memory is taught as before.
    #[cfg(unix)]
    #[test]
    fn probe_plan_falls_back_on_ipc_frame_hold_or_timeout() {
        use super::super::ipc_client::{learning_plan_within, test_support::short_tempdir};
        use std::io::{Read, Write};
        use std::os::unix::net::UnixListener;
        let lan = OutboxRoute {
            carrier: OutboxCarrier::Lan,
            dial: "192.168.1.37:7420".into(),
        };
        let inet = OutboxRoute {
            carrier: OutboxCarrier::Internet,
            dial: "203.0.113.7:7422".into(),
        };
        let planned = vec![lan.clone(), inet.clone()];
        let dir = short_tempdir();
        let peer = [9u8; 32];
        ProbePlan::with(planned.clone(), None, Some("n1")).teach(
            dir.path(),
            &peer,
            &[(0, false), (1, true)],
            now_ms(),
        );
        // A service that decodes the request as raven-node does and answers
        // each connection in turn; the last one it reads and never answers.
        let listener = UnixListener::bind(raven_core::default_socket_path(dir.path())).unwrap();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let server = std::thread::spawn(move || {
            let answers = [
                Some(IpcResponse::Error {
                    v: IPC_VERSION,
                    code: "IPC_FRAME".into(),
                    message: "unknown op".into(),
                }),
                Some(IpcResponse::Error {
                    v: IPC_VERSION,
                    code: "LEARNING_HOLD".into(),
                    message: raven_core::learning::LEARNING_HOLD.into(),
                }),
                Some(IpcResponse::LearningPlan {
                    v: IPC_VERSION,
                    order: vec!["internet_dial".into(), "lan_dial".into()],
                    why: "learn: state=off order=lan,internet why=off".into(),
                    state: "off".into(),
                    carry: Vec::new(),
                }),
                None,
            ];
            for answer in answers {
                let (mut stream, _) = listener.accept().unwrap();
                let mut len = [0u8; 4];
                stream.read_exact(&mut len).unwrap();
                let mut frame = len.to_vec();
                frame.resize(4 + u32::from_be_bytes(len) as usize, 0);
                stream.read_exact(&mut frame[4..]).unwrap();
                assert!(matches!(
                    raven_core::decode_request(&frame),
                    Ok(IpcRequest::LearningPlan { .. })
                ));
                match answer {
                    Some(resp) => stream
                        .write_all(&raven_core::encode_response(&resp).unwrap())
                        .unwrap(),
                    None => {
                        let _ = done_rx.recv();
                    }
                }
            }
        });
        let hex_peer = hex::encode(peer);
        let mut answers = Vec::new();
        for _ in 0..3 {
            answers.push(learning_plan_within(
                dir.path(),
                &hex_peer,
                LEARNING_PLAN_TIMEOUT,
            ));
        }
        let started = std::time::Instant::now();
        let stalled = learning_plan_within(dir.path(), &hex_peer, Duration::from_millis(200));
        let waited = started.elapsed();
        let _ = done_tx.send(());
        server.join().unwrap();
        assert_eq!(answers[0], Ok(None), "IPC_FRAME");
        assert_eq!(answers[1], Ok(None), "LEARNING_HOLD");
        assert!(matches!(&answers[2], Ok(Some(p)) if p.state == "off"));
        assert!(stalled.is_err(), "{stalled:?}");
        assert!(waited < LEARNING_PLAN_TIMEOUT, "{waited:?}");
        answers.push(stalled);
        // No service at all, and not asked (learning gate shut).
        let _ = std::fs::remove_file(raven_core::default_socket_path(dir.path()));
        answers.push(learning_plan_within(
            dir.path(),
            &hex_peer,
            LEARNING_PLAN_TIMEOUT,
        ));
        assert!(answers[4].is_err());
        let mut asked: Vec<Option<_>> = answers.into_iter().map(Some).collect();
        asked.push(None);
        for asked in asked {
            let shown = format!("{asked:?}");
            let plan =
                ProbePlan::planned_on(dir.path(), &peer, planned.clone(), Some("n1".into()), asked);
            assert_eq!(plan.order, [1, 0], "{shown}");
            assert_eq!(plan.preferred.as_ref(), Some(&inet), "{shown}");
            assert!(!plan.learned, "{shown}");
        }
        // Taught as before: the remembered Internet route failed, LAN
        // answered, so it is forgotten.
        ProbePlan::planned_on(dir.path(), &peer, planned, Some("n1".into()), None).teach(
            dir.path(),
            &peer,
            &[(1, false), (0, true)],
            now_ms(),
        );
        assert_eq!(
            route_memory::preferred_route(dir.path(), &peer, Some("n1"), now_ms()),
            None
        );
    }

    #[test]
    fn already_sealed_decode_refuses_raw_payload() {
        use base64::Engine;
        let raw = base64::engine::general_purpose::STANDARD.encode(b"hello");
        let err = decode_already_sealed_envelope_b64(&raw).unwrap_err();
        assert!(
            err.contains("already-sealed") || err.contains("RavenEnvelopeV1"),
            "{err}"
        );
    }

    fn lab_cert(user: &Identity, device_id: &str, not_after_ms: u64) -> DeviceCertificate {
        DeviceCertificate::issue(
            user,
            user.public_key_bytes(),
            [7u8; 32],
            device_id,
            0,
            not_after_ms,
            0,
        )
        .unwrap()
    }

    #[test]
    fn imported_peer_cert_must_verify_and_bind() {
        let peer = Identity::from_seed(&[0x31; 32]);
        let other = Identity::from_seed(&[0x32; 32]);
        let pk = peer.public_key_bytes();
        let now = now_ms();
        let good = lab_cert(&peer, PRIMARY_DEVICE_ID, now + 60_000);
        verify_imported_peer_cert(&good, &pk, now).unwrap();

        // Wrong key binding.
        assert!(verify_imported_peer_cert(&good, &other.public_key_bytes(), now).is_err());
        // Tampered device_id breaks the signature (previously accepted unverified).
        let mut forged = good.clone();
        forged.device_id = "ash-other".into();
        assert_eq!(
            verify_imported_peer_cert(&forged, &pk, now).unwrap_err(),
            "DEVICE_CERT_BAD_SIG"
        );
        // Expired.
        let expired = lab_cert(&peer, PRIMARY_DEVICE_ID, 1);
        assert_eq!(
            verify_imported_peer_cert(&expired, &pk, now).unwrap_err(),
            "DEVICE_CERT_EXPIRED"
        );
        // Control characters in a (validly signed) device_id.
        let ctl = lab_cert(&peer, "ash\nprimary", now + 60_000);
        assert!(verify_imported_peer_cert(&ctl, &pk, now).is_err());
    }

    #[test]
    fn peer_cert_cache_refuses_to_overwrite_corrupt_file() {
        let dir = tempfile::tempdir().unwrap();
        let peer = Identity::from_seed(&[0x33; 32]);
        let path = dir.path().join(PEER_CERT_CACHE);
        std::fs::write(&path, b"{not json").unwrap();
        let cert = lab_cert(&peer, PRIMARY_DEVICE_ID, now_ms() + 60_000);
        let err = cache_peer_cert(dir.path(), &peer.public_key_bytes(), &cert).unwrap_err();
        assert!(err.contains("corrupt"), "{err}");
        assert_eq!(std::fs::read(&path).unwrap(), b"{not json");
    }

    #[test]
    fn peer_cert_cache_merges_existing_entries() {
        let dir = tempfile::tempdir().unwrap();
        let a = Identity::from_seed(&[0x34; 32]);
        let b = Identity::from_seed(&[0x35; 32]);
        let now = now_ms();
        cache_peer_cert(
            dir.path(),
            &a.public_key_bytes(),
            &lab_cert(&a, "d", now + 60_000),
        )
        .unwrap();
        cache_peer_cert(
            dir.path(),
            &b.public_key_bytes(),
            &lab_cert(&b, "d", now + 60_000),
        )
        .unwrap();
        let raw = std::fs::read_to_string(dir.path().join(PEER_CERT_CACHE)).unwrap();
        let map: HashMap<String, DeviceCertificate> = serde_json::from_str(&raw).unwrap();
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn peer_cert_cache_import_respects_shared_cap() {
        let dir = tempfile::tempdir().unwrap();
        let a = Identity::from_seed(&[0x37; 32]);
        let now = now_ms();
        let cert = lab_cert(&a, "d", now + 60_000);
        let full: HashMap<String, DeviceCertificate> = (0..MAX_PEER_CERT_CACHE_KEYS)
            .map(|i| (format!("{i:064x}"), cert.clone()))
            .collect();
        let path = dir.path().join(PEER_CERT_CACHE);
        std::fs::write(&path, serde_json::to_string(&full).unwrap()).unwrap();
        let before = std::fs::read(&path).unwrap();
        let err = cache_peer_cert(dir.path(), &a.public_key_bytes(), &cert).unwrap_err();
        assert!(err.contains("full"), "{err}");
        assert_eq!(std::fs::read(&path).unwrap(), before);
        // Replacing an existing key does not grow the cache and is allowed.
        let mut existing = [0u8; 32];
        existing[31] = 1;
        cache_peer_cert(dir.path(), &existing, &cert).unwrap();
    }

    #[test]
    fn import_peer_cert_is_lab_gated() {
        if raven_core::pair_init::lab_test_a_enabled() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let peer = Identity::from_seed(&[0x36; 32]);
        let file = dir.path().join("cert.json");
        let cert = lab_cert(&peer, PRIMARY_DEVICE_ID, now_ms() + 60_000);
        std::fs::write(&file, serde_json::to_string(&cert).unwrap()).unwrap();
        let err = import_peer_device_cert(dir.path(), &hex::encode(peer.public_key_bytes()), &file)
            .unwrap_err();
        assert!(err.contains("RAVEN_LAB_TEST_A"), "{err}");
        assert!(!dir.path().join(PEER_CERT_CACHE).exists());
    }

    #[test]
    fn already_sealed_dial_refuses_unpacked_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let err = lan_dial_already_sealed(dir.path(), "127.0.0.1:9", &"ab".repeat(32), b"hello")
            .unwrap_err();
        assert!(
            err.contains("already-sealed") || err.contains("RavenEnvelopeV1"),
            "{err}"
        );
    }
}

#[cfg(test)]
mod revocation_and_offline_tests {
    use super::*;
    use raven_core::device_revocation::DeviceRevocationV1;
    use raven_core::device_sync::RevocationRecord;
    use raven_core::device_sync::RevocationStore;

    const FAR_FUTURE: u64 = u64::MAX / 2;

    /// The lab file-backed stores. These tests must never reach the OS keychain,
    /// whatever environment `cargo test` runs in; set once and left set (a restore
    /// would race with the other tests, which use the same backends).
    fn lab_backends() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            for key in [
                "RAVEN_SESSION_BACKEND",
                "RAVEN_PREKEY_BACKEND",
                "RAVEN_CHAT_HISTORY_BACKEND",
            ] {
                unsafe { std::env::set_var(key, "locked-file") };
            }
        });
    }

    fn cert(user: &Identity, ed: [u8; 32], x: [u8; 32], device_id: &str) -> DeviceCertificate {
        DeviceCertificate::issue(user, ed, x, device_id, 0, FAR_FUTURE, 0).unwrap()
    }

    fn revoke_legacy(owner: &Identity, dir: &Path, device_id: &str) {
        let mut store = RevocationStore::load_checked(dir).unwrap();
        let rec = RevocationRecord::issue(owner, device_id, 1, 10, "test").unwrap();
        assert!(store.apply(rec).unwrap());
        store.save(dir).unwrap();
    }

    fn revoke_rvdr1(owner: &Identity, dir: &Path, victim: &DeviceCertificate) {
        let wire = DeviceRevocationV1 {
            identity_address: owner.address(),
            device_id: victim.device_id.as_bytes().to_vec(),
            device_ed_pub: victim.device_ed_pub,
            device_x_pub: victim.device_x_pub,
            device_cert_hash: raven_core::device_certificate_hash(victim).unwrap(),
            issuer_device_id: b"desk".to_vec(),
            issuer_seq: 1,
            revocation_id: [9u8; 16],
            reason_code: 1,
            created_at_ms: 10,
            signature: [0u8; 64],
        }
        .sign(owner)
        .unwrap()
        .encode()
        .unwrap();
        let mut store = RevocationStore::load_checked(dir).unwrap();
        assert!(store.apply_rvdr1(&owner.public_key_bytes(), &wire).unwrap());
        store.save(dir).unwrap();
    }

    #[test]
    fn peer_denial_is_lineage_aware_not_just_legacy_device_id() {
        let owner = Identity::from_seed(&[0x61; 32]);
        let dev = Identity::from_seed(&[0x62; 32]);
        let phone = cert(&owner, dev.public_key_bytes(), [3u8; 32], "phone");
        // Same keys re-certified under a new device_id (the RVDR1 §2.2 evasion).
        let recert = cert(&owner, dev.public_key_bytes(), [3u8; 32], "phone-2");
        let fresh = cert(
            &owner,
            Identity::from_seed(&[0x63; 32]).public_key_bytes(),
            [5u8; 32],
            "tablet",
        );

        let clean = tempfile::tempdir().unwrap();
        assert!(!peer_lineage_denied(clean.path(), &phone).unwrap());

        let legacy = tempfile::tempdir().unwrap();
        revoke_legacy(&owner, legacy.path(), "phone");
        assert!(peer_lineage_denied(legacy.path(), &phone).unwrap());
        assert!(!peer_lineage_denied(legacy.path(), &fresh).unwrap());

        let rvdr1 = tempfile::tempdir().unwrap();
        revoke_rvdr1(&owner, rvdr1.path(), &phone);
        assert!(peer_lineage_denied(rvdr1.path(), &phone).unwrap());
        assert!(
            peer_lineage_denied(rvdr1.path(), &recert).unwrap(),
            "reused keys under a new device_id stay denied"
        );
        assert!(!peer_lineage_denied(rvdr1.path(), &fresh).unwrap());
        // The old predicate (what ACK acceptance used) missed exactly this case.
        let store = RevocationStore::load_checked(rvdr1.path()).unwrap();
        assert!(!store.is_revoked(&hex::encode(recert.user_ed_pub), &recert.device_id));
    }

    #[test]
    fn peer_denial_refuses_a_corrupt_revocation_store() {
        let owner = Identity::from_seed(&[0x64; 32]);
        let phone = cert(&owner, [1u8; 32], [2u8; 32], "phone");
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("revocations.json"), b"{not json").unwrap();
        assert!(peer_lineage_denied(dir.path(), &phone).is_err());
    }

    /// An existing confirmed session skips the PairInit-time check, so the send
    /// path itself must refuse a revoked peer lineage (daemon parity), judged on
    /// the certificate the session is bound to.
    #[test]
    fn send_path_refuses_revoked_peer_lineage() {
        // Lab backend: this test must never touch the OS keychain.
        lab_backends();
        let local = Identity::from_seed(&[0x65; 32]);
        let peer = Identity::from_seed(&[0x66; 32]);
        let dev = Identity::from_seed(&[0x67; 32]);
        let peer_cert = cert(&peer, dev.public_key_bytes(), [7u8; 32], "phone");
        let recert = cert(&peer, dev.public_key_bytes(), [7u8; 32], "phone-2");
        let digest = |c: &DeviceCertificate| raven_core::device_certificate_hash(c).unwrap();

        let check = |dir: &Path, victim: &DeviceCertificate, bound: &DeviceCertificate| {
            let (local_cert, _registry) = ensure_local_device_cert(dir, &local).unwrap();
            let mut store = IndexedSessionStore::open(dir).unwrap();
            refuse_revoked_peer(dir, &mut store, &local_cert, victim, &digest(bound))
        };

        let clean = tempfile::tempdir().unwrap();
        check(clean.path(), &peer_cert, &peer_cert).expect("unrevoked peer is allowed");

        let legacy = tempfile::tempdir().unwrap();
        revoke_legacy(&peer, legacy.path(), "phone");
        let err = check(legacy.path(), &peer_cert, &peer_cert).unwrap_err();
        assert!(err.contains(raven_core::ATSAM_LINEAGE_REVOKED), "{err}");
        assert!(err.contains("peer device lineage is revoked"), "{err}");

        // A session established under `recert` is lineage-checked on `recert`.
        let rvdr1 = tempfile::tempdir().unwrap();
        revoke_rvdr1(&peer, rvdr1.path(), &peer_cert);
        let err = check(rvdr1.path(), &recert, &recert).unwrap_err();
        assert!(err.contains(raven_core::ATSAM_LINEAGE_REVOKED), "{err}");
    }

    /// The holder of a legacy-revoked device key re-certifies it under a new
    /// `device_id`: the legacy `(user, device_id)` record no longer matches, so
    /// only the session binding stops the send.
    #[test]
    fn send_path_refuses_recertified_cert_that_evades_a_legacy_revocation() {
        lab_backends();
        let local = Identity::from_seed(&[0x6a; 32]);
        let peer = Identity::from_seed(&[0x6b; 32]);
        let dev = Identity::from_seed(&[0x6c; 32]);
        let bound = cert(&peer, dev.public_key_bytes(), [7u8; 32], "phone");
        let recert = cert(&peer, dev.public_key_bytes(), [7u8; 32], "phone-2");
        let bound_digest = raven_core::device_certificate_hash(&bound).unwrap();

        let dir = tempfile::tempdir().unwrap();
        revoke_legacy(&peer, dir.path(), "phone");
        // The lineage check alone is evaded by the new device_id.
        assert!(peer_lineage_denied(dir.path(), &bound).unwrap());
        assert!(!peer_lineage_denied(dir.path(), &recert).unwrap());

        let (local_cert, _registry) = ensure_local_device_cert(dir.path(), &local).unwrap();
        let mut store = IndexedSessionStore::open(dir.path()).unwrap();
        let err = refuse_revoked_peer(dir.path(), &mut store, &local_cert, &recert, &bound_digest)
            .unwrap_err();
        assert!(err.starts_with(raven_core::ATSAM_SESSION_REQUIRED), "{err}");
        assert!(err.contains("not the one bound"), "{err}");
        assert!(err.contains("nothing was sent"), "{err}");
        // The cert the session is bound to is still refused as revoked.
        let err = refuse_revoked_peer(dir.path(), &mut store, &local_cert, &bound, &bound_digest)
            .unwrap_err();
        assert!(err.contains(raven_core::ATSAM_LINEAGE_REVOKED), "{err}");
    }

    #[test]
    fn session_bound_cert_check_is_exact_on_the_cert_hash() {
        let owner = Identity::from_seed(&[0x6d; 32]);
        let dev = Identity::from_seed(&[0x6e; 32]);
        let bound = cert(&owner, dev.public_key_bytes(), [3u8; 32], "phone");
        let digest = raven_core::device_certificate_hash(&bound).unwrap();
        require_session_bound_peer_cert(&bound, &digest).unwrap();
        // Same keys, new device_id: a different certificate.
        let recert = cert(&owner, dev.public_key_bytes(), [3u8; 32], "phone-2");
        assert!(require_session_bound_peer_cert(&recert, &digest).is_err());
        // An all-zero digest binds nothing.
        assert!(require_session_bound_peer_cert(&bound, &[0u8; 32]).is_err());
    }

    /// The recipient the outcome sentences name in these tests.
    fn bob_ctx(dir: &Path) -> SendCtx {
        SendCtx {
            name: "Bob".into(),
            selector: "--petname Bob".into(),
            dial: "127.0.0.1:9".into(),
            data_dir: Some(dir.to_path_buf()),
            ..SendCtx::default()
        }
    }

    #[test]
    fn chat_text_with_the_reserved_app_prefix_is_never_sent() {
        let dir = tempfile::tempdir().unwrap();
        let id = Identity::from_seed(&[0x6b; 32]);
        let routes = [DialRoute {
            carrier: DialCarrier::Lan,
            dial: "127.0.0.1:9".into(),
        }];
        let peer = hex::encode(Identity::from_seed(&[0x6c; 32]).public_key_bytes());
        for text in ["RVNAPP/1 a2a-request/1 00\n{}", "RVNAPP/"] {
            let err = run_pair_init_and_send_routes(
                dir.path(),
                &id,
                &routes,
                &ProbePlan::in_order(1),
                &peer,
                text,
                &bob_ctx(dir.path()),
            )
            .unwrap_err();
            assert_eq!(err, RESERVED_PREFIX_REFUSAL);
        }
        // Only the prefix is reserved, not the word.
        assert!(raven_core::app_channel::chat_text_allowed(
            "see RVNAPP/1 in the spec"
        ));
        assert!(
            std::fs::read_dir(dir.path()).unwrap().next().is_none(),
            "nothing was created"
        );
    }

    #[test]
    fn only_the_sends_own_message_is_marked_for_friend_custody() {
        let dir = tempfile::tempdir().unwrap();
        let peer_pub = Identity::from_seed(&[0x6a; 32]).public_key_bytes();
        let routes = [DialRoute {
            carrier: DialCarrier::Lan,
            dial: "127.0.0.1:9".into(),
        }];
        let later = now_ms() + 3_600_000;
        let (own, earlier, forced, closed) = ([1u8; 16], [2u8; 16], [3u8; 16], [4u8; 16]);
        use raven_core::custody_gate::{set_custody_gates_for_this_thread, CustodyGates};
        // Gate closed: nothing is marked, whatever the send asked for.
        set_custody_gates_for_this_thread(Some(CustodyGates {
            live: false,
            wan: false,
        }));
        OutboxHandoff::new(dir.path(), &routes, peer_pub, None)
            .with_custody(true)
            .record_own(&closed, later);
        set_custody_gates_for_this_thread(Some(CustodyGates {
            live: true,
            wan: false,
        }));
        let auto = OutboxHandoff::new(dir.path(), &routes, peer_pub, None).with_custody(true);
        auto.record(&earlier, later);
        let _ = auto.note_own(&own, later);
        // `--carrier lan`: the send forced a carrier, so no friend carries it.
        let lan = OutboxHandoff::new(dir.path(), &routes, peer_pub, None).with_custody(false);
        lan.record_own(&forced, later);
        set_custody_gates_for_this_thread(None);
        let records = raven_core::outbox::object_route_records(dir.path(), now_ms()).unwrap();
        assert!(!records[&closed].custody, "custody gate closed");
        assert!(records[&own].custody, "own message, no carrier forced");
        assert!(
            !records[&earlier].custody,
            "an earlier row keeps its own send's choice"
        );
        assert!(
            !records[&forced].custody,
            "a forced carrier never goes via a friend"
        );
    }

    /// G4: a send that forced no carrier records `auto` even when this attempt
    /// had a single LAN route; `lan` only when asked. A later handoff that
    /// re-notes the row never changes the choice it was recorded with.
    #[test]
    fn a_send_that_forced_no_carrier_records_auto_on_one_lan_route() {
        let dir = tempfile::tempdir().unwrap();
        let peer_pub = Identity::from_seed(&[0x6b; 32]).public_key_bytes();
        let routes = [DialRoute {
            carrier: DialCarrier::Lan,
            dial: "127.0.0.1:9".into(),
        }];
        let later = now_ms() + 3_600_000;
        let (own, forced, derived) = ([1u8; 16], [2u8; 16], [3u8; 16]);
        let handoff = |choice| OutboxHandoff::new(dir.path(), &routes, peer_pub, choice);
        handoff(Some(CarrierChoice::Auto)).record_own(&own, later);
        handoff(Some(CarrierChoice::Lan)).record_own(&forced, later);
        handoff(None).record_own(&derived, later);
        let lan = OutboxRoute {
            carrier: OutboxCarrier::Lan,
            dial: "127.0.0.1:9".into(),
        };
        let records = raven_core::outbox::object_route_records(dir.path(), now_ms()).unwrap();
        assert_eq!(records[&own].choice, CarrierChoice::Auto);
        assert_eq!(records[&own].routes, vec![lan.clone()]);
        assert_eq!(records[&forced].choice, CarrierChoice::Lan);
        assert_eq!(
            records[&derived].choice,
            CarrierChoice::Lan,
            "no choice given: derived from the one LAN route"
        );
        // Re-noted by a later send of the other kind: unchanged.
        handoff(Some(CarrierChoice::Lan)).record(&own, later);
        handoff(Some(CarrierChoice::Auto)).record(&forced, later);
        let records = raven_core::outbox::object_route_records(dir.path(), now_ms()).unwrap();
        assert_eq!(records[&own].choice, CarrierChoice::Auto);
        assert_eq!(records[&forced].choice, CarrierChoice::Lan);
        assert_eq!(records[&forced].routes, vec![lan]);
    }

    #[test]
    fn unreachable_peer_without_a_session_says_nothing_was_queued() {
        lab_backends();
        let dir = tempfile::tempdir().unwrap();
        let local = Identity::from_seed(&[0x68; 32]);
        let peer = Identity::from_seed(&[0x69; 32]);
        let peer_pub = peer.public_key_bytes();
        assert!(offline_send_target(dir.path(), &peer_pub)
            .unwrap()
            .is_none());

        let (local_cert, registry) = ensure_local_device_cert(dir.path(), &local).unwrap();
        let routes = [DialRoute {
            carrier: DialCarrier::Lan,
            dial: "127.0.0.1:9".into(),
        }];
        let handoff = OutboxHandoff::new(dir.path(), &routes, peer_pub, None);
        let err = send_when_peer_unreachable(
            dir.path(),
            &local,
            &registry,
            &local_cert,
            "127.0.0.1:9",
            &hex::encode(peer_pub),
            &peer_pub,
            "hello",
            DialCarrier::Lan,
            "ipc LAN_DIAL: lan connect: cannot connect to 127.0.0.1:9 (127.0.0.1:9: Connection \
             refused (os error 61))"
                .into(),
            &bob_ctx(dir.path()),
            &handoff,
        )
        .unwrap_err();
        assert!(err.starts_with("NOT SENT: "), "{err}");
        assert!(err.contains("Bob"), "names the person: {err}");
        assert!(
            !dir.path()
                .join(raven_core::outbox::OUTBOX_ROUTES_FILE)
                .exists(),
            "nothing was queued, so nothing was handed to the outbox"
        );
        assert!(err.contains("It was not kept"), "{err}");
        assert!(
            err.contains("a first message needs you and Bob both online"),
            "{err}"
        );
        assert!(
            err.contains("Ask Bob to open Raven, then send again."),
            "gives the next step: {err}"
        );
        assert!(
            err.contains("(technical: ipc LAN_DIAL: lan connect")
                && err.contains("Connection refused"),
            "the raw text stays at the end: {err}"
        );
        assert!(!err.contains("status delivered"), "{err}");
    }

    #[test]
    fn delivery_status_wording_distinguishes_queued_from_not_sent() {
        let ctx = bob_ctx(Path::new("/p"));
        let day = RetryNote {
            expires_at_ms: now_ms() + raven_core::ENVELOPE_VALIDITY_MS,
            copy_expires_at_ms: 0,
            background: false,
            custodians: Vec::new(),
            carry_first: None,
        };
        let queued = queued_text(
            &ctx,
            "ipc LAN_DIAL: lan dial timeout; mid=abababab…",
            "\"see you at 5\"",
            &day,
        );
        assert!(queued.starts_with("not delivered yet"), "{queued}");
        assert!(queued.contains("queued locally"), "{queued}");
        assert!(queued.contains("\"see you at 5\""), "{queued}");
        assert!(queued.contains("abababab"), "{queued}");
        assert!(queued.contains("timeout"), "{queued}");
        // The retry promise carries the real window (the envelope validity, a
        // day), and says when nothing retries in the background.
        assert!(queued.contains("in about 24 h)"), "{queued}");
        assert!(queued.contains("expires"), "{queued}");
        assert!(queued.contains("NOT retried automatically"), "{queued}");
        let kept = queued_text(
            &ctx,
            "ipc LAN_DIAL: lan dial timeout; mid=abababab…",
            "\"see you at 5\"",
            &RetryNote {
                background: true,
                ..day.clone()
            },
        );
        assert!(kept.contains("raven-node keeps trying"), "{kept}");
        assert!(!kept.contains("NOT retried"), "{kept}");
        assert!(SUPERSEDED_SESSION.contains("marked failed"));
        assert!(EXPIRED_BEFORE_DELIVERY.contains("marked expired (not delivered)"));
        for why in [EXPIRED_BEFORE_DELIVERY, SUPERSEDED_SESSION] {
            assert!(why.contains("send it again"), "{why}");
        }
        let held = earlier_undelivered_text(
            &ctx,
            "ipc LAN_DIAL: lan dial timeout",
            "\"see you at 5\"",
            &day,
        );
        assert!(held.starts_with("NOT SENT"), "{held}");
        assert!(held.contains("not queued"), "{held}");
        assert!(!held.contains("queued locally"), "{held}");
        let unconfirmed = unconfirmed_text(
            &ctx,
            "WAITING_FOR_ENDPOINT_ACK: no sealed ACK came back; mid=abababab…",
            "",
            &day,
        );
        assert!(
            unconfirmed.starts_with("sent, delivery unconfirmed"),
            "{unconfirmed}"
        );
        assert!(unconfirmed.contains("Do not retype it"), "{unconfirmed}");
    }

    #[test]
    fn internet_hold_message_is_the_shared_gate_text() {
        assert!(INTERNET_DIRECT_HOLD.starts_with("INTERNET_DIRECT_HOLD:"));
        assert!(INTERNET_DIRECT_HOLD.contains("RAVEN_LAB_TEST_A=0"));
        assert!(INTERNET_DIRECT_HOLD.contains("INTERNET_DIRECT_PRODUCTION_ENABLED=true"));
        assert!(!INTERNET_DIRECT_HOLD.contains("lab-only"));
    }
}

/// The whole `ash send` path against an in-process stand-in for the local daemon
/// and the peer (a UDS server that answers `LanDial` by driving the peer's real
/// `dispatch_frame`), with the lab file backends so nothing touches an OS
/// keystore. Black-box for the send logic: only the daemon boundary is faked.
#[cfg(all(test, unix))]
mod send_path_tests {
    use super::super::ipc_client::test_support::short_tempdir;
    use super::*;
    use base64::Engine;
    use raven_core::envelope::EnvType;
    use raven_core::ipc::{decode_request, encode_response};
    use raven_core::lan_dispatch::{dispatch_frame, encode_local_offer, local_bundle};
    use std::io::{Read, Write};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
    use std::sync::Arc;

    const DOWN: u8 = 0;
    const UP: u8 = 1;
    const REFUSE_ALL: u8 = 2;

    const PEER_CLOSED_TEXT: &str = "LAN_DIAL_PEER_CLOSED: the peer closed the connection without \
        replying; the frames were sent, delivery is unconfirmed and a retry is safe";

    fn lab_backends() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            for key in [
                "RAVEN_SESSION_BACKEND",
                "RAVEN_PREKEY_BACKEND",
                "RAVEN_CHAT_HISTORY_BACKEND",
            ] {
                unsafe { std::env::set_var(key, "locked-file") };
            }
        });
    }

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    fn contacts_json(peer: &[u8; 32]) -> String {
        format!(
            r#"[{{"petname":"Peer","public_tag":"","alias":"","address":"","pub_hex":"{}","pinned":false,"lan_dial":""}}]"#,
            hex::encode(peer)
        )
    }

    /// Faults the fake daemon injects; each counts down as it fires.
    #[derive(Default)]
    struct Faults {
        /// Message frames the peer refuses (closes on) before it behaves again.
        refuse_messages: AtomicUsize,
        /// Dials that carry frames and that the peer's listener sheds at the
        /// handshake (none of the frames reaches it), before it accepts again.
        shed_frame_dials: AtomicUsize,
    }

    /// Fire one unit of a fault counter: decrement it if positive.
    /// (A plain CAS loop: `fetch_update` is deprecated from Rust 1.99, and its
    /// `try_update` replacement does not exist on the pinned CI toolchain.)
    fn fire(counter: &AtomicUsize) -> bool {
        let mut left = counter.load(Ordering::SeqCst);
        while left > 0 {
            match counter.compare_exchange(left, left - 1, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => return true,
                Err(actual) => left = actual,
            }
        }
        false
    }

    struct Rig {
        a: tempfile::TempDir,
        b: tempfile::TempDir,
        alice: Identity,
        bob: Identity,
        mode: Arc<AtomicU8>,
        faults: Arc<Faults>,
    }

    impl Rig {
        fn new(seed: u8) -> Self {
            lab_backends();
            let a = short_tempdir();
            let b = short_tempdir();
            let alice = Identity::from_seed(&[seed; 32]);
            let bob = Identity::from_seed(&[seed.wrapping_add(1); 32]);
            ensure_lab_local_material(a.path(), &alice).unwrap();
            ensure_lab_local_material(b.path(), &bob).unwrap();
            let a_bundle = local_bundle(a.path(), &alice).unwrap();
            let bob_pub = bob.public_key_bytes();
            let alice_pub = alice.public_key_bytes();
            std::fs::write(a.path().join("contacts.json"), contacts_json(&bob_pub)).unwrap();
            std::fs::write(b.path().join("contacts.json"), contacts_json(&alice_pub)).unwrap();
            let mode = Arc::new(AtomicU8::new(UP));
            let faults = Arc::new(Faults::default());

            let listener = UnixListener::bind(raven_core::default_socket_path(a.path())).unwrap();
            let (b_dir, bob2, m, f) = (
                b.path().to_path_buf(),
                Identity::from_seed(&[seed.wrapping_add(1); 32]),
                mode.clone(),
                faults.clone(),
            );
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else { return };
                    serve_one(&mut stream, &b_dir, &bob2, &a_bundle, &alice_pub, &m, &f);
                }
            });
            Self {
                a,
                b,
                alice,
                bob,
                mode,
                faults,
            }
        }

        fn send(&self, text: &str) -> Result<(), String> {
            self.send_recording(text, None)
        }

        /// `send` with what the send asked for (`SendCtx::choice`).
        fn send_choosing(&self, text: &str, choice: CarrierChoice) -> Result<(), String> {
            self.send_recording(text, Some(choice))
        }

        fn send_recording(&self, text: &str, choice: Option<CarrierChoice>) -> Result<(), String> {
            run_pair_init_and_send_on(
                self.a.path(),
                &self.alice,
                "127.0.0.1:9",
                &hex::encode(self.bob.public_key_bytes()),
                text,
                DialCarrier::Lan,
                &SendCtx {
                    name: "Peer".into(),
                    selector: "--petname Peer".into(),
                    dial: "127.0.0.1:9".into(),
                    data_dir: Some(self.a.path().to_path_buf()),
                    choice,
                    ..SendCtx::default()
                },
            )
        }

        fn set_mode(&self, mode: u8) {
            self.mode.store(mode, Ordering::SeqCst);
        }

        fn bob_inbox(&self) -> Vec<String> {
            let mut store = IndexedSessionStore::open(self.b.path()).unwrap();
            let mut texts: Vec<String> = store
                .list_endpoint_inbox()
                .unwrap()
                .into_iter()
                .map(|row| String::from_utf8_lossy(&row.plaintext).into_owned())
                .collect();
            texts.sort();
            texts
        }

        fn alice_sessions(&self) -> usize {
            IndexedSessionStore::open(self.a.path())
                .unwrap()
                .find_confirmed_sessions_for_peer_at(&self.bob.public_key_bytes(), now_ms())
                .unwrap()
                .len()
        }

        /// Messages to Bob still waiting: prepared, or queued without an ACK
        /// (an unreachable peer's messages are handed to the outbox queue).
        fn alice_pending(&self) -> usize {
            self.alice_waiting().len()
        }

        fn alice_waiting(&self) -> Vec<raven_core::EndpointOutbound> {
            let store = IndexedSessionStore::open(self.a.path()).unwrap();
            let bob = self.bob.public_key_bytes();
            let mut rows = store
                .pending_endpoint_outbound_for_recipient(Some(&bob))
                .unwrap();
            rows.extend(
                store
                    .awaiting_ack_endpoint_outbound_for_recipient(Some(&bob))
                    .unwrap(),
            );
            rows.retain(|row| row.kind == EndpointOutboundKind::Message);
            rows
        }

        fn alice_history(&self) -> Vec<(String, String)> {
            raven_core::ChatHistory::load(self.a.path())
                .unwrap()
                .entries
                .into_iter()
                .filter(|e| e.direction == "out")
                .map(|e| (e.body, e.delivery))
                .collect()
        }
    }

    /// One framed `IpcRequest` in, one framed `IpcResponse` out.
    fn serve_one(
        stream: &mut UnixStream,
        b_dir: &Path,
        bob: &Identity,
        a_bundle: &raven_core::LanBundle,
        alice_pub: &[u8; 32],
        mode: &AtomicU8,
        faults: &Faults,
    ) {
        let mut len = [0u8; 4];
        if stream.read_exact(&mut len).is_err() {
            return;
        }
        let mut frame = len.to_vec();
        frame.resize(4 + u32::from_be_bytes(len) as usize, 0);
        if stream.read_exact(&mut frame[4..]).is_err() {
            return;
        }
        let error = |message: &str| IpcResponse::Error {
            v: IPC_VERSION,
            code: "LAN_DIAL".into(),
            message: message.into(),
        };
        let response = match decode_request(&frame) {
            Ok(IpcRequest::Ping { .. }) => IpcResponse::Pong { v: IPC_VERSION },
            Ok(IpcRequest::LanDial { frames_b64, .. }) => {
                let frames: Vec<Vec<u8>> = frames_b64
                    .iter()
                    .map(|s| base64::engine::general_purpose::STANDARD.decode(s).unwrap())
                    .collect();
                let mode = mode.load(Ordering::SeqCst);
                let shed = !frames.is_empty() && fire(&faults.shed_frame_dials);
                if mode == DOWN {
                    error("lan connect: cannot connect to 127.0.0.1:9 (connection refused)")
                } else if shed {
                    // The listener hung up in the middle of the handshake: nothing
                    // of ours was processed.
                    error(
                        "peer closed the connection during the handshake (3 attempts); the \
                         peer may be at its connection limit or may not be a RAVEN node",
                    )
                } else {
                    let offer = encode_local_offer(b_dir, bob).unwrap();
                    let mut replies = vec![b64(&offer)];
                    let mut failure = None;
                    for f in &frames {
                        let is_message = Envelope::unpack(f)
                            .is_some_and(|e| e.env_type == EnvType::Message as u8);
                        let refused =
                            mode == REFUSE_ALL || (is_message && fire(&faults.refuse_messages));
                        if refused {
                            failure = Some(PEER_CLOSED_TEXT.to_string());
                            break;
                        }
                        match dispatch_frame(b_dir, bob, a_bundle, alice_pub, f) {
                            Ok(more) => replies.extend(more.iter().map(|r| b64(r))),
                            Err(_) => {
                                // The daemon closes on a dispatch error: the dialer
                                // sees a silent peer.
                                failure = Some(PEER_CLOSED_TEXT.to_string());
                                break;
                            }
                        }
                    }
                    match failure {
                        Some(text) => error(&text),
                        None => IpcResponse::LanDialResult {
                            v: IPC_VERSION,
                            frames_b64: replies,
                        },
                    }
                }
            }
            _ => error("unsupported request"),
        };
        let _ = stream.write_all(&encode_response(&response).unwrap());
    }

    fn mid_of(queued_text: &str) -> String {
        let after = queued_text.split("mid=").nth(1).expect("mid= in text");
        after
            .chars()
            .take_while(|c| c.is_ascii_hexdigit())
            .collect()
    }

    /// The headline regression. A queued message M1 is retried (and delivered) at
    /// the start of the next send; a *new* message that then fails before its own
    /// dial (here: a control character) reported "not delivered yet: message
    /// mid=<M1> is queued locally" because the retry had left its binding and
    /// staged flag behind. The new text was never staged: it must say so.
    #[test]
    fn a_new_message_that_fails_early_is_not_reported_as_queued_under_the_earlier_one() {
        let rig = Rig::new(0x80);
        rig.send("hello").expect("first contact delivers");
        rig.set_mode(DOWN);
        let queued = rig.send("queued one").unwrap_err();
        assert!(queued.starts_with("not delivered yet"), "{queued}");
        let m1 = mid_of(&queued);
        rig.set_mode(UP);

        let err = rig.send("bad\u{1b}[31mtext").unwrap_err();
        assert!(err.starts_with("NOT SENT: "), "{err}");
        assert!(err.contains("Nothing was queued"), "{err}");
        assert!(!err.contains("queued locally"), "{err}");
        assert!(
            !err.contains(&m1),
            "must not name the earlier message: {err}"
        );
        assert_eq!(
            send_failure_line(&err),
            err,
            "and the CLI prints it as it is: no queued prefix, no second refusal prefix"
        );
        // The retry of M1 inside that send did deliver it, and nothing of the new
        // text was staged anywhere.
        assert_eq!(rig.bob_inbox(), vec!["hello", "queued one"]);
        assert_eq!(rig.alice_pending(), 0);
        assert!(
            rig.alice_history()
                .iter()
                .all(|(body, _)| !body.contains("bad")),
            "{:?}",
            rig.alice_history()
        );
        // The channel is healthy afterwards.
        rig.send("fine").unwrap();
        assert_eq!(rig.bob_inbox(), vec!["fine", "hello", "queued one"]);
    }

    /// A refused retry of a row on the *current* session is kept (the refusal may
    /// be transient), the error names the likely cause, and the new text is not
    /// queued.
    #[test]
    fn refused_retry_on_the_current_session_keeps_the_row_and_says_why() {
        let rig = Rig::new(0x82);
        rig.send("hello").unwrap();
        rig.set_mode(DOWN);
        let queued = rig.send("held back").unwrap_err();
        assert!(queued.starts_with("not delivered yet"), "{queued}");
        rig.set_mode(UP);
        rig.faults.refuse_messages.store(1, Ordering::SeqCst);

        let err = rig.send("second").unwrap_err();
        assert!(err.starts_with("NOT SENT: an earlier message"), "{err}");
        assert!(
            err.contains("\"held back\""),
            "shows the text, not an id: {err}"
        );
        assert!(err.contains("this message was not queued"), "{err}");
        assert!(err.contains("without saying why"), "{err}");
        assert!(err.contains("not have you in their contacts"), "{err}");
        assert_eq!(rig.alice_pending(), 1, "the earlier row stays queued");
        // Once the peer behaves, the next send delivers both, in order.
        rig.send("third").unwrap();
        assert_eq!(rig.bob_inbox(), vec!["held back", "hello", "third"]);
        assert_eq!(rig.alice_pending(), 0);
    }

    /// Review C-time-deadlines-1: a message the contact read and refused
    /// stays prepared, and its route record says it was written. Read past
    /// its deadline, as a later send that gives it up reads it (the live
    /// records no longer list it), it did leave this computer. A prepared row
    /// without that mark still never left; a queued one did, unless unsent.
    #[test]
    fn a_message_read_and_refused_is_not_never_sent_once_it_expires() {
        let rig = Rig::new(0x99);
        rig.send("hello").unwrap();
        rig.faults.refuse_messages.store(1, Ordering::SeqCst);
        let queued = rig.send("read and refused").unwrap_err();
        assert!(queued.starts_with("not delivered yet"), "{queued}");
        let bob = rig.bob.public_key_bytes();
        let mut rows = IndexedSessionStore::open(rig.a.path())
            .unwrap()
            .pending_endpoint_outbound_for_recipient(Some(&bob))
            .unwrap();
        assert_eq!(rows.len(), 1, "still prepared");
        let row = rows.remove(0);
        let expired = envelope_expiry(&row.immutable_envelope_bytes);
        assert!(
            raven_core::outbox::object_route_records(rig.a.path(), expired)
                .unwrap()
                .is_empty()
        );
        let evidence = raven_core::outbox::object_route_evidence(rig.a.path(), expired).unwrap();
        let record = evidence.get(&row.message_id);
        assert!(record.is_some_and(|r| r.written), "{record:?}");
        assert!(!never_left_computer(false, record));
        assert!(never_left_computer(false, None));
        assert!(!never_left_computer(true, None));
    }

    /// A row sealed under a session the reachable peer refuses, while a newer
    /// confirmed session exists, can never be delivered: it is abandoned (marked
    /// failed) instead of blocking every send until its envelope expires.
    #[test]
    fn row_on_a_superseded_session_that_the_peer_refuses_is_abandoned() {
        let rig = Rig::new(0x84);
        rig.send("hello").unwrap();
        rig.set_mode(DOWN);
        let queued = rig.send("stuck on the old session").unwrap_err();
        assert!(queued.starts_with("not delivered yet"), "{queued}");
        // A newer confirmed session with the same peer (a re-pair).
        std::thread::sleep(Duration::from_millis(20));
        let old_sessions = rig.alice_sessions();
        rig.set_mode(UP);
        {
            let bob_bundle = local_bundle(rig.b.path(), &rig.bob).unwrap();
            let (init, key) =
                create_initiator_pair_init(rig.a.path(), &rig.alice, &bob_bundle).unwrap();
            let a_bundle = local_bundle(rig.a.path(), &rig.alice).unwrap();
            let replies = dispatch_frame(
                rig.b.path(),
                &rig.bob,
                &a_bundle,
                &rig.alice.public_key_bytes(),
                &wrap_pair_init(&rig.alice, &init).unwrap(),
            )
            .unwrap();
            let response = first_pair_response(&replies).expect("PairResponse");
            IndexedSessionStore::open(rig.a.path())
                .unwrap()
                .confirm_verified_pair_response(&key, &init, &response, now_ms())
                .unwrap();
        }
        assert_eq!(rig.alice_sessions(), old_sessions + 1);
        // The peer refuses the old row's retry once (it lost that session), then
        // accepts the new message on the new session.
        rig.faults.refuse_messages.store(1, Ordering::SeqCst);
        rig.send("on the new session")
            .expect("not blocked by the stale row");
        assert_eq!(rig.alice_pending(), 0);
        let history = rig.alice_history();
        assert!(
            history
                .iter()
                .any(|(body, state)| body == "stuck on the old session" && state == "failed"),
            "{history:?}"
        );
        assert_eq!(rig.bob_inbox(), vec!["hello", "on the new session"]);
    }

    /// C (ash side): a queued message whose ACK already came back another way
    /// (raven-node's outbox, or the peer pushing it) is recorded as delivered
    /// by the next send and never dialled again, and the new message goes out
    /// behind it as usual.
    #[test]
    fn a_queued_message_already_acknowledged_is_not_dialled_again() {
        let rig = Rig::new(0x8a);
        rig.send("hello").unwrap();
        rig.set_mode(DOWN);
        let queued = rig.send("acked elsewhere").unwrap_err();
        assert!(queued.starts_with("not delivered yet"), "{queued}");
        // Bob got the exact bytes some other way; his ACK reaches Alice's store
        // without touching the row (the F8 race).
        let row = rig.alice_waiting().remove(0);
        let a_bundle = local_bundle(rig.a.path(), &rig.alice).unwrap();
        let ack = dispatch_frame(
            rig.b.path(),
            &rig.bob,
            &a_bundle,
            &rig.alice.public_key_bytes(),
            &row.immutable_envelope_bytes,
        )
        .unwrap()
        .into_iter()
        .find(|f| Envelope::unpack(f).is_some())
        .unwrap();
        let key = IndexedSessionStore::open(rig.a.path())
            .unwrap()
            .record_key_for_session_id(&row.session_id)
            .unwrap()
            .unwrap();
        let bob_cert = local_bundle(rig.b.path(), &rig.bob).unwrap().cert;
        IndexedSessionStore::open(rig.a.path())
            .unwrap()
            .accept_ack_envelope(&key, &ack, &bob_cert, false, now_ms())
            .unwrap();
        // Bob is still down: the next send must not dial (or wait on) the
        // delivered row, and queues its own text.
        let err = rig.send("next").unwrap_err();
        assert!(err.starts_with("not delivered yet"), "{err}");
        assert!(!err.contains("earlier message"), "{err}");
        assert!(rig
            .alice_history()
            .iter()
            .any(|(body, state)| body == "acked elsewhere" && state == "delivered"));
        assert_eq!(rig.alice_pending(), 1, "only the new message is queued");
    }

    /// D(b) (ash side): an earlier message the store refuses only because the
    /// clock stepped back (it is dated ahead of now) is kept, not given up as
    /// expired, and the next send says why.
    #[test]
    fn an_earlier_message_dated_ahead_of_the_clock_is_kept_not_expired() {
        let rig = Rig::new(0x8c);
        rig.send("hello").unwrap();
        // Stage a message sealed 10 minutes "in the future" (a fast clock that
        // was corrected since), its dial failing.
        let ahead = now_ms() + 10 * 60_000;
        let (cert, registry) = ensure_local_device_cert(rig.a.path(), &rig.alice).unwrap();
        let device =
            AuthorizedEndpointDevice::authorize(&cert, &rig.alice, &registry, ahead).unwrap();
        let bob = rig.bob.public_key_bytes();
        let mut store = IndexedSessionStore::open(rig.a.path()).unwrap();
        let key = store
            .find_confirmed_session_for_peer(&bob)
            .unwrap()
            .unwrap();
        let session = store.session_id_for_record_key(&key).unwrap();
        let end = store.session_expires_at(&key).unwrap();
        let a_dir = rig.a.path().to_path_buf();
        let _ = store.send_message_envelope(
            &key,
            "from a fast clock",
            &device,
            ahead,
            (ahead + 3_600_000).min(end),
            ahead,
            &mut rand::rngs::OsRng,
            &mut |d: &[u8; 32], bytes: &[u8]| {
                let env = Envelope::unpack(bytes).unwrap();
                raven_core::ensure_outbound_queued_history(
                    &a_dir,
                    &bob,
                    &session,
                    d,
                    &env.message_id,
                    ahead,
                    Some("from a fast clock"),
                )
                .unwrap();
                Err(())
            },
        );
        drop(store);
        assert_eq!(rig.alice_pending(), 1);
        let err = rig.send("now").unwrap_err();
        assert!(err.starts_with("NOT SENT: an earlier message"), "{err}");
        assert!(err.contains("ENDPOINT_NOT_CURRENTLY_VALID"), "{err}");
        assert!(err.contains("did the clock change"), "{err}");
        assert_eq!(rig.alice_pending(), 1, "kept, not abandoned");
        assert!(rig
            .alice_history()
            .iter()
            .any(|(body, state)| body == "from a fast clock" && state == "queued"));
    }

    /// First contact: the PairInit itself is refused silently (the stranger case,
    /// the peer logs "peer is not a local contact" and says nothing on the wire).
    /// The error must name the likely cause.
    #[test]
    fn silently_refused_pair_init_names_the_missing_contact() {
        let rig = Rig::new(0x86);
        rig.set_mode(REFUSE_ALL);
        let err = rig.send("hello").unwrap_err();
        assert!(
            err.starts_with("NOT SENT: Peer did not accept your first message"),
            "{err}"
        );
        assert!(
            err.contains("most often Peer has not added you as a contact yet"),
            "{err}"
        );
        assert!(err.contains("ask them to add you"), "{err}");
        assert!(err.contains("Nothing was queued"), "{err}");
        assert!(
            err.contains("PEER_CLOSED"),
            "the raw text stays at the end: {err}"
        );
        // The sentence itself must not repeat the daemon's "a retry is safe": a
        // retry does nothing until they add you. Only the raw tail keeps it.
        let sentence = err.split("(technical:").next().unwrap();
        assert!(!sentence.contains("retry is safe"), "{err}");
        assert!(!err.contains("status delivered"), "{err}");
        assert_eq!(rig.alice_sessions(), 0);
    }

    /// Concurrent `ash send`s from one profile used to interleave: two first
    /// contacts each ran PairInit and left two sessions (the pair then stayed
    /// wedged), and a burst fought over the single outstanding-message slot, so
    /// some of the texts were lost. Serialised per peer, every send succeeds on
    /// the one session the first of them created.
    #[test]
    fn concurrent_first_contact_sends_share_one_session_and_all_deliver() {
        let rig = Arc::new(Rig::new(0x88));
        const N: usize = 6;
        let barrier = Arc::new(std::sync::Barrier::new(N));
        let handles: Vec<_> = (0..N)
            .map(|i| {
                let (rig, barrier) = (rig.clone(), barrier.clone());
                std::thread::spawn(move || {
                    barrier.wait();
                    rig.send(&format!("burst {i}"))
                })
            })
            .collect();
        let results: Vec<Result<(), String>> =
            handles.into_iter().map(|h| h.join().unwrap()).collect();
        for (i, r) in results.iter().enumerate() {
            assert!(r.is_ok(), "send {i}: {r:?}");
        }
        assert_eq!(rig.alice_sessions(), 1, "exactly one PairInit may have won");
        let expected: Vec<String> = {
            let mut v: Vec<String> = (0..N).map(|i| format!("burst {i}")).collect();
            v.sort();
            v
        };
        assert_eq!(rig.bob_inbox(), expected);
        assert_eq!(rig.alice_pending(), 0);
    }

    /// A burst of concurrent sends overflows the peer's per-source handshake cap
    /// and the listener hangs up *during the handshake*: none of our frames got
    /// through, so the PairInit dial and the message dial are repeated (like the
    /// RLB1 probe) instead of reporting a failed dial or leaving the text queued.
    #[test]
    fn pair_init_and_message_dials_shed_at_the_handshake_are_retried() {
        let rig = Rig::new(0x8a);
        // First contact: the PairInit dial is shed once, then goes through.
        rig.faults.shed_frame_dials.store(1, Ordering::SeqCst);
        rig.send("hello")
            .expect("a shed PairInit dial is retried, not reported");
        assert_eq!(rig.faults.shed_frame_dials.load(Ordering::SeqCst), 0);
        assert_eq!(rig.alice_sessions(), 1, "one PairInit, not one per attempt");
        // The message dial is shed twice, then goes through.
        rig.faults.shed_frame_dials.store(2, Ordering::SeqCst);
        rig.send("second")
            .expect("a shed message dial is retried, not queued");
        assert_eq!(rig.faults.shed_frame_dials.load(Ordering::SeqCst), 0);
        assert_eq!(rig.alice_pending(), 0, "delivered, not left queued");
        assert_eq!(rig.bob_inbox(), vec!["hello", "second"]);
        assert!(
            rig.alice_history()
                .iter()
                .all(|(_, state)| state != "failed"),
            "{:?}",
            rig.alice_history()
        );
    }

    /// A reachable peer whose dials keep failing at the transport (shed at the
    /// handshake more often than the dial retries) queues each message behind
    /// the last instead of refusing the next one; once the link recovers, the
    /// next send delivers everything.
    #[test]
    fn transport_failures_on_a_reachable_peer_queue_messages_behind_each_other() {
        let rig = Rig::new(0x91);
        rig.send("hello").unwrap();
        rig.faults.shed_frame_dials.store(1_000, Ordering::SeqCst);
        let one = rig.send("one").unwrap_err();
        assert!(one.starts_with("not delivered yet"), "{one}");
        let two = rig.send("two").unwrap_err();
        assert!(
            two.starts_with("not delivered yet"),
            "queued too, not refused: {two}"
        );
        assert_eq!(rig.alice_pending(), 2);
        rig.faults.shed_frame_dials.store(0, Ordering::SeqCst);
        rig.send("three").unwrap();
        assert_eq!(rig.bob_inbox(), vec!["hello", "one", "three", "two"]);
        assert_eq!(rig.alice_pending(), 0);
    }

    /// A message the peer refused stays prepared. When the peer is then
    /// unreachable, the next send hands that row to the outbox queue (no
    /// dial) and queues its own text behind it, instead of failing with a
    /// false "another send is still running".
    #[test]
    fn an_earlier_prepared_row_is_queued_not_blocking_while_the_peer_is_down() {
        let rig = Rig::new(0x93);
        rig.send("hello").unwrap();
        rig.faults.refuse_messages.store(1, Ordering::SeqCst);
        let refused = rig.send("refused once").unwrap_err();
        assert!(!refused.contains("still running"), "{refused}");
        let prepared = IndexedSessionStore::open(rig.a.path())
            .unwrap()
            .pending_endpoint_outbound_for_recipient(Some(&rig.bob.public_key_bytes()))
            .unwrap();
        assert_eq!(prepared.len(), 1, "the refused message is still prepared");

        rig.set_mode(DOWN);
        let queued = rig.send("while down").unwrap_err();
        assert!(queued.starts_with("not delivered yet"), "{queued}");
        assert!(!queued.contains("still running"), "{queued}");
        assert_eq!(rig.alice_pending(), 2, "both wait, in order");
        let still_prepared = IndexedSessionStore::open(rig.a.path())
            .unwrap()
            .pending_endpoint_outbound_for_recipient(Some(&rig.bob.public_key_bytes()))
            .unwrap();
        assert!(
            still_prepared.is_empty(),
            "handed to the queue, not left prepared"
        );

        rig.set_mode(UP);
        rig.send("back").unwrap();
        assert_eq!(
            rig.bob_inbox(),
            vec!["back", "hello", "refused once", "while down"]
        );
    }

    fn alice_record(rig: &Rig, mid: &[u8; 16]) -> Option<raven_core::outbox::ObjectRoutes> {
        raven_core::outbox::object_route_records(rig.a.path(), now_ms())
            .unwrap()
            .remove(mid)
    }

    /// B-offline-lan-1 (any-network plan P2.R1), `raven send`'s side: a
    /// contact whose only route is a learned one (cutoff F7's guess at the
    /// address it last came from, for a contact added from an invite line,
    /// as `resolve_send_target` plans it) goes down `run_send`'s one-route
    /// LAN send. A message queued there while the contact is away records no
    /// copy of that address for raven-node's outbox, whose worker plans it
    /// again at each attempt through its own on-link filter (a recorded copy
    /// would be dialled on every retry, on any network). The app's side:
    /// tui/controller.rs's
    /// `a_message_queued_on_a_learned_route_alone_never_records_it`.
    #[test]
    fn a_cli_send_queued_on_a_learned_route_alone_never_records_it() {
        let rig = Rig::new(0xB7);
        rig.send("hello").unwrap();
        rig.set_mode(DOWN);
        let guess = "192.168.1.44:7420".to_string();
        let target = super::super::SendTarget {
            routes: vec![DialRoute {
                carrier: DialCarrier::Lan,
                dial: guess.clone(),
            }],
            pub_hex: hex::encode(rig.bob.public_key_bytes()),
            listen: "127.0.0.1:0".into(),
            env_lan_dial: None,
            learned_lan_dials: vec![guess.clone()],
            unrecorded: vec![guess.clone()],
            learned_p2p: None,
            explicit_dial: false,
            lan_unsaved: true,
        };
        let queued = super::super::run_send(
            rig.a.path(),
            &rig.alice,
            &target,
            "while away",
            super::super::CarrierChoice::Auto,
        )
        .unwrap_err();
        assert!(queued.starts_with("not delivered yet"), "{queued}");
        let waiting = rig.alice_waiting();
        assert_eq!(waiting.len(), 1, "queued");
        let record = alice_record(&rig, &waiting[0].message_id).expect("recorded");
        assert!(
            !record.routes.iter().any(|r| r.dial == guess),
            "the learned route was recorded: {record:?}"
        );
        rig.set_mode(UP);
        rig.send("back").unwrap();
        assert_eq!(rig.bob_inbox(), vec!["back", "hello", "while away"]);
    }

    /// A prepared message whose own `--carrier` excludes this send's carrier is
    /// handed to the queue for its own carrier, not left blocking the lane: the
    /// new message still goes out.
    #[test]
    fn a_prepared_row_for_another_carrier_does_not_block_the_lane() {
        let rig = Rig::new(0x95);
        rig.send("hello").unwrap();
        rig.faults.refuse_messages.store(1, Ordering::SeqCst);
        let _ = rig.send("internet only").unwrap_err();
        let row = rig.alice_waiting().remove(0);
        // A record keeps its first send's choice: start over as Internet.
        clear_object_routes(rig.a.path(), &[row.message_id]).unwrap();
        record_object_routes(
            rig.a.path(),
            &row.message_id,
            &rig.bob.public_key_bytes(),
            CarrierChoice::Internet,
            &[],
            now_ms() + 3_600_000,
            now_ms(),
        )
        .unwrap();
        rig.send("over lan").expect("the lane is free");
        assert_eq!(rig.bob_inbox(), vec!["hello", "over lan"]);
        let waiting = rig.alice_waiting();
        assert_eq!(waiting.len(), 1, "the internet-only message still waits");
        assert_eq!(
            waiting[0].state,
            raven_core::EndpointOutboxState::Queued,
            "handed to the queue, not prepared"
        );
        assert!(alice_record(&rig, &row.message_id).is_some_and(|r| r.unsent));
    }

    /// G4: each queued message keeps the carrier choice of its own send. A
    /// later send that redials an earlier queued row and fails on it re-notes
    /// that row, but never rewrites its choice: a `lan` row is not widened by
    /// a later auto send, and an auto row is not narrowed by a later `lan` one.
    #[test]
    fn each_queued_message_keeps_its_own_sends_carrier_choice() {
        for (seed, first, second) in [
            (0x99, CarrierChoice::Lan, CarrierChoice::Auto),
            (0x9b, CarrierChoice::Auto, CarrierChoice::Lan),
        ] {
            let rig = Rig::new(seed);
            rig.send("hello").unwrap();
            // Two messages queued behind each other, each by its own send.
            rig.faults.shed_frame_dials.store(1_000, Ordering::SeqCst);
            let one = rig.send_choosing("one", first).unwrap_err();
            assert!(one.starts_with("not delivered yet"), "{one}");
            let one_mid = rig.alice_waiting().remove(0).message_id;
            let two = rig.send_choosing("two", second).unwrap_err();
            assert!(two.starts_with("not delivered yet"), "{two}");
            let waiting: Vec<[u8; 16]> = rig.alice_waiting().iter().map(|r| r.message_id).collect();
            assert_eq!(waiting.len(), 2, "both queued");
            let two_mid = *waiting.iter().find(|m| **m != one_mid).unwrap();
            assert_eq!(alice_record(&rig, &one_mid).unwrap().choice, first);
            assert_eq!(alice_record(&rig, &two_mid).unwrap().choice, second);
            // The next send (the other kind) redials "one" first; the peer
            // refuses it, so that send re-notes it for the outbox and stops.
            rig.faults.shed_frame_dials.store(0, Ordering::SeqCst);
            rig.faults.refuse_messages.store(1, Ordering::SeqCst);
            let err = rig.send_choosing("three", second).unwrap_err();
            assert!(err.starts_with("NOT SENT: an earlier message"), "{err}");
            assert!(err.contains("\"one\""), "{err}");
            assert_eq!(
                alice_record(&rig, &one_mid).unwrap().choice,
                first,
                "{seed:#x}: re-noted by a later send, still its own send's choice"
            );
            assert_eq!(alice_record(&rig, &two_mid).unwrap().choice, second);
        }
    }

    /// A message queued while the peer was down is "unsent" until a carrier
    /// writes it; `raven send` writing it (here refused after reading) clears it.
    #[test]
    fn a_cli_write_of_a_queued_message_clears_unsent() {
        let rig = Rig::new(0x97);
        rig.send("hello").unwrap();
        rig.set_mode(DOWN);
        let _ = rig.send("queued while down").unwrap_err();
        let row = rig.alice_waiting().remove(0);
        assert!(alice_record(&rig, &row.message_id).is_some_and(|r| r.unsent));
        rig.set_mode(UP);
        rig.faults.refuse_messages.store(1, Ordering::SeqCst);
        let _ = rig.send("next").unwrap_err();
        assert!(
            alice_record(&rig, &row.message_id).is_some_and(|r| !r.unsent),
            "the peer read the frames: not unsent any more"
        );
    }

    /// Cutoff pack follow-up (FU-4 re-verify): with raven-node down, `raven
    /// status` reads the store. A message queued while the contact could not
    /// be reached is still "queued" past its deadline (the route evidence
    /// outlives the live record), so it "will not be sent", never "may have
    /// arrived"; once a carrier wrote it, it may have. The long horizon
    /// (on in release builds since 2026-10, when a message waits 7 days
    /// instead) is off on this thread, so the deadline is the envelope's.
    #[test]
    fn a_message_queued_while_unreachable_never_reads_as_sent_past_its_deadline() {
        raven_core::horizon::set_lab_horizon_for_this_thread(Some(false));
        let rig = Rig::new(0x9d);
        rig.send("hello").unwrap();
        rig.set_mode(DOWN);
        let queued = rig.send("queued while down").unwrap_err();
        assert!(queued.starts_with("not delivered yet"), "{queued}");
        let row = rig.alice_waiting().remove(0);
        assert!(alice_record(&rig, &row.message_id).is_some_and(|r| r.unsent));
        let expired = envelope_expiry(&row.immutable_envelope_bytes);
        let line = |now: u64| super::super::ext::waiting_messages_line(rig.a.path(), now);
        assert!(
            line(now_ms()).is_some_and(|l| l.starts_with("Waiting messages: 1 (")),
            "{:?}",
            line(now_ms())
        );
        assert_eq!(
            line(expired).as_deref(),
            Some("Waiting messages: none (1 ran out of time and will not be sent).")
        );

        // A carrier writes it (the contact reads and refuses it): it may have
        // arrived once its time ran out.
        rig.set_mode(UP);
        rig.faults.refuse_messages.store(1, Ordering::SeqCst);
        let _ = rig.send("next").unwrap_err();
        assert!(alice_record(&rig, &row.message_id).is_some_and(|r| !r.unsent));
        assert_eq!(
            line(expired).as_deref(),
            Some("Waiting messages: none (1 was sent but not confirmed in time and may have arrived).")
        );
        raven_core::horizon::set_lab_horizon_for_this_thread(None);
    }

    #[test]
    fn rlb1_probe_retries_only_while_the_peer_sheds_load() {
        let shed = "ipc LAN_DIAL: peer closed the connection during the handshake (3 attempts); \
                    the peer may be at its connection limit";
        // Overflow of a burst: shed twice, then through.
        let mut calls = 0;
        let mut slept = Vec::new();
        let got = retry_while_peer_sheds_load(
            5,
            Duration::from_millis(100),
            |d| slept.push(d),
            || {
                calls += 1;
                if calls < 3 {
                    Err(shed.to_string())
                } else {
                    Ok(calls)
                }
            },
        );
        assert_eq!(got, Ok(3));
        assert_eq!(slept.len(), 2);
        assert!(slept[0] >= Duration::from_millis(100) && slept[0] <= Duration::from_millis(150));
        assert!(slept[1] >= Duration::from_millis(200) && slept[1] <= Duration::from_millis(300));
        // A peer that keeps shedding is given up on after the last attempt, unchanged.
        let mut calls = 0;
        let err = retry_while_peer_sheds_load(
            3,
            Duration::ZERO,
            |_| {},
            || {
                calls += 1;
                Err::<(), _>(shed.to_string())
            },
        )
        .unwrap_err();
        assert_eq!((calls, err.as_str()), (3, shed));
        // Anything else (peer down, bad bundle) is not retried: one attempt.
        for other in [
            "ipc LAN_DIAL: lan connect: cannot connect (Connection refused)",
            "peer did not return an RLB1 bundle",
        ] {
            let mut calls = 0;
            let err = retry_while_peer_sheds_load(
                5,
                Duration::ZERO,
                |_| {},
                || {
                    calls += 1;
                    Err::<(), _>(other.to_string())
                },
            )
            .unwrap_err();
            assert_eq!((calls, err.as_str()), (1, other));
        }
    }

    #[test]
    fn peer_send_lock_is_per_peer_and_times_out_with_a_clear_message() {
        let dir = tempfile::tempdir().unwrap();
        let (p1, p2) = ([1u8; 32], [2u8; 32]);
        let held = acquire_send_lock(dir.path(), &p1).unwrap();
        // Another peer is not held up.
        let other = acquire_send_lock_within(dir.path(), &p2, Duration::from_millis(50));
        assert!(other.is_ok());
        // The same peer waits, then gives up with an actionable message.
        let started = std::time::Instant::now();
        let err = match acquire_send_lock_within(dir.path(), &p1, Duration::from_millis(80)) {
            Ok(_) => panic!("lock must be held"),
            Err(e) => e,
        };
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(err.starts_with("NOT SENT, nothing queued"), "{err}");
        assert!(err.contains("another `ash send` to this peer"), "{err}");
        assert!(err.contains("raven-node's outbox"), "{err}");
        drop(held);
        // raven-node's outbox takes the very same lock (shared core type).
        let worker = PeerSendLock::acquire_within(dir.path(), &p1, Duration::ZERO).unwrap();
        assert!(acquire_send_lock_within(dir.path(), &p1, Duration::from_millis(80)).is_err());
        drop(worker);
        assert!(acquire_send_lock_within(dir.path(), &p1, Duration::from_millis(80)).is_ok());
        // The lock file is the inert `*.lock.sqlite` shape (first-install safe).
        let names: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert!(
            names
                .iter()
                .all(|n| n.starts_with(".send_") && n.contains(".lock.sqlite")),
            "{names:?}"
        );
    }

    /// K: a send that finds the per-peer lock taken (raven-node's outbox doing
    /// its store work, or another terminal) says so in one line and waits a
    /// bounded time; a free lock prints nothing.
    #[test]
    fn a_send_behind_a_held_lock_says_it_is_waiting_and_stays_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let peer = [7u8; 32];
        let mut lines = Vec::new();
        let free = acquire_send_lock_noting_within(
            dir.path(),
            &peer,
            "Bob",
            Duration::from_secs(1),
            &mut |l| lines.push(l.to_string()),
        );
        assert!(free.is_ok() && lines.is_empty(), "{lines:?}");
        drop(free);

        // Held briefly (the worker's store-only section): wait, then go on.
        let held = PeerSendLock::acquire_within(dir.path(), &peer, Duration::ZERO).unwrap();
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            drop(held);
        });
        let got = acquire_send_lock_noting_within(
            dir.path(),
            &peer,
            "Bob",
            Duration::from_secs(5),
            &mut |l| lines.push(l.to_string()),
        );
        releaser.join().unwrap();
        assert!(got.is_ok());
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].starts_with("waiting: another send to Bob"),
            "{}",
            lines[0]
        );
        assert!(lines[0].contains("raven-node"), "{}", lines[0]);
        assert!(lines[0].contains("at most 5s"), "{}", lines[0]);
        drop(got);

        // Held throughout: the wait ends at its bound with the refusal.
        let _held = PeerSendLock::acquire_within(dir.path(), &peer, Duration::ZERO).unwrap();
        lines.clear();
        let started = std::time::Instant::now();
        let err = match acquire_send_lock_noting_within(
            dir.path(),
            &peer,
            "Bob",
            Duration::from_millis(150),
            &mut |l| lines.push(l.to_string()),
        ) {
            Ok(_) => panic!("lock must be held"),
            Err(e) => e,
        };
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(lines.len(), 1);
        assert!(err.starts_with("NOT SENT, nothing queued"), "{err}");
        // The production bound is stated in the line and is finite.
        assert!(send_lock_waiting_text("Bob", PEER_SEND_LOCK_WAIT).contains("at most 120s"));
    }

    #[test]
    fn send_failure_line_distinguishes_queued_unconfirmed_and_refused() {
        let ctx = SendCtx {
            name: "Bob".into(),
            ..SendCtx::default()
        };
        let day = RetryNote {
            expires_at_ms: now_ms() + raven_core::ENVELOPE_VALIDITY_MS,
            copy_expires_at_ms: 0,
            background: false,
            custodians: Vec::new(),
            carry_first: None,
        };
        let queued = queued_text(&ctx, "ipc: timed out; mid=07070707…", "", &day);
        assert_eq!(
            send_failure_line(&queued),
            queued,
            "queued is not a refusal"
        );
        let unconfirmed = unconfirmed_text(
            &ctx,
            "WAITING_FOR_ENDPOINT_ACK: no sealed ACK came back; mid=07070707…",
            "",
            &day,
        );
        assert_eq!(send_failure_line(&unconfirmed), unconfirmed);
        assert!(!unconfirmed.contains("send refused"), "{unconfirmed}");
        // An *earlier* message awaiting its ACK means this one was not queued.
        let earlier = earlier_unconfirmed_text(&ctx, "\"see you\"");
        assert!(earlier.starts_with("NOT SENT"), "{earlier}");
        assert!(earlier.contains("this message was not queued"), "{earlier}");
        assert_eq!(send_failure_line(&earlier), earlier);
        // Text no sentence covers keeps the old refusal form, untouched inside...
        assert_eq!(
            send_failure_line("ATSAM_SESSION_REQUIRED: not the one bound"),
            "send refused: ATSAM_SESSION_REQUIRED: not the one bound"
        );
        // ...a raw daemon error becomes a NOT SENT sentence.
        let raw = send_failure_line(
            "ipc LAN_DIAL: lan connect: cannot connect to 127.0.0.1:9 (127.0.0.1:9: Connection \
             refused (os error 61))",
        );
        assert!(raw.starts_with("NOT SENT: "), "{raw}");
        assert!(raw.contains("Connection refused"), "{raw}");
        assert_eq!(
            not_sent_nothing_queued(&ctx, "NOT SENT: earlier message"),
            "NOT SENT: earlier message"
        );
        let plain = not_sent_nothing_queued(&ctx, "bad payload");
        assert!(plain.starts_with("NOT SENT: "), "{plain}");
        assert!(plain.contains("(technical: bad payload)"), "{plain}");
    }

    // ── The long message horizon (Phase 5a, P5.8) ──────────────────────────

    /// This thread's horizon lab switch, set back when the test ends.
    struct HorizonOn;

    impl HorizonOn {
        fn set(on: bool) -> Self {
            raven_core::horizon::set_lab_horizon_for_this_thread(Some(on));
            Self
        }
    }

    impl Drop for HorizonOn {
        fn drop(&mut self) {
            raven_core::horizon::set_lab_horizon_for_this_thread(None);
        }
    }

    impl Rig {
        fn alice_parked(&self) -> Vec<raven_core::indexed_session_store::ParkedOutbound> {
            IndexedSessionStore::open(self.a.path())
                .unwrap()
                .parked_for_recipient(&self.bob.public_key_bytes())
                .unwrap()
        }

        /// Bob's inbox in the order the messages arrived.
        fn bob_inbox_in_order(&self) -> Vec<String> {
            let mut store = IndexedSessionStore::open(self.b.path()).unwrap();
            let mut rows = store.list_endpoint_inbox().unwrap();
            rows.sort_by_key(|row| row.received_at_ms);
            rows.into_iter()
                .map(|row| String::from_utf8_lossy(&row.plaintext).into_owned())
                .collect()
        }

        /// A message to Bob parked as a send without a session parks it
        /// (staged with the sentinel binding, no sealed copy).
        fn park_directly(&self, text: &str) -> [u8; 16] {
            use rand::RngCore;
            let bob = self.bob.public_key_bytes();
            let mut mid = [0u8; 16];
            rand::rngs::OsRng.fill_bytes(&mut mid);
            let now = now_ms();
            let zero = raven_core::horizon::SENTINEL_BINDING;
            raven_core::ensure_outbound_queued_history(
                self.a.path(),
                &bob,
                &zero,
                &zero,
                &mid,
                now,
                Some(text),
            )
            .unwrap();
            let deadline = raven_core::horizon::message_deadline(now);
            assert!(IndexedSessionStore::open(self.a.path())
                .unwrap()
                .park_outbound(&bob, &mid, None, now, deadline, now)
                .unwrap());
            mid
        }
    }

    /// With the horizon on, a send to a contact that is unreachable and has
    /// no session is parked until its deadline instead of NOT SENT: the
    /// body staged with the zero sentinel binding, history `queued`, a route
    /// record that says it never left this computer, and the queued line in
    /// the parked words. When the contact is back, the next send sets up a
    /// session and delivers it first, then its own message.
    #[test]
    fn send_to_offline_contact_without_session_parks_when_gate_on() {
        let _horizon = HorizonOn::set(true);
        let rig = Rig::new(0xC1);
        rig.set_mode(DOWN);
        let before = now_ms();
        let err = rig.send("while you were away").unwrap_err();
        assert!(err.starts_with(super::super::ext::QUEUED_PREFIX), "{err}");
        assert!(
            err.contains(
                "is queued: Peer isn't reachable now. When you are both on the same network, \
                 RAVEN first sets up a new secure connection, then sends it. It can wait until"
            ),
            "{err}"
        );
        assert!(err.contains("\"while you were away\""), "{err}");
        assert!(err.contains("HORIZON_PARKED"), "{err}");
        assert!(!err.contains("NOT SENT"), "{err}");
        // Not "it is gone" in the chat either.
        assert_eq!(send_failure_line(&err), err);
        assert_eq!(rig.alice_sessions(), 0, "nothing was paired");
        let parked = rig.alice_parked();
        assert_eq!(parked.len(), 1);
        let row = &parked[0];
        assert_eq!(row.from_session, None);
        assert!(row.created_at_ms >= before);
        assert_eq!(
            row.deadline_ms,
            raven_core::horizon::message_deadline(row.created_at_ms)
        );
        let staged = raven_core::load_staged_outbound_body(rig.a.path(), &row.message_id)
            .unwrap()
            .expect("the body is staged");
        assert!(raven_core::horizon::is_sentinel_stage(&staged));
        assert_eq!(staged.body, "while you were away");
        assert_eq!(
            rig.alice_history(),
            vec![("while you were away".to_string(), "queued".to_string())]
        );
        let record = alice_record(&rig, &row.message_id).expect("route record");
        assert!(record.unsent, "it never left this computer");
        // The crash repair of the stage keeps it waiting.
        raven_core::reconcile_outbound_stage_history(rig.a.path()).unwrap();
        assert_eq!(rig.alice_history()[0].1, "queued");

        rig.set_mode(UP);
        rig.send("back again").unwrap();
        assert!(rig.alice_parked().is_empty());
        assert_eq!(
            rig.bob_inbox_in_order(),
            vec!["while you were away", "back again"]
        );
        assert!(
            rig.alice_history().iter().all(|(_, d)| d == "delivered"),
            "{:?}",
            rig.alice_history()
        );
        assert!(
            raven_core::load_staged_outbound_body(rig.a.path(), &row.message_id)
                .unwrap()
                .is_none()
        );
    }

    /// The gate off: the same send says NOT SENT as before and parks nothing.
    #[test]
    fn send_to_offline_contact_without_session_is_not_sent_when_gate_off() {
        let _horizon = HorizonOn::set(false);
        let rig = Rig::new(0xC3);
        rig.set_mode(DOWN);
        let err = rig.send("anyone").unwrap_err();
        assert!(err.starts_with("NOT SENT: "), "{err}");
        assert!(err.contains("It was not kept: a first message"), "{err}");
        assert!(rig.alice_parked().is_empty());
        assert!(rig.alice_history().is_empty());
        assert!(raven_core::list_staged_outbound_bodies(rig.a.path())
            .unwrap()
            .is_empty());
    }

    /// Parked messages count toward MAX_QUEUED_PER_PEER, on the parking
    /// path (no session) and on the queueing one (a session).
    #[test]
    fn parked_rows_count_toward_max_queued_per_peer() {
        let _horizon = HorizonOn::set(true);
        let rig = Rig::new(0xC5);
        rig.set_mode(DOWN);
        for i in 0..MAX_QUEUED_PER_PEER {
            rig.park_directly(&format!("parked {i}"));
        }
        let err = rig.send("one too many").unwrap_err();
        assert!(
            err.starts_with("NOT SENT: 32 earlier messages to Peer are already waiting"),
            "{err}"
        );
        assert_eq!(rig.alice_parked().len(), MAX_QUEUED_PER_PEER);
        assert!(rig
            .alice_history()
            .iter()
            .all(|(body, _)| body != "one too many"));
        let store = IndexedSessionStore::open(rig.a.path()).unwrap();
        assert_eq!(
            waiting_for_peer(rig.a.path(), &store, &rig.bob.public_key_bytes()).unwrap(),
            MAX_QUEUED_PER_PEER
        );
    }

    /// Before a new message is sealed into a session, the contact's parked
    /// messages are sealed into it first, under the same send lock: offline,
    /// they queue ahead of it (lower ratchet indices); back online, all are
    /// delivered in send order.
    #[test]
    fn parked_rows_resealed_before_new_message_in_same_send() {
        let _horizon = HorizonOn::set(true);
        let rig = Rig::new(0xC7);
        rig.send("hello").unwrap();
        let first = rig.park_directly("parked first");
        let second = rig.park_directly("parked second");
        rig.set_mode(DOWN);
        let err = rig.send("new one").unwrap_err();
        assert!(err.starts_with(super::super::ext::QUEUED_PREFIX), "{err}");
        assert!(rig.alice_parked().is_empty(), "sealed again");
        let mut waiting = rig.alice_waiting();
        waiting.sort_by_key(|row| row.ratchet_index);
        let order: Vec<[u8; 16]> = waiting.iter().map(|row| row.message_id).collect();
        assert_eq!(order.len(), 3);
        assert_eq!(&order[..2], &[first, second], "parked ones first");
        // Their stages follow the new copies.
        for row in &waiting[..2] {
            let staged = raven_core::load_staged_outbound_body(rig.a.path(), &row.message_id)
                .unwrap()
                .unwrap();
            assert!(!raven_core::horizon::is_sentinel_stage(&staged));
            assert_eq!(staged.session_id_hex, hex::encode(row.session_id));
        }
        rig.set_mode(UP);
        rig.send("and now").unwrap();
        assert_eq!(
            rig.bob_inbox_in_order(),
            vec![
                "hello",
                "parked first",
                "parked second",
                "new one",
                "and now"
            ]
        );
    }

    /// Review 5a-1: `raven outbox cancel` of a message parked before any
    /// session existed. It was listed as waiting, yet the cancel said it was
    /// not waiting, and it was delivered once Bob was back. Now it is given
    /// up (history `cancelled`, its stage and route record gone), a second
    /// cancel says it is not waiting, and nothing of it reaches Bob.
    #[test]
    fn cancel_stops_a_message_parked_without_a_session() {
        let _horizon = HorizonOn::set(true);
        let rig = Rig::new(0xCB);
        rig.set_mode(DOWN);
        let err = rig.send("never mind").unwrap_err();
        assert!(err.contains("HORIZON_PARKED"), "{err}");
        let mid = rig.alice_parked()[0].message_id;
        assert!(alice_record(&rig, &mid).is_some());
        super::super::ext::cancel_outbound(rig.a.path(), &mid, true).unwrap();
        assert!(rig.alice_parked().is_empty());
        assert!(raven_core::load_staged_outbound_body(rig.a.path(), &mid)
            .unwrap()
            .is_none());
        assert!(alice_record(&rig, &mid).is_none());
        assert_eq!(
            rig.alice_history(),
            vec![("never mind".to_string(), "cancelled".to_string())]
        );
        let again = super::super::ext::cancel_outbound(rig.a.path(), &mid, true).unwrap_err();
        assert!(again.contains("is not waiting to be delivered"), "{again}");
        rig.set_mode(UP);
        rig.send("hello again").unwrap();
        assert_eq!(rig.bob_inbox_in_order(), vec!["hello again"]);
        assert!(rig
            .alice_history()
            .contains(&("never mind".to_string(), "cancelled".to_string())));
    }

    /// Review 5a-1: the same for a message parked from its session (its
    /// envelope ran out while Bob was away): it has no outbox row any more,
    /// and is cancelled all the same.
    #[test]
    fn cancel_stops_a_message_parked_from_its_session() {
        let _horizon = HorizonOn::set(true);
        let rig = Rig::new(0xCD);
        rig.send("hello").unwrap();
        rig.set_mode(DOWN);
        rig.send("parked from the session").unwrap_err();
        let row = rig.alice_waiting().remove(0);
        let bob = rig.bob.public_key_bytes();
        let mut store = IndexedSessionStore::open(rig.a.path()).unwrap();
        let key = store
            .record_key_for_session_id(&row.session_id)
            .unwrap()
            .unwrap();
        let parked = raven_core::outbox::park_or_give_up_expired(
            rig.a.path(),
            &mut store,
            &key,
            &bob,
            &row.session_id,
            &row.object_digest,
            &row.message_id,
            false,
            now_ms(),
        )
        .unwrap();
        assert!(
            matches!(parked, raven_core::outbox::ExpiredMessage::Parked { .. }),
            "{parked:?}"
        );
        drop(store);
        assert!(rig.alice_waiting().is_empty());
        assert_eq!(rig.alice_parked()[0].from_session, Some(row.session_id));
        super::super::ext::cancel_outbound(rig.a.path(), &row.message_id, true).unwrap();
        assert!(rig.alice_parked().is_empty());
        assert!(
            raven_core::load_staged_outbound_body(rig.a.path(), &row.message_id)
                .unwrap()
                .is_none()
        );
        assert!(rig.alice_history().contains(&(
            "parked from the session".to_string(),
            "cancelled".to_string()
        )));
        rig.set_mode(UP);
        rig.send("after").unwrap();
        assert_eq!(rig.bob_inbox_in_order(), vec!["hello", "after"]);
    }

    /// The letter gate open for this thread (Phase 5b): the custody gate,
    /// the horizon and the letters.
    struct LettersOn;

    impl LettersOn {
        fn set() -> Self {
            use raven_core::custody_gate::{set_custody_gates_for_this_thread, CustodyGates};
            set_custody_gates_for_this_thread(Some(CustodyGates {
                live: true,
                wan: false,
            }));
            raven_core::horizon::set_lab_horizon_for_this_thread(Some(true));
            raven_core::horizon::set_lab_letter_for_this_thread(Some(true));
            Self
        }
    }

    impl Drop for LettersOn {
        fn drop(&mut self) {
            raven_core::horizon::set_lab_letter_for_this_thread(None);
            raven_core::horizon::set_lab_horizon_for_this_thread(None);
            raven_core::custody_gate::set_custody_gates_for_this_thread(None);
        }
    }

    /// Re-verify of review 5a-1/cross-4: `raven outbox cancel` of a message
    /// the worker had already moved into a sealed letter together with
    /// another one. Only its outbox copy was given up: the letter book kept
    /// the letter as it was, the worker still offered it to friends, and Bob
    /// could collect the cancelled message from it. Now that letter is
    /// marked to be withdrawn (never offered again), and the worker's
    /// re-letter seals what else it carried into a new letter without the
    /// cancelled message.
    #[test]
    fn cancel_takes_the_message_out_of_its_letter() {
        use raven_core::horizon::letters::{build_letters, has_unlettered, reletter, DirectCopy};
        use raven_core::letter_deposits;
        let _letters = LettersOn::set();
        let rig = Rig::new(0xCF);
        rig.send("hello").unwrap();
        rig.set_mode(DOWN);
        rig.send("keep me").unwrap_err();
        rig.send("cancel me").unwrap_err();
        let mut waiting = rig.alice_waiting();
        waiting.sort_by_key(|row| row.ratchet_index);
        assert_eq!(waiting.len(), 2);
        let (keep, cancel) = (waiting[0].message_id, waiting[1].message_id);
        let direct: Vec<DirectCopy> = waiting
            .iter()
            .map(|row| DirectCopy {
                message_id: row.message_id,
                session_id: row.session_id,
            })
            .collect();
        let a = rig.a.path();
        let bob = rig.bob.public_key_bytes();
        let mut store = IndexedSessionStore::open(a).unwrap();
        let build = build_letters(a, &rig.alice, &mut store, &bob, &direct, now_ms()).unwrap();
        assert_eq!(build.held, None);
        assert_eq!(build.letters.len(), 1);
        assert_eq!(build.letters[0].message_ids, vec![keep, cancel]);
        drop(store);
        super::super::ext::cancel_outbound(a, &cancel, true).unwrap();
        assert!(rig
            .alice_history()
            .contains(&("cancel me".to_string(), "cancelled".to_string())));
        let book = letter_deposits::load(a, now_ms()).unwrap();
        assert!(
            book.carrying(&bob, &cancel).is_empty(),
            "no letter that may still be offered carries the cancelled message"
        );
        assert!(book
            .letters
            .iter()
            .all(|row| row.withdraw || !row.message_ids.contains(&cancel)));
        // The worker's letter step letters what the withdrawn letter carried
        // besides (review letters-3's re-letter): `keep` only.
        let mut store = IndexedSessionStore::open(a).unwrap();
        assert!(has_unlettered(a, &mut store, &bob, now_ms()));
        let rows = reletter(a, &rig.alice, &mut store, &bob, now_ms()).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].message_ids, vec![keep]);
        let book = letter_deposits::load(a, now_ms()).unwrap();
        assert_eq!(book.carrying(&bob, &keep).len(), 1);
        assert!(book.carrying(&bob, &cancel).is_empty());
    }

    /// The cancel answer says when Bob may have the message anyway: a
    /// letter already with a friend (it may be collected before its
    /// withdraw arrives), a book that could not be read, or a copy a carrier
    /// already wrote. The TUI reads `may have it anyway`.
    #[test]
    fn the_cancel_answer_names_a_letter_already_with_a_friend() {
        use raven_core::letter_deposits::CancelledLetters;
        let note = super::super::ext::cancelled_note;
        let held = Ok(CancelledLetters {
            withdrawn: 1,
            with_friend: true,
        });
        let line = note("Bob", false, &held);
        assert!(line.contains("already with a friend"), "{line}");
        assert!(line.contains("may have it anyway"), "{line}");
        let unreadable = note("Bob", false, &Err("letter_deposits.json: locked".into()));
        assert!(unreadable.contains("may have it anyway"));
        let placed_nowhere = Ok(CancelledLetters {
            withdrawn: 1,
            with_friend: false,
        });
        assert_eq!(note("Bob", false, &placed_nowhere), "");
        assert!(note("Bob", true, &placed_nowhere).contains("already sent once"));
    }

    /// RetryNote shows the message's deadline (written + 7 d) while the
    /// horizon is on; the envelope's expiry while it is off.
    #[test]
    fn retry_note_shows_the_deadline() {
        let rig = Rig::new(0xC9);
        rig.send("hello").unwrap();
        rig.set_mode(DOWN);
        let _horizon = HorizonOn::set(false);
        rig.send("queued").unwrap_err();
        let row = rig.alice_waiting().remove(0);
        let expiry = envelope_expiry(&row.immutable_envelope_bytes);
        let staged = raven_core::load_staged_outbound_body(rig.a.path(), &row.message_id)
            .unwrap()
            .unwrap();
        let routes = [DialRoute {
            carrier: DialCarrier::Lan,
            dial: "127.0.0.1:9".into(),
        }];
        let handoff = OutboxHandoff::new(rig.a.path(), &routes, rig.bob.public_key_bytes(), None);
        assert_eq!(handoff.note(&row.message_id, expiry).expires_at_ms, expiry);
        let _horizon = HorizonOn::set(true);
        let deadline = raven_core::horizon::message_deadline(staged.created_at_ms);
        assert!(deadline > expiry);
        assert_eq!(
            handoff.note(&row.message_id, expiry).expires_at_ms,
            deadline
        );
        assert_eq!(
            handoff.note_own(&row.message_id, expiry).expires_at_ms,
            deadline
        );
        // No staged body: the envelope's expiry.
        assert_eq!(handoff.note(&[0x77; 16], expiry).expires_at_ms, expiry);
        // The queued line names it: "(in 6 days)" or "(in 7 days)", never 24 h.
        let err = rig.send("queued too").unwrap_err();
        assert!(err.starts_with(super::super::ext::QUEUED_PREFIX), "{err}");
        assert!(!err.contains("(in about 24 h)"), "{err}");
    }
}
