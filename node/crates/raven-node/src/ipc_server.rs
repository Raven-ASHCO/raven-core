//! Local IPC server — UDS on Unix, named pipe on Windows.
//!
//! Shared request handling and length-prefixed JSON framing live here
//! (`raven_core::ipc`, IPC_VERSION=1). Transport bind/accept is cfg-gated:
//! Unix uses a `0600` socket (bound atomically, single-instance lock, owned
//! data dir) plus peer-cred UID check; Windows binds the per-user pipe
//! `{WINDOWS_NAMED_PIPE}-{SID}` with a current-user DACL (fail-closed).
//! Requests still refuse secret field names (`raven_core::ipc`).
//! `SealUnderSession` is served only after the same peer-cred / pipe-ACL gate.
//! Blocking work (SQLite, identity/secret store, seal) runs on the blocking
//! pool; `Ping` is answered inline so a busy daemon never looks dead.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use raven_core::bridge::authenticated_object_digest;
use raven_core::envelope::Envelope;
use raven_core::forward_queue::{ForwardItem, ForwardQueue, ForwardState};
#[cfg(unix)]
use raven_core::ipc::default_socket_path;
use raven_core::ipc::{
    decode_request_checked, encode_response, IpcRequest, IpcResponse, IPC_VERSION, MAX_IPC_FRAME,
};
use raven_core::load_identity_required;
use raven_core::{seal_app_payload_under_session, ATSAM_LINEAGE_REVOKED, ATSAM_SESSION_REQUIRED};
use tokio::time::Duration;

use crate::internet_direct;
use crate::lan_direct;

const IPC_IO_TIMEOUT: Duration = Duration::from_secs(10);
/// Concurrent IPC connections. Accept waits for a slot (kernel backlog holds
/// the rest), so a flood of local clients cannot exhaust the daemon's fds.
pub(crate) const MAX_IPC_CONNECTIONS: usize = 64;
/// How often the UDS server checks that its socket path still points at it.
#[cfg(unix)]
const SOCKET_WATCH_INTERVAL: Duration = Duration::from_secs(1);
const LAN_DIAL_TIMEOUT: Duration = Duration::from_secs(45);
/// The refusal of a LAN dial while `raven lan off` is in effect
/// (protocol/RAVEN_ERROR_CODES_V1.md).
const LAN_OFF: &str = "LAN_OFF";
const INTERNET_DIAL_TIMEOUT: Duration = Duration::from_secs(45);
use raven_core::node_policy::{load_policy, update_settings};
use raven_core::queue::{DeliveryState, OutgoingQueue, QueueItem};
use raven_core::transport::TransportKind;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
#[cfg(unix)]
use tokio::sync::Semaphore;

#[cfg(windows)]
#[path = "ipc_server_windows.rs"]
mod windows;

#[cfg(unix)]
pub fn socket_path(data_dir: &Path) -> PathBuf {
    default_socket_path(data_dir)
}

/// Return true iff the connected peer's effective UID matches ours.
/// Denies cross-user local clients even if they somehow open the socket.
#[cfg(unix)]
fn peer_uid_matches_self(stream: &UnixStream) -> bool {
    use std::os::fd::AsRawFd;
    let fd = stream.as_raw_fd();
    let self_uid = unsafe { libc::geteuid() };

    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    {
        let mut euid: libc::uid_t = 0;
        let mut egid: libc::gid_t = 0;
        let rc = unsafe { libc::getpeereid(fd, &mut euid, &mut egid) };
        if rc != 0 {
            return false;
        }
        euid == self_uid
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if rc != 0 {
            return false;
        }
        cred.uid == self_uid
    }

    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    )))]
    {
        let _ = (fd, self_uid);
        // Unknown Unix: no peer-cred API wired up. Fail closed rather than
        // trusting socket mode 0600 alone.
        false
    }
}

async fn read_frame<S>(stream: &mut S) -> Result<Vec<u8>, String>
where
    S: AsyncRead + Unpin,
{
    let read = async {
        let mut len_buf = [0u8; 4];
        stream
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| e.to_string())?;
        let n = u32::from_be_bytes(len_buf) as usize;
        if n == 0 || n > raven_core::MAX_IPC_FRAME {
            return Err("IPC_FRAME".into());
        }
        let mut buf = vec![0u8; 4 + n];
        buf[0..4].copy_from_slice(&len_buf);
        stream
            .read_exact(&mut buf[4..])
            .await
            .map_err(|e| e.to_string())?;
        Ok(buf)
    };
    tokio::time::timeout(IPC_IO_TIMEOUT, read)
        .await
        .map_err(|_| "ipc read timeout".to_string())?
}

/// Serializes policy read-modify-write (`SetPolicy`) against policy reads
/// (`Status`) in this process. IPC ops run concurrently on the blocking pool,
/// so without this two `SetPolicy` calls could lose an update.
static POLICY_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn policy_guard() -> std::sync::MutexGuard<'static, ()> {
    POLICY_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// `Status` capabilities from the p2p status: `p2p` while the host is up,
/// `p2p_relay` while it also relays under this node's own PeerId (debug
/// lab only), and `p2p_friend_relay` while the friend relay is up (its own
/// task: with or without the host).
fn p2p_capabilities(info: Option<&raven_core::ipc::P2pStatusInfo>) -> Vec<&'static str> {
    let mut caps = Vec::new();
    if let Some(info) = info.filter(|i| i.up) {
        caps.push("p2p");
        if info.relay.is_some() {
            caps.push("p2p_relay");
        }
    }
    if info
        .and_then(|i| i.friend_relay.as_ref())
        .is_some_and(|f| f.state == "up")
    {
        caps.push("p2p_friend_relay");
    }
    caps
}

fn handle_req(req: IpcRequest, data_dir: &Path, forward: &Option<ForwardQueue>) -> IpcResponse {
    match req {
        IpcRequest::Ping { v } => IpcResponse::Pong { v },
        IpcRequest::Status { v, retry_key } => {
            let policy = {
                let _policy = policy_guard();
                load_policy(data_dir)
            };
            // Transport capabilities do not depend on the forward queue: the
            // listeners are up or not on their own. Bridge / store / relay do
            // (they run on it), and only while the bridge is actually running.
            let mut caps: Vec<String> = vec!["ipc".into()];
            if crate::lan_direct::listener_is_up() {
                caps.push("lan_direct".into());
            }
            if crate::internet_direct::listener_is_up() {
                caps.push("internet_direct".into());
            }
            // The app channel (RDAP over Raven) needs the gate and a worker.
            if raven_core::app_channel::app_channel_live_enabled() && crate::outbox::is_running() {
                caps.push("app_channel".into());
            }
            // Session renewal (Phase 3) needs the gate and a running renewer.
            if raven_core::session_renewal::session_renewal_live_enabled()
                && crate::renewal::is_running()
            {
                caps.push("session_renewal".into());
            }
            let p2p = crate::p2p::status_snapshot();
            caps.extend(p2p_capabilities(p2p.as_ref()).into_iter().map(String::from));
            let pending = match forward {
                Some(q) => {
                    if !crate::bridge_degraded() {
                        if policy.bridge {
                            caps.push("bridge".into());
                        }
                        if policy.store {
                            caps.push("store".into());
                        }
                        if policy.relay {
                            caps.push("relay".into());
                        }
                    }
                    q.count_pending().unwrap_or_else(|e| {
                        eprintln!("raven-node ipc: forward queue count failed: {e}");
                        0
                    }) as u64
                }
                None => 0u64,
            };
            // Why the LAN listener is down, while its bind fails (a token:
            // never the OS's text).
            let (lan_listen_wanted, lan_bind_error) = crate::lan_direct::bind_error();
            IpcResponse::Status {
                v,
                bridge: policy.bridge,
                store: policy.store,
                relay: policy.relay,
                forward_pending: pending,
                capabilities: caps,
                p2p: p2p.map(Box::new),
                pid: Some(std::process::id()),
                lan_listen: crate::lan_direct::listener_addr().map(|a| a.to_string()),
                last_paths: crate::delivery_paths::snapshot(),
                route_hints: crate::hints::status(data_dir),
                unreachable: crate::delivery_paths::unreachable_snapshot(),
                egress: crate::netwatch::last_egress(),
                lan_listen_wanted,
                lan_bind_error: lan_bind_error.map(str::to_owned),
                clock_skew: crate::clock_notes::snapshot(),
                unanswered: crate::clock_notes::unanswered_snapshot(),
                at_rest: Some(crate::at_rest_boot::status(data_dir, retry_key)),
                // With the LAN listener's row, the LAN beacon's counts
                // (`held` while its gate is closed).
                // P3.C6: how many contacts were seen on this network in
                // the last ten minutes, and whose address answered with
                // another key.
                lan: crate::lan_direct::lan_status().map(|mut lan| {
                    lan.beacon = Some(Box::new(crate::lan_beacon::counts()));
                    lan.friends_here_10m = Some(crate::lan_beacon::friends_here_10m());
                    lan.pin_blocked = crate::delivery_paths::pin_blocked_snapshot();
                    lan
                }),
                // Phase 6b: memory-only counts; absent while the security
                // events gate is shut (a release build's Status is what it
                // was).
                security: crate::security::status().map(Box::new),
                // Counts and states only; absent while the nearby gate is
                // closed (a release build's Status is what it was).
                nearby: crate::nearby::status(data_dir).map(Box::new),
                // The Tor onion carrier (lab): its status line; absent while
                // its gate is closed.
                tor: crate::onion::status_text(),
                // Learning connectivity (Phase 6a): absent while its gate is
                // shut; state, counts and this network's rows otherwise.
                learning: crate::learning::status(data_dir).map(Box::new),
                // Lock v2 (P6.40): `false` here (a locked node answers
                // `locked_status`); absent while its gate is shut.
                locked: crate::lock::status(),
                // RUP1 (P6.49): counts only; absent while the exchange is
                // not active (a release build's Status is what it was).
                updates: crate::update_exchange::status(data_dir),
            }
        }
        // `raven update download` approved a download (Phase 6b P6.49):
        // fetch it now. Nothing is read or written here.
        IpcRequest::UpdateKick { v } => {
            if crate::update_exchange::active() {
                crate::update_exchange::kick();
                IpcResponse::Accepted { v }
            } else {
                IpcResponse::Error {
                    v,
                    code: raven_core::ipc::UPDATE_EXCHANGE_OFF.into(),
                    message: "this raven-node passes no updates between friends".into(),
                }
            }
        }
        // Answered by `dispatch` before any pool thread (Lock v2).
        IpcRequest::Lock { v } | IpcRequest::Unlock { v, .. } => IpcResponse::Error {
            v,
            code: "INTERNAL".into(),
            message: "lock requests are answered by the dispatcher".into(),
        },
        // `raven lan on|off` (Phase 3): applied at once. ash has written
        // node_policy.json (and the meeting time of `raven lan on --for`,
        // P3.C2); nothing is read or written here.
        IpcRequest::SetLan { v, on, until_ms } => {
            crate::lan_meeting::apply(on, until_ms);
            IpcResponse::LanSet {
                v,
                on,
                applied: true,
                until_ms: until_ms.filter(|_| on),
            }
        }
        IpcRequest::SetPolicy {
            v,
            bridge,
            store,
            relay,
        } => {
            let _policy = policy_guard();
            // node_policy.json alone (privacy pack PP.6): the relay addresses
            // a sealed profile keeps in its sidecar are never read or written
            // here, so this works while the at-rest key is not loaded yet.
            let changed = update_settings(data_dir, |p| {
                if let Some(b) = bridge {
                    p.bridge = b;
                    p.auto_policy = false;
                }
                if let Some(s) = store {
                    p.store = s;
                    p.auto_policy = false;
                }
                if let Some(r) = relay {
                    p.relay = r;
                    p.auto_policy = false;
                }
            });
            match changed {
                Ok(()) => IpcResponse::Accepted { v },
                Err(e) => IpcResponse::Error {
                    v,
                    code: "INTERNAL".into(),
                    message: e.to_string(),
                },
            }
        }
        IpcRequest::EnqueueSealed {
            v,
            envelope_b64,
            peer_hint,
        } => {
            // The request frame (MAX_IPC_FRAME) already bounds envelope_b64, so
            // IPC can carry envelopes up to ~190 KiB; MAX_ENVELOPE_BYTES below
            // is the queue's own limit.
            let packed = match base64_decode(&envelope_b64) {
                Ok(b) => b,
                Err(e) => {
                    return IpcResponse::Error {
                        v,
                        code: "IPC_BAD_B64".into(),
                        message: e,
                    };
                }
            };
            if packed.len() > raven_core::forward_queue::MAX_ENVELOPE_BYTES {
                return IpcResponse::Error {
                    v,
                    code: "IPC_FRAME".into(),
                    message: "envelope too large".into(),
                };
            }
            let Some(env) = Envelope::unpack(&packed) else {
                return IpcResponse::Error {
                    v,
                    code: "IPC_BAD_ENVELOPE".into(),
                    message: "not a RavenEnvelopeV1".into(),
                };
            };
            let now = raven_core::clock::now_ms();
            // Custody allow-list (F3): both queues below hand these bytes to a
            // relay or store, so only a sealed indexed-session message or ACK
            // is accepted, never PairInit / PairResponse, demo or plaintext.
            if let Err(refusal) = raven_core::carrier_admission::admit_relayable(&packed, now) {
                return IpcResponse::Error {
                    v,
                    code: "IPC_NOT_RELAYABLE".into(),
                    message: format!(
                        "not a sealed indexed-session message or ACK; refused before custody \
                         ({refusal:?})"
                    ),
                };
            }
            let peer = peer_hint.unwrap_or_else(|| "ipc".into());
            // Prefer forward queue when available (always-on bridge); also mirror outbox.
            if let Some(q) = forward {
                let item = ForwardItem {
                    object_digest: authenticated_object_digest(&env),
                    message_id: env.message_id,
                    packed_envelope: packed.clone(),
                    ingress: TransportKind::Internet,
                    egress: TransportKind::Internet,
                    state: ForwardState::Queued,
                    created_at_ms: now,
                    expires_at_ms: env.expires_at.max(now.saturating_add(60_000)),
                    previous_hop: peer.clone(),
                };
                if let Err(e) = q.enqueue(&item) {
                    return IpcResponse::Error {
                        v,
                        code: forward_queue_error_code(&e).into(),
                        message: e.to_string(),
                    };
                }
            }
            let outbox_path = data_dir.join("queue.sqlite");
            match OutgoingQueue::open(&outbox_path) {
                Ok(oq) => {
                    let item = QueueItem {
                        message_id: env.message_id,
                        packed_envelope: packed,
                        peer_addr: peer,
                        state: DeliveryState::Queued,
                        created_at_ms: now,
                    };
                    if let Err(e) = oq.enqueue(&item) {
                        return IpcResponse::Error {
                            v,
                            code: "OUTBOX".into(),
                            message: outbox_failed_message(forward.is_some(), &e.to_string()),
                        };
                    }
                }
                Err(e) => {
                    return IpcResponse::Error {
                        v,
                        code: "OUTBOX".into(),
                        message: outbox_failed_message(forward.is_some(), &e.to_string()),
                    };
                }
            }
            IpcResponse::Accepted { v }
        }
        IpcRequest::SealUnderSession {
            v,
            peer_hint,
            app_payload_b64,
        } => {
            // Cheap checks first: never touch the identity lock / secret store
            // for a request that is malformed anyway.
            if !is_device_pub_hex(&peer_hint) {
                return IpcResponse::Error {
                    v,
                    code: "SEAL_PEER_HINT".into(),
                    message: "SEAL_PEER_HINT: peer_hint must be 64 hex chars (device Ed25519)"
                        .into(),
                };
            }
            let payload = match base64_decode(&app_payload_b64) {
                Ok(b) => b,
                Err(e) => {
                    return IpcResponse::Error {
                        v,
                        code: "IPC_BAD_B64".into(),
                        message: e,
                    };
                }
            };
            let identity = match load_identity_required(data_dir) {
                Ok(id) => id,
                Err(_) => {
                    return IpcResponse::Error {
                        v,
                        code: ATSAM_SESSION_REQUIRED.into(),
                        message: format!(
                            "{ATSAM_SESSION_REQUIRED}: local identity missing; session plane unusable"
                        ),
                    };
                }
            };
            match seal_app_payload_under_session(data_dir, &identity, &peer_hint, &payload) {
                Ok(packed) => IpcResponse::SealUnderSessionResult {
                    v,
                    envelope_b64: b64_encode(&packed),
                },
                Err(e) => {
                    let code = if e.starts_with(ATSAM_LINEAGE_REVOKED) {
                        ATSAM_LINEAGE_REVOKED
                    } else if e.starts_with(ATSAM_SESSION_REQUIRED) {
                        ATSAM_SESSION_REQUIRED
                    } else if e.starts_with("SEAL_PEER_HINT") {
                        "SEAL_PEER_HINT"
                    } else if e.starts_with("SEAL_PAYLOAD") {
                        "SEAL_PAYLOAD"
                    } else {
                        "SEAL"
                    };
                    IpcResponse::Error {
                        v,
                        code: code.into(),
                        message: e,
                    }
                }
            }
        }
        IpcRequest::OutboxKick {
            v,
            peer_pub_hex,
            retry,
            custody_now,
        } => {
            let peer = match peer_pub_hex.as_deref().map(parse_hex_array::<32>) {
                None => None,
                Some(Some(peer)) => Some(peer),
                Some(None) => {
                    return IpcResponse::Error {
                        v,
                        code: "IPC_BAD_PEER".into(),
                        message: "peer_pub_hex must be 64 hex chars".into(),
                    };
                }
            };
            if custody_now {
                // `raven outbox hand-off`: friends may take what waits
                // without the 60 s wait (a failed direct try still first).
                crate::custody::hand_off(peer);
            }
            if retry {
                // Only an explicit retry lifts custody parks and pulls the
                // fetches forward (a send's own kick must not); a park for
                // misbehaviour (Phase 6b R6) too.
                crate::custody::retry();
            }
            // Every OutboxKick comes from a user's action (a send, `raven outbox
            // retry`/`cancel`, a reset step): it also starts that contact's
            // backoff over (G5).
            if crate::outbox::kick(peer.as_ref(), true, true) {
                IpcResponse::Accepted { v }
            } else {
                IpcResponse::Error {
                    v,
                    code: "OUTBOX_WORKER_OFF".into(),
                    message: "this raven-node runs no outbox worker (only `raven-node service` \
                              does): nothing is retried in the background"
                        .into(),
                }
            }
        }
        IpcRequest::OutboxStatus { v, message_id_hex } => {
            let Some(mid) = parse_hex_array::<16>(&message_id_hex) else {
                return IpcResponse::Error {
                    v,
                    code: "IPC_BAD_MESSAGE_ID".into(),
                    message: "message_id_hex must be 32 hex chars".into(),
                };
            };
            match crate::outbox::status_anywhere(data_dir, &mid) {
                Some(mut item) => {
                    crate::delivery_paths::fill_why(&mut item);
                    IpcResponse::OutboxStatusResult { v, item }
                }
                None => IpcResponse::Error {
                    v,
                    code: "OUTBOX_NOT_FOUND".into(),
                    message: "no outbound message with that id on this profile".into(),
                },
            }
        }
        IpcRequest::OutboxList {
            v,
            peer_pub_hex,
            limit,
        } => {
            let peer = match peer_pub_hex.as_deref().map(parse_hex_array::<32>) {
                None => None,
                Some(Some(peer)) => Some(peer),
                Some(None) => {
                    return IpcResponse::Error {
                        v,
                        code: "IPC_BAD_PEER".into(),
                        message: "peer_pub_hex must be 64 hex chars".into(),
                    };
                }
            };
            let limit = limit
                .unwrap_or(50)
                .clamp(1, raven_core::ipc::MAX_OUTBOX_LIST) as usize;
            match crate::outbox::list_anywhere(data_dir, peer.as_ref(), limit) {
                Ok((worker_running, mut items)) => {
                    items.iter_mut().for_each(crate::delivery_paths::fill_why);
                    IpcResponse::OutboxListResult {
                        v,
                        worker_running,
                        items,
                    }
                }
                Err(e) => IpcResponse::Error {
                    v,
                    code: "OUTBOX_STORE".into(),
                    message: e,
                },
            }
        }
        IpcRequest::LanDial { v, .. } => IpcResponse::Error {
            v,
            code: "INTERNAL".into(),
            message: "LanDial must be handled asynchronously".into(),
        },
        IpcRequest::LanLocate { v, .. } => IpcResponse::Error {
            v,
            code: "INTERNAL".into(),
            message: "LanLocate must be handled asynchronously".into(),
        },
        IpcRequest::InternetDial { v, .. } => IpcResponse::Error {
            v,
            code: "INTERNAL".into(),
            message: "InternetDial must be handled asynchronously".into(),
        },
        IpcRequest::P2pDial { v, .. } => IpcResponse::Error {
            v,
            code: "INTERNAL".into(),
            message: "P2pDial must be handled asynchronously".into(),
        },
        IpcRequest::NearbyDial { v, .. } => IpcResponse::Error {
            v,
            code: "INTERNAL".into(),
            message: "NearbyDial must be handled asynchronously".into(),
        },
        IpcRequest::OnionDial { v, .. } => IpcResponse::Error {
            v,
            code: "INTERNAL".into(),
            message: "OnionDial must be handled asynchronously".into(),
        },
        // `raven nearby …` (Phase 5): the hold while the nearby gate is
        // closed (nothing read or written); `enable` / `disable` write the
        // ask-once consent, and `background_on` / `background_off` the
        // background-mail consent (OD-C8), under the policy lock, and the
        // service applies it at once.
        IpcRequest::NearbyControl {
            v,
            action,
            peer_pub_hex,
            ttl_secs,
        } => {
            let _policy = (raven_core::nearby_live_enabled()
                && matches!(
                    action.as_str(),
                    "enable" | "disable" | "background_on" | "background_off"
                ))
            .then(policy_guard);
            match crate::nearby::control(data_dir, &action, peer_pub_hex.as_deref(), ttl_secs) {
                Ok(status) => IpcResponse::NearbyControlResult {
                    v,
                    status: Box::new(status),
                },
                Err((code, message)) => IpcResponse::Error {
                    v,
                    code: code.into(),
                    message,
                },
            }
        }
        IpcRequest::AppSubmit {
            v,
            peer_identity_hex,
            content_type,
            client_ref,
            body_b64,
            ttl_ms,
            resend,
        } => crate::app_channel::submit(
            v,
            crate::app_channel::SubmitReq {
                peer_identity_hex,
                content_type,
                client_ref,
                body_b64,
                ttl_ms,
                resend,
            },
        ),
        IpcRequest::AppInboxPage { v, .. } => IpcResponse::Error {
            v,
            code: "INTERNAL".into(),
            message: "AppInboxPage must be handled asynchronously".into(),
        },
        IpcRequest::AppInboxAck {
            v,
            consumer,
            items,
            disposition,
        } => crate::app_channel::ack(v, data_dir, &consumer, &items, &disposition),
        IpcRequest::AgentSign { v, statement } => {
            crate::app_channel::agent_sign(v, data_dir, &statement)
        }
        // Learning connectivity (Phase 6a): the hold while its gate is shut
        // (nothing is read or written; the client keeps today's static
        // order). While on, the plan is the learned order the worker uses.
        IpcRequest::LearningPlan { v, peer_pub_hex } => crate::learning::ipc_plan(
            v,
            &peer_pub_hex,
            crate::outbox::static_carriers,
            crate::outbox::custodian_candidates,
        ),
        IpcRequest::LearningReset { v, peer_pub_hex } => {
            // The sends' memory of failed routes goes too (E2 r38: after a
            // reset a send tries every route again).
            match peer_pub_hex.as_deref() {
                Some(hex) => {
                    if let Some(peer) = parse_hex_array::<32>(hex) {
                        crate::delivery_paths::forget_failed_routes(Some(&peer));
                    }
                }
                None => crate::delivery_paths::forget_failed_routes(None),
            }
            crate::learning::ipc_reset(v, data_dir, peer_pub_hex.as_deref())
        }
        // E2 r9: how received messages came (`raven inbox`), and what a send
        // to one contact may skip (its race and its quick queue).
        IpcRequest::Arrivals { v } => crate::arrivals::ipc_rows(v),
        IpcRequest::ContactReach {
            v,
            peer_pub_hex,
            routes,
        } => contact_reach(data_dir, v, &peer_pub_hex, &routes),
    }
}

/// IPC `ContactReach` (E2 r9): since when the contact was last on an
/// authenticated LAN link with us, and which of the send's `routes` failed
/// lately, by index (never an address).
fn contact_reach(
    data_dir: &Path,
    v: u16,
    peer_pub_hex: &str,
    routes: &[raven_core::ipc::ReachRoute],
) -> IpcResponse {
    let Some(peer) = parse_hex_array::<32>(peer_pub_hex) else {
        return IpcResponse::Error {
            v,
            code: "IPC_BAD_PEER".into(),
            message: "peer_pub_hex must be 64 hex chars".into(),
        };
    };
    IpcResponse::ContactReach {
        v,
        lan_seen_s: crate::delivery_paths::lan_seen_age(&peer).map(|d| d.as_secs()),
        failed: crate::delivery_paths::reach_failures(&peer, routes),
        // E2 r40: Tor did not reach the friend lately and the outbox already
        // carries a message to it (Tor first, with Tor's full wait): a send
        // queues for it instead of waiting for Tor again.
        tor_busy: crate::delivery_paths::tor_tried_lately(&peer)
            && crate::outbox::carrying(data_dir, &peer),
    }
}

/// A send's dial (IPC) to `expected_pub_hex` over `carrier` at `dial` (E2 r9
/// #2): a route that is down (nobody answered in time, no route, nothing
/// listening there, Tor could not reach it or is not ready here) is kept
/// for the next send, route by route; an answer, or a Raven that refused us
/// (a friend adding us back may change that at once: carrier matrix C90)
/// forgets that route's failure only (E2 r40: a Tor answer cleared the
/// LAN's too). E2 r38 (field K4): a friend's computer on the LAN with its
/// Raven stopped refused the LAN dial, and that refusal cleared what p2p
/// and Tor had just failed, so every send dialled all three again (15-23 s
/// each).
fn note_send_dial<T, E>(
    carrier: raven_core::OutboxCarrier,
    dial: &str,
    expected_pub_hex: &str,
    outcome: &Result<Result<T, String>, E>,
) {
    let Some(peer) = parse_hex_array::<32>(expected_pub_hex) else {
        return;
    };
    match outcome {
        Ok(Err(e)) if silent_failure(e) => {
            crate::delivery_paths::route_failed(&peer, carrier, dial, e);
        }
        Err(_) => crate::delivery_paths::route_failed(&peer, carrier, dial, "timed out"),
        // An answer, or a Raven that refused us: that route is not down.
        Ok(_) => crate::delivery_paths::route_answered(&peer, carrier, dial),
    }
}

/// A dial error that says the route is down (dialling again soon only
/// fails again): not reachable in time, no route, nothing listening there
/// (a refused connect: the computer is up, its Raven is not), Tor could not
/// reach the contact or is not ready on this computer.
fn silent_failure(e: &str) -> bool {
    use crate::outbox::code;
    matches!(
        crate::outbox::dial_error_code(e),
        code::NOT_REACHABLE
            | code::NO_ROUTE
            | code::NOT_LISTENING
            | code::ONION_UNREACHABLE
            | code::ONION_NOT_READY
    )
}

/// IPC error code for a forward-queue enqueue failure: only a full queue is
/// back-pressure a client should retry; bad input and storage faults are not.
fn forward_queue_error_code(e: &raven_core::forward_queue::ForwardQueueError) -> &'static str {
    use raven_core::forward_queue::ForwardQueueError as E;
    match e {
        E::QueueFull(_) => "QUEUE_FULL",
        E::BadId | E::BadObjectDigest => "IPC_BAD_ENVELOPE",
        E::TooLarge(_) => "IPC_FRAME",
        E::Sqlite(_) => "QUEUE_IO",
    }
}

/// The forward row is written before the outbox row. When the outbox step
/// fails the envelope may already be queued for the bridge, so say that: the
/// forward enqueue is idempotent, a retry is safe and a "failed" send may
/// still be delivered.
fn outbox_failed_message(forward_queued: bool, cause: &str) -> String {
    if forward_queued {
        format!("{cause} (the envelope is already in the forward queue and may still be delivered; retrying is safe)")
    } else {
        cause.to_string()
    }
}

fn is_device_pub_hex(s: &str) -> bool {
    let t = s.trim();
    t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Exactly `N` bytes of hex (either case), or `None`.
fn parse_hex_array<const N: usize>(s: &str) -> Option<[u8; N]> {
    let t = s.trim();
    if t.len() != N * 2 {
        return None;
    }
    hex::decode(t).ok()?.try_into().ok()
}

/// Ops that read or write the shared forward queue (serialized by its lock).
fn needs_forward_queue(req: &IpcRequest) -> bool {
    matches!(
        req,
        IpcRequest::Status { .. } | IpcRequest::EnqueueSealed { .. }
    )
}

/// Blocking request work (SQLite, policy files, identity/secret store, seal).
/// Must run on the blocking pool. Only queue ops take the queue lock, so a slow
/// `SealUnderSession` never serializes `Status` / `EnqueueSealed` behind it.
fn handle_req_blocking(
    req: IpcRequest,
    data_dir: &Path,
    forward: &Mutex<Option<ForwardQueue>>,
) -> IpcResponse {
    if needs_forward_queue(&req) {
        let fwd = forward.blocking_lock();
        handle_req(req, data_dir, &fwd)
    } else {
        handle_req(req, data_dir, &None)
    }
}

fn b64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Friend custody frames never ride the local dial ops (design §10): only the
/// worker and the fetcher speak RFC1, after their own gate and contact
/// checks. Lab runs may.
fn refuse_custody_frames(v: u16, frames: &[Vec<u8>]) -> Option<IpcResponse> {
    let custody = frames
        .iter()
        .any(|f| raven_core::friend_custody::is_rfc1(f));
    (custody && !raven_core::pair_init::lab_test_a_enabled()).then(|| IpcResponse::Error {
        v,
        code: "CUSTODY_IPC_REFUSED".into(),
        message: "friend custody frames are not accepted on IPC dials".into(),
    })
}

async fn handle_lan_dial(data_dir: &Path, req: IpcRequest) -> IpcResponse {
    let IpcRequest::LanDial {
        v,
        lan_dial,
        expected_pub_hex,
        frames_b64,
    } = req
    else {
        return IpcResponse::Error {
            v: IPC_VERSION,
            code: "INTERNAL".into(),
            message: "not LanDial".into(),
        };
    };
    // `raven lan off`: no LAN dial at all (nothing is decoded or resolved).
    if raven_core::lan_user_off() {
        return IpcResponse::Error {
            v,
            code: LAN_OFF.into(),
            message: format!("{LAN_OFF}: raven lan off is in effect (raven lan on)"),
        };
    }
    let mut frames = Vec::new();
    for item in frames_b64 {
        match base64_decode(&item) {
            Ok(b) => frames.push(b),
            Err(e) => {
                return IpcResponse::Error {
                    v,
                    code: "IPC_BAD_B64".into(),
                    message: e,
                };
            }
        }
    }
    if let Some(refusal) = refuse_custody_frames(v, &frames) {
        return refusal;
    }
    let work = lan_direct::dial(data_dir, &lan_dial, &expected_pub_hex, &frames);
    let outcome = tokio::time::timeout(LAN_DIAL_TIMEOUT, work).await;
    note_send_dial(
        raven_core::OutboxCarrier::Lan,
        &lan_dial,
        &expected_pub_hex,
        &outcome,
    );
    match outcome {
        Ok(Ok(replies)) => IpcResponse::LanDialResult {
            v,
            frames_b64: replies.iter().map(|f| b64_encode(f)).collect(),
        },
        // `raven lan verified-only on` (P3.C2): refused before dialling, in
        // its own code.
        Ok(Err(e)) if e.starts_with(raven_core::LAN_VERIFIED_ONLY) => IpcResponse::Error {
            v,
            code: raven_core::LAN_VERIFIED_ONLY.into(),
            message: e,
        },
        Ok(Err(e)) => IpcResponse::Error {
            v,
            code: "LAN_DIAL".into(),
            message: e,
        },
        Err(_) => IpcResponse::Error {
            v,
            code: "LAN_DIAL_TIMEOUT".into(),
            message: "lan dial exceeded 45s".into(),
        },
    }
}

/// `raven send`'s nearby search (IPC `LanLocate`, Phase 3 P3.11,
/// RAVEN_LAN_BEACON_V1 §8): where the LAN beacon found the contact's LAN
/// listener ([`crate::lan_beacon::locate`]), waiting at most
/// [`crate::lan_beacon::LOCATE_MAX`] for a round's answer. For a current,
/// unblocked contact only (else the outbox's code). Empty at once while LAN
/// is off, while `raven lan verified-only on` keeps an unverified contact
/// off the LAN, and while the beacon does not run (its gate is closed).
/// Dial strings only, at most two, for that send alone: never saved.
async fn handle_lan_locate(data_dir: &Path, req: IpcRequest) -> IpcResponse {
    handle_lan_locate_with(data_dir, req, |peer, wait| async move {
        crate::lan_beacon::locate(&peer, wait).await
    })
    .await
}

/// [`handle_lan_locate`] with the beacon's search (`locate`) passed in.
async fn handle_lan_locate_with<F, Fut>(data_dir: &Path, req: IpcRequest, locate: F) -> IpcResponse
where
    F: FnOnce([u8; 32], Duration) -> Fut,
    Fut: std::future::Future<Output = Vec<String>>,
{
    use crate::outbox::code;
    use raven_core::outbox::{contact_admission, ContactAdmission};
    let IpcRequest::LanLocate {
        v,
        peer_pub_hex,
        wait_ms,
    } = req
    else {
        return IpcResponse::Error {
            v: IPC_VERSION,
            code: "INTERNAL".into(),
            message: "not LanLocate".into(),
        };
    };
    let Some(peer) = parse_hex_array::<32>(&peer_pub_hex) else {
        return IpcResponse::Error {
            v,
            code: "IPC_BAD_PEER".into(),
            message: "peer_pub_hex must be 64 hex chars".into(),
        };
    };
    let dd = data_dir.to_path_buf();
    // Ok(whether the contact may use the LAN), or why it is no contact.
    let admitted = tokio::task::spawn_blocking(move || match contact_admission(&dd, &peer) {
        ContactAdmission::Allowed(c) => {
            Ok(c.pinned || !raven_core::node_policy::lan_verified_only(&dd))
        }
        ContactAdmission::NotContact => Err((code::NOT_A_CONTACT, "not one of your contacts")),
        ContactAdmission::Blocked => Err((code::CONTACT_BLOCKED, "a blocked contact")),
        ContactAdmission::Unreadable => Err((
            code::CONTACTS_UNREADABLE,
            "the contact book or block list cannot be read",
        )),
    })
    .await;
    let lan_ok = match admitted {
        Ok(Ok(lan_ok)) => lan_ok,
        Ok(Err((code, why))) => {
            return IpcResponse::Error {
                v,
                code: code.into(),
                message: format!("no nearby search: {why}"),
            };
        }
        Err(e) => {
            return IpcResponse::Error {
                v,
                code: "INTERNAL".into(),
                message: format!("ipc worker: {e}"),
            };
        }
    };
    // `raven lan off`, or an unverified contact under `raven lan
    // verified-only on`: nothing on the LAN, so nothing to look for.
    if !lan_ok || !raven_core::lan_usable_now() {
        return IpcResponse::LanLocated {
            v,
            dials: Vec::new(),
        };
    }
    let wait = Duration::from_millis(u64::from(wait_ms)).min(crate::lan_beacon::LOCATE_MAX);
    let found = locate(peer, wait).await;
    IpcResponse::LanLocated {
        v,
        dials: raven_core::outbox::beacon_lan_dials(&found),
    }
}

async fn handle_internet_dial(data_dir: &Path, req: IpcRequest) -> IpcResponse {
    let IpcRequest::InternetDial {
        v,
        internet_dial,
        expected_pub_hex,
        frames_b64,
    } = req
    else {
        return IpcResponse::Error {
            v: IPC_VERSION,
            code: "INTERNAL".into(),
            message: "not InternetDial".into(),
        };
    };
    let mut frames = Vec::new();
    for item in frames_b64 {
        match base64_decode(&item) {
            Ok(b) => frames.push(b),
            Err(e) => {
                return IpcResponse::Error {
                    v,
                    code: "IPC_BAD_B64".into(),
                    message: e,
                };
            }
        }
    }
    if let Some(refusal) = refuse_custody_frames(v, &frames) {
        return refusal;
    }
    let work = internet_direct::dial(data_dir, &internet_dial, &expected_pub_hex, &frames);
    let outcome = tokio::time::timeout(INTERNET_DIAL_TIMEOUT, work).await;
    note_send_dial(
        raven_core::OutboxCarrier::Internet,
        &internet_dial,
        &expected_pub_hex,
        &outcome,
    );
    match outcome {
        Ok(Ok(replies)) => IpcResponse::InternetDialResult {
            v,
            frames_b64: replies.iter().map(|f| b64_encode(f)).collect(),
        },
        Ok(Err(e)) => IpcResponse::Error {
            v,
            code: "INTERNET_DIAL".into(),
            message: e,
        },
        Err(_) => IpcResponse::Error {
            v,
            code: "INTERNET_DIAL_TIMEOUT".into(),
            message: "internet dial exceeded 45s".into(),
        },
    }
}

async fn handle_p2p_dial(data_dir: &Path, req: IpcRequest) -> IpcResponse {
    let IpcRequest::P2pDial {
        v,
        multiaddr,
        expected_pub_hex,
        frames_b64,
    } = req
    else {
        return IpcResponse::Error {
            v: IPC_VERSION,
            code: "INTERNAL".into(),
            message: "not P2pDial".into(),
        };
    };
    let mut frames = Vec::new();
    for item in frames_b64 {
        match base64_decode(&item) {
            Ok(b) => frames.push(b),
            Err(e) => {
                return IpcResponse::Error {
                    v,
                    code: "IPC_BAD_B64".into(),
                    message: e,
                };
            }
        }
    }
    if let Some(refusal) = refuse_custody_frames(v, &frames) {
        return refusal;
    }
    // Same rules as the outbox: gate, verified contacts only (`p2p::dial`).
    let work = crate::p2p::dial_with_path(data_dir, &multiaddr, &expected_pub_hex, &frames);
    let outcome = tokio::time::timeout(INTERNET_DIAL_TIMEOUT, work).await;
    note_send_dial(
        raven_core::OutboxCarrier::P2p,
        &multiaddr,
        &expected_pub_hex,
        &outcome,
    );
    match outcome {
        Ok(Ok((replies, path))) => p2p_dial_reply(v, &replies, path),
        Ok(Err(e)) => IpcResponse::Error {
            v,
            code: "P2P_DIAL".into(),
            message: e,
        },
        Err(_) => IpcResponse::Error {
            v,
            code: "P2P_DIAL_TIMEOUT".into(),
            message: "p2p dial exceeded 45s".into(),
        },
    }
}

/// IPC `OnionDial` (lab, `raven send` to a contact reached over Tor): the
/// same rules as the outbox's onion dials ([`crate::onion::dial_with_meta`]:
/// the gate, a verified contact, a ready helper), Tor's waits.
async fn handle_onion_dial(data_dir: &Path, req: IpcRequest) -> IpcResponse {
    let IpcRequest::OnionDial {
        v,
        onion_dial,
        expected_pub_hex,
        frames_b64,
    } = req
    else {
        return IpcResponse::Error {
            v: IPC_VERSION,
            code: "INTERNAL".into(),
            message: "not OnionDial".into(),
        };
    };
    let mut frames = Vec::new();
    for item in frames_b64 {
        match base64_decode(&item) {
            Ok(b) => frames.push(b),
            Err(e) => {
                return IpcResponse::Error {
                    v,
                    code: "IPC_BAD_B64".into(),
                    message: e,
                };
            }
        }
    }
    if let Some(refusal) = refuse_custody_frames(v, &frames) {
        return refusal;
    }
    let work = crate::onion::dial_with_meta(
        data_dir,
        &onion_dial,
        &expected_pub_hex,
        &frames,
        crate::learning::DialMeta::default(),
    );
    let within = raven_core::onion::ONION_DIAL_DEADLINE + Duration::from_secs(5);
    let outcome = tokio::time::timeout(within, work).await;
    note_send_dial(
        raven_core::OutboxCarrier::Onion,
        &onion_dial,
        &expected_pub_hex,
        &outcome,
    );
    match outcome {
        Ok(Ok(replies)) => IpcResponse::OnionDialResult {
            v,
            frames_b64: replies.iter().map(|f| b64_encode(f)).collect(),
        },
        Ok(Err(e)) => IpcResponse::Error {
            v,
            code: crate::outbox::dial_error_code(&e).into(),
            message: e,
        },
        Err(_) => IpcResponse::Error {
            v,
            code: "ONION_DIAL_TIMEOUT".into(),
            message: format!("onion dial exceeded {}s", within.as_secs()),
        },
    }
}

/// IPC `NearbyDial` (Phase 5, `raven send --carrier nearby`): the same rules
/// as the outbox's nearby dials ([`crate::nearby::dial`]: the gate, the
/// route naming exactly this contact, verified contacts only, an engine).
async fn handle_nearby_dial(data_dir: &Path, req: IpcRequest) -> IpcResponse {
    let IpcRequest::NearbyDial {
        v,
        nearby_dial,
        expected_pub_hex,
        frames_b64,
    } = req
    else {
        return IpcResponse::Error {
            v: IPC_VERSION,
            code: "INTERNAL".into(),
            message: "not NearbyDial".into(),
        };
    };
    let mut frames = Vec::new();
    for item in frames_b64 {
        match base64_decode(&item) {
            Ok(b) => frames.push(b),
            Err(e) => {
                return IpcResponse::Error {
                    v,
                    code: "IPC_BAD_B64".into(),
                    message: e,
                };
            }
        }
    }
    if let Some(refusal) = refuse_custody_frames(v, &frames) {
        return refusal;
    }
    let work = crate::nearby::dial(data_dir, &nearby_dial, &expected_pub_hex, &frames);
    match tokio::time::timeout(INTERNET_DIAL_TIMEOUT, work).await {
        Ok(Ok(replies)) => IpcResponse::NearbyDialResult {
            v,
            frames_b64: replies.iter().map(|f| b64_encode(f)).collect(),
        },
        Ok(Err(e)) => IpcResponse::Error {
            v,
            code: nearby_dial_code(&e).into(),
            message: e,
        },
        Err(_) => IpcResponse::Error {
            v,
            code: "NEARBY_DIAL_TIMEOUT".into(),
            message: "nearby dial exceeded 45s".into(),
        },
    }
}

/// A failed nearby dial's IPC code: the stable nearby codes where the error
/// names one, else `NEARBY_DIAL`.
fn nearby_dial_code(e: &str) -> &'static str {
    [
        "NEARBY_HOLD",
        "NEARBY_NOT_RUNNING",
        "NEARBY_NOT_IN_RANGE",
        "NEARBY_BUSY",
    ]
    .into_iter()
    .find(|code| e.starts_with(code))
    .unwrap_or("NEARBY_DIAL")
}

/// A p2p dial's answer: the replies and how the link travelled (absent when
/// unknown; LAN and Internet direct answers carry no path: always direct).
fn p2p_dial_reply(
    v: u16,
    replies: &[Vec<u8>],
    path: Option<raven_core::DeliveryPath>,
) -> IpcResponse {
    IpcResponse::P2pDialResult {
        v,
        frames_b64: replies.iter().map(|f| b64_encode(f)).collect(),
        path: path.map(|p| p.label().to_string()),
    }
}

fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s.trim()))
        .map_err(|e| e.to_string())
}

/// Lock v2 (P6.40): what a locked raven-node answers to anything but
/// `Ping`, `Status`, `Lock` and `Unlock`.
const LOCKED_MESSAGE: &str = raven_core::privacy::LOCKED_V2_TEXT;

/// A locked raven-node's `Status`: that it is locked, its pid and IPC, and
/// nothing else (no row would be true while it is locked).
fn locked_status(v: u16) -> IpcResponse {
    IpcResponse::Status {
        v,
        bridge: false,
        store: false,
        relay: false,
        forward_pending: 0,
        capabilities: vec!["ipc".into()],
        p2p: None,
        pid: Some(std::process::id()),
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
        locked: Some(true),
        updates: None,
    }
}

/// `Lock` and `Unlock`'s answer.
fn lock_state(v: u16, reply: crate::lock::LockReply) -> IpcResponse {
    IpcResponse::LockState {
        v,
        locked: reply.locked,
        passphrase: reply.passphrase,
        failed_unlocks: reply.failed_unlocks,
    }
}

fn lock_held(v: u16) -> IpcResponse {
    IpcResponse::Error {
        v,
        code: raven_core::ipc::LOCK_V2_HELD.into(),
        message: "Lock v2 is not enabled in this build".into(),
    }
}

/// IPC `Unlock` (Lock v2): the passphrase (base64) is decoded into bytes
/// that are wiped after the check; neither is ever logged or answered.
async fn handle_unlock(
    v: u16,
    data_dir: &Path,
    passphrase_b64: Option<raven_core::ipc::IpcSecret>,
) -> IpcResponse {
    use crate::lock::UnlockError;
    let passphrase = match passphrase_b64.as_ref().map(|p| p.decode_b64()) {
        None => None,
        Some(Some(bytes)) => Some(bytes),
        Some(None) => {
            return IpcResponse::Error {
                v,
                code: "IPC_FRAME".into(),
                message: "the passphrase is not base64".into(),
            }
        }
    };
    drop(passphrase_b64);
    let error = |code: &str, message: String| IpcResponse::Error {
        v,
        code: code.into(),
        message,
    };
    match crate::lock::unlock(data_dir, passphrase).await {
        Ok(reply) => lock_state(v, reply),
        Err(UnlockError::Held) => lock_held(v),
        Err(UnlockError::Wait(secs)) => error(
            raven_core::ipc::UNLOCK_WAIT,
            format!("Wait {secs} s before you try again."),
        ),
        Err(UnlockError::Wrong) => error(
            raven_core::ipc::UNLOCK_WRONG_PASSPHRASE,
            "That passphrase is not right.".into(),
        ),
        Err(UnlockError::Required) => error(
            raven_core::ipc::UNLOCK_PASSPHRASE_REQUIRED,
            "This profile has a Raven passphrase: type it to unlock.".into(),
        ),
        Err(UnlockError::Failed(why)) => error("INTERNAL", format!("unlock failed: {why}")),
    }
}

async fn dispatch(
    frame: &[u8],
    data_dir: &Arc<PathBuf>,
    forward: &Arc<Mutex<Option<ForwardQueue>>>,
) -> IpcResponse {
    match decode_request_checked(frame) {
        // Liveness: no lock, no I/O — a busy daemon must still answer Ping.
        Ok(IpcRequest::Ping { v }) => IpcResponse::Pong { v },
        // Lock v2 (P6.40): while locked only these four are served.
        Ok(IpcRequest::Lock { v }) => match crate::lock::lock(data_dir).await {
            Ok(reply) => lock_state(v, reply),
            Err(crate::lock::Held) => lock_held(v),
        },
        Ok(IpcRequest::Unlock { v, passphrase_b64 }) => {
            handle_unlock(v, data_dir, passphrase_b64).await
        }
        Ok(IpcRequest::Status { v, .. }) if crate::lock::is_locked() => locked_status(v),
        // (The decoder already checked every request's `v`.)
        Ok(_) if crate::lock::is_locked() => IpcResponse::Error {
            v: IPC_VERSION,
            code: raven_core::ipc::LOCKED.into(),
            message: LOCKED_MESSAGE.into(),
        },
        Ok(req @ IpcRequest::LanDial { .. }) => handle_lan_dial(data_dir, req).await,
        Ok(req @ IpcRequest::LanLocate { .. }) => handle_lan_locate(data_dir, req).await,
        Ok(req @ IpcRequest::InternetDial { .. }) => handle_internet_dial(data_dir, req).await,
        Ok(req @ IpcRequest::P2pDial { .. }) => handle_p2p_dial(data_dir, req).await,
        Ok(req @ IpcRequest::NearbyDial { .. }) => handle_nearby_dial(data_dir, req).await,
        Ok(req @ IpcRequest::OnionDial { .. }) => handle_onion_dial(data_dir, req).await,
        // Long-poll: waits on the inbox generation, not on a pool thread.
        Ok(IpcRequest::AppInboxPage {
            v,
            consumer,
            takeover,
            content_type,
            after,
            limit,
            wait_ms,
        }) => {
            crate::app_channel::page(
                v,
                Arc::clone(data_dir),
                crate::app_channel::PageReq {
                    consumer,
                    takeover,
                    content_type,
                    after,
                    limit,
                    wait_ms,
                },
            )
            .await
        }
        Ok(req) => {
            let dd = data_dir.clone();
            let fq = forward.clone();
            tokio::task::spawn_blocking(move || handle_req_blocking(req, &dd, &fq))
                .await
                .unwrap_or_else(|e| IpcResponse::Error {
                    v: IPC_VERSION,
                    code: "INTERNAL".into(),
                    message: format!("ipc worker: {e}"),
                })
        }
        Err(e) => IpcResponse::Error {
            v: IPC_VERSION,
            code: e.code.into(),
            message: e.message,
        },
    }
}

/// Encode `resp`, or an explicit `IPC_FRAME` error if it does not fit in one
/// IPC frame — never leave the client with a bare EOF after side effects.
fn encode_response_or_error(resp: &IpcResponse) -> Vec<u8> {
    encode_response(resp).unwrap_or_else(|e| {
        let fallback = IpcResponse::Error {
            v: IPC_VERSION,
            code: "IPC_FRAME".into(),
            message: format!("{e} (limit {MAX_IPC_FRAME} bytes)"),
        };
        encode_response(&fallback).expect("small error response fits")
    })
}

async fn serve_one<S>(
    mut stream: S,
    data_dir: Arc<PathBuf>,
    forward: Arc<Mutex<Option<ForwardQueue>>>,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut frame = match read_frame(&mut stream).await {
        Ok(f) => f,
        Err(_) => return,
    };
    let resp = dispatch(&frame, &data_dir, &forward).await;
    // It may have carried Lock v2's passphrase.
    raven_core::ipc::wipe_frame(&mut frame);
    let out = encode_response_or_error(&resp);
    let _ = tokio::time::timeout(IPC_IO_TIMEOUT, async {
        stream.write_all(&out).await.ok()?;
        stream.flush().await.ok()?;
        Some(())
    })
    .await;
}

/// Open the forward queue the IPC server shares with the bridge. `None` path
/// means "no bridge configured". A path that cannot be opened is an error that
/// stops the server: running on would answer `EnqueueSealed` with `Accepted`
/// for envelopes the bridge never sees.
pub(crate) fn open_forward_queue(
    forward_path: Option<PathBuf>,
) -> Result<Arc<Mutex<Option<ForwardQueue>>>, String> {
    let queue = match forward_path {
        Some(p) => Some(
            ForwardQueue::open(&p)
                .map_err(|e| format!("forward queue {} unavailable: {e}", p.display()))?,
        ),
        None => None,
    };
    Ok(Arc::new(Mutex::new(queue)))
}

/// Bind the platform IPC transport and serve until the process exits.
pub async fn run_ipc_server(
    data_dir: PathBuf,
    forward_path: Option<PathBuf>,
) -> Result<(), String> {
    #[cfg(unix)]
    {
        run_uds_server(data_dir, forward_path).await
    }
    #[cfg(windows)]
    {
        windows::run_named_pipe_server(data_dir, forward_path).await
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (data_dir, forward_path);
        Err("IPC transport not supported on this OS".into())
    }
}

/// Create `data_dir` 0700 if missing and refuse one this user does not own or
/// that anyone may write to: its owner could swap the socket under us. A
/// group-writable dir we own is tightened (group write removed) instead of
/// refused: umask 002 makes that the default on user-private-group systems,
/// and otherwise any group member could replace the socket (Unix clients do
/// not check the server's UID).
#[cfg(unix)]
fn ensure_private_data_dir(data_dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    // Never build the "no profile could be determined" placeholder (a root process
    // on a minimal system could otherwise create its tree).
    raven_core::paths::require_resolved_data_dir(data_dir)?;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(data_dir)
        .map_err(|e| format!("create {}: {e}", data_dir.display()))?;
    let meta = std::fs::metadata(data_dir).map_err(|e| format!("{}: {e}", data_dir.display()))?;
    let me = unsafe { libc::geteuid() };
    if !meta.is_dir() || meta.uid() != me {
        return Err(format!(
            "ipc: data dir {} is not a directory owned by uid {me}; refusing to serve IPC",
            data_dir.display()
        ));
    }
    if meta.mode() & 0o002 != 0 {
        return Err(format!(
            "ipc: data dir {} is world-writable; refusing to serve IPC",
            data_dir.display()
        ));
    }
    if meta.mode() & 0o020 != 0 {
        let tightened = meta.mode() & 0o7777 & !0o022;
        std::fs::set_permissions(data_dir, std::fs::Permissions::from_mode(tightened)).map_err(
            |e| {
                format!(
                    "ipc: data dir {} is group-writable and chmod failed ({e}); refusing to serve IPC",
                    data_dir.display()
                )
            },
        )?;
        eprintln!(
            "raven-node ipc: removed group write permission from data dir {} (now {:o})",
            data_dir.display(),
            tightened
        );
    }
    Ok(())
}

/// Single-instance lock next to the socket, held for the server's lifetime
/// (the kernel drops it on exit, so a crash never leaves it stuck).
#[cfg(unix)]
fn acquire_instance_lock(sock: &Path) -> Result<std::fs::File, String> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    let path = raven_core::ipc::instance_lock_path(sock);
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .map_err(|e| format!("open {}: {e}", path.display()))?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let e = std::io::Error::last_os_error();
        return Err(if e.kind() == std::io::ErrorKind::WouldBlock {
            format!(
                "another raven-node IPC server is running for {} (lock held); not replacing it",
                sock.display()
            )
        } else {
            format!("lock {}: {e}", path.display())
        });
    }
    Ok(file)
}

/// Unlink a leftover socket only if nothing answers on it. Never unlinks a
/// live daemon's endpoint or a non-socket file.
#[cfg(unix)]
fn remove_stale_socket(sock: &Path) -> Result<(), String> {
    use std::io::ErrorKind;
    use std::os::unix::fs::FileTypeExt;
    let meta = match std::fs::symlink_metadata(sock) {
        Ok(m) => m,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("{}: {e}", sock.display())),
    };
    if !meta.file_type().is_socket() {
        return Err(format!(
            "{} exists and is not a socket; refusing to replace it",
            sock.display()
        ));
    }
    match std::os::unix::net::UnixStream::connect(sock) {
        Ok(_) => Err(format!(
            "a live IPC server is listening on {}; refusing to unlink it",
            sock.display()
        )),
        Err(e) if matches!(e.kind(), ErrorKind::ConnectionRefused | ErrorKind::NotFound) => {
            match std::fs::remove_file(sock) {
                Err(e) if e.kind() != ErrorKind::NotFound => {
                    Err(format!("remove stale {}: {e}", sock.display()))
                }
                _ => Ok(()),
            }
        }
        Err(e) => Err(format!(
            "probe {}: {e}; refusing to unlink it",
            sock.display()
        )),
    }
}

/// Bind `sock` so it is never reachable with a mode looser than 0600: bind in
/// a fresh 0700 staging dir, chmod (checked), then rename into place. The
/// staging path is shorter than `sock`, so it fits `sun_path` whenever `sock`
/// does.
#[cfg(unix)]
fn bind_private_uds(sock: &Path) -> Result<UnixListener, String> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let parent = sock
        .parent()
        .ok_or_else(|| format!("{} has no parent", sock.display()))?;
    let staging = parent.join(format!(".rn{:08x}", rand::random::<u32>()));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&staging)
        .map_err(|e| format!("create {}: {e}", staging.display()))?;
    let tmp = staging.join("s");
    let bound = (|| -> Result<std::os::unix::net::UnixListener, String> {
        let listener = std::os::unix::net::UnixListener::bind(&tmp)
            .map_err(|e| format!("bind {}: {e}", sock.display()))?;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("chmod 0600 {}: {e}", sock.display()))?;
        std::fs::rename(&tmp, sock).map_err(|e| format!("publish {}: {e}", sock.display()))?;
        Ok(listener)
    })();
    let _ = std::fs::remove_file(&tmp);
    let _ = std::fs::remove_dir(&staging);
    let listener = bound?;
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    UnixListener::from_std(listener).map_err(|e| e.to_string())
}

/// (dev, inode) of the socket path, to notice when it was unlinked/replaced.
#[cfg(unix)]
fn socket_identity(sock: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(sock)
        .ok()
        .map(|m| (m.dev(), m.ino()))
}

/// Bind UDS with mode 0600 and serve until the process exits.
#[cfg(unix)]
async fn run_uds_server(data_dir: PathBuf, forward_path: Option<PathBuf>) -> Result<(), String> {
    ensure_private_data_dir(&data_dir)?;
    let sock = socket_path(&data_dir);
    let _instance_lock = acquire_instance_lock(&sock)?;
    // Before the endpoint is published: a queue that cannot open must not
    // leave a socket behind that answers and then loses envelopes.
    let forward = open_forward_queue(forward_path)?;
    remove_stale_socket(&sock)?;
    let mut listener = bind_private_uds(&sock)?;
    let mut bound = socket_identity(&sock);
    eprintln!("raven-node ipc: listening {}", sock.display());

    let data_dir = Arc::new(data_dir);
    let slots = Arc::new(Semaphore::new(MAX_IPC_CONNECTIONS));
    let mut watch = tokio::time::interval(SOCKET_WATCH_INTERVAL);
    watch.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        let permit = slots
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| "ipc connection limiter closed".to_string())?;
        let stream = loop {
            tokio::select! {
                (stream, _) = crate::accept_retrying("raven-node ipc", || listener.accept()) => {
                    break stream;
                }
                _ = watch.tick() => {
                    if bound.is_some() && socket_identity(&sock) == bound {
                        continue;
                    }
                    // Our path was unlinked or replaced (e.g. a client "cleaning
                    // up" a socket it wrongly thought stale). We hold the instance
                    // lock, so no other raven-node serves this data dir: publish
                    // our endpoint again instead of running orphaned.
                    match bind_private_uds(&sock) {
                        Ok(fresh) => {
                            listener = fresh;
                            bound = socket_identity(&sock);
                            eprintln!("raven-node ipc: re-bound {}", sock.display());
                        }
                        Err(e) => eprintln!("raven-node ipc: re-bind failed: {e}"),
                    }
                }
            }
        };
        if !peer_uid_matches_self(&stream) {
            eprintln!("raven-node ipc: reject peer (uid mismatch)");
            continue;
        }
        let dd = data_dir.clone();
        let fq = forward.clone();
        tokio::spawn(async move {
            let _permit = permit;
            serve_one(stream, dd, fq).await;
        });
    }
}

/// Client helper for same-process smoke tests.
#[cfg(unix)]
#[allow(dead_code)]
pub async fn client_ping(sock: &Path) -> Result<IpcResponse, String> {
    let mut stream = UnixStream::connect(sock)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    let req = raven_core::encode_request(&IpcRequest::Ping { v: IPC_VERSION })?;
    stream.write_all(&req).await.map_err(|e| e.to_string())?;
    stream.flush().await.map_err(|e| e.to_string())?;
    let frame = read_frame(&mut stream).await?;
    raven_core::decode_response(&frame)
}

#[cfg(test)]
mod tests {
    use super::*;
    use raven_core::ipc::{IpcRequest, IpcResponse, IPC_VERSION};

    /// E2 r9 #2 (carrier matrix C90): only a silent failure is kept for the
    /// next send's quick queue; a refusal or a closed port shows the
    /// contact's computer is there.
    #[test]
    fn only_silent_dial_failures_count_for_the_quick_queue() {
        for e in [
            "lan connect: cannot connect to 192.0.2.7:7420 (timed out)",
            "lan connect: cannot connect to 192.0.2.7:7420 (Connection refused)",
            "P2P_UNREACHABLE: no route to the contact",
            "ONION_UNREACHABLE: the contact's onion service did not answer over Tor",
            "ONION_NOT_READY: Tor is not ready on this computer yet",
        ] {
            assert!(silent_failure(e), "{e}");
        }
        for e in [
            "LINK_NOT_ACCEPTED: the peer closed the link",
            "rlb1 offer identity mismatch",
            "lan_dial_peer_closed",
        ] {
            assert!(!silent_failure(e), "{e}");
        }
    }

    /// E2 r38 (field K4): mac-a's computer on the LAN, its Raven stopped.
    /// The LAN dial is refused at once, p2p and Tor do not answer: each
    /// route's failure is kept (the refusal no longer clears the others),
    /// so the next send finds every route failed and queues at once. A
    /// Raven that refuses us, or an answer, still clears them.
    #[test]
    fn a_stopped_raven_on_the_lan_keeps_every_routes_failure() {
        use raven_core::OutboxCarrier;
        let peer = [0x4B; 32];
        let hex = hex::encode(peer);
        let fail = |carrier, dial: &str, e: &str| {
            note_send_dial::<(), ()>(carrier, dial, &hex, &Ok(Err(e.to_string())));
        };
        fail(
            OutboxCarrier::Lan,
            "192.168.0.16:17420",
            "lan connect: cannot connect to 192.168.0.16:17420 (Connection refused (os error \
             61))",
        );
        fail(
            OutboxCarrier::P2p,
            "/p2p/12D3KooWExample",
            "P2P_UNREACHABLE: the contact is unreachable on every p2p address it has",
        );
        note_send_dial::<(), ()>(OutboxCarrier::Onion, "onion:ab", &hex, &Err(()));
        let mut failed: Vec<String> = crate::delivery_paths::failed_routes(&peer)
            .into_iter()
            .map(|f| f.carrier)
            .collect();
        failed.sort();
        assert_eq!(failed, ["lan_dial", "onion_dial", "p2p_dial"]);
        // The friend's Raven refused us on the LAN: that route is not down
        // (what it says may change at once); the others stay.
        fail(
            OutboxCarrier::Lan,
            "192.168.0.16:17420",
            "LINK_NOT_ACCEPTED: closed",
        );
        let mut left: Vec<String> = crate::delivery_paths::failed_routes(&peer)
            .into_iter()
            .map(|f| f.carrier)
            .collect();
        left.sort();
        assert_eq!(left, ["onion_dial", "p2p_dial"]);
    }

    #[test]
    fn pipe_name_constant_is_exact() {
        assert_eq!(raven_core::WINDOWS_NAMED_PIPE, r"\\.\pipe\raven-node");
        assert_eq!(
            raven_core::default_pipe_name(),
            raven_core::WINDOWS_NAMED_PIPE
        );
    }

    /// The p2p dial's answer names how the link travelled, by its token,
    /// and says nothing when that is unknown.
    #[test]
    fn p2p_dial_reply_names_the_path() {
        let replies = vec![b"abc".to_vec()];
        for path in raven_core::DeliveryPath::ALL {
            match p2p_dial_reply(IPC_VERSION, &replies, Some(path)) {
                IpcResponse::P2pDialResult {
                    frames_b64,
                    path: Some(token),
                    ..
                } => {
                    assert_eq!(frames_b64, vec![b64_encode(b"abc")]);
                    assert_eq!(raven_core::DeliveryPath::parse(&token), Some(path));
                }
                other => panic!("{other:?}"),
            }
        }
        match p2p_dial_reply(IPC_VERSION, &[], None) {
            IpcResponse::P2pDialResult {
                frames_b64, path, ..
            } => assert!(frames_b64.is_empty() && path.is_none()),
            other => panic!("{other:?}"),
        }
    }

    /// Phase 3 `raven outbox hand-off`: `custody_now` arms the worker's
    /// hand-off for that contact (whether or not a worker runs to take the
    /// kick); a plain kick arms nothing. Custody frames on IPC dials are
    /// still refused outside the lab.
    #[test]
    fn outbox_kick_custody_now_arms_hand_off() {
        let dir = tempfile::tempdir().unwrap();
        let (handed, plain) = ([0xC8; 32], [0xC9; 32]);
        let kick = |peer: &[u8; 32], custody_now: bool| IpcRequest::OutboxKick {
            v: IPC_VERSION,
            peer_pub_hex: Some(hex::encode(peer)),
            retry: true,
            custody_now,
        };
        let after = raven_core::custody_client::custody_after_ms();
        let _ = handle_req(kick(&plain, false), dir.path(), &None);
        assert_eq!(crate::custody::custody_after_for(&plain), after);
        let _ = handle_req(kick(&handed, true), dir.path(), &None);
        assert_eq!(crate::custody::custody_after_for(&handed), 0);
        assert_eq!(crate::custody::custody_after_for(&plain), after);
        // A bad peer is refused before anything is armed.
        let bad = IpcRequest::OutboxKick {
            v: IPC_VERSION,
            peer_pub_hex: Some("zz".into()),
            retry: true,
            custody_now: true,
        };
        match handle_req(bad, dir.path(), &None) {
            IpcResponse::Error { code, .. } => assert_eq!(code, "IPC_BAD_PEER"),
            other => panic!("{other:?}"),
        }
        // CUSTODY_IPC_REFUSED is unchanged.
        let rfc1 = raven_core::friend_custody::encode_request(
            &[1; 8],
            &raven_core::friend_custody::Rfc1Request::Release {
                digests: vec![[2; 32]],
            },
        );
        let refused = refuse_custody_frames(IPC_VERSION, &[rfc1]);
        if raven_core::pair_init::lab_test_a_enabled() {
            assert!(refused.is_none());
        } else {
            assert!(
                matches!(refused, Some(IpcResponse::Error { ref code, .. }) if code == "CUSTODY_IPC_REFUSED"),
                "{refused:?}"
            );
        }
        assert!(refuse_custody_frames(IPC_VERSION, &[b"plain".to_vec()]).is_none());
    }

    #[test]
    fn enqueue_sealed_never_seals_app_payload() {
        use base64::Engine;
        let dir = tempfile::tempdir().unwrap();
        let req = IpcRequest::EnqueueSealed {
            v: IPC_VERSION,
            envelope_b64: base64::engine::general_purpose::STANDARD.encode(b"not-a-raven-envelope"),
            peer_hint: Some("peer".into()),
        };
        let resp = handle_req(req, dir.path(), &None);
        match resp {
            IpcResponse::Error { code, .. } => {
                assert_eq!(code, "IPC_BAD_ENVELOPE");
            }
            other => panic!("EnqueueSealed must not seal app bytes: {other:?}"),
        }
        assert!(
            !dir.path().join("queue.sqlite").exists(),
            "EnqueueSealed must not create an outbox from unsealed bytes"
        );
    }

    fn frame(req: &IpcRequest) -> Vec<u8> {
        raven_core::encode_request(req).unwrap()
    }

    fn shared(dir: &Path) -> (Arc<PathBuf>, Arc<Mutex<Option<ForwardQueue>>>) {
        (Arc::new(dir.to_path_buf()), Arc::new(Mutex::new(None)))
    }

    /// Phase 6a (P6.10, P6.11): through the socket's decoder, both learning
    /// ops are answered with the learning hold while the learning gate is
    /// shut, nothing is read or written, and `Status` carries no `learning`.
    /// With the gate open (`RAVEN_LAB_LEARNING=1` runs) they are answered
    /// (without a worker the plan has none) and `Status` has a row.
    #[test]
    fn learning_ops_answer_hold_while_the_gate_is_shut() {
        let dir = tempfile::tempdir().unwrap();
        let (dd, fq) = shared(dir.path());
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let live = raven_core::learning::learning_live();
        let key = "ab".repeat(32);
        for req in [
            IpcRequest::LearningPlan {
                v: IPC_VERSION,
                peer_pub_hex: key.clone(),
            },
            IpcRequest::LearningReset {
                v: IPC_VERSION,
                peer_pub_hex: Some(key.clone()),
            },
            IpcRequest::LearningReset {
                v: IPC_VERSION,
                peer_pub_hex: None,
            },
        ] {
            assert!(!needs_forward_queue(&req), "{req:?}");
            let resp = rt.block_on(dispatch(&frame(&req), &dd, &fq));
            if live {
                // Answered (a plan needs the worker's resolver, which these
                // tests do not run; there is no file to reset).
                assert!(
                    match &resp {
                        IpcResponse::Error { code, .. } => code != "LEARNING_HOLD",
                        IpcResponse::LearningReset { cleared, .. } => *cleared == 0,
                        _ => false,
                    },
                    "{req:?}: {resp:?}"
                );
                continue;
            }
            match resp {
                IpcResponse::Error { code, message, .. } => {
                    assert_eq!(code, "LEARNING_HOLD", "{req:?}");
                    assert_eq!(message, raven_core::learning::LEARNING_HOLD);
                }
                other => panic!("{req:?}: {other:?}"),
            }
        }
        // Another IPC version is refused before the op is looked at.
        let wrong = br#"{"op":"learning_reset","v":2}"#;
        let mut framed = (wrong.len() as u32).to_be_bytes().to_vec();
        framed.extend_from_slice(wrong);
        assert!(matches!(
            rt.block_on(dispatch(&framed, &dd, &fq)),
            IpcResponse::Error { ref code, .. } if code == "IPC_VERSION"
        ));
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            0,
            "nothing written"
        );
        match handle_req(IpcRequest::status(), dir.path(), &None) {
            IpcResponse::Status { learning, .. } => {
                assert_eq!(learning.is_some(), live, "{learning:?}")
            }
            other => panic!("{other:?}"),
        }
    }

    /// Phase 5 (P5.25, P5.27): through the socket's decoder, with the
    /// nearby gate closed a nearby dial or control is answered with the hold:
    /// nothing is dialled, and nothing is written (not even the ask-once
    /// consent). With the lab gate open and no engine: a dial for an
    /// unverified contact is refused before any radio work, `status` answers
    /// (radio off), `on` / `off` / `foreground` say nearby is not running and
    /// `enable` / `disable` write only the consent.
    #[test]
    fn nearby_ops_answer_the_hold_and_change_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (dd, fq) = shared(dir.path());
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let key = "ab".repeat(32);
        if raven_core::nearby_live_enabled() {
            let ask = |action: &str| {
                let req = IpcRequest::NearbyControl {
                    v: IPC_VERSION,
                    action: action.into(),
                    peer_pub_hex: Some(key.clone()),
                    ttl_secs: None,
                };
                rt.block_on(dispatch(&frame(&req), &dd, &fq))
            };
            for action in ["on", "off", "foreground"] {
                assert!(
                    matches!(ask(action), IpcResponse::Error { ref code, .. } if code == "NEARBY_NOT_RUNNING"),
                    "{action}"
                );
            }
            let IpcResponse::NearbyControlResult { status, .. } = ask("status") else {
                panic!("status")
            };
            assert!(status.gate_live && !status.enabled);
            assert_eq!((status.radio.as_str(), status.pipes), ("off", 0));
            let dial = IpcRequest::NearbyDial {
                v: IPC_VERSION,
                nearby_dial: raven_core::outbox::nearby_dial_for(&[0xab; 32]),
                expected_pub_hex: key.clone(),
                frames_b64: vec!["QUJD".into()],
            };
            let IpcResponse::Error { message, .. } = rt.block_on(dispatch(&frame(&dial), &dd, &fq))
            else {
                panic!("refused")
            };
            assert!(
                message.starts_with(raven_core::CONTACT_NOT_VERIFIED),
                "{message}"
            );
            assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
            let IpcResponse::NearbyControlResult { status, .. } = ask("enable") else {
                panic!("enable")
            };
            assert!(status.enabled);
            assert_eq!(
                raven_core::node_policy::nearby_settings(dir.path()),
                (true, false)
            );
            let IpcResponse::NearbyControlResult { status, .. } = ask("disable") else {
                panic!("disable")
            };
            assert!(!status.enabled);
            // OD-C8: background mail is its own setting; nearby stays off.
            let IpcResponse::NearbyControlResult { status, .. } = ask("background_on") else {
                panic!("background_on")
            };
            assert!(status.background_mail && !status.enabled);
            assert_eq!(
                raven_core::node_policy::nearby_settings(dir.path()),
                (false, true)
            );
            let IpcResponse::NearbyControlResult { status, .. } = ask("background_off") else {
                panic!("background_off")
            };
            assert!(!status.background_mail);
            assert_eq!(
                raven_core::node_policy::nearby_settings(dir.path()),
                (false, false)
            );
            return;
        }
        let want = "NEARBY_HOLD";
        let dial = IpcRequest::NearbyDial {
            v: IPC_VERSION,
            nearby_dial: raven_core::outbox::nearby_dial_for(&[0xab; 32]),
            expected_pub_hex: key.clone(),
            frames_b64: vec!["QUJD".into()],
        };
        let controls =
            raven_core::ipc::NEARBY_CONTROL_ACTIONS.map(|action| IpcRequest::NearbyControl {
                v: IPC_VERSION,
                action: action.into(),
                peer_pub_hex: Some(key.clone()),
                ttl_secs: Some(900),
            });
        for req in std::iter::once(dial).chain(controls) {
            match rt.block_on(dispatch(&frame(&req), &dd, &fq)) {
                IpcResponse::Error { code, message, .. } => {
                    assert_eq!(code, want, "{req:?}");
                    assert_eq!(message, raven_core::NEARBY_HOLD);
                }
                other => panic!("{req:?}: {other:?}"),
            }
        }
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            0,
            "nothing written"
        );
    }

    /// Regression: Ping was served under the forward-queue mutex, behind slow
    /// SealUnderSession / SQLite work, so a busy daemon looked dead.
    #[tokio::test]
    async fn ping_and_seal_do_not_wait_for_forward_queue_lock() {
        use base64::Engine;
        let dir = tempfile::tempdir().unwrap();
        let (dd, fq) = shared(dir.path());
        let _held = fq.lock().await;
        let pong = tokio::time::timeout(
            Duration::from_secs(5),
            dispatch(&frame(&IpcRequest::Ping { v: IPC_VERSION }), &dd, &fq),
        )
        .await
        .expect("Ping must not wait for the queue lock");
        assert_eq!(pong, IpcResponse::Pong { v: IPC_VERSION });
        let seal = IpcRequest::SealUnderSession {
            v: IPC_VERSION,
            peer_hint: "ab".repeat(32),
            app_payload_b64: base64::engine::general_purpose::STANDARD.encode(b"hi"),
        };
        let resp = tokio::time::timeout(Duration::from_secs(10), dispatch(&frame(&seal), &dd, &fq))
            .await
            .expect("SealUnderSession must not wait for the queue lock");
        assert!(
            matches!(resp, IpcResponse::Error { ref code, .. } if code == ATSAM_SESSION_REQUIRED)
        );
    }

    /// Lock v2 (P6.40): with the gate shut `Lock` and `Unlock` answer
    /// `LOCK_V2_HELD` and `Status` has no `locked` (an older daemon's
    /// `IPC_FRAME` is ash's other fallback to v1). With it live a locked node
    /// answers `Ping`, a `Status` that says so and holds nothing else, and
    /// `LOCKED` to every other request, until `Unlock`; a passphrase that is
    /// not base64 is refused without being quoted.
    #[test]
    fn a_locked_node_serves_only_ping_status_lock_and_unlock() {
        use raven_core::security_gate::{set_lab_for_this_thread, SecGate};
        let _state = crate::lan_direct::listener_state_test_lock();
        let dir = tempfile::tempdir().unwrap();
        let (dd, fq) = shared(dir.path());
        let error_code = |resp: IpcResponse| match resp {
            IpcResponse::Error { code, message, .. } => (code, message),
            other => panic!("{other:?}"),
        };
        let lock = frame(&IpcRequest::Lock { v: IPC_VERSION });
        let unlock = |passphrase: Option<&str>| {
            frame(&IpcRequest::Unlock {
                v: IPC_VERSION,
                passphrase_b64: passphrase.map(|p| raven_core::ipc::IpcSecret::new(p.into())),
            })
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            set_lab_for_this_thread(SecGate::LocalProtection, Some(false));
            let (code, _) = error_code(dispatch(&lock, &dd, &fq).await);
            assert_eq!(code, raven_core::ipc::LOCK_V2_HELD);
            let (code, _) = error_code(dispatch(&unlock(None), &dd, &fq).await);
            assert_eq!(code, raven_core::ipc::LOCK_V2_HELD);
            assert!(matches!(
                handle_req(IpcRequest::status(), dir.path(), &None),
                IpcResponse::Status { locked: None, .. }
            ));

            set_lab_for_this_thread(SecGate::LocalProtection, Some(true));
            assert!(matches!(
                handle_req(IpcRequest::status(), dir.path(), &None),
                IpcResponse::Status {
                    locked: Some(false),
                    ..
                }
            ));
            assert_eq!(
                dispatch(&lock, &dd, &fq).await,
                IpcResponse::LockState {
                    v: IPC_VERSION,
                    locked: true,
                    passphrase: false,
                    failed_unlocks: 0
                }
            );
            assert_eq!(
                dispatch(&frame(&IpcRequest::Ping { v: IPC_VERSION }), &dd, &fq).await,
                IpcResponse::Pong { v: IPC_VERSION }
            );
            match dispatch(&frame(&IpcRequest::status()), &dd, &fq).await {
                IpcResponse::Status {
                    locked,
                    capabilities,
                    pid,
                    lan_listen,
                    at_rest,
                    last_paths,
                    ..
                } => {
                    assert_eq!(locked, Some(true));
                    assert_eq!(capabilities, ["ipc"]);
                    assert_eq!(pid, Some(std::process::id()));
                    assert!(lan_listen.is_none() && at_rest.is_none() && last_paths.is_empty());
                }
                other => panic!("{other:?}"),
            }
            for req in [
                IpcRequest::OutboxList {
                    v: IPC_VERSION,
                    peer_pub_hex: None,
                    limit: None,
                },
                IpcRequest::SetLan {
                    v: IPC_VERSION,
                    on: false,
                    until_ms: None,
                },
                IpcRequest::LanDial {
                    v: IPC_VERSION,
                    lan_dial: "127.0.0.1:9".into(),
                    expected_pub_hex: "ab".repeat(32),
                    frames_b64: Vec::new(),
                },
            ] {
                let (code, message) = error_code(dispatch(&frame(&req), &dd, &fq).await);
                assert_eq!(code, raven_core::ipc::LOCKED, "{req:?}");
                assert_eq!(message, LOCKED_MESSAGE);
            }
            let (code, message) =
                error_code(dispatch(&unlock(Some("%%not base64%%")), &dd, &fq).await);
            assert_eq!(code, "IPC_FRAME");
            assert!(!message.contains("not base64%%"), "{message}");
            assert!(crate::lock::is_locked());
            assert_eq!(
                dispatch(&unlock(None), &dd, &fq).await,
                IpcResponse::LockState {
                    v: IPC_VERSION,
                    locked: false,
                    passphrase: false,
                    failed_unlocks: 0
                }
            );
            assert!(!crate::lock::is_locked());
            let after = dispatch(
                &frame(&IpcRequest::OutboxList {
                    v: IPC_VERSION,
                    peer_pub_hex: None,
                    limit: None,
                }),
                &dd,
                &fq,
            )
            .await;
            assert!(
                !matches!(&after, IpcResponse::Error { code, .. } if code == raven_core::ipc::LOCKED),
                "{after:?}"
            );
            set_lab_for_this_thread(SecGate::LocalProtection, None);
        });
    }

    /// Regression: base64 values containing a denylisted token were refused
    /// with IPC_FORBIDDEN_FIELD.
    #[tokio::test]
    async fn payload_values_with_secret_words_reach_the_handler() {
        let dir = tempfile::tempdir().unwrap();
        let (dd, fq) = shared(dir.path());
        let req = IpcRequest::EnqueueSealed {
            v: IPC_VERSION,
            envelope_b64: "c2VlZHNlZWRzZWVk".into(), // "seedseedseed", not an envelope
            peer_hint: Some("seed-peer".into()),
        };
        match dispatch(&frame(&req), &dd, &fq).await {
            IpcResponse::Error { code, .. } => assert_eq!(code, "IPC_BAD_ENVELOPE"),
            other => panic!("unexpected {other:?}"),
        }
        let body = br#"{"op":"ping","v":1,"seed":"x"}"#;
        let mut raw = (body.len() as u32).to_be_bytes().to_vec();
        raw.extend_from_slice(body);
        match dispatch(&raw, &dd, &fq).await {
            IpcResponse::Error { code, .. } => assert_eq!(code, "IPC_FORBIDDEN_FIELD"),
            other => panic!("secret key must be refused: {other:?}"),
        }
    }

    /// Regression: an oversized response was silently dropped (client saw EOF
    /// after the side effects had happened).
    #[test]
    fn oversized_response_becomes_explicit_error() {
        let resp = IpcResponse::LanDialResult {
            v: IPC_VERSION,
            frames_b64: vec!["A".repeat(MAX_IPC_FRAME)],
        };
        let out = encode_response_or_error(&resp);
        match raven_core::decode_response(&out).unwrap() {
            IpcResponse::Error { code, message, .. } => {
                assert_eq!(code, "IPC_FRAME");
                assert!(message.contains("too large"), "{message}");
            }
            other => panic!("expected explicit error, got {other:?}"),
        }
    }

    #[test]
    fn seal_rejects_malformed_peer_hint_before_identity_work() {
        let dir = tempfile::tempdir().unwrap();
        let req = IpcRequest::SealUnderSession {
            v: IPC_VERSION,
            peer_hint: "not-hex".into(),
            app_payload_b64: "aGk=".into(),
        };
        match handle_req(req, dir.path(), &None) {
            IpcResponse::Error { code, .. } => assert_eq!(code, "SEAL_PEER_HINT"),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[cfg(unix)]
    async fn wait_for_ping(sock: &Path) -> IpcResponse {
        for _ in 0..200 {
            if let Ok(r) = client_ping(sock).await {
                return r;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("no IPC server at {}", sock.display());
    }

    /// Regression: a second `ipc`/`service` unlinked the live daemon's socket.
    #[cfg(unix)]
    #[tokio::test]
    async fn second_server_never_steals_live_socket() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        let first = tokio::spawn(run_uds_server(data.clone(), None));
        let sock = socket_path(&data);
        assert_eq!(
            wait_for_ping(&sock).await,
            IpcResponse::Pong { v: IPC_VERSION }
        );
        let before = socket_identity(&sock);

        let err = tokio::time::timeout(Duration::from_secs(5), run_uds_server(data.clone(), None))
            .await
            .expect("second server fails fast")
            .unwrap_err();
        assert!(err.contains("already") || err.contains("lock"), "{err}");
        assert_eq!(
            socket_identity(&sock),
            before,
            "live socket must not be replaced"
        );
        assert_eq!(
            client_ping(&sock).await.unwrap(),
            IpcResponse::Pong { v: IPC_VERSION }
        );

        let sock_mode = std::fs::symlink_metadata(&sock)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(sock_mode & 0o777, 0o600);
        let dir_mode = std::fs::metadata(&data).unwrap().permissions().mode();
        assert_eq!(dir_mode & 0o777, 0o700, "fresh data dir is private");
        first.abort();
    }

    /// Stale socket (daemon crashed) is replaced; a non-socket is not touched.
    #[cfg(unix)]
    #[tokio::test]
    async fn stale_socket_is_replaced_but_regular_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().to_path_buf();
        let sock = socket_path(&data);
        drop(std::os::unix::net::UnixListener::bind(&sock).unwrap());
        assert!(sock.exists(), "stale socket left behind");
        let server = tokio::spawn(run_uds_server(data.clone(), None));
        assert_eq!(
            wait_for_ping(&sock).await,
            IpcResponse::Pong { v: IPC_VERSION }
        );
        server.abort();
        let _ = server.await;

        let other = tempfile::tempdir().unwrap();
        let sock = socket_path(other.path());
        std::fs::write(&sock, b"not a socket").unwrap();
        let err = run_uds_server(other.path().to_path_buf(), None)
            .await
            .unwrap_err();
        assert!(err.contains("not a socket"), "{err}");
        assert_eq!(std::fs::read(&sock).unwrap(), b"not a socket");
    }

    /// If the socket path is unlinked under a running daemon (e.g. by a client
    /// "cleaning up"), the lock holder re-publishes it instead of running orphaned.
    #[cfg(unix)]
    #[tokio::test]
    async fn unlinked_socket_is_republished() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().to_path_buf();
        let server = tokio::spawn(run_uds_server(data.clone(), None));
        let sock = socket_path(&data);
        wait_for_ping(&sock).await;
        std::fs::remove_file(&sock).unwrap();
        assert_eq!(
            wait_for_ping(&sock).await,
            IpcResponse::Pong { v: IPC_VERSION }
        );
        server.abort();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn world_writable_data_dir_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("open");
        std::fs::create_dir(&data).unwrap();
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o777)).unwrap();
        let err = run_uds_server(data.clone(), None).await.unwrap_err();
        assert!(err.contains("world-writable"), "{err}");
        assert!(!socket_path(&data).exists());
    }

    /// Review residual (node-swarm#17): a group-writable data dir let group
    /// members replace the socket. It is tightened (not refused, since umask
    /// 002 creates such dirs by default) before the socket is published.
    #[cfg(unix)]
    #[test]
    fn group_writable_data_dir_is_tightened() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("shared");
        std::fs::create_dir(&data).unwrap();
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o775)).unwrap();
        ensure_private_data_dir(&data).expect("owned group-writable dir is tightened");
        let mode = std::fs::metadata(&data).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755, "group write removed, nothing else changed");
        // Already private: untouched.
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700)).unwrap();
        ensure_private_data_dir(&data).unwrap();
        let mode = std::fs::metadata(&data).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    /// The "no profile could be determined" placeholder is refused before anything
    /// is created under it.
    #[cfg(unix)]
    #[test]
    fn unresolved_profile_placeholder_is_never_created() {
        let placeholder = raven_core::resolve_raven_data_dir(None, None, None);
        assert!(raven_core::paths::is_unresolved_data_dir(&placeholder));
        let err = ensure_private_data_dir(&placeholder).unwrap_err();
        assert!(
            err.contains("cannot determine the Raven data directory"),
            "{err}"
        );
    }

    /// Regression: moving IPC ops off the forward-queue mutex also removed
    /// the serialization of `SetPolicy` (load, modify, truncate + write).
    /// Concurrent updates to different fields must all survive, and `Status`
    /// must never observe a half-written policy file.
    #[test]
    fn concurrent_set_policy_and_status_are_serialized() {
        let dir = tempfile::tempdir().unwrap();
        let set = |bridge: Option<bool>, store: Option<bool>, relay: Option<bool>| {
            IpcRequest::SetPolicy {
                v: IPC_VERSION,
                bridge,
                store,
                relay,
            }
        };
        for _round in 0..40 {
            let reset = handle_req(
                set(Some(false), Some(false), Some(false)),
                dir.path(),
                &None,
            );
            assert!(matches!(reset, IpcResponse::Accepted { .. }));
            let barrier = std::sync::Barrier::new(3);
            std::thread::scope(|scope| {
                for update in [
                    set(Some(true), None, None),
                    set(None, Some(true), None),
                    set(None, None, Some(true)),
                ] {
                    let barrier = &barrier;
                    let data_dir = dir.path();
                    scope.spawn(move || {
                        barrier.wait();
                        let resp = handle_req(update, data_dir, &None);
                        assert!(matches!(resp, IpcResponse::Accepted { .. }), "{resp:?}");
                    });
                }
            });
            let policy = load_policy(dir.path());
            assert!(
                policy.bridge && policy.store && policy.relay,
                "lost policy update: {policy:?}"
            );
        }

        // Non-default policy; a torn read would parse as the defaults.
        let resp = handle_req(set(Some(false), Some(false), Some(true)), dir.path(), &None);
        assert!(matches!(resp, IpcResponse::Accepted { .. }));
        std::thread::scope(|scope| {
            scope.spawn(|| {
                for _ in 0..300 {
                    let resp = handle_req(set(None, None, Some(true)), dir.path(), &None);
                    assert!(matches!(resp, IpcResponse::Accepted { .. }));
                }
            });
            scope.spawn(|| {
                for _ in 0..300 {
                    match handle_req(IpcRequest::status(), dir.path(), &None) {
                        IpcResponse::Status {
                            bridge,
                            store,
                            relay,
                            ..
                        } => assert!(!bridge && !store && relay, "torn policy read"),
                        other => panic!("{other:?}"),
                    }
                }
            });
        });
    }

    /// Privacy pack PP.6: SetPolicy changes node_policy.json's settings
    /// alone, so in a sealed profile it works before the at-rest key is
    /// loaded, and the relay addresses in the sealed sidecar stay.
    #[test]
    fn set_policy_works_before_the_key_and_keeps_the_relay_sidecar() {
        let lab = ["RAVEN_CHAT_HISTORY_BACKEND", "RAVEN_IDENTITY_BACKEND"]
            .iter()
            .any(|k| std::env::var(k).is_ok_and(|v| v == "locked-file"));
        if !(cfg!(windows) || (cfg!(debug_assertions) && lab)) {
            eprintln!("skipped: needs a debug build and RAVEN_CHAT_HISTORY_BACKEND=locked-file");
            return;
        }
        use raven_core::at_rest::{self, MigratePolicy};
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        std::fs::write(dd.join(raven_core::BACKEND_MARKER_NAME), b"locked-file\n").unwrap();
        let sealed =
            raven_core::privacy::migrate_all(dd, crate::now_ms(), MigratePolicy::Allow).unwrap();
        assert_eq!(sealed.outcome, raven_core::privacy::MigrateOutcome::Sealed);
        let relay = format!(
            "/ip4/198.51.100.7/tcp/7423/p2p/{}",
            raven_core::p2p_route::local_peer_id(&raven_core::Identity::from_seed(&[4; 32]))
        );
        raven_core::node_policy::save_policy(
            dd,
            &raven_core::NodePolicy {
                p2p_relays: vec![relay.clone()],
                ..raven_core::NodePolicy::default()
            },
        )
        .unwrap();
        let sidecar_path = raven_core::node_policy::policy_peers_path(dd);
        let sidecar = std::fs::read(&sidecar_path).unwrap();
        at_rest::forget_cached_keys(dd);
        let resp = handle_req(
            IpcRequest::SetPolicy {
                v: IPC_VERSION,
                bridge: Some(false),
                store: None,
                relay: None,
            },
            dd,
            &None,
        );
        assert!(matches!(resp, IpcResponse::Accepted { .. }), "{resp:?}");
        assert_eq!(std::fs::read(&sidecar_path).unwrap(), sidecar);
        let plain = std::fs::read_to_string(raven_core::policy_path(dd)).unwrap();
        assert!(plain.contains(r#""bridge": false"#) && !plain.contains("p2p_relays"));
        at_rest::keys_load_with(dd, MigratePolicy::Allow).unwrap();
        let policy = load_policy(dd);
        assert!(!policy.bridge && !policy.auto_policy);
        assert_eq!(policy.p2p_relays, [relay]);
    }

    #[test]
    fn seal_under_session_refuses_without_session() {
        use base64::Engine;
        let dir = tempfile::tempdir().unwrap();
        let req = IpcRequest::SealUnderSession {
            v: IPC_VERSION,
            peer_hint: "ab".repeat(32),
            app_payload_b64: base64::engine::general_purpose::STANDARD.encode(b"hello"),
        };
        let resp = handle_req(req, dir.path(), &None);
        match resp {
            IpcResponse::Error { code, message, .. } => {
                assert_eq!(code, ATSAM_SESSION_REQUIRED);
                assert!(
                    !message.contains(ATSAM_LINEAGE_REVOKED),
                    "missing session must not report revoke: {message}"
                );
            }
            other => panic!("expected ATSAM_SESSION_REQUIRED, got {other:?}"),
        }
    }

    /// Raven's clock, as the code under test reads it (the suite may run on
    /// a lab clock).
    fn wall_ms() -> u64 {
        raven_core::clock::now_ms()
    }

    /// An envelope custody admits: sealed indexed-session shape, valid now.
    fn sealed_envelope(id: u8, body: Vec<u8>) -> Vec<u8> {
        use raven_core::envelope::{EnvType, Envelope};
        Envelope {
            env_type: EnvType::Message as u8,
            flags: 0,
            message_id: [id; 16],
            routing_tag: [0x44; 16],
            dest_device_hint: 0,
            created_at: wall_ms(),
            expires_at: wall_ms() + 60 * 60 * 1000,
            hop_limit: 4,
            replication_budget: 1,
            anti_replay_nonce: [0x55; 12],
            ratchet_header_ciphertext: vec![],
            message_ciphertext: body,
            sender_authentication: vec![0u8; 64],
        }
        .pack()
    }

    fn sealed_envelope_b64(id: u8) -> String {
        use raven_core::carrier_admission::{opaque_indexed_body_for_tests, RelayableKind};
        b64_encode(&sealed_envelope(
            id,
            opaque_indexed_body_for_tests(RelayableKind::Message, &[id; 32]),
        ))
    }

    /// F3: `EnqueueSealed` feeds the bridge custody queue and the legacy
    /// outbox, so a wrapped PairInit or a plaintext body is refused before
    /// either queue exists.
    #[test]
    fn enqueue_sealed_refuses_pairing_and_plaintext_before_custody() {
        use raven_core::pair_init::{INIT_MAGIC, INIT_WIRE_LEN};
        let dir = tempfile::tempdir().unwrap();
        let mut init = INIT_MAGIC.to_vec();
        init.resize(INIT_WIRE_LEN, 0x01);
        for body in [init, b"plaintext hello".to_vec()] {
            let req = IpcRequest::EnqueueSealed {
                v: IPC_VERSION,
                envelope_b64: b64_encode(&sealed_envelope(7, body)),
                peer_hint: Some("peer".into()),
            };
            match handle_req(req, dir.path(), &None) {
                IpcResponse::Error { code, .. } => assert_eq!(code, "IPC_NOT_RELAYABLE"),
                other => panic!("must be refused: {other:?}"),
            }
        }
        assert!(!dir.path().join("queue.sqlite").exists());
        match handle_req(enqueue_req(8), dir.path(), &None) {
            IpcResponse::Accepted { .. } => {}
            other => panic!("a sealed object is accepted: {other:?}"),
        }
    }

    fn enqueue_req(id: u8) -> IpcRequest {
        IpcRequest::EnqueueSealed {
            v: IPC_VERSION,
            envelope_b64: sealed_envelope_b64(id),
            peer_hint: Some("peer".into()),
        }
    }

    /// Regression: a forward queue that failed to open was swallowed (`.ok()`),
    /// so the server ran on, answered `EnqueueSealed` with `Accepted` for
    /// envelopes the bridge never saw, and `Status` hid every capability.
    /// Now the server refuses to start, before it publishes its socket.
    #[cfg(unix)]
    #[tokio::test]
    async fn unopenable_forward_queue_stops_the_server_before_the_socket_exists() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        std::fs::create_dir_all(&data).unwrap();
        let bad = data.join("forward_queue.sqlite");
        std::fs::write(
            &bad,
            b"not a database, but long enough to be read as one ................",
        )
        .unwrap();
        let err = run_uds_server(data.clone(), Some(bad)).await.unwrap_err();
        assert!(err.contains("forward queue"), "{err}");
        assert!(err.contains("forward_queue.sqlite"), "{err}");
        assert!(
            !socket_path(&data).exists(),
            "no endpoint for a daemon that cannot serve"
        );
        // No path configured is the legitimate no-bridge setup.
        assert!(open_forward_queue(None).unwrap().lock().await.is_none());
    }

    /// Regression: with the forward queue absent `Status` reported only
    /// `["ipc"]`; transport capabilities are independent of it, and the
    /// bridge ones follow the bridge actually running.
    #[test]
    fn status_capabilities_follow_the_bridge_not_just_the_queue() {
        // No LAN listener of another test may show up in these capabilities.
        let _state = crate::lan_direct::listener_state_test_lock();
        let dir = tempfile::tempdir().unwrap();
        let set = IpcRequest::SetPolicy {
            v: IPC_VERSION,
            bridge: Some(true),
            store: Some(true),
            relay: Some(true),
        };
        assert!(matches!(
            handle_req(set, dir.path(), &None),
            IpcResponse::Accepted { .. }
        ));
        let queue = ForwardQueue::open(&dir.path().join("forward_queue.sqlite")).unwrap();
        let caps =
            |fwd: &Option<ForwardQueue>| match handle_req(IpcRequest::status(), dir.path(), fwd) {
                IpcResponse::Status { capabilities, .. } => capabilities,
                other => panic!("{other:?}"),
            };
        let fwd = Some(queue);
        assert_eq!(caps(&fwd), ["ipc", "bridge", "store", "relay"]);
        crate::BRIDGE_DEGRADED.store(true, std::sync::atomic::Ordering::Relaxed);
        let degraded = caps(&fwd);
        crate::BRIDGE_DEGRADED.store(false, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            degraded,
            ["ipc"],
            "a bridge that is not running is not advertised"
        );
        assert_eq!(caps(&None), ["ipc"], "no queue, no bridge");
    }

    /// Phase 2 (P2.21): `p2p_friend_relay` is advertised only while the
    /// friend relay is up, with or without the p2p host; consent alone, a
    /// closed gate, a start or a failure is not enough. `p2p` and
    /// `p2p_relay` follow the host as before.
    #[test]
    fn capability_p2p_friend_relay_only_while_up() {
        use raven_core::ipc::{FriendRelayInfo, P2pStatusInfo, RelayCounts};
        let friend = |state: &str| {
            Some(FriendRelayInfo {
                state: state.into(),
                consent: "yes".into(),
                ..FriendRelayInfo::default()
            })
        };
        let info = |up: bool, friend_relay: Option<FriendRelayInfo>| P2pStatusInfo {
            up,
            friend_relay,
            ..P2pStatusInfo::default()
        };
        assert!(p2p_capabilities(None).is_empty());
        assert!(p2p_capabilities(Some(&info(false, None))).is_empty());
        assert_eq!(p2p_capabilities(Some(&info(true, None))), ["p2p"]);
        assert_eq!(
            p2p_capabilities(Some(&info(true, friend("up")))),
            ["p2p", "p2p_friend_relay"]
        );
        assert_eq!(
            p2p_capabilities(Some(&info(false, friend("up")))),
            ["p2p_friend_relay"],
            "the friend relay runs without the host"
        );
        for state in ["off", "held", "starting", "failed", ""] {
            assert_eq!(
                p2p_capabilities(Some(&info(true, friend(state)))),
                ["p2p"],
                "{state}"
            );
        }
        let profile_role = P2pStatusInfo {
            relay: Some(RelayCounts::default()),
            ..info(true, friend("up"))
        };
        assert_eq!(
            p2p_capabilities(Some(&profile_role)),
            ["p2p", "p2p_relay", "p2p_friend_relay"]
        );
    }

    /// P3.14: `session_renewal` is advertised only while renewal is live (the
    /// lab switch, in a debug build) and the renewer runs. IPC_VERSION is
    /// unchanged: one more string in an existing list.
    #[test]
    fn session_renewal_capability_needs_the_switch_and_the_renewer() {
        use raven_core::session_renewal::set_lab_session_renewal_for_this_thread as switch;
        let dir = tempfile::tempdir().unwrap();
        let has = || match handle_req(IpcRequest::status(), dir.path(), &None) {
            IpcResponse::Status { capabilities, .. } => {
                capabilities.contains(&"session_renewal".to_string())
            }
            other => panic!("{other:?}"),
        };
        switch(Some(false));
        assert!(!has());
        {
            let _renewer = crate::renewal::RunningForTest::set();
            assert!(!has(), "the renewer runs, the switch is off");
            switch(Some(true));
            assert_eq!(has(), cfg!(debug_assertions), "both");
        }
        assert!(!has(), "the switch on, no renewer");
        switch(None);
    }

    /// `Status` names this process (so `ash listen` can advise stopping exactly
    /// it) and the LAN listener's address only while one is bound.
    #[test]
    fn status_names_this_process() {
        let _state = crate::lan_direct::listener_state_test_lock();
        let dir = tempfile::tempdir().unwrap();
        match handle_req(IpcRequest::status(), dir.path(), &None) {
            IpcResponse::Status {
                pid,
                lan_listen,
                capabilities,
                ..
            } => {
                assert_eq!(pid, Some(std::process::id()));
                assert_eq!(lan_listen, None, "no listener runs");
                assert!(!capabilities.contains(&"lan_direct".to_string()));
            }
            other => panic!("{other:?}"),
        }
        // A bind that failed is named by its address and kind (CP.5), and
        // forgotten once the listener is up.
        let bind_fields = || match handle_req(IpcRequest::status(), dir.path(), &None) {
            IpcResponse::Status {
                lan_listen_wanted,
                lan_bind_error,
                ..
            } => (lan_listen_wanted, lan_bind_error),
            other => panic!("{other:?}"),
        };
        crate::lan_direct::record_bind_error(
            "192.0.2.10:7499",
            raven_core::ipc::LAN_BIND_ADDR_NOT_HERE,
        );
        assert_eq!(
            bind_fields(),
            (
                Some("192.0.2.10:7499".to_string()),
                Some("addr_not_here".to_string())
            )
        );
        let up = crate::lan_direct::listener_bound("127.0.0.1:7531".parse().unwrap());
        assert_eq!(bind_fields(), (None, None));
        drop(up);
    }

    /// Phase 3 P3.5: `SetLan` turns LAN off and on in the running node at
    /// once (its listener's switch and raven-core's, which LAN dials and
    /// custody links read) and `Status.lan` says so. node_policy.json is
    /// ash's: SetLan reads and writes nothing.
    #[test]
    fn set_lan_applies_live() {
        let _state = crate::lan_direct::listener_state_test_lock();
        let _lan = crate::lan_direct::lan_switch_for_test();
        let _plan = crate::lan_direct::plan_for_test("auto", false);
        let dir = tempfile::tempdir().unwrap();
        let mode = || match handle_req(IpcRequest::status(), dir.path(), &None) {
            IpcResponse::Status { lan, .. } => lan.map(|row| row.mode),
            other => panic!("{other:?}"),
        };
        let set = |on: bool| {
            handle_req(
                IpcRequest::SetLan {
                    v: IPC_VERSION,
                    on,
                    until_ms: None,
                },
                dir.path(),
                &None,
            )
        };
        assert_eq!(mode().as_deref(), Some(raven_core::ipc::LAN_MODE_ON));
        for on in [false, true, true, false, true] {
            assert_eq!(
                set(on),
                IpcResponse::LanSet {
                    v: IPC_VERSION,
                    on,
                    applied: true,
                    until_ms: None,
                }
            );
            assert_eq!(crate::lan_direct::lan_on(), on);
            assert_eq!(raven_core::lan_user_off(), !on);
            assert_eq!(
                raven_core::lan_usable_now(),
                on && raven_core::lan_direct_live_enabled()
            );
            let want = if on {
                raven_core::ipc::LAN_MODE_ON
            } else {
                raven_core::ipc::LAN_MODE_OFF
            };
            assert_eq!(mode().as_deref(), Some(want));
        }
        assert!(!dir.path().join("node_policy.json").exists());
        // Through the socket's decoder too, and a wrong version is refused.
        let (dd, fq) = shared(dir.path());
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let frame_off = frame(&IpcRequest::SetLan {
            v: IPC_VERSION,
            on: false,
            until_ms: None,
        });
        assert!(matches!(
            rt.block_on(dispatch(&frame_off, &dd, &fq)),
            IpcResponse::LanSet {
                on: false,
                applied: true,
                ..
            }
        ));
        assert!(!crate::lan_direct::lan_on());
        let body = br#"{"op":"set_lan","v":2,"on":true}"#;
        let mut raw = (body.len() as u32).to_be_bytes().to_vec();
        raw.extend_from_slice(body);
        match rt.block_on(dispatch(&raw, &dd, &fq)) {
            IpcResponse::Error { code, .. } => assert_eq!(code, "IPC_VERSION"),
            other => panic!("{other:?}"),
        }
        assert!(
            !crate::lan_direct::lan_on(),
            "a refused request changes nothing"
        );
    }

    /// Phase 3 P3.C2: `SetLan` with a meeting time (`raven lan on --for`)
    /// turns LAN on until then and says which time it holds; one already
    /// past turns it off; `on` without a time drops it; `off` holds none.
    /// Nothing is read or written (ash saved the time).
    #[test]
    fn set_lan_with_a_meeting_time_holds_it_and_says_so() {
        let _state = crate::lan_direct::listener_state_test_lock();
        let _lan = crate::lan_direct::lan_switch_for_test();
        let dir = tempfile::tempdir().unwrap();
        let set = |on: bool, until_ms: Option<u64>| {
            handle_req(
                IpcRequest::SetLan {
                    v: IPC_VERSION,
                    on,
                    until_ms,
                },
                dir.path(),
                &None,
            )
        };
        let now = raven_core::clock::now_ms();
        let soon = now + 30 * 60_000;
        let told = |on: bool, until_ms: Option<u64>| IpcResponse::LanSet {
            v: IPC_VERSION,
            on,
            applied: true,
            until_ms,
        };
        assert_eq!(set(true, Some(soon)), told(true, Some(soon)));
        assert!(crate::lan_direct::lan_on());
        assert!(!raven_core::lan_user_off());
        assert_eq!(set(true, Some(now - 1)), told(true, Some(now - 1)));
        assert!(!crate::lan_direct::lan_on(), "a time already past is off");
        assert!(raven_core::lan_user_off());
        assert_eq!(set(true, None), told(true, None));
        assert!(crate::lan_direct::lan_on());
        assert_eq!(set(false, Some(soon)), told(false, None));
        assert!(!crate::lan_direct::lan_on());
        assert_eq!(set(true, None), told(true, None));
        assert!(crate::lan_direct::lan_on());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    /// Custody handoff (P5.21): an IPC LAN, Internet or p2p dial carrying a
    /// HANDOFF or a TAGS frame is refused (CUSTODY_IPC_REFUSED) outside the
    /// lab, before anything is dialled; with the lab unlock the frames are
    /// passed on like any other RFC1 frame (not dialled here).
    #[test]
    fn ipc_dials_refuse_handoff_and_tags_frames_outside_the_lab() {
        use raven_core::custody_handoff::{Rhw1, TagsAction};
        use raven_core::friend_custody::{encode_request, Rfc1Request};
        let _lan = crate::lan_direct::lan_switch_untouched();
        let dir = tempfile::tempdir().unwrap();
        let (dd, fq) = shared(dir.path());
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let handoff = encode_request(
            &[0xB0; 8],
            &Rfc1Request::Handoff {
                record: Rhw1::forward([9; 32], vec![0x5a; 300]),
            },
        );
        let tags = encode_request(
            &[0xA0; 8],
            &Rfc1Request::Tags {
                action: TagsAction::Register,
                entries: vec![([7; 16], 1_000)],
            },
        );
        let lab = raven_core::pair_init::lab_test_a_enabled();
        for frame_bytes in [handoff, tags] {
            if lab {
                assert!(refuse_custody_frames(IPC_VERSION, &[frame_bytes]).is_none());
                continue;
            }
            let frames_b64 = vec![b64_encode(&frame_bytes)];
            let expected_pub_hex = "ab".repeat(32);
            for req in [
                IpcRequest::LanDial {
                    v: IPC_VERSION,
                    lan_dial: "127.0.0.1:9".into(),
                    expected_pub_hex: expected_pub_hex.clone(),
                    frames_b64: frames_b64.clone(),
                },
                IpcRequest::InternetDial {
                    v: IPC_VERSION,
                    internet_dial: "127.0.0.1:9".into(),
                    expected_pub_hex: expected_pub_hex.clone(),
                    frames_b64: frames_b64.clone(),
                },
                IpcRequest::P2pDial {
                    v: IPC_VERSION,
                    multiaddr: "/ip4/127.0.0.1/tcp/9".into(),
                    expected_pub_hex: expected_pub_hex.clone(),
                    frames_b64: frames_b64.clone(),
                },
            ] {
                match rt.block_on(dispatch(&frame(&req), &dd, &fq)) {
                    IpcResponse::Error { code, .. } => {
                        assert_eq!(code, "CUSTODY_IPC_REFUSED", "{req:?}");
                    }
                    other => panic!("{other:?}"),
                }
            }
        }
    }

    /// While `raven lan off` is in effect an IPC LAN dial is refused with
    /// LAN_OFF before anything is decoded or dialled; once LAN is on again
    /// the same request reaches the dial's own checks.
    #[test]
    fn lan_dial_refused_with_lan_off() {
        let _lan = crate::lan_direct::lan_switch_for_test();
        let dir = tempfile::tempdir().unwrap();
        let (dd, fq) = shared(dir.path());
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        // Bad base64: the dial's first check, never reached while off.
        let req = IpcRequest::LanDial {
            v: IPC_VERSION,
            lan_dial: "127.0.0.1:9".into(),
            expected_pub_hex: "ab".repeat(32),
            frames_b64: vec!["not base64!".into()],
        };
        crate::lan_direct::set_lan_on(false);
        match rt.block_on(dispatch(&frame(&req), &dd, &fq)) {
            IpcResponse::Error { code, message, .. } => {
                assert_eq!(code, "LAN_OFF");
                assert_eq!(
                    message,
                    "LAN_OFF: raven lan off is in effect (raven lan on)"
                );
            }
            other => panic!("{other:?}"),
        }
        crate::lan_direct::set_lan_on(true);
        match rt.block_on(dispatch(&frame(&req), &dd, &fq)) {
            IpcResponse::Error { code, .. } => assert_eq!(code, "IPC_BAD_B64"),
            other => panic!("{other:?}"),
        }
    }

    /// `Status.lan`: absent while this process runs no LAN listener; then
    /// fixed words, the listener's own bound addresses, a flag and the LAN
    /// beacon's counts (Phase 3 step 10), how many contacts were seen here
    /// and whose address answered with another key (P3.C6: keys only, as
    /// the beacon's `no_answer`), nothing else (no other address).
    #[test]
    fn status_lan_fields_are_counts_and_listen_strings_only() {
        use raven_core::ipc::{
            BeaconCounts, LanStatus, LAN_MODE_FIXED, LAN_MODE_ON, LAN_MODE_THIS_COMPUTER,
        };
        let _state = crate::lan_direct::listener_state_test_lock();
        let _lan = crate::lan_direct::lan_switch_untouched();
        let dir = tempfile::tempdir().unwrap();
        let raw = || match handle_req(IpcRequest::status(), dir.path(), &None) {
            IpcResponse::Status { lan, .. } => lan,
            other => panic!("{other:?}"),
        };
        // Other tests in this process link and block (process-wide state):
        // the count is always there, and both are checked below.
        let lan = || {
            raw().map(|mut row| {
                assert!(row.friends_here_10m.is_some(), "{row:?}");
                row.friends_here_10m = None;
                row.pin_blocked.clear();
                row
            })
        };
        assert_eq!(lan(), None, "no LAN listener in this process");
        // No beacon task runs in a test: its gate's word, and no counts.
        let beacon = BeaconCounts {
            state: if raven_core::lan_beacon_live() {
                "starting"
            } else {
                "held"
            }
            .into(),
            ..BeaconCounts::default()
        };
        for (lan_listen, auto_live, mode, local_only) in [
            ("auto", true, LAN_MODE_ON, true),
            ("auto", false, LAN_MODE_ON, false),
            ("127.0.0.1:7531", true, LAN_MODE_THIS_COMPUTER, false),
            ("0.0.0.0:7531", false, LAN_MODE_FIXED, false),
        ] {
            let _plan = crate::lan_direct::plan_for_test(lan_listen, auto_live);
            assert_eq!(
                lan(),
                Some(LanStatus {
                    mode: mode.into(),
                    listen: Vec::new(),
                    local_only,
                    beacon: Some(Box::new(beacon.clone())),
                    ..LanStatus::default()
                }),
                "{lan_listen}"
            );
        }
        let _plan = crate::lan_direct::plan_for_test("auto", true);
        let up = crate::lan_direct::listeners_bound(vec![
            "[::]:7531".parse().unwrap(),
            "0.0.0.0:7531".parse().unwrap(),
        ]);
        let row = raw().expect("a LAN row");
        assert_eq!(row.listen, ["0.0.0.0:7531", "[::]:7531"]);
        let json = serde_json::to_value(&row).unwrap();
        let mut keys: Vec<&str> = json
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .filter(|k| *k != "pin_blocked")
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            ["beacon", "friends_here_10m", "listen", "local_only", "mode"]
        );
        assert!(json["friends_here_10m"].is_u64(), "{json}");
        let is_key = |k: &serde_json::Value| {
            k.as_str()
                .is_some_and(|k| k.len() == 64 && k.bytes().all(|b| b.is_ascii_hexdigit()))
        };
        assert!(row.pin_blocked.len() <= 8, "{json}");
        assert!(
            json.get("pin_blocked")
                .is_none_or(|b| b.as_array().unwrap().iter().all(is_key)),
            "{json}"
        );
        // The beacon's: a state word, counts and a flag; contact keys only
        // in `no_answer` (P3.C3), never an address.
        let counts = json["beacon"].as_object().unwrap();
        for (key, value) in counts {
            match key.as_str() {
                "state" => assert!(value.is_string()),
                "echo_ok" => assert!(value.is_boolean()),
                "no_answer" => assert!(value.as_array().unwrap().iter().all(|k| k
                    .as_str()
                    .is_some_and(|k| k.len() == 64 && k.bytes().all(|b| b.is_ascii_hexdigit())))),
                _ => assert!(value.is_u64(), "{key}: {value}"),
            }
        }
        for listen in &row.listen {
            let at: std::net::SocketAddr = listen.parse().unwrap();
            assert!(at.ip().is_unspecified() && at.port() == 7531, "{listen}");
        }
        drop(up);
        assert_eq!(raw().expect("a LAN row").listen, Vec::<String>::new());
    }

    /// `Status` lists how the last delivery to each contact travelled: a LAN
    /// dial that brought back a receipt shows up as the contact's key and
    /// labels only (no address).
    #[test]
    fn status_lists_the_last_paths() {
        use raven_core::envelope::EnvType;
        let dir = tempfile::tempdir().unwrap();
        let contact = [0x5C; 32];
        let message = crate::delivery_paths::tests::envelope(EnvType::Message);
        let ack = crate::delivery_paths::tests::envelope(EnvType::Ack);
        crate::delivery_paths::note(
            &contact,
            raven_core::OutboxCarrier::Lan,
            Some(raven_core::outbox::DeliveryPath::Direct),
            &[message],
            &[ack],
        );
        let IpcResponse::Status { last_paths, .. } =
            handle_req(IpcRequest::status(), dir.path(), &None)
        else {
            panic!("not a Status");
        };
        let row = last_paths
            .iter()
            .find(|r| r.peer_pub_hex == hex::encode(contact))
            .unwrap_or_else(|| panic!("{last_paths:?}"));
        assert_eq!(
            (row.carrier.as_str(), row.path.as_str()),
            ("lan_dial", "direct")
        );
        assert!(row.age_s < 60, "{row:?}");
        assert!(last_paths.len() <= crate::delivery_paths::LIST_MAX);
    }

    /// `Status` lists the contacts the last p2p dial could not reach: the
    /// contact's key and the reason block only (no address, no PeerId).
    #[test]
    fn status_lists_the_unreachable_with_reason_only() {
        use raven_core::reach_diag::Why;
        let dir = tempfile::tempdir().unwrap();
        let bob = [0x5D; 32];
        crate::delivery_paths::note_unreachable(
            &bob,
            &crate::delivery_paths::tests::diag(Why::BothNat),
            None,
        );
        let IpcResponse::Status { unreachable, .. } =
            handle_req(IpcRequest::status(), dir.path(), &None)
        else {
            panic!("not a Status");
        };
        let row = unreachable
            .iter()
            .find(|r| r.peer_pub_hex == hex::encode(bob))
            .unwrap_or_else(|| panic!("{unreachable:?}"));
        assert!(row.reason.starts_with("reach: why=both_nat "), "{row:?}");
        assert_eq!(
            raven_core::reach_diag::Diag::find(&row.reason).map(|d| d.why),
            Some(Why::BothNat)
        );
        assert!(row.age_s < 60, "{row:?}");
        assert!(unreachable.len() <= crate::delivery_paths::LIST_MAX);
        let json = serde_json::to_string(&unreachable).unwrap();
        assert!(!json.contains('/') && !json.contains("12D3KooW"), "{json}");
    }

    /// `OutboxList` / `OutboxStatus` give a reason only to a live p2p object
    /// whose last error is NOT_REACHABLE: a LAN object, a delivered one and
    /// one waiting for its ACK stay empty, as does a contact with no reason.
    #[test]
    fn outbox_why_only_for_live_p2p_not_reachable() {
        use raven_core::ipc::OutboxItem;
        use raven_core::reach_diag::Why;
        let bob = [0x5E; 32];
        crate::delivery_paths::note_unreachable(
            &bob,
            &crate::delivery_paths::tests::diag(Why::ContactOffline),
            None,
        );
        let item = |carrier: &str, state: &str, code: &str, peer: [u8; 32]| OutboxItem {
            message_id_hex: "11".repeat(16),
            peer_pub_hex: hex::encode(peer),
            kind: "message".into(),
            state: state.into(),
            carrier: carrier.into(),
            last_error_code: code.into(),
            ..OutboxItem::default()
        };
        // The reason with its age (`asof=`): a remembered check.
        let filled = |mut i: OutboxItem| {
            crate::delivery_paths::fill_why(&mut i);
            match raven_core::reach_diag::Diag::find(&i.why) {
                Some(mut d) => {
                    assert!(d.asof_s.is_some_and(|s| s < 60), "{}", i.why);
                    d.asof_s = None;
                    d.render()
                }
                None => i.why,
            }
        };
        let reason = "reach: why=contact_offline me=unreachable";
        assert_eq!(
            filled(item("p2p_dial", "queued", "NOT_REACHABLE", bob)),
            reason
        );
        assert_eq!(
            filled(item("p2p_dial", "held", "NOT_REACHABLE", bob)),
            reason
        );
        let mut upper = item("p2p_dial", "queued", "NOT_REACHABLE", bob);
        upper.peer_pub_hex = upper.peer_pub_hex.to_uppercase();
        assert_eq!(filled(upper), reason);
        for other in [
            item("lan_dial", "queued", "NOT_REACHABLE", bob),
            item("internet_dial", "queued", "NOT_REACHABLE", bob),
            item("p2p_dial", "delivered", "", bob),
            item("p2p_dial", "delivered", "NOT_REACHABLE", bob),
            item("p2p_dial", "sent", "NO_ACK_YET", bob),
            item("p2p_dial", "queued", "NO_ACK_YET", bob),
            item("p2p_dial", "expired", "NOT_REACHABLE", bob),
            item("p2p_dial", "queued", "NOT_REACHABLE", [0x5F; 32]),
        ] {
            assert_eq!(filled(other.clone()), "", "{other:?}");
        }
        // A key that is not 32 bytes of hex: nothing.
        let mut short = item("p2p_dial", "queued", "NOT_REACHABLE", bob);
        short.peer_pub_hex.truncate(62);
        assert_eq!(filled(short), "");
    }

    /// `Status.egress` is netwatch's last default-route reading: the lab
    /// file's `egress none`, then `egress 0a`.
    #[tokio::test]
    async fn status_egress_follows_the_lab_netwatch_file() {
        let _lock = crate::netwatch::egress_test_lock().await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("net.txt");
        let egress = || match handle_req(IpcRequest::status(), dir.path(), &None) {
            IpcResponse::Status { egress, .. } => egress,
            other => panic!("{other:?}"),
        };
        crate::netwatch::set_last_egress(None);
        assert_eq!(egress(), None, "not read yet");
        std::fs::write(&path, "egress none\n").unwrap();
        let task = crate::netwatch::lab_reader(path.clone());
        let wait_for = |want: Option<bool>| async move {
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            while egress() != want {
                assert!(
                    std::time::Instant::now() < deadline,
                    "{want:?} not within 10 s"
                );
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        };
        wait_for(Some(false)).await;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        std::io::Write::write_all(&mut file, b"egress 0a\n").unwrap();
        wait_for(Some(true)).await;
        task.abort();
        let _ = task.await;
        crate::netwatch::set_last_egress(None);
    }

    /// `Status` has a route hints row only while route hints are live, with
    /// counts only: what the contacts' route hints said and whom this node
    /// hides its IP from.
    #[test]
    fn status_reports_route_hints_only_while_live() {
        let dir = tempfile::tempdir().unwrap();
        let key = |n: u8| hex::encode([n; 32]);
        std::fs::write(
            dir.path().join("contacts.json"),
            serde_json::json!([
                {"pub_hex": key(1), "pinned": true, "hide_ip": true},
                {"pub_hex": key(1).to_uppercase(), "pinned": true, "hide_ip": true},
                {"pub_hex": key(2), "pinned": true},
            ])
            .to_string(),
        )
        .unwrap();
        let IpcResponse::Status { route_hints, .. } =
            handle_req(IpcRequest::status(), dir.path(), &None)
        else {
            panic!("not a Status");
        };
        if !raven_core::route_hints::route_hints_live() {
            assert_eq!(route_hints, None);
            return;
        }
        let row = route_hints.expect("live: a row");
        assert!(row.live);
        assert_eq!((row.learned, row.hidden_contacts), (0, 1));
        assert!(!row.hide_ip);
    }

    /// Phase 6b (P6.24): `Status.security` only while the security events
    /// gate is live (a release build's Status is what it was): counts and a
    /// flag, the responses gate still shut.
    #[test]
    fn status_reports_security_only_while_the_gate_is_live() {
        use raven_core::security_gate::{self, SecGate};
        let dir = tempfile::tempdir().unwrap();
        let security = || match handle_req(IpcRequest::status(), dir.path(), &None) {
            IpcResponse::Status { security, .. } => security,
            other => panic!("{other:?}"),
        };
        security_gate::set_lab_for_this_thread(SecGate::Events, Some(false));
        assert_eq!(security(), None);
        security_gate::set_lab_for_this_thread(SecGate::Events, Some(true));
        // The responses gate shut even in a run that sets its switch.
        security_gate::set_lab_for_this_thread(SecGate::Responses, Some(false));
        let live = security_gate::live(SecGate::Events);
        let row = security();
        security_gate::set_lab_for_this_thread(SecGate::Events, None);
        security_gate::set_lab_for_this_thread(SecGate::Responses, None);
        if !live {
            assert_eq!(row, None, "a release build cannot open it");
            return;
        }
        let row = row.expect("live: a row");
        assert!(!row.responses_live);
        assert_eq!(row.bans_active, 0);
    }

    /// Regression: every forward-queue error was reported as QUEUE_FULL
    /// (retryable back-pressure), including bad input.
    #[test]
    fn forward_queue_errors_get_distinct_codes() {
        use raven_core::forward_queue::ForwardQueueError as E;
        assert_eq!(forward_queue_error_code(&E::QueueFull(512)), "QUEUE_FULL");
        assert_eq!(forward_queue_error_code(&E::BadId), "IPC_BAD_ENVELOPE");
        assert_eq!(
            forward_queue_error_code(&E::BadObjectDigest),
            "IPC_BAD_ENVELOPE"
        );
        assert_eq!(forward_queue_error_code(&E::TooLarge(2)), "IPC_FRAME");
        let dir = tempfile::tempdir().unwrap();
        let bad = dir.path().join("q.sqlite");
        std::fs::write(&bad, vec![b'x'; 200]).unwrap();
        let sqlite = ForwardQueue::open(&bad)
            .err()
            .expect("garbage is not a queue");
        assert_eq!(forward_queue_error_code(&sqlite), "QUEUE_IO");

        // End to end: a genuinely full queue is the only QUEUE_FULL.
        let q =
            ForwardQueue::open_with_limits(&dir.path().join("full.sqlite"), 0, 1 << 20).unwrap();
        match handle_req(enqueue_req(1), dir.path(), &Some(q)) {
            IpcResponse::Error { code, .. } => assert_eq!(code, "QUEUE_FULL"),
            other => panic!("{other:?}"),
        }
    }

    /// The forward row is written before the outbox row. When the outbox
    /// step fails the client must be told the envelope is already queued for
    /// the bridge (and that retrying is safe), not just "failed".
    #[test]
    fn outbox_failure_after_forward_enqueue_says_so() {
        let dir = tempfile::tempdir().unwrap();
        // A directory where the outbox database should be makes it unopenable.
        std::fs::create_dir(dir.path().join("queue.sqlite")).unwrap();
        let q = ForwardQueue::open(&dir.path().join("forward_queue.sqlite")).unwrap();
        let fwd = Some(q);
        match handle_req(enqueue_req(2), dir.path(), &fwd) {
            IpcResponse::Error { code, message, .. } => {
                assert_eq!(code, "OUTBOX");
                assert!(
                    message.contains("already in the forward queue"),
                    "{message}"
                );
                assert!(message.contains("retrying is safe"), "{message}");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(fwd.as_ref().unwrap().count_pending().unwrap(), 1);
        // Without a forward queue there is nothing to claim.
        assert_eq!(outbox_failed_message(false, "disk full"), "disk full");
    }

    /// `LanLocate` for `key`, waiting `wait_ms`, with a LAN beacon that has
    /// found `found`: the answer, and the wait the beacon was given (`None`:
    /// it was not asked).
    async fn locate_with(
        dir: &Path,
        key: &str,
        wait_ms: u32,
        found: &[&str],
    ) -> (IpcResponse, Option<Duration>) {
        let asked = Arc::new(std::sync::Mutex::new(None));
        let seen = Arc::clone(&asked);
        let found: Vec<String> = found.iter().map(|d| d.to_string()).collect();
        let req = IpcRequest::LanLocate {
            v: IPC_VERSION,
            peer_pub_hex: key.into(),
            wait_ms,
        };
        let resp = handle_lan_locate_with(dir, req, move |_, wait| {
            *seen.lock().unwrap() = Some(wait);
            async move { found }
        })
        .await;
        let wait = *asked.lock().unwrap();
        (resp, wait)
    }

    /// Phase 3 P3.11: `LanLocate` answers where the LAN beacon found a
    /// current contact (local-network dial strings only, at most two, IPv4
    /// first, a zone kept), and lets it wait for a round's answer at most
    /// 1.5 s however long the client would wait. A bad key and a key that is
    /// no contact are refused. While LAN is off, for an unverified contact
    /// under `raven lan verified-only on`, and while the beacon does not run
    /// (its gate is closed: `held`) the list is empty at once.
    #[test]
    fn lan_locate_returns_fresh_candidates_or_waits_at_most_1500ms() {
        let _lan = crate::lan_direct::lan_switch_for_test();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .unwrap();
        rt.block_on(lan_locate_cases());
    }

    /// The cases of the test above, on its runtime with a paused clock.
    async fn lan_locate_cases() {
        let dir = tempfile::tempdir().unwrap();
        let (dd, fq) = shared(dir.path());
        let bob = hex::encode([0xB0; 32]);
        std::fs::write(
            dir.path().join("contacts.json"),
            format!(
                r#"[{{"petname":"Bob","pub_hex":"{bob}","pinned":false,"lan_dial":"192.168.1.20:7420"}}]"#
            ),
        )
        .unwrap();
        let located = |dials: &[&str]| IpcResponse::LanLocated {
            v: IPC_VERSION,
            dials: dials.iter().map(|d| d.to_string()).collect(),
        };
        let finds = [
            "[fe80::1%en0]:47532",
            "203.0.113.9:47532",
            "192.168.1.30:47532",
        ];
        let max = crate::lan_beacon::LOCATE_MAX;
        assert_eq!(max, Duration::from_millis(2_000));
        for (wait_ms, wait) in [
            (0, Duration::ZERO),
            (1_000, Duration::from_millis(1_000)),
            (2_000, max),
            (60_000, max),
            (u32::MAX, max),
        ] {
            assert_eq!(
                locate_with(dir.path(), &bob, wait_ms, &finds).await,
                (
                    located(&["192.168.1.30:47532", "[fe80::1%en0]:47532"]),
                    Some(wait)
                ),
                "{wait_ms}"
            );
        }
        assert_eq!(
            locate_with(dir.path(), &bob, 1_000, &[]).await,
            (located(&[]), Some(Duration::from_millis(1_000))),
            "nothing found"
        );
        // Refused before the beacon is asked.
        for (key, code) in [
            ("xyz".to_string(), "IPC_BAD_PEER"),
            ("b0".repeat(31), "IPC_BAD_PEER"),
            (hex::encode([0xC0; 32]), "NOT_A_CONTACT"),
        ] {
            match locate_with(dir.path(), &key, 1_000, &finds).await {
                (IpcResponse::Error { code: got, .. }, None) => assert_eq!(got, code, "{key}"),
                other => panic!("{key}: {other:?}"),
            }
        }
        // LAN off, and Bob unverified under `raven lan verified-only on`:
        // empty, the beacon not asked.
        crate::lan_direct::set_lan_on(false);
        assert_eq!(
            locate_with(dir.path(), &bob, 1_000, &finds).await,
            (located(&[]), None)
        );
        crate::lan_direct::set_lan_on(true);
        raven_core::node_policy::set_lan_verified_only(dir.path(), true).unwrap();
        assert_eq!(
            locate_with(dir.path(), &bob, 1_000, &finds).await,
            (located(&[]), None)
        );
        raven_core::node_policy::set_lan_verified_only(dir.path(), false).unwrap();
        // This process's beacon does not run: empty at once.
        let req = IpcRequest::LanLocate {
            v: IPC_VERSION,
            peer_pub_hex: bob.clone(),
            wait_ms: 1_000,
        };
        let asked = tokio::time::Instant::now();
        assert_eq!(dispatch(&frame(&req), &dd, &fq).await, located(&[]));
        assert_eq!(tokio::time::Instant::now(), asked, "at once");
    }
}
