//! App channel node ops (`docs/design/2026-10-rdap-app-channel.md` §8, §9):
//! `AppSubmit` seals an agent payload for a contact's node and hands it to
//! the outbox worker; `AppInboxPage` / `AppInboxAck` serve received payloads
//! to the one bound consumer (RDAP). Gated: `APP_CHANNEL_HOLD` unless
//! [`raven_core::app_channel::app_channel_live_enabled`].
//!
//! Lock order (§10): pairing runs before the per-peer send lock, which is
//! then held only for the store work (never across a dial); the app store is
//! written inside the seal's handoff callback, after the session commit.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine as _;
use raven_core::app_channel::{
    app_body_text_ok, app_channel_live_enabled, content_type_ok, content_type_registered,
    encode_frame, MAX_APP_BODY_BYTES,
};
use raven_core::app_store::{
    AppOutRecord, AppStore, Dedup, Disposition, MetadataOnly, OutState, PageQuery, PairSpend,
    PlatformRowSealer, APP_PAIR_BUDGET_PER_DAY,
};
use raven_core::clock::now_ms;
use raven_core::indexed_session_store::{IndexedSessionRecordKey, IndexedSessionStoreError};
use raven_core::ipc::{AppInboxEntry, AppInboxRef, IpcResponse};
use raven_core::outbox::{
    contact_admission, localize_lan_route, record_object_routes, set_object_unsent, CarrierChoice,
    ContactAdmission, OutboxCarrier, OutboxRoute, PeerSendLock, LOCALIZE_RESOLVE_TIMEOUT,
};
use raven_core::{AuthorizedEndpointDevice, IndexedSessionStore, LanBundle, PRIMARY_DEVICE_ID};

use crate::outbox::{code, dial_error_code, AttemptCtx};

/// A sealed app object needs at least this much validity left (§8.2).
pub(crate) const APP_MIN_ENVELOPE_MS: u64 = 10 * 60 * 1000;
const APP_DEFAULT_TTL_MS: u64 = 4 * 3_600_000;
const APP_MAX_TTL_MS: u64 = 24 * 3_600_000;
/// App objects in flight to one peer device (§8.1).
const APP_QUEUE_MAX: u32 = 16;
/// Half the receiver's forward-jump limit: chat keeps the other half.
const APP_MAX_SESSION_SPAN: u64 = raven_core::indexed_session_store::MAX_FORWARD_JUMP / 2;
/// One probe.
const APP_PROBE_DEADLINE: Duration = Duration::from_secs(10);
/// Route resolution (LAN name lookups) and every probe of one `AppSubmit`
/// together, from the start of `resolve()`.
const APP_PROBE_BUDGET: Duration = Duration::from_secs(30);
/// A probe with less than this left is not dialled.
const APP_PROBE_MIN: Duration = Duration::from_secs(2);
/// A walk that found nobody is not repeated for the same routes within this.
const APP_PROBE_COOLDOWN: Duration = Duration::from_secs(15);
/// A p2p refusal that would decide a walk is dialled again this long after
/// it, inside [`APP_PROBE_BUDGET`] ([`probe`]).
const APP_REFUSAL_RECHECK: Duration = Duration::from_secs(1);
/// Above the 30 s first-reply wait of the responder's link.
const APP_PAIR_DEADLINE: Duration = Duration::from_secs(35);
const APP_LOCK_WAIT: Duration = Duration::from_secs(5);
const APP_PAIR_SPACING_MS: u64 = 60_000;
/// ash `lab app-submit` (cli.rs `cmd_lab_app_submit`) and RDAP
/// (raven_ipc.py `APP_SUBMIT_TIMEOUT_SEC`) wait 90 s.
const APP_CLIENT_TIMEOUT: Duration = Duration::from_secs(90);
/// Seal, stores, bundle cache and IPC.
const APP_SUBMIT_SLACK: Duration = Duration::from_secs(10);
// LAN name lookups (at most 3 LAN routes) still leave the last probe its
// full deadline.
const _: () = assert!(
    3 * LOCALIZE_RESOLVE_TIMEOUT.as_secs() + APP_PROBE_DEADLINE.as_secs()
        <= APP_PROBE_BUDGET.as_secs()
);
// Three lock waits: submit_with's PeerSendLock and pair_with_peer's two
// PairIo::locked calls. 30 + 3*5 + 35 + 10 = 90.
const _: () = assert!(
    APP_PROBE_BUDGET.as_secs()
        + 3 * APP_LOCK_WAIT.as_secs()
        + APP_PAIR_DEADLINE.as_secs()
        + APP_SUBMIT_SLACK.as_secs()
        <= APP_CLIENT_TIMEOUT.as_secs()
);
const MAX_CLIENT_REF: usize = 96;
const MAX_CONSUMER: usize = 64;
const PAGE_DEFAULT: u16 = 8;
const PAGE_MAX: u16 = 32;
const PAGE_BYTE_BUDGET: usize = 192 * 1024;
const ACK_MAX: usize = 32;
const LONG_POLL_MAX_MS: u32 = 20_000;
const LONG_POLL_TICK: Duration = Duration::from_millis(250);

type AppResult<T> = Result<T, (&'static str, String)>;

fn err<T>(code: &'static str, message: impl Into<String>) -> AppResult<T> {
    Err((code, message.into()))
}

fn to_response(v: u16, result: AppResult<IpcResponse>) -> IpcResponse {
    result.unwrap_or_else(|(code, message)| IpcResponse::Error {
        v,
        code: code.into(),
        message,
    })
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    let t = s.trim();
    if t.len() != 64 {
        return None;
    }
    hex::decode(t).ok()?.try_into().ok()
}

fn hex16(s: &str) -> Option<[u8; 16]> {
    let t = s.trim();
    if t.len() != 32 {
        return None;
    }
    hex::decode(t).ok()?.try_into().ok()
}

/// `[A-Za-z0-9._:-]`, 1..=`max`.
fn token_ok(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

fn gate() -> AppResult<()> {
    if app_channel_live_enabled() {
        Ok(())
    } else {
        err(
            "APP_CHANNEL_HOLD",
            "the app channel is not enabled in this build",
        )
    }
}

fn lab() -> bool {
    raven_core::pair_init::lab_test_a_enabled()
}

fn decode_b64(s: &str) -> Option<Vec<u8>> {
    let engine = base64::engine::general_purpose::STANDARD;
    engine.decode(s.trim()).ok()
}

// ------------------------------------------------------------------ submit

/// One `AppSubmit` request (§9.1).
pub(crate) struct SubmitReq {
    pub(crate) peer_identity_hex: String,
    pub(crate) content_type: String,
    pub(crate) client_ref: String,
    pub(crate) body_b64: String,
    pub(crate) ttl_ms: Option<u64>,
    pub(crate) resend: bool,
}

/// `AppSubmit` (blocking: store, keystore, dials). Uses the running worker's
/// identity, dialer and gates; refuses with `OUTBOX_WORKER_OFF` without one.
pub(crate) fn submit(v: u16, req: SubmitReq) -> IpcResponse {
    let Some(ctx) = crate::outbox::attempt_ctx() else {
        return to_response(
            v,
            gate().and_then(|()| {
                err(
                    "OUTBOX_WORKER_OFF",
                    "only `raven-node service` (with its outbox worker) sends app payloads",
                )
            }),
        );
    };
    to_response(
        v,
        submit_with(&ctx, req, now_ms()).map(|r| r.into_response(v)),
    )
}

/// What `AppSubmit` answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Submitted {
    pub(crate) message_id: [u8; 16],
    pub(crate) app_id: [u8; 16],
    pub(crate) state: OutState,
    pub(crate) expires_at_ms: u64,
    pub(crate) duplicate: bool,
    pub(crate) attempt_seq: u32,
}

impl Submitted {
    fn into_response(self, v: u16) -> IpcResponse {
        IpcResponse::AppSubmitResult {
            v,
            message_id_hex: hex::encode(self.message_id),
            app_id_hex: hex::encode(self.app_id),
            state: self.state.as_str().into(),
            expires_at_ms: self.expires_at_ms,
            duplicate: self.duplicate,
            attempt_seq: self.attempt_seq,
        }
    }
}

/// A checked submit request.
struct Checked {
    identity: [u8; 32],
    content_type: String,
    client_ref: String,
    body: String,
    digest: [u8; 32],
    ttl_ms: u64,
    resend: bool,
}

fn check(req: SubmitReq) -> AppResult<Checked> {
    gate()?;
    let Some(identity) = hex32(&req.peer_identity_hex) else {
        return err("APP_BAD_IDENTITY", "peer_identity_hex must be 64 hex chars");
    };
    let ct = req.content_type.trim().to_string();
    if !content_type_ok(&ct) || !content_type_registered(&ct, lab()) {
        return err(
            "APP_BAD_CONTENT_TYPE",
            "content type is not registered on this node",
        );
    }
    if !token_ok(&req.client_ref, MAX_CLIENT_REF) {
        return err(
            "APP_BAD_CLIENT_REF",
            "client_ref must be 1..96 of [A-Za-z0-9._:-]",
        );
    }
    let Some(body) = decode_b64(&req.body_b64) else {
        return err("IPC_BAD_B64", "body_b64 is not base64");
    };
    if body.len() > MAX_APP_BODY_BYTES {
        return err(
            "APP_PAYLOAD_TOO_LARGE",
            format!("the body is over {MAX_APP_BODY_BYTES} bytes"),
        );
    }
    if !app_body_text_ok(&body) {
        return err(
            "APP_PAYLOAD_INVALID",
            "the body must be UTF-8 text without control characters",
        );
    }
    let ttl_ms = req.ttl_ms.unwrap_or(APP_DEFAULT_TTL_MS);
    if !(APP_MIN_ENVELOPE_MS..=APP_MAX_TTL_MS).contains(&ttl_ms) {
        return err(
            "APP_BAD_TTL",
            "ttl_ms must be between 10 minutes and 24 hours",
        );
    }
    let digest = raven_core::app_channel::body_digest(&body);
    let body = String::from_utf8(body).map_err(|_| ("APP_PAYLOAD_INVALID", String::new()))?;
    Ok(Checked {
        identity,
        content_type: ct,
        client_ref: req.client_ref,
        body,
        digest,
        ttl_ms,
        resend: req.resend,
    })
}

/// `(answer now, resend as (app_id, attempt))`: with no answer, seal (a
/// fresh object when there is no resend either).
type Decision = (Option<Submitted>, Option<([u8; 16], u32)>);

/// A route as planned, and as it is dialled (localized).
type RoutePair = (OutboxRoute, OutboxRoute);

/// The decision for `(peer, client_ref)` (§8.3).
fn decide(data_dir: &Path, c: &Checked) -> AppResult<Decision> {
    let store = AppStore::open(data_dir, &MetadataOnly).map_err(|e| ("APP_STORE", e))?;
    match store
        .dedup(
            &c.identity,
            &c.client_ref,
            &c.content_type,
            &c.digest,
            c.resend,
        )
        .map_err(|e| ("APP_STORE", e))?
    {
        Dedup::Fresh => Ok((None, None)),
        Dedup::Resend { app_id, seq } => Ok((None, Some((app_id, seq)))),
        Dedup::Conflict => err(
            "APP_CLIENT_REF_CONFLICT",
            "this client_ref was used for a different body or content type",
        ),
        Dedup::LineageRevoked => err(
            "ATSAM_LINEAGE_REVOKED",
            "the contact's device lineage is revoked; nothing was sent",
        ),
        Dedup::Return { .. } => {
            let rec = store
                .outbox_record(&c.identity, &c.client_ref)
                .map_err(|e| ("APP_STORE", e))?
                .ok_or(("APP_STORE", "record vanished".to_string()))?;
            Ok((
                Some(Submitted {
                    message_id: rec.message_id,
                    app_id: rec.app_id,
                    state: rec.state,
                    expires_at_ms: rec.expires_at_ms,
                    duplicate: true,
                    attempt_seq: rec.attempt_seq,
                }),
                None,
            ))
        }
    }
}

/// The contact's device and its dialable routes (§4.5: under today's LAN
/// rule the device key is the identity key), in dial order. Planned by the
/// worker's own resolver ([`crate::outbox::peer_plan`]): the on-link filter,
/// the route memory (read, never taught), connected first, learned routes
/// and hide-IP are the worker's.
fn resolve(
    ctx: &AttemptCtx,
    identity: &[u8; 32],
    now: u64,
) -> AppResult<([u8; 32], Vec<RoutePair>)> {
    let book = match contact_admission(&ctx.data_dir, identity) {
        ContactAdmission::Allowed(c) => c,
        ContactAdmission::NotContact => {
            return err(
                "NOT_A_CONTACT",
                "that identity is not a contact of this node",
            )
        }
        ContactAdmission::Blocked => return err("CONTACT_BLOCKED", "that contact is blocked"),
        ContactAdmission::Unreadable => {
            return err("CONTACTS_UNREADABLE", "the contact book cannot be read")
        }
    };
    let device = *identity;
    let routes = crate::outbox::peer_plan(ctx, &device, book, now)
        .auto_dial(&device, ctx.connected, &mut |r, pinned| {
            localize_lan_route(r, pinned, LOCALIZE_RESOLVE_TIMEOUT)
        })
        .into_iter()
        .filter(|(planned, _)| planned.carrier.confidential_to_endpoint())
        .collect();
    Ok((device, routes))
}

/// The newest confirmed session with `device` that has at least
/// [`APP_MIN_ENVELOPE_MS`] left, and its end.
fn usable_session(
    store: &mut IndexedSessionStore,
    device: &[u8; 32],
    now: u64,
) -> AppResult<Option<(IndexedSessionRecordKey, u64)>> {
    let keys = store
        .find_confirmed_sessions_for_peer_at(device, now)
        .map_err(|e| ("APP_STORE", e.redacted_display()))?;
    for key in keys {
        let Ok(sid) = store.session_id_for_record_key(&key) else {
            continue;
        };
        if store.session_is_retired(&sid).unwrap_or(false) {
            continue;
        }
        let ends = store
            .session_expires_at(&key)
            .map_err(|e| ("APP_STORE", e.redacted_display()))?;
        if ends >= now.saturating_add(APP_MIN_ENVELOPE_MS) {
            return Ok(Some((key, ends)));
        }
    }
    Ok(None)
}

fn inflight(data_dir: &Path, device: &[u8; 32]) -> AppResult<()> {
    let n = AppStore::open(data_dir, &MetadataOnly)
        .and_then(|s| s.inflight_for_device(device))
        .map_err(|e| ("APP_STORE", e))?;
    if n >= APP_QUEUE_MAX {
        return err(
            "APP_QUEUE_FULL",
            format!("{APP_QUEUE_MAX} app payloads are already in flight to this contact"),
        );
    }
    Ok(())
}

/// Refuse (retryable) while the contact is [`APP_MAX_SESSION_SPAN`] or more
/// messages behind on the session. A receiver may defer an app payload
/// (commits nothing), and one that falls more than `MAX_FORWARD_JUMP` behind
/// can no longer read any later message on the session, chat included.
fn backlog(store: &mut IndexedSessionStore, key: &IndexedSessionRecordKey) -> AppResult<()> {
    let span = store
        .unacknowledged_message_span(key)
        .map_err(|e| ("APP_STORE", e.redacted_display()))?;
    if span >= APP_MAX_SESSION_SPAN {
        return err(
            "APP_PEER_BACKLOG",
            format!(
                "{span} messages to this contact are not acknowledged yet; \
                 app payloads wait so chat is never blocked"
            ),
        );
    }
    Ok(())
}

/// `ResetIo` for daemon pairing: short store locks, deadline-bounded dials.
struct PairIo<'a> {
    ctx: &'a AttemptCtx,
    device: [u8; 32],
    store: &'a mut IndexedSessionStore,
}

impl raven_core::session_reset::ResetIo for PairIo<'_> {
    fn locked(
        &mut self,
        f: &mut dyn FnMut(&mut IndexedSessionStore) -> Result<(), String>,
    ) -> Result<(), String> {
        let _lock = PeerSendLock::acquire_within(&self.ctx.data_dir, &self.device, APP_LOCK_WAIT)?;
        f(self.store)
    }

    fn dial(&mut self, route: &OutboxRoute, frames: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, String> {
        self.ctx.dialer.dial_within(
            &self.ctx.data_dir,
            route,
            &hex::encode(self.device),
            frames,
            APP_PAIR_DEADLINE,
        )
    }
}

/// The next probe's deadline: [`APP_PROBE_DEADLINE`] cut to what is left of
/// [`APP_PROBE_BUDGET`] after `spent`. A route before the last also leaves
/// `APP_PROBE_DEADLINE` for the last one, so stalled routes ahead cannot
/// starve it (plans put p2p last). `None` below [`APP_PROBE_MIN`]: that
/// route is not dialled.
fn probe_deadline(spent: Duration, last: bool) -> Option<Duration> {
    let left = APP_PROBE_BUDGET.saturating_sub(spent);
    let left = if last {
        left
    } else {
        left.saturating_sub(APP_PROBE_DEADLINE)
    };
    Some(left.min(APP_PROBE_DEADLINE)).filter(|d| *d >= APP_PROBE_MIN)
}

/// Why one probed route gave no offer from the contact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Miss {
    /// The contact's node turned this node away.
    NotAccepted,
    /// A p2p route's own PeerId turned this dial away at once. The contact's
    /// verdict only once a second dial is turned away too ([`probe`]): a node
    /// re-homing its p2p host or shutting down looks the same once. (A
    /// relay's answer, `CONNECTION_FAILED` included, is never a refusal: a
    /// contact reached only through a relay whose gate turns the circuit
    /// away gives `APP_PEER_UNREACHABLE`, retried, never
    /// `LINK_NOT_ACCEPTED`.)
    Refused,
    /// An offer naming another key.
    ForeignKey,
    Other,
}

/// A dial error: `NotAccepted` when `dial_error_code(e)` is
/// `LINK_NOT_ACCEPTED` (LAN / Internet: closed after our signed hello,
/// `netutil::closed_before_peer_identity`); `Refused` when the route is p2p
/// and `target_refused` (the contact's own PeerId turned this dial away at
/// once: its peer gate, or something passing). Everything else is `Other`,
/// including a dial-level identity mismatch (`WRONG_IDENTITY`): retryable,
/// as with one route, and safe for an address another node took over.
fn miss_for(route: &OutboxRoute, error: &str, target_refused: bool) -> Miss {
    if dial_error_code(error) == code::LINK_NOT_ACCEPTED {
        Miss::NotAccepted
    } else if route.carrier == OutboxCarrier::P2p && target_refused {
        Miss::Refused
    } else {
        Miss::Other
    }
}

/// A walk that found no offer from the contact. `LINK_NOT_ACCEPTED` and
/// `WRONG_IDENTITY`, which a client does not retry, only when every route
/// was dialled and each one agrees; `APP_PEER_UNREACHABLE` otherwise
/// (also when the budget skipped a route, and for a p2p refusal that was
/// not confirmed, [`Miss::Refused`]), whichever route failed last.
fn probe_failure(misses: &[Miss], walked_all: bool) -> (&'static str, String) {
    let every = |m: Miss| walked_all && !misses.is_empty() && misses.iter().all(|x| *x == m);
    if every(Miss::NotAccepted) {
        (
            "LINK_NOT_ACCEPTED",
            "the contact's node does not accept this node".into(),
        )
    } else if every(Miss::ForeignKey) {
        (
            "WRONG_IDENTITY",
            "another key answered at the contact's address".into(),
        )
    } else {
        (
            "APP_PEER_UNREACHABLE",
            "no usable session and the contact's node did not answer; nothing was sent".into(),
        )
    }
}

/// The probe (§8.2): a frame-less dial of every route in the given order (the
/// resolver's: a connected p2p route first, then the remembered one, then plan
/// order), each within [`probe_deadline`] from `started`; a route the budget
/// cannot cover is skipped. The first offer naming `device` wins: its bundle
/// and that route's dial form. An offer from another key fails that route
/// only. `refused` tells whether a p2p route's own PeerId turned the dial that
/// started at the given time away ([`crate::p2p::target_refused_since`]).
/// When every route turned this node away and a p2p route's refusal is part
/// of that ([`Miss::Refused`]), that route is dialled again after
/// [`APP_REFUSAL_RECHECK`], within the same budget: only a second refusal
/// makes it the contact's verdict (`LINK_NOT_ACCEPTED`, not retried), and an
/// offer then wins. One log line per walk, codes only. Spends no pairing
/// budget and never teaches the route memory.
fn probe(
    ctx: &AttemptCtx,
    device: &[u8; 32],
    routes: &[RoutePair],
    started: Instant,
    refused: fn(&OutboxRoute, Instant) -> bool,
) -> AppResult<(LanBundle, OutboxRoute)> {
    let expected = hex::encode(device);
    // One frame-less dial: the offer naming `device`, or why not (a code).
    let dial_once = |dial: &OutboxRoute, deadline: Duration| {
        let since = Instant::now();
        let answer = ctx
            .dialer
            .dial_within(&ctx.data_dir, dial, &expected, &[], deadline)
            .map(|replies| {
                replies
                    .iter()
                    .find_map(|f| raven_core::parse_peer_offer(f).ok())
            });
        match answer {
            Ok(Some(bundle))
                if bundle.cert.user_ed_pub == *device || bundle.cert.device_ed_pub == *device =>
            {
                Ok(bundle)
            }
            Ok(Some(_)) => Err((Miss::ForeignKey, code::WRONG_IDENTITY)),
            // The peer answered without an offer.
            Ok(None) => Err((Miss::Other, code::DIAL_FAILED)),
            Err(e) => Err(match miss_for(dial, &e, refused(dial, since)) {
                miss @ (Miss::NotAccepted | Miss::Refused) => (miss, code::LINK_NOT_ACCEPTED),
                miss => (miss, dial_error_code(&e)),
            }),
        }
    };
    let mut misses = Vec::new();
    let mut walked_all = true;
    let mut log = Vec::new();
    let mut offered = None;
    for (i, (_, dial)) in routes.iter().enumerate() {
        let label = dial.carrier.label();
        let Some(deadline) = probe_deadline(started.elapsed(), i + 1 == routes.len()) else {
            walked_all = false;
            log.push(format!("{label} skipped"));
            continue;
        };
        match dial_once(dial, deadline) {
            Ok(bundle) => {
                log.push(format!("{label} offer"));
                offered = Some((bundle, dial.clone()));
                break;
            }
            Err((miss, why)) => {
                log.push(format!("{label} {why}"));
                misses.push(miss);
            }
        }
    }
    // Every route turned this node away, a p2p route's PeerId among them:
    // dial each such route again. Here every route was dialled once and
    // none offered, so `misses[k]` is `routes[k]`'s.
    let refusing = |m: &Miss| matches!(m, Miss::NotAccepted | Miss::Refused);
    if offered.is_none()
        && walked_all
        && misses.iter().all(refusing)
        && misses.contains(&Miss::Refused)
    {
        // No room for the pause and a dial: the refusal stays unconfirmed.
        let room = probe_deadline(started.elapsed() + APP_REFUSAL_RECHECK, true).is_some();
        if room {
            std::thread::sleep(APP_REFUSAL_RECHECK);
        }
        for (k, (_, dial)) in routes.iter().enumerate() {
            if misses.get(k) != Some(&Miss::Refused) {
                continue;
            }
            let label = dial.carrier.label();
            let Some(deadline) = probe_deadline(started.elapsed(), true).filter(|_| room) else {
                log.push(format!("{label} recheck skipped"));
                continue;
            };
            match dial_once(dial, deadline) {
                Ok(bundle) => {
                    log.push(format!("{label} recheck offer"));
                    offered = Some((bundle, dial.clone()));
                    break;
                }
                Err((miss, why)) => {
                    log.push(format!("{label} recheck {why}"));
                    misses[k] = match miss {
                        Miss::Refused | Miss::NotAccepted => Miss::NotAccepted,
                        other => other,
                    };
                }
            }
        }
    }
    // A local request: no limiter. Codes only (no address, PeerId or name).
    eprintln!("raven-node app: probe {}", log.join(", "));
    offered.ok_or_else(|| probe_failure(&misses, walked_all))
}

/// Walks that found nobody, per (data dir, device): when, and the planned
/// routes walked ([`APP_PROBE_COOLDOWN`]). In memory only; cleared above
/// [`MAX_PROBE_MISSES`] entries.
type ProbeMisses = HashMap<(PathBuf, [u8; 32]), (Instant, Vec<OutboxRoute>)>;
const MAX_PROBE_MISSES: usize = 256;

fn probe_misses() -> &'static Mutex<ProbeMisses> {
    static M: std::sync::OnceLock<Mutex<ProbeMisses>> = std::sync::OnceLock::new();
    M.get_or_init(Default::default)
}

/// Is a walk over `routes` (planned forms, in dial order) due a rest at
/// `now`: the `last` walk that found nobody went over the same routes within
/// [`APP_PROBE_COOLDOWN`]? A changed route list probes at once.
fn probe_cooled(
    last: Option<(Instant, &[OutboxRoute])>,
    routes: &[OutboxRoute],
    now: Instant,
) -> bool {
    last.is_some_and(|(at, walked)| {
        walked == routes && now.saturating_duration_since(at) < APP_PROBE_COOLDOWN
    })
}

/// The pairing budget's answer to `spend`: the refusal text of the read-only
/// check before any dial ([`pair_budget_open`]) and of the spend itself.
fn budget_refusal(spend: PairSpend) -> AppResult<()> {
    match spend {
        PairSpend::Spent => Ok(()),
        PairSpend::TooSoon(until) => err(
            "APP_PAIR_BUDGET",
            format!("automatic pairing is paused until {until} (unix ms)"),
        ),
        PairSpend::UsedUp => err(
            "APP_PAIR_BUDGET",
            "the automatic pairing budget for this contact is used up for today",
        ),
    }
}

/// Could a PairInit to `device` be spent at `now` (RN-5: refused without a
/// dial)? Read only: the transactional spend before the PairInit stays the
/// authority against a concurrent submit.
fn pair_budget_open(app: &AppStore, device: &[u8; 32], now: u64) -> AppResult<()> {
    let last = app
        .last_pair_attempt_at(device)
        .map_err(|e| ("APP_STORE", e))?;
    if let Some(until) = last
        .map(|at| at.saturating_add(APP_PAIR_SPACING_MS))
        .filter(|until| now < *until)
    {
        return budget_refusal(PairSpend::TooSoon(until));
    }
    let today = app
        .pair_attempts_today(device, now)
        .map_err(|e| ("APP_STORE", e))?;
    if today >= APP_PAIR_BUDGET_PER_DAY {
        return budget_refusal(PairSpend::UsedUp);
    }
    Ok(())
}

/// No usable session: one budgeted PairInit (§8.2). In order: the pairing
/// gate; a route; the pairing budget, read only (`APP_PAIR_BUDGET` without a
/// dial); the cooldown after a walk over the same routes that found nobody;
/// the [`probe`] (every route in dial order, budgeted from `started`); the
/// offered bundle cached; the attempt spent, before the PairInit dial so a
/// crash counts; then the PairInit over the route that offered. The probe
/// spends no budget and never teaches the route memory.
fn pair(
    ctx: &AttemptCtx,
    store: &mut IndexedSessionStore,
    device: &[u8; 32],
    routes: &[RoutePair],
    started: Instant,
    now: u64,
) -> AppResult<()> {
    if !raven_core::pair_init::live_enabled() && !raven_core::lan_direct_live_enabled() {
        return err(
            "APP_CHANNEL_HOLD",
            "automatic pairing is not enabled in this build",
        );
    }
    if routes.is_empty() {
        return err("NO_ROUTE", "no dialable route for that contact");
    }
    {
        let app = AppStore::open(&ctx.data_dir, &MetadataOnly).map_err(|e| ("APP_STORE", e))?;
        pair_budget_open(&app, device, now)?;
    }
    let planned: Vec<OutboxRoute> = routes.iter().map(|(p, _)| p.clone()).collect();
    let key = (ctx.data_dir.clone(), *device);
    {
        let misses = probe_misses().lock().unwrap_or_else(|e| e.into_inner());
        let last = misses.get(&key).map(|(at, w)| (*at, w.as_slice()));
        if probe_cooled(last, &planned, Instant::now()) {
            return err(
                "APP_PEER_UNREACHABLE",
                "the contact's node did not answer a moment ago; nothing was sent",
            );
        }
    }
    let probed = probe(
        ctx,
        device,
        routes,
        started,
        crate::p2p::target_refused_since,
    );
    {
        // Only a walk that found nobody rests; any other answer ends it.
        let mut misses = probe_misses().lock().unwrap_or_else(|e| e.into_inner());
        match &probed {
            Err((why, _)) if *why == "APP_PEER_UNREACHABLE" => {
                if misses.len() >= MAX_PROBE_MISSES && !misses.contains_key(&key) {
                    misses.clear();
                }
                misses.insert(key, (Instant::now(), planned));
            }
            _ => {
                misses.remove(&key);
            }
        }
    }
    let (bundle, route) = probed?;
    raven_core::cache_peer_bundle(&ctx.data_dir, &bundle).map_err(|e| {
        if e.starts_with(raven_core::lan_dispatch::PEER_PREKEY_RESET) {
            ("PEER_PREKEY_RESET", e)
        } else {
            ("APP_STORE", e)
        }
    })?;
    {
        let mut app = AppStore::open(&ctx.data_dir, &MetadataOnly).map_err(|e| ("APP_STORE", e))?;
        budget_refusal(
            app.spend_pair_attempt(device, now, APP_PAIR_SPACING_MS)
                .map_err(|e| ("APP_STORE", e))?,
        )?;
    }
    let local = route.carrier == OutboxCarrier::Lan;
    let mut io = PairIo {
        ctx,
        device: *device,
        store,
    };
    raven_core::session_reset::pair_with_peer(
        &ctx.data_dir,
        &ctx.identity,
        &bundle,
        &route,
        local,
        false,
        &mut io,
    )
    .map(|_| ())
    .map_err(|e| {
        if e.contains("PEER_PREKEY_RESET") {
            ("PEER_PREKEY_RESET", e)
        } else {
            (
                "APP_PEER_UNREACHABLE",
                "the contact's node did not complete pairing; nothing was sent".to_string(),
            )
        }
    })
}

/// Prepared Message rows to `device` with no stage, no history row and no app
/// record can never be dialled (§8.4); one would hold the session's lane.
/// Called under the send lock.
fn clear_orphan_prepared(
    data_dir: &Path,
    store: &mut IndexedSessionStore,
    device: &[u8; 32],
) -> AppResult<()> {
    use raven_core::indexed_session_store::{EndpointOutboundKind, EndpointOutboxState};
    let rows = store
        .pending_endpoint_outbound_for_recipient(Some(device))
        .map_err(|e| ("APP_STORE", e.redacted_display()))?;
    for row in rows {
        if row.kind != EndpointOutboundKind::Message || row.state != EndpointOutboxState::Prepared {
            continue;
        }
        let staged = raven_core::load_staged_outbound_body(data_dir, &row.message_id)
            .map_err(|e| ("APP_STORE", e.to_string()))?
            .is_some();
        let in_history = raven_core::ChatHistory::load(data_dir)
            .map(|h| {
                h.entries.iter().any(|e| {
                    e.direction == "out"
                        && e.message_id_hex
                            .eq_ignore_ascii_case(&hex::encode(row.message_id))
                })
            })
            .map_err(|e| ("APP_STORE", e.to_string()))?;
        let app = raven_core::app_channel::is_app_outbound(data_dir, &row.message_id)
            .map_err(|e| ("APP_STORE", e))?;
        if staged || in_history || app {
            continue;
        }
        let Some(key) = store
            .record_key_for_session_id(&row.session_id)
            .map_err(|e| ("APP_STORE", e.redacted_display()))?
        else {
            continue;
        };
        let _ = store
            .abandon_undelivered_outbound(&key, &row.object_digest)
            .map_err(|e| ("APP_STORE", e.redacted_display()))?;
    }
    Ok(())
}

/// The whole `AppSubmit` path (§8.1).
pub(crate) fn submit_with(ctx: &AttemptCtx, req: SubmitReq, now: u64) -> AppResult<Submitted> {
    let c = check(req)?;
    let data_dir = ctx.data_dir.as_path();
    if let (Some(done), _) = decide(data_dir, &c)? {
        return Ok(done);
    }
    // The probe budget counts from here: LAN name lookups are inside it.
    let started = Instant::now();
    let (device, routes) = resolve(ctx, &c.identity, now)?;
    inflight(data_dir, &device)?;
    let mut store =
        IndexedSessionStore::open(data_dir).map_err(|e| ("APP_STORE", e.redacted_display()))?;
    if usable_session(&mut store, &device, now)?.is_none() {
        if let Err(e) = pair(ctx, &mut store, &device, &routes, started, now) {
            // A concurrent submit may have paired meanwhile.
            if usable_session(&mut store, &device, now)?.is_none() {
                return Err(e);
            }
        }
    }

    let _lock = PeerSendLock::acquire_within(data_dir, &device, APP_LOCK_WAIT).map_err(|e| {
        if raven_core::outbox::send_lock_busy(&e) {
            (
                "SEND_IN_PROGRESS",
                "another send to this contact is in progress".to_string(),
            )
        } else {
            ("APP_STORE", e)
        }
    })?;
    // Re-decide under the lock: a concurrent submit may have sealed it.
    let (done, resend) = decide(data_dir, &c)?;
    if let Some(done) = done {
        return Ok(done);
    }
    inflight(data_dir, &device)?;
    let Some((key, session_ends)) = usable_session(&mut store, &device, now)? else {
        return err(
            "ATSAM_SESSION_REQUIRED",
            "the session ended during the request; try again",
        );
    };
    clear_orphan_prepared(data_dir, &mut store, &device)?;
    backlog(&mut store, &key)?;
    let peer_cert = raven_core::lan_dispatch::session_bound_peer_certificate(
        data_dir, &mut store, &key, &device,
    )
    .map_err(|e| ("APP_STORE", e))?
    .ok_or((
        "ATSAM_SESSION_REQUIRED",
        "no session-bound certificate for the contact".to_string(),
    ))?;
    let (local_cert, registry) = raven_core::device_cert::ensure_local_device_certificate(
        data_dir,
        &ctx.identity,
        PRIMARY_DEVICE_ID,
    )
    .map_err(|e| ("IDENTITY_UNAVAILABLE", e))?;
    if raven_core::refuse_if_session_lineage_revoked(data_dir, &local_cert, &peer_cert).is_err() {
        return err(
            "ATSAM_LINEAGE_REVOKED",
            "the session's device lineage is revoked; nothing was sent",
        );
    }
    let local_device =
        AuthorizedEndpointDevice::authorize(&local_cert, &ctx.identity, &registry, now).map_err(
            |_| {
                (
                    "ATSAM_LINEAGE_REVOKED",
                    "this device is not authorized".to_string(),
                )
            },
        )?;
    let expires = raven_core::outbox::envelope_expires_at(now, session_ends)
        .map_err(|_| {
            (
                "ATSAM_SESSION_REQUIRED",
                "the session is ending".to_string(),
            )
        })?
        .min(now.saturating_add(c.ttl_ms));
    if expires < now.saturating_add(APP_MIN_ENVELOPE_MS) {
        return err(
            "ATSAM_SESSION_REQUIRED",
            "the session ends too soon; try again",
        );
    }
    let (app_id, seq) = match resend {
        Some((app_id, seq)) => (app_id, seq),
        None => (rand::random::<[u8; 16]>(), 0),
    };
    let frame = encode_frame(&c.content_type, &app_id, &c.body, lab())
        .map_err(|e| (e.code(), "the payload cannot be framed".to_string()))?;
    let session_id = store
        .session_id_for_record_key(&key)
        .map_err(|e| ("APP_STORE", e.redacted_display()))?;

    let mut recorded: Option<([u8; 16], u64)> = None;
    let mut record_error = None;
    let result = store.send_message_envelope(
        &key,
        &frame,
        &local_device,
        now,
        expires,
        now,
        &mut rand::rngs::OsRng,
        &mut |digest: &[u8; 32], bytes: &[u8]| {
            let env = raven_core::Envelope::unpack(bytes).ok_or(())?;
            let rec = AppOutRecord {
                peer_identity: c.identity,
                client_ref: c.client_ref.clone(),
                peer_device: device,
                content_type: c.content_type.clone(),
                app_id,
                body_sha256: c.digest,
                message_id: env.message_id,
                session_id,
                object_digest: *digest,
                created_at_ms: now,
                expires_at_ms: env.expires_at,
                state: OutState::Queued,
                last_error_code: String::new(),
                attempt_seq: seq,
            };
            match AppStore::open(data_dir, &MetadataOnly).and_then(|mut s| s.put_record(&rec, now))
            {
                Ok(()) => {
                    recorded = Some((env.message_id, env.expires_at));
                    Ok(*digest)
                }
                Err(e) => {
                    record_error = Some(e);
                    Err(())
                }
            }
        },
    );
    let (message_id, expires_at_ms) = match (result, recorded) {
        (Ok(_), Some(done)) => done,
        (Err(IndexedSessionStoreError::OutboundPending), _) => {
            return err(
                "APP_LANE_BUSY",
                "an earlier message to this contact must go first; try again",
            )
        }
        (
            Err(
                IndexedSessionStoreError::LocalDeviceUnauthorized
                | IndexedSessionStoreError::RevokedDevice,
            ),
            _,
        ) => {
            return err(
                "ATSAM_LINEAGE_REVOKED",
                "the session's device lineage is revoked; nothing was sent",
            )
        }
        (Err(IndexedSessionStoreError::OutboundQueueHandoff), None) | (Ok(_), None) => {
            // Sealed but never recorded: never on the wire. Drop the row so
            // it cannot hold the lane.
            let _ = clear_orphan_prepared(data_dir, &mut store, &device);
            return err(
                "APP_STORE",
                record_error.unwrap_or_else(|| "the app record was not written".into()),
            );
        }
        (Err(e), _) => return err("APP_STORE", e.redacted_display()),
    };
    // The carrier choice only, and "not on the wire yet" until a carrier
    // writes it. With no record, the worker fails narrow to LAN only (the
    // object planner's doc, raven-core outbox.rs). There are no routes,
    // because at every attempt the worker re-plans this contact through
    // peer_plan, the resolver AppSubmit used. A recorded copy could only go
    // stale: an off-link learned address, a contact hidden since, or a route
    // that was forgotten.
    let _ = record_object_routes(
        data_dir,
        &message_id,
        &device,
        CarrierChoice::Auto,
        &[],
        expires_at_ms,
        now,
    );
    let _ = set_object_unsent(data_dir, &message_id, true, now);
    drop(_lock);
    // A machine drives app submits: due now, but the backoff stands (G5).
    crate::outbox::kick(Some(&device), true, false);
    Ok(Submitted {
        message_id,
        app_id,
        state: OutState::Queued,
        expires_at_ms,
        duplicate: false,
        attempt_seq: seq,
    })
}

// ------------------------------------------------------------------ inbox

/// One `AppInboxPage` request.
pub(crate) struct PageReq {
    pub(crate) consumer: String,
    pub(crate) takeover: bool,
    pub(crate) content_type: Option<String>,
    pub(crate) after: Option<String>,
    pub(crate) limit: Option<u16>,
    pub(crate) wait_ms: Option<u32>,
}

fn parse_cursor(s: &str) -> Option<(u64, [u8; 32], [u8; 16])> {
    let mut parts = s.split('.');
    let at = parts.next()?.parse::<u64>().ok()?;
    let sender = hex32(parts.next()?)?;
    let mid = hex16(parts.next()?)?;
    if parts.next().is_some() {
        return None;
    }
    Some((at, sender, mid))
}

fn format_cursor((at, sender, mid): (u64, [u8; 32], [u8; 16])) -> String {
    format!("{at}.{}.{}", hex::encode(sender), hex::encode(mid))
}

/// Page-time re-check of one item (§7.5, G5.2(5)): contact, block and lineage
/// from the session-bound certificate stored with it.
fn recheck(
    data_dir: &Path,
    item: &raven_core::app_store::AppInboxItem,
) -> Result<Option<Disposition>, String> {
    match contact_admission(data_dir, &item.sender_identity) {
        ContactAdmission::Allowed(_) => {}
        ContactAdmission::NotContact => return Ok(Some(Disposition::NotContact)),
        ContactAdmission::Blocked => return Ok(Some(Disposition::Blocked)),
        ContactAdmission::Unreadable => return Err("CONTACTS_UNREADABLE".into()),
    }
    let Ok(cert) = serde_json::from_str::<raven_core::DeviceCertificate>(&item.cert_json) else {
        return Ok(Some(Disposition::Rejected));
    };
    let revocations = raven_core::RevocationStore::load_checked(data_dir)?;
    if revocations.denies_certificate(&cert)? {
        return Ok(Some(Disposition::Revoked));
    }
    Ok(None)
}

struct Page {
    items: Vec<AppInboxEntry>,
    next: Option<String>,
    more: bool,
    pending: u32,
}

fn page_once(data_dir: &Path, req: &PageReq, takeover: bool) -> AppResult<Page> {
    gate()?;
    if !token_ok(&req.consumer, MAX_CONSUMER) {
        return err(
            "APP_BAD_CONSUMER",
            "consumer must be 1..64 of [A-Za-z0-9._:-]",
        );
    }
    let content_type = match req.content_type.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(ct) if content_type_ok(ct) && content_type_registered(ct, lab()) => Some(ct),
        Some(_) => {
            return err(
                "APP_BAD_CONTENT_TYPE",
                "content type is not registered on this node",
            )
        }
    };
    let after = match req.after.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(c) => Some(parse_cursor(c).ok_or(("APP_BAD_CURSOR", "bad cursor".to_string()))?),
    };
    let limit = req.limit.unwrap_or(PAGE_DEFAULT).min(PAGE_MAX) as usize;
    let sealer = PlatformRowSealer::new(data_dir);
    let mut store = AppStore::open(data_dir, &sealer).map_err(|e| ("APP_STORE", e))?;
    let query = PageQuery {
        content_type,
        after,
        limit,
        byte_budget: PAGE_BYTE_BUDGET,
    };
    let now = now_ms();
    let result = store
        .page_query(&req.consumer, takeover, &query, now, &|item| {
            recheck(data_dir, item)
        })
        .map_err(|e| {
            if e.starts_with("APP_CONSUMER_BUSY") {
                ("APP_CONSUMER_BUSY", e)
            } else if e.starts_with("CONTACTS_UNREADABLE") {
                (
                    "CONTACTS_UNREADABLE",
                    "the contact book cannot be read".to_string(),
                )
            } else {
                ("APP_STORE", e)
            }
        })?;
    let engine = base64::engine::general_purpose::STANDARD;
    let items = result
        .items
        .into_iter()
        .map(|item| {
            let verified = matches!(
                contact_admission(data_dir, &item.sender_identity),
                ContactAdmission::Allowed(ref c) if c.pinned
            );
            AppInboxEntry {
                sender_identity_hex: hex::encode(item.sender_identity),
                sender_device_hex: hex::encode(item.sender_device),
                sender_address: raven_core::encode_address(&item.sender_identity),
                sender_verified: verified,
                message_id_hex: hex::encode(item.message_id),
                app_id_hex: hex::encode(item.app_id),
                content_type: item.content_type,
                created_at_ms: item.created_at_ms,
                received_at_ms: item.received_at_ms,
                expires_at_ms: item.expires_at_ms,
                body_b64: engine.encode(item.body.as_bytes()),
            }
        })
        .collect();
    Ok(Page {
        items,
        next: result.next.map(format_cursor),
        more: result.more,
        pending: result.pending,
    })
}

/// `AppInboxPage`: a blocking page read; when it is empty and `wait_ms > 0`,
/// wait (at most 20 s) for the inbox generation to move, then read again.
pub(crate) async fn page(v: u16, data_dir: Arc<PathBuf>, req: PageReq) -> IpcResponse {
    let wait = Duration::from_millis(u64::from(req.wait_ms.unwrap_or(0).min(LONG_POLL_MAX_MS)));
    let deadline = tokio::time::Instant::now() + wait;
    let req = Arc::new(req);
    let mut takeover = req.takeover;
    loop {
        let seen = raven_core::app_channel::generation();
        let (dd, r) = (Arc::clone(&data_dir), Arc::clone(&req));
        let once = tokio::task::spawn_blocking(move || page_once(&dd, &r, takeover))
            .await
            .unwrap_or_else(|e| err("INTERNAL", format!("app page worker: {e}")));
        // A takeover binds once; the re-reads only page.
        takeover = false;
        let page = match once {
            Ok(page) => page,
            Err((code, message)) => {
                return IpcResponse::Error {
                    v,
                    code: code.into(),
                    message,
                }
            }
        };
        let limit = req.limit.unwrap_or(PAGE_DEFAULT);
        if !page.items.is_empty() || limit == 0 || tokio::time::Instant::now() >= deadline {
            return IpcResponse::AppInboxPageResult {
                v,
                items: page.items,
                next: page.next,
                more: page.more,
                pending: page.pending,
            };
        }
        while raven_core::app_channel::generation() == seen {
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(LONG_POLL_TICK).await;
        }
    }
}

/// `AppInboxAck` (blocking). Unknown refs are ignored: acks are idempotent.
pub(crate) fn ack(
    v: u16,
    data_dir: &Path,
    consumer: &str,
    items: &[AppInboxRef],
    disposition: &str,
) -> IpcResponse {
    to_response(
        v,
        ack_inner(data_dir, consumer, items, disposition)
            .map(|removed| IpcResponse::AppInboxAckResult { v, removed }),
    )
}

fn ack_inner(
    data_dir: &Path,
    consumer: &str,
    items: &[AppInboxRef],
    disposition: &str,
) -> AppResult<u32> {
    gate()?;
    if !token_ok(consumer, MAX_CONSUMER) {
        return err(
            "APP_BAD_CONSUMER",
            "consumer must be 1..64 of [A-Za-z0-9._:-]",
        );
    }
    let disposition = match disposition {
        "done" => Disposition::Done,
        "rejected" => Disposition::Rejected,
        _ => {
            return err(
                "APP_BAD_DISPOSITION",
                "disposition must be done or rejected",
            )
        }
    };
    if items.len() > ACK_MAX {
        return err("APP_BAD_ACK", format!("at most {ACK_MAX} items per ack"));
    }
    let mut parsed = Vec::with_capacity(items.len());
    for item in items {
        let (Some(sender), Some(mid)) =
            (hex32(&item.sender_device_hex), hex16(&item.message_id_hex))
        else {
            return err("APP_BAD_ACK", "bad item reference");
        };
        parsed.push((sender, mid));
    }
    let mut store = AppStore::open(data_dir, &MetadataOnly).map_err(|e| ("APP_STORE", e))?;
    let now = now_ms();
    let mut removed = 0;
    for (sender, mid) in parsed {
        match store.ack(consumer, &sender, &mid, disposition, now) {
            Ok(true) => removed += 1,
            Ok(false) => {}
            Err(e) if e.starts_with("APP_CONSUMER_BUSY") => return Err(("APP_CONSUMER_BUSY", e)),
            Err(e) => return Err(("APP_STORE", e)),
        }
    }
    if removed > 0 {
        raven_core::app_channel::bump_generation();
    }
    Ok(removed)
}

// ------------------------------------------------------------------ AgentSign

/// Rate windows (§4.2): locally initiated tasks, and answers per recipient
/// and in total, each over the last minute.
const SIGN_WINDOW: Duration = Duration::from_secs(60);
const SIGN_TASKS_PER_MIN: usize = 60;
const SIGN_ANSWERS_PER_RECIPIENT_PER_MIN: usize = 30;
const SIGN_ANSWERS_PER_MIN: usize = 120;

#[derive(Default)]
struct SignWindows {
    tasks: std::collections::VecDeque<std::time::Instant>,
    answers: std::collections::VecDeque<std::time::Instant>,
    per_recipient:
        std::collections::HashMap<String, std::collections::VecDeque<std::time::Instant>>,
}

fn sign_windows() -> &'static std::sync::Mutex<SignWindows> {
    static W: std::sync::OnceLock<std::sync::Mutex<SignWindows>> = std::sync::OnceLock::new();
    W.get_or_init(Default::default)
}

/// Take one slot in the window for `kind` (`false`: the bucket is empty).
fn take_sign_slot(kind: &str, recipient: &str, now: std::time::Instant) -> bool {
    let mut w = sign_windows().lock().unwrap_or_else(|e| e.into_inner());
    let fresh = |q: &mut std::collections::VecDeque<std::time::Instant>| {
        while q
            .front()
            .is_some_and(|t| now.saturating_duration_since(*t) >= SIGN_WINDOW)
        {
            q.pop_front();
        }
    };
    if kind == "task" {
        fresh(&mut w.tasks);
        if w.tasks.len() >= SIGN_TASKS_PER_MIN {
            return false;
        }
        w.tasks.push_back(now);
        return true;
    }
    fresh(&mut w.answers);
    w.per_recipient.retain(|_, q| {
        while q
            .front()
            .is_some_and(|t| now.saturating_duration_since(*t) >= SIGN_WINDOW)
        {
            q.pop_front();
        }
        !q.is_empty()
    });
    let per = w.per_recipient.get(recipient).map_or(0, |q| q.len());
    if w.answers.len() >= SIGN_ANSWERS_PER_MIN || per >= SIGN_ANSWERS_PER_RECIPIENT_PER_MIN {
        return false;
    }
    w.answers.push_back(now);
    w.per_recipient
        .entry(recipient.to_string())
        .or_default()
        .push_back(now);
    true
}

/// The key of the contact whose RVN1 address is `address`, if any. A book
/// that cannot be read (sealed without its key, corrupt) is an error of the
/// signature that asked, never "not a contact" (privacy pack PP.4).
fn contact_key_for_address(data_dir: &Path, address: &str) -> AppResult<Option<[u8; 32]>> {
    let rows: Vec<serde_json::Value> = raven_core::contact_book::read_rows(data_dir)
        .map_err(|_| {
            (
                "CONTACTS_UNREADABLE",
                "the contact book cannot be read".to_string(),
            )
        })?
        .unwrap_or_default();
    Ok(rows
        .iter()
        .filter_map(|row| hex32(row.get("pub_hex")?.as_str()?))
        .find(|key| raven_core::encode_address(key) == address))
}

/// `AgentSign` (blocking: contact book, identity store).
pub(crate) fn agent_sign(
    v: u16,
    data_dir: &Path,
    statement: &raven_core::agent_sign::AgentDelegationStatement,
) -> IpcResponse {
    to_response(
        v,
        agent_sign_inner(data_dir, statement, now_ms() / 1000).map(|(address, public, sig)| {
            IpcResponse::AgentSignResult {
                v,
                signer_address: address,
                signer_pub_hex: public,
                signature_b64: base64::engine::general_purpose::STANDARD.encode(sig),
            }
        }),
    )
}

fn agent_sign_inner(
    data_dir: &Path,
    statement: &raven_core::agent_sign::AgentDelegationStatement,
    now_secs: u64,
) -> AppResult<(String, String, [u8; 64])> {
    gate()?;
    // The worker's identity when it runs; otherwise from the store.
    let identity = match crate::outbox::attempt_ctx() {
        Some(ctx) => Arc::clone(&ctx.identity),
        None => Arc::new(
            raven_core::load_identity_required(data_dir)
                .map_err(|e| ("IDENTITY_UNAVAILABLE", e.to_string()))?,
        ),
    };
    let own = identity.address();
    // An RVN1 address is a hash of the key: find the contact whose key
    // encodes to it, then run the usual admission (blocked, unreadable).
    let recipient_key = contact_key_for_address(data_dir, &statement.recipient)?;
    let is_contact = |recipient: &str| {
        recipient == statement.recipient
            && recipient_key.is_some_and(|key| {
                matches!(
                    contact_admission(data_dir, &key),
                    ContactAdmission::Allowed(_)
                )
            })
    };
    let bytes = raven_core::agent_sign::validate(statement, &own, &is_contact, now_secs)
        .map_err(|e| (e.code(), "the delegation statement was refused".to_string()))?;
    if !take_sign_slot(
        &statement.kind,
        &statement.recipient,
        std::time::Instant::now(),
    ) {
        return err(
            "AGENT_SIGN_RATE",
            "too many signatures in the last minute; retry shortly",
        );
    }
    let sig = raven_core::agent_sign::sign(&identity, &bytes);
    Ok((own, hex::encode(identity.public_key_bytes()), sig))
}

#[cfg(test)]
mod tests {
    use super::*;
    // Qualified: a glob would clash with this module's own `pair` (E0659).
    use crate::outbox::test_rig as rig;
    use crate::outbox::{peer_plan, PeerPlan};
    use raven_core::identity::Identity;
    use raven_core::outbox::{object_route_records, plan_object_routes_preferring};
    use std::net::IpAddr;
    use std::sync::atomic::Ordering;

    const DAY: u64 = 24 * 60 * 60 * 1000;
    /// Bob's saved LAN and Internet addresses, and where he last reached A
    /// from on his saved LAN port (`lan_seen`): a network A may have left.
    const SAVED: &str = "10.0.0.5:7420";
    const INET: &str = "203.0.113.9:7422";
    const LEARNED: &str = "192.168.1.20:7420";

    /// A's data dir and the resolver's context parts: nothing here dials
    /// ([`rig::NoDial`]) or opens a store.
    struct Node {
        dir: tempfile::TempDir,
        alice: Arc<Identity>,
        bob: [u8; 32],
        nodial: Arc<rig::NoDial>,
    }

    impl Node {
        fn new(seed: u8) -> Self {
            Self {
                dir: tempfile::tempdir().unwrap(),
                alice: Arc::new(Identity::from_seed(&[seed; 32])),
                bob: Identity::from_seed(&[seed.wrapping_add(1); 32]).public_key_bytes(),
                nodial: Arc::new(rig::NoDial::default()),
            }
        }

        fn dir(&self) -> &Path {
            self.dir.path()
        }

        /// LAN only, the route memory off, netwatch's view not known.
        fn ctx(&self) -> AttemptCtx {
            rig::test_ctx(self.dir(), Arc::clone(&self.alice), self.nodial.clone())
        }

        /// Every carrier gate open.
        fn ctx_all(&self) -> AttemptCtx {
            AttemptCtx {
                internet_live: rig::on,
                p2p_live: rig::on,
                ..self.ctx()
            }
        }

        /// Bob last reached A from [`LEARNED`]'s IP.
        fn seen(&self) {
            let ip: IpAddr = "192.168.1.20".parse().unwrap();
            raven_core::lan_seen::record_contact_seen(self.dir(), &self.bob, ip, None, now_ms())
                .unwrap();
        }

        /// What `resolve` plans for Bob under `ctx`, as planned.
        fn resolved(&self, ctx: &AttemptCtx) -> Vec<OutboxRoute> {
            let (device, routes) = resolve(ctx, &self.bob, now_ms()).unwrap();
            assert_eq!(device, self.bob);
            routes.into_iter().map(|(planned, _)| planned).collect()
        }

        /// The worker's resolver for Bob under `ctx`.
        fn plan(&self, ctx: &AttemptCtx) -> PeerPlan {
            let ContactAdmission::Allowed(book) = contact_admission(self.dir(), &self.bob) else {
                panic!("Bob is a contact");
            };
            peer_plan(ctx, &self.bob, book, now_ms())
        }

        /// The routes the worker plans for the recorded object `mid` under
        /// `ctx` (its record, the resolver's contact and gates).
        fn object_plan(&self, ctx: &AttemptCtx, mid: &[u8; 16]) -> Vec<OutboxRoute> {
            let records = object_route_records(self.dir(), now_ms()).unwrap();
            let plan = self.plan(ctx);
            plan_object_routes_preferring(records.get(mid), &plan.contact, plan.gates, None).routes
        }

        fn record(&self, mid: &[u8; 16], routes: &[OutboxRoute]) {
            record_object_routes(
                self.dir(),
                mid,
                &self.bob,
                CarrierChoice::Auto,
                routes,
                now_ms() + DAY,
                now_ms(),
            )
            .unwrap();
        }

        /// One verified contacts.json row for Bob: saved LAN and Internet
        /// addresses, hidden from or not.
        fn book_hidden(&self, hide_ip: bool) {
            let row = serde_json::json!([{
                "pub_hex": hex::encode(self.bob),
                "pinned": true,
                "lan_dial": SAVED,
                "internet_dial": INET,
                "hide_ip": hide_ip,
            }]);
            std::fs::write(
                self.dir().join("contacts.json"),
                serde_json::to_vec(&row).unwrap(),
            )
            .unwrap();
        }
    }

    fn off_link(_: IpAddr) -> Option<bool> {
        Some(false)
    }

    fn on_link(_: IpAddr) -> Option<bool> {
        Some(true)
    }

    fn has_inet(routes: &[OutboxRoute]) -> bool {
        routes.iter().any(|r| r.carrier == OutboxCarrier::Internet)
    }

    /// 6a: AppSubmit plans as the worker does (0b.6): a learned LAN address
    /// on none of this computer's networks is not dialled, so the signed
    /// bind never goes to whoever holds it now; on link or not known, it is.
    #[test]
    fn resolve_leaves_out_an_off_link_learned_lan_route_like_the_worker() {
        let node = Node::new(0x61);
        rig::contacts(node.dir(), &node.bob, SAVED, "", false);
        node.seen();
        let (saved, learned) = (rig::lan(SAVED), rig::lan(LEARNED));
        let at = |on_link: fn(IpAddr) -> Option<bool>| {
            node.resolved(&AttemptCtx {
                on_link,
                ..node.ctx()
            })
        };
        assert_eq!(at(off_link), std::slice::from_ref(&saved));
        assert_eq!(at(on_link), [saved.clone(), learned.clone()]);
        assert_eq!(at(rig::unknown_link), [saved, learned]);
        assert_eq!(node.nodial.dials(), 0);
    }

    /// The worker's dial order, through `resolve`: a connected contact's p2p
    /// route first, then the remembered route, then plan order.
    #[test]
    fn resolve_orders_connected_then_remembered_routes_first() {
        let node = Node::new(0x63);
        let p = rig::contacts_all(node.dir(), &node.bob, SAVED, INET);
        node.seen();
        let (saved, i) = (rig::lan(SAVED), rig::inet(INET));
        rig::remember(node.dir(), &node.bob, &i, "test-net");
        let at = |connected: fn(&OutboxRoute) -> bool| {
            node.resolved(&AttemptCtx {
                net_tag: rig::test_net,
                on_link: off_link,
                connected,
                ..node.ctx_all()
            })
        };
        assert_eq!(
            at(rig::p2p_connected),
            [p.clone(), i.clone(), saved.clone()]
        );
        assert_eq!(at(rig::never_connected), [i, saved, p]);
        assert_eq!(node.nodial.dials(), 0);
    }

    /// The app record holds the carrier choice only: an address learned on
    /// a network this computer has left never comes back through it.
    #[test]
    fn an_app_record_never_brings_back_an_off_link_learned_route() {
        let node = Node::new(0x65);
        rig::contacts(node.dir(), &node.bob, SAVED, "", false);
        node.seen();
        let learned = rig::lan(LEARNED);
        let here = AttemptCtx {
            on_link,
            ..node.ctx()
        };
        let resolved = node.resolved(&here);
        assert!(resolved.contains(&learned), "{resolved:?}");
        // Recorded as submit_with records it.
        let mid = [0x65; 16];
        node.record(&mid, &[]);
        let left = AttemptCtx {
            on_link: off_link,
            ..node.ctx()
        };
        assert_eq!(node.object_plan(&left, &mid), [rig::lan(SAVED)]);

        // _before_6a_it_did: a record holding the routes AppSubmit planned
        // on that network brought the learned address back after the
        // computer left it. This documents the bug; it is not how app
        // objects are recorded now.
        let old = [0x66; 16];
        node.record(&old, &resolved);
        assert!(node.object_plan(&left, &old).contains(&learned));
        assert_eq!(node.nodial.dials(), 0);
    }

    /// Hide my IP (step 4 (c)) reaches AppSubmit: no Internet direct route
    /// for a contact this node hides its IP from.
    #[test]
    fn resolve_plans_no_internet_direct_for_a_hidden_contact() {
        let node = Node::new(0x67);
        node.book_hidden(false);
        assert!(has_inet(&node.resolved(&node.ctx_all())));
        node.book_hidden(true);
        let hidden = node.resolved(&node.ctx_all());
        assert_eq!(hidden, [rig::lan(SAVED)]);
        assert_eq!(node.nodial.dials(), 0);
    }

    /// Phase 6a (P6.12, OD6a-11): AppSubmit, the route-hints announcer and
    /// the worker share one resolver, so they follow the same learned
    /// carrier order (and, with learning off, the same static one); none of
    /// them teaches the route memory. Nothing is dialled.
    #[test]
    fn app_submit_and_announcer_follow_the_same_order() {
        let node = Node::new(0x75);
        node.book_hidden(false);
        let ctx = node.ctx_all();
        let chat = [0x75; 16];
        node.record(&chat, &[]);
        let announced = |ctx: &AttemptCtx| -> Vec<OutboxRoute> {
            crate::hints::announce_routes(ctx, &node.bob, now_ms())
                .into_iter()
                .map(|(planned, _)| planned)
                .collect()
        };
        let worker = |ctx: &AttemptCtx| -> Vec<OutboxRoute> {
            let records = object_route_records(node.dir(), now_ms()).unwrap();
            node.plan(ctx)
                .object_routes(&node.bob, records.get(&chat))
                .routes
        };
        let statics = [rig::lan(SAVED), rig::inet(INET)];
        assert_eq!(node.resolved(&ctx), statics);
        assert_eq!(announced(&ctx), statics);
        assert_eq!(worker(&ctx), statics);
        let mut learning = crate::learning::TestService::loaded(node.dir(), Some("home"));
        learning.teach(&node.bob, OutboxCarrier::Lan, OutboxCarrier::Internet, 4);
        let learned = [rig::inet(INET), rig::lan(SAVED)];
        assert_eq!(node.resolved(&ctx), learned);
        assert_eq!(announced(&ctx), learned);
        assert_eq!(worker(&ctx), learned);
        drop(learning);
        assert_eq!(node.resolved(&ctx), statics);
        assert!(!node
            .dir()
            .join(raven_core::route_memory::ROUTE_MEMORY_FILE)
            .exists());
        assert_eq!(node.nodial.dials(), 0);
    }

    /// `raven node hide-ip on` (every contact) reaches AppSubmit and the
    /// worker's resolver whatever the route hints gate: no Internet direct
    /// route, as the p2p dialer and the peer gate already apply it.
    #[test]
    fn node_hide_ip_plans_no_internet_direct_whatever_the_route_hints_gate() {
        let node = Node::new(0x71);
        node.book_hidden(false);
        let ctx = node.ctx_all();
        let chat = [0x71; 16];
        node.record(&chat, &[rig::inet(INET)]);
        assert!(has_inet(&node.resolved(&ctx)));
        raven_core::node_policy::save_policy(
            node.dir(),
            &raven_core::NodePolicy {
                hide_ip: true,
                ..Default::default()
            },
        )
        .unwrap();
        let hidden = node.resolved(&ctx);
        assert_eq!(hidden, [rig::lan(SAVED)]);
        let dial = node
            .plan(&ctx)
            .auto_dial(&node.bob, rig::never_connected, &mut |r, _| Ok(r.clone()));
        assert!(
            dial.iter()
                .all(|(r, _)| r.carrier != OutboxCarrier::Internet),
            "{dial:?}"
        );
        let routes = node.object_plan(&ctx, &chat);
        assert!(!has_inet(&routes), "{routes:?}");
        assert_eq!(node.nodial.dials(), 0);
    }

    /// Hide-IP for records written earlier: neither an app record (choice
    /// only) nor one holding the book's Internet route (chat sends, app
    /// records before 6a) plans an Internet route once the contact is
    /// hidden.
    #[test]
    fn an_object_plans_no_internet_route_once_its_contact_is_hidden() {
        let node = Node::new(0x69);
        node.book_hidden(false);
        let (app, chat) = ([0x69; 16], [0x6a; 16]);
        node.record(&app, &[]);
        node.record(&chat, &[rig::inet(INET)]);
        let ctx = node.ctx_all();
        assert!(has_inet(&node.object_plan(&ctx, &app)));
        assert!(has_inet(&node.object_plan(&ctx, &chat)));
        node.book_hidden(true);
        for mid in [app, chat] {
            let routes = node.object_plan(&ctx, &mid);
            assert!(!has_inet(&routes), "{routes:?}");
            assert!(routes.contains(&rig::lan(SAVED)));
        }
    }

    /// While route hints are live, AppSubmit plans what a verified
    /// contact's RRH1 taught this node: its learned PeerId.
    #[test]
    fn resolve_plans_learned_rrh1_routes_while_route_hints_are_live() {
        if !raven_core::route_hints::route_hints_live() {
            eprintln!("skipped: route hints are off (RAVEN_LAB_ROUTE_HINTS=1, debug)");
            return;
        }
        let node = Node::new(0x6b);
        rig::contacts(node.dir(), &node.bob, SAVED, "", true);
        let peer_id = raven_core::p2p_route::local_peer_id(&Identity::from_seed(&[0x6d; 32]));
        let hints = raven_core::route_hints::ValidHints {
            generation: 7,
            ttl_s: raven_core::route_hints::RRH1_DEFAULT_TTL_S,
            peer_id: Some(peer_id.clone()),
            ..Default::default()
        };
        // Told over a p2p link whose PeerId is the one it names: proven.
        let link = raven_core::route_hints::HintLink {
            carrier: OutboxCarrier::P2p,
            peer_ip: None,
            peer_zone: None,
            link_peer_id: Some(&peer_id),
            book_peer_id: None,
            pinned: true,
            sender: node.bob,
            local: node.alice.public_key_bytes(),
            local_p2p: raven_core::p2p_route::libp2p_ed25519_public(&node.alice),
            local_relay: None,
            lab_local: false,
            lab_loopback: false,
        };
        let applied =
            raven_core::learned_routes::apply(node.dir(), &node.bob, &hints, &link, None, now_ms())
                .unwrap();
        assert!(
            matches!(applied, raven_core::learned_routes::Applied::Changed { .. }),
            "{applied:?}"
        );
        let learned = OutboxRoute {
            carrier: OutboxCarrier::P2p,
            dial: raven_core::p2p_route::peer_route(&peer_id),
        };
        assert_eq!(node.resolved(&node.ctx_all()), [rig::lan(SAVED), learned]);
        assert_eq!(node.nodial.dials(), 0);
    }

    /// RN-11: the admission codes stand, before any plan or dial.
    #[test]
    fn resolve_keeps_the_admission_codes() {
        let node = Node::new(0x6f);
        let code = |node: &Node| resolve(&node.ctx(), &node.bob, now_ms()).unwrap_err().0;
        // A stranger: the book names someone else.
        rig::contacts(node.dir(), &[0x01; 32], SAVED, "", true);
        assert_eq!(code(&node), "NOT_A_CONTACT");
        rig::contacts(node.dir(), &node.bob, SAVED, "", true);
        let mut blocks = raven_core::BlockList::default();
        blocks.block(&hex::encode(node.bob));
        blocks.save(node.dir()).unwrap();
        assert_eq!(code(&node), "CONTACT_BLOCKED");
        raven_core::BlockList::default().save(node.dir()).unwrap();
        std::fs::write(node.dir().join("contacts.json"), "{not json").unwrap();
        assert_eq!(code(&node), "CONTACTS_UNREADABLE");
        assert_eq!(node.nodial.dials(), 0);
    }

    // ---------------------------------------------- 6b: the no-session probe

    /// The p2p route of [`rig::contacts_all`]'s book, without a book.
    fn p2p_route() -> OutboxRoute {
        let peer_id = raven_core::p2p_route::local_peer_id(&Identity::from_seed(&[0x77; 32]));
        OutboxRoute {
            carrier: OutboxCarrier::P2p,
            dial: raven_core::p2p_route::peer_route(&peer_id),
        }
    }

    fn never_refused(_: &OutboxRoute, _: Instant) -> bool {
        false
    }

    thread_local! {
        /// [`refused_once`]: the FakeNet, and the mode its p2p route takes
        /// after the one refusal.
        static AFTER_REFUSAL: std::cell::RefCell<Option<(Arc<rig::FakeNet>, u8)>> =
            const { std::cell::RefCell::new(None) };
    }

    /// The contact's PeerId turned the first p2p dial away (something
    /// passing); from then on the route behaves as [`AFTER_REFUSAL`] says.
    fn refused_once(route: &OutboxRoute, _: Instant) -> bool {
        route.carrier == OutboxCarrier::P2p
            && AFTER_REFUSAL
                .with(|a| a.borrow_mut().take())
                .is_some_and(|(net, mode)| {
                    net.route_modes.lock().unwrap().insert(route.clone(), mode);
                    true
                })
    }

    /// The budget keeps the last planned route's share (plans put p2p
    /// last): a stalled route ahead cannot starve it, and nothing is dialled
    /// with under 2 s left.
    #[test]
    fn probe_deadlines_keep_the_last_route_s_share() {
        let at = |spent: f64, last: bool| probe_deadline(Duration::from_secs_f64(spent), last);
        let s = Duration::from_secs;
        assert_eq!(at(0.0, true), Some(s(10)));
        assert_eq!(at(0.0, false), Some(s(10)));
        assert_eq!(at(15.0, false), Some(s(5)));
        assert_eq!(at(15.0, true), Some(s(10)));
        assert_eq!(at(19.0, false), None);
        assert_eq!(at(25.0, true), Some(s(5)));
        assert_eq!(at(28.5, true), None);
        for spent in [30.0, 45.0] {
            assert_eq!(at(spent, true), None);
            assert_eq!(at(spent, false), None);
        }
    }

    /// LINK_NOT_ACCEPTED and WRONG_IDENTITY (not retried) only when every
    /// route was dialled and each one agrees, whichever failed last.
    #[test]
    fn probe_failure_blames_the_contact_only_when_every_route_agrees() {
        use Miss::{ForeignKey as F, NotAccepted as N, Other as O, Refused as R};
        let answer = |misses: &[Miss], walked_all: bool| probe_failure(misses, walked_all).0;
        assert_eq!(answer(&[N], true), "LINK_NOT_ACCEPTED");
        assert_eq!(answer(&[N, N, N], true), "LINK_NOT_ACCEPTED");
        assert_eq!(answer(&[N, O], true), "APP_PEER_UNREACHABLE");
        assert_eq!(answer(&[O, N], true), "APP_PEER_UNREACHABLE");
        // The budget skipped a route.
        assert_eq!(answer(&[N], false), "APP_PEER_UNREACHABLE");
        assert_eq!(answer(&[F, F], true), "WRONG_IDENTITY");
        assert_eq!(answer(&[F, N], true), "APP_PEER_UNREACHABLE");
        assert_eq!(answer(&[], true), "APP_PEER_UNREACHABLE");
        // A p2p refusal the recheck did not confirm is not the contact's
        // verdict.
        assert_eq!(answer(&[R], true), "APP_PEER_UNREACHABLE");
        assert_eq!(answer(&[N, N, R], true), "APP_PEER_UNREACHABLE");
    }

    /// A p2p dial the contact's own PeerId turned away is its refusal (one-way
    /// trust over p2p), to be confirmed by a second dial ([`probe`]); the
    /// error text alone is not. A dial-level identity mismatch stays
    /// retryable.
    #[test]
    fn a_p2p_refusal_by_the_contact_counts_as_not_accepted() {
        let (p2p, lan) = (p2p_route(), rig::lan(SAVED));
        let unreachable = crate::p2p::P2P_UNREACHABLE;
        assert_eq!(miss_for(&p2p, unreachable, true), Miss::Refused);
        assert_eq!(miss_for(&p2p, unreachable, false), Miss::Other);
        let not_accepted = crate::netutil::LINK_NOT_ACCEPTED;
        assert_eq!(miss_for(&lan, not_accepted, false), Miss::NotAccepted);
        assert_eq!(
            miss_for(&lan, "rlb1 offer identity mismatch", false),
            Miss::Other
        );
        // Only a p2p route's PeerId refuses.
        assert_eq!(miss_for(&lan, "connection refused", true), Miss::Other);
    }

    /// A walk that found nobody rests only for the same routes in the same
    /// order, and only within the cooldown.
    #[test]
    fn probe_cooled_only_for_the_same_routes_inside_the_cooldown() {
        let t0 = Instant::now();
        let walked = [rig::lan(SAVED), rig::inet(INET)];
        let last = Some((t0, &walked[..]));
        assert!(!probe_cooled(None, &walked, t0));
        assert!(probe_cooled(last, &walked, t0));
        assert!(probe_cooled(last, &walked, t0 + Duration::from_secs(14)));
        assert!(!probe_cooled(last, &walked, t0 + APP_PROBE_COOLDOWN));
        assert!(!probe_cooled(last, &walked[..1], t0));
        assert!(!probe_cooled(last, &[rig::inet(INET), rig::lan(SAVED)], t0));
        let more = [rig::lan(SAVED), rig::inet(INET), p2p_route()];
        assert!(!probe_cooled(last, &more, t0));
    }

    /// A and Bob with a [`rig::FakeNet`] between them: Bob's book pins A,
    /// A's book is each test's own, and there is no session yet.
    struct Peers {
        a: tempfile::TempDir,
        _b: tempfile::TempDir,
        alice: Arc<Identity>,
        bob: [u8; 32],
        b_bundle: LanBundle,
        net: Arc<rig::FakeNet>,
    }

    impl Peers {
        /// `None` without the lab file backends (it says so).
        fn new(seed: u8) -> Option<Self> {
            if !rig::lab_backends() {
                return None;
            }
            let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
            let alice = Identity::from_seed(&[seed; 32]);
            let bob = Identity::from_seed(&[seed.wrapping_add(1); 32]);
            for (dir, id) in [(a.path(), &alice), (b.path(), &bob)] {
                raven_core::device_cert::ensure_local_device_certificate(
                    dir,
                    id,
                    PRIMARY_DEVICE_ID,
                )
                .unwrap();
                raven_core::ensure_local_prekey(dir, id).unwrap();
            }
            rig::contacts(b.path(), &alice.public_key_bytes(), "", "", true);
            let a_bundle = raven_core::local_bundle(a.path(), &alice).unwrap();
            let b_bundle = raven_core::local_bundle(b.path(), &bob).unwrap();
            let bob_pub = bob.public_key_bytes();
            let alice_pub = alice.public_key_bytes();
            let net = rig::FakeNet::new(b.path().to_path_buf(), bob, a_bundle, alice_pub);
            Some(Self {
                a,
                _b: b,
                alice: Arc::new(alice),
                bob: bob_pub,
                b_bundle,
                net: Arc::new(net),
            })
        }

        fn dir(&self) -> &Path {
            self.a.path()
        }

        /// Every carrier gate open; the route memory off, nobody connected.
        fn ctx(&self) -> AttemptCtx {
            AttemptCtx {
                internet_live: rig::on,
                p2p_live: rig::on,
                ..rig::test_ctx(self.dir(), Arc::clone(&self.alice), self.net.clone())
            }
        }

        /// Bob's verified row in A's book (saved LAN, Internet, p2p): his
        /// p2p route.
        fn book(&self) -> OutboxRoute {
            rig::contacts_all(self.dir(), &self.bob, SAVED, INET)
        }

        /// Dials of `route` behave as `mode`; the rest as the FakeNet's
        /// mode (DOWN until a test sets it).
        fn set(&self, route: &OutboxRoute, mode: u8) {
            self.net
                .route_modes
                .lock()
                .unwrap()
                .insert(route.clone(), mode);
        }

        fn set_all(&self, mode: u8) {
            self.net.mode.store(mode, Ordering::SeqCst);
        }

        /// (route, frames) per dial so far.
        fn log(&self) -> Vec<(OutboxRoute, usize)> {
            self.net.log.lock().unwrap().clone()
        }

        fn dials(&self) -> usize {
            self.net.dials.load(Ordering::SeqCst)
        }

        /// [`probe`] over `routes` (each as planned and dialled, set to its
        /// mode) for `device`, from a fresh log: the route that offered, and
        /// the routes dialled (each frame-less).
        fn walk(
            &self,
            routes: &[(OutboxRoute, u8)],
            device: &[u8; 32],
            refused: fn(&OutboxRoute, Instant) -> bool,
        ) -> (AppResult<OutboxRoute>, Vec<OutboxRoute>) {
            self.walk_from(routes, device, refused, Instant::now())
        }

        /// [`Self::walk`] with the budget counted from `started`.
        fn walk_from(
            &self,
            routes: &[(OutboxRoute, u8)],
            device: &[u8; 32],
            refused: fn(&OutboxRoute, Instant) -> bool,
            started: Instant,
        ) -> (AppResult<OutboxRoute>, Vec<OutboxRoute>) {
            self.net.log.lock().unwrap().clear();
            for (route, mode) in routes {
                self.set(route, *mode);
            }
            let pairs: Vec<RoutePair> =
                routes.iter().map(|(r, _)| (r.clone(), r.clone())).collect();
            let out = probe(&self.ctx(), device, &pairs, started, refused);
            let dialled = self
                .log()
                .into_iter()
                .map(|(route, frames)| {
                    assert_eq!(frames, 0, "a probe is frame-less");
                    route
                })
                .collect();
            (out.map(|(_, route)| route), dialled)
        }

        fn req(&self, client_ref: &str) -> SubmitReq {
            SubmitReq {
                peer_identity_hex: hex::encode(self.bob),
                content_type: raven_core::app_channel::CT_TEST.into(),
                client_ref: client_ref.into(),
                body_b64: base64::engine::general_purpose::STANDARD.encode("agent task 1"),
                ttl_ms: None,
                resend: false,
            }
        }

        fn pair_attempts(&self) -> i64 {
            AppStore::open(self.dir(), &MetadataOnly)
                .unwrap()
                .pair_attempts_today(&self.bob, now_ms())
                .unwrap()
        }
    }

    /// Submit tests run the gated op: the lab unlock (RAVEN_LAB_TEST_A=1).
    fn submit_peers(seed: u8) -> Option<Peers> {
        if !app_channel_live_enabled() {
            eprintln!("skipped: the app channel is held (RAVEN_LAB_TEST_A=1, debug)");
            return None;
        }
        Peers::new(seed)
    }

    /// x4 as a unit test: a dead LAN and a dead Internet route ahead of a
    /// working p2p route. The walk reaches p2p, which the old two-route walk
    /// never did.
    #[test]
    fn the_probe_walks_past_two_dead_routes() {
        let Some(peers) = Peers::new(0x71) else {
            return;
        };
        let (lan, inet, p2p) = (rig::lan(SAVED), rig::inet(INET), p2p_route());
        let routes = [
            (lan.clone(), rig::DOWN),
            (inet.clone(), rig::DOWN),
            (p2p.clone(), rig::UP),
        ];
        let (out, dialled) = peers.walk(&routes, &peers.bob, never_refused);
        assert_eq!(out.unwrap(), p2p);
        assert_eq!(dialled, [lan, inet, p2p]);
    }

    #[test]
    fn the_probe_stops_at_the_first_offer() {
        let Some(peers) = Peers::new(0x73) else {
            return;
        };
        let (lan, inet) = (rig::lan(SAVED), rig::inet(INET));
        let routes = [(lan.clone(), rig::UP), (inet, rig::UP)];
        let (out, dialled) = peers.walk(&routes, &peers.bob, never_refused);
        assert_eq!(out.unwrap(), lan);
        assert_eq!(dialled, [lan]);
    }

    /// The probe walks `resolve`'s order: a connected contact's p2p route
    /// first, and it offers.
    #[test]
    fn the_probe_takes_a_connected_route_first() {
        let Some(peers) = Peers::new(0x75) else {
            return;
        };
        let p2p = peers.book();
        peers.set_all(rig::UP);
        let ctx = AttemptCtx {
            connected: rig::p2p_connected,
            ..peers.ctx()
        };
        let (device, routes) = resolve(&ctx, &peers.bob, now_ms()).unwrap();
        assert_eq!(routes.len(), 3, "{routes:?}");
        let (_, route) = probe(&ctx, &device, &routes, Instant::now(), never_refused).unwrap();
        assert_eq!(route, p2p);
        assert_eq!(peers.log(), [(p2p, 0)]);
    }

    #[test]
    fn the_probe_maps_refusals_end_to_end() {
        let Some(peers) = Peers::new(0x7b) else {
            return;
        };
        let (lan, inet, p2p) = (rig::lan(SAVED), rig::inet(INET), p2p_route());
        let answer = |out: AppResult<OutboxRoute>| out.unwrap_err().0;
        let bob = peers.bob;
        // One route: as before 6b.
        let (out, _) = peers.walk(&[(lan.clone(), rig::NOT_ACCEPTED)], &bob, never_refused);
        assert_eq!(answer(out), "LINK_NOT_ACCEPTED");
        // A refusal and a route down: not the contact's verdict.
        let routes = [(lan.clone(), rig::NOT_ACCEPTED), (inet.clone(), rig::DOWN)];
        let (out, dialled) = peers.walk(&routes, &bob, never_refused);
        assert_eq!(answer(out), "APP_PEER_UNREACHABLE");
        assert_eq!(dialled, [lan.clone(), inet.clone()]);
        // One-way trust (§12 row 22): LAN and Internet refuse this node and
        // the contact's p2p gate turned the p2p dial away, the recheck too.
        let refusing = [
            (lan.clone(), rig::NOT_ACCEPTED),
            (inet.clone(), rig::NOT_ACCEPTED),
            (p2p.clone(), rig::DOWN),
        ];
        let (out, dialled) = peers.walk(&refusing, &bob, |r, _| r.carrier == OutboxCarrier::P2p);
        assert_eq!(answer(out), "LINK_NOT_ACCEPTED");
        assert_eq!(dialled, [lan.clone(), inet, p2p.clone(), p2p.clone()]);
        // The same contact behind a relay: its gate turns the circuit away
        // before Noise and the relay answers CONNECTION_FAILED, which is
        // never a refusal (`p2p::target_refused_since` stays false,
        // `a_relay_s_circuit_answer_is_never_a_quick_close`): a failed STOP
        // to a contact that is gone gives the same answer. The walk then
        // cannot blame the contact: retryable, and for a p2p-only contact
        // too (no recheck: nothing refused).
        let (out, _) = peers.walk(&refusing, &bob, never_refused);
        assert_eq!(answer(out), "APP_PEER_UNREACHABLE");
        let (out, dialled) = peers.walk(&[(p2p.clone(), rig::DOWN)], &bob, never_refused);
        assert_eq!(answer(out), "APP_PEER_UNREACHABLE");
        assert_eq!(dialled, [p2p]);
        // A dial-level identity mismatch: retryable, as before.
        let (out, _) = peers.walk(&[(lan.clone(), rig::WRONG_ID)], &bob, never_refused);
        assert_eq!(answer(out), "APP_PEER_UNREACHABLE");
        // Bob's offer, probed for another device: another key answered.
        let other = Identity::from_seed(&[0x7f; 32]).public_key_bytes();
        let (out, _) = peers.walk(&[(lan, rig::UP)], &other, never_refused);
        assert_eq!(answer(out), "WRONG_IDENTITY");
    }

    /// A p2p refusal decides a walk only when the recheck dial is turned
    /// away too: something passing (the contact's node re-homing its p2p
    /// host or shutting down, its relay's STOP failing) stays retryable, and
    /// an offer on the recheck wins. With no budget left for the recheck the
    /// refusal is not confirmed either.
    #[test]
    fn a_p2p_refusal_the_recheck_does_not_repeat_stays_retryable() {
        let Some(peers) = Peers::new(0x7d) else {
            return;
        };
        let (lan, inet, p2p) = (rig::lan(SAVED), rig::inet(INET), p2p_route());
        let answer = |out: AppResult<OutboxRoute>| out.unwrap_err().0;
        let bob = peers.bob;
        let refuse_once_then = |mode: u8| {
            AFTER_REFUSAL.with(|a| *a.borrow_mut() = Some((Arc::clone(&peers.net), mode)));
        };
        // A p2p-only contact, down on the recheck.
        refuse_once_then(rig::DOWN);
        let (out, dialled) = peers.walk(&[(p2p.clone(), rig::DOWN)], &bob, refused_once);
        assert_eq!(answer(out), "APP_PEER_UNREACHABLE");
        assert_eq!(dialled, [p2p.clone(), p2p.clone()]);
        // LAN and Internet refuse this node, p2p only once.
        refuse_once_then(rig::DOWN);
        let refusing = [
            (lan.clone(), rig::NOT_ACCEPTED),
            (inet.clone(), rig::NOT_ACCEPTED),
            (p2p.clone(), rig::DOWN),
        ];
        let (out, dialled) = peers.walk(&refusing, &bob, refused_once);
        assert_eq!(answer(out), "APP_PEER_UNREACHABLE");
        assert_eq!(dialled, [lan, inet, p2p.clone(), p2p.clone()]);
        // The recheck offers: it wins.
        refuse_once_then(rig::UP);
        let (out, dialled) = peers.walk(&[(p2p.clone(), rig::DOWN)], &bob, refused_once);
        assert_eq!(out.unwrap(), p2p);
        assert_eq!(dialled, [p2p.clone(), p2p.clone()]);
        // 2.5 s of budget left: room for the first dial, not for the pause
        // and a recheck.
        let late = Instant::now()
            .checked_sub(APP_PROBE_BUDGET - Duration::from_millis(2_500))
            .expect("the clock runs");
        let always = |r: &OutboxRoute, _: Instant| r.carrier == OutboxCarrier::P2p;
        let (out, dialled) = peers.walk_from(&[(p2p.clone(), rig::DOWN)], &bob, always, late);
        assert_eq!(answer(out), "APP_PEER_UNREACHABLE");
        assert_eq!(dialled, [p2p]);
    }

    /// RN-2 + x4: no session, a dead LAN and a dead Internet route ahead of
    /// a working p2p route. AppSubmit pairs over p2p (one attempt spent),
    /// records the carrier choice only, and teaches the route memory nothing.
    #[test]
    fn a_submit_without_a_session_pairs_past_two_dead_routes() {
        let Some(peers) = submit_peers(0x81) else {
            return;
        };
        let p2p = peers.book();
        let (lan, inet) = (rig::lan(SAVED), rig::inet(INET));
        peers.set(&lan, rig::DOWN);
        peers.set(&inet, rig::DOWN);
        peers.set(&p2p, rig::UP);
        // The route memory on: the probe and the pairing must not write it.
        let ctx = AttemptCtx {
            net_tag: rig::test_net,
            ..peers.ctx()
        };
        let done = submit_with(&ctx, peers.req("r1"), now_ms()).unwrap();
        assert_eq!((done.state, done.duplicate), (OutState::Queued, false));
        // Three frame-less probes, then the PairInit over the route that
        // offered.
        assert_eq!(
            peers.log(),
            [(lan, 0), (inet, 0), (p2p.clone(), 0), (p2p, 1)]
        );
        assert_eq!(peers.pair_attempts(), 1);
        let records = object_route_records(peers.dir(), now_ms()).unwrap();
        let rec = records.get(&done.message_id).expect("the app record");
        assert_eq!(rec.choice, CarrierChoice::Auto);
        assert!(rec.routes.is_empty() && rec.unsent, "{rec:?}");
        let memory = peers
            .dir()
            .join(raven_core::route_memory::ROUTE_MEMORY_FILE);
        assert!(!memory.exists());
    }

    /// RN-4: no session and no route answering: nothing sealed or recorded,
    /// no attempt spent. A submit right after, over the same routes, does
    /// not walk them again.
    #[test]
    fn a_submit_with_no_route_answering_seals_nothing() {
        let Some(peers) = submit_peers(0x83) else {
            return;
        };
        let p2p = peers.book();
        let ctx = peers.ctx();
        let (code, message) = submit_with(&ctx, peers.req("r1"), now_ms()).unwrap_err();
        assert_eq!(code, "APP_PEER_UNREACHABLE", "{message}");
        assert_eq!(
            peers.log(),
            [(rig::lan(SAVED), 0), (rig::inet(INET), 0), (p2p, 0)]
        );
        assert_eq!(peers.pair_attempts(), 0);
        let app = AppStore::open(peers.dir(), &MetadataOnly).unwrap();
        assert!(app.outbox_record(&peers.bob, "r1").unwrap().is_none());
        assert!(object_route_records(peers.dir(), now_ms())
            .unwrap()
            .is_empty());
        let (code, message) = submit_with(&ctx, peers.req("r2"), now_ms()).unwrap_err();
        assert_eq!(code, "APP_PEER_UNREACHABLE");
        assert!(message.contains("a moment ago"), "{message}");
        assert_eq!(peers.dials(), 3, "the cooldown: no new dial");
    }

    /// RN-5: a spent pairing budget (used up for the day, or the last
    /// attempt under a minute ago) refuses before any dial.
    #[test]
    fn a_spent_pairing_budget_refuses_before_any_dial() {
        const HOUR: u64 = 3_600_000;
        let cases: [(u8, &[u64], &str); 2] = [
            (0x85, &[4 * HOUR, 3 * HOUR, 2 * HOUR, HOUR], "used up"),
            (0x87, &[10_000], "paused until"),
        ];
        for (seed, spent_ago, says) in cases {
            let Some(peers) = submit_peers(seed) else {
                return;
            };
            peers.book();
            peers.set_all(rig::UP);
            let now = now_ms();
            let mut app = AppStore::open(peers.dir(), &MetadataOnly).unwrap();
            for ago in spent_ago {
                let spent = app
                    .spend_pair_attempt(&peers.bob, now - ago, APP_PAIR_SPACING_MS)
                    .unwrap();
                assert_eq!(spent, PairSpend::Spent);
            }
            drop(app);
            let (code, message) = submit_with(&peers.ctx(), peers.req("r1"), now).unwrap_err();
            assert_eq!(code, "APP_PAIR_BUDGET", "{message}");
            assert!(message.contains(says), "{message}");
            assert_eq!(peers.dials(), 0);
        }
    }

    /// RN-6: a usable session: no probe and no pairing. The worker dials,
    /// and none runs here.
    #[test]
    fn a_submit_with_a_session_does_not_probe() {
        let Some(peers) = submit_peers(0x89) else {
            return;
        };
        peers.book();
        peers.set_all(rig::UP);
        raven_core::cache_peer_bundle(peers.dir(), &peers.b_bundle).unwrap();
        rig::pair(
            peers.dir(),
            &peers.alice,
            &peers.net.b_dir,
            &peers.net.bob,
            &peers.net.a_bundle,
            &peers.b_bundle,
        );
        let done = submit_with(&peers.ctx(), peers.req("r1"), now_ms()).unwrap();
        assert_eq!(done.state, OutState::Queued);
        assert_eq!(peers.dials(), 0);
        assert_eq!(peers.pair_attempts(), 0);
        assert!(!crate::outbox::kick(Some(&peers.bob), true, false));
    }

    /// Privacy pack PP.4 (review R23): a book this node cannot open fails
    /// the signature with CONTACTS_UNREADABLE (retryable), never "not a
    /// contact".
    #[test]
    fn quiet_readers_fail_their_operation_on_key_unavailable() {
        use crate::at_rest_boot::tests::{lab_hist_key, profile_with, seal, serial};
        if !lab_hist_key() {
            return;
        }
        let bob = [0x0b; 32];
        let dir = profile_with(&[bob]);
        let dd = dir.path();
        let address = raven_core::encode_address(&bob);
        assert_eq!(contact_key_for_address(dd, &address), Ok(Some(bob)));
        assert_eq!(contact_key_for_address(dd, "rvn1nobody"), Ok(None));
        {
            let _serial = serial();
            seal(dd);
        }
        assert_eq!(contact_key_for_address(dd, &address), Ok(Some(bob)));
        raven_core::at_rest::forget_cached_keys(dd);
        let (code, _) = contact_key_for_address(dd, &address).unwrap_err();
        assert_eq!(code, "CONTACTS_UNREADABLE");
        // No book at all is no contact, not an error.
        let empty = tempfile::tempdir().unwrap();
        assert_eq!(contact_key_for_address(empty.path(), &address), Ok(None));
    }
}
