//! Proactive session renewal (Phase 3 item 4, any-network plan §3 Phase 3).
//!
//! A session this node starts lasts a day
//! ([`crate::lan_dispatch::LAN_SESSION_LIFETIME_MS`]) and an envelope never
//! outlives its session, so a message sealed 23 h into a session lives 1 h,
//! and once the session has ended nothing can be sealed for a contact that is
//! away. Renewal starts an ordinary PairInit V1 with a contact on a live,
//! endpoint-authenticated link (LAN, Internet direct, p2p) while the newest
//! session still has time left, so what is queued for a contact that then
//! leaves keeps almost a day.
//!
//! - **Never re-seals, never retires.** Queued messages keep their session and
//!   deadline; the old and the new session overlap until the old one expires
//!   (`RAVEN_PAIR_INIT_V1.md` §6: distinct PairInits make distinct sessions,
//!   and a responder keeps accepting a new `init_id` while a confirmed session
//!   exists). Both sides pick the newest the same way.
//! - **Who renews.** The side that did NOT start the newest session, below
//!   [`RENEW_BELOW_MS`] (primary: the initiator alternates, so each side holds
//!   about one responder claim per contact); the other side below
//!   [`RENEW_FALLBACK_BELOW_MS`] (fallback: a contact that cannot dial us, runs
//!   an older build or has the gate off). After the last session ended
//!   (lapsed, within [`RENEW_LAPSED_MAX_MS`]) the smaller device key goes
//!   first and the other side [`RENEW_LAPSED_FALLBACK_MS`] later. Whoever
//!   renews dials.
//! - **Bounded.** One automatic re-pair budget per contact, shared with
//!   Phase 5's horizon re-pair: [`REPAIR_MAX_PER_DAY`] rounds a day,
//!   [`REPAIR_COOLDOWN_MS`] apart, counted durably before the PairInit exists
//!   ([`IndexedSessionStore::begin_repair_attempt`]); failures back off
//!   ([`RENEW_RETRY_STEPS_MS`]). A contact with no route that may carry a
//!   PairInit costs nothing ([`code::RENEW_NO_ROUTE`]).
//! - **Yields.** To the session-reset step while retired rows wait for a
//!   re-seal, and it stops on fork evidence, a reset loop and a prekey pin
//!   refusal. Unverified contacts renew over the local network only.
//! - **A lost PairResponse** is finished with the same signed PairInit, byte
//!   for byte (§6 makes it idempotent): [`RENEW_RESPONSE_RETRIES`] quick
//!   resends, then on the next live link until it expires or something newer
//!   is confirmed.
//! - **Gate:** [`SESSION_RENEWAL_PRODUCTION_ENABLED`] (false); a debug build
//!   opens it with `RAVEN_LAB_SESSION_RENEWAL=1` (a release build never reads
//!   it). raven-node runs the step (P3.14); this module is pure policy and the
//!   step itself.
//! - **Early re-key** (Phase 6b R2 and R3, step P6.27; the security
//!   responses gate and `node_policy.security_auto_rekey`): after a security
//!   event only the contact's signature or this computer's own disk can raise
//!   (an object that fails authentication or is replayed, three index jumps
//!   in an hour, a rollback of local state), [`request_early`] makes
//!   [`decide`] answer Due ([`Role::Early`]) on the next live link, within
//!   the same re-pair budget, at most once per contact per
//!   [`EARLY_MIN_GAP_MS`]. Once the new session is confirmed the older ones
//!   are retired for sending (`LocalSecurityRekey`, so the reset step
//!   re-seals what waited in them) and take the contact's objects for
//!   [`EARLY_OLD_ACCEPT_MS`] more; after that a contact's SESSION_QUERY
//!   about one of them is answered NO_SESSION, so it re-seals what it had
//!   waiting there. Only while the reset step is live (Phase 6 review
//!   sensing-1). Nothing is ever blocked or removed.

use std::cell::Cell;
use std::path::Path;
use std::time::Duration;

use crate::identity::Identity;
use crate::indexed_session_store::{
    record_key_for_init, IndexedSessionRecordKey, IndexedSessionStore, IndexedSessionStoreError,
    PeerRenewalState, SessionLifecycle, SessionRetireCause,
};
use crate::lan_rlb1::LanBundle;
use crate::outbox::{localize_lan_route, OutboxCarrier, OutboxRoute, LOCALIZE_RESOLVE_TIMEOUT};
use crate::pair_init::{decode_init, encode_init, PairInit, PairResponse};
use crate::security_events::SecKind;
use crate::security_gate::{self, SecGate};
use crate::session_reset::{
    bound_offer, first_pair_response, note_presented_cert, session_reset_live_enabled, ResetIo,
};

/// Phase 3 item 4 production gate: stays `false` until the owner signs the
/// Phase 3 LAN amendment's renewal section.
pub const SESSION_RENEWAL_PRODUCTION_ENABLED: bool = false;

thread_local! {
    static LAB: Cell<Option<bool>> = const { Cell::new(None) };
}

/// Renewal is live: [`SESSION_RENEWAL_PRODUCTION_ENABLED`], or in a debug
/// build this thread's override, else `RAVEN_LAB_SESSION_RENEWAL=1`; unless
/// a security notice holds it (P6.45, close-only).
pub fn session_renewal_live_enabled() -> bool {
    (SESSION_RENEWAL_PRODUCTION_ENABLED
        || (cfg!(debug_assertions)
            && LAB.with(Cell::get).unwrap_or_else(|| {
                crate::p2p_gate::lab_flag(true, || std::env::var("RAVEN_LAB_SESSION_RENEWAL").ok())
            })))
        && crate::suite_policy::hold_allows(crate::suite_registry::FEATURE_SESSION_RENEWAL)
}

/// In-process tests switch renewal for the current thread only (the
/// environment variable would leak into every other test of the binary).
/// Ignored in release builds, like the variable.
#[doc(hidden)]
pub fn set_lab_session_renewal_for_this_thread(on: Option<bool>) {
    LAB.with(|cell| cell.set(on));
}

// ---------------------------------------------------------------------------
// Constants (owner decision D-R4: starting values, to be tuned after R24)
// ---------------------------------------------------------------------------

const HOUR_MS: u64 = 3_600_000;
/// A day: the budget's window, and how long a round is remembered.
pub const DAY_MS: u64 = 24 * HOUR_MS;
/// The primary side renews when less than this is left.
pub const RENEW_BELOW_MS: u64 = 12 * HOUR_MS;
/// The side that started the newest session renews when less than this is left.
pub const RENEW_FALLBACK_BELOW_MS: u64 = 10 * HOUR_MS;
/// A lapsed pair is set up again within this of its last session's end.
pub const RENEW_LAPSED_MAX_MS: u64 = 14 * DAY_MS;
/// The larger device key waits this long for the smaller one after a lapse.
pub const RENEW_LAPSED_FALLBACK_MS: u64 = 10 * 60_000;
/// The per-contact automatic re-pair budget (renewal now, Phase 5's horizon
/// re-pair later): rounds per 24 h window ...
pub const REPAIR_MAX_PER_DAY: u8 = 4;
/// ... and the gap between two rounds (crossed or duplicate rounds).
pub const REPAIR_COOLDOWN_MS: u64 = crate::session_reset::RESET_PAIRINIT_COOLDOWN_MS;
/// Backoff after 1, 2, 3 and 4 or more failed rounds in a row.
pub const RENEW_RETRY_STEPS_MS: [u64; 4] = [30 * 60_000, HOUR_MS, 2 * HOUR_MS, 4 * HOUR_MS];
/// Exact-bytes resends of a PairInit whose PairResponse was lost ...
pub const RENEW_RESPONSE_RETRIES: usize = 2;
/// ... this far apart (well inside the reset step's 60 s young-session rule).
pub const RENEW_RESPONSE_RETRY_GAP_MS: u64 = 5_000;
/// No route that may carry a PairInit: ask again after this.
pub const RENEW_NO_ROUTE_WAIT_MS: u64 = 10 * 60_000;
/// Phase 6b R2 (OD6b-5): at most one early re-key per contact in this long
/// (inside the shared re-pair budget) ...
pub const EARLY_MIN_GAP_MS: u64 = 6 * HOUR_MS;
/// ... an early re-key not met in this long lapses (every session it was
/// about has ended by then) ...
pub const EARLY_PENDING_MS: u64 = DAY_MS;
/// ... and a session it retired takes the contact's objects this long more
/// (what the contact sealed before it saw the new session).
pub const EARLY_OLD_ACCEPT_MS: u64 = 10 * 60_000;

// Renewal at 12 h leaves a whole second half of a 24 h session.
const _: () = assert!(2 * RENEW_BELOW_MS <= crate::lan_dispatch::LAN_SESSION_LIFETIME_MS);
const _: () = assert!(RENEW_FALLBACK_BELOW_MS < RENEW_BELOW_MS);
// A renewed session is a re-seal target long before the reset step skips it.
const _: () =
    assert!(RENEW_FALLBACK_BELOW_MS > crate::session_reset::RESET_TARGET_MIN_REMAINING_MS);
// Every daemon-started pairing together stays below the responder's claim cap
// per initiator: renewal, the reset step and the app channel's own budget.
const _: () = assert!(
    REPAIR_MAX_PER_DAY as usize
        + crate::session_reset::RESET_MAX_AUTO_ROUNDS_PER_DAY
        + (crate::app_store::APP_PAIR_BUDGET_PER_DAY as usize)
        < crate::prekey_lifecycle::MAX_ACCEPTED_PREKEY_CLAIMS_PER_INITIATOR
);
// An early re-key outlives every session it is about.
const _: () = assert!(EARLY_PENDING_MS >= crate::lan_dispatch::LAN_SESSION_LIFETIME_MS);
// The quick resends end before the responder's new session counts as old.
const _: () = assert!(
    RENEW_RESPONSE_RETRY_GAP_MS * (RENEW_RESPONSE_RETRIES as u64)
        < crate::session_reset::RESET_NO_SESSION_MIN_AGE_MS
);

/// Status codes of the step (raven-node's logs; stable strings).
pub mod code {
    /// The contact has rows in retired sessions: the reset step owns it.
    pub const RENEW_RESET_PENDING: &str = "RENEW_RESET_PENDING";
    /// Lapsed, and the contact's smaller key goes first.
    pub const RENEW_WAIT_PEER: &str = "RENEW_WAIT_PEER";
    /// Failed rounds back off.
    pub const RENEW_BACKOFF: &str = "RENEW_BACKOFF";
    /// The day's re-pair budget is used up.
    pub const RENEW_DAILY_CAP: &str = "RENEW_DAILY_CAP";
    /// The last re-pair round was less than a minute ago.
    pub const REPAIR_COOLDOWN: &str = "REPAIR_COOLDOWN";
    /// No planned route may carry a PairInit (or the LAN is off).
    pub const RENEW_NO_ROUTE: &str = "RENEW_NO_ROUTE";
}

// ---------------------------------------------------------------------------
// The decision (pure; the clock is injected)
// ---------------------------------------------------------------------------

/// Which side renews (see the module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Did not start the newest session, or the smaller key after a lapse.
    Primary,
    /// Started the newest session, or the larger key after a lapse.
    Fallback,
    /// An early re-key this node asked for (Phase 6b R2, [`request_early`]).
    Early,
}

impl Role {
    pub fn label(self) -> &'static str {
        match self {
            Role::Primary => "primary",
            Role::Fallback => "fallback",
            Role::Early => "early",
        }
    }
}

/// The newest sendable session with the contact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Newest {
    pub we_initiated: bool,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
}

/// What [`decide`] looks at.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RenewView {
    /// Our device key sorts before the contact's (bytewise).
    pub ours_is_smaller: bool,
    pub newest: Option<Newest>,
    /// Undelivered rows in retired sessions (the reset gate on).
    pub retired_rows: usize,
    /// Fork evidence within the reset step's hold.
    pub fork_hold: bool,
    /// The reset step's round cap reached today.
    pub reset_loop_hold: bool,
    pub state: PeerRenewalState,
    /// When this node first saw the pair lapsed on a live link (raven-node).
    pub lapsed_noticed_at_ms: Option<u64>,
    /// An early re-key is pending (Phase 6b R2): asked for less than
    /// [`EARLY_PENDING_MS`] ago, and the newest session was not confirmed
    /// after it.
    pub early: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RenewDecision {
    /// Nothing to do; `recheck_at_ms` is when the newest session crosses its
    /// threshold (callers memoize it), `None` when nothing will change on
    /// its own.
    NotDue {
        recheck_at_ms: Option<u64>,
    },
    Due(Role),
    Wait {
        until_ms: u64,
        code: &'static str,
    },
    Held(&'static str),
}

/// Renew now? Pure: `now_ms` is injected (the tests time-travel here).
pub fn decide(view: &RenewView, now_ms: u64) -> RenewDecision {
    match session_due(view, now_ms) {
        Ok(role) => match budget(&view.state, now_ms) {
            Ok(()) => RenewDecision::Due(role),
            Err((until_ms, code)) => RenewDecision::Wait { until_ms, code },
        },
        Err(decision) => decision,
    }
}

/// [`decide`]'s session half: who renews now, or why nobody does. The step
/// asks it again under the create lock (the budget was spent by then).
fn session_due(view: &RenewView, now_ms: u64) -> Result<Role, RenewDecision> {
    if view.retired_rows > 0 {
        return Err(RenewDecision::Held(code::RENEW_RESET_PENDING));
    }
    if view.fork_hold {
        return Err(RenewDecision::Held(
            crate::session_reset::code::PEER_IDENTITY_FORK,
        ));
    }
    if view.reset_loop_hold {
        return Err(RenewDecision::Held(
            crate::session_reset::code::PEER_RESET_LOOP,
        ));
    }
    // An early re-key: this side renews now, whoever started the newest
    // session, and also when none is left to send in (its state is what
    // the request doubts).
    if view.early {
        return Ok(Role::Early);
    }
    if let Some(newest) = view.newest {
        // Alternate the initiator: the side that did not start it goes first.
        let (role, below) = if newest.we_initiated {
            (Role::Fallback, RENEW_FALLBACK_BELOW_MS)
        } else {
            (Role::Primary, RENEW_BELOW_MS)
        };
        if newest.expires_at_ms.saturating_sub(now_ms) >= below {
            return Err(RenewDecision::NotDue {
                recheck_at_ms: Some(newest.expires_at_ms.saturating_sub(below)),
            });
        }
        return Ok(role);
    }
    // Lapsed: no sendable session, and the pair's last one ended lately.
    let Some(ended) = view.state.last_session_expires_at_ms else {
        return Err(RenewDecision::NotDue {
            recheck_at_ms: None,
        });
    };
    if now_ms.saturating_sub(ended) > RENEW_LAPSED_MAX_MS {
        return Err(RenewDecision::NotDue {
            recheck_at_ms: None,
        });
    }
    if view.ours_is_smaller {
        return Ok(Role::Primary);
    }
    let after = view
        .lapsed_noticed_at_ms
        .unwrap_or(now_ms)
        .saturating_add(RENEW_LAPSED_FALLBACK_MS);
    if now_ms < after {
        return Err(RenewDecision::Wait {
            until_ms: after,
            code: code::RENEW_WAIT_PEER,
        });
    }
    Ok(Role::Fallback)
}

/// [`decide`]'s budget half: the day's cap, the failure backoff, the
/// cooldown. `Err((until, code))` to wait.
fn budget(state: &PeerRenewalState, now_ms: u64) -> Result<(), (u64, &'static str)> {
    let window_end = state.window_start_ms.saturating_add(DAY_MS);
    if now_ms < window_end && state.attempts_in_window >= REPAIR_MAX_PER_DAY {
        return Err((window_end, code::RENEW_DAILY_CAP));
    }
    if let (Some(last), failures) = (state.last_attempt_at_ms, state.failures) {
        if failures > 0 {
            let step = RENEW_RETRY_STEPS_MS[usize::from(failures - 1).min(3)];
            let next = last.saturating_add(step);
            if now_ms < next {
                return Err((next, code::RENEW_BACKOFF));
            }
        }
    }
    repair_budget(state, now_ms)
}

/// The shared re-pair budget alone (renewal now, Phase 5's horizon re-pair
/// later): at most [`REPAIR_MAX_PER_DAY`] rounds in the window, the last
/// one at least [`REPAIR_COOLDOWN_MS`] ago. `Err((until, code))` to wait.
pub fn repair_budget(state: &PeerRenewalState, now_ms: u64) -> Result<(), (u64, &'static str)> {
    let window_end = state.window_start_ms.saturating_add(DAY_MS);
    if now_ms < window_end && state.attempts_in_window >= REPAIR_MAX_PER_DAY {
        return Err((window_end, code::RENEW_DAILY_CAP));
    }
    if let Some(last) = state.last_attempt_at_ms {
        let until = last.saturating_add(REPAIR_COOLDOWN_MS);
        if now_ms < until {
            return Err((until, code::REPAIR_COOLDOWN));
        }
    }
    Ok(())
}

/// Count one re-pair round at `now_ms` in `state` when [`repair_budget`]
/// allows it (the window rolls a day after it started); the store's
/// [`IndexedSessionStore::begin_repair_attempt`] persists the result.
pub fn begin_attempt(state: &mut PeerRenewalState, now_ms: u64) -> Result<(), (u64, &'static str)> {
    repair_budget(state, now_ms)?;
    if now_ms >= state.window_start_ms.saturating_add(DAY_MS) {
        state.window_start_ms = now_ms;
        state.attempts_in_window = 0;
    }
    state.attempts_in_window = state.attempts_in_window.saturating_add(1);
    state.last_attempt_at_ms = Some(now_ms);
    Ok(())
}

// ---------------------------------------------------------------------------
// Early re-key (Phase 6b R2 and R3, step P6.27)
// ---------------------------------------------------------------------------

/// Ask this node to renew its session with `peer` early, because of
/// `reason` (design A R2: an object of the contact's that failed
/// authentication or was replayed, three index jumps in an hour; R3: local
/// state rolled back). `Ok(true)`: noted; the renewer's next step for
/// `peer` renews (on the next live link), within the shared re-pair budget.
/// `Ok(false)`, nothing written: the responses gate is shut, or an early
/// re-key with `peer` was taken less than [`EARLY_MIN_GAP_MS`] ago. The
/// caller applies `node_policy.security_auto_rekey`. Never blocks, unpins
/// or removes anyone.
pub fn request_early(
    store: &mut IndexedSessionStore,
    peer: &[u8; 32],
    reason: SecKind,
    now_ms: u64,
) -> Result<bool, IndexedSessionStoreError> {
    if !security_gate::live(SecGate::Responses) {
        return Ok(false);
    }
    store.request_early_renewal(peer, reason.code(), now_ms)
}

/// R3: [`request_early`] for every contact this node (`local`, its device
/// key) holds a live session with: an unexpired head, read from the public
/// metadata only (a session whose protected state rolled back is skipped
/// by every lookup that opens it, and its contact needs the re-key most).
/// The contacts it was noted for (the 6 h cap leaves out the others); the
/// renewer spreads them over its global bucket.
pub fn request_early_for_live_peers(
    store: &mut IndexedSessionStore,
    local: &[u8; 32],
    reason: SecKind,
    now_ms: u64,
) -> Result<Vec<[u8; 32]>, IndexedSessionStoreError> {
    let mut peers: Vec<[u8; 32]> = Vec::new();
    for key in store.list_readable_record_keys()? {
        let peer = if key.initiator_device_ed25519 == *local {
            key.responder_device_ed25519
        } else {
            key.initiator_device_ed25519
        };
        if peer != *local && !peers.contains(&peer) && store.head_expires_at_ms(&key)? > now_ms {
            peers.push(peer);
        }
    }
    let mut asked = Vec::new();
    for peer in peers {
        if request_early(store, &peer, reason, now_ms)? {
            asked.push(peer);
        }
    }
    Ok(asked)
}

/// Is the early re-key in `state` still pending at `now_ms` with `newest`
/// (the newest sendable session, if any) as it is? Met once a session was
/// confirmed at or after the request, on this node's clock (the reset
/// sidecar's `confirmed_at_ms`); lapsed after [`EARLY_PENDING_MS`].
fn early_pending(
    store: &mut IndexedSessionStore,
    state: &PeerRenewalState,
    newest: Option<&IndexedSessionRecordKey>,
    now_ms: u64,
) -> Result<bool, String> {
    let Some(requested) = state.early_requested_at_ms else {
        return Ok(false);
    };
    if now_ms >= requested.saturating_add(EARLY_PENDING_MS) {
        return Ok(false);
    }
    match newest {
        Some(newest) => Ok(!confirmed_since(store, newest, requested)?),
        None => Ok(true),
    }
}

/// Was `key` confirmed at or after `at_ms` (this node's clock)?
fn confirmed_since(
    store: &mut IndexedSessionStore,
    key: &IndexedSessionRecordKey,
    at_ms: u64,
) -> Result<bool, String> {
    let sid = store.session_id_for_record_key(key).map_err(store_err)?;
    Ok(store
        .session_reset_info(&sid)
        .map_err(store_err)?
        .and_then(|info| info.confirmed_at_ms)
        .is_some_and(|confirmed| confirmed >= at_ms))
}

/// After a renewal confirmed `new` with `peer`: an early re-key it met is
/// done, and every other sendable session confirmed before the request is
/// retired for sending ([`SessionRetireCause::LocalSecurityRekey`]), so
/// Phase 2a re-seals what waited in it and it takes no new object from the
/// contact after [`EARLY_OLD_ACCEPT_MS`]. Only while the reset step is
/// live: what the contact sealed in it and could not deliver in time comes
/// back through the reset step's SESSION_QUERY (answered NO_SESSION once
/// the session is closed, so the contact re-seals it); with the step shut
/// the old sessions take the contact's objects until they end, as after
/// any renewal (Phase 6 review sensing-1). A session still holding this
/// node's undelivered messages is retired only when `new` is a session the
/// step re-seals into (set up over a local-network route); otherwise it
/// keeps them and ends as it would have (nothing is stranded). How many
/// sessions were retired.
fn finish_early(
    store: &mut IndexedSessionStore,
    peer: &[u8; 32],
    new: &IndexedSessionRecordKey,
    now_ms: u64,
) -> Result<usize, String> {
    let state = store.peer_renewal_state(peer).map_err(store_err)?;
    let Some(requested) = state.early_requested_at_ms else {
        return Ok(0);
    };
    store
        .finish_early_renewal(peer, requested)
        .map_err(store_err)?;
    if !session_reset_live_enabled() {
        return Ok(0);
    }
    let new_sid = store.session_id_for_record_key(new).map_err(store_err)?;
    let reseals = store
        .session_reset_info(&new_sid)
        .map_err(store_err)?
        .is_some_and(|info| info.initiated_local);
    let mut retired = 0;
    for key in store
        .find_sendable_sessions_for_peer_at(peer, now_ms)
        .map_err(store_err)?
    {
        if key == *new || confirmed_since(store, &key, requested)? {
            continue;
        }
        let sid = store.session_id_for_record_key(&key).map_err(store_err)?;
        let waiting = store
            .undelivered_messages_in_session(&sid, peer)
            .map_err(store_err)?;
        if waiting > 0 && !reseals {
            continue;
        }
        if store
            .retire_session(&key, peer, SessionRetireCause::LocalSecurityRekey, now_ms)
            .map_err(store_err)?
        {
            retired += 1;
        }
    }
    Ok(retired)
}

// ---------------------------------------------------------------------------
// The step
// ---------------------------------------------------------------------------

/// Inputs of one renewal step for one contact.
pub struct RenewEnv<'a> {
    pub data_dir: &'a Path,
    pub identity: &'a Identity,
    pub peer: [u8; 32],
    /// The contact's planned routes, preference order (the caller applied the
    /// gates, hide-IP and the verified-contact rule).
    pub routes: &'a [OutboxRoute],
    /// The contact is verified (pinned): any confidential route; otherwise
    /// LAN routes that resolve to local-network addresses only.
    pub pinned: bool,
    pub lapsed_noticed_at_ms: Option<u64>,
    pub now_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenewStep {
    /// Nothing to do (gate off, not due, or a crossed renewal landed first);
    /// `recheck_at_ms` as in [`RenewDecision::NotDue`].
    NotDue {
        recheck_at_ms: Option<u64>,
    },
    Renewed {
        role: Role,
        carrier: OutboxCarrier,
        /// A lost PairResponse was finished with the same PairInit.
        retried_pending: bool,
    },
    Wait {
        until_ms: u64,
        code: &'static str,
    },
    Held(&'static str),
    /// The probe or the PairInit exchange failed: the round counts as a failure.
    Unreachable(String),
}

fn store_err(e: IndexedSessionStoreError) -> String {
    e.redacted_display()
}

/// A route that may carry a PairInit now: an endpoint-confidential carrier,
/// and a LAN route only while the LAN is usable (`raven lan off`).
fn may_carry_pair_init(route: &OutboxRoute) -> bool {
    route.carrier.confidential_to_endpoint()
        && (route.carrier != OutboxCarrier::Lan || crate::lan_usable_now())
}

/// One renewal step for `env.peer`: decide under the peer's lock, count the
/// round, probe the routes, then renew (or finish a lost PairResponse).
pub fn run_renewal_step(env: &RenewEnv, io: &mut dyn ResetIo) -> Result<RenewStep, String> {
    if !session_renewal_live_enabled() {
        return Ok(RenewStep::NotDue {
            recheck_at_ms: None,
        });
    }
    let (peer, now) = (env.peer, env.now_ms);
    // First: a route that may carry a PairInit, or nothing is decided,
    // counted or dialled (`raven lan off`, closed gates, hide-IP).
    let routes: Vec<&OutboxRoute> = env
        .routes
        .iter()
        .filter(|route| may_carry_pair_init(route))
        .collect();
    if routes.is_empty() {
        return Ok(RenewStep::Wait {
            until_ms: now.saturating_add(RENEW_NO_ROUTE_WAIT_MS),
            code: code::RENEW_NO_ROUTE,
        });
    }
    // 1. Decide under the peer's send lock: a send or reset step to this
    // peer finishes first. The round is counted before any PairInit exists.
    let local = env.identity.public_key_bytes();
    let mut decision = RenewDecision::NotDue {
        recheck_at_ms: None,
    };
    let mut pending = None;
    // The budget before this step's round, when it counted one.
    let mut counted: Option<PeerRenewalState> = None;
    io.locked(&mut |store| {
        let view = renew_view(store, &local, &peer, env.lapsed_noticed_at_ms, now)?;
        if let Some(newest) = view.newest {
            store
                .note_session_end_seen(&peer, newest.expires_at_ms)
                .map_err(store_err)?;
        }
        pending = valid_pending(store, &view, &peer, now)?;
        decision = decide(&view, now);
        if matches!(decision, RenewDecision::Due(_)) && pending.is_none() {
            match store.begin_repair_attempt(&peer, now).map_err(store_err)? {
                Ok(()) => counted = Some(view.state.clone()),
                Err((until_ms, code)) => decision = RenewDecision::Wait { until_ms, code },
            }
        }
        Ok(())
    })?;
    let role = match (&decision, &pending) {
        (RenewDecision::Held(code), _) => return Ok(RenewStep::Held(code)),
        (RenewDecision::Due(role), _) => *role,
        // A lost PairResponse is always worth finishing (not a new round).
        (_, Some(_)) => Role::Primary,
        (RenewDecision::Wait { until_ms, code }, None) => {
            return Ok(RenewStep::Wait {
                until_ms: *until_ms,
                code,
            })
        }
        (RenewDecision::NotDue { recheck_at_ms }, None) => {
            return Ok(RenewStep::NotDue {
                recheck_at_ms: *recheck_at_ms,
            })
        }
    };
    let mut created = false;
    let step = probe_and_renew(env, io, routes, role, pending.as_deref(), &mut created);
    match (step, counted) {
        // The peer's send lock was busy (an `ash send` to this contact holds
        // it past the wait) before a PairInit was created: a quick retry
        // (the caller's), and the round goes back so the cooldown does not
        // hold it (review C-4). A busy lock here too leaves it counted.
        (Err(e), Some(prior)) if !created && crate::outbox::send_lock_busy(&e) => {
            let _ = io.locked(&mut |store| {
                store
                    .give_back_repair_attempt(&peer, now, &prior)
                    .map_err(store_err)
            });
            Err(e)
        }
        (step, _) => step,
    }
}

/// [`run_renewal_step`] after its first lock: probe the routes, then renew
/// (or finish a lost PairResponse). `created` tells whether a PairInit was
/// created (and kept for a resend).
fn probe_and_renew(
    env: &RenewEnv,
    io: &mut dyn ResetIo,
    routes: Vec<&OutboxRoute>,
    role: Role,
    pending: Option<&[u8]>,
    created: &mut bool,
) -> Result<RenewStep, String> {
    let (peer, now) = (env.peer, env.now_ms);
    // 2. Probe the routes in order; the first verified offer wins. An
    // unverified contact only over LAN routes on the local network.
    let mut last = String::from(code::RENEW_NO_ROUTE);
    for planned in routes {
        let route = if planned.carrier == OutboxCarrier::Lan {
            match localize_lan_route(planned, env.pinned, LOCALIZE_RESOLVE_TIMEOUT) {
                Ok(route) => route,
                Err(refusal) => {
                    last = format!("{refusal:?}");
                    continue;
                }
            }
        } else if env.pinned {
            planned.clone()
        } else {
            last = "an unverified contact renews over the local network only".into();
            continue;
        };
        let replies = match io.dial(&route, &[]) {
            Ok(replies) => replies,
            Err(e) => {
                last = e;
                continue;
            }
        };
        let Some(offer) = bound_offer(&replies, &peer, now) else {
            last = "the contact's offer did not verify".into();
            continue;
        };
        crate::lan_dispatch::cache_peer_bundle(env.data_dir, &offer)?;
        // 3. Lost-state evidence first (reset gate on): a renewed certificate
        // retires the old sessions, and the reset step takes the contact over.
        if session_reset_live_enabled() {
            let mut retired = 0;
            io.locked(&mut |store| {
                retired = note_presented_cert(env.data_dir, store, &peer, &offer.cert, now)?;
                Ok(())
            })?;
            if retired > 0 {
                io.locked(&mut |store| {
                    store.finish_renewal_attempt(&peer, true).map_err(store_err)
                })?;
                return Ok(RenewStep::Held(code::RENEW_RESET_PENDING));
            }
        }
        let local_route = route.carrier == OutboxCarrier::Lan
            && localize_lan_route(&route, false, LOCALIZE_RESOLVE_TIMEOUT).is_ok();
        let outcome = match pending {
            Some(wire) => resend_pending(env, wire, &route, io),
            None => renew_pair(env, &offer, &route, local_route, io, created),
        };
        // The contact answered the probe: no second route.
        return match outcome {
            Ok(Some(new)) => {
                io.locked(&mut |store| {
                    store.clear_renewal_pending(&peer).map_err(store_err)?;
                    store
                        .finish_renewal_attempt(&peer, true)
                        .map_err(store_err)?;
                    // An early re-key this round met (Phase 6b R2).
                    finish_early(store, &peer, &new, now).map(|_| ())
                })?;
                Ok(RenewStep::Renewed {
                    role,
                    carrier: route.carrier,
                    retried_pending: pending.is_some(),
                })
            }
            // Asked again under the create lock: a crossed renewal or a
            // send's own PairInit landed first.
            Ok(None) => Ok(RenewStep::NotDue {
                recheck_at_ms: None,
            }),
            // Our own lock, not the contact: no failure, no backoff; the
            // caller tries again shortly (a kept PairInit is resent then).
            Err(e) if crate::outbox::send_lock_busy(&e) => Err(e),
            Err(e) if e.starts_with(crate::lan_dispatch::PEER_PREKEY_RESET) => {
                fail(env, io)?;
                Ok(RenewStep::Held(crate::lan_dispatch::PEER_PREKEY_RESET))
            }
            Err(e) => {
                fail(env, io)?;
                Ok(RenewStep::Unreachable(e))
            }
        };
    }
    fail(env, io)?;
    Ok(RenewStep::Unreachable(last))
}

fn fail(env: &RenewEnv, io: &mut dyn ResetIo) -> Result<(), String> {
    io.locked(&mut |store| {
        store
            .finish_renewal_attempt(&env.peer, false)
            .map_err(store_err)
    })
}

/// What [`decide`] needs from the store (metadata, the newest session's
/// protected lifecycle, the reset tables).
fn renew_view(
    store: &mut IndexedSessionStore,
    local: &[u8; 32],
    peer: &[u8; 32],
    lapsed_noticed_at_ms: Option<u64>,
    now_ms: u64,
) -> Result<RenewView, String> {
    let summary = store
        .newest_sendable_summary(peer, now_ms)
        .map_err(store_err)?;
    let newest = summary
        .as_ref()
        .map(|(key, created_at_ms, expires_at_ms)| Newest {
            we_initiated: key.initiator_device_ed25519 == *local,
            created_at_ms: *created_at_ms,
            expires_at_ms: *expires_at_ms,
        });
    let retired_rows = if session_reset_live_enabled() {
        store
            .retired_undelivered_messages_for_recipient(peer)
            .map_err(store_err)?
            .len()
    } else {
        0
    };
    // The reset step's holds, over the same window it uses.
    let reset = store.peer_reset_state(peer).map_err(store_err)?;
    let since = now_ms
        .saturating_sub(crate::session_reset::RESET_DAY_MS)
        .max(reset.user_confirmed_at_ms.unwrap_or(0));
    let fork_hold = reset.fork_evidence_at_ms.is_some_and(|at| at > since);
    let reset_loop_hold = store.reset_rounds_since(peer, since).map_err(store_err)?
        >= crate::session_reset::RESET_MAX_AUTO_ROUNDS_PER_DAY;
    let state = store.peer_renewal_state(peer).map_err(store_err)?;
    let early = early_pending(store, &state, summary.as_ref().map(|s| &s.0), now_ms)?;
    Ok(RenewView {
        ours_is_smaller: local < peer,
        newest,
        retired_rows,
        fork_hold,
        reset_loop_hold,
        state,
        lapsed_noticed_at_ms,
        early,
    })
}

/// The pending PairInit when it is still worth finishing: unexpired, its
/// provisional session still here and unconfirmed, nothing newer confirmed.
/// Any other is dropped here.
fn valid_pending(
    store: &mut IndexedSessionStore,
    view: &RenewView,
    peer: &[u8; 32],
    now_ms: u64,
) -> Result<Option<Vec<u8>>, String> {
    let (Some(wire), Some(expires)) = (
        view.state.pending_init.as_ref(),
        view.state.pending_expires_at_ms,
    ) else {
        return Ok(None);
    };
    let keep = match decode_init(wire) {
        Ok(init) if expires > now_ms => {
            let newer = view
                .newest
                .is_some_and(|newest| newest.created_at_ms >= init.created_at_ms);
            !newer
                && match store.session_lifecycle(&record_key_for_init(&init)) {
                    Ok(lifecycle) => lifecycle == SessionLifecycle::Provisional,
                    Err(error @ IndexedSessionStoreError::MetaKeyUnavailable(_)) => {
                        return Err(store_err(error))
                    }
                    Err(_) => false,
                }
        }
        _ => false,
    };
    if keep {
        return Ok(Some(wire.clone()));
    }
    store.clear_renewal_pending(peer).map_err(store_err)?;
    Ok(None)
}

/// [`crate::session_reset::pair_with_peer`] for a renewal: the decision is
/// asked again inside the create lock (`None`: no longer due, nothing
/// created), the session is marked initiated without a reset round, and the
/// PairInit is kept for an exact resend before it is sent. The confirmed
/// session.
fn renew_pair(
    env: &RenewEnv,
    offer: &LanBundle,
    route: &OutboxRoute,
    local_route: bool,
    io: &mut dyn ResetIo,
    made: &mut bool,
) -> Result<Option<IndexedSessionRecordKey>, String> {
    let (peer, now) = (env.peer, env.now_ms);
    let local = env.identity.public_key_bytes();
    let mut created = None;
    io.locked(&mut |store| {
        let view = renew_view(store, &local, &peer, env.lapsed_noticed_at_ms, now)?;
        if session_due(&view, now).is_err() {
            return Ok(());
        }
        let (init, key) =
            crate::lan_dispatch::create_initiator_pair_init(env.data_dir, env.identity, offer)?;
        // Not a reset round: renewals never count toward the reset step's
        // round cap or cooldown. Over a local-network route the session is a
        // re-seal target (lost-state §9.2), as any local session is.
        store
            .mark_session_initiated(&key, &peer, local_route, false, crate::clock::now_ms())
            .map_err(store_err)?;
        let wire = encode_init(&init).map_err(|e| format!("pair init: {e:?}"))?;
        store
            .set_renewal_pending(&peer, &wire, init.expires_at_ms)
            .map_err(store_err)?;
        created = Some((init, key));
        Ok(())
    })?;
    let Some((init, key)) = created else {
        return Ok(None);
    };
    *made = true;
    let response = exchange(env.identity, &init, route, io)?;
    confirm(env, &key, &init, &response, io)?;
    Ok(Some(key))
}

/// Finish a lost PairResponse: the kept PairInit, byte for byte. The
/// confirmed session.
fn resend_pending(
    env: &RenewEnv,
    wire: &[u8],
    route: &OutboxRoute,
    io: &mut dyn ResetIo,
) -> Result<Option<IndexedSessionRecordKey>, String> {
    let init = decode_init(wire).map_err(|e| format!("pending pair init: {e}"))?;
    let key = record_key_for_init(&init);
    let response = exchange(env.identity, &init, route, io)?;
    confirm(env, &key, &init, &response, io)?;
    Ok(Some(key))
}

/// Confirm under the lock; a response that does not confirm drops the kept
/// PairInit (it would only be answered the same way again).
fn confirm(
    env: &RenewEnv,
    key: &IndexedSessionRecordKey,
    init: &PairInit,
    response: &PairResponse,
    io: &mut dyn ResetIo,
) -> Result<(), String> {
    let mut refused = None;
    io.locked(&mut |store| {
        if let Err(e) =
            store.confirm_verified_pair_response(key, init, response, crate::clock::now_ms())
        {
            store.clear_renewal_pending(&env.peer).map_err(store_err)?;
            refused = Some(store_err(e));
        }
        Ok(())
    })?;
    refused.map_or(Ok(()), Err)
}

#[cfg(test)]
thread_local! {
    static RETRY_GAP_OVERRIDE: Cell<Option<u64>> = const { Cell::new(None) };
}

/// Unit tests only: the quick resends' gap on this thread (every build
/// outside the tests waits [`RENEW_RESPONSE_RETRY_GAP_MS`]).
#[cfg(test)]
pub(crate) fn set_response_retry_gap_for_this_thread(ms: Option<u64>) {
    RETRY_GAP_OVERRIDE.with(|cell| cell.set(ms));
}

fn response_retry_gap() -> Duration {
    #[cfg(test)]
    if let Some(ms) = RETRY_GAP_OVERRIDE.with(Cell::get) {
        return Duration::from_millis(ms);
    }
    Duration::from_millis(RENEW_RESPONSE_RETRY_GAP_MS)
}

/// Send `init` and take its PairResponse: on a missing one the same signed
/// PairInit again, up to [`RENEW_RESPONSE_RETRIES`] times (a fresh OOB
/// wrapper each time; the responder answers by `init_id` and init hash).
fn exchange(
    identity: &Identity,
    init: &PairInit,
    route: &OutboxRoute,
    io: &mut dyn ResetIo,
) -> Result<PairResponse, String> {
    let mut last = String::from("WAITING_FOR_PAIR_RESPONSE: no PairResponse");
    for attempt in 0..=RENEW_RESPONSE_RETRIES {
        if attempt > 0 {
            std::thread::sleep(response_retry_gap());
        }
        let frame = crate::lan_dispatch::wrap_pair_init(identity, init)?;
        match io.dial(route, &[frame]) {
            Ok(replies) => {
                if let Some(response) = first_pair_response(&replies) {
                    return Ok(response);
                }
            }
            Err(e) => last = e,
        }
    }
    Err(last)
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: u64 = 1_900_000_000_000;
    const MIN: u64 = 60_000;

    fn view(newest: Option<Newest>) -> RenewView {
        RenewView {
            newest,
            ..RenewView::default()
        }
    }

    fn newest(we_initiated: bool, left: u64) -> Option<Newest> {
        Some(Newest {
            we_initiated,
            created_at_ms: T + left - DAY_MS,
            expires_at_ms: T + left,
        })
    }

    fn lapsed(ended_ago: u64, smaller: bool, noticed: Option<u64>) -> RenewView {
        RenewView {
            ours_is_smaller: smaller,
            state: PeerRenewalState {
                last_session_expires_at_ms: Some(T - ended_ago),
                ..PeerRenewalState::default()
            },
            lapsed_noticed_at_ms: noticed,
            ..RenewView::default()
        }
    }

    #[test]
    fn decide_table_with_injected_clock() {
        use RenewDecision::{Due, Held, NotDue, Wait};
        // We did not start the newest session: the primary side, below 12 h.
        let primary = [
            (13 * HOUR_MS, false),
            (12 * HOUR_MS, false),
            (12 * HOUR_MS - MIN, true),
            (MIN, true),
        ];
        for (left, due) in primary {
            let got = decide(&view(newest(false, left)), T);
            if due {
                assert_eq!(got, Due(Role::Primary), "{left}");
            } else {
                assert_eq!(
                    got,
                    NotDue {
                        recheck_at_ms: Some(T + left - RENEW_BELOW_MS)
                    },
                    "{left}"
                );
            }
        }
        // We started it: the fallback side, below 10 h.
        for (left, due) in [
            (11 * HOUR_MS, false),
            (10 * HOUR_MS, false),
            (10 * HOUR_MS - MIN, true),
        ] {
            let got = decide(&view(newest(true, left)), T);
            if due {
                assert_eq!(got, Due(Role::Fallback), "{left}");
            } else {
                assert_eq!(
                    got,
                    NotDue {
                        recheck_at_ms: Some(T + left - RENEW_FALLBACK_BELOW_MS)
                    },
                    "{left}"
                );
            }
        }
        // Lapsed: the smaller key at once, the larger after 10 min.
        assert_eq!(decide(&lapsed(HOUR_MS, true, None), T), Due(Role::Primary));
        assert_eq!(
            decide(&lapsed(HOUR_MS, false, None), T),
            Wait {
                until_ms: T + 10 * MIN,
                code: code::RENEW_WAIT_PEER
            }
        );
        assert_eq!(
            decide(&lapsed(HOUR_MS, false, Some(T - 10 * MIN)), T),
            Due(Role::Fallback)
        );
        // Too long ago, or never seen: nothing.
        assert_eq!(
            decide(&lapsed(15 * DAY_MS, true, None), T),
            NotDue {
                recheck_at_ms: None
            }
        );
        assert_eq!(
            decide(&view(None), T),
            NotDue {
                recheck_at_ms: None
            }
        );
        // The reset step's holds win.
        let due = view(newest(false, HOUR_MS));
        assert_eq!(
            decide(
                &RenewView {
                    retired_rows: 2,
                    ..due.clone()
                },
                T
            ),
            Held(code::RENEW_RESET_PENDING)
        );
        assert_eq!(
            decide(
                &RenewView {
                    fork_hold: true,
                    ..due.clone()
                },
                T
            ),
            Held(crate::session_reset::code::PEER_IDENTITY_FORK)
        );
        assert_eq!(
            decide(
                &RenewView {
                    reset_loop_hold: true,
                    ..due.clone()
                },
                T
            ),
            Held(crate::session_reset::code::PEER_RESET_LOOP)
        );
        // Four rounds in the window: the cap, until it rolls.
        let window = T - 5 * HOUR_MS;
        let capped = RenewView {
            state: PeerRenewalState {
                window_start_ms: window,
                attempts_in_window: REPAIR_MAX_PER_DAY,
                last_attempt_at_ms: Some(T - 4 * HOUR_MS),
                ..PeerRenewalState::default()
            },
            ..due.clone()
        };
        assert_eq!(
            decide(&capped, T),
            Wait {
                until_ms: window + DAY_MS,
                code: code::RENEW_DAILY_CAP
            }
        );
        let rolled = window + DAY_MS;
        let after = RenewView {
            newest: Some(Newest {
                we_initiated: false,
                created_at_ms: rolled - DAY_MS + HOUR_MS,
                expires_at_ms: rolled + HOUR_MS,
            }),
            ..capped.clone()
        };
        assert_eq!(decide(&after, rolled), Due(Role::Primary));
        // Failures back off from the last round.
        for (failures, step) in [
            (1u8, 30 * MIN),
            (2, HOUR_MS),
            (3, 2 * HOUR_MS),
            (5, 4 * HOUR_MS),
        ] {
            let last = T - MIN;
            let backing = RenewView {
                state: PeerRenewalState {
                    window_start_ms: last,
                    attempts_in_window: 1,
                    last_attempt_at_ms: Some(last),
                    failures,
                    ..PeerRenewalState::default()
                },
                ..due.clone()
            };
            assert_eq!(
                decide(&backing, T),
                Wait {
                    until_ms: last + step,
                    code: code::RENEW_BACKOFF
                },
                "{failures}"
            );
            assert_eq!(decide(&backing, last + step), Due(Role::Primary));
        }
        // A round 30 s ago without a failure: the shared cooldown.
        let cooling = RenewView {
            state: PeerRenewalState {
                window_start_ms: T - 30_000,
                attempts_in_window: 1,
                last_attempt_at_ms: Some(T - 30_000),
                ..PeerRenewalState::default()
            },
            ..due.clone()
        };
        assert_eq!(
            decide(&cooling, T),
            Wait {
                until_ms: T + 30_000,
                code: code::REPAIR_COOLDOWN
            }
        );
        assert_eq!(decide(&cooling, T + 30_000), Due(Role::Primary));
    }

    /// Phase 6b R2: a pending early re-key makes this side renew now on
    /// either side of the thresholds and with no session left, behind the
    /// reset step's holds and inside the shared budget.
    #[test]
    fn an_early_rekey_is_due_now_within_the_holds_and_the_budget() {
        use RenewDecision::{Due, Held, Wait};
        let early = |newest| RenewView {
            early: true,
            ..view(newest)
        };
        for (we_initiated, left) in [(false, 20 * HOUR_MS), (true, 23 * HOUR_MS), (true, MIN)] {
            assert_eq!(
                decide(&early(newest(we_initiated, left)), T),
                Due(Role::Early),
                "{we_initiated} {left}"
            );
        }
        assert_eq!(
            decide(
                &RenewView {
                    retired_rows: 1,
                    ..early(newest(false, 20 * HOUR_MS))
                },
                T
            ),
            Held(code::RENEW_RESET_PENDING)
        );
        let window = T - HOUR_MS;
        let capped = RenewView {
            state: PeerRenewalState {
                window_start_ms: window,
                attempts_in_window: REPAIR_MAX_PER_DAY,
                last_attempt_at_ms: Some(T - 2 * MIN),
                ..PeerRenewalState::default()
            },
            ..early(newest(false, 20 * HOUR_MS))
        };
        assert_eq!(
            decide(&capped, T),
            Wait {
                until_ms: window + DAY_MS,
                code: code::RENEW_DAILY_CAP
            }
        );
        // No session left to send in (it ended, or its state rolled back):
        // this side still goes now, not after the other.
        let lapsed = RenewView {
            early: true,
            ..lapsed(HOUR_MS, false, None)
        };
        assert_eq!(decide(&lapsed, T), Due(Role::Early));
        assert_eq!(
            decide(
                &RenewView {
                    early: true,
                    ..view(None)
                },
                T
            ),
            Due(Role::Early)
        );
        assert_eq!(Role::Early.label(), "early");
        const {
            assert!(EARLY_MIN_GAP_MS == 6 * HOUR_MS);
            assert!(EARLY_OLD_ACCEPT_MS == 10 * MIN);
        }
    }

    #[test]
    fn begin_attempt_counts_rolls_and_cools_down() {
        let mut state = PeerRenewalState::default();
        let mut at = T;
        for n in 1..=REPAIR_MAX_PER_DAY {
            begin_attempt(&mut state, at).unwrap();
            assert_eq!(state.attempts_in_window, n);
            assert_eq!(state.window_start_ms, T);
            let cooling = if n < REPAIR_MAX_PER_DAY {
                (at + REPAIR_COOLDOWN_MS, code::REPAIR_COOLDOWN)
            } else {
                (T + DAY_MS, code::RENEW_DAILY_CAP)
            };
            assert_eq!(begin_attempt(&mut state.clone(), at + 59_999), Err(cooling));
            at += REPAIR_COOLDOWN_MS;
        }
        assert_eq!(
            begin_attempt(&mut state, at),
            Err((T + DAY_MS, code::RENEW_DAILY_CAP))
        );
        begin_attempt(&mut state, T + DAY_MS).unwrap();
        assert_eq!(
            (state.window_start_ms, state.attempts_in_window),
            (T + DAY_MS, 1)
        );
    }

    /// Two always-linked contacts over 30 days, the clock in 5 min ticks; each
    /// renewal makes a 24 h session the renewer started. The initiator
    /// alternates, renewals come about every 12 h, a side holds at most 2
    /// live responder claims (24 h each) and about 1 on average, and no
    /// contact spends more than 4 rounds in any 24 h.
    #[test]
    fn thresholds_bound_the_claim_quota_over_30_days() {
        const TICK: u64 = 5 * MIN;
        // (initiator: 0 = A, 1 = B, created, expires)
        let mut sessions: Vec<(usize, u64, u64)> = vec![(0, T, T + DAY_MS)];
        let mut states = [PeerRenewalState::default(), PeerRenewalState::default()];
        let mut renewals: Vec<(usize, u64)> = Vec::new();
        let mut claim_samples = [0u64, 0u64];
        let mut claim_max = [0usize, 0usize];
        let mut samples = 0u64;
        let mut now = T;
        while now < T + 30 * DAY_MS {
            for (side, state) in states.iter_mut().enumerate() {
                let newest = sessions
                    .iter()
                    .filter(|s| s.2 > now)
                    .max_by_key(|s| s.1)
                    .map(|s| Newest {
                        we_initiated: s.0 == side,
                        created_at_ms: s.1,
                        expires_at_ms: s.2,
                    });
                let v = RenewView {
                    ours_is_smaller: side == 0,
                    newest,
                    state: state.clone(),
                    ..RenewView::default()
                };
                if let RenewDecision::Due(_) = decide(&v, now) {
                    begin_attempt(state, now).unwrap();
                    sessions.push((side, now, now + DAY_MS));
                    renewals.push((side, now));
                }
            }
            // A responder keeps each claim (the other side's PairInit) a day.
            for (side, (most, total)) in claim_max.iter_mut().zip(&mut claim_samples).enumerate() {
                let claims = sessions
                    .iter()
                    .filter(|s| s.0 != side && s.1 <= now && now < s.1 + DAY_MS)
                    .count();
                *most = (*most).max(claims);
                *total += claims as u64;
            }
            samples += 1;
            now += TICK;
        }
        assert!(renewals.len() >= 55 && renewals.len() <= 62, "{renewals:?}");
        for pair in renewals.windows(2) {
            assert_ne!(pair[0].0, pair[1].0, "the initiator alternates");
            let gap = pair[1].1 - pair[0].1;
            assert!(
                (11 * HOUR_MS..=13 * HOUR_MS).contains(&gap),
                "about 12 h apart: {gap}"
            );
        }
        for side in 0..2 {
            assert!(claim_max[side] <= 2, "side {side}: {}", claim_max[side]);
            let average = claim_samples[side] as f64 / samples as f64;
            assert!((0.8..=1.2).contains(&average), "side {side}: {average}");
            let mine: Vec<u64> = renewals
                .iter()
                .filter(|r| r.0 == side)
                .map(|r| r.1)
                .collect();
            for (i, start) in mine.iter().enumerate() {
                let in_day = mine[i..].iter().filter(|t| **t < start + DAY_MS).count();
                assert!(in_day <= usize::from(REPAIR_MAX_PER_DAY), "side {side}");
            }
        }
    }

    #[test]
    fn the_gate_is_closed_and_the_switch_is_per_thread() {
        const {
            assert!(!SESSION_RENEWAL_PRODUCTION_ENABLED);
        }
        set_lab_session_renewal_for_this_thread(Some(true));
        assert_eq!(session_renewal_live_enabled(), cfg!(debug_assertions));
        set_lab_session_renewal_for_this_thread(Some(false));
        assert!(!session_renewal_live_enabled());
        set_lab_session_renewal_for_this_thread(None);
    }
}
