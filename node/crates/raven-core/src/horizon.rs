//! Long message horizon (Phase 5, past the 24 h limit; plan
//! `docs/roadmap/plans/phase45-design.json`, horizon and letters design).
//!
//! Sessions and envelopes keep their 24 h ([`crate::lan_dispatch::LAN_SESSION_LIFETIME_MS`];
//! an envelope lives at most min(session end, 24 h)). A message gets its own
//! deadline, [`MESSAGE_HORIZON_MS`] after it was written, set once and never
//! extended. Until then Raven keeps it in two parts:
//!
//! - **5a, park and re-pair** ([`LONG_HORIZON_PRODUCTION_ENABLED`]): a message
//!   whose envelope or session expired is parked, not given up; when the
//!   contact is reachable again it is re-sealed under the same message id into
//!   a fresh session (an existing one, or one re-paired then), in send order,
//!   at most [`HORIZON_MAX_COPIES`] times. Re-pairing draws on the one
//!   per-contact automatic re-pair budget shared with Phase 3's session
//!   renewal ([`HORIZON_MAX_ROUNDS_PER_DAY`] rounds a day,
//!   [`HORIZON_PAIRINIT_COOLDOWN_MS`] apart). Receivers drop a copy they
//!   already took ([`receiver_dedup_live`]).
//! - **5b, sealed letters** ([`ASYNC_LETTER_PRODUCTION_ENABLED`]): when the
//!   contact cannot be reached, messages move into a letter session (a
//!   signed-prekey PairInit of up to [`LETTER_SESSION_LIFETIME_MS`], at most
//!   [`LETTER_SESSION_MAX_MESSAGES`] provisional messages) that a friend
//!   custodian holds as an RAL1 letter. Letters need the horizon and the
//!   friend custody gates.
//!
//! This module holds the gates, the constants, a message's deadline
//! ([`deadline_for`]) and the horizon step ([`run_horizon_step`], P5.7: re-seal
//! or re-pair, in send order; [`reseal_parked_before_send`], a send's re-seal
//! ahead of its new message, P5.8); the store and letter steps build on them. The
//! outbox parks an expired message through
//! [`crate::outbox::park_or_give_up_expired`] (P5.6), and the worker runs the
//! step right after the session reset step of each attempt.
//!
//! **Gates:** the horizon (5a) was switched on in release builds in 2026-10,
//! after the three-machine field test (debug builds with the lab switches
//! on); not independently reviewed. Sealed letters (5b) stay off until the
//! owner signs the letter waiver. A debug build closes the horizon with
//! `RAVEN_LAB_HORIZON=0` and opens letters with the Lab Test A unlock plus
//! `RAVEN_LAB_LETTER=1` ([`crate::pair_init::lab_gate`],
//! [`crate::pair_init::lab_switch`]); a release build never reads either
//! variable.

use std::cell::Cell;
use std::path::Path;

pub mod letters;

use crate::custody_gate::CustodyGates;
use crate::identity::Identity;
use crate::indexed_session_store::{
    EndpointDeliveryState, EndpointOutbound, EndpointOutboundKind, IndexedSessionRecordKey,
    IndexedSessionStore, MAX_ENDPOINT_ENVELOPE_LIFETIME_MS,
};
use crate::outbox::{
    localize_lan_route, GiveUp, OutboxCarrier, OutboxRoute, HISTORY_CANCELLED, HISTORY_EXPIRED,
    HISTORY_FAILED, LOCALIZE_RESOLVE_TIMEOUT,
};
use crate::prekey_lifecycle::{
    MAX_ACCEPTED_PREKEY_CLAIMS_PER_INITIATOR, MAX_PAIR_INIT_LIFETIME_MS,
};
use crate::session_renewal::code::RENEW_NO_ROUTE;
use crate::session_renewal::{REPAIR_COOLDOWN_MS, REPAIR_MAX_PER_DAY};
use crate::session_reset::{
    authorized_local, bound_offer, hand_off_prepared, identity_revoked, note_presented_cert,
    session_reset_live_enabled, store_err, ResetIo, RESET_RESEAL_MIN_REMAINING_MS,
};

/// Phase 5a production gate (park and re-pair up to [`MESSAGE_HORIZON_MS`]).
/// Switched on 2026-10 after the three-machine field test; not
/// independently reviewed.
pub const LONG_HORIZON_PRODUCTION_ENABLED: bool = true;
/// Phase 5b production gate (sealed async PairInit letters, RAL1, over
/// friend custody).
pub const ASYNC_LETTER_PRODUCTION_ENABLED: bool = false;
// Letters are the horizon's second half and ride friend custody.
const _: () = assert!(
    !ASYNC_LETTER_PRODUCTION_ENABLED
        || (LONG_HORIZON_PRODUCTION_ENABLED
            && crate::custody_gate::FRIEND_CUSTODY_PRODUCTION_ENABLED)
);

/// The horizon's debug lab switch: "0" closes it ([`crate::pair_init::lab_gate`]).
pub const LAB_HORIZON: &str = "RAVEN_LAB_HORIZON";
/// The letters' debug lab switch (with `RAVEN_LAB_TEST_A=1`); letters also
/// need [`LAB_HORIZON`] and the friend custody gate.
pub const LAB_LETTER: &str = "RAVEN_LAB_LETTER";

thread_local! {
    static HORIZON_LAB: Cell<Option<bool>> = const { Cell::new(None) };
    static LETTER_LAB: Cell<Option<bool>> = const { Cell::new(None) };
}

/// This thread's override of a lab switch; always `None` in a release build.
fn lab_override(cell: &'static std::thread::LocalKey<Cell<Option<bool>>>) -> Option<bool> {
    if cfg!(debug_assertions) {
        cell.with(Cell::get)
    } else {
        None
    }
}

/// 5a is live: [`LONG_HORIZON_PRODUCTION_ENABLED`]; in a debug build this
/// thread's override decides, else `RAVEN_LAB_HORIZON` ("0" closes it,
/// [`crate::pair_init::lab_gate`]); unless a security notice holds it
/// (P6.45, close-only).
pub fn horizon_live_enabled() -> bool {
    lab_override(&HORIZON_LAB)
        .unwrap_or_else(|| crate::pair_init::lab_gate(LONG_HORIZON_PRODUCTION_ENABLED, LAB_HORIZON))
        && crate::suite_policy::hold_allows(crate::suite_registry::FEATURE_LONG_HORIZON)
}

/// 5b is live: the horizon is live, the friend custody gate is live
/// ([`CustodyGates::current`]), and [`ASYNC_LETTER_PRODUCTION_ENABLED`] or in
/// a debug build this thread's override, else `RAVEN_LAB_LETTER` with the
/// Lab Test A unlock; unless a security notice holds letters or marks
/// `ral1/1` BROKEN (P6.45, close-only).
pub fn letter_live_enabled() -> bool {
    letter_gate(
        horizon_live_enabled(),
        CustodyGates::current().live,
        ASYNC_LETTER_PRODUCTION_ENABLED,
        || lab_override(&LETTER_LAB).unwrap_or_else(|| crate::pair_init::lab_switch(LAB_LETTER)),
    ) && crate::suite_policy::hold_allows(crate::suite_registry::FEATURE_ASYNC_LETTER)
}

/// [`letter_live_enabled`] from its inputs: `lab` is read only while the
/// horizon and custody gates are both live.
fn letter_gate(
    horizon_live: bool,
    custody_live: bool,
    production: bool,
    lab: impl FnOnce() -> bool,
) -> bool {
    horizon_live && custody_live && (production || lab())
}

/// Receivers drop a copy of a message they already took (same sender, same
/// message id): needed as soon as anything re-seals, the session reset step
/// or the horizon.
pub fn receiver_dedup_live() -> bool {
    session_reset_live_enabled() || horizon_live_enabled()
}

/// In-process tests switch the horizon on or off for the current thread
/// only (the environment variable would leak into every other test of the
/// binary), without the Lab Test A unlock; `None` goes back to the const
/// and the environment. Ignored in release builds.
#[doc(hidden)]
pub fn set_lab_horizon_for_this_thread(on: Option<bool>) {
    HORIZON_LAB.with(|cell| cell.set(on));
}

/// [`set_lab_horizon_for_this_thread`] for `RAVEN_LAB_LETTER`.
#[doc(hidden)]
pub fn set_lab_letter_for_this_thread(on: Option<bool>) {
    LETTER_LAB.with(|cell| cell.set(on));
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const HOUR_MS: u64 = 3_600_000;
/// A day.
pub const DAY_MS: u64 = 24 * HOUR_MS;

/// How long Raven keeps trying a message: its deadline is
/// `created_at + MESSAGE_HORIZON_MS` (owner decision O5-2: 7 d).
pub const MESSAGE_HORIZON_MS: u64 = 7 * DAY_MS;
/// At most this many sealed copies of one message (the first one included).
pub const HORIZON_MAX_COPIES: u8 = 8;
/// The gap between two horizon re-pairs with one contact: the shared
/// automatic re-pair budget's ([`crate::session_renewal`]).
pub const HORIZON_PAIRINIT_COOLDOWN_MS: u64 = REPAIR_COOLDOWN_MS;
/// Horizon re-pairs with one contact per 24 h window, counted together with
/// Phase 3's renewals (one budget).
pub const HORIZON_MAX_ROUNDS_PER_DAY: usize = REPAIR_MAX_PER_DAY as usize;

/// A session the horizon step re-seals parked messages into has at least
/// this long left (as the reset step's targets,
/// [`crate::session_reset::RESET_TARGET_MIN_REMAINING_MS`]).
pub const HORIZON_TARGET_MIN_REMAINING_MS: u64 = 10 * 60 * 1000;

/// The longest letter session this implementation starts (O5-4) ...
pub const LETTER_SESSION_LIFETIME_MS: u64 = 7 * DAY_MS;
/// ... and the shortest: none is started below a day.
pub const LETTER_MIN_SESSION_LIFETIME_MS: u64 = DAY_MS;
/// Provisional message indices 0-15 in one letter session (O5-4; an addendum
/// to ATSAM_ENDPOINT_TRANSACTION_V1 §4.1).
pub const LETTER_SESSION_MAX_MESSAGES: u32 = 16;
/// New letter sessions per contact per 24 h.
pub const LETTER_SESSIONS_PER_PEER_PER_DAY: usize = 1;
/// A responder keeps at most this many letter claims per initiator.
pub const MAX_LETTER_CLAIMS_PER_INITIATOR: usize = 8;

/// The deadline of a message written at `created_at_ms`: set once, never
/// extended (a re-sealed copy keeps its message's).
pub fn message_deadline(created_at_ms: u64) -> u64 {
    created_at_ms.saturating_add(MESSAGE_HORIZON_MS)
}

/// The session id and object digest a message's stage carries while no
/// sealed copy of it exists (staged to a contact without a session, P5.8):
/// all zero, which no real session or object has.
pub const SENTINEL_BINDING: [u8; 32] = [0u8; 32];

/// Does this stage carry the [`SENTINEL_BINDING`]?
pub fn is_sentinel_stage(staged: &crate::chat_history::StagedOutboundBody) -> bool {
    let zero = hex::encode(SENTINEL_BINDING);
    staged.session_id_hex.eq_ignore_ascii_case(&zero)
        && staged.object_digest_hex.eq_ignore_ascii_case(&zero)
}

/// When the outbound message `message_id` to `peer` was written, and its
/// deadline ([`message_deadline`]): from its stage (bound to `peer`), else
/// from its history row (a body kept there only). `None` without either,
/// as for an app channel object, which has neither: it keeps its own
/// expiry.
pub fn deadline_for(
    data_dir: &std::path::Path,
    peer: &[u8; 32],
    message_id: &[u8; 16],
) -> Option<(u64, u64)> {
    let peer_hex = hex::encode(peer);
    let created = match crate::chat_history::load_staged_outbound_body(data_dir, message_id) {
        Ok(Some(staged)) if staged.peer_pub_hex.eq_ignore_ascii_case(&peer_hex) => {
            staged.created_at_ms
        }
        Ok(Some(_)) | Err(_) => return None,
        Ok(None) => {
            let mid_hex = hex::encode(message_id);
            crate::ChatHistory::load(data_dir)
                .ok()?
                .entries
                .into_iter()
                .find(|e| {
                    e.direction == "out"
                        && e.peer_pub_hex.eq_ignore_ascii_case(&peer_hex)
                        && e.message_id_hex.eq_ignore_ascii_case(&mid_hex)
                        && !e.body.is_empty()
                })?
                .created_at_ms
        }
    };
    (created > 0).then(|| (created, message_deadline(created)))
}

// ---------------------------------------------------------------------------
// The horizon step (5a): re-seal or re-pair, in send order
// ---------------------------------------------------------------------------

/// Inputs of one horizon step for one contact.
pub struct HorizonEnv<'a> {
    pub data_dir: &'a Path,
    pub identity: &'a Identity,
    pub peer: [u8; 32],
    /// The contact's planned routes, preference order (the caller applied the
    /// gates, hide-IP and the verified-contact rule): where a re-pair may go,
    /// over any carrier that may carry a PairInit (owner decision O5-3, as a
    /// first send). Empty: nothing is dialled.
    pub routes: &'a [OutboxRoute],
    /// The contact is verified (pinned): any such route; otherwise LAN routes
    /// on the local network only (as session renewal).
    pub pinned: bool,
    pub now_ms: u64,
}

/// One parked message sealed again.
#[derive(Debug, Clone)]
pub struct ResealedParked {
    pub message_id: [u8; 16],
    /// The session of the copy that was parked, when known.
    pub from_session: Option<[u8; 32]>,
    pub new: EndpointOutbound,
}

/// What a horizon step did to a contact's parked messages.
#[derive(Debug, Clone, Default)]
pub struct HorizonReport {
    /// Sealed again under their own message ids, in send order.
    pub resealed: Vec<ResealedParked>,
    /// A copy was delivered after all (a late ACK): settled.
    pub delivered: Vec<[u8; 16]>,
    /// Past the deadline: given up (history `expired`), each with whether it
    /// never left this computer (its route record's `unsent`, CP.6).
    pub expired: Vec<([u8; 16], bool)>,
    /// At [`HORIZON_MAX_COPIES`]: given up (history `failed`).
    pub capped: Vec<[u8; 16]>,
    /// No body left to seal (stage nor history): given up.
    pub no_body: Vec<[u8; 16]>,
    /// The contact's identity or the session's lineage is revoked: given up
    /// (history `failed`), never sealed again.
    pub revoked: Vec<[u8; 16]>,
    /// Still parked when the step ended.
    pub parked: usize,
}

impl HorizonReport {
    /// Messages that left the parked table for good this step (each needs no
    /// route record any more).
    pub fn finished(&self) -> Vec<[u8; 16]> {
        self.delivered
            .iter()
            .chain(self.expired.iter().map(|(mid, _)| mid))
            .chain(&self.capped)
            .chain(&self.no_body)
            .chain(&self.revoked)
            .copied()
            .collect()
    }

    /// Nothing changed.
    pub fn is_empty(&self) -> bool {
        self.resealed.is_empty() && self.finished().is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HorizonStep {
    /// Nothing is parked for the contact (any more).
    Nothing,
    /// Sealed again into a session that was there (no dial).
    Resealed,
    /// Re-paired over `carrier`, then sealed again.
    Repaired { carrier: OutboxCarrier },
    /// No PairInit now: the shared re-pair budget
    /// ([`crate::session_renewal::code::REPAIR_COOLDOWN`],
    /// [`crate::session_renewal::code::RENEW_DAILY_CAP`]), fork evidence or
    /// the reset loop cap, the contact's prekey pin, or no route that may
    /// carry a PairInit ([`crate::session_renewal::code::RENEW_NO_ROUTE`]).
    Held(&'static str),
    /// No route reached the contact, or the pairing failed: back off.
    Unreachable(String),
}

/// One horizon step for `env.peer` (Phase 5a; design `run_horizon_step`).
/// Under the peer's lock, store work only: crash repair, the deadline sweep,
/// then every parked message is sealed again into a sendable session
/// ([`IndexedSessionStore::horizon_target_for_peer`]) in send order. Without
/// one, at most one synchronous PairInit per step over the first route that
/// answers, never holding the lock across a dial, bounded by the contact's one
/// automatic re-pair budget shared with Phase 3's renewal
/// ([`IndexedSessionStore::begin_repair_attempt`], counted only once an offer
/// verified). With the gate off it reads nothing.
pub fn run_horizon_step(
    env: &HorizonEnv,
    io: &mut dyn ResetIo,
) -> Result<(HorizonStep, HorizonReport), String> {
    let mut report = HorizonReport::default();
    if !horizon_live_enabled() {
        return Ok((HorizonStep::Nothing, report));
    }
    let (data_dir, identity, peer, now) = (env.data_dir, env.identity, env.peer, env.now_ms);
    let mut target = None;
    let mut hold = None;
    io.locked(&mut |store| {
        settle_parked(data_dir, identity, store, &peer, now, &mut report)?;
        if store
            .parked_for_recipient(&peer)
            .map_err(store_err)?
            .is_empty()
        {
            return Ok(());
        }
        target = horizon_target(store, &peer, now)?;
        match &target {
            Some(target) => {
                reseal_parked(data_dir, identity, store, &peer, target, now, &mut report)?
            }
            None => hold = repair_hold(store, &peer, now)?,
        }
        report.parked = store.parked_for_recipient(&peer).map_err(store_err)?.len();
        Ok(())
    })?;
    if target.is_some() {
        return Ok((HorizonStep::Resealed, report));
    }
    if report.parked == 0 {
        return Ok((HorizonStep::Nothing, report));
    }
    if let Some(code) = hold {
        return Ok((HorizonStep::Held(code), report));
    }
    let mut last = None;
    for planned in env.routes.iter().filter(|r| may_carry_pair_init(r)) {
        let route = if planned.carrier == OutboxCarrier::Lan {
            match localize_lan_route(planned, env.pinned, LOCALIZE_RESOLVE_TIMEOUT) {
                Ok(route) => route,
                Err(refusal) => {
                    last = Some(format!("{refusal:?}"));
                    continue;
                }
            }
        } else if env.pinned {
            planned.clone()
        } else {
            last = Some("an unverified contact re-pairs over the local network only".into());
            continue;
        };
        let replies = match io.dial(&route, &[]) {
            Ok(replies) => replies,
            Err(e) => {
                last = Some(e);
                continue;
            }
        };
        let Some(offer) = bound_offer(&replies, &peer, now) else {
            last = Some("the contact's offer did not verify".into());
            continue;
        };
        crate::lan_dispatch::cache_peer_bundle(data_dir, &offer)?;
        // The round counts before the PairInit exists (a crash only
        // over-counts); a lost-state certificate retires the old sessions
        // first (the reset gate on), as renewal does.
        let mut budget = Ok(());
        io.locked(&mut |store| {
            if session_reset_live_enabled() {
                note_presented_cert(data_dir, store, &peer, &offer.cert, now)?;
            }
            budget = store.begin_repair_attempt(&peer, now).map_err(store_err)?;
            Ok(())
        })?;
        if let Err((_, code)) = budget {
            return Ok((HorizonStep::Held(code), report));
        }
        let local_route = route.carrier == OutboxCarrier::Lan
            && localize_lan_route(&route, false, LOCALIZE_RESOLVE_TIMEOUT).is_ok();
        // The contact answered the probe: no second route.
        if let Err(e) = crate::session_reset::pair_with_peer(
            data_dir,
            identity,
            &offer,
            &route,
            local_route,
            false,
            io,
        ) {
            if e.starts_with(crate::lan_dispatch::PEER_PREKEY_RESET) {
                return Ok((
                    HorizonStep::Held(crate::lan_dispatch::PEER_PREKEY_RESET),
                    report,
                ));
            }
            return Ok((HorizonStep::Unreachable(e), report));
        }
        let mut sealed = false;
        io.locked(&mut |store| {
            if let Some(target) = horizon_target(store, &peer, now)? {
                reseal_parked(data_dir, identity, store, &peer, &target, now, &mut report)?;
                sealed = true;
            }
            report.parked = store.parked_for_recipient(&peer).map_err(store_err)?.len();
            Ok(())
        })?;
        if !sealed {
            return Ok((
                HorizonStep::Unreachable("the new session cannot carry them".into()),
                report,
            ));
        }
        return Ok((
            HorizonStep::Repaired {
                carrier: route.carrier,
            },
            report,
        ));
    }
    let Some(last) = last else {
        return Ok((HorizonStep::Held(RENEW_NO_ROUTE), report));
    };
    if letter_live_enabled() {
        return letter_step(env, io, last, report);
    }
    Ok((HorizonStep::Unreachable(last), report))
}

/// A send's half of the horizon (P5.8): before a new message to `peer` is
/// sealed into `target`, the session the send seals it into, `peer`'s
/// parked messages are sealed again into it first, in send order, so the
/// new message never overtakes them. Run under the peer's send lock, which
/// the send holds: [`settle_parked`] (crash repair, revoked and past their
/// deadline given up), then the horizon step's re-seal. One whose expired
/// copy is in `target` itself stays parked for another session. Nothing is
/// dialled. Gate off: nothing.
pub fn reseal_parked_before_send(
    data_dir: &Path,
    identity: &Identity,
    store: &mut IndexedSessionStore,
    peer: &[u8; 32],
    target: &IndexedSessionRecordKey,
    now_ms: u64,
) -> Result<HorizonReport, String> {
    let mut report = HorizonReport::default();
    if !horizon_live_enabled() {
        return Ok(report);
    }
    settle_parked(data_dir, identity, store, peer, now_ms, &mut report)?;
    if !store
        .parked_for_recipient(peer)
        .map_err(store_err)?
        .is_empty()
    {
        reseal_parked(data_dir, identity, store, peer, target, now_ms, &mut report)?;
    }
    report.parked = store.parked_for_recipient(peer).map_err(store_err)?.len();
    Ok(report)
}

/// Where `peer`'s parked messages go now
/// ([`IndexedSessionStore::horizon_target_for_peer`]), unless that session
/// already holds a copy of the oldest one (its envelope ran out before the
/// session did): a session takes a message id once, so they wait for
/// another session (a re-pair) instead, in send order.
fn horizon_target(
    store: &mut IndexedSessionStore,
    peer: &[u8; 32],
    now_ms: u64,
) -> Result<Option<IndexedSessionRecordKey>, String> {
    let Some(target) = store
        .horizon_target_for_peer(peer, now_ms)
        .map_err(store_err)?
    else {
        return Ok(None);
    };
    let sid = store
        .session_id_for_record_key(&target)
        .map_err(store_err)?;
    match store.parked_for_recipient(peer).map_err(store_err)?.first() {
        Some(oldest) if holds_copy(store, peer, &oldest.message_id, &sid)? => Ok(None),
        _ => Ok(Some(target)),
    }
}

/// Does session `sid` hold a copy of `mid` to `peer` (an outbox or an
/// outstanding row)?
fn holds_copy(
    store: &IndexedSessionStore,
    peer: &[u8; 32],
    mid: &[u8; 16],
    sid: &[u8; 32],
) -> Result<bool, String> {
    Ok(store
        .message_copies_for_recipient(peer, mid)
        .map_err(store_err)?
        .iter()
        .any(|c| c.session_id == *sid))
}

/// 5b: what waits is moved into a letter session by the worker's custody
/// phase, where the custodians that serve letters are known
/// ([`letters::build_letters`], P5.15): here the contact is unreachable.
fn letter_step(
    _env: &HorizonEnv,
    _io: &mut dyn ResetIo,
    last: String,
    report: HorizonReport,
) -> Result<(HorizonStep, HorizonReport), String> {
    Ok((HorizonStep::Unreachable(last), report))
}

/// A route that may carry a PairInit now (as renewal's): an
/// endpoint-confidential carrier, and LAN only while it is usable.
fn may_carry_pair_init(route: &OutboxRoute) -> bool {
    route.carrier.confidential_to_endpoint()
        && (route.carrier != OutboxCarrier::Lan || crate::lan_usable_now())
}

/// Why no PairInit may start now (`None`: one may): fork evidence or the
/// reset loop cap within the reset step's window (as renewal), then the
/// shared re-pair budget, read only (it is counted once an offer verified).
fn repair_hold(
    store: &mut IndexedSessionStore,
    peer: &[u8; 32],
    now_ms: u64,
) -> Result<Option<&'static str>, String> {
    let reset = store.peer_reset_state(peer).map_err(store_err)?;
    let since = now_ms
        .saturating_sub(crate::session_reset::RESET_DAY_MS)
        .max(reset.user_confirmed_at_ms.unwrap_or(0));
    if reset.fork_evidence_at_ms.is_some_and(|at| at > since) {
        return Ok(Some(crate::session_reset::code::PEER_IDENTITY_FORK));
    }
    if store.reset_rounds_since(peer, since).map_err(store_err)?
        >= crate::session_reset::RESET_MAX_AUTO_ROUNDS_PER_DAY
    {
        return Ok(Some(crate::session_reset::code::PEER_RESET_LOOP));
    }
    let state = store.peer_renewal_state(peer).map_err(store_err)?;
    Ok(crate::session_renewal::repair_budget(&state, now_ms)
        .err()
        .map(|(_, code)| code))
}

/// The local half of a horizon step, under the peer's lock: crash repair
/// ([`crate::session_reset::reconcile_resealed_outbound`], parked rows and
/// sentinel stages included), a revoked identity's parked messages given up,
/// and those past their deadline given up as `expired` (also for a contact
/// no message may go to now). Nothing is sealed or dialled. Gate off: nothing.
pub fn settle_parked(
    data_dir: &Path,
    identity: &Identity,
    store: &mut IndexedSessionStore,
    peer: &[u8; 32],
    now_ms: u64,
    report: &mut HorizonReport,
) -> Result<(), String> {
    if !horizon_live_enabled() {
        return Ok(());
    }
    let before: Vec<[u8; 16]> = store
        .parked_for_recipient(peer)
        .map_err(store_err)?
        .iter()
        .map(|row| row.message_id)
        .collect();
    crate::session_reset::reconcile_resealed_outbound(data_dir, identity, store, peer, now_ms)?;
    let rows = store.parked_for_recipient(peer).map_err(store_err)?;
    // Settled by a late ACK (or a live copy took over) in the reconcile.
    for mid in before {
        if !rows.iter().any(|row| row.message_id == mid)
            && store
                .message_copies_for_recipient(peer, &mid)
                .map_err(store_err)?
                .iter()
                .any(|c| {
                    matches!(
                        c.delivery_state,
                        Some(EndpointDeliveryState::Delivered | EndpointDeliveryState::Read)
                    )
                })
        {
            report.delivered.push(mid);
        }
    }
    if rows.is_empty() {
        return Ok(());
    }
    if identity_revoked(data_dir, peer)? {
        // Never sealed again for a revoked identity.
        for row in rows {
            give_up_parked_message(data_dir, store, peer, &row.message_id, HISTORY_FAILED)?;
            report.revoked.push(row.message_id);
        }
        return Ok(());
    }
    let due: Vec<_> = rows
        .into_iter()
        .filter(|row| row.deadline_ms <= now_ms)
        .collect();
    if due.is_empty() {
        return Ok(());
    }
    let evidence = crate::outbox::object_route_evidence(data_dir, now_ms).unwrap_or_default();
    for row in due {
        let never_sent = evidence
            .get(&row.message_id)
            .is_some_and(|e| e.unsent && !e.written && !e.with_friend);
        give_up_parked_message(data_dir, store, peer, &row.message_id, HISTORY_EXPIRED)?;
        report.expired.push((row.message_id, never_sent));
    }
    Ok(())
}

/// Give up the parked message `mid` to `peer`: its history takes `delivery`
/// (with the staged body, whatever copy the stage names), the stage goes,
/// then the parked row (history first: a crash in between gives it up again).
fn give_up_parked_message(
    data_dir: &Path,
    store: &mut IndexedSessionStore,
    peer: &[u8; 32],
    mid: &[u8; 16],
    delivery: &str,
) -> Result<(), String> {
    crate::session_reset::settle_history(data_dir, peer, mid, delivery)?;
    store.give_up_parked(peer, mid).map_err(store_err)?;
    Ok(())
}

/// Stop the parked message `mid` to `peer` for good (`raven outbox cancel`,
/// review 5a-1): given up as the step gives one up
/// ([`give_up_parked_message`]: history first, with the staged body, then
/// the stage, then the parked row), with history [`HISTORY_CANCELLED`].
/// A copy the contact confirmed meanwhile (a late ACK the step has not
/// settled yet) makes it delivered instead ([`GiveUp::Delivered`]).
/// `Ok(None)`: `mid` is not parked for `peer` (any more). Run under the
/// peer's send lock, which the worker's horizon step takes too, so the step
/// never seals it again meanwhile. Follows the store, not the gate (a row
/// parked while the gate was on is still listed as waiting). The caller
/// clears its route record.
pub fn cancel_parked(
    data_dir: &Path,
    store: &mut IndexedSessionStore,
    peer: &[u8; 32],
    mid: &[u8; 16],
) -> Result<Option<GiveUp>, String> {
    if !store
        .parked_for_recipient(peer)
        .map_err(store_err)?
        .iter()
        .any(|row| row.message_id == *mid)
    {
        return Ok(None);
    }
    let confirmed = store
        .message_copies_for_recipient(peer, mid)
        .map_err(store_err)?
        .iter()
        .any(|c| {
            matches!(
                c.delivery_state,
                Some(EndpointDeliveryState::Delivered | EndpointDeliveryState::Read)
            )
        });
    if confirmed {
        give_up_parked_message(data_dir, store, peer, mid, "delivered")?;
        return Ok(Some(GiveUp::Delivered));
    }
    give_up_parked_message(data_dir, store, peer, mid, HISTORY_CANCELLED)?;
    Ok(Some(GiveUp::Abandoned))
}

/// The contact `peer` is being removed (review 5a-2): every message parked
/// for it is given up as [`cancel_parked`] gives one up (history
/// `cancelled`, or `delivered` for one a late ACK confirmed; its stage
/// cleared), and its route record is cleared. Run before
/// [`crate::indexed_session_store::forget_session_end`] forgets the parked
/// rows: without this their stages stayed for good, each with the body and
/// the removed contact's key, and their history said `queued`, since
/// nothing sends, expires or clears a stage whose parked row is gone. Run
/// under the peer's send lock. Follows the store, not the gate. The message
/// ids given up.
pub fn give_up_parked_for_contact(
    data_dir: &Path,
    store: &mut IndexedSessionStore,
    peer: &[u8; 32],
) -> Result<Vec<[u8; 16]>, String> {
    let mut gone = Vec::new();
    for row in store.parked_for_recipient(peer).map_err(store_err)? {
        if cancel_parked(data_dir, store, peer, &row.message_id)?.is_some() {
            gone.push(row.message_id);
        }
    }
    // Hints only: a record left behind plans nothing for a removed contact.
    let _ = crate::outbox::clear_object_routes(data_dir, &gone);
    Ok(gone)
}

/// The body and write time of the parked message `mid` to `peer`: its stage
/// (bound to `peer`, whatever copy it names), else the history row that holds
/// one.
fn parked_body(
    data_dir: &Path,
    peer: &[u8; 32],
    mid: &[u8; 16],
) -> Result<Option<(String, u64)>, String> {
    let peer_hex = hex::encode(peer);
    if let Some(staged) =
        crate::chat_history::load_staged_outbound_body(data_dir, mid).map_err(|e| e.to_string())?
    {
        if staged.peer_pub_hex.eq_ignore_ascii_case(&peer_hex) {
            return Ok(Some((staged.body, staged.created_at_ms)));
        }
        return Ok(None);
    }
    let mid_hex = hex::encode(mid);
    Ok(crate::ChatHistory::load(data_dir)
        .map_err(|e| e.to_string())?
        .entries
        .into_iter()
        .find(|e| {
            e.direction == "out"
                && e.peer_pub_hex.eq_ignore_ascii_case(&peer_hex)
                && e.message_id_hex.eq_ignore_ascii_case(&mid_hex)
                && !e.body.is_empty()
        })
        .map(|e| (e.body, e.created_at_ms)))
}

/// Seal `peer`'s parked messages again into `target`, in the original send
/// order (design `reseal_parked`, like the reset step's
/// [`crate::session_reset::reseal_retired_outbound`]): under the same message
/// id, each at most [`HORIZON_MAX_COPIES`] times in all (the re-seal ledger,
/// bumped in its own transaction first and kept until the deadline plus a
/// day), valid until min(deadline, the target's end, now + 24 h); the seal
/// and the unpark are one transaction, and the stage follows the new copy.
/// Run under the peer's lock.
fn reseal_parked(
    data_dir: &Path,
    identity: &Identity,
    store: &mut IndexedSessionStore,
    peer: &[u8; 32],
    target: &IndexedSessionRecordKey,
    now_ms: u64,
    report: &mut HorizonReport,
) -> Result<(), String> {
    let into = ResealInto {
        limit: usize::MAX,
        validity_ms: crate::outbox::ENVELOPE_VALIDITY_MS,
    };
    reseal_parked_with(
        data_dir, identity, store, peer, target, into, now_ms, report,
    )
}

/// How [`reseal_parked_with`] seals: at most `limit` messages, each valid
/// at most `validity_ms` from now (a letter session's copies live as long
/// as the session, up to the deadline, P5.15).
#[derive(Debug, Clone, Copy)]
struct ResealInto {
    limit: usize,
    validity_ms: u64,
}

/// [`reseal_parked`] with `into`'s limit and validity.
#[allow(clippy::too_many_arguments)]
fn reseal_parked_with(
    data_dir: &Path,
    identity: &Identity,
    store: &mut IndexedSessionStore,
    peer: &[u8; 32],
    target: &IndexedSessionRecordKey,
    into: ResealInto,
    now_ms: u64,
    report: &mut HorizonReport,
) -> Result<(), String> {
    let rows = store.parked_for_recipient(peer).map_err(store_err)?;
    if rows.is_empty() {
        return Ok(());
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
            for row in rows {
                give_up_parked_message(data_dir, store, peer, &row.message_id, HISTORY_FAILED)?;
                report.revoked.push(row.message_id);
            }
            return Ok(());
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
        .find(|r| r.session_id == target_sid && r.kind == EndpointOutboundKind::Message)
    {
        hand_off_prepared(data_dir, store, target, peer, &row, &local, now_ms)?;
    }
    let mut rng = rand::rngs::OsRng;
    let mut sealed = 0usize;
    for row in rows {
        if sealed >= into.limit {
            break;
        }
        let mid = row.message_id;
        if holds_copy(store, peer, &mid, &target_sid)? {
            // Its expired copy is in this very session: it and what was sent
            // after it wait for another session, in send order.
            break;
        }
        if store.reseal_count(peer, &mid).map_err(store_err)? >= HORIZON_MAX_COPIES - 1 {
            // The first copy and seven more: no further copy.
            give_up_parked_message(data_dir, store, peer, &mid, HISTORY_FAILED)?;
            report.capped.push(mid);
            continue;
        }
        let Some((body, created)) = parked_body(data_dir, peer, &mid)? else {
            give_up_parked_message(data_dir, store, peer, &mid, HISTORY_FAILED)?;
            report.no_body.push(mid);
            continue;
        };
        let margin = now_ms.saturating_add(RESET_RESEAL_MIN_REMAINING_MS);
        if row.deadline_ms <= margin {
            give_up_parked_message(data_dir, store, peer, &mid, HISTORY_EXPIRED)?;
            report.expired.push((mid, false));
            continue;
        }
        let expires = row
            .deadline_ms
            .min(target_expires)
            .min(now_ms.saturating_add(into.validity_ms));
        if expires <= margin {
            // The target ends first: it waits for a longer one.
            continue;
        }
        store
            .bump_reseal_ledger(peer, &mid, row.deadline_ms, now_ms)
            .map_err(store_err)?;
        let mut cb = |digest: &[u8; 32], _bytes: &[u8]| -> Result<[u8; 32], ()> {
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
            .reseal_parked_envelope(
                target, &body, &mid, &local, now_ms, expires, now_ms, &mut rng, &mut cb,
            )
            .map_err(store_err)?;
        // Friends hold only an old copy: the new one is left again.
        let _ = crate::outbox::clear_object_custodians(data_dir, &mid, now_ms);
        sealed += 1;
        report.resealed.push(ResealedParked {
            message_id: mid,
            from_session: row.from_session,
            new,
        });
    }
    Ok(())
}

// The design's values (O5-2; 3, 7, 14 or 30 d were the options).
const _: () = assert!(MESSAGE_HORIZON_MS >= crate::lan_dispatch::LAN_SESSION_LIFETIME_MS);
const _: () = assert!(MESSAGE_HORIZON_MS <= 30 * DAY_MS);
const _: () = assert!(HORIZON_PAIRINIT_COOLDOWN_MS == 60_000);
const _: () = assert!(HORIZON_MAX_ROUNDS_PER_DAY == 4);
const _: () =
    assert!(HORIZON_TARGET_MIN_REMAINING_MS == crate::session_reset::RESET_TARGET_MIN_REMAINING_MS);
// A letter session is a PairInit, and its envelopes are endpoint envelopes:
// both cap it.
const _: () = assert!(
    LETTER_SESSION_LIFETIME_MS <= MAX_PAIR_INIT_LIFETIME_MS
        && LETTER_SESSION_LIFETIME_MS <= MAX_ENDPOINT_ENVELOPE_LIFETIME_MS
);
const _: () = assert!(LETTER_MIN_SESSION_LIFETIME_MS <= LETTER_SESSION_LIFETIME_MS);
// Letter claims are prekey claims.
const _: () = assert!(MAX_LETTER_CLAIMS_PER_INITIATOR <= MAX_ACCEPTED_PREKEY_CLAIMS_PER_INITIATOR);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::custody_gate::set_custody_gates_for_this_thread;

    /// 2026-10: the horizon is on in release builds, letters stay off.
    #[test]
    fn horizon_flag_is_on_and_letters_stay_off() {
        const {
            assert!(LONG_HORIZON_PRODUCTION_ENABLED);
            assert!(!ASYNC_LETTER_PRODUCTION_ENABLED);
            assert!(MESSAGE_HORIZON_MS == 7 * 24 * 3_600_000);
        }
    }

    /// Letters need the horizon and the friend custody gate, whatever their
    /// own switch says; their switch is not even read without both.
    #[test]
    fn letter_gate_requires_horizon_and_custody_gates() {
        for horizon in [false, true] {
            for custody in [false, true] {
                for production in [false, true] {
                    for lab in [false, true] {
                        let mut read = false;
                        let live = letter_gate(horizon, custody, production, || {
                            read = true;
                            lab
                        });
                        assert_eq!(
                            live,
                            horizon && custody && (production || lab),
                            "{horizon} {custody} {production} {lab}"
                        );
                        if !(horizon && custody) {
                            assert!(!read, "switch read with a closed gate");
                        }
                    }
                }
            }
        }
        if !cfg!(debug_assertions) {
            return;
        }
        // The live function, with this thread's overrides.
        let closed = CustodyGates {
            live: false,
            wan: false,
        };
        let open = CustodyGates {
            live: true,
            wan: false,
        };
        set_lab_letter_for_this_thread(Some(true));
        for (horizon, custody, want) in [
            (false, closed, false),
            (false, open, false),
            (true, closed, false),
            (true, open, true),
        ] {
            set_lab_horizon_for_this_thread(Some(horizon));
            set_custody_gates_for_this_thread(Some(custody));
            assert_eq!(horizon_live_enabled(), horizon);
            assert_eq!(letter_live_enabled(), want, "{horizon} {custody:?}");
            assert_eq!(
                receiver_dedup_live(),
                horizon || session_reset_live_enabled()
            );
        }
        set_lab_letter_for_this_thread(Some(false));
        assert!(!letter_live_enabled(), "letter switch off");
        set_lab_horizon_for_this_thread(None);
        set_lab_letter_for_this_thread(None);
        set_custody_gates_for_this_thread(None);
    }

    /// 2026-10: the horizon is on in release builds and letters stay off.
    /// `RAVEN_LAB_LETTER` goes through [`crate::pair_init::lab_switch`]:
    /// without the Lab Test A unlock it stays closed whatever it says;
    /// `RAVEN_LAB_HORIZON=0` closes the horizon in a debug build.
    #[test]
    fn horizon_is_on_and_letters_need_lab_test_a() {
        use crate::pair_init::{lab_gate_value, lab_switch_value, lab_test_a_enabled};
        const {
            assert!(LONG_HORIZON_PRODUCTION_ENABLED);
            assert!(!ASYNC_LETTER_PRODUCTION_ENABLED);
        }
        for v in ["1", "true", "TRUE", "yes"] {
            assert!(!lab_switch_value(true, false, Some(v)), "no TEST_A: {v}");
            assert!(lab_switch_value(true, true, Some(v)), "{v}");
        }
        assert!(!lab_gate_value(
            true,
            LONG_HORIZON_PRODUCTION_ENABLED,
            false,
            Some("0")
        ));
        assert!(lab_gate_value(
            false,
            LONG_HORIZON_PRODUCTION_ENABLED,
            false,
            Some("0")
        ));
        // No override on this thread: the live functions follow the
        // environment, as a node does.
        let set = std::env::var(LAB_HORIZON).ok();
        assert_eq!(
            horizon_live_enabled(),
            lab_gate_value(
                cfg!(debug_assertions),
                LONG_HORIZON_PRODUCTION_ENABLED,
                lab_test_a_enabled(),
                set.as_deref()
            )
        );
        if !lab_test_a_enabled() {
            assert!(!letter_live_enabled() || ASYNC_LETTER_PRODUCTION_ENABLED);
        }
    }
}
