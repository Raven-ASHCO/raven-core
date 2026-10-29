//! Session renewal's per-contact state (Phase 3 item 4,
//! [`crate::session_renewal`]): the one automatic re-pair budget a contact
//! has (renewal now, Phase 5's horizon re-pair later), the failure backoff,
//! when the pair's newest session ends, and the PairInit whose PairResponse
//! was lost (resent byte for byte, `RAVEN_PAIR_INIT_V1.md` §6).
//!
//! One additive table, `peer_session_renewal` (`CREATE TABLE IF NOT
//! EXISTS`), in either schema: a profile that is not sealed keeps schema 1's
//! clear columns, which older builds ignore; a sealed profile's store (schema
//! 4, [`super::sealed`]) keys the device (`kh_peer_device`) and seals every
//! other value in the row's `meta` (the pending PairInit names both devices),
//! with a clear prune hour. [`METADATA_SCHEMA_VERSION`] is unchanged. The
//! moves to and from schema 4 and a re-key carry the rows ([`move_forward`],
//! [`move_back`]). A table found in the other layout's shape (an older build
//! of the pack moved or unsealed the store without knowing it) is dropped
//! and created again ([`ensure_table`]): it holds only a budget and a
//! resend. Removing a contact forgets its row ([`forget`], storage rule
//! "real erase").
//!
//! Phase 6b R2 (step P6.27) keeps a contact's early re-key in the same row
//! (when it was asked for, why, and the last one taken): in the sealed
//! `meta` of schema 4, three nullable clear columns in schema 1 (added to a
//! table an older build made, [`add_early_columns`]). No new table.

use super::sealed::{self, Layout, RenewalMeta};
use super::*;
use crate::at_rest::{self, MetaKeys, ValueType};
use crate::sqlite_rebuild::{self as rebuild, Migration, RebuildError, Steps};

/// The longest PairInit kept for a resend (the table's CHECK).
pub const RENEWAL_PENDING_MAX_BYTES: usize = 8192;

/// One contact's renewal state; `Default` when it has no row.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeerRenewalState {
    /// Start of the budget's 24 h window (0: none yet).
    pub window_start_ms: u64,
    /// Re-pair rounds begun in that window.
    pub attempts_in_window: u8,
    pub last_attempt_at_ms: Option<u64>,
    /// Failed rounds in a row (the backoff); a success clears it.
    pub failures: u8,
    /// The newest session end seen with this contact (the lapsed case).
    pub last_session_expires_at_ms: Option<u64>,
    /// The PairInit (wire bytes) whose PairResponse was lost, and its expiry.
    pub pending_init: Option<Vec<u8>>,
    pub pending_expires_at_ms: Option<u64>,
    /// Phase 6b R2 (step P6.27): an early re-key asked for at this time,
    /// until a renewal confirmed after it meets it (or it lapses,
    /// [`crate::session_renewal::EARLY_PENDING_MS`]) ...
    pub early_requested_at_ms: Option<u64>,
    /// ... why (the trigger's `SecKind` code) ...
    pub early_reason: Option<u16>,
    /// ... and when the last one was taken (one per
    /// [`crate::session_renewal::EARLY_MIN_GAP_MS`]).
    pub last_early_ms: Option<u64>,
}

pub(super) fn create_renewal_schema(conn: &Connection) -> Result<(), IndexedSessionStoreError> {
    ensure_table(conn, false)?;
    Ok(())
}

/// Whether the store holds the table keyed (schema 4's shape).
pub(super) fn keyed(conn: &Connection) -> rusqlite::Result<bool> {
    Ok(rebuild::columns(conn, sealed::RENEWAL)?
        .iter()
        .any(|column| column == "kh_peer_device"))
}

/// The table, created in the shape `keyed` asks for when it is missing. A
/// keyed table where a clear one is wanted (an older build of the pack
/// unsealed the store without knowing it; nothing here can open its rows
/// without the keys) is dropped and created clear, in one IMMEDIATE
/// transaction that reads the shape again (or in the caller's), and only
/// while the store's heads are clear: in a keyed store the table stays
/// (another opener's move to schema 4 committed after the caller read the
/// store's shape; review C-2). A clear table where a keyed one is wanted
/// stays: its rows move with the keys ([`ensure_keyed`], or the caller's
/// rebuild).
pub(super) fn ensure_table(conn: &Connection, keyed: bool) -> rusqlite::Result<()> {
    let create = sealed::create_if_missing(sealed::RENEWAL, sealed::renewal_columns(keyed));
    if keyed || !self::keyed(conn)? {
        conn.execute_batch(&create)?;
        return add_early_columns(conn);
    }
    let replace = |conn: &Connection| -> rusqlite::Result<()> {
        if !self::keyed(conn)? {
            return conn.execute_batch(&create);
        }
        if rebuild::shape(conn, sealed::HEADS, sealed::KEYED_COLUMN)? == rebuild::Shape::Keyed {
            return Ok(());
        }
        conn.execute_batch("DROP TABLE peer_session_renewal;")?;
        conn.execute_batch(&create)
    };
    if !conn.is_autocommit() {
        return replace(conn);
    }
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)?;
    let _in_tx = crate::paths::HeldMark::transaction();
    replace(&tx)?;
    tx.commit()
}

/// A clear table an older build made gets the early re-key columns (Phase
/// 6b R2, step P6.27; [`sealed::RENEWAL_EARLY_COLUMNS`]): additive, nullable,
/// ignored by older builds. Nothing is written when they are there (or the
/// table is keyed: there they live in the sealed `meta`).
fn add_early_columns(conn: &Connection) -> rusqlite::Result<()> {
    let columns = rebuild::columns(conn, sealed::RENEWAL)?;
    if !columns.iter().any(|column| column == "peer_device") {
        return Ok(());
    }
    for (name, definition) in sealed::RENEWAL_EARLY_COLUMNS {
        if !columns.iter().any(|column| column == name) {
            conn.execute_batch(&format!(
                "ALTER TABLE {} ADD COLUMN {name} {definition};",
                sealed::RENEWAL
            ))?;
        }
    }
    Ok(())
}

/// A keyed store's open ([`sealed::prepare_schema`]): the table created
/// keyed when it is missing, and clear rows an older build of the pack left
/// behind when it moved the store without knowing this table moved now
/// (keyed and sealed, rowids kept; [`move_forward`]) in one IMMEDIATE
/// transaction that reads the table's and the heads' shape again. `false`:
/// the heads are clear now (an unseal moved the store back since the open
/// read its shape; review C-2), nothing is changed and the open reads the
/// store again (a clear store's renewal rows never get keyed).
pub(super) fn ensure_keyed(
    conn: &Connection,
    keys: &MetaKeys,
) -> Result<bool, IndexedSessionStoreError> {
    if keyed(conn)? {
        return Ok(true);
    }
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)?;
    let _in_tx = crate::paths::HeldMark::transaction();
    if rebuild::shape(&tx, sealed::HEADS, sealed::KEYED_COLUMN)? != rebuild::Shape::Keyed {
        tx.commit()?;
        return Ok(false);
    }
    ensure_table(&tx, true)?;
    if !keyed(&tx)? {
        move_forward(&tx, keys, &mut Steps::default()).map_err(super::rebuild_error)?;
    }
    tx.commit()?;
    Ok(true)
}

fn ms(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn opt_ms(value: Option<i64>) -> Option<u64> {
    value.and_then(|v| u64::try_from(v).ok())
}

fn small(value: i64) -> u8 {
    u8::try_from(value.clamp(0, 255)).unwrap_or(u8::MAX)
}

/// When the prune may delete a row: once the pair's last session ended
/// [`crate::session_renewal::RENEW_LAPSED_MAX_MS`] ago, its last round is a
/// day old, its pending PairInit (if any) has expired, an early re-key
/// asked for has lapsed and the last one's 6 h cap is over.
fn goes_at(state: &PeerRenewalState) -> u64 {
    let ended = state.last_session_expires_at_ms.map_or(0, |at| {
        at.saturating_add(crate::session_renewal::RENEW_LAPSED_MAX_MS)
    });
    let attempted = state
        .last_attempt_at_ms
        .map_or(0, |at| at.saturating_add(crate::session_renewal::DAY_MS));
    let early = state.early_requested_at_ms.map_or(0, |at| {
        at.saturating_add(crate::session_renewal::EARLY_PENDING_MS)
    });
    let capped = state.last_early_ms.map_or(0, |at| {
        at.saturating_add(crate::session_renewal::EARLY_MIN_GAP_MS)
    });
    ended
        .max(attempted)
        .max(state.pending_expires_at_ms.unwrap_or(0))
        .max(early)
        .max(capped)
}

fn meta_of(peer: &[u8], state: &PeerRenewalState) -> RenewalMeta {
    RenewalMeta {
        peer_device: hex::encode(peer),
        window_start_ms: ms(state.window_start_ms),
        attempts_in_window: i64::from(state.attempts_in_window),
        last_attempt_at_ms: state.last_attempt_at_ms.map(ms),
        failures: i64::from(state.failures),
        last_session_expires_at_ms: state.last_session_expires_at_ms.map(ms),
        pending_init: state
            .pending_init
            .as_deref()
            .map(hex::encode)
            .unwrap_or_default(),
        pending_expires_at_ms: state.pending_expires_at_ms.map(ms),
        early_requested_at_ms: state.early_requested_at_ms.map(ms),
        early_reason: state.early_reason.map(i64::from),
        last_early_ms: state.last_early_ms.map(ms),
    }
}

/// A meta's state and clear device; `None` when a value is out of range.
fn state_of(meta: &RenewalMeta) -> Option<([u8; 32], PeerRenewalState)> {
    let peer = sealed::device_of(&meta.peer_device).ok()?;
    let pending_init = if meta.pending_init.is_empty() {
        None
    } else {
        let wire = hex::decode(&meta.pending_init).ok()?;
        if wire.len() > RENEWAL_PENDING_MAX_BYTES {
            return None;
        }
        Some(wire)
    };
    let pending_expires_at_ms = opt_ms(meta.pending_expires_at_ms);
    // Both or neither, as the clear table's CHECK has it.
    let (pending_init, pending_expires_at_ms) = match (pending_init, pending_expires_at_ms) {
        (Some(wire), Some(expires)) => (Some(wire), Some(expires)),
        _ => (None, None),
    };
    let mut state = PeerRenewalState {
        window_start_ms: u64::try_from(meta.window_start_ms).unwrap_or(0),
        attempts_in_window: small(meta.attempts_in_window),
        last_attempt_at_ms: opt_ms(meta.last_attempt_at_ms),
        failures: small(meta.failures),
        last_session_expires_at_ms: opt_ms(meta.last_session_expires_at_ms),
        pending_init,
        pending_expires_at_ms,
        ..PeerRenewalState::default()
    };
    set_early(
        &mut state,
        meta.early_requested_at_ms,
        meta.early_reason,
        meta.last_early_ms,
    );
    Some((peer, state))
}

/// The early re-key values as either shape holds them: a request and its
/// reason both or neither; an out-of-range value reads as none.
fn set_early(
    state: &mut PeerRenewalState,
    requested: Option<i64>,
    reason: Option<i64>,
    last: Option<i64>,
) {
    let reason = reason.and_then(|r| u16::try_from(r).ok());
    (state.early_requested_at_ms, state.early_reason) = match (opt_ms(requested), reason) {
        (Some(at), Some(reason)) => (Some(at), Some(reason)),
        _ => (None, None),
    };
    state.last_early_ms = opt_ms(last);
}

type ClearRow = (
    i64,
    i64,
    Option<i64>,
    i64,
    Option<i64>,
    Option<Vec<u8>>,
    Option<i64>,
    // The early re-key (step P6.27).
    (Option<i64>, Option<i64>, Option<i64>),
);

fn clear_state(row: ClearRow) -> PeerRenewalState {
    let (window, attempts, last, failures, ended, pending, pending_expires, early) = row;
    let mut state = PeerRenewalState {
        window_start_ms: u64::try_from(window).unwrap_or(0),
        attempts_in_window: small(attempts),
        last_attempt_at_ms: opt_ms(last),
        failures: small(failures),
        last_session_expires_at_ms: opt_ms(ended),
        pending_init: pending,
        pending_expires_at_ms: opt_ms(pending_expires),
        ..PeerRenewalState::default()
    };
    set_early(&mut state, early.0, early.1, early.2);
    state
}

/// A clear row's values from `row`, its first at `at` (in
/// [`CLEAR_COLUMNS`]' order).
fn clear_row(row: &rusqlite::Row<'_>, at: usize) -> rusqlite::Result<ClearRow> {
    Ok((
        row.get(at)?,
        row.get(at + 1)?,
        row.get(at + 2)?,
        row.get(at + 3)?,
        row.get(at + 4)?,
        row.get(at + 5)?,
        row.get(at + 6)?,
        (row.get(at + 7)?, row.get(at + 8)?, row.get(at + 9)?),
    ))
}

const CLEAR_COLUMNS: &str = "window_start_ms, attempts_in_window, last_attempt_at_ms, failures,
     last_session_expires_at_ms, pending_init, pending_expires_at_ms,
     early_requested_at_ms, early_reason, last_early_ms";

/// `peer`'s row. A keyed row whose `meta` does not open fails (the row's
/// corruption, never a fresh budget); the prune removes it by its hour.
fn load(
    conn: &Connection,
    layout: &Layout,
    peer: &[u8; 32],
) -> Result<Option<PeerRenewalState>, IndexedSessionStoreError> {
    if let Some(sealer) = layout.keyed() {
        let kp = sealer.device(peer);
        let meta: Option<Vec<u8>> = conn
            .query_row(
                "SELECT meta FROM peer_session_renewal WHERE kh_peer_device = ?1",
                params![kp.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        let Some(meta) = meta else {
            return Ok(None);
        };
        let meta: RenewalMeta = sealer.open(sealed::RENEWAL, &kp, &meta)?;
        return match state_of(&meta) {
            Some((device, state)) if device == *peer => Ok(Some(state)),
            _ => Err(IndexedSessionStoreError::CorruptEndpointState),
        };
    }
    let row: Option<ClearRow> = conn
        .query_row(
            &format!("SELECT {CLEAR_COLUMNS} FROM peer_session_renewal WHERE peer_device = ?1"),
            params![peer.as_slice()],
            |row| clear_row(row, 0),
        )
        .optional()?;
    Ok(row.map(clear_state))
}

fn put(
    conn: &Connection,
    layout: &Layout,
    peer: &[u8; 32],
    state: &PeerRenewalState,
) -> Result<(), IndexedSessionStoreError> {
    if let Some(sealer) = layout.keyed() {
        let kp = sealer.device(peer);
        conn.execute(
            "INSERT INTO peer_session_renewal (kh_peer_device, prune_after_hour, meta)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(kh_peer_device) DO UPDATE
               SET prune_after_hour = excluded.prune_after_hour, meta = excluded.meta",
            params![
                kp.as_slice(),
                sealed::prune_hour(ms(goes_at(state))),
                sealer.seal(sealed::RENEWAL, &kp, &meta_of(peer, state)),
            ],
        )?;
        return Ok(());
    }
    conn.execute(
        &format!(
            "INSERT INTO peer_session_renewal (peer_device, {CLEAR_COLUMNS})
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(peer_device) DO UPDATE
               SET window_start_ms = excluded.window_start_ms,
                   attempts_in_window = excluded.attempts_in_window,
                   last_attempt_at_ms = excluded.last_attempt_at_ms,
                   failures = excluded.failures,
                   last_session_expires_at_ms = excluded.last_session_expires_at_ms,
                   pending_init = excluded.pending_init,
                   pending_expires_at_ms = excluded.pending_expires_at_ms,
                   early_requested_at_ms = excluded.early_requested_at_ms,
                   early_reason = excluded.early_reason,
                   last_early_ms = excluded.last_early_ms"
        ),
        params![
            peer.as_slice(),
            ms(state.window_start_ms),
            i64::from(state.attempts_in_window),
            state.last_attempt_at_ms.map(ms),
            i64::from(state.failures),
            state.last_session_expires_at_ms.map(ms),
            state.pending_init,
            state.pending_expires_at_ms.map(ms),
            state.early_requested_at_ms.map(ms),
            state.early_reason.map(i64::from),
            state.last_early_ms.map(ms),
        ],
    )?;
    Ok(())
}

/// Forget `peer`'s row (its contact was removed), in whichever shape the
/// table has; no table is fine. The metadata reader's connection
/// ([`super::forget_session_end`]): nothing is created.
pub(super) fn forget(
    conn: &Connection,
    sealer: Option<&sealed::Sealer>,
    peer: &[u8; 32],
) -> Result<(), IndexedSessionStoreError> {
    let columns = rebuild::columns(conn, sealed::RENEWAL)?;
    if columns.iter().any(|column| column == "kh_peer_device") {
        if let Some(sealer) = sealer {
            conn.execute(
                "DELETE FROM peer_session_renewal WHERE kh_peer_device = ?1",
                params![sealer.device(peer).as_slice()],
            )?;
        }
    } else if columns.iter().any(|column| column == "peer_device") {
        conn.execute(
            "DELETE FROM peer_session_renewal WHERE peer_device = ?1",
            params![peer.as_slice()],
        )?;
    }
    Ok(())
}

impl IndexedSessionStore {
    /// `peer`'s renewal state ([`PeerRenewalState::default`] without a row).
    pub fn peer_renewal_state(
        &self,
        peer: &[u8; 32],
    ) -> Result<PeerRenewalState, IndexedSessionStoreError> {
        Ok(load(&self.conn, &self.layout, peer)?.unwrap_or_default())
    }

    /// The newest sendable session with `peer` (the head of
    /// [`Self::find_sendable_sessions_for_peer_at`], the order both nodes
    /// share): its key, `created_at_ms` and `expires_at_ms`.
    pub fn newest_sendable_summary(
        &mut self,
        peer: &[u8; 32],
        now_ms: u64,
    ) -> Result<Option<(IndexedSessionRecordKey, u64, u64)>, IndexedSessionStoreError> {
        let Some(key) = self
            .find_sendable_sessions_for_peer_at(peer, now_ms)?
            .into_iter()
            .next()
        else {
            return Ok(None);
        };
        let (_, _, _, created, expires) = self.head_summary(&key)?;
        Ok(Some((key, created, expires)))
    }

    /// The newest session end seen with `peer` (max-merged; written only
    /// when it moves forward).
    pub fn note_session_end_seen(
        &mut self,
        peer: &[u8; 32],
        expires_at_ms: u64,
    ) -> Result<(), IndexedSessionStoreError> {
        let newer = |state: &Option<PeerRenewalState>| {
            state
                .as_ref()
                .and_then(|s| s.last_session_expires_at_ms)
                .is_none_or(|seen| seen < expires_at_ms)
        };
        if !newer(&load(&self.conn, &self.layout, peer)?) {
            return Ok(());
        }
        let layout = &self.layout;
        sealed::in_write_tx(&self.conn, |conn| {
            let state = load(conn, layout, peer)?;
            if !newer(&state) {
                return Ok(());
            }
            let mut state = state.unwrap_or_default();
            state.last_session_expires_at_ms = Some(expires_at_ms);
            put(conn, layout, peer, &state)
        })
    }

    /// ONE per-peer automatic re-pair budget (renewal now; Phase 5 horizon
    /// re-pair later): at most [`crate::session_renewal::REPAIR_MAX_PER_DAY`]
    /// rounds per 24 h window and
    /// [`crate::session_renewal::REPAIR_COOLDOWN_MS`] between rounds. Its own
    /// IMMEDIATE transaction (or the caller's), BEFORE the PairInit exists
    /// (a crash only over-counts). `Ok(Err((until, code)))` when the budget
    /// says wait; nothing is counted then.
    pub fn begin_repair_attempt(
        &mut self,
        peer: &[u8; 32],
        now_ms: u64,
    ) -> Result<Result<(), (u64, &'static str)>, IndexedSessionStoreError> {
        let layout = &self.layout;
        sealed::in_write_tx(&self.conn, |conn| {
            let mut state = load(conn, layout, peer)?.unwrap_or_default();
            if let Err(wait) = crate::session_renewal::begin_attempt(&mut state, now_ms) {
                return Ok(Err(wait));
            }
            put(conn, layout, peer, &state)?;
            Ok(Ok(()))
        })
    }

    /// Give back the round [`Self::begin_repair_attempt`] counted at
    /// `counted_at_ms` when no PairInit came of it (the peer's send lock was
    /// busy before the renewal could create one, review C-4): the budget's
    /// window, count and last round are `prior`'s again. A row whose last
    /// round is another, or that keeps a PairInit, stays as it is.
    pub fn give_back_repair_attempt(
        &mut self,
        peer: &[u8; 32],
        counted_at_ms: u64,
        prior: &PeerRenewalState,
    ) -> Result<(), IndexedSessionStoreError> {
        let layout = &self.layout;
        sealed::in_write_tx(&self.conn, |conn| {
            let Some(mut state) = load(conn, layout, peer)? else {
                return Ok(());
            };
            if state.last_attempt_at_ms != Some(counted_at_ms) || state.pending_init.is_some() {
                return Ok(());
            }
            state.window_start_ms = prior.window_start_ms;
            state.attempts_in_window = prior.attempts_in_window;
            state.last_attempt_at_ms = prior.last_attempt_at_ms;
            put(conn, layout, peer, &state)
        })
    }

    /// The end of a round [`Self::begin_repair_attempt`] began: a success
    /// clears the failure count, a failure adds one (the backoff).
    pub fn finish_renewal_attempt(
        &mut self,
        peer: &[u8; 32],
        ok: bool,
    ) -> Result<(), IndexedSessionStoreError> {
        let layout = &self.layout;
        sealed::in_write_tx(&self.conn, |conn| {
            let mut state = load(conn, layout, peer)?.unwrap_or_default();
            state.failures = if ok {
                0
            } else {
                state.failures.saturating_add(1)
            };
            put(conn, layout, peer, &state)
        })
    }

    /// Keep the PairInit `init_wire` (exactly as it went on the wire) for a
    /// resend until `expires_at_ms`: its PairResponse may be lost.
    pub fn set_renewal_pending(
        &mut self,
        peer: &[u8; 32],
        init_wire: &[u8],
        expires_at_ms: u64,
    ) -> Result<(), IndexedSessionStoreError> {
        if init_wire.is_empty() || init_wire.len() > RENEWAL_PENDING_MAX_BYTES {
            return Err(IndexedSessionStoreError::InvalidBinding);
        }
        let layout = &self.layout;
        sealed::in_write_tx(&self.conn, |conn| {
            let mut state = load(conn, layout, peer)?.unwrap_or_default();
            state.pending_init = Some(init_wire.to_vec());
            state.pending_expires_at_ms = Some(expires_at_ms);
            put(conn, layout, peer, &state)
        })
    }

    /// Drop `peer`'s pending PairInit (confirmed, expired or superseded).
    pub fn clear_renewal_pending(
        &mut self,
        peer: &[u8; 32],
    ) -> Result<(), IndexedSessionStoreError> {
        let layout = &self.layout;
        sealed::in_write_tx(&self.conn, |conn| {
            let Some(mut state) = load(conn, layout, peer)? else {
                return Ok(());
            };
            if state.pending_init.is_none() {
                return Ok(());
            }
            state.pending_init = None;
            state.pending_expires_at_ms = None;
            put(conn, layout, peer, &state)
        })
    }

    /// Phase 6b R2 (step P6.27): note an early re-key with `peer` asked for
    /// at `now_ms` because of `reason` (a `SecKind` code). `Ok(false)`, and
    /// nothing written, within [`crate::session_renewal::EARLY_MIN_GAP_MS`]
    /// of the last one taken (either way round: a clock set back does not
    /// hold it longer).
    pub fn request_early_renewal(
        &mut self,
        peer: &[u8; 32],
        reason: u16,
        now_ms: u64,
    ) -> Result<bool, IndexedSessionStoreError> {
        let layout = &self.layout;
        sealed::in_write_tx(&self.conn, |conn| {
            let mut state = load(conn, layout, peer)?.unwrap_or_default();
            if state
                .last_early_ms
                .is_some_and(|at| at.abs_diff(now_ms) < crate::session_renewal::EARLY_MIN_GAP_MS)
            {
                return Ok(false);
            }
            state.early_requested_at_ms = Some(now_ms);
            state.early_reason = Some(reason);
            state.last_early_ms = Some(now_ms);
            put(conn, layout, peer, &state)?;
            Ok(true)
        })
    }

    /// The early re-key asked for at `requested_at_ms` was met (a renewal
    /// confirmed after it): it is no longer pending. A newer request stays;
    /// the 6 h cap ([`PeerRenewalState::last_early_ms`]) is kept.
    pub fn finish_early_renewal(
        &mut self,
        peer: &[u8; 32],
        requested_at_ms: u64,
    ) -> Result<(), IndexedSessionStoreError> {
        let layout = &self.layout;
        sealed::in_write_tx(&self.conn, |conn| {
            let Some(mut state) = load(conn, layout, peer)? else {
                return Ok(());
            };
            if state.early_requested_at_ms != Some(requested_at_ms) {
                return Ok(());
            }
            state.early_requested_at_ms = None;
            state.early_reason = None;
            put(conn, layout, peer, &state)
        })
    }

    /// Delete the rows nothing needs any more: no unexpired pending
    /// PairInit, the pair's last session ended more than
    /// [`crate::session_renewal::RENEW_LAPSED_MAX_MS`] ago and the last round
    /// is more than a day old. Best effort for the caller. How many went.
    pub fn prune_renewal_state(&mut self, now_ms: u64) -> Result<usize, IndexedSessionStoreError> {
        let now = ms(now_ms);
        let Some(sealer) = self.layout.keyed() else {
            let keep = ms(crate::session_renewal::RENEW_LAPSED_MAX_MS);
            let day = ms(crate::session_renewal::DAY_MS);
            let early = ms(crate::session_renewal::EARLY_PENDING_MS);
            let gap = ms(crate::session_renewal::EARLY_MIN_GAP_MS);
            return Ok(self.conn.execute(
                "DELETE FROM peer_session_renewal
                 WHERE (pending_expires_at_ms IS NULL OR pending_expires_at_ms < ?1)
                   AND (last_session_expires_at_ms IS NULL OR last_session_expires_at_ms < ?2)
                   AND (last_attempt_at_ms IS NULL OR last_attempt_at_ms < ?3)
                   AND (early_requested_at_ms IS NULL OR early_requested_at_ms < ?4)
                   AND (last_early_ms IS NULL OR last_early_ms < ?5)",
                params![
                    now,
                    now.saturating_sub(keep),
                    now.saturating_sub(day),
                    now.saturating_sub(early),
                    now.saturating_sub(gap),
                ],
            )?);
        };
        // Schema 4: the hours that may have gone, then each row's exact
        // times; a meta that does not open goes by its hour.
        let rows: Vec<(Vec<u8>, i64, Vec<u8>)> = {
            let mut statement = self.conn.prepare(
                "SELECT kh_peer_device, prune_after_hour, meta FROM peer_session_renewal
                 WHERE prune_after_hour <= ?1",
            )?;
            let mapped = statement.query_map(params![sealed::may_have_expired(now)], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })?;
            mapped.collect::<Result<_, _>>()?
        };
        let mut gone = 0;
        for (kp, hour, meta) in rows {
            let expired = match sealer.open::<RenewalMeta>(sealed::RENEWAL, &kp, &meta) {
                Ok(meta) => state_of(&meta).is_none_or(|(_, state)| goes_at(&state) < now_ms),
                Err(error @ IndexedSessionStoreError::MetaKeyUnavailable(_)) => return Err(error),
                Err(_) => sealed::surely_expired(hour, now),
            };
            if expired {
                gone += self.conn.execute(
                    "DELETE FROM peer_session_renewal WHERE kh_peer_device = ?1",
                    params![kp],
                )?;
            }
        }
        Ok(gone)
    }
}

/// Schema 1 -> 4's part for this table ([`sealed::migrate_forward`], and a
/// re-key's way forward): the clear rows rebuilt keyed, rowids kept. The
/// rows moved.
pub(super) fn move_forward(
    tx: &Transaction<'_>,
    keys: &MetaKeys,
    steps: &mut Steps,
) -> Result<u32, RebuildError> {
    steps.step()?;
    // A clear table an older build made: its early re-key columns first.
    add_early_columns(tx)?;
    tx.execute_batch(&format!(
        "CREATE TABLE {}__new ({});",
        sealed::RENEWAL,
        sealed::renewal_columns(true)
    ))?;
    let rows: Vec<(i64, Vec<u8>, ClearRow)> = {
        let mut statement = tx.prepare(&format!(
            "SELECT rowid, peer_device, {CLEAR_COLUMNS} FROM peer_session_renewal"
        ))?;
        let mapped =
            statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?, clear_row(row, 2)?)))?;
        mapped.collect::<Result<_, _>>()?
    };
    let mut moved = 0u32;
    for (rowid, peer, row) in rows {
        steps.step()?;
        let state = clear_state(row);
        let kp = at_rest::index(keys, ValueType::DeviceKey, &peer);
        let plain = Zeroizing::new(
            serde_json::to_vec(&meta_of(&peer, &state)).expect("strings and numbers"),
        );
        tx.execute(
            "INSERT INTO peer_session_renewal__new (rowid, kh_peer_device, prune_after_hour, meta)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                rowid,
                kp.as_slice(),
                sealed::prune_hour(ms(goes_at(&state))),
                at_rest::seal_row(keys, sealed::RENEWAL, &kp, &plain),
            ],
        )?;
        moved += 1;
    }
    steps.step()?;
    tx.execute_batch("DROP TABLE peer_session_renewal;")?;
    steps.step()?;
    tx.execute_batch("ALTER TABLE peer_session_renewal__new RENAME TO peer_session_renewal;")?;
    Ok(moved)
}

/// Schema 4 -> 1's part for this table ([`sealed::migrate_back`], and a
/// re-key's way back): each keyed row written back clear, rowids kept; a row
/// whose `meta` does not open is left out and counted (`dropped`).
pub(super) fn move_back(
    tx: &Transaction<'_>,
    keys: &MetaKeys,
    steps: &mut Steps,
    expected: &mut [(&'static str, i64)],
    report: &mut Migration,
) -> Result<(), RebuildError> {
    steps.step()?;
    tx.execute_batch(&format!(
        "CREATE TABLE {}__new ({});",
        sealed::RENEWAL,
        sealed::renewal_columns(false)
    ))?;
    let rows: Vec<(i64, Vec<u8>, Vec<u8>)> = {
        let mut statement =
            tx.prepare("SELECT rowid, kh_peer_device, meta FROM peer_session_renewal")?;
        let mapped = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
        mapped.collect::<Result<_, _>>()?
    };
    for (rowid, kp, meta) in rows {
        steps.step()?;
        let opened = at_rest::open_row(keys, sealed::RENEWAL, &kp, &meta)
            .ok()
            .and_then(|plain| serde_json::from_slice::<RenewalMeta>(&plain).ok())
            .and_then(|meta| state_of(&meta));
        let Some((peer, state)) = opened else {
            sealed::dropped(expected, sealed::RENEWAL, report);
            continue;
        };
        tx.execute(
            &format!(
                "INSERT INTO peer_session_renewal__new (rowid, peer_device, {CLEAR_COLUMNS})
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)"
            ),
            params![
                rowid,
                peer.as_slice(),
                ms(state.window_start_ms),
                i64::from(state.attempts_in_window),
                state.last_attempt_at_ms.map(ms),
                i64::from(state.failures),
                state.last_session_expires_at_ms.map(ms),
                state.pending_init,
                state.pending_expires_at_ms.map(ms),
                state.early_requested_at_ms.map(ms),
                state.early_reason.map(i64::from),
                state.last_early_ms.map(ms),
            ],
        )?;
        report.rows += 1;
    }
    steps.step()?;
    tx.execute_batch("DROP TABLE peer_session_renewal;")?;
    steps.step()?;
    tx.execute_batch("ALTER TABLE peer_session_renewal__new RENAME TO peer_session_renewal;")?;
    Ok(())
}
