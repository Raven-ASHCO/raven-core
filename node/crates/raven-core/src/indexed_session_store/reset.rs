//! Session-reset sidecar: retirement, re-seal ledger and per-peer reset state
//! (design `docs/design/2026-10-lost-state-recovery.md` §10).
//!
//! The tables are additive (`CREATE TABLE IF NOT EXISTS`) in schema 1, which
//! older builds keep opening, simply ignoring retirement. The sidecar
//! cascades with its session head, so an older build's prune keeps it
//! consistent. In a sealed profile's store (schema 2, privacy pack PP.13,
//! [`super::sealed`]) every device key and message id here is keyed and the
//! times are in each row's sealed `meta`, with a clear 0/1 flag where a query
//! tests a time for NULL; what one UPSERT does in schema 1 is a read, a
//! change and a write of the row in one transaction.

use std::collections::HashMap;

use super::sealed::{self, device_of, LedgerMeta, PeerStateMeta, ResetMeta, Sealer};
use super::*;

pub(super) fn create_reset_schema(conn: &Connection) -> Result<(), IndexedSessionStoreError> {
    conn.execute_batch(&sealed::create_if_missing(
        sealed::RESET,
        sealed::reset_columns(false),
    ))?;
    conn.execute_batch(sealed::reset_index(false))?;
    conn.execute_batch(&sealed::create_if_missing(
        sealed::LEDGER,
        sealed::ledger_columns(false),
    ))?;
    conn.execute_batch(&sealed::create_if_missing(
        sealed::PEER_STATE,
        sealed::peer_state_columns(false),
    ))?;
    Ok(())
}

fn ms(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn opt_ms(value: Option<i64>) -> Option<u64> {
    value.and_then(|v| u64::try_from(v).ok())
}

/// `r.retired_at_ms IS NOT NULL` in either layout, for the reset row `alias`.
pub(super) fn retired_test(layout: &Layout, alias: &str) -> String {
    match layout {
        Layout::Clear => format!("{alias}retired_at_ms IS NOT NULL"),
        Layout::Keyed(_) => format!("{alias}retired = 1"),
    }
}

pub(super) fn session_is_retired(
    conn: &Connection,
    layout: &Layout,
    session_id: &[u8; 32],
) -> Result<bool, IndexedSessionStoreError> {
    Ok(conn
        .query_row(
            &format!(
                "SELECT 1 FROM indexed_session_reset
                 WHERE session_id = ?1 AND {}",
                retired_test(layout, "")
            ),
            params![session_id.as_slice()],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .is_some())
}

/// Was `session_id` retired by a local security re-key (Phase 6b R2, step
/// P6.27) at least [`crate::session_renewal::EARLY_OLD_ACCEPT_MS`] before
/// `now_ms`? It then takes no new object from the contact. The clear
/// `retire_cause` decides first, so only such a session opens its `meta`.
pub(super) fn rekey_closed(
    conn: &Connection,
    layout: &Layout,
    session_id: &[u8; 32],
    now_ms: u64,
) -> Result<bool, IndexedSessionStoreError> {
    let cause = SessionRetireCause::LocalSecurityRekey as i64;
    let clear_retired_at: Option<Option<i64>> = conn
        .query_row(
            &format!(
                "SELECT {} FROM indexed_session_reset WHERE session_id = ?1 AND retire_cause = ?2",
                match layout {
                    Layout::Clear => "retired_at_ms",
                    Layout::Keyed(_) => "NULL",
                }
            ),
            params![session_id.as_slice(), cause],
            |row| row.get(0),
        )
        .optional()?;
    let Some(clear_retired_at) = clear_retired_at else {
        return Ok(false);
    };
    let retired_at = match layout.keyed() {
        Some(sealer) => {
            keyed_reset(conn, sealer, session_id)?.and_then(|row| row.meta.retired_at_ms)
        }
        None => clear_retired_at,
    };
    Ok(opt_ms(retired_at)
        .is_some_and(|at| now_ms >= at.saturating_add(crate::session_renewal::EARLY_OLD_ACCEPT_MS)))
}

/// Before the first `LocalSecurityRekey` (7) row: a reset table made with
/// the CHECK of causes 1-6 (every store before step P6.27) is rebuilt in
/// place in [`sealed::reset_columns`]' shape (1-7), rows and rowids kept,
/// its index made again; nothing refers to it. One IMMEDIATE transaction
/// (or the caller's) that reads the shape again; a table already wide is
/// left alone, so only that gated path ever pays for it.
fn widen_retire_causes(conn: &Connection) -> Result<(), IndexedSessionStoreError> {
    fn wide(conn: &Connection) -> rusqlite::Result<bool> {
        let sql: Option<String> = conn
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1",
                params![sealed::RESET],
                |row| row.get(0),
            )
            .optional()?;
        Ok(sql.is_none_or(|sql| sql.contains("retire_cause BETWEEN 1 AND 7")))
    }
    if wide(conn)? {
        return Ok(());
    }
    sealed::in_write_tx(conn, |conn| {
        if wide(conn)? {
            return Ok(());
        }
        let columns = crate::sqlite_rebuild::columns(conn, sealed::RESET)?;
        let keyed = columns.iter().any(|column| column == "kh_peer_device");
        let list = columns.join(", ");
        conn.execute_batch(&format!(
            "CREATE TABLE {table}__new ({shape});
             INSERT INTO {table}__new (rowid, {list}) SELECT rowid, {list} FROM {table};
             DROP TABLE {table};
             ALTER TABLE {table}__new RENAME TO {table};
             {index}",
            table = sealed::RESET,
            shape = sealed::reset_columns(keyed),
            index = sealed::reset_index(keyed),
        ))?;
        Ok(())
    })
}

/// A schema-2 reset row: its clear flags and its sealed times.
struct KeyedReset {
    initiated_local: i64,
    retire_cause: Option<i64>,
    meta: ResetMeta,
}

impl KeyedReset {
    fn new(peer: &[u8; 32]) -> Self {
        Self {
            initiated_local: 0,
            retire_cause: None,
            meta: ResetMeta {
                peer_device: hex::encode(peer),
                ..ResetMeta::default()
            },
        }
    }
}

fn keyed_reset(
    conn: &Connection,
    sealer: &Sealer,
    session_id: &[u8; 32],
) -> Result<Option<KeyedReset>, IndexedSessionStoreError> {
    let raw: Option<(i64, Option<i64>, Vec<u8>)> = conn
        .query_row(
            "SELECT initiated_local, retire_cause, meta FROM indexed_session_reset
             WHERE session_id = ?1",
            params![session_id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((initiated_local, retire_cause, meta)) = raw else {
        return Ok(None);
    };
    Ok(Some(KeyedReset {
        initiated_local,
        retire_cause,
        meta: sealer.open(sealed::RESET, session_id, &meta)?,
    }))
}

fn put_keyed_reset(
    conn: &Connection,
    sealer: &Sealer,
    session_id: &[u8; 32],
    row: &KeyedReset,
) -> Result<(), IndexedSessionStoreError> {
    let peer = device_of(&row.meta.peer_device)?;
    conn.execute(
        "INSERT INTO indexed_session_reset
           (session_id, kh_peer_device, confirmed, initiated_local, reset_round, retired,
            retire_cause, meta)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
         ON CONFLICT(session_id) DO UPDATE
           SET kh_peer_device = excluded.kh_peer_device, confirmed = excluded.confirmed,
               initiated_local = excluded.initiated_local, reset_round = excluded.reset_round,
               retired = excluded.retired, retire_cause = excluded.retire_cause,
               meta = excluded.meta",
        params![
            session_id.as_slice(),
            sealer.device(&peer).as_slice(),
            i64::from(row.meta.confirmed_at_ms.is_some()),
            row.initiated_local,
            i64::from(row.meta.reset_round_at_ms.is_some()),
            i64::from(row.meta.retired_at_ms.is_some()),
            row.retire_cause,
            sealer.seal(sealed::RESET, session_id, &row.meta),
        ],
    )?;
    Ok(())
}

/// Record when this node first saw `session_id` confirmed (first write wins).
pub(super) fn note_confirmed(
    conn: &Connection,
    layout: &Layout,
    session_id: &[u8; 32],
    peer: &[u8; 32],
    now_ms: u64,
) -> Result<(), IndexedSessionStoreError> {
    if let Some(sealer) = layout.keyed() {
        return sealed::in_write_tx(conn, |conn| {
            let mut row =
                keyed_reset(conn, sealer, session_id)?.unwrap_or_else(|| KeyedReset::new(peer));
            if row.meta.confirmed_at_ms.is_none() {
                row.meta.confirmed_at_ms = Some(ms(now_ms));
                put_keyed_reset(conn, sealer, session_id, &row)?;
            }
            Ok(())
        });
    }
    conn.execute(
        "INSERT INTO indexed_session_reset (session_id, peer_device, confirmed_at_ms)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(session_id) DO UPDATE
           SET confirmed_at_ms = COALESCE(confirmed_at_ms, excluded.confirmed_at_ms)",
        params![session_id.as_slice(), peer.as_slice(), ms(now_ms)],
    )?;
    Ok(())
}

/// When a re-seal ledger row goes: a day after its message's expiry.
pub(super) fn ledger_expiry(expires_at_ms: i64) -> i64 {
    expires_at_ms.saturating_add(86_400_000)
}

/// The ledger outlives the original session (a message lives at most a day);
/// one more day of slack keeps the per-message cap honest across reinstalls.
pub(super) fn prune_reseal_ledger(
    conn: &Connection,
    layout: &Layout,
    now_ms: u64,
) -> Result<(), IndexedSessionStoreError> {
    let Some(sealer) = layout.keyed() else {
        conn.execute(
            "DELETE FROM endpoint_reseal_ledger WHERE expires_at_ms + 86400000 <= ?1",
            params![ms(now_ms)],
        )?;
        return Ok(());
    };
    // The hours that may have gone, then each row's exact expiry (PP.13).
    let now = ms(now_ms);
    type Row = (Vec<u8>, Vec<u8>, i64, Vec<u8>);
    let rows: Vec<Row> = {
        let mut statement = conn.prepare(
            "SELECT kh_recipient_device, kh_message_id, prune_after_hour, meta
             FROM endpoint_reseal_ledger WHERE prune_after_hour <= ?1",
        )?;
        let mapped = statement.query_map(params![sealed::may_have_expired(now)], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?;
        mapped.collect::<Result<_, _>>()?
    };
    for (kr, km, hour, meta) in rows {
        let gone = match sealer.open::<LedgerMeta>(sealed::LEDGER, &[&kr[..], &km].concat(), &meta)
        {
            Ok(meta) => ledger_expiry(meta.expires_at_ms) <= now,
            Err(error @ IndexedSessionStoreError::MetaKeyUnavailable(_)) => return Err(error),
            Err(_) => sealed::surely_expired(hour, now),
        };
        if gone {
            conn.execute(
                "DELETE FROM endpoint_reseal_ledger
                 WHERE kh_recipient_device = ?1 AND kh_message_id = ?2",
                params![kr, km],
            )?;
        }
    }
    Ok(())
}

/// Why a session was retired for sending. 1-2 are phase 2a, 3-6 phase 2b.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SessionRetireCause {
    PeerNoSession = 1,
    PeerCertRenewed = 2,
    PeerSaysOurSendStale = 3,
    PeerReceiveStale = 4,
    LocalSawPeerSendStale = 5,
    LocalReceiveStale = 6,
    /// Phase 6b R2 (step P6.27): this node renewed the session early after
    /// a security event and retired the older one; it takes the contact's
    /// objects for [`crate::session_renewal::EARLY_OLD_ACCEPT_MS`] more.
    LocalSecurityRekey = 7,
    /// A cause this build does not know (a newer build's): a plain
    /// retirement. Read only, never written (the column's CHECK refuses 0).
    Other = 0,
}

impl SessionRetireCause {
    /// The cause stored as `value`; one this build does not know reads as
    /// [`Self::Other`] (a retired session stays retired, whatever a newer
    /// build called it).
    pub fn from_i64(value: i64) -> Self {
        match value {
            1 => Self::PeerNoSession,
            2 => Self::PeerCertRenewed,
            3 => Self::PeerSaysOurSendStale,
            4 => Self::PeerReceiveStale,
            5 => Self::LocalSawPeerSendStale,
            6 => Self::LocalReceiveStale,
            7 => Self::LocalSecurityRekey,
            _ => Self::Other,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionResetInfo {
    pub peer_device: [u8; 32],
    pub confirmed_at_ms: Option<u64>,
    /// We initiated this session over a local-network route (re-seal target).
    pub initiated_local: bool,
    pub reset_round_at_ms: Option<u64>,
    pub retired_at_ms: Option<u64>,
    pub retire_cause: Option<SessionRetireCause>,
}

impl SessionResetInfo {
    pub fn retired(&self) -> bool {
        self.retired_at_ms.is_some()
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PeerResetState {
    pub fork_evidence_at_ms: Option<u64>,
    pub user_confirmed_at_ms: Option<u64>,
}

/// One copy of a logical message to a recipient, in one session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageCopy {
    pub session_id: [u8; 32],
    pub object_digest: Option<[u8; 32]>,
    pub delivery_state: Option<EndpointDeliveryState>,
    pub has_outbox_row: bool,
    pub retired: bool,
}

type HeadSummary = ([u8; 32], [u8; 32], [u8; 32], u64, u64);

impl IndexedSessionStore {
    /// `(session_id, initiator_device, responder_device, created_at_ms,
    /// expires_at_ms)` from public metadata only (a schema-2 head's meta is
    /// opened with K_meta, no protected session state).
    pub(super) fn head_summary(
        &self,
        key: &IndexedSessionRecordKey,
    ) -> Result<HeadSummary, IndexedSessionStoreError> {
        let record_key = record_key_digest(key)?;
        let raw = self
            .conn
            .query_row(
                &format!(
                    "SELECT session_id, {} FROM indexed_session_heads WHERE record_key = ?1",
                    sealed::head_columns(&self.layout, "")
                ),
                params![record_key.as_slice()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        sealed::raw_head(&self.layout, row, 1)?,
                    ))
                },
            )
            .optional()?;
        let (sid, raw) = raw.ok_or(IndexedSessionStoreError::NotFound)?;
        let head = self.layout.head(raw)?;
        Ok((
            exact_array(&sid)?,
            head.key.initiator_device_ed25519,
            head.key.responder_device_ed25519,
            u64::try_from(head.created_at_ms).unwrap_or(0),
            u64::try_from(head.expires_at_ms).unwrap_or(0),
        ))
    }

    fn session_id_with_peer(
        &self,
        key: &IndexedSessionRecordKey,
        peer: &[u8; 32],
    ) -> Result<[u8; 32], IndexedSessionStoreError> {
        let (sid, idev, rdev, _, _) = self.head_summary(key)?;
        if idev != *peer && rdev != *peer {
            return Err(IndexedSessionStoreError::DeviceBindingMismatch);
        }
        Ok(sid)
    }

    /// Head `created_at_ms` for a session id (public metadata).
    pub fn session_created_at_ms(
        &self,
        session_id: &[u8; 32],
    ) -> Result<Option<u64>, IndexedSessionStoreError> {
        let raw = self
            .conn
            .query_row(
                &format!(
                    "SELECT {} FROM indexed_session_heads WHERE session_id = ?1",
                    sealed::head_columns(&self.layout, "")
                ),
                params![session_id.as_slice()],
                |row| sealed::raw_head(&self.layout, row, 0),
            )
            .optional()?;
        let Some(raw) = raw else {
            return Ok(None);
        };
        // Schema 1 reads the column alone: a malformed identity there never
        // hid the time.
        let created = match (&self.layout, raw) {
            (Layout::Clear, sealed::RawHead::Clear { created_at_ms, .. }) => created_at_ms,
            (_, raw) => self.layout.head(raw)?.created_at_ms,
        };
        Ok(Some(u64::try_from(created).unwrap_or(0)))
    }

    /// Retire `key` for sending Messages (the contact lost it). Idempotent;
    /// `Ok(true)` only when this call retired it.
    pub fn retire_session(
        &mut self,
        key: &IndexedSessionRecordKey,
        peer: &[u8; 32],
        cause: SessionRetireCause,
        now_ms: u64,
    ) -> Result<bool, IndexedSessionStoreError> {
        let sid = self.session_id_with_peer(key, peer)?;
        if cause == SessionRetireCause::LocalSecurityRekey {
            widen_retire_causes(&self.conn)?;
        }
        if let Some(sealer) = self.layout.keyed() {
            return sealed::in_write_tx(&self.conn, |conn| {
                let mut row =
                    keyed_reset(conn, sealer, &sid)?.unwrap_or_else(|| KeyedReset::new(peer));
                if row.meta.retired_at_ms.is_some() {
                    return Ok(false);
                }
                row.meta.retired_at_ms = Some(ms(now_ms));
                row.retire_cause = Some(cause as i64);
                put_keyed_reset(conn, sealer, &sid, &row)?;
                Ok(true)
            });
        }
        let changed = self.conn.execute(
            "INSERT INTO indexed_session_reset
               (session_id, peer_device, retired_at_ms, retire_cause)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(session_id) DO UPDATE
               SET retired_at_ms = excluded.retired_at_ms,
                   retire_cause = excluded.retire_cause
               WHERE retired_at_ms IS NULL",
            params![sid.as_slice(), peer.as_slice(), ms(now_ms), cause as u8],
        )?;
        Ok(changed > 0)
    }

    pub fn session_reset_info(
        &self,
        session_id: &[u8; 32],
    ) -> Result<Option<SessionResetInfo>, IndexedSessionStoreError> {
        if let Some(sealer) = self.layout.keyed() {
            let Some(row) = keyed_reset(&self.conn, sealer, session_id)? else {
                return Ok(None);
            };
            return Ok(Some(SessionResetInfo {
                peer_device: device_of(&row.meta.peer_device)?,
                confirmed_at_ms: opt_ms(row.meta.confirmed_at_ms),
                initiated_local: row.initiated_local == 1,
                reset_round_at_ms: opt_ms(row.meta.reset_round_at_ms),
                retired_at_ms: opt_ms(row.meta.retired_at_ms),
                retire_cause: row.retire_cause.map(SessionRetireCause::from_i64),
            }));
        }
        type Row = (
            Vec<u8>,
            Option<i64>,
            i64,
            Option<i64>,
            Option<i64>,
            Option<i64>,
        );
        let raw: Option<Row> = self
            .conn
            .query_row(
                "SELECT peer_device, confirmed_at_ms, initiated_local, reset_round_at_ms,
                        retired_at_ms, retire_cause
                 FROM indexed_session_reset WHERE session_id = ?1",
                params![session_id.as_slice()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()?;
        let Some((peer, confirmed, local, round, retired, cause)) = raw else {
            return Ok(None);
        };
        Ok(Some(SessionResetInfo {
            peer_device: exact_array(&peer)?,
            confirmed_at_ms: opt_ms(confirmed),
            initiated_local: local == 1,
            reset_round_at_ms: opt_ms(round),
            retired_at_ms: opt_ms(retired),
            retire_cause: cause.map(SessionRetireCause::from_i64),
        }))
    }

    pub fn session_is_retired(
        &self,
        session_id: &[u8; 32],
    ) -> Result<bool, IndexedSessionStoreError> {
        session_is_retired(&self.conn, &self.layout, session_id)
    }

    /// We initiated `key` (PairInit sent by this node). `local_route`: over a
    /// local-network route, which makes it an automatic re-seal target.
    /// `reset_round`: started by a reset round (counted by the round cap and
    /// the cooldown even when the round fails later).
    pub fn mark_session_initiated(
        &mut self,
        key: &IndexedSessionRecordKey,
        peer: &[u8; 32],
        local_route: bool,
        reset_round: bool,
        now_ms: u64,
    ) -> Result<(), IndexedSessionStoreError> {
        let sid = self.session_id_with_peer(key, peer)?;
        let round = reset_round.then_some(ms(now_ms));
        if let Some(sealer) = self.layout.keyed() {
            return sealed::in_write_tx(&self.conn, |conn| {
                let mut row =
                    keyed_reset(conn, sealer, &sid)?.unwrap_or_else(|| KeyedReset::new(peer));
                row.initiated_local = row.initiated_local.max(i64::from(local_route));
                row.meta.reset_round_at_ms = row.meta.reset_round_at_ms.or(round);
                put_keyed_reset(conn, sealer, &sid, &row)
            });
        }
        self.conn.execute(
            "INSERT INTO indexed_session_reset
               (session_id, peer_device, initiated_local, reset_round_at_ms)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(session_id) DO UPDATE
               SET initiated_local = MAX(initiated_local, excluded.initiated_local),
                   reset_round_at_ms = COALESCE(reset_round_at_ms, excluded.reset_round_at_ms)",
            params![
                sid.as_slice(),
                peer.as_slice(),
                i64::from(local_route),
                round
            ],
        )?;
        Ok(())
    }

    /// Reset rounds with `peer` started at or after `since_ms`.
    pub fn reset_rounds_since(
        &self,
        peer: &[u8; 32],
        since_ms: u64,
    ) -> Result<usize, IndexedSessionStoreError> {
        if self.layout.is_keyed() {
            let since = ms(since_ms);
            return Ok(self
                .keyed_reset_rounds(peer)?
                .into_iter()
                .filter(|at| *at >= since)
                .count());
        }
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM indexed_session_reset
             WHERE peer_device = ?1 AND reset_round_at_ms IS NOT NULL
               AND reset_round_at_ms >= ?2",
            params![peer.as_slice(), ms(since_ms)],
            |row| row.get(0),
        )?;
        Ok(usize::try_from(n).unwrap_or(0))
    }

    /// Most recent reset round with `peer` (cooldown).
    pub fn last_reset_round_at(
        &self,
        peer: &[u8; 32],
    ) -> Result<Option<u64>, IndexedSessionStoreError> {
        if self.layout.is_keyed() {
            return Ok(opt_ms(self.keyed_reset_rounds(peer)?.into_iter().max()));
        }
        let v: Option<i64> = self.conn.query_row(
            "SELECT MAX(reset_round_at_ms) FROM indexed_session_reset WHERE peer_device = ?1",
            params![peer.as_slice()],
            |row| row.get(0),
        )?;
        Ok(opt_ms(v))
    }

    /// When each reset round with `peer` started (schema 2: the rows' metas).
    fn keyed_reset_rounds(&self, peer: &[u8; 32]) -> Result<Vec<i64>, IndexedSessionStoreError> {
        let Some(sealer) = self.layout.keyed() else {
            return Ok(Vec::new());
        };
        let rows: Vec<(Vec<u8>, Vec<u8>)> = {
            let mut statement = self.conn.prepare(
                "SELECT session_id, meta FROM indexed_session_reset
                 WHERE kh_peer_device = ?1 AND reset_round = 1",
            )?;
            let mapped = statement.query_map(params![sealer.device(peer).as_slice()], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })?;
            mapped.collect::<Result<_, _>>()?
        };
        let mut rounds = Vec::with_capacity(rows.len());
        for (sid, meta) in rows {
            let meta: ResetMeta = sealer.open(sealed::RESET, &sid, &meta)?;
            rounds.extend(meta.reset_round_at_ms);
        }
        Ok(rounds)
    }

    /// A schema-2 peer-state row's values (a default one when there is none).
    fn keyed_peer_state(
        &self,
        sealer: &Sealer,
        peer: &[u8; 32],
    ) -> Result<PeerStateMeta, IndexedSessionStoreError> {
        let kp = sealer.device(peer);
        let meta: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT meta FROM peer_reset_state WHERE kh_peer_device = ?1",
                params![kp.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        match meta {
            Some(meta) => sealer.open(sealed::PEER_STATE, &kp, &meta),
            None => Ok(PeerStateMeta {
                peer_device: hex::encode(peer),
                ..PeerStateMeta::default()
            }),
        }
    }

    /// Change `peer`'s schema-2 peer-state row (read, change, write in one
    /// transaction).
    fn update_keyed_peer_state(
        &mut self,
        sealer: &Sealer,
        peer: &[u8; 32],
        change: impl FnOnce(&mut PeerStateMeta),
    ) -> Result<(), IndexedSessionStoreError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let _in_tx = crate::paths::HeldMark::transaction();
        let kp = sealer.device(peer);
        let meta: Option<Vec<u8>> = tx
            .query_row(
                "SELECT meta FROM peer_reset_state WHERE kh_peer_device = ?1",
                params![kp.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        let mut state = match meta {
            Some(meta) => sealer.open(sealed::PEER_STATE, &kp, &meta)?,
            None => PeerStateMeta {
                peer_device: hex::encode(peer),
                ..PeerStateMeta::default()
            },
        };
        change(&mut state);
        tx.execute(
            "INSERT INTO peer_reset_state (kh_peer_device, meta) VALUES (?1, ?2)
             ON CONFLICT(kh_peer_device) DO UPDATE SET meta = excluded.meta",
            params![kp.as_slice(), sealer.seal(sealed::PEER_STATE, &kp, &state)],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// FE1: traffic made at `made_at_ms` (its envelope's `created_at`)
    /// accepted on a session we retired because the contact said it had no
    /// session. When we initiated it (the contact confirmed before it
    /// replied), the grace has passed and the object was made after the
    /// retirement ([`crate::session_reset::RESET_FORK_MADE_AFTER_MS`]: one
    /// made before and delivered late proves nothing), someone else still
    /// holds the contact's state: record fork evidence. `Ok(true)` when
    /// recorded.
    pub fn note_inbound_on_retired(
        &mut self,
        session_id: &[u8; 32],
        local_is_initiator: bool,
        made_at_ms: u64,
        now_ms: u64,
    ) -> Result<bool, IndexedSessionStoreError> {
        let Some(info) = self.session_reset_info(session_id)? else {
            return Ok(false);
        };
        let (Some(retired_at), Some(SessionRetireCause::PeerNoSession)) =
            (info.retired_at_ms, info.retire_cause)
        else {
            return Ok(false);
        };
        if !local_is_initiator
            || now_ms < retired_at.saturating_add(crate::session_reset::RESET_FORK_GRACE_MS)
            || made_at_ms
                < retired_at.saturating_add(crate::session_reset::RESET_FORK_MADE_AFTER_MS)
        {
            return Ok(false);
        }
        if let Some(sealer) = self.layout.sealer() {
            self.update_keyed_peer_state(&sealer, &info.peer_device, |state| {
                state.fork_evidence_at_ms = Some(ms(now_ms));
            })?;
            return Ok(true);
        }
        self.conn.execute(
            "INSERT INTO peer_reset_state (peer_device, fork_evidence_at_ms) VALUES (?1, ?2)
             ON CONFLICT(peer_device) DO UPDATE SET fork_evidence_at_ms = excluded.fork_evidence_at_ms",
            params![info.peer_device.as_slice(), ms(now_ms)],
        )?;
        Ok(true)
    }

    pub fn peer_reset_state(
        &self,
        peer: &[u8; 32],
    ) -> Result<PeerResetState, IndexedSessionStoreError> {
        if let Some(sealer) = self.layout.keyed() {
            let state = self.keyed_peer_state(sealer, peer)?;
            return Ok(PeerResetState {
                fork_evidence_at_ms: opt_ms(state.fork_evidence_at_ms),
                user_confirmed_at_ms: opt_ms(state.user_confirmed_at_ms),
            });
        }
        let raw: Option<(Option<i64>, Option<i64>)> = self
            .conn
            .query_row(
                "SELECT fork_evidence_at_ms, user_confirmed_at_ms FROM peer_reset_state
                 WHERE peer_device = ?1",
                params![peer.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        Ok(raw
            .map(|(fork, confirmed)| PeerResetState {
                fork_evidence_at_ms: opt_ms(fork),
                user_confirmed_at_ms: opt_ms(confirmed),
            })
            .unwrap_or_default())
    }

    /// `raven outbox resend`: the user confirmed the contact reset RAVEN.
    pub fn confirm_peer_reset(
        &mut self,
        peer: &[u8; 32],
        now_ms: u64,
    ) -> Result<(), IndexedSessionStoreError> {
        if let Some(sealer) = self.layout.sealer() {
            return self.update_keyed_peer_state(&sealer, peer, |state| {
                state.user_confirmed_at_ms = Some(ms(now_ms));
            });
        }
        self.conn.execute(
            "INSERT INTO peer_reset_state (peer_device, user_confirmed_at_ms) VALUES (?1, ?2)
             ON CONFLICT(peer_device) DO UPDATE SET user_confirmed_at_ms = excluded.user_confirmed_at_ms",
            params![peer.as_slice(), ms(now_ms)],
        )?;
        Ok(())
    }

    /// Confirmed, unexpired, not retired sessions with `peer` that may seal
    /// new Messages, newest first (the order of
    /// [`Self::find_confirmed_sessions_for_peer_at`]): a letter-class session
    /// ([`Self::session_is_letter_class`]: a letter session's row, P5.12, or
    /// a peer-started one longer than a LAN session; ACKs only) never is.
    pub fn find_sendable_sessions_for_peer_at(
        &mut self,
        peer: &[u8; 32],
        now_ms: u64,
    ) -> Result<Vec<IndexedSessionRecordKey>, IndexedSessionStoreError> {
        let mut out = Vec::new();
        for key in self.unretired_sessions_for_peer_at(peer, now_ms)? {
            let (sid, initiator, _, created, expires) = self.head_summary(&key)?;
            if !self.session_is_letter_class(&sid, initiator == *peer, created, expires)? {
                out.push(key);
            }
        }
        Ok(out)
    }

    /// Confirmed, unexpired, not retired sessions with `peer`, newest first,
    /// letter-class ones included (what a renewed certificate retires).
    pub fn unretired_sessions_for_peer_at(
        &mut self,
        peer: &[u8; 32],
        now_ms: u64,
    ) -> Result<Vec<IndexedSessionRecordKey>, IndexedSessionStoreError> {
        let confirmed = self.find_confirmed_sessions_for_peer_at(peer, now_ms)?;
        let mut out = Vec::with_capacity(confirmed.len());
        for key in confirmed {
            let (sid, _, _, _, _) = self.head_summary(&key)?;
            if !session_is_retired(&self.conn, &self.layout, &sid)? {
                out.push(key);
            }
        }
        Ok(out)
    }

    pub fn find_sendable_session_for_peer(
        &mut self,
        peer: &[u8; 32],
    ) -> Result<Option<IndexedSessionRecordKey>, IndexedSessionStoreError> {
        Ok(self
            .find_sendable_sessions_for_peer_at(peer, crate::clock::now_ms())?
            .into_iter()
            .next())
    }

    /// Newest sendable session newer than every retired session that still
    /// holds undelivered rows to `peer`, with enough time left, and (unless the
    /// user confirmed) one we initiated over a local-network route (§9.2).
    /// Never a letter-class one ([`Self::find_sendable_sessions_for_peer_at`]).
    pub fn reseal_target_for_peer(
        &mut self,
        peer: &[u8; 32],
        user_confirmed: bool,
        now_ms: u64,
    ) -> Result<Option<IndexedSessionRecordKey>, IndexedSessionStoreError> {
        // The head's created_at is the initiator's clock; a peer clock ahead
        // would otherwise make every session we set up look older. We retired
        // the session at our own clock, after it was created: cap with that.
        let mut newest_retired = 0u64;
        for row in self.retired_undelivered_messages_for_recipient(peer)? {
            if let Some(created) = self.session_created_at_ms(&row.session_id)? {
                let retired_at = self
                    .session_reset_info(&row.session_id)?
                    .and_then(|info| info.retired_at_ms)
                    .unwrap_or(created);
                newest_retired = newest_retired.max(created.min(retired_at));
            }
        }
        for key in self.find_sendable_sessions_for_peer_at(peer, now_ms)? {
            let (sid, _, _, created, expires) = self.head_summary(&key)?;
            if created <= newest_retired
                || expires.saturating_sub(now_ms)
                    < crate::session_reset::RESET_TARGET_MIN_REMAINING_MS
            {
                continue;
            }
            let local = self
                .session_reset_info(&sid)?
                .is_some_and(|info| info.initiated_local);
            if user_confirmed || local {
                return Ok(Some(key));
            }
        }
        Ok(None)
    }

    /// Message rows (Prepared or Queued, outstanding `Sent`) to `peer` held in
    /// retired sessions, in original send order: envelope `created_at`, then
    /// session `created_at_ms`, then ratchet index.
    pub fn retired_undelivered_messages_for_recipient(
        &self,
        peer: &[u8; 32],
    ) -> Result<Vec<EndpointOutbound>, IndexedSessionStoreError> {
        // The session's creation time: schema 1's column, or a schema-2
        // head's meta (PP.13).
        let created = match self.layout {
            Layout::Clear => "h.created_at_ms, NULL, NULL",
            Layout::Keyed(_) => "0, h.record_key, h.meta",
        };
        // The outbox columns go through the endpoint layout; the heads' and
        // the reset sidecar's are added after (their keyed names are not the
        // endpoint tables' in schema 2).
        let outbox = self.layout.ep(&format!(
            "SELECT {}
             FROM endpoint_outbox o
             WHERE o.kind = 1 AND o.state IN (0, 1) AND o.kh_recipient_device = ?1
               AND NOT EXISTS (
                 SELECT 1 FROM endpoint_outstanding_messages m
                 WHERE m.session_id = o.session_id AND m.kh_message_id = o.kh_message_id
                   AND m.kh_recipient_device = o.kh_recipient_device
                   AND m.delivery_state IN (1, 2))",
            endpoints::outbox_columns(&self.layout, "o.")
        ));
        let (columns, filter) = outbox
            .split_once("FROM endpoint_outbox o")
            .expect("the query names the outbox");
        let mut statement = self.conn.prepare(&format!(
            "{columns}, {created}
             FROM endpoint_outbox o
             JOIN indexed_session_reset r ON r.session_id = o.session_id
             JOIN indexed_session_heads h ON h.session_id = o.session_id
             {filter} AND {}",
            retired_test(&self.layout, "r.")
        ))?;
        let rows = statement.query_map(params![self.layout.ep_device(peer)], |row| {
            Ok((
                endpoints::raw(row, 0, endpoints::OUTBOX_WIDTH)?,
                row.get::<_, i64>(endpoints::OUTBOX_WIDTH)?,
                row.get::<_, Option<Vec<u8>>>(endpoints::OUTBOX_WIDTH + 1)?,
                row.get::<_, Option<Vec<u8>>>(endpoints::OUTBOX_WIDTH + 2)?,
            ))
        })?;
        let mut out = Vec::new();
        let mut created_of = HashMap::new();
        for row in rows {
            let (raw, clear_created, record_key, meta) = row?;
            let raw = endpoints::outbox_row(&self.layout, raw)?.db_row();
            let session_created = match (self.layout.keyed(), record_key, meta) {
                (Some(sealer), Some(record_key), Some(meta)) => {
                    if let Some(created) = created_of.get(&record_key) {
                        *created
                    } else {
                        let head: sealed::HeadMeta =
                            sealer.open(sealed::HEADS, &record_key, &meta)?;
                        created_of.insert(record_key, head.created_at_ms);
                        head.created_at_ms
                    }
                }
                _ => clear_created,
            };
            let decoded = decode_endpoint_outbound_row(raw)?;
            let created = Envelope::unpack(&decoded.immutable_envelope_bytes)
                .map(|e| e.created_at)
                .unwrap_or(0);
            out.push((created, session_created, decoded));
        }
        out.sort_by_key(|row| (row.0, row.1, row.2.ratchet_index));
        Ok(out.into_iter().map(|(_, _, row)| row).collect())
    }

    /// Message rows to `peer` in `session_id` not delivered yet (Prepared or
    /// Queued, outstanding `Sent`): what retiring that session would leave
    /// to the re-seal (Phase 6b R2, step P6.27).
    pub fn undelivered_messages_in_session(
        &self,
        session_id: &[u8; 32],
        peer: &[u8; 32],
    ) -> Result<usize, IndexedSessionStoreError> {
        let n: i64 = self.conn.query_row(
            &self.layout.ep("SELECT COUNT(*) FROM endpoint_outbox o
                 WHERE o.session_id = ?1 AND o.kind = 1 AND o.state IN (0, 1)
                   AND o.kh_recipient_device = ?2
                   AND NOT EXISTS (
                     SELECT 1 FROM endpoint_outstanding_messages m
                     WHERE m.session_id = o.session_id AND m.kh_message_id = o.kh_message_id
                       AND m.kh_recipient_device = o.kh_recipient_device
                       AND m.delivery_state IN (1, 2))"),
            params![session_id.as_slice(), self.layout.ep_device(peer)],
            |row| row.get(0),
        )?;
        Ok(usize::try_from(n).unwrap_or(0))
    }

    /// The outbound object `digest` to `peer` in any session, with its
    /// outstanding delivery state.
    pub fn outbound_by_digest_for_recipient(
        &self,
        digest: &[u8; 32],
        peer: &[u8; 32],
    ) -> Result<Option<(EndpointOutbound, Option<EndpointDeliveryState>)>, IndexedSessionStoreError>
    {
        let raw = endpoints::outbox_rows(
            &self.conn,
            &self.layout,
            &format!(
                "SELECT {} FROM endpoint_outbox
                 WHERE kh_object_digest = ?1 AND kh_recipient_device = ?2
                 ORDER BY rowid ASC LIMIT 1",
                endpoints::outbox_columns(&self.layout, "")
            ),
            params![self.layout.ep_digest(digest), self.layout.ep_device(peer)],
        )?
        .into_iter()
        .next();
        let Some(raw) = raw else {
            return Ok(None);
        };
        let row = decode_endpoint_outbound_row(raw.db_row())?;
        let delivery = self_delivery_state_in_connection(
            &self.conn,
            &self.layout,
            &row.session_id,
            &row.message_id,
            &row.recipient_device,
        )?;
        Ok(Some((row, delivery)))
    }

    /// Every copy of logical message `mid` to `peer`: one per session that has
    /// an outstanding row or an outbox row for it.
    pub fn message_copies_for_recipient(
        &self,
        peer: &[u8; 32],
        mid: &[u8; 16],
    ) -> Result<Vec<MessageCopy>, IndexedSessionStoreError> {
        // The outbox digest comes with its `meta` in schema 3 (NULL in a
        // clear store); the reset sidecar's test is added after the endpoint
        // SQL (its keyed names are not the endpoint tables' in schema 2).
        let copies = self.layout.ep(&format!(
            "SELECT s.session_id,
                    (SELECT o.kh_object_digest FROM endpoint_outbox o
                      WHERE o.session_id = s.session_id AND o.kh_message_id = ?2
                        AND o.kh_recipient_device = ?1 AND o.kind = 1),
                    (SELECT {} FROM endpoint_outbox o
                      WHERE o.session_id = s.session_id AND o.kh_message_id = ?2
                        AND o.kh_recipient_device = ?1 AND o.kind = 1),
                    (SELECT m.delivery_state FROM endpoint_outstanding_messages m
                      WHERE m.session_id = s.session_id AND m.kh_message_id = ?2
                        AND m.kh_recipient_device = ?1),
                    EXISTS (SELECT 1 FROM indexed_session_reset r
                      WHERE r.session_id = s.session_id AND RETIRED_TEST)
             FROM (SELECT session_id FROM endpoint_outbox
                    WHERE kh_recipient_device = ?1 AND kh_message_id = ?2 AND kind = 1
                   UNION
                   SELECT session_id FROM endpoint_outstanding_messages
                    WHERE kh_recipient_device = ?1 AND kh_message_id = ?2) s",
            if self.layout.endpoints().is_some() {
                "o.meta"
            } else {
                "NULL"
            }
        ));
        let mut statement = self
            .conn
            .prepare(&copies.replace("RETIRED_TEST", &retired_test(&self.layout, "r.")))?;
        let rows = statement.query_map(
            params![self.layout.ep_device(peer), self.layout.ep_mid(mid)],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Option<Vec<u8>>>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, bool>(4)?,
                ))
            },
        )?;
        let mut out = Vec::new();
        for row in rows {
            let (sid, stored_digest, meta, delivery, retired) = row?;
            let digest = match (self.layout.endpoints(), stored_digest, meta) {
                (Some(sealer), Some(stored), Some(meta)) => {
                    let mut key = sid.clone();
                    key.extend_from_slice(&stored);
                    let meta: endpoints::OutboxMeta =
                        sealer.open(endpoints::OUTBOX, &key, &meta)?;
                    Some(
                        hex::decode(&meta.object_digest)
                            .map_err(|_| IndexedSessionStoreError::CorruptEndpointState)?,
                    )
                }
                (_, digest, _) => digest,
            };
            out.push(MessageCopy {
                session_id: exact_array(&sid)?,
                has_outbox_row: digest.is_some(),
                object_digest: digest.map(|d| exact_array(&d)).transpose()?,
                delivery_state: delivery
                    .map(|v| {
                        u8::try_from(v)
                            .map_err(|_| IndexedSessionStoreError::CorruptEndpointState)
                            .and_then(EndpointDeliveryState::from_u8)
                    })
                    .transpose()?,
                retired,
            });
        }
        Ok(out)
    }

    /// A copy of `mid` to `peer` lives in a non-retired session other than
    /// `except_session` (it was re-sealed there).
    pub fn live_copy_elsewhere(
        &self,
        peer: &[u8; 32],
        mid: &[u8; 16],
        except_session: &[u8; 32],
    ) -> Result<bool, IndexedSessionStoreError> {
        Ok(self
            .message_copies_for_recipient(peer, mid)?
            .iter()
            .any(|copy| copy.session_id != *except_session && !copy.retired))
    }

    /// Inbox copies of `mid` from `sender` across sessions (receiver collapse).
    pub fn inbox_copies(
        &self,
        sender: &[u8; 32],
        mid: &[u8; 16],
    ) -> Result<usize, IndexedSessionStoreError> {
        endpoints::inbox_copies(&self.conn, &self.layout, sender, mid)
    }

    /// Seal `text` again under `key` with the logical id of the copy in a
    /// retired session. Everything else is a normal seal (new nonces, new
    /// index, new digest).
    #[allow(clippy::too_many_arguments)]
    pub fn reseal_message_envelope<R, F>(
        &mut self,
        key: &IndexedSessionRecordKey,
        text: &str,
        message_id: &[u8; 16],
        local_device: &AuthorizedEndpointDevice<'_>,
        created_at_ms: u64,
        expires_at_ms: u64,
        now_ms: u64,
        rng: &mut R,
        enqueue_idempotently: &mut F,
    ) -> Result<EndpointOutbound, IndexedSessionStoreError>
    where
        R: RngCore + CryptoRng,
        F: FnMut(&[u8; 32], &[u8]) -> Result<[u8; 32], ()>,
    {
        self.seal_message_inner(
            key,
            text,
            Some(*message_id),
            false,
            local_device,
            created_at_ms,
            expires_at_ms,
            now_ms,
            rng,
            enqueue_idempotently,
        )
    }

    /// Drop the outbox row of an undelivered Message copy in `key`'s session.
    /// The outstanding row stays, so a late ACK under that session still
    /// settles the message.
    pub fn retire_outbound_copy(
        &mut self,
        key: &IndexedSessionRecordKey,
        object_digest: &[u8; 32],
    ) -> Result<bool, IndexedSessionStoreError> {
        let (sid, _, _, _, _) = self.head_summary(key)?;
        let changed = self.conn.execute(
            &self.layout.ep("DELETE FROM endpoint_outbox
                 WHERE session_id = ?1 AND kh_object_digest = ?2 AND kind = 1
                   AND state IN (0, 1)"),
            params![sid.as_slice(), self.layout.ep_digest(object_digest)],
        )?;
        Ok(changed > 0)
    }

    /// Count one more re-seal of `mid` to `peer`, in its own transaction before
    /// the seal (a crash can only over-count). Returns the new count. The row
    /// lives a day past the latest `orig_expires_ms` it was given (the horizon
    /// step passes the message's deadline, so the count outlives parking).
    pub fn bump_reseal_ledger(
        &mut self,
        peer: &[u8; 32],
        mid: &[u8; 16],
        orig_expires_ms: u64,
        now_ms: u64,
    ) -> Result<u8, IndexedSessionStoreError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let _in_tx = crate::paths::HeldMark::transaction();
        if let Some(sealer) = self.layout.keyed() {
            // Schema 2 (PP.13): the row's count and flag are clear, its
            // times in the meta.
            let (kr, km) = (sealer.device(peer), sealer.message_id(mid));
            let pk = [kr, km].concat();
            let existing: Option<(i64, Vec<u8>)> = tx
                .query_row(
                    "SELECT reseals, meta FROM endpoint_reseal_ledger
                     WHERE kh_recipient_device = ?1 AND kh_message_id = ?2",
                    params![kr.as_slice(), km.as_slice()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            let (reseals, meta) = match existing {
                Some((reseals, meta)) => {
                    let mut meta: LedgerMeta = sealer.open(sealed::LEDGER, &pk, &meta)?;
                    meta.last_reseal_at_ms = ms(now_ms);
                    meta.expires_at_ms = meta.expires_at_ms.max(ms(orig_expires_ms));
                    ((reseals + 1).min(255), meta)
                }
                None => (
                    1,
                    LedgerMeta {
                        recipient_device: hex::encode(peer),
                        message_id: hex::encode(mid),
                        last_reseal_at_ms: ms(now_ms),
                        expires_at_ms: ms(orig_expires_ms),
                    },
                ),
            };
            tx.execute(
                "INSERT INTO endpoint_reseal_ledger
                   (kh_recipient_device, kh_message_id, reseals, notified, prune_after_hour, meta)
                 VALUES (?1, ?2, ?3, 0, ?4, ?5)
                 ON CONFLICT(kh_recipient_device, kh_message_id) DO UPDATE
                   SET reseals = excluded.reseals, notified = 0,
                       prune_after_hour = excluded.prune_after_hour, meta = excluded.meta",
                params![
                    kr.as_slice(),
                    km.as_slice(),
                    reseals,
                    sealed::prune_hour(ledger_expiry(meta.expires_at_ms)),
                    sealer.seal(sealed::LEDGER, &pk, &meta),
                ],
            )?;
            tx.commit()?;
            return Ok(u8::try_from(reseals).unwrap_or(u8::MAX));
        }
        tx.execute(
            "INSERT INTO endpoint_reseal_ledger
               (recipient_device, message_id, reseals, last_reseal_at_ms, expires_at_ms)
             VALUES (?1, ?2, 1, ?3, ?4)
             ON CONFLICT(recipient_device, message_id) DO UPDATE
               SET reseals = MIN(reseals + 1, 255),
                   last_reseal_at_ms = excluded.last_reseal_at_ms,
                   expires_at_ms = MAX(expires_at_ms, excluded.expires_at_ms),
                   notified = 0",
            params![
                peer.as_slice(),
                mid.as_slice(),
                ms(now_ms),
                ms(orig_expires_ms)
            ],
        )?;
        let n: i64 = tx.query_row(
            "SELECT reseals FROM endpoint_reseal_ledger
             WHERE recipient_device = ?1 AND message_id = ?2",
            params![peer.as_slice(), mid.as_slice()],
            |row| row.get(0),
        )?;
        tx.commit()?;
        Ok(u8::try_from(n).unwrap_or(u8::MAX))
    }

    pub fn reseal_count(
        &self,
        peer: &[u8; 32],
        mid: &[u8; 16],
    ) -> Result<u8, IndexedSessionStoreError> {
        let (columns, peer_value, mid_value) = match self.layout.keyed() {
            None => (
                "recipient_device = ?1 AND message_id = ?2",
                peer.to_vec(),
                mid.to_vec(),
            ),
            Some(sealer) => (
                "kh_recipient_device = ?1 AND kh_message_id = ?2",
                sealer.device(peer).to_vec(),
                sealer.message_id(mid).to_vec(),
            ),
        };
        let n: Option<i64> = self
            .conn
            .query_row(
                &format!("SELECT reseals FROM endpoint_reseal_ledger WHERE {columns}"),
                params![peer_value, mid_value],
                |row| row.get(0),
            )
            .optional()?;
        Ok(n.map_or(0, |n| u8::try_from(n).unwrap_or(u8::MAX)))
    }

    /// Message ids to `peer` in the ledger (crash reconciliation).
    pub fn resealed_message_ids(
        &self,
        peer: &[u8; 32],
    ) -> Result<Vec<[u8; 16]>, IndexedSessionStoreError> {
        if let Some(sealer) = self.layout.keyed() {
            // The order of the re-seals, from each row's meta (a stable sort
            // over the rows' order).
            let mut ids = Vec::new();
            for (_, meta) in self.keyed_ledger_rows(sealer, peer, false)? {
                ids.push((
                    meta.last_reseal_at_ms,
                    exact_array::<16>(
                        &hex::decode(&meta.message_id)
                            .map_err(|_| IndexedSessionStoreError::CorruptEndpointState)?,
                    )?,
                ));
            }
            ids.sort_by_key(|(at, _)| *at);
            return Ok(ids.into_iter().map(|(_, id)| id).collect());
        }
        let mut statement = self.conn.prepare(
            "SELECT message_id FROM endpoint_reseal_ledger WHERE recipient_device = ?1
             ORDER BY last_reseal_at_ms ASC",
        )?;
        let rows = statement.query_map(params![peer.as_slice()], |row| row.get::<_, Vec<u8>>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(exact_array(&row?)?);
        }
        Ok(out)
    }

    /// Re-seals of messages to `peer` not reported yet: `(count, newest
    /// re-seal instant)`; marks them reported.
    pub fn take_unnotified_reseals(
        &mut self,
        peer: &[u8; 32],
    ) -> Result<(usize, u64), IndexedSessionStoreError> {
        if let Some(sealer) = self.layout.sealer() {
            let tx = self
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let _in_tx = crate::paths::HeldMark::transaction();
            let rows = keyed_ledger_rows(&tx, &sealer, peer, true)?;
            let last = rows.iter().map(|(_, meta)| meta.last_reseal_at_ms).max();
            tx.execute(
                "UPDATE endpoint_reseal_ledger SET notified = 1
                 WHERE kh_recipient_device = ?1 AND notified = 0",
                params![sealer.device(peer).as_slice()],
            )?;
            tx.commit()?;
            return Ok((rows.len(), opt_ms(last).unwrap_or(0)));
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let _in_tx = crate::paths::HeldMark::transaction();
        let (n, last): (i64, Option<i64>) = tx.query_row(
            "SELECT COUNT(*), MAX(last_reseal_at_ms) FROM endpoint_reseal_ledger
             WHERE recipient_device = ?1 AND notified = 0",
            params![peer.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        tx.execute(
            "UPDATE endpoint_reseal_ledger SET notified = 1
             WHERE recipient_device = ?1 AND notified = 0",
            params![peer.as_slice()],
        )?;
        tx.commit()?;
        Ok((usize::try_from(n).unwrap_or(0), opt_ms(last).unwrap_or(0)))
    }

    /// `peer`'s schema-2 ledger rows (`unnotified`: only those not reported
    /// yet), in the rows' order, their metas opened.
    fn keyed_ledger_rows(
        &self,
        sealer: &Sealer,
        peer: &[u8; 32],
        unnotified: bool,
    ) -> Result<Vec<(Vec<u8>, LedgerMeta)>, IndexedSessionStoreError> {
        keyed_ledger_rows(&self.conn, sealer, peer, unnotified)
    }

    /// Read-only: the confirmed session with `peer` whose inbound route tag
    /// matches the packed RVN1 Message or Ack `packed`, newest first, exactly
    /// as the accept paths select it. No receive state moves. A session an
    /// early security re-key closed ([`rekey_closed`]: it takes no new
    /// object from the contact any more) matches nothing, so a SESSION_QUERY
    /// about an object sealed in it is answered NO_SESSION and the contact
    /// re-seals what waits there (Phase 6 review sensing-1).
    pub fn match_inbound_session(
        &mut self,
        peer: &[u8; 32],
        packed: &[u8],
        now_ms: u64,
    ) -> Result<Option<IndexedSessionRecordKey>, IndexedSessionStoreError> {
        Ok(
            match self.match_inbound_session_detail(peer, packed, now_ms)? {
                InboundSessionMatch::Matched(key) => Some(key),
                InboundSessionMatch::ClosedByRekey | InboundSessionMatch::NoMatch => None,
            },
        )
    }

    /// [`Self::match_inbound_session`], telling apart a session this node
    /// closed itself after an early security re-key
    /// ([`InboundSessionMatch::ClosedByRekey`]) from none at all: the
    /// SESSION_QUERY answer is NO_SESSION for both, and only the words of
    /// the log differ (Phase 6 review re-verify, sensing-1).
    pub fn match_inbound_session_detail(
        &mut self,
        peer: &[u8; 32],
        packed: &[u8],
        now_ms: u64,
    ) -> Result<InboundSessionMatch, IndexedSessionStoreError> {
        let env =
            Envelope::unpack(packed).ok_or(IndexedSessionStoreError::InvalidEndpointEnvelope)?;
        if env.env_type != EnvType::Message as u8 && env.env_type != EnvType::Ack as u8 {
            return Err(IndexedSessionStoreError::EndpointTypeMismatch);
        }
        let index = parse_indexed_message_header(&env.message_ciphertext)
            .map_err(|_| IndexedSessionStoreError::InvalidIndexedMessage)?;
        let mut closed_by_rekey = false;
        for key in self.find_confirmed_sessions_for_peer_at(peer, now_ms)? {
            let record_key = record_key_digest(&key)?;
            let account = hex::encode(record_key);
            let backend = Arc::clone(&self.backend);
            let tx = self.conn.transaction()?;
            let _in_tx = crate::paths::HeldMark::transaction();
            let state = match load_and_reconcile(
                &tx,
                &self.layout,
                backend.as_ref(),
                &account,
                &record_key,
            ) {
                Ok(state) => state,
                Err(error) if is_session_scoped_state_error(&error) => continue,
                Err(error) => return Err(error),
            };
            let direction = state.binding.local_role.inbound_direction();
            let hint_ok = env.dest_device_hint == 0
                || env.dest_device_hint
                    == endpoint_device_hint(local_device_for_binding(&state.binding));
            let matched = hint_ok
                && derive_route_tag(
                    &state.ratchets.root,
                    env.created_at,
                    index,
                    env.env_type,
                    direction,
                )
                .is_ok_and(|expected| route_tag_eq(&env.routing_tag, &expected));
            let closed =
                matched && rekey_closed(&tx, &self.layout, &state.binding.session_id, now_ms)?;
            drop(state);
            tx.commit()?;
            if matched && !closed {
                return Ok(InboundSessionMatch::Matched(key));
            }
            closed_by_rekey |= closed;
        }
        Ok(if closed_by_rekey {
            InboundSessionMatch::ClosedByRekey
        } else {
            InboundSessionMatch::NoMatch
        })
    }

    /// Did `peer` itself replace a session it then said it no longer has?
    /// A session with `peer` that this node retired because `peer` answered
    /// NO_SESSION about it ([`SessionRetireCause::PeerNoSession`], not
    /// expired), while a newer sendable session that `peer` started, under
    /// the same device certificate, is here: what an early security re-key
    /// on its side leaves (Phase 6b R2/R3: it renews, then closes the older
    /// sessions), and also a restore after which it set up a new one. Not a
    /// reinstall (a new certificate), nor a contact that lost its state
    /// and set up nothing since. ash words its reset lines by it: the
    /// contact's RAVEN replaced the connection, rather than lost it (Phase
    /// 6 review re-verify, sensing-1). It is no proof of a re-key (someone
    /// holding the contact's key could do the same), so held messages
    /// still wait for the person (§9.2, P2).
    pub fn contact_replaced_retired_session(
        &mut self,
        peer: &[u8; 32],
        now_ms: u64,
    ) -> Result<bool, IndexedSessionStoreError> {
        let mut retired = Vec::new();
        for key in self.find_confirmed_sessions_for_peer_at(peer, now_ms)? {
            let (sid, _, _, created, _) = self.head_summary(&key)?;
            let cause = self
                .session_reset_info(&sid)?
                .and_then(|info| info.retire_cause);
            if cause == Some(SessionRetireCause::PeerNoSession) {
                retired.push((created, self.remote_certificate_digest(&key)?));
            }
        }
        if retired.is_empty() {
            return Ok(false);
        }
        for key in self.find_sendable_sessions_for_peer_at(peer, now_ms)? {
            if key.initiator_device_ed25519 != *peer {
                continue;
            }
            let (_, _, _, created, _) = self.head_summary(&key)?;
            let cert = self.remote_certificate_digest(&key)?;
            if retired
                .iter()
                .any(|(was_created, was_cert)| created > *was_created && cert == *was_cert)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

/// What [`IndexedSessionStore::match_inbound_session_detail`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboundSessionMatch {
    /// The session the object was sealed in.
    Matched(IndexedSessionRecordKey),
    /// It was sealed in a session this node closed itself after an early
    /// security re-key ([`rekey_closed`]).
    ClosedByRekey,
    /// In no session this node has.
    NoMatch,
}

/// `peer`'s schema-2 re-seal ledger rows: their keyed message ids and metas.
fn keyed_ledger_rows(
    conn: &Connection,
    sealer: &Sealer,
    peer: &[u8; 32],
    unnotified: bool,
) -> Result<Vec<(Vec<u8>, LedgerMeta)>, IndexedSessionStoreError> {
    let kr = sealer.device(peer);
    let rows: Vec<(Vec<u8>, Vec<u8>)> = {
        let mut statement = conn.prepare(&format!(
            "SELECT kh_message_id, meta FROM endpoint_reseal_ledger
             WHERE kh_recipient_device = ?1{}
             ORDER BY rowid ASC",
            if unnotified { " AND notified = 0" } else { "" }
        ))?;
        let mapped =
            statement.query_map(params![kr.as_slice()], |row| Ok((row.get(0)?, row.get(1)?)))?;
        mapped.collect::<Result<_, _>>()?
    };
    let mut out = Vec::with_capacity(rows.len());
    for (km, meta) in rows {
        let meta = sealer.open(sealed::LEDGER, &[&kr[..], &km].concat(), &meta)?;
        out.push((km, meta));
    }
    Ok(out)
}
