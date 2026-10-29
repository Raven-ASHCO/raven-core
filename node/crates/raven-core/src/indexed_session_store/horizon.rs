//! How long a contact's sessions can still take new messages, and when the
//! last one ended (cutoff pack CP.6, M2), from SQLite metadata only.
//!
//! [`SessionMetadataReader`] opens the metadata file as it is: it never
//! creates it (a fresh profile's `raven contact list` must not create a
//! store), builds no protected backend (no Keychain or Secret Service) and
//! changes no schema. "Confirmed" is the session-reset sidecar's
//! `confirmed_at_ms`, which both roles stamp when a session is confirmed.
//!
//! A prune deletes an expired head with its sidecar, so it first remembers
//! the end in `peer_session_end` (one row per contact, newest end, kept
//! [`SESSION_END_KEEP_MS`]): after that "the secure connection ended" stays
//! known instead of reading as "never paired". Additive, like the reset
//! sidecar: older builds of schema 1 ignore the table.
//!
//! Removing a contact forgets its end ([`forget_session_end`], storage rule
//! "real erase"). Its heads stay until they expire, so the removal also
//! leaves `peer_session_end_erased`: the newest head it covers, which the
//! prune does not remember again (review C-time-deadlines-5). That row goes
//! with the last head it covers, so it never outlives the heads, which
//! already hold the contact's device key until then. A contact added back
//! is no longer erased: the prune first drops its mark
//! ([`IndexedSessionStore::readmit_session_ends`]), so the end of an old
//! session it goes on using is remembered again (review FU-5).
//!
//! In a sealed profile's store (schema 2, privacy pack PP.13,
//! [`super::sealed`]) both tables key the device and seal the times; the
//! reader opens the metas with the at-rest key this process loaded (no
//! keychain item) and computes in Rust what schema 1 asks SQLite for.

use super::sealed::{self, device_of, ErasedMeta, HeadMeta, ResetMeta, Sealer, SessionEndMeta};
use super::*;
use rusqlite::OpenFlags;

/// How long the end of a contact's last session is remembered (30 days, as
/// long as `lan_seen` keeps where a contact was seen).
pub const SESSION_END_KEEP_MS: u64 = 30 * 24 * 60 * 60 * 1000;

pub(super) fn create_horizon_schema(conn: &Connection) -> Result<(), IndexedSessionStoreError> {
    conn.execute_batch(&sealed::create_if_missing(
        sealed::SESSION_END,
        sealed::session_end_columns(false),
    ))?;
    conn.execute_batch(&erased_schema(&Layout::Clear))?;
    Ok(())
}

/// The removed contacts' marks (see the module docs): heads of
/// `peer_device` created at or before `created_to_ms` are not remembered.
fn erased_schema(layout: &Layout) -> String {
    sealed::create_if_missing(sealed::ERASED, sealed::erased_columns(layout.is_keyed()))
}

/// When a remembered end goes: [`SESSION_END_KEEP_MS`] after it (the prune
/// forgets an end older than that, strictly).
pub(super) fn session_end_expiry(ended_at_ms: i64) -> i64 {
    ended_at_ms
        .saturating_add(i64::try_from(SESSION_END_KEEP_MS).unwrap_or(i64::MAX))
        .saturating_add(1)
}

/// A confirmed session's head and reset row, schema 2.
struct KeyedEnd {
    head: HeadMeta,
    init_id: [u8; 16],
    reset: ResetMeta,
}

/// Every confirmed head of `peer` with its reset row (`peer`: its keyed
/// device, on both sides of the join), in a schema-2 store (the `init_id`
/// from the head's meta in schema 4).
fn keyed_confirmed_heads(
    conn: &Connection,
    sealer: &Sealer,
    peer: &[u8; 32],
) -> Result<Vec<KeyedEnd>, IndexedSessionStoreError> {
    let kp = sealer.device(peer);
    type Row = (Vec<u8>, Vec<u8>, Option<Vec<u8>>, Vec<u8>, Vec<u8>);
    let init_column = if sealer.init_keyed() {
        "NULL"
    } else {
        "h.init_id"
    };
    let rows: Vec<Row> = {
        let mut statement = conn.prepare(&format!(
            "SELECT h.session_id, h.record_key, {init_column}, h.meta, r.meta
             FROM indexed_session_heads h
             JOIN indexed_session_reset r ON r.session_id = h.session_id
             WHERE (h.kh_initiator_device = ?1 OR h.kh_responder_device = ?1)
               AND r.kh_peer_device = ?1 AND r.confirmed = 1"
        ))?;
        let mapped = statement.query_map(params![kp.as_slice()], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })?;
        mapped.collect::<Result<_, _>>()?
    };
    let mut out = Vec::with_capacity(rows.len());
    for (session_id, record_key, init_id, head, reset) in rows {
        let head: HeadMeta = sealer.open(sealed::HEADS, &record_key, &head)?;
        let init_id = match init_id {
            Some(clear) => exact_array(&clear)?,
            None => sealed::init_id_of(&head.init_id)?,
        };
        out.push(KeyedEnd {
            head,
            reset: sealer.open(sealed::RESET, &session_id, &reset)?,
            init_id,
        });
    }
    Ok(out)
}

/// The created times of every head of `peer`'s reset rows (schema 2): what a
/// removal mark covers. A head whose meta does not open counts as covered.
fn keyed_peer_head_times(
    conn: &Connection,
    sealer: &Sealer,
    kp: &[u8],
) -> Result<Vec<i64>, IndexedSessionStoreError> {
    let rows: Vec<(Vec<u8>, Vec<u8>)> = {
        let mut statement = conn.prepare(
            "SELECT h.record_key, h.meta FROM indexed_session_heads h
             JOIN indexed_session_reset r ON r.session_id = h.session_id
             WHERE r.kh_peer_device = ?1",
        )?;
        let mapped = statement.query_map(params![kp], |row| Ok((row.get(0)?, row.get(1)?)))?;
        mapped.collect::<Result<_, _>>()?
    };
    let mut times = Vec::with_capacity(rows.len());
    for (record_key, meta) in rows {
        match sealer.open::<HeadMeta>(sealed::HEADS, &record_key, &meta) {
            Ok(head) => times.push(head.created_at_ms),
            Err(error @ IndexedSessionStoreError::MetaKeyUnavailable(_)) => return Err(error),
            Err(_) => times.push(i64::MIN),
        }
    }
    Ok(times)
}

/// A schema-2 removal mark of `kp` (`None`: none).
fn keyed_mark(
    conn: &Connection,
    sealer: &Sealer,
    kp: &[u8],
) -> Result<Option<ErasedMeta>, IndexedSessionStoreError> {
    let meta: Option<Vec<u8>> = conn
        .query_row(
            "SELECT meta FROM peer_session_end_erased WHERE kh_peer_device = ?1",
            params![kp],
            |row| row.get(0),
        )
        .optional()?;
    meta.map(|meta| sealer.open(sealed::ERASED, kp, &meta))
        .transpose()
}

/// A schema-2 remembered end of `kp` (`None`: none).
fn keyed_end(
    conn: &Connection,
    sealer: &Sealer,
    kp: &[u8],
) -> Result<Option<SessionEndMeta>, IndexedSessionStoreError> {
    let meta: Option<Vec<u8>> = conn
        .query_row(
            "SELECT meta FROM peer_session_end WHERE kh_peer_device = ?1",
            params![kp],
            |row| row.get(0),
        )
        .optional()?;
    meta.map(|meta| sealer.open(sealed::SESSION_END, kp, &meta))
        .transpose()
}

/// Before a prune deletes `session_id`'s head: remember when it ended (its
/// expiry, or its retirement when that came first), if it was confirmed and
/// its contact was not removed since it was created.
pub(super) fn note_session_end(
    tx: &Transaction<'_>,
    layout: &Layout,
    session_id: &[u8],
) -> Result<(), IndexedSessionStoreError> {
    let Some(sealer) = layout.keyed() else {
        tx.execute(
            "INSERT INTO peer_session_end (peer_device, ended_at_ms)
             SELECT r.peer_device,
                    MIN(h.expires_at_ms, COALESCE(r.retired_at_ms, h.expires_at_ms))
             FROM indexed_session_heads h
             JOIN indexed_session_reset r ON r.session_id = h.session_id
             WHERE h.session_id = ?1 AND r.confirmed_at_ms IS NOT NULL
               AND NOT EXISTS (
                 SELECT 1 FROM peer_session_end_erased e
                 WHERE e.peer_device = r.peer_device AND h.created_at_ms <= e.created_to_ms)
             ON CONFLICT(peer_device) DO UPDATE
               SET ended_at_ms = MAX(ended_at_ms, excluded.ended_at_ms)",
            params![session_id],
        )?;
        return Ok(());
    };
    // Schema 2: the confirmed head and its reset row, by the session (PP.13).
    let row: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = tx
        .query_row(
            "SELECT h.record_key, h.meta, r.meta FROM indexed_session_heads h
             JOIN indexed_session_reset r ON r.session_id = h.session_id
             WHERE h.session_id = ?1 AND r.confirmed = 1",
            params![session_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((record_key, head, reset)) = row else {
        return Ok(());
    };
    // A meta that does not open leaves the end unknown (the prune goes on).
    let opened = sealer
        .open::<HeadMeta>(sealed::HEADS, &record_key, &head)
        .and_then(|head| {
            let reset: ResetMeta = sealer.open(sealed::RESET, session_id, &reset)?;
            Ok((head, device_of(&reset.peer_device)?, reset))
        });
    let (head, peer, reset) = match opened {
        Ok(opened) => opened,
        Err(error @ IndexedSessionStoreError::MetaKeyUnavailable(_)) => return Err(error),
        Err(_) => return Ok(()),
    };
    let kp = sealer.device(&peer);
    if keyed_mark(tx, sealer, &kp)?.is_some_and(|mark| head.created_at_ms <= mark.created_to_ms) {
        return Ok(());
    }
    let ended = head
        .expires_at_ms
        .min(reset.retired_at_ms.unwrap_or(head.expires_at_ms));
    let ended = keyed_end(tx, sealer, &kp)?.map_or(ended, |end| end.ended_at_ms.max(ended));
    put_keyed_end(tx, sealer, &peer, ended)
}

fn put_keyed_end(
    conn: &Connection,
    sealer: &Sealer,
    peer: &[u8; 32],
    ended_at_ms: i64,
) -> Result<(), IndexedSessionStoreError> {
    let kp = sealer.device(peer);
    let meta = SessionEndMeta {
        peer_device: hex::encode(peer),
        ended_at_ms,
    };
    conn.execute(
        "INSERT INTO peer_session_end (kh_peer_device, prune_after_hour, meta)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(kh_peer_device) DO UPDATE
           SET prune_after_hour = excluded.prune_after_hour, meta = excluded.meta",
        params![
            kp.as_slice(),
            sealed::prune_hour(session_end_expiry(ended_at_ms)),
            sealer.seal(sealed::SESSION_END, &kp, &meta),
        ],
    )?;
    Ok(())
}

/// Forget remembered ends older than [`SESSION_END_KEEP_MS`], and removal
/// marks whose heads are all gone.
pub(super) fn prune_session_ends(
    conn: &Connection,
    layout: &Layout,
    now_ms: u64,
) -> Result<(), IndexedSessionStoreError> {
    let cutoff = now_ms.saturating_sub(SESSION_END_KEEP_MS);
    let Some(sealer) = layout.keyed() else {
        conn.execute(
            "DELETE FROM peer_session_end WHERE ended_at_ms < ?1",
            params![i64::try_from(cutoff).unwrap_or(i64::MAX)],
        )?;
        conn.execute(
            "DELETE FROM peer_session_end_erased
             WHERE NOT EXISTS (
               SELECT 1 FROM indexed_session_heads h
               JOIN indexed_session_reset r ON r.session_id = h.session_id
               WHERE r.peer_device = peer_session_end_erased.peer_device
                 AND h.created_at_ms <= peer_session_end_erased.created_to_ms)",
            [],
        )?;
        return Ok(());
    };
    // Schema 2 (PP.13): the hours that may have gone, then each end's exact
    // time; a meta that does not open goes by its hour.
    let now = i64::try_from(now_ms).unwrap_or(i64::MAX);
    let cutoff = i64::try_from(cutoff).unwrap_or(i64::MAX);
    let ends: Vec<(Vec<u8>, i64, Vec<u8>)> = {
        let mut statement = conn.prepare(
            "SELECT kh_peer_device, prune_after_hour, meta FROM peer_session_end
             WHERE prune_after_hour <= ?1",
        )?;
        let mapped = statement.query_map(params![sealed::may_have_expired(now)], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?;
        mapped.collect::<Result<_, _>>()?
    };
    for (kp, hour, meta) in ends {
        let gone = match sealer.open::<SessionEndMeta>(sealed::SESSION_END, &kp, &meta) {
            Ok(end) => end.ended_at_ms < cutoff,
            Err(error @ IndexedSessionStoreError::MetaKeyUnavailable(_)) => return Err(error),
            Err(_) => sealed::surely_expired(hour, now),
        };
        if gone {
            conn.execute(
                "DELETE FROM peer_session_end WHERE kh_peer_device = ?1",
                params![kp],
            )?;
        }
    }
    let marks: Vec<(Vec<u8>, Vec<u8>)> = {
        let mut statement =
            conn.prepare("SELECT kh_peer_device, meta FROM peer_session_end_erased")?;
        let mapped = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        mapped.collect::<Result<_, _>>()?
    };
    for (kp, meta) in marks {
        // A mark that does not open covers every head: it goes with the last.
        let created_to = match sealer.open::<ErasedMeta>(sealed::ERASED, &kp, &meta) {
            Ok(mark) => mark.created_to_ms,
            Err(error @ IndexedSessionStoreError::MetaKeyUnavailable(_)) => return Err(error),
            Err(_) => i64::MAX,
        };
        let covers = keyed_peer_head_times(conn, sealer, &kp)?
            .into_iter()
            .any(|created| created <= created_to);
        if !covers {
            conn.execute(
                "DELETE FROM peer_session_end_erased WHERE kh_peer_device = ?1",
                params![kp],
            )?;
        }
    }
    Ok(())
}

impl IndexedSessionStore {
    /// Drop the removal marks of keys that are contacts again (`contacts`:
    /// the contact book's keys, lowercase hex), before a prune: a contact
    /// added back after `raven contact remove` is no longer erased, so the
    /// end of a session still here (an old one it goes on using included) is
    /// remembered again (review FU-5). The marks of removed contacts stay.
    /// Returns how many went.
    pub fn readmit_session_ends(
        &self,
        contacts: &std::collections::HashSet<String>,
    ) -> Result<usize, IndexedSessionStoreError> {
        if let Some(sealer) = self.layout.keyed() {
            // Schema 2: each contact's keyed device (the marks name no one).
            let mut readmitted = 0;
            for contact in contacts {
                let Ok(peer) = hex::decode(contact) else {
                    continue;
                };
                if peer.len() != 32 || hex::encode(&peer) != *contact {
                    continue;
                }
                readmitted += self.conn.execute(
                    "DELETE FROM peer_session_end_erased WHERE kh_peer_device = ?1",
                    params![sealer.device(&peer).as_slice()],
                )?;
            }
            return Ok(readmitted);
        }
        let marked: Vec<Vec<u8>> = {
            let mut statement = self
                .conn
                .prepare("SELECT peer_device FROM peer_session_end_erased")?;
            let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
            rows.collect::<Result<_, _>>()?
        };
        let mut readmitted = 0;
        for peer in marked
            .iter()
            .filter(|peer| contacts.contains(&hex::encode(peer)))
        {
            readmitted += self.conn.execute(
                "DELETE FROM peer_session_end_erased WHERE peer_device = ?1",
                params![peer.as_slice()],
            )?;
        }
        Ok(readmitted)
    }
}

/// What a contact's sessions allow at one instant.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PeerSessionHorizon {
    /// The expiry of the newest confirmed, unexpired session that is not
    /// retired: a message sealed now can wait at most until then. None when
    /// there is none.
    pub sendable_until_ms: Option<u64>,
    /// When the last confirmed session with the contact ended (expired, or
    /// was retired), when that is known. None for a contact never paired
    /// (or not within [`SESSION_END_KEEP_MS`]).
    pub ended_at_ms: Option<u64>,
}

/// A read-only view of the session store's metadata (see the module docs).
pub struct SessionMetadataReader {
    conn: Connection,
    /// Schema 1 or 2, by the heads' shape (PP.13).
    layout: Layout,
}

impl SessionMetadataReader {
    /// The profile's session metadata, or None when it has no store yet. A
    /// sealed profile's store opens only with the at-rest key this process
    /// loaded ([`IndexedSessionStoreError::MetaKeyUnavailable`]).
    pub fn open(data_dir: &Path) -> Result<Option<Self>, IndexedSessionStoreError> {
        let path = data_dir.join(INDEXED_SESSION_METADATA_FILE);
        if !path.is_file() {
            return Ok(None);
        }
        // Read-write so a WAL database opens without its `-shm` file
        // existing; never CREATE. Only [`forget_session_end`] writes (and
        // may add its additive table).
        let conn = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        conn.busy_timeout(Duration::from_secs(2))?;
        // `forget_session_end` deletes through it (PP.2).
        crate::paths::harden_sqlite(&conn)?;
        let layout = sealed::reader_layout(&conn, data_dir)?;
        Ok(Some(Self { conn, layout }))
    }

    /// The `init_id` of every session head, from metadata only (a sealed
    /// profile's heads opened with the at-rest key this process loaded, no
    /// keychain item): the harnesses' control for the record-key check
    /// (review B-sealed-stores-1, [`super::record_key_names_friend`]).
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn init_ids(&self) -> Result<Vec<[u8; 16]>, IndexedSessionStoreError> {
        let mut statement = self.conn.prepare(&format!(
            "SELECT {} FROM indexed_session_heads",
            sealed::head_columns(&self.layout, "")
        ))?;
        let rows = statement.query_map([], |row| sealed::raw_head(&self.layout, row, 0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(self.layout.head(row?)?.key.init_id);
        }
        Ok(out)
    }

    /// [`PeerSessionHorizon`] for the contact whose device key is `peer`.
    pub fn peer_horizon(
        &self,
        peer: &[u8; 32],
        now_ms: u64,
    ) -> Result<PeerSessionHorizon, IndexedSessionStoreError> {
        let now = i64::try_from(now_ms).unwrap_or(i64::MAX);
        let ms = |v: i64| u64::try_from(v).unwrap_or(0);
        if let Some(sealer) = self.layout.keyed() {
            // Schema 2 (PP.13): every confirmed head of the contact, then in
            // Rust what schema 1 asks SQLite for.
            let mut heads = keyed_confirmed_heads(&self.conn, sealer, peer)?;
            sealed::newest_first_by(&mut heads, |end| (end.head.created_at_ms, end.init_id));
            let sendable = heads
                .iter()
                .find(|end| end.head.expires_at_ms > now && end.reset.retired_at_ms.is_none())
                .map(|end| end.head.expires_at_ms);
            let ended_here = heads
                .iter()
                .filter(|end| end.head.expires_at_ms <= now || end.reset.retired_at_ms.is_some())
                .map(|end| {
                    end.head
                        .expires_at_ms
                        .min(end.reset.retired_at_ms.unwrap_or(end.head.expires_at_ms))
                })
                .max();
            let remembered =
                keyed_end(&self.conn, sealer, &sealer.device(peer))?.map(|end| end.ended_at_ms);
            let ended = ended_here.max(remembered).map(ms);
            return Ok(PeerSessionHorizon {
                sendable_until_ms: sendable.map(ms),
                ended_at_ms: ended.filter(|at| *at <= now_ms),
            });
        }
        // The newest first, as the send path picks its session.
        let sendable: Option<i64> = self
            .conn
            .query_row(
                "SELECT h.expires_at_ms FROM indexed_session_heads h
                 JOIN indexed_session_reset r ON r.session_id = h.session_id
                 WHERE (h.initiator_device = ?1 OR h.responder_device = ?1)
                   AND r.peer_device = ?1
                   AND h.expires_at_ms > ?2
                   AND r.confirmed_at_ms IS NOT NULL
                   AND r.retired_at_ms IS NULL
                 ORDER BY h.created_at_ms DESC, h.init_id DESC
                 LIMIT 1",
                params![peer.as_slice(), now],
                |row| row.get(0),
            )
            .optional()?;
        // Ended and not pruned yet: expired, or retired first.
        let ended_here: Option<i64> = self.conn.query_row(
            "SELECT MAX(MIN(h.expires_at_ms, COALESCE(r.retired_at_ms, h.expires_at_ms)))
             FROM indexed_session_heads h
             JOIN indexed_session_reset r ON r.session_id = h.session_id
             WHERE (h.initiator_device = ?1 OR h.responder_device = ?1)
               AND r.peer_device = ?1
               AND r.confirmed_at_ms IS NOT NULL
               AND (h.expires_at_ms <= ?2 OR r.retired_at_ms IS NOT NULL)",
            params![peer.as_slice(), now],
            |row| row.get(0),
        )?;
        // Ended and pruned: remembered by the prune (a store no build of
        // this pack has opened yet has no such table).
        let remembered: Option<i64> = if self.has_table("peer_session_end")? {
            self.conn
                .query_row(
                    "SELECT ended_at_ms FROM peer_session_end WHERE peer_device = ?1",
                    params![peer.as_slice()],
                    |row| row.get(0),
                )
                .optional()?
        } else {
            None
        };
        let ended = ended_here.max(remembered).map(ms);
        Ok(PeerSessionHorizon {
            sendable_until_ms: sendable.map(ms),
            ended_at_ms: ended.filter(|at| *at <= now_ms),
        })
    }

    fn has_table(&self, name: &str) -> Result<bool, IndexedSessionStoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
                params![name],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .is_some())
    }
}

/// Forget when `peer`'s last session ended (its contact was removed: storage
/// rule "real erase"), now and when its heads still here are pruned later
/// (see the module docs), its session renewal row (Phase 3 item 4), and its
/// parked and inbound-seen rows (Phase 5, P5.4). No
/// store or no such row is fine. The parked rows only: the caller gives
/// their messages up first, stage and history included
/// ([`crate::horizon::give_up_parked_for_contact`], review 5a-2).
pub fn forget_session_end(
    data_dir: &Path,
    peer: &[u8; 32],
) -> Result<(), IndexedSessionStoreError> {
    let Some(reader) = SessionMetadataReader::open(data_dir)? else {
        return Ok(());
    };
    if let Some(sealer) = reader.layout.keyed() {
        // Schema 2 (PP.13): one transaction (the mark's newest head is read,
        // compared and written back).
        return sealed::in_write_tx(&reader.conn, |conn| {
            let kp = sealer.device(peer);
            conn.execute(
                "DELETE FROM peer_session_end WHERE kh_peer_device = ?1",
                params![kp.as_slice()],
            )?;
            // Session renewal's row too (Phase 3 item 4), and the
            // horizon's parked and inbound-seen rows (Phase 5, P5.4).
            super::renewal::forget(conn, Some(sealer), peer)?;
            super::parked::forget(conn, Some(sealer), peer)?;
            let Some(newest) = keyed_peer_head_times(conn, sealer, &kp)?.into_iter().max() else {
                return Ok(());
            };
            let created_to = keyed_mark(conn, sealer, &kp)?
                .map_or(newest, |mark| mark.created_to_ms.max(newest));
            let meta = ErasedMeta {
                peer_device: hex::encode(peer),
                created_to_ms: created_to,
            };
            conn.execute(
                "INSERT INTO peer_session_end_erased (kh_peer_device, meta) VALUES (?1, ?2)
                 ON CONFLICT(kh_peer_device) DO UPDATE SET meta = excluded.meta",
                params![kp.as_slice(), sealer.seal(sealed::ERASED, &kp, &meta)],
            )?;
            Ok(())
        });
    }
    if reader.has_table("peer_session_end")? {
        reader.conn.execute(
            "DELETE FROM peer_session_end WHERE peer_device = ?1",
            params![peer.as_slice()],
        )?;
    }
    super::renewal::forget(&reader.conn, None, peer)?;
    super::parked::forget(&reader.conn, None, peer)?;
    if reader.has_table("indexed_session_reset")? {
        reader.conn.execute_batch(&erased_schema(&reader.layout))?;
        reader.conn.execute(
            "INSERT INTO peer_session_end_erased (peer_device, created_to_ms)
             SELECT r.peer_device, MAX(h.created_at_ms)
             FROM indexed_session_heads h
             JOIN indexed_session_reset r ON r.session_id = h.session_id
             WHERE r.peer_device = ?1
             GROUP BY r.peer_device
             ON CONFLICT(peer_device) DO UPDATE
               SET created_to_ms = MAX(created_to_ms, excluded.created_to_ms)",
            params![peer.as_slice()],
        )?;
    }
    Ok(())
}

/// Session heads written straight into a profile's metadata, with no
/// protected state: enough for the metadata reads and a prune.
#[cfg(test)]
pub(crate) mod test_rows {
    use super::*;

    /// A store at `data_dir` (created on first use) with one head between
    /// this computer and `peer`, numbered `seq`: `confirmed` stamps its
    /// sidecar, `retired_at_ms` retires it. A sealed store (schema 2) gets
    /// the same rows keyed and sealed.
    pub(crate) fn insert_head(
        data_dir: &Path,
        seq: u8,
        peer: &[u8; 32],
        created_at_ms: u64,
        expires_at_ms: u64,
        confirmed: bool,
        retired_at_ms: Option<u64>,
    ) -> IndexedSessionStore {
        let backend = Arc::new(LockedFileSessionBackend::new(data_dir).expect("backend"));
        let store = IndexedSessionStore::open_with_backend(
            &data_dir.join(INDEXED_SESSION_METADATA_FILE),
            backend,
        )
        .expect("open");
        let ms = |v: u64| i64::try_from(v).unwrap();
        let session_id = [seq ^ 0x80; 32];
        if let Some(sealer) = store.layout.keyed() {
            let record_key = [seq; 32];
            let head = HeadMeta {
                initiator_address: "rvn1local".into(),
                responder_address: "rvn1peer".into(),
                initiator_device: hex::encode([0x01_u8; 32]),
                responder_device: hex::encode(peer),
                created_at_ms: ms(created_at_ms),
                expires_at_ms: ms(expires_at_ms),
                init_id: if sealer.init_keyed() {
                    hex::encode([seq; 16])
                } else {
                    String::new()
                },
            };
            store
                .conn
                .execute(
                    &format!(
                        "INSERT INTO indexed_session_heads
                           (record_key, binding_digest, profile_id, kh_initiator_address,
                            kh_responder_address, kh_initiator_device, kh_responder_device, {},
                            init_hash, session_id, generation, created_hour, prune_after_hour,
                            meta)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 0, ?11, ?12, ?13)",
                        sealer.init_column()
                    ),
                    params![
                        record_key.as_slice(),
                        [0xB0_u8; 32].as_slice(),
                        PROFILE_ID,
                        sealer.address("rvn1local").as_slice(),
                        sealer.address("rvn1peer").as_slice(),
                        sealer.device(&[0x01_u8; 32]).as_slice(),
                        sealer.device(peer).as_slice(),
                        sealer.init_value(&[seq; 16]),
                        [0xC0_u8; 32].as_slice(),
                        session_id.as_slice(),
                        sealed::hour_down(ms(created_at_ms)),
                        sealed::prune_hour(ms(expires_at_ms)),
                        sealer.seal(sealed::HEADS, &record_key, &head),
                    ],
                )
                .expect("head");
            let reset = ResetMeta {
                peer_device: hex::encode(peer),
                confirmed_at_ms: confirmed.then(|| ms(created_at_ms)),
                reset_round_at_ms: None,
                retired_at_ms: retired_at_ms.map(ms),
            };
            store
                .conn
                .execute(
                    "INSERT INTO indexed_session_reset
                       (session_id, kh_peer_device, confirmed, retired, retire_cause, meta)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        session_id.as_slice(),
                        sealer.device(peer).as_slice(),
                        i64::from(confirmed),
                        i64::from(retired_at_ms.is_some()),
                        retired_at_ms.map(|_| 1i64),
                        sealer.seal(sealed::RESET, &session_id, &reset),
                    ],
                )
                .expect("sidecar");
            return store;
        }
        store
            .conn
            .execute(
                "INSERT INTO indexed_session_heads
                   (record_key, binding_digest, profile_id, initiator_address,
                    responder_address, initiator_device, responder_device, init_id,
                    init_hash, session_id, generation, created_at_ms, expires_at_ms)
                 VALUES (?1, ?2, ?3, 'rvn1local', 'rvn1peer', ?4, ?5, ?6, ?7, ?8, 0, ?9, ?10)",
                params![
                    [seq; 32].as_slice(),
                    [0xB0_u8; 32].as_slice(),
                    PROFILE_ID,
                    [0x01_u8; 32].as_slice(),
                    peer.as_slice(),
                    [seq; 16].as_slice(),
                    [0xC0_u8; 32].as_slice(),
                    session_id.as_slice(),
                    ms(created_at_ms),
                    ms(expires_at_ms),
                ],
            )
            .expect("head");
        store
            .conn
            .execute(
                "INSERT INTO indexed_session_reset
                   (session_id, peer_device, confirmed_at_ms, retired_at_ms, retire_cause)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    session_id.as_slice(),
                    peer.as_slice(),
                    confirmed.then(|| ms(created_at_ms)),
                    retired_at_ms.map(ms),
                    retired_at_ms.map(|_| 1i64),
                ],
            )
            .expect("sidecar");
        store
    }
}

#[cfg(test)]
mod tests {
    use super::test_rows::insert_head;
    use super::*;

    const HOUR: u64 = 3_600_000;
    const NOW: u64 = 1_800_000_000_000;
    const BOB: [u8; 32] = [0xBB; 32];

    fn horizon(dir: &Path, now: u64) -> PeerSessionHorizon {
        SessionMetadataReader::open(dir)
            .unwrap()
            .expect("a store")
            .peer_horizon(&BOB, now)
            .unwrap()
    }

    #[test]
    fn no_store_is_opened_or_created_by_the_reader() {
        let dir = tempfile::tempdir().unwrap();
        assert!(SessionMetadataReader::open(dir.path()).unwrap().is_none());
        forget_session_end(dir.path(), &BOB).unwrap();
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn the_newest_confirmed_live_session_decides_and_others_do_not_count() {
        let dir = tempfile::tempdir().unwrap();
        // Provisional (never confirmed): not a session that can take one.
        insert_head(
            dir.path(),
            1,
            &BOB,
            NOW - HOUR,
            NOW + 20 * HOUR,
            false,
            None,
        );
        assert_eq!(horizon(dir.path(), NOW), PeerSessionHorizon::default());
        // Confirmed: it decides. A newer one decides over it.
        insert_head(
            dir.path(),
            2,
            &BOB,
            NOW - 2 * HOUR,
            NOW + 3 * HOUR,
            true,
            None,
        );
        assert_eq!(
            horizon(dir.path(), NOW).sendable_until_ms,
            Some(NOW + 3 * HOUR)
        );
        insert_head(
            dir.path(),
            3,
            &BOB,
            NOW - HOUR / 2,
            NOW + 5 * HOUR,
            true,
            None,
        );
        assert_eq!(
            horizon(dir.path(), NOW).sendable_until_ms,
            Some(NOW + 5 * HOUR)
        );
        // Retired by a session reset: no longer sendable, and it ended then.
        insert_head(
            dir.path(),
            4,
            &BOB,
            NOW - HOUR / 4,
            NOW + 9 * HOUR,
            true,
            Some(NOW - 60_000),
        );
        let h = horizon(dir.path(), NOW);
        assert_eq!(h.sendable_until_ms, Some(NOW + 5 * HOUR));
        assert_eq!(h.ended_at_ms, Some(NOW - 60_000));
        // Another contact sees none of it.
        let reader = SessionMetadataReader::open(dir.path()).unwrap().unwrap();
        assert_eq!(
            reader.peer_horizon(&[0xCC; 32], NOW).unwrap(),
            PeerSessionHorizon::default()
        );
    }

    #[test]
    fn a_prune_remembers_when_a_confirmed_session_ended() {
        let dir = tempfile::tempdir().unwrap();
        let ended = NOW - HOUR;
        insert_head(dir.path(), 1, &BOB, ended - 24 * HOUR, ended, true, None);
        // An unconfirmed pairing that expired is no session that ended.
        let carol = [0xCC; 32];
        let mut store = insert_head(
            dir.path(),
            2,
            &carol,
            NOW - 30 * HOUR,
            NOW - 6 * HOUR,
            false,
            None,
        );
        let before = horizon(dir.path(), NOW);
        assert_eq!(before.sendable_until_ms, None);
        assert_eq!(before.ended_at_ms, Some(ended));
        assert_eq!(store.prune_expired_sessions(NOW).unwrap(), 2);
        // The head is gone; its end is not.
        assert_eq!(horizon(dir.path(), NOW), before);
        let reader = SessionMetadataReader::open(dir.path()).unwrap().unwrap();
        assert_eq!(
            reader.peer_horizon(&carol, NOW).unwrap(),
            PeerSessionHorizon::default()
        );
        // Kept 30 days, then forgotten by the next prune.
        store
            .prune_expired_sessions(ended + SESSION_END_KEEP_MS)
            .unwrap();
        assert_eq!(horizon(dir.path(), NOW).ended_at_ms, Some(ended));
        store
            .prune_expired_sessions(ended + SESSION_END_KEEP_MS + 1)
            .unwrap();
        assert_eq!(horizon(dir.path(), NOW).ended_at_ms, None);
    }

    /// Review C-time-deadlines-5: a contact removed while its session is
    /// live (or expired but not pruned yet) stays forgotten after the prune;
    /// the mark goes with its heads, and a new pairing is remembered again.
    #[test]
    fn removing_the_contact_before_the_prune_is_not_undone_by_it() {
        let dir = tempfile::tempdir().unwrap();
        let carol = [0xCC; 32];
        // Live, and expired but not pruned yet.
        insert_head(
            dir.path(),
            1,
            &BOB,
            NOW - 2 * HOUR,
            NOW + 20 * HOUR,
            true,
            None,
        );
        insert_head(
            dir.path(),
            2,
            &BOB,
            NOW - 30 * HOUR,
            NOW - 6 * HOUR,
            true,
            None,
        );
        let mut store = insert_head(
            dir.path(),
            3,
            &carol,
            NOW - 30 * HOUR,
            NOW - 6 * HOUR,
            true,
            None,
        );
        forget_session_end(dir.path(), &BOB).unwrap();
        let marks = |store: &IndexedSessionStore| -> i64 {
            store
                .conn
                .query_row("SELECT COUNT(*) FROM peer_session_end_erased", [], |r| {
                    r.get(0)
                })
                .unwrap()
        };
        assert_eq!(marks(&store), 1, "only the removed contact is marked");
        store.prune_expired_sessions(NOW).unwrap();
        assert_eq!(horizon(dir.path(), NOW).ended_at_ms, None);
        assert_eq!(marks(&store), 1, "its live head is still here");
        let later = NOW + 21 * HOUR;
        store.prune_expired_sessions(later).unwrap();
        assert_eq!(horizon(dir.path(), later).ended_at_ms, None);
        assert_eq!(marks(&store), 0, "the mark went with its last head");
        // Another contact's end is remembered as before.
        let reader = SessionMetadataReader::open(dir.path()).unwrap().unwrap();
        assert_eq!(
            reader.peer_horizon(&carol, later).unwrap().ended_at_ms,
            Some(NOW - 6 * HOUR)
        );
        // Added and paired again: that session's end is remembered.
        let mut store = insert_head(
            dir.path(),
            4,
            &BOB,
            later + HOUR,
            later + 9 * HOUR,
            true,
            None,
        );
        store.prune_expired_sessions(later + 10 * HOUR).unwrap();
        assert_eq!(
            horizon(dir.path(), later + 10 * HOUR).ended_at_ms,
            Some(later + 9 * HOUR)
        );
    }

    /// Review FU-5: a contact removed while its session was live, then
    /// added back and still using that session: once the prune readmits it
    /// (its key is in the book again), that session's end is remembered when
    /// it is pruned. A contact still removed keeps its mark.
    #[test]
    fn a_contact_added_back_has_its_old_session_end_remembered() {
        let dir = tempfile::tempdir().unwrap();
        let carol = [0xCC; 32];
        let end = NOW + 20 * HOUR;
        insert_head(dir.path(), 1, &BOB, NOW - 2 * HOUR, end, true, None);
        let mut store = insert_head(dir.path(), 2, &carol, NOW - 2 * HOUR, end, true, None);
        forget_session_end(dir.path(), &BOB).unwrap();
        forget_session_end(dir.path(), &carol).unwrap();
        // Bob is added back; Carol is not.
        let book: std::collections::HashSet<String> = [hex::encode(BOB)].into();
        assert_eq!(store.readmit_session_ends(&book).unwrap(), 1);
        assert_eq!(store.readmit_session_ends(&book).unwrap(), 0, "once");
        let later = end + HOUR;
        store.prune_expired_sessions(later).unwrap();
        assert_eq!(horizon(dir.path(), later).ended_at_ms, Some(end));
        let reader = SessionMetadataReader::open(dir.path()).unwrap().unwrap();
        assert_eq!(
            reader.peer_horizon(&carol, later).unwrap().ended_at_ms,
            None,
            "still removed: still erased"
        );
    }

    #[test]
    fn removing_the_contact_forgets_its_end() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = insert_head(
            dir.path(),
            1,
            &BOB,
            NOW - 30 * HOUR,
            NOW - 6 * HOUR,
            true,
            None,
        );
        store.prune_expired_sessions(NOW).unwrap();
        assert_eq!(horizon(dir.path(), NOW).ended_at_ms, Some(NOW - 6 * HOUR));
        forget_session_end(dir.path(), &BOB).unwrap();
        assert_eq!(horizon(dir.path(), NOW).ended_at_ms, None);
    }

    #[test]
    fn secure_delete_is_on_after_open() {
        let dir = tempfile::tempdir().unwrap();
        insert_head(dir.path(), 1, &BOB, NOW - HOUR, NOW + HOUR, true, None);
        let reader = SessionMetadataReader::open(dir.path()).unwrap().unwrap();
        assert_eq!(crate::paths::scrub_test::secure_delete(&reader.conn), 1);
    }

    /// PP.2: forgetting a removed contact's end overwrites it. The marker is
    /// the contact's device key, which after the prune only the remembered
    /// end holds.
    #[test]
    fn a_deleted_row_leaves_no_bytes_after_checkpoint() {
        use crate::paths::scrub_test;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(INDEXED_SESSION_METADATA_FILE);
        let peer = scrub_test::marker();
        let mut store = insert_head(
            dir.path(),
            1,
            &peer,
            NOW - 30 * HOUR,
            NOW - 6 * HOUR,
            true,
            None,
        );
        assert_eq!(store.prune_expired_sessions(NOW).unwrap(), 1);
        if store.layout.is_keyed() {
            // A sealed store never writes the key in clear (PP.13).
            crate::paths::checkpoint_truncate(&store.conn).unwrap();
            assert!(!scrub_test::main_file_holds(&path, &peer));
            forget_session_end(dir.path(), &peer).unwrap();
            return;
        }
        scrub_test::assert_written(&store.conn, &path, &peer);
        forget_session_end(dir.path(), &peer).unwrap();
        let checkpoint = crate::paths::checkpoint_truncate(&store.conn).unwrap();
        assert!(checkpoint.completed(), "{checkpoint:?}");
        scrub_test::assert_scrubbed(&path, &peer);
    }
}
