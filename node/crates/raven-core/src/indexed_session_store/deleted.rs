//! Inbox rows the user deleted (privacy pack PP.8: a clear that sticks).
//!
//! Deleting a chat removes its `endpoint_inbox` rows and leaves one row per
//! object in `endpoint_inbox_deleted`. The object's receipt, ACK intent and
//! logical-message row stay, so a re-delivered copy (its ACK was lost) is
//! still a duplicate: it is answered with the same immutable ACK and shown
//! nowhere. Without the rows, the session-expiry archive and the duplicate
//! path have nothing to write back into the chat history.
//!
//! - **Who reads it.** The duplicate path of a direct link and of a relayed
//!   delivery ([`IndexedSessionStore::inbox_row_deleted`]): a committed object
//!   whose inbox row is missing and has a tombstone was deleted by the user,
//!   never `CorruptEndpointState`; without a tombstone it stays an error. The
//!   replay of an acceptance journal treats a tombstoned row as accepted.
//! - **The per-sender floor.** `max_received_at_ms` keeps the paging cursor's
//!   floor of the rows that went, so a later row never sorts before a cursor
//!   saved over them (`monotonic_received_at_ms`).
//! - **Lifetime.** A session's tombstones go with it in
//!   `prune_expired_sessions`, deleted explicitly before its receipts (no
//!   foreign key, so an older build's prune leaves orphans, which the next
//!   prune of this build removes).
//!
//! Additive to schema 1, like the reset and horizon sidecars: older builds
//! ignore the table (they find no inbox row to resurrect). In a sealed
//! profile's schema-3 store (PP.14) the object digest and the sender are
//! keyed, both times are in the row's `meta`, and a clear `seq` (the deleted
//! row's) lets the floor read only the tombstones newer than the sender's
//! newest row.

use super::endpoints::{self, DeletedMeta};
use super::*;

pub(super) fn create_deleted_schema(conn: &Connection) -> Result<(), IndexedSessionStoreError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS endpoint_inbox_deleted (
           session_id BLOB NOT NULL CHECK(length(session_id) = 32),
           object_digest BLOB NOT NULL CHECK(length(object_digest) = 32),
           sender_device BLOB NOT NULL CHECK(length(sender_device) = 32),
           deleted_at_ms INTEGER NOT NULL CHECK(deleted_at_ms >= 0),
           max_received_at_ms INTEGER NOT NULL CHECK(max_received_at_ms >= 0),
           PRIMARY KEY(session_id, object_digest)
         );",
    )?;
    Ok(())
}

/// What a deletion of inbox rows did, counts only
/// ([`IndexedSessionStore::delete_inbox_for_sender`],
/// [`IndexedSessionStore::delete_inbox_older_than`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InboxDeletion {
    /// Chat rows deleted, each leaving a tombstone.
    pub deleted: u32,
    /// Rows left for the next deletion or the session's prune: an acceptance
    /// of theirs still being committed (its journal is pending), or a session
    /// or row that cannot be read now.
    pub skipped: u32,
    /// The WAL checkpoint after the delete completed, so what it overwrote
    /// reached the main file (PP.2). `false`: another connection was in the
    /// way, and a later prune pass checkpoints again. `true` when nothing was
    /// deleted.
    pub scrubbed: bool,
}

/// Was the inbox row of `(session_id, object_digest)` deleted by the user?
pub(super) fn is_deleted(
    conn: &Connection,
    layout: &Layout,
    session_id: &[u8; 32],
    object_digest: &[u8; 32],
) -> Result<bool, IndexedSessionStoreError> {
    Ok(conn
        .query_row(
            &layout.ep("SELECT 1 FROM endpoint_inbox_deleted
                 WHERE session_id = ?1 AND kh_object_digest = ?2"),
            params![session_id.as_slice(), layout.ep_digest(object_digest)],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .is_some())
}

/// The newest `received_at_ms` among `sender_device`'s deleted rows. In
/// schema 3 only the tombstones at or after `newest_seq` (the `seq` of the
/// sender's newest live row) can hold one above that row's own stamp: the
/// others are opened only when the sender has no live row left.
pub(super) fn deleted_received_floor(
    conn: &Connection,
    layout: &Layout,
    sender_device: &[u8; 32],
    newest_seq: i64,
) -> Result<Option<i64>, IndexedSessionStoreError> {
    let Some(sealer) = layout.endpoints() else {
        return Ok(conn.query_row(
            "SELECT MAX(max_received_at_ms) FROM endpoint_inbox_deleted WHERE sender_device = ?1",
            params![sender_device.as_slice()],
            |row| row.get(0),
        )?);
    };
    let mut statement = conn.prepare(
        "SELECT session_id, kh_object_digest, meta FROM endpoint_inbox_deleted
         WHERE kh_sender_device = ?1 AND seq >= ?2",
    )?;
    let rows = statement.query_map(
        params![sealer.device(sender_device).as_slice(), newest_seq],
        |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        },
    )?;
    let mut floor = None;
    for row in rows {
        let (session_id, digest, meta) = row?;
        // A damaged tombstone is skipped: it is a floor, never a row to show.
        match sealer.open::<DeletedMeta>(endpoints::DELETED, &[session_id, digest].concat(), &meta)
        {
            Ok(meta) => floor = floor.max(Some(meta.max_received_at_ms)),
            Err(error @ IndexedSessionStoreError::MetaKeyUnavailable(_)) => return Err(error),
            Err(_) => continue,
        }
    }
    Ok(floor)
}

/// The prune, before it deletes `session_id`'s receipts: its tombstones go.
pub(super) fn delete_session_tombstones(
    tx: &Transaction<'_>,
    session_id: &[u8],
) -> Result<(), IndexedSessionStoreError> {
    tx.execute(
        "DELETE FROM endpoint_inbox_deleted WHERE session_id = ?1",
        params![session_id],
    )?;
    Ok(())
}

/// Tombstones whose session is gone (an older build's prune knows nothing of
/// them).
pub(super) fn delete_orphan_tombstones(conn: &Connection) -> Result<(), IndexedSessionStoreError> {
    conn.execute(
        "DELETE FROM endpoint_inbox_deleted WHERE session_id NOT IN
           (SELECT session_id FROM indexed_session_heads)",
        [],
    )?;
    Ok(())
}

fn ms(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// The rows a deletion looks at, by session: the session's record key digest,
/// its public key and its rows' object digests (oldest first).
type Candidates = BTreeMap<[u8; 32], (IndexedSessionRecordKey, Vec<[u8; 32]>)>;

/// Which of a deletion's rows go.
enum UpTo {
    /// At or before a reader's place in the store's order.
    Position(InboxPosition),
    /// Received at or before this time.
    Received(i64),
}

impl UpTo {
    fn takes(&self, entry: &endpoints::InboxEntry) -> bool {
        match self {
            UpTo::Position(position) if position.order == InboxOrder::Seq => {
                entry.seq.is_some_and(|seq| seq as u64 <= position.seq)
            }
            UpTo::Position(position) => {
                !position.received_after(entry.received_at_ms, &entry.message_id)
            }
            UpTo::Received(at) => entry.received_at_ms <= *at,
        }
    }
}

impl IndexedSessionStore {
    /// Deletes the chat rows `sender_device` sent (all of them, or those at
    /// or before `up_to`, a reader's place: [`EndpointInboxRow::position`]),
    /// leaving a tombstone for each: "delete chat with {name}" and
    /// `/clear-local-history` (PP.8). A place of the other order (taken
    /// before the store moved to schema 3) is placed first
    /// ([`Self::resolve_inbox_position`]). An
    /// agent payload is RDAP's (the app channel) and is never deleted here.
    /// Receipts, ACK intents and logical-message rows stay, so duplicate
    /// detection and idempotent ACKs keep working.
    ///
    /// A row whose acceptance journal is still pending (its commit is under
    /// way in another store instance, or was cut short by a crash) is skipped
    /// and counted: deleting it would make the journal's replay find its row
    /// missing. So is a row of a session that cannot be read now. One
    /// IMMEDIATE transaction; then a WAL checkpoint (PP.2), its outcome in
    /// [`InboxDeletion::scrubbed`].
    pub fn delete_inbox_for_sender(
        &mut self,
        sender_device: &[u8; 32],
        up_to: Option<&InboxPosition>,
    ) -> Result<InboxDeletion, IndexedSessionStoreError> {
        let up_to = match up_to {
            Some(position) => UpTo::Position(self.resolve_inbox_position(sender_device, position)?),
            None => UpTo::Received(i64::MAX),
        };
        self.delete_inbox_rows(Some(sender_device), up_to)
    }

    /// Like [`Self::delete_inbox_for_sender`], for every sender's chat rows
    /// received before `before_ms` (the retention pass, PP.9).
    pub fn delete_inbox_older_than(
        &mut self,
        before_ms: u64,
    ) -> Result<InboxDeletion, IndexedSessionStoreError> {
        if before_ms == 0 {
            return Ok(InboxDeletion {
                scrubbed: true,
                ..InboxDeletion::default()
            });
        }
        self.delete_inbox_rows(None, UpTo::Received(ms(before_ms) - 1))
    }

    /// Did the user delete the inbox row of this committed object? Metadata
    /// only (no keystore): the duplicate paths ask it when the row is missing.
    pub fn inbox_row_deleted(
        &self,
        session_id: &[u8; 32],
        object_digest: &[u8; 32],
    ) -> Result<bool, IndexedSessionStoreError> {
        is_deleted(&self.conn, &self.layout, session_id, object_digest)
    }

    /// Chat rows of `sender` (every sender: `None`) that `up_to` takes.
    fn delete_inbox_rows(
        &mut self,
        sender: Option<&[u8; 32]>,
        up_to: UpTo,
    ) -> Result<InboxDeletion, IndexedSessionStoreError> {
        let mut report = InboxDeletion {
            scrubbed: true,
            ..InboxDeletion::default()
        };
        // A journal left by a crash is replayed first, as before every
        // per-session operation. A session that cannot be read keeps its rows.
        let listed = deletion_candidates(&self.conn, &self.layout, sender, &up_to)?;
        if listed.is_empty() {
            return Ok(report);
        }
        let mut unreadable = BTreeSet::new();
        for record_key in listed.into_keys() {
            match self.recover_pending_for_digest(&record_key) {
                Ok(()) => {}
                Err(error) if is_session_scoped_state_error(&error) => {
                    log_skipped_session(&record_key, &error);
                    unreadable.insert(record_key);
                }
                Err(error) => return Err(error),
            }
        }
        #[cfg(test)]
        self.run_after_recovery_hook();
        let count = |digests: &[[u8; 32]]| u32::try_from(digests.len()).unwrap_or(u32::MAX);
        let deleted_at = ms(crate::clock::now_ms());
        let backend = Arc::clone(&self.backend);
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let _in_tx = crate::paths::HeldMark::transaction();
        // Listed again under the write lock: a row committed since then by
        // another store instance is seen here with its journal.
        for (record_key, (key, digests)) in deletion_candidates(&tx, &self.layout, sender, &up_to)?
        {
            if unreadable.contains(&record_key) {
                report.skipped = report.skipped.saturating_add(count(&digests));
                continue;
            }
            let account = hex::encode(record_key);
            let state = match load_and_reconcile(
                &tx,
                &self.layout,
                backend.as_ref(),
                &account,
                &record_key,
            ) {
                Ok(state) if state.binding.key == key => state,
                Ok(_) => {
                    report.skipped = report.skipped.saturating_add(count(&digests));
                    continue;
                }
                Err(error) if is_session_scoped_state_error(&error) => {
                    log_skipped_session(&record_key, &error);
                    report.skipped = report.skipped.saturating_add(count(&digests));
                    continue;
                }
                Err(error) => return Err(error),
            };
            // Only an acceptance journal names an inbox row. Still pending
            // here, its writer is between its commit and its journal clear (or
            // died there): the replay must find the row, so it stays.
            let pending = state.pending_acceptance.as_ref().map(|p| p.object_digest);
            for digest in digests {
                if pending == Some(digest) {
                    report.skipped = report.skipped.saturating_add(1);
                    continue;
                }
                let row = match read_endpoint_inbox_row(
                    &tx,
                    &self.layout,
                    &state.ratchets.root,
                    &state.binding.session_id,
                    &digest,
                ) {
                    Ok(Some(row)) => row,
                    Ok(None) => continue,
                    Err(error) if is_session_scoped_state_error(&error) => {
                        report.skipped = report.skipped.saturating_add(1);
                        continue;
                    }
                    Err(error) => return Err(error),
                };
                // An agent payload belongs to RDAP's app inbox, never to chat.
                if !matches!(
                    crate::app_channel::classify(&row.plaintext),
                    crate::app_channel::PayloadClass::Chat
                ) {
                    continue;
                }
                insert_tombstone(&tx, &self.layout, &row, deleted_at)?;
                tx.execute(
                    &self.layout.ep("DELETE FROM endpoint_inbox
                         WHERE session_id = ?1 AND kh_object_digest = ?2"),
                    params![
                        row.session_id.as_slice(),
                        self.layout.ep_digest(&row.object_digest)
                    ],
                )?;
                report.deleted = report.deleted.saturating_add(1);
            }
        }
        tx.commit()?;
        if report.deleted > 0 {
            // Committed either way: an error or a busy checkpoint leaves the
            // overwrite to the next prune pass's checkpoint.
            report.scrubbed = crate::paths::checkpoint_truncate(&self.conn)
                .is_ok_and(|checkpoint| checkpoint.completed());
        }
        Ok(report)
    }
}

/// The inbox rows a deletion looks at, by session (`sender`: every sender
/// when `None`; the rows `up_to` takes), oldest first. A clear store narrows
/// by the time in SQL; schema 3 by `seq` for a reader's place, and opens
/// each row's `meta` for a time (the retention pass).
fn deletion_candidates(
    conn: &Connection,
    layout: &Layout,
    sender: Option<&[u8; 32]>,
    up_to: &UpTo,
) -> Result<Candidates, IndexedSessionStoreError> {
    let (narrow, order, bound) = match (layout.endpoints(), up_to) {
        (Some(_), UpTo::Position(position)) => (
            "i.seq <= ?2",
            "i.seq ASC",
            i64::try_from(position.seq).unwrap_or(i64::MAX),
        ),
        (Some(_), UpTo::Received(_)) => ("?2 IS NOT NULL", "i.seq ASC", 0),
        (None, UpTo::Position(position)) => (
            "i.received_at_ms <= ?2",
            "i.received_at_ms ASC, i.message_id ASC",
            i64::try_from(position.seq).unwrap_or(i64::MAX),
        ),
        (None, UpTo::Received(at)) => (
            "i.received_at_ms <= ?2",
            "i.received_at_ms ASC, i.message_id ASC",
            *at,
        ),
    };
    let mut statement = conn.prepare(&layout.ep(&format!(
        "SELECT {}, {}
         FROM endpoint_inbox i
         JOIN indexed_session_heads h ON h.session_id = i.session_id
         WHERE (?1 IS NULL OR i.kh_sender_device = ?1) AND {narrow}
         ORDER BY {order}",
        sealed::head_columns(layout, "h."),
        endpoints::inbox_entry_columns(layout, "i.")
    )))?;
    let rows = statement.query_map(params![sender.map(|s| layout.ep_device(s)), bound], |row| {
        Ok((
            sealed::raw_head(layout, row, 0)?,
            endpoints::raw(row, 8, endpoints::INBOX_ENTRY_WIDTH)?,
        ))
    })?;
    let mut candidates = Candidates::new();
    let mut heads = std::collections::HashMap::new();
    for row in rows {
        let (raw, entry) = row?;
        // The rows of a session whose head does not open stay, as a row
        // that does not open does (for the session's prune).
        let Some(head) = layout.head_cached(raw, &mut heads)? else {
            continue;
        };
        let key = head.key;
        // A row that does not open stays (for the session's prune).
        let (Some(entry), _) = endpoints::listed_entry(layout, &key, entry)? else {
            continue;
        };
        if !up_to.takes(&entry) {
            continue;
        }
        candidates
            .entry(record_key_digest(&key)?)
            .or_insert_with(|| (key, Vec::new()))
            .1
            .push(entry.object_digest);
    }
    Ok(candidates)
}

/// The tombstone of a deleted inbox row: its object, its sender, when it
/// went and the stamp it had (the floor of later rows).
fn insert_tombstone(
    tx: &Transaction<'_>,
    layout: &Layout,
    row: &EndpointInboxRow,
    deleted_at: i64,
) -> Result<(), IndexedSessionStoreError> {
    let Some(sealer) = layout.endpoints() else {
        tx.execute(
            "INSERT OR IGNORE INTO endpoint_inbox_deleted
             (session_id, object_digest, sender_device, deleted_at_ms,
              max_received_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                row.session_id.as_slice(),
                row.object_digest.as_slice(),
                row.sender_device.as_slice(),
                deleted_at,
                ms(row.received_at_ms),
            ],
        )?;
        return Ok(());
    };
    let digest = sealer.digest(&row.object_digest);
    let meta = DeletedMeta {
        object_digest: hex::encode(row.object_digest),
        sender_device: hex::encode(row.sender_device),
        deleted_at_ms: deleted_at,
        max_received_at_ms: ms(row.received_at_ms),
    };
    tx.execute(
        "INSERT OR IGNORE INTO endpoint_inbox_deleted
         (session_id, kh_object_digest, kh_sender_device, seq, meta)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            row.session_id.as_slice(),
            digest.as_slice(),
            sealer.device(&row.sender_device).as_slice(),
            i64::try_from(row.position.seq).unwrap_or(i64::MAX),
            sealer.seal(
                endpoints::DELETED,
                &[row.session_id.as_slice(), digest.as_slice()].concat(),
                &meta
            ),
        ],
    )?;
    Ok(())
}
