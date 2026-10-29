//! Letter sessions (Phase 5b, P5.12; [`crate::horizon`]): the sessions whose
//! PairInit travels in an RAL1 letter (`protocol/RAVEN_ASYNC_LETTER_V1.md`).
//!
//! One row per such session in `indexed_session_letter`, keyed by its
//! `session_id` and cascading with its head (an expired session's row goes
//! with the prune's head; removing a contact leaves both until then, like
//! the reset sidecar). `role` 1 is a session this node started for a letter
//! ([`crate::lan_dispatch::create_letter_pair_init`]): the row keeps the exact
//! PairInit, since a retry or a direct completion resends those bytes
//! (`RAVEN_PAIR_INIT_V1.md` §6), and its provisional initiator may seal
//! message indices 0 to [`crate::horizon::LETTER_SESSION_MAX_MESSAGES`] - 1
//! ([`provisional_message_cap`]; `ATSAM_ENDPOINT_TRANSACTION_V1.md` §4.1).
//! `role` 2 is one this node accepted from a letter
//! ([`crate::lan_dispatch::accept_pair_init_core`]); its row keeps the exact
//! PairResponse (P5.14), since the REPLY letter that carries it back may
//! leave days later and the link's cached copy lasts minutes
//! ([`IndexedSessionStore::letter_reply`]). Both are letter-class:
//! never a target for new direct Messages
//! ([`IndexedSessionStore::session_is_letter_class`]).
//!
//! The table is additive (`CREATE TABLE IF NOT EXISTS`) in either schema, as
//! session renewal's ([`super::renewal`]): a profile that is not sealed keeps
//! schema 1's clear columns, which older builds ignore; a sealed profile's
//! store (schema 4, [`super::sealed`]) keys the peer device (`kh_peer_device`)
//! and seals the device, the PairInit (both devices and addresses), the
//! PairResponse and the time in the row's `meta`, bound to the clear
//! `session_id` (R20). A clear table P5.12 made without the PairResponse
//! column gains it at the next open ([`ensure_table`]). `role` is
//! a clear code in both: the provisional cap reads it inside the seal's own
//! transaction. [`METADATA_SCHEMA_VERSION`] is unchanged. The moves to and
//! from schema 4 and a re-key carry the rows with their rowids
//! ([`move_forward`], [`move_back`]); a table found in the other layout's
//! shape is handled as session renewal's is ([`ensure_table`]).

use serde::{Deserialize, Serialize};

use super::sealed::{self, Layout};
use super::*;
use crate::at_rest::{self, MetaKeys, ValueType};
use crate::pair_init::{INIT_WIRE_LEN, RESPONSE_WIRE_LEN};
use crate::sqlite_rebuild::{self as rebuild, Migration, RebuildError, Steps};

/// The letter sessions' table.
pub(super) const LETTER: &str = "indexed_session_letter";

/// Its sealed value in schema 4: one `meta` per row, bound to the session.
pub(super) const SEALED: sealed::SealedColumn = (LETTER, "meta", LETTER, &["session_id"]);

// The clear table's CHECKs name the PairInit and PairResponse lengths.
const _: () = assert!(INIT_WIRE_LEN == 2788 && RESPONSE_WIRE_LEN == 228);

/// The clear column a responder's row keeps its PairResponse in (P5.14).
const REPLY_COLUMN: &str = "pair_response";
/// Its definition, for the table and for the column added to a P5.12 one.
const REPLY_COLUMN_DEF: &str =
    "pair_response BLOB CHECK(pair_response IS NULL OR length(pair_response) = 228)";

/// Who started a letter session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LetterRole {
    /// This node sealed the PairInit into a letter (provisional until the
    /// REPLY letter or a direct PairResponse confirms it).
    Initiator = 1,
    /// This node accepted the PairInit from a letter.
    Responder = 2,
}

impl LetterRole {
    fn from_i64(value: i64) -> Option<Self> {
        match value {
            1 => Some(Self::Initiator),
            2 => Some(Self::Responder),
            _ => None,
        }
    }
}

/// One letter session's row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LetterSession {
    pub session_id: [u8; 32],
    /// The other side's device key.
    pub peer_device: [u8; 32],
    pub role: LetterRole,
    /// The exact PairInit wire ([`INIT_WIRE_LEN`] bytes) of a session this
    /// node started; `None` for [`LetterRole::Responder`].
    pub pair_init: Option<Vec<u8>>,
    /// The session's start (its PairInit's `created_at_ms`).
    pub created_at_ms: u64,
}

#[derive(Serialize, Deserialize)]
pub(super) struct LetterMeta {
    peer_device: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pair_init: String,
    created_at_ms: i64,
    /// A responder's PairResponse wire (P5.14); absent in P5.12's rows.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pair_response: String,
}

fn ms(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn meta_of(row: &LetterSession, reply: Option<&[u8]>) -> LetterMeta {
    LetterMeta {
        peer_device: hex::encode(row.peer_device),
        pair_init: row
            .pair_init
            .as_deref()
            .map(hex::encode)
            .unwrap_or_default(),
        created_at_ms: ms(row.created_at_ms),
        pair_response: reply.map(hex::encode).unwrap_or_default(),
    }
}

/// A PairResponse a row of `role` may keep (the clear table's CHECKs).
fn valid_reply(role: LetterRole, reply: Option<&[u8]>) -> bool {
    match reply {
        None => true,
        Some(wire) => role == LetterRole::Responder && wire.len() == RESPONSE_WIRE_LEN,
    }
}

/// A keyed row's PairResponse; `Err` when it is not one a row may keep.
fn reply_of(role: LetterRole, meta: &LetterMeta) -> Result<Option<Vec<u8>>, ()> {
    let reply = if meta.pair_response.is_empty() {
        None
    } else {
        Some(hex::decode(&meta.pair_response).map_err(|_| ())?)
    };
    if valid_reply(role, reply.as_deref()) {
        Ok(reply)
    } else {
        Err(())
    }
}

/// A row whose role and PairInit agree (the clear table's CHECK).
fn valid(role: LetterRole, pair_init: Option<&[u8]>) -> bool {
    match (role, pair_init) {
        (LetterRole::Initiator, Some(wire)) => wire.len() == INIT_WIRE_LEN,
        (LetterRole::Responder, None) => true,
        _ => false,
    }
}

/// A keyed row's values; `None` when one is out of range.
fn row_of(session_id: [u8; 32], role: i64, meta: &LetterMeta) -> Option<LetterSession> {
    let role = LetterRole::from_i64(role)?;
    let pair_init = if meta.pair_init.is_empty() {
        None
    } else {
        Some(hex::decode(&meta.pair_init).ok()?)
    };
    if !valid(role, pair_init.as_deref()) {
        return None;
    }
    Some(LetterSession {
        session_id,
        peer_device: sealed::device_of(&meta.peer_device).ok()?,
        role,
        pair_init,
        created_at_ms: u64::try_from(meta.created_at_ms).ok()?,
    })
}

pub(super) fn letter_columns(keyed: bool) -> &'static str {
    if keyed {
        "session_id     BLOB PRIMARY KEY NOT NULL CHECK(length(session_id) = 32),
         kh_peer_device BLOB NOT NULL CHECK(length(kh_peer_device) = 32),
         role           INTEGER NOT NULL CHECK(role IN (1, 2)),
         meta           BLOB NOT NULL,
         FOREIGN KEY(session_id) REFERENCES indexed_session_heads(session_id) ON DELETE CASCADE"
    } else {
        "session_id    BLOB PRIMARY KEY NOT NULL CHECK(length(session_id) = 32),
         peer_device   BLOB NOT NULL CHECK(length(peer_device) = 32),
         role          INTEGER NOT NULL CHECK(role IN (1, 2)),
         pair_init     BLOB CHECK(pair_init IS NULL OR length(pair_init) = 2788),
         created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
         pair_response BLOB CHECK(pair_response IS NULL OR length(pair_response) = 228),
         CHECK((role = 1) = (pair_init IS NOT NULL)),
         CHECK(role = 2 OR pair_response IS NULL),
         FOREIGN KEY(session_id) REFERENCES indexed_session_heads(session_id) ON DELETE CASCADE"
    }
}

pub(super) fn create_letter_schema(conn: &Connection) -> Result<(), IndexedSessionStoreError> {
    ensure_table(conn, false)?;
    Ok(())
}

/// Whether the store holds the table keyed (schema 4's shape).
pub(super) fn keyed(conn: &Connection) -> rusqlite::Result<bool> {
    Ok(rebuild::columns(conn, LETTER)?
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
    let create = sealed::create_if_missing(LETTER, letter_columns(keyed));
    if keyed {
        return conn.execute_batch(&create);
    }
    if !self::keyed(conn)? {
        conn.execute_batch(&create)?;
        return ensure_reply_column(conn);
    }
    let replace = |conn: &Connection| -> rusqlite::Result<()> {
        if !self::keyed(conn)? {
            return conn.execute_batch(&create);
        }
        if rebuild::shape(conn, sealed::HEADS, sealed::KEYED_COLUMN)? == rebuild::Shape::Keyed {
            return Ok(());
        }
        conn.execute_batch(&format!("DROP TABLE {LETTER};"))?;
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

/// A clear table P5.12 made (no PairResponse column) gains the column,
/// empty: additive, and only while the table is clear.
fn ensure_reply_column(conn: &Connection) -> rusqlite::Result<()> {
    if rebuild::columns(conn, LETTER)?
        .iter()
        .any(|column| column == REPLY_COLUMN)
    {
        return Ok(());
    }
    conn.execute_batch(&format!(
        "ALTER TABLE {LETTER} ADD COLUMN {REPLY_COLUMN_DEF};"
    ))
}

/// The clear table's PairResponse column as a SELECT term: `NULL` for a
/// clear table P5.12 made without it.
fn reply_select(conn: &Connection) -> rusqlite::Result<&'static str> {
    Ok(
        if rebuild::columns(conn, LETTER)?
            .iter()
            .any(|column| column == REPLY_COLUMN)
        {
            REPLY_COLUMN
        } else {
            "NULL"
        },
    )
}

/// A keyed store's open ([`sealed::prepare_schema`]): the table created
/// keyed when it is missing, and clear rows an older build of the pack left
/// behind moved forward, in one IMMEDIATE transaction that reads the table's
/// and the heads' shape again. `false`: the heads are clear now (an unseal
/// moved the store back since the open read its shape; review C-2), nothing
/// is changed and the open reads the store again.
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

/// The role of `session_id`'s letter row, if it has one (a clear column in
/// either layout).
pub(super) fn role_of(
    conn: &Connection,
    session_id: &[u8; 32],
) -> Result<Option<LetterRole>, IndexedSessionStoreError> {
    let role: Option<i64> = conn
        .query_row(
            &format!("SELECT role FROM {LETTER} WHERE session_id = ?1"),
            params![session_id.as_slice()],
            |row| row.get(0),
        )
        .optional()?;
    match role {
        None => Ok(None),
        Some(role) => LetterRole::from_i64(role)
            .map(Some)
            .ok_or(IndexedSessionStoreError::CorruptEndpointState),
    }
}

/// How many provisional message indices `state`'s session may seal (read
/// in the caller's transaction): [`crate::horizon::LETTER_SESSION_MAX_MESSAGES`]
/// for a provisional initiator's Message in a session this node started for
/// a letter ([`LetterRole::Initiator`]), 1 (index 0 only) for every other.
/// ACKs and provisional responders get nothing from it: the caller refuses
/// them before the cap counts.
pub(super) fn provisional_message_cap(
    conn: &Connection,
    state: &ProtectedSessionState,
    kind: EndpointOutboundKind,
) -> Result<u32, IndexedSessionStoreError> {
    if state.binding.lifecycle != SessionLifecycle::Provisional
        || state.binding.local_role != LocalRole::Initiator
        || kind != EndpointOutboundKind::Message
    {
        return Ok(1);
    }
    Ok(match role_of(conn, &state.binding.session_id)? {
        Some(LetterRole::Initiator) => crate::horizon::LETTER_SESSION_MAX_MESSAGES,
        _ => 1,
    })
}

/// `session_id`'s row. A keyed row whose `meta` does not open fails (fail
/// closed).
fn load(
    conn: &Connection,
    layout: &Layout,
    session_id: &[u8; 32],
) -> Result<Option<LetterSession>, IndexedSessionStoreError> {
    if let Some(sealer) = layout.keyed() {
        let raw: Option<(Vec<u8>, i64, Vec<u8>)> = conn
            .query_row(
                &format!("SELECT kh_peer_device, role, meta FROM {LETTER} WHERE session_id = ?1"),
                params![session_id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((kp, role, meta)) = raw else {
            return Ok(None);
        };
        let meta: LetterMeta = sealer.open(LETTER, session_id, &meta)?;
        return match row_of(*session_id, role, &meta) {
            Some(row) if sealer.device(&row.peer_device).as_slice() == kp.as_slice() => {
                Ok(Some(row))
            }
            _ => Err(IndexedSessionStoreError::CorruptEndpointState),
        };
    }
    type ClearRow = (Vec<u8>, i64, Option<Vec<u8>>, i64);
    let raw: Option<ClearRow> = conn
        .query_row(
            &format!(
                "SELECT peer_device, role, pair_init, created_at_ms FROM {LETTER}
                 WHERE session_id = ?1"
            ),
            params![session_id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let Some((peer, role, pair_init, created)) = raw else {
        return Ok(None);
    };
    let role = LetterRole::from_i64(role).ok_or(IndexedSessionStoreError::CorruptEndpointState)?;
    Ok(Some(LetterSession {
        session_id: *session_id,
        peer_device: exact_array(&peer)?,
        role,
        pair_init,
        created_at_ms: u64::try_from(created).unwrap_or(0),
    }))
}

fn insert(
    conn: &Connection,
    layout: &Layout,
    row: &LetterSession,
    reply: Option<&[u8]>,
) -> Result<(), IndexedSessionStoreError> {
    if let Some(sealer) = layout.keyed() {
        conn.execute(
            &format!(
                "INSERT INTO {LETTER} (session_id, kh_peer_device, role, meta)
                 VALUES (?1, ?2, ?3, ?4)"
            ),
            params![
                row.session_id.as_slice(),
                sealer.device(&row.peer_device).as_slice(),
                row.role as i64,
                sealer.seal(LETTER, &row.session_id, &meta_of(row, reply)),
            ],
        )?;
        return Ok(());
    }
    conn.execute(
        &format!(
            "INSERT INTO {LETTER}
               (session_id, peer_device, role, pair_init, created_at_ms, pair_response)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)"
        ),
        params![
            row.session_id.as_slice(),
            row.peer_device.as_slice(),
            row.role as i64,
            row.pair_init,
            ms(row.created_at_ms),
            reply,
        ],
    )?;
    Ok(())
}

/// `session_id`'s kept PairResponse, if its row has one. A keyed row whose
/// `meta` does not open fails (fail closed).
fn load_reply(
    conn: &Connection,
    layout: &Layout,
    session_id: &[u8; 32],
) -> Result<Option<Vec<u8>>, IndexedSessionStoreError> {
    if let Some(sealer) = layout.keyed() {
        let raw: Option<(i64, Vec<u8>)> = conn
            .query_row(
                &format!("SELECT role, meta FROM {LETTER} WHERE session_id = ?1"),
                params![session_id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((role, meta)) = raw else {
            return Ok(None);
        };
        let meta: LetterMeta = sealer.open(LETTER, session_id, &meta)?;
        let role =
            LetterRole::from_i64(role).ok_or(IndexedSessionStoreError::CorruptEndpointState)?;
        return reply_of(role, &meta).map_err(|()| IndexedSessionStoreError::CorruptEndpointState);
    }
    let reply: Option<Option<Vec<u8>>> = conn
        .query_row(
            &format!(
                "SELECT {} FROM {LETTER} WHERE session_id = ?1",
                reply_select(conn)?
            ),
            params![session_id.as_slice()],
            |row| row.get(0),
        )
        .optional()?;
    Ok(reply.flatten())
}

/// Store `reply` on `session_id`'s row (which has none yet).
fn set_reply(
    conn: &Connection,
    layout: &Layout,
    row: &LetterSession,
    reply: &[u8],
) -> Result<(), IndexedSessionStoreError> {
    let changed = match layout.keyed() {
        Some(sealer) => conn.execute(
            &format!("UPDATE {LETTER} SET meta = ?2 WHERE session_id = ?1"),
            params![
                row.session_id.as_slice(),
                sealer.seal(LETTER, &row.session_id, &meta_of(row, Some(reply))),
            ],
        )?,
        None => conn.execute(
            &format!("UPDATE {LETTER} SET {REPLY_COLUMN} = ?2 WHERE session_id = ?1"),
            params![row.session_id.as_slice(), reply],
        )?,
    };
    if changed != 1 {
        return Err(IndexedSessionStoreError::CorruptEndpointState);
    }
    Ok(())
}

/// The session ids of `peer`'s letter rows of `role`.
fn sessions_of(
    conn: &Connection,
    layout: &Layout,
    peer: &[u8; 32],
    role: LetterRole,
) -> Result<Vec<[u8; 32]>, IndexedSessionStoreError> {
    let (column, device) = match layout.keyed() {
        Some(sealer) => ("kh_peer_device", sealer.device(peer)),
        None => ("peer_device", *peer),
    };
    let mut statement = conn.prepare(&format!(
        "SELECT session_id FROM {LETTER} WHERE {column} = ?1 AND role = ?2"
    ))?;
    let ids = statement
        .query_map(params![device.as_slice(), role as i64], |row| {
            row.get::<_, Vec<u8>>(0)
        })?
        .collect::<Result<Vec<_>, _>>()?;
    ids.iter().map(|id| exact_array(id)).collect()
}

impl IndexedSessionStore {
    /// Mark `key`'s session as a letter session of `role`, once: the peer is
    /// the other device of the key, the time the head's start. `pair_init`
    /// is the exact PairInit wire of a session this node started
    /// ([`LetterRole::Initiator`]) and `None` for one it accepted. Marking
    /// it again with the same values is a no-op; other values are a
    /// [`IndexedSessionStoreError::BindingConflict`].
    pub fn mark_letter_session(
        &mut self,
        key: &IndexedSessionRecordKey,
        role: LetterRole,
        pair_init: Option<&[u8]>,
    ) -> Result<(), IndexedSessionStoreError> {
        if !valid(role, pair_init) {
            return Err(IndexedSessionStoreError::InvalidBinding);
        }
        let (session_id, initiator, responder, created, _) = self.head_summary(key)?;
        let row = LetterSession {
            session_id,
            peer_device: match role {
                LetterRole::Initiator => responder,
                LetterRole::Responder => initiator,
            },
            role,
            pair_init: pair_init.map(<[u8]>::to_vec),
            created_at_ms: created,
        };
        let layout = &self.layout;
        sealed::in_write_tx(&self.conn, |conn| match load(conn, layout, &session_id)? {
            Some(existing) if existing == row => Ok(()),
            Some(_) => Err(IndexedSessionStoreError::BindingConflict),
            None => insert(conn, layout, &row, None),
        })
    }

    /// Mark `key`'s session as one this node accepted from a letter
    /// ([`LetterRole::Responder`]) and keep `pair_response`, the exact
    /// PairResponse wire it answered with: the REPLY letter carries it back,
    /// possibly days later ([`Self::letter_reply`]). Once only: the same
    /// values again are a no-op, a row marked without a PairResponse gets
    /// this one, and anything else is a
    /// [`IndexedSessionStoreError::BindingConflict`].
    pub fn mark_letter_responder(
        &mut self,
        key: &IndexedSessionRecordKey,
        pair_response: &[u8],
    ) -> Result<(), IndexedSessionStoreError> {
        if !valid_reply(LetterRole::Responder, Some(pair_response)) {
            return Err(IndexedSessionStoreError::InvalidBinding);
        }
        let (session_id, initiator, _, created, _) = self.head_summary(key)?;
        let row = LetterSession {
            session_id,
            peer_device: initiator,
            role: LetterRole::Responder,
            pair_init: None,
            created_at_ms: created,
        };
        let layout = &self.layout;
        sealed::in_write_tx(&self.conn, |conn| match load(conn, layout, &session_id)? {
            Some(existing) if existing == row => match load_reply(conn, layout, &session_id)? {
                Some(kept) if kept == pair_response => Ok(()),
                Some(_) => Err(IndexedSessionStoreError::BindingConflict),
                None => set_reply(conn, layout, &row, pair_response),
            },
            Some(_) => Err(IndexedSessionStoreError::BindingConflict),
            None => insert(conn, layout, &row, Some(pair_response)),
        })
    }

    /// The PairResponse wire kept for `session_id`, a session this node
    /// accepted from a letter ([`Self::mark_letter_responder`]); `None` for
    /// any other session.
    pub fn letter_reply(
        &self,
        session_id: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, IndexedSessionStoreError> {
        load_reply(&self.conn, &self.layout, session_id)
    }

    /// `session_id`'s letter row, if it is a letter session.
    pub fn letter_session(
        &self,
        session_id: &[u8; 32],
    ) -> Result<Option<LetterSession>, IndexedSessionStoreError> {
        load(&self.conn, &self.layout, session_id)
    }

    /// `session_id`'s letter role, if it is a letter session.
    pub fn letter_role(
        &self,
        session_id: &[u8; 32],
    ) -> Result<Option<LetterRole>, IndexedSessionStoreError> {
        role_of(&self.conn, session_id)
    }

    /// The next message index `key`'s session would seal (its message
    /// lane's `next_index`, P5.15): a letter session this node started takes
    /// indices below [`crate::horizon::LETTER_SESSION_MAX_MESSAGES`] while it
    /// is provisional.
    pub fn message_send_next_index(
        &mut self,
        key: &IndexedSessionRecordKey,
    ) -> Result<u64, IndexedSessionStoreError> {
        self.recover_pending_for_key(key)?;
        let record_key = record_key_digest(key)?;
        let account = hex::encode(record_key);
        let backend = Arc::clone(&self.backend);
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let _in_tx = crate::paths::HeldMark::transaction();
        let state = load_and_reconcile(&tx, &self.layout, backend.as_ref(), &account, &record_key)?;
        if &state.binding.key != key {
            return Err(IndexedSessionStoreError::BindingConflict);
        }
        let next = state.ratchets.message_send.next_index;
        drop(state);
        tx.commit()?;
        Ok(next)
    }

    /// `peer`'s letter sessions of `role` that have not expired at `now_ms`,
    /// with their keys, newest first (by start, then session id). A head
    /// gone or expired is skipped (the prune takes its row with it).
    pub fn live_letter_sessions_for_peer(
        &self,
        peer: &[u8; 32],
        role: LetterRole,
        now_ms: u64,
    ) -> Result<Vec<(IndexedSessionRecordKey, LetterSession)>, IndexedSessionStoreError> {
        let mut out = Vec::new();
        for session_id in sessions_of(&self.conn, &self.layout, peer, role)? {
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
                continue;
            };
            let head = self.layout.head(raw)?;
            if u64::try_from(head.expires_at_ms).unwrap_or(0) <= now_ms {
                continue;
            }
            if let Some(row) = load(&self.conn, &self.layout, &session_id)? {
                out.push((head.key, row));
            }
        }
        out.sort_by(|(_, a), (_, b)| {
            b.created_at_ms
                .cmp(&a.created_at_ms)
                .then(b.session_id.cmp(&a.session_id))
        });
        Ok(out)
    }

    /// Whether `session_id` is letter-class: it has a letter row, or the
    /// peer started it for longer than a LAN session
    /// ([`super::parked::session_is_letter_class`], the only signal a
    /// responder of an older letter path has). Such a session never takes a
    /// new direct Message ([`Self::find_sendable_sessions_for_peer_at`]).
    pub(super) fn session_is_letter_class(
        &self,
        session_id: &[u8; 32],
        peer_initiated: bool,
        created_ms: u64,
        expires_ms: u64,
    ) -> Result<bool, IndexedSessionStoreError> {
        Ok(
            super::parked::session_is_letter_class(peer_initiated, created_ms, expires_ms)
                || role_of(&self.conn, session_id)?.is_some(),
        )
    }
}

/// Schema 1 -> 4's part for this table ([`sealed::migrate_forward`], a
/// re-key's way forward, and [`ensure_keyed`]): the clear rows rebuilt
/// keyed, rowids kept. The rows moved.
pub(super) fn move_forward(
    tx: &Transaction<'_>,
    keys: &MetaKeys,
    steps: &mut Steps,
) -> Result<u32, RebuildError> {
    steps.step()?;
    tx.execute_batch(&format!(
        "CREATE TABLE {LETTER}__new ({});",
        letter_columns(true)
    ))?;
    type ClearRow = (
        i64,
        Vec<u8>,
        Vec<u8>,
        i64,
        Option<Vec<u8>>,
        i64,
        Option<Vec<u8>>,
    );
    let rows: Vec<ClearRow> = {
        // A clear table P5.12 made has no PairResponse column.
        let mut statement = tx.prepare(&format!(
            "SELECT rowid, session_id, peer_device, role, pair_init, created_at_ms, {}
             FROM {LETTER}",
            reply_select(tx)?
        ))?;
        let mapped = statement.query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
            ))
        })?;
        mapped.collect::<Result<_, _>>()?
    };
    let mut moved = 0u32;
    for (rowid, session_id, peer, role, pair_init, created, reply) in rows {
        steps.step()?;
        let kp = at_rest::index(keys, ValueType::DeviceKey, &peer);
        let meta = LetterMeta {
            peer_device: hex::encode(&peer),
            pair_init: pair_init.as_deref().map(hex::encode).unwrap_or_default(),
            created_at_ms: created,
            pair_response: reply.as_deref().map(hex::encode).unwrap_or_default(),
        };
        let plain =
            Zeroizing::new(serde_json::to_vec(&meta).expect("strings and numbers serialize"));
        tx.execute(
            &format!(
                "INSERT INTO {LETTER}__new (rowid, session_id, kh_peer_device, role, meta)
                 VALUES (?1, ?2, ?3, ?4, ?5)"
            ),
            params![
                rowid,
                session_id,
                kp.as_slice(),
                role,
                at_rest::seal_row(keys, LETTER, &session_id, &plain),
            ],
        )?;
        moved += 1;
    }
    steps.step()?;
    tx.execute_batch(&format!("DROP TABLE {LETTER};"))?;
    steps.step()?;
    tx.execute_batch(&format!("ALTER TABLE {LETTER}__new RENAME TO {LETTER};"))?;
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
        "CREATE TABLE {LETTER}__new ({});",
        letter_columns(false)
    ))?;
    type KeyedRow = (i64, Vec<u8>, i64, Vec<u8>);
    let rows: Vec<KeyedRow> = {
        let mut statement = tx.prepare(&format!(
            "SELECT rowid, session_id, role, meta FROM {LETTER}"
        ))?;
        let mapped = statement.query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?;
        mapped.collect::<Result<_, _>>()?
    };
    // The keyed device is not compared: a re-key's way back holds keys whose
    // index key is already the new one.
    for (rowid, session_id, role, meta) in rows {
        steps.step()?;
        let opened = <[u8; 32]>::try_from(session_id.as_slice())
            .ok()
            .and_then(|sid| {
                let plain = at_rest::open_row(keys, LETTER, &sid, &meta).ok()?;
                let meta = serde_json::from_slice::<LetterMeta>(&plain).ok()?;
                let row = row_of(sid, role, &meta)?;
                let reply = reply_of(row.role, &meta).ok()?;
                Some((row, reply))
            });
        let Some((row, reply)) = opened else {
            sealed::dropped(expected, LETTER, report);
            continue;
        };
        tx.execute(
            &format!(
                "INSERT INTO {LETTER}__new
                   (rowid, session_id, peer_device, role, pair_init, created_at_ms,
                    pair_response)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"
            ),
            params![
                rowid,
                row.session_id.as_slice(),
                row.peer_device.as_slice(),
                row.role as i64,
                row.pair_init,
                ms(row.created_at_ms),
                reply,
            ],
        )?;
        report.rows += 1;
    }
    steps.step()?;
    tx.execute_batch(&format!("DROP TABLE {LETTER};"))?;
    steps.step()?;
    tx.execute_batch(&format!("ALTER TABLE {LETTER}__new RENAME TO {LETTER};"))?;
    Ok(())
}
