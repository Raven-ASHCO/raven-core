//! The session store's endpoint tables at rest (privacy pack PP.14;
//! docs/design/2026-10-at-rest-metadata.md sections 4.12 and 7.3).
//!
//! Since schema 3 (schema 4, [`METADATA_SCHEMA_VERSION`], changed only the
//! heads) the receipts, the inbox, the ACK intents, the outstanding
//! messages, the ACK receipts, the outbox and the inbox tombstones (PP.8)
//! hold their message ids, object digests, device keys and wire nonces as
//! keyed lookups (`kh_*`, by value type, so the primary keys, the UNIQUE
//! constraints and the foreign keys keep their shape: equal values give
//! equal keys). Every clear value and time is in
//! the row's sealed `meta` (AAD: the table and the row's key as stored). The
//! stored wire objects (`immutable_envelope_bytes`, `immutable_ack_bytes`)
//! are sealed whole, with a keyed digest of the exact bytes beside them
//! (`kh_envelope`, `kh_ack`, value type `object-bytes`): the equality checks
//! that compared the bytes compare the digests (a random-nonce seal is
//! never equal twice; review R20). `endpoint_inbox.sealed_local_row` is not
//! sealed again: it is under the session's own key, its AAD binds the clear
//! session id, object digest, message id and sender device (the reader
//! takes them from `meta`), and a journal's replay compares its bytes
//! exactly. Kept clear: `session_id`, `kind`, `state`, `status`,
//! `delivery_state`, `ratchet_index` and `session_generation`.
//!
//! **The inbox order.** A clear store pages a sender's inbox by
//! `(received_at_ms, message_id)`; a keyed message id and a sealed time
//! cannot serve that, so the schema-3 inbox has an insertion `seq` (its
//! rowid, `AUTOINCREMENT`: never used twice, even after the newest row
//! goes). A reader's place is an [`InboxPosition`] in the order of the store
//! it was taken in; the store moves a position of the other order
//! ([`IndexedSessionStore::resolve_inbox_position`]), so a cursor saved
//! before the move shows every later row once and none twice.
//!
//! **The SQL** of the store's queries is written once, with the keyed
//! column names; [`Layout::ep`] gives the clear names in schema 1 and 2, and
//! the values are bound in their stored form ([`Layout::ep_digest`] and its
//! siblings). Rows are read in either shape and handed on as the clear
//! values schema 1 holds.

use std::collections::{HashMap, HashSet};

use rusqlite::types::Value;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::sealed::{self, Layout, SealedColumn, Sealer};
use super::*;
use crate::at_rest::{self, MetaKeys, ValueType};
use crate::sqlite_rebuild::{self as rebuild, Migration, RebuildError, Steps};

pub(super) const RECEIPTS: &str = "endpoint_receipts";
pub(super) const INBOX: &str = "endpoint_inbox";
pub(super) const ACK_INTENTS: &str = "endpoint_ack_intents";
pub(super) const OUTSTANDING: &str = "endpoint_outstanding_messages";
pub(super) const ACK_RECEIPTS: &str = "endpoint_ack_receipts";
pub(super) const OUTBOX: &str = "endpoint_outbox";
pub(super) const DELETED: &str = "endpoint_inbox_deleted";

/// The keyed column of `endpoint_receipts` that tells the two shapes apart.
const KEYED_COLUMN: &str = "kh_object_digest";

/// The AAD labels of the sealed wire objects.
pub(super) const ENVELOPE_LABEL: &str = "endpoint_outbox.immutable_envelope_bytes";
pub(super) const ACK_LABEL: &str = "endpoint_ack_intents.immutable_ack_bytes";

/// What sealing adds to a value (format byte, epoch, nonce and tag).
pub(super) const SEALED_OVERHEAD: usize = 1 + at_rest::EPOCH_BODY_OVERHEAD;

/// The sealed values of the endpoint tables in schema 3.
pub(super) const SEALED: [SealedColumn; 9] = [
    (
        RECEIPTS,
        "meta",
        RECEIPTS,
        &["session_id", "kh_object_digest"],
    ),
    (INBOX, "meta", INBOX, &["session_id", "kh_object_digest"]),
    (
        ACK_INTENTS,
        "meta",
        ACK_INTENTS,
        &["session_id", "kh_object_digest"],
    ),
    (
        ACK_INTENTS,
        "immutable_ack_bytes",
        ACK_LABEL,
        &["session_id", "kh_object_digest"],
    ),
    (
        OUTSTANDING,
        "meta",
        OUTSTANDING,
        &["session_id", "kh_message_id", "kh_recipient_device"],
    ),
    (
        ACK_RECEIPTS,
        "meta",
        ACK_RECEIPTS,
        &["session_id", "kh_object_digest"],
    ),
    (OUTBOX, "meta", OUTBOX, &["session_id", "kh_object_digest"]),
    (
        OUTBOX,
        "immutable_envelope_bytes",
        ENVELOPE_LABEL,
        &["session_id", "kh_object_digest"],
    ),
    (
        DELETED,
        "meta",
        DELETED,
        &["session_id", "kh_object_digest"],
    ),
];

/// Whether the endpoint tables are keyed (schema 3).
pub(super) fn keyed(conn: &Connection) -> rusqlite::Result<bool> {
    Ok(rebuild::shape(conn, RECEIPTS, KEYED_COLUMN)? == rebuild::Shape::Keyed)
}

// ── Schemas ──────────────────────────────────────────────────────────────

/// A table's columns in schema 1 and 2, exactly as every older build
/// creates them (`ENDPOINT_SCHEMA`, and PP.8's tombstones).
pub(super) fn clear_columns(table: &str) -> &'static str {
    match table {
        RECEIPTS => {
            "session_id BLOB NOT NULL CHECK(length(session_id) = 32),
               object_digest BLOB NOT NULL CHECK(length(object_digest) = 32),
               message_id BLOB NOT NULL CHECK(length(message_id) = 16),
               sender_device BLOB NOT NULL CHECK(length(sender_device) = 32),
               session_generation INTEGER NOT NULL CHECK(session_generation >= 0),
               PRIMARY KEY(session_id, object_digest),
               UNIQUE(session_id, sender_device, message_id),
               FOREIGN KEY(session_id) REFERENCES indexed_session_heads(session_id)"
        }
        INBOX => {
            "session_id BLOB NOT NULL CHECK(length(session_id) = 32),
               object_digest BLOB NOT NULL CHECK(length(object_digest) = 32),
               message_id BLOB NOT NULL CHECK(length(message_id) = 16),
               sender_device BLOB NOT NULL CHECK(length(sender_device) = 32),
               created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
               received_at_ms INTEGER NOT NULL CHECK(received_at_ms >= 0),
               sealed_local_row BLOB NOT NULL,
               PRIMARY KEY(session_id, object_digest),
               FOREIGN KEY(session_id, object_digest)
                 REFERENCES endpoint_receipts(session_id, object_digest)"
        }
        ACK_INTENTS => {
            "session_id BLOB NOT NULL CHECK(length(session_id) = 32),
               object_digest BLOB NOT NULL CHECK(length(object_digest) = 32),
               message_id BLOB NOT NULL CHECK(length(message_id) = 16),
               remote_device BLOB NOT NULL CHECK(length(remote_device) = 32),
               status INTEGER NOT NULL CHECK(status IN (1, 2)),
               state INTEGER NOT NULL CHECK(state IN (0, 1)),
               immutable_ack_bytes BLOB,
               PRIMARY KEY(session_id, object_digest),
               FOREIGN KEY(session_id, object_digest)
                 REFERENCES endpoint_receipts(session_id, object_digest)"
        }
        OUTSTANDING => {
            "session_id BLOB NOT NULL CHECK(length(session_id) = 32),
               message_id BLOB NOT NULL CHECK(length(message_id) = 16),
               recipient_device BLOB NOT NULL CHECK(length(recipient_device) = 32),
               delivery_state INTEGER NOT NULL CHECK(delivery_state IN (0, 1, 2)),
               PRIMARY KEY(session_id, message_id, recipient_device),
               FOREIGN KEY(session_id) REFERENCES indexed_session_heads(session_id)"
        }
        ACK_RECEIPTS => {
            "session_id BLOB NOT NULL CHECK(length(session_id) = 32),
               object_digest BLOB NOT NULL CHECK(length(object_digest) = 32),
               outer_message_id BLOB NOT NULL CHECK(length(outer_message_id) = 16),
               remote_device BLOB NOT NULL CHECK(length(remote_device) = 32),
               acked_message_id BLOB NOT NULL CHECK(length(acked_message_id) = 16),
               status INTEGER NOT NULL CHECK(status IN (1, 2)),
               ack_nonce BLOB NOT NULL CHECK(length(ack_nonce) = 12),
               created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
               session_generation INTEGER NOT NULL CHECK(session_generation >= 0),
               PRIMARY KEY(session_id, object_digest),
               UNIQUE(session_id, remote_device, outer_message_id),
               UNIQUE(session_id, remote_device, ack_nonce),
               FOREIGN KEY(session_id) REFERENCES indexed_session_heads(session_id)"
        }
        OUTBOX => {
            "session_id BLOB NOT NULL CHECK(length(session_id) = 32),
               object_digest BLOB NOT NULL CHECK(length(object_digest) = 32),
               kind INTEGER NOT NULL CHECK(kind IN (1, 2)),
               message_id BLOB NOT NULL CHECK(length(message_id) = 16),
               recipient_device BLOB NOT NULL CHECK(length(recipient_device) = 32),
               ratchet_index INTEGER NOT NULL CHECK(ratchet_index >= 0),
               source_ack_intent BLOB CHECK(source_ack_intent IS NULL OR length(source_ack_intent) = 32),
               ack_nonce BLOB CHECK(ack_nonce IS NULL OR length(ack_nonce) = 12),
               seal_nonce BLOB NOT NULL CHECK(length(seal_nonce) = 12),
               anti_replay_nonce BLOB NOT NULL CHECK(length(anti_replay_nonce) = 12),
               immutable_envelope_bytes BLOB NOT NULL
                 CHECK(length(immutable_envelope_bytes) >= 86
                   AND length(immutable_envelope_bytes) <= 262656),
               state INTEGER NOT NULL CHECK(state IN (0, 1)),
               session_generation INTEGER NOT NULL CHECK(session_generation >= 0),
               PRIMARY KEY(session_id, object_digest),
               UNIQUE(session_id, message_id),
               UNIQUE(session_id, seal_nonce),
               UNIQUE(session_id, anti_replay_nonce),
               UNIQUE(session_id, ack_nonce),
               UNIQUE(session_id, source_ack_intent),
               CHECK((kind = 1 AND source_ack_intent IS NULL AND ack_nonce IS NULL)
                  OR (kind = 2 AND source_ack_intent IS NOT NULL AND ack_nonce IS NOT NULL)),
               FOREIGN KEY(session_id) REFERENCES indexed_session_heads(session_id)"
        }
        _ => {
            "session_id BLOB NOT NULL CHECK(length(session_id) = 32),
           object_digest BLOB NOT NULL CHECK(length(object_digest) = 32),
           sender_device BLOB NOT NULL CHECK(length(sender_device) = 32),
           deleted_at_ms INTEGER NOT NULL CHECK(deleted_at_ms >= 0),
           max_received_at_ms INTEGER NOT NULL CHECK(max_received_at_ms >= 0),
           PRIMARY KEY(session_id, object_digest)"
        }
    }
}

/// A 32-byte keyed column.
fn kh(name: &str, nullable: bool) -> String {
    if nullable {
        format!("{name} BLOB CHECK({name} IS NULL OR length({name}) = 32)")
    } else {
        format!("{name} BLOB NOT NULL CHECK(length({name}) = 32)")
    }
}

/// A table's columns in schema 3: the same keys, UNIQUE constraints and
/// foreign keys over the keyed columns.
fn keyed_columns(table: &str) -> String {
    let sid = "session_id BLOB NOT NULL CHECK(length(session_id) = 32)";
    let digest = kh("kh_object_digest", false);
    match table {
        RECEIPTS => format!(
            "{sid}, {digest}, {}, {},
             session_generation INTEGER NOT NULL CHECK(session_generation >= 0),
             meta BLOB NOT NULL,
             PRIMARY KEY(session_id, kh_object_digest),
             UNIQUE(session_id, kh_sender_device, kh_message_id),
             FOREIGN KEY(session_id) REFERENCES indexed_session_heads(session_id)",
            kh("kh_message_id", false),
            kh("kh_sender_device", false),
        ),
        INBOX => format!(
            "seq INTEGER PRIMARY KEY AUTOINCREMENT,
             {sid}, {digest}, {}, {},
             meta BLOB NOT NULL,
             sealed_local_row BLOB NOT NULL,
             UNIQUE(session_id, kh_object_digest),
             FOREIGN KEY(session_id, kh_object_digest)
               REFERENCES endpoint_receipts(session_id, kh_object_digest)",
            kh("kh_message_id", false),
            kh("kh_sender_device", false),
        ),
        ACK_INTENTS => format!(
            "{sid}, {digest}, {}, {},
             status INTEGER NOT NULL CHECK(status IN (1, 2)),
             state INTEGER NOT NULL CHECK(state IN (0, 1)),
             immutable_ack_bytes BLOB,
             {},
             meta BLOB NOT NULL,
             CHECK((immutable_ack_bytes IS NULL) = (kh_ack IS NULL)),
             PRIMARY KEY(session_id, kh_object_digest),
             FOREIGN KEY(session_id, kh_object_digest)
               REFERENCES endpoint_receipts(session_id, kh_object_digest)",
            kh("kh_message_id", false),
            kh("kh_remote_device", false),
            kh("kh_ack", true),
        ),
        OUTSTANDING => format!(
            "{sid}, {}, {},
             delivery_state INTEGER NOT NULL CHECK(delivery_state IN (0, 1, 2)),
             meta BLOB NOT NULL,
             PRIMARY KEY(session_id, kh_message_id, kh_recipient_device),
             FOREIGN KEY(session_id) REFERENCES indexed_session_heads(session_id)",
            kh("kh_message_id", false),
            kh("kh_recipient_device", false),
        ),
        ACK_RECEIPTS => format!(
            "{sid}, {digest}, {}, {}, {},
             status INTEGER NOT NULL CHECK(status IN (1, 2)),
             {},
             session_generation INTEGER NOT NULL CHECK(session_generation >= 0),
             meta BLOB NOT NULL,
             PRIMARY KEY(session_id, kh_object_digest),
             UNIQUE(session_id, kh_remote_device, kh_outer_message_id),
             UNIQUE(session_id, kh_remote_device, kh_ack_nonce),
             FOREIGN KEY(session_id) REFERENCES indexed_session_heads(session_id)",
            kh("kh_outer_message_id", false),
            kh("kh_remote_device", false),
            kh("kh_acked_message_id", false),
            kh("kh_ack_nonce", false),
        ),
        OUTBOX => format!(
            "{sid}, {digest},
             kind INTEGER NOT NULL CHECK(kind IN (1, 2)),
             {}, {},
             ratchet_index INTEGER NOT NULL CHECK(ratchet_index >= 0),
             {}, {}, {}, {},
             immutable_envelope_bytes BLOB NOT NULL
               CHECK(length(immutable_envelope_bytes) >= {}
                 AND length(immutable_envelope_bytes) <= {}),
             {},
             state INTEGER NOT NULL CHECK(state IN (0, 1)),
             session_generation INTEGER NOT NULL CHECK(session_generation >= 0),
             meta BLOB NOT NULL,
             PRIMARY KEY(session_id, kh_object_digest),
             UNIQUE(session_id, kh_message_id),
             UNIQUE(session_id, kh_seal_nonce),
             UNIQUE(session_id, kh_anti_replay_nonce),
             UNIQUE(session_id, kh_ack_nonce),
             UNIQUE(session_id, kh_source_ack_intent),
             CHECK((kind = 1 AND kh_source_ack_intent IS NULL AND kh_ack_nonce IS NULL)
                OR (kind = 2 AND kh_source_ack_intent IS NOT NULL AND kh_ack_nonce IS NOT NULL)),
             FOREIGN KEY(session_id) REFERENCES indexed_session_heads(session_id)",
            kh("kh_message_id", false),
            kh("kh_recipient_device", false),
            kh("kh_source_ack_intent", true),
            kh("kh_ack_nonce", true),
            kh("kh_seal_nonce", false),
            kh("kh_anti_replay_nonce", false),
            // The clear column's bounds, sealed.
            86 + SEALED_OVERHEAD,
            262_656 + SEALED_OVERHEAD,
            kh("kh_envelope", false),
        ),
        _ => format!(
            "{sid}, {digest}, {},
             seq INTEGER NOT NULL CHECK(seq >= 0),
             meta BLOB NOT NULL,
             PRIMARY KEY(session_id, kh_object_digest)",
            kh("kh_sender_device", false),
        ),
    }
}

/// The indexes of schema 3 (a sender's inbox and tombstones by `seq`).
fn keyed_indexes(table: &str) -> &'static str {
    match table {
        INBOX => {
            "CREATE INDEX IF NOT EXISTS endpoint_inbox_by_sender
             ON endpoint_inbox(kh_sender_device, seq);"
        }
        DELETED => {
            "CREATE INDEX IF NOT EXISTS endpoint_inbox_deleted_by_sender
             ON endpoint_inbox_deleted(kh_sender_device, seq);"
        }
        _ => "",
    }
}

/// The endpoint tables in the order they are rebuilt (each after the
/// tables its rows refer to).
pub(super) const TABLES: [&str; 7] = [
    RECEIPTS,
    INBOX,
    ACK_INTENTS,
    OUTSTANDING,
    ACK_RECEIPTS,
    OUTBOX,
    DELETED,
];

/// A sealed profile's first store: the endpoint tables in schema 3.
pub(super) fn create_keyed(conn: &Connection) -> Result<(), IndexedSessionStoreError> {
    for table in TABLES {
        conn.execute_batch(&sealed::create_if_missing(table, &keyed_columns(table)))?;
        conn.execute_batch(keyed_indexes(table))?;
    }
    Ok(())
}

// ── Sealed values ────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
pub(super) struct ReceiptMeta {
    pub object_digest: String,
    pub message_id: String,
    pub sender_device: String,
}

#[derive(Serialize, Deserialize)]
pub(super) struct InboxMeta {
    pub object_digest: String,
    pub message_id: String,
    pub sender_device: String,
    pub created_at_ms: i64,
    pub received_at_ms: i64,
}

#[derive(Serialize, Deserialize)]
pub(super) struct AckIntentMeta {
    pub object_digest: String,
    pub message_id: String,
    pub remote_device: String,
}

#[derive(Serialize, Deserialize)]
pub(super) struct OutstandingMeta {
    pub message_id: String,
    pub recipient_device: String,
}

#[derive(Serialize, Deserialize)]
pub(super) struct AckReceiptMeta {
    pub object_digest: String,
    pub outer_message_id: String,
    pub remote_device: String,
    pub acked_message_id: String,
    pub ack_nonce: String,
    pub created_at_ms: i64,
}

#[derive(Serialize, Deserialize)]
pub(super) struct OutboxMeta {
    pub object_digest: String,
    pub message_id: String,
    pub recipient_device: String,
    pub source_ack_intent: Option<String>,
    pub ack_nonce: Option<String>,
    pub seal_nonce: String,
    pub anti_replay_nonce: String,
}

#[derive(Serialize, Deserialize)]
pub(super) struct DeletedMeta {
    pub object_digest: String,
    pub sender_device: String,
    pub deleted_at_ms: i64,
    pub max_received_at_ms: i64,
}

fn unhex(value: &str) -> Result<Vec<u8>, IndexedSessionStoreError> {
    hex::decode(value).map_err(|_| IndexedSessionStoreError::CorruptEndpointState)
}

fn unhex_opt(value: Option<&String>) -> Result<Option<Vec<u8>>, IndexedSessionStoreError> {
    value.map(|value| unhex(value)).transpose()
}

/// The key a row's sealed values are bound to: its session and the keyed
/// columns of its primary key, as stored.
fn pk(session_id: &[u8], keyed: &[&[u8]]) -> Vec<u8> {
    let mut out = session_id.to_vec();
    for part in keyed {
        out.extend_from_slice(part);
    }
    out
}

// ── The layout's endpoint SQL and values ─────────────────────────────────

impl Layout {
    /// Endpoint SQL written with the keyed column names, for this store: as
    /// written in schema 3; in schema 1 and 2 each `kh_<name>` is the clear
    /// `<name>`, and `kh_envelope` / `kh_ack` are the stored bytes they
    /// digest. Only endpoint-table SQL goes through here (the heads keep
    /// their own keyed names in schema 2).
    pub(super) fn ep(&self, sql: &str) -> String {
        if self.endpoints().is_some() {
            return sql.to_string();
        }
        let word = |c: char| c.is_ascii_alphanumeric() || c == '_';
        let mut out = String::with_capacity(sql.len());
        let mut rest = sql;
        let mut after_word = false;
        while let Some(c) = rest.chars().next() {
            if !after_word && rest.starts_with("kh_") {
                let end = rest.find(|c: char| !word(c)).unwrap_or(rest.len());
                let name = &rest[..end];
                out.push_str(match name {
                    "kh_envelope" => "immutable_envelope_bytes",
                    "kh_ack" => "immutable_ack_bytes",
                    keyed => &keyed[3..],
                });
                rest = &rest[end..];
                after_word = true;
                continue;
            }
            out.push(c);
            after_word = word(c);
            rest = &rest[c.len_utf8()..];
        }
        out
    }

    fn ep_value(&self, value: &[u8], keyed: impl Fn(&Sealer, &[u8]) -> [u8; 32]) -> Vec<u8> {
        match self.endpoints() {
            Some(sealer) => keyed(sealer, value).to_vec(),
            None => value.to_vec(),
        }
    }

    /// An object digest as an endpoint table stores it.
    pub(super) fn ep_digest(&self, digest: &[u8]) -> Vec<u8> {
        self.ep_value(digest, Sealer::digest)
    }

    /// A message id as an endpoint table stores it.
    pub(super) fn ep_mid(&self, message_id: &[u8]) -> Vec<u8> {
        self.ep_value(message_id, Sealer::message_id)
    }

    /// A device key as an endpoint table stores it.
    pub(super) fn ep_device(&self, device: &[u8]) -> Vec<u8> {
        self.ep_value(device, Sealer::device)
    }

    /// A wire nonce as an endpoint table stores it.
    pub(super) fn ep_nonce(&self, nonce: &[u8]) -> Vec<u8> {
        self.ep_value(nonce, Sealer::nonce)
    }

    /// Stored wire bytes as an equality compares them (`kh_envelope`,
    /// `kh_ack`; the bytes themselves in schema 1 and 2).
    pub(super) fn ep_bytes(&self, bytes: &[u8]) -> Vec<u8> {
        self.ep_value(bytes, Sealer::object_bytes)
    }
}

// ── Rows, in either shape ────────────────────────────────────────────────

/// `width` columns of `row` from `at`, as stored.
pub(super) fn raw(
    row: &rusqlite::Row<'_>,
    at: usize,
    width: usize,
) -> rusqlite::Result<Vec<Value>> {
    (at..at + width).map(|i| row.get::<_, Value>(i)).collect()
}

fn take(values: &mut [Value], at: usize) -> Value {
    std::mem::replace(&mut values[at], Value::Null)
}

fn blob(values: &mut [Value], at: usize) -> Result<Vec<u8>, IndexedSessionStoreError> {
    match take(values, at) {
        Value::Blob(bytes) => Ok(bytes),
        _ => Err(IndexedSessionStoreError::CorruptEndpointState),
    }
}

fn opt_blob(values: &mut [Value], at: usize) -> Result<Option<Vec<u8>>, IndexedSessionStoreError> {
    match take(values, at) {
        Value::Null => Ok(None),
        Value::Blob(bytes) => Ok(Some(bytes)),
        _ => Err(IndexedSessionStoreError::CorruptEndpointState),
    }
}

fn int(values: &mut [Value], at: usize) -> Result<i64, IndexedSessionStoreError> {
    match take(values, at) {
        Value::Integer(value) => Ok(value),
        _ => Err(IndexedSessionStoreError::CorruptEndpointState),
    }
}

/// An outbox row with every column as schema 1 holds it.
pub(super) struct OutboxRow {
    pub session_id: Vec<u8>,
    pub object_digest: Vec<u8>,
    pub kind: i64,
    pub message_id: Vec<u8>,
    pub recipient_device: Vec<u8>,
    pub ratchet_index: i64,
    pub source_ack_intent: Option<Vec<u8>>,
    pub ack_nonce: Option<Vec<u8>>,
    pub seal_nonce: Vec<u8>,
    pub anti_replay_nonce: Vec<u8>,
    pub immutable_envelope_bytes: Vec<u8>,
    pub state: i64,
    pub session_generation: i64,
}

impl OutboxRow {
    /// The columns `decode_endpoint_outbound_row` checks.
    pub(super) fn db_row(self) -> EndpointOutboxDbRow {
        (
            self.session_id,
            self.object_digest,
            self.kind,
            self.message_id,
            self.recipient_device,
            self.ratchet_index,
            self.state,
            self.immutable_envelope_bytes,
        )
    }

    /// The columns the binding checks compare.
    pub(super) fn details(&self) -> EndpointOutboxDetailsDbRow {
        (
            self.source_ack_intent.clone(),
            self.ack_nonce.clone(),
            self.seal_nonce.clone(),
            self.anti_replay_nonce.clone(),
            self.session_generation,
        )
    }
}

pub(super) const OUTBOX_WIDTH: usize = 13;

/// The outbox columns a query reads ([`OUTBOX_WIDTH`] in either shape), from
/// `alias` (`"o."`, or `""`).
pub(super) fn outbox_columns(layout: &Layout, alias: &str) -> String {
    let a = alias;
    if layout.endpoints().is_some() {
        format!(
            "{a}session_id, {a}kh_object_digest, {a}kind, {a}meta, NULL, {a}ratchet_index, NULL,
             NULL, NULL, NULL, {a}immutable_envelope_bytes, {a}state, {a}session_generation"
        )
    } else {
        format!(
            "{a}session_id, {a}object_digest, {a}kind, {a}message_id, {a}recipient_device,
             {a}ratchet_index, {a}source_ack_intent, {a}ack_nonce, {a}seal_nonce,
             {a}anti_replay_nonce, {a}immutable_envelope_bytes, {a}state, {a}session_generation"
        )
    }
}

/// An outbox row read with [`outbox_columns`].
pub(super) fn outbox_row(
    layout: &Layout,
    mut v: Vec<Value>,
) -> Result<OutboxRow, IndexedSessionStoreError> {
    let session_id = blob(&mut v, 0)?;
    let stored_digest = blob(&mut v, 1)?;
    let kind = int(&mut v, 2)?;
    let ratchet_index = int(&mut v, 5)?;
    let stored_bytes = blob(&mut v, 10)?;
    let state = int(&mut v, 11)?;
    let session_generation = int(&mut v, 12)?;
    let Some(sealer) = layout.endpoints() else {
        return Ok(OutboxRow {
            session_id,
            object_digest: stored_digest,
            kind,
            message_id: blob(&mut v, 3)?,
            recipient_device: blob(&mut v, 4)?,
            ratchet_index,
            source_ack_intent: opt_blob(&mut v, 6)?,
            ack_nonce: opt_blob(&mut v, 7)?,
            seal_nonce: blob(&mut v, 8)?,
            anti_replay_nonce: blob(&mut v, 9)?,
            immutable_envelope_bytes: stored_bytes,
            state,
            session_generation,
        });
    };
    let key = pk(&session_id, &[&stored_digest]);
    let meta: OutboxMeta = sealer.open(OUTBOX, &key, &blob(&mut v, 3)?)?;
    Ok(OutboxRow {
        object_digest: unhex(&meta.object_digest)?,
        kind,
        message_id: unhex(&meta.message_id)?,
        recipient_device: unhex(&meta.recipient_device)?,
        ratchet_index,
        source_ack_intent: unhex_opt(meta.source_ack_intent.as_ref())?,
        ack_nonce: unhex_opt(meta.ack_nonce.as_ref())?,
        seal_nonce: unhex(&meta.seal_nonce)?,
        anti_replay_nonce: unhex(&meta.anti_replay_nonce)?,
        immutable_envelope_bytes: sealer.open_bytes(ENVELOPE_LABEL, &key, &stored_bytes)?,
        state,
        session_generation,
        session_id,
    })
}

/// The outbox row of `(session_id, object_digest)`.
pub(super) fn outbox_by_object(
    conn: &Connection,
    layout: &Layout,
    session_id: &[u8; 32],
    object_digest: &[u8; 32],
) -> Result<Option<OutboxRow>, IndexedSessionStoreError> {
    let raw_row = conn
        .query_row(
            &layout.ep(&format!(
                "SELECT {} FROM endpoint_outbox WHERE session_id = ?1 AND kh_object_digest = ?2",
                outbox_columns(layout, "")
            )),
            params![session_id.as_slice(), layout.ep_digest(object_digest)],
            |row| raw(row, 0, OUTBOX_WIDTH),
        )
        .optional()?;
    raw_row.map(|v| outbox_row(layout, v)).transpose()
}

/// Every outbox row a query selects (its columns from [`outbox_columns`]
/// first), in the query's order.
pub(super) fn outbox_rows(
    conn: &Connection,
    layout: &Layout,
    sql: &str,
    bind: impl rusqlite::Params,
) -> Result<Vec<OutboxRow>, IndexedSessionStoreError> {
    let mut statement = conn.prepare(&layout.ep(sql))?;
    let rows = statement.query_map(bind, |row| raw(row, 0, OUTBOX_WIDTH))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(outbox_row(layout, row?)?);
    }
    Ok(out)
}

/// A new outbox row (the journal's prepared object).
pub(super) fn insert_outbox(
    conn: &Connection,
    layout: &Layout,
    pending: &PendingOutbound,
) -> Result<(), IndexedSessionStoreError> {
    let Some(sealer) = layout.endpoints() else {
        conn.execute(
            "INSERT INTO endpoint_outbox
             (session_id, object_digest, kind, message_id, recipient_device,
              ratchet_index, source_ack_intent, ack_nonce, seal_nonce, anti_replay_nonce,
              immutable_envelope_bytes, state, session_generation)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 0, ?12)",
            params![
                pending.session_id.as_slice(),
                pending.object_digest.as_slice(),
                pending.kind as u8,
                pending.message_id.as_slice(),
                pending.recipient_device.as_slice(),
                pending.ratchet_index,
                pending
                    .source_ack_intent
                    .as_ref()
                    .map(|value| value.as_slice()),
                pending.ack_nonce.as_ref().map(|value| value.as_slice()),
                pending.seal_nonce.as_slice(),
                pending.anti_replay_nonce.as_slice(),
                pending.immutable_envelope_bytes.as_slice(),
                pending.public_generation as i64,
            ],
        )?;
        return Ok(());
    };
    let digest = sealer.digest(&pending.object_digest);
    let key = pk(&pending.session_id, &[&digest]);
    let meta = OutboxMeta {
        object_digest: hex::encode(pending.object_digest),
        message_id: hex::encode(pending.message_id),
        recipient_device: hex::encode(pending.recipient_device),
        source_ack_intent: pending.source_ack_intent.map(hex::encode),
        ack_nonce: pending.ack_nonce.map(hex::encode),
        seal_nonce: hex::encode(pending.seal_nonce),
        anti_replay_nonce: hex::encode(pending.anti_replay_nonce),
    };
    conn.execute(
        "INSERT INTO endpoint_outbox
         (session_id, kh_object_digest, kind, kh_message_id, kh_recipient_device,
          ratchet_index, kh_source_ack_intent, kh_ack_nonce, kh_seal_nonce,
          kh_anti_replay_nonce, immutable_envelope_bytes, kh_envelope, state,
          session_generation, meta)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 0, ?13, ?14)",
        params![
            pending.session_id.as_slice(),
            digest.as_slice(),
            pending.kind as u8,
            sealer.message_id(&pending.message_id).as_slice(),
            sealer.device(&pending.recipient_device).as_slice(),
            pending.ratchet_index,
            pending
                .source_ack_intent
                .map(|v| sealer.digest(&v).to_vec()),
            pending.ack_nonce.map(|v| sealer.nonce(&v).to_vec()),
            sealer.nonce(&pending.seal_nonce).as_slice(),
            sealer.nonce(&pending.anti_replay_nonce).as_slice(),
            sealer.seal_bytes(ENVELOPE_LABEL, &key, &pending.immutable_envelope_bytes),
            sealer
                .object_bytes(&pending.immutable_envelope_bytes)
                .as_slice(),
            pending.public_generation as i64,
            sealer.seal(OUTBOX, &key, &meta),
        ],
    )?;
    Ok(())
}

/// A receipt's message id, sender device and generation.
pub(super) type ReceiptValues = (Vec<u8>, Vec<u8>, i64);

/// The receipt of `(session_id, object_digest)`: its message id, sender
/// device and generation.
pub(super) fn receipt_by_object(
    conn: &Connection,
    layout: &Layout,
    session_id: &[u8; 32],
    object_digest: &[u8; 32],
) -> Result<Option<ReceiptValues>, IndexedSessionStoreError> {
    let Some(sealer) = layout.endpoints() else {
        return Ok(conn
            .query_row(
                "SELECT message_id, sender_device, session_generation
                 FROM endpoint_receipts WHERE session_id = ?1 AND object_digest = ?2",
                params![session_id.as_slice(), object_digest.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?);
    };
    let digest = sealer.digest(object_digest);
    let raw_row: Option<(Vec<u8>, i64)> = conn
        .query_row(
            "SELECT meta, session_generation
             FROM endpoint_receipts WHERE session_id = ?1 AND kh_object_digest = ?2",
            params![session_id.as_slice(), digest.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((meta, generation)) = raw_row else {
        return Ok(None);
    };
    let meta: ReceiptMeta = sealer.open(RECEIPTS, &pk(session_id, &[&digest]), &meta)?;
    if unhex(&meta.object_digest)? != object_digest {
        return Err(IndexedSessionStoreError::CorruptEndpointState);
    }
    Ok(Some((
        unhex(&meta.message_id)?,
        unhex(&meta.sender_device)?,
        generation,
    )))
}

/// The object digest a query of one keyed table selects (`kh_object_digest`
/// and `meta`, in that order, from `table`), opened.
fn object_of(
    conn: &Connection,
    layout: &Layout,
    table: &str,
    sql: &str,
    session_id: &[u8; 32],
    bind: impl rusqlite::Params,
) -> Result<Option<[u8; 32]>, IndexedSessionStoreError> {
    let Some(sealer) = layout.endpoints() else {
        let raw_row: Option<Vec<u8>> = conn
            .query_row(&layout.ep(sql), bind, |row| row.get(0))
            .optional()?;
        return raw_row.map(|value| exact_array(&value)).transpose();
    };
    let raw_row: Option<(Vec<u8>, Vec<u8>)> = conn
        .query_row(sql, bind, |row| Ok((row.get(0)?, row.get(1)?)))
        .optional()?;
    let Some((digest, meta)) = raw_row else {
        return Ok(None);
    };
    #[derive(Deserialize)]
    struct Digest {
        object_digest: String,
    }
    let meta: Digest = sealer.open(table, &pk(session_id, &[&digest]), &meta)?;
    let clear = exact_array(&unhex(&meta.object_digest)?)?;
    if sealer.digest(&clear) != digest.as_slice() {
        return Err(IndexedSessionStoreError::CorruptEndpointState);
    }
    Ok(Some(clear))
}

/// The receipt of `sender_device`'s logical message `message_id`.
pub(super) fn logical_object(
    conn: &Connection,
    layout: &Layout,
    session_id: &[u8; 32],
    sender_device: &[u8; 32],
    message_id: &[u8; 16],
) -> Result<Option<[u8; 32]>, IndexedSessionStoreError> {
    let columns = if layout.endpoints().is_some() {
        "kh_object_digest, meta"
    } else {
        "kh_object_digest"
    };
    object_of(
        conn,
        layout,
        RECEIPTS,
        &format!(
            "SELECT {columns} FROM endpoint_receipts
             WHERE session_id = ?1 AND kh_sender_device = ?2 AND kh_message_id = ?3"
        ),
        session_id,
        params![
            session_id.as_slice(),
            layout.ep_device(sender_device),
            layout.ep_mid(message_id)
        ],
    )
}

/// The ACK receipt whose `column` (`kh_ack_nonce` or `kh_outer_message_id`)
/// holds `value` from `remote_device`.
pub(super) fn ack_receipt_object(
    conn: &Connection,
    layout: &Layout,
    session_id: &[u8; 32],
    remote_device: &[u8; 32],
    column: &str,
    value: Vec<u8>,
) -> Result<Option<[u8; 32]>, IndexedSessionStoreError> {
    let columns = if layout.endpoints().is_some() {
        "kh_object_digest, meta"
    } else {
        "kh_object_digest"
    };
    object_of(
        conn,
        layout,
        ACK_RECEIPTS,
        &format!(
            "SELECT {columns} FROM endpoint_ack_receipts
             WHERE session_id = ?1 AND kh_remote_device = ?2 AND {column} = ?3"
        ),
        session_id,
        params![
            session_id.as_slice(),
            layout.ep_device(remote_device),
            value
        ],
    )
}

/// The receipt, the inbox row and the ACK intent of an accepted message.
pub(super) fn insert_acceptance(
    conn: &Connection,
    layout: &Layout,
    pending: &PendingAcceptance,
) -> Result<(), IndexedSessionStoreError> {
    let Some(sealer) = layout.endpoints() else {
        conn.execute(
            "INSERT INTO endpoint_receipts
             (session_id, object_digest, message_id, sender_device, session_generation)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                pending.session_id.as_slice(),
                pending.object_digest.as_slice(),
                pending.message_id.as_slice(),
                pending.sender_device.as_slice(),
                pending.public_generation as i64,
            ],
        )?;
        conn.execute(
            "INSERT INTO endpoint_inbox
             (session_id, object_digest, message_id, sender_device, created_at_ms,
              received_at_ms, sealed_local_row)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                pending.session_id.as_slice(),
                pending.object_digest.as_slice(),
                pending.message_id.as_slice(),
                pending.sender_device.as_slice(),
                pending.created_at_ms as i64,
                pending.received_at_ms as i64,
                pending.sealed_local_inbox_row.as_slice(),
            ],
        )?;
        conn.execute(
            "INSERT INTO endpoint_ack_intents
             (session_id, object_digest, message_id, remote_device, status, state,
              immutable_ack_bytes)
             VALUES (?1, ?2, ?3, ?4, ?5, 0, NULL)",
            params![
                pending.session_id.as_slice(),
                pending.object_digest.as_slice(),
                pending.message_id.as_slice(),
                pending.sender_device.as_slice(),
                pending.ack_status,
            ],
        )?;
        return Ok(());
    };
    let digest = sealer.digest(&pending.object_digest);
    let (mid, sender) = (
        sealer.message_id(&pending.message_id),
        sealer.device(&pending.sender_device),
    );
    let key = pk(&pending.session_id, &[&digest]);
    let (digest_hex, mid_hex, sender_hex) = (
        hex::encode(pending.object_digest),
        hex::encode(pending.message_id),
        hex::encode(pending.sender_device),
    );
    let receipt = ReceiptMeta {
        object_digest: digest_hex.clone(),
        message_id: mid_hex.clone(),
        sender_device: sender_hex.clone(),
    };
    conn.execute(
        "INSERT INTO endpoint_receipts
         (session_id, kh_object_digest, kh_message_id, kh_sender_device, session_generation,
          meta)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            pending.session_id.as_slice(),
            digest.as_slice(),
            mid.as_slice(),
            sender.as_slice(),
            pending.public_generation as i64,
            sealer.seal(RECEIPTS, &key, &receipt),
        ],
    )?;
    let inbox = InboxMeta {
        object_digest: digest_hex.clone(),
        message_id: mid_hex.clone(),
        sender_device: sender_hex.clone(),
        created_at_ms: pending.created_at_ms as i64,
        received_at_ms: pending.received_at_ms as i64,
    };
    conn.execute(
        "INSERT INTO endpoint_inbox
         (session_id, kh_object_digest, kh_message_id, kh_sender_device, meta,
          sealed_local_row)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            pending.session_id.as_slice(),
            digest.as_slice(),
            mid.as_slice(),
            sender.as_slice(),
            sealer.seal(INBOX, &key, &inbox),
            pending.sealed_local_inbox_row.as_slice(),
        ],
    )?;
    let intent = AckIntentMeta {
        object_digest: digest_hex,
        message_id: mid_hex,
        remote_device: sender_hex,
    };
    conn.execute(
        "INSERT INTO endpoint_ack_intents
         (session_id, kh_object_digest, kh_message_id, kh_remote_device, status, state,
          immutable_ack_bytes, kh_ack, meta)
         VALUES (?1, ?2, ?3, ?4, ?5, 0, NULL, NULL, ?6)",
        params![
            pending.session_id.as_slice(),
            digest.as_slice(),
            mid.as_slice(),
            sender.as_slice(),
            pending.ack_status,
            sealer.seal(ACK_INTENTS, &key, &intent),
        ],
    )?;
    Ok(())
}

/// An inbox row's clear values (its sealed local row read too when asked).
pub(super) struct InboxRecord {
    pub object_digest: Vec<u8>,
    pub message_id: Vec<u8>,
    pub sender_device: Vec<u8>,
    pub created_at_ms: i64,
    pub received_at_ms: i64,
    /// The schema-3 `seq` (`None` in a clear store).
    pub seq: Option<i64>,
    pub sealed_local_row: Vec<u8>,
}

impl InboxRecord {
    /// Where the row stands in its sender's order.
    pub(super) fn position(&self) -> Result<InboxPosition, IndexedSessionStoreError> {
        let at = |value: i64| {
            u64::try_from(value).map_err(|_| IndexedSessionStoreError::CorruptEndpointState)
        };
        Ok(match self.seq {
            Some(seq) => InboxPosition::seq(at(seq)?),
            None => InboxPosition::received(
                at(self.received_at_ms)?,
                Some(exact_array(&self.message_id)?),
            ),
        })
    }
}

/// The inbox row of `(session_id, object_digest)`.
pub(super) fn inbox_by_object(
    conn: &Connection,
    layout: &Layout,
    session_id: &[u8; 32],
    object_digest: &[u8; 32],
) -> Result<Option<InboxRecord>, IndexedSessionStoreError> {
    let Some(sealer) = layout.endpoints() else {
        type Clear = (Vec<u8>, Vec<u8>, Vec<u8>, i64, i64, Vec<u8>);
        let raw_row: Option<Clear> = conn
            .query_row(
                "SELECT object_digest, message_id, sender_device, created_at_ms,
                        received_at_ms, sealed_local_row
                 FROM endpoint_inbox WHERE session_id = ?1 AND object_digest = ?2",
                params![session_id.as_slice(), object_digest.as_slice()],
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
        return Ok(raw_row.map(
            |(object_digest, message_id, sender_device, created, received, sealed_local_row)| {
                InboxRecord {
                    object_digest,
                    message_id,
                    sender_device,
                    created_at_ms: created,
                    received_at_ms: received,
                    seq: None,
                    sealed_local_row,
                }
            },
        ));
    };
    let digest = sealer.digest(object_digest);
    let raw_row: Option<(i64, Vec<u8>, Vec<u8>)> = conn
        .query_row(
            "SELECT seq, meta, sealed_local_row
             FROM endpoint_inbox WHERE session_id = ?1 AND kh_object_digest = ?2",
            params![session_id.as_slice(), digest.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((seq, meta, sealed_local_row)) = raw_row else {
        return Ok(None);
    };
    let meta: InboxMeta = sealer.open(INBOX, &pk(session_id, &[&digest]), &meta)?;
    Ok(Some(InboxRecord {
        object_digest: unhex(&meta.object_digest)?,
        message_id: unhex(&meta.message_id)?,
        sender_device: unhex(&meta.sender_device)?,
        created_at_ms: meta.created_at_ms,
        received_at_ms: meta.received_at_ms,
        seq: Some(seq),
        sealed_local_row,
    }))
}

/// An inbox row a listing names (no sealed local row): its object, its
/// time and its place.
pub(super) struct InboxEntry {
    pub object_digest: [u8; 32],
    pub message_id: [u8; 16],
    pub received_at_ms: i64,
    pub seq: Option<i64>,
}

pub(super) const INBOX_ENTRY_WIDTH: usize = 5;

/// The inbox columns a listing reads ([`INBOX_ENTRY_WIDTH`] in either
/// shape), from `alias` (`"i."`).
pub(super) fn inbox_entry_columns(layout: &Layout, alias: &str) -> String {
    let a = alias;
    if layout.endpoints().is_some() {
        format!("{a}session_id, {a}kh_object_digest, {a}meta, NULL, {a}seq")
    } else {
        format!("{a}session_id, {a}object_digest, {a}message_id, {a}received_at_ms, NULL")
    }
}

/// An inbox row read with [`inbox_entry_columns`].
pub(super) fn inbox_entry(
    layout: &Layout,
    mut v: Vec<Value>,
) -> Result<InboxEntry, IndexedSessionStoreError> {
    let session_id = blob(&mut v, 0)?;
    let stored_digest = blob(&mut v, 1)?;
    let Some(sealer) = layout.endpoints() else {
        return Ok(InboxEntry {
            object_digest: exact_array(&stored_digest)?,
            message_id: exact_array(&blob(&mut v, 2)?)?,
            received_at_ms: int(&mut v, 3)?,
            seq: None,
        });
    };
    let seq = int(&mut v, 4)?;
    let meta: InboxMeta = sealer.open(
        INBOX,
        &pk(&session_id, &[&stored_digest]),
        &blob(&mut v, 2)?,
    )?;
    Ok(InboxEntry {
        object_digest: exact_array(&unhex(&meta.object_digest)?)?,
        message_id: exact_array(&unhex(&meta.message_id)?)?,
        received_at_ms: meta.received_at_ms,
        seq: Some(seq),
    })
}

/// An inbox row a listing names, read with [`inbox_entry_columns`], and its
/// `seq` (schema 3). A row whose `meta` does not open is that row's damage:
/// logged (once per process for its session) and `None`, so the listing
/// goes on past it (its `seq` is clear) as it goes past a row whose sealed
/// local row does not open. A key not loaded fails the listing.
pub(super) fn listed_entry(
    layout: &Layout,
    key: &IndexedSessionRecordKey,
    values: Vec<Value>,
) -> Result<(Option<InboxEntry>, Option<i64>), IndexedSessionStoreError> {
    let seq = listed_seq(&values);
    match inbox_entry(layout, values) {
        Ok(entry) => Ok((Some(entry), seq)),
        Err(error) if is_session_scoped_state_error(&error) => {
            log_skipped_session(&record_key_digest(key)?, &error);
            Ok((None, seq))
        }
        Err(error) => Err(error),
    }
}

/// The clear `seq` of an inbox row a listing names (schema 3; `None` in a
/// clear store), without opening anything: a listing moves past a row of
/// a session whose head does not open by it.
pub(super) fn listed_seq(values: &[Value]) -> Option<i64> {
    match values.get(4) {
        Some(Value::Integer(seq)) => Some(*seq),
        _ => None,
    }
}

/// The newest `received_at_ms` of `sender_device`'s inbox rows, and the
/// `seq` of that row (schema 3; `0` in a clear store). In schema 3 the
/// newest row by `seq` holds it: every row is stamped after the sender's
/// newest one ([`monotonic_received_at_ms`]).
pub(super) fn newest_received(
    conn: &Connection,
    layout: &Layout,
    sender_device: &[u8; 32],
) -> Result<(Option<i64>, i64), IndexedSessionStoreError> {
    let Some(sealer) = layout.endpoints() else {
        let live: Option<i64> = conn.query_row(
            "SELECT MAX(received_at_ms) FROM endpoint_inbox WHERE sender_device = ?1",
            params![sender_device.as_slice()],
            |row| row.get(0),
        )?;
        return Ok((live, 0));
    };
    // The newest row whose `meta` opens (a damaged one is that row's
    // problem, never every later message's from this sender).
    let mut statement = conn.prepare(
        "SELECT seq, session_id, kh_object_digest, meta FROM endpoint_inbox
         WHERE kh_sender_device = ?1 ORDER BY seq DESC",
    )?;
    let rows = statement.query_map(params![sealer.device(sender_device).as_slice()], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, Vec<u8>>(2)?,
            row.get::<_, Vec<u8>>(3)?,
        ))
    })?;
    for row in rows {
        let (seq, session_id, digest, meta) = row?;
        match sealer.open::<InboxMeta>(INBOX, &pk(&session_id, &[&digest]), &meta) {
            Ok(meta) => return Ok((Some(meta.received_at_ms), seq)),
            Err(error @ IndexedSessionStoreError::MetaKeyUnavailable(_)) => return Err(error),
            Err(_) => continue,
        }
    }
    Ok((None, 0))
}

/// The inbox rows holding `sender`'s logical message `message_id` (one per
/// session that received it).
pub(super) fn inbox_copies(
    conn: &Connection,
    layout: &Layout,
    sender: &[u8; 32],
    message_id: &[u8; 16],
) -> Result<usize, IndexedSessionStoreError> {
    let n: i64 = conn.query_row(
        &layout.ep("SELECT COUNT(*) FROM endpoint_inbox
             WHERE kh_sender_device = ?1 AND kh_message_id = ?2"),
        params![layout.ep_device(sender), layout.ep_mid(message_id)],
        |row| row.get(0),
    )?;
    Ok(usize::try_from(n).unwrap_or(0))
}

/// An ACK intent with every column as schema 1 holds it.
pub(super) struct AckIntentRow {
    pub session_id: Vec<u8>,
    pub object_digest: Vec<u8>,
    pub message_id: Vec<u8>,
    pub remote_device: Vec<u8>,
    pub status: i64,
    pub state: i64,
    pub immutable_ack_bytes: Option<Vec<u8>>,
}

pub(super) const ACK_INTENT_WIDTH: usize = 7;

/// The ACK intent columns a query reads ([`ACK_INTENT_WIDTH`] in either
/// shape).
pub(super) fn ack_intent_columns(layout: &Layout) -> &'static str {
    if layout.endpoints().is_some() {
        "session_id, kh_object_digest, meta, NULL, status, state, immutable_ack_bytes"
    } else {
        "session_id, object_digest, message_id, remote_device, status, state, immutable_ack_bytes"
    }
}

/// An ACK intent read with [`ack_intent_columns`].
pub(super) fn ack_intent_row(
    layout: &Layout,
    mut v: Vec<Value>,
) -> Result<AckIntentRow, IndexedSessionStoreError> {
    let session_id = blob(&mut v, 0)?;
    let stored_digest = blob(&mut v, 1)?;
    let status = int(&mut v, 4)?;
    let state = int(&mut v, 5)?;
    let stored_bytes = opt_blob(&mut v, 6)?;
    let Some(sealer) = layout.endpoints() else {
        return Ok(AckIntentRow {
            session_id,
            object_digest: stored_digest,
            message_id: blob(&mut v, 2)?,
            remote_device: blob(&mut v, 3)?,
            status,
            state,
            immutable_ack_bytes: stored_bytes,
        });
    };
    let key = pk(&session_id, &[&stored_digest]);
    let meta: AckIntentMeta = sealer.open(ACK_INTENTS, &key, &blob(&mut v, 2)?)?;
    Ok(AckIntentRow {
        object_digest: unhex(&meta.object_digest)?,
        message_id: unhex(&meta.message_id)?,
        remote_device: unhex(&meta.remote_device)?,
        status,
        state,
        immutable_ack_bytes: stored_bytes
            .map(|sealed| sealer.open_bytes(ACK_LABEL, &key, &sealed))
            .transpose()?,
        session_id,
    })
}

/// The ACK intent of `(session_id, object_digest)`.
pub(super) fn ack_intent_by_object(
    conn: &Connection,
    layout: &Layout,
    session_id: &[u8; 32],
    object_digest: &[u8; 32],
) -> Result<Option<AckIntentRow>, IndexedSessionStoreError> {
    let raw_row = conn
        .query_row(
            &layout.ep(&format!(
                "SELECT {} FROM endpoint_ack_intents
                 WHERE session_id = ?1 AND kh_object_digest = ?2",
                ack_intent_columns(layout)
            )),
            params![session_id.as_slice(), layout.ep_digest(object_digest)],
            |row| raw(row, 0, ACK_INTENT_WIDTH),
        )
        .optional()?;
    raw_row.map(|v| ack_intent_row(layout, v)).transpose()
}

/// Every ACK intent a query selects (its columns from
/// [`ack_intent_columns`] first).
pub(super) fn ack_intent_rows(
    conn: &Connection,
    layout: &Layout,
    sql: &str,
) -> Result<Vec<AckIntentRow>, IndexedSessionStoreError> {
    let mut statement = conn.prepare(&layout.ep(sql))?;
    let rows = statement.query_map([], |row| raw(row, 0, ACK_INTENT_WIDTH))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(ack_intent_row(layout, row?)?);
    }
    Ok(out)
}

/// The ACK bytes of a pending intent, set once: `Ok(1)` when they are set
/// now or were these bytes already (`only_if_unset_or_equal`), `Ok(0)` when
/// the row does not match. Schema 3 seals them and compares `kh_ack`.
pub(super) fn set_ack_bytes(
    conn: &Connection,
    layout: &Layout,
    session_id: &[u8; 32],
    object_digest: &[u8; 32],
    bytes: &[u8],
    only_if_unset_or_equal: bool,
) -> Result<usize, IndexedSessionStoreError> {
    let condition = if only_if_unset_or_equal {
        "AND (kh_ack IS NULL OR kh_ack = ?4)"
    } else {
        "AND ?4 IS NOT NULL"
    };
    let stored = match layout.endpoints() {
        Some(sealer) => {
            let key = pk(session_id, &[&sealer.digest(object_digest)]);
            sealer.seal_bytes(ACK_LABEL, &key, bytes)
        }
        None => bytes.to_vec(),
    };
    let set_digest = if layout.endpoints().is_some() {
        ", kh_ack = ?4"
    } else {
        ""
    };
    Ok(conn.execute(
        &layout.ep(&format!(
            "UPDATE endpoint_ack_intents SET immutable_ack_bytes = ?1{set_digest}
             WHERE session_id = ?2 AND kh_object_digest = ?3 AND state = 0 {condition}"
        )),
        params![
            stored,
            session_id.as_slice(),
            layout.ep_digest(object_digest),
            layout.ep_bytes(bytes)
        ],
    )?)
}

/// A new outstanding row for a sent message (kept when it is there).
pub(super) fn insert_outstanding(
    conn: &Connection,
    layout: &Layout,
    session_id: &[u8; 32],
    message_id: &[u8; 16],
    recipient_device: &[u8; 32],
) -> Result<(), IndexedSessionStoreError> {
    let Some(sealer) = layout.endpoints() else {
        conn.execute(
            "INSERT INTO endpoint_outstanding_messages
             (session_id, message_id, recipient_device, delivery_state)
             VALUES (?1, ?2, ?3, 0)
             ON CONFLICT(session_id, message_id, recipient_device) DO NOTHING",
            params![
                session_id.as_slice(),
                message_id.as_slice(),
                recipient_device.as_slice()
            ],
        )?;
        return Ok(());
    };
    let (mid, recipient) = (
        sealer.message_id(message_id),
        sealer.device(recipient_device),
    );
    let meta = OutstandingMeta {
        message_id: hex::encode(message_id),
        recipient_device: hex::encode(recipient_device),
    };
    conn.execute(
        "INSERT INTO endpoint_outstanding_messages
         (session_id, kh_message_id, kh_recipient_device, delivery_state, meta)
         VALUES (?1, ?2, ?3, 0, ?4)
         ON CONFLICT(session_id, kh_message_id, kh_recipient_device) DO NOTHING",
        params![
            session_id.as_slice(),
            mid.as_slice(),
            recipient.as_slice(),
            sealer.seal(OUTSTANDING, &pk(session_id, &[&mid, &recipient]), &meta),
        ],
    )?;
    Ok(())
}

/// The ACK receipt of `(session_id, object_digest)`.
pub(super) fn ack_receipt_by_object(
    conn: &Connection,
    layout: &Layout,
    session_id: &[u8; 32],
    object_digest: &[u8; 32],
) -> Result<Option<AckReceiptIdentity>, IndexedSessionStoreError> {
    let Some(sealer) = layout.endpoints() else {
        let raw_row: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = conn
            .query_row(
                "SELECT outer_message_id, remote_device, acked_message_id
                 FROM endpoint_ack_receipts WHERE session_id = ?1 AND object_digest = ?2",
                params![session_id.as_slice(), object_digest.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        return raw_row
            .map(|(outer_message, remote, acked)| {
                Ok(AckReceiptIdentity {
                    outer_message_id: exact_array(&outer_message)?,
                    remote_device: exact_array(&remote)?,
                    acked_message_id: exact_array(&acked)?,
                })
            })
            .transpose();
    };
    let digest = sealer.digest(object_digest);
    let meta: Option<Vec<u8>> = conn
        .query_row(
            "SELECT meta FROM endpoint_ack_receipts
             WHERE session_id = ?1 AND kh_object_digest = ?2",
            params![session_id.as_slice(), digest.as_slice()],
            |row| row.get(0),
        )
        .optional()?;
    let Some(meta) = meta else {
        return Ok(None);
    };
    let meta: AckReceiptMeta = sealer.open(ACK_RECEIPTS, &pk(session_id, &[&digest]), &meta)?;
    if unhex(&meta.object_digest)? != object_digest {
        return Err(IndexedSessionStoreError::CorruptEndpointState);
    }
    Ok(Some(AckReceiptIdentity {
        outer_message_id: exact_array(&unhex(&meta.outer_message_id)?)?,
        remote_device: exact_array(&unhex(&meta.remote_device)?)?,
        acked_message_id: exact_array(&unhex(&meta.acked_message_id)?)?,
    }))
}

/// A new ACK receipt (the journal's accepted ACK).
pub(super) fn insert_ack_receipt(
    conn: &Connection,
    layout: &Layout,
    pending: &PendingAckAcceptance,
) -> Result<(), IndexedSessionStoreError> {
    let Some(sealer) = layout.endpoints() else {
        conn.execute(
            "INSERT INTO endpoint_ack_receipts
             (session_id, object_digest, outer_message_id, remote_device,
              acked_message_id, status, ack_nonce, created_at_ms, session_generation)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                pending.session_id.as_slice(),
                pending.object_digest.as_slice(),
                pending.outer_message_id.as_slice(),
                pending.remote_device.as_slice(),
                pending.acked_message_id.as_slice(),
                pending.status,
                pending.ack_nonce.as_slice(),
                pending.created_at_ms as i64,
                pending.public_generation as i64,
            ],
        )?;
        return Ok(());
    };
    let digest = sealer.digest(&pending.object_digest);
    let meta = AckReceiptMeta {
        object_digest: hex::encode(pending.object_digest),
        outer_message_id: hex::encode(pending.outer_message_id),
        remote_device: hex::encode(pending.remote_device),
        acked_message_id: hex::encode(pending.acked_message_id),
        ack_nonce: hex::encode(pending.ack_nonce),
        created_at_ms: pending.created_at_ms as i64,
    };
    conn.execute(
        "INSERT INTO endpoint_ack_receipts
         (session_id, kh_object_digest, kh_outer_message_id, kh_remote_device,
          kh_acked_message_id, status, kh_ack_nonce, session_generation, meta)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            pending.session_id.as_slice(),
            digest.as_slice(),
            sealer.message_id(&pending.outer_message_id).as_slice(),
            sealer.device(&pending.remote_device).as_slice(),
            sealer.message_id(&pending.acked_message_id).as_slice(),
            pending.status,
            sealer.nonce(&pending.ack_nonce).as_slice(),
            pending.public_generation as i64,
            sealer.seal(ACK_RECEIPTS, &pk(&pending.session_id, &[&digest]), &meta),
        ],
    )?;
    Ok(())
}

// ── The inbox order ──────────────────────────────────────────────────────

/// What an [`InboxPosition`] counts: the order a store lists a sender's
/// inbox in.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InboxOrder {
    /// A clear store (schema 1, and a PP.13 build's schema 2):
    /// `received_at_ms`, strictly increasing per sender
    /// (`monotonic_received_at_ms`), then the message id.
    #[default]
    Received,
    /// A sealed profile's schema-3 store (PP.14): the rows' insertion `seq`,
    /// never used twice.
    Seq,
}

/// A reader's place in one sender's inbox
/// ([`IndexedSessionStore::list_endpoint_inbox_for_sender_after`]): the rows
/// after it are the ones not read yet. The derived order is the listing
/// order within one [`InboxOrder`] (a position of the newer order sorts
/// after every one of the older: a store only moves forward).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InboxPosition {
    pub order: InboxOrder,
    /// The last row's `seq` ([`InboxOrder::Seq`]) or `received_at_ms`
    /// ([`InboxOrder::Received`]); `0` before every row.
    pub seq: u64,
    /// The last row's message id in the [`InboxOrder::Received`] order
    /// (`None`: before every row stamped `seq`); always `None` in the
    /// [`InboxOrder::Seq`] order.
    pub message_id: Option<[u8; 16]>,
}

impl InboxPosition {
    /// Before every row, in either order.
    pub const START: Self = Self {
        order: InboxOrder::Received,
        seq: 0,
        message_id: None,
    };

    /// A position in the [`InboxOrder::Received`] order (a cursor saved by a
    /// build before PP.14 is one).
    pub fn received(received_at_ms: u64, message_id: Option<[u8; 16]>) -> Self {
        Self {
            order: InboxOrder::Received,
            seq: received_at_ms,
            message_id,
        }
    }

    /// A position in the [`InboxOrder::Seq`] order.
    pub fn seq(seq: u64) -> Self {
        Self {
            order: InboxOrder::Seq,
            seq,
            message_id: None,
        }
    }

    /// Before every row (in either order).
    pub fn is_start(&self) -> bool {
        self.seq == 0 && self.message_id.is_none()
    }

    /// Whether a row of the [`InboxOrder::Received`] order stamped
    /// `received_at_ms` with `message_id` is after this position.
    pub(super) fn received_after(&self, received_at_ms: i64, message_id: &[u8; 16]) -> bool {
        let at = i64::try_from(self.seq).unwrap_or(i64::MAX);
        received_at_ms > at
            || (received_at_ms == at && self.message_id.is_none_or(|last| *message_id > last))
    }
}

impl IndexedSessionStore {
    /// The order this store lists a sender's inbox in.
    pub fn inbox_order(&self) -> InboxOrder {
        if self.layout.endpoints().is_some() {
            InboxOrder::Seq
        } else {
            InboxOrder::Received
        }
    }

    /// `position` as a position of this store's order with exactly the same
    /// rows of `sender_device` after it. A position of the
    /// [`InboxOrder::Received`] order in a schema-3 store (a cursor saved
    /// before the store moved): the rows after it are those stamped after
    /// it, which (stamped in insertion order) are the newest by `seq`; the
    /// position is the `seq` just before the oldest of them, or the newest
    /// `seq` this store has given when there is none (a cleared chat stays
    /// cleared, every later row is shown). A position of the
    /// [`InboxOrder::Seq`] order in a clear store (one moved back by
    /// `raven privacy unseal` while a reader held it) cannot be placed: the
    /// start, so nothing is lost (rows already read may be listed again).
    pub fn resolve_inbox_position(
        &self,
        sender_device: &[u8; 32],
        position: &InboxPosition,
    ) -> Result<InboxPosition, IndexedSessionStoreError> {
        let order = self.inbox_order();
        if position.order == order {
            return Ok(*position);
        }
        if position.is_start() || order == InboxOrder::Received {
            return Ok(InboxPosition {
                order,
                ..InboxPosition::START
            });
        }
        let Some(sealer) = self.layout.endpoints() else {
            return Ok(InboxPosition::START);
        };
        let mut statement = self.conn.prepare(
            "SELECT seq, session_id, kh_object_digest, meta FROM endpoint_inbox
             WHERE kh_sender_device = ?1 ORDER BY seq DESC",
        )?;
        let rows =
            statement.query_map(params![sealer.device(sender_device).as_slice()], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            })?;
        let mut oldest_after = None;
        for row in rows {
            let (seq, session_id, digest, meta) = row?;
            let meta: InboxMeta = match sealer.open(INBOX, &pk(&session_id, &[&digest]), &meta) {
                Ok(meta) => meta,
                Err(error @ IndexedSessionStoreError::MetaKeyUnavailable(_)) => return Err(error),
                Err(_) => continue,
            };
            let Ok(message_id) = unhex(&meta.message_id).and_then(|id| exact_array::<16>(&id))
            else {
                continue;
            };
            if !position.received_after(meta.received_at_ms, &message_id) {
                break;
            }
            oldest_after = Some(seq);
        }
        drop(statement);
        let seq = match oldest_after {
            Some(seq) => seq.saturating_sub(1),
            None => newest_seq(&self.conn)?,
        };
        Ok(InboxPosition::seq(u64::try_from(seq).unwrap_or(0)))
    }
}

/// `raven privacy unseal` (PP.18), before a schema-3 store moves back: the
/// [`InboxOrder::Received`] position with exactly the rows of
/// `sender_device` after it that come after `seq` in the
/// [`InboxOrder::Seq`] order, so a chat's saved place survives the move (a
/// build before PP.14 reads only that order). The rows are stamped in
/// insertion order per sender (`monotonic_received_at_ms`), so it is the
/// stamp and message id of the sender's newest row at or before `seq`, from
/// its `meta`; with none, the start. A metadata-only read.
pub(super) fn received_position(
    conn: &Connection,
    keys: &MetaKeys,
    sender_device: &[u8; 32],
    seq: u64,
) -> Result<InboxPosition, String> {
    let device = at_rest::index(keys, ValueType::DeviceKey, sender_device);
    let mut statement = conn
        .prepare(
            "SELECT session_id, kh_object_digest, meta FROM endpoint_inbox
             WHERE kh_sender_device = ?1 AND seq <= ?2 ORDER BY seq DESC",
        )
        .map_err(|e| e.to_string())?;
    let rows = statement
        .query_map(
            params![device.as_slice(), i64::try_from(seq).unwrap_or(i64::MAX)],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )
        .map_err(|e| e.to_string())?;
    for row in rows {
        let (session_id, digest, meta) = row.map_err(|e| e.to_string())?;
        let Some(meta) = open_json::<InboxMeta>(keys, INBOX, &pk(&session_id, &[&digest]), &meta)
        else {
            continue;
        };
        let Ok(message_id) = unhex(&meta.message_id).and_then(|id| exact_array::<16>(&id)) else {
            continue;
        };
        return Ok(InboxPosition::received(
            u64::try_from(meta.received_at_ms).unwrap_or(0),
            Some(message_id),
        ));
    }
    Ok(InboxPosition::START)
}

/// The tombstones' `seq` and the inbox's `AUTOINCREMENT` counter of a
/// schema-3 store, read before a re-key moves it back and forward again
/// (`raven privacy rotate-meta`, PP.18) and put back after
/// ([`restore_order`]): the forward half places each tombstone anew and
/// counts from the newest row left, while a cursor may already be past a
/// `seq` a deleted row had.
pub(super) fn save_order(tx: &Transaction<'_>) -> rusqlite::Result<(Vec<(i64, i64)>, i64)> {
    let tombstones = rows_of(tx, "SELECT rowid, seq FROM endpoint_inbox_deleted", |r| {
        Ok((r.get(0)?, r.get(1)?))
    })?;
    Ok((tombstones, newest_seq_raw(tx)?))
}

/// [`save_order`]'s values back, after the forward half of a re-key.
pub(super) fn restore_order(
    tx: &Transaction<'_>,
    (tombstones, newest): &(Vec<(i64, i64)>, i64),
) -> rusqlite::Result<()> {
    for (rowid, seq) in tombstones {
        tx.execute(
            "UPDATE endpoint_inbox_deleted SET seq = ?2 WHERE rowid = ?1",
            params![rowid, seq],
        )?;
    }
    if *newest > newest_seq_raw(tx)? {
        tx.execute(
            "DELETE FROM sqlite_sequence WHERE name = 'endpoint_inbox'",
            [],
        )?;
        tx.execute(
            "INSERT INTO sqlite_sequence (name, seq) VALUES ('endpoint_inbox', ?1)",
            params![newest],
        )?;
    }
    Ok(())
}

fn newest_seq_raw(conn: &Connection) -> rusqlite::Result<i64> {
    conn.query_row(
        "SELECT MAX(
           COALESCE((SELECT seq FROM sqlite_sequence WHERE name = 'endpoint_inbox'), 0),
           COALESCE((SELECT MAX(seq) FROM endpoint_inbox), 0))",
        [],
        |row| row.get(0),
    )
}

/// The newest `seq` the schema-3 inbox has given (its `AUTOINCREMENT`
/// counter: a later row's `seq` is above it even when that row went).
pub(super) fn newest_seq(conn: &Connection) -> Result<i64, IndexedSessionStoreError> {
    Ok(conn.query_row(
        "SELECT MAX(
           COALESCE((SELECT seq FROM sqlite_sequence WHERE name = 'endpoint_inbox'), 0),
           COALESCE((SELECT MAX(seq) FROM endpoint_inbox), 0))",
        [],
        |row| row.get(0),
    )?)
}

// ── Migration (privacy pack PP.14) ───────────────────────────────────────

fn rows_of<T, F>(conn: &Connection, sql: &str, map: F) -> rusqlite::Result<Vec<T>>
where
    F: FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
{
    let mut statement = conn.prepare(sql)?;
    let mapped = statement.query_map([], map)?;
    mapped.collect()
}

fn seal_json<T: Serialize>(keys: &MetaKeys, table: &str, key: &[u8], value: &T) -> Vec<u8> {
    let plain = Zeroizing::new(serde_json::to_vec(value).expect("strings and numbers serialize"));
    at_rest::seal_row(keys, table, key, &plain)
}

fn open_json<T: DeserializeOwned>(
    keys: &MetaKeys,
    table: &str,
    key: &[u8],
    blob: &[u8],
) -> Option<T> {
    let plain = at_rest::open_row(keys, table, key, blob).ok()?;
    serde_json::from_slice(&plain).ok()
}

/// One table's rebuild: create the new shape, copy, drop, rename, indexes.
fn rebuild_table(
    tx: &Transaction<'_>,
    steps: &mut Steps,
    table: &str,
    columns: &str,
    copy: impl FnOnce(&Transaction<'_>, &mut Steps) -> Result<u32, RebuildError>,
    indexes: &str,
) -> Result<u32, RebuildError> {
    steps.step()?;
    tx.execute_batch(&format!("CREATE TABLE {table}__new ({columns});"))?;
    let rows = copy(tx, steps)?;
    steps.step()?;
    tx.execute_batch(&format!("DROP TABLE {table};"))?;
    steps.step()?;
    tx.execute_batch(&format!("ALTER TABLE {table}__new RENAME TO {table};"))?;
    if !indexes.is_empty() {
        steps.step()?;
        tx.execute_batch(indexes)?;
    }
    Ok(rows)
}

/// Schema 2 -> 3's part of `sealed::migrate_forward`: the seven endpoint
/// tables rebuilt keyed, inside its transaction, rowids kept (the inbox's
/// rowid becomes its `seq`, so the insertion order is the one the rows
/// had). A tombstone gets the `seq` of the sender's newest row stamped
/// before it (the floor of `monotonic_received_at_ms` needs no other).
/// The rows moved.
pub(super) fn move_forward(
    tx: &Transaction<'_>,
    keys: &MetaKeys,
    steps: &mut Steps,
    leave_one_out: &mut bool,
) -> Result<u32, RebuildError> {
    let digest = |v: &[u8]| at_rest::index(keys, ValueType::ObjectDigest, v);
    let mid = |v: &[u8]| at_rest::index(keys, ValueType::MessageId, v);
    let device = |v: &[u8]| at_rest::index(keys, ValueType::DeviceKey, v);
    let nonce = |v: &[u8]| at_rest::index(keys, ValueType::Nonce, v);
    let object_bytes = |v: &[u8]| at_rest::index(keys, ValueType::ObjectBytes, v);
    let mut skip_first = |n: usize| {
        if *leave_one_out && n == 0 {
            *leave_one_out = false;
            return true;
        }
        false
    };
    let mut moved = 0u32;

    moved += rebuild_table(
        tx,
        steps,
        RECEIPTS,
        &keyed_columns(RECEIPTS),
        |tx, steps| {
            type Row = (i64, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, i64);
            let rows: Vec<Row> = rows_of(
                tx,
                "SELECT rowid, session_id, object_digest, message_id, sender_device,
                    session_generation FROM endpoint_receipts",
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                    ))
                },
            )?;
            let mut n = 0;
            for (i, (rowid, sid, od, m, sender, generation)) in rows.into_iter().enumerate() {
                if skip_first(i) {
                    continue;
                }
                steps.step()?;
                let kd = digest(&od);
                let meta = ReceiptMeta {
                    object_digest: hex::encode(&od),
                    message_id: hex::encode(&m),
                    sender_device: hex::encode(&sender),
                };
                tx.execute(
                    "INSERT INTO endpoint_receipts__new
                   (rowid, session_id, kh_object_digest, kh_message_id, kh_sender_device,
                    session_generation, meta)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        rowid,
                        sid,
                        kd.as_slice(),
                        mid(&m).as_slice(),
                        device(&sender).as_slice(),
                        generation,
                        seal_json(keys, RECEIPTS, &pk(&sid, &[&kd]), &meta),
                    ],
                )?;
                n += 1;
            }
            Ok(n)
        },
        "",
    )?;

    // The inbox: its rows by sender and stamp, for the tombstones' `seq`.
    let mut stamped: HashMap<Vec<u8>, Vec<(i64, i64)>> = HashMap::new();
    moved += rebuild_table(
        tx,
        steps,
        INBOX,
        &keyed_columns(INBOX),
        |tx, steps| {
            type Row = (i64, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, i64, i64, Vec<u8>);
            let rows: Vec<Row> = rows_of(
                tx,
                "SELECT rowid, session_id, object_digest, message_id, sender_device, created_at_ms,
                    received_at_ms, sealed_local_row FROM endpoint_inbox ORDER BY rowid",
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                        r.get(7)?,
                    ))
                },
            )?;
            let mut n = 0;
            for (rowid, sid, od, m, sender, created, received, local) in rows {
                steps.step()?;
                let kd = digest(&od);
                let meta = InboxMeta {
                    object_digest: hex::encode(&od),
                    message_id: hex::encode(&m),
                    sender_device: hex::encode(&sender),
                    created_at_ms: created,
                    received_at_ms: received,
                };
                tx.execute(
                    "INSERT INTO endpoint_inbox__new
                   (seq, session_id, kh_object_digest, kh_message_id, kh_sender_device, meta,
                    sealed_local_row)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        rowid,
                        sid,
                        kd.as_slice(),
                        mid(&m).as_slice(),
                        device(&sender).as_slice(),
                        seal_json(keys, INBOX, &pk(&sid, &[&kd]), &meta),
                        local,
                    ],
                )?;
                stamped.entry(sender).or_default().push((received, rowid));
                n += 1;
            }
            Ok(n)
        },
        keyed_indexes(INBOX),
    )?;

    moved += rebuild_table(
        tx,
        steps,
        ACK_INTENTS,
        &keyed_columns(ACK_INTENTS),
        |tx, steps| {
            type Row = (
                i64,
                Vec<u8>,
                Vec<u8>,
                Vec<u8>,
                Vec<u8>,
                i64,
                i64,
                Option<Vec<u8>>,
            );
            let rows: Vec<Row> = rows_of(
                tx,
                "SELECT rowid, session_id, object_digest, message_id, remote_device, status, state,
                    immutable_ack_bytes FROM endpoint_ack_intents",
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                        r.get(7)?,
                    ))
                },
            )?;
            let mut n = 0;
            for (rowid, sid, od, m, remote, status, state, bytes) in rows {
                steps.step()?;
                let kd = digest(&od);
                let key = pk(&sid, &[&kd]);
                let meta = AckIntentMeta {
                    object_digest: hex::encode(&od),
                    message_id: hex::encode(&m),
                    remote_device: hex::encode(&remote),
                };
                tx.execute(
                    "INSERT INTO endpoint_ack_intents__new
                   (rowid, session_id, kh_object_digest, kh_message_id, kh_remote_device,
                    status, state, immutable_ack_bytes, kh_ack, meta)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                    params![
                        rowid,
                        sid,
                        kd.as_slice(),
                        mid(&m).as_slice(),
                        device(&remote).as_slice(),
                        status,
                        state,
                        bytes
                            .as_ref()
                            .map(|b| at_rest::seal_row(keys, ACK_LABEL, &key, b)),
                        bytes.as_ref().map(|b| object_bytes(b).to_vec()),
                        seal_json(keys, ACK_INTENTS, &key, &meta),
                    ],
                )?;
                n += 1;
            }
            Ok(n)
        },
        "",
    )?;

    moved += rebuild_table(
        tx,
        steps,
        OUTSTANDING,
        &keyed_columns(OUTSTANDING),
        |tx, steps| {
            type Row = (i64, Vec<u8>, Vec<u8>, Vec<u8>, i64);
            let rows: Vec<Row> = rows_of(
                tx,
                "SELECT rowid, session_id, message_id, recipient_device, delivery_state
             FROM endpoint_outstanding_messages",
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )?;
            let mut n = 0;
            for (rowid, sid, m, recipient, delivery) in rows {
                steps.step()?;
                let (km, kr) = (mid(&m), device(&recipient));
                let meta = OutstandingMeta {
                    message_id: hex::encode(&m),
                    recipient_device: hex::encode(&recipient),
                };
                tx.execute(
                    "INSERT INTO endpoint_outstanding_messages__new
                   (rowid, session_id, kh_message_id, kh_recipient_device, delivery_state, meta)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        rowid,
                        sid,
                        km.as_slice(),
                        kr.as_slice(),
                        delivery,
                        seal_json(keys, OUTSTANDING, &pk(&sid, &[&km, &kr]), &meta),
                    ],
                )?;
                n += 1;
            }
            Ok(n)
        },
        "",
    )?;

    moved += rebuild_table(
        tx,
        steps,
        ACK_RECEIPTS,
        &keyed_columns(ACK_RECEIPTS),
        |tx, steps| {
            type Row = (
                i64,
                Vec<u8>,
                Vec<u8>,
                Vec<u8>,
                Vec<u8>,
                Vec<u8>,
                i64,
                Vec<u8>,
                i64,
                i64,
            );
            let rows: Vec<Row> = rows_of(
                tx,
                "SELECT rowid, session_id, object_digest, outer_message_id, remote_device,
                    acked_message_id, status, ack_nonce, created_at_ms, session_generation
             FROM endpoint_ack_receipts",
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                        r.get(7)?,
                        r.get(8)?,
                        r.get(9)?,
                    ))
                },
            )?;
            let mut n = 0;
            for (rowid, sid, od, outer, remote, acked, status, ack_nonce, created, generation) in
                rows
            {
                steps.step()?;
                let kd = digest(&od);
                let meta = AckReceiptMeta {
                    object_digest: hex::encode(&od),
                    outer_message_id: hex::encode(&outer),
                    remote_device: hex::encode(&remote),
                    acked_message_id: hex::encode(&acked),
                    ack_nonce: hex::encode(&ack_nonce),
                    created_at_ms: created,
                };
                tx.execute(
                    "INSERT INTO endpoint_ack_receipts__new
                   (rowid, session_id, kh_object_digest, kh_outer_message_id, kh_remote_device,
                    kh_acked_message_id, status, kh_ack_nonce, session_generation, meta)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                    params![
                        rowid,
                        sid,
                        kd.as_slice(),
                        mid(&outer).as_slice(),
                        device(&remote).as_slice(),
                        mid(&acked).as_slice(),
                        status,
                        nonce(&ack_nonce).as_slice(),
                        generation,
                        seal_json(keys, ACK_RECEIPTS, &pk(&sid, &[&kd]), &meta),
                    ],
                )?;
                n += 1;
            }
            Ok(n)
        },
        "",
    )?;

    moved += rebuild_table(
        tx,
        steps,
        OUTBOX,
        &keyed_columns(OUTBOX),
        |tx, steps| {
            let rows: Vec<Vec<Value>> = rows_of(
                tx,
                "SELECT rowid, session_id, object_digest, kind, message_id, recipient_device,
                    ratchet_index, source_ack_intent, ack_nonce, seal_nonce, anti_replay_nonce,
                    immutable_envelope_bytes, state, session_generation
             FROM endpoint_outbox",
                |r| raw(r, 0, 14),
            )?;
            let corrupt = |_| RebuildError::Sqlite(rusqlite::Error::InvalidQuery);
            let mut n = 0;
            for mut v in rows {
                steps.step()?;
                let rowid = int(&mut v, 0).map_err(corrupt)?;
                let sid = blob(&mut v, 1).map_err(corrupt)?;
                let od = blob(&mut v, 2).map_err(corrupt)?;
                let m = blob(&mut v, 4).map_err(corrupt)?;
                let recipient = blob(&mut v, 5).map_err(corrupt)?;
                let source = opt_blob(&mut v, 7).map_err(corrupt)?;
                let ack_nonce = opt_blob(&mut v, 8).map_err(corrupt)?;
                let seal = blob(&mut v, 9).map_err(corrupt)?;
                let anti = blob(&mut v, 10).map_err(corrupt)?;
                let bytes = blob(&mut v, 11).map_err(corrupt)?;
                let kd = digest(&od);
                let key = pk(&sid, &[&kd]);
                let meta = OutboxMeta {
                    object_digest: hex::encode(&od),
                    message_id: hex::encode(&m),
                    recipient_device: hex::encode(&recipient),
                    source_ack_intent: source.as_ref().map(hex::encode),
                    ack_nonce: ack_nonce.as_ref().map(hex::encode),
                    seal_nonce: hex::encode(&seal),
                    anti_replay_nonce: hex::encode(&anti),
                };
                tx.execute(
                    "INSERT INTO endpoint_outbox__new
                   (rowid, session_id, kh_object_digest, kind, kh_message_id,
                    kh_recipient_device, ratchet_index, kh_source_ack_intent, kh_ack_nonce,
                    kh_seal_nonce, kh_anti_replay_nonce, immutable_envelope_bytes, kh_envelope,
                    state, session_generation, meta)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
                    params![
                        rowid,
                        sid,
                        kd.as_slice(),
                        take(&mut v, 3),
                        mid(&m).as_slice(),
                        device(&recipient).as_slice(),
                        take(&mut v, 6),
                        source.as_ref().map(|s| digest(s).to_vec()),
                        ack_nonce.as_ref().map(|s| nonce(s).to_vec()),
                        nonce(&seal).as_slice(),
                        nonce(&anti).as_slice(),
                        at_rest::seal_row(keys, ENVELOPE_LABEL, &key, &bytes),
                        object_bytes(&bytes).as_slice(),
                        take(&mut v, 12),
                        take(&mut v, 13),
                        seal_json(keys, OUTBOX, &key, &meta),
                    ],
                )?;
                n += 1;
            }
            Ok(n)
        },
        "",
    )?;

    // The tombstones: a `seq` that places each after the sender's newest
    // row stamped before it.
    for stamps in stamped.values_mut() {
        stamps.sort_unstable();
    }
    moved += rebuild_table(
        tx,
        steps,
        DELETED,
        &keyed_columns(DELETED),
        |tx, steps| {
            type Row = (i64, Vec<u8>, Vec<u8>, Vec<u8>, i64, i64);
            let rows: Vec<Row> = rows_of(
                tx,
                "SELECT rowid, session_id, object_digest, sender_device, deleted_at_ms,
                    max_received_at_ms FROM endpoint_inbox_deleted",
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                    ))
                },
            )?;
            let mut n = 0;
            for (rowid, sid, od, sender, deleted_at, max_received) in rows {
                steps.step()?;
                let kd = digest(&od);
                let placed = stamped
                    .get(&sender)
                    .map(|stamps| {
                        stamps
                            .iter()
                            .filter(|(received, _)| *received < max_received)
                            .map(|(_, seq)| *seq)
                            .max()
                            .unwrap_or(0)
                    })
                    .unwrap_or(0);
                let meta = DeletedMeta {
                    object_digest: hex::encode(&od),
                    sender_device: hex::encode(&sender),
                    deleted_at_ms: deleted_at,
                    max_received_at_ms: max_received,
                };
                tx.execute(
                    "INSERT INTO endpoint_inbox_deleted__new
                   (rowid, session_id, kh_object_digest, kh_sender_device, seq, meta)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        rowid,
                        sid,
                        kd.as_slice(),
                        device(&sender).as_slice(),
                        placed,
                        seal_json(keys, DELETED, &pk(&sid, &[&kd]), &meta),
                    ],
                )?;
                n += 1;
            }
            Ok(n)
        },
        keyed_indexes(DELETED),
    )?;
    Ok(moved)
}

/// Schema 3 -> 2's part of `sealed::migrate_back`: the seven endpoint tables
/// in today's clear columns, rowids kept (the inbox's `seq` is its rowid
/// again; the tombstones' `seq` goes). A row whose sealed values do not open
/// here is left out and counted, and so are the inbox row and ACK intent of
/// a receipt left out (their foreign key would point nowhere).
pub(super) fn move_back(
    tx: &Transaction<'_>,
    keys: &MetaKeys,
    steps: &mut Steps,
    expected: &mut [(&'static str, i64)],
    report: &mut Migration,
) -> Result<(), RebuildError> {
    let mut gone: HashSet<Vec<u8>> = HashSet::new();

    rebuild_table(
        tx,
        steps,
        RECEIPTS,
        clear_columns(RECEIPTS),
        |tx, steps| {
            type Row = (i64, Vec<u8>, Vec<u8>, i64, Vec<u8>);
            let rows: Vec<Row> = rows_of(
                tx,
                "SELECT rowid, session_id, kh_object_digest, session_generation, meta
             FROM endpoint_receipts",
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )?;
            for (rowid, sid, kd, generation, meta) in rows {
                steps.step()?;
                let key = pk(&sid, &[&kd]);
                let Some(meta) = open_json::<ReceiptMeta>(keys, RECEIPTS, &key, &meta) else {
                    sealed::dropped(expected, RECEIPTS, report);
                    gone.insert(key);
                    continue;
                };
                let values = (
                    unhex(&meta.object_digest),
                    unhex(&meta.message_id),
                    unhex(&meta.sender_device),
                );
                let (Ok(od), Ok(m), Ok(sender)) = values else {
                    sealed::dropped(expected, RECEIPTS, report);
                    gone.insert(key);
                    continue;
                };
                tx.execute(
                    "INSERT INTO endpoint_receipts__new
                   (rowid, session_id, object_digest, message_id, sender_device,
                    session_generation)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![rowid, sid, od, m, sender, generation],
                )?;
                report.rows += 1;
            }
            Ok(0)
        },
        "",
    )?;

    rebuild_table(
        tx,
        steps,
        INBOX,
        clear_columns(INBOX),
        |tx, steps| {
            type Row = (i64, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);
            let rows: Vec<Row> = rows_of(
                tx,
                "SELECT seq, session_id, kh_object_digest, meta, sealed_local_row
             FROM endpoint_inbox",
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )?;
            for (seq, sid, kd, meta, local) in rows {
                steps.step()?;
                let key = pk(&sid, &[&kd]);
                let opened = (!gone.contains(&key))
                    .then(|| open_json::<InboxMeta>(keys, INBOX, &key, &meta))
                    .flatten();
                let values = opened.and_then(|meta| {
                    Some((
                        unhex(&meta.object_digest).ok()?,
                        unhex(&meta.message_id).ok()?,
                        unhex(&meta.sender_device).ok()?,
                        meta.created_at_ms,
                        meta.received_at_ms,
                    ))
                });
                let Some((od, m, sender, created, received)) = values else {
                    sealed::dropped(expected, INBOX, report);
                    continue;
                };
                tx.execute(
                    "INSERT INTO endpoint_inbox__new
                   (rowid, session_id, object_digest, message_id, sender_device, created_at_ms,
                    received_at_ms, sealed_local_row)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![seq, sid, od, m, sender, created, received, local],
                )?;
                report.rows += 1;
            }
            Ok(0)
        },
        "",
    )?;

    rebuild_table(
        tx,
        steps,
        ACK_INTENTS,
        clear_columns(ACK_INTENTS),
        |tx, steps| {
            type Row = (i64, Vec<u8>, Vec<u8>, i64, i64, Option<Vec<u8>>, Vec<u8>);
            let rows: Vec<Row> = rows_of(
            tx,
            "SELECT rowid, session_id, kh_object_digest, status, state, immutable_ack_bytes, meta
             FROM endpoint_ack_intents",
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                ))
            },
        )?;
            for (rowid, sid, kd, status, state, sealed_bytes, meta) in rows {
                steps.step()?;
                let key = pk(&sid, &[&kd]);
                let opened = (!gone.contains(&key))
                    .then(|| open_json::<AckIntentMeta>(keys, ACK_INTENTS, &key, &meta))
                    .flatten();
                let bytes = match &sealed_bytes {
                    None => Some(None),
                    Some(sealed) => at_rest::open_row(keys, ACK_LABEL, &key, sealed)
                        .ok()
                        .map(|plain| Some(plain.to_vec())),
                };
                let values = opened.zip(bytes).and_then(|(meta, bytes)| {
                    Some((
                        unhex(&meta.object_digest).ok()?,
                        unhex(&meta.message_id).ok()?,
                        unhex(&meta.remote_device).ok()?,
                        bytes,
                    ))
                });
                let Some((od, m, remote, bytes)) = values else {
                    sealed::dropped(expected, ACK_INTENTS, report);
                    continue;
                };
                tx.execute(
                    "INSERT INTO endpoint_ack_intents__new
                   (rowid, session_id, object_digest, message_id, remote_device, status, state,
                    immutable_ack_bytes)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![rowid, sid, od, m, remote, status, state, bytes],
                )?;
                report.rows += 1;
            }
            Ok(0)
        },
        "",
    )?;

    rebuild_table(
        tx,
        steps,
        OUTSTANDING,
        clear_columns(OUTSTANDING),
        |tx, steps| {
            type Row = (i64, Vec<u8>, Vec<u8>, Vec<u8>, i64, Vec<u8>);
            let rows: Vec<Row> = rows_of(
                tx,
                "SELECT rowid, session_id, kh_message_id, kh_recipient_device, delivery_state, meta
             FROM endpoint_outstanding_messages",
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                    ))
                },
            )?;
            for (rowid, sid, km, kr, delivery, meta) in rows {
                steps.step()?;
                let key = pk(&sid, &[&km, &kr]);
                let values =
                    open_json::<OutstandingMeta>(keys, OUTSTANDING, &key, &meta).and_then(|meta| {
                        Some((
                            unhex(&meta.message_id).ok()?,
                            unhex(&meta.recipient_device).ok()?,
                        ))
                    });
                let Some((m, recipient)) = values else {
                    sealed::dropped(expected, OUTSTANDING, report);
                    continue;
                };
                tx.execute(
                    "INSERT INTO endpoint_outstanding_messages__new
                   (rowid, session_id, message_id, recipient_device, delivery_state)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![rowid, sid, m, recipient, delivery],
                )?;
                report.rows += 1;
            }
            Ok(0)
        },
        "",
    )?;

    rebuild_table(
        tx,
        steps,
        ACK_RECEIPTS,
        clear_columns(ACK_RECEIPTS),
        |tx, steps| {
            type Row = (i64, Vec<u8>, Vec<u8>, i64, i64, Vec<u8>);
            let rows: Vec<Row> = rows_of(
                tx,
                "SELECT rowid, session_id, kh_object_digest, status, session_generation, meta
             FROM endpoint_ack_receipts",
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                    ))
                },
            )?;
            for (rowid, sid, kd, status, generation, meta) in rows {
                steps.step()?;
                let key = pk(&sid, &[&kd]);
                let values =
                    open_json::<AckReceiptMeta>(keys, ACK_RECEIPTS, &key, &meta).and_then(|meta| {
                        Some((
                            unhex(&meta.object_digest).ok()?,
                            unhex(&meta.outer_message_id).ok()?,
                            unhex(&meta.remote_device).ok()?,
                            unhex(&meta.acked_message_id).ok()?,
                            unhex(&meta.ack_nonce).ok()?,
                            meta.created_at_ms,
                        ))
                    });
                let Some((od, outer, remote, acked, ack_nonce, created)) = values else {
                    sealed::dropped(expected, ACK_RECEIPTS, report);
                    continue;
                };
                tx.execute(
                    "INSERT INTO endpoint_ack_receipts__new
                   (rowid, session_id, object_digest, outer_message_id, remote_device,
                    acked_message_id, status, ack_nonce, created_at_ms, session_generation)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                    params![
                        rowid, sid, od, outer, remote, acked, status, ack_nonce, created,
                        generation
                    ],
                )?;
                report.rows += 1;
            }
            Ok(0)
        },
        "",
    )?;

    rebuild_table(
        tx,
        steps,
        OUTBOX,
        clear_columns(OUTBOX),
        |tx, steps| {
            type Row = (i64, Vec<u8>, Vec<u8>, i64, i64, Vec<u8>, i64, i64, Vec<u8>);
            let rows: Vec<Row> = rows_of(
                tx,
                "SELECT rowid, session_id, kh_object_digest, kind, ratchet_index,
                    immutable_envelope_bytes, state, session_generation, meta
             FROM endpoint_outbox",
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                        r.get(7)?,
                        r.get(8)?,
                    ))
                },
            )?;
            for (rowid, sid, kd, kind, index, sealed_bytes, state, generation, meta) in rows {
                steps.step()?;
                let key = pk(&sid, &[&kd]);
                let bytes = at_rest::open_row(keys, ENVELOPE_LABEL, &key, &sealed_bytes)
                    .ok()
                    .map(|plain| plain.to_vec());
                let values = open_json::<OutboxMeta>(keys, OUTBOX, &key, &meta)
                    .zip(bytes)
                    .and_then(|(meta, bytes)| {
                        Some((
                            unhex(&meta.object_digest).ok()?,
                            unhex(&meta.message_id).ok()?,
                            unhex(&meta.recipient_device).ok()?,
                            unhex_opt(meta.source_ack_intent.as_ref()).ok()?,
                            unhex_opt(meta.ack_nonce.as_ref()).ok()?,
                            unhex(&meta.seal_nonce).ok()?,
                            unhex(&meta.anti_replay_nonce).ok()?,
                            bytes,
                        ))
                    });
                let Some((od, m, recipient, source, ack_nonce, seal, anti, bytes)) = values else {
                    sealed::dropped(expected, OUTBOX, report);
                    continue;
                };
                tx.execute(
                    "INSERT INTO endpoint_outbox__new
                   (rowid, session_id, object_digest, kind, message_id, recipient_device,
                    ratchet_index, source_ack_intent, ack_nonce, seal_nonce, anti_replay_nonce,
                    immutable_envelope_bytes, state, session_generation)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                    params![
                        rowid, sid, od, kind, m, recipient, index, source, ack_nonce, seal, anti,
                        bytes, state, generation
                    ],
                )?;
                report.rows += 1;
            }
            Ok(0)
        },
        "",
    )?;

    rebuild_table(
        tx,
        steps,
        DELETED,
        clear_columns(DELETED),
        |tx, steps| {
            type Row = (i64, Vec<u8>, Vec<u8>, Vec<u8>);
            let rows: Vec<Row> = rows_of(
                tx,
                "SELECT rowid, session_id, kh_object_digest, meta FROM endpoint_inbox_deleted",
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )?;
            for (rowid, sid, kd, meta) in rows {
                steps.step()?;
                let key = pk(&sid, &[&kd]);
                let values =
                    open_json::<DeletedMeta>(keys, DELETED, &key, &meta).and_then(|meta| {
                        Some((
                            unhex(&meta.object_digest).ok()?,
                            unhex(&meta.sender_device).ok()?,
                            meta.deleted_at_ms,
                            meta.max_received_at_ms,
                        ))
                    });
                let Some((od, sender, deleted_at, max_received)) = values else {
                    sealed::dropped(expected, DELETED, report);
                    continue;
                };
                tx.execute(
                    "INSERT INTO endpoint_inbox_deleted__new
                   (rowid, session_id, object_digest, sender_device, deleted_at_ms,
                    max_received_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![rowid, sid, od, sender, deleted_at, max_received],
                )?;
                report.rows += 1;
            }
            Ok(0)
        },
        "",
    )?;
    Ok(())
}
