//! The long message horizon's store half (Phase 5 part 5a, P5.4;
//! [`crate::horizon`]): parked outbound messages and the inbound messages
//! already seen.
//!
//! **Parked outbound** (`endpoint_parked_outbound`): a message whose envelope
//! or session expired before its deadline (`created_at +`
//! [`crate::horizon::MESSAGE_HORIZON_MS`]) leaves the outbox and waits here,
//! one row per contact and message id, until the horizon step seals it again
//! into a fresh session ([`IndexedSessionStore::reseal_parked_envelope`], the
//! seal and the unpark in one transaction) or gives it up
//! ([`IndexedSessionStore::give_up_parked`]). Parking keeps the message's
//! `endpoint_outstanding_messages` row, so a late ACK under the old session
//! still settles it. The session prune never touches a parked row: the
//! worker owns the deadlines. Rows come back in the original send order:
//! the message's `created_at_ms`, then `send_order` (the order rows were
//! first parked in, kept equal to the row's rowid, which every rebuild
//! keeps).
//!
//! **Inbound seen** (`endpoint_inbound_seen`): the message ids a contact's
//! messages arrived under, kept until `keep_until_ms` (the sender's deadline
//! plus a day), so a receiver collapses a re-sealed copy even after the
//! first copy's inbox row was pruned or left the 2,000-entry history.
//! While receiver dedup is live ([`crate::horizon::receiver_dedup_live`],
//! P5.5) the accept path notes each message in its own transaction at its
//! receive time, kept the horizon plus a day from then
//! ([`IndexedSessionStore::inbound_received_again`] tells a later copy).
//! [`IndexedSessionStore::prune_expired_sessions`] deletes the rows past it.
//!
//! Both tables are additive (`CREATE TABLE IF NOT EXISTS`) in either schema,
//! like session renewal's ([`super::renewal`]): a profile that is not sealed
//! keeps schema 1's clear columns (older builds ignore the tables); a sealed
//! profile's store (schema 4, [`super::sealed`]) keys the device and the
//! message id (`kh_*`, the AAD of the row's sealed `meta`) and seals every
//! other value, the inbound table with a clear prune hour.
//! [`METADATA_SCHEMA_VERSION`] is unchanged. The moves to and from schema 4
//! and a re-key carry the rows with their rowids ([`move_forward`],
//! [`move_back`]); a table found in the other layout's shape is handled as
//! session renewal's is ([`ensure_tables`]). Removing a contact forgets its
//! rows in both tables ([`forget`], storage rule "real erase"): the horizon
//! step never sends to a removed contact. Its parked messages are given up
//! before that, stage and history included
//! ([`crate::horizon::give_up_parked_for_contact`]), so no staged body is
//! left behind (review 5a-2).

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::sealed::{self, Layout};
use super::*;
use crate::at_rest::{self, MetaKeys, ValueType};
use crate::sqlite_rebuild::{self as rebuild, Migration, RebuildError, Steps};

/// The parked outbound messages' table.
pub(super) const PARKED: &str = "endpoint_parked_outbound";
/// The inbound messages already seen.
pub(super) const SEEN: &str = "endpoint_inbound_seen";

/// Their sealed values in schema 4: one `meta` per row, bound to the keyed
/// device and message id.
pub(super) const SEALED: [sealed::SealedColumn; 2] = [
    (
        PARKED,
        "meta",
        PARKED,
        &["kh_recipient_device", "kh_message_id"],
    ),
    (SEEN, "meta", SEEN, &["kh_peer_device", "kh_message_id"]),
];

/// One parked outbound message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParkedOutbound {
    pub recipient_device: [u8; 32],
    pub message_id: [u8; 16],
    /// When the message was written (the history's or stage's time, not a
    /// re-sealed envelope's).
    pub created_at_ms: u64,
    /// Until when Raven keeps trying; set once, never extended.
    pub deadline_ms: u64,
    /// When it was first parked.
    pub parked_at_ms: u64,
    /// The session of the copy parked last (`None`: none was named).
    pub from_session: Option<[u8; 32]>,
    /// Breaks ties of `created_at_ms`: the order rows were first parked in.
    pub send_order: u64,
}

/// A contact with parked messages (the worker's probe entry).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParkedPeer {
    pub peer: [u8; 32],
    pub parked: usize,
    pub first_deadline_ms: u64,
    pub last_deadline_ms: u64,
}

/// One inbound message seen.
#[derive(Debug, Clone, PartialEq, Eq)]
struct InboundSeen {
    peer_device: [u8; 32],
    message_id: [u8; 16],
    first_seen_ms: u64,
    keep_until_ms: u64,
}

#[derive(Serialize, Deserialize)]
pub(super) struct ParkedMeta {
    recipient_device: String,
    message_id: String,
    created_at_ms: i64,
    deadline_ms: i64,
    parked_at_ms: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    from_session: String,
    send_order: i64,
}

#[derive(Serialize, Deserialize)]
pub(super) struct SeenMeta {
    peer_device: String,
    message_id: String,
    first_seen_ms: i64,
    keep_until_ms: i64,
}

/// A keyed row's sealed `meta`, as stored.
type KeyedMeta = Vec<u8>;

fn ms(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn unsigned(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

fn array<const N: usize>(hex_value: &str) -> Option<[u8; N]> {
    hex::decode(hex_value).ok()?.try_into().ok()
}

// ── One table, in either layout ──────────────────────────────────────────

/// A row of one of the two tables: keyed by a device and a message id, the
/// other values clear (schema 1) or in the sealed `meta` (schema 4).
trait KeptRow: Sized {
    const TABLE: &'static str;
    /// The clear device column (`kh_<name>` when keyed).
    const DEVICE: &'static str;
    /// The clear columns after the device and the message id.
    const VALUES: &'static [&'static str];
    /// The keyed table keeps a clear prune hour.
    const HOUR: bool;
    type Meta: Serialize + DeserializeOwned;

    fn columns(keyed: bool) -> &'static str;
    fn device(&self) -> &[u8; 32];
    fn message_id(&self) -> &[u8; 16];
    /// The clear values ([`Self::VALUES`]) read from `row` at `at`.
    fn from_clear(
        device: [u8; 32],
        message_id: [u8; 16],
        row: &rusqlite::Row<'_>,
        at: usize,
    ) -> rusqlite::Result<Self>;
    fn clear_values(&self) -> Vec<rusqlite::types::Value>;
    fn meta(&self) -> Self::Meta;
    /// `None` when a value is out of range.
    fn from_meta(meta: Self::Meta) -> Option<Self>;
    /// The keyed row's prune hour ([`Self::HOUR`]).
    fn hour(&self) -> i64 {
        0
    }
}

impl KeptRow for ParkedOutbound {
    const TABLE: &'static str = PARKED;
    const DEVICE: &'static str = "recipient_device";
    const VALUES: &'static [&'static str] = &[
        "created_at_ms",
        "deadline_ms",
        "parked_at_ms",
        "from_session",
        "send_order",
    ];
    const HOUR: bool = false;
    type Meta = ParkedMeta;

    fn columns(keyed: bool) -> &'static str {
        if keyed {
            "kh_recipient_device BLOB NOT NULL CHECK(length(kh_recipient_device) = 32),
             kh_message_id       BLOB NOT NULL CHECK(length(kh_message_id) = 32),
             meta                BLOB NOT NULL,
             PRIMARY KEY(kh_recipient_device, kh_message_id)"
        } else {
            "recipient_device BLOB NOT NULL CHECK(length(recipient_device) = 32),
             message_id       BLOB NOT NULL CHECK(length(message_id) = 16),
             created_at_ms    INTEGER NOT NULL CHECK(created_at_ms >= 0),
             deadline_ms      INTEGER NOT NULL CHECK(deadline_ms > created_at_ms),
             parked_at_ms     INTEGER NOT NULL CHECK(parked_at_ms >= 0),
             from_session     BLOB CHECK(from_session IS NULL OR length(from_session) = 32),
             send_order       INTEGER NOT NULL CHECK(send_order >= 0),
             PRIMARY KEY(recipient_device, message_id)"
        }
    }

    fn device(&self) -> &[u8; 32] {
        &self.recipient_device
    }

    fn message_id(&self) -> &[u8; 16] {
        &self.message_id
    }

    fn from_clear(
        device: [u8; 32],
        message_id: [u8; 16],
        row: &rusqlite::Row<'_>,
        at: usize,
    ) -> rusqlite::Result<Self> {
        Ok(Self {
            recipient_device: device,
            message_id,
            created_at_ms: unsigned(row.get(at)?),
            deadline_ms: unsigned(row.get(at + 1)?),
            parked_at_ms: unsigned(row.get(at + 2)?),
            from_session: row.get(at + 3)?,
            send_order: unsigned(row.get(at + 4)?),
        })
    }

    fn clear_values(&self) -> Vec<rusqlite::types::Value> {
        use rusqlite::types::Value;
        vec![
            Value::Integer(ms(self.created_at_ms)),
            Value::Integer(ms(self.deadline_ms)),
            Value::Integer(ms(self.parked_at_ms)),
            self.from_session
                .map_or(Value::Null, |sid| Value::Blob(sid.to_vec())),
            Value::Integer(ms(self.send_order)),
        ]
    }

    fn meta(&self) -> ParkedMeta {
        ParkedMeta {
            recipient_device: hex::encode(self.recipient_device),
            message_id: hex::encode(self.message_id),
            created_at_ms: ms(self.created_at_ms),
            deadline_ms: ms(self.deadline_ms),
            parked_at_ms: ms(self.parked_at_ms),
            from_session: self.from_session.map(hex::encode).unwrap_or_default(),
            send_order: ms(self.send_order),
        }
    }

    fn from_meta(meta: ParkedMeta) -> Option<Self> {
        let from_session = if meta.from_session.is_empty() {
            None
        } else {
            Some(array(&meta.from_session)?)
        };
        Some(Self {
            recipient_device: array(&meta.recipient_device)?,
            message_id: array(&meta.message_id)?,
            created_at_ms: u64::try_from(meta.created_at_ms).ok()?,
            deadline_ms: u64::try_from(meta.deadline_ms).ok()?,
            parked_at_ms: u64::try_from(meta.parked_at_ms).ok()?,
            from_session,
            send_order: u64::try_from(meta.send_order).ok()?,
        })
    }
}

impl KeptRow for InboundSeen {
    const TABLE: &'static str = SEEN;
    const DEVICE: &'static str = "peer_device";
    const VALUES: &'static [&'static str] = &["first_seen_ms", "keep_until_ms"];
    const HOUR: bool = true;
    type Meta = SeenMeta;

    fn columns(keyed: bool) -> &'static str {
        if keyed {
            "kh_peer_device   BLOB NOT NULL CHECK(length(kh_peer_device) = 32),
             kh_message_id    BLOB NOT NULL CHECK(length(kh_message_id) = 32),
             prune_after_hour INTEGER NOT NULL,
             meta             BLOB NOT NULL,
             PRIMARY KEY(kh_peer_device, kh_message_id)"
        } else {
            "peer_device   BLOB NOT NULL CHECK(length(peer_device) = 32),
             message_id    BLOB NOT NULL CHECK(length(message_id) = 16),
             first_seen_ms INTEGER NOT NULL CHECK(first_seen_ms >= 0),
             keep_until_ms INTEGER NOT NULL CHECK(keep_until_ms >= 0),
             PRIMARY KEY(peer_device, message_id)"
        }
    }

    fn device(&self) -> &[u8; 32] {
        &self.peer_device
    }

    fn message_id(&self) -> &[u8; 16] {
        &self.message_id
    }

    fn from_clear(
        device: [u8; 32],
        message_id: [u8; 16],
        row: &rusqlite::Row<'_>,
        at: usize,
    ) -> rusqlite::Result<Self> {
        Ok(Self {
            peer_device: device,
            message_id,
            first_seen_ms: unsigned(row.get(at)?),
            keep_until_ms: unsigned(row.get(at + 1)?),
        })
    }

    fn clear_values(&self) -> Vec<rusqlite::types::Value> {
        use rusqlite::types::Value;
        vec![
            Value::Integer(ms(self.first_seen_ms)),
            Value::Integer(ms(self.keep_until_ms)),
        ]
    }

    fn meta(&self) -> SeenMeta {
        SeenMeta {
            peer_device: hex::encode(self.peer_device),
            message_id: hex::encode(self.message_id),
            first_seen_ms: ms(self.first_seen_ms),
            keep_until_ms: ms(self.keep_until_ms),
        }
    }

    fn from_meta(meta: SeenMeta) -> Option<Self> {
        Some(Self {
            peer_device: array(&meta.peer_device)?,
            message_id: array(&meta.message_id)?,
            first_seen_ms: u64::try_from(meta.first_seen_ms).ok()?,
            keep_until_ms: u64::try_from(meta.keep_until_ms).ok()?,
        })
    }

    /// The row goes once `keep_until_ms` has passed.
    fn hour(&self) -> i64 {
        sealed::prune_hour(ms(self.keep_until_ms))
    }
}

/// The keyed device and message id of a row, and the AAD of its `meta`.
fn keyed_pk(keys: &MetaKeys, device: &[u8], message_id: &[u8]) -> ([u8; 32], [u8; 32], Vec<u8>) {
    let kd = at_rest::index(keys, ValueType::DeviceKey, device);
    let km = at_rest::index(keys, ValueType::MessageId, message_id);
    (kd, km, [kd.as_slice(), km.as_slice()].concat())
}

fn sealer_pk(sealer: &sealed::Sealer, device: &[u8], message_id: &[u8]) -> ([u8; 32], [u8; 32]) {
    (sealer.device(device), sealer.message_id(message_id))
}

/// Whether the store holds `T`'s table keyed (schema 4's shape).
fn table_keyed<T: KeptRow>(conn: &Connection) -> rusqlite::Result<bool> {
    let keyed = format!("kh_{}", T::DEVICE);
    Ok(rebuild::columns(conn, T::TABLE)?.contains(&keyed))
}

/// The parked table's columns in either shape (tests build older stores).
#[cfg(test)]
pub(super) fn parked_columns(keyed: bool) -> &'static str {
    ParkedOutbound::columns(keyed)
}

/// Both tables keyed (a store [`ensure_keyed`] or a move made keyed).
pub(super) fn keyed(conn: &Connection) -> rusqlite::Result<bool> {
    Ok(table_keyed::<ParkedOutbound>(conn)? && table_keyed::<InboundSeen>(conn)?)
}

/// `T`'s table, created in the shape `keyed` asks for when it is missing;
/// a keyed table where a clear one is wanted is dropped and created clear
/// (nothing here can open its rows without the keys), as session renewal's
/// ([`super::renewal::ensure_table`]): only while the store's heads are
/// clear, so a keyed store's table stays (another opener's move to schema 4
/// committed after the caller read the store's shape; review C-2).
fn ensure_table<T: KeptRow>(conn: &Connection, keyed: bool) -> rusqlite::Result<()> {
    let create = sealed::create_if_missing(T::TABLE, T::columns(keyed));
    if keyed || !table_keyed::<T>(conn)? {
        return conn.execute_batch(&create);
    }
    let replace = |conn: &Connection| -> rusqlite::Result<()> {
        if !table_keyed::<T>(conn)? {
            return conn.execute_batch(&create);
        }
        if rebuild::shape(conn, sealed::HEADS, sealed::KEYED_COLUMN)? == rebuild::Shape::Keyed {
            return Ok(());
        }
        conn.execute_batch(&format!("DROP TABLE {};", T::TABLE))?;
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

/// Both tables, in the shape `keyed` asks for when they are missing.
pub(super) fn ensure_tables(conn: &Connection, keyed: bool) -> rusqlite::Result<()> {
    ensure_table::<ParkedOutbound>(conn, keyed)?;
    ensure_table::<InboundSeen>(conn, keyed)
}

/// Schema 1's open: both tables, clear when missing.
pub(super) fn create_parked_schema(conn: &Connection) -> Result<(), IndexedSessionStoreError> {
    ensure_tables(conn, false)?;
    Ok(())
}

/// A keyed store's open ([`sealed::prepare_schema`]): both tables keyed, and
/// clear rows an older build of the pack left behind moved forward, in one
/// IMMEDIATE transaction that reads the tables' and the heads' shape again.
/// `false`: the heads are clear now (an unseal moved the store back since
/// the open read its shape), nothing is changed and the open reads the
/// store again, as session renewal's ([`super::renewal::ensure_keyed`],
/// review C-2).
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
    ensure_tables(&tx, true)?;
    if !keyed(&tx)? {
        move_forward(&tx, keys, &mut Steps::default()).map_err(super::rebuild_error)?;
    }
    tx.commit()?;
    Ok(true)
}

fn keyed_device_column<T: KeptRow>() -> String {
    format!("kh_{}", T::DEVICE)
}

/// One keyed row's `meta` opened and checked against its keyed device.
fn open_keyed<T: KeptRow>(
    sealer: &sealed::Sealer,
    kd: &[u8],
    km: &[u8],
    meta: &[u8],
) -> Result<T, IndexedSessionStoreError> {
    let pk = [kd, km].concat();
    let meta: T::Meta = sealer.open(T::TABLE, &pk, meta)?;
    let row = T::from_meta(meta).ok_or(IndexedSessionStoreError::CorruptEndpointState)?;
    let (rd, rm) = sealer_pk(sealer, row.device(), row.message_id());
    if rd.as_slice() != kd || rm.as_slice() != km {
        return Err(IndexedSessionStoreError::CorruptEndpointState);
    }
    Ok(row)
}

/// The rows of `T`'s table with `filter` on the device and message id (the
/// device alone, both, or neither). A keyed row whose `meta` does not open
/// fails the read (fail closed, never skipped).
fn select<T: KeptRow>(
    conn: &Connection,
    layout: &Layout,
    device: Option<&[u8; 32]>,
    message_id: Option<&[u8; 16]>,
) -> Result<Vec<T>, IndexedSessionStoreError> {
    let mut out = Vec::new();
    if let Some(sealer) = layout.keyed() {
        let mut sql = format!(
            "SELECT {}, kh_message_id, meta FROM {} WHERE 1 = 1",
            keyed_device_column::<T>(),
            T::TABLE
        );
        let mut values: Vec<Vec<u8>> = Vec::new();
        if let Some(device) = device {
            sql.push_str(&format!(" AND {} = ?", keyed_device_column::<T>()));
            values.push(sealer.device(device).to_vec());
        }
        if let Some(mid) = message_id {
            sql.push_str(" AND kh_message_id = ?");
            values.push(sealer.message_id(mid).to_vec());
        }
        sql.push_str(" ORDER BY rowid");
        let rows: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = {
            let mut statement = conn.prepare(&sql)?;
            let mapped = statement.query_map(rusqlite::params_from_iter(values.iter()), |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })?;
            mapped.collect::<Result<_, _>>()?
        };
        for (kd, km, meta) in rows {
            out.push(open_keyed::<T>(sealer, &kd, &km, &meta)?);
        }
        return Ok(out);
    }
    let mut sql = format!(
        "SELECT {}, message_id, {} FROM {} WHERE 1 = 1",
        T::DEVICE,
        T::VALUES.join(", "),
        T::TABLE
    );
    let mut values: Vec<Vec<u8>> = Vec::new();
    if let Some(device) = device {
        sql.push_str(&format!(" AND {} = ?", T::DEVICE));
        values.push(device.to_vec());
    }
    if let Some(mid) = message_id {
        sql.push_str(" AND message_id = ?");
        values.push(mid.to_vec());
    }
    sql.push_str(" ORDER BY rowid");
    let mut statement = conn.prepare(&sql)?;
    let mapped = statement.query_map(rusqlite::params_from_iter(values.iter()), |row| {
        T::from_clear(row.get(0)?, row.get(1)?, row, 2)
    })?;
    for row in mapped {
        out.push(row?);
    }
    Ok(out)
}

fn load_one<T: KeptRow>(
    conn: &Connection,
    layout: &Layout,
    device: &[u8; 32],
    message_id: &[u8; 16],
) -> Result<Option<T>, IndexedSessionStoreError> {
    Ok(select::<T>(conn, layout, Some(device), Some(message_id))?
        .into_iter()
        .next())
}

/// Insert or replace `row` (an existing row keeps its rowid); a new row
/// gets `rowid` when one is given.
fn put<T: KeptRow>(
    conn: &Connection,
    layout: &Layout,
    row: &T,
    rowid: Option<i64>,
) -> Result<(), IndexedSessionStoreError> {
    use rusqlite::types::Value;
    let rowid = rowid.map_or(Value::Null, Value::Integer);
    if let Some(sealer) = layout.keyed() {
        let (kd, km) = sealer_pk(sealer, row.device(), row.message_id());
        let pk = [kd.as_slice(), km.as_slice()].concat();
        let device = keyed_device_column::<T>();
        let (hour_column, hour_value, hour_update) = if T::HOUR {
            (
                ", prune_after_hour",
                ", ?5",
                "prune_after_hour = excluded.prune_after_hour, ",
            )
        } else {
            ("", "", "")
        };
        let mut values = vec![
            rowid,
            Value::Blob(kd.to_vec()),
            Value::Blob(km.to_vec()),
            Value::Blob(sealer.seal(T::TABLE, &pk, &row.meta())),
        ];
        if T::HOUR {
            values.push(Value::Integer(row.hour()));
        }
        conn.execute(
            &format!(
                "INSERT INTO {table} (rowid, {device}, kh_message_id, meta{hour_column})
                 VALUES (?1, ?2, ?3, ?4{hour_value})
                 ON CONFLICT({device}, kh_message_id) DO UPDATE
                   SET {hour_update}meta = excluded.meta",
                table = T::TABLE,
            ),
            rusqlite::params_from_iter(values),
        )?;
        return Ok(());
    }
    let names = T::VALUES.join(", ");
    let marks: Vec<String> = (0..T::VALUES.len())
        .map(|n| format!("?{}", n + 4))
        .collect();
    let updates: Vec<String> = T::VALUES
        .iter()
        .map(|column| format!("{column} = excluded.{column}"))
        .collect();
    let mut values = vec![
        rowid,
        Value::Blob(row.device().to_vec()),
        Value::Blob(row.message_id().to_vec()),
    ];
    values.extend(row.clear_values());
    conn.execute(
        &format!(
            "INSERT INTO {table} (rowid, {device}, message_id, {names})
             VALUES (?1, ?2, ?3, {marks})
             ON CONFLICT({device}, message_id) DO UPDATE SET {updates}",
            table = T::TABLE,
            device = T::DEVICE,
            marks = marks.join(", "),
            updates = updates.join(", "),
        ),
        rusqlite::params_from_iter(values),
    )?;
    Ok(())
}

/// Delete `T`'s row of `device` and `message_id` (all of `device`'s with no
/// message id). How many went.
fn delete<T: KeptRow>(
    conn: &Connection,
    layout: &Layout,
    device: &[u8; 32],
    message_id: Option<&[u8; 16]>,
) -> Result<usize, IndexedSessionStoreError> {
    let (device_column, device_value, mid_value) = match layout.keyed() {
        Some(sealer) => (
            keyed_device_column::<T>(),
            sealer.device(device).to_vec(),
            message_id.map(|mid| sealer.message_id(mid).to_vec()),
        ),
        None => (
            T::DEVICE.to_owned(),
            device.to_vec(),
            message_id.map(|mid| mid.to_vec()),
        ),
    };
    let mid_column = if layout.is_keyed() {
        "kh_message_id"
    } else {
        "message_id"
    };
    Ok(match mid_value {
        Some(mid) => conn.execute(
            &format!(
                "DELETE FROM {} WHERE {device_column} = ?1 AND {mid_column} = ?2",
                T::TABLE
            ),
            params![device_value, mid],
        )?,
        None => conn.execute(
            &format!("DELETE FROM {} WHERE {device_column} = ?1", T::TABLE),
            params![device_value],
        )?,
    })
}

// ── Used by the seal path, the prune and a contact's removal ─────────────

/// Whether `message_id` to `peer` is parked (inside the seal's transaction).
pub(super) fn is_parked(
    conn: &Connection,
    layout: &Layout,
    peer: &[u8; 32],
    message_id: &[u8; 16],
) -> Result<bool, IndexedSessionStoreError> {
    let (column, device, mid) = match layout.keyed() {
        Some(sealer) => (
            "kh_recipient_device",
            sealer.device(peer).to_vec(),
            sealer.message_id(message_id).to_vec(),
        ),
        None => ("recipient_device", peer.to_vec(), message_id.to_vec()),
    };
    let mid_column = if layout.is_keyed() {
        "kh_message_id"
    } else {
        "message_id"
    };
    Ok(conn
        .query_row(
            &format!("SELECT 1 FROM {PARKED} WHERE {column} = ?1 AND {mid_column} = ?2"),
            params![device, mid],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .is_some())
}

/// A live copy of `message_id` to `peer` was just written to the outbox
/// (a message's outbound rows, applied first-hand or replayed from its
/// protected journal): its parked row goes in the same transaction, so a
/// crash leaves the message parked or sealed, never both or neither.
pub(super) fn unpark(
    conn: &Connection,
    layout: &Layout,
    peer: &[u8; 32],
    message_id: &[u8; 16],
) -> Result<usize, IndexedSessionStoreError> {
    delete::<ParkedOutbound>(conn, layout, peer, Some(message_id))
}

/// Note that a message `message_id` from `peer` arrived at `now_ms`, kept
/// until `keep_until_ms`, in the caller's transaction (the accept path's,
/// first-hand or replayed from its journal, or
/// [`IndexedSessionStore::note_inbound_seen`]'s). A later note may only
/// extend the keep; the first time stays. Whether it was new.
pub(super) fn note_seen(
    conn: &Connection,
    layout: &Layout,
    peer: &[u8; 32],
    message_id: &[u8; 16],
    now_ms: u64,
    keep_until_ms: u64,
) -> Result<bool, IndexedSessionStoreError> {
    if now_ms > i64::MAX as u64 || keep_until_ms > i64::MAX as u64 {
        return Err(IndexedSessionStoreError::EndpointNotCurrentlyValid);
    }
    let existing = load_one::<InboundSeen>(conn, layout, peer, message_id)?;
    let row = match &existing {
        Some(old) if old.keep_until_ms >= keep_until_ms => return Ok(false),
        Some(old) => InboundSeen {
            keep_until_ms,
            ..old.clone()
        },
        None => InboundSeen {
            peer_device: *peer,
            message_id: *message_id,
            first_seen_ms: now_ms,
            keep_until_ms,
        },
    };
    put(conn, layout, &row, None)?;
    Ok(existing.is_none())
}

/// Delete the inbound-seen rows whose `keep_until_ms` has passed (the
/// session prune's last step). How many went. In schema 4, the hours that
/// may have passed, then each row's exact time; a `meta` that does not open
/// goes by its hour.
pub(super) fn prune_inbound_seen(
    conn: &Connection,
    layout: &Layout,
    now_ms: u64,
) -> Result<usize, IndexedSessionStoreError> {
    let now = ms(now_ms);
    let Some(sealer) = layout.keyed() else {
        return Ok(conn.execute(
            "DELETE FROM endpoint_inbound_seen WHERE keep_until_ms < ?1",
            params![now],
        )?);
    };
    // (rowid, kh_peer_device, kh_message_id, prune_after_hour, meta)
    type Row = (i64, Vec<u8>, Vec<u8>, i64, KeyedMeta);
    let rows: Vec<Row> = {
        let mut statement = conn.prepare(
            "SELECT rowid, kh_peer_device, kh_message_id, prune_after_hour, meta
             FROM endpoint_inbound_seen WHERE prune_after_hour <= ?1",
        )?;
        let mapped = statement.query_map(params![sealed::may_have_expired(now)], |row| {
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
    let mut gone = 0;
    for (rowid, kd, km, hour, meta) in rows {
        let expired = match open_keyed::<InboundSeen>(sealer, &kd, &km, &meta) {
            Ok(seen) => seen.keep_until_ms < now_ms,
            Err(error @ IndexedSessionStoreError::MetaKeyUnavailable(_)) => return Err(error),
            Err(_) => sealed::surely_expired(hour, now),
        };
        if expired {
            gone += conn.execute(
                "DELETE FROM endpoint_inbound_seen WHERE rowid = ?1",
                params![rowid],
            )?;
        }
    }
    Ok(gone)
}

/// Forget `peer`'s rows in both tables (its contact was removed), in
/// whichever shape the tables have; no table is fine. The metadata reader's
/// connection ([`super::forget_session_end`]): nothing is created.
pub(super) fn forget(
    conn: &Connection,
    sealer: Option<&sealed::Sealer>,
    peer: &[u8; 32],
) -> Result<(), IndexedSessionStoreError> {
    fn forget_in<T: KeptRow>(
        conn: &Connection,
        sealer: Option<&sealed::Sealer>,
        peer: &[u8; 32],
    ) -> Result<(), IndexedSessionStoreError> {
        let columns = rebuild::columns(conn, T::TABLE)?;
        let keyed = keyed_device_column::<T>();
        if columns.contains(&keyed) {
            if let Some(sealer) = sealer {
                conn.execute(
                    &format!("DELETE FROM {} WHERE {keyed} = ?1", T::TABLE),
                    params![sealer.device(peer).as_slice()],
                )?;
            }
        } else if columns.iter().any(|column| column == T::DEVICE) {
            conn.execute(
                &format!("DELETE FROM {} WHERE {} = ?1", T::TABLE, T::DEVICE),
                params![peer.as_slice()],
            )?;
        }
        Ok(())
    }
    forget_in::<ParkedOutbound>(conn, sealer, peer)?;
    forget_in::<InboundSeen>(conn, sealer, peer)
}

// ── The store's API ──────────────────────────────────────────────────────

impl IndexedSessionStore {
    /// Park the message `message_id` to `peer` until `deadline_ms`, in one
    /// IMMEDIATE transaction: the parked row (an existing one keeps its send
    /// order, its first `created_at_ms` and `parked_at_ms`, and the earliest
    /// deadline wins), and the copy's outbox row in `from_session` deleted
    /// (`None`, or a copy already gone: nothing to delete, as for a session
    /// the prune took). Its `endpoint_outstanding_messages` row stays, so a
    /// late ACK under that session still settles the message. `Ok(false)`:
    /// nothing changed, because an ACK already settled a copy or the
    /// deadline has passed (the caller gives the message up).
    pub fn park_outbound(
        &mut self,
        peer: &[u8; 32],
        message_id: &[u8; 16],
        from_session: Option<&[u8; 32]>,
        created_at_ms: u64,
        deadline_ms: u64,
        now_ms: u64,
    ) -> Result<bool, IndexedSessionStoreError> {
        if deadline_ms <= created_at_ms
            || deadline_ms > i64::MAX as u64
            || now_ms > i64::MAX as u64
            || *message_id == [0u8; 16]
        {
            return Err(IndexedSessionStoreError::EndpointNotCurrentlyValid);
        }
        if now_ms >= deadline_ms {
            return Ok(false);
        }
        let layout = &self.layout;
        sealed::in_write_tx(&self.conn, |conn| {
            let settled = conn
                .query_row(
                    &layout.ep("SELECT 1 FROM endpoint_outstanding_messages
                         WHERE kh_recipient_device = ?1 AND kh_message_id = ?2
                           AND delivery_state IN (1, 2)
                         LIMIT 1"),
                    params![layout.ep_device(peer), layout.ep_mid(message_id)],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?
                .is_some();
            if settled {
                return Ok(false);
            }
            if let Some(sid) = from_session {
                conn.execute(
                    &layout.ep("DELETE FROM endpoint_outbox
                         WHERE session_id = ?1 AND kh_message_id = ?2
                           AND kh_recipient_device = ?3 AND kind = 1"),
                    params![
                        sid.as_slice(),
                        layout.ep_mid(message_id),
                        layout.ep_device(peer)
                    ],
                )?;
            }
            let existing = load_one::<ParkedOutbound>(conn, layout, peer, message_id)?;
            let (row, rowid) = match existing {
                Some(old) => (
                    ParkedOutbound {
                        created_at_ms: old.created_at_ms.min(created_at_ms),
                        deadline_ms: old.deadline_ms.min(deadline_ms),
                        from_session: from_session.copied().or(old.from_session),
                        ..old
                    },
                    None,
                ),
                None => {
                    // The next rowid, which the row takes: its send order.
                    let next: i64 = conn.query_row(
                        &format!("SELECT COALESCE(MAX(rowid), 0) + 1 FROM {PARKED}"),
                        [],
                        |row| row.get(0),
                    )?;
                    (
                        ParkedOutbound {
                            recipient_device: *peer,
                            message_id: *message_id,
                            created_at_ms,
                            deadline_ms,
                            parked_at_ms: now_ms,
                            from_session: from_session.copied(),
                            send_order: unsigned(next),
                        },
                        Some(next),
                    )
                }
            };
            put(conn, layout, &row, rowid)?;
            Ok(true)
        })
    }

    /// `peer`'s parked messages in the original send order (`created_at_ms`,
    /// then `send_order`).
    pub fn parked_for_recipient(
        &self,
        peer: &[u8; 32],
    ) -> Result<Vec<ParkedOutbound>, IndexedSessionStoreError> {
        let mut rows = select::<ParkedOutbound>(&self.conn, &self.layout, Some(peer), None)?;
        rows.sort_by_key(|row| (row.created_at_ms, row.send_order));
        Ok(rows)
    }

    /// Every contact with parked messages, by device key: how many, and the
    /// first and last deadline.
    pub fn parked_peers(&self) -> Result<Vec<ParkedPeer>, IndexedSessionStoreError> {
        let mut peers: std::collections::BTreeMap<[u8; 32], ParkedPeer> =
            std::collections::BTreeMap::new();
        for row in select::<ParkedOutbound>(&self.conn, &self.layout, None, None)? {
            let entry = peers
                .entry(row.recipient_device)
                .or_insert_with(|| ParkedPeer {
                    peer: row.recipient_device,
                    parked: 0,
                    first_deadline_ms: row.deadline_ms,
                    last_deadline_ms: row.deadline_ms,
                });
            entry.parked += 1;
            entry.first_deadline_ms = entry.first_deadline_ms.min(row.deadline_ms);
            entry.last_deadline_ms = entry.last_deadline_ms.max(row.deadline_ms);
        }
        Ok(peers.into_values().collect())
    }

    /// Seal the parked message `message_id` again under `key` (its contact
    /// is the session's peer): a normal seal with the logical id kept, and
    /// the parked row deleted in the seal's own transaction (also when its
    /// journal is replayed). A message no longer parked (given up, or sealed
    /// already) is refused ([`IndexedSessionStoreError::NotFound`]).
    #[allow(clippy::too_many_arguments)]
    pub fn reseal_parked_envelope<R, F>(
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
            true,
            local_device,
            created_at_ms,
            expires_at_ms,
            now_ms,
            rng,
            enqueue_idempotently,
        )
    }

    /// Give up the parked message `message_id` to `peer` (its deadline
    /// passed, or the copy cap). Whether a row went.
    pub fn give_up_parked(
        &mut self,
        peer: &[u8; 32],
        message_id: &[u8; 16],
    ) -> Result<bool, IndexedSessionStoreError> {
        Ok(delete::<ParkedOutbound>(&self.conn, &self.layout, peer, Some(message_id))? > 0)
    }

    /// Note that a message `message_id` from `peer` arrived, kept until
    /// `keep_until_ms` (a later note may only extend it; the first time
    /// stays). In one IMMEDIATE transaction, or in the caller's. Whether it
    /// was new. The accept path notes in its own transaction
    /// ([`note_seen`]).
    pub fn note_inbound_seen(
        &mut self,
        peer: &[u8; 32],
        message_id: &[u8; 16],
        now_ms: u64,
        keep_until_ms: u64,
    ) -> Result<bool, IndexedSessionStoreError> {
        let layout = &self.layout;
        sealed::in_write_tx(&self.conn, |conn| {
            note_seen(conn, layout, peer, message_id, now_ms, keep_until_ms)
        })
    }

    /// Whether a message `message_id` from `peer` was seen (and not pruned).
    pub fn inbound_seen(
        &self,
        peer: &[u8; 32],
        message_id: &[u8; 16],
    ) -> Result<bool, IndexedSessionStoreError> {
        Ok(self.inbound_first_seen_ms(peer, message_id)?.is_some())
    }

    /// When a message `message_id` from `peer` was first seen (`None`: never,
    /// or its row was pruned).
    pub fn inbound_first_seen_ms(
        &self,
        peer: &[u8; 32],
        message_id: &[u8; 16],
    ) -> Result<Option<u64>, IndexedSessionStoreError> {
        Ok(
            load_one::<InboundSeen>(&self.conn, &self.layout, peer, message_id)?
                .map(|seen| seen.first_seen_ms),
        )
    }

    /// Whether the inbox row of `message_id` from `peer` received at
    /// `received_at_ms` is a later copy of a message already taken: its first
    /// copy was seen before (receiver dedup, P5.5). This holds after the first
    /// copy's inbox row was pruned or its history entry left the 2,000-entry
    /// cap. The accept path notes a message at its receive time, which is
    /// strictly increasing per sender, so the first copy itself is never a
    /// later copy.
    pub fn inbound_received_again(
        &self,
        peer: &[u8; 32],
        message_id: &[u8; 16],
        received_at_ms: u64,
    ) -> Result<bool, IndexedSessionStoreError> {
        Ok(self
            .inbound_first_seen_ms(peer, message_id)?
            .is_some_and(|first| first < received_at_ms))
    }

    /// Where the horizon step re-seals `peer`'s parked messages: the newest
    /// sendable session ([`Self::find_sendable_sessions_for_peer_at`]) with
    /// at least [`crate::horizon::HORIZON_TARGET_MIN_REMAINING_MS`] left
    /// that is not letter-class ([`Self::session_is_letter_class`]).
    pub fn horizon_target_for_peer(
        &mut self,
        peer: &[u8; 32],
        now_ms: u64,
    ) -> Result<Option<IndexedSessionRecordKey>, IndexedSessionStoreError> {
        for key in self.find_sendable_sessions_for_peer_at(peer, now_ms)? {
            let (sid, initiator, _, created, expires) = self.head_summary(&key)?;
            if self.session_is_letter_class(&sid, initiator == *peer, created, expires)?
                || expires.saturating_sub(now_ms) < crate::horizon::HORIZON_TARGET_MIN_REMAINING_MS
            {
                continue;
            }
            return Ok(Some(key));
        }
        Ok(None)
    }
}

/// A letter-class session takes no new direct messages. Here, the time
/// rule: one the peer started that lives longer than a LAN session
/// ([`crate::lan_dispatch::LAN_SESSION_LIFETIME_MS`]), the only signal a
/// responder has without a letter row. Letter sessions either side marked
/// have their own row (P5.12, [`super::letters`]);
/// [`IndexedSessionStore::session_is_letter_class`] asks both. Every
/// sendable session passes that test
/// ([`IndexedSessionStore::find_sendable_sessions_for_peer_at`]): new
/// Messages, the reset step's and the horizon step's re-seal targets.
pub(super) fn session_is_letter_class(
    peer_initiated: bool,
    created_ms: u64,
    expires_ms: u64,
) -> bool {
    peer_initiated
        && expires_ms.saturating_sub(created_ms) > crate::lan_dispatch::LAN_SESSION_LIFETIME_MS
}

// ── The moves ────────────────────────────────────────────────────────────

/// Schema 1 -> 4's part for both tables ([`sealed::migrate_forward`], a
/// re-key's way forward, and [`ensure_keyed`]): a table still clear rebuilt
/// keyed, rowids kept. The rows moved.
pub(super) fn move_forward(
    tx: &Transaction<'_>,
    keys: &MetaKeys,
    steps: &mut Steps,
) -> Result<u32, RebuildError> {
    Ok(table_forward::<ParkedOutbound>(tx, keys, steps)?
        + table_forward::<InboundSeen>(tx, keys, steps)?)
}

fn table_forward<T: KeptRow>(
    tx: &Transaction<'_>,
    keys: &MetaKeys,
    steps: &mut Steps,
) -> Result<u32, RebuildError> {
    if table_keyed::<T>(tx)? {
        return Ok(0);
    }
    steps.step()?;
    tx.execute_batch(&format!(
        "CREATE TABLE {}__new ({});",
        T::TABLE,
        T::columns(true)
    ))?;
    let rows: Vec<(i64, T)> = {
        let mut statement = tx.prepare(&format!(
            "SELECT rowid, {}, message_id, {} FROM {}",
            T::DEVICE,
            T::VALUES.join(", "),
            T::TABLE
        ))?;
        let mapped = statement.query_map([], |row| {
            Ok((
                row.get(0)?,
                T::from_clear(row.get(1)?, row.get(2)?, row, 3)?,
            ))
        })?;
        mapped.collect::<Result<_, _>>()?
    };
    let (hour_column, hour_value) = if T::HOUR {
        (", prune_after_hour", ", ?5")
    } else {
        ("", "")
    };
    let mut moved = 0u32;
    for (rowid, row) in rows {
        steps.step()?;
        let (kd, km, pk) = keyed_pk(keys, row.device(), row.message_id());
        let plain = Zeroizing::new(serde_json::to_vec(&row.meta()).expect("strings and numbers"));
        let mut values = vec![
            rusqlite::types::Value::Integer(rowid),
            rusqlite::types::Value::Blob(kd.to_vec()),
            rusqlite::types::Value::Blob(km.to_vec()),
            rusqlite::types::Value::Blob(at_rest::seal_row(keys, T::TABLE, &pk, &plain)),
        ];
        if T::HOUR {
            values.push(rusqlite::types::Value::Integer(row.hour()));
        }
        tx.execute(
            &format!(
                "INSERT INTO {table}__new (rowid, kh_{device}, kh_message_id, meta{hour_column})
                 VALUES (?1, ?2, ?3, ?4{hour_value})",
                table = T::TABLE,
                device = T::DEVICE,
            ),
            rusqlite::params_from_iter(values),
        )?;
        moved += 1;
    }
    steps.step()?;
    tx.execute_batch(&format!("DROP TABLE {};", T::TABLE))?;
    steps.step()?;
    tx.execute_batch(&format!(
        "ALTER TABLE {table}__new RENAME TO {table};",
        table = T::TABLE
    ))?;
    Ok(moved)
}

/// Schema 4 -> 1's part for both tables ([`sealed::migrate_back`], and a
/// re-key's way back): each keyed row written back clear, rowids kept; a
/// row whose `meta` does not open is left out and counted (`dropped`).
pub(super) fn move_back(
    tx: &Transaction<'_>,
    keys: &MetaKeys,
    steps: &mut Steps,
    expected: &mut [(&'static str, i64)],
    report: &mut Migration,
) -> Result<(), RebuildError> {
    table_back::<ParkedOutbound>(tx, keys, steps, expected, report)?;
    table_back::<InboundSeen>(tx, keys, steps, expected, report)
}

fn table_back<T: KeptRow>(
    tx: &Transaction<'_>,
    keys: &MetaKeys,
    steps: &mut Steps,
    expected: &mut [(&'static str, i64)],
    report: &mut Migration,
) -> Result<(), RebuildError> {
    if !table_keyed::<T>(tx)? {
        return Ok(());
    }
    steps.step()?;
    tx.execute_batch(&format!(
        "CREATE TABLE {}__new ({});",
        T::TABLE,
        T::columns(false)
    ))?;
    let rows: Vec<(i64, Vec<u8>, Vec<u8>, KeyedMeta)> = {
        let mut statement = tx.prepare(&format!(
            "SELECT rowid, kh_{}, kh_message_id, meta FROM {}",
            T::DEVICE,
            T::TABLE
        ))?;
        let mapped = statement.query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?;
        mapped.collect::<Result<_, _>>()?
    };
    let marks: Vec<String> = (0..T::VALUES.len())
        .map(|n| format!("?{}", n + 4))
        .collect();
    for (rowid, kd, km, meta) in rows {
        steps.step()?;
        let pk = [kd.as_slice(), km.as_slice()].concat();
        let opened = at_rest::open_row(keys, T::TABLE, &pk, &meta)
            .ok()
            .and_then(|plain| serde_json::from_slice::<T::Meta>(&plain).ok())
            // The AAD binds the stored keyed values; a re-key's way back
            // holds a new index key, so they are not computed again here.
            .and_then(T::from_meta);
        let Some(row) = opened else {
            sealed::dropped(expected, T::TABLE, report);
            continue;
        };
        let mut values = vec![
            rusqlite::types::Value::Integer(rowid),
            rusqlite::types::Value::Blob(row.device().to_vec()),
            rusqlite::types::Value::Blob(row.message_id().to_vec()),
        ];
        values.extend(row.clear_values());
        tx.execute(
            &format!(
                "INSERT INTO {table}__new (rowid, {device}, message_id, {names})
                 VALUES (?1, ?2, ?3, {marks})",
                table = T::TABLE,
                device = T::DEVICE,
                names = T::VALUES.join(", "),
                marks = marks.join(", "),
            ),
            rusqlite::params_from_iter(values),
        )?;
        report.rows += 1;
    }
    steps.step()?;
    tx.execute_batch(&format!("DROP TABLE {};", T::TABLE))?;
    steps.step()?;
    tx.execute_batch(&format!(
        "ALTER TABLE {table}__new RENAME TO {table};",
        table = T::TABLE
    ))?;
    Ok(())
}
