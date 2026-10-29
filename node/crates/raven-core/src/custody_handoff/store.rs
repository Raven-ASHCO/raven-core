//! The handoff store: `<data_dir>/custody_handoff.sqlite` (Phase 5 P5.19,
//! `protocol/RAVEN_CUSTODY_HANDOFF_V1.md` §3, §6).
//!
//! Two tables, in a file of their own so `friend_custody.sqlite` keeps its
//! schema and a rollback stays safe:
//!
//! - `custody_forward_v1`: the objects a first custodian (F1) holds to hand
//!   on to a named next hop (FORWARD), one row per (digest, next hop), with
//!   the forwarder's state (pending, handed, refused) and its back-off;
//! - `custody_tags_v1`: the inbound store tags recipients registered at a
//!   final custodian (F2) for DELIVER (TAGS REGISTER), each with its expiry
//!   and a conflict mark.
//!
//! Rows stay until they expire (TTL only, errata rule 9): a handed row
//! answers a re-FORWARD `DUPLICATE` and is never sent again. Every refusal
//! refuses; nothing is evicted.
//!
//! **At rest (docs/design/2026-10-at-rest-metadata.md sections 6.2, 7.6).**
//! In a sealed profile the store is at schema 2: the digest, the next hop,
//! the depositor and the recipient are keyed lookups (`kh_object_digest`,
//! `kh_next_hop`, `kh_depositor`, `kh_recipient`); the RSO1 is sealed whole
//! and every other value (the clear keys, the store tag, the times, the
//! last code and the attempts) is in each row's sealed `meta`. Only the
//! forward state, the size, the conflict mark, the tag (named on the wire)
//! and `prune_after_hour` stay clear. A profile that is not sealed keeps
//! schema 1 (clear columns). A clear store in a sealed profile moves to
//! schema 2 at its open and in the privacy passes ([`migrate`]); [`unseal`]
//! is the way back and [`rekey`] keys it again. Both shapes hold so few rows
//! (1,024 forward rows, 8,192 tags at most) that every move reads them
//! whole, decides in memory and writes the other shape in one transaction.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rusqlite::{params, Connection, ErrorCode, TransactionBehavior};
use serde::{Deserialize, Serialize};

use crate::at_rest::{self, MetaKeys, Mode, ValueType};
use crate::friend_custody::CustodyCode;
use crate::sqlite_rebuild::{self as rebuild, Migration, RebuildError, RowReseal, Shape};

pub const HANDOFF_DB_FILE: &str = "custody_handoff.sqlite";
/// Schema 2: keyed lookups, sealed `meta` and sealed RSO1, in a sealed
/// profile.
const SCHEMA_VERSION: i64 = 2;
/// Schema 1: the clear columns (a profile that is not sealed).
const CLEAR_VERSION: i64 = 1;
/// This store's row in `raven_schema`.
const STORE: &str = "custody_handoff";
const FORWARD: &str = "custody_forward_v1";
const TAGS: &str = "custody_tags_v1";
/// The keyed column that tells the forward table's two shapes apart.
const KEYED_COLUMN: &str = "kh_object_digest";
/// The AAD label of a forward row's sealed RSO1 (its `meta` uses the table).
const RSO1_LABEL: &str = "custody_forward_v1.rso1";

// Limits (spec §6)
pub const MAX_FORWARD_NODE_ROWS: usize = 1_024;
pub const MAX_FORWARD_NODE_BYTES: i64 = 32 * 1024 * 1024;
pub const MAX_FORWARD_DEPOSITOR_ROWS: usize = 128;
pub const MAX_FORWARD_DEPOSITOR_BYTES: i64 = 8 * 1024 * 1024;
pub const MAX_FORWARD_PAIR_ROWS: usize = 64;
pub const MAX_FORWARD_BYTES_PER_MINUTE: i64 = 2 * 1024 * 1024;
/// Next hops one object may be held for (two first-level custodians times
/// one next hop each: spec §4).
pub const MAX_NEXT_HOPS_PER_DIGEST: usize = 2;
pub const MAX_TAGS_PER_RECIPIENT: usize = 512;
pub const MAX_NODE_TAGS: i64 = 8_192;
/// A registration never outlives this (REGISTER clamps to now + 72 h).
pub const MAX_TAG_TTL_MS: u64 = 72 * 60 * 60 * 1000;
const MINUTE_MS: u64 = 60_000;
/// Expired rows of each table a write purges first.
const PURGE_PER_WRITE: i64 = 64;
/// A quarantined copy goes once every row it held has expired.
const QUARANTINE_KEEP_MS: u64 = 8 * 24 * 60 * 60 * 1000;

/// A forward row's state.
pub const STATE_PENDING: u8 = 0;
/// The next hop answered STORED or DUPLICATE: never sent again.
pub const STATE_HANDED: u8 = 1;
/// The next hop answered a terminal refusal.
pub const STATE_REFUSED: u8 = 2;

pub fn handoff_db_path(data_dir: &Path) -> PathBuf {
    data_dir.join(HANDOFF_DB_FILE)
}

/// Both tables in either shape, under the index names every build uses.
fn tables(keyed: bool) -> &'static str {
    if keyed {
        "CREATE TABLE IF NOT EXISTS custody_forward_v1 (
           kh_object_digest BLOB NOT NULL CHECK(length(kh_object_digest)=32),
           kh_next_hop      BLOB NOT NULL CHECK(length(kh_next_hop)=32),
           kh_depositor     BLOB NOT NULL CHECK(length(kh_depositor)=32),
           rso1             BLOB NOT NULL,
           bytes            INTEGER NOT NULL,
           state            INTEGER NOT NULL DEFAULT 0,
           meta             BLOB NOT NULL,
           prune_after_hour INTEGER NOT NULL,
           PRIMARY KEY (kh_object_digest, kh_next_hop));
         CREATE INDEX IF NOT EXISTS idx_fwd_due  ON custody_forward_v1(state);
         CREATE INDEX IF NOT EXISTS idx_fwd_pair ON custody_forward_v1(kh_depositor, kh_next_hop);
         CREATE INDEX IF NOT EXISTS idx_fwd_exp  ON custody_forward_v1(prune_after_hour);
         CREATE TABLE IF NOT EXISTS custody_tags_v1 (
           store_tag        BLOB PRIMARY KEY NOT NULL CHECK(length(store_tag)=16),
           kh_recipient     BLOB NOT NULL CHECK(length(kh_recipient)=32),
           conflicted       INTEGER NOT NULL DEFAULT 0,
           meta             BLOB NOT NULL,
           prune_after_hour INTEGER NOT NULL);
         CREATE INDEX IF NOT EXISTS idx_tags_recipient ON custody_tags_v1(kh_recipient);
         CREATE INDEX IF NOT EXISTS idx_tags_exp       ON custody_tags_v1(prune_after_hour);"
    } else {
        "CREATE TABLE IF NOT EXISTS custody_forward_v1 (
           object_digest  BLOB NOT NULL CHECK(length(object_digest)=32),
           next_hop       BLOB NOT NULL CHECK(length(next_hop)=32),
           depositor      BLOB NOT NULL CHECK(length(depositor)=32),
           store_tag      BLOB NOT NULL CHECK(length(store_tag)=16),
           rso1           BLOB NOT NULL,
           bytes          INTEGER NOT NULL,
           admitted_at_ms INTEGER NOT NULL,
           expires_at_ms  INTEGER NOT NULL,
           state          INTEGER NOT NULL DEFAULT 0,
           last_code      INTEGER,
           attempts       INTEGER NOT NULL DEFAULT 0,
           next_try_ms    INTEGER NOT NULL,
           PRIMARY KEY (object_digest, next_hop));
         CREATE INDEX IF NOT EXISTS idx_fwd_due  ON custody_forward_v1(state, next_try_ms);
         CREATE INDEX IF NOT EXISTS idx_fwd_pair ON custody_forward_v1(depositor, next_hop);
         CREATE TABLE IF NOT EXISTS custody_tags_v1 (
           store_tag        BLOB PRIMARY KEY NOT NULL CHECK(length(store_tag)=16),
           recipient        BLOB NOT NULL CHECK(length(recipient)=32),
           expires_at_ms    INTEGER NOT NULL,
           conflicted       INTEGER NOT NULL DEFAULT 0,
           registered_at_ms INTEGER NOT NULL);
         CREATE INDEX IF NOT EXISTS idx_tags_recipient ON custody_tags_v1(recipient);"
    }
}

/// The pragmas a store is opened or created with (§6.6: pages are freed).
const PRAGMAS: &str =
    "PRAGMA auto_vacuum=INCREMENTAL; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;";

// ── Rows ─────────────────────────────────────────────────────────────────

/// A forward row's values: the clear columns of schema 1, a schema-2 row's
/// sealed `meta`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Fwd {
    digest: [u8; 32],
    next_hop: [u8; 32],
    depositor: [u8; 32],
    store_tag: [u8; 16],
    admitted_at_ms: u64,
    expires_at_ms: u64,
    last_code: Option<u8>,
    attempts: u32,
    next_try_ms: u64,
}

/// One forward row as read: its stored key columns, the clear columns of
/// either shape, and its values (`None`: a schema-2 `meta` that does not
/// open here).
struct FwdRow {
    pk: [Vec<u8>; 2],
    bytes: i64,
    state: u8,
    hour: i64,
    fwd: Option<Fwd>,
}

/// A row whose `meta` does not open is live until its hour has passed (the
/// conservative answer for the caps).
fn live_by(expires: Option<u64>, hour: i64, now_ms: u64) -> bool {
    match expires {
        Some(expires) => expires > now_ms,
        None => hour > rebuild::hour_of(now_ms),
    }
}

impl FwdRow {
    fn live(&self, now_ms: u64) -> bool {
        live_by(
            self.fwd.as_ref().map(|f| f.expires_at_ms),
            self.hour,
            now_ms,
        )
    }
}

/// A tag registration's values (schema 2: its sealed `meta`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TagMeta {
    recipient: [u8; 32],
    expires_at_ms: u64,
    registered_at_ms: u64,
}

struct TagRow {
    store_tag: [u8; 16],
    conflicted: bool,
    hour: i64,
    meta: Option<TagMeta>,
}

impl TagRow {
    fn live(&self, now_ms: u64) -> bool {
        live_by(
            self.meta.as_ref().map(|m| m.expires_at_ms),
            self.hour,
            now_ms,
        )
    }
}

/// Which tags [`load_tags`] reads.
enum TagFilter<'a> {
    All,
    Tag(&'a [u8; 16]),
    Recipient(&'a [u8; 32]),
}

fn ms(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn arr<const N: usize>(bytes: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    if bytes.len() == N {
        out.copy_from_slice(bytes);
    }
    out
}

fn text(e: impl std::fmt::Display) -> String {
    e.to_string()
}

/// The stored key columns of (digest, next hop).
fn fwd_pk(keys: Option<&MetaKeys>, digest: &[u8; 32], next_hop: &[u8; 32]) -> [Vec<u8>; 2] {
    match keys {
        None => [digest.to_vec(), next_hop.to_vec()],
        Some(keys) => [
            at_rest::index(keys, ValueType::ObjectDigest, digest).to_vec(),
            at_rest::index(keys, ValueType::DeviceKey, next_hop).to_vec(),
        ],
    }
}

/// A schema-2 forward row's AAD key: both keyed columns as stored.
fn aad(pk: &[Vec<u8>; 2]) -> Vec<u8> {
    [pk[0].as_slice(), pk[1].as_slice()].concat()
}

fn fwd_cols(keyed: bool) -> (&'static str, &'static str) {
    if keyed {
        ("kh_object_digest", "kh_next_hop")
    } else {
        ("object_digest", "next_hop")
    }
}

fn device(keys: Option<&MetaKeys>, key: &[u8; 32]) -> Vec<u8> {
    keys.map_or_else(
        || key.to_vec(),
        |keys| at_rest::index(keys, ValueType::DeviceKey, key).to_vec(),
    )
}

fn seal_json<T: Serialize>(keys: &MetaKeys, table: &str, pk: &[u8], value: &T) -> Vec<u8> {
    let plain =
        zeroize::Zeroizing::new(serde_json::to_vec(value).expect("arrays and numbers serialize"));
    at_rest::seal_row(keys, table, pk, &plain)
}

fn open_json<T: for<'de> Deserialize<'de>>(
    keys: &MetaKeys,
    table: &str,
    pk: &[u8],
    blob: &[u8],
) -> Option<T> {
    let plain = at_rest::open_row(keys, table, pk, blob).ok()?;
    serde_json::from_slice(&plain).ok()
}

/// The forward rows (all, or the one at `pk`), without their RSO1.
fn load_forward(
    conn: &Connection,
    keys: Option<&MetaKeys>,
    pk: Option<&[Vec<u8>; 2]>,
) -> rusqlite::Result<Vec<FwdRow>> {
    let (c1, c2) = fwd_cols(keys.is_some());
    let filter = if pk.is_some() {
        format!(" WHERE {c1} = ?1 AND {c2} = ?2")
    } else {
        String::new()
    };
    let args: Vec<&[u8]> = pk.map_or_else(Vec::new, |pk| vec![&pk[0][..], &pk[1][..]]);
    let args = rusqlite::params_from_iter(args);
    match keys {
        None => {
            let mut stmt = conn.prepare(&format!(
                "SELECT object_digest, next_hop, depositor, store_tag, bytes, admitted_at_ms,
                        expires_at_ms, state, last_code, attempts, next_try_ms
                 FROM custody_forward_v1{filter}"
            ))?;
            let rows = stmt.query_map(args, |r| {
                let fwd = Fwd {
                    digest: arr(&r.get::<_, Vec<u8>>(0)?),
                    next_hop: arr(&r.get::<_, Vec<u8>>(1)?),
                    depositor: arr(&r.get::<_, Vec<u8>>(2)?),
                    store_tag: arr(&r.get::<_, Vec<u8>>(3)?),
                    admitted_at_ms: r.get::<_, i64>(5)?.max(0) as u64,
                    expires_at_ms: r.get::<_, i64>(6)?.max(0) as u64,
                    last_code: r.get::<_, Option<i64>>(8)?.map(|c| c as u8),
                    attempts: r.get::<_, i64>(9)?.clamp(0, i64::from(u32::MAX)) as u32,
                    next_try_ms: r.get::<_, i64>(10)?.max(0) as u64,
                };
                Ok(FwdRow {
                    pk: [fwd.digest.to_vec(), fwd.next_hop.to_vec()],
                    bytes: r.get(4)?,
                    state: r.get::<_, i64>(7)? as u8,
                    hour: rebuild::prune_after_hour(fwd.expires_at_ms),
                    fwd: Some(fwd),
                })
            })?;
            rows.collect()
        }
        Some(keys) => {
            let mut stmt = conn.prepare(&format!(
                "SELECT kh_object_digest, kh_next_hop, bytes, state, meta, prune_after_hour
                 FROM custody_forward_v1{filter}"
            ))?;
            let rows = stmt.query_map(args, |r| {
                let pk = [r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?];
                let meta: Vec<u8> = r.get(4)?;
                let fwd = open_json(keys, FORWARD, &aad(&pk), &meta);
                Ok(FwdRow {
                    pk,
                    bytes: r.get(2)?,
                    state: r.get::<_, i64>(3)? as u8,
                    hour: r.get(5)?,
                    fwd,
                })
            })?;
            rows.collect()
        }
    }
}

/// The RSO1 of the forward row at `pk` (`None`: no row, or a sealed one
/// that does not open here).
fn forward_rso1(
    conn: &Connection,
    keys: Option<&MetaKeys>,
    pk: &[Vec<u8>; 2],
) -> rusqlite::Result<Option<Vec<u8>>> {
    let (c1, c2) = fwd_cols(keys.is_some());
    let blob: Option<Vec<u8>> = rusqlite::OptionalExtension::optional(conn.query_row(
        &format!("SELECT rso1 FROM custody_forward_v1 WHERE {c1} = ?1 AND {c2} = ?2"),
        params![pk[0], pk[1]],
        |r| r.get(0),
    ))?;
    Ok(match (blob, keys) {
        (Some(rso1), None) => Some(rso1),
        (Some(sealed), Some(keys)) => at_rest::open_row(keys, RSO1_LABEL, &aad(pk), &sealed)
            .ok()
            .map(|plain| plain.to_vec()),
        (None, _) => None,
    })
}

/// Insert (or replace an expired leftover of) one forward row.
fn insert_forward(
    conn: &Connection,
    keys: Option<&MetaKeys>,
    fwd: &Fwd,
    state: u8,
    rso1: &[u8],
) -> rusqlite::Result<()> {
    let bytes = rso1.len() as i64;
    match keys {
        None => conn.execute(
            "INSERT OR REPLACE INTO custody_forward_v1
               (object_digest, next_hop, depositor, store_tag, rso1, bytes, admitted_at_ms,
                expires_at_ms, state, last_code, attempts, next_try_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                fwd.digest.as_slice(),
                fwd.next_hop.as_slice(),
                fwd.depositor.as_slice(),
                fwd.store_tag.as_slice(),
                rso1,
                bytes,
                ms(fwd.admitted_at_ms),
                ms(fwd.expires_at_ms),
                i64::from(state),
                fwd.last_code.map(i64::from),
                i64::from(fwd.attempts),
                ms(fwd.next_try_ms),
            ],
        ),
        Some(keys) => {
            let pk = fwd_pk(Some(keys), &fwd.digest, &fwd.next_hop);
            let key = aad(&pk);
            conn.execute(
                "INSERT OR REPLACE INTO custody_forward_v1
                   (kh_object_digest, kh_next_hop, kh_depositor, rso1, bytes, state, meta,
                    prune_after_hour)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    pk[0],
                    pk[1],
                    device(Some(keys), &fwd.depositor),
                    at_rest::seal_row(keys, RSO1_LABEL, &key, rso1),
                    bytes,
                    i64::from(state),
                    seal_json(keys, FORWARD, &key, fwd),
                    rebuild::prune_after_hour(fwd.expires_at_ms),
                ],
            )
        }
    }
    .map(|_| ())
}

/// A forward row's state and values after an attempt (the RSO1 stays).
fn update_forward(
    conn: &Connection,
    keys: Option<&MetaKeys>,
    pk: &[Vec<u8>; 2],
    fwd: &Fwd,
    state: u8,
) -> rusqlite::Result<usize> {
    match keys {
        None => conn.execute(
            "UPDATE custody_forward_v1 SET state = ?3, last_code = ?4, attempts = ?5,
               next_try_ms = ?6
             WHERE object_digest = ?1 AND next_hop = ?2",
            params![
                pk[0],
                pk[1],
                i64::from(state),
                fwd.last_code.map(i64::from),
                i64::from(fwd.attempts),
                ms(fwd.next_try_ms),
            ],
        ),
        Some(keys) => conn.execute(
            "UPDATE custody_forward_v1 SET state = ?3, meta = ?4
             WHERE kh_object_digest = ?1 AND kh_next_hop = ?2",
            params![
                pk[0],
                pk[1],
                i64::from(state),
                seal_json(keys, FORWARD, &aad(pk), fwd),
            ],
        ),
    }
}

fn delete_forward(conn: &Connection, keyed: bool, pk: &[Vec<u8>; 2]) -> rusqlite::Result<usize> {
    let (c1, c2) = fwd_cols(keyed);
    conn.execute(
        &format!("DELETE FROM custody_forward_v1 WHERE {c1} = ?1 AND {c2} = ?2"),
        params![pk[0], pk[1]],
    )
}

fn load_tags(
    conn: &Connection,
    keys: Option<&MetaKeys>,
    filter: TagFilter<'_>,
) -> rusqlite::Result<Vec<TagRow>> {
    let recipient_col = if keys.is_some() {
        "kh_recipient"
    } else {
        "recipient"
    };
    let (filter, arg): (String, Vec<u8>) = match filter {
        TagFilter::All => (String::new(), Vec::new()),
        TagFilter::Tag(tag) => (" WHERE store_tag = ?1".into(), tag.to_vec()),
        TagFilter::Recipient(r) => (format!(" WHERE {recipient_col} = ?1"), device(keys, r)),
    };
    let args: Vec<&[u8]> = if filter.is_empty() {
        Vec::new()
    } else {
        vec![&arg[..]]
    };
    let args = rusqlite::params_from_iter(args);
    match keys {
        None => {
            let mut stmt = conn.prepare(&format!(
                "SELECT store_tag, recipient, expires_at_ms, conflicted, registered_at_ms
                 FROM custody_tags_v1{filter}"
            ))?;
            let rows = stmt.query_map(args, |r| {
                let meta = TagMeta {
                    recipient: arr(&r.get::<_, Vec<u8>>(1)?),
                    expires_at_ms: r.get::<_, i64>(2)?.max(0) as u64,
                    registered_at_ms: r.get::<_, i64>(4)?.max(0) as u64,
                };
                Ok(TagRow {
                    store_tag: arr(&r.get::<_, Vec<u8>>(0)?),
                    conflicted: r.get::<_, i64>(3)? != 0,
                    hour: rebuild::prune_after_hour(meta.expires_at_ms),
                    meta: Some(meta),
                })
            })?;
            rows.collect()
        }
        Some(keys) => {
            let mut stmt = conn.prepare(&format!(
                "SELECT store_tag, conflicted, meta, prune_after_hour FROM custody_tags_v1{filter}"
            ))?;
            let rows = stmt.query_map(args, |r| {
                let store_tag: Vec<u8> = r.get(0)?;
                let meta: Vec<u8> = r.get(2)?;
                Ok(TagRow {
                    meta: open_json(keys, TAGS, &store_tag, &meta),
                    store_tag: arr(&store_tag),
                    conflicted: r.get::<_, i64>(1)? != 0,
                    hour: r.get(3)?,
                })
            })?;
            rows.collect()
        }
    }
}

/// Insert or replace the registration of `tag`.
fn put_tag(
    conn: &Connection,
    keys: Option<&MetaKeys>,
    tag: &[u8; 16],
    meta: &TagMeta,
    conflicted: bool,
) -> rusqlite::Result<()> {
    match keys {
        None => conn.execute(
            "INSERT OR REPLACE INTO custody_tags_v1
               (store_tag, recipient, expires_at_ms, conflicted, registered_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                tag.as_slice(),
                meta.recipient.as_slice(),
                ms(meta.expires_at_ms),
                i64::from(conflicted),
                ms(meta.registered_at_ms),
            ],
        ),
        Some(keys) => conn.execute(
            "INSERT OR REPLACE INTO custody_tags_v1
               (store_tag, kh_recipient, conflicted, meta, prune_after_hour)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                tag.as_slice(),
                device(Some(keys), &meta.recipient),
                i64::from(conflicted),
                seal_json(keys, TAGS, tag, meta),
                rebuild::prune_after_hour(meta.expires_at_ms),
            ],
        ),
    }
    .map(|_| ())
}

/// Live tags on this node (schema 2 by the hour: the hour that may not
/// have passed yet counts, the conservative answer for the cap).
fn node_tags(conn: &Connection, keyed: bool, now_ms: u64) -> rusqlite::Result<i64> {
    if keyed {
        conn.query_row(
            "SELECT COUNT(*) FROM custody_tags_v1 WHERE prune_after_hour > ?1",
            params![rebuild::hour_of(now_ms)],
            |r| r.get(0),
        )
    } else {
        conn.query_row(
            "SELECT COUNT(*) FROM custody_tags_v1 WHERE expires_at_ms > ?1",
            params![ms(now_ms)],
            |r| r.get(0),
        )
    }
}

/// A write's expiry purge: at most [`PURGE_PER_WRITE`] rows of each table
/// (schema 2: by the hour that has passed).
fn purge_some_expired(conn: &Connection, keyed: bool, now_ms: u64) -> rusqlite::Result<()> {
    let (column, bound) = if keyed {
        ("prune_after_hour", rebuild::hour_of(now_ms))
    } else {
        ("expires_at_ms", ms(now_ms))
    };
    for table in [FORWARD, TAGS] {
        conn.execute(
            &format!(
                "DELETE FROM {table} WHERE rowid IN (
                   SELECT rowid FROM {table} WHERE {column} <= ?1 LIMIT ?2)"
            ),
            params![bound, PURGE_PER_WRITE],
        )?;
    }
    Ok(())
}

// ── The store ────────────────────────────────────────────────────────────

/// What the store says about a DELIVER's store tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagState {
    /// No live registration (or one that does not open here).
    Unknown,
    /// Two recipients registered it: nobody gets it until it expires.
    Conflicted,
    /// Registered by this recipient.
    Live([u8; 32]),
}

/// A REGISTER's answer (TAGS_RESULT).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TagsOutcome {
    pub code: CustodyCode,
    /// Registered or extended.
    pub accepted: u8,
    /// Tags another recipient holds (now conflicted).
    pub conflicts: u8,
}

/// A pending forward row that is due ([`HandoffStore::forward_due`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DueForward {
    pub digest: [u8; 32],
    pub next_hop: [u8; 32],
    pub depositor: [u8; 32],
    pub store_tag: [u8; 16],
    pub rso1: Vec<u8>,
    pub expires_at_ms: u64,
    pub attempts: u32,
    pub last_code: Option<u8>,
}

/// What the store holds (`raven node custody status`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HandoffUsage {
    pub pending: i64,
    pub handed: i64,
    pub refused: i64,
    /// The forward rows' RSO1 bytes.
    pub bytes: i64,
    pub tags: i64,
}

/// The custodian's handoff store (module docs).
pub struct HandoffStore {
    conn: Connection,
    /// A schema-2 store's keys (`None`: schema 1).
    keys: Option<Arc<MetaKeys>>,
}

/// Why one open attempt failed: a damaged file is quarantined and the open
/// tried once more.
enum OpenFailure {
    Corrupt,
    Other(String),
}

impl From<rusqlite::Error> for OpenFailure {
    fn from(e: rusqlite::Error) -> Self {
        match e.sqlite_error_code() {
            Some(ErrorCode::NotADatabase | ErrorCode::DatabaseCorrupt) => Self::Corrupt,
            _ => Self::Other(e.to_string()),
        }
    }
}

impl From<String> for OpenFailure {
    fn from(e: String) -> Self {
        Self::Other(e)
    }
}

/// The at-rest keys this process loaded (never a keystore call).
fn cached_keys(data_dir: &Path) -> Result<Arc<MetaKeys>, String> {
    at_rest::keys_cached(data_dir).map_err(|e| format!("custody handoff store: {e}"))
}

/// Move a damaged store aside as `custody_handoff.sqlite.corrupt-<ms>` (its
/// WAL and shared-memory files go: they belong to the damaged file).
fn quarantine(path: &Path) -> Result<(), String> {
    let now = crate::clock::now_ms();
    let mut aside = path.as_os_str().to_os_string();
    aside.push(format!(".corrupt-{now}"));
    std::fs::rename(path, &aside).map_err(text)?;
    for suffix in ["-wal", "-shm"] {
        let mut side = path.as_os_str().to_os_string();
        side.push(suffix);
        let _ = std::fs::remove_file(side);
    }
    eprintln!("raven-node custody: handoff store damaged; moved aside");
    Ok(())
}

impl HandoffStore {
    /// Open an existing store; `Ok(None)` when there is no file (nothing is
    /// created).
    pub fn open_existing(data_dir: &Path) -> Result<Option<Self>, String> {
        let path = handoff_db_path(data_dir);
        if !path.exists() {
            return Ok(None);
        }
        Self::open_at(data_dir, &path).map(|(store, _)| Some(store))
    }

    /// Open, creating the store (the first admitted FORWARD or REGISTER).
    pub fn open_or_create(data_dir: &Path) -> Result<Self, String> {
        Self::open_at(data_dir, &handoff_db_path(data_dir)).map(|(store, _)| store)
    }

    /// Open the store at `path` in the shape the profile's mode asks for
    /// (`true`: a clear store moved to schema 2 now). A damaged file is
    /// quarantined and a new store created in its place.
    fn open_at(data_dir: &Path, path: &Path) -> Result<(Self, bool), String> {
        match Self::open_once(data_dir, path) {
            Ok(opened) => Ok(opened),
            Err(OpenFailure::Other(e)) => Err(e),
            Err(OpenFailure::Corrupt) => {
                quarantine(path)?;
                Self::open_once(data_dir, path).map_err(|e| match e {
                    OpenFailure::Corrupt => format!("{HANDOFF_DB_FILE}: damaged"),
                    OpenFailure::Other(e) => e,
                })
            }
        }
    }

    fn open_once(data_dir: &Path, path: &Path) -> Result<(Self, bool), OpenFailure> {
        let sealed = crate::privacy::mode(data_dir) == Mode::Sealed;
        // Before anything is created: no key, no store (never a clear one).
        if sealed {
            cached_keys(data_dir)?;
        }
        let conn = crate::paths::open_private_data_dir_sqlite(path)?;
        conn.busy_timeout(std::time::Duration::from_secs(10))?;
        crate::paths::harden_sqlite(&conn)?;
        let mut conn = conn;
        let mut migrated = false;
        // Three rounds at most: create or migrate, then open what is there.
        for _ in 0..3 {
            let version = rebuild::user_version(&conn)?;
            let recorded = rebuild::recorded(&conn, STORE)?.map(|(version, _)| version);
            if version > SCHEMA_VERSION || recorded.is_some_and(|v| v > SCHEMA_VERSION) {
                return Err("custody handoff store is newer than this build"
                    .to_string()
                    .into());
            }
            let keys = match rebuild::shape(&conn, FORWARD, KEYED_COLUMN)? {
                Shape::Keyed => {
                    let keys = cached_keys(data_dir)?;
                    if version != SCHEMA_VERSION || recorded != Some(SCHEMA_VERSION) {
                        rebuild::restamp(&mut conn, STORE, SCHEMA_VERSION)?;
                    }
                    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")?;
                    Some(keys)
                }
                Shape::Missing if sealed => {
                    create_keyed(&mut conn)?;
                    continue;
                }
                Shape::Clear if sealed => {
                    let keys = cached_keys(data_dir)?;
                    match migrate_forward(path, &keys, &crate::disk_space::free_bytes) {
                        Ok(done) => {
                            migrated |= !done.already;
                            continue;
                        }
                        // Deferred: the store keeps working as it is.
                        Err(RebuildError::NoSpace { .. }) => {
                            open_clear(&conn)?;
                            None
                        }
                        Err(e) => return Err(format!("{HANDOFF_DB_FILE}: {e}").into()),
                    }
                }
                Shape::Missing | Shape::Clear => {
                    open_clear(&conn)?;
                    None
                }
            };
            // Both tables always move together; a store whose tags are in
            // the other shape is not one this build wrote.
            let tags_keyed = rebuild::columns(&conn, TAGS)?
                .iter()
                .any(|c| c == "kh_recipient");
            if tags_keyed != keys.is_some() {
                return Err(format!("{HANDOFF_DB_FILE}: its tables disagree").into());
            }
            return Ok((Self { conn, keys }, migrated));
        }
        Err(format!("{HANDOFF_DB_FILE} changed shape while it was opened; try again").into())
    }

    fn keys(&self) -> Option<&MetaKeys> {
        self.keys.as_deref()
    }

    /// One admitted FORWARD (spec §3.1, after the checks a handler makes
    /// without the store): in one IMMEDIATE transaction the expiry purge,
    /// DUPLICATE, CONFLICT, the next-hop count, the caps, then the row.
    /// `Ok` only once it is committed.
    #[allow(clippy::too_many_arguments)]
    pub fn forward(
        &mut self,
        digest: &[u8; 32],
        next_hop: &[u8; 32],
        depositor: &[u8; 32],
        store_tag: &[u8; 16],
        rso1: &[u8],
        expires_at_ms: u64,
        now_ms: u64,
    ) -> Result<CustodyCode, String> {
        let keys = self.keys.clone();
        let keys = keys.as_deref();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(text)?;
        let _in_tx = crate::paths::HeldMark::transaction();
        purge_some_expired(&tx, keys.is_some(), now_ms).map_err(text)?;
        let rows = load_forward(&tx, keys, None).map_err(text)?;
        let live: Vec<&FwdRow> = rows.iter().filter(|r| r.live(now_ms)).collect();
        let bytes = rso1.len() as i64;
        let refusal = forward_refusal(
            &live,
            (digest, next_hop, depositor, store_tag),
            bytes,
            now_ms,
        );
        if let Some(code) = refusal {
            // Keep the purge: a refusal must not roll it back.
            tx.commit().map_err(text)?;
            if code == CustodyCode::Conflict {
                eprintln!("raven-node custody: handoff refused (CUSTODY_CONFLICT)");
            }
            return Ok(code);
        }
        let fwd = Fwd {
            digest: *digest,
            next_hop: *next_hop,
            depositor: *depositor,
            store_tag: *store_tag,
            admitted_at_ms: now_ms,
            expires_at_ms,
            last_code: None,
            attempts: 0,
            next_try_ms: now_ms,
        };
        insert_forward(&tx, keys, &fwd, STATE_PENDING, rso1).map_err(text)?;
        tx.commit().map_err(text)?;
        Ok(CustodyCode::Ok)
    }

    /// Who holds `store_tag` now (DELIVER, spec §3.3). Read-only.
    pub fn tag_recipient(&self, store_tag: &[u8; 16], now_ms: u64) -> Result<TagState, String> {
        let rows = load_tags(&self.conn, self.keys(), TagFilter::Tag(store_tag)).map_err(text)?;
        Ok(match rows.into_iter().find(|r| r.live(now_ms)) {
            None => TagState::Unknown,
            Some(row) if row.conflicted => TagState::Conflicted,
            Some(TagRow {
                meta: Some(meta), ..
            }) => TagState::Live(meta.recipient),
            Some(_) => TagState::Unknown,
        })
    }

    /// TAGS REGISTER by `registrant` (spec §3.4), in one IMMEDIATE
    /// transaction: each expiry clamped to now + 72 h (entries already
    /// expired skipped); a free tag is registered, the registrant's own one
    /// extended to the later expiry, another recipient's one marked
    /// conflicted until the later of both expiries; past the caps an entry
    /// is refused (`QUOTA`) and nothing is evicted.
    pub fn register(
        &mut self,
        registrant: &[u8; 32],
        entries: &[([u8; 16], u64)],
        now_ms: u64,
    ) -> Result<TagsOutcome, String> {
        let keys = self.keys.clone();
        let keys = keys.as_deref();
        let latest = now_ms.saturating_add(MAX_TAG_TTL_MS);
        let mut outcome = TagsOutcome {
            code: CustodyCode::Ok,
            accepted: 0,
            conflicts: 0,
        };
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(text)?;
        let _in_tx = crate::paths::HeldMark::transaction();
        purge_some_expired(&tx, keys.is_some(), now_ms).map_err(text)?;
        let mut own = load_tags(&tx, keys, TagFilter::Recipient(registrant))
            .map_err(text)?
            .iter()
            .filter(|r| r.live(now_ms))
            .count();
        let mut node = node_tags(&tx, keys.is_some(), now_ms).map_err(text)?;
        for (tag, expires) in entries {
            let expires = (*expires).min(latest);
            if expires <= now_ms {
                continue;
            }
            let held = load_tags(&tx, keys, TagFilter::Tag(tag))
                .map_err(text)?
                .into_iter()
                .find(|r| r.live(now_ms));
            match held {
                None => {
                    if own >= MAX_TAGS_PER_RECIPIENT || node >= MAX_NODE_TAGS {
                        outcome.code = CustodyCode::Quota;
                        continue;
                    }
                    let meta = TagMeta {
                        recipient: *registrant,
                        expires_at_ms: expires,
                        registered_at_ms: now_ms,
                    };
                    put_tag(&tx, keys, tag, &meta, false).map_err(text)?;
                    own += 1;
                    node += 1;
                    outcome.accepted = outcome.accepted.saturating_add(1);
                }
                Some(TagRow {
                    meta: Some(mut meta),
                    conflicted,
                    ..
                }) => {
                    let mine = meta.recipient == *registrant && !conflicted;
                    meta.expires_at_ms = meta.expires_at_ms.max(expires);
                    put_tag(&tx, keys, tag, &meta, !mine).map_err(text)?;
                    if mine {
                        outcome.accepted = outcome.accepted.saturating_add(1);
                    } else {
                        outcome.conflicts = outcome.conflicts.saturating_add(1);
                    }
                }
                // A registration that does not open here: nobody's to take.
                Some(_) => outcome.conflicts = outcome.conflicts.saturating_add(1),
            }
        }
        tx.commit().map_err(text)?;
        if outcome.conflicts > 0 {
            eprintln!(
                "raven-node custody: {} handoff tag conflicts",
                outcome.conflicts
            );
        }
        Ok(outcome)
    }

    /// TAGS WITHDRAW: deletes only `registrant`'s own unconflicted tags.
    /// Tags deleted.
    pub fn withdraw(&mut self, registrant: &[u8; 32], tags: &[[u8; 16]]) -> Result<u8, String> {
        let keys = self.keys.clone();
        let keys = keys.as_deref();
        let column = if keys.is_some() {
            "kh_recipient"
        } else {
            "recipient"
        };
        let who = device(keys, registrant);
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(text)?;
        let _in_tx = crate::paths::HeldMark::transaction();
        let mut withdrawn = 0usize;
        for tag in tags {
            withdrawn += tx
                .execute(
                    &format!(
                        "DELETE FROM custody_tags_v1
                         WHERE store_tag = ?1 AND {column} = ?2 AND conflicted = 0"
                    ),
                    params![tag.as_slice(), who],
                )
                .map_err(text)?;
        }
        tx.commit().map_err(text)?;
        Ok(u8::try_from(withdrawn).unwrap_or(u8::MAX))
    }

    /// Pending, live rows whose next try is due, oldest first, at most
    /// `limit` (the forwarder, spec §3.2). Read-only.
    pub fn forward_due(&self, now_ms: u64, limit: usize) -> Result<Vec<DueForward>, String> {
        self.forward_due_for(now_ms, limit, &|_| false)
    }

    /// [`Self::forward_due`], where the rows for a next hop `early` names
    /// are due whatever their next try (the forwarder's triggers: that hop
    /// was seen, a kick, a network change; spec §3.2).
    pub fn forward_due_for(
        &self,
        now_ms: u64,
        limit: usize,
        early: &dyn Fn(&[u8; 32]) -> bool,
    ) -> Result<Vec<DueForward>, String> {
        let keys = self.keys();
        let rows = load_forward(&self.conn, keys, None).map_err(text)?;
        let mut due: Vec<(&FwdRow, &Fwd)> = rows
            .iter()
            .filter(|r| r.state == STATE_PENDING && r.live(now_ms))
            .filter_map(|r| r.fwd.as_ref().map(|f| (r, f)))
            .filter(|(_, f)| f.next_try_ms <= now_ms || early(&f.next_hop))
            .collect();
        due.sort_by_key(|(_, f)| (f.admitted_at_ms, f.digest, f.next_hop));
        let mut out = Vec::new();
        for (row, fwd) in due.into_iter().take(limit) {
            let Some(rso1) = forward_rso1(&self.conn, keys, &row.pk).map_err(text)? else {
                continue;
            };
            out.push(DueForward {
                digest: fwd.digest,
                next_hop: fwd.next_hop,
                depositor: fwd.depositor,
                store_tag: fwd.store_tag,
                rso1,
                expires_at_ms: fwd.expires_at_ms,
                attempts: fwd.attempts,
                last_code: fwd.last_code,
            });
        }
        Ok(out)
    }

    /// The next hop answered STORED or DUPLICATE: the row is never sent
    /// again (it answers a re-FORWARD `DUPLICATE` until it expires).
    pub fn mark_handed(
        &mut self,
        digest: &[u8; 32],
        next_hop: &[u8; 32],
        code: CustodyCode,
    ) -> Result<bool, String> {
        self.attempted(digest, next_hop, STATE_HANDED, None, code)
    }

    /// The next hop answered a terminal refusal.
    pub fn mark_refused(
        &mut self,
        digest: &[u8; 32],
        next_hop: &[u8; 32],
        code: CustodyCode,
    ) -> Result<bool, String> {
        self.attempted(digest, next_hop, STATE_REFUSED, None, code)
    }

    /// Try again at `next_try_ms` (TAG_UNKNOWN, or a transient answer).
    pub fn backoff(
        &mut self,
        digest: &[u8; 32],
        next_hop: &[u8; 32],
        next_try_ms: u64,
        code: CustodyCode,
    ) -> Result<bool, String> {
        self.attempted(digest, next_hop, STATE_PENDING, Some(next_try_ms), code)
    }

    /// One attempt's outcome on the row (`false`: no such row here, or one
    /// that does not open).
    fn attempted(
        &mut self,
        digest: &[u8; 32],
        next_hop: &[u8; 32],
        state: u8,
        next_try_ms: Option<u64>,
        code: CustodyCode,
    ) -> Result<bool, String> {
        let keys = self.keys.clone();
        let keys = keys.as_deref();
        let pk = fwd_pk(keys, digest, next_hop);
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(text)?;
        let _in_tx = crate::paths::HeldMark::transaction();
        let Some(mut fwd) = load_forward(&tx, keys, Some(&pk))
            .map_err(text)?
            .into_iter()
            .next()
            .and_then(|row| row.fwd)
        else {
            return Ok(false);
        };
        fwd.attempts = fwd.attempts.saturating_add(1);
        fwd.last_code = Some(code as u8);
        if let Some(next) = next_try_ms {
            fwd.next_try_ms = next;
        }
        let changed = update_forward(&tx, keys, &pk, &fwd, state).map_err(text)?;
        tx.commit().map_err(text)?;
        Ok(changed > 0)
    }

    /// Every durable prune (spec §3.2 retention): expired rows go, and so do
    /// forward rows whose depositor or next hop, and tags whose recipient,
    /// is no longer a pinned, unblocked contact; then incremental vacuum and
    /// a checkpoint, so what went leaves the file too. Rows removed.
    pub fn maintain(
        &mut self,
        now_ms: u64,
        still_allowed: &dyn Fn(&[u8; 32]) -> bool,
    ) -> Result<usize, String> {
        let keys = self.keys.clone();
        let keys = keys.as_deref();
        // Decided before the write transaction: the contact book is read
        // outside it, once per key.
        let mut allowed: HashMap<[u8; 32], bool> = HashMap::new();
        let mut ok = |key: &[u8; 32]| *allowed.entry(*key).or_insert_with(|| still_allowed(key));
        let forward: Vec<[Vec<u8>; 2]> = load_forward(&self.conn, keys, None)
            .map_err(text)?
            .into_iter()
            .filter(|row| {
                !row.live(now_ms)
                    || row
                        .fwd
                        .as_ref()
                        .is_some_and(|f| !ok(&f.depositor) || !ok(&f.next_hop))
            })
            .map(|row| row.pk)
            .collect();
        let tags: Vec<[u8; 16]> = load_tags(&self.conn, keys, TagFilter::All)
            .map_err(text)?
            .into_iter()
            .filter(|row| !row.live(now_ms) || row.meta.as_ref().is_some_and(|m| !ok(&m.recipient)))
            .map(|row| row.store_tag)
            .collect();
        let mut removed = 0;
        if !forward.is_empty() || !tags.is_empty() {
            let tx = self
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(text)?;
            let _in_tx = crate::paths::HeldMark::transaction();
            for pk in &forward {
                removed += delete_forward(&tx, keys.is_some(), pk).map_err(text)?;
            }
            for tag in &tags {
                removed += tx
                    .execute(
                        "DELETE FROM custody_tags_v1 WHERE store_tag = ?1",
                        params![tag.as_slice()],
                    )
                    .map_err(text)?;
            }
            tx.commit().map_err(text)?;
        }
        let _ = self.conn.execute_batch("PRAGMA incremental_vacuum;");
        // Busy (a reader in the way) is left to the next durable prune.
        let _ = crate::paths::checkpoint_truncate(&self.conn);
        Ok(removed)
    }

    /// `raven node custody off --purge`: every forward row and every tag,
    /// then a checkpoint. Rows deleted.
    pub fn purge(&mut self) -> Result<usize, String> {
        let purged = self
            .conn
            .execute("DELETE FROM custody_forward_v1", [])
            .map_err(text)?
            + self
                .conn
                .execute("DELETE FROM custody_tags_v1", [])
                .map_err(text)?;
        let _ = self.conn.execute_batch("PRAGMA incremental_vacuum;");
        let _ = crate::paths::checkpoint_truncate(&self.conn);
        Ok(purged)
    }

    /// What the store holds (counts only; rows not yet purged included).
    pub fn usage(&self) -> Result<HandoffUsage, String> {
        let mut usage = HandoffUsage::default();
        {
            let mut stmt = self
                .conn
                .prepare(
                    "SELECT state, COUNT(*), COALESCE(SUM(bytes), 0) FROM custody_forward_v1
                     GROUP BY state",
                )
                .map_err(text)?;
            let rows = stmt
                .query_map([], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, i64>(2)?,
                    ))
                })
                .map_err(text)?;
            for row in rows {
                let (state, count, bytes) = row.map_err(text)?;
                match u8::try_from(state).unwrap_or(STATE_REFUSED) {
                    STATE_PENDING => usage.pending += count,
                    STATE_HANDED => usage.handed += count,
                    _ => usage.refused += count,
                }
                usage.bytes += bytes;
            }
        }
        usage.tags = self
            .conn
            .query_row("SELECT COUNT(*) FROM custody_tags_v1", [], |r| r.get(0))
            .map_err(text)?;
        Ok(usage)
    }
}

/// The checks of a FORWARD's transaction on the live rows, in the spec's
/// order: DUPLICATE, CONFLICT, the next hops per digest (QUOTA), the node
/// caps (STORE_FULL), the depositor and pair caps (QUOTA), the depositor's
/// bytes per minute (RATE_LIMITED). A row whose `meta` does not open counts
/// for the node only.
fn forward_refusal(
    live: &[&FwdRow],
    (digest, next_hop, depositor, store_tag): (&[u8; 32], &[u8; 32], &[u8; 32], &[u8; 16]),
    bytes: i64,
    now_ms: u64,
) -> Option<CustodyCode> {
    let same: Vec<&Fwd> = live
        .iter()
        .filter_map(|r| r.fwd.as_ref())
        .filter(|f| f.digest == *digest)
        .collect();
    if same
        .iter()
        .any(|f| f.next_hop == *next_hop && f.store_tag == *store_tag)
    {
        return Some(CustodyCode::Duplicate);
    }
    if same.iter().any(|f| f.store_tag != *store_tag) {
        return Some(CustodyCode::Conflict);
    }
    if same.len() >= MAX_NEXT_HOPS_PER_DIGEST {
        return Some(CustodyCode::Quota);
    }
    let node_bytes: i64 = live.iter().map(|r| r.bytes).sum();
    if live.len() >= MAX_FORWARD_NODE_ROWS || node_bytes + bytes > MAX_FORWARD_NODE_BYTES {
        return Some(CustodyCode::StoreFull);
    }
    let theirs: Vec<(&FwdRow, &Fwd)> = live
        .iter()
        .filter_map(|r| r.fwd.as_ref().map(|f| (*r, f)))
        .filter(|(_, f)| f.depositor == *depositor)
        .collect();
    let their_bytes: i64 = theirs.iter().map(|(r, _)| r.bytes).sum();
    let pair = theirs
        .iter()
        .filter(|(_, f)| f.next_hop == *next_hop)
        .count();
    if theirs.len() >= MAX_FORWARD_DEPOSITOR_ROWS
        || their_bytes + bytes > MAX_FORWARD_DEPOSITOR_BYTES
        || pair >= MAX_FORWARD_PAIR_ROWS
    {
        return Some(CustodyCode::Quota);
    }
    let recent_from = now_ms.saturating_sub(MINUTE_MS);
    let recent: i64 = theirs
        .iter()
        .filter(|(_, f)| f.admitted_at_ms >= recent_from)
        .map(|(r, _)| r.bytes)
        .sum();
    if recent + bytes > MAX_FORWARD_BYTES_PER_MINUTE {
        return Some(CustodyCode::RateLimited);
    }
    None
}

/// A clear store's tables and version, at every open of one.
fn open_clear(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(&format!(
        "{PRAGMAS}\n{}\nPRAGMA user_version = {CLEAR_VERSION};",
        tables(false)
    ))
}

fn create_keyed(conn: &mut Connection) -> rusqlite::Result<()> {
    conn.execute_batch(PRAGMAS)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let _in_tx = crate::paths::HeldMark::transaction();
    if rebuild::shape(&tx, FORWARD, KEYED_COLUMN)? == Shape::Missing {
        tx.execute_batch(tables(true))?;
        rebuild::record(&tx, STORE, SCHEMA_VERSION, false)?;
    }
    tx.commit()
}

// ── Moving between the shapes (privacy pack rules) ───────────────────────

/// Both tables read whole in the shape `from` (`None`: clear), dropped, and
/// written in the shape `to`, inside the caller's transaction. Rows whose
/// sealed values do not open with `from` are left out and counted
/// (`dropped`). What each table must hold afterwards.
fn move_tables(
    tx: &Connection,
    from: Option<&MetaKeys>,
    to: Option<&MetaKeys>,
    report: &mut Migration,
) -> Result<[(&'static str, i64); 2], RebuildError> {
    let mut forward = Vec::new();
    let mut dropped = 0u32;
    for row in load_forward(tx, from, None)? {
        match (row.fwd, forward_rso1(tx, from, &row.pk)?) {
            (Some(fwd), Some(rso1)) => forward.push((fwd, row.state, rso1)),
            _ => dropped += 1,
        }
    }
    let mut tags = Vec::new();
    for row in load_tags(tx, from, TagFilter::All)? {
        match row.meta {
            Some(meta) => tags.push((row.store_tag, meta, row.conflicted)),
            None => dropped += 1,
        }
    }
    tx.execute_batch(
        "DROP TABLE IF EXISTS custody_forward_v1; DROP TABLE IF EXISTS custody_tags_v1;",
    )?;
    tx.execute_batch(tables(to.is_some()))?;
    for (fwd, state, rso1) in &forward {
        insert_forward(tx, to, fwd, *state, rso1)?;
    }
    for (tag, meta, conflicted) in &tags {
        put_tag(tx, to, tag, meta, *conflicted)?;
    }
    report.rows = u32::try_from(forward.len() + tags.len()).unwrap_or(u32::MAX);
    report.dropped = dropped;
    Ok([(FORWARD, forward.len() as i64), (TAGS, tags.len() as i64)])
}

/// One move of the store at `path` on `conn`: from the shape `from` (else
/// nothing to do) to the shape `to`, counts checked before the commit,
/// recorded as `version`, then the scrub.
fn rebuild_store(
    mut conn: Connection,
    from: Option<&MetaKeys>,
    to: Option<&MetaKeys>,
    version: i64,
    free: rebuild::FreeBytes<'_>,
) -> Result<Migration, RebuildError> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let _in_tx = crate::paths::HeldMark::transaction();
    let want = if from.is_some() {
        Shape::Keyed
    } else {
        Shape::Clear
    };
    if rebuild::shape(&tx, FORWARD, KEYED_COLUMN)? != want {
        return Ok(Migration::already());
    }
    let mut report = Migration::default();
    let expected = move_tables(&tx, from, to, &mut report)?;
    rebuild::verify(&tx, &expected)?;
    rebuild::record(&tx, STORE, version, true)?;
    tx.commit()?;
    let scrubbed = rebuild::scrub(&conn, STORE, free)?;
    report.scrub_pending = !scrubbed.complete;
    Ok(report)
}

/// Schema 1 -> 2 (the open in a sealed profile, and [`migrate`]).
fn migrate_forward(
    path: &Path,
    keys: &MetaKeys,
    free: rebuild::FreeBytes<'_>,
) -> Result<Migration, RebuildError> {
    rebuild::space_ok(path, free).map_err(|needed| RebuildError::NoSpace { needed })?;
    let conn = rebuild::dedicated(path)?;
    rebuild::arm_disk_full(&conn)?;
    rebuild_store(conn, None, Some(keys), SCHEMA_VERSION, free)
}

fn store_error(e: RebuildError) -> String {
    match e {
        RebuildError::Key(key) => format!("custody handoff store: {key}"),
        other => format!("{HANDOFF_DB_FILE}: {other}"),
    }
}

/// The eager half of the migration (`privacy::migrate_all` and the prune
/// passes): in a sealed profile with its keys loaded, an existing clear
/// store moves to schema 2. `true` when it moved now.
pub fn migrate(data_dir: &Path) -> Result<bool, String> {
    if !needs_migration(data_dir) || crate::privacy::mode(data_dir) != Mode::Sealed {
        return Ok(false);
    }
    let (_, migrated) = HandoffStore::open_at(data_dir, &handoff_db_path(data_dir))?;
    Ok(migrated)
}

/// Whether the store's header says it is still clear (no SQLite open).
pub fn needs_migration(data_dir: &Path) -> bool {
    let path = handoff_db_path(data_dir);
    path.exists() && rebuild::header_user_version(&path).is_none_or(|v| v < SCHEMA_VERSION)
}

/// The way back (`raven privacy unseal`): a schema-2 store moves to schema
/// 1 with the keys this process loaded. Nothing to do without a store or on
/// a clear one.
pub fn unseal(data_dir: &Path) -> Result<Migration, String> {
    let path = handoff_db_path(data_dir);
    if !path.exists() {
        return Ok(Migration::already());
    }
    let keys = cached_keys(data_dir)?;
    let free = &crate::disk_space::free_bytes;
    rebuild::space_ok(&path, free)
        .map_err(|needed| store_error(RebuildError::NoSpace { needed }))?;
    let conn = rebuild::dedicated(&path).map_err(|e| store_error(e.into()))?;
    rebuild_store(conn, Some(&keys), None, CLEAR_VERSION, free).map_err(store_error)
}

/// `raven privacy rotate-meta`: a schema-2 store is keyed again with the
/// keys this process holds now (a new `k_index`; the epochs they hold open
/// the old rows), on a connection that writes nothing before the commit.
pub fn rekey(data_dir: &Path) -> Result<Migration, String> {
    let path = handoff_db_path(data_dir);
    if !path.exists() {
        return Ok(Migration::already());
    }
    let keys = cached_keys(data_dir)?;
    let free = &crate::disk_space::free_bytes;
    rebuild::space_ok(&path, free)
        .map_err(|needed| store_error(RebuildError::NoSpace { needed }))?;
    let conn = rebuild::rekey_connection(&path).map_err(|e| store_error(e.into()))?;
    rebuild_store(conn, Some(&keys), Some(&keys), SCHEMA_VERSION, free).map_err(store_error)
}

/// A pending scrub is done now (the prune passes). `None` when nothing was
/// pending.
pub fn finish_scrub(data_dir: &Path) -> Option<bool> {
    rebuild::finish_scrub(
        &handoff_db_path(data_dir),
        STORE,
        &crate::disk_space::free_bytes,
    )
    .ok()
    .flatten()
}

/// Whether a scrub of the store is pending (`raven privacy status`).
pub fn scrub_pending(data_dir: &Path) -> bool {
    rebuild::scrub_pending(&handoff_db_path(data_dir), STORE)
}

/// Rows whose sealed values are not on epoch `current` (by their first
/// bytes; no key, no lock): the rotation's old-object count. `0` without a
/// schema-2 store.
pub fn rows_off_epoch(data_dir: &Path, current: u32) -> Result<u32, String> {
    let path = handoff_db_path(data_dir);
    if !path.exists() {
        return Ok(0);
    }
    let conn = Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)
        .map_err(text)?;
    conn.busy_timeout(std::time::Duration::from_secs(2))
        .map_err(text)?;
    if rebuild::shape(&conn, FORWARD, KEYED_COLUMN).map_err(text)? != Shape::Keyed {
        return Ok(0);
    }
    let epoch = current.to_be_bytes().to_vec();
    let n: i64 = conn
        .query_row(
            "SELECT (SELECT COUNT(*) FROM custody_forward_v1
                     WHERE substr(meta, 2, 4) != ?1 OR substr(rso1, 2, 4) != ?1)
                  + (SELECT COUNT(*) FROM custody_tags_v1 WHERE substr(meta, 2, 4) != ?1)",
            params![epoch],
            |r| r.get(0),
        )
        .map_err(text)?;
    Ok(u32::try_from(n).unwrap_or(u32::MAX))
}

/// A schema-2 forward row's keyed key columns, `meta` and sealed RSO1.
type SealedForward = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

/// A data-key rotation's step for this store (PP.10): in one IMMEDIATE
/// transaction every sealed value not on the current epoch is opened and
/// sealed again under it, then the WAL is checkpointed. Values that do not
/// open are left as they are (`unreadable`).
pub fn reseal_rows(data_dir: &Path) -> Result<RowReseal, String> {
    let mut report = RowReseal::default();
    let path = handoff_db_path(data_dir);
    if !path.exists() || crate::privacy::mode(data_dir) != Mode::Sealed {
        return Ok(report);
    }
    let keys = cached_keys(data_dir)?;
    let current = keys.current_epoch();
    if rows_off_epoch(data_dir, current)? == 0 {
        return Ok(report);
    }
    let (mut store, _) = HandoffStore::open_at(data_dir, &path)?;
    if store.keys.is_none() {
        return Ok(report);
    }
    let epoch = current.to_be_bytes().to_vec();
    let tx = store
        .conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(text)?;
    let _in_tx = crate::paths::HeldMark::transaction();
    let forward: Vec<SealedForward> = {
        let mut stmt = tx
            .prepare(
                "SELECT kh_object_digest, kh_next_hop, meta, rso1 FROM custody_forward_v1
                 WHERE substr(meta, 2, 4) != ?1 OR substr(rso1, 2, 4) != ?1",
            )
            .map_err(text)?;
        let rows = stmt
            .query_map(params![epoch], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })
            .map_err(text)?;
        rows.collect::<Result<_, _>>().map_err(text)?
    };
    for (kd, kn, meta, rso1) in forward {
        let key = [kd.as_slice(), kn.as_slice()].concat();
        let (Ok(meta), Ok(rso1)) = (
            at_rest::open_row(&keys, FORWARD, &key, &meta),
            at_rest::open_row(&keys, RSO1_LABEL, &key, &rso1),
        ) else {
            report.unreadable += 1;
            continue;
        };
        tx.execute(
            "UPDATE custody_forward_v1 SET meta = ?3, rso1 = ?4
             WHERE kh_object_digest = ?1 AND kh_next_hop = ?2",
            params![
                kd,
                kn,
                at_rest::seal_row(&keys, FORWARD, &key, &meta),
                at_rest::seal_row(&keys, RSO1_LABEL, &key, &rso1)
            ],
        )
        .map_err(text)?;
        report.resealed += 1;
    }
    let tags: Vec<(Vec<u8>, Vec<u8>)> = {
        let mut stmt = tx
            .prepare("SELECT store_tag, meta FROM custody_tags_v1 WHERE substr(meta, 2, 4) != ?1")
            .map_err(text)?;
        let rows = stmt
            .query_map(params![epoch], |r| Ok((r.get(0)?, r.get(1)?)))
            .map_err(text)?;
        rows.collect::<Result<_, _>>().map_err(text)?
    };
    for (tag, meta) in tags {
        let Ok(meta) = at_rest::open_row(&keys, TAGS, &tag, &meta) else {
            report.unreadable += 1;
            continue;
        };
        tx.execute(
            "UPDATE custody_tags_v1 SET meta = ?2 WHERE store_tag = ?1",
            params![tag, at_rest::seal_row(&keys, TAGS, &tag, &meta)],
        )
        .map_err(text)?;
        report.resealed += 1;
    }
    tx.commit().map_err(text)?;
    if report.resealed > 0 {
        report.scrub_pending = crate::paths::checkpoint_truncate(&store.conn)
            .map_or(true, |checkpoint| checkpoint.busy);
    }
    Ok(report)
}

/// Quarantined copies whose rows have all expired go (best effort).
pub(super) fn drop_old_quarantine(data_dir: &Path, now_ms: u64) {
    let prefix = format!("{HANDOFF_DB_FILE}.corrupt-");
    let Ok(entries) = std::fs::read_dir(data_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(stamp) = name
            .to_str()
            .and_then(|name| name.strip_prefix(&prefix))
            .and_then(|stamp| stamp.parse::<u64>().ok())
        else {
            continue;
        };
        if now_ms.saturating_sub(stamp) > QUARANTINE_KEEP_MS {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

#[cfg(test)]
impl HandoffStore {
    /// Tests: the store's connection (shape and raw bytes checks).
    pub(crate) fn conn_for_tests(&self) -> &Connection {
        &self.conn
    }
}
