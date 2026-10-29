//! Durable owed ACKs (`docs/design/2026-10-friend-custody.md` §9).
//!
//! A sealed ACK we owe a contact, but could not hand back on the link that
//! brought its message (F8), or that answers a message we fetched from a
//! custodian, is kept here until it is written directly or expires. The table
//! never evicts: when it is full, relayed ingest pushes back
//! (`OWED_ACK_FULL`) and the message stays with the custodian.
//!
//! `<data_dir>/owed_acks.sqlite`, created lazily.
//!
//! **At rest (privacy pack PP.12; docs/design/2026-10-at-rest-metadata.md
//! section 7).** In a sealed profile the store is at schema 2: the ACK
//! digest, the peer and the custodians are keyed lookups (`kh_ack_digest`,
//! `kh_peer`, `kh_custodian`: [`crate::at_rest::index`] by value type), the
//! ACK's bytes are sealed whole (their clear header names devices), and the
//! clear values, the times and the origin are in each row's sealed `meta`;
//! only `prune_after_hour` (the expiry rounded up to the hour, for the
//! prune) and the random `session_id` stay clear. A profile that is not
//! sealed keeps schema 1, today's columns. A clear store in a sealed profile
//! moves to schema 2 with the rebuild recipe of [`crate::sqlite_rebuild`]
//! (eagerly from `privacy::migrate_all`, and on open); [`unseal`] is the way
//! back. Without the profile's at-rest key a sealed profile's store does not
//! open ([`OwedError::KeyUnavailable`]), never a clear fallback.
//!
//! An older build that meets schema 2 sets the file aside as
//! `owed_acks.sqlite.corrupt-<ms>` and starts an empty clear store (review
//! R06): [`merge_set_asides`] brings the set-aside rows back once this build
//! runs again, and seals a set-aside that does not open as schema 2 where
//! it is.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::at_rest::{self, AtRestError, Kind, MetaKeys, Mode, ValueType};
use crate::sqlite_rebuild::{self as rebuild, Migration, RebuildError, RowReseal, Shape, Steps};

pub const OWED_ACKS_FILE: &str = "owed_acks.sqlite";
pub const MAX_OWED_PER_PEER: i64 = 256;
pub const MAX_OWED_TOTAL: i64 = 2_048;
/// Schema 2 (PP.12): keyed lookups and sealed `meta`.
const SCHEMA_VERSION: i64 = 2;
/// Schema 1: today's clear columns (a profile that is not sealed, and every
/// older build).
const CLEAR_VERSION: i64 = 1;
/// This store's row in `raven_schema`.
const STORE: &str = "owed_acks";
const ACKS: &str = "owed_acks_v1";
const HELD: &str = "owed_ack_held_v1";
/// The keyed column that tells the two shapes apart.
const KEYED_COLUMN: &str = "kh_ack_digest";
/// The AAD label of a row's sealed ACK bytes (its `meta` uses the table).
const BYTES_LABEL: &str = "owed_acks_v1.bytes";
/// What an older build (and this one) names a store it set aside.
const SET_ASIDE_PREFIX: &str = "owed_acks.sqlite.corrupt-";

/// Where an owed ACK came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Origin {
    /// Its reply could not be written on the inbound link (F8).
    Link = 0,
    /// It answers a message fetched from a custodian.
    Relayed = 1,
    /// A Prepared ACK row handed to a custodian.
    Prepared = 2,
    /// Rebuilt from the session store after corruption: push-only.
    Rebuilt = 3,
}

impl Origin {
    fn from_i64(v: i64) -> Self {
        match v {
            1 => Self::Relayed,
            2 => Self::Prepared,
            3 => Self::Rebuilt,
            _ => Self::Link,
        }
    }

    /// Rebuilt entries are never deposited (they would use up a custodian's
    /// quota for ACKs the links may already have carried).
    pub fn may_deposit(self) -> bool {
        self != Self::Rebuilt
    }
}

#[derive(Debug)]
pub enum OwedError {
    /// The peer (256) or the table (2,048) is full: back-pressure.
    Full,
    Store(String),
    /// The profile is sealed and this process holds no at-rest key: the
    /// store waits for it (never set aside, never read in clear).
    KeyUnavailable(String),
}

impl std::fmt::Display for OwedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Full => f.write_str("OWED_ACK_FULL"),
            Self::Store(e) | Self::KeyUnavailable(e) => write!(f, "OWED_ACKS_UNAVAILABLE: {e}"),
        }
    }
}

impl From<rusqlite::Error> for OwedError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Store(e.to_string())
    }
}

impl From<AtRestError> for OwedError {
    fn from(e: AtRestError) -> Self {
        match e {
            AtRestError::KeyUnavailable(_)
            | AtRestError::KeyLost(_)
            | AtRestError::StaleKeys { .. } => Self::KeyUnavailable(e.to_string()),
            _ => Self::Store("corrupt owed ack row".into()),
        }
    }
}

impl From<RebuildError> for OwedError {
    fn from(e: RebuildError) -> Self {
        match e {
            RebuildError::Key(key) => key.into(),
            other => Self::Store(format!("{OWED_ACKS_FILE}: {other}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwedAck {
    pub ack_digest: [u8; 32],
    pub peer: [u8; 32],
    pub session_id: Option<[u8; 32]>,
    pub bytes: Vec<u8>,
    pub expires_at_ms: u64,
    pub origin: Origin,
    /// Custodians already holding a copy.
    pub held_by: Vec<[u8; 32]>,
}

/// An open error that means the file itself is unusable (newer schema,
/// failed integrity check, not a database), not a transient fault.
fn unusable(err: &str) -> bool {
    let e = err.to_ascii_lowercase();
    e.contains("newer than this build")
        || e.contains("integrity check")
        || e.contains("not a database")
        || e.contains("malformed")
        || e.contains("corrupt")
}

/// An open error that is SQLite's BUSY: another connection holds the lock.
fn busy(err: &str) -> bool {
    err.contains("database is locked") || err.contains("database is busy")
}

/// Serializes setting an unusable `owed_acks.sqlite` aside, and merging set-
/// aside stores back (the writer lock of `owed_acks.sqlite.corrupt-*` in
/// `at_rest::FILES`).
pub(crate) const OWED_ACKS_ASIDE_LOCK: &str = ".owed_acks_aside.lock.sqlite";

/// How long one open waits on another connection's lock (its busy timeout).
const BUSY_WAIT: std::time::Duration = std::time::Duration::from_secs(10);
/// [`OwedAcks::open`] retries an open that SQLite answered BUSY at once this
/// many times (10 ms doubling to 200 ms: about 1.5 s in all), as the session
/// store's first open does.
const OPEN_BUSY_RETRIES: usize = 10;

pub fn owed_acks_path(data_dir: &Path) -> PathBuf {
    data_dir.join(OWED_ACKS_FILE)
}

fn ms(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

fn arr32(v: &[u8]) -> Result<[u8; 32], OwedError> {
    v.try_into()
        .map_err(|_| OwedError::Store("corrupt owed ack row".into()))
}

fn hex32(text: &str) -> Result<[u8; 32], OwedError> {
    arr32(&hex::decode(text).map_err(|_| OwedError::Store("corrupt owed ack row".into()))?)
}

// ── Schemas ──────────────────────────────────────────────────────────────

/// Schema 1 exactly as every build before PP.12 creates it (and this one in
/// a profile that is not sealed).
const CLEAR_SCHEMA: &str = "PRAGMA journal_mode=WAL;
     PRAGMA synchronous=FULL;
     CREATE TABLE IF NOT EXISTS owed_acks_v1 (
       ack_digest BLOB PRIMARY KEY NOT NULL CHECK(length(ack_digest)=32),
       peer BLOB NOT NULL CHECK(length(peer)=32),
       session_id BLOB CHECK(session_id IS NULL OR length(session_id)=32),
       bytes BLOB NOT NULL,
       expires_at_ms INTEGER NOT NULL,
       origin INTEGER NOT NULL,
       recorded_at_ms INTEGER NOT NULL);
     CREATE INDEX IF NOT EXISTS idx_owed_peer ON owed_acks_v1(peer);
     CREATE TABLE IF NOT EXISTS owed_ack_held_v1 (
       ack_digest BLOB NOT NULL, custodian BLOB NOT NULL,
       PRIMARY KEY (ack_digest, custodian));
     PRAGMA user_version = 1;";

/// `owed_acks_v1` named `name`, in either shape. The keyed index keeps the
/// clear one's name, so an older build's `CREATE INDEX IF NOT EXISTS` is a
/// no-op on a migrated store.
fn acks_table(name: &str, keyed: bool) -> String {
    if keyed {
        format!(
            "CREATE TABLE {name} (
               kh_ack_digest BLOB PRIMARY KEY NOT NULL CHECK(length(kh_ack_digest)=32),
               kh_peer BLOB NOT NULL CHECK(length(kh_peer)=32),
               session_id BLOB CHECK(session_id IS NULL OR length(session_id)=32),
               bytes BLOB NOT NULL,
               meta BLOB NOT NULL,
               prune_after_hour INTEGER NOT NULL);"
        )
    } else {
        format!(
            "CREATE TABLE {name} (
               ack_digest BLOB PRIMARY KEY NOT NULL CHECK(length(ack_digest)=32),
               peer BLOB NOT NULL CHECK(length(peer)=32),
               session_id BLOB CHECK(session_id IS NULL OR length(session_id)=32),
               bytes BLOB NOT NULL,
               expires_at_ms INTEGER NOT NULL,
               origin INTEGER NOT NULL,
               recorded_at_ms INTEGER NOT NULL);"
        )
    }
}

fn held_table(name: &str, keyed: bool) -> String {
    if keyed {
        format!(
            "CREATE TABLE {name} (
               kh_ack_digest BLOB NOT NULL, kh_custodian BLOB NOT NULL, meta BLOB NOT NULL,
               PRIMARY KEY (kh_ack_digest, kh_custodian));"
        )
    } else {
        format!(
            "CREATE TABLE {name} (
               ack_digest BLOB NOT NULL, custodian BLOB NOT NULL,
               PRIMARY KEY (ack_digest, custodian));"
        )
    }
}

fn peer_index(keyed: bool) -> &'static str {
    if keyed {
        "CREATE INDEX idx_owed_peer ON owed_acks_v1(kh_peer);"
    } else {
        "CREATE INDEX idx_owed_peer ON owed_acks_v1(peer);"
    }
}

// ── Sealed values ────────────────────────────────────────────────────────

/// A schema-2 row's clear values.
#[derive(Serialize, Deserialize)]
struct AckMeta {
    ack_digest: String,
    peer: String,
    expires_at_ms: u64,
    origin: i64,
    recorded_at_ms: u64,
}

#[derive(Serialize, Deserialize)]
struct HeldMeta {
    custodian: String,
}

/// One owed ACK's values, whatever the shape.
struct Clear {
    ack_digest: Vec<u8>,
    peer: Vec<u8>,
    session_id: Option<Vec<u8>>,
    bytes: Vec<u8>,
    expires_at_ms: u64,
    origin: i64,
    recorded_at_ms: u64,
}

fn kh_digest(keys: &MetaKeys, digest: &[u8]) -> [u8; 32] {
    at_rest::index(keys, ValueType::ObjectDigest, digest)
}

fn kh_device(keys: &MetaKeys, device: &[u8]) -> [u8; 32] {
    at_rest::index(keys, ValueType::DeviceKey, device)
}

/// `(meta, sealed bytes)` of a schema-2 row whose key is `kd`.
fn seal_ack(keys: &MetaKeys, kd: &[u8; 32], ack: &Clear) -> (Vec<u8>, Vec<u8>) {
    let meta = Zeroizing::new(
        serde_json::to_vec(&AckMeta {
            ack_digest: hex::encode(&ack.ack_digest),
            peer: hex::encode(&ack.peer),
            expires_at_ms: ack.expires_at_ms,
            origin: ack.origin,
            recorded_at_ms: ack.recorded_at_ms,
        })
        .expect("strings and numbers serialize"),
    );
    (
        at_rest::seal_row(keys, ACKS, kd, &meta),
        at_rest::seal_row(keys, BYTES_LABEL, kd, &ack.bytes),
    )
}

/// A schema-2 row's values (its `meta` and bytes opened).
fn open_ack(
    keys: &MetaKeys,
    kd: &[u8],
    session_id: Option<Vec<u8>>,
    meta: &[u8],
    bytes: &[u8],
) -> Result<Clear, OwedError> {
    let plain = at_rest::open_row(keys, ACKS, kd, meta)?;
    let meta: AckMeta = serde_json::from_slice(&plain)
        .map_err(|_| OwedError::Store("corrupt owed ack row".into()))?;
    let corrupt = |_| OwedError::Store("corrupt owed ack row".into());
    Ok(Clear {
        ack_digest: hex::decode(&meta.ack_digest).map_err(corrupt)?,
        peer: hex::decode(&meta.peer).map_err(corrupt)?,
        session_id,
        bytes: at_rest::open_row(keys, BYTES_LABEL, kd, bytes)?.to_vec(),
        expires_at_ms: meta.expires_at_ms,
        origin: meta.origin,
        recorded_at_ms: meta.recorded_at_ms,
    })
}

fn held_pk(kd: &[u8], kc: &[u8]) -> Vec<u8> {
    [kd, kc].concat()
}

fn seal_held(keys: &MetaKeys, kd: &[u8], kc: &[u8], custodian: &[u8]) -> Vec<u8> {
    let meta = serde_json::json!({ "custodian": hex::encode(custodian) }).to_string();
    at_rest::seal_row(keys, HELD, &held_pk(kd, kc), meta.as_bytes())
}

fn open_held(keys: &MetaKeys, kd: &[u8], kc: &[u8], meta: &[u8]) -> Result<[u8; 32], OwedError> {
    let plain = at_rest::open_row(keys, HELD, &held_pk(kd, kc), meta)?;
    let meta: HeldMeta = serde_json::from_slice(&plain)
        .map_err(|_| OwedError::Store("corrupt owed ack row".into()))?;
    hex32(&meta.custodian)
}

/// The at-rest keys this process loaded (never a keystore call).
fn cached_keys(data_dir: &Path) -> Result<Arc<MetaKeys>, OwedError> {
    at_rest::keys_cached(data_dir).map_err(|e| OwedError::KeyUnavailable(e.to_string()))
}

/// What the digest column holds for `digest` (`keys`: schema 2).
fn digest_value(keys: Option<&MetaKeys>, digest: &[u8; 32]) -> Vec<u8> {
    keys.map_or_else(|| digest.to_vec(), |keys| kh_digest(keys, digest).to_vec())
}

/// What a device column (peer, custodian) holds for `device`.
fn device_value(keys: Option<&MetaKeys>, device: &[u8; 32]) -> Vec<u8> {
    keys.map_or_else(|| device.to_vec(), |keys| kh_device(keys, device).to_vec())
}

/// Which schema the open store is at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Layout {
    /// Schema 1: clear columns.
    Clear,
    /// Schema 2: keyed lookups and sealed `meta`.
    Keyed,
}

/// One open store. A handle lives for an operation or a few (every caller
/// opens it where it needs it): a schema-2 store's keys are the ones this
/// process held when it opened, read again when a row names an epoch they
/// lack (a rotation since). A write with keys a rotation has just replaced
/// seals under the older epoch, which stays readable through the
/// rotation's grace and is sealed again before it goes (review R04).
pub struct OwedAcks {
    conn: Connection,
    data_dir: PathBuf,
    layout: Layout,
    keys: Option<Arc<MetaKeys>>,
}

impl OwedAcks {
    /// Open (creating it) the table. A newer schema or a failed integrity
    /// check sets the file aside ([`set_aside_in_place`]) and starts empty;
    /// the caller then rebuilds push-only entries from the session store
    /// (`rebuilt == true`).
    ///
    /// Concurrent openers of an unusable file set it aside once, and each
    /// gets a working store: the set-aside, the fresh store and its rebuild
    /// happen under `.owed_acks_aside.lock.sqlite`, and an opener that found
    /// the file unusable opens again under that lock (another opener may
    /// have just set it aside and started the fresh store).
    pub fn open(data_dir: &Path) -> Result<(Self, bool), OwedError> {
        let path = owed_acks_path(data_dir);
        match Self::open_settled(data_dir, &path) {
            Ok((store, migrated)) => {
                // A clear store in a sealed profile was an older build's
                // fresh one (review R06): bring back what it set aside.
                if migrated {
                    let _ = merge_set_asides(data_dir);
                }
                Ok((store, false))
            }
            // Only a file that is really unusable is set aside: a busy or
            // unreadable one (I/O, permissions) is an error, never data loss.
            Err(OwedError::Store(e)) if unusable(&e) => {
                // One set-aside at a time, and only of a file that is still
                // unusable under the lock: a concurrent opener may already
                // have replaced it with a fresh, rebuilt one.
                let _aside_lock =
                    crate::paths::DataDirLock::acquire(data_dir, OWED_ACKS_ASIDE_LOCK)
                        .map_err(OwedError::Store)?;
                match Self::open_settled(data_dir, &path) {
                    Ok((store, _)) => return Ok((store, false)),
                    Err(OwedError::Store(e)) if path.exists() && unusable(&e) => {}
                    Err(e) => return Err(e),
                }
                let aside =
                    path.with_extension(format!("sqlite.corrupt-{}", crate::clock::now_ms()));
                set_aside_in_place(&path, &aside).map_err(|e| OwedError::Store(e.to_string()))?;
                eprintln!("raven: owed_acks.sqlite was unusable and was set aside; rebuilding");
                let (mut fresh, _) = Self::open_settled(data_dir, &path)?;
                let _ = fresh.rebuild_from_sessions(data_dir);
                Ok((fresh, true))
            }
            Err(e) => Err(e),
        }
    }

    /// [`Self::open_at`], again while SQLite answers BUSY at once: two first
    /// opens of a fresh file (a profile's first, or the one a set-aside
    /// left) race on `PRAGMA journal_mode=WAL` and the schema, and SQLite
    /// answers BUSY there without waiting its busy timeout. Opening is
    /// idempotent: retried, briefly and bounded. A BUSY that waited the
    /// whole busy timeout is returned as it is.
    fn open_settled(data_dir: &Path, path: &Path) -> Result<(Self, bool), OwedError> {
        let mut wait = std::time::Duration::from_millis(10);
        for _ in 0..OPEN_BUSY_RETRIES {
            let started = std::time::Instant::now();
            match Self::open_at(data_dir, path) {
                Err(OwedError::Store(e)) if busy(&e) && started.elapsed() < BUSY_WAIT => {
                    std::thread::sleep(wait);
                    wait = (wait * 2).min(std::time::Duration::from_millis(200));
                }
                other => return other,
            }
        }
        Self::open_at(data_dir, path)
    }

    /// After a set-aside: every queued, unexpired ACK the session store still
    /// holds becomes a push-only entry (`Origin::Rebuilt`, never deposited).
    fn rebuild_from_sessions(&mut self, data_dir: &Path) -> Result<usize, OwedError> {
        let now = crate::clock::now_ms();
        let store = crate::IndexedSessionStore::open(data_dir)
            .map_err(|e| OwedError::Store(e.redacted_display()))?;
        let rows = store
            .live_queued_ack_rows(now)
            .map_err(|e| OwedError::Store(e.redacted_display()))?;
        let mut n = 0;
        for row in rows {
            if self
                .record(
                    &row.recipient,
                    Some(row.session_id),
                    &row.object_digest,
                    &row.bytes,
                    row.expires_at_ms,
                    Origin::Rebuilt,
                    now,
                )
                .is_ok()
            {
                n += 1;
            }
        }
        Ok(n)
    }

    /// Open only if the file exists (no creation).
    pub fn open_existing(data_dir: &Path) -> Result<Option<Self>, OwedError> {
        if !owed_acks_path(data_dir).exists() {
            return Ok(None);
        }
        Self::open(data_dir).map(|(s, _)| Some(s))
    }

    /// Open the store at `path`, bringing it to the schema the profile's mode
    /// asks for: schema 2 in a sealed profile (created so, or migrated from a
    /// clear store, then `true`), schema 1 otherwise. A schema-2 store opens
    /// only with the keys loaded, whatever the mode. Too little free disk
    /// space to migrate leaves a clear store as it is until a later pass.
    fn open_at(data_dir: &Path, path: &Path) -> Result<(Self, bool), OwedError> {
        let sealed = crate::privacy::mode(data_dir) == Mode::Sealed;
        // Before anything is created: no key, no store (never a clear one).
        if sealed {
            cached_keys(data_dir)?;
        }
        let mut conn = crate::paths::open_private_data_dir_sqlite(path)?;
        conn.busy_timeout(BUSY_WAIT)?;
        // A cleared or expired ACK is overwritten, not left in the file (PP.2).
        crate::paths::harden_sqlite(&conn)?;
        let mut migrated = false;
        // Three rounds at most: create or migrate, then open what is there
        // (a racing creator may leave either shape).
        for _ in 0..3 {
            let version = rebuild::user_version(&conn)?;
            let recorded = rebuild::recorded(&conn, STORE)?.map(|(version, _)| version);
            if version > SCHEMA_VERSION || recorded.is_some_and(|v| v > SCHEMA_VERSION) {
                return Err(OwedError::Store(
                    "owed_acks.sqlite is newer than this build".into(),
                ));
            }
            let ok: String = conn.query_row("PRAGMA quick_check", [], |r| r.get(0))?;
            if ok != "ok" {
                return Err(OwedError::Store(
                    "owed_acks.sqlite failed its integrity check".into(),
                ));
            }
            let (layout, keys) = match rebuild::shape(&conn, ACKS, KEYED_COLUMN)? {
                Shape::Keyed => {
                    let keys = cached_keys(data_dir)?;
                    // Stamped again where an older process stamped its own
                    // number (review R06): never migrated twice.
                    if version != SCHEMA_VERSION || recorded != Some(SCHEMA_VERSION) {
                        rebuild::restamp(&mut conn, STORE, SCHEMA_VERSION)?;
                    }
                    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")?;
                    (Layout::Keyed, Some(keys))
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
                        // Deferred: the store keeps working as it is, and
                        // the next pass (or open) tries again.
                        Err(RebuildError::NoSpace { .. }) => {
                            conn.execute_batch(CLEAR_SCHEMA)?;
                            (Layout::Clear, None)
                        }
                        Err(e) => return Err(e.into()),
                    }
                }
                Shape::Missing | Shape::Clear => {
                    conn.execute_batch(CLEAR_SCHEMA)?;
                    (Layout::Clear, None)
                }
            };
            return Ok((
                Self {
                    conn,
                    data_dir: data_dir.to_path_buf(),
                    layout,
                    keys,
                },
                migrated,
            ));
        }
        Err(OwedError::Store(
            "owed_acks.sqlite changed shape while it was opened; try again".into(),
        ))
    }

    fn keyed(&self) -> bool {
        self.layout == Layout::Keyed
    }

    fn keys(&self) -> Result<Arc<MetaKeys>, OwedError> {
        match &self.keys {
            Some(keys) => Ok(Arc::clone(keys)),
            None => cached_keys(&self.data_dir),
        }
    }

    /// `(ack digest, peer, custodian)` column names.
    fn cols(&self) -> (&'static str, &'static str, &'static str) {
        match self.layout {
            Layout::Clear => ("ack_digest", "peer", "custodian"),
            Layout::Keyed => ("kh_ack_digest", "kh_peer", "kh_custodian"),
        }
    }

    /// The keys of a schema-2 store (`None`: schema 1), once per operation.
    fn layout_keys(&self) -> Result<Option<Arc<MetaKeys>>, OwedError> {
        match self.layout {
            Layout::Clear => Ok(None),
            Layout::Keyed => self.keys().map(Some),
        }
    }

    /// Room for one more owed ACK to `peer`.
    pub fn has_room(&self, peer: &[u8; 32]) -> Result<bool, OwedError> {
        let (_, peer_col, _) = self.cols();
        let (per_peer, total): (i64, i64) = self.conn.query_row(
            &format!(
                "SELECT (SELECT COUNT(*) FROM owed_acks_v1 WHERE {peer_col} = ?1),
                        (SELECT COUNT(*) FROM owed_acks_v1)"
            ),
            params![device_value(self.layout_keys()?.as_deref(), peer)],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        Ok(per_peer < MAX_OWED_PER_PEER && total < MAX_OWED_TOTAL)
    }

    /// Record an owed ACK. Idempotent; fills a missing session id; never
    /// evicts (`Full` instead).
    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &mut self,
        peer: &[u8; 32],
        session_id: Option<[u8; 32]>,
        ack_digest: &[u8; 32],
        bytes: &[u8],
        expires_at_ms: u64,
        origin: Origin,
        now_ms: u64,
    ) -> Result<(), OwedError> {
        let (digest_col, peer_col, _) = self.cols();
        let keys = self.layout_keys()?;
        let digest_key = digest_value(keys.as_deref(), ack_digest);
        let peer_key = device_value(keys.as_deref(), peer);
        // Sealed before the write transaction (no keystore call either way).
        let sealed = match keys.as_deref() {
            None => None,
            Some(keys) => Some(seal_ack(
                keys,
                &arr32(&digest_key)?,
                &Clear {
                    ack_digest: ack_digest.to_vec(),
                    peer: peer.to_vec(),
                    session_id: None,
                    bytes: bytes.to_vec(),
                    expires_at_ms,
                    origin: origin as i64,
                    recorded_at_ms: now_ms,
                },
            )),
        };
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let _in_tx = crate::paths::HeldMark::transaction();
        let exists: Option<i64> = tx
            .query_row(
                &format!("SELECT 1 FROM owed_acks_v1 WHERE {digest_col} = ?1"),
                params![digest_key],
                |r| r.get(0),
            )
            .optional()?;
        if exists.is_some() {
            if let Some(sid) = session_id {
                tx.execute(
                    &format!(
                        "UPDATE owed_acks_v1 SET session_id = ?2
                         WHERE {digest_col} = ?1 AND session_id IS NULL"
                    ),
                    params![digest_key, sid.as_slice()],
                )?;
            }
            tx.commit()?;
            return Ok(());
        }
        let (per_peer, total): (i64, i64) = tx.query_row(
            &format!(
                "SELECT (SELECT COUNT(*) FROM owed_acks_v1 WHERE {peer_col} = ?1),
                        (SELECT COUNT(*) FROM owed_acks_v1)"
            ),
            params![peer_key],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        if per_peer >= MAX_OWED_PER_PEER || total >= MAX_OWED_TOTAL {
            return Err(OwedError::Full);
        }
        match sealed {
            None => tx.execute(
                "INSERT INTO owed_acks_v1
                   (ack_digest, peer, session_id, bytes, expires_at_ms, origin, recorded_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    ack_digest.as_slice(),
                    peer.as_slice(),
                    session_id.map(|s| s.to_vec()),
                    bytes,
                    ms(expires_at_ms),
                    origin as u8,
                    ms(now_ms),
                ],
            )?,
            Some((meta, sealed_bytes)) => tx.execute(
                "INSERT INTO owed_acks_v1
                   (kh_ack_digest, kh_peer, session_id, bytes, meta, prune_after_hour)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    digest_key,
                    peer_key,
                    session_id.map(|s| s.to_vec()),
                    sealed_bytes,
                    meta,
                    rebuild::prune_after_hour(expires_at_ms),
                ],
            )?,
        };
        tx.commit()?;
        Ok(())
    }

    /// Every live owed ACK (expired ones are deleted first: the owed-ACK
    /// prune, which ends with a checkpoint).
    pub fn list(&mut self, now_ms: u64) -> Result<Vec<OwedAck>, OwedError> {
        if self.keyed() {
            return self.list_keyed(now_ms);
        }
        self.conn.execute(
            "DELETE FROM owed_ack_held_v1 WHERE ack_digest IN
               (SELECT ack_digest FROM owed_acks_v1 WHERE expires_at_ms <= ?1)",
            params![ms(now_ms)],
        )?;
        self.conn.execute(
            "DELETE FROM owed_acks_v1 WHERE expires_at_ms <= ?1",
            params![ms(now_ms)],
        )?;
        // What this and earlier deletes overwrote reaches the main file and
        // the WAL is emptied (PP.2). Busy (a reader in the way) is left to
        // the next scan's prune; it never fails the listing.
        let _ = crate::paths::checkpoint_truncate(&self.conn);
        type Row = (Vec<u8>, Vec<u8>, Option<Vec<u8>>, Vec<u8>, i64, i64);
        let rows: Vec<Row> = {
            let mut stmt = self.conn.prepare(
                "SELECT ack_digest, peer, session_id, bytes, expires_at_ms, origin
                 FROM owed_acks_v1 ORDER BY recorded_at_ms, ack_digest",
            )?;
            let mapped = stmt.query_map([], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                ))
            })?;
            mapped.collect::<Result<_, _>>()?
        };
        let mut out = Vec::with_capacity(rows.len());
        for (digest, peer, sid, bytes, expires, origin) in rows {
            let ack_digest = arr32(&digest)?;
            let held_by: Vec<[u8; 32]> = {
                let mut stmt = self
                    .conn
                    .prepare("SELECT custodian FROM owed_ack_held_v1 WHERE ack_digest = ?1")?;
                let mapped = stmt.query_map(params![digest], |r| r.get::<_, Vec<u8>>(0))?;
                let raw: Vec<Vec<u8>> = mapped.collect::<Result<_, _>>()?;
                raw.iter().map(|c| arr32(c)).collect::<Result<_, _>>()?
            };
            out.push(OwedAck {
                ack_digest,
                peer: arr32(&peer)?,
                session_id: sid.as_deref().map(arr32).transpose()?,
                bytes,
                expires_at_ms: u64::try_from(expires).unwrap_or(0),
                origin: Origin::from_i64(origin),
                held_by,
            });
        }
        Ok(out)
    }

    /// [`Self::list`] of a schema-2 store: the prune deletes by the coarse
    /// hour, then every row's exact expiry from its `meta` decides; same
    /// order (recorded, digest).
    fn list_keyed(&mut self, now_ms: u64) -> Result<Vec<OwedAck>, OwedError> {
        match self.list_keyed_with(now_ms) {
            // A row names an epoch these keys lack (a rotation since the
            // open): once more with the keys this process holds now.
            Err(OwedError::KeyUnavailable(_)) => {
                self.keys = Some(cached_keys(&self.data_dir)?);
                self.list_keyed_with(now_ms)
            }
            listed => listed,
        }
    }

    fn list_keyed_with(&mut self, now_ms: u64) -> Result<Vec<OwedAck>, OwedError> {
        let keys = self.keys()?;
        let hour = rebuild::hour_of(now_ms);
        self.conn.execute(
            "DELETE FROM owed_ack_held_v1 WHERE kh_ack_digest IN
               (SELECT kh_ack_digest FROM owed_acks_v1 WHERE prune_after_hour <= ?1)",
            params![hour],
        )?;
        self.conn.execute(
            "DELETE FROM owed_acks_v1 WHERE prune_after_hour <= ?1",
            params![hour],
        )?;
        type Row = (Vec<u8>, Option<Vec<u8>>, Vec<u8>, Vec<u8>);
        let rows: Vec<Row> = {
            let mut stmt = self
                .conn
                .prepare("SELECT kh_ack_digest, session_id, bytes, meta FROM owed_acks_v1")?;
            let mapped =
                stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?;
            mapped.collect::<Result<_, _>>()?
        };
        let mut live = Vec::with_capacity(rows.len());
        let mut expired = Vec::new();
        for (kd, sid, bytes, meta) in rows {
            let ack = open_ack(&keys, &kd, sid, &meta, &bytes)?;
            if ack.expires_at_ms <= now_ms {
                expired.push(kd);
            } else {
                live.push((kd, ack));
            }
        }
        if !expired.is_empty() {
            let tx = self
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let _in_tx = crate::paths::HeldMark::transaction();
            for kd in &expired {
                tx.execute(
                    "DELETE FROM owed_ack_held_v1 WHERE kh_ack_digest = ?1",
                    params![kd],
                )?;
                tx.execute(
                    "DELETE FROM owed_acks_v1 WHERE kh_ack_digest = ?1",
                    params![kd],
                )?;
            }
            tx.commit()?;
        }
        // As the clear listing: what the deletes overwrote reaches the main
        // file; busy is left to the next scan's prune.
        let _ = crate::paths::checkpoint_truncate(&self.conn);
        live.sort_by(|(_, a), (_, b)| {
            (a.recorded_at_ms, &a.ack_digest).cmp(&(b.recorded_at_ms, &b.ack_digest))
        });
        let mut out = Vec::with_capacity(live.len());
        for (kd, ack) in live {
            let mut held_by: Vec<[u8; 32]> = {
                let mut stmt = self.conn.prepare(
                    "SELECT kh_custodian, meta FROM owed_ack_held_v1 WHERE kh_ack_digest = ?1",
                )?;
                let mapped = stmt.query_map(params![kd], |r| {
                    Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?))
                })?;
                let raw: Vec<(Vec<u8>, Vec<u8>)> = mapped.collect::<Result<_, _>>()?;
                raw.iter()
                    .map(|(kc, meta)| open_held(&keys, &kd, kc, meta))
                    .collect::<Result<_, _>>()?
            };
            held_by.sort();
            out.push(OwedAck {
                ack_digest: arr32(&ack.ack_digest)?,
                peer: arr32(&ack.peer)?,
                session_id: ack.session_id.as_deref().map(arr32).transpose()?,
                bytes: ack.bytes,
                expires_at_ms: ack.expires_at_ms,
                origin: Origin::from_i64(ack.origin),
                held_by,
            });
        }
        Ok(out)
    }

    /// Written directly, expired, or owed to a non-contact: forget them.
    pub fn clear(&mut self, digests: &[[u8; 32]]) -> Result<usize, OwedError> {
        let (digest_col, _, _) = self.cols();
        let keys = self.layout_keys()?;
        let keys: Vec<Vec<u8>> = digests
            .iter()
            .map(|d| digest_value(keys.as_deref(), d))
            .collect();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let _in_tx = crate::paths::HeldMark::transaction();
        let mut n = 0;
        for d in &keys {
            tx.execute(
                &format!("DELETE FROM owed_ack_held_v1 WHERE {digest_col} = ?1"),
                params![d],
            )?;
            n += tx.execute(
                &format!("DELETE FROM owed_acks_v1 WHERE {digest_col} = ?1"),
                params![d],
            )?;
        }
        tx.commit()?;
        Ok(n)
    }

    /// `custodian` now holds a copy of `digest`.
    pub fn add_held(&mut self, digest: &[u8; 32], custodian: &[u8; 32]) -> Result<(), OwedError> {
        // Only for an ACK this table owes: no orphan held rows.
        if !self.keyed() {
            self.conn.execute(
                "INSERT OR IGNORE INTO owed_ack_held_v1 (ack_digest, custodian)
                 SELECT ?1, ?2 WHERE EXISTS (SELECT 1 FROM owed_acks_v1 WHERE ack_digest = ?1)",
                params![digest.as_slice(), custodian.as_slice()],
            )?;
            return Ok(());
        }
        let keys = self.keys()?;
        let (kd, kc) = (kh_digest(&keys, digest), kh_device(&keys, custodian));
        self.conn.execute(
            "INSERT OR IGNORE INTO owed_ack_held_v1 (kh_ack_digest, kh_custodian, meta)
             SELECT ?1, ?2, ?3 WHERE EXISTS (SELECT 1 FROM owed_acks_v1 WHERE kh_ack_digest = ?1)",
            params![
                kd.as_slice(),
                kc.as_slice(),
                seal_held(&keys, &kd, &kc, custodian)
            ],
        )?;
        Ok(())
    }

    /// The contact was removed or blocked.
    pub fn drop_peer(&mut self, peer: &[u8; 32]) -> Result<usize, OwedError> {
        let (digest_col, peer_col, _) = self.cols();
        let peer_key = device_value(self.layout_keys()?.as_deref(), peer);
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let _in_tx = crate::paths::HeldMark::transaction();
        tx.execute(
            &format!(
                "DELETE FROM owed_ack_held_v1 WHERE {digest_col} IN
                   (SELECT {digest_col} FROM owed_acks_v1 WHERE {peer_col} = ?1)"
            ),
            params![peer_key],
        )?;
        let n = tx.execute(
            &format!("DELETE FROM owed_acks_v1 WHERE {peer_col} = ?1"),
            params![peer_key],
        )?;
        tx.commit()?;
        Ok(n)
    }

    /// (rows, fraction of the total capacity in use).
    pub fn fill(&self) -> Result<(i64, f64), OwedError> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM owed_acks_v1", [], |r| r.get(0))?;
        Ok((n, n as f64 / MAX_OWED_TOTAL as f64))
    }
}

/// [`OwedAcks::open`]'s set-aside: the unusable store's bytes go to `aside`
/// (synced), its -wal and -shm are deleted, and the file itself is emptied
/// for the fresh store, which so keeps its inode. Renaming it aside instead
/// put a new file at `owed_acks.sqlite` whose -wal and -shm another opener's
/// connection to the old file (opened just before, read just after) shared
/// by name, while SQLite, which keeps its locks per file, told them apart:
/// that first read reset or deleted them under the new store ("disk I/O
/// error", "locking protocol", or a process with the -shm mapped stopped).
/// (On Windows the rename also failed, a sharing violation, while another
/// process had the file open.)
fn set_aside_in_place(path: &Path, aside: &Path) -> std::io::Result<()> {
    std::fs::copy(path, aside)?;
    // Write access: Windows syncs no file opened only to read.
    std::fs::OpenOptions::new()
        .write(true)
        .open(aside)?
        .sync_all()?;
    for side in ["-wal", "-shm"] {
        let mut p = path.as_os_str().to_owned();
        p.push(side);
        let _ = std::fs::remove_file(PathBuf::from(p));
    }
    let file = std::fs::OpenOptions::new().write(true).open(path)?;
    file.set_len(0)?;
    file.sync_all()?;
    crate::paths::sync_dir_best_effort(path.parent().unwrap_or(Path::new(".")));
    Ok(())
}

/// A schema-2 store created in one IMMEDIATE transaction (a sealed profile's
/// first store). A racing creator's store is kept as it is.
fn create_keyed(conn: &mut Connection) -> Result<(), OwedError> {
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let _in_tx = crate::paths::HeldMark::transaction();
    if rebuild::shape(&tx, ACKS, KEYED_COLUMN)? == Shape::Missing {
        tx.execute_batch(&acks_table(ACKS, true))?;
        tx.execute_batch(peer_index(true))?;
        tx.execute_batch(&held_table(HELD, true))?;
        rebuild::record(&tx, STORE, SCHEMA_VERSION, false)?;
    }
    tx.commit()?;
    Ok(())
}

// ── Migration (privacy pack PP.12) ───────────────────────────────────────

/// Schema 1 -> 2 with the rebuild recipe ([`crate::sqlite_rebuild`]): both
/// tables rebuilt in one IMMEDIATE transaction, rowids kept, counts checked
/// before the commit, then the scrub.
fn migrate_forward(
    path: &Path,
    keys: &MetaKeys,
    free: rebuild::FreeBytes<'_>,
) -> Result<Migration, RebuildError> {
    rebuild::space_ok(path, free).map_err(|needed| RebuildError::NoSpace { needed })?;
    let mut steps = Steps::default();
    let mut conn = rebuild::dedicated(path)?;
    rebuild::arm_disk_full(&conn)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let _in_tx = crate::paths::HeldMark::transaction();
    // Again inside the transaction: another process may have migrated.
    if rebuild::shape(&tx, ACKS, KEYED_COLUMN)? != Shape::Clear {
        return Ok(Migration::already());
    }
    let before = [
        (ACKS, rebuild::count(&tx, ACKS)?),
        (HELD, rebuild::count(&tx, HELD)?),
    ];
    let rows = forward_tables(&tx, keys, &mut steps)?;
    steps.step()?;
    rebuild::verify(&tx, &before)?;
    rebuild::record(&tx, STORE, SCHEMA_VERSION, true)?;
    steps.step()?;
    tx.commit()?;
    steps.step()?;
    let scrubbed = rebuild::scrub(&conn, STORE, free)?;
    Ok(Migration {
        rows,
        scrub_pending: !scrubbed.complete,
        ..Migration::default()
    })
}

/// Schema 1 -> 2's tables inside the caller's transaction (the migration,
/// and the second half of a re-key): both rebuilt keyed, rowids kept. The
/// rows moved.
fn forward_tables(
    tx: &rusqlite::Transaction<'_>,
    keys: &MetaKeys,
    steps: &mut Steps,
) -> Result<u32, RebuildError> {
    let mut rows = 0u32;
    steps.step()?;
    tx.execute_batch(&acks_table("owed_acks_v1__new", true))?;
    type Row = (
        i64,
        Vec<u8>,
        Vec<u8>,
        Option<Vec<u8>>,
        Vec<u8>,
        i64,
        i64,
        i64,
    );
    let acks: Vec<Row> = {
        let mut stmt = tx.prepare(
            "SELECT rowid, ack_digest, peer, session_id, bytes, expires_at_ms, origin,
                    recorded_at_ms FROM owed_acks_v1",
        )?;
        let mapped = stmt.query_map([], |r| {
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
        })?;
        mapped.collect::<Result<_, _>>()?
    };
    let leave_one_out = rebuild::drop_one_row();
    for (n, (rowid, digest, peer, sid, bytes, expires, origin, recorded)) in
        acks.into_iter().enumerate()
    {
        if leave_one_out && n == 0 {
            continue;
        }
        steps.step()?;
        let kd = kh_digest(keys, &digest);
        let kp = kh_device(keys, &peer);
        let expires_at_ms = u64::try_from(expires).unwrap_or(0);
        let (meta, sealed) = seal_ack(
            keys,
            &kd,
            &Clear {
                ack_digest: digest,
                peer,
                session_id: None,
                bytes,
                expires_at_ms,
                origin,
                recorded_at_ms: u64::try_from(recorded).unwrap_or(0),
            },
        );
        tx.execute(
            "INSERT INTO owed_acks_v1__new
               (rowid, kh_ack_digest, kh_peer, session_id, bytes, meta, prune_after_hour)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                rowid,
                kd.as_slice(),
                kp.as_slice(),
                sid,
                sealed,
                meta,
                rebuild::prune_after_hour(expires_at_ms),
            ],
        )?;
        rows += 1;
    }
    steps.step()?;
    tx.execute_batch("DROP TABLE owed_acks_v1;")?;
    steps.step()?;
    tx.execute_batch("ALTER TABLE owed_acks_v1__new RENAME TO owed_acks_v1;")?;
    steps.step()?;
    tx.execute_batch(peer_index(true))?;
    steps.step()?;
    tx.execute_batch(&held_table("owed_ack_held_v1__new", true))?;
    let held: Vec<(i64, Vec<u8>, Vec<u8>)> = {
        let mut stmt = tx.prepare("SELECT rowid, ack_digest, custodian FROM owed_ack_held_v1")?;
        let mapped = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        mapped.collect::<Result<_, _>>()?
    };
    for (rowid, digest, custodian) in held {
        steps.step()?;
        let (kd, kc) = (kh_digest(keys, &digest), kh_device(keys, &custodian));
        tx.execute(
            "INSERT INTO owed_ack_held_v1__new (rowid, kh_ack_digest, kh_custodian, meta)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                rowid,
                kd.as_slice(),
                kc.as_slice(),
                seal_held(keys, &kd, &kc, &custodian)
            ],
        )?;
        rows += 1;
    }
    steps.step()?;
    tx.execute_batch("DROP TABLE owed_ack_held_v1;")?;
    steps.step()?;
    tx.execute_batch("ALTER TABLE owed_ack_held_v1__new RENAME TO owed_ack_held_v1;")?;
    Ok(rows)
}

/// Schema 2 -> 1 (`raven privacy unseal`, PP.18): the same recipe; rows
/// whose sealed values do not open with the keys loaded here are left out
/// and counted (`dropped`), and the count check expects exactly that.
fn migrate_back(
    path: &Path,
    keys: &MetaKeys,
    free: rebuild::FreeBytes<'_>,
) -> Result<Migration, RebuildError> {
    rebuild::space_ok(path, free).map_err(|needed| RebuildError::NoSpace { needed })?;
    let mut steps = Steps::default();
    let mut conn = rebuild::dedicated(path)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let _in_tx = crate::paths::HeldMark::transaction();
    if rebuild::shape(&tx, ACKS, KEYED_COLUMN)? != Shape::Keyed {
        return Ok(Migration::already());
    }
    let mut report = Migration::default();
    let expected = back_tables(&tx, keys, &mut steps, &mut report)?;
    steps.step()?;
    rebuild::verify(&tx, &expected)?;
    rebuild::record(&tx, STORE, CLEAR_VERSION, true)?;
    steps.step()?;
    tx.commit()?;
    let scrubbed = rebuild::scrub(&conn, STORE, free)?;
    report.scrub_pending = !scrubbed.complete;
    Ok(report)
}

/// Schema 2 -> 1's tables inside the caller's transaction (the way back,
/// and the first half of a re-key): rows whose sealed values do not open
/// with `keys` are left out and counted in `report`. What each table must
/// hold afterwards.
fn back_tables(
    tx: &rusqlite::Transaction<'_>,
    keys: &MetaKeys,
    steps: &mut Steps,
    report: &mut Migration,
) -> Result<[(&'static str, i64); 2], RebuildError> {
    let (acks_before, held_before) = (rebuild::count(tx, ACKS)?, rebuild::count(tx, HELD)?);
    steps.step()?;
    tx.execute_batch(&acks_table("owed_acks_v1__new", false))?;
    type Row = (i64, Vec<u8>, Option<Vec<u8>>, Vec<u8>, Vec<u8>);
    let acks: Vec<Row> = {
        let mut stmt =
            tx.prepare("SELECT rowid, kh_ack_digest, session_id, bytes, meta FROM owed_acks_v1")?;
        let mapped = stmt.query_map([], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })?;
        mapped.collect::<Result<_, _>>()?
    };
    let mut digests = std::collections::HashMap::new();
    let mut dropped_acks = 0i64;
    for (rowid, kd, sid, bytes, meta) in acks {
        steps.step()?;
        let Ok(ack) = open_ack(keys, &kd, sid, &meta, &bytes) else {
            dropped_acks += 1;
            continue;
        };
        tx.execute(
            "INSERT INTO owed_acks_v1__new
               (rowid, ack_digest, peer, session_id, bytes, expires_at_ms, origin, recorded_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                rowid,
                ack.ack_digest,
                ack.peer,
                ack.session_id,
                ack.bytes,
                ms(ack.expires_at_ms),
                ack.origin,
                ms(ack.recorded_at_ms),
            ],
        )?;
        digests.insert(kd, ack.ack_digest.clone());
        report.rows += 1;
    }
    steps.step()?;
    tx.execute_batch("DROP TABLE owed_acks_v1;")?;
    steps.step()?;
    tx.execute_batch("ALTER TABLE owed_acks_v1__new RENAME TO owed_acks_v1;")?;
    steps.step()?;
    tx.execute_batch(peer_index(false))?;
    steps.step()?;
    tx.execute_batch(&held_table("owed_ack_held_v1__new", false))?;
    type Held = (i64, Vec<u8>, Vec<u8>, Vec<u8>);
    let held: Vec<Held> = {
        let mut stmt =
            tx.prepare("SELECT rowid, kh_ack_digest, kh_custodian, meta FROM owed_ack_held_v1")?;
        let mapped = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?;
        mapped.collect::<Result<_, _>>()?
    };
    let mut dropped_held = 0i64;
    for (rowid, kd, kc, meta) in held {
        steps.step()?;
        // A held row whose ACK row is gone (or did not open) cannot name its
        // ACK in clear.
        let (Some(digest), Ok(custodian)) = (digests.get(&kd), open_held(keys, &kd, &kc, &meta))
        else {
            dropped_held += 1;
            continue;
        };
        tx.execute(
            "INSERT INTO owed_ack_held_v1__new (rowid, ack_digest, custodian) VALUES (?1, ?2, ?3)",
            params![rowid, digest.as_slice(), custodian.as_slice()],
        )?;
        report.rows += 1;
    }
    steps.step()?;
    tx.execute_batch("DROP TABLE owed_ack_held_v1;")?;
    steps.step()?;
    tx.execute_batch("ALTER TABLE owed_ack_held_v1__new RENAME TO owed_ack_held_v1;")?;
    report.dropped = u32::try_from(dropped_acks + dropped_held).unwrap_or(u32::MAX);
    Ok([
        (ACKS, acks_before - dropped_acks),
        (HELD, held_before - dropped_held),
    ])
}

/// Privacy pack PP.12, the eager half of the migration
/// (`privacy::migrate_all`, and the prune passes): in a sealed profile with
/// its keys loaded, an existing clear store moves to schema 2 (and what an
/// older build set aside is merged back). `true` when it moved now. A store
/// that cannot be opened is left as it is (never set aside here: the next
/// real open decides).
pub fn migrate(data_dir: &Path) -> Result<bool, OwedError> {
    let path = owed_acks_path(data_dir);
    // Schema 2 by its header: nothing to open (an older process's stamp still
    // in the WAL is put right by the next open).
    if !needs_migration(data_dir) || crate::privacy::mode(data_dir) != Mode::Sealed {
        return Ok(false);
    }
    let (_, migrated) = OwedAcks::open_at(data_dir, &path)?;
    Ok(migrated)
}

/// Whether the store's header says it is still clear (no SQLite open; a
/// commit still in the WAL is not seen, so `true` may only mean "look").
pub fn needs_migration(data_dir: &Path) -> bool {
    let path = owed_acks_path(data_dir);
    path.exists() && rebuild::header_user_version(&path).is_none_or(|v| v < SCHEMA_VERSION)
}

/// The way back (`raven privacy unseal`, PP.18): a schema-2 store moves to
/// schema 1 with the keys this process loaded. Nothing to do without a
/// store or on a clear one.
pub fn unseal(data_dir: &Path) -> Result<Migration, OwedError> {
    let path = owed_acks_path(data_dir);
    if !path.exists() {
        return Ok(Migration::already());
    }
    let keys = cached_keys(data_dir)?;
    Ok(migrate_back(&path, &keys, &crate::disk_space::free_bytes)?)
}

/// Schema 2 -> 2 under new keys (`raven privacy rotate-meta`, PP.18): in
/// one IMMEDIATE transaction on a connection that writes nothing before
/// the commit ([`rebuild::rekey_connection`]), both tables go back to their
/// clear columns and forward again, so every keyed value is computed anew
/// and every sealed value sealed under the current epoch; counts checked,
/// then the scrub. `keys` open every epoch the rows are under.
fn rekey_store(
    path: &Path,
    keys: &MetaKeys,
    free: rebuild::FreeBytes<'_>,
) -> Result<Migration, RebuildError> {
    rebuild::space_ok(path, free).map_err(|needed| RebuildError::NoSpace { needed })?;
    let mut steps = Steps::default();
    let mut conn = rebuild::rekey_connection(path)?;
    rebuild::arm_disk_full(&conn)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let _in_tx = crate::paths::HeldMark::transaction();
    if rebuild::shape(&tx, ACKS, KEYED_COLUMN)? != Shape::Keyed {
        return Ok(Migration::already());
    }
    let mut report = Migration::default();
    let expected = back_tables(&tx, keys, &mut steps, &mut report)?;
    report.rows = forward_tables(&tx, keys, &mut steps)?;
    rebuild::verify(&tx, &expected)?;
    rebuild::record(&tx, STORE, SCHEMA_VERSION, true)?;
    tx.commit()?;
    let scrubbed = rebuild::scrub(&conn, STORE, free)?;
    report.scrub_pending = !scrubbed.complete;
    Ok(report)
}

/// `raven privacy rotate-meta` (PP.18): a schema-2 store is keyed again
/// with the keys this process holds now (a new `k_index`; the epochs it
/// holds open the old rows). Nothing to do without a store or on a clear
/// one. Rows that do not open are left out and counted (`dropped`).
pub fn rekey(data_dir: &Path) -> Result<Migration, OwedError> {
    let path = owed_acks_path(data_dir);
    if !path.exists() {
        return Ok(Migration::already());
    }
    let keys = cached_keys(data_dir)?;
    Ok(rekey_store(&path, &keys, &crate::disk_space::free_bytes)?)
}

/// A pending scrub (a `VACUUM` or checkpoint a reader held up) is done now:
/// the prune passes. `None` when nothing was pending.
pub fn finish_scrub(data_dir: &Path) -> Option<bool> {
    rebuild::finish_scrub(
        &owed_acks_path(data_dir),
        STORE,
        &crate::disk_space::free_bytes,
    )
    .ok()
    .flatten()
}

/// Whether a scrub of the store is pending (`raven privacy status`).
pub fn scrub_pending(data_dir: &Path) -> bool {
    rebuild::scrub_pending(&owed_acks_path(data_dir), STORE)
}

// ── Set-aside stores (review R06) ────────────────────────────────────────

/// What [`merge_set_asides`] did (counts only).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AsideMerge {
    /// Set-aside stores merged back and deleted.
    pub merged: u32,
    /// Rows they brought back (live, not already present, within the caps).
    pub rows: u32,
    /// Set-aside files that did not open as this profile's schema 2,
    /// sealed where they are (`raven privacy status` lists them).
    pub sealed: u32,
}

/// The set-aside stores in `data_dir` (`owed_acks.sqlite.corrupt-<ms>`; not
/// their SQLite sidecars), sealed or not, by name.
fn set_asides(data_dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(data_dir) else {
        return Vec::new();
    };
    let mut found: Vec<PathBuf> = entries
        .flatten()
        .filter(|entry| entry.file_type().is_ok_and(|t| t.is_file()))
        .filter(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            name.starts_with(SET_ASIDE_PREFIX)
                && !["-wal", "-shm", "-journal"]
                    .iter()
                    .any(|side| name.ends_with(side))
        })
        .map(|entry| entry.path())
        .collect();
    found.sort();
    found
}

fn is_sealed_file(path: &Path) -> bool {
    use std::io::Read;
    let mut head = [0u8; 4];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut head))
        .is_ok()
        && at_rest::is_sealed(&head)
}

fn remove_sidecars(path: &Path) {
    for side in ["-wal", "-shm", "-journal"] {
        let mut p = path.as_os_str().to_os_string();
        p.push(side);
        let _ = std::fs::remove_file(PathBuf::from(p));
    }
}

/// How many set-aside stores are kept sealed for inspection (`raven privacy
/// status`): one small read each.
pub fn sealed_set_asides(data_dir: &Path) -> u16 {
    let n = set_asides(data_dir)
        .iter()
        .filter(|path| is_sealed_file(path))
        .count();
    u16::try_from(n).unwrap_or(u16::MAX)
}

/// Review R06: an older build that met schema 2 renamed the store
/// `owed_acks.sqlite.corrupt-<ms>` and rebuilt an empty clear one. In a
/// sealed profile with its keys loaded, under `.owed_acks_aside.lock.sqlite`:
/// every set-aside that opens as this profile's schema 2 (each row's sealed
/// values open here) gives its live rows that are not already present back
/// to the store (within the caps), then it is deleted; one that does not
/// (another file, a damaged one, an older build's own clear set-aside) is
/// sealed in place (RMS1, kind [`Kind::OwedAcksAside`]) and kept.
pub fn merge_set_asides(data_dir: &Path) -> Result<AsideMerge, OwedError> {
    let mut report = AsideMerge::default();
    if crate::privacy::mode(data_dir) != Mode::Sealed {
        return Ok(report);
    }
    if !set_asides(data_dir)
        .iter()
        .any(|path| !is_sealed_file(path))
    {
        return Ok(report);
    }
    let keys = cached_keys(data_dir)?;
    let _lock = crate::paths::DataDirLock::acquire(data_dir, OWED_ACKS_ASIDE_LOCK)
        .map_err(OwedError::Store)?;
    let (mut store, _) = OwedAcks::open_at(data_dir, &owed_acks_path(data_dir))?;
    if !store.keyed() {
        // Not migrated yet (free space): the merge waits for it.
        return Ok(report);
    }
    let now = crate::clock::now_ms();
    for aside in set_asides(data_dir) {
        if is_sealed_file(&aside) {
            continue;
        }
        match merge_one(&mut store, &keys, &aside, now) {
            Ok(Some(rows)) => {
                std::fs::remove_file(&aside).map_err(|e| OwedError::Store(e.to_string()))?;
                remove_sidecars(&aside);
                report.merged += 1;
                report.rows += rows;
            }
            // Busy or locked: tried again by the next pass.
            Err(OwedError::Store(e)) if e.contains("locked") || e.contains("busy") => {}
            Ok(None) | Err(_) => {
                remove_sidecars(&aside);
                at_rest::migrate_file_held(data_dir, &aside, Kind::OwedAcksAside)
                    .map_err(|e| OwedError::Store(e.to_string()))?;
                report.sealed += 1;
            }
        }
    }
    Ok(report)
}

/// One set-aside into `store`: `None` when it is not this profile's
/// schema 2 (every row of it must open here), else the rows inserted.
fn merge_one(
    store: &mut OwedAcks,
    keys: &MetaKeys,
    aside: &Path,
    now_ms: u64,
) -> Result<Option<u32>, OwedError> {
    type AckRow = (Vec<u8>, Vec<u8>, Option<Vec<u8>>, Vec<u8>, Vec<u8>, i64);
    type HeldRow = (Vec<u8>, Vec<u8>, Vec<u8>);
    let (acks, held): (Vec<AckRow>, Vec<HeldRow>) = {
        let conn = Connection::open_with_flags(aside, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        conn.busy_timeout(std::time::Duration::from_secs(2))?;
        let Ok(ok) = conn.query_row("PRAGMA quick_check", [], |r| r.get::<_, String>(0)) else {
            return Ok(None);
        };
        if ok != "ok" || rebuild::shape(&conn, ACKS, KEYED_COLUMN)? != Shape::Keyed {
            return Ok(None);
        }
        let acks = {
            let mut stmt = conn.prepare(
                "SELECT kh_ack_digest, kh_peer, session_id, bytes, meta, prune_after_hour
                 FROM owed_acks_v1",
            )?;
            let mapped = stmt.query_map([], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                ))
            })?;
            mapped.collect::<Result<_, _>>()?
        };
        let held = {
            let mut stmt =
                conn.prepare("SELECT kh_ack_digest, kh_custodian, meta FROM owed_ack_held_v1")?;
            let mapped = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
            mapped.collect::<Result<_, _>>()?
        };
        (acks, held)
    };
    let mut opened = Vec::with_capacity(acks.len());
    for (kd, kp, sid, bytes, meta, hour) in acks {
        let Ok(ack) = open_ack(keys, &kd, sid.clone(), &meta, &bytes) else {
            return Ok(None);
        };
        opened.push((kd, kp, sid, bytes, meta, hour, ack));
    }
    for (kd, kc, meta) in &held {
        if open_held(keys, kd, kc, meta).is_err() {
            return Ok(None);
        }
    }
    opened.sort_by(|a, b| {
        (a.6.recorded_at_ms, &a.6.ack_digest).cmp(&(b.6.recorded_at_ms, &b.6.ack_digest))
    });
    let tx = store
        .conn
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let _in_tx = crate::paths::HeldMark::transaction();
    let mut inserted = 0u32;
    let hour_now = rebuild::hour_of(now_ms);
    for (kd, kp, sid, bytes, meta, hour, ack) in opened {
        if hour <= hour_now || ack.expires_at_ms <= now_ms {
            continue;
        }
        let (per_peer, total): (i64, i64) = tx.query_row(
            "SELECT (SELECT COUNT(*) FROM owed_acks_v1 WHERE kh_peer = ?1),
                    (SELECT COUNT(*) FROM owed_acks_v1)",
            params![kp],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        if per_peer >= MAX_OWED_PER_PEER || total >= MAX_OWED_TOTAL {
            continue;
        }
        // Bound to the row's table and key, not to the file: copied as it is.
        inserted += u32::try_from(tx.execute(
            "INSERT OR IGNORE INTO owed_acks_v1
               (kh_ack_digest, kh_peer, session_id, bytes, meta, prune_after_hour)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![kd, kp, sid, bytes, meta, hour],
        )?)
        .unwrap_or(0);
    }
    for (kd, kc, meta) in held {
        tx.execute(
            "INSERT OR IGNORE INTO owed_ack_held_v1 (kh_ack_digest, kh_custodian, meta)
             SELECT ?1, ?2, ?3 WHERE EXISTS (SELECT 1 FROM owed_acks_v1 WHERE kh_ack_digest = ?1)",
            params![kd, kc, meta],
        )?;
    }
    tx.commit()?;
    Ok(Some(inserted))
}

// ── Data-key rotation (PP.10 hand-off) ───────────────────────────────────

/// Rows whose sealed values are not on epoch `current` (both tables, by
/// their first bytes; no key, no lock): the rotation's old-object count.
/// `0` without a schema-2 store.
pub fn rows_off_epoch(data_dir: &Path, current: u32) -> Result<u32, OwedError> {
    let path = owed_acks_path(data_dir);
    if !path.exists() {
        return Ok(0);
    }
    let conn = Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    conn.busy_timeout(std::time::Duration::from_secs(2))?;
    if rebuild::shape(&conn, ACKS, KEYED_COLUMN)? != Shape::Keyed {
        return Ok(0);
    }
    let n: i64 = conn.query_row(
        "SELECT (SELECT COUNT(*) FROM owed_acks_v1
                 WHERE substr(meta, 2, 4) != ?1 OR substr(bytes, 2, 4) != ?1)
              + (SELECT COUNT(*) FROM owed_ack_held_v1 WHERE substr(meta, 2, 4) != ?1)",
        params![current.to_be_bytes().to_vec()],
        |r| r.get(0),
    )?;
    Ok(u32::try_from(n).unwrap_or(u32::MAX))
}

/// A data-key rotation's step for this store (PP.10): in one IMMEDIATE
/// transaction every sealed value not on the current epoch is opened and
/// sealed again under it, then the WAL is checkpointed. A sealed profile
/// with its keys loaded; nothing to do without a schema-2 store. Values that
/// do not open are left as they are (`unreadable`).
pub fn reseal_rows(data_dir: &Path) -> Result<RowReseal, OwedError> {
    let mut report = RowReseal::default();
    let path = owed_acks_path(data_dir);
    if !path.exists() || crate::privacy::mode(data_dir) != Mode::Sealed {
        return Ok(report);
    }
    let keys = cached_keys(data_dir)?;
    let current = keys.current_epoch();
    if rows_off_epoch(data_dir, current)? == 0 {
        return Ok(report);
    }
    let (mut store, _) = OwedAcks::open_at(data_dir, &path)?;
    if !store.keyed() {
        return Ok(report);
    }
    let epoch = current.to_be_bytes().to_vec();
    let tx = store
        .conn
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let _in_tx = crate::paths::HeldMark::transaction();
    let acks: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = {
        let mut stmt = tx.prepare(
            "SELECT kh_ack_digest, bytes, meta FROM owed_acks_v1
             WHERE substr(meta, 2, 4) != ?1 OR substr(bytes, 2, 4) != ?1",
        )?;
        let mapped = stmt.query_map(params![epoch], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        mapped.collect::<Result<_, _>>()?
    };
    for (kd, bytes, meta) in acks {
        let (Ok(plain_meta), Ok(plain_bytes)) = (
            at_rest::open_row(&keys, ACKS, &kd, &meta),
            at_rest::open_row(&keys, BYTES_LABEL, &kd, &bytes),
        ) else {
            report.unreadable += 1;
            continue;
        };
        tx.execute(
            "UPDATE owed_acks_v1 SET bytes = ?2, meta = ?3 WHERE kh_ack_digest = ?1",
            params![
                kd,
                at_rest::seal_row(&keys, BYTES_LABEL, &kd, &plain_bytes),
                at_rest::seal_row(&keys, ACKS, &kd, &plain_meta)
            ],
        )?;
        report.resealed += 1;
    }
    let held: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = {
        let mut stmt = tx.prepare(
            "SELECT kh_ack_digest, kh_custodian, meta FROM owed_ack_held_v1
             WHERE substr(meta, 2, 4) != ?1",
        )?;
        let mapped = stmt.query_map(params![epoch], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        mapped.collect::<Result<_, _>>()?
    };
    for (kd, kc, meta) in held {
        let pk = held_pk(&kd, &kc);
        let Ok(plain) = at_rest::open_row(&keys, HELD, &pk, &meta) else {
            report.unreadable += 1;
            continue;
        };
        tx.execute(
            "UPDATE owed_ack_held_v1 SET meta = ?3 WHERE kh_ack_digest = ?1 AND kh_custodian = ?2",
            params![kd, kc, at_rest::seal_row(&keys, HELD, &pk, &plain)],
        )?;
        report.resealed += 1;
    }
    tx.commit()?;
    if report.resealed > 0 {
        report.scrub_pending = crate::paths::checkpoint_truncate(&store.conn)
            .map_or(true, |checkpoint| checkpoint.busy);
    }
    Ok(report)
}

/// A schema-1 store at `data_dir`, as an older build creates it (tests of
/// other modules).
#[cfg(test)]
pub(crate) fn create_clear_store_for_tests(data_dir: &Path) {
    Connection::open(owed_acks_path(data_dir))
        .unwrap()
        .execute_batch(CLEAR_SCHEMA)
        .unwrap();
}

#[cfg(test)]
mod tests;
