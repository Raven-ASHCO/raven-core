//! The security ledger: `<data_dir>/security_events.sqlite`
//! (`docs/roadmap/plans/phase6-design.json`, step P6.23; design A §3-§4,
//! owner decision OD6b-3).
//!
//! What a profile keeps of its security events across restarts: one count
//! per kind, subject and day, and one open alert per kind and subject (at
//! most [`MAX_OPEN_ALERTS`]). raven-node writes it from one writer thread
//! (step P6.24), ash through [`DirectSink`] (P6.25); the responses (P6.27,
//! P6.28) write the action they took into the alert ([`SecurityLedger::set_action`]).
//!
//! **What is kept.** No IP address, port, message id, network tag,
//! plaintext or stranger key, ever: a network-attributed event is stored
//! only as its kind's count for the day, with no subject. Subjects are
//! 32-byte contact, custodian, depositor, relay (`SHA-256("rvn1/sec/relay"
//! || PeerId bytes)`) or update-passer keys. Counts are by day, alert times
//! by hour. Counts and resolved alerts go after [`RETENTION_DAYS`]
//! ([`SecurityLedger::prune`]); open alerts stay until they are resolved.
//!
//! **At rest (docs/design/2026-10-at-rest-metadata.md section 7.7).** Born
//! keyed: a subject is stored as `kh_subject = at_rest::index(DeviceKey,
//! key)`, and the clear key only inside the row's sealed `meta`
//! (`at_rest::seal_row`). There is no clear shape: a profile that is not
//! sealed, or a process that has not loaded the at-rest key, has no ledger
//! (the open says why, [`LedgerError::is_skipped`]; the caller keeps its
//! events in memory). `raven privacy unseal` deletes the file ([`unseal`]),
//! `raven privacy rotate-meta` keys it again ([`rekey`]) and the data-key
//! rotation reseals its `meta` blobs ([`reseal_rows`]).
//!
//! **The file.** Created only while [`SecGate::Events`] is live, through the
//! private-file helpers (0600; an owner-only DACL on Windows),
//! `secure_delete=ON`, `PRAGMA user_version = 1`. A newer version is refused
//! and left as it is; a damaged file, or one keyed under another profile key,
//! is moved aside as `security_events.sqlite.corrupt` (the peer cache's
//! pattern) and a new one created.
//!
//! **Writes.** At most one write per kind and subject per
//! [`WRITE_INTERVAL_MS`]: events in between are counted in memory and go
//! with that pair's next write, which comes sooner when the severity rises
//! or the day changes. [`SecurityLedger::flush`] (and the drop) writes what
//! is left. Two processes write the file; a lost write loses a count, never
//! more.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use rusqlite::{params, Connection, ErrorCode, OptionalExtension, TransactionBehavior};

use crate::at_rest::{self, MetaKeys, Mode, ValueType};
use crate::security_events::{Attribution, CarrierRole, SecEvent, SecKind, SecSink, Severity};
use crate::security_gate::{self, SecGate};
use crate::sqlite_rebuild::{self as rebuild, Migration, RowReseal};

pub use crate::paths::SECURITY_LEDGER_FILE;

/// The only schema: keyed from the first version.
const SCHEMA_VERSION: i64 = 1;
const COUNTS: &str = "sec_counts";
const ALERTS: &str = "sec_alerts";
/// The keyed column both tables have (what tells this file's shape).
const KEYED_COLUMN: &str = "kh_subject";

/// At most one write per kind and subject this often (design A §3).
pub const WRITE_INTERVAL_MS: u64 = 60_000;
/// Counts and resolved alerts are kept this many days.
pub const RETENTION_DAYS: u64 = 30;
/// Open alerts kept at most; the oldest of the lowest severity goes first.
pub const MAX_OPEN_ALERTS: i64 = 256;
/// Kind and subject pairs the rate limiter remembers; past it, what is
/// pending is written and the memory starts over.
const MAX_PENDING: usize = 4_096;
/// raven-node's writer thread waits this long for the other process.
const BUSY_TIMEOUT: Duration = Duration::from_secs(2);
/// [`DirectSink`] (ash) waits no longer than this: best effort.
pub const DIRECT_BUSY_TIMEOUT: Duration = Duration::from_millis(250);
/// The longest fixed action code ([`SecurityLedger::set_action`]).
const ACTION_MAX_LEN: usize = 32;

const HOUR_MS: u64 = 60 * 60 * 1000;
const DAY_MS: u64 = 24 * HOUR_MS;

/// `sec_meta` keys.
const META_KEY_CHECK: &str = "key_check";
const META_LAST_PRUNE: &str = "last_prune_day";
const META_DROPPED: &str = "dropped";
/// The keyed digest of this value under the profile's lookup key tells a
/// ledger keyed under another key apart (it is never a device key).
const KEY_CHECK_VALUE: &[u8] = b"rvn1/security-ledger/key-check/v1";

/// The tables (design A §4, keyed): the subject is `kh_subject`, its clear
/// key in `meta`; both are NULL for a row about nobody (a network count, a
/// local event, an update nobody passed on). The unique indexes treat a NULL
/// subject as one value: one count per day, kind and subject, and one open
/// alert (state 0 or 1) per kind and subject.
const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS sec_counts (
  day        INTEGER NOT NULL,
  kind       INTEGER NOT NULL,
  kh_subject BLOB CHECK(kh_subject IS NULL OR length(kh_subject) = 32),
  n          INTEGER NOT NULL,
  meta       BLOB,
  CHECK((kh_subject IS NULL) = (meta IS NULL)));
CREATE UNIQUE INDEX IF NOT EXISTS sec_counts_key
  ON sec_counts(day, kind, ifnull(kh_subject, x''));
CREATE TABLE IF NOT EXISTS sec_alerts (
  id            INTEGER PRIMARY KEY,
  kind          INTEGER NOT NULL,
  kh_subject    BLOB CHECK(kh_subject IS NULL OR length(kh_subject) = 32),
  first_hour    INTEGER NOT NULL,
  last_hour     INTEGER NOT NULL,
  n             INTEGER NOT NULL,
  severity      INTEGER NOT NULL,
  state         INTEGER NOT NULL DEFAULT 0,
  action        TEXT,
  resolved_hour INTEGER,
  meta          BLOB,
  CHECK((kh_subject IS NULL) = (meta IS NULL)));
CREATE UNIQUE INDEX IF NOT EXISTS sec_alerts_open
  ON sec_alerts(kind, ifnull(kh_subject, x'')) WHERE state < 2;
CREATE INDEX IF NOT EXISTS sec_alerts_subject ON sec_alerts(kh_subject);
CREATE TABLE IF NOT EXISTS sec_meta (
  k TEXT PRIMARY KEY NOT NULL,
  v BLOB);
";

pub fn ledger_path(data_dir: &Path) -> PathBuf {
    data_dir.join(SECURITY_LEDGER_FILE)
}

/// Where a damaged ledger is moved aside (one copy; a newer one replaces it).
pub fn quarantine_path(data_dir: &Path) -> PathBuf {
    aside_of(&ledger_path(data_dir))
}

fn aside_of(path: &Path) -> PathBuf {
    let mut aside = path.as_os_str().to_os_string();
    aside.push(".corrupt");
    PathBuf::from(aside)
}

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut side = path.as_os_str().to_os_string();
    side.push(suffix);
    PathBuf::from(side)
}

// ── Errors and values ────────────────────────────────────────────────────

/// Why the ledger did not open or write.
#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    /// [`SecGate::Events`] is shut: no ledger, nothing written.
    #[error("security events are off in this build")]
    GateClosed,
    /// The profile is not sealed: it keeps no ledger (never a plain one).
    #[error("this profile is not encrypted, so it keeps no security ledger")]
    NotSealed,
    /// This process has not loaded the at-rest key (or it is gone).
    #[error("security ledger: the at-rest key is not available: {0}")]
    KeyUnavailable(String),
    /// A newer Raven wrote the ledger: left as it is.
    #[error("security ledger: a newer Raven wrote it (version {0}); left as it is")]
    Newer(i64),
    /// Still unreadable after it was moved aside and created again.
    #[error("security ledger: damaged")]
    Damaged,
    /// [`SecurityLedger::set_action`] takes fixed codes only.
    #[error("security ledger: {0:?} is not a fixed action code")]
    BadAction(&'static str),
    #[error("security ledger: {0}")]
    Store(String),
}

impl LedgerError {
    /// The ledger is not there for this process (gate shut, profile not
    /// sealed, key not loaded): the caller keeps its events in memory and
    /// does not count a failure.
    pub fn is_skipped(&self) -> bool {
        matches!(
            self,
            LedgerError::GateClosed | LedgerError::NotSealed | LedgerError::KeyUnavailable(_)
        )
    }
}

impl From<rusqlite::Error> for LedgerError {
    fn from(e: rusqlite::Error) -> Self {
        LedgerError::Store(e.to_string())
    }
}

fn text(e: impl std::fmt::Display) -> String {
    e.to_string()
}

/// One alert row's id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AlertId(pub i64);

/// Where an alert stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AlertState {
    New,
    /// The person saw it; a higher severity makes it new again.
    Seen,
    Resolved,
}

impl AlertState {
    fn code(self) -> i64 {
        match self {
            AlertState::New => 0,
            AlertState::Seen => 1,
            AlertState::Resolved => 2,
        }
    }

    fn from_code(code: i64) -> Option<Self> {
        match code {
            0 => Some(AlertState::New),
            1 => Some(AlertState::Seen),
            2 => Some(AlertState::Resolved),
            _ => None,
        }
    }
}

fn severity_code(s: Severity) -> i64 {
    match s {
        Severity::Notice => 0,
        Severity::Suspicious => 1,
        Severity::Alert => 2,
    }
}

fn severity_of(code: i64) -> Severity {
    match code {
        i64::MIN..=0 => Severity::Notice,
        1 => Severity::Suspicious,
        _ => Severity::Alert,
    }
}

/// Whom a stored row is about, as its sealed `meta` holds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LedgerSubject {
    /// A contact's device key.
    Contact([u8; 32]),
    /// A custodian, depositor or relay key.
    Carrier { key: [u8; 32], role: CarrierRole },
    /// The contact who passed a security update on (design D).
    PassedBy([u8; 32]),
}

/// `meta`'s plaintext: a role byte and the key.
const SUBJECT_LEN: usize = 33;

impl LedgerSubject {
    /// The subject of an event that may reach the ledger with one: never a
    /// network source.
    pub fn of(who: &Attribution) -> Option<Self> {
        match *who {
            Attribution::Network { .. } | Attribution::Local => None,
            Attribution::Contact { peer } => Some(LedgerSubject::Contact(peer)),
            Attribution::Carrier { carrier, role } => {
                Some(LedgerSubject::Carrier { key: carrier, role })
            }
            Attribution::Update { passed_by } => passed_by.map(LedgerSubject::PassedBy),
        }
    }

    pub fn key(&self) -> &[u8; 32] {
        match self {
            LedgerSubject::Contact(key)
            | LedgerSubject::Carrier { key, .. }
            | LedgerSubject::PassedBy(key) => key,
        }
    }

    fn encode(&self) -> [u8; SUBJECT_LEN] {
        let role = match self {
            LedgerSubject::Contact(_) => 1,
            LedgerSubject::Carrier {
                role: CarrierRole::Custodian,
                ..
            } => 2,
            LedgerSubject::Carrier {
                role: CarrierRole::Depositor,
                ..
            } => 3,
            LedgerSubject::Carrier {
                role: CarrierRole::Relay,
                ..
            } => 4,
            LedgerSubject::PassedBy(_) => 5,
        };
        let mut out = [0u8; SUBJECT_LEN];
        out[0] = role;
        out[1..].copy_from_slice(self.key());
        out
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != SUBJECT_LEN {
            return None;
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes[1..]);
        let carrier = |role| LedgerSubject::Carrier { key, role };
        match bytes[0] {
            1 => Some(LedgerSubject::Contact(key)),
            2 => Some(carrier(CarrierRole::Custodian)),
            3 => Some(carrier(CarrierRole::Depositor)),
            4 => Some(carrier(CarrierRole::Relay)),
            5 => Some(LedgerSubject::PassedBy(key)),
            _ => None,
        }
    }
}

/// One open (or seen) alert.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Alert {
    pub id: AlertId,
    pub kind: SecKind,
    /// None: about this computer, or an update nobody passed on.
    pub subject: Option<LedgerSubject>,
    /// Hours since the Unix epoch.
    pub first_hour: u64,
    pub last_hour: u64,
    pub n: u64,
    /// The highest severity seen.
    pub severity: Severity,
    pub state: AlertState,
    /// The fixed code of what Raven did (`REKEY_REQUESTED`, ...).
    pub action: Option<String>,
}

/// One day's count of one kind about one subject.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DayCount {
    /// Days since the Unix epoch.
    pub day: u64,
    pub kind: SecKind,
    /// None: network sources (all of them together), this computer, or an
    /// update nobody passed on.
    pub subject: Option<LedgerSubject>,
    pub n: u64,
}

/// What the rate limiter keys on: a kind and whom it is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Slot {
    /// Any network source: one day count per kind, never a subject or an alert.
    Network,
    /// About nobody stored (this computer, an update nobody passed on).
    Nobody,
    Key([u8; 32]),
}

impl Slot {
    fn of(who: &Attribution) -> Self {
        match who {
            Attribution::Network { .. } => Slot::Network,
            other => match LedgerSubject::of(other) {
                Some(subject) => Slot::Key(*subject.key()),
                None => Slot::Nobody,
            },
        }
    }
}

/// The events of one slot not written yet, and when it was last written.
#[derive(Clone, Copy, Debug)]
struct Pending {
    subject: Option<LedgerSubject>,
    day: u64,
    n: u64,
    first_hour: u64,
    last_hour: u64,
    /// The highest severity since the last write.
    severity: Severity,
    written_at_ms: Option<u64>,
    written_severity: Option<Severity>,
    alert: Option<AlertId>,
}

fn sql_int(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn uint(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

/// A count row's AAD key: its day, kind and keyed subject as stored.
fn count_pk(day: i64, kind: i64, kh: &[u8]) -> Vec<u8> {
    let mut pk = Vec::with_capacity(8 + 8 + kh.len());
    pk.extend_from_slice(&day.to_be_bytes());
    pk.extend_from_slice(&kind.to_be_bytes());
    pk.extend_from_slice(kh);
    pk
}

/// An alert row's AAD key: its kind and keyed subject as stored.
fn alert_pk(kind: i64, kh: &[u8]) -> Vec<u8> {
    let mut pk = Vec::with_capacity(8 + kh.len());
    pk.extend_from_slice(&kind.to_be_bytes());
    pk.extend_from_slice(kh);
    pk
}

fn keyed(keys: &MetaKeys, subject: &LedgerSubject) -> [u8; 32] {
    at_rest::index(keys, ValueType::DeviceKey, subject.key())
}

fn key_check(keys: &MetaKeys) -> [u8; 32] {
    at_rest::index(keys, ValueType::DeviceKey, KEY_CHECK_VALUE)
}

/// Open a row's sealed subject (None: it does not open with these keys).
fn open_subject(keys: &MetaKeys, table: &str, pk: &[u8], meta: &[u8]) -> Option<LedgerSubject> {
    at_rest::open_row(keys, table, pk, meta)
        .ok()
        .and_then(|plain| LedgerSubject::decode(&plain))
}

/// The at-rest keys this process loaded (never a keystore call).
fn cached_keys(data_dir: &Path) -> Result<Arc<MetaKeys>, LedgerError> {
    at_rest::keys_cached(data_dir).map_err(|e| LedgerError::KeyUnavailable(e.to_string()))
}

// ── Opening ──────────────────────────────────────────────────────────────

/// Why one open attempt failed: a damaged file is moved aside and the open
/// tried once more.
enum OpenFailure {
    Corrupt,
    Ledger(LedgerError),
}

impl From<rusqlite::Error> for OpenFailure {
    fn from(e: rusqlite::Error) -> Self {
        match e.sqlite_error_code() {
            Some(ErrorCode::NotADatabase | ErrorCode::DatabaseCorrupt) => OpenFailure::Corrupt,
            _ => OpenFailure::Ledger(e.into()),
        }
    }
}

/// Move a damaged ledger aside (its WAL and shared-memory files go: they
/// belong to the damaged file). An earlier copy is replaced.
fn quarantine(path: &Path) -> Result<(), LedgerError> {
    let aside = aside_of(path);
    // Windows refuses to rename over a leftover from an earlier quarantine.
    let _ = std::fs::remove_file(&aside);
    if std::fs::rename(path, &aside).is_err() {
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(LedgerError::Store(format!("quarantine: {e}"))),
        }
    }
    for suffix in ["-wal", "-shm", "-journal"] {
        let _ = std::fs::remove_file(sidecar(path, suffix));
    }
    eprintln!("raven security: the security ledger was damaged; moved aside");
    Ok(())
}

/// Whether both tables have this file's keyed shape.
fn is_ours(conn: &Connection) -> rusqlite::Result<bool> {
    for table in [COUNTS, ALERTS] {
        if !rebuild::columns(conn, table)?
            .iter()
            .any(|c| c == KEYED_COLUMN)
        {
            return Ok(false);
        }
    }
    Ok(!rebuild::columns(conn, "sec_meta")?.is_empty())
}

/// One open of the file at `path`: created at version 1 when empty; a
/// newer version refused; a file that is not this ledger, or one keyed under
/// another key, reported damaged.
fn open_once(path: &Path, keys: &MetaKeys, busy: Duration) -> Result<Connection, OpenFailure> {
    let mut conn = crate::paths::open_private_data_dir_sqlite(path)?;
    conn.busy_timeout(busy)?;
    crate::paths::harden_sqlite(&conn)?;
    // auto_vacuum takes effect only on a new file (before the first table).
    conn.execute_batch(
        "PRAGMA auto_vacuum=INCREMENTAL; PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;",
    )?;
    let check = key_check(keys);
    {
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let _in_tx = crate::paths::HeldMark::transaction();
        let version = rebuild::user_version(&tx)?;
        if version > SCHEMA_VERSION {
            return Err(OpenFailure::Ledger(LedgerError::Newer(version)));
        }
        if version == 0 {
            // A new file: nothing in it may be someone else's.
            let tables: i64 = tx.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'",
                [],
                |r| r.get(0),
            )?;
            if tables != 0 {
                return Err(OpenFailure::Corrupt);
            }
            tx.execute_batch(SCHEMA)?;
            tx.execute(
                "INSERT INTO sec_meta (k, v) VALUES (?1, ?2)",
                params![META_KEY_CHECK, check.as_slice()],
            )?;
            tx.execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION};"))?;
        } else {
            if !is_ours(&tx)? {
                return Err(OpenFailure::Corrupt);
            }
            let stored: Option<Vec<u8>> = tx
                .query_row(
                    "SELECT v FROM sec_meta WHERE k = ?1",
                    params![META_KEY_CHECK],
                    |r| r.get(0),
                )
                .optional()?;
            if stored.as_deref() != Some(check.as_slice()) {
                // Keyed under another key (a profile sealed anew): nothing
                // in it opens here.
                return Err(OpenFailure::Corrupt);
            }
        }
        tx.commit()?;
    }
    Ok(conn)
}

// ── The ledger ───────────────────────────────────────────────────────────

/// A profile's security ledger, open for reading and writing (module docs).
pub struct SecurityLedger {
    data_dir: PathBuf,
    conn: Connection,
    pending: HashMap<(SecKind, Slot), Pending>,
    /// When the next pass writes the pairs whose interval has passed.
    next_sweep_ms: u64,
}

impl SecurityLedger {
    /// Open the ledger, creating it if needed. Nothing is created while
    /// [`SecGate::Events`] is shut, in a profile that is not sealed, or
    /// without the at-rest key ([`LedgerError::is_skipped`]).
    pub fn open(data_dir: &Path) -> Result<Self, LedgerError> {
        Self::open_with(data_dir, BUSY_TIMEOUT)
    }

    fn open_with(data_dir: &Path, busy: Duration) -> Result<Self, LedgerError> {
        if !security_gate::live(SecGate::Events) {
            return Err(LedgerError::GateClosed);
        }
        if crate::privacy::mode(data_dir) != Mode::Sealed {
            return Err(LedgerError::NotSealed);
        }
        // Before anything is created: no key, no ledger (never a clear one).
        let keys = cached_keys(data_dir)?;
        let path = ledger_path(data_dir);
        let conn = match open_once(&path, &keys, busy) {
            Ok(conn) => conn,
            Err(OpenFailure::Ledger(e)) => return Err(e),
            Err(OpenFailure::Corrupt) => {
                quarantine(&path)?;
                match open_once(&path, &keys, busy) {
                    Ok(conn) => conn,
                    Err(OpenFailure::Corrupt) => return Err(LedgerError::Damaged),
                    Err(OpenFailure::Ledger(e)) => return Err(e),
                }
            }
        };
        Ok(Self {
            data_dir: data_dir.to_path_buf(),
            conn,
            pending: HashMap::new(),
            next_sweep_ms: 0,
        })
    }

    /// Record one event noted with `severity` ([`crate::security_events::note`]),
    /// at most one write per kind and subject per [`WRITE_INTERVAL_MS`]
    /// (sooner when the severity rises or the day changes). A
    /// network-attributed event only adds to its kind's count for the day.
    /// Returns the alert the event belongs to (None for a network event).
    /// On an error the event stays pending for the next write.
    pub fn record(
        &mut self,
        ev: &SecEvent,
        severity: Severity,
        now_ms: u64,
    ) -> Result<Option<AlertId>, LedgerError> {
        let slot = Slot::of(&ev.who);
        let key = (ev.kind, slot);
        let day = ev.at_ms / DAY_MS;
        let hour = ev.at_ms / HOUR_MS;
        if self.pending.len() >= MAX_PENDING && !self.pending.contains_key(&key) {
            // Bounded memory: write what is pending and start over (a failed
            // write loses those counts, never more).
            let _ = self.flush(now_ms);
            self.pending.retain(|_, p| p.n > 0);
            if self.pending.len() >= MAX_PENDING {
                self.pending.clear();
            }
        }
        let held_day = self.pending.get(&key).filter(|p| p.n > 0).map(|p| p.day);
        if held_day.is_some_and(|held| held != day) {
            // The day changed: the earlier day's events go to their own row.
            self.write_slot(key, now_ms)?;
        }
        let entry = self.pending.entry(key).or_insert(Pending {
            subject: None,
            day,
            n: 0,
            first_hour: hour,
            last_hour: hour,
            severity,
            written_at_ms: None,
            written_severity: None,
            alert: None,
        });
        if entry.n == 0 {
            entry.day = day;
            entry.first_hour = hour;
            entry.last_hour = hour;
            entry.severity = severity;
        }
        entry.subject = LedgerSubject::of(&ev.who);
        entry.n = entry.n.saturating_add(1);
        entry.first_hour = entry.first_hour.min(hour);
        entry.last_hour = entry.last_hour.max(hour);
        entry.severity = entry.severity.max(severity);
        let due = entry
            .written_at_ms
            .is_none_or(|at| now_ms.saturating_sub(at) >= WRITE_INTERVAL_MS)
            || (slot != Slot::Network && entry.written_severity.is_none_or(|w| severity > w));
        if due {
            self.write_slot(key, now_ms)?;
        }
        let alert = self.pending.get(&key).and_then(|p| p.alert);
        self.sweep(now_ms);
        Ok(alert)
    }

    /// Write every pending pair whose interval has passed, at most once per
    /// interval (best effort: a failed one stays pending).
    fn sweep(&mut self, now_ms: u64) {
        if now_ms < self.next_sweep_ms {
            return;
        }
        self.next_sweep_ms = now_ms.saturating_add(WRITE_INTERVAL_MS);
        let due: Vec<(SecKind, Slot)> = self
            .pending
            .iter()
            .filter(|(_, p)| {
                p.n > 0
                    && p.written_at_ms
                        .is_none_or(|at| now_ms.saturating_sub(at) >= WRITE_INTERVAL_MS)
            })
            .map(|(key, _)| *key)
            .collect();
        for key in due {
            let _ = self.write_slot(key, now_ms);
        }
    }

    /// The once-a-minute pass on its own (raven-node's writer thread, when no
    /// event came to run it): the pairs whose interval has passed are
    /// written, the others wait.
    pub fn sweep_due(&mut self, now_ms: u64) {
        self.sweep(now_ms);
    }

    /// Write everything pending now, whatever the interval.
    pub fn flush(&mut self, now_ms: u64) -> Result<(), LedgerError> {
        let keys: Vec<(SecKind, Slot)> = self
            .pending
            .iter()
            .filter(|(_, p)| p.n > 0)
            .map(|(key, _)| *key)
            .collect();
        let mut first = Ok(());
        for key in keys {
            if let Err(e) = self.write_slot(key, now_ms) {
                if first.is_ok() {
                    first = Err(e);
                }
            }
        }
        first
    }

    /// Add `n` network-source events of `kind` to day `day`'s count at once
    /// (a writer that keeps network events in memory and flushes them by the
    /// hour, design A §3): no subject, no alert, no rate limit.
    pub fn add_network_count(
        &mut self,
        day: u64,
        kind: SecKind,
        n: u64,
    ) -> Result<(), LedgerError> {
        if n == 0 {
            return Ok(());
        }
        let keys = cached_keys(&self.data_dir)?;
        let hour = day.saturating_mul(24);
        let counted = Pending {
            subject: None,
            day,
            n,
            first_hour: hour,
            last_hour: hour,
            severity: Severity::Notice,
            written_at_ms: None,
            written_severity: None,
            alert: None,
        };
        write_rows(&mut self.conn, &keys, kind, Slot::Network, &counted).map(|_| ())
    }

    /// Write one pair's pending events (its day count, and its alert unless
    /// it is a network count) in one transaction.
    fn write_slot(&mut self, key: (SecKind, Slot), now_ms: u64) -> Result<(), LedgerError> {
        let Some(p) = self.pending.get(&key).copied() else {
            return Ok(());
        };
        if p.n == 0 {
            return Ok(());
        }
        let keys = cached_keys(&self.data_dir)?;
        let alert = write_rows(&mut self.conn, &keys, key.0, key.1, &p)?;
        if let Some(p) = self.pending.get_mut(&key) {
            p.n = 0;
            p.written_at_ms = Some(now_ms);
            p.written_severity = Some(p.written_severity.map_or(p.severity, |w| w.max(p.severity)));
            p.severity = Severity::Notice;
            p.alert = alert;
        }
        Ok(())
    }

    /// The open and seen alerts, the most severe and the latest first. Rows
    /// whose `meta` does not open with this profile's keys are left out.
    pub fn open_alerts(&self) -> Result<Vec<Alert>, LedgerError> {
        let keys = cached_keys(&self.data_dir)?;
        let mut stmt = self.conn.prepare(
            "SELECT id, kind, kh_subject, first_hour, last_hour, n, severity, state, action, meta
             FROM sec_alerts WHERE state < 2
             ORDER BY severity DESC, last_hour DESC, id DESC",
        )?;
        type Row = (
            i64,
            i64,
            Option<Vec<u8>>,
            i64,
            i64,
            i64,
            i64,
            i64,
            Option<String>,
            Option<Vec<u8>>,
        );
        let rows: Vec<Row> = stmt
            .query_map([], |r| {
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
            })?
            .collect::<Result<_, _>>()?;
        let mut alerts = Vec::with_capacity(rows.len());
        for (id, kind, kh, first, last, n, severity, state, action, meta) in rows {
            let Some(kind_value) = u16::try_from(kind).ok().and_then(SecKind::from_code) else {
                continue;
            };
            let Some(state) = AlertState::from_code(state) else {
                continue;
            };
            let subject = match (kh, meta) {
                (Some(kh), Some(meta)) => {
                    match open_subject(&keys, ALERTS, &alert_pk(kind, &kh), &meta) {
                        Some(subject) => Some(subject),
                        None => continue,
                    }
                }
                _ => None,
            };
            alerts.push(Alert {
                id: AlertId(id),
                kind: kind_value,
                subject,
                first_hour: uint(first),
                last_hour: uint(last),
                n: uint(n),
                severity: severity_of(severity),
                state,
                action,
            });
        }
        Ok(alerts)
    }

    /// The day counts from `since_day` (days since the Unix epoch) on, by
    /// day and kind. What is still pending in memory is not in them.
    pub fn counts(&self, since_day: u64) -> Result<Vec<DayCount>, LedgerError> {
        let keys = cached_keys(&self.data_dir)?;
        let mut stmt = self.conn.prepare(
            "SELECT day, kind, kh_subject, n, meta FROM sec_counts WHERE day >= ?1
             ORDER BY day, kind, kh_subject",
        )?;
        type Row = (i64, i64, Option<Vec<u8>>, i64, Option<Vec<u8>>);
        let rows: Vec<Row> = stmt
            .query_map(params![sql_int(since_day)], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })?
            .collect::<Result<_, _>>()?;
        let mut counts = Vec::with_capacity(rows.len());
        for (day, kind, kh, n, meta) in rows {
            let Some(kind_value) = u16::try_from(kind).ok().and_then(SecKind::from_code) else {
                continue;
            };
            let subject = match (kh, meta) {
                (Some(kh), Some(meta)) => {
                    match open_subject(&keys, COUNTS, &count_pk(day, kind, &kh), &meta) {
                        Some(subject) => Some(subject),
                        None => continue,
                    }
                }
                _ => None,
            };
            counts.push(DayCount {
                day: uint(day),
                kind: kind_value,
                subject,
                n: uint(n),
            });
        }
        Ok(counts)
    }

    /// Record what Raven did about alert `id`: a fixed code (`A-Z`, `0-9`,
    /// `_`, at most 32 characters), never free text. `Ok(false)`: no such
    /// alert any more.
    pub fn set_action(&mut self, id: AlertId, code: &'static str) -> Result<bool, LedgerError> {
        let fixed = !code.is_empty()
            && code.len() <= ACTION_MAX_LEN
            && code
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_');
        if !fixed {
            return Err(LedgerError::BadAction(code));
        }
        let changed = self.conn.execute(
            "UPDATE sec_alerts SET action = ?2 WHERE id = ?1",
            params![id.0, code],
        )?;
        Ok(changed > 0)
    }

    /// The person saw alert `id` (a higher severity later makes it new
    /// again). `Ok(false)`: not a new alert.
    pub fn mark_seen(&mut self, id: AlertId) -> Result<bool, LedgerError> {
        let changed = self.conn.execute(
            "UPDATE sec_alerts SET state = ?2 WHERE id = ?1 AND state = ?3",
            params![id.0, AlertState::Seen.code(), AlertState::New.code()],
        )?;
        Ok(changed > 0)
    }

    /// Resolve alert `id`; it is kept [`RETENTION_DAYS`] from now. A later
    /// event of its kind and subject opens a new alert. `Ok(false)`: not
    /// open.
    pub fn resolve(&mut self, id: AlertId, now_ms: u64) -> Result<bool, LedgerError> {
        let changed = self.conn.execute(
            "UPDATE sec_alerts SET state = ?2, resolved_hour = ?3 WHERE id = ?1 AND state < ?2",
            params![id.0, AlertState::Resolved.code(), sql_int(now_ms / HOUR_MS)],
        )?;
        for p in self.pending.values_mut() {
            if p.alert == Some(id) {
                p.alert = None;
            }
        }
        Ok(changed > 0)
    }

    /// Resolve every open alert about `peer` (any kind, any role): how many.
    pub fn resolve_contact(&mut self, peer: &[u8; 32], now_ms: u64) -> Result<usize, LedgerError> {
        let keys = cached_keys(&self.data_dir)?;
        let kh = at_rest::index(&keys, ValueType::DeviceKey, peer);
        let changed = self.conn.execute(
            "UPDATE sec_alerts SET state = ?2, resolved_hour = ?3
             WHERE kh_subject = ?1 AND state < ?2",
            params![
                kh.as_slice(),
                AlertState::Resolved.code(),
                sql_int(now_ms / HOUR_MS)
            ],
        )?;
        for ((_, slot), p) in self.pending.iter_mut() {
            if *slot == Slot::Key(*peer) {
                p.alert = None;
            }
        }
        Ok(changed)
    }

    /// `raven security clear` (after the person typed the confirmation):
    /// every count and alert goes, what is pending too, and the copy of a
    /// damaged ledger.
    pub fn clear(&mut self) -> Result<(), LedgerError> {
        {
            let tx = self
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let _in_tx = crate::paths::HeldMark::transaction();
            tx.execute_batch(&format!(
                "DELETE FROM sec_counts; DELETE FROM sec_alerts;
                 DELETE FROM sec_meta WHERE k != '{META_KEY_CHECK}';"
            ))?;
            tx.commit()?;
        }
        self.pending.clear();
        let _ = std::fs::remove_file(quarantine_path(&self.data_dir));
        self.compact();
        Ok(())
    }

    /// The retention pass: counts and resolved alerts older than
    /// [`RETENTION_DAYS`] go, open alerts beyond [`MAX_OPEN_ALERTS`] go
    /// (the oldest of the lowest severity first), and a damaged ledger's
    /// copy goes once it is that old.
    pub fn prune(&mut self, now_ms: u64) -> Result<(), LedgerError> {
        let today = now_ms / DAY_MS;
        {
            let tx = self
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let _in_tx = crate::paths::HeldMark::transaction();
            if let Some(cut) = today.checked_sub(RETENTION_DAYS) {
                tx.execute(
                    "DELETE FROM sec_counts WHERE day <= ?1",
                    params![sql_int(cut)],
                )?;
            }
            if let Some(cut) = (now_ms / HOUR_MS).checked_sub(RETENTION_DAYS * 24) {
                tx.execute(
                    "DELETE FROM sec_alerts WHERE state = ?1 AND resolved_hour <= ?2",
                    params![AlertState::Resolved.code(), sql_int(cut)],
                )?;
            }
            enforce_cap(&tx)?;
            tx.execute(
                "INSERT INTO sec_meta (k, v) VALUES (?1, ?2)
                 ON CONFLICT(k) DO UPDATE SET v = excluded.v",
                params![META_LAST_PRUNE, sql_int(today)],
            )?;
            tx.commit()?;
        }
        let aside = quarantine_path(&self.data_dir);
        let old = std::fs::metadata(&aside)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|at| at.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|at| u64::try_from(at.as_millis()).unwrap_or(u64::MAX))
            .is_some_and(|at| now_ms.saturating_sub(at) >= RETENTION_DAYS * DAY_MS);
        if old {
            let _ = std::fs::remove_file(&aside);
        }
        self.compact();
        Ok(())
    }

    /// Events the caller dropped before they reached the ledger (raven-node's
    /// full writer queue, design A §6): added to the stored counter.
    pub fn note_dropped(&mut self, n: u64) -> Result<(), LedgerError> {
        self.conn.execute(
            "INSERT INTO sec_meta (k, v) VALUES (?1, ?2)
             ON CONFLICT(k) DO UPDATE SET v = v + excluded.v",
            params![META_DROPPED, sql_int(n)],
        )?;
        Ok(())
    }

    /// How many alerts are open (new or seen), without opening any `meta`
    /// (raven-node's `Status.security.alerts_open`).
    pub fn open_alert_count(&self) -> Result<u64, LedgerError> {
        let n: i64 =
            self.conn
                .query_row("SELECT count(*) FROM sec_alerts WHERE state < 2", [], |r| {
                    r.get(0)
                })?;
        Ok(uint(n))
    }

    /// The dropped-event counter ([`Self::note_dropped`]).
    pub fn dropped(&self) -> Result<u64, LedgerError> {
        let n: Option<i64> = self
            .conn
            .query_row(
                "SELECT v FROM sec_meta WHERE k = ?1",
                params![META_DROPPED],
                |r| r.get(0),
            )
            .optional()?;
        Ok(n.map_or(0, uint))
    }

    /// After a bulk delete: give freed pages back and empty the WAL (best
    /// effort; `secure_delete` already zeroed what was deleted).
    fn compact(&self) {
        let _ = self.conn.execute_batch("PRAGMA incremental_vacuum;");
        let _ = crate::paths::checkpoint_truncate(&self.conn);
    }
}

impl Drop for SecurityLedger {
    /// What is still pending is written (best effort).
    fn drop(&mut self) {
        let _ = self.flush(crate::clock::now_ms());
    }
}

/// One pair's write: its day count (a new row seals the subject), then its
/// alert (opened, or counted into the open one), then the cap. Returns the
/// alert's id, None for a network count or when the cap dropped it.
fn write_rows(
    conn: &mut Connection,
    keys: &MetaKeys,
    kind: SecKind,
    slot: Slot,
    p: &Pending,
) -> Result<Option<AlertId>, LedgerError> {
    let kind_code = i64::from(kind.code());
    let day = sql_int(p.day);
    // A network count never has a subject, whatever the event carried.
    let subject = match slot {
        Slot::Network => None,
        Slot::Nobody | Slot::Key(_) => p.subject,
    };
    let kh = subject.as_ref().map(|s| keyed(keys, s));
    let kh_bytes = kh.as_ref().map(|k| k.as_slice());
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let _in_tx = crate::paths::HeldMark::transaction();
    let counted = tx.execute(
        "UPDATE sec_counts SET n = n + ?4
         WHERE day = ?1 AND kind = ?2 AND ifnull(kh_subject, x'') = ifnull(?3, x'')",
        params![day, kind_code, kh_bytes, sql_int(p.n)],
    )?;
    if counted == 0 {
        let meta = match (&subject, &kh) {
            (Some(s), Some(kh)) => Some(at_rest::seal_row(
                keys,
                COUNTS,
                &count_pk(day, kind_code, kh),
                &s.encode(),
            )),
            _ => None,
        };
        tx.execute(
            "INSERT INTO sec_counts (day, kind, kh_subject, n, meta) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![day, kind_code, kh_bytes, sql_int(p.n), meta],
        )?;
    }
    let alert = if slot == Slot::Network {
        None
    } else {
        let severity = severity_code(p.severity);
        let open: Option<i64> = tx
            .query_row(
                "SELECT id FROM sec_alerts
                 WHERE kind = ?1 AND ifnull(kh_subject, x'') = ifnull(?2, x'') AND state < 2",
                params![kind_code, kh_bytes],
                |r| r.get(0),
            )
            .optional()?;
        let id = match open {
            Some(id) => {
                // A higher severity makes a seen alert new again.
                tx.execute(
                    "UPDATE sec_alerts SET n = n + ?2, first_hour = min(first_hour, ?3),
                       last_hour = max(last_hour, ?4),
                       state = CASE WHEN ?5 > severity THEN 0 ELSE state END,
                       severity = max(severity, ?5)
                     WHERE id = ?1",
                    params![
                        id,
                        sql_int(p.n),
                        sql_int(p.first_hour),
                        sql_int(p.last_hour),
                        severity
                    ],
                )?;
                id
            }
            None => {
                let meta = match (&subject, &kh) {
                    (Some(s), Some(kh)) => Some(at_rest::seal_row(
                        keys,
                        ALERTS,
                        &alert_pk(kind_code, kh),
                        &s.encode(),
                    )),
                    _ => None,
                };
                tx.execute(
                    "INSERT INTO sec_alerts
                       (kind, kh_subject, first_hour, last_hour, n, severity, state, meta)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7)",
                    params![
                        kind_code,
                        kh_bytes,
                        sql_int(p.first_hour),
                        sql_int(p.last_hour),
                        sql_int(p.n),
                        severity,
                        meta
                    ],
                )?;
                tx.last_insert_rowid()
            }
        };
        enforce_cap(&tx)?;
        let kept: Option<i64> = tx
            .query_row(
                "SELECT id FROM sec_alerts WHERE id = ?1",
                params![id],
                |r| r.get(0),
            )
            .optional()?;
        kept.map(AlertId)
    };
    tx.commit()?;
    Ok(alert)
}

/// At most [`MAX_OPEN_ALERTS`] open alerts: the oldest of the lowest
/// severity go first.
fn enforce_cap(conn: &Connection) -> rusqlite::Result<()> {
    let open: i64 = conn.query_row("SELECT COUNT(*) FROM sec_alerts WHERE state < 2", [], |r| {
        r.get(0)
    })?;
    if open > MAX_OPEN_ALERTS {
        conn.execute(
            "DELETE FROM sec_alerts WHERE id IN (
               SELECT id FROM sec_alerts WHERE state < 2
               ORDER BY severity ASC, last_hour ASC, id ASC LIMIT ?1)",
            params![open - MAX_OPEN_ALERTS],
        )?;
    }
    Ok(())
}

/// Every row's table and kind code, read without the keys: tests in other
/// crates count what another process wrote (step P6.25). `None`: no file.
#[cfg(any(test, feature = "test-helpers"))]
pub fn rows_on_disk(data_dir: &Path) -> Result<Option<Vec<(&'static str, u16)>>, String> {
    let path = ledger_path(data_dir);
    if !path.exists() {
        return Ok(None);
    }
    let conn = Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(text)?;
    let mut rows = Vec::new();
    for table in [COUNTS, ALERTS] {
        let mut stmt = conn
            .prepare(&format!("SELECT kind FROM {table} ORDER BY rowid"))
            .map_err(text)?;
        let kinds = stmt.query_map([], |r| r.get::<_, i64>(0)).map_err(text)?;
        for kind in kinds {
            rows.push((table, u16::try_from(kind.map_err(text)?).map_err(text)?));
        }
    }
    Ok(Some(rows))
}

// ── ash's sink ───────────────────────────────────────────────────────────

/// ash's [`SecSink`] (design A §3): writes each event into the ledger
/// directly, best effort. It opens the ledger at the first event (waiting at
/// most [`DIRECT_BUSY_TIMEOUT`] for raven-node), keeps it for the process,
/// and counts a failure instead of failing anything. A clone shares the same
/// ledger, so the caller can keep one to [`DirectSink::flush`] at exit.
#[derive(Clone)]
pub struct DirectSink {
    inner: Arc<DirectInner>,
}

struct DirectInner {
    data_dir: PathBuf,
    ledger: Mutex<Option<SecurityLedger>>,
    failures: AtomicU64,
}

impl DirectSink {
    pub fn new(data_dir: &Path) -> Self {
        Self {
            inner: Arc::new(DirectInner {
                data_dir: data_dir.to_path_buf(),
                ledger: Mutex::new(None),
                failures: AtomicU64::new(0),
            }),
        }
    }

    /// Writes that failed (a skipped ledger is not a failure).
    pub fn failures(&self) -> u64 {
        self.inner.failures.load(Ordering::Relaxed)
    }

    /// Write what is pending now (at the process's end).
    pub fn flush(&self) {
        let mut ledger = self
            .inner
            .ledger
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(ledger) = ledger.as_mut() {
            if ledger.flush(crate::clock::now_ms()).is_err() {
                self.inner.failures.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

impl SecSink for DirectSink {
    fn accept(&self, ev: &SecEvent, severity: Severity) {
        let mut ledger = self
            .inner
            .ledger
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if ledger.is_none() {
            match SecurityLedger::open_with(&self.inner.data_dir, DIRECT_BUSY_TIMEOUT) {
                Ok(opened) => *ledger = Some(opened),
                Err(e) => {
                    if !e.is_skipped() {
                        self.inner.failures.fetch_add(1, Ordering::Relaxed);
                    }
                    return;
                }
            }
        }
        if let Some(ledger) = ledger.as_mut() {
            if ledger.record(ev, severity, crate::clock::now_ms()).is_err() {
                self.inner.failures.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

// ── The privacy passes (docs/design/2026-10-at-rest-metadata.md 7.7) ─────

/// A keyed row as the privacy passes read it: rowid, day (0 for an alert),
/// kind, `kh_subject` and `meta`.
type SubjectRow = (i64, i64, i64, Vec<u8>, Vec<u8>);

/// An existing ledger at this build's version, for a privacy pass (no gate:
/// these passes handle a file that is there, and never create one). `None`:
/// no file, or not one this build reads.
fn existing(path: &Path) -> Result<Option<Connection>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let conn = rebuild::dedicated(path).map_err(text)?;
    let version = rebuild::user_version(&conn).map_err(text)?;
    if version > SCHEMA_VERSION {
        return Err(LedgerError::Newer(version).to_string());
    }
    if version < SCHEMA_VERSION || !is_ours(&conn).map_err(text)? {
        return Ok(None);
    }
    Ok(Some(conn))
}

/// `raven privacy unseal`: the ledger has no clear shape, so it goes (with
/// its sidecars and a damaged copy). Its rows are not reported as left out:
/// nothing in them failed to open.
pub fn unseal(data_dir: &Path) -> Result<Migration, String> {
    let path = ledger_path(data_dir);
    let aside = aside_of(&path);
    if !path.exists() && !aside.exists() {
        return Ok(Migration::already());
    }
    for file in [
        path.clone(),
        sidecar(&path, "-wal"),
        sidecar(&path, "-shm"),
        sidecar(&path, "-journal"),
        aside,
    ] {
        match std::fs::remove_file(&file) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("{SECURITY_LEDGER_FILE}: {e}")),
        }
    }
    crate::paths::sync_dir_best_effort(data_dir);
    Ok(Migration::default())
}

/// `raven privacy rotate-meta`: every keyed subject is computed again under
/// the new lookup key (the epochs the keys hold open the old `meta`), in one
/// transaction on a connection that writes nothing before the commit. A row
/// whose `meta` does not open goes (`dropped`).
pub fn rekey(data_dir: &Path) -> Result<Migration, String> {
    let path = ledger_path(data_dir);
    if existing(&path)?.is_none() {
        return Ok(Migration::already());
    }
    let keys = at_rest::keys_cached(data_dir).map_err(|e| format!("security ledger: {e}"))?;
    let mut conn = rebuild::rekey_connection(&path).map_err(text)?;
    let mut done = Migration::default();
    {
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(text)?;
        let _in_tx = crate::paths::HeldMark::transaction();
        for table in [COUNTS, ALERTS] {
            let rows: Vec<SubjectRow> = {
                let day = if table == COUNTS { "day" } else { "0" };
                let mut stmt = tx
                    .prepare(&format!(
                        "SELECT rowid, {day}, kind, kh_subject, meta FROM {table}
                         WHERE kh_subject IS NOT NULL"
                    ))
                    .map_err(text)?;
                let rows = stmt
                    .query_map([], |r| {
                        Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
                    })
                    .map_err(text)?;
                rows.collect::<Result<_, _>>().map_err(text)?
            };
            for (rowid, day, kind, kh, meta) in rows {
                let pk = |kh: &[u8]| {
                    if table == COUNTS {
                        count_pk(day, kind, kh)
                    } else {
                        alert_pk(kind, kh)
                    }
                };
                let Some(subject) = open_subject(&keys, table, &pk(&kh), &meta) else {
                    tx.execute(&format!("DELETE FROM {table} WHERE rowid = ?1"), [rowid])
                        .map_err(text)?;
                    done.dropped += 1;
                    continue;
                };
                let new_kh = keyed(&keys, &subject);
                let sealed = at_rest::seal_row(&keys, table, &pk(&new_kh), &subject.encode());
                tx.execute(
                    &format!("UPDATE {table} SET kh_subject = ?2, meta = ?3 WHERE rowid = ?1"),
                    params![rowid, new_kh.as_slice(), sealed],
                )
                .map_err(text)?;
                done.rows += 1;
            }
        }
        tx.execute(
            "INSERT INTO sec_meta (k, v) VALUES (?1, ?2)
             ON CONFLICT(k) DO UPDATE SET v = excluded.v",
            params![META_KEY_CHECK, key_check(&keys).as_slice()],
        )
        .map_err(text)?;
        tx.commit().map_err(text)?;
    }
    done.scrub_pending = crate::paths::checkpoint_truncate(&conn).map_or(true, |c| c.busy);
    Ok(done)
}

/// Sealed `meta` blobs not on epoch `current` (by their first bytes; no key,
/// no lock): the data-key rotation's old-object count. `0` without a ledger.
pub fn rows_off_epoch(data_dir: &Path, current: u32) -> Result<u32, String> {
    let path = ledger_path(data_dir);
    if !path.exists() {
        return Ok(0);
    }
    let conn = Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)
        .map_err(text)?;
    conn.busy_timeout(Duration::from_secs(2)).map_err(text)?;
    if rebuild::user_version(&conn).map_err(text)? != SCHEMA_VERSION
        || !is_ours(&conn).map_err(text)?
    {
        return Ok(0);
    }
    let epoch = current.to_be_bytes().to_vec();
    let n: i64 = conn
        .query_row(
            "SELECT (SELECT COUNT(*) FROM sec_counts
                     WHERE meta IS NOT NULL AND substr(meta, 2, 4) != ?1)
                  + (SELECT COUNT(*) FROM sec_alerts
                     WHERE meta IS NOT NULL AND substr(meta, 2, 4) != ?1)",
            params![epoch],
            |r| r.get(0),
        )
        .map_err(text)?;
    Ok(u32::try_from(n).unwrap_or(u32::MAX))
}

/// The data-key rotation's step for the ledger (PP.10): in one IMMEDIATE
/// transaction every `meta` not on the current epoch is opened and sealed
/// again under it, then the WAL is checkpointed. One that does not open is
/// left as it is (`unreadable`).
pub fn reseal_rows(data_dir: &Path) -> Result<RowReseal, String> {
    let mut report = RowReseal::default();
    let path = ledger_path(data_dir);
    if !path.exists() || crate::privacy::mode(data_dir) != Mode::Sealed {
        return Ok(report);
    }
    let keys = at_rest::keys_cached(data_dir).map_err(|e| format!("security ledger: {e}"))?;
    let current = keys.current_epoch();
    if rows_off_epoch(data_dir, current)? == 0 {
        return Ok(report);
    }
    let Some(mut conn) = existing(&path)? else {
        return Ok(report);
    };
    let epoch = current.to_be_bytes().to_vec();
    {
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(text)?;
        let _in_tx = crate::paths::HeldMark::transaction();
        for table in [COUNTS, ALERTS] {
            let day = if table == COUNTS { "day" } else { "0" };
            let rows: Vec<SubjectRow> = {
                let mut stmt = tx
                    .prepare(&format!(
                        "SELECT rowid, {day}, kind, kh_subject, meta FROM {table}
                         WHERE meta IS NOT NULL AND substr(meta, 2, 4) != ?1"
                    ))
                    .map_err(text)?;
                let rows = stmt
                    .query_map(params![epoch], |r| {
                        Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
                    })
                    .map_err(text)?;
                rows.collect::<Result<_, _>>().map_err(text)?
            };
            for (rowid, day, kind, kh, meta) in rows {
                let pk = if table == COUNTS {
                    count_pk(day, kind, &kh)
                } else {
                    alert_pk(kind, &kh)
                };
                let Ok(plain) = at_rest::open_row(&keys, table, &pk, &meta) else {
                    report.unreadable += 1;
                    continue;
                };
                tx.execute(
                    &format!("UPDATE {table} SET meta = ?2 WHERE rowid = ?1"),
                    params![rowid, at_rest::seal_row(&keys, table, &pk, &plain)],
                )
                .map_err(text)?;
                report.resealed += 1;
            }
        }
        tx.commit().map_err(text)?;
    }
    if report.resealed > 0 {
        report.scrub_pending = crate::paths::checkpoint_truncate(&conn).map_or(true, |c| c.busy);
    }
    Ok(report)
}

#[cfg(test)]
mod tests;
