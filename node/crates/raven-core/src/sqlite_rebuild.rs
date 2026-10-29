//! The SQLite rebuild recipe of the privacy pack (PP.12; PP.13, PP.14 and
//! PP.17 reuse it; docs/design/2026-10-at-rest-metadata.md section 7): how
//! a store moves the columns that name friends to keyed lookups and sealed
//! `meta` blobs, and back (`raven privacy unseal`, PP.18).
//!
//! - **A dedicated connection.** `foreign_keys=OFF` and
//!   `legacy_alter_table=OFF` are set BEFORE the transaction: the bundled
//!   SQLite turns foreign keys on by default and the pragma is a no-op inside
//!   one. `temp_store=MEMORY` keeps sorts and index builds out of the OS temp
//!   folder; `secure_delete=ON` overwrites what the rebuild frees.
//! - **One `BEGIN IMMEDIATE`.** The store re-reads its version and shape
//!   inside it (another process may have migrated), then per table: `CREATE
//!   TABLE <t>__new`, the rows copied with their rowids, `DROP TABLE <t>`,
//!   `ALTER TABLE <t>__new RENAME TO <t>`, the indexes created again. The old
//!   table is never renamed first (SQLite >= 3.26 moves child references
//!   with it).
//! - **Checked before COMMIT** ([`verify`]): every table holds as many rows
//!   as before and `PRAGMA foreign_key_check` is empty; otherwise the
//!   transaction rolls back. The [`SCHEMA_TABLE`] row and `user_version` are
//!   written in the same transaction ([`record`]).
//! - **Then a scrub** ([`scrub`]): one `VACUUM` (pages freed before
//!   `secure_delete` existed stay on the freelist otherwise) and
//!   `checkpoint_truncate`. While another connection is in the way the row
//!   keeps `scrub_pending` and the next prune pass finishes it
//!   ([`finish_scrub`]).
//! - **Free space first** ([`space_ok`]): at least twice the store plus
//!   64 MiB, or nothing is started.
//!
//! **Version by shape (review R06).** Older builds stamp `PRAGMA
//! user_version` after `CREATE TABLE IF NOT EXISTS`, outside a transaction,
//! so an older process that read the version before a migration can stamp
//! the old number on a migrated store. A store reads its shape ([`shape`])
//! and its [`SCHEMA_TABLE`] row and, where they disagree with
//! `user_version`, stamps it again ([`restamp`]) instead of migrating twice.

use std::path::Path;
use std::time::Duration;

use rusqlite::{params, Connection, OptionalExtension};

/// The table every migrated store keeps its version in:
/// `raven_schema(store, version, scrub_pending)`.
pub const SCHEMA_TABLE: &str = "raven_schema";
/// What a rebuild or a `VACUUM` needs free beyond twice the store's size.
pub const SPACE_MARGIN_BYTES: u64 = 64 << 20;
/// `prune_after_hour` counts hours since the Unix epoch.
pub const HOUR_MS: u64 = 60 * 60 * 1000;
/// How long a `VACUUM` waits for another connection's write lock.
const VACUUM_WAIT: Duration = Duration::from_millis(250);

/// The clear expiry column of a migrated row, coarsened: `expires_at_ms`
/// rounded UP to the hour. Only the prune reads it; every decision reads the
/// exact time from the row's sealed `meta`.
pub fn prune_after_hour(expires_at_ms: u64) -> i64 {
    i64::try_from(expires_at_ms.div_ceil(HOUR_MS)).unwrap_or(i64::MAX)
}

/// The hours a prune deletes: rows with `prune_after_hour <= this` expired
/// for sure (their exact expiry is at or before the end of that hour).
pub fn hour_of(now_ms: u64) -> i64 {
    i64::try_from(now_ms / HOUR_MS).unwrap_or(i64::MAX)
}

/// Which columns a store's key table has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    /// No such table yet (a new file).
    Missing,
    /// Today's clear columns.
    Clear,
    /// The keyed columns of a migrated store.
    Keyed,
}

/// The shape of `table`: [`Shape::Keyed`] when it has `keyed_column`.
pub fn shape(conn: &Connection, table: &str, keyed_column: &str) -> rusqlite::Result<Shape> {
    let columns = columns(conn, table)?;
    Ok(if columns.is_empty() {
        Shape::Missing
    } else if columns.iter().any(|c| c == keyed_column) {
        Shape::Keyed
    } else {
        Shape::Clear
    })
}

/// The column names of `table` (empty when there is no such table).
pub fn columns(conn: &Connection, table: &str) -> rusqlite::Result<Vec<String>> {
    let mut stmt = conn.prepare("SELECT name FROM pragma_table_info(?1)")?;
    let rows = stmt.query_map(params![table], |r| r.get::<_, String>(0))?;
    rows.collect()
}

pub fn user_version(conn: &Connection) -> rusqlite::Result<i64> {
    conn.query_row("PRAGMA user_version", [], |r| r.get(0))
}

/// `PRAGMA user_version` from a database file's header (bytes 60..64), with
/// no SQLite open: `None` for a missing or short file, or one that is not a
/// SQLite database. A commit still in the WAL is not seen.
pub fn header_user_version(path: &Path) -> Option<i64> {
    use std::io::Read;
    let mut head = [0u8; 64];
    std::fs::File::open(path).ok()?.read_exact(&mut head).ok()?;
    if &head[..16] != b"SQLite format 3\0" {
        return None;
    }
    Some(i64::from(i32::from_be_bytes([
        head[60], head[61], head[62], head[63],
    ])))
}

/// The store's [`SCHEMA_TABLE`] row: its version and whether a scrub is
/// pending. `None` without the table or the row.
pub fn recorded(conn: &Connection, store: &str) -> rusqlite::Result<Option<(i64, bool)>> {
    let exists: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
            params![SCHEMA_TABLE],
            |r| r.get(0),
        )
        .optional()?;
    if exists.is_none() {
        return Ok(None);
    }
    conn.query_row(
        "SELECT version, scrub_pending FROM raven_schema WHERE store = ?1",
        params![store],
        |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)? != 0)),
    )
    .optional()
}

/// Write the store's version: its [`SCHEMA_TABLE`] row and `user_version`,
/// inside the caller's migration transaction.
pub fn record(
    conn: &Connection,
    store: &str,
    version: i64,
    scrub_pending: bool,
) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS raven_schema (
           store TEXT PRIMARY KEY NOT NULL,
           version INTEGER NOT NULL,
           scrub_pending INTEGER NOT NULL DEFAULT 0 CHECK(scrub_pending IN (0, 1)));",
    )?;
    conn.execute(
        "INSERT INTO raven_schema (store, version, scrub_pending) VALUES (?1, ?2, ?3)
         ON CONFLICT(store) DO UPDATE SET version = excluded.version,
           scrub_pending = excluded.scrub_pending",
        params![store, version, i64::from(scrub_pending)],
    )?;
    conn.pragma_update(None, "user_version", version)
}

/// Stamp `version` again (review R06: an older process stamped its own
/// number on a store whose shape says `version`), keeping the scrub mark.
/// One IMMEDIATE transaction; the shape is the caller's, read before.
pub fn restamp(conn: &mut Connection, store: &str, version: i64) -> rusqlite::Result<()> {
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let _in_tx = crate::paths::HeldMark::transaction();
    let pending = recorded(&tx, store)?.is_some_and(|(_, pending)| pending);
    record(&tx, store, version, pending)?;
    tx.commit()
}

/// The connection a rebuild runs on (see the module docs).
pub fn dedicated(path: &Path) -> rusqlite::Result<Connection> {
    let conn = crate::paths::open_private_data_dir_sqlite(path)?;
    conn.busy_timeout(Duration::from_secs(10))?;
    conn.execute_batch(
        "PRAGMA foreign_keys=OFF;
         PRAGMA legacy_alter_table=OFF;
         PRAGMA temp_store=MEMORY;",
    )?;
    crate::paths::harden_sqlite(&conn)?;
    Ok(conn)
}

/// The connection a re-key runs on (`raven privacy rotate-meta`, PP.18):
/// [`dedicated`] with `cache_spill=OFF`, so no page is written before the
/// commit. A re-key moves each table back to its clear columns and forward
/// again under the new keys inside one transaction; the clear half lives in
/// memory only, and `secure_delete` zeroes the pages it freed before the
/// commit writes them.
pub fn rekey_connection(path: &Path) -> rusqlite::Result<Connection> {
    let conn = dedicated(path)?;
    conn.execute_batch("PRAGMA cache_spill=OFF;")?;
    Ok(conn)
}

/// The store's bytes on disk: the file and its WAL.
pub fn store_bytes(path: &Path) -> u64 {
    let mut wal = path.as_os_str().to_os_string();
    wal.push("-wal");
    [path.to_path_buf(), wal.into()]
        .iter()
        .filter_map(|p| std::fs::metadata(p).ok())
        .map(|m| m.len())
        .sum()
}

/// Reads the free space on the disk that holds a path
/// ([`crate::disk_space::free_bytes`]; tests pass their own).
pub type FreeBytes<'a> = &'a dyn Fn(&Path) -> Option<u64>;

/// The free-space preflight (review R22): `Err(needed)` when less than twice
/// the store plus [`SPACE_MARGIN_BYTES`] is free. A disk that does not say
/// passes.
pub fn space_ok(path: &Path, free: FreeBytes<'_>) -> Result<(), u64> {
    let needed = store_bytes(path)
        .saturating_mul(2)
        .saturating_add(SPACE_MARGIN_BYTES);
    #[cfg(test)]
    if fault::take(|f| f == Fault::NoSpace) {
        return Err(needed);
    }
    match free(path) {
        Some(free) if free < needed => Err(needed),
        _ => Ok(()),
    }
}

/// Why a rebuild stopped. Nothing was changed (the transaction rolled
/// back), except for a [`RebuildError::Scrub`] after the commit.
#[derive(Debug)]
pub enum RebuildError {
    Sqlite(rusqlite::Error),
    /// A table holds another number of rows than before.
    Count {
        table: &'static str,
        before: i64,
        after: i64,
    },
    /// `PRAGMA foreign_key_check` found rows.
    ForeignKeys,
    /// Not enough free disk space (about this many bytes).
    NoSpace {
        needed: u64,
    },
    /// The at-rest key is not loaded, or a sealed value did not open.
    Key(crate::at_rest::AtRestError),
    /// A test's injected stop at this statement.
    #[cfg(test)]
    Crash(u32),
}

impl std::fmt::Display for RebuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sqlite(e) => write!(f, "migration stopped: {e}"),
            Self::Count {
                table,
                before,
                after,
            } => write!(
                f,
                "migration stopped: {table} would hold {after} rows instead of {before}; \
                 nothing was changed"
            ),
            Self::ForeignKeys => f.write_str(
                "migration stopped: a row would lose the row it refers to; nothing was changed",
            ),
            Self::NoSpace { needed } => write!(
                f,
                "migration deferred: about {} MiB of free disk space needed",
                needed.div_ceil(1 << 20)
            ),
            Self::Key(e) => write!(f, "migration stopped: {e}"),
            #[cfg(test)]
            Self::Crash(at) => write!(f, "injected stop at statement {at}"),
        }
    }
}

impl From<rusqlite::Error> for RebuildError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Sqlite(e)
    }
}

impl From<crate::at_rest::AtRestError> for RebuildError {
    fn from(e: crate::at_rest::AtRestError) -> Self {
        Self::Key(e)
    }
}

/// What a store's migration did (counts only).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Migration {
    /// The store had the target shape already: nothing was written.
    pub already: bool,
    /// Rows moved, in every table.
    pub rows: u32,
    /// Rows left out because their sealed values did not open here (the way
    /// back only; the count check expected exactly these).
    pub dropped: u32,
    /// The `VACUUM` or the checkpoint after the commit did not complete:
    /// the next prune pass finishes it.
    pub scrub_pending: bool,
}

impl Migration {
    pub fn already() -> Self {
        Self {
            already: true,
            ..Self::default()
        }
    }
}

/// What a data-key rotation's pass over one store's sealed values did
/// (PP.10, `privacy::reseal_everything`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RowReseal {
    /// Values sealed again under the current epoch (from the chat-history
    /// key, or an older epoch).
    pub resealed: u32,
    /// Values that do not open with a key here: left as they are (rows of
    /// the app inbox: for the page, which sets them aside).
    pub unreadable: u32,
    /// The checkpoint after the rewrite found readers in the way: the old
    /// bytes stay in the WAL until a later checkpoint.
    pub scrub_pending: bool,
}

pub fn count(conn: &Connection, table: &str) -> rusqlite::Result<i64> {
    conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
}

/// Before COMMIT: every table holds the rows it should, and no foreign key
/// points nowhere.
pub fn verify(conn: &Connection, expected: &[(&'static str, i64)]) -> Result<(), RebuildError> {
    for (table, before) in expected {
        let after = count(conn, table)?;
        if after != *before {
            return Err(RebuildError::Count {
                table,
                before: *before,
                after,
            });
        }
    }
    let mut stmt = conn.prepare("PRAGMA foreign_key_check")?;
    if stmt.query([])?.next()?.is_some() {
        return Err(RebuildError::ForeignKeys);
    }
    Ok(())
}

/// Counts a rebuild's statements: a test stops it before any one of them,
/// as a crash would ([`fault`]).
#[derive(Debug, Default)]
pub struct Steps(u32);

impl Steps {
    /// Before the next statement.
    pub fn step(&mut self) -> Result<(), RebuildError> {
        #[cfg(test)]
        {
            let at = self.0;
            if fault::take(|f| f == Fault::CrashAt(at)) {
                return Err(RebuildError::Crash(at));
            }
        }
        self.0 += 1;
        Ok(())
    }

    /// How many statements ran.
    pub fn taken(&self) -> u32 {
        self.0
    }
}

/// A test's fault in a rebuild: whether to leave one row out (the count
/// check must catch it).
pub fn drop_one_row() -> bool {
    #[cfg(test)]
    {
        fault::take(|f| f == Fault::DropOneRow)
    }
    #[cfg(not(test))]
    {
        false
    }
}

/// A test's disk-full fault: the dedicated connection may not grow the file
/// (`PRAGMA max_page_count`), so the next write fails with `SQLITE_FULL` as
/// a full disk would.
pub fn arm_disk_full(_conn: &Connection) -> rusqlite::Result<()> {
    #[cfg(test)]
    if fault::take(|f| f == Fault::DiskFull) {
        let pages: i64 = _conn.query_row("PRAGMA page_count", [], |r| r.get(0))?;
        _conn.query_row(&format!("PRAGMA max_page_count = {pages}"), [], |_| Ok(()))?;
    }
    Ok(())
}

/// What [`scrub`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scrubbed {
    /// The `VACUUM` ran and the WAL was emptied afterwards.
    pub complete: bool,
}

/// After a committed rebuild: one `VACUUM`, then `checkpoint_truncate`; only
/// when both did their work is the store's `scrub_pending` cleared (and the
/// WAL emptied once more). A connection in the way (a reader on an older
/// snapshot, a writer), or too little free space, leaves it pending for the
/// next prune pass. Outside any transaction.
pub fn scrub(conn: &Connection, store: &str, free: FreeBytes<'_>) -> rusqlite::Result<Scrubbed> {
    let path = conn
        .path()
        .map(std::path::PathBuf::from)
        .unwrap_or_default();
    if space_ok(&path, free).is_err() {
        return Ok(Scrubbed { complete: false });
    }
    let own_ms: i64 = conn.query_row("PRAGMA busy_timeout", [], |r| r.get(0))?;
    conn.busy_timeout(VACUUM_WAIT)?;
    #[cfg(test)]
    let vacuumed = !fault::take(|f| f == Fault::VacuumBusy) && conn.execute_batch("VACUUM").is_ok();
    #[cfg(not(test))]
    let vacuumed = conn.execute_batch("VACUUM").is_ok();
    conn.busy_timeout(Duration::from_millis(u64::try_from(own_ms).unwrap_or(0)))?;
    let emptied = crate::paths::checkpoint_truncate(conn)?.completed();
    if !(vacuumed && emptied) {
        return Ok(Scrubbed { complete: false });
    }
    if recorded(conn, store)?.is_some_and(|(_, pending)| pending) {
        conn.execute(
            "UPDATE raven_schema SET scrub_pending = 0 WHERE store = ?1",
            params![store],
        )?;
        // The one page that changed (no friend data on it).
        let _ = crate::paths::checkpoint_truncate(conn);
    }
    Ok(Scrubbed { complete: true })
}

/// The next prune pass: a store whose [`SCHEMA_TABLE`] row says a scrub is
/// pending is scrubbed now. `Ok(None)` when nothing was pending (or there is
/// no such store), `Ok(Some(complete))` otherwise.
pub fn finish_scrub(
    path: &Path,
    store: &str,
    free: FreeBytes<'_>,
) -> rusqlite::Result<Option<bool>> {
    if !path.exists() || !scrub_pending(path, store) {
        return Ok(None);
    }
    let conn = dedicated(path)?;
    if !recorded(&conn, store)?.is_some_and(|(_, pending)| pending) {
        return Ok(None);
    }
    scrub(&conn, store, free).map(|s| Some(s.complete))
}

/// Whether a store's scrub is pending (status; one read, no write). `false`
/// for a missing file or one that cannot be read.
pub fn scrub_pending(path: &Path, store: &str) -> bool {
    if !path.exists() {
        return false;
    }
    let Ok(conn) = Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    ) else {
        return false;
    };
    let _ = conn.busy_timeout(Duration::from_millis(250));
    recorded(&conn, store).is_ok_and(|row| row.is_some_and(|(_, pending)| pending))
}

/// A test's fault in a rebuild (one, on this thread, taken once).
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// Stop before statement N, as a crash would.
    CrashAt(u32),
    /// Leave one row out of the copy.
    DropOneRow,
    /// The disk fills up during the rebuild (`SQLITE_FULL`).
    DiskFull,
    /// The free-space preflight fails.
    NoSpace,
    /// Another connection holds the write lock when the `VACUUM` runs.
    VacuumBusy,
}

#[cfg(test)]
pub mod fault {
    use super::Fault;
    use std::cell::Cell;

    thread_local! {
        static ARMED: Cell<Option<Fault>> = const { Cell::new(None) };
    }

    pub fn arm(fault: Fault) {
        ARMED.with(|armed| armed.set(Some(fault)));
    }

    pub fn disarm() {
        ARMED.with(|armed| armed.set(None));
    }

    /// Whether the armed fault matches `pred`; it is disarmed if so.
    pub(super) fn take(pred: impl Fn(Fault) -> bool) -> bool {
        ARMED.with(|armed| match armed.get() {
            Some(fault) if pred(fault) => {
                armed.set(None);
                true
            }
            _ => false,
        })
    }

    /// Still armed (the stop was never reached).
    pub fn armed() -> bool {
        ARMED.with(|armed| armed.get().is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prune_hours_round_up_and_the_prune_never_deletes_early() {
        assert_eq!(prune_after_hour(0), 0);
        assert_eq!(prune_after_hour(1), 1);
        assert_eq!(prune_after_hour(HOUR_MS), 1);
        assert_eq!(prune_after_hour(HOUR_MS + 1), 2);
        for expires in [1, HOUR_MS - 1, HOUR_MS, 5 * HOUR_MS + 17] {
            // Deleted by the hour only once the exact expiry has passed.
            for now in [expires - 1, expires, expires + HOUR_MS] {
                if prune_after_hour(expires) <= hour_of(now) {
                    assert!(expires <= now, "{expires} pruned at {now}");
                }
            }
        }
    }

    #[test]
    fn version_shape_and_header() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.sqlite");
        let mut conn = dedicated(&path).unwrap();
        conn.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE t (kh_x BLOB);")
            .unwrap();
        assert_eq!(shape(&conn, "t", "kh_x").unwrap(), Shape::Keyed);
        assert_eq!(shape(&conn, "t", "kh_y").unwrap(), Shape::Clear);
        assert_eq!(shape(&conn, "u", "kh_x").unwrap(), Shape::Missing);
        assert_eq!(recorded(&conn, "s").unwrap(), None);
        record(&conn, "s", 2, true).unwrap();
        assert_eq!(recorded(&conn, "s").unwrap(), Some((2, true)));
        assert_eq!(user_version(&conn).unwrap(), 2);
        conn.pragma_update(None, "user_version", 1).unwrap();
        restamp(&mut conn, "s", 2).unwrap();
        assert_eq!(user_version(&conn).unwrap(), 2);
        assert_eq!(recorded(&conn, "s").unwrap(), Some((2, true)));
        crate::paths::checkpoint_truncate(&conn).unwrap();
        assert_eq!(header_user_version(&path), Some(2));
        assert!(scrub_pending(&path, "s"));
        assert_eq!(
            finish_scrub(&path, "s", &|_| None).unwrap(),
            Some(true),
            "nothing in the way"
        );
        assert!(!scrub_pending(&path, "s"));
        assert_eq!(finish_scrub(&path, "s", &|_| None).unwrap(), None);
        assert_eq!(header_user_version(&dir.path().join("none")), None);
    }

    #[test]
    fn a_vacuum_with_a_reader_in_the_way_stays_pending() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.sqlite");
        let conn = dedicated(&path).unwrap();
        conn.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE t (x BLOB);")
            .unwrap();
        record(&conn, "s", 2, true).unwrap();
        let reader = Connection::open(&path).unwrap();
        reader
            .execute_batch("BEGIN; SELECT COUNT(*) FROM t;")
            .unwrap();
        assert!(!scrub(&conn, "s", &|_| None).unwrap().complete);
        assert!(scrub_pending(&path, "s"));
        reader.execute_batch("COMMIT;").unwrap();
        assert_eq!(finish_scrub(&path, "s", &|_| None).unwrap(), Some(true));
        // Too little space: not even started.
        record(&conn, "s", 2, true).unwrap();
        assert!(!scrub(&conn, "s", &|_| Some(1)).unwrap().complete);
        assert!(scrub_pending(&path, "s"));
    }
}
