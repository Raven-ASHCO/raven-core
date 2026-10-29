//! Shared Raven data-dir and LAN bind defaults for ash and raven-node.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Default LAN listener for `raven-node service` (reachable from other LAN hosts).
/// Phase 6b P6.36: a profile that picked a random port
/// ([`crate::node_policy::profile_lan_port`]) listens there instead; this one
/// stays for every existing profile.
pub const DEFAULT_LAN_LISTEN: &str = "0.0.0.0:7420";
/// [`DEFAULT_LAN_LISTEN`]'s port: what ash suggests and shows, and the port the
/// cutoff pack guesses for a contact whose own port is unknown (F7).
pub const DEFAULT_LAN_PORT: u16 = 7420;
/// `--lan-listen auto` (Phase 3, D7): every interface, IPv4 and IPv6, local
/// sources only, while [`crate::lan_gate::LAN_AUTO_LISTEN_PRODUCTION_ENABLED`]
/// is live; until then it means `0.0.0.0:<port>`.
pub const LAN_LISTEN_AUTO: &str = "auto";
/// Mock BLE stays loopback-only.
pub const DEFAULT_BLE_LISTEN: &str = "127.0.0.1:7421";
/// Port of the (opt-in, lab-gated) Internet-direct listener: distinct from LAN
/// direct (7420) and mock BLE (7421). Transports design 2026-10 §3.6.
pub const DEFAULT_INTERNET_PORT: u16 = 7422;
/// Reserved for the libp2p host (TCP + QUIC), transports design §3.6.
pub const DEFAULT_P2P_PORT: u16 = 7423;
/// Ports RAVEN itself uses besides LAN direct (mock BLE, Internet direct,
/// libp2p, the friend relay): never suggest one of them as a LAN listener for
/// a second profile.
pub const RESERVED_RAVEN_PORTS: [u16; 4] = [
    7421,
    DEFAULT_INTERNET_PORT,
    DEFAULT_P2P_PORT,
    crate::p2p_route::FRIEND_RELAY_PORT,
];
/// Shared device_id for the local cert + prekey on this node.
pub const PRIMARY_DEVICE_ID: &str = "ash-primary";
/// Per-profile log the auto-started `raven-node service` writes its stdout and
/// stderr to (0600, in the data dir; `ash` creates it).
pub const SERVICE_LOG_NAME: &str = "raven-node-service.log";
/// The security ledger (Phase 6b P6.23, [`crate::security_ledger`]): keyed
/// and sealed, only in a sealed profile and only while security events are
/// live.
pub const SECURITY_LEDGER_FILE: &str = "security_events.sqlite";

/// A `--lan-listen` setting ([`parse_lan_listen`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LanListen {
    /// [`LAN_LISTEN_AUTO`] on `port` ([`DEFAULT_LAN_PORT`] unless `auto:PORT`).
    Auto { port: u16 },
    /// Any other value, kept as given (surrounding blanks removed): the
    /// listener parses it when it binds (`[fe80::1%en0]:7420`, whose named
    /// zone [`crate::netifs::scoped_v6_socket`] reads, and port 0 for tests
    /// included).
    Fixed(String),
}

/// A `--lan-listen` value: `auto` or `auto:PORT` (port 1-65535, either case)
/// is [`LanListen::Auto`]; anything else is [`LanListen::Fixed`]. Blank, or
/// `auto:` with no valid port, is an error that says what is expected.
pub fn parse_lan_listen(raw: &str) -> Result<LanListen, String> {
    let s = raw.trim();
    let expected = || {
        format!(
            "LAN listen address must be IP:PORT (e.g. 0.0.0.0:{DEFAULT_LAN_PORT}), \
             \"{LAN_LISTEN_AUTO}\" or \"{LAN_LISTEN_AUTO}:PORT\" (port 1-65535); got \"{}\"",
            crate::sanitize::sanitize_terminal_line(s)
        )
    };
    if s.is_empty() {
        return Err(expected());
    }
    if s.eq_ignore_ascii_case(LAN_LISTEN_AUTO) {
        return Ok(LanListen::Auto {
            port: DEFAULT_LAN_PORT,
        });
    }
    let auto_port = s
        .get(..LAN_LISTEN_AUTO.len() + 1)
        .filter(|head| head.eq_ignore_ascii_case("auto:"))
        .map(|head| &s[head.len()..]);
    match auto_port {
        Some(port) => match port.parse::<u16>() {
            Ok(port) if port != 0 => Ok(LanListen::Auto { port }),
            _ => Err(expected()),
        },
        None => Ok(LanListen::Fixed(s.to_owned())),
    }
}

/// A `--lan-listen` value for the profile whose picked port is `chosen`
/// (Phase 6b P6.36, [`crate::node_policy::profile_lan_port`]): a bare
/// [`LAN_LISTEN_AUTO`], which names no port, becomes `auto:<chosen>`; a value
/// that names its port (`auto:PORT`, IP:PORT) and any value without `chosen`
/// is kept as given.
pub fn profile_lan_listen(raw: &str, chosen: Option<u16>) -> String {
    match chosen {
        Some(port) if raw.trim().eq_ignore_ascii_case(LAN_LISTEN_AUTO) => {
            format!("{LAN_LISTEN_AUTO}:{port}")
        }
        _ => raw.to_owned(),
    }
}

/// An `auto` LAN listener accepts a connection only from a local source:
/// loopback, private (RFC 1918), link-local or unique-local
/// ([`crate::outbox::is_local_network_ip`]), or an address `on_link` says is
/// on one of this computer's networks. 100.64.0.0/10 (CGNAT, Tailscale) is
/// not local (owner decision): such peers keep an explicit
/// `--lan-listen 0.0.0.0:7420`, which accepts any source.
pub fn lan_source_is_local(ip: IpAddr, on_link: impl Fn(IpAddr) -> bool) -> bool {
    crate::outbox::is_local_network_ip(ip) || on_link(ip)
}

/// Final path component of the placeholder returned by the infallible
/// resolvers when no profile directory can be determined.
pub const UNRESOLVED_DATA_DIR_NAME: &str = "RAVEN_DATA_DIR-unresolved-set-HOME-or-RAVEN_DATA_DIR";

/// Placeholder for "no profile directory could be determined". It is absolute
/// and sits under a path that no process can create (a child of `/dev/null`,
/// or of the NUL device on Windows), so using it can only fail. It must never
/// degrade into a working-directory-relative profile, which would silently give
/// every working directory its own identity, history and queue.
fn unresolved_data_dir() -> PathBuf {
    #[cfg(unix)]
    let base = PathBuf::from("/dev/null");
    #[cfg(not(unix))]
    let base = PathBuf::from(r"\\.\NUL");
    base.join(UNRESOLVED_DATA_DIR_NAME)
}

/// True for the placeholder returned when the profile directory is unresolved.
pub fn is_unresolved_data_dir(dir: &Path) -> bool {
    dir.components()
        .any(|c| c.as_os_str() == UNRESOLVED_DATA_DIR_NAME)
}

fn unresolved_data_dir_error() -> String {
    "cannot determine the Raven data directory: set RAVEN_DATA_DIR (or ASH_DATA_DIR), \
     pass --data-dir, or set HOME"
        .to_string()
}

/// Only an absolute home is usable. An empty or relative `HOME` would make the
/// default profile depend on the working directory.
fn usable_home(p: Option<PathBuf>) -> Option<PathBuf> {
    p.filter(|p| p.is_absolute())
}

/// Home directory from the environment: `HOME`, then on Windows `USERPROFILE`,
/// then `HOMEDRIVE` + `HOMEPATH` (plain `cmd` / PowerShell sessions set no `HOME`).
fn home_dir_from_env() -> Option<PathBuf> {
    let var = |key: &str| std::env::var_os(key).map(PathBuf::from);
    #[cfg(not(windows))]
    {
        usable_home(var("HOME"))
    }
    #[cfg(windows)]
    {
        usable_home(var("HOME"))
            .or_else(|| usable_home(var("USERPROFILE")))
            .or_else(|| {
                let (drive, path) = (var("HOMEDRIVE")?, var("HOMEPATH")?);
                usable_home(Some(PathBuf::from(format!(
                    "{}{}",
                    drive.display(),
                    path.display()
                ))))
            })
    }
}

/// Resolve the shared Raven profile directory.
///
/// Order: `RAVEN_DATA_DIR`, else `ASH_DATA_DIR`, else if `~/.raven-ash` exists
/// and `~/.raven` does not keep the legacy ash dir, else `~/.raven`.
///
/// When none of those can be determined (no override and no usable home) the
/// result is an unusable placeholder (see [`is_unresolved_data_dir`]) so the
/// first use fails with a clear error instead of creating a working-directory
/// relative profile. Callers that can report an error up front should use
/// [`try_default_raven_data_dir`].
pub fn default_raven_data_dir() -> PathBuf {
    try_default_raven_data_dir().unwrap_or_else(|_| unresolved_data_dir())
}

/// [`default_raven_data_dir`], but an undeterminable directory is an error.
pub fn try_default_raven_data_dir() -> Result<PathBuf, String> {
    try_resolve_raven_data_dir(
        std::env::var_os("RAVEN_DATA_DIR").map(PathBuf::from),
        std::env::var_os("ASH_DATA_DIR").map(PathBuf::from),
        home_dir_from_env(),
    )
}

/// Infallible form of [`try_resolve_raven_data_dir`]; the unresolved case
/// yields the unusable placeholder (see [`default_raven_data_dir`]).
pub fn resolve_raven_data_dir(
    raven_data_dir: Option<PathBuf>,
    ash_data_dir: Option<PathBuf>,
    home: Option<PathBuf>,
) -> PathBuf {
    try_resolve_raven_data_dir(raven_data_dir, ash_data_dir, home)
        .unwrap_or_else(|_| unresolved_data_dir())
}

pub fn try_resolve_raven_data_dir(
    raven_data_dir: Option<PathBuf>,
    ash_data_dir: Option<PathBuf>,
    home: Option<PathBuf>,
) -> Result<PathBuf, String> {
    if let Some(p) = nonempty(raven_data_dir) {
        return Ok(p);
    }
    if let Some(p) = nonempty(ash_data_dir) {
        return Ok(p);
    }
    let Some(home) = usable_home(home) else {
        return Err(unresolved_data_dir_error());
    };
    let raven = home.join(".raven");
    let raven_ash = home.join(".raven-ash");
    if raven_ash.is_dir() && !raven.exists() {
        return Ok(raven_ash);
    }
    Ok(raven)
}

fn nonempty(p: Option<PathBuf>) -> Option<PathBuf> {
    p.filter(|p| !p.as_os_str().is_empty())
}

/// Refuse the unresolved-profile placeholder before anything is created.
///
/// Entry points that resolved their profile through the infallible resolvers
/// (a clap default, say) call this once up front, so the user gets the
/// explanatory error instead of whichever store happens to fail first with
/// `Not a directory`.
pub fn require_resolved_data_dir(dir: &Path) -> Result<(), String> {
    if is_unresolved_data_dir(dir) {
        return Err(unresolved_data_dir_error());
    }
    Ok(())
}

fn reject_unresolved_dir(dir: &Path) -> Result<(), String> {
    require_resolved_data_dir(dir)
}

/// Create the Raven data directory (and any missing parents) owner-only
/// (0700) on Unix, and strip group/other access from an existing one. On
/// Windows the same with a protected DACL that allows only the current user
/// (inherited by everything created inside; see `win_acl`).
///
/// Only for the data directory itself (and directories Raven owns inside it);
/// never for caller-chosen locations such as export destinations or a
/// `--forward-db` parent. Fails closed when the mode cannot be restricted,
/// rather than keeping private state in a shared dir.
pub fn ensure_private_dir(dir: &Path) -> Result<(), String> {
    reject_unresolved_dir(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| e.to_string())?;
        let metadata = std::fs::metadata(dir).map_err(|e| e.to_string())?;
        if !metadata.is_dir() {
            return Err(format!("{} is not a directory", dir.display()));
        }
        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode & 0o7700))
                .map_err(|e| format!("cannot restrict {} to owner-only: {e}", dir.display()))?;
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        create_dirs_owner_only(dir)?;
        let metadata = std::fs::metadata(dir).map_err(|e| e.to_string())?;
        if !metadata.is_dir() {
            return Err(format!("{} is not a directory", dir.display()));
        }
        crate::win_acl::restrict_path(dir, crate::win_acl::Kind::Dir)
    }
    #[cfg(not(any(unix, windows)))]
    {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())
    }
}

/// Create missing parents of a private file owner-only, without touching the
/// mode (or, on Windows, the ACL) of directories that already exist (they may
/// be user-chosen).
fn create_private_parents(parent: &Path) -> Result<(), String> {
    reject_unresolved_dir(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .map_err(|e| e.to_string())
    }
    #[cfg(windows)]
    {
        create_dirs_owner_only(parent)
    }
    #[cfg(not(any(unix, windows)))]
    {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())
    }
}

/// Windows `DirBuilder::mode(0o700).recursive(true)`: create `dir` and its
/// missing parents, then give each directory this call created (outermost
/// first) the owner-only DACL. Directories that already existed are left
/// alone. A new directory is empty until its DACL is set.
#[cfg(windows)]
fn create_dirs_owner_only(dir: &Path) -> Result<(), String> {
    let mut missing = Vec::new();
    let mut cursor = Some(dir);
    while let Some(p) = cursor.filter(|p| !p.as_os_str().is_empty()) {
        if p.exists() {
            break;
        }
        missing.push(p.to_path_buf());
        cursor = p.parent();
    }
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    for created in missing.iter().rev() {
        crate::win_acl::restrict_path(created, crate::win_acl::Kind::Dir)?;
    }
    Ok(())
}

/// Non-Unix: create `path` exclusively. On Windows it is opened unshared and
/// gets the owner-only DACL before the caller writes anything.
#[cfg(not(unix))]
fn open_new_private(path: &Path) -> Result<std::fs::File, String> {
    #[cfg(windows)]
    {
        crate::win_acl::create_new_owner_only(path)
    }
    #[cfg(not(windows))]
    {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| e.to_string())
    }
}

/// A Windows error code from an ACL read or write that says the file is
/// gone (`ERROR_FILE_NOT_FOUND` 2, `ERROR_PATH_NOT_FOUND` 3): another program
/// removed it meanwhile (`win_acl::restrict_path_if_present`).
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn acl_error_means_gone(code: u32) -> bool {
    matches!(code, 2 | 3)
}

/// The words when a file or folder cannot be made owner-only on Windows:
/// the FAT32 / exFAT hint only when its volume keeps no ACLs
/// (`volume_acls == Some(false)`); an NTFS volume, or one Windows says
/// nothing about, gets the reason alone (E2 r9: the hint was wrong on NTFS).
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn owner_only_refusal(path: &str, why: &str, volume_acls: Option<bool>) -> String {
    let hint = if volume_acls == Some(false) {
        " (this drive keeps no file permissions, as FAT32 and exFAT drives do not, so it cannot \
         hold a Raven profile: use an NTFS drive)"
    } else {
        ""
    };
    format!("cannot restrict {path} to owner-only: {why}{hint}")
}

#[cfg(any(unix, windows))]
fn sqlite_sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

/// Prepare a SQLite database at a path the caller may have chosen
/// (`raven-node ipc --forward-db <path>`): missing parent directories are
/// created owner-only (0700), but an existing parent is never chmod-ed (it may
/// be `~/Documents`, a shared project dir or `/tmp`, and tightening it would
/// break whatever else lives there). The database plus any existing `-wal` /
/// `-shm` / `-journal` sidecars become 0600 on Unix, and the database file is
/// created 0600 *before* SQLite opens it, so SQLite (which gives new sidecars
/// the database file's mode) never creates world-readable files. On Windows
/// the database and its existing sidecars get the owner-only file DACL; a
/// sidecar SQLite creates later inherits its directory's ACL (owner-only in
/// the data dir and in any parent created here).
///
/// A database that lives directly in the Raven data dir uses
/// [`prepare_private_data_dir_sqlite_file`], which also locks the directory.
pub fn prepare_private_sqlite_file(path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        create_private_parents(parent)?;
    }
    restrict_private_sqlite_files(path)
}

/// [`prepare_private_sqlite_file`] for a database inside the Raven data dir
/// (its parent *is* the profile directory): the data dir is created 0700 or, if
/// it already exists, stripped of group/other access, failing closed when that
/// is not possible.
pub fn prepare_private_data_dir_sqlite_file(path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        // An unfinished erase (privacy pack PP.16) closed the profile: no
        // Raven lock or store opens in it, so no process writes a file again
        // (or mints K_hist under the key-init lock) while it is emptied.
        crate::erase::refuse_if_unfinished(parent)?;
        ensure_private_dir(parent)?;
    }
    restrict_private_sqlite_files(path)
}

fn restrict_private_sqlite_files(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
        {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.to_string()),
        }
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let candidate = sqlite_sidecar(path, suffix);
            let metadata = match std::fs::symlink_metadata(&candidate) {
                Ok(metadata) => metadata,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e.to_string()),
            };
            if !metadata.file_type().is_file() {
                return Err(format!(
                    "{} is not a regular file; refusing to open private database",
                    candidate.display()
                ));
            }
            if metadata.permissions().mode() & 0o077 != 0 {
                match std::fs::set_permissions(&candidate, std::fs::Permissions::from_mode(0o600)) {
                    Ok(()) => {}
                    // A sidecar SQLite removed concurrently needs no chmod.
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e.to_string()),
                }
            }
        }
    }
    #[cfg(windows)]
    {
        match std::fs::symlink_metadata(path) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Owner-only before SQLite opens it; a concurrent creator
                // wins the race, and its file is restricted below.
                if let Err(e) = open_new_private(path) {
                    if std::fs::symlink_metadata(path).is_err() {
                        return Err(e);
                    }
                }
            }
            Err(e) => return Err(e.to_string()),
        }
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let candidate = sqlite_sidecar(path, suffix);
            let metadata = match std::fs::symlink_metadata(&candidate) {
                Ok(metadata) => metadata,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e.to_string()),
            };
            if !metadata.file_type().is_file() {
                return Err(format!(
                    "{} is not a regular file; refusing to open private database",
                    candidate.display()
                ));
            }
            // A sidecar SQLite removed concurrently needs no ACL, even when
            // it is there again a moment later (another connection's next
            // transaction): that one inherits the folder's (E2 r9).
            crate::win_acl::restrict_path_if_present(&candidate, crate::win_acl::Kind::File)?;
        }
    }
    #[cfg(not(any(unix, windows)))]
    let _ = path;
    Ok(())
}

fn open_prepared_sqlite(
    path: &Path,
    prepare: fn(&Path) -> Result<(), String>,
) -> rusqlite::Result<rusqlite::Connection> {
    prepare(path).map_err(|message| {
        rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CANTOPEN),
            Some(message),
        )
    })?;
    rusqlite::Connection::open(path)
}

/// [`prepare_private_sqlite_file`] then `Connection::open`.
pub fn open_private_sqlite(path: &Path) -> rusqlite::Result<rusqlite::Connection> {
    open_prepared_sqlite(path, prepare_private_sqlite_file)
}

/// [`prepare_private_data_dir_sqlite_file`] then `Connection::open`.
pub fn open_private_data_dir_sqlite(path: &Path) -> rusqlite::Result<rusqlite::Connection> {
    open_prepared_sqlite(path, prepare_private_data_dir_sqlite_file)
}

/// Every Raven SQLite store calls this right after open (privacy pack PP.2):
/// deleted rows, the space a shrinking row leaves and freed pages are then
/// overwritten with zeros instead of staying readable in the file.
///
/// `secure_delete` is a per-connection setting and the bundled SQLite is not
/// built with `SQLITE_SECURE_DELETE`, so every connection that can delete
/// needs it. The file format is unchanged: older builds open the files as
/// before. Lock databases (`DataDirLock`, `*.lock.sqlite`,
/// `prekey_lifecycle.sqlite`) hold nothing and skip it. Pages freed before a
/// store was first opened this way stay on its freelist until a `VACUUM`.
pub fn harden_sqlite(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    conn.execute_batch("PRAGMA secure_delete=ON;")
}

/// What [`checkpoint_truncate`] did: the row of `PRAGMA wal_checkpoint(TRUNCATE)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checkpoint {
    /// Another connection was in the way (a reader on an older snapshot, or
    /// a writer): the WAL was not emptied, and what a delete overwrote may
    /// not have reached the main file yet. A later pass completes it.
    pub busy: bool,
    /// Frames in the WAL (0 once it was emptied; -1 when the database is not
    /// in WAL mode).
    pub log: i64,
    /// Frames moved into the main file (as `log`).
    pub checkpointed: i64,
}

impl Checkpoint {
    /// Everything reached the main file and the WAL is empty.
    pub fn completed(&self) -> bool {
        !self.busy
    }
}

/// The longest [`checkpoint_truncate`] waits for other connections. A
/// TRUNCATE checkpoint holds the write lock while it waits for readers, so it
/// never waits a store's whole busy timeout: writers would stall behind it.
const CHECKPOINT_WAIT: Duration = Duration::from_millis(250);

/// After a bulk delete in WAL mode (PP.2): moves what the delete overwrote
/// into the main file and empties the WAL.
///
/// Callers never assume it completed: while another connection holds a read
/// snapshot (raven-node and the ash chat poller keep connections open) it is
/// [`Checkpoint::busy`], and the caller's next prune pass checkpoints again.
/// It waits at most [`CHECKPOINT_WAIT`] (or the connection's own shorter busy
/// timeout), then restores the connection's timeout. Run it outside a
/// transaction.
///
/// It cleans what the filesystem shows (a copied data dir, a later backup).
/// The old WAL frames and freed pages stay in freed disk blocks until they are
/// overwritten; only key rotation (PP.10) and full-disk encryption cover those.
pub fn checkpoint_truncate(conn: &rusqlite::Connection) -> rusqlite::Result<Checkpoint> {
    // 0 is no timeout or a custom busy handler: left as it is.
    let own_ms: i64 = conn.query_row("PRAGMA busy_timeout", [], |row| row.get(0))?;
    let own = Duration::from_millis(u64::try_from(own_ms).unwrap_or(0));
    let shortened = own > CHECKPOINT_WAIT;
    if shortened {
        conn.busy_timeout(CHECKPOINT_WAIT)?;
    }
    let checkpoint = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
        Ok(Checkpoint {
            busy: row.get::<_, i64>(0)? != 0,
            log: row.get(1)?,
            checkpointed: row.get(2)?,
        })
    });
    if shortened {
        conn.busy_timeout(own)?;
    }
    checkpoint
}

/// Cross-process exclusive lock via a small SQLite file (BEGIN EXCLUSIVE).
/// Holds until dropped. Used for peer-cache / registry RMW that must not race.
pub struct DataDirLock {
    _connection: rusqlite::Connection,
    _held: HeldMark,
}

#[cfg(debug_assertions)]
thread_local! {
    static HELD_LOCKS: std::sync::Arc<std::sync::atomic::AtomicUsize> =
        std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
}

/// Counts, in debug builds, the Raven cross-process locks a thread holds
/// ([`DataDirLock`] and the chat-history locks) and the store transactions it
/// is inside, while it lives (privacy pack PP.3, review R13):
/// `at_rest::keys_load`, the one at-rest function that may call the keystore
/// (and so wait on a macOS dialog), asserts the count is zero. The count stays
/// with the acquiring thread even when the lock is dropped on another one (a
/// lock held across an `.await`). Release builds keep nothing.
pub(crate) struct HeldMark {
    #[cfg(debug_assertions)]
    counter: Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>,
}

impl HeldMark {
    pub(crate) fn new() -> Self {
        #[cfg(debug_assertions)]
        {
            use std::sync::atomic::Ordering;
            let counter = HELD_LOCKS
                .try_with(|count| {
                    count.fetch_add(1, Ordering::SeqCst);
                    std::sync::Arc::clone(count)
                })
                .ok();
            Self { counter }
        }
        #[cfg(not(debug_assertions))]
        Self {}
    }

    /// Held next to a Raven store's SQLite transaction, for as long as it
    /// may be open.
    pub(crate) fn transaction() -> Self {
        Self::new()
    }
}

impl Drop for HeldMark {
    fn drop(&mut self) {
        #[cfg(debug_assertions)]
        if let Some(count) = &self.counter {
            count.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

/// Whether the calling thread holds a Raven data-dir lock or is inside a
/// store transaction ([`HeldMark`]). Always `false` in a release build.
pub(crate) fn thread_holds_raven_lock() -> bool {
    #[cfg(debug_assertions)]
    {
        HELD_LOCKS
            .try_with(|count| count.load(std::sync::atomic::Ordering::SeqCst) > 0)
            .unwrap_or(false)
    }
    #[cfg(not(debug_assertions))]
    {
        false
    }
}

/// How long [`DataDirLock::acquire`] waits for another holder.
const DATA_DIR_LOCK_WAIT: Duration = Duration::from_secs(10);

impl DataDirLock {
    pub fn acquire(data_dir: &Path, lock_file_name: &str) -> Result<Self, String> {
        Self::acquire_within(data_dir, lock_file_name, DATA_DIR_LOCK_WAIT)
    }

    /// [`Self::acquire`] with a caller-chosen wait, for locks whose holders
    /// legitimately keep them longer than the 10 s default (a send that is
    /// waiting on the network, say). Same lock file and same failure text.
    pub fn acquire_within(
        data_dir: &Path,
        lock_file_name: &str,
        wait: Duration,
    ) -> Result<Self, String> {
        // Creates/tightens the owner-only data dir, then a 0600 lock file.
        let path = data_dir.join(lock_file_name);
        let connection = open_private_data_dir_sqlite(&path).map_err(|e| e.to_string())?;
        connection.busy_timeout(wait).map_err(|e| e.to_string())?;
        connection
            .execute_batch("BEGIN EXCLUSIVE")
            .map_err(|e| format!("data-dir lock {lock_file_name}: {e}"))?;
        Ok(Self {
            _connection: connection,
            _held: HeldMark::new(),
        })
    }

    /// [`Self::acquire_within`] of a lock file that exists already: `None`
    /// when there is none, and none is created (privacy pack PP.6: an older
    /// build's per-friend lock name is taken while it exists, never made).
    /// Same failure text as [`Self::acquire_within`].
    pub fn acquire_existing_within(
        data_dir: &Path,
        lock_file_name: &str,
        wait: Duration,
    ) -> Result<Option<Self>, String> {
        let path = data_dir.join(lock_file_name);
        match std::fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_file() => {}
            Ok(_) => {
                return Err(format!(
                    "data-dir lock {lock_file_name}: not a regular file"
                ))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("data-dir lock {lock_file_name}: {e}")),
        }
        let flags =
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let connection = match rusqlite::Connection::open_with_flags(&path, flags) {
            Ok(connection) => connection,
            // Removed in between (its holder let it go and deleted it).
            Err(_) if std::fs::symlink_metadata(&path).is_err() => return Ok(None),
            Err(e) => return Err(format!("data-dir lock {lock_file_name}: {e}")),
        };
        connection
            .busy_timeout(wait)
            .map_err(|e| format!("data-dir lock {lock_file_name}: {e}"))?;
        connection
            .execute_batch("BEGIN EXCLUSIVE")
            .map_err(|e| format!("data-dir lock {lock_file_name}: {e}"))?;
        Ok(Some(Self {
            _connection: connection,
            _held: HeldMark::new(),
        }))
    }
}

/// Temp name for [`atomic_write_private`]. It must never depend on the file
/// contents (often secret key material): a directory listing would otherwise
/// leak secret bits. The suffix is 64 bits from the OS CSPRNG.
fn private_temp_path(parent: &Path, path: &Path) -> PathBuf {
    use rand::RngCore;
    parent.join(format!(
        ".{}.tmp.{:016x}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("raven"),
        rand::rngs::OsRng.next_u64()
    ))
}

/// Flush a directory entry after a rename or create has already committed.
///
/// Best effort on purpose, and the single policy for every atomic writer: the
/// new file is complete and in place by now, so a failing directory fsync (a
/// filesystem that cannot fsync a directory, such as some SMB / exFAT / FUSE
/// mounts) must not turn a finished write into a reported failure that callers
/// then retry forever. The file's own contents were fsynced before the rename,
/// so the worst case after a crash is the previous complete file, never a torn
/// one. A no-op on non-Unix targets.
pub fn sync_dir_best_effort(dir: &Path) {
    #[cfg(unix)]
    if let Ok(handle) = std::fs::File::open(dir) {
        let _ = handle.sync_all();
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// Atomically replace `path` (temp + rename) with owner-only mode on Unix.
/// On Windows the temp file is created exclusively and unshared, gets the
/// owner-only DACL before anything is written, is synced, then renamed over
/// the destination (MoveFileEx REPLACE_EXISTING; the DACL moves with it) —
/// never a torn partial write.
pub fn atomic_write_private(path: &Path, contents: &[u8]) -> Result<(), String> {
    atomic_write_private_verified(path, contents, |_| Ok(()))
}

/// [`atomic_write_private`] that hands the complete, synced temp file to
/// `verify` before the rename (privacy pack PP.3: a sealed file must open to
/// exactly the bytes it replaces). An `Err` from `verify` removes the temp
/// file and leaves `path` as it was.
pub(crate) fn atomic_write_private_verified(
    path: &Path,
    contents: &[u8],
    verify: impl FnOnce(&Path) -> Result<(), String>,
) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "atomic write: missing parent".to_string())?;
    create_private_parents(parent)?;
    let tmp = private_temp_path(parent, path);

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let write = (|| -> Result<(), String> {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)
                .map_err(|e| e.to_string())?;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|e| e.to_string())?;
            f.write_all(contents).map_err(|e| e.to_string())?;
            f.sync_all().map_err(|e| e.to_string())?;
            Ok(())
        })()
        .and_then(|()| verify(&tmp));
        if let Err(e) = write {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        if let Err(e) = std::fs::rename(&tmp, path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e.to_string());
        }
        sync_dir_best_effort(parent);
        Ok(())
    }
    #[cfg(not(unix))]
    {
        use std::io::Write;
        // The unshared handle closes at the end of the closure, before `verify`
        // opens the file.
        let write = (|| -> Result<(), String> {
            let mut f = open_new_private(&tmp)?;
            f.write_all(contents).map_err(|e| e.to_string())?;
            f.sync_all().map_err(|e| e.to_string())?;
            Ok(())
        })()
        .and_then(|()| verify(&tmp));
        if let Err(e) = write {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        if let Err(e) = std::fs::rename(&tmp, path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e.to_string());
        }
        Ok(())
    }
}

/// Create `path` exclusively with owner-only mode on Unix (the owner-only DACL
/// on Windows, set before anything is written). Fails when the file already
/// exists. First-install writes of secret material must use this — never a
/// replace-capable write.
pub fn create_new_private(path: &Path, contents: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "create-new write: missing parent".to_string())?;
    create_private_parents(parent)?;
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| e.to_string())?;
        if let Err(e) = (|| -> Result<(), String> {
            f.set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|e| e.to_string())?;
            f.write_all(contents).map_err(|e| e.to_string())?;
            f.sync_all().map_err(|e| e.to_string())?;
            Ok(())
        })() {
            let _ = std::fs::remove_file(path);
            return Err(e);
        }
        sync_dir_best_effort(parent);
        Ok(())
    }
    #[cfg(not(unix))]
    {
        use std::io::Write;
        let mut f = open_new_private(path)?;
        let written = (|| -> Result<(), String> {
            f.write_all(contents).map_err(|e| e.to_string())?;
            f.sync_all().map_err(|e| e.to_string())?;
            Ok(())
        })();
        // Closed first: an unshared handle would block the removal.
        drop(f);
        if let Err(e) = written {
            let _ = std::fs::remove_file(path);
            return Err(e);
        }
        Ok(())
    }
}

/// Shared by the PP.2 tests of every SQLite store: a random marker written
/// through the store, then looked for in the database file.
#[cfg(test)]
pub(crate) mod scrub_test {
    use std::path::{Path, PathBuf};

    /// 32 random bytes: nothing a store writes on its own.
    pub(crate) fn marker() -> [u8; 32] {
        rand::random()
    }

    fn wal_path(db: &Path) -> PathBuf {
        let mut name = db.as_os_str().to_os_string();
        name.push("-wal");
        PathBuf::from(name)
    }

    /// Whether the main database file holds `marker`, as bytes or as hex.
    pub(crate) fn main_file_holds(db: &Path, marker: &[u8]) -> bool {
        let bytes = std::fs::read(db).expect("the main database file");
        assert!(!bytes.is_empty(), "{} is empty", db.display());
        let hex = hex::encode(marker);
        bytes.windows(marker.len()).any(|window| window == marker)
            || bytes
                .windows(hex.len())
                .any(|window| window.eq_ignore_ascii_case(hex.as_bytes()))
    }

    /// The size of the database's WAL; 0 when there is none.
    pub(crate) fn wal_len(db: &Path) -> u64 {
        std::fs::metadata(wal_path(db)).map_or(0, |meta| meta.len())
    }

    /// `PRAGMA secure_delete` on `conn`.
    pub(crate) fn secure_delete(conn: &rusqlite::Connection) -> i64 {
        conn.query_row("PRAGMA secure_delete", [], |row| row.get(0))
            .unwrap()
    }

    /// Before the delete: a completed checkpoint has put the marker into the
    /// main file, so its absence later means something.
    pub(crate) fn assert_written(conn: &rusqlite::Connection, db: &Path, marker: &[u8]) {
        let checkpoint = super::checkpoint_truncate(conn).unwrap();
        assert!(checkpoint.completed(), "{checkpoint:?}");
        assert!(
            main_file_holds(db, marker),
            "the marker never reached {}",
            db.display()
        );
    }

    /// After the delete and a completed checkpoint: the marker is gone from
    /// the main file and the WAL is empty. An empty WAL proves nothing about
    /// the freed disk blocks its old frames were in (PP.2's honest scope).
    pub(crate) fn assert_scrubbed(db: &Path, marker: &[u8]) {
        assert!(
            !main_file_holds(db, marker),
            "the deleted marker is still readable in {}",
            db.display()
        );
        assert_eq!(wal_len(db), 0, "the WAL was not emptied");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raven_env_wins_over_ash_and_home() {
        let p = resolve_raven_data_dir(
            Some(PathBuf::from("/explicit/raven")),
            Some(PathBuf::from("/explicit/ash")),
            Some(PathBuf::from("/home/u")),
        );
        assert_eq!(p, PathBuf::from("/explicit/raven"));
    }

    #[test]
    fn ash_env_wins_when_raven_env_absent() {
        let p = resolve_raven_data_dir(
            None,
            Some(PathBuf::from("/explicit/ash")),
            Some(PathBuf::from("/home/u")),
        );
        assert_eq!(p, PathBuf::from("/explicit/ash"));
    }

    #[test]
    fn empty_env_values_are_ignored() {
        let home = tempfile::tempdir().unwrap();
        let p = resolve_raven_data_dir(
            Some(PathBuf::from("")),
            Some(PathBuf::from("")),
            Some(home.path().to_path_buf()),
        );
        assert_eq!(p, home.path().join(".raven"));
    }

    #[test]
    fn keeps_existing_raven_ash_when_raven_absent() {
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir(home.path().join(".raven-ash")).unwrap();
        let p = resolve_raven_data_dir(None, None, Some(home.path().to_path_buf()));
        assert_eq!(p, home.path().join(".raven-ash"));
    }

    #[test]
    fn prefers_raven_when_both_exist() {
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir(home.path().join(".raven-ash")).unwrap();
        std::fs::create_dir(home.path().join(".raven")).unwrap();
        let p = resolve_raven_data_dir(None, None, Some(home.path().to_path_buf()));
        assert_eq!(p, home.path().join(".raven"));
    }

    #[test]
    fn defaults_to_raven_when_neither_exists() {
        let home = tempfile::tempdir().unwrap();
        let p = resolve_raven_data_dir(None, None, Some(home.path().to_path_buf()));
        assert_eq!(p, home.path().join(".raven"));
    }

    /// A missing HOME used to resolve to the working-directory-relative
    /// `./raven-data`, silently giving every working directory its own
    /// identity, history and queue.
    #[test]
    fn missing_home_is_never_a_cwd_relative_profile() {
        let p = resolve_raven_data_dir(None, None, None);
        assert!(p.is_absolute(), "{p:?}");
        assert!(is_unresolved_data_dir(&p), "{p:?}");
        let err = try_resolve_raven_data_dir(None, None, None).unwrap_err();
        assert!(
            err.contains("HOME") && err.contains("RAVEN_DATA_DIR"),
            "{err}"
        );
        // The placeholder can never be created or written into.
        let err = ensure_private_dir(&p).unwrap_err();
        assert!(err.contains("RAVEN_DATA_DIR"), "{err}");
        assert!(atomic_write_private(&p.join("x.json"), b"{}").is_err());
        assert!(open_private_sqlite(&p.join("q.sqlite")).is_err());
        assert!(DataDirLock::acquire(&p, ".probe.lock.sqlite").is_err());
    }

    #[test]
    fn empty_or_relative_home_counts_as_missing() {
        for home in [
            PathBuf::from(""),
            PathBuf::from("."),
            PathBuf::from("rel/home"),
        ] {
            let p = resolve_raven_data_dir(None, None, Some(home.clone()));
            assert!(is_unresolved_data_dir(&p), "{home:?} -> {p:?}");
            assert!(try_resolve_raven_data_dir(None, None, Some(home)).is_err());
        }
    }

    #[test]
    fn explicit_data_dir_does_not_need_home() {
        let p = try_resolve_raven_data_dir(Some(PathBuf::from("/explicit/raven")), None, None);
        assert_eq!(p.unwrap(), PathBuf::from("/explicit/raven"));
        let p = try_resolve_raven_data_dir(None, Some(PathBuf::from("/explicit/ash")), None);
        assert_eq!(p.unwrap(), PathBuf::from("/explicit/ash"));
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_is_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("contacts.json");
        atomic_write_private(&path, b"[]").unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(std::fs::read(&path).unwrap(), b"[]");
    }

    #[test]
    fn create_new_private_never_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.seed");
        create_new_private(&path, b"first").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
        assert!(create_new_private(&path, b"second").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"first");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn atomic_temp_names_come_from_csprng_not_contents() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("device_x25519.secret");
        let names: std::collections::HashSet<PathBuf> = (0..64)
            .map(|_| private_temp_path(dir.path(), &target))
            .collect();
        assert_eq!(names.len(), 64, "temp suffixes must be random per call");
        // Same secret written twice leaves no content-derived temp behind.
        atomic_write_private(&target, &[0x42; 32]).unwrap();
        atomic_write_private(&target, &[0x42; 32]).unwrap();
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .filter(|n| n.to_string_lossy().contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    #[cfg(unix)]
    #[test]
    fn data_dir_is_created_and_tightened_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let fresh = root.path().join("a").join("raven");
        ensure_private_dir(&fresh).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&fresh), 0o700);

        let legacy = root.path().join("legacy");
        std::fs::create_dir(&legacy).unwrap();
        std::fs::set_permissions(&legacy, std::fs::Permissions::from_mode(0o755)).unwrap();
        let _lock = DataDirLock::acquire(&legacy, ".probe.lock.sqlite").unwrap();
        assert_eq!(
            mode(&legacy),
            0o700,
            "existing data dir must lose group/other access"
        );
        assert_eq!(mode(&legacy.join(".probe.lock.sqlite")), 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_never_chmods_an_existing_user_chosen_parent() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let export_dir = root.path().join("Desktop");
        std::fs::create_dir(&export_dir).unwrap();
        std::fs::set_permissions(&export_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        atomic_write_private(&export_dir.join("prekey.json"), b"{}").unwrap();
        assert_eq!(
            std::fs::metadata(&export_dir).unwrap().permissions().mode() & 0o777,
            0o755
        );
        let created = root.path().join("new").join("nested");
        atomic_write_private(&created.join("x.json"), b"{}").unwrap();
        assert_eq!(
            std::fs::metadata(&created).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    /// E2 r9 (win-c): a SQLite journal that vanished while its ACL was set
    /// failed the outbox with the FAT32 hint on an NTFS drive. A file that
    /// is gone (os error 2 or 3) is benign; the hint comes only when the
    /// volume keeps no ACLs.
    #[test]
    fn owner_only_refusal_names_fat32_only_for_a_volume_without_acls() {
        assert!(acl_error_means_gone(2) && acl_error_means_gone(3));
        assert!(!acl_error_means_gone(5), "access denied is a real failure");
        assert!(!acl_error_means_gone(0));
        let why = "The system cannot find the file specified. (os error 2)";
        for volume in [Some(true), None] {
            let text = owner_only_refusal(r"C:\p\.lock.sqlite-journal", why, volume);
            assert_eq!(
                text,
                format!(r"cannot restrict C:\p\.lock.sqlite-journal to owner-only: {why}")
            );
            assert!(!text.contains("FAT32"), "{text}");
        }
        let fat = owner_only_refusal(r"E:\raven", "Access is denied. (os error 5)", Some(false));
        assert!(fat.contains("FAT32") && fat.contains("NTFS"), "{fat}");
    }

    #[cfg(unix)]
    #[test]
    fn private_sqlite_database_and_sidecars_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("queue.sqlite");
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        {
            let conn = open_private_sqlite(&path).unwrap();
            conn.execute_batch(
                "PRAGMA journal_mode=WAL; CREATE TABLE t(x); INSERT INTO t VALUES (1);",
            )
            .unwrap();
            assert_eq!(mode(&path), 0o600);
            assert_eq!(mode(&sqlite_sidecar(&path, "-wal")), 0o600);
            assert_eq!(mode(&sqlite_sidecar(&path, "-shm")), 0o600);
        }
        // Files left world-readable by an older build are tightened on open.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let stale_wal = sqlite_sidecar(&path, "-wal");
        if stale_wal.exists() {
            std::fs::set_permissions(&stale_wal, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        let _conn = open_private_sqlite(&path).unwrap();
        assert_eq!(mode(&path), 0o600);
        if stale_wal.exists() {
            assert_eq!(mode(&stale_wal), 0o600);
        }
    }

    /// A database path chosen by the caller (`--forward-db`) must never cost an
    /// existing directory its permissions: not a shared scratch dir (root would
    /// turn /tmp from 1777 into 1700), not a user dir such as `~/Documents` or
    /// a group project dir. Only the data-dir flavour locks its directory.
    #[cfg(unix)]
    #[test]
    fn private_sqlite_never_chmods_an_existing_caller_chosen_parent() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o7777;
        let chmod = |p: &Path, m: u32| {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap()
        };

        for (name, dir_mode) in [
            ("scratch", 0o1777),
            ("Documents", 0o755),
            ("project", 0o775),
        ] {
            let dir = root.path().join(name);
            std::fs::create_dir(&dir).unwrap();
            chmod(&dir, dir_mode);
            drop(open_private_sqlite(&dir.join("fwd.sqlite")).unwrap());
            assert_eq!(mode(&dir), dir_mode, "{name} must be left alone");
            assert_eq!(mode(&dir.join("fwd.sqlite")), 0o600, "{name}");
        }

        // Missing parents are still created owner-only.
        let nested = root.path().join("new").join("dir");
        drop(open_private_sqlite(&nested.join("fwd.sqlite")).unwrap());
        assert_eq!(mode(&nested), 0o700);
        assert_eq!(mode(&root.path().join("new")), 0o700);

        // The data-dir flavour tightens an existing directory, even a shared
        // one: private state must not be kept in a shared directory.
        let shared = root.path().join("scratch");
        chmod(&shared, 0o1777);
        drop(open_private_data_dir_sqlite(&shared.join("lock.sqlite")).unwrap());
        assert_eq!(mode(&shared) & 0o777, 0o700);
        let profile = root.path().join("Documents");
        chmod(&profile, 0o755);
        drop(open_private_data_dir_sqlite(&profile.join("queue.sqlite")).unwrap());
        assert_eq!(mode(&profile), 0o700);
    }

    #[cfg(unix)]
    #[test]
    fn private_sqlite_refuses_symlinked_database() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("elsewhere.sqlite");
        std::fs::write(&real, b"").unwrap();
        let link = dir.path().join("queue.sqlite");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(open_private_sqlite(&link).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_replaces_existing_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        atomic_write_private(&path, b"v1").unwrap();
        atomic_write_private(&path, b"v2-longer").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"v2-longer");
    }

    /// A second profile's LAN listener is never suggested on a port RAVEN
    /// itself uses, the friend relay's 7427 included (ash skips them all).
    #[test]
    fn reserved_ports_hold_the_friend_relay_port() {
        assert_eq!(RESERVED_RAVEN_PORTS, [7421, 7422, 7423, 7427]);
        assert!(RESERVED_RAVEN_PORTS.contains(&crate::p2p_route::FRIEND_RELAY_PORT));
        assert_eq!(DEFAULT_P2P_PORT, crate::p2p_route::DEFAULT_P2P_PORT);
        let lan: std::net::SocketAddr = DEFAULT_LAN_LISTEN.parse().unwrap();
        assert_eq!(lan.port(), DEFAULT_LAN_PORT);
        assert!(!RESERVED_RAVEN_PORTS.contains(&lan.port()));
    }

    /// Phase 3 P3.2: `auto` and `auto:PORT` are the automatic listener;
    /// anything else is kept as given for the listener to bind.
    #[test]
    fn parse_lan_listen_table() {
        let auto = |port| Ok(LanListen::Auto { port });
        let fixed = |s: &str| Ok(LanListen::Fixed(s.into()));
        for (raw, want) in [
            ("auto", auto(7420)),
            (" AUTO ", auto(7420)),
            ("auto:7424", auto(7424)),
            ("Auto:1", auto(1)),
            ("auto:65535", auto(65535)),
            ("0.0.0.0:7420", fixed("0.0.0.0:7420")),
            ("[::]:7420", fixed("[::]:7420")),
            ("[fe80::1%en0]:7420", fixed("[fe80::1%en0]:7420")),
            ("127.0.0.1:0", fixed("127.0.0.1:0")),
            (" 192.168.1.5:7420 ", fixed("192.168.1.5:7420")),
            ("automatic", fixed("automatic")),
        ] {
            assert_eq!(parse_lan_listen(raw), want, "{raw:?}");
        }
        assert_eq!(parse_lan_listen(LAN_LISTEN_AUTO), auto(DEFAULT_LAN_PORT));
        for bad in [
            "",
            "  ",
            "auto:",
            "auto:0",
            "auto:70000",
            "auto:-1",
            "auto:x",
            "auto: 7420",
        ] {
            let err = parse_lan_listen(bad).unwrap_err();
            assert!(
                err.contains("\"auto:PORT\" (port 1-65535)"),
                "{bad:?}: {err}"
            );
        }
    }

    /// Phase 6b P6.36: only a bare `auto` takes the profile's picked port;
    /// a value that names a port, and every value of a profile without one,
    /// stays as given.
    #[test]
    fn profile_lan_listen_table() {
        for (raw, chosen, want) in [
            ("auto", Some(43_210), "auto:43210"),
            (" AUTO ", Some(43_210), "auto:43210"),
            ("auto", None, "auto"),
            ("auto:7424", Some(43_210), "auto:7424"),
            ("0.0.0.0:7420", Some(43_210), "0.0.0.0:7420"),
            ("127.0.0.1:0", Some(43_210), "127.0.0.1:0"),
            ("automatic", Some(43_210), "automatic"),
        ] {
            assert_eq!(profile_lan_listen(raw, chosen), want, "{raw:?} {chosen:?}");
        }
        assert_eq!(
            parse_lan_listen(&profile_lan_listen("auto", Some(43_210))),
            Ok(LanListen::Auto { port: 43_210 })
        );
    }

    /// Phase 3 P3.2: an `auto` listener's source rule. 100.64.0.0/10 is not
    /// local (owner decision); `on_link` adds this computer's own networks.
    #[test]
    fn lan_source_is_local_table() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        for local in [
            "127.0.0.1",
            "::1",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.1.2",
            "169.254.10.20",
            "fe80::1",
            "febf::1",
            "fc00::1",
            "fd12:3456::1",
            "::ffff:192.168.1.2",
        ] {
            assert!(lan_source_is_local(ip(local), |_| false), "{local}");
        }
        for remote in [
            "100.64.0.1",
            "100.127.255.254",
            "8.8.8.8",
            "172.32.0.1",
            "2001:db8::1",
            "fec0::1",
            "::ffff:8.8.8.8",
        ] {
            assert!(!lan_source_is_local(ip(remote), |_| false), "{remote}");
            assert!(lan_source_is_local(ip(remote), |_| true), "{remote}");
            let only = ip(remote);
            assert!(lan_source_is_local(ip(remote), |at| at == only), "{remote}");
        }
        assert!(!lan_source_is_local(ip("100.64.0.1"), |at| at == ip("100.64.0.2")));
    }

    /// A WAL database with one table, its connection hardened, waiting at
    /// most `wait` for other connections.
    fn scrub_db(db: &Path, wait: Duration) -> rusqlite::Connection {
        let conn = open_private_sqlite(db).unwrap();
        conn.busy_timeout(wait).unwrap();
        harden_sqlite(&conn).unwrap();
        conn.execute_batch(
            "PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS t(v BLOB NOT NULL);",
        )
        .unwrap();
        conn
    }

    /// PP.2: the bundled SQLite leaves deleted bytes in place unless a
    /// connection asks otherwise.
    #[test]
    fn harden_sqlite_turns_secure_delete_on() {
        let dir = tempfile::tempdir().unwrap();
        let conn = open_private_sqlite(&dir.path().join("t.sqlite")).unwrap();
        assert_eq!(scrub_test::secure_delete(&conn), 0, "the bundled default");
        harden_sqlite(&conn).unwrap();
        assert_eq!(scrub_test::secure_delete(&conn), 1);
    }

    #[test]
    fn a_deleted_row_leaves_no_bytes_after_checkpoint() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("t.sqlite");
        let conn = scrub_db(&db, Duration::from_secs(5));
        let marker = scrub_test::marker();
        conn.execute("INSERT INTO t VALUES (?1)", [marker.as_slice()])
            .unwrap();
        scrub_test::assert_written(&conn, &db, &marker);
        conn.execute("DELETE FROM t", []).unwrap();
        let checkpoint = checkpoint_truncate(&conn).unwrap();
        assert!(checkpoint.completed(), "{checkpoint:?}");
        assert_eq!((checkpoint.log, checkpoint.checkpointed), (0, 0));
        scrub_test::assert_scrubbed(&db, &marker);
    }

    /// Review R19: a reader holding a snapshot from before the delete keeps
    /// the checkpoint from completing. It says busy (the main file still
    /// holds the bytes), returns without waiting the connection's own busy
    /// timeout, leaves that timeout as it was, and a later pass completes it.
    #[test]
    fn checkpoint_with_an_open_reader_reports_busy_and_a_later_pass_completes() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("t.sqlite");
        let conn = scrub_db(&db, Duration::from_secs(10));
        let marker = scrub_test::marker();
        conn.execute("INSERT INTO t VALUES (?1)", [marker.as_slice()])
            .unwrap();
        scrub_test::assert_written(&conn, &db, &marker);

        let reader = rusqlite::Connection::open(&db).unwrap();
        reader
            .execute_batch("BEGIN; SELECT count(*) FROM t;")
            .unwrap();
        conn.execute("DELETE FROM t", []).unwrap();
        let started = std::time::Instant::now();
        let busy = checkpoint_truncate(&conn).unwrap();
        assert!(busy.busy && !busy.completed(), "{busy:?}");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the checkpoint waited the connection's own busy timeout"
        );
        let own: i64 = conn
            .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
            .unwrap();
        assert_eq!(own, 10_000, "the connection's busy timeout is restored");
        assert!(scrub_test::main_file_holds(&db, &marker));
        assert!(scrub_test::wal_len(&db) > 0);

        reader.execute_batch("COMMIT;").unwrap();
        let done = checkpoint_truncate(&conn).unwrap();
        assert!(done.completed(), "{done:?}");
        scrub_test::assert_scrubbed(&db, &marker);
    }

    /// Why PP.12-PP.14 run one VACUUM per store: pages freed while
    /// secure_delete was off (every prune before PP.2) keep their bytes on
    /// the freelist. Hardening the connection later and checkpointing does
    /// not touch them; VACUUM does.
    #[test]
    fn pages_freed_before_secure_delete_stay_until_vacuum() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("t.sqlite");
        let marker = scrub_test::marker();
        {
            // An older build: no secure_delete. Enough rows to fill whole
            // pages, so the delete frees pages, not only cells.
            let old = open_private_sqlite(&db).unwrap();
            old.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE t(v BLOB NOT NULL);")
                .unwrap();
            let row = [marker.as_slice(), &[0x5A; 96]].concat();
            for _ in 0..128 {
                old.execute("INSERT INTO t VALUES (?1)", [row.as_slice()])
                    .unwrap();
            }
            scrub_test::assert_written(&old, &db, &marker);
            old.execute("DELETE FROM t", []).unwrap();
            assert!(checkpoint_truncate(&old).unwrap().completed());
            assert!(
                scrub_test::main_file_holds(&db, &marker),
                "deleted without secure_delete: still readable"
            );
        }
        let conn = scrub_db(&db, Duration::from_secs(5));
        conn.execute_batch("INSERT INTO t VALUES (x'00'); DELETE FROM t;")
            .unwrap();
        assert!(checkpoint_truncate(&conn).unwrap().completed());
        assert!(
            scrub_test::main_file_holds(&db, &marker),
            "secure_delete does not reach pages freed before it was on"
        );
        conn.execute_batch("VACUUM;").unwrap();
        assert!(checkpoint_truncate(&conn).unwrap().completed());
        scrub_test::assert_scrubbed(&db, &marker);
    }

    /// A connection without a busy timeout (or with its own busy handler)
    /// keeps it: the checkpoint only ever shortens a longer wait.
    #[test]
    fn checkpoint_keeps_a_connection_without_a_busy_timeout_as_it_was() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("t.sqlite");
        let conn = scrub_db(&db, Duration::ZERO);
        assert!(checkpoint_truncate(&conn).unwrap().completed());
        let own: i64 = conn
            .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
            .unwrap();
        assert_eq!(own, 0);
        // Not in WAL mode: nothing to checkpoint, nothing pending.
        let plain = rusqlite::Connection::open_in_memory().unwrap();
        let none = checkpoint_truncate(&plain).unwrap();
        assert!(none.completed(), "{none:?}");
        assert_eq!((none.log, none.checkpointed), (-1, -1));
    }
}
