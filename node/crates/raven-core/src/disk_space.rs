//! Free space on the disk that holds a profile, and the one sentence a user
//! needs when a store fails because that disk is full.
//!
//! SQLite says so plainly only sometimes (`SQLITE_FULL`, "database or disk is
//! full"). When it cannot even create its `-wal` / `-journal` file it reports
//! CANTOPEN or IOERR ("unable to open database file"), and the prekey store
//! folds every SQLite error into a redacted "database failed". Free space is
//! the one signal they all share, so a storage error counts as a full disk when
//! its text says so or when less than [`FULL_BELOW_BYTES`] is free.
//!
//! Diagnostics only: nothing here changes what is stored, sent or refused.

use std::path::Path;

/// A storage failure while less than this is free counts as a full disk (32 MiB).
pub const FULL_BELOW_BYTES: u64 = 32 << 20;
/// Below this `ash doctor` / `ash status` say "low"; it is also the amount the
/// disk-full sentence asks the user to free (512 MiB).
pub const LOW_BELOW_BYTES: u64 = 512 << 20;

/// Bytes this user may still write on the disk that holds `dir`, or `None` when
/// the system does not say. `dir` need not exist yet (a profile before
/// `ash init`): the nearest existing ancestor is asked instead.
pub fn free_bytes(dir: &Path) -> Option<u64> {
    for at in dir.ancestors() {
        // A relative path ends in "": that is the current directory.
        let at = if at.as_os_str().is_empty() {
            Path::new(".")
        } else {
            at
        };
        if at.exists() {
            return os_free_bytes(at);
        }
    }
    None
}

/// Darwin: `statfs`, not `statvfs`, whose 32-bit block counts saturate on a
/// large APFS volume.
#[cfg(any(target_os = "macos", target_os = "ios"))]
fn os_free_bytes(path: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut st = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: `c_path` is NUL-terminated and outlives the call; `st` is a
    // properly sized out-param that is read only after a 0 return.
    if unsafe { libc::statfs(c_path.as_ptr(), st.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: `statfs` returned 0, so it filled `st`.
    let st = unsafe { st.assume_init() };
    st.f_bavail.checked_mul(u64::from(st.f_bsize))
}

/// Other Unix: `statvfs`. `f_bavail`, not `f_bfree`: ext4 keeps 5% for root,
/// which this user cannot write to.
#[cfg(all(unix, not(any(target_os = "macos", target_os = "ios"))))]
// `fsblkcnt_t` and `c_ulong` are 32-bit on some targets and 64-bit on others.
#[allow(clippy::unnecessary_cast)]
fn os_free_bytes(path: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut st = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: `c_path` is NUL-terminated and outlives the call; `st` is a
    // properly sized out-param that is read only after a 0 return.
    if unsafe { libc::statvfs(c_path.as_ptr(), st.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: `statvfs` returned 0, so it filled `st`.
    let st = unsafe { st.assume_init() };
    (st.f_bavail as u64).checked_mul(st.f_frsize as u64)
}

#[cfg(windows)]
fn os_free_bytes(path: &Path) -> Option<u64> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut free_to_caller = 0u64;
    // SAFETY: `wide` is NUL-terminated and outlives the call; the one
    // out-param is a plain local and the other two are optional (null).
    let ok = unsafe {
        GetDiskFreeSpaceExW(
            wide.as_ptr(),
            &mut free_to_caller,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    (ok != 0).then_some(free_to_caller)
}

#[cfg(not(any(unix, windows)))]
fn os_free_bytes(_path: &Path) -> Option<u64> {
    None
}

/// Error text, from SQLite or the OS, that names a full disk or an exhausted
/// quota.
pub fn text_says_disk_full(text: &str) -> bool {
    const MARKERS: [&str; 7] = [
        // SQLITE_FULL
        "database or disk is full",
        // ENOSPC (Linux and macOS)
        "no space left on device",
        // EDQUOT: Linux, then macOS spelling
        "disk quota exceeded",
        "disc quota exceeded",
        // Windows ERROR_DISK_FULL (112), ERROR_HANDLE_DISK_FULL (39)
        "not enough space on the disk",
        "the disk is full",
        // io::ErrorKind::StorageFull without an OS code
        "no storage space",
    ];
    let lower = text.to_ascii_lowercase();
    MARKERS.iter().any(|m| lower.contains(m))
}

/// What happens once space is freed: how the disk-full sentence ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnceFreed {
    /// The service keeps running and tries again by itself (its listeners'
    /// store checks).
    CarriesOn,
    /// Nothing tries again by itself: the command has to run again.
    RunAgain,
    /// The service exited: nothing runs until a command starts it again.
    NotRunning,
}

impl OnceFreed {
    fn text(self) -> &'static str {
        match self {
            Self::CarriesOn => "free some space and raven-node carries on by itself",
            Self::RunAgain => "free some space, then run the command again",
            Self::NotRunning => {
                "free some space, then run the command again (raven-node is not running)"
            }
        }
    }
}

/// The disk-full sentence for a store under `dir` that failed with `detail`,
/// given `free` bytes: `Some` when the text names a full disk or less than
/// [`FULL_BELOW_BYTES`] is free, `None` otherwise (the error is something else).
/// `then` says what freeing space does.
pub fn disk_full_note_given(
    dir: &Path,
    detail: &str,
    free: Option<u64>,
    then: OnceFreed,
) -> Option<String> {
    if !text_says_disk_full(detail) && !free.is_some_and(|b| b < FULL_BELOW_BYTES) {
        return None;
    }
    Some(format!(
        "disk is full{}: RAVEN cannot save to {} until at least {} of free space is available; \
         {}",
        free.map(|b| format!(" (only {} free)", human_bytes(b)))
            .unwrap_or_default(),
        dir.display(),
        human_bytes(LOW_BELOW_BYTES),
        then.text()
    ))
}

/// [`disk_full_note_given`] with the free space measured now.
pub fn disk_full_note(dir: &Path, detail: &str, then: OnceFreed) -> Option<String> {
    disk_full_note_given(dir, detail, free_bytes(dir), then)
}

/// `detail`, followed by the disk-full sentence when it applies. The original
/// text stays first: logs and scripts grep for it. For the running service,
/// which carries on by itself once space is freed.
pub fn with_disk_full_note(dir: &Path, detail: String) -> String {
    match disk_full_note(dir, &detail, OnceFreed::CarriesOn) {
        Some(note) => format!("{detail} \u{2014} {note}"),
        None => detail,
    }
}

/// A size in words people read: whole MB below 1 GB, else GB to one decimal
/// (binary units, the way the OS counts them).
pub fn human_bytes(b: u64) -> String {
    const MIB: u64 = 1 << 20;
    const GIB: u64 = 1 << 30;
    if b < GIB {
        format!("{} MB", (b + MIB / 2) / MIB)
    } else {
        format!("{:.1} GB", b as f64 / GIB as f64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disk_full_text_from_every_layer_is_recognised() {
        assert!(text_says_disk_full("database or disk is full"));
        assert!(text_says_disk_full(
            "indexed session SQLite: Database or disk is full"
        ));
        #[cfg(unix)]
        {
            let enospc = std::io::Error::from_raw_os_error(libc::ENOSPC).to_string();
            assert!(text_says_disk_full(&enospc), "{enospc}");
            let edquot = std::io::Error::from_raw_os_error(libc::EDQUOT).to_string();
            assert!(text_says_disk_full(&edquot), "{edquot}");
        }
        #[cfg(windows)]
        for code in [112, 39] {
            let text = std::io::Error::from_raw_os_error(code).to_string();
            assert!(text_says_disk_full(&text), "{text}");
        }
        let full = std::io::Error::from(std::io::ErrorKind::StorageFull).to_string();
        assert!(text_says_disk_full(&full), "{full}");
        for other in [
            "unable to open database file",
            "prekey lifecycle metadata database failed",
            "connection refused",
        ] {
            assert!(!text_says_disk_full(other), "{other}");
        }
    }

    /// A real SQLITE_FULL without filling the disk: cap the database at 8 pages.
    #[test]
    fn sqlite_full_reports_as_disk_full() {
        let dir = tempfile::tempdir().unwrap();
        let conn = rusqlite::Connection::open(dir.path().join("full.db")).unwrap();
        conn.execute_batch("PRAGMA max_page_count=8; CREATE TABLE t (b BLOB);")
            .unwrap();
        let err = conn
            .execute("INSERT INTO t VALUES (zeroblob(1048576))", [])
            .unwrap_err();
        assert_eq!(
            err.sqlite_error_code(),
            Some(rusqlite::ErrorCode::DiskFull),
            "{err}"
        );
        assert!(text_says_disk_full(&err.to_string()), "{err}");
        let store = crate::IndexedSessionStoreError::Sqlite(err).to_string();
        assert!(text_says_disk_full(&store), "{store}");
    }

    #[test]
    fn cantopen_counts_as_full_only_when_the_disk_is_nearly_full() {
        let dir = Path::new("/profile");
        let cantopen = "indexed session SQLite: unable to open database file";
        let on = OnceFreed::CarriesOn;
        let note = disk_full_note_given(dir, cantopen, Some(1 << 20), on).unwrap();
        assert!(note.contains("disk is full (only 1 MB free)"), "{note}");
        assert!(note.contains("512 MB"), "{note}");
        assert!(note.contains("/profile"), "{note}");
        assert_eq!(
            disk_full_note_given(dir, cantopen, Some(10 << 30), on),
            None
        );
        assert_eq!(disk_full_note_given(dir, cantopen, None, on), None);
        // A quota is full while the disk is not: the text alone decides.
        let quota =
            disk_full_note_given(dir, "database or disk is full", Some(10 << 30), on).unwrap();
        assert!(
            quota.starts_with("disk is full (only 10.0 GB free):"),
            "{quota}"
        );
        let unknown = disk_full_note_given(dir, "database or disk is full", None, on).unwrap();
        assert!(
            unknown.starts_with("disk is full: RAVEN cannot save"),
            "{unknown}"
        );
    }

    #[test]
    fn with_note_keeps_the_original_text_first() {
        let dir = tempfile::tempdir().unwrap();
        let detail = "outbox: database or disk is full".to_string();
        let noted = with_disk_full_note(dir.path(), detail.clone());
        assert!(
            noted.starts_with(&format!("{detail} \u{2014} disk is full")),
            "{noted}"
        );
        // Anything else comes back unchanged (this test disk is not full).
        let other = "connection refused".to_string();
        assert_eq!(with_disk_full_note(dir.path(), other.clone()), other);
    }

    /// Only a service that keeps running carries on by itself once space is
    /// freed; one that exited (or never answered) needs the command again.
    #[test]
    fn the_note_says_what_freeing_space_does() {
        let dir = Path::new("/profile");
        let full = "database or disk is full";
        let note = |then| disk_full_note_given(dir, full, Some(1 << 20), then).unwrap();
        let running = note(OnceFreed::CarriesOn);
        assert!(
            running.ends_with("; free some space and raven-node carries on by itself"),
            "{running}"
        );
        let again = note(OnceFreed::RunAgain);
        assert!(
            again.ends_with("; free some space, then run the command again"),
            "{again}"
        );
        let stopped = note(OnceFreed::NotRunning);
        assert!(
            stopped.ends_with(
                "; free some space, then run the command again (raven-node is not running)"
            ),
            "{stopped}"
        );
        for text in [&again, &stopped] {
            assert!(!text.contains("carries on by itself"), "{text}");
        }
        // The running service's own errors keep their wording.
        let dir = tempfile::tempdir().unwrap();
        let noted = with_disk_full_note(dir.path(), format!("outbox: {full}"));
        assert!(
            noted.ends_with("raven-node carries on by itself"),
            "{noted}"
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn free_bytes_answers_for_a_dir_and_its_missing_child() {
        let dir = tempfile::tempdir().unwrap();
        let here = free_bytes(dir.path()).unwrap();
        assert!(here > 0);
        let child = free_bytes(&dir.path().join("not").join("yet")).unwrap();
        assert!(here.abs_diff(child) <= 64 << 20, "{here} vs {child}");
        assert!(free_bytes(Path::new("relative-profile-that-does-not-exist")).is_some());
    }

    #[test]
    fn human_bytes_rounds_for_people() {
        assert_eq!(human_bytes(0), "0 MB");
        assert_eq!(human_bytes(3 << 20), "3 MB");
        assert_eq!(human_bytes(LOW_BELOW_BYTES), "512 MB");
        assert_eq!(human_bytes((412 << 30) / 10), "41.2 GB");
    }
}
