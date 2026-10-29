//! Lock v2's refusal in this process (Phase 6 P6.40, gate
//! `LOCAL_PROTECTION`; design C §6 v2).
//!
//! While raven-node holds a profile locked (IPC `Lock`) it has dropped every
//! key it cached, and none may come back before `Unlock`: the at-rest key
//! (`at_rest::keys_load`), the identity (`identity_store::load_identity`),
//! the chat-history key, the session and prekey stores and the passphrase
//! vault refuse to load one for that profile ([`refuse`]), so a task still
//! winding down when the caches went cannot quietly reload them. Per data
//! dir (tests run several profiles in one process): only raven-node engages
//! it, and only while the local-protection gate is live, so a build with the
//! gate shut never refuses anything. ash and every other process are
//! unaffected: they read their own keys, as before Lock v2 (the design's
//! honest limit until daemon-owned secrets).

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

/// What a key load says while its profile is locked.
pub const LOCKED_REFUSAL: &str = "Raven is locked: run `raven unlock` to open it again";

/// One locked profile: the name raven-node gave and its canonical name.
struct Held {
    given: PathBuf,
    canonical: PathBuf,
}

static LOCKED: Mutex<Vec<Held>> = Mutex::new(Vec::new());

fn locked() -> MutexGuard<'static, Vec<Held>> {
    LOCKED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn canonical(data_dir: &Path) -> PathBuf {
    std::fs::canonicalize(data_dir).unwrap_or_else(|_| data_dir.to_path_buf())
}

/// raven-node locked this profile: every key load of it in this process
/// refuses until [`release`].
pub fn engage(data_dir: &Path) {
    let canonical = canonical(data_dir);
    let mut held = locked();
    if !held.iter().any(|h| h.given == data_dir) {
        held.push(Held {
            given: data_dir.to_path_buf(),
            canonical,
        });
    }
}

/// The profile is unlocked again (after the passphrase, if it has one, was
/// checked), under whichever name it was locked.
pub fn release(data_dir: &Path) {
    let canonical = canonical(data_dir);
    locked().retain(|h| h.given != data_dir && h.canonical != canonical);
}

/// Whether this process holds the profile locked. No system call while no
/// profile is locked (every key load asks).
pub fn engaged(data_dir: &Path) -> bool {
    {
        let held = locked();
        if held.is_empty() {
            return false;
        }
        if held.iter().any(|h| h.given == data_dir) {
            return true;
        }
    }
    let canonical = canonical(data_dir);
    locked().iter().any(|h| h.canonical == canonical)
}

/// `Err(LOCKED_REFUSAL)` while the profile is locked.
pub fn refuse(data_dir: &Path) -> Result<(), &'static str> {
    if engaged(data_dir) {
        Err(LOCKED_REFUSAL)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_lock_holds_its_own_profile_under_either_name_and_no_other() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("p");
        std::fs::create_dir(&dir).unwrap();
        let other = tmp.path().join("q");
        std::fs::create_dir(&other).unwrap();
        // Another spelling of the same folder.
        let spelled = tmp.path().join("p").join("..").join("p");
        assert!(refuse(&dir).is_ok());
        engage(&spelled);
        assert!(engaged(&dir), "the canonical name is held too");
        assert_eq!(refuse(&spelled), Err(LOCKED_REFUSAL));
        assert!(!engaged(&other), "another profile is not locked");
        release(&dir);
        assert!(!engaged(&spelled));
        assert!(refuse(&dir).is_ok());
    }
}
