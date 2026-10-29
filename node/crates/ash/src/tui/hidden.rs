//! Messages deleted in a desktop app: `<data_dir>/desktop_hidden.json`.
//!
//! The desktop engine's `messages.delete` (raven-client) takes an ended
//! message of yours out of the chat for good, and Send again does the same
//! with the message it replaces: the history row stays until the
//! chat-keeping time ends, and its id goes into this file. Every chat leaves
//! a row whose id is listed out, by this one rule, in the desktop apps and
//! in the terminal app (E1: the terminal app still listed them). The engine
//! writes the file; the terminal app only reads it.
//!
//! Ids only (random numbers that name nobody), the newest [`MAX_IDS`]; plain,
//! written atomically and owner-only (raven-core's at-rest registry lists the
//! file as plain). A missing or unreadable file hides nothing.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The file's name inside the data directory.
pub(crate) const FILE_NAME: &str = "desktop_hidden.json";
/// Ids kept at most (the oldest go first).
const MAX_IDS: usize = 2000;
/// Larger files are not read.
const MAX_FILE_BYTES: usize = 256 * 1024;

#[derive(Serialize, Deserialize, Default)]
struct Hidden {
    #[serde(default)]
    messages: Vec<String>,
}

pub(crate) fn path(data_dir: &Path) -> PathBuf {
    data_dir.join(FILE_NAME)
}

/// The deleted messages' ids, as saved (none when the file is missing or
/// unreadable).
pub(crate) fn load(data_dir: &Path) -> Vec<String> {
    std::fs::read(path(data_dir))
        .ok()
        .filter(|b| b.len() <= MAX_FILE_BYTES)
        .and_then(|b| serde_json::from_slice::<Hidden>(&b).ok())
        .map(|h| h.messages)
        .unwrap_or_default()
}

/// [`load`] as a set of ids in lower case, for [`hides`].
pub(crate) fn load_set(data_dir: &Path) -> HashSet<String> {
    load(data_dir)
        .into_iter()
        .map(|id| id.to_ascii_lowercase())
        .collect()
}

/// Whether the history row `id` was deleted (`hidden` from [`load_set`]).
pub(crate) fn hides(hidden: &HashSet<String>, id: &str) -> bool {
    !id.is_empty() && hidden.contains(&id.to_ascii_lowercase())
}

/// Writes the deleted messages' ids, the newest [`MAX_IDS`] of them (the
/// desktop engine's; the terminal app never writes the file).
#[cfg_attr(not(feature = "engine"), allow(dead_code))]
pub(crate) fn save(data_dir: &Path, ids: &[String]) -> Result<(), String> {
    let start = ids.len().saturating_sub(MAX_IDS);
    let raw = serde_json::to_vec(&Hidden {
        messages: ids[start..].to_vec(),
    })
    .map_err(|e| e.to_string())?;
    raven_core::atomic_write_private(&path(data_dir), &raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_round_trip_and_match_in_any_case() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load(dir.path()).is_empty());
        save(dir.path(), &["AB".repeat(16), "pending-3".into()]).unwrap();
        let set = load_set(dir.path());
        assert!(hides(&set, &"ab".repeat(16)));
        assert!(hides(&set, &"AB".repeat(16)));
        assert!(!hides(&set, &"cd".repeat(16)));
        assert!(!hides(&set, ""));
        // The newest MAX_IDS only.
        let many: Vec<String> = (0..MAX_IDS + 5).map(|i| format!("{i:032x}")).collect();
        save(dir.path(), &many).unwrap();
        let kept = load(dir.path());
        assert_eq!(kept.len(), MAX_IDS);
        assert_eq!(kept.first(), many.get(5));
        // A file that can't be read hides nothing.
        std::fs::write(path(dir.path()), b"not json").unwrap();
        assert!(load(dir.path()).is_empty());
    }
}
