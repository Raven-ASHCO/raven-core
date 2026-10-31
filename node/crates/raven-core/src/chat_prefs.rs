//! The chat controls kept on this device (0.1.1, the owner's chat
//! controls): which chats are pinned to the top of the chat list, and which
//! were deleted from it (`raven chats delete`, the apps' "Delete chat"),
//! hidden until a new message arrives. Every UI on this device reads the same
//! file: the CLI, the terminal app and the desktop and phone apps
//! (raven-client's `chats.*` ops). Nothing of it is ever sent: the other
//! person is never told.
//!
//! [`CHAT_PREFS_FILE`] holds `{"pinned": [chat, ...], "hidden": [{"chat":
//! chat, "at_ms": ms}, ...]}`, a chat being [`contact_chat`] or
//! [`group_chat`]. It names friends' keys and groups, so it is sealed (RMS1
//! kind 129) in a sealed profile; a plain profile keeps plain JSON, and the
//! migration seals it with the rest. A file with nothing in it is removed.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::at_rest::{self, AtRestError, Kind};

/// The chat controls' file in the data dir.
pub const CHAT_PREFS_FILE: &str = "chat_prefs.json";

/// Its writer lock (`at_rest::FILES`).
pub const CHAT_PREFS_LOCK: &str = ".at_rest.chat_prefs.lock.sqlite";

/// At most this many pinned chats and as many hidden ones are kept (the
/// oldest go first): a contact book holds far fewer friends and groups.
pub const MAX_CHATS: usize = 1024;

/// One chat deleted from the list at `at_ms` (Raven's clock): hidden while
/// no message newer than that arrived.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HiddenChat {
    pub chat: String,
    pub at_ms: u64,
}

/// What [`CHAT_PREFS_FILE`] holds.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatPrefs {
    /// Pinned chats, the newest pin first.
    #[serde(default)]
    pub pinned: Vec<String>,
    #[serde(default)]
    pub hidden: Vec<HiddenChat>,
}

/// The chat with one friend: their key, lowercase hex.
pub fn contact_chat(pub_hex: &str) -> String {
    format!("contact:{}", pub_hex.trim().to_ascii_lowercase())
}

/// A group chat: its id, lowercase hex.
pub fn group_chat(id_hex: &str) -> String {
    format!("group:{}", id_hex.trim().to_ascii_lowercase())
}

impl ChatPrefs {
    pub fn is_pinned(&self, chat: &str) -> bool {
        self.pinned.iter().any(|p| p == chat)
    }

    /// Deleted from the chat list and no message came since: `newest_ms` is
    /// the newest message of that chat (0 without one).
    pub fn is_hidden(&self, chat: &str, newest_ms: u64) -> bool {
        self.hidden
            .iter()
            .any(|h| h.chat == chat && newest_ms <= h.at_ms)
    }

    fn set_pinned(&mut self, chat: &str, pinned: bool) {
        self.pinned.retain(|p| p != chat);
        if pinned {
            self.pinned.insert(0, chat.to_owned());
            self.pinned.truncate(MAX_CHATS);
        }
    }

    fn hide(&mut self, chat: &str, at_ms: u64) {
        self.hidden.retain(|h| h.chat != chat);
        self.hidden.insert(
            0,
            HiddenChat {
                chat: chat.to_owned(),
                at_ms,
            },
        );
        self.hidden.truncate(MAX_CHATS);
    }

    fn forget(&mut self, chat: &str) {
        self.pinned.retain(|p| p != chat);
        self.hidden.retain(|h| h.chat != chat);
    }

    fn is_empty(&self) -> bool {
        self.pinned.is_empty() && self.hidden.is_empty()
    }
}

fn prefs_path(data_dir: &Path) -> PathBuf {
    data_dir.join(CHAT_PREFS_FILE)
}

/// The saved chat controls; nothing pinned or hidden without a file. An
/// error when it cannot be read now: one that [`AtRestError::is_unavailable`]
/// says may work later (the at-rest key of a sealed profile not loaded yet),
/// or one that will not (a changed byte, another profile's file, bad JSON).
pub fn load(data_dir: &Path) -> Result<ChatPrefs, AtRestError> {
    Ok(
        at_rest::load_json::<ChatPrefs>(data_dir, &prefs_path(data_dir), Kind::ChatPrefs)?
            .unwrap_or_default(),
    )
}

/// Read, change and write the file under its writer lock: RMS1 in a sealed
/// profile (refused, `KeyUnavailable`, while the key is not loaded: never
/// plaintext there), plain JSON otherwise; removed once nothing is left in
/// it. A file that cannot be read is never written over. Refused
/// (`NoIdentity`) on a profile without an identity, where a file would make
/// the first `raven init` refuse the profile.
fn edit(data_dir: &Path, change: impl FnOnce(&mut ChatPrefs)) -> Result<(), AtRestError> {
    if !crate::identity_store::identity_recorded(data_dir)
        .map_err(|e| AtRestError::Io(e.to_string()))?
    {
        return Err(AtRestError::NoIdentity);
    }
    let path = prefs_path(data_dir);
    let lock = at_rest::lock_file(data_dir, &path, Kind::ChatPrefs)?;
    let mut prefs = lock.load_json::<ChatPrefs>()?.unwrap_or_default();
    let before = prefs.clone();
    change(&mut prefs);
    if prefs == before {
        return Ok(());
    }
    if prefs.is_empty() {
        match std::fs::remove_file(&path) {
            Ok(()) => crate::paths::sync_dir_best_effort(data_dir),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(AtRestError::Io(e.to_string())),
        }
        return Ok(());
    }
    lock.store_json(&prefs)
}

/// Pin `chat` to the top of the chat list, or unpin it. `pinned` as asked.
pub fn set_pinned(data_dir: &Path, chat: &str, pinned: bool) -> Result<bool, AtRestError> {
    edit(data_dir, |p| p.set_pinned(chat, pinned))?;
    Ok(pinned)
}

/// Leave `chat` out of the chat list until a message newer than `at_ms`
/// arrives (Delete chat).
pub fn hide(data_dir: &Path, chat: &str, at_ms: u64) -> Result<(), AtRestError> {
    edit(data_dir, |p| p.hide(chat, at_ms))
}

/// Forget everything kept for `chat` (its contact was removed, or the group
/// left for good). Nothing is made when there is no file.
pub fn forget(data_dir: &Path, chat: &str) -> Result<(), AtRestError> {
    if std::fs::symlink_metadata(prefs_path(data_dir))
        .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
    {
        return Ok(());
    }
    edit(data_dir, |p| p.forget(chat))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contact_book::tests::{profile, seal};

    const T: u64 = 1_800_000_000_000;
    const BOB: &str = "AA11";

    /// Pinned and hidden chats round-trip; a chat is hidden only until a
    /// message newer than its deletion; a newer pin goes first; a file with
    /// nothing left in it is removed, and a profile without an identity gets
    /// nothing at all.
    #[test]
    fn pins_and_hidden_chats_round_trip_and_an_empty_file_goes() {
        let bare = tempfile::tempdir().unwrap();
        assert!(matches!(
            set_pinned(bare.path(), "contact:aa", true),
            Err(AtRestError::NoIdentity)
        ));
        assert_eq!(std::fs::read_dir(bare.path()).unwrap().count(), 0);
        forget(bare.path(), "contact:aa").unwrap();
        assert_eq!(std::fs::read_dir(bare.path()).unwrap().count(), 0);

        let dir = profile();
        let dd = dir.path();
        assert_eq!(load(dd).unwrap(), ChatPrefs::default());
        let bob = contact_chat(BOB);
        assert_eq!(bob, "contact:aa11");
        let club = group_chat("BEEF");
        assert!(set_pinned(dd, &bob, true).unwrap());
        set_pinned(dd, &club, true).unwrap();
        let prefs = load(dd).unwrap();
        assert_eq!(prefs.pinned, vec![club.clone(), bob.clone()]);
        assert!(prefs.is_pinned(&bob) && !prefs.is_hidden(&bob, 0));

        hide(dd, &bob, T).unwrap();
        let prefs = load(dd).unwrap();
        assert!(prefs.is_hidden(&bob, 0));
        assert!(prefs.is_hidden(&bob, T), "nothing newer came");
        assert!(
            !prefs.is_hidden(&bob, T + 1),
            "a new message shows it again"
        );
        assert!(!prefs.is_hidden(&club, 0));
        hide(dd, &bob, T + 10).unwrap();
        assert_eq!(load(dd).unwrap().hidden.len(), 1, "one entry per chat");

        set_pinned(dd, &club, false).unwrap();
        forget(dd, &bob).unwrap();
        assert!(!dd.join(CHAT_PREFS_FILE).exists(), "nothing left: removed");
        assert_eq!(load(dd).unwrap(), ChatPrefs::default());
    }

    /// Privacy: in a sealed profile the file is RMS1 (kind 129) and names no
    /// key; it reads back with the key, says "not now" without it, and the
    /// migration seals a plain one.
    #[test]
    fn chat_prefs_are_sealed_in_a_sealed_profile() {
        let dir = profile();
        let dd = dir.path();
        let key = "ab".repeat(32);
        set_pinned(dd, &contact_chat(&key), true).unwrap();
        assert!(!at_rest::is_sealed(
            &std::fs::read(dd.join(CHAT_PREFS_FILE)).unwrap()
        ));
        seal(dd);
        let bytes = std::fs::read(dd.join(CHAT_PREFS_FILE)).unwrap();
        assert!(at_rest::is_sealed_as(Kind::ChatPrefs, &bytes), "migrated");
        assert_eq!(bytes[5], 129, "kind 129");
        assert!(!bytes.windows(key.len()).any(|w| w == key.as_bytes()));
        assert!(load(dd).unwrap().is_pinned(&contact_chat(&key)));
        hide(dd, &contact_chat(&key), T).unwrap();
        let bytes = std::fs::read(dd.join(CHAT_PREFS_FILE)).unwrap();
        assert!(at_rest::is_sealed_as(Kind::ChatPrefs, &bytes));

        at_rest::forget_cached_keys(dd);
        let waiting = load(dd).unwrap_err();
        assert!(waiting.is_unavailable(), "{waiting}");
        assert!(matches!(
            set_pinned(dd, "contact:cd", true),
            Err(AtRestError::KeyUnavailable(_))
        ));
        assert_eq!(std::fs::read(dd.join(CHAT_PREFS_FILE)).unwrap(), bytes);
    }
}
