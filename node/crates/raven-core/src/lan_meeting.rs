//! The meeting time (Phase 3 P3.C2, cutoff M1): `raven lan on --for <time>`
//! opens the local network for a meeting, and LAN turns off by itself when
//! that time comes, as `raven lan off` does (no LAN listener, LAN dial or
//! beacon). In a cutoff people meet at known times; a listener that is open
//! all day on every network tells everyone there that this computer runs a
//! service on a fixed port.
//!
//! [`LAN_MEETING_FILE`] holds `{"until_ms": <ms since the epoch on Raven's
//! clock>}`. It says when a meeting ended, so it is sealed (RMS1 kind 32) in
//! a sealed profile; a plain profile keeps plain JSON, and the migration
//! seals it with the rest. ash writes it (`raven lan on --for`) and removes
//! it (`raven lan on` without a time, `raven lan off`; no key needed);
//! raven-node only reads it, at start, and is told a new one with IPC
//! `SetLan`. A time that has passed stays until then: `raven lan status`
//! says when listening stopped, and a restart after it keeps LAN off.
//!
//! Reading it needs the at-rest key in a sealed profile. raven-node, which
//! loads that key on a thread of its own, keeps LAN off while the file is
//! there and the key is not (nobody is admitted before the key anyway); a
//! file that does not open with the key keeps LAN off until `raven lan on`
//! removes it (fail closed).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::at_rest::{self, AtRestError, Kind};

/// The meeting time's file in the data dir.
pub const LAN_MEETING_FILE: &str = "lan_meeting.json";

/// Its writer lock (`at_rest::FILES`).
pub const LAN_MEETING_LOCK: &str = ".at_rest.lan_meeting.lock.sqlite";

/// The longest meeting (`raven lan on --for` takes at most a day): a saved
/// meeting time further ahead than this counts as over ([`lan_on_at`]), so a
/// clock set back after `raven lan on --for` never keeps LAN open longer.
pub const MAX_MEETING_MS: u64 = 24 * 60 * 60 * 1000;

#[derive(Serialize, Deserialize)]
struct Meeting {
    until_ms: u64,
}

fn meeting_path(data_dir: &Path) -> PathBuf {
    data_dir.join(LAN_MEETING_FILE)
}

/// The saved meeting time: `None` without one. An error when it cannot be
/// read now: one that [`AtRestError::is_unavailable`] says may work later
/// (above all `KeyUnavailable`, while this process has not loaded the
/// at-rest key of a sealed profile), or one that will not (a changed byte,
/// another profile's file, bad JSON).
pub fn load_until(data_dir: &Path) -> Result<Option<u64>, AtRestError> {
    Ok(
        at_rest::load_json::<Meeting>(data_dir, &meeting_path(data_dir), Kind::LanMeeting)?
            .map(|meeting| meeting.until_ms),
    )
}

/// Save the meeting time (`raven lan on --for`) under its writer lock: RMS1
/// in a sealed profile (refused, `KeyUnavailable`, while the key is not
/// loaded: never plaintext there), plain JSON otherwise. Refused
/// (`NoIdentity`) on a profile without an identity, where a file would make
/// the first `raven init` refuse the profile.
pub fn save_until(data_dir: &Path, until_ms: u64) -> Result<(), AtRestError> {
    if !crate::identity_store::identity_recorded(data_dir)
        .map_err(|e| AtRestError::Io(e.to_string()))?
    {
        return Err(AtRestError::NoIdentity);
    }
    at_rest::lock_file(data_dir, &meeting_path(data_dir), Kind::LanMeeting)?
        .store_json(&Meeting { until_ms })
}

/// Remove the meeting time (`raven lan on` without a time, `raven lan off`):
/// no key is needed, and nothing (not even a lock file) is made when there
/// is none. `true` when there was one.
pub fn clear(data_dir: &Path) -> Result<bool, AtRestError> {
    let path = meeting_path(data_dir);
    if std::fs::symlink_metadata(&path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) {
        return Ok(false);
    }
    let _lock = at_rest::lock_file(data_dir, &path, Kind::LanMeeting)?;
    match std::fs::remove_file(&path) {
        Ok(()) => {
            crate::paths::sync_dir_best_effort(data_dir);
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(AtRestError::Io(e.to_string())),
    }
}

/// Whether LAN is on at `now_ms` (Raven's clock): `raven lan off` is not in
/// effect (`lan_off`), and there is no meeting time or it has not come yet.
/// A meeting time more than [`MAX_MEETING_MS`] ahead is over (fail closed):
/// no meeting is that long, so the clock was set back since it was saved.
pub fn lan_on_at(lan_off: bool, until_ms: Option<u64>, now_ms: u64) -> bool {
    !lan_off && until_ms.is_none_or(|until| now_ms < until && until - now_ms <= MAX_MEETING_MS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contact_book::tests::{profile, seal};

    const T: u64 = 1_800_000_000_000;

    #[test]
    fn lan_is_on_until_the_meeting_time_and_never_while_lan_is_off() {
        for (lan_off, until, now, on) in [
            (false, None, T, true),
            (true, None, T, false),
            (false, Some(T + 1), T, true),
            (false, Some(T), T, false),
            (false, Some(T - 1), T, false),
            (true, Some(T + 60_000), T, false),
            // A day ahead at most: further is a clock set back (B-1).
            (false, Some(T + MAX_MEETING_MS), T, true),
            (false, Some(T + MAX_MEETING_MS + 1), T, false),
        ] {
            assert_eq!(lan_on_at(lan_off, until, now), on, "{lan_off} {until:?}");
        }
    }

    /// A plain profile keeps plain JSON; a profile without an identity gets
    /// nothing at all (not even a lock file); removing needs no key and is
    /// `false` when there was nothing.
    #[test]
    fn the_meeting_time_needs_an_identity_and_round_trips() {
        let bare = tempfile::tempdir().unwrap();
        assert!(matches!(
            save_until(bare.path(), T),
            Err(AtRestError::NoIdentity)
        ));
        assert_eq!(std::fs::read_dir(bare.path()).unwrap().count(), 0);
        assert!(!clear(bare.path()).unwrap());
        assert_eq!(std::fs::read_dir(bare.path()).unwrap().count(), 0);

        let dir = profile();
        let dd = dir.path();
        assert_eq!(load_until(dd).unwrap(), None);
        save_until(dd, T).unwrap();
        let raw = std::fs::read_to_string(dd.join(LAN_MEETING_FILE)).unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&raw).unwrap(),
            serde_json::json!({ "until_ms": T })
        );
        assert_eq!(load_until(dd).unwrap(), Some(T));
        save_until(dd, T + 5).unwrap();
        assert_eq!(load_until(dd).unwrap(), Some(T + 5));
        assert!(clear(dd).unwrap());
        assert!(!dd.join(LAN_MEETING_FILE).exists());
        assert_eq!(load_until(dd).unwrap(), None);
        assert!(!clear(dd).unwrap());
    }

    /// Privacy: in a sealed profile the file is RMS1 (kind 32) and names no
    /// time; it reads back with the key, says "not now" without it (raven-node
    /// before its key thread loaded the key) and "never" once a byte changed;
    /// `raven lan on` removes it with no key. The migration seals a plain one.
    #[test]
    fn the_meeting_time_is_sealed_in_a_sealed_profile() {
        let dir = profile();
        let dd = dir.path();
        save_until(dd, T).unwrap();
        assert!(!at_rest::is_sealed(
            &std::fs::read(dd.join(LAN_MEETING_FILE)).unwrap()
        ));
        seal(dd);
        let bytes = std::fs::read(dd.join(LAN_MEETING_FILE)).unwrap();
        assert!(at_rest::is_sealed_as(Kind::LanMeeting, &bytes), "migrated");
        assert_eq!(bytes[5], 32, "kind 32");
        let digits = T.to_string();
        assert!(!bytes.windows(digits.len()).any(|w| w == digits.as_bytes()));
        assert_eq!(load_until(dd).unwrap(), Some(T));
        save_until(dd, T + 7).unwrap();
        let bytes = std::fs::read(dd.join(LAN_MEETING_FILE)).unwrap();
        assert!(at_rest::is_sealed_as(Kind::LanMeeting, &bytes));
        assert_eq!(load_until(dd).unwrap(), Some(T + 7));

        let mut changed = bytes.clone();
        let last = changed.len() - 1;
        changed[last] ^= 1;
        std::fs::write(dd.join(LAN_MEETING_FILE), &changed).unwrap();
        let damaged = load_until(dd).unwrap_err();
        assert!(!damaged.is_unavailable(), "{damaged}");
        std::fs::write(dd.join(LAN_MEETING_FILE), &bytes).unwrap();

        at_rest::forget_cached_keys(dd);
        let waiting = load_until(dd).unwrap_err();
        assert!(
            matches!(waiting, AtRestError::KeyUnavailable(_)),
            "{waiting}"
        );
        assert!(waiting.is_unavailable());
        assert!(matches!(
            save_until(dd, T + 9),
            Err(AtRestError::KeyUnavailable(_))
        ));
        assert_eq!(std::fs::read(dd.join(LAN_MEETING_FILE)).unwrap(), bytes);
        assert!(clear(dd).unwrap(), "no key needed to remove it");
        assert!(!dd.join(LAN_MEETING_FILE).exists());
    }
}
