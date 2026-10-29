//! Opening the profile as the CLI opens it before every command, and what
//! `profile.state`, `privacy.state` and `privacy.unlock` say and do.
//!
//! Before any command, cli.rs's `run` refuses a profile whose erase or key
//! change did not finish, loads the profile's at-rest key (a sealed profile
//! can't be read without it) and seals what is still plain, and takes what
//! the privacy pack forgets off the disk; the terminal app starts from there
//! too. The engine keeps the profile open for as long as the app runs, so
//! [`Inner::open`], before every operation that touches the profile, reads
//! the two refusals each time (an erase can begin in a terminal while the
//! app is open), runs the rest once (the engine bridge's `open_profile`),
//! and loads the at-rest key again when a sealed profile's is missing:
//! raven-node, which the app starts, seals a release build's profile at its
//! own start.

use std::path::Path;
use std::time::{Duration, Instant};

use ash_engine::engine::{self as bridge, Closed};
use serde_json::{json, Value};

use crate::engine::{lock, Inner};
use crate::envelope::{code, ApiError, OpResult};
use crate::explain;
use crate::settings;

/// A sealed profile whose key a load did not give is asked again after this
/// long at the earliest, unless the app asks (`profile.state`) or
/// raven-node was just started: a keychain that refused should not be asked
/// at every operation.
const KEY_RETRY: Duration = Duration::from_secs(60);

/// What [`Inner::open`] did so far.
#[derive(Debug, Default)]
pub(crate) struct OpenState {
    /// The bridge's `open_profile` ran to its end in this engine.
    opened: bool,
    /// When a key load last left a sealed profile without its key.
    key_failed_at: Option<Instant>,
}

/// When [`Inner::open_as`] loads the at-rest key of a sealed profile this
/// process does not hold it for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyLoad {
    /// Unless a load failed less than [`KEY_RETRY`] ago.
    IfDue,
    /// Now (the app asked, or raven-node was just started).
    Now,
}

/// A refusal of cli.rs's `run` as an API error: raven-core's sentence names
/// the command that finishes what was left unfinished.
pub(crate) fn closed_error(closed: &Closed) -> ApiError {
    ApiError::new(code::PROFILE_UNREADABLE, closed.text(), closed.text())
}

/// The at-rest key of a sealed profile is not loaded in this process.
pub(crate) fn key_missing_error(data_dir: &Path) -> ApiError {
    let plain = explain::explain_key_missing(raven_core::at_rest::key_lost(data_dir));
    ApiError::new(
        code::KEYCHAIN_DENIED,
        format!("{} {}", plain.headline, plain.next)
            .trim()
            .to_owned(),
        raven_core::privacy::key_unavailable_text(data_dir),
    )
}

impl Inner {
    /// Before every operation that touches the profile (see the module
    /// docs). Never call it under a data-dir lock.
    pub(crate) fn open(&self) -> Result<(), ApiError> {
        self.open_as(KeyLoad::IfDue)
    }

    pub(crate) fn open_as(&self, keys: KeyLoad) -> Result<(), ApiError> {
        let dir = self.data_dir()?;
        if let Some(closed) = bridge::closed(dir) {
            return Err(closed_error(&closed));
        }
        let mut state = lock(&self.open_state);
        if !state.opened {
            bridge::open_profile(dir).map_err(|closed| closed_error(&closed))?;
            state.opened = true;
        } else if bridge::at_rest_key_missing(dir)
            && (keys == KeyLoad::Now
                || state
                    .key_failed_at
                    .is_none_or(|at| at.elapsed() >= KEY_RETRY))
        {
            bridge::load_at_rest(dir);
        } else {
            return Ok(());
        }
        state.key_failed_at = bridge::at_rest_key_missing(dir).then(Instant::now);
        drop(state);
        self.after_key_load(dir);
        Ok(())
    }

    /// A new identity's profile, as the CLI's next command would take it:
    /// sealed now where this build seals (the at-rest key loaded with it).
    pub(crate) fn seal_new_profile(&self) {
        let Ok(dir) = self.data_dir() else {
            return;
        };
        let mut state = lock(&self.open_state);
        bridge::load_at_rest(dir);
        state.key_failed_at = bridge::at_rest_key_missing(dir).then(Instant::now);
        drop(state);
        self.after_key_load(dir);
    }

    /// The engine's own files once the key may be loaded: an older
    /// engine's name leaves `desktop_settings.json`, and a plain
    /// `desktop_private.rms` in a sealed profile is sealed in place. Best
    /// effort: what could not move stays as it was. The settings are read
    /// again (before the identity exists they live in memory only).
    fn after_key_load(&self, dir: &Path) {
        if !self.identity_on_record() {
            return;
        }
        let _ = settings::move_name_out(dir);
        let _ = settings::seal_private_in_place(dir);
        self.forget_settings();
    }

    /// `profile.state`: the refusals first, then the identity, then whether
    /// the at-rest key is there and whether `raven lock` locked it. The key
    /// of a sealed profile is asked for now.
    pub(crate) fn profile_state(&self) -> Value {
        let dir = match self.data_dir() {
            Ok(dir) => dir,
            Err(e) => return json!({"state": "unreadable", "reason": e.message}),
        };
        if let Err(e) = self.open_as(KeyLoad::Now) {
            return json!({"state": "unreadable", "reason": e.message, "detail": e.detail});
        }
        if self.cached_identity().is_none() {
            match bridge::try_load_identity(dir) {
                Ok(Some(id)) => {
                    self.keep_identity(id);
                }
                Ok(None) => return json!({"state": "new"}),
                Err(why) => {
                    let (_, plain) = explain::explain_identity(&why);
                    return json!({
                        "state": "unreadable",
                        "reason": format!("{} {}", plain.headline, plain.next).trim().to_owned(),
                        "detail": why,
                    });
                }
            }
        }
        if bridge::at_rest_key_missing(dir) {
            let e = key_missing_error(dir);
            return json!({"state": "unreadable", "reason": e.message, "detail": e.detail});
        }
        if raven_core::privacy::lock_state(dir).locked_by_user {
            let plain = explain::explain_node_start(bridge::LOCKED_TEXT);
            return json!({
                "state": "locked",
                "reason": format!("{} {}", plain.headline, plain.next).trim().to_owned(),
            });
        }
        json!({"state": "ready"})
    }

    /// `privacy.state`: whether the profile is sealed (`encrypted`) and
    /// locked, as raven-core's privacy pack records it (file reads only).
    /// `available` stays false until the apps offer the pack's actions.
    pub(crate) fn privacy_state(&self) -> OpResult {
        let dir = self.data_dir()?;
        Ok(json!({
            "available": false,
            "encrypted": raven_core::privacy::mode(dir) == raven_core::at_rest::Mode::Sealed,
            "locked": raven_core::privacy::lock_state(dir).locked_by_user,
        }))
    }

    /// `privacy.unlock`: the user said to start Raven again after `raven
    /// lock` (the Locked screen's Unlock). The lock is cleared, as `raven
    /// unlock` clears it first and as the terminal app's UNLOCK does; Raven's
    /// own login item is never touched (one the lock turned off stays off
    /// until `raven unlock`). Answers as `profile.state`.
    pub(crate) fn privacy_unlock(&self) -> OpResult {
        let dir = self.data_dir()?;
        if let Some(closed) = bridge::closed(dir) {
            return Err(closed_error(&closed));
        }
        raven_core::privacy::set_unlocked(dir).map_err(|why| {
            ApiError::new(
                code::INTERNAL,
                "Raven couldn't unlock. Run `raven unlock` in a terminal.",
                why,
            )
        })?;
        Ok(self.profile_state())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusals_and_a_missing_key_get_their_codes_and_words() {
        let erase = closed_error(&Closed::EraseUnfinished(
            raven_core::erase::UNFINISHED_TEXT.to_owned(),
        ));
        assert_eq!(erase.code, code::PROFILE_UNREADABLE);
        assert_eq!(erase.message, raven_core::erase::UNFINISHED_TEXT);
        let rotation = closed_error(&Closed::MetaRotationUnfinished(
            raven_core::privacy::META_ROTATION_UNFINISHED_TEXT.to_owned(),
        ));
        assert!(rotation.message.contains("raven privacy rotate-meta"));

        let dir = tempfile::tempdir().unwrap();
        let missing = key_missing_error(dir.path());
        assert_eq!(missing.code, code::KEYCHAIN_DENIED);
        assert!(missing.message.contains("keychain"), "{}", missing.message);
        assert_eq!(missing.detail, raven_core::privacy::KEY_UNAVAILABLE_TEXT);
        let lost = explain::explain_key_missing(true);
        assert!(lost.headline.contains("no longer"), "{}", lost.headline);
        assert_ne!(lost, explain::explain_key_missing(false));
    }
}
