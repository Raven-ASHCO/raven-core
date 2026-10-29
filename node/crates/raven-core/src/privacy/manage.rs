//! `raven privacy status | seal-now | unseal | rotate-meta |
//! forget-moved-aside` (privacy pack PP.18;
//! docs/design/2026-10-at-rest-metadata.md sections 6.8 and 8): the user's
//! own commands around the at-rest sealing, local only and never from a
//! message, an advisory or a remote request.
//!
//! - [`report`] says what is sealed and what is not, file by file and store
//!   by store ([`PrivacyReport::to_json`]: `raven privacy status --json`).
//! - [`unseal_all`] is the way back to a build before the pack (review R12):
//!   with this profile's node stopped, under the at-rest lock, the mode goes
//!   to `unsealed_by_user` first (no writer seals again, no migration runs),
//!   then every sealed file, the history, the stage, the app rows and the
//!   SQLite stores are written back in the forms that build reads, and
//!   `meta_key.rmk` goes last. Each part is a no-op once done, so a crash
//!   anywhere is finished by running it again.
//! - [`seal_now`] leaves `unsealed_by_user` and runs the migration.
//! - [`rotate_meta`] gives the profile a new `k_index` and a new epoch (a
//!   profile that suspects its keys were exposed): every keyed value is
//!   computed again, store by store, and every sealed object sealed again,
//!   then the old epochs go.
//! - [`forget_moved_aside`] deletes the plaintext histories an older build
//!   stranded (`chat_history.json.untrusted-plaintext.*`), overwritten first.

use std::path::{Path, PathBuf};

use super::*;
use crate::at_rest::Kind;

// ── UX copy ───────────────────────────────────────────────────────────────

/// Every command, one line, while the user's unsealing holds.
pub const UNSEALED_TEXT: &str = "This profile is not encrypted (you ran `raven privacy unseal`). \
    To encrypt it again: `raven privacy seal-now`.";

/// `raven privacy unseal`'s question (typed `unseal`).
pub const UNSEAL_QUESTION: &str = "Write this profile's records unencrypted so an older Raven \
    version can open it? Anyone who reads this disk can then see your friends list and who you \
    wrote to. Raven stops now, and this version won't encrypt them again until you run `raven \
    privacy seal-now`. Type unseal to continue:";

/// What `raven privacy unseal` says when it is done.
pub const UNSEAL_DONE: [&str; 2] = [
    "Done. You can now start the older Raven version.",
    "Raven won't encrypt them again until you run `raven privacy seal-now`.",
];

/// `raven privacy rotate-meta`'s question (typed `rotate`).
pub const ROTATE_META_QUESTION: &str = "Change all of this profile's encryption keys on this \
    computer? Use this if you think someone copied them. Raven stops now and re-encrypts your \
    friends list, addresses and message records; it starts again when you send or run `raven \
    listen`. Type rotate to continue:";

/// `raven privacy forget-moved-aside`'s question (typed `delete`).
pub const FORGET_MOVED_ASIDE_QUESTION: &str = "Delete the unencrypted chat history copies an \
    older Raven version left in this profile? They can't be opened again. Type delete to \
    confirm:";

/// Any command but the few that may run, while a `raven privacy
/// rotate-meta` did not finish (its stores may be keyed under either key).
pub const META_ROTATION_UNFINISHED_TEXT: &str = "A key change of this Raven profile did not \
    finish. Run `raven privacy rotate-meta` to finish it.";

/// `raven privacy status` while an unsealing did not finish.
pub const UNSEAL_UNFINISHED_TEXT: &str = "Writing this profile's records unencrypted did not \
    finish. Run `raven privacy unseal` again to finish it.";

/// `raven privacy seal-now` in a build that does not seal.
pub const SEAL_NOT_ALLOWED_TEXT: &str = "This Raven build does not encrypt profiles (a debug \
    build without RAVEN_LAB_AT_REST=1). Nothing was changed.";

/// `raven privacy rotate-meta` in a profile that is not encrypted.
pub const NOT_SEALED_TEXT: &str = "This profile is not encrypted, so it has no keys to change.";

/// The prefix of the plaintext histories an older build moved aside.
const MOVED_ASIDE_PREFIX: &str = "chat_history.json.untrusted-plaintext.";

/// The SQLite stores: the file, its keyed schema (a sealed profile's) and
/// the schema a build before the pack reads (each store's module keeps
/// them; `stores_report_the_schema_of_each_mode` checks this table).
const STORES: [(&str, i64, i64); 5] = [
    (
        crate::indexed_session_store::INDEXED_SESSION_METADATA_FILE,
        4,
        1,
    ),
    (crate::owed_acks::OWED_ACKS_FILE, 2, 1),
    (crate::app_store::APP_STORE_FILE, 3, 2),
    (crate::friend_custody::CUSTODY_DB_FILE, 2, 1),
    // Phase 5 P5.19: no build before the pack has it; 1 is its clear schema.
    (crate::custody_handoff::HANDOFF_DB_FILE, 2, 1),
];

/// Why a privacy command did not run (or stopped).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandError {
    /// This profile's raven-node still answers: the caller stops it first
    /// (and says how when it cannot).
    NodeRunning,
    /// Anything else, in words. What was done before it is kept; running
    /// the command again finishes it.
    Failed(String),
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NodeRunning => f.write_str("Raven is still running for this profile"),
            Self::Failed(why) => f.write_str(why),
        }
    }
}

fn failed(e: impl std::fmt::Display) -> CommandError {
    CommandError::Failed(e.to_string())
}

/// Whether a `raven privacy rotate-meta` did not finish (its record is
/// there) and that command can still finish it: not once the user began
/// `raven privacy unseal`, which ends it its own way (it moves every store
/// back and drops the record; review B-sealed-stores-3).
pub fn meta_rotation_unfinished(data_dir: &Path) -> bool {
    meta_rotation_recorded(data_dir) && mode(data_dir) != Mode::UnsealedByUser
}

fn meta_rotation_recorded(data_dir: &Path) -> bool {
    read_file(data_dir).is_ok_and(|file| file.is_some_and(|file| file.meta_rotation.is_some()))
}

/// `Err` while a `raven privacy rotate-meta` did not finish: raven-node does
/// not start and ash runs only that command, `raven privacy unseal`, `raven
/// privacy status` and `raven erase` (a store may still be keyed under the
/// old `k_index`, which no key file holds any more). The text names the
/// command that finishes it: [`META_ROTATION_UNFINISHED_TEXT`], or
/// [`UNSEAL_UNFINISHED_TEXT`] once an unseal began (rotate-meta refuses an
/// unsealed profile, so pointing there left no way out but erase; review
/// B-sealed-stores-3).
pub fn refuse_if_meta_rotation_unfinished(data_dir: &Path) -> Result<(), String> {
    if !meta_rotation_recorded(data_dir) {
        return Ok(());
    }
    if mode(data_dir) == Mode::UnsealedByUser {
        return Err(UNSEAL_UNFINISHED_TEXT.to_owned());
    }
    Err(META_ROTATION_UNFINISHED_TEXT.to_owned())
}

/// Whether `raven privacy unseal` did not finish: the profile says it is
/// unsealed and the key file is still there (it goes last).
pub fn unseal_unfinished(data_dir: &Path) -> bool {
    mode(data_dir) == Mode::UnsealedByUser && data_dir.join(META_KEY_FILE).exists()
}

// ── Status ────────────────────────────────────────────────────────────────

/// One SQLite store as `raven privacy status` shows it (by its header: a
/// commit still in its WAL is not seen).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreVersion {
    pub file: &'static str,
    pub user_version: i64,
    /// At its keyed schema (a sealed profile's), with no table that its
    /// keyed schema leaves in clear holding rows.
    pub keyed: bool,
    /// The tables the keyed schema leaves in clear that hold rows: the app
    /// channel's outbox and pairing budget (lab only; review
    /// E-harness-docs-ci-8). Such a store is not called keyed.
    pub clear_tables: Vec<&'static str>,
}

/// Everything `raven privacy status` says (PP.18): file names, store
/// versions, times and counts; never a friend's name, key or address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivacyReport {
    pub status: PrivacyStatus,
    /// Registered files that exist, sealed and plain (their names below the
    /// profile).
    pub sealed_files: Vec<String>,
    pub plain_files: Vec<String>,
    pub stores: Vec<StoreVersion>,
    pub keep: ChatKeep,
    /// The next retention deletion (`None`: none with this setting).
    pub next_deletion_at_ms: Option<u64>,
    pub rotation: RotationState,
    pub scrub_pending: bool,
    pub set_aside_stores: u16,
    /// The plaintext histories an older build moved aside.
    pub moved_aside: Vec<String>,
    pub unseal_unfinished: bool,
    pub meta_rotation_unfinished: bool,
}

/// How long a friend's address is kept without contact (PP.7).
pub const FORGET_ADDRESSES_AFTER_DAYS: u64 = 30;

/// [`PrivacyReport`] of this profile now: its files, a few small reads, no
/// keystore call, no lock.
pub fn report(data_dir: &Path, now_ms: u64) -> PrivacyReport {
    let forms = file_forms(data_dir).unwrap_or_default();
    let names = |sealed: bool| {
        forms
            .iter()
            .filter(|(_, s)| *s == sealed)
            .map(|(name, _)| name.clone())
            .collect()
    };
    let outlook = retention_outlook(data_dir, now_ms).ok();
    let stores = store_status(data_dir);
    let status = status(data_dir);
    // An older build's per-friend send locks: their names hold friends'
    // keys, so a pattern stands for each (review B-sealed-stores-4).
    let mut plain_files: Vec<String> = names(false);
    if status.mode == Mode::Sealed {
        let mut locks: Vec<String> = crate::outbox::legacy_send_lock_files(data_dir)
            .into_iter()
            .map(|(_, name)| {
                if name.ends_with("-journal") {
                    ".send_*.lock.sqlite-journal".to_owned()
                } else {
                    ".send_*.lock.sqlite".to_owned()
                }
            })
            .collect();
        locks.sort();
        plain_files.extend(locks);
    }
    PrivacyReport {
        status,
        sealed_files: names(true),
        plain_files,
        stores: store_versions(data_dir),
        keep: outlook
            .as_ref()
            .map_or_else(|| chat_keep(data_dir), |outlook| outlook.keep),
        next_deletion_at_ms: outlook.and_then(|outlook| outlook.next_at_ms),
        rotation: rotation_state(data_dir),
        scrub_pending: stores.scrub_pending,
        set_aside_stores: stores.set_aside_stores,
        moved_aside: moved_aside_files(data_dir)
            .iter()
            .filter_map(|path| path.file_name())
            .map(|name| name.to_string_lossy().into_owned())
            .collect(),
        unseal_unfinished: unseal_unfinished(data_dir),
        meta_rotation_unfinished: meta_rotation_unfinished(data_dir),
    }
}

/// The SQLite stores that exist, with their header's `user_version` and
/// whether each is keyed ([`StoreVersion::keyed`]).
pub fn store_versions(data_dir: &Path) -> Vec<StoreVersion> {
    STORES
        .iter()
        .filter_map(|(file, keyed, _)| {
            let version = crate::sqlite_rebuild::header_user_version(&data_dir.join(file))?;
            // The app store's keyed schema keys its sender columns only: one
            // whose outbox or pairing budget holds rows (or that cannot be
            // read for them) still names friends in clear.
            let (clear_tables, readable) = if *file == crate::app_store::APP_STORE_FILE {
                match crate::app_store::clear_tables_with_rows(data_dir) {
                    Ok(tables) => (tables, true),
                    Err(_) => (Vec::new(), false),
                }
            } else {
                (Vec::new(), true)
            };
            Some(StoreVersion {
                file,
                user_version: version,
                keyed: version >= *keyed && readable && clear_tables.is_empty(),
                clear_tables,
            })
        })
        .collect()
}

impl PrivacyReport {
    /// `raven privacy status --json`: `{"v":1, ...}`, the version first.
    /// Fields are only ever added; a reader ignores the ones it does not
    /// know.
    pub fn to_json(&self) -> serde_json::Value {
        let notes = self.status.to_ipc(self.status.state()).notes;
        serde_json::json!({
            "v": 1,
            "mode": self.status.mode.as_str(),
            "state": self.status.state(),
            "files": {
                "sealed": self.sealed_files,
                "plain": self.plain_files,
            },
            "stores": self.stores.iter().map(|store| serde_json::json!({
                "file": store.file,
                "user_version": store.user_version,
                "keyed": store.keyed,
                "clear_tables": store.clear_tables,
            })).collect::<Vec<_>>(),
            "chats": {
                "keep": self.keep.as_str(),
                "next_deletion_at_ms": self.next_deletion_at_ms,
            },
            "addresses": {
                "forget_after_days": FORGET_ADDRESSES_AFTER_DAYS,
            },
            "rotation": {
                "last_at_ms": self.rotation.last_rotation_at_ms,
                "old_epoch_held": self.rotation.old_epoch_held(),
                "due": self.rotation.due,
                "old_objects": self.rotation.old_objects,
            },
            "scrub_pending": self.scrub_pending,
            "set_aside_stores": self.set_aside_stores,
            "moved_aside": self.moved_aside,
            "notes": notes,
            "unfinished": {
                "unseal": self.unseal_unfinished,
                "rotate_meta": self.meta_rotation_unfinished,
            },
        })
    }
}

// ── The way back: `raven privacy unseal` ──────────────────────────────────

/// What [`unseal_all`] did: counts only.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UnsealReport {
    /// Nothing was ever sealed here and nothing needed writing back (on
    /// Windows no blob K_hist sealed): only the mode was recorded.
    pub already_plain: bool,
    /// Sealed files written back in plain (the noise pins and the policy's
    /// sidecar under their older names).
    pub files: u16,
    /// Chat cursors placed in the order an older build reads.
    pub cursors: u16,
    /// The history and the outbound stage were written back.
    pub history: bool,
    pub stage: bool,
    /// App rows written back under the chat-history key.
    pub app_rows: u32,
    /// SQLite rows moved back to their clear columns ...
    pub rows: u32,
    /// ... and rows left out because their sealed values did not open (and
    /// friend custody's released digests).
    pub dropped: u32,
    /// Files and app rows that do not open with this profile's keys: left
    /// as they are (they did not open before either).
    pub unreadable: u32,
    /// A store's scrub waits for the next prune pass.
    pub scrub_pending: bool,
}

/// Privacy pack PP.18, `raven privacy unseal` (review R12): write this
/// profile back in the forms a build before the pack reads, and keep this
/// build from sealing it again until `raven privacy seal-now`. The caller
/// stopped this profile's node; `node_gone` says whether it is still gone
/// ([`CommandError::NodeRunning`] otherwise, nothing changed). Refused while
/// an erase did not finish. In this order, every part a no-op once done:
///
/// 1. The at-rest keys are loaded (outside every lock: a keystore call),
///    the at-rest lock is taken, the protected state of each session head
///    whose `meta` does not open is deleted (a failure leaves the profile
///    as it was), and the mode is `unsealed_by_user`: no writer seals from
///    here on, and no migration seals again.
/// 2. Each chat cursor saved in the schema-3 inbox order is placed in the
///    order an older build reads, while the store still has its keys.
/// 3. Every registered sealed file is written back in plain under its
///    writer lock (`at_rest::unseal_file`); the noise pins go back to
///    `lan_noise_pins.json` and the policy's sidecar into
///    `node_policy.json`.
/// 4. The history (RVNHIST1, `stored_at_ms` dropped), the outbound stage
///    (RVNOSTG1) and the app rows go back under the chat-history key
///    directly (on Windows DPAPI directly, as before PP.11).
/// 5. The SQLite stores move back with the rebuild recipe: owed ACKs to
///    schema 1, the app store to 2, friend custody to 1 and, outside the
///    at-rest lock (its open replays journals), the session store to 1.
/// 6. `meta_key.rmk` goes last, and the records of what was sealed with it.
///
/// A profile without `meta_key.rmk` has only its mode recorded, and on
/// Windows its history, stage and app rows that K_hist sealed behind PP.11's
/// tag go back DPAPI-direct with K_hist from its file (review
/// A-keys-format-1: the sealing was held back while K_hist existed).
///
/// Lock files keep their keyed names: an older build creates its own.
pub fn unseal_all(
    data_dir: &Path,
    node_gone: &dyn Fn() -> bool,
) -> Result<UnsealReport, CommandError> {
    crate::erase::refuse_if_unfinished(data_dir).map_err(CommandError::Failed)?;
    let mut report = UnsealReport::default();
    let key_file = data_dir.join(META_KEY_FILE).exists();
    if mode(data_dir) == Mode::Plain && !key_file {
        // Nothing was ever sealed here: recorded, so this build never seals
        // it by itself. On Windows what K_hist sealed while the sealing was
        // held back goes back DPAPI-direct (review A-keys-format-1).
        if !node_gone() {
            return Err(CommandError::NodeRunning);
        }
        set_mode(data_dir, Mode::UnsealedByUser).map_err(failed)?;
        untag_for_older_build(data_dir, &mut report)?;
        report.already_plain =
            !report.history && !report.stage && report.app_rows == 0 && report.unreadable == 0;
        return Ok(report);
    }
    if key_file {
        at_rest::keys_load_with(data_dir, MigratePolicy::Never).map_err(|e| {
            if e.is_unavailable() {
                CommandError::Failed(key_unavailable_text(data_dir).to_owned())
            } else {
                failed(e)
            }
        })?;
    }
    if !node_gone() {
        return Err(CommandError::NodeRunning);
    }
    let all = DataDirLock::acquire(data_dir, at_rest::AT_REST_LOCK).map_err(failed)?;
    if key_file {
        // The protected state of each session head that does not open goes
        // before the mode changes (review B-sealed-stores-3): a keystore
        // delete that fails leaves the profile as it was.
        crate::indexed_session_store::forget_unreadable_sessions(data_dir)
            .map_err(CommandError::Failed)?;
    }
    set_mode(data_dir, Mode::UnsealedByUser).map_err(failed)?;
    if key_file {
        report.cursors = place_cursors(data_dir).map_err(failed)?;
        unseal_files(data_dir, &mut report)?;
        #[cfg(test)]
        tests::crash_point(tests::Crash::UnsealedFiles).map_err(failed)?;
        report.history = crate::chat_history::ChatHistory::unseal(data_dir).map_err(failed)?;
        report.stage = crate::chat_history::unseal_stage(data_dir).map_err(failed)?;
        let rows = crate::app_store::unseal_rows(data_dir).map_err(failed)?;
        report.app_rows = rows.resealed;
        report.unreadable += rows.unreadable;
        report.scrub_pending |= rows.scrub_pending;
        let stores = [
            crate::owed_acks::unseal(data_dir).map_err(|e| e.to_string()),
            crate::app_store::unseal(data_dir),
            crate::friend_custody::unseal(data_dir),
            crate::custody_handoff::unseal(data_dir),
            // No clear shape: the security ledger goes (Phase 6b P6.23).
            crate::security_ledger::unseal(data_dir),
            // Nor the learning model, which is never in clear (Phase 6a
            // P6.9): it goes, and an older build never read it (review
            // learning-3). unseal_files left it sealed until now.
            crate::learning::store::delete(data_dir)
                .map(|()| crate::sqlite_rebuild::Migration::default()),
        ];
        for moved in stores {
            add_moved(&mut report, moved.map_err(CommandError::Failed)?);
        }
        #[cfg(test)]
        tests::crash_point(tests::Crash::UnsealedStores).map_err(failed)?;
        drop(all);
        add_moved(
            &mut report,
            crate::indexed_session_store::unseal(data_dir).map_err(CommandError::Failed)?,
        );
        #[cfg(test)]
        tests::crash_point(tests::Crash::UnsealedAll).map_err(failed)?;
    } else {
        drop(all);
        // An unsealing without a key file that stopped after the mode was
        // recorded: its Windows part, as in the first run.
        untag_for_older_build(data_dir, &mut report)?;
    }
    let _all = DataDirLock::acquire(data_dir, at_rest::AT_REST_LOCK).map_err(failed)?;
    at_rest::delete_key_file(data_dir).map_err(failed)?;
    update(data_dir, |file| {
        file.mode = Some(Mode::UnsealedByUser.as_str().to_owned());
        file.kinds.clear();
        file.rotation = None;
        file.rotation_due = false;
        file.meta_rotation = None;
        file.space_deferred_at_ms = None;
        file.space_needed_bytes = None;
        // `raven privacy seal-now` seals as a first sealing: its notice
        // again, and no plain file is a downgrade leftover.
        file.notices.sealing_shown = false;
        file.notices.older_build_wrote_plain = false;
        file.notices.older_build_pinned_differently = 0;
    })
    .map_err(failed)?;
    Ok(report)
}

/// Windows, [`unseal_all`] in a profile without `meta_key.rmk` (review
/// A-keys-format-1): the history, the stage and the app rows K_hist sealed
/// behind PP.11's tag (written while the sealing was held back, by a debug
/// build's pass without the lab switch, or after a sealing that stopped
/// before its key file) go back DPAPI-direct, the form a build before PP.11
/// reads, with K_hist from its file. The mode says unsealed already; each
/// part is a no-op once done.
#[cfg(any(test, windows))]
fn untag_for_older_build(data_dir: &Path, report: &mut UnsealReport) -> Result<(), CommandError> {
    use crate::chat_history::windows_key;
    if !windows_key::active() {
        return Ok(());
    }
    report.history |= windows_key::untag_history(data_dir).map_err(failed)?;
    report.stage |= windows_key::untag_stage(data_dir).map_err(failed)?;
    let rows = crate::app_store::untag_rows(data_dir).map_err(CommandError::Failed)?;
    report.app_rows = report.app_rows.saturating_add(rows.resealed);
    report.unreadable = report.unreadable.saturating_add(rows.unreadable);
    report.scrub_pending |= rows.scrub_pending;
    Ok(())
}

/// Nothing outside Windows: K_hist seals no tagged blob there.
#[cfg(not(any(test, windows)))]
fn untag_for_older_build(_data_dir: &Path, _report: &mut UnsealReport) -> Result<(), CommandError> {
    Ok(())
}

fn add_moved(report: &mut UnsealReport, moved: crate::sqlite_rebuild::Migration) {
    report.rows = report.rows.saturating_add(moved.rows);
    report.dropped = report.dropped.saturating_add(moved.dropped);
    report.scrub_pending |= moved.scrub_pending;
}

/// Step 3 of [`unseal_all`]: every registered sealed file that is sealed,
/// back in plain. One that does not open with this profile's keys (a
/// changed byte, another profile's) is left as it is and counted; one that
/// cannot be read now stops the command. Not the learning model: it has no
/// clear shape, and [`unseal_all`] deletes it with the stores.
fn unseal_files(data_dir: &Path, report: &mut UnsealReport) -> Result<(), CommandError> {
    let pins = data_dir.join(crate::lan_noise_pin::NOISE_PIN_SEALED_FILE);
    for (path, kind) in sealed_files(data_dir) {
        if kind == Kind::LearningStore {
            continue;
        }
        let sealed = file_head(&path).is_some_and(|head| at_rest::is_sealed_as(kind, &head));
        if !sealed && kind != Kind::NodePolicyPeers && path != pins {
            continue;
        }
        let done = match kind {
            Kind::NodePolicyPeers => crate::node_policy::unseal_peers(data_dir).map(drop),
            Kind::NoisePins if path == pins => {
                crate::lan_noise_pin::unseal_into_plain(data_dir).map(drop)
            }
            _ => at_rest::unseal_file(data_dir, &path, kind),
        };
        match done {
            Ok(()) => report.files = report.files.saturating_add(1),
            Err(
                AtRestError::Tampered { .. }
                | AtRestError::WrongKind { .. }
                | AtRestError::Truncated
                | AtRestError::NewerFormat(_)
                | AtRestError::Json(_),
            ) => report.unreadable += 1,
            Err(e) => {
                let name = path.strip_prefix(data_dir).unwrap_or(&path).display();
                return Err(CommandError::Failed(format!("{name}: {e}")));
            }
        }
    }
    Ok(())
}

/// Step 2 of [`unseal_all`]: each cursor of `chat_inbox_cursors.json` saved
/// in the schema-3 inbox order (`{"seq": n}`, PP.14) is placed in the order
/// a build before PP.14 reads (`{"received_at_ms": t, "message_id_hex":
/// ..}`) with exactly the same messages after it, while the session store
/// still has its keyed columns; written under the file's writer lock (in
/// plain: the mode says so). How many were placed; none without a keyed
/// store.
fn place_cursors(data_dir: &Path) -> Result<u16, String> {
    let path = data_dir.join(crate::chat_history::CHAT_INBOX_CURSORS_FILE);
    if std::fs::symlink_metadata(&path).is_err() {
        return Ok(0);
    }
    let lock =
        at_rest::lock_file(data_dir, &path, Kind::ChatInboxCursors).map_err(|e| e.to_string())?;
    let Some(raw) = lock.load_bytes().map_err(|e| e.to_string())? else {
        return Ok(0);
    };
    // Not a cursor map this build can read: the chat refuses it either way,
    // and step 3 writes it back as it is.
    let Ok(serde_json::Value::Object(mut map)) = serde_json::from_slice(&raw) else {
        return Ok(0);
    };
    let mut placed = 0u16;
    for (contact, entry) in map.iter_mut() {
        let Some(seq) = entry.get("seq").and_then(serde_json::Value::as_u64) else {
            continue;
        };
        let Some(device) = hex::decode(contact)
            .ok()
            .and_then(|raw| <[u8; 32]>::try_from(raw).ok())
        else {
            continue;
        };
        // Without a keyed store there is nothing after it to place.
        let position = crate::indexed_session_store::received_position_of(data_dir, &device, seq)?
            .unwrap_or(crate::indexed_session_store::InboxPosition::START);
        let mut placed_entry = serde_json::Map::new();
        placed_entry.insert("received_at_ms".into(), position.seq.into());
        if let Some(id) = position.message_id {
            placed_entry.insert("message_id_hex".into(), hex::encode(id).into());
        }
        *entry = serde_json::Value::Object(placed_entry);
        placed = placed.saturating_add(1);
    }
    if placed == 0 {
        return Ok(0);
    }
    let json =
        serde_json::to_vec_pretty(&serde_json::Value::Object(map)).map_err(|e| e.to_string())?;
    lock.store_bytes(&json).map_err(|e| e.to_string())?;
    Ok(placed)
}

// ── `raven privacy seal-now` ──────────────────────────────────────────────

/// Privacy pack PP.18, `raven privacy seal-now`: leave `unsealed_by_user`
/// and seal this profile ([`migrate_all_with`], which also moves every
/// SQLite store forward and scrubs it; then [`upkeep_stores`] finishes a
/// scrub a reader held up). `policy` says whether this build may seal
/// ([`SEAL_NOT_ALLOWED_TEXT`] otherwise, nothing changed); while an older
/// raven-node answers (`older_node`) nothing changes either
/// ([`MigrateOutcome::OlderNodeRunning`]). A profile sealed already is
/// sealed further (what an older build wrote since). Call it at the
/// command's top level, never under a lock: it may load the keys.
pub fn seal_now(
    data_dir: &Path,
    now_ms: u64,
    policy: MigratePolicy,
    older_node: Option<&dyn Fn() -> bool>,
) -> Result<MigrateReport, String> {
    crate::erase::refuse_if_unfinished(data_dir)?;
    refuse_if_meta_rotation_unfinished(data_dir)?;
    if !policy.allows_sealing() {
        return Err(SEAL_NOT_ALLOWED_TEXT.to_owned());
    }
    if mode(data_dir) == Mode::UnsealedByUser {
        if older_node.is_some_and(|answers| answers()) {
            return Ok(MigrateReport::only(MigrateOutcome::OlderNodeRunning));
        }
        set_mode(data_dir, Mode::Plain).map_err(|e| e.to_string())?;
    }
    let report =
        migrate_all_with(data_dir, now_ms, policy, older_node).map_err(|e| e.to_string())?;
    if report.outcome == MigrateOutcome::Sealed {
        let _ = upkeep_stores(data_dir);
    }
    Ok(report)
}

// ── `raven privacy rotate-meta` ───────────────────────────────────────────

/// What [`rotate_meta`] did: counts only.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MetaRotationReport {
    /// This run picked a key change up that an earlier one started.
    pub resumed: bool,
    /// The epoch everything is sealed under now.
    pub epoch: u32,
    /// SQLite rows keyed again ...
    pub rows: u32,
    /// ... and rows left out (they did not open; friend custody's released
    /// digests).
    pub dropped: u32,
    /// Files, the history, the stage and app rows sealed again.
    pub resealed: u32,
    /// Per-friend lock files renamed.
    pub lock_files: u16,
    /// A store's scrub waits for the next prune pass.
    pub scrub_pending: bool,
}

/// Privacy pack PP.18, `raven privacy rotate-meta`: for a profile that
/// suspects an exposure of its keys, a new `k_index` AND a new epoch. The
/// caller stopped this profile's node (`node_gone`, as for [`unseal_all`]);
/// sealed profiles only ([`NOT_SEALED_TEXT`]), keys loaded. In this order:
///
/// 1. Every session-store journal is replayed under the old keys.
/// 2. Under the at-rest lock: the protected state of each session head
///    whose `meta` does not open is deleted (a failure leaves the profile
///    as it was), the change is recorded in `privacy.json`
///    (from here on only this command, unseal, status and erase run on the
///    profile, and raven-node does not start), then the key file gets the
///    new `k_index` and the new epoch as current, keeping the old epochs
///    ([`at_rest::begin_meta_rotation`]): the new key is on disk before any
///    store uses it.
/// 3. Each SQLite store is keyed again in one rebuild-recipe transaction
///    (its keyed values are primary keys): back to the clear columns and
///    forward under the new keys in memory, nothing clear written.
/// 4. Each friend's keyed send-lock file gets its new name, both names held
///    while the old file goes; a keyed lock file no friend in the book has
///    goes.
/// 5. Every sealed file, the history, the stage and the app rows are sealed
///    again under the new epoch (the data-key rotation's pass).
/// 6. The old epochs leave the key file, and the record goes.
///
/// A crash anywhere is finished by running it again (every step is a no-op
/// once done; a store keyed again twice is the same store). Lock files of an
/// interrupted run keep their old names (they name no friend either) until
/// the run that finishes it deletes them (step 4).
pub fn rotate_meta(
    data_dir: &Path,
    now_ms: u64,
    node_gone: &dyn Fn() -> bool,
) -> Result<MetaRotationReport, CommandError> {
    crate::erase::refuse_if_unfinished(data_dir).map_err(CommandError::Failed)?;
    if mode(data_dir) != Mode::Sealed {
        return Err(CommandError::Failed(NOT_SEALED_TEXT.to_owned()));
    }
    let keys_here = |data_dir: &Path| {
        at_rest::keys_cached(data_dir)
            .map_err(|_| CommandError::Failed(key_unavailable_text(data_dir).to_owned()))
    };
    keys_here(data_dir)?;
    if !node_gone() {
        return Err(CommandError::NodeRunning);
    }
    let mut report = MetaRotationReport {
        resumed: meta_rotation_unfinished(data_dir),
        ..MetaRotationReport::default()
    };
    if !report.resumed {
        crate::indexed_session_store::settle_journals(data_dir).map_err(CommandError::Failed)?;
    }
    let all = DataDirLock::acquire(data_dir, at_rest::AT_REST_LOCK).map_err(failed)?;
    // The keys as they are under the lock (review A-keys-format-3): a
    // data-key rotation pass since the check above may have made the next
    // epoch current, and epoch `to` must be one this command adds. Every
    // epoch change happens under this lock and the passes leave the profile
    // alone once the change is recorded, so from here on epoch `to` current
    // means this command's own begin (a run picking it up again).
    let before = keys_here(data_dir)?;
    // The protected state of each session head that does not open goes
    // before the key change is recorded (review B-sealed-stores-3): a
    // keystore delete that fails stops a first run while raven-node still
    // starts the profile, and the store's re-key needs no keystore call.
    crate::indexed_session_store::forget_unreadable_sessions(data_dir)
        .map_err(CommandError::Failed)?;
    let file = read_file(data_dir).map_err(failed)?.unwrap_or_default();
    let (record, old_names) = match file.meta_rotation {
        Some(record) => (record, Vec::new()),
        None => {
            let to = before
                .epochs()
                .last()
                .and_then(|newest| newest.checked_add(1))
                .ok_or_else(|| failed(format!("{META_KEY_FILE}: no epoch number left")))?;
            let record = MetaRotationRecord {
                to,
                started_at_ms: now_ms,
            };
            let names = lock_names(data_dir, &before);
            update(data_dir, |file| file.meta_rotation = Some(record)).map_err(failed)?;
            #[cfg(test)]
            tests::crash_point(tests::Crash::MetaRotationRecorded).map_err(failed)?;
            (record, names)
        }
    };
    drop(before);
    let keys = at_rest::begin_meta_rotation(data_dir, record.to).map_err(failed)?;
    report.epoch = record.to;
    #[cfg(test)]
    tests::crash_point(tests::Crash::MetaKeyChanged).map_err(failed)?;
    let stores = [
        crate::owed_acks::rekey(data_dir).map_err(|e| e.to_string()),
        crate::app_store::rekey(data_dir),
        crate::friend_custody::rekey(data_dir),
        crate::indexed_session_store::rekey(data_dir),
        crate::custody_handoff::rekey(data_dir),
        crate::security_ledger::rekey(data_dir),
    ];
    for moved in stores {
        let moved = moved.map_err(CommandError::Failed)?;
        report.rows = report.rows.saturating_add(moved.rows);
        report.dropped = report.dropped.saturating_add(moved.dropped);
        report.scrub_pending |= moved.scrub_pending;
        #[cfg(test)]
        tests::crash_point(tests::Crash::MetaStoreRekeyed).map_err(failed)?;
    }
    report.lock_files = rename_lock_files(data_dir, &old_names, &keys);
    drop(keys);
    let mut resealed = RotationReport::default();
    reseal_everything(data_dir, &mut resealed).map_err(failed)?;
    report.resealed = resealed.resealed;
    report.scrub_pending |= resealed.scrub_pending;
    if resealed.pending > 0 {
        return Err(CommandError::Failed(format!(
            "{} could not be encrypted again now. Run `raven privacy rotate-meta` again.",
            if resealed.pending == 1 {
                "1 record".to_owned()
            } else {
                format!("{} records", resealed.pending)
            }
        )));
    }
    at_rest::drop_old_epochs(data_dir).map_err(failed)?;
    update(data_dir, |file| {
        file.meta_rotation = None;
        file.rotation = None;
        file.rotation_due = false;
        file.last_rotation_at_ms = Some(now_ms);
    })
    .map_err(failed)?;
    drop(all);
    Ok(report)
}

/// The keyed send-lock file names of the friends in the book under `keys`
/// (the old ones, before the key file changes): `(friend's key, name)`.
fn lock_names(data_dir: &Path, keys: &at_rest::MetaKeys) -> Vec<([u8; 32], String)> {
    crate::outbox::book_devices(data_dir)
        .unwrap_or_default()
        .into_iter()
        .map(|device| (device, at_rest::lock_name(keys, &device)))
        .collect()
}

/// Step 4 of [`rotate_meta`]: each old send-lock file that exists is taken
/// (a send in progress holds it: then it keeps its name), the new one too,
/// and the old file goes while the new one is held. Then a keyed lock file
/// no friend in the book has under the new keys goes unless a send holds it
/// ([`crate::outbox::PeerSendLock::remove_stray_keyed_files`]: a contact
/// removed before the upgrade, a run that stopped before this step). How
/// many were renamed.
fn rename_lock_files(
    data_dir: &Path,
    old_names: &[([u8; 32], String)],
    keys: &at_rest::MetaKeys,
) -> u16 {
    const WAIT: std::time::Duration = std::time::Duration::from_millis(500);
    let mut renamed = 0u16;
    for (device, old) in old_names {
        let new = at_rest::lock_name(keys, device);
        if *old == new {
            continue;
        }
        let Ok(Some(old_held)) = DataDirLock::acquire_existing_within(data_dir, old, WAIT) else {
            continue;
        };
        let Ok(_new_held) = DataDirLock::acquire_within(data_dir, &new, WAIT) else {
            continue;
        };
        // Windows deletes no file this process still has open: the old one
        // is let go first, the new one still held (as
        // `PeerSendLock::remove_legacy_files` does).
        drop(old_held);
        if std::fs::remove_file(data_dir.join(old)).is_ok() {
            renamed = renamed.saturating_add(1);
        }
    }
    if renamed > 0 {
        crate::paths::sync_dir_best_effort(data_dir);
    }
    crate::outbox::PeerSendLock::remove_stray_keyed_files(data_dir, keys);
    renamed
}

// ── `raven privacy forget-moved-aside` ────────────────────────────────────

/// The plaintext histories an older build stranded in this profile
/// (`chat_history.json.untrusted-plaintext.*`: moved aside, never
/// imported), sorted.
pub fn moved_aside_files(data_dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(data_dir) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .flatten()
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with(MOVED_ASIDE_PREFIX))
        })
        .filter(|entry| entry.file_type().is_ok_and(|t| t.is_file()))
        .map(|entry| entry.path())
        .collect();
    files.sort();
    files
}

/// Privacy pack PP.18, `raven privacy forget-moved-aside` (after the typed
/// confirmation): overwrite each of [`moved_aside_files`] with zeros, then
/// delete it. How many went; the first failure stops it (what went is
/// gone).
pub fn forget_moved_aside(data_dir: &Path) -> Result<usize, String> {
    let mut removed = 0;
    for path in moved_aside_files(data_dir) {
        if crate::erase::remove_file(&path, true)? {
            removed += 1;
        }
    }
    if removed > 0 {
        crate::paths::sync_dir_best_effort(data_dir);
    }
    Ok(removed)
}
