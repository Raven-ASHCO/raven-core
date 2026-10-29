//! Erase this profile (privacy pack PP.16, `raven erase`;
//! docs/design/2026-10-at-rest-metadata.md section 4.14).
//!
//! ash's `raven erase` runs the steps in this order (review R03, R15):
//!
//! 0. [`refusal`]: nothing is changed unless the folder is a Raven profile
//!    (an identity on record, an unfinished erase, or one of the files only
//!    Raven writes), is not the home folder, a folder above it or a
//!    filesystem root, and, in a debug build, lies inside
//!    `RAVEN_LAB_ERASE_ROOT`.
//! 1. ash stops the node and confirms it stopped (no IPC answer, the
//!    instance lock free); only then [`begin`] writes the plain marker
//!    [`MARKER_FILE`] (fsynced). From then on every entry point of this build
//!    refuses the profile with [`UNFINISHED_TEXT`] except `raven erase`: ash
//!    and raven-node at their start, ash's auto-start, and every Raven lock
//!    or store opened in the folder ([`refuse_if_unfinished`] in
//!    `paths::prepare_private_data_dir_sqlite_file`, the session store, the
//!    prekey store, K_hist's and `meta_key.rmk`'s creation). So no process
//!    mints K_hist again or recreates a file, and a Raven process still open
//!    on the profile refuses its next operation.
//! 2. [`execute`], crypto-erase first: K_hist (the keychain or Secret
//!    Service item, Windows' `chat_history_key.dpapi`, or the passphrase
//!    vault, which holds it and every other key of the profile). From that
//!    moment the chat history, the outbound stage, the app rows,
//!    `meta_key.rmk` and with it every sealed file and SQLite meta blob are
//!    unreadable. Then the identity item, every per-session item and the
//!    prekey item: their names are derived from this data dir only (the
//!    session items from the store's record keys, which stay clear, and on
//!    macOS and GNU/Linux every item of the session service whose account
//!    starts with this data dir's namespace: one whose head was never
//!    recorded, or all of them when the store can't be read), so no item of
//!    another profile is ever named.
//! 3. The small key files, and an interrupted write's temp copy of one,
//!    overwritten and then deleted (hygiene only: on APFS and SSDs an
//!    overwrite lands in new blocks).
//! 4. Only Raven's files: what the registry ([`crate::at_rest::FILES`])
//!    names, its declared patterns, quarantine copies (`<file>.corrupt*`)
//!    and interrupted writes' temp files (`.<file>.tmp.<16 hex>`) beside
//!    them, Raven's own folders, then this profile's IPC socket and its lock
//!    (in the long-path fallback only `/tmp/raven-<euid>/raven-<hash>.sock`
//!    and its `.lock`: the folder is shared by every profile of the user). A
//!    pass that finds a file written meanwhile (a process already inside a
//!    write when the marker went down) deletes it too. The marker goes last,
//!    and the folder only when it is empty then. Unknown files are left and
//!    listed. No symbolic link is followed: a link is deleted as a link, or
//!    left when it is not Raven's, and a file is deleted only while every
//!    folder on its way from the data dir is a real one.
//!
//! [`execute`] goes on past a failure and reports each one; the marker stays
//! until a run had none, so `raven erase` again (the plan is made from what
//! exists) finishes the work while the profile stays closed. A run in which
//! a conversation key could not be deleted, or the store's record keys could
//! not be read and no namespace pass got through, keeps the session store
//! (it names those keys) for the next run.
//!
//! No log line, no IPC, nothing on the wire: the report is for the user's
//! terminal.

use std::path::{Path, PathBuf};

use crate::at_rest::{self, rule_for};
use crate::sanitize::sanitize_terminal_line;

/// The marker of an erase that began: plain, holds no data. Registered in
/// [`crate::at_rest::FILES`]; older builds ignore it.
pub const MARKER_FILE: &str = "erase_in_progress";

/// What every entry point but `raven erase` says while the marker is there
/// (the privacy pack's UX copy).
pub const UNFINISHED_TEXT: &str =
    "An erase of this Raven profile did not finish. Run `raven erase` to finish it.";

/// What a debug build says outside `RAVEN_LAB_ERASE_ROOT`, or without it.
pub const LAB_GUARD_TEXT: &str = "this debug build erases only a profile inside \
     RAVEN_LAB_ERASE_ROOT (a lab switch), and it is not set or this folder is outside it: a \
     release build erases any Raven profile";

/// Files only Raven writes: one of them shows that a folder without an
/// identity record is a Raven profile (one whose erase stopped part-way
/// keeps the marker). A file any program could name (`contacts.json`) is not
/// proof.
const PROOF_FILES: &[&str] = &[
    MARKER_FILE,
    at_rest::META_KEY_FILE,
    crate::privacy::PRIVACY_FILE,
    crate::keystore_vault::VAULT_FILE_NAME,
    crate::keystore_select::KEYSTORE_MARKER_NAME,
    crate::identity_store::SEED_FILE_NAME,
    crate::chat_history::WINDOWS_HISTORY_KEY_FILE,
    crate::indexed_session_store::INDEXED_SESSION_METADATA_FILE,
    crate::paths::SERVICE_LOG_NAME,
    "raven-node.sock.lock",
];

/// The folders that hold nothing but per-session and prekey secrets
/// (Windows' DPAPI blobs, the lab backend's files): every file in them goes
/// with the keys of step 2.
const SESSION_SECRETS_DIR: &str = "indexed-session-secrets";
const PREKEY_SECRETS_DIR: &str = "prekey-lifecycle-secrets";
/// The lab prekey backend's file (debug builds only).
const PREKEY_LAB_FILE: &str = "prekey_lifecycle.protected";

/// Step 3: small files that hold keys, overwritten before they are deleted.
const KEY_FILES: &[&str] = &[
    at_rest::META_KEY_FILE,
    crate::identity_store::SEED_FILE_NAME,
    "device_x25519.secret",
    "lab_device_x25519.secret",
    "relay_key.ed25519",
    "friend_relay/relay_key.ed25519",
];

/// How many times [`execute`] looks again for files written while it ran.
const AGAIN_PASSES: usize = 3;

/// Whether an erase of this profile began and did not finish.
pub fn in_progress(data_dir: &Path) -> bool {
    std::fs::symlink_metadata(data_dir.join(MARKER_FILE)).is_ok()
}

/// [`UNFINISHED_TEXT`] while an erase of this profile is unfinished.
pub fn refuse_if_unfinished(data_dir: &Path) -> Result<(), String> {
    if in_progress(data_dir) {
        Err(UNFINISHED_TEXT.to_owned())
    } else {
        Ok(())
    }
}

/// The refusal for a folder erase will not touch (the UX copy).
pub fn not_a_profile_text(data_dir: &Path) -> String {
    format!(
        "This folder doesn't look like a Raven profile, so erase won't touch it: {}",
        sanitize_terminal_line(&data_dir.display().to_string())
    )
}

// ── Step 0: refusals ────────────────────────────────────────────────────────

/// Why `raven erase` must not touch `data_dir` (step 0), or None. Reads
/// only: nothing is changed when a refusal applies.
pub fn refusal(data_dir: &Path) -> Option<String> {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from);
    refusal_with(
        data_dir,
        home.as_deref(),
        cfg!(debug_assertions),
        crate::p2p_gate::lab_switch(crate::lan_gate::LAB_ERASE_ROOT),
    )
}

/// [`refusal`]'s rule: `home` the user's home folder, `debug` whether this
/// is a debug build, `erase_root` the lab switch (a release build passes
/// None and never reads it).
pub(crate) fn refusal_with(
    data_dir: &Path,
    home: Option<&Path>,
    debug: bool,
    erase_root: Option<String>,
) -> Option<String> {
    let not_a_profile = || Some(not_a_profile_text(data_dir));
    let Ok(dir) = std::fs::canonicalize(data_dir) else {
        return not_a_profile();
    };
    if !dir.is_dir() || dir.parent().is_none() {
        return not_a_profile();
    }
    if let Some(home) = home.and_then(|home| std::fs::canonicalize(home).ok()) {
        if home.starts_with(&dir) {
            return not_a_profile();
        }
    }
    if debug {
        let root = erase_root
            .map(PathBuf::from)
            .filter(|root| root.is_absolute())
            .and_then(|root| std::fs::canonicalize(root).ok());
        match root {
            Some(root) if dir.starts_with(&root) && dir != root => {}
            _ => return Some(LAB_GUARD_TEXT.to_owned()),
        }
    }
    if is_raven_profile(&dir) {
        None
    } else {
        not_a_profile()
    }
}

/// An identity on record, or one of the [`PROOF_FILES`].
fn is_raven_profile(dir: &Path) -> bool {
    matches!(crate::identity_store::identity_recorded(dir), Ok(true))
        || PROOF_FILES
            .iter()
            .any(|name| std::fs::symlink_metadata(dir.join(name)).is_ok())
}

// ── Step 1: the marker ──────────────────────────────────────────────────────

/// Writes the marker (plain, fsynced with its folder). ash calls it only once
/// the node is confirmed stopped; from then on the profile is closed to every
/// entry point but `raven erase`. An existing marker (a second run) is kept.
pub fn begin(data_dir: &Path) -> Result<(), String> {
    match crate::paths::create_new_private(&data_dir.join(MARKER_FILE), b"raven erase\n") {
        Ok(()) => Ok(()),
        Err(_) if in_progress(data_dir) => Ok(()),
        Err(e) => Err(format!("the erase could not begin: {e}")),
    }
}

/// Takes the marker away again, when nothing has been erased yet (a node
/// answered once more after it went down): the profile stays as it was.
pub fn abandon(data_dir: &Path) -> Result<(), String> {
    match std::fs::remove_file(data_dir.join(MARKER_FILE)) {
        Ok(()) => {
            crate::paths::sync_dir_best_effort(data_dir);
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

// ── The plan ────────────────────────────────────────────────────────────────

/// Which key an item holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRole {
    /// K_hist, the chat-history key: the key root of everything sealed.
    HistKey,
    /// The passphrase vault: K_hist and every other key of the profile.
    Vault,
    Identity,
    /// One conversation's keys.
    Session,
    /// The key-exchange (prekey) keys.
    Prekey,
}

impl KeyRole {
    fn words(self) -> &'static str {
        match self {
            KeyRole::HistKey => "the chat-history key",
            KeyRole::Vault => "the passphrase vault",
            KeyRole::Identity => "the identity key",
            KeyRole::Session => "a conversation key",
            KeyRole::Prekey => "the key-exchange keys",
        }
    }
}

/// One keystore entry of this profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeystoreItem {
    /// A macOS keychain or Secret Service generic password: its service and
    /// account, derived from this data dir only.
    Platform {
        role: KeyRole,
        service: &'static str,
        account: String,
    },
    /// Every keychain or Secret Service item of `service` whose account
    /// starts with `prefix` (this profile's session namespace): the
    /// per-session items an interrupted session start may have left without
    /// a head, and every one when the store's record keys can't be read.
    /// macOS and GNU/Linux.
    PlatformPrefix {
        role: KeyRole,
        service: &'static str,
        prefix: String,
    },
    /// A file in the data dir that holds keys: overwritten, then deleted.
    File { role: KeyRole, path: PathBuf },
}

impl KeystoreItem {
    fn platform(role: KeyRole, (service, account): (&'static str, String)) -> Self {
        KeystoreItem::Platform {
            role,
            service,
            account,
        }
    }

    fn role(&self) -> KeyRole {
        match self {
            KeystoreItem::Platform { role, .. }
            | KeystoreItem::PlatformPrefix { role, .. }
            | KeystoreItem::File { role, .. } => *role,
        }
    }

    /// What it is, in words, for the report.
    pub fn describe(&self, data_dir: &Path) -> String {
        let store = if cfg!(target_os = "macos") {
            "the keychain"
        } else {
            "the Secret Service"
        };
        match self {
            KeystoreItem::Platform { role, .. } => format!("{} ({store})", role.words()),
            KeystoreItem::PlatformPrefix { .. } => {
                format!("conversation keys left without a session ({store})")
            }
            KeystoreItem::File { role, path } => {
                format!("{} ({})", role.words(), relative(data_dir, path))
            }
        }
    }
}

/// Something that could not be erased: what failed, and what is therefore
/// still on this computer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub what: String,
    pub left: String,
}

/// What [`execute`] will delete, in its order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ErasePlan {
    /// The canonical data dir.
    pub data_dir: PathBuf,
    /// Step 2, K_hist first.
    pub keystore: Vec<KeystoreItem>,
    /// Step 3: overwritten, then deleted.
    pub key_files: Vec<PathBuf>,
    /// Step 4: Raven's files.
    pub data_files: Vec<PathBuf>,
    /// Raven's own folders, removed once empty (inner ones first).
    pub raven_dirs: Vec<PathBuf>,
    /// Step 5: this profile's IPC socket and its instance lock.
    pub socket_files: Vec<PathBuf>,
    /// Left in place because Raven did not create them.
    pub left_unknown: Vec<PathBuf>,
    /// What no erase reaches (step 6; the UX copy's words). ash adds the
    /// passphrase file the user made, when there is one.
    pub not_erasable: Vec<String>,
    /// What ash could not erase before [`execute`] (Raven's login item):
    /// reported as failures, so the marker stays.
    pub failed_before: Vec<Failure>,
    /// Step 2 could not read the session store's record keys (the failure
    /// is in `failed_before`): the store then stays in a run in which no
    /// namespace pass got through (review C-deletion-erase-1).
    pub session_keys_unlisted: bool,
}

/// This profile's erase plan, made from what exists now. Reads only.
pub fn plan(data_dir: &Path) -> Result<ErasePlan, String> {
    let dir = std::fs::canonicalize(data_dir).map_err(|e| {
        format!(
            "{}: {}",
            sanitize_terminal_line(&data_dir.display().to_string()),
            e
        )
    })?;
    let platform = platform_keystore_in_use(&dir);
    plan_with(&dir, platform)
}

/// Whether this process's keystore backends use the OS keystore (the macOS
/// keychain, GNU/Linux's Secret Service) for this profile: then its items are
/// planned. Never in a unit test, a debug build with a `locked-file` lab
/// backend, a passphrase-vault profile, or on Windows (keys in files there).
fn platform_keystore_in_use(data_dir: &Path) -> bool {
    if cfg!(test) {
        return false;
    }
    if cfg!(debug_assertions) {
        let lab = [
            "RAVEN_IDENTITY_BACKEND",
            "RAVEN_SESSION_BACKEND",
            "RAVEN_PREKEY_BACKEND",
            "RAVEN_CHAT_HISTORY_BACKEND",
        ]
        .iter()
        .any(|key| std::env::var_os(key).is_some_and(|v| v == "locked-file"));
        if lab {
            return false;
        }
    }
    #[cfg(target_os = "macos")]
    {
        let _ = data_dir;
        true
    }
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        !matches!(
            crate::keystore_select::uses_vault(data_dir, false),
            Ok(true)
        )
    }
    #[cfg(not(any(target_os = "macos", all(target_os = "linux", target_env = "gnu"))))]
    {
        let _ = data_dir;
        false
    }
}

/// [`plan`] of the canonical `dir`; `platform`: plan the OS keystore's items.
pub(crate) fn plan_with(dir: &Path, platform: bool) -> Result<ErasePlan, String> {
    let mut plan = ErasePlan {
        data_dir: dir.to_path_buf(),
        not_erasable: not_erasable(),
        ..ErasePlan::default()
    };
    // Step 2. K_hist first, wherever it is.
    if platform {
        plan.keystore.push(KeystoreItem::platform(
            KeyRole::HistKey,
            crate::chat_history::history_key_item(dir),
        ));
    }
    for (name, role) in [
        (
            crate::chat_history::WINDOWS_HISTORY_KEY_FILE,
            KeyRole::HistKey,
        ),
        (crate::keystore_vault::VAULT_FILE_NAME, KeyRole::Vault),
    ] {
        let path = dir.join(name);
        if entry_exists(&path) {
            plan.keystore.push(KeystoreItem::File { role, path });
        }
    }
    if platform {
        plan.keystore.push(KeystoreItem::platform(
            KeyRole::Identity,
            crate::identity_store::keychain_item(dir),
        ));
        let (service, namespace) = crate::indexed_session_store::erase_namespace(dir);
        match crate::indexed_session_store::erase_record_keys(dir) {
            Ok(keys) => {
                for key in keys {
                    plan.keystore.push(KeystoreItem::Platform {
                        role: KeyRole::Session,
                        service,
                        account: format!("{namespace}:{}", hex::encode(key)),
                    });
                }
            }
            Err(e) => {
                plan.session_keys_unlisted = true;
                plan.failed_before.push(Failure {
                    what: format!(
                        "the conversation keys could not be listed ({})",
                        sanitize_terminal_line(&e)
                    ),
                    left: KeystoreItem::PlatformPrefix {
                        role: KeyRole::Session,
                        service,
                        prefix: format!("{namespace}:"),
                    }
                    .describe(dir),
                })
            }
        }
        // Then every item of the service in this data dir's namespace: one
        // whose head was never recorded, all of them when the store can't be
        // read (the keychain too since review C-deletion-erase-1).
        if cfg!(any(
            target_os = "macos",
            all(target_os = "linux", target_env = "gnu")
        )) {
            plan.keystore.push(KeystoreItem::PlatformPrefix {
                role: KeyRole::Session,
                service,
                prefix: format!("{namespace}:"),
            });
        }
        plan.keystore.push(KeystoreItem::platform(
            KeyRole::Prekey,
            crate::prekey_lifecycle::erase_item(dir),
        ));
    }
    for (folder, role) in [
        (SESSION_SECRETS_DIR, KeyRole::Session),
        (PREKEY_SECRETS_DIR, KeyRole::Prekey),
    ] {
        let path = dir.join(folder);
        if !is_real_dir(&path) {
            continue;
        }
        for entry in entries(&path) {
            if is_real_dir(&entry) {
                plan.left_unknown.push(entry);
            } else {
                plan.keystore.push(KeystoreItem::File { role, path: entry });
            }
        }
        plan.raven_dirs.push(path);
    }
    let prekey_lab = dir.join(PREKEY_LAB_FILE);
    if entry_exists(&prekey_lab) {
        plan.keystore.push(KeystoreItem::File {
            role: KeyRole::Prekey,
            path: prekey_lab,
        });
    }
    // Step 3. One in a subfolder only while that folder is a real one: a
    // link is never followed out of the profile (review C-deletion-erase-2;
    // the walk below then lists the link).
    for name in KEY_FILES {
        let path = dir.join(name);
        if in_real_folders(dir, name) && entry_exists(&path) && !is_real_dir(&path) {
            plan.key_files.push(path);
        }
    }
    // Step 5: this profile's socket and lock only.
    let socket = crate::ipc::default_socket_path(dir);
    let lock = crate::ipc::instance_lock_path(&socket);
    for path in [socket, lock] {
        if entry_exists(&path) && !is_real_dir(&path) {
            plan.socket_files.push(path);
        }
    }
    // Step 4: what is left of the folder, Raven's or not.
    let taken: Vec<PathBuf> = plan
        .keystore
        .iter()
        .filter_map(|item| match item {
            KeystoreItem::File { path, .. } => Some(path.clone()),
            _ => None,
        })
        .chain(plan.key_files.iter().cloned())
        .chain(plan.socket_files.iter().cloned())
        .collect();
    for entry in entries(dir) {
        let Some(name) = entry
            .file_name()
            .and_then(|n| n.to_str())
            .map(str::to_owned)
        else {
            plan.left_unknown.push(entry);
            continue;
        };
        if name == MARKER_FILE
            || name == SESSION_SECRETS_DIR
            || name == PREKEY_SECRETS_DIR
            || taken.contains(&entry)
        {
            continue;
        }
        if is_real_dir(&entry) {
            if !raven_folder(&name) {
                plan.left_unknown.push(entry);
                continue;
            }
            plan_folder(&mut plan, &taken, entry, &name);
        } else if key_temp(&name) {
            plan.key_files.push(entry);
        } else if ravens_file(&name) {
            plan.data_files.push(entry);
        } else {
            plan.left_unknown.push(entry);
        }
    }
    Ok(plan)
}

/// One of Raven's folders (`name` below the profile): its files Raven's
/// or not, and the folders in it the registry names files in, the same way
/// (`updates/staged/<build serial>/`, P6.47). A link is never followed: it
/// is not a real folder, so it is listed as it is.
fn plan_folder(plan: &mut ErasePlan, taken: &[PathBuf], folder: PathBuf, name: &str) {
    for inner in entries(&folder) {
        let below = inner
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| format!("{name}/{n}"));
        match below {
            _ if taken.contains(&inner) => {}
            Some(below) if is_real_dir(&inner) && raven_folder(&below) => {
                plan_folder(plan, taken, inner, &below)
            }
            Some(below) if !is_real_dir(&inner) && key_temp(&below) => plan.key_files.push(inner),
            Some(below) if !is_real_dir(&inner) && ravens_file(&below) => {
                plan.data_files.push(inner)
            }
            _ => plan.left_unknown.push(inner),
        }
    }
    plan.raven_dirs.push(folder);
}

/// The UX copy's list of what no erase reaches (without the passphrase
/// file, which ash adds).
fn not_erasable() -> Vec<String> {
    vec![
        "your shell history and terminal scrollback".to_owned(),
        if cfg!(target_os = "macos") {
            "Time Machine backups and disk snapshots, if any".to_owned()
        } else {
            "backups and disk snapshots, if any".to_owned()
        },
        "files copied elsewhere".to_owned(),
    ]
}

/// A name the registry gives `raven erase` (its declared patterns too), a
/// quarantine copy of one (`<file>.corrupt`, `<file>.corrupt-<n>`,
/// `<file>.corrupt.<n>`), or an interrupted write's temp file beside one (in
/// a folder too: the registry's own temp pattern covers the top only;
/// review C-deletion-erase-3).
fn ravens_file(name: &str) -> bool {
    if name == MARKER_FILE {
        return false;
    }
    if rule_for(name).is_some_and(|rule| rule.erase) {
        return true;
    }
    if temp_of(name).is_some_and(|file| rule_for(&file).is_some_and(|rule| rule.erase)) {
        return true;
    }
    name.rfind(".corrupt")
        .filter(|&at| {
            let rest = &name[at + ".corrupt".len()..];
            rest.is_empty() || rest.starts_with('-') || rest.starts_with('.')
        })
        .is_some_and(|at| rule_for(&name[..at]).is_some_and(|rule| rule.erase))
}

/// A folder the registry names files in (`contact_inbox/`, `friend_relay/`,
/// `lan_pair_response/`, ...), its patterns' folders too (`updates/staged/*`
/// for `updates/staged/5`).
fn raven_folder(name: &str) -> bool {
    let depth = name.split('/').count();
    at_rest::FILES.iter().any(|rule| {
        let segments: Vec<&str> = rule.name.split('/').collect();
        rule.erase
            && segments.len() > depth
            && at_rest::registry::glob_match(&segments[..depth].join("/"), name)
    })
}

/// The file `name` was being written to when `name` is the temp file of an
/// interrupted atomic write (`.<file>.tmp.<16 hex>` in the same folder,
/// `paths::atomic_write_private`): `contact_inbox/.00ff.wire.tmp.<hex>`
/// gives `contact_inbox/00ff.wire`.
fn temp_of(name: &str) -> Option<String> {
    let (folder, last) = match name.rsplit_once('/') {
        Some((folder, last)) => (format!("{folder}/"), last),
        None => (String::new(), name),
    };
    if !crate::privacy::is_temp_name(last) {
        return None;
    }
    let (file, _) = last.strip_prefix('.')?.rsplit_once(".tmp.")?;
    Some(format!("{folder}{file}"))
}

/// A temp copy of one of the [`KEY_FILES`]: overwritten like the key.
fn key_temp(name: &str) -> bool {
    temp_of(name).is_some_and(|file| KEY_FILES.contains(&file.as_str()))
}

/// Whether every folder of `name` (a `/`-separated path below `dir`) is a
/// real folder, not a symbolic link to one.
fn in_real_folders(dir: &Path, name: &str) -> bool {
    let mut folder = dir.to_path_buf();
    let mut parts: Vec<&str> = name.split('/').collect();
    parts.pop();
    parts.into_iter().all(|part| {
        folder.push(part);
        is_real_dir(&folder)
    })
}

fn entry_exists(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

/// A folder itself, not a symbolic link to one (a link is deleted as a link:
/// erase never follows one out of the profile).
fn is_real_dir(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|meta| meta.is_dir())
}

/// The entries of a folder, sorted (none when it can't be read).
fn entries(dir: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|list| list.filter_map(|e| e.ok().map(|e| e.path())).collect())
        .unwrap_or_default();
    out.sort();
    out
}

/// `path` below `dir`, with `/`, for the report; the whole path when it is
/// elsewhere (the socket's fallback).
fn relative(dir: &Path, path: &Path) -> String {
    let shown = path
        .strip_prefix(dir)
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .unwrap_or_else(|_| path.display().to_string());
    sanitize_terminal_line(&shown)
}

// ── Execution ───────────────────────────────────────────────────────────────

/// What [`execute`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EraseReport {
    /// Keystore items and key files that existed and are gone.
    pub keys: usize,
    /// Other files that existed and are gone.
    pub files: usize,
    /// Each thing that could not be erased, in order.
    pub failures: Vec<Failure>,
    /// What is left in the folder because Raven did not create it.
    pub left_unknown: Vec<PathBuf>,
    /// The marker went: nothing of Raven's is left that this erase could
    /// reach.
    pub finished: bool,
    /// The folder itself went (it was empty at the end).
    pub folder_removed: bool,
    /// Raven's files this run kept on purpose for the next one: the session
    /// store while a conversation key it names may be left.
    pub kept: Vec<String>,
}

impl EraseReport {
    /// What is still on this computer, for the report ("Still on this
    /// computer: ...").
    pub fn still_here(&self) -> Vec<String> {
        self.failures
            .iter()
            .map(|f| f.left.clone())
            .chain(self.kept.iter().cloned())
            .collect()
    }
}

/// How [`execute`] deletes (a test records the order instead).
pub(crate) trait Remover {
    /// Ok(true) when the item was there and is gone now.
    fn keystore_item(&mut self, item: &KeystoreItem) -> Result<bool, String>;
    /// Ok(true) when the file was there and is gone now; `overwrite`: write
    /// zeros over a regular file first (best effort).
    fn file(&mut self, path: &Path, overwrite: bool) -> Result<bool, String>;
    /// Removes the folder when it is empty: Ok(true) when it went.
    fn empty_dir(&mut self, path: &Path) -> Result<bool, String>;
}

/// Carries out `plan` (steps 2 to 5) after [`begin`]; `progress` gets a few
/// words before each part. Goes on past a failure and reports each.
pub fn execute(plan: &ErasePlan, progress: &mut dyn FnMut(&str)) -> EraseReport {
    execute_with(plan, &mut Disk(&plan.data_dir), progress)
}

pub(crate) fn execute_with(
    plan: &ErasePlan,
    remover: &mut dyn Remover,
    progress: &mut dyn FnMut(&str),
) -> EraseReport {
    let dir = plan.data_dir.as_path();
    let mut report = EraseReport {
        failures: plan.failed_before.clone(),
        ..EraseReport::default()
    };
    if !in_progress(dir) {
        report.failures.push(Failure {
            what: "the erase did not begin (no marker)".to_owned(),
            left: "everything".to_owned(),
        });
        report.left_unknown = plan.left_unknown.clone();
        return report;
    }
    progress("Deleting the keys...");
    // The session store names each conversation key (its record keys): it
    // stays while one may be left that no later run could name otherwise
    // (review C-deletion-erase-1).
    let mut session_left = false;
    let mut namespace_swept = false;
    for item in &plan.keystore {
        let gone = delete_item(dir, item, remover, &mut report);
        if item.role() == KeyRole::Session {
            session_left |= !gone;
            namespace_swept |= gone && matches!(item, KeystoreItem::PlatformPrefix { .. });
        }
    }
    let keep_sessions = session_left || (plan.session_keys_unlisted && !namespace_swept);
    for path in &plan.key_files {
        delete_file(dir, path, true, remover, &mut report, true);
    }
    progress("Deleting Raven's files...");
    for path in plan.data_files.iter().chain(&plan.socket_files) {
        if keep_sessions && is_session_store(dir, path) {
            let store = crate::indexed_session_store::INDEXED_SESSION_METADATA_FILE.to_owned();
            if !report.kept.contains(&store) {
                report.kept.push(store);
            }
            continue;
        }
        delete_file(dir, path, false, remover, &mut report, false);
    }
    // A process that was already inside a write when the marker went down
    // may have finished it since (its next one is refused): look again.
    // After a failure the marker stays anyway, and the next run looks.
    let mut last = plan.clone();
    if report.failures.is_empty() && report.kept.is_empty() {
        for pass in 0..=AGAIN_PASSES {
            let again = match plan_with(dir, false) {
                Ok(again) => again,
                Err(e) => {
                    report.failures.push(Failure {
                        what: format!("the folder could not be read again ({e})"),
                        left: "Raven's files".to_owned(),
                    });
                    break;
                }
            };
            let more = again.keystore.len()
                + again.key_files.len()
                + again.data_files.len()
                + again.socket_files.len();
            last = again;
            if more == 0 {
                break;
            }
            if pass == AGAIN_PASSES {
                report.failures.push(Failure {
                    what: "Raven's files kept coming back: another Raven process still writes                            to this profile"
                        .to_owned(),
                    left: format!("{more} of Raven's files"),
                });
                break;
            }
            for item in &last.keystore {
                delete_item(dir, item, remover, &mut report);
            }
            for path in &last.key_files {
                delete_file(dir, path, true, remover, &mut report, true);
            }
            for path in last.data_files.iter().chain(&last.socket_files) {
                delete_file(dir, path, false, remover, &mut report, false);
            }
            if !report.failures.is_empty() {
                break;
            }
        }
    }
    let mut folders: Vec<&PathBuf> = plan.raven_dirs.iter().chain(&last.raven_dirs).collect();
    folders.sort_by(|a, b| {
        b.components()
            .count()
            .cmp(&a.components().count())
            .then(a.cmp(b))
    });
    folders.dedup();
    for folder in folders {
        if let Err(e) = remover.empty_dir(folder) {
            report.failures.push(Failure {
                what: format!("{} could not be removed ({e})", relative(dir, folder)),
                left: format!("the folder {}", relative(dir, folder)),
            });
        }
    }
    report.left_unknown = last.left_unknown;
    if !report.failures.is_empty() || !report.kept.is_empty() {
        return report;
    }
    match remover.file(&dir.join(MARKER_FILE), false) {
        Ok(_) => {
            crate::paths::sync_dir_best_effort(dir);
            report.finished = true;
            report.folder_removed = matches!(remover.empty_dir(dir), Ok(true));
        }
        Err(e) => report.failures.push(Failure {
            what: format!("{MARKER_FILE} could not be deleted ({e})"),
            left: MARKER_FILE.to_owned(),
        }),
    }
    report
}

/// Deletes one keystore item: false when that failed (reported).
fn delete_item(
    dir: &Path,
    item: &KeystoreItem,
    remover: &mut dyn Remover,
    report: &mut EraseReport,
) -> bool {
    match remover.keystore_item(item) {
        Ok(true) => report.keys += 1,
        Ok(false) => {}
        Err(e) => {
            report.failures.push(Failure {
                what: format!(
                    "{} could not be deleted ({})",
                    item.describe(dir),
                    sanitize_terminal_line(&e)
                ),
                left: item.describe(dir),
            });
            return false;
        }
    }
    true
}

/// The session store or one of its sidecars (its WAL may hold the newest
/// heads).
fn is_session_store(dir: &Path, path: &Path) -> bool {
    let store = crate::indexed_session_store::INDEXED_SESSION_METADATA_FILE;
    ["", "-wal", "-shm", "-journal"]
        .iter()
        .any(|suffix| *path == dir.join(format!("{store}{suffix}")))
}

fn delete_file(
    dir: &Path,
    path: &Path,
    overwrite: bool,
    remover: &mut dyn Remover,
    report: &mut EraseReport,
    key: bool,
) {
    match remover.file(path, overwrite) {
        Ok(true) if key => report.keys += 1,
        Ok(true) => report.files += 1,
        Ok(false) => {}
        Err(e) => report.failures.push(Failure {
            what: format!(
                "{} could not be deleted ({})",
                relative(dir, path),
                sanitize_terminal_line(&e)
            ),
            left: relative(dir, path),
        }),
    }
}

/// The real deletes, in the canonical data dir it holds.
struct Disk<'a>(&'a Path);

impl Remover for Disk<'_> {
    fn keystore_item(&mut self, item: &KeystoreItem) -> Result<bool, String> {
        match item {
            KeystoreItem::Platform {
                role,
                service,
                account,
            } => platform_delete(*role, service, account),
            KeystoreItem::PlatformPrefix {
                role,
                service,
                prefix,
            } => platform_delete_prefix(*role, service, prefix),
            KeystoreItem::File { path, .. } => remove_planned_file(self.0, path, true),
        }
    }

    fn file(&mut self, path: &Path, overwrite: bool) -> Result<bool, String> {
        remove_planned_file(self.0, path, overwrite)
    }

    fn empty_dir(&mut self, path: &Path) -> Result<bool, String> {
        remove_empty_dir(path)
    }
}

/// [`remove_file`] for a planned file: one in the data dir goes only while
/// every folder on its way from the data dir is a real folder, so a link put
/// in place after the plan was made is never followed out of the profile
/// (review C-deletion-erase-2). The socket's fallback, outside the data dir,
/// is deleted as it is.
fn remove_planned_file(data_dir: &Path, path: &Path, overwrite: bool) -> Result<bool, String> {
    if path.starts_with(data_dir) {
        for folder in path.ancestors().skip(1) {
            match std::fs::symlink_metadata(folder) {
                Ok(meta) if meta.is_dir() => {}
                Ok(_) => {
                    return Err("a folder in its path is a symbolic link (not followed)".into())
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
                Err(e) => return Err(e.to_string()),
            }
            if folder == data_dir {
                break;
            }
        }
    }
    remove_file(path, overwrite)
}

/// Deletes one file (a symbolic link as the link itself); with `overwrite`
/// a regular file gets zeros over its length first, fsynced (best effort).
pub(crate) fn remove_file(path: &Path, overwrite: bool) -> Result<bool, String> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e.to_string()),
    };
    if meta.is_dir() {
        return Err("a folder is in its place".to_owned());
    }
    if overwrite && meta.is_file() {
        overwrite_with_zeros(path, meta.len());
    }
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.to_string()),
    }
}

fn overwrite_with_zeros(path: &Path, len: u64) {
    use std::io::Write;
    // The key files are small; a larger file is not overwritten whole.
    const MAX: u64 = 64 * 1024 * 1024;
    let Ok(mut file) = std::fs::OpenOptions::new().write(true).open(path) else {
        return;
    };
    let zeros = [0u8; 8192];
    let mut left = len.min(MAX);
    while left > 0 {
        let n = left.min(zeros.len() as u64) as usize;
        if file.write_all(&zeros[..n]).is_err() {
            return;
        }
        left -= n as u64;
    }
    let _ = file.sync_all();
}

/// Removes a folder when it is empty: Ok(false) when it holds anything (or
/// is gone).
pub(crate) fn remove_empty_dir(path: &Path) -> Result<bool, String> {
    match std::fs::read_dir(path) {
        Ok(mut list) => {
            if list.next().is_some() {
                return Ok(false);
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e.to_string()),
    }
    match std::fs::remove_dir(path) {
        Ok(()) => {
            if let Some(parent) = path.parent() {
                crate::paths::sync_dir_best_effort(parent);
            }
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.to_string()),
    }
}

// ── The OS keystores (production deletes; the owner's real row R34) ─────────

/// Deletes one generic password of this profile (every copy, should there be
/// more than one): Ok(true) when one was there. Not found is not an error.
#[cfg(target_os = "macos")]
fn platform_delete(role: KeyRole, service: &str, account: &str) -> Result<bool, String> {
    let mut deleted = false;
    for _ in 0..8 {
        if !keychain_delete_item(role, service, account)? {
            return Ok(deleted);
        }
        deleted = true;
    }
    Ok(deleted)
}

/// errSecItemNotFound: the only status that proves no such item exists.
#[cfg(target_os = "macos")]
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25_300;

/// What a keychain call for `role` is about, for the wait hint.
#[cfg(target_os = "macos")]
fn keychain_what(role: KeyRole) -> crate::macos_keychain::KeychainWhat {
    use crate::macos_keychain::KeychainWhat;
    match role {
        KeyRole::HistKey | KeyRole::Vault => KeychainWhat::ChatHistoryKey,
        KeyRole::Identity => KeychainWhat::IdentitySeed,
        KeyRole::Session => KeychainWhat::SessionSecret,
        KeyRole::Prekey => KeychainWhat::PrekeyState,
    }
}

/// One keychain delete, inside the access-dialog guard.
#[cfg(target_os = "macos")]
fn keychain_delete_item(role: KeyRole, service: &str, account: &str) -> Result<bool, String> {
    use crate::macos_keychain::guarded;
    use security_framework::passwords::delete_generic_password;
    match guarded(keychain_what(role), || {
        delete_generic_password(service, account)
    }) {
        Ok(()) => Ok(true),
        Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(false),
        Err(e) => Err(format!("keychain delete failed: {e}")),
    }
}

/// Deletes every generic password of `service` whose account starts with
/// `prefix` (this profile's session namespace), each by its account:
/// Ok(true) when any was there. It finds an item whose head was never
/// recorded, and every one when the store's record keys can't be read
/// (review C-deletion-erase-1).
#[cfg(target_os = "macos")]
fn platform_delete_prefix(role: KeyRole, service: &str, prefix: &str) -> Result<bool, String> {
    let mut deleted = false;
    for account in keychain_accounts(role, service)? {
        if account.starts_with(prefix) {
            deleted |= platform_delete(role, service, &account)?;
        }
    }
    Ok(deleted)
}

/// The account of every generic password of `service`, inside the
/// access-dialog guard. Attributes only: no secret is read, so no item asks
/// for access (owner row R34.6 records it).
#[cfg(target_os = "macos")]
fn keychain_accounts(role: KeyRole, service: &str) -> Result<Vec<String>, String> {
    use crate::macos_keychain::guarded;
    use security_framework::item::{ItemClass, ItemSearchOptions, Limit};
    // kSecAttrAccount's key in a search result's attributes.
    const ACCOUNT: &str = "acct";
    match guarded(keychain_what(role), || {
        ItemSearchOptions::new()
            .class(ItemClass::generic_password())
            .service(service)
            .load_attributes(true)
            .limit(Limit::All)
            .search()
    }) {
        Ok(found) => Ok(found
            .iter()
            .filter_map(|item| item.simplify_dict()?.remove(ACCOUNT))
            .collect()),
        Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(Vec::new()),
        Err(e) => Err(format!("keychain search failed: {e}")),
    }
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn platform_delete(_role: KeyRole, service: &str, account: &str) -> Result<bool, String> {
    secret_service_delete(service, Some(account), None)
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn platform_delete_prefix(_role: KeyRole, service: &str, prefix: &str) -> Result<bool, String> {
    secret_service_delete(service, None, Some(prefix))
}

/// Deletes the Secret Service items of `service` with this `account`, or
/// whose account starts with `prefix`: Ok(true) when any was there.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn secret_service_delete(
    service: &str,
    account: Option<&str>,
    prefix: Option<&str>,
) -> Result<bool, String> {
    use secret_service::{EncryptionType, SecretService};
    use std::collections::HashMap;
    let ss = SecretService::new(EncryptionType::Dh)
        .map_err(|e| format!("secret-service connection failed: {e}"))?;
    let collection = ss
        .get_default_collection()
        .map_err(|e| format!("secret-service collection failed: {e}"))?;
    match collection.is_locked() {
        Ok(false) => {}
        Ok(true) => return Err("secret-service collection locked".to_owned()),
        Err(e) => return Err(format!("secret-service is_locked failed: {e}")),
    }
    let mut query = HashMap::from([("service", service)]);
    if let Some(account) = account {
        query.insert("account", account);
    }
    let items = collection
        .search_items(query)
        .map_err(|e| format!("secret-service search failed: {e}"))?;
    let mut deleted = false;
    for item in items {
        if let Some(prefix) = prefix {
            let attributes = item
                .get_attributes()
                .map_err(|e| format!("secret-service attributes failed: {e}"))?;
            if !attributes
                .get("account")
                .is_some_and(|name| name.starts_with(prefix))
            {
                continue;
            }
        }
        item.delete()
            .map_err(|e| format!("secret-service delete failed: {e}"))?;
        deleted = true;
    }
    Ok(deleted)
}

/// No OS keystore here: nothing is planned for one (keys live in files).
#[cfg(not(any(target_os = "macos", all(target_os = "linux", target_env = "gnu"))))]
fn platform_delete(_role: KeyRole, _service: &str, _account: &str) -> Result<bool, String> {
    Err("no OS keystore on this system".to_owned())
}

#[cfg(not(any(target_os = "macos", all(target_os = "linux", target_env = "gnu"))))]
fn platform_delete_prefix(_role: KeyRole, _service: &str, _prefix: &str) -> Result<bool, String> {
    Ok(false)
}

#[cfg(test)]
mod tests;
