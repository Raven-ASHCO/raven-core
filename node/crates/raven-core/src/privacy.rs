//! `privacy.json`: the profile's privacy mode, markers and settings (privacy
//! pack; docs/design/2026-10-at-rest-metadata.md section 4).
//!
//! Plain JSON on purpose: it holds no friend data, and Raven reads it before
//! any keystore call. PP.3 added the profile mode ([`mode`], [`set_mode`]);
//! PP.4 the migration ([`migrate_all`]), its markers (`sealed_since_day`,
//! `kinds`, the free-space deferral), the notices and [`status`]; later steps
//! add the retention setting and more. Fields this build does not know are
//! kept when it writes the file, so an older build of the pack never drops
//! what a newer one recorded.
//!
//! The migration (architecture section 7): [`migrate_all`] runs at raven-node
//! service start and at the top of every ash command that reads the profile.
//! It seals only in release builds or debug builds with `RAVEN_LAB_AT_REST=1`
//! (unit tests pass [`MigratePolicy::Allow`]), never in mode
//! `unsealed_by_user`, only in a profile with an identity on record, only
//! after the free-space preflight, and (from ash) only when no OLDER
//! raven-node answers for the profile (upgrade interlock). It loads the
//! at-rest key first, outside every lock, then takes `.at_rest.lock.sqlite`,
//! flips the mode to sealed (fsynced) and seals each registered plain file
//! under its own writer lock (re-read, seal, verify, rename). A plain file of
//! a kind already recorded as sealed is a downgrade leftover (an older build
//! wrote it): sealed again, with a note for `raven status`. PP.5 adds the
//! friend-key files, moves the noise pins into their sealed file (merging an
//! older build's plain pins), seals plain quarantine copies (`<file>.corrupt`)
//! in place, settles an older build's quarantine of a sealed peer-cache file,
//! and deletes interrupted writes' temp files older than an hour. PP.6 adds
//! the address and activity files (sightings, learned routes, outbox routes,
//! route memory, chat read positions, the CLI's alias and nearby stores, the
//! incoming contact requests, the relay memory and a profile's friend relay
//! status and key) and moves `node_policy.json`'s relay addresses to its
//! sealed sidecar ([`crate::node_policy::seal_peers`]); data removed from a
//! sealed file (a removed contact, a block-list change) marks a data-key
//! rotation due ([`mark_rotation_due`], PP.10). PP.7 forgets friends'
//! addresses after 30 days without contact ([`forget_stale_addresses`]),
//! in a sealed profile and a plain one alike. PP.8 deletes a chat so that it
//! stays deleted ([`delete_chat`]). PP.9 keeps chats for 7, 30 (the default)
//! or 90 days or always ([`chat_keep`], [`set_chat_keep`]) and deletes older
//! ones ([`apply_retention`]); the first migration pass of a build that may
//! seal starts the retention clock, with a one-time notice and a 7-day grace
//! for a profile that already holds chats. PP.10 rotates the data keys
//! ([`rotate_data_key`]): history, the outbound stage and app rows move
//! under epoch keys inside `meta_key.rmk` (K_hist never changes), and a
//! rotation after a deletion re-seals everything under a new epoch and then
//! drops the old one, so what was deleted no longer opens with this
//! computer's keys. PP.11 gives Windows a real K_hist
//! (`chat_history::windows_key`, DPAPI-wrapped in `chat_history_key.dpapi`):
//! the migration creates it and moves what an older Windows build sealed
//! with DPAPI directly under it eagerly, `meta_key.rmk` first, so deleting
//! that one file is a crypto-erase on Windows too. PP.15 records `raven
//! lock` ([`lock_state`], [`set_locked`]): while it holds, ash starts no
//! raven-node by itself.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::at_rest::{self, AtRestError, Kind, MigratePolicy, Migrated, Mode, META_KEY_FILE};
use crate::indexed_session_store::InboxDeletion;
use crate::ipc::{AtRestStatus, IpcResponse};
use crate::paths::DataDirLock;

/// The file in the data dir: `{"v":1,"mode":"sealed", ...}`.
pub const PRIVACY_FILE: &str = "privacy.json";
/// Its writer lock. Lock order: `.at_rest.lock.sqlite`, then this one.
pub const PRIVACY_LOCK: &str = ".privacy.lock.sqlite";
const FILE_VERSION: u32 = 1;
/// Far larger than any settings file; a bigger one is not ours.
const MAX_FILE_BYTES: u64 = 64 * 1024;

/// The files [`migrate_all`] seals in place, with their kinds: the contact
/// book (PP.4), the friend-key files (PP.5) and the address and activity
/// files (PP.6). The noise pins move to a file of their own instead
/// ([`crate::lan_noise_pin::merge_plain_into_sealed`]), the incoming contact
/// requests are sealed one by one ([`contact_inbox_files`]) and the policy's
/// relay addresses move to its sidecar ([`crate::node_policy::seal_peers`]).
pub const MIGRATED: &[(&str, Kind)] = &[
    (crate::contact_book::CONTACTS_FILE, Kind::Contacts),
    (crate::lan_dispatch::PEER_CERT_CACHE, Kind::PeerDeviceCerts),
    (crate::prekey_bundle::PREKEY_STORE_FILE, Kind::PrekeyStore),
    (crate::lan_dispatch::PEER_CACHE_STAGE, Kind::PeerCacheStage),
    (crate::chat_history::BLOCK_LIST_FILE, Kind::BlockedPubs),
    (
        crate::device_cert::DEVICE_REGISTRY_FILE,
        Kind::DeviceRegistry,
    ),
    (crate::device_sync::REVOCATIONS_FILE, Kind::Revocations),
    (
        crate::device_sync::RVDR1_CLAIMS_FILE,
        Kind::DeviceRevocationsRvdr1,
    ),
    (crate::device_sync::SYNC_SEEN_FILE, Kind::DeviceSyncSeen),
    (
        crate::route_hints::ROUTE_HINTS_STATE_FILE,
        Kind::RouteHintsState,
    ),
    (crate::bootstrap::BOOTSTRAP_FILE, Kind::Bootstrap),
    (crate::relay_allow::RELAY_ALLOW_FILE, Kind::RelayAllow),
    (crate::device_cert::DEVICE_X_SECRET, Kind::DeviceXSecret),
    (crate::lan_seen::LAN_SEEN_FILE, Kind::LanSeen),
    (
        crate::learned_routes::LEARNED_ROUTES_FILE,
        Kind::LearnedRoutes,
    ),
    (crate::outbox::OUTBOX_ROUTES_FILE, Kind::OutboxRoutes),
    (crate::route_memory::ROUTE_MEMORY_FILE, Kind::RouteMemory),
    (
        crate::chat_history::CHAT_INBOX_CURSORS_FILE,
        Kind::ChatInboxCursors,
    ),
    (crate::alias_record::ALIAS_CLAIMS_FILE, Kind::AliasClaims),
    (crate::nearby::NEARBY_REGISTRY_FILE, Kind::NearbyRegistry),
    (crate::relay_select::RELAY_MEMORY_FILE, Kind::RelayMemory),
    ("friend_relay/relay_status.json", Kind::FriendRelayStatus),
    ("friend_relay/relay_key.ed25519", Kind::FriendRelayKey),
    (crate::lan_meeting::LAN_MEETING_FILE, Kind::LanMeeting),
    (crate::custody_home::CUSTODY_HOME_FILE, Kind::CustodyHome),
    (
        crate::peer_rotation::PEER_SCHEDULES_FILE,
        Kind::PeerSchedules,
    ),
    (
        crate::peer_rotation::ROTATION_STATE_FILE,
        Kind::PeerRotationState,
    ),
    (
        crate::lan_dispatch::PREKEY_PUBLISHED_LOCAL_FILE,
        Kind::PrekeyPublishedLocal,
    ),
    (
        crate::letter_deposits::LETTER_DEPOSITS_FILE,
        Kind::LetterDeposits,
    ),
    (
        crate::capability_floor::CAPABILITY_FLOOR_FILE,
        Kind::CapabilityFloor,
    ),
    (crate::pair_seed::PAIR_SEEDS_FILE, Kind::PairSeeds),
    (crate::update_state::UPDATE_STATE_FILE, Kind::UpdateState),
    (crate::link_knock::KNOCK_REPLAYS_FILE, Kind::KnockReplays),
];

/// Kinds [`migrate_all`] records besides the [`MIGRATED`] files': the noise
/// pins (PP.5; recorded once they moved), the incoming contact requests and
/// the policy's sidecar (PP.6).
const RECORDED_EXTRA: [Kind; 3] = [Kind::NoisePins, Kind::ContactInbox, Kind::NodePolicyPeers];

/// The incoming contact requests the CLI keeps: the `<request id>.wire`
/// files of `contact_inbox/` (each RMS1 kind 28 once sealed), as paths
/// below the profile; none when the folder is missing or unreadable.
pub fn contact_inbox_files(data_dir: &Path) -> Vec<std::path::PathBuf> {
    let dir = data_dir.join(crate::contact_request::CONTACT_INBOX_DIR);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut files: Vec<std::path::PathBuf> = entries
        .flatten()
        .filter(|entry| entry.file_type().is_ok_and(|t| t.is_file()))
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "wire"))
        .collect();
    files.sort();
    files
}

/// Registered files whose quarantine copy (`<file>.corrupt`: an older
/// build's, or one this build moved aside) may hold their data in clear:
/// [`migrate_all`] seals a plain copy in place under the file's kind, kept
/// for a manual look (review R30).
const QUARANTINED: &[(&str, Kind)] = &[
    (crate::lan_dispatch::PEER_CERT_CACHE, Kind::PeerDeviceCerts),
    (crate::prekey_bundle::PREKEY_STORE_FILE, Kind::PrekeyStore),
    (crate::lan_dispatch::PEER_CACHE_STAGE, Kind::PeerCacheStage),
    (crate::device_sync::REVOCATIONS_FILE, Kind::Revocations),
    (crate::bootstrap::BOOTSTRAP_FILE, Kind::Bootstrap),
    (crate::lan_noise_pin::NOISE_PIN_FILE, Kind::NoisePins),
];

/// The peer cache's files: an older build moves one it cannot parse (a
/// sealed one) to `<file>.corrupt` and heals. A copy that opens under this
/// profile's key comes back when the file is missing; otherwise the file is
/// current (sealed again) and the copy goes.
const PEER_CACHE_KINDS: [Kind; 3] = [
    Kind::PeerDeviceCerts,
    Kind::PrekeyStore,
    Kind::PeerCacheStage,
];
/// The peer cache's committed generation (plain: a number).
const PEER_CACHE_GENERATION_FILE: &str = "peer_cache.generation";

/// `.<name>.tmp.<16 hex>` files of interrupted atomic writes this old are
/// deleted (no write takes this long; they may hold plaintext).
const STALE_TEMP_AGE: std::time::Duration = std::time::Duration::from_secs(60 * 60);

const DAY_MS: u64 = 24 * 60 * 60 * 1000;
const HOUR_MS: u64 = 60 * 60 * 1000;
/// The free-space preflight: twice the profile plus this much.
const SPACE_MARGIN_BYTES: u64 = 64 << 20;

// ── The words `Status.at_rest` and the CLI use (fixed tokens) ─────────────

/// Every registered file this build migrates is sealed, and the key is here.
pub const STATE_SEALED: &str = "sealed";
/// raven-node is loading the at-rest key (a keychain call may wait on a
/// dialog); its listeners admit nobody meanwhile.
pub const STATE_WAITING_FOR_KEYCHAIN: &str = "waiting_for_keychain";
/// The keystore did not give the key: retried with backoff.
pub const STATE_KEY_UNAVAILABLE: &str = "key_unavailable";
/// The key file is there but the key that opens it is gone from the
/// keystore (missing, or no longer opening; review A-keys-format-4): retried
/// only at the slowest step and when the user asks.
pub const STATE_KEY_LOST: &str = "key_lost";
/// The key is loaded and the files are being sealed.
pub const STATE_MIGRATING: &str = "migrating";
/// Not sealed: this build does not seal it (a debug build without
/// `RAVEN_LAB_AT_REST=1`), or it has no identity yet.
pub const STATE_PLAIN: &str = "plain";
/// `raven privacy unseal` (PP.18): nothing seals until `raven privacy
/// seal-now`.
pub const STATE_UNSEALED_BY_USER: &str = "unsealed_by_user";
/// Sealing waits for free disk space (retried at most once an hour).
pub const STATE_NEEDS_DISK_SPACE: &str = "needs_disk_space";

/// An older build wrote a registered file in plain; it was sealed again.
pub const NOTE_OLDER_BUILD_WROTE_PLAIN: &str = "older_build_wrote_plain";
/// An older build pinned a contact's computer key (M0) to another key than
/// the sealed pin; the sealed pin was kept.
pub const NOTE_OLDER_BUILD_PINNED_DIFFERENTLY: &str = "older_build_pinned_differently";
/// A file this process could not read (a sealed one without its key, a
/// changed byte) was kept as it was: a write that would have replaced it was
/// skipped (the advisory-file rule).
pub const NOTE_UNREADABLE_FILE_KEPT: &str = "unreadable_file_kept";
/// A store's freed pages wait for a VACUUM (PP.12-PP.14).
pub const NOTE_SCRUB_PENDING: &str = "scrub_pending";
/// An older raven-node answers for this profile: sealing waits for its
/// restart.
pub const NOTE_OLDER_NODE_RUNNING: &str = "older_node_running";

// ── UX copy (the privacy pack design's `ux_copy`) ─────────────────────────

/// Status, doctor and any command that needs the book while the key root is
/// unavailable.
pub const KEY_UNAVAILABLE_TEXT: &str = "Raven can't open your friends list: it needs your \
    keychain (or your Raven passphrase). Until then nobody can connect to you and nothing is \
    sent. On a Mac, answer the keychain dialog; with a passphrase file, check that it is in \
    place. Raven tries again in a few minutes, and right away when you run `raven status`.";

/// [`KEY_UNAVAILABLE_TEXT`]'s place when the key is gone for good, not
/// waiting for a dialog (review A-keys-format-4): a new login keychain, a
/// profile copied to another computer or account, a Windows account whose
/// key no longer opens it.
pub const KEY_LOST_TEXT: &str = "Raven can't open your friends list: the key that encrypts \
    this profile is no longer in your keychain (or your Raven passphrase vault), or no longer \
    opens for this Windows account. Nobody can connect to you and nothing is sent. Put back the \
    keychain or the backup this profile came from, then run `raven status`; otherwise run \
    `raven erase` and set Raven up again.";

/// The key-root sentence for this profile: [`KEY_LOST_TEXT`] when this
/// process's last key load found the key gone ([`at_rest::key_lost`]),
/// [`KEY_UNAVAILABLE_TEXT`] otherwise. No keystore call.
pub fn key_unavailable_text(data_dir: &Path) -> &'static str {
    if at_rest::key_lost(data_dir) {
        KEY_LOST_TEXT
    } else {
        KEY_UNAVAILABLE_TEXT
    }
}

/// Shown once, after the first migration.
pub const SEALING_NOTICE: &str = "Raven now encrypts your friends list, their addresses and \
    your message records on this computer with your keys. Older Raven versions can't open this \
    profile. To go back to an older version, run `raven privacy unseal` first.";

/// With the sealing notice on macOS: raven-node now reads the chat-history
/// key at start.
pub const KEYCHAIN_AT_START_TEXT: &str = "Raven may ask once for access to your keychain when \
    it starts. Choose Always Allow so Raven can receive messages while you are away.";

/// Shown once by `raven status` after a downgrade leftover was sealed again.
pub const OLDER_BUILD_TEXT: &str = "An older Raven version wrote some of this profile's files \
    unencrypted. Raven encrypted them again.";

/// An older raven-node still answers (ash, at most once a day).
pub fn older_node_text(restart_advice: &str) -> String {
    format!("Raven was updated. Restart Raven so it can finish the update: {restart_advice}")
}

/// Sealing waits for free disk space (`raven status`).
pub fn disk_space_text(needed_bytes: u64) -> String {
    format!(
        "Raven needs more free disk space to finish encrypting this profile (about {} MB). \
         Nothing was changed.",
        needed_bytes.div_ceil(1 << 20)
    )
}

// ── The file ──────────────────────────────────────────────────────────────

#[derive(Debug, Default, Serialize, Deserialize)]
struct PrivacyFile {
    #[serde(default)]
    v: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mode: Option<String>,
    /// Days since the Unix epoch when the profile was first sealed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sealed_since_day: Option<u64>,
    /// The kinds sealed so far ([`Kind::name`]), recorded after their files
    /// were sealed: a plain file of one of them is a downgrade leftover.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    kinds: Vec<String>,
    #[serde(default, skip_serializing_if = "Notices::is_empty")]
    notices: Notices,
    /// The free-space preflight deferred sealing at this time ...
    #[serde(default, skip_serializing_if = "Option::is_none")]
    space_deferred_at_ms: Option<u64>,
    /// ... needing about this many bytes free.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    space_needed_bytes: Option<u64>,
    /// Data was removed from sealed files (a removed contact, a block-list
    /// change; PP.7-PP.9 add theirs): older sealed versions of those files in
    /// freed disk blocks still hold it until the next data-key rotation
    /// (PP.10), which clears this.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    rotation_due: bool,
    /// How long chats are kept (PP.9): `"7d"`, `"30d"`, `"90d"` or
    /// `"always"`; absent: 30 days ([`chat_keep`]). Here and not in
    /// `node_policy.json`, which an older build rewrites without the fields
    /// it does not know.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    chat_keep: Option<String>,
    /// The retention pass deletes nothing before this time (PP.9): recorded
    /// by the first migration pass of a build that may seal; a profile that
    /// already holds chats gets a grace ([`RETENTION_GRACE_MS`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retention_starts_at_ms: Option<u64>,
    /// The last retention pass found that nothing can go before this time
    /// (PP.9): passes before it read no history (no keystore call).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retention_next_at_ms: Option<u64>,
    /// When the last data-key rotation started (PP.10): at most one start a
    /// day.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_rotation_at_ms: Option<u64>,
    /// A data-key rotation under way (PP.10); cleared once its old epoch is
    /// dropped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rotation: Option<RotationRecord>,
    /// `raven lock` stopped Raven (PP.15): ash starts no raven-node by itself
    /// (the send path, `raven listen`) until `raven unlock`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    locked_by_user: bool,
    /// What `raven lock` did to Raven's own login item for this profile
    /// (PP.15): `"unloaded"` (for the login session) or `"disabled"` (until
    /// `raven unlock`, which turns it back on and then clears this).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    lock_login_item: Option<String>,
    /// Who set the lock (review E-harness-docs-ci-3): `"app"`, the
    /// full-screen app's Lock, which opening the app clears; `"cli"`, `raven
    /// lock`, which only `raven unlock` or a yes to the app's question
    /// clears. A lock without it (an older build of the pack set it) counts
    /// as `raven lock`'s.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    lock_by: Option<String>,
    /// `raven privacy rotate-meta` under way (PP.18): recorded before the key
    /// file gets its new `k_index`, cleared once the old epochs are gone.
    /// While it is here the profile is closed to everything but that command
    /// (and `raven privacy unseal`, `raven privacy status`, `raven erase`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    meta_rotation: Option<MetaRotationRecord>,
    /// Everything else (later steps' fields), kept as it is.
    #[serde(flatten)]
    other: serde_json::Map<String, serde_json::Value>,
}

/// A data-key rotation under way (`privacy.json` `"rotation"`), recorded
/// before its new epoch is added: the epoch it moves away from and when it
/// started (the grace counts from then).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct RotationRecord {
    from: u32,
    started_at_ms: u64,
}

/// `raven privacy rotate-meta` under way (`privacy.json` `"meta_rotation"`,
/// PP.18): the new epoch it moves everything to (a new `k_index` with it)
/// and when it started.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct MetaRotationRecord {
    to: u32,
    started_at_ms: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Notices {
    /// The one-time sealing notice was shown.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    sealing_shown: bool,
    /// A downgrade leftover was sealed again; `raven status` says so once.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    older_build_wrote_plain: bool,
    /// Contacts an older build pinned to another computer key than the
    /// sealed pin, which was kept (counted until `raven status` said the
    /// older-build sentence).
    #[serde(default, skip_serializing_if = "is_zero")]
    older_build_pinned_differently: u64,
    /// The day the "an older Raven is still running" line was last shown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    older_node_day: Option<u64>,
    /// The one-time retention notice is due (PP.9: a profile that held
    /// chats when this build first saw it).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    retention_pending: bool,
    #[serde(flatten)]
    other: serde_json::Map<String, serde_json::Value>,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

impl Notices {
    fn is_empty(&self) -> bool {
        !self.sealing_shown
            && !self.older_build_wrote_plain
            && self.older_build_pinned_differently == 0
            && self.older_node_day.is_none()
            && !self.retention_pending
            && self.other.is_empty()
    }
}

/// The profile's at-rest mode.
///
/// - No mode recorded (no `privacy.json`, or no `mode` in it): [`Mode::Plain`],
///   unless `meta_key.rmk` exists. The key is created just before a profile is
///   first sealed, so a profile with a key and no recorded mode is being
///   sealed: [`Mode::Sealed`].
/// - A file that cannot be read or parsed, or a mode this build does not know
///   (a newer build wrote it): [`Mode::Sealed`]. Writers then seal or fail
///   closed (no key loaded); they never fall back to plaintext. Readers accept
///   both forms in every mode.
pub fn mode(data_dir: &Path) -> Mode {
    let recorded = match read_file(data_dir) {
        Ok(Some(file)) => file.mode,
        Ok(None) => None,
        Err(_) => return Mode::Sealed,
    };
    match recorded {
        Some(name) => Mode::parse(&name).unwrap_or(Mode::Sealed),
        None if data_dir.join(META_KEY_FILE).exists() => Mode::Sealed,
        None => Mode::Plain,
    }
}

/// Record `mode` (atomic, fsynced) under [`PRIVACY_LOCK`], keeping every
/// other field. Refuses to replace a `privacy.json` it cannot parse.
pub fn set_mode(data_dir: &Path, mode: Mode) -> Result<(), AtRestError> {
    update(data_dir, |file| file.mode = Some(mode.as_str().to_owned()))
}

/// Change the file under [`PRIVACY_LOCK`] (atomic, fsynced), keeping every
/// field `change` does not touch. Refuses to replace a file it cannot parse.
fn update(data_dir: &Path, change: impl FnOnce(&mut PrivacyFile)) -> Result<(), AtRestError> {
    let _lock = DataDirLock::acquire(data_dir, PRIVACY_LOCK).map_err(AtRestError::Io)?;
    let mut file = read_file(data_dir)?.unwrap_or_default();
    file.v = file.v.max(FILE_VERSION);
    change(&mut file);
    let raw = serde_json::to_vec_pretty(&file).map_err(|e| AtRestError::Json(e.to_string()))?;
    crate::paths::atomic_write_private(&data_dir.join(PRIVACY_FILE), &raw).map_err(AtRestError::Io)
}

fn read_file(data_dir: &Path) -> Result<Option<PrivacyFile>, AtRestError> {
    use std::io::Read;
    let path = data_dir.join(PRIVACY_FILE);
    let file = match std::fs::File::open(&path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(AtRestError::Io(format!("{PRIVACY_FILE}: {e}"))),
    };
    let mut raw = Vec::new();
    file.take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut raw)
        .map_err(|e| AtRestError::Io(format!("{PRIVACY_FILE}: {e}")))?;
    if raw.len() as u64 > MAX_FILE_BYTES {
        return Err(AtRestError::Io(format!(
            "{PRIVACY_FILE} exceeds the local size limit"
        )));
    }
    serde_json::from_slice(&raw)
        .map(Some)
        .map_err(|e| AtRestError::Json(format!("{PRIVACY_FILE} corrupt: {e}")))
}

/// Data was removed from this profile's sealed files (a removed contact, a
/// block-list change): ask for the next data-key rotation (PP.10), which
/// makes the older sealed versions of those files left in freed disk blocks
/// unreadable with this computer's keys. Only in a sealed profile (a plain
/// one does not rotate); a no-op when it is due already.
pub fn mark_rotation_due(data_dir: &Path) -> Result<(), AtRestError> {
    if mode(data_dir) != Mode::Sealed || rotation_due(data_dir) {
        return Ok(());
    }
    update(data_dir, |file| file.rotation_due = true)
}

/// Whether a data-key rotation is due ([`mark_rotation_due`]).
pub fn rotation_due(data_dir: &Path) -> bool {
    read_file(data_dir).is_ok_and(|file| file.is_some_and(|file| file.rotation_due))
}

// ── The migration ─────────────────────────────────────────────────────────

/// What [`migrate_all`] found and did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MigrateReport {
    pub outcome: MigrateOutcome,
    /// Files this pass sealed.
    pub sealed: u16,
    /// Of them, plain copies an older build wrote in this sealed profile
    /// (`notices.older_build_wrote_plain` is set).
    pub leftovers: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrateOutcome {
    /// The profile is sealed and every file this build migrates is sealed
    /// (this pass may have sealed some); its key is loaded.
    Sealed,
    /// Plain, and this build does not seal it (a debug build without
    /// `RAVEN_LAB_AT_REST=1`).
    NotAllowed,
    /// Plain, and no identity on record yet: nothing is created.
    NoIdentity,
    /// `raven privacy unseal`: nothing seals until `raven privacy seal-now`.
    UnsealedByUser,
    /// An older raven-node answers for this profile: sealing now would lock
    /// it out (upgrade interlock). Nothing was changed.
    OlderNodeRunning,
    /// Not enough free disk space (about `needed` bytes): nothing was
    /// changed; retried at most once an hour.
    NeedsDiskSpace { needed: u64 },
}

impl MigrateReport {
    fn only(outcome: MigrateOutcome) -> Self {
        Self {
            outcome,
            sealed: 0,
            leftovers: 0,
        }
    }
}

/// Seal this profile's registered plain files (architecture section 7):
/// raven-node at its start, which is the node and needs no interlock. Call
/// it at a process's or a command's top level, never under a data-dir lock:
/// it may call the keystore ([`at_rest::keys_load_with`], which may show the
/// one-time macOS keychain dialog). Cheap once sealed: two reads of
/// `privacy.json` (the record, the retention start), the cached key and one
/// small read per migrated file, the chat history's and the outbound stage's
/// first bytes and, where the app store exists, its rows' first bytes.
///
/// In a sealed profile the chat history, the outbound stage and the app
/// rows that K_hist still seals directly move under the epoch data keys
/// (PP.10, [`move_epoch_data`]), each under its own lock; best effort, the
/// next pass (or the data-key rotation) finishes what is left.
///
/// On Windows (PP.11, `move_under_windows_key`) a profile an older build
/// sealed with DPAPI directly gets its own K_hist and its `meta_key.rmk`
/// re-wrapped under it first; one that is not sealed (a debug build without
/// the lab switch) has its history, stage and app rows moved under K_hist.
///
/// The SQLite stores move to their keyed schemas in a sealed profile (PP.12,
/// `move_stores`): owed ACKs and the app store, with an older build's
/// set-aside owed-ACK store merged back, and the session store (PP.13, after
/// the at-rest lock is released: its open reads each session's protected
/// state); ash asks `older_node` first when a store still has to move. A scrub the move could not finish is left to
/// the prune passes ([`upkeep_stores`]).
///
/// A build that may seal (`policy`) also starts the retention clock once
/// (PP.9, [`apply_retention`]): `retention_starts_at_ms` is now for a
/// profile without chats (a new one) and now plus the grace for one that
/// holds chats, which also gets the one-time retention notice
/// ([`take_retention_notice`]).
///
/// In a sealed profile the key is loaded first (readers need it whatever
/// happens next); an unavailable key is an error, never a plaintext fallback.
pub fn migrate_all(
    data_dir: &Path,
    now_ms: u64,
    policy: MigratePolicy,
) -> Result<MigrateReport, AtRestError> {
    migrate_all_with(data_dir, now_ms, policy, None)
}

/// [`migrate_all`] with the upgrade interlock (ash, the terminal app):
/// `older_node` is asked only when this pass would seal something, and
/// answers whether a raven-node of an OLDER build answers IPC Status for this
/// profile ([`node_is_older`]); it then seals nothing.
pub fn migrate_all_with(
    data_dir: &Path,
    now_ms: u64,
    policy: MigratePolicy,
    older_node: Option<&dyn Fn() -> bool>,
) -> Result<MigrateReport, AtRestError> {
    migrate_inner(data_dir, now_ms, policy, older_node, &|dir| {
        crate::disk_space::free_bytes(dir)
    })
}

/// A raven-node answered this to IPC Status: is it an older build (or
/// something this build cannot tell)? A build of the pack always reports
/// `at_rest`.
pub fn node_is_older(response: &IpcResponse) -> bool {
    !matches!(
        response,
        IpcResponse::Status {
            at_rest: Some(_),
            ..
        }
    )
}

fn migrate_inner(
    data_dir: &Path,
    now_ms: u64,
    policy: MigratePolicy,
    older_node: Option<&dyn Fn() -> bool>,
    free_bytes: &dyn Fn(&Path) -> Option<u64>,
) -> Result<MigrateReport, AtRestError> {
    let was = mode(data_dir);
    // Only a build that may seal starts the retention clock (PP.9): a debug
    // build without the lab switch deletes no chat either.
    let may_start = policy.allows_sealing();
    match was {
        Mode::UnsealedByUser => {
            if may_start {
                let _ = record_retention_start(data_dir, now_ms);
            }
            return Ok(MigrateReport::only(MigrateOutcome::UnsealedByUser));
        }
        Mode::Plain => {
            if !policy.allows_sealing() {
                // Not sealed, but on Windows still under its own K_hist
                // (PP.11).
                #[cfg(any(test, windows))]
                move_under_windows_key(data_dir, false, older_node)?;
                return Ok(MigrateReport::only(MigrateOutcome::NotAllowed));
            }
            // Before anything is written: a fresh profile stays exactly as
            // it is (privacy.json would make identity creation refuse it).
            if !crate::identity_store::identity_recorded(data_dir)
                .map_err(|e| AtRestError::Io(e.to_string()))?
            {
                return Ok(MigrateReport::only(MigrateOutcome::NoIdentity));
            }
        }
        Mode::Sealed => {
            at_rest::keys_load_with(data_dir, policy)?;
            // Windows: the key file under the profile's own K_hist (PP.11),
            // before anything else here.
            #[cfg(any(test, windows))]
            move_under_windows_key(data_dir, true, None)?;
            remove_stale_temp_files(data_dir);
            // An older build's per-friend send locks, named by the friend's
            // key (review B-sealed-stores-4), and its cached PairResponses,
            // named by an init_id (B-sealed-stores-1).
            crate::outbox::PeerSendLock::remove_legacy_files(data_dir);
            crate::lan_dispatch::remove_plain_pair_responses(data_dir);
            if plain_files(data_dir)?.is_empty() && fully_recorded(data_dir) {
                // Nothing plain; an older build's quarantine copy of a sealed
                // peer-cache file is still settled (best effort: the next
                // pass tries again).
                let _ = settle_quarantined(data_dir);
                // The SQLite stores (PP.12), before their rows move epochs; a
                // store the interlock holds back is not opened either.
                let stores = move_stores(data_dir, older_node, true);
                move_epoch_data(data_dir, !stores.held_back);
                if may_start {
                    let _ = record_retention_start(data_dir, now_ms);
                }
                return Ok(MigrateReport::only(MigrateOutcome::Sealed));
            }
        }
    }
    // Only a pass that seals something asks the interlock and the free
    // space; one that finishes the record of a crashed pass does not.
    if was == Mode::Plain || !plain_files(data_dir)?.is_empty() {
        if older_node.is_some_and(|answers| answers()) {
            return Ok(MigrateReport::only(MigrateOutcome::OlderNodeRunning));
        }
        let file = read_file(data_dir)?.unwrap_or_default();
        if let (Some(at), Some(needed)) = (file.space_deferred_at_ms, file.space_needed_bytes) {
            if now_ms < at.saturating_add(HOUR_MS) && now_ms >= at {
                return Ok(MigrateReport::only(MigrateOutcome::NeedsDiskSpace {
                    needed,
                }));
            }
        }
        let needed = profile_bytes(data_dir)
            .saturating_mul(2)
            .saturating_add(SPACE_MARGIN_BYTES);
        if free_bytes(data_dir).is_some_and(|free| free < needed) {
            let chats = holds_chats(data_dir);
            update(data_dir, |file| {
                file.space_deferred_at_ms = Some(now_ms);
                file.space_needed_bytes = Some(needed);
                if may_start {
                    start_retention(file, now_ms, chats);
                }
            })?;
            return Ok(MigrateReport::only(MigrateOutcome::NeedsDiskSpace {
                needed,
            }));
        }
    }
    // The key first, outside every lock (it may wait on a keychain dialog):
    // created here on the first sealing.
    at_rest::keys_load_with(data_dir, policy)?;
    // Windows: a key file an interrupted sealing of an older build left
    // DPAPI-direct goes under K_hist too (PP.11; the sealed arm above did a
    // sealed profile's).
    #[cfg(any(test, windows))]
    if was == Mode::Plain {
        move_under_windows_key(data_dir, true, None)?;
    }
    let _all = DataDirLock::acquire(data_dir, at_rest::AT_REST_LOCK).map_err(AtRestError::Io)?;
    let recorded_mode = read_file(data_dir)?.and_then(|file| file.mode);
    match recorded_mode.as_deref().map(Mode::parse) {
        // `raven privacy unseal` won the race: it stays unsealed.
        Some(Some(Mode::UnsealedByUser)) => {
            return Ok(MigrateReport::only(MigrateOutcome::UnsealedByUser));
        }
        // Sealed already, or a newer build's mode (sealed for this build's
        // writers): kept as it is.
        Some(Some(Mode::Sealed)) | Some(None) => {}
        // The mode first (fsynced): no writer writes plaintext once sealing
        // has begun, and a crash leaves a mix readers accept.
        None | Some(Some(Mode::Plain)) => set_mode(data_dir, Mode::Sealed)?,
    }
    #[cfg(test)]
    tests::crash_point(tests::Crash::AfterModeFlip)?;
    let recorded = read_file(data_dir)?.unwrap_or_default().kinds;
    let was_recorded = |kind: Kind| recorded.iter().any(|k| k == kind.name());
    let (mut sealed, mut leftovers) = (0u16, 0u16);
    let inbox = contact_inbox_files(data_dir);
    let files = MIGRATED
        .iter()
        .map(|(name, kind)| (data_dir.join(name), *kind))
        .chain(inbox.into_iter().map(|path| (path, Kind::ContactInbox)));
    for (path, kind) in files {
        // A file that is not there needs no lock (and leaves no lock file).
        if std::fs::symlink_metadata(&path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
        {
            continue;
        }
        if at_rest::migrate_file(data_dir, &path, kind)? == Migrated::Sealed {
            sealed += 1;
            if was_recorded(kind) {
                leftovers += 1;
            }
        }
    }
    // The policy's relay addresses move to its sealed sidecar (the sidecar
    // first, then node_policy.json without them). A move that cannot be made
    // now (a sidecar that does not open) leaves both as they are, counted
    // plain, and the next pass tries again.
    let peers_moved = match crate::node_policy::seal_peers(data_dir) {
        Ok(moved) => {
            if moved {
                sealed += 1;
                if was_recorded(Kind::NodePolicyPeers) {
                    leftovers += 1;
                }
            }
            true
        }
        Err(_) => false,
    };
    // The noise pins move to their sealed file. One that cannot be merged
    // now (a newer build's plain file, a sealed one that does not open) stays
    // as it is, counted plain, and is tried again by the next pass.
    let (mut pins_moved, mut pin_conflicts) = (true, 0u64);
    match crate::lan_noise_pin::merge_plain_into_sealed(data_dir) {
        Ok(merge) if merge.found => {
            sealed += 1;
            if was_recorded(Kind::NoisePins) {
                leftovers += 1;
            }
            pin_conflicts = u64::try_from(merge.conflicts).unwrap_or(u64::MAX);
        }
        Ok(_) => {}
        Err(_) => pins_moved = false,
    }
    sealed = sealed.saturating_add(settle_quarantined(data_dir)?);
    // The SQLite stores (PP.12; the interlock was asked above, when this
    // pass found anything to seal). The session store moves after the lock
    // (below): its open reads each session's protected state.
    move_stores(data_dir, None, false);
    move_epoch_data(data_dir, true);
    #[cfg(test)]
    tests::crash_point(tests::Crash::AfterSeal)?;
    remove_stale_temp_files(data_dir);
    let chats = holds_chats(data_dir);
    update(data_dir, |file| {
        file.sealed_since_day.get_or_insert(now_ms / DAY_MS);
        if may_start {
            start_retention(file, now_ms, chats);
        }
        let kinds =
            MIGRATED
                .iter()
                .map(|(_, kind)| *kind)
                .chain(RECORDED_EXTRA.into_iter().filter(|kind| match kind {
                    Kind::NoisePins => pins_moved,
                    Kind::NodePolicyPeers => peers_moved,
                    _ => true,
                }));
        for kind in kinds {
            if !file.kinds.iter().any(|k| k == kind.name()) {
                file.kinds.push(kind.name().to_owned());
            }
        }
        if leftovers > 0 {
            file.notices.older_build_wrote_plain = true;
        }
        file.notices.older_build_pinned_differently = file
            .notices
            .older_build_pinned_differently
            .saturating_add(pin_conflicts);
        file.space_deferred_at_ms = None;
        file.space_needed_bytes = None;
    })?;
    // The session store (PP.13), outside the at-rest lock: its open replays
    // journals and reads each session's protected state, which may wait on
    // a keychain. Best effort: the next pass (or its next open) finishes it.
    drop(_all);
    // An older build's per-friend send locks, named by the friend's key
    // (review B-sealed-stores-4): one a send holds goes with a later pass.
    // The PairResponses cached before the sealing, named by an init_id
    // (B-sealed-stores-1).
    crate::outbox::PeerSendLock::remove_legacy_files(data_dir);
    crate::lan_dispatch::remove_plain_pair_responses(data_dir);
    let _ = crate::indexed_session_store::migrate(data_dir);
    Ok(MigrateReport {
        outcome: MigrateOutcome::Sealed,
        sealed,
        leftovers,
    })
}

/// `privacy.json` records the profile as sealed and every kind this build
/// migrates (a pass that crashed after sealing has not recorded them yet).
fn fully_recorded(data_dir: &Path) -> bool {
    read_file(data_dir).is_ok_and(|file| {
        file.is_some_and(|file| {
            file.mode.as_deref().map(Mode::parse) != Some(Some(Mode::Plain))
                && file.mode.is_some()
                && MIGRATED
                    .iter()
                    .map(|(_, kind)| *kind)
                    .chain(RECORDED_EXTRA)
                    .all(|kind| file.kinds.iter().any(|k| k == kind.name()))
        })
    })
}

/// Every file this build seals that exists, and whether it is sealed: the
/// [`MIGRATED`] files, the incoming contact requests, the noise pins (the
/// sealed file; a plain one is always to be merged), the policy's sidecar
/// (and `node_policy.json` while it still names relays: plain) and the
/// quarantine copies (one small read each).
fn file_forms(data_dir: &Path) -> Result<Vec<(String, bool)>, AtRestError> {
    let mut forms = Vec::new();
    for (name, kind) in MIGRATED {
        if let Some(sealed) = file_form(&data_dir.join(name), *kind)? {
            forms.push(((*name).to_owned(), sealed));
        }
    }
    for path in contact_inbox_files(data_dir) {
        if let Some(sealed) = file_form(&path, Kind::ContactInbox)? {
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            forms.push((
                format!("{}/{name}", crate::contact_request::CONTACT_INBOX_DIR),
                sealed,
            ));
        }
    }
    let peers = crate::node_policy::POLICY_PEERS_FILE;
    if let Some(sealed) = file_form(&data_dir.join(peers), Kind::NodePolicyPeers)? {
        forms.push((peers.to_owned(), sealed));
    }
    if crate::node_policy::peers_in_plain(data_dir) {
        forms.push((crate::node_policy::POLICY_FILE.to_owned(), false));
    }
    let pins = crate::lan_noise_pin::NOISE_PIN_SEALED_FILE;
    if let Some(sealed) = file_form(&data_dir.join(pins), Kind::NoisePins)? {
        forms.push((pins.to_owned(), sealed));
    }
    let plain_pins = crate::lan_noise_pin::NOISE_PIN_FILE;
    if file_form(&data_dir.join(plain_pins), Kind::NoisePins)?.is_some() {
        forms.push((plain_pins.to_owned(), false));
    }
    for (name, kind) in QUARANTINED {
        let copy = format!("{name}.corrupt");
        if let Some(sealed) = file_form(&data_dir.join(&copy), *kind)? {
            forms.push((copy, sealed));
        }
    }
    Ok(forms)
}

/// The files this build seals that exist in plain.
fn plain_files(data_dir: &Path) -> Result<Vec<String>, AtRestError> {
    Ok(file_forms(data_dir)?
        .into_iter()
        .filter(|(_, sealed)| !sealed)
        .map(|(name, _)| name)
        .collect())
}

/// `Some(true)`: sealed (RMS1), `Some(false)`: plain, `None`: missing. A raw
/// secret's plain file of exactly its length is plain whatever it starts
/// with ([`at_rest::is_sealed_as`]).
fn file_form(path: &Path, kind: Kind) -> Result<Option<bool>, AtRestError> {
    use std::io::Read;
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(AtRestError::Io(e.to_string())),
    };
    let len = file
        .metadata()
        .map_err(|e| AtRestError::Io(e.to_string()))?
        .len();
    let mut head = Vec::with_capacity(4);
    file.take(4)
        .read_to_end(&mut head)
        .map_err(|e| AtRestError::Io(e.to_string()))?;
    if kind.is_raw_secret() && len == 32 {
        return Ok(Some(false));
    }
    Ok(Some(at_rest::is_sealed(&head)))
}

/// Seal each plain quarantine copy ([`QUARANTINED`]) in place, under its
/// file's writer lock, and settle a sealed peer-cache copy that opens under
/// this profile's key to a file's JSON (an older build moved it aside
/// because it could not read it): restored when its file is missing,
/// deleted otherwise (the file is current and sealed by now). The stage
/// comes back only beside a committed generation, which orders its replay
/// (without one any stage would replay over the committed files). Every
/// other copy (sealed and not ours, not JSON, or of another file) is left as
/// it is. Sealed mode, the key loaded. Returns how many copies were sealed.
fn settle_quarantined(data_dir: &Path) -> Result<u16, AtRestError> {
    let io = |e: std::io::Error| AtRestError::Io(e.to_string());
    let mut sealed = 0u16;
    for (name, kind) in QUARANTINED {
        let copy = data_dir.join(format!("{name}.corrupt"));
        if std::fs::symlink_metadata(&copy).is_err() {
            continue;
        }
        let _lock = at_rest::lock_file(data_dir, &copy, *kind)?;
        let Some(raw) = at_rest::read_raw(&copy)? else {
            continue;
        };
        if !at_rest::is_sealed_as(*kind, &raw) {
            if at_rest::migrate_file_held(data_dir, &copy, *kind)? == Migrated::Sealed {
                sealed += 1;
            }
            continue;
        }
        if !PEER_CACHE_KINDS.contains(kind) {
            continue;
        }
        let keys = at_rest::keys_cached(data_dir)?;
        let ours = at_rest::open(&keys, *kind, &raw)
            .is_ok_and(|plain| serde_json::from_slice::<serde_json::Value>(&plain).is_ok());
        if !ours {
            continue;
        }
        let file = data_dir.join(name);
        match std::fs::symlink_metadata(&file) {
            Ok(_) => std::fs::remove_file(&copy).map_err(io)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let ordered = *kind != Kind::PeerCacheStage
                    || data_dir.join(PEER_CACHE_GENERATION_FILE).is_file();
                if !ordered {
                    continue;
                }
                std::fs::rename(&copy, &file).map_err(io)?;
            }
            Err(e) => return Err(io(e)),
        }
        crate::paths::sync_dir_best_effort(data_dir);
    }
    Ok(sealed)
}

/// Delete the `.<name>.tmp.<16 hex>` files of interrupted atomic writes
/// (`paths::atomic_write_private`) older than [`STALE_TEMP_AGE`] from the
/// profile and its folders one level down: nothing ever cleaned them, and
/// they may hold plaintext; no write in flight is that old. Best effort, by
/// this computer's clock; returns how many went.
fn remove_stale_temp_files(data_dir: &Path) -> usize {
    // The system clock (no lab offset): it is set beside the OS's own
    // modification times.
    let now = crate::clock::system_now();
    let mut dirs = vec![data_dir.to_path_buf()];
    if let Ok(entries) = std::fs::read_dir(data_dir) {
        dirs.extend(
            entries
                .flatten()
                .filter(|entry| entry.file_type().is_ok_and(|t| t.is_dir()))
                .map(|entry| entry.path()),
        );
    }
    let mut removed = 0;
    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let stale = entry.file_name().to_str().is_some_and(is_temp_name)
                && entry.file_type().is_ok_and(|t| t.is_file())
                && entry
                    .metadata()
                    .and_then(|meta| meta.modified())
                    .ok()
                    .and_then(|at| now.duration_since(at).ok())
                    .is_some_and(|age| age >= STALE_TEMP_AGE);
            if stale && std::fs::remove_file(entry.path()).is_ok() {
                removed += 1;
            }
        }
    }
    removed
}

/// `.<name>.tmp.<16 lowercase hex>`: the temp name of
/// `paths::atomic_write_private` (`raven erase` deletes one beside a file of
/// Raven's, in Raven's folders too).
pub(crate) fn is_temp_name(name: &str) -> bool {
    name.strip_prefix('.')
        .and_then(|rest| rest.rsplit_once(".tmp."))
        .is_some_and(|(base, suffix)| {
            !base.is_empty()
                && suffix.len() == 16
                && suffix
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}

/// The bytes the profile's regular files hold (its folder and two levels of
/// subfolders; links are not followed).
fn profile_bytes(dir: &Path) -> u64 {
    fn walk(dir: &Path, depth: u8) -> u64 {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return 0;
        };
        entries
            .flatten()
            .map(|entry| match entry.file_type() {
                Ok(t) if t.is_file() => entry.metadata().map_or(0, |m| m.len()),
                Ok(t) if t.is_dir() && depth > 0 => walk(&entry.path(), depth - 1),
                _ => 0,
            })
            .fold(0u64, u64::saturating_add)
    }
    walk(dir, 2)
}

// ── Forgetting addresses (PP.7) ───────────────────────────────────────────

/// What [`forget_stale_addresses`] took off the disk: counts only (the log
/// line names no one, no address and no time).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ForgetReport {
    /// Sightings older than 30 days (`lan_seen.json`).
    pub sightings: usize,
    /// Learned routes (`learned_routes.json`): entries that went, or lost
    /// their routes, relays or exact times.
    pub learned_routes: usize,
    /// Remembered routes past their lease (`route_memory.json`).
    pub remembered_routes: usize,
    /// Records of messages the outbox no longer holds (`outbox_routes.json`).
    pub message_routes: usize,
    /// Contacts' PeerId schedule entries behind their clocks
    /// (`peer_schedules.json`, Phase 4).
    pub peer_schedules: usize,
    /// Files left as they were: they could not be read (a sealed one whose
    /// key is not loaded, a changed byte), locked or written. The next pass
    /// tries again.
    pub kept: usize,
}

impl ForgetReport {
    /// Entries taken off the disk in all.
    pub fn removed(&self) -> usize {
        self.sightings
            + self.learned_routes
            + self.remembered_routes
            + self.message_routes
            + self.peer_schedules
    }
}

impl std::fmt::Display for ForgetReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "sightings={} learned_routes={} route_memory={} outbox_routes={} peer_schedules={} \
             kept={}",
            self.sightings,
            self.learned_routes,
            self.remembered_routes,
            self.message_routes,
            self.peer_schedules,
            self.kept
        )
    }
}

/// Privacy pack PP.7, owner decision "friends' addresses forgotten after 30
/// days without contact" (OD-C10 (a)): take off the disk what no dial reads
/// any more. Sightings older than 30 days ([`crate::lan_seen::prune`]); the
/// learned routes as their readers see them, with the tombstone of a contact
/// unheard for 30 days (no RRH1, no authenticated LAN link) cut to its
/// generation and a day ([`crate::learned_routes::prune`]); remembered
/// routes past their lease ([`crate::route_memory::prune`]); the records of
/// messages the outbox no longer holds
/// ([`crate::outbox::forget_finished_object_routes`]); contacts' PeerId
/// schedule entries behind their clocks
/// ([`crate::peer_rotation::prune_schedules`], Phase 4). The contact book's
/// saved addresses stay (the user saved them: `raven contact
/// forget-address`), and so do the noise pins (keys, removed with the
/// contact) and the relay settings.
///
/// raven-node runs it with every durable prune
/// ([`crate::lan_dispatch::prune_expired_lan_durable_state`]), ash at its
/// start when no raven-node answers. No keystore call: a sealed file whose
/// key this process has not loaded is left for the next pass. Each file
/// under its own writer lock; best effort. A pass that removed anything
/// marks a data-key rotation due ([`mark_rotation_due`]): the older sealed
/// versions of these files in freed disk blocks still hold what went.
pub fn forget_stale_addresses(data_dir: &Path, now_ms: u64) -> ForgetReport {
    forget_stale_addresses_with(data_dir, now_ms, || outbox_message_ids(data_dir))
}

/// [`forget_stale_addresses`] with the outbox's message ids read by
/// `in_outbox`.
fn forget_stale_addresses_with(
    data_dir: &Path,
    now_ms: u64,
    in_outbox: impl FnOnce() -> Result<std::collections::HashSet<[u8; 16]>, String>,
) -> ForgetReport {
    let mut report = ForgetReport::default();
    let mut count = |result: Result<usize, String>| {
        result.unwrap_or_else(|_| {
            report.kept += 1;
            0
        })
    };
    // Read before the old sightings go (they say "not heard" anyway).
    let last_link = crate::lan_seen::sighting_times(data_dir);
    let sightings = count(crate::lan_seen::prune(data_dir, now_ms));
    let learned_routes = count(crate::learned_routes::prune(
        data_dir,
        now_ms,
        last_link.as_ref(),
    ));
    let remembered_routes = count(crate::route_memory::prune(data_dir, now_ms));
    let message_routes = count(crate::outbox::forget_finished_object_routes(
        data_dir, now_ms, in_outbox,
    ));
    let peer_schedules = count(crate::peer_rotation::prune_schedules(data_dir, now_ms));
    report.sightings = sightings;
    report.learned_routes = learned_routes;
    report.remembered_routes = remembered_routes;
    report.message_routes = message_routes;
    report.peer_schedules = peer_schedules;
    if report.removed() > 0 {
        let _ = mark_rotation_due(data_dir);
    }
    report
}

/// The message ids the outbox holds: the store's prepared and queued rows,
/// as `raven outbox list` reads them (ACK rows too: a superset is safe),
/// and, while the long message horizon is live (Phase 5a), its parked
/// messages, which wait for a new session until their deadlines: their
/// route records (carrier choice, custody consent, the never-sent flag) and
/// history rows stay too (P5.9). None without a store (none is created).
fn outbox_message_ids(data_dir: &Path) -> Result<std::collections::HashSet<[u8; 16]>, String> {
    use crate::indexed_session_store::{IndexedSessionStore, INDEXED_SESSION_METADATA_FILE};
    if !data_dir.join(INDEXED_SESSION_METADATA_FILE).exists() {
        return Ok(std::collections::HashSet::new());
    }
    let store = IndexedSessionStore::open(data_dir).map_err(|e| e.redacted_display())?;
    let mut ids = std::collections::HashSet::new();
    for rows in [
        store.pending_endpoint_outbound(),
        store.awaiting_ack_endpoint_outbound(),
    ] {
        ids.extend(
            rows.map_err(|e| e.redacted_display())?
                .into_iter()
                .map(|row| row.message_id),
        );
    }
    if crate::horizon::horizon_live_enabled() {
        for peer in store.parked_peers().map_err(|e| e.redacted_display())? {
            ids.extend(
                store
                    .parked_for_recipient(&peer.peer)
                    .map_err(|e| e.redacted_display())?
                    .into_iter()
                    .map(|row| row.message_id),
            );
        }
    }
    Ok(ids)
}

// ── Deleting a chat (PP.8) ────────────────────────────────────────────────

/// What [`delete_chat`] removed: counts only.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ChatDeletion {
    /// Chat history rows, both directions.
    pub history: u32,
    /// The session store's received rows ([`InboxDeletion`]).
    pub inbox: InboxDeletion,
}

/// "Delete chat with {name}" and `/clear-local-history` (privacy pack PP.8):
/// a clear that sticks. First the messages `peer` sent leave the session
/// store (all of them, or those at or before `up_to`, a reader's place in
/// the inbox: PP.14), each leaving a tombstone, so neither the
/// session-expiry archive nor a re-delivered copy writes them back into the
/// history
/// ([`crate::indexed_session_store::IndexedSessionStore::delete_inbox_for_sender`];
/// agent payloads are RDAP's and stay). Then every history row of `peer`,
/// both directions ([`crate::chat_history::ChatHistory::delete_for_contact`]).
/// In that order: a failure in between leaves the history, which a second
/// run deletes, never store rows the archive would bring back.
///
/// Messages still waiting to be sent to `peer` stay: their outbox rows and
/// staged bodies are not touched, the stage reconcile shows them as waiting
/// again, and their rows turn delivered (or expired) when they finish
/// ([`crate::lan_dispatch::ensure_outbound_queued_history`]). A deletion
/// that removed anything marks a data-key rotation due
/// ([`mark_rotation_due`], PP.10). A profile without a session store gets
/// none.
pub fn delete_chat(
    data_dir: &Path,
    peer: &[u8; 32],
    up_to: Option<&crate::indexed_session_store::InboxPosition>,
) -> Result<ChatDeletion, String> {
    use crate::indexed_session_store::{IndexedSessionStore, INDEXED_SESSION_METADATA_FILE};
    let mut deletion = ChatDeletion::default();
    if data_dir.join(INDEXED_SESSION_METADATA_FILE).exists() {
        let mut store = IndexedSessionStore::open(data_dir).map_err(|e| e.redacted_display())?;
        deletion.inbox = store
            .delete_inbox_for_sender(peer, up_to)
            .map_err(|e| e.redacted_display())?;
    } else {
        deletion.inbox.scrubbed = true;
    }
    let deleted_history =
        crate::chat_history::ChatHistory::delete_for_contact(data_dir, &hex::encode(peer))
            .map_err(|e| e.to_string());
    // What already went is in older copies until the next rotation.
    if deletion.inbox.deleted > 0 || deleted_history.as_ref().is_ok_and(|n| *n > 0) {
        let _ = mark_rotation_due(data_dir);
    }
    deletion.history = deleted_history?;
    Ok(deletion)
}

// ── Keeping chats (PP.9) ──────────────────────────────────────────────────

/// The grace before the first retention deletion in a profile that already
/// held chats when this build first saw it (OD-PP-3 (a)), so people can
/// choose 90 days or "always" first. Debug builds: `RAVEN_LAB_RETENTION_GRACE_MS`.
pub const RETENTION_GRACE_MS: u64 = 7 * DAY_MS;
/// A retention pass that found nothing to delete reads the history again
/// within a day at the latest (inbox rows and staged bodies without a
/// history row, a clock set back) ...
const RETENTION_RECHECK_MAX_MS: u64 = DAY_MS;
/// ... and not before an hour (a message still waiting to be sent whose row
/// is already old).
const RETENTION_RECHECK_MIN_MS: u64 = HOUR_MS;
/// A pass that failed (the history key or a store not available now) is
/// tried again after this long.
const RETENTION_RETRY_MS: u64 = HOUR_MS;

/// How long chats are kept on this computer (owner decision OD-PP-4: 7 / 30
/// / 90 days or always, default 30 days). Stored in `privacy.json` as
/// `"chat_keep"`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ChatKeep {
    Days7,
    #[default]
    Days30,
    Days90,
    Always,
}

impl ChatKeep {
    pub const ALL: [ChatKeep; 4] = [
        ChatKeep::Days7,
        ChatKeep::Days30,
        ChatKeep::Days90,
        ChatKeep::Always,
    ];

    /// `"7d"`, `"30d"`, `"90d"` or `"always"` (the file's and the CLI's word).
    pub fn as_str(self) -> &'static str {
        match self {
            ChatKeep::Days7 => "7d",
            ChatKeep::Days30 => "30d",
            ChatKeep::Days90 => "90d",
            ChatKeep::Always => "always",
        }
    }

    pub fn parse(word: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|keep| keep.as_str() == word)
    }

    /// The days chats are kept; `None` for always.
    pub fn days(self) -> Option<u64> {
        match self {
            ChatKeep::Days7 => Some(7),
            ChatKeep::Days30 => Some(30),
            ChatKeep::Days90 => Some(90),
            ChatKeep::Always => None,
        }
    }

    fn keep_ms(self) -> Option<u64> {
        self.days().map(|days| days * DAY_MS)
    }
}

/// The setting as `file` records it: absent is 30 days; a word this build
/// does not know (a newer build wrote it) keeps everything, never more
/// deletion than the user chose.
fn keep_of(file: &PrivacyFile) -> ChatKeep {
    file.chat_keep.as_deref().map_or(ChatKeep::Days30, |word| {
        ChatKeep::parse(word).unwrap_or(ChatKeep::Always)
    })
}

/// How long this profile keeps chats. A `privacy.json` that cannot be read
/// keeps everything (nothing is deleted on a guess).
pub fn chat_keep(data_dir: &Path) -> ChatKeep {
    match read_file(data_dir) {
        Ok(file) => keep_of(&file.unwrap_or_default()),
        Err(_) => ChatKeep::Always,
    }
}

/// `raven chats keep` and the terminal app's "Keep chats for": record the
/// setting (atomic, fsynced, every other field kept). The next retention
/// pass reads the history again. Refused on a profile without an identity
/// (a settings file would make the first `raven init` refuse it).
pub fn set_chat_keep(data_dir: &Path, keep: ChatKeep) -> Result<(), String> {
    if !crate::identity_store::identity_recorded(data_dir).map_err(|e| e.to_string())? {
        return Err("this profile has no identity yet: run `raven init` first".into());
    }
    update(data_dir, |file| {
        file.chat_keep = Some(keep.as_str().to_owned());
        file.retention_next_at_ms = None;
    })
    .map_err(|e| e.to_string())
}

/// When the retention pass may first delete (`None`: no build that may seal
/// has started it in this profile yet).
pub fn retention_starts_at(data_dir: &Path) -> Option<u64> {
    read_file(data_dir)
        .ok()
        .flatten()
        .and_then(|file| file.retention_starts_at_ms)
}

/// The grace before the first deletion of a profile that held chats.
fn retention_grace_ms() -> u64 {
    crate::p2p_gate::lab_switch(crate::lan_gate::LAB_RETENTION_GRACE_MS)
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(RETENTION_GRACE_MS)
}

/// Whether the profile holds chats (a history or an outbound stage): one
/// that does when this build first sees it gets the grace and the notice.
fn holds_chats(data_dir: &Path) -> bool {
    crate::chat_history::history_path(data_dir).exists()
        || crate::chat_history::outbound_body_stage_path(data_dir).exists()
}

/// Start the retention clock in `file` once: now for a profile without
/// chats, now plus the grace (and the notice) for one that holds some.
fn start_retention(file: &mut PrivacyFile, now_ms: u64, holds_chats: bool) {
    if file.retention_starts_at_ms.is_some() {
        return;
    }
    if holds_chats {
        file.retention_starts_at_ms = Some(now_ms.saturating_add(retention_grace_ms()));
        file.notices.retention_pending = true;
    } else {
        file.retention_starts_at_ms = Some(now_ms);
    }
    file.retention_next_at_ms = None;
}

/// [`start_retention`] on the file, when it has not started yet.
fn record_retention_start(data_dir: &Path, now_ms: u64) -> Result<(), AtRestError> {
    if read_file(data_dir)?.is_some_and(|file| file.retention_starts_at_ms.is_some()) {
        return Ok(());
    }
    let chats = holds_chats(data_dir);
    update(data_dir, |file| start_retention(file, now_ms, chats))
}

/// What [`apply_retention`] took off the disk: counts only (the log line
/// names no one, no message and no time).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RetentionReport {
    /// The pass looked at the chats: the setting is not "always", the grace
    /// is over and the last pass did not find that nothing could go yet.
    pub ran: bool,
    /// Chat history rows, both directions.
    pub history: u32,
    /// Contacts whose chat lost rows.
    pub chats: u32,
    /// The session store's received rows ([`InboxDeletion`]).
    pub inbox: InboxDeletion,
    /// Staged bodies of messages that already finished.
    pub staged: u32,
    /// Old rows kept because their message still waits to be sent.
    pub waiting: u32,
}

impl RetentionReport {
    /// Entries taken off the disk in all.
    pub fn removed(&self) -> u32 {
        self.history
            .saturating_add(self.inbox.deleted)
            .saturating_add(self.staged)
    }
}

impl std::fmt::Display for RetentionReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "history={} chats={} inbox={} staged={} waiting={} skipped={}",
            self.history,
            self.chats,
            self.inbox.deleted,
            self.staged,
            self.waiting,
            self.inbox.skipped
        )
    }
}

/// Privacy pack PP.9, owner decision "delete old chats automatically"
/// (OD-PP-4): delete what is older than the setting ([`chat_keep`]) once
/// the retention clock started ([`retention_starts_at`]; the grace of an
/// existing profile). Counts only. In this order:
///
/// 1. The session store's received chat rows received before the cutoff
///    ([`crate::indexed_session_store::IndexedSessionStore::delete_inbox_older_than`],
///    each leaving a tombstone, then a checkpoint whose outcome is
///    `inbox.scrubbed`), so the session-expiry archive cannot write a
///    deleted row back into the history.
/// 2. The staged bodies of finished messages sent before the cutoff
///    ([`crate::chat_history::clear_finished_staged_older_than`]), so the
///    stage reconcile cannot write one back either.
/// 3. The history rows kept since before the cutoff
///    ([`crate::chat_history::ChatHistory::delete_older_than`]: by when this
///    computer stored them; a legacy row by the conservative age).
///
/// Messages still waiting to be sent are never deleted: their outbound rows
/// and staged bodies stay until they finish (they expire by their own
/// rules), and the outbox itself is not touched. When the outbox cannot be
/// read nothing is deleted. A pass that removed anything marks a data-key
/// rotation due ([`mark_rotation_due`], PP.10). The pass records when the
/// next one can find anything (`retention_next_at_ms`), so the passes before
/// it read no history and make no keystore call.
///
/// raven-node runs it with every durable prune
/// ([`crate::lan_dispatch::prune_expired_lan_durable_state`]), ash at its
/// start when no raven-node answers.
pub fn apply_retention(data_dir: &Path, now_ms: u64) -> Result<RetentionReport, String> {
    apply_retention_with(data_dir, now_ms, || outbox_message_ids(data_dir))
}

/// [`apply_retention`] with the outbox's message ids read by `in_outbox`.
fn apply_retention_with(
    data_dir: &Path,
    now_ms: u64,
    in_outbox: impl FnOnce() -> Result<std::collections::HashSet<[u8; 16]>, String>,
) -> Result<RetentionReport, String> {
    let mut report = RetentionReport::default();
    // No settings file, or one that cannot be read: nothing started, or
    // keep everything ([`chat_keep`]).
    let Ok(Some(file)) = read_file(data_dir) else {
        return Ok(report);
    };
    let Some(keep_ms) = keep_of(&file).keep_ms() else {
        return Ok(report);
    };
    match file.retention_starts_at_ms {
        Some(starts) if now_ms >= starts => {}
        _ => return Ok(report),
    }
    // Nothing could go yet (a clock set back past the recheck window does
    // not hold the pass up).
    if let Some(next) = file.retention_next_at_ms {
        if now_ms < next && next <= now_ms.saturating_add(RETENTION_RECHECK_MAX_MS) {
            return Ok(report);
        }
    }
    report.ran = true;
    let cutoff = now_ms.saturating_sub(keep_ms);
    let pass = retention_pass(data_dir, cutoff, in_outbox, &mut report);
    let next = match &pass {
        Ok(oldest_kept) => oldest_kept
            .map_or(u64::MAX, |since| {
                since.saturating_add(keep_ms).saturating_add(1)
            })
            .clamp(
                now_ms.saturating_add(RETENTION_RECHECK_MIN_MS),
                now_ms.saturating_add(RETENTION_RECHECK_MAX_MS),
            ),
        Err(_) => now_ms.saturating_add(RETENTION_RETRY_MS),
    };
    let _ = update(data_dir, |file| file.retention_next_at_ms = Some(next));
    // What already went is in older copies until the next rotation.
    if report.removed() > 0 {
        let _ = mark_rotation_due(data_dir);
    }
    pass.map(|_| report)
}

/// The deletions of [`apply_retention_with`], counted into `report`; the
/// oldest age of the history rows that stay.
fn retention_pass(
    data_dir: &Path,
    cutoff_ms: u64,
    in_outbox: impl FnOnce() -> Result<std::collections::HashSet<[u8; 16]>, String>,
    report: &mut RetentionReport,
) -> Result<Option<u64>, String> {
    use crate::indexed_session_store::{IndexedSessionStore, INDEXED_SESSION_METADATA_FILE};
    let waiting = in_outbox()?;
    if data_dir.join(INDEXED_SESSION_METADATA_FILE).exists() {
        let mut store = IndexedSessionStore::open(data_dir).map_err(|e| e.redacted_display())?;
        report.inbox = store
            .delete_inbox_older_than(cutoff_ms)
            .map_err(|e| e.redacted_display())?;
    } else {
        report.inbox.scrubbed = true;
    }
    report.staged =
        crate::chat_history::clear_finished_staged_older_than(data_dir, cutoff_ms, &waiting)
            .map_err(|e| e.to_string())?;
    let history =
        crate::chat_history::ChatHistory::delete_older_than(data_dir, cutoff_ms, &waiting)
            .map_err(|e| e.to_string())?;
    report.history = history.deleted;
    report.chats = history.chats;
    report.waiting = history.waiting;
    Ok(history.oldest_kept_ms)
}

/// What the retention setting means for this profile now (`raven chats
/// status`; `raven privacy status` later).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionOutlook {
    pub keep: ChatKeep,
    /// The retention clock's start (`None`: not started in this profile).
    pub starts_at_ms: Option<u64>,
    /// When the next messages go (at this time or at the first pass after
    /// it; at or before `now` when they are due already); `None`: none will
    /// with this setting (always, no chats, or only messages still waiting
    /// to be sent).
    pub next_at_ms: Option<u64>,
    /// The history messages that go then (due within the hour after it,
    /// which the passes take together) ...
    pub messages: u32,
    /// ... and the chats (contacts) they belong to.
    pub chats: u32,
}

/// [`RetentionOutlook`] of this profile at `now_ms`: reads the history (the
/// history key) and the outbox; changes nothing.
pub fn retention_outlook(data_dir: &Path, now_ms: u64) -> Result<RetentionOutlook, String> {
    let file = read_file(data_dir)
        .map_err(|e| e.to_string())?
        .unwrap_or_default();
    let keep = keep_of(&file);
    let mut outlook = RetentionOutlook {
        keep,
        starts_at_ms: file.retention_starts_at_ms,
        next_at_ms: None,
        messages: 0,
        chats: 0,
    };
    let (Some(keep_ms), Some(starts)) = (keep.keep_ms(), file.retention_starts_at_ms) else {
        return Ok(outlook);
    };
    let waiting = outbox_message_ids(data_dir)?;
    let history = crate::chat_history::ChatHistory::load(data_dir).map_err(|e| e.to_string())?;
    // A row goes at the first pass once it is older than the setting, and
    // not before the start.
    let due: Vec<(u64, &str)> = history
        .entries
        .iter()
        .filter(|entry| !entry.is_waiting(&waiting))
        .map(|entry| {
            let at = entry
                .kept_since_ms()
                .saturating_add(keep_ms)
                .saturating_add(1)
                .max(starts);
            (at, entry.peer_pub_hex.as_str())
        })
        .collect();
    let Some(next) = due.iter().map(|(at, _)| *at).min() else {
        return Ok(outlook);
    };
    // Already due: everything due by now goes at the next pass.
    let window = next.max(now_ms).saturating_add(RETENTION_RECHECK_MIN_MS);
    let going: Vec<&str> = due
        .iter()
        .filter(|(at, _)| *at <= window)
        .map(|(_, peer)| *peer)
        .collect();
    let chats: std::collections::HashSet<&str> = going.iter().copied().collect();
    outlook.next_at_ms = Some(next);
    outlook.messages = u32::try_from(going.len()).unwrap_or(u32::MAX);
    outlook.chats = u32::try_from(chats.len()).unwrap_or(u32::MAX);
    Ok(outlook)
}

/// The one-time retention notice is due: when the first deletion may come
/// (the terminal app reads it without taking it; PP.21).
pub fn retention_notice_due(data_dir: &Path) -> Option<u64> {
    let file = read_file(data_dir).ok().flatten()?;
    if !file.notices.retention_pending || keep_of(&file) == ChatKeep::Always {
        return None;
    }
    file.retention_starts_at_ms
}

/// The one-time retention notice (UX copy): `Some((setting, first deletion
/// time))` once, and it is marked shown. A profile that keeps chats always
/// by then is not told (the notice is cleared).
pub fn take_retention_notice(data_dir: &Path) -> Option<(ChatKeep, u64)> {
    let file = read_file(data_dir).ok().flatten()?;
    if !file.notices.retention_pending {
        return None;
    }
    let keep = keep_of(&file);
    let starts = file.retention_starts_at_ms;
    let due = take_once(data_dir, |n| std::mem::take(&mut n.retention_pending));
    match (due, keep, starts) {
        (true, ChatKeep::Days7 | ChatKeep::Days30 | ChatKeep::Days90, Some(at)) => Some((keep, at)),
        _ => None,
    }
}

/// The retention notice (UX copy): `when` is "on {date}" in local time (or
/// "in about 7 days" when the local time is not known).
pub fn retention_notice_text(keep: ChatKeep, when: &str) -> String {
    format!(
        "New: Raven deletes chats older than {} days from this computer. The first deletion is \
         {when}. To keep chats longer or always: `raven chats keep 90d` or `raven chats keep \
         always`.",
        keep.days().unwrap_or(30)
    )
}

/// What `raven chats keep` says (UX copy).
pub fn chat_keep_text(keep: ChatKeep) -> String {
    match keep.days() {
        Some(days) => format!(
            "Keep chats on this computer for {days} days. Older chats are deleted from this \
             computer. Your friends' copies aren't."
        ),
        None => "Raven keeps your chats on this computer until you delete them.".to_owned(),
    }
}

// ── Lock now v1 (PP.15) ───────────────────────────────────────────────────

/// What `raven lock` says when ash would start raven-node by itself while
/// the profile is locked (the send path, `raven listen`; UX copy).
pub const LOCKED_TEXT: &str = "Raven is locked. Run `raven unlock` to start it again.";
/// `raven status`'s first line while the profile is locked and no
/// raven-node answers (UX copy).
pub const LOCKED_STATUS_LINE: &str =
    "Raven is locked (stopped). Run `raven unlock` to start it again.";

/// Lock v2 (Phase 6 P6.40, gate `LOCAL_PROTECTION`): `raven status`'s first
/// line while raven-node runs locked (UX copy).
pub const LOCKED_V2_STATUS_LINE: &str = "Raven is locked. Friends can't reach you; your messages \
     wait here. Run `raven unlock` to open it.";
/// Lock v2: what a locked raven-node answers to any request but Ping,
/// Status, Lock and Unlock, and why a send is refused while it is locked.
pub const LOCKED_V2_TEXT: &str = "Raven is locked. Run `raven unlock` to open it again.";
/// Lock v2: the locked screen's first line and `raven lock`'s result.
pub const LOCKED_V2_SCREEN: &str =
    "Raven is locked. Friends can't reach you; your messages wait here.";

/// Lock v2: what a lock does not protect on a profile without a Raven
/// passphrase (UX copy; design C): its keys are in this computer's login
/// store, open to anyone who can log in as the user. macOS can switch to a
/// Raven passphrase (Settings).
pub fn keys_open_to_login_text() -> &'static str {
    if cfg!(target_os = "macos") {
        "On this computer, your Raven keys are in your login keychain. Anyone who can log in as \
         you can open them. Lock your screen too, or set a Raven passphrase (Settings)."
    } else if cfg!(windows) {
        "On this computer, your Raven keys are protected by your Windows account. Anyone who \
         can log in as you can open them. Lock your screen too."
    } else {
        "On this computer, your Raven keys are in your desktop keyring. Anyone who can log in as \
         you can open them. Lock your screen too."
    }
}

/// What `raven lock` did to Raven's own login item for this profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LockedItem {
    /// Unloaded for this login session (launchd's `bootout`, systemd's
    /// `stop`, the scheduler's `/End`): it starts Raven again at the next
    /// login.
    Unloaded,
    /// Also turned off until `raven unlock` (`disable`).
    Disabled,
}

impl LockedItem {
    pub fn as_str(self) -> &'static str {
        match self {
            LockedItem::Unloaded => "unloaded",
            LockedItem::Disabled => "disabled",
        }
    }

    /// A word this build does not know (a newer build wrote it) reads as
    /// [`LockedItem::Disabled`]: `raven unlock` then turns the item back on,
    /// which is what an unlock is for.
    fn of_word(word: &str) -> LockedItem {
        match word {
            "unloaded" => LockedItem::Unloaded,
            _ => LockedItem::Disabled,
        }
    }
}

/// The lock as `privacy.json` records it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LockState {
    /// `raven lock` (or the full-screen app's Lock) stopped Raven and no
    /// `raven unlock` (nor an app start that cleared it, PP.23) came since.
    pub locked_by_user: bool,
    /// What the lock did to Raven's own login item, until `raven unlock`
    /// turned it back on.
    pub login_item: Option<LockedItem>,
    /// The lock is the full-screen app's own (`privacy.json` `lock_by`):
    /// opening the app clears it. Otherwise `raven lock` set it, and the app
    /// asks before it starts Raven (review E-harness-docs-ci-3).
    pub by_app: bool,
}

/// `lock_by` of a lock the full-screen app's Lock set.
const LOCK_BY_APP: &str = "app";
/// `lock_by` of a lock `raven lock` set.
const LOCK_BY_CLI: &str = "cli";

/// The profile's lock. A `privacy.json` that cannot be read holds no lock:
/// nobody locked a file that no build could have written.
pub fn lock_state(data_dir: &Path) -> LockState {
    let Ok(Some(file)) = read_file(data_dir) else {
        return LockState::default();
    };
    LockState {
        locked_by_user: file.locked_by_user,
        login_item: file.lock_login_item.as_deref().map(LockedItem::of_word),
        by_app: file.locked_by_user && file.lock_by.as_deref() == Some(LOCK_BY_APP),
    }
}

/// `raven lock`: record the lock (atomic, fsynced, every other field kept),
/// with what it did to Raven's own login item; an item already recorded as
/// [`LockedItem::Disabled`] stays so (it is still off). The lock is `raven
/// lock`'s from now on, whoever set it before. Refused on a profile without
/// an identity (a settings file would make the first `raven init` refuse
/// it).
pub fn set_locked(data_dir: &Path, login_item: Option<LockedItem>) -> Result<(), String> {
    lock(data_dir, false, login_item)
}

/// The full-screen app's Lock (PP.23; review E-harness-docs-ci-3):
/// [`set_locked`], recorded as the app's own, so opening the app clears it
/// again. A lock `raven lock` set stays its own: the app's Lock never
/// makes it one that opening the app clears.
pub fn set_locked_by_app(data_dir: &Path, login_item: Option<LockedItem>) -> Result<(), String> {
    lock(data_dir, true, login_item)
}

fn lock(data_dir: &Path, by_app: bool, login_item: Option<LockedItem>) -> Result<(), String> {
    if !crate::identity_store::identity_recorded(data_dir).map_err(|e| e.to_string())? {
        return Err("this profile has no identity yet: there is no Raven to lock".into());
    }
    update(data_dir, |file| {
        let cli_lock = file.locked_by_user && file.lock_by.as_deref() != Some(LOCK_BY_APP);
        file.locked_by_user = true;
        if !by_app || !cli_lock {
            let by = if by_app { LOCK_BY_APP } else { LOCK_BY_CLI };
            file.lock_by = Some(by.to_owned());
        }
        let was = file.lock_login_item.as_deref().map(LockedItem::of_word);
        file.lock_login_item = was.max(login_item).map(|item| item.as_str().to_owned());
    })
    .map_err(|e| e.to_string())
}

/// `raven unlock` (first), a `raven lock` that did not stop Raven, and the
/// app when it opens on its own lock or the user said to start Raven again:
/// the profile is no longer locked, by anyone. What the lock did to the
/// login item stays recorded until [`clear_lock_login_item`]. Writes nothing
/// when it is not locked.
pub fn set_unlocked(data_dir: &Path) -> Result<(), String> {
    if !lock_state(data_dir).locked_by_user {
        return Ok(());
    }
    update(data_dir, |file| {
        file.locked_by_user = false;
        file.lock_by = None;
    })
    .map_err(|e| e.to_string())
}

/// `raven unlock` turned Raven's own login item back on (or it is gone):
/// forget what the lock did to it. Writes nothing when nothing is recorded.
pub fn clear_lock_login_item(data_dir: &Path) -> Result<(), String> {
    if lock_state(data_dir).login_item.is_none() {
        return Ok(());
    }
    update(data_dir, |file| file.lock_login_item = None).map_err(|e| e.to_string())
}

// ── Data-key rotation (PP.10) ─────────────────────────────────────────────

/// How long an old epoch stays in `meta_key.rmk` after a rotation started,
/// at least: a process that loaded the keys just before the start and seals
/// afterwards seals under the old epoch, still readable, and a later pass
/// re-seals it before the epoch goes.
pub const ROTATION_GRACE_MS: u64 = DAY_MS;
/// How long a rotation pass waits for a migration or another pass.
const ROTATION_LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

/// What [`rotate_data_key`] did: counts only (the log line names nothing).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RotationReport {
    /// A new epoch was added and made current (step 1).
    pub started: bool,
    /// Objects sealed again under the current epoch (steps 2 and 4).
    pub resealed: u32,
    /// The old epoch left `meta_key.rmk` (step 4).
    pub dropped: bool,
    /// Objects not on the current epoch that could not be sealed again now
    /// (a lock held, a read failed): the drop waits for them.
    pub pending: u32,
    /// Objects that open with no key here (a changed byte): left as they
    /// are; they do not hold the drop up.
    pub unreadable: u32,
    /// A store's old row bytes wait for a later checkpoint of its WAL.
    pub scrub_pending: bool,
}

impl RotationReport {
    /// Anything worth a log line.
    pub fn did_anything(&self) -> bool {
        self.started || self.dropped || self.resealed > 0 || self.pending > 0
    }
}

impl std::fmt::Display for RotationReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "started={} resealed={} dropped={} pending={} unreadable={}",
            self.started, self.resealed, self.dropped, self.pending, self.unreadable
        )
    }
}

/// How a pass may go beyond the schedule (`raven privacy rotate-now`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct RotateNow {
    /// Start a rotation whether or not one is due (still one at a time).
    start: bool,
    /// End the grace: drop the old epoch once a re-scan finds nothing left
    /// on it.
    drop: bool,
}

/// Privacy pack PP.10: one pass of the data-key rotation, which makes what
/// was deleted (older sealed copies of files and rows in freed disk blocks)
/// unreadable with this computer's keys. K_hist and `k_index` never change;
/// only the epoch keys inside `meta_key.rmk` do. Each step can be re-run
/// after a crash at any point:
///
/// 1. When a rotation is due ([`mark_rotation_due`]) and none started today:
///    record it in `privacy.json` (the due mark cleared), then add epoch
///    e+1 and make it current ([`at_rest::add_epoch`]). Every writer seals
///    under it from its next key read on.
/// 2. Re-seal every object not on the current epoch, each under its own
///    lock or transaction: the chat history and the outbound stage (their
///    locks), the app rows and the SQLite stores' meta blobs (one
///    transaction per store, then a checkpoint; PP.12: the app store and
///    owed ACKs) and every registered sealed file (its writer lock).
/// 3. The grace: epoch e stays for at least [`ROTATION_GRACE_MS`], so a
///    process that loaded the keys before step 1 and sealed under e
///    afterwards loses nothing; the next pass re-seals it.
/// 4. The first pass after the grace re-scans everything: what is still not
///    on the current epoch is re-sealed and the pass stops there; once a
///    re-scan finds nothing left (and nothing it could not re-seal now), e
///    leaves the key file ([`at_rest::drop_old_epochs`]).
///
/// raven-node runs it with every durable prune (every 10 minutes), ash at
/// its start when no raven-node answers. No keystore call: the keys this
/// process loaded ([`at_rest::keys_cached`]; an error without them). A
/// profile that is not sealed never rotates (nothing happens). Under
/// `.at_rest.lock.sqlite` (a pass that waits more than 2 s for it is skipped).
pub fn rotate_data_key(data_dir: &Path, now_ms: u64) -> Result<RotationReport, String> {
    rotate_pass(data_dir, now_ms, RotateNow::default())
}

/// `raven privacy rotate-now` (hidden; the owner's real-row check R34):
/// start a rotation now (one at a time) and re-seal; with `drop_now` also
/// end the grace and drop the old epoch as soon as a re-scan finds nothing
/// left on it (up to three passes). Only for a check by hand: a process
/// that read the keys just before the start and seals right after it loses
/// that write when the grace is cut short.
pub fn rotate_data_key_now(
    data_dir: &Path,
    now_ms: u64,
    drop_now: bool,
) -> Result<RotationReport, String> {
    let mut total = rotate_pass(
        data_dir,
        now_ms,
        RotateNow {
            start: true,
            drop: false,
        },
    )?;
    if !drop_now {
        return Ok(total);
    }
    for _ in 0..3 {
        let pass = rotate_pass(
            data_dir,
            now_ms,
            RotateNow {
                start: false,
                drop: true,
            },
        )?;
        total.resealed = total.resealed.saturating_add(pass.resealed);
        total.unreadable = pass.unreadable;
        total.pending = pass.pending;
        total.scrub_pending |= pass.scrub_pending;
        if pass.dropped || !holds_old_epoch(data_dir) {
            total.dropped |= pass.dropped;
            break;
        }
    }
    Ok(total)
}

/// The key file holds an epoch besides the current one.
fn holds_old_epoch(data_dir: &Path) -> bool {
    at_rest::keys_cached(data_dir).is_ok_and(|keys| keys.epochs().len() > 1)
}

fn rotate_pass(data_dir: &Path, now_ms: u64, now: RotateNow) -> Result<RotationReport, String> {
    let mut report = RotationReport::default();
    if mode(data_dir) != Mode::Sealed {
        return Ok(report);
    }
    let text = |e: AtRestError| e.to_string();
    at_rest::keys_cached(data_dir).map_err(text)?;
    let _all = DataDirLock::acquire_within(data_dir, at_rest::AT_REST_LOCK, ROTATION_LOCK_WAIT)?;
    let file = read_file(data_dir).map_err(text)?.unwrap_or_default();
    // `raven privacy rotate-meta` (PP.18) did not finish: its stores may
    // still be keyed under the old `k_index`, and only it moves them on.
    if file.meta_rotation.is_some() {
        return Ok(report);
    }
    let keys = at_rest::keys_cached(data_dir).map_err(text)?;
    let held = keys.epochs();
    let mut record = match file.rotation {
        // Dropped already: a crash came before the record was cleared.
        Some(record) if held.len() == 1 && keys.current_epoch() != record.from => {
            update(data_dir, |file| file.rotation = None).map_err(text)?;
            return Ok(report);
        }
        Some(record) => record,
        // An old epoch without a record (a settings file put back): its
        // grace counts from now.
        None if held.len() > 1 => {
            let record = RotationRecord {
                from: held[0],
                started_at_ms: now_ms,
            };
            update(data_dir, |file| file.rotation = Some(record)).map_err(text)?;
            record
        }
        None => {
            let today = now_ms / DAY_MS;
            let started_today = file
                .last_rotation_at_ms
                .is_some_and(|at| at / DAY_MS == today);
            if !now.start && !(file.rotation_due && !started_today) {
                return Ok(report);
            }
            // Recorded first, the due mark with it: a deletion from here on
            // marks the next rotation, since the copies it leaves may be
            // sealed under the new epoch.
            let record = RotationRecord {
                from: keys.current_epoch(),
                started_at_ms: now_ms,
            };
            update(data_dir, |file| {
                file.rotation = Some(record);
                file.rotation_due = false;
                file.last_rotation_at_ms = Some(now_ms);
            })
            .map_err(text)?;
            #[cfg(test)]
            tests::crash_point(tests::Crash::RotationRecorded).map_err(text)?;
            record
        }
    };
    // Step 1 (again after a crash before it).
    if keys.current_epoch() == record.from {
        at_rest::add_epoch(data_dir, record.from).map_err(text)?;
        report.started = true;
        #[cfg(test)]
        tests::crash_point(tests::Crash::RotationStarted).map_err(text)?;
    }
    // A clock set back before the start: the grace counts from now.
    if now_ms < record.started_at_ms {
        record.started_at_ms = now_ms;
        update(data_dir, |file| file.rotation = Some(record)).map_err(text)?;
    }
    // Step 2, and step 4's re-scan.
    reseal_everything(data_dir, &mut report).map_err(text)?;
    let grace_over = now.drop || now_ms >= record.started_at_ms.saturating_add(ROTATION_GRACE_MS);
    if report.started || !grace_over || report.resealed > 0 || report.pending > 0 {
        return Ok(report);
    }
    // Step 4: nothing is left on the old epoch.
    at_rest::drop_old_epochs(data_dir).map_err(text)?;
    report.dropped = true;
    #[cfg(test)]
    tests::crash_point(tests::Crash::EpochDropped).map_err(text)?;
    update(data_dir, |file| file.rotation = None).map_err(text)?;
    Ok(report)
}

/// Re-seal every object not on the current epoch into `report` (a
/// rotation's step 2 and step 4's re-scan). A sealed profile, its keys
/// loaded, under the at-rest lock.
fn reseal_everything(data_dir: &Path, report: &mut RotationReport) -> Result<(), AtRestError> {
    use crate::chat_history::{reseal_stage, ChatHistory, ChatHistoryError};
    let mut history = |result: Result<bool, ChatHistoryError>| match result {
        Ok(true) => report.resealed += 1,
        Ok(false) => {}
        // Not now (a lock held, a read failed, the key not here): the drop
        // waits. Unsafe metadata too: what is in that file must not be lost.
        Err(
            ChatHistoryError::Io(_)
            | ChatHistoryError::ProtectedStoreUnavailable(_)
            | ChatHistoryError::MissingProtectedKey
            | ChatHistoryError::UnsafeFileMetadata,
        ) => report.pending += 1,
        Err(_) => report.unreadable += 1,
    };
    history(ChatHistory::reseal(data_dir));
    #[cfg(test)]
    tests::crash_point(tests::Crash::ResealedHistory)?;
    history(reseal_stage(data_dir));
    #[cfg(test)]
    tests::crash_point(tests::Crash::ResealedStage)?;
    let mut rows = |result: Result<crate::app_store::RowReseal, String>| match result {
        Ok(rows) => {
            report.resealed += rows.resealed;
            report.unreadable += rows.unreadable;
            report.scrub_pending |= rows.scrub_pending;
        }
        // Not now (a store busy, the key not here): the drop waits.
        Err(_) => report.pending += 1,
    };
    // The app rows and, with them, the SQLite stores' meta blobs (PP.12).
    rows(crate::app_store::reseal_rows(data_dir));
    rows(crate::owed_acks::reseal_rows(data_dir).map_err(|e| e.to_string()));
    rows(crate::indexed_session_store::reseal_rows(data_dir));
    rows(crate::friend_custody::reseal_rows(data_dir));
    rows(crate::custody_handoff::reseal_rows(data_dir));
    rows(crate::security_ledger::reseal_rows(data_dir));
    #[cfg(test)]
    tests::crash_point(tests::Crash::ResealedAppRows)?;
    for (path, kind) in sealed_files(data_dir) {
        match at_rest::reseal_file(data_dir, &path, kind) {
            Ok(at_rest::Resealed::Resealed) => report.resealed += 1,
            Ok(_) => {}
            // An epoch the key file does not hold opens with no key here.
            Err(AtRestError::KeyUnavailable(_) | AtRestError::KeyLost(_) | AtRestError::Io(_)) => {
                report.pending += 1
            }
            Err(_) => report.unreadable += 1,
        }
    }
    #[cfg(test)]
    tests::crash_point(tests::Crash::ResealedFiles)?;
    Ok(())
}

/// Every file `at_rest::FILES` registers as sealed that exists in this
/// profile (a pattern's files in its folder), with its kind.
fn sealed_files(data_dir: &Path) -> Vec<(std::path::PathBuf, Kind)> {
    let mut files = Vec::new();
    for rule in at_rest::FILES {
        let at_rest::Rule::Sealed(kind) = rule.rule else {
            continue;
        };
        if !rule.name.contains('*') {
            let path = data_dir.join(rule.name);
            if std::fs::symlink_metadata(&path).is_ok() {
                files.push((path, kind));
            }
            continue;
        }
        let folder = rule.name.rsplit_once('/').map_or("", |(folder, _)| folder);
        let Ok(entries) = std::fs::read_dir(data_dir.join(folder)) else {
            continue;
        };
        let mut found: Vec<std::path::PathBuf> = entries
            .flatten()
            .filter(|entry| entry.file_type().is_ok_and(|t| t.is_file()))
            .filter(|entry| {
                let name = entry.file_name().to_string_lossy().into_owned();
                let below = if folder.is_empty() {
                    name
                } else {
                    format!("{folder}/{name}")
                };
                at_rest::registry::glob_match(rule.name, &below)
            })
            .map(|entry| entry.path())
            .collect();
        found.sort();
        files.extend(found.into_iter().map(|path| (path, kind)));
    }
    files
}

/// Windows (PP.11, review R18): put the profile under its own K_hist, in this
/// order, each step leaving files that open either way (a crash anywhere is
/// finished by the next pass): create `chat_history_key.dpapi` if missing;
/// in a sealed profile (`sealed`: sealed, or being sealed by this pass)
/// re-wrap `meta_key.rmk` under it (temp, verified, rename), and its history,
/// stage and app rows then move under the epoch keys in [`move_epoch_data`];
/// in a profile that is not sealed, move the DPAPI-direct history, stage and
/// app rows under K_hist with its format tag. Nothing is deleted. Cheap once
/// done (first bytes only), and nothing is created in a profile with nothing
/// DPAPI-direct. Best effort: what fails now the next pass does (only a
/// test's injected crash is an error). A profile that is not sealed keeps
/// its files while an older raven-node answers for it (`older_node`).
#[cfg(any(test, windows))]
fn move_under_windows_key(
    data_dir: &Path,
    sealed: bool,
    older_node: Option<&dyn Fn() -> bool>,
) -> Result<(), AtRestError> {
    use crate::chat_history::windows_key;
    if !windows_key::active() {
        return Ok(());
    }
    let left = if sealed {
        at_rest::key_file_dpapi_direct(data_dir)
    } else {
        windows_key::dpapi_files_left(data_dir)
            || crate::app_store::dpapi_rows_left(data_dir).unwrap_or(false)
    };
    if !left || (!sealed && older_node.is_some_and(|answers| answers())) {
        return Ok(());
    }
    let Ok(hist) = windows_key::hist_key(data_dir, true) else {
        return Ok(());
    };
    #[cfg(test)]
    tests::crash_point(tests::Crash::WindowsKeyCreated)?;
    if sealed {
        at_rest::adopt_hist(data_dir, hist);
        let _ = at_rest::rewrap_key_file(data_dir);
        #[cfg(test)]
        tests::crash_point(tests::Crash::WindowsKeyFileRewrapped)?;
    } else {
        drop(hist);
        let _ = windows_key::rewrap_history(data_dir);
        let _ = windows_key::rewrap_stage(data_dir);
        let _ = crate::app_store::rewrap_dpapi_rows(data_dir);
    }
    Ok(())
}

/// Move the chat history, the outbound stage and (with `app_rows`) the app
/// rows that K_hist still seals directly (or an older epoch) under the
/// current epoch (the migration's part of PP.10): each under its own lock or
/// transaction, best effort. A sealed profile with its keys loaded. The app
/// rows wait while the upgrade interlock holds the app store back (PP.12:
/// opening it would move it to schema 3).
fn move_epoch_data(data_dir: &Path, app_rows: bool) {
    let _ = crate::chat_history::ChatHistory::reseal(data_dir);
    let _ = crate::chat_history::reseal_stage(data_dir);
    if app_rows {
        let _ = crate::app_store::reseal_rows(data_dir);
    }
}

/// What [`upkeep_stores`] did: counts only (a log line names nothing).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StoreUpkeep {
    /// Stores moved to their keyed schema now.
    pub migrated: u16,
    /// Rows an older build's set-aside owed-ACK store gave back.
    pub merged_rows: u32,
    /// Set-aside owed-ACK stores that did not open as this profile's, sealed
    /// where they are.
    pub sealed_set_asides: u32,
    /// Stores that could not be moved now (tried again by the next pass).
    pub failed: u16,
    /// A store's scrub (its `VACUUM` and checkpoint) is still pending.
    pub scrub_pending: bool,
    /// A store still has to move, and an older raven-node answers: left as
    /// it is (the upgrade interlock).
    pub held_back: bool,
}

impl StoreUpkeep {
    /// Anything worth a log line.
    pub fn did_anything(&self) -> bool {
        self.migrated > 0 || self.merged_rows > 0 || self.sealed_set_asides > 0
    }
}

impl std::fmt::Display for StoreUpkeep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "migrated={} merged_rows={} sealed_set_asides={} failed={} scrub_pending={}",
            self.migrated,
            self.merged_rows,
            self.sealed_set_asides,
            self.failed,
            self.scrub_pending
        )
    }
}

/// Privacy pack PP.12, the prune passes' part (raven-node every 10 minutes,
/// ash when no node answers): [`move_stores`], then a scrub a reader or a
/// writer held up is finished, and an older build's send lock a send held
/// at the last pass goes (review B-sealed-stores-4). No keystore call.
pub fn upkeep_stores(data_dir: &Path) -> StoreUpkeep {
    let mut report = move_stores(data_dir, None, true);
    crate::outbox::PeerSendLock::remove_legacy_files(data_dir);
    if mode(data_dir) == Mode::Sealed {
        for scrub in [
            crate::owed_acks::finish_scrub(data_dir),
            crate::app_store::finish_scrub(data_dir),
            crate::indexed_session_store::finish_scrub(data_dir),
            crate::friend_custody::finish_scrub(data_dir),
            crate::custody_handoff::finish_scrub(data_dir),
        ] {
            report.scrub_pending |= scrub == Some(false);
        }
    }
    report
}

/// Privacy pack PP.12: the SQLite stores' part of the migration (and of the
/// prune passes), in a sealed profile with its keys loaded (nothing
/// otherwise). Each store moves to its keyed schema with the rebuild recipe
/// of [`crate::sqlite_rebuild`] under its own transaction (owed ACKs 1 -> 2,
/// the app store 2 -> 3, friend custody 1 -> 2 (PP.17), custody handoff
/// 1 -> 2 (Phase 5 P5.19), and with `sessions`
/// the session store 1 -> 2, PP.13, after its journal recovery), and an
/// older build's set-aside
/// owed-ACK store is merged back (review R06). Best effort: what fails now
/// the next pass (or the store's next open) does. A store still to move is
/// left while `older_node` answers that an older raven-node runs (ash's
/// upgrade interlock; it is asked only then). Cheap when nothing is to move:
/// the stores' headers and one folder listing. No keystore call (the
/// session store's open reads its sessions' protected state, so a caller
/// under a data-dir lock leaves it out).
fn move_stores(
    data_dir: &Path,
    older_node: Option<&dyn Fn() -> bool>,
    sessions: bool,
) -> StoreUpkeep {
    let mut report = StoreUpkeep::default();
    if mode(data_dir) != Mode::Sealed || at_rest::keys_cached(data_dir).is_err() {
        return report;
    }
    let to_move = crate::owed_acks::needs_migration(data_dir)
        || crate::app_store::needs_migration(data_dir)
        || crate::friend_custody::needs_migration(data_dir)
        || crate::custody_handoff::needs_migration(data_dir)
        || (sessions && crate::indexed_session_store::needs_migration(data_dir));
    report.held_back = to_move && older_node.is_some_and(|answers| answers());
    if !report.held_back {
        let mut moved = |result: Result<bool, String>| match result {
            Ok(true) => report.migrated += 1,
            Ok(false) => {}
            Err(_) => report.failed += 1,
        };
        moved(crate::owed_acks::migrate(data_dir).map_err(|e| e.to_string()));
        moved(crate::app_store::migrate(data_dir));
        moved(crate::friend_custody::migrate(data_dir));
        moved(crate::custody_handoff::migrate(data_dir));
        if sessions {
            moved(crate::indexed_session_store::migrate(data_dir));
        }
        if let Ok(merge) = crate::owed_acks::merge_set_asides(data_dir) {
            report.merged_rows = merge.rows;
            report.sealed_set_asides = merge.sealed;
        }
    }
    report
}

/// Where the data-key rotation stands (`raven privacy status`): from the
/// files and this process's keys, no keystore call and no lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationState {
    /// The epoch new data is sealed under (`None`: not sealed, or the key is
    /// not loaded in this process).
    pub current_epoch: Option<u32>,
    /// Every epoch `meta_key.rmk` holds: two during a rotation's grace.
    pub epochs_held: Vec<u32>,
    /// Objects on another epoch than the current one, or still under K_hist
    /// directly (by their first bytes).
    pub old_objects: u32,
    /// When the last rotation started.
    pub last_rotation_at_ms: Option<u64>,
    /// A rotation under way: when it started.
    pub started_at_ms: Option<u64>,
    /// Data was removed since the last rotation started: the next is due.
    pub due: bool,
}

impl RotationState {
    /// An old epoch is still held (a rotation's grace, or its re-scan).
    pub fn old_epoch_held(&self) -> bool {
        self.epochs_held.len() > 1
    }
}

/// [`RotationState`] of this profile now.
pub fn rotation_state(data_dir: &Path) -> RotationState {
    let file = read_file(data_dir).ok().flatten().unwrap_or_default();
    let keys = (mode(data_dir) == Mode::Sealed)
        .then(|| at_rest::keys_cached(data_dir).ok())
        .flatten();
    let mut state = RotationState {
        current_epoch: keys.as_ref().map(|keys| keys.current_epoch()),
        epochs_held: keys.as_ref().map(|keys| keys.epochs()).unwrap_or_default(),
        old_objects: 0,
        last_rotation_at_ms: file.last_rotation_at_ms,
        started_at_ms: file.rotation.map(|record| record.started_at_ms),
        due: file.rotation_due,
    };
    let Some(current) = state.current_epoch else {
        return state;
    };
    use crate::chat_history::{history_form, stage_form, SealForm};
    let off =
        |form: SealForm| !matches!(form, SealForm::Missing) && form != SealForm::Epoch(current);
    let mut old = usize::from(off(history_form(data_dir))) + usize::from(off(stage_form(data_dir)));
    old += crate::app_store::row_epochs(data_dir)
        .unwrap_or_default()
        .into_iter()
        .filter(|epoch| *epoch != Some(current))
        .count();
    // The SQLite stores' meta blobs (PP.12).
    let rows = crate::app_store::meta_rows_off_epoch(data_dir, current).unwrap_or(0)
        + crate::owed_acks::rows_off_epoch(data_dir, current).unwrap_or(0)
        + crate::indexed_session_store::rows_off_epoch(data_dir, current).unwrap_or(0)
        + crate::friend_custody::rows_off_epoch(data_dir, current).unwrap_or(0)
        + crate::custody_handoff::rows_off_epoch(data_dir, current).unwrap_or(0)
        + crate::security_ledger::rows_off_epoch(data_dir, current).unwrap_or(0);
    old += usize::try_from(rows).unwrap_or(usize::MAX);
    old += sealed_files(data_dir)
        .into_iter()
        .filter(|(path, kind)| {
            file_head(path).is_some_and(|head| {
                at_rest::is_sealed_as(*kind, &head)
                    && at_rest::sealed_file_epoch(&head) != Some(current)
            })
        })
        .count();
    state.old_objects = u32::try_from(old).unwrap_or(u32::MAX);
    state
}

/// A file's first bytes (an RMS1 header; a raw secret's whole plain file).
fn file_head(path: &Path) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut head = Vec::with_capacity(33);
    std::fs::File::open(path)
        .ok()?
        .take(33)
        .read_to_end(&mut head)
        .ok()?;
    Some(head)
}

/// What `raven privacy status --verify-copy` found for a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyCheck {
    /// It opens with this profile's current keys.
    Opens,
    /// A Raven file of this kind that opens with none of them.
    DoesNotOpen,
    /// Not encrypted at all.
    Plain,
    /// Not a file this build knows.
    Unknown,
}

/// Privacy pack PP.10, the owner's real-row check R34 (`raven privacy status
/// --verify-copy <file>`, hidden): whether `path`, a copy of one of this
/// profile's files (an older `chat_history.json`, `contacts.json`, ...),
/// opens with the keys this process holds now; it says nothing about what
/// is inside. A copy that K_hist sealed directly (RVNHIST1, RVNOSTG1) and a
/// copy of `meta_key.rmk` open as long as K_hist exists: rotation changes
/// the epoch keys only (the honest limit). No keystore call: an error when
/// the keys are not loaded here.
pub fn verify_copy(data_dir: &Path, path: &Path) -> Result<CopyCheck, String> {
    let raw = at_rest::read_raw(path)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "no such file".to_string())?;
    let opens = |yes: bool| {
        if yes {
            CopyCheck::Opens
        } else {
            CopyCheck::DoesNotOpen
        }
    };
    if let Some(opened) = crate::chat_history::copy_opens(data_dir, &raw) {
        return opened.map(opens).map_err(|e| e.to_string());
    }
    if raw.starts_with(b"RMK1") {
        return at_rest::key_file_opens(data_dir, &raw)
            .map(opens)
            .map_err(|e| e.to_string());
    }
    if at_rest::is_sealed(&raw) {
        let Some(kind) = raw.get(5).copied().and_then(Kind::from_code) else {
            return Ok(CopyCheck::DoesNotOpen);
        };
        let keys = at_rest::keys_cached(data_dir).map_err(|e| e.to_string())?;
        return Ok(opens(at_rest::open(&keys, kind, &raw).is_ok()));
    }
    let first = raw.iter().copied().find(|b| !b.is_ascii_whitespace());
    Ok(if matches!(first, Some(b'{' | b'[')) {
        CopyCheck::Plain
    } else {
        CopyCheck::Unknown
    })
}

// ── Status and notices ────────────────────────────────────────────────────

/// The profile's at-rest state as this process sees it (`raven status`,
/// `raven doctor`, `raven privacy status`; raven-node reports its own,
/// which knows about the key it is waiting for). No keystore call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivacyStatus {
    pub mode: Mode,
    /// Files this build migrates that are sealed, and that are plain.
    pub sealed_files: u16,
    pub plain_files: u16,
    /// This process holds the profile's at-rest key ([`at_rest::keys_cached`]).
    pub keys_loaded: bool,
    /// This process's last key load found the key gone
    /// ([`at_rest::key_lost`]; review A-keys-format-4).
    pub key_lost: bool,
    /// A downgrade leftover was sealed again and nobody was told yet.
    pub older_build_wrote_plain: bool,
    /// Contacts an older build pinned to another computer key than the
    /// sealed pin (which was kept), until `raven status` said so.
    pub older_build_pinned_differently: u64,
    /// Writes this process skipped in this profile rather than replace a
    /// file it could not read ([`at_rest::skipped_writes`]).
    pub skipped_writes: u64,
    /// Sealing waits for free disk space (about this many bytes).
    pub needs_disk_space: Option<u64>,
}

/// The SQLite stores as `raven privacy status` shows them (PP.12; PP.18 adds
/// the rest): a few small reads, no keystore call, no lock.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StoreStatus {
    /// Set-aside owed-ACK stores kept sealed for inspection.
    pub set_aside_stores: u16,
    /// A store's scrub (its `VACUUM`, its checkpoint) waits for the next
    /// prune pass.
    pub scrub_pending: bool,
}

/// [`StoreStatus`] of this profile now.
pub fn store_status(data_dir: &Path) -> StoreStatus {
    StoreStatus {
        set_aside_stores: crate::owed_acks::sealed_set_asides(data_dir),
        scrub_pending: crate::owed_acks::scrub_pending(data_dir)
            || crate::app_store::scrub_pending(data_dir)
            || crate::indexed_session_store::scrub_pending(data_dir)
            || crate::friend_custody::scrub_pending(data_dir)
            || crate::custody_handoff::scrub_pending(data_dir),
    }
}

impl PrivacyStatus {
    /// The state word ([`STATE_SEALED`], ...).
    pub fn state(&self) -> &'static str {
        match self.mode {
            Mode::UnsealedByUser => STATE_UNSEALED_BY_USER,
            Mode::Sealed if !self.keys_loaded && self.key_lost => STATE_KEY_LOST,
            Mode::Sealed if !self.keys_loaded => STATE_KEY_UNAVAILABLE,
            _ if self.needs_disk_space.is_some() => STATE_NEEDS_DISK_SPACE,
            Mode::Sealed => STATE_SEALED,
            Mode::Plain => STATE_PLAIN,
        }
    }

    /// `Status.at_rest` under `state` (raven-node passes its own word).
    pub fn to_ipc(&self, state: &str) -> AtRestStatus {
        let notes = [
            (self.older_build_wrote_plain, NOTE_OLDER_BUILD_WROTE_PLAIN),
            (
                self.older_build_pinned_differently > 0,
                NOTE_OLDER_BUILD_PINNED_DIFFERENTLY,
            ),
            (self.skipped_writes > 0, NOTE_UNREADABLE_FILE_KEPT),
        ];
        AtRestStatus {
            state: state.to_owned(),
            sealed_files: self.sealed_files,
            plain_files: self.plain_files,
            notes: notes
                .into_iter()
                .filter(|(due, _)| *due)
                .map(|(_, note)| note.to_owned())
                .collect(),
        }
    }
}

/// [`PrivacyStatus`] of this profile, from its files and this process's key
/// cache (no keystore call, no lock).
pub fn status(data_dir: &Path) -> PrivacyStatus {
    let forms = file_forms(data_dir).unwrap_or_default();
    let count = |sealed: bool| {
        u16::try_from(forms.iter().filter(|(_, s)| *s == sealed).count()).unwrap_or(u16::MAX)
    };
    let file = read_file(data_dir).ok().flatten().unwrap_or_default();
    let mode = mode(data_dir);
    PrivacyStatus {
        mode,
        sealed_files: count(true),
        plain_files: count(false).saturating_add(legacy_send_locks(data_dir, mode)),
        keys_loaded: at_rest::keys_cached(data_dir).is_ok(),
        key_lost: at_rest::key_lost(data_dir),
        older_build_wrote_plain: file.notices.older_build_wrote_plain,
        older_build_pinned_differently: file.notices.older_build_pinned_differently,
        skipped_writes: at_rest::skipped_writes(data_dir),
        needs_disk_space: file.space_deferred_at_ms.and(file.space_needed_bytes),
    }
}

/// An older build's per-friend send locks left in a sealed profile (each
/// name holds a friend's key; review B-sealed-stores-4): plain files until a
/// pass deletes them ([`crate::outbox::PeerSendLock::remove_legacy_files`]).
/// None in a profile that is not sealed, which names its locks that way.
fn legacy_send_locks(data_dir: &Path, mode: Mode) -> u16 {
    if mode != Mode::Sealed {
        return 0;
    }
    u16::try_from(crate::outbox::legacy_send_lock_files(data_dir).len()).unwrap_or(u16::MAX)
}

/// The one-time sealing notice is due: the profile is sealed and it was
/// never shown (the terminal app reads it without taking it; PP.21). No
/// write.
pub fn sealing_notice_due(data_dir: &Path) -> bool {
    mode(data_dir) == Mode::Sealed
        && read_file(data_dir).is_ok_and(|f| !f.is_some_and(|f| f.notices.sealing_shown))
}

/// The one-time sealing notice is due (the profile is sealed and it was
/// never shown): `true` once, and it is marked shown.
pub fn take_sealing_notice(data_dir: &Path) -> bool {
    if mode(data_dir) != Mode::Sealed
        || read_file(data_dir).map_or(true, |f| f.is_some_and(|f| f.notices.sealing_shown))
    {
        return false;
    }
    take_once(data_dir, |n| {
        let due = !n.sealing_shown;
        n.sealing_shown = true;
        due
    })
}

/// The "an older Raven is still running" line is due: at most once a day.
pub fn take_older_node_notice(data_dir: &Path, now_ms: u64) -> bool {
    let today = now_ms / DAY_MS;
    if read_file(data_dir).map_or(true, |f| {
        f.is_some_and(|f| f.notices.older_node_day == Some(today))
    }) {
        return false;
    }
    take_once(data_dir, |n| {
        let due = n.older_node_day != Some(today);
        n.older_node_day = Some(today);
        due
    })
}

/// A downgrade leftover was sealed again and nobody was told: `true` once
/// (`raven status` says so), and the note is cleared, with the count of
/// noise pins an older build set differently (that older build wrote a plain
/// pin file, so the same sentence covers it).
pub fn take_older_build_note(data_dir: &Path) -> bool {
    if !read_file(data_dir).is_ok_and(|f| {
        f.is_some_and(|f| {
            f.notices.older_build_wrote_plain || f.notices.older_build_pinned_differently > 0
        })
    }) {
        return false;
    }
    take_once(data_dir, |n| {
        n.older_build_pinned_differently = 0;
        std::mem::take(&mut n.older_build_wrote_plain)
    })
}

/// Run `take` on the notices under the lock; its answer, or `false` when the
/// file cannot be updated (a notice is never worth an error).
fn take_once(data_dir: &Path, take: impl FnOnce(&mut Notices) -> bool) -> bool {
    let mut due = false;
    update(data_dir, |file| due = take(&mut file.notices)).is_ok() && due
}

mod manage;
pub use manage::{
    forget_moved_aside, meta_rotation_unfinished, moved_aside_files,
    refuse_if_meta_rotation_unfinished, report, rotate_meta, seal_now, store_versions, unseal_all,
    unseal_unfinished, CommandError, MetaRotationReport, PrivacyReport, StoreVersion, UnsealReport,
    FORGET_ADDRESSES_AFTER_DAYS, FORGET_MOVED_ASIDE_QUESTION, META_ROTATION_UNFINISHED_TEXT,
    NOT_SEALED_TEXT, ROTATE_META_QUESTION, SEAL_NOT_ALLOWED_TEXT, UNSEALED_TEXT, UNSEAL_DONE,
    UNSEAL_QUESTION, UNSEAL_UNFINISHED_TEXT,
};

#[cfg(test)]
pub(crate) mod tests;

#[cfg(test)]
mod friend_files_tests;

#[cfg(test)]
mod address_files_tests;

#[cfg(test)]
mod forget_tests;

#[cfg(test)]
mod retention_tests;

#[cfg(test)]
mod rotation_tests;

#[cfg(test)]
mod store_tests;

#[cfg(test)]
mod windows_key_tests;

#[cfg(test)]
mod lock_tests;

#[cfg(test)]
mod manage_tests;

/// Tests elsewhere in the crate: start the retention clock at `starts_at_ms`
/// with `keep`, as a migration pass and `raven chats keep` would (no
/// identity needed).
#[cfg(test)]
pub(crate) fn start_retention_for_tests(data_dir: &Path, starts_at_ms: u64, keep: ChatKeep) {
    update(data_dir, |file| {
        file.retention_starts_at_ms = Some(starts_at_ms);
        file.chat_keep = Some(keep.as_str().to_owned());
        file.retention_next_at_ms = None;
    })
    .unwrap();
}
