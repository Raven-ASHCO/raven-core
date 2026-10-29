//! Sealed metadata at rest (privacy pack PP.3; docs/design/2026-10-at-rest-metadata.md).
//!
//! The core every later step of the pack builds on: the contact book (PP.4),
//! the friend-key files of PP.5 and the address and activity files of PP.6
//! read and write through it.
//!
//! - **Keys.** `meta_key.rmk` holds a random payload (`k_index`, one data key
//!   per epoch, the current epoch) wrapped by the profile's chat-history key
//!   K_hist through [`DomainProtector`] (domain `raven/meta-key/v1`): no new
//!   keychain item. [`keys_load`] is the only function here that calls the
//!   keystore; it runs at a process's start or a command's top level, never
//!   under a data-dir lock or inside a store transaction (debug builds assert
//!   it). Everything else uses [`keys_cached`], which never calls the
//!   keystore and re-reads the key file with the cached K_hist when another
//!   process rewrote it.
//! - **Formats.** RMS1 sealed files (`"RMS1" || 0x01 || kind || epoch ||
//!   nonce[24] || ct || tag[16]`, XChaCha20-Poly1305 under the epoch's
//!   `meta-file` key, AAD `"rvn1/meta-seal/v1" || kind || epoch`) and sealed
//!   row blobs (`0x01 || epoch || nonce[24] || ct || tag[16]`, AAD
//!   `"rvn1/meta-row/v1" || table || 0x00 || pk || epoch`); keyed lookups by
//!   value type ([`index`]) and per-friend lock names ([`lock_name`]).
//! - **Files.** [`load_json`] reads RMS1 or plain JSON; [`store_json`] writes
//!   RMS1 only when the profile is sealed ([`crate::privacy::mode`]) and
//!   today's exact bytes otherwise, under the file's writer lock named in
//!   [`FILES`] ([`write_held`] when the caller holds that lock already).
//!   [`migrate_file`] seals one file in place and verifies the sealed copy
//!   before the rename; [`unseal_file`] is the way back. A reader that treats
//!   an unreadable file as empty reads it with [`load_json_advisory`] and
//!   never writes over what it could not read.
//!
//! Never a plaintext fallback: an unreadable key is an error of the operation
//! that needed it, and an unreadable key file is never replaced.
//!
//! Lock order: `.at_rest.lock.sqlite` ([`AT_REST_LOCK`]), then a file's
//! writer lock, then the history / stage locks. The keystore is never called
//! under any of them.

pub mod registry;

#[cfg(test)]
pub(crate) mod tests;

pub use registry::{rule_for, FileRule, Rule, FILES};

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use chacha20poly1305::aead::{Aead, KeyInit, Payload as AeadPayload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::chat_history::{ChatHistoryError, DomainProtector, HistKey};
use crate::paths::DataDirLock;

/// The wrapped key file: `"RMK1" || 0x01 || DomainProtector(raven/meta-key/v1)`
/// of the payload. Created only in a profile that is being sealed and has an
/// identity on record.
pub const META_KEY_FILE: &str = "meta_key.rmk";
/// Serialises creators of [`META_KEY_FILE`] (and, PP.10, its rewrites).
const META_KEY_LOCK: &str = ".meta_key.lock.sqlite";
/// The profile-wide migration lock (`privacy::migrate_all`, PP.4). Taken
/// before any file's writer lock, never after one.
pub const AT_REST_LOCK: &str = ".at_rest.lock.sqlite";
/// How long a creator waits for another creator of the key file.
const META_KEY_LOCK_WAIT: Duration = Duration::from_secs(2);

const KEY_FILE_MAGIC: &[u8; 4] = b"RMK1";
const SEALED_MAGIC: &[u8; 4] = b"RMS1";
/// The format version byte of the key file, RMS1 files and row blobs.
const FORMAT_VERSION: u8 = 1;
/// The [`DomainProtector`] domain that wraps the payload.
const META_KEY_DOMAIN: &[u8] = b"raven/meta-key/v1";
/// HKDF-SHA256 salt of every key below the payload.
const KDF_SALT: &[u8] = b"rvn1/meta/v1";
const KDF_INFO_INDEX: &[u8] = b"index";
const KDF_INFO_LOCK: &[u8] = b"lock-name";
const SEAL_AAD: &[u8] = b"rvn1/meta-seal/v1";
const ROW_AAD: &[u8] = b"rvn1/meta-row/v1";
const INDEX_DOMAIN: &[u8] = b"rvn1/meta-index/v1";
const LOCK_NAME_DOMAIN: &[u8] = b"rvn1/lock-name/v1";

/// `"RMS1" || version || kind || epoch`.
const SEALED_HEADER_LEN: usize = 4 + 1 + 1 + 4;
/// `version || epoch`.
const ROW_HEADER_LEN: usize = 1 + 4;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
/// The bytes RMS1 adds around a plaintext (header, nonce, tag): a reader
/// that caps a file's size adds this to its plaintext limit.
pub const SEALED_OVERHEAD: u64 = (SEALED_HEADER_LEN + NONCE_LEN + TAG_LEN) as u64;
/// A raw secret's plain file ([`Kind::is_raw_secret`]) is exactly this long.
const RAW_SECRET_LEN: usize = 32;
/// The `kind` of a [`AtRestError::Tampered`] that is not a sealed file: the
/// key file itself, or a row blob.
pub const NOT_A_FILE_KIND: u8 = 0;

/// The key file is a few hundred bytes; anything this large is not one.
const MAX_KEY_FILE_BYTES: u64 = 64 * 1024;
/// Far above any registered file; a bigger one is refused, never read whole.
pub(crate) const MAX_SEALED_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// What a sealed file is: the kind byte of RMS1, also bound into its AAD, so
/// a sealed file swapped in under another name fails to open
/// ([`AtRestError::WrongKind`]). Numbers are fixed forever.
#[repr(u8)]
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Kind {
    Contacts = 1,
    LanSeen = 2,
    LearnedRoutes = 3,
    OutboxRoutes = 4,
    PeerDeviceCerts = 5,
    PrekeyStore = 6,
    BlockedPubs = 7,
    DeviceRegistry = 8,
    ChatInboxCursors = 9,
    TuiPrivate = 10,
    /// `capability_floor.json`: each contact's capability high-water mark
    /// (Phase 6b P6.29, [`crate::capability_floor`]).
    CapabilityFloor = 11,
    /// `pair_seeds.json`: each contact's rotating pair seeds (Phase 6b
    /// P6.38, [`crate::pair_seed`]).
    PairSeeds = 12,
    RouteMemory = 13,
    Revocations = 14,
    DeviceSyncSeen = 15,
    NoisePins = 16,
    RouteHintsState = 17,
    PeerCacheStage = 18,
    NodePolicyPeers = 19,
    Bootstrap = 20,
    RelayAllow = 21,
    /// `learning.bin`: the learning model (Phase 6a P6.9,
    /// [`crate::learning::store`]), sealed from its first write.
    LearningStore = 22,
    /// `updates/state`: the release key set, the newest advisory, the
    /// transparency log and the freeze evidence (Phase 6b P6.44,
    /// [`crate::update_state`]).
    UpdateState = 23,
    DeviceXSecret = 24,
    DeviceRevocationsRvdr1 = 25,
    AliasClaims = 26,
    NearbyRegistry = 27,
    ContactInbox = 28,
    // 29-31: the PP.1 inventory's finds (Phase 2 relays).
    RelayMemory = 29,
    FriendRelayStatus = 30,
    FriendRelayKey = 31,
    /// `lan_meeting.json`: when the LAN turns off after `raven lan on --for`
    /// (Phase 3 P3.C2, cutoff M1): the end of a meeting.
    LanMeeting = 32,
    /// `custody_home.json`: the home custodians picked and the dropped ones
    /// still drained (Phase 3 P3.18, [`crate::custody_home`]).
    CustodyHome = 33,
    // 34..=63 reserved: Phase 3 and Phase 5.
    /// An `owed_acks.sqlite.corrupt-<ms>` set-aside that did not open as the
    /// profile's schema 2, kept sealed for inspection (PP.12, review R06).
    OwedAcksAside = 64,
    /// A responder's cached PairResponse, `lan_pair_response/<name>` (review
    /// B-sealed-stores-1 and -5): it holds the PairInit's `init_id`, which
    /// with the session store's clear record key names the friend, and the
    /// session's exact times.
    PairResponse = 65,
    /// `peer_schedules.json`: contacts' PeerId rotation schedules (Phase 4
    /// P4.25, [`crate::peer_rotation`]). Phase 4 numbers count up from 66, so
    /// they never meet Phase 3's, which count up from 33 in the parallel lane.
    PeerSchedules = 66,
    /// `peer_rotation_state.json`: since when this profile announces its own
    /// coming PeerIds (Phase 4 P4.28, [`crate::peer_rotation`]).
    PeerRotationState = 67,
    /// `prekey_published_local.json`: this device's own signed prekey
    /// bundles as published, so an async letter sealed to a generation
    /// retired since still finds its bundle (Phase 5 P5.11,
    /// [`crate::lan_dispatch::local_published_bundle_by_hash`]). Phase 5's
    /// letters and handoff count up from 68.
    PrekeyPublishedLocal = 68,
    /// `letter_deposits.json`: the RAL1 letters this node left with friends,
    /// with the custodians that hold each one (Phase 5 P5.15,
    /// [`crate::letter_deposits`]).
    LetterDeposits = 69,
    /// `knock_replays.bin`: the RLK1 link knock's matched nonces, kept
    /// across restarts for 3 days (Phase 6 review traffic-9,
    /// [`crate::link_knock::KNOCK_REPLAYS_FILE`]); lane 6b's first of
    /// 112-119.
    KnockReplays = 112,
    /// `updates/downloads`: the releases pinned contacts offered this
    /// computer, the person's download approvals and how far each download
    /// got (Phase 6b P6.49, [`crate::update_downloads`]). Kinds of this
    /// lane count up from 120 (lane 6b uses 112-119; the desktop 128).
    UpdateDownloads = 120,
    /// `desktop_private.rms`: the desktop apps' copy of the user's own name
    /// (node/crates/raven-client), as `tui_private.rms` is the terminal
    /// app's. The desktop apps' numbers count up from 128, a lane of their
    /// own, so they never meet the phases' lanes.
    DesktopPrivate = 128,
    /// `groups.json`: every group's roster, messages, held frames and
    /// intents ([`crate::group::store`]). Groups count up from 144, a lane of
    /// their own.
    Groups = 144,
}

impl Kind {
    /// Every kind, in code order.
    pub const ALL: [Kind; 43] = [
        Kind::Contacts,
        Kind::LanSeen,
        Kind::LearnedRoutes,
        Kind::OutboxRoutes,
        Kind::PeerDeviceCerts,
        Kind::PrekeyStore,
        Kind::BlockedPubs,
        Kind::DeviceRegistry,
        Kind::ChatInboxCursors,
        Kind::TuiPrivate,
        Kind::CapabilityFloor,
        Kind::PairSeeds,
        Kind::RouteMemory,
        Kind::Revocations,
        Kind::DeviceSyncSeen,
        Kind::NoisePins,
        Kind::RouteHintsState,
        Kind::PeerCacheStage,
        Kind::NodePolicyPeers,
        Kind::Bootstrap,
        Kind::RelayAllow,
        Kind::LearningStore,
        Kind::UpdateState,
        Kind::DeviceXSecret,
        Kind::DeviceRevocationsRvdr1,
        Kind::AliasClaims,
        Kind::NearbyRegistry,
        Kind::ContactInbox,
        Kind::RelayMemory,
        Kind::FriendRelayStatus,
        Kind::FriendRelayKey,
        Kind::LanMeeting,
        Kind::CustodyHome,
        Kind::OwedAcksAside,
        Kind::PairResponse,
        Kind::PeerSchedules,
        Kind::PeerRotationState,
        Kind::PrekeyPublishedLocal,
        Kind::LetterDeposits,
        Kind::KnockReplays,
        Kind::UpdateDownloads,
        Kind::DesktopPrivate,
        Kind::Groups,
    ];

    /// The kind byte of RMS1.
    pub fn code(self) -> u8 {
        self as u8
    }

    pub fn from_code(code: u8) -> Option<Kind> {
        Self::ALL.into_iter().find(|kind| kind.code() == code)
    }

    /// A stable name: a file that had no writer lock before the pack gets
    /// `.at_rest.<name>.lock.sqlite`.
    pub fn name(self) -> &'static str {
        match self {
            Kind::Contacts => "contacts",
            Kind::LanSeen => "lan_seen",
            Kind::LearnedRoutes => "learned_routes",
            Kind::OutboxRoutes => "outbox_routes",
            Kind::PeerDeviceCerts => "peer_device_certs",
            Kind::PrekeyStore => "prekey_store",
            Kind::BlockedPubs => "blocked_pubs",
            Kind::DeviceRegistry => "device_registry",
            Kind::ChatInboxCursors => "chat_inbox_cursors",
            Kind::TuiPrivate => "tui_private",
            Kind::CapabilityFloor => "capability_floor",
            Kind::PairSeeds => "pair_seeds",
            Kind::RouteMemory => "route_memory",
            Kind::Revocations => "revocations",
            Kind::DeviceSyncSeen => "device_sync_seen",
            Kind::NoisePins => "noise_pins",
            Kind::RouteHintsState => "route_hints_state",
            Kind::PeerCacheStage => "peer_cache_stage",
            Kind::NodePolicyPeers => "node_policy_peers",
            Kind::Bootstrap => "bootstrap",
            Kind::RelayAllow => "relay_allow",
            Kind::LearningStore => "learning_store",
            Kind::UpdateState => "update_state",
            Kind::DeviceXSecret => "device_x_secret",
            Kind::DeviceRevocationsRvdr1 => "device_revocations_rvdr1",
            Kind::AliasClaims => "alias_claims",
            Kind::NearbyRegistry => "nearby_registry",
            Kind::ContactInbox => "contact_inbox",
            Kind::RelayMemory => "relay_memory",
            Kind::FriendRelayStatus => "friend_relay_status",
            Kind::FriendRelayKey => "friend_relay_key",
            Kind::LanMeeting => "lan_meeting",
            Kind::CustodyHome => "custody_home",
            Kind::OwedAcksAside => "owed_acks_aside",
            Kind::PairResponse => "pair_response",
            Kind::PeerSchedules => "peer_schedules",
            Kind::PeerRotationState => "peer_rotation_state",
            Kind::PrekeyPublishedLocal => "prekey_published_local",
            Kind::LetterDeposits => "letter_deposits",
            Kind::KnockReplays => "knock_replays",
            Kind::UpdateDownloads => "update_downloads",
            Kind::DesktopPrivate => "desktop_private",
            Kind::Groups => "groups",
        }
    }

    /// A raw 32-byte secret, not JSON: its plain file is exactly 32 bytes,
    /// and a file of that length is plain whatever its first bytes (one
    /// plain secret in 2^32 starts with "RMS1"; a sealed one is longer).
    pub fn is_raw_secret(self) -> bool {
        matches!(self, Kind::DeviceXSecret | Kind::FriendRelayKey)
    }
}

/// The type of a value behind a keyed lookup column ([`index`]): equal values
/// give equal digests in every table, so keys, constraints and joins keep
/// their shape. Labels are fixed forever.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValueType {
    DeviceKey,
    Rvn1Address,
    MessageId,
    ObjectDigest,
    Nonce,
    /// Stored wire bytes compared for equality (`kh_envelope`, `kh_ack`).
    ObjectBytes,
}

impl ValueType {
    pub fn label(self) -> &'static str {
        match self {
            ValueType::DeviceKey => "device-key",
            ValueType::Rvn1Address => "rvn1-address",
            ValueType::MessageId => "message-id",
            ValueType::ObjectDigest => "object-digest",
            ValueType::Nonce => "nonce",
            ValueType::ObjectBytes => "object-bytes",
        }
    }
}

/// What an epoch's data key is for (its HKDF info; fixed forever).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataUse {
    /// RMS1 sealed files.
    MetaFile,
    /// SQLite meta blobs and sealed wire blobs (PP.12-PP.14, PP.17).
    MetaRow,
    /// `chat_history.json`, magic RVNHIST2 (PP.10).
    History,
    /// `outbound_body_stage.bin`, magic RVNOSTG2 (PP.10).
    Stage,
    /// `app_channel.sqlite3` sealed rows, tag 0x02 (PP.10).
    AppRow,
}

impl DataUse {
    const ALL: [DataUse; 5] = [
        DataUse::MetaFile,
        DataUse::MetaRow,
        DataUse::History,
        DataUse::Stage,
        DataUse::AppRow,
    ];

    fn info(self) -> &'static [u8] {
        match self {
            DataUse::MetaFile => b"meta-file",
            DataUse::MetaRow => b"meta-row",
            DataUse::History => b"history",
            DataUse::Stage => b"stage",
            DataUse::AppRow => b"app-row",
        }
    }
}

/// The profile's at-rest mode, recorded in `privacy.json`
/// ([`crate::privacy::mode`]). Writers follow it; readers accept both forms
/// in every mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Today's bytes (no profile has been sealed, or a debug build without
    /// `RAVEN_LAB_AT_REST=1`).
    Plain,
    /// Writers seal; only `privacy::migrate_all` moves a profile here.
    Sealed,
    /// `raven privacy unseal` (PP.18): today's bytes, and nothing seals again
    /// until `raven privacy seal-now`.
    UnsealedByUser,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Plain => "plain",
            Mode::Sealed => "sealed",
            Mode::UnsealedByUser => "unsealed_by_user",
        }
    }

    pub fn parse(text: &str) -> Option<Mode> {
        [Mode::Plain, Mode::Sealed, Mode::UnsealedByUser]
            .into_iter()
            .find(|mode| mode.as_str() == text)
    }
}

/// Whether a caller may seal a profile (and so create its key file).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigratePolicy {
    /// This build's own rule ([`crate::lan_gate::at_rest_seal_allowed`]): a
    /// release build seals; a debug build only with `RAVEN_LAB_AT_REST=1`.
    Auto,
    /// Unit tests: seal whatever the build (no environment variable, so no
    /// race between parallel tests).
    #[cfg(any(test, feature = "test-helpers"))]
    Allow,
    /// Read-only tools: never seal and never create a key.
    Never,
}

impl MigratePolicy {
    pub fn allows_sealing(self) -> bool {
        match self {
            MigratePolicy::Auto => crate::lan_gate::at_rest_seal_allowed(),
            #[cfg(any(test, feature = "test-helpers"))]
            MigratePolicy::Allow => true,
            MigratePolicy::Never => false,
        }
    }
}

/// What [`migrate_file`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Migrated {
    /// The plain file was sealed in place.
    Sealed,
    /// It was sealed already: nothing written.
    AlreadySealed,
    /// There is no such file: nothing written.
    Missing,
}

#[derive(Debug, thiserror::Error)]
pub enum AtRestError {
    /// The keystore (keychain, Secret Service, vault passphrase) did not give
    /// the chat-history key, or this process has not loaded the at-rest key.
    #[error("the at-rest key is unavailable: {0}")]
    KeyUnavailable(String),
    /// `meta_key.rmk` is there, but the chat-history key that wraps it is
    /// not: the keystore has no such item (a new login keychain, a profile
    /// copied to another computer or account), or the key no longer opens
    /// (on Windows `chat_history_key.dpapi` is gone, or no longer unwraps
    /// for this account). Readers fail closed as for
    /// [`AtRestError::KeyUnavailable`] (the key may be put back), but no
    /// dialog is waiting: the user is told the key is gone (review
    /// A-keys-format-4).
    #[error("the at-rest key is gone: {0}")]
    KeyLost(String),
    /// A key file is created only in a profile with an identity on record.
    #[error("this profile has no identity yet")]
    NoIdentity,
    /// Authentication failed: a wrong key or a changed byte. `kind` is
    /// [`NOT_A_FILE_KIND`] for the key file itself and for row blobs.
    #[error("sealed data failed authentication (kind {kind})")]
    Tampered { kind: u8 },
    #[error("a sealed file of kind {got} where kind {want} belongs")]
    WrongKind { want: u8, got: u8 },
    #[error("sealed data is truncated")]
    Truncated,
    #[error("sealed data has a newer format (version {0}); a newer Raven wrote it")]
    NewerFormat(u8),
    /// Sealed under an epoch this process has not loaded. The caller's top
    /// level loads the keys again ([`keys_load`]) and retries once; still
    /// unknown is tampering.
    #[error("sealed data names key epoch {epoch}, which this process has not loaded")]
    StaleKeys { epoch: u32 },
    /// The profile is not being sealed: no key is created, and nothing is
    /// sealed in place.
    #[error("this profile is not in sealed mode")]
    NotSealedMode,
    #[error("{0}")]
    Io(String),
    #[error("{0}")]
    Json(String),
}

impl AtRestError {
    /// The read may work later with nothing changed on disk: the key is not
    /// loaded (yet) or is gone from the keystore (it may be put back), the
    /// file names an epoch this process has not loaded, or reading failed.
    /// Everything else says the bytes are not what this build can open;
    /// readers that kept today's texts say `... read: ...` for the first and
    /// `... corrupt: ...` for the rest.
    pub fn is_unavailable(&self) -> bool {
        matches!(
            self,
            AtRestError::KeyUnavailable(_)
                | AtRestError::KeyLost(_)
                | AtRestError::StaleKeys { .. }
                | AtRestError::Io(_)
        )
    }
}

/// The loaded at-rest keys of one profile. The payload is wiped on drop; the
/// lookup and lock-name keys come from the stable `k_index`, the data keys
/// from each epoch's key.
pub struct MetaKeys {
    payload: KeyPayload,
    index: Zeroizing<[u8; 32]>,
    lock: Zeroizing<[u8; 32]>,
    /// Every loaded epoch's data keys, derived once at load (PP.12: a store
    /// seals and opens a row blob per row, and an HKDF per blob cost more
    /// than the cipher).
    data: Vec<(u32, DataUse, Zeroizing<[u8; 32]>)>,
}

impl MetaKeys {
    fn from_payload(payload: KeyPayload) -> MetaKeys {
        let index = hkdf32(&payload.k_index, KDF_INFO_INDEX);
        let lock = hkdf32(&payload.k_index, KDF_INFO_LOCK);
        let data = payload
            .epochs
            .iter()
            .flat_map(|(epoch, key)| {
                DataUse::ALL
                    .into_iter()
                    .map(move |use_| (*epoch, use_, hkdf32(key, use_.info())))
            })
            .collect();
        MetaKeys {
            payload,
            index,
            lock,
            data,
        }
    }

    /// The epoch new data is sealed under.
    pub fn current_epoch(&self) -> u32 {
        self.payload.current
    }

    /// Every epoch this process can open, ascending.
    pub fn epochs(&self) -> Vec<u32> {
        self.payload
            .epochs
            .iter()
            .map(|(epoch, _)| *epoch)
            .collect()
    }

    /// The data key of `epoch` for `use_`, if that epoch is loaded.
    pub(crate) fn data_key(&self, epoch: u32, use_: DataUse) -> Option<Zeroizing<[u8; 32]>> {
        self.data
            .iter()
            .find(|(e, u, _)| *e == epoch && *u == use_)
            .map(|(_, _, key)| key.clone())
    }
}

impl std::fmt::Debug for MetaKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MetaKeys")
            .field("epochs", &self.epochs())
            .field("current", &self.payload.current)
            .finish_non_exhaustive()
    }
}

/// The wrapped payload: canonical JSON
/// `{"v":1,"k_index":"<hex>","epochs":[{"e":1,"k":"<hex>"}],"current":1}`.
struct KeyPayload {
    k_index: Zeroizing<[u8; 32]>,
    /// Ascending, unique; `current` is one of them.
    epochs: Vec<(u32, Zeroizing<[u8; 32]>)>,
    current: u32,
}

const PAYLOAD_VERSION: u32 = 1;

#[derive(Deserialize)]
struct PayloadVersion {
    v: u32,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct RawPayload {
    v: u32,
    k_index: String,
    epochs: Vec<RawEpoch>,
    current: u32,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct RawEpoch {
    e: u32,
    k: String,
}

impl KeyPayload {
    /// A new profile key: random `k_index` and epoch 1.
    fn mint() -> KeyPayload {
        KeyPayload {
            k_index: random_key(),
            epochs: vec![(1, random_key())],
            current: 1,
        }
    }

    fn to_json(&self) -> Zeroizing<Vec<u8>> {
        // Reserved up front: a reallocation would leave key bytes behind in
        // freed memory.
        let mut out = Zeroizing::new(Vec::with_capacity(128 + 96 * self.epochs.len()));
        out.extend_from_slice(br#"{"v":1,"k_index":""#);
        push_hex(&mut out, &self.k_index[..]);
        out.extend_from_slice(br#"","epochs":["#);
        for (n, (epoch, key)) in self.epochs.iter().enumerate() {
            if n > 0 {
                out.push(b',');
            }
            out.extend_from_slice(format!(r#"{{"e":{epoch},"k":""#).as_bytes());
            push_hex(&mut out, &key[..]);
            out.extend_from_slice(br#""}"#);
        }
        out.extend_from_slice(format!(r#"],"current":{}}}"#, self.current).as_bytes());
        out
    }

    fn parse(json: &[u8]) -> Result<KeyPayload, AtRestError> {
        let tampered = AtRestError::Tampered {
            kind: NOT_A_FILE_KIND,
        };
        let version: PayloadVersion = serde_json::from_slice(json).map_err(|_| tampered)?;
        if version.v > PAYLOAD_VERSION {
            return Err(AtRestError::NewerFormat(
                u8::try_from(version.v).unwrap_or(u8::MAX),
            ));
        }
        let tampered = || AtRestError::Tampered {
            kind: NOT_A_FILE_KIND,
        };
        let raw: RawPayload = serde_json::from_slice(json).map_err(|_| tampered())?;
        if raw.v != PAYLOAD_VERSION {
            return Err(tampered());
        }
        let k_index = key_from_hex(&raw.k_index).ok_or_else(tampered)?;
        let mut epochs = Vec::with_capacity(raw.epochs.len());
        for epoch in &raw.epochs {
            if epochs.last().is_some_and(|(last, _)| *last >= epoch.e) {
                return Err(tampered());
            }
            epochs.push((epoch.e, key_from_hex(&epoch.k).ok_or_else(tampered)?));
        }
        if !epochs.iter().any(|(epoch, _)| *epoch == raw.current) {
            return Err(tampered());
        }
        Ok(KeyPayload {
            k_index,
            epochs,
            current: raw.current,
        })
    }
}

fn random_key() -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut key[..]);
    key
}

fn push_hex(out: &mut Vec<u8>, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        out.push(HEX[usize::from(byte >> 4)]);
        out.push(HEX[usize::from(byte & 0x0f)]);
    }
}

/// Exactly 64 lowercase hex digits (the canonical form [`push_hex`] writes).
fn key_from_hex(text: &str) -> Option<Zeroizing<[u8; 32]>> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut key = Zeroizing::new([0u8; 32]);
    hex::decode_to_slice(text, &mut key[..]).ok()?;
    Some(key)
}

fn hkdf32(ikm: &[u8; 32], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(KDF_SALT), ikm);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(info, okm.as_mut_slice())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    okm
}

/// (len, mtime in ns, file id) of a file: changes whenever another process
/// replaces it (every write here renames a freshly written temp file over
/// the old one, so at least its write time moves on).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FileStamp {
    len: u64,
    modified_ns: i128,
    id: (u64, u64),
}

impl FileStamp {
    pub(crate) fn of(meta: &std::fs::Metadata) -> FileStamp {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            FileStamp {
                len: meta.len(),
                modified_ns: i128::from(meta.mtime()) * 1_000_000_000
                    + i128::from(meta.mtime_nsec()),
                id: (meta.dev(), meta.ino()),
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            // The stable std API has no file index: the creation time stands
            // in (name tunnelling may hand a renamed-in file the old one's,
            // so the write time carries the change).
            FileStamp {
                len: meta.file_size(),
                modified_ns: i128::from(meta.last_write_time()) * 100,
                id: (meta.creation_time(), 0),
            }
        }
        #[cfg(not(any(unix, windows)))]
        {
            let modified_ns = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |d| i128::try_from(d.as_nanos()).unwrap_or(i128::MAX));
            FileStamp {
                len: meta.len(),
                modified_ns,
                id: (0, 0),
            }
        }
    }
}

/// A file's bytes and the stamp they were read under.
type StampedBytes = (Zeroizing<Vec<u8>>, FileStamp);

/// A file's bytes (capped at `max`) and the stamp they belong to: stat, read,
/// stat, retried while a rename lands in between. `None` when it is missing.
fn read_stable(path: &Path, max: u64) -> Result<Option<StampedBytes>, AtRestError> {
    for _ in 0..8 {
        let Some(before) = stat(path)? else {
            return Ok(None);
        };
        let Some(bytes) = read_capped(path, max)? else {
            return Ok(None);
        };
        if stat(path)? == Some(before) {
            return Ok(Some((bytes, before)));
        }
    }
    Err(AtRestError::Io(format!(
        "{}: kept changing while it was read",
        file_label(path)
    )))
}

fn stat(path: &Path) -> Result<Option<FileStamp>, AtRestError> {
    match std::fs::metadata(path) {
        Ok(meta) => Ok(Some(FileStamp::of(&meta))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(AtRestError::Io(format!("{}: {e}", file_label(path)))),
    }
}

fn read_capped(path: &Path, max: u64) -> Result<Option<Zeroizing<Vec<u8>>>, AtRestError> {
    use std::io::Read;
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(AtRestError::Io(format!("{}: {e}", file_label(path)))),
    };
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| AtRestError::Io(format!("{}: {e}", file_label(path))))?;
    if bytes.len() as u64 > max {
        return Err(AtRestError::Io(format!(
            "{} exceeds the local size limit",
            file_label(path)
        )));
    }
    Ok(Some(bytes))
}

/// A file's first `n` bytes (fewer when it is shorter); `None` when it is
/// missing.
fn read_head(path: &Path, n: usize) -> Result<Option<Vec<u8>>, AtRestError> {
    use std::io::Read;
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(AtRestError::Io(format!("{}: {e}", file_label(path)))),
    };
    let mut head = Vec::with_capacity(n);
    file.take(n as u64)
        .read_to_end(&mut head)
        .map_err(|e| AtRestError::Io(format!("{}: {e}", file_label(path))))?;
    Ok(Some(head))
}

/// The file name for messages (never the full path).
fn file_label(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

// ── Keys: load once (the keystore), then use the cache ────────────────────

/// Where K_hist comes from: the platform keystore, or a counting fake in
/// unit tests.
pub(crate) trait HistKeySource: Sync {
    /// May call the keystore. With `create`, a profile without K_hist gets
    /// one, exactly as the chat-history path mints it.
    fn load(&self, data_dir: &Path, create: bool) -> Result<HistKey, AtRestError>;
}

struct PlatformHistKey;

impl HistKeySource for PlatformHistKey {
    /// Without `create` (a key file is there to unwrap) a K_hist that is
    /// missing or corrupt is [`AtRestError::KeyLost`].
    fn load(&self, data_dir: &Path, create: bool) -> Result<HistKey, AtRestError> {
        DomainProtector::new(META_KEY_DOMAIN)
            .load_hist_key(data_dir, create)
            .map_err(|e| hist_key_error(e, !create))
    }
}

/// K_hist's error as the key file's: with `for_key_file` (the key file is
/// there) a missing or corrupt K_hist is [`AtRestError::KeyLost`]; anything
/// else (the keystore did not answer, the user denied it, a read failed) is
/// [`AtRestError::KeyUnavailable`] (review A-keys-format-4).
fn hist_key_error(error: ChatHistoryError, for_key_file: bool) -> AtRestError {
    match error {
        ChatHistoryError::MissingProtectedKey | ChatHistoryError::CorruptProtectedKey
            if for_key_file =>
        {
            AtRestError::KeyLost(error.to_string())
        }
        other => AtRestError::KeyUnavailable(other.to_string()),
    }
}

struct CacheEntry {
    /// The data dir as the loader named it ([`forget_cached_keys`] matches it
    /// too, should the directory be gone by then).
    given: PathBuf,
    hist: HistKey,
    keys: Arc<MetaKeys>,
    stamp: FileStamp,
}

/// Per canonical data dir: K_hist, the unwrapped keys and the key file's
/// stamp. Caching K_hist adds no exposure: a process that holds the data keys
/// can open everything K_hist protects.
static KEY_CACHE: Mutex<BTreeMap<PathBuf, CacheEntry>> = Mutex::new(BTreeMap::new());
/// One key load per profile at a time in this process: a second caller waits
/// for the first and then finds the keys cached (at most one keystore call
/// outstanding, so at most one dialog).
static LOAD_GATES: Mutex<BTreeMap<PathBuf, Arc<Mutex<()>>>> = Mutex::new(BTreeMap::new());
/// Per canonical data dir: this process's last key load found the key file
/// without the chat-history key that opens it ([`AtRestError::KeyLost`]).
/// Status and the commands' texts say the key is gone instead of "answer
/// the keychain dialog" (review A-keys-format-4); a load that works, or
/// fails otherwise, clears it.
static LOST: Mutex<BTreeSet<PathBuf>> = Mutex::new(BTreeSet::new());

fn lock_lost() -> MutexGuard<'static, BTreeSet<PathBuf>> {
    LOST.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Record whether `result`, a key load of the profile at `canonical`, found
/// its key gone.
fn note_lost<T>(canonical: &Path, result: &Result<T, AtRestError>) {
    if matches!(result, Err(AtRestError::KeyLost(_))) {
        lock_lost().insert(canonical.to_path_buf());
    } else {
        lock_lost().remove(canonical);
    }
}

/// Whether this process's last key load of `data_dir` found the key file
/// without its chat-history key ([`AtRestError::KeyLost`]). No keystore
/// call.
pub fn key_lost(data_dir: &Path) -> bool {
    lock_lost().contains(&canonical_dir(data_dir))
}

fn lock_cache() -> MutexGuard<'static, BTreeMap<PathBuf, CacheEntry>> {
    KEY_CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn canonical_dir(data_dir: &Path) -> PathBuf {
    std::fs::canonicalize(data_dir).unwrap_or_else(|_| data_dir.to_path_buf())
}

/// Load this profile's at-rest keys: the only function here that calls the
/// keystore (it reads K_hist, which may show the one-time macOS keychain
/// dialog). Call it at process start or at a command's top level, never under
/// a data-dir lock or inside a store's SQLite transaction (debug builds
/// assert both). Cached afterwards: later calls in this process call no
/// keystore.
///
/// An existing `meta_key.rmk` is unwrapped (never replaced, whatever its
/// state). A missing one is created only when [`MigratePolicy::Auto`] allows
/// sealing, the profile is not `unsealed_by_user` ([`AtRestError::NotSealedMode`]
/// otherwise) and it has an identity on record ([`AtRestError::NoIdentity`]).
pub fn keys_load(data_dir: &Path) -> Result<Arc<MetaKeys>, AtRestError> {
    keys_load_with(data_dir, MigratePolicy::Auto)
}

/// [`keys_load`] under an explicit policy: [`MigratePolicy::Never`] for a
/// read-only tool (it unwraps an existing key and never creates one).
pub fn keys_load_with(
    data_dir: &Path,
    policy: MigratePolicy,
) -> Result<Arc<MetaKeys>, AtRestError> {
    keys_load_from(data_dir, policy, &PlatformHistKey, key_fault_requested())
}

/// `RAVEN_LAB_AT_REST_KEY_FAULT=unavailable` (debug builds only; a release
/// build never reads it): every key load fails as an unreadable keystore
/// would.
fn key_fault_requested() -> bool {
    key_fault_value(crate::p2p_gate::lab_switch(crate::lan_gate::LAB_AT_REST_KEY_FAULT).as_deref())
}

fn key_fault_value(value: Option<&str>) -> bool {
    value == Some("unavailable")
}

pub(crate) fn keys_load_from(
    data_dir: &Path,
    policy: MigratePolicy,
    source: &dyn HistKeySource,
    fault: bool,
) -> Result<Arc<MetaKeys>, AtRestError> {
    debug_assert!(
        !crate::paths::thread_holds_raven_lock(),
        "at_rest::keys_load runs at a process's or a command's top level, never under a \
         data-dir lock or inside a store transaction: it may wait on a keystore dialog"
    );
    if fault {
        return Err(AtRestError::KeyUnavailable(
            "the keystore is unavailable (RAVEN_LAB_AT_REST_KEY_FAULT)".into(),
        ));
    }
    // Lock v2 (P6.40): raven-node dropped this profile's keys, and none
    // comes back before `Unlock`.
    crate::local_lock::refuse(data_dir).map_err(|why| AtRestError::KeyUnavailable(why.into()))?;
    let canonical = canonical_dir(data_dir);
    let gate = {
        let mut gates = LOAD_GATES
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Arc::clone(gates.entry(canonical.clone()).or_default())
    };
    let _one_load = gate.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    {
        let mut cache = lock_cache();
        if let Some(entry) = cache.get_mut(&canonical) {
            if stat(&data_dir.join(META_KEY_FILE))?.is_some() {
                let refreshed = refresh(entry, data_dir);
                note_lost(&canonical, &refreshed);
                refreshed?;
                return Ok(Arc::clone(&entry.keys));
            }
            // The key file is gone (the profile was unsealed or erased): its
            // keys go with it, and a new one follows only the rules below.
            cache.remove(&canonical);
        }
    }
    let loaded = load_or_create(data_dir, policy, source);
    note_lost(&canonical, &loaded);
    let loaded = loaded?;
    // A lock that came while the key loaded keeps it out of the cache.
    crate::local_lock::refuse(data_dir).map_err(|why| AtRestError::KeyUnavailable(why.into()))?;
    let keys = Arc::clone(&loaded.keys);
    lock_cache().insert(
        canonical,
        CacheEntry {
            given: data_dir.to_path_buf(),
            hist: loaded.hist,
            keys: loaded.keys,
            stamp: loaded.stamp,
        },
    );
    Ok(keys)
}

/// The keys [`keys_load`] loaded, without any keystore call. When another
/// process rewrote `meta_key.rmk` (a rotation, PP.10) it is unwrapped again
/// with the cached K_hist; one stat per call otherwise. Nothing loaded in
/// this process (or the key file is gone): [`AtRestError::KeyUnavailable`].
pub fn keys_cached(data_dir: &Path) -> Result<Arc<MetaKeys>, AtRestError> {
    let canonical = canonical_dir(data_dir);
    let mut cache = lock_cache();
    let entry = cache.get_mut(&canonical).ok_or_else(|| {
        AtRestError::KeyUnavailable("the at-rest key is not loaded in this process".into())
    })?;
    refresh(entry, data_dir)?;
    Ok(Arc::clone(&entry.keys))
}

/// Drop this profile's cached K_hist and keys (Phase 6 Lock v2); both are
/// wiped as they drop. A holder of an `Arc<MetaKeys>` keeps its copy until it
/// drops it. What the last load found ([`key_lost`]) goes too.
pub fn forget_cached_keys(data_dir: &Path) {
    let canonical = canonical_dir(data_dir);
    let removed: Vec<CacheEntry> = {
        let mut cache = lock_cache();
        let names: Vec<PathBuf> = cache
            .iter()
            .filter(|(name, entry)| **name == canonical || entry.given == data_dir)
            .map(|(name, _)| name.clone())
            .collect();
        names.iter().filter_map(|name| cache.remove(name)).collect()
    };
    drop(removed);
    lock_lost().remove(&canonical);
}

fn refresh(entry: &mut CacheEntry, data_dir: &Path) -> Result<(), AtRestError> {
    let path = data_dir.join(META_KEY_FILE);
    let missing = || AtRestError::KeyUnavailable(format!("{META_KEY_FILE} is missing"));
    if stat(&path)?.ok_or_else(missing)? == entry.stamp {
        return Ok(());
    }
    let (bytes, stamp) = read_stable(&path, MAX_KEY_FILE_BYTES)?.ok_or_else(missing)?;
    entry.keys = Arc::new(unwrap_key_file(&entry.hist, data_dir, &bytes)?);
    entry.stamp = stamp;
    Ok(())
}

struct Loaded {
    hist: HistKey,
    keys: Arc<MetaKeys>,
    stamp: FileStamp,
}

fn load_or_create(
    data_dir: &Path,
    policy: MigratePolicy,
    source: &dyn HistKeySource,
) -> Result<Loaded, AtRestError> {
    let path = data_dir.join(META_KEY_FILE);
    if let Some((bytes, stamp)) = read_stable(&path, MAX_KEY_FILE_BYTES)? {
        // A file this build cannot read costs no keystore call.
        key_file_header(&bytes)?;
        // Never mints K_hist: a key file without its K_hist stays unreadable.
        let hist = source.load(data_dir, false)?;
        let keys = unwrap_key_file(&hist, data_dir, &bytes)?;
        return Ok(Loaded {
            hist,
            keys: Arc::new(keys),
            stamp,
        });
    }
    create_key_file(data_dir, policy, source)
}

/// First sealing of a profile: mint and wrap the payload outside any lock,
/// then write it under [`META_KEY_LOCK`] unless a racing creator already did
/// (its key is adopted, ours dropped).
fn create_key_file(
    data_dir: &Path,
    policy: MigratePolicy,
    source: &dyn HistKeySource,
) -> Result<Loaded, AtRestError> {
    if !policy.allows_sealing() || crate::privacy::mode(data_dir) == Mode::UnsealedByUser {
        return Err(AtRestError::NotSealedMode);
    }
    // An unfinished erase (PP.16) deleted the key root on purpose.
    crate::erase::refuse_if_unfinished(data_dir).map_err(AtRestError::KeyUnavailable)?;
    // Before anything is created: a fresh profile stays exactly as it was.
    if !crate::identity_store::identity_recorded(data_dir)
        .map_err(|e| AtRestError::Io(e.to_string()))?
    {
        return Err(AtRestError::NoIdentity);
    }
    let hist = source.load(data_dir, true)?;
    let payload = KeyPayload::mint();
    let file = wrap_key_file(&hist, data_dir, &payload)?;
    drop(payload);
    let path = data_dir.join(META_KEY_FILE);
    {
        let _lock = DataDirLock::acquire_within(data_dir, META_KEY_LOCK, META_KEY_LOCK_WAIT)
            .map_err(AtRestError::Io)?;
        if stat(&path)?.is_none() {
            crate::paths::atomic_write_private(&path, &file).map_err(AtRestError::Io)?;
            #[cfg(test)]
            tests::note_key_file_created(data_dir);
        }
    }
    // Ours, or the racing creator's: read back what is there now, outside
    // the lock, and prove that it opens.
    let (bytes, stamp) = read_stable(&path, MAX_KEY_FILE_BYTES)?
        .ok_or_else(|| AtRestError::Io(format!("{META_KEY_FILE} vanished after it was written")))?;
    let keys = unwrap_key_file(&hist, data_dir, &bytes)?;
    Ok(Loaded {
        hist,
        keys: Arc::new(keys),
        stamp,
    })
}

// ── Rotation: the key file's epochs (PP.10) ──────────────────────────────

/// This process's cached K_hist of `data_dir` (no keystore call): for a
/// rotation's rewrite of the key file and for opening data K_hist sealed
/// directly (RVNHIST1, RVNOSTG1, untagged app rows) while it moves under the
/// epoch keys. [`AtRestError::KeyUnavailable`] when [`keys_load`] has not run
/// here.
pub(crate) fn cached_hist(data_dir: &Path) -> Result<HistKey, AtRestError> {
    lock_cache()
        .get(&canonical_dir(data_dir))
        .map(|entry| entry.hist.clone())
        .ok_or_else(|| {
            AtRestError::KeyUnavailable("the at-rest key is not loaded in this process".into())
        })
}

/// Step 1 of a data-key rotation (`privacy::rotate_data_key`): while the key
/// file holds `from` alone, add epoch `from + 1` and make it current; every
/// writer seals under it from its next [`keys_cached`] on, and `from` stays
/// readable. Anything else is left as it is (a racing pass did it, or a
/// rotation is under way). Returns the keys now in force.
pub(crate) fn add_epoch(data_dir: &Path, from: u32) -> Result<Arc<MetaKeys>, AtRestError> {
    rewrite_key_file(data_dir, |payload, _| {
        if payload.current != from || payload.epochs.len() != 1 {
            return Ok(None);
        }
        let next = from
            .checked_add(1)
            .ok_or_else(|| AtRestError::Io(format!("{META_KEY_FILE}: no epoch number left")))?;
        let mut epochs = payload.epochs.clone();
        epochs.push((next, random_key()));
        Ok(Some(KeyPayload {
            k_index: payload.k_index.clone(),
            epochs,
            current: next,
        }))
    })
}

/// The last step of a rotation: keep the current epoch only. Data still
/// sealed under a dropped epoch no longer opens with any key this computer
/// holds (the caller re-scanned first and found none left).
pub(crate) fn drop_old_epochs(data_dir: &Path) -> Result<Arc<MetaKeys>, AtRestError> {
    rewrite_key_file(data_dir, |payload, _| {
        if payload.epochs.len() == 1 {
            return Ok(None);
        }
        let current = payload.current;
        Ok(Some(KeyPayload {
            k_index: payload.k_index.clone(),
            epochs: payload
                .epochs
                .iter()
                .filter(|(epoch, _)| *epoch == current)
                .cloned()
                .collect(),
            current,
        }))
    })
}

/// The first step of `raven privacy rotate-meta` (PP.18), for a profile that
/// suspects its keys were exposed: unless epoch `to` is current already,
/// the key file gets a NEW `k_index` and epoch `to` (a new random key) as
/// its current epoch, and keeps every epoch it held, so everything sealed
/// so far still opens. Every keyed value of the stores is then computed
/// again under the new `k_index` (`privacy::rotate_meta`), and the old
/// epochs leave last ([`drop_old_epochs`]). The new `k_index` is on disk
/// before any store uses it: a crash never leaves a store keyed under a key
/// nothing holds. Returns the keys now in force.
pub(crate) fn begin_meta_rotation(data_dir: &Path, to: u32) -> Result<Arc<MetaKeys>, AtRestError> {
    rewrite_key_file(data_dir, |payload, _| {
        if payload.current == to {
            return Ok(None);
        }
        if payload.epochs.iter().any(|(epoch, _)| *epoch >= to) {
            return Err(AtRestError::Io(format!(
                "{META_KEY_FILE}: epoch {to} is not a new epoch"
            )));
        }
        let mut epochs = payload.epochs.clone();
        epochs.push((to, random_key()));
        Ok(Some(KeyPayload {
            k_index: random_key(),
            epochs,
            current: to,
        }))
    })
}

/// The last step of `raven privacy unseal` (PP.18): delete `meta_key.rmk`
/// under [`META_KEY_LOCK`] (nothing is sealed under it any more) and drop
/// this process's cached keys. A missing file is fine.
pub(crate) fn delete_key_file(data_dir: &Path) -> Result<(), AtRestError> {
    {
        let _lock = DataDirLock::acquire_within(data_dir, META_KEY_LOCK, META_KEY_LOCK_WAIT)
            .map_err(AtRestError::Io)?;
        match std::fs::remove_file(data_dir.join(META_KEY_FILE)) {
            Ok(()) => crate::paths::sync_dir_best_effort(data_dir),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(AtRestError::Io(format!("{META_KEY_FILE}: {e}"))),
        }
    }
    forget_cached_keys(data_dir);
    Ok(())
}

/// Rewrite `meta_key.rmk` with what `change` makes of its payload and the
/// file's bytes (`None`: nothing to change). No keystore call: the new
/// payload is built and wrapped with the cached K_hist outside any lock,
/// then written (temp, fsync, rename) under [`META_KEY_LOCK`] only if the
/// file is still the one it was built from (its stamp), and only once the
/// written temp file opens to that payload; otherwise it starts again from
/// the file another process wrote. `k_index`, and with it every keyed lookup
/// and lock name, changes only in [`begin_meta_rotation`].
fn rewrite_key_file(
    data_dir: &Path,
    change: impl Fn(&KeyPayload, &[u8]) -> Result<Option<KeyPayload>, AtRestError>,
) -> Result<Arc<MetaKeys>, AtRestError> {
    let path = data_dir.join(META_KEY_FILE);
    let missing = || AtRestError::KeyUnavailable(format!("{META_KEY_FILE} is missing"));
    let hist = cached_hist(data_dir)?;
    for _ in 0..8 {
        let (bytes, stamp) = read_stable(&path, MAX_KEY_FILE_BYTES)?.ok_or_else(missing)?;
        let keys = unwrap_key_file(&hist, data_dir, &bytes)?;
        let Some(next) = change(&keys.payload, &bytes)? else {
            return keys_cached(data_dir);
        };
        let file = wrap_key_file(&hist, data_dir, &next)?;
        let json = next.to_json();
        drop(next);
        let lock = DataDirLock::acquire_within(data_dir, META_KEY_LOCK, META_KEY_LOCK_WAIT)
            .map_err(AtRestError::Io)?;
        if stat(&path)? != Some(stamp) {
            continue;
        }
        crate::paths::atomic_write_private_verified(&path, &file, |written| {
            let written = std::fs::read(written).map_err(|e| e.to_string())?;
            match unwrap_key_file(&hist, data_dir, &written) {
                Ok(opened) if opened.payload.to_json() == json => Ok(()),
                Ok(_) => Err(format!("{META_KEY_FILE}: the written copy differs")),
                Err(e) => Err(format!(
                    "{META_KEY_FILE}: the written copy does not open: {e}"
                )),
            }
        })
        .map_err(AtRestError::Io)?;
        drop(lock);
        return keys_cached(data_dir);
    }
    Err(AtRestError::Io(format!(
        "{META_KEY_FILE} kept changing while it was rewritten"
    )))
}

/// Windows (privacy pack PP.11): this process's cached K_hist becomes `hist`,
/// the key `privacy::migrate_all` just created for a profile that had none,
/// so the re-wrap of the key file ([`rewrap_key_file`]) and every seal after
/// it use it. Nothing changes when the keys are not loaded here.
#[cfg(any(test, windows))]
pub(crate) fn adopt_hist(data_dir: &Path, hist: HistKey) {
    if let Some(entry) = lock_cache().get_mut(&canonical_dir(data_dir)) {
        entry.hist = hist;
    }
}

/// Windows (privacy pack PP.11, review R18): a key file an older build wrapped
/// with DPAPI directly is wrapped again under K_hist, eagerly (nothing else
/// ever rewrites it before a rotation). The same payload, so every key,
/// epoch, keyed lookup and lock name stays; written as a rotation's rewrite
/// is (temp, fsync, verified, rename, under [`META_KEY_LOCK`]), with no
/// keystore call. `Ok(true)` when it was DPAPI-direct and is under K_hist
/// now; a missing file, or one under K_hist already, is `Ok(false)`. This
/// process's keys must be loaded with K_hist itself ([`adopt_hist`]).
#[cfg(any(test, windows))]
pub(crate) fn rewrap_key_file(data_dir: &Path) -> Result<bool, AtRestError> {
    if !key_file_dpapi_direct(data_dir) {
        return Ok(false);
    }
    if !matches!(cached_hist(data_dir)?, HistKey::Wrapped(_)) {
        return Err(AtRestError::KeyUnavailable(
            "K_hist is not loaded in this process".into(),
        ));
    }
    rewrite_key_file(data_dir, |payload, bytes| {
        Ok(wrapped_dpapi_direct(bytes).then(|| KeyPayload {
            k_index: payload.k_index.clone(),
            epochs: payload.epochs.clone(),
            current: payload.current,
        }))
    })?;
    Ok(!key_file_dpapi_direct(data_dir))
}

/// Windows (PP.11): whether `meta_key.rmk` is still wrapped with DPAPI
/// directly (an older build's), by its first bytes; no key, no lock.
#[cfg(any(test, windows))]
pub(crate) fn key_file_dpapi_direct(data_dir: &Path) -> bool {
    let len = KEY_FILE_MAGIC.len() + 1 + crate::chat_history::windows_key::DPAPI_BLOB_VERSION.len();
    read_head(&data_dir.join(META_KEY_FILE), len)
        .ok()
        .flatten()
        .is_some_and(|head| wrapped_dpapi_direct(&head))
}

/// A key file's bytes (or its first ones): is the wrapped part DPAPI-direct?
#[cfg(any(test, windows))]
fn wrapped_dpapi_direct(file: &[u8]) -> bool {
    file.starts_with(KEY_FILE_MAGIC)
        && file
            .get(KEY_FILE_MAGIC.len() + 1..)
            .is_some_and(crate::chat_history::windows_key::is_dpapi_direct)
}

/// Whether `bytes` (a copy of a key file) unwrap with this process's cached
/// K_hist (`raven privacy status --verify-copy`). No keystore call.
pub(crate) fn key_file_opens(data_dir: &Path, bytes: &[u8]) -> Result<bool, AtRestError> {
    let hist = cached_hist(data_dir)?;
    match unwrap_key_file(&hist, data_dir, bytes) {
        Ok(_) => Ok(true),
        Err(
            AtRestError::Tampered { .. } | AtRestError::Truncated | AtRestError::NewerFormat(_),
        ) => Ok(false),
        Err(other) => Err(other),
    }
}

/// The epoch an RMS1 file names (`None`: not RMS1, or too short).
pub fn sealed_file_epoch(bytes: &[u8]) -> Option<u32> {
    (is_sealed(bytes) && bytes.len() >= SEALED_HEADER_LEN)
        .then(|| u32::from_be_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]))
}

/// What [`reseal_file`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resealed {
    /// No such file.
    Missing,
    /// Plain bytes: the migration's business, not the rotation's.
    Plain,
    /// Sealed under the current epoch already: nothing written.
    Current,
    /// Opened and sealed again under the current epoch.
    Resealed,
}

/// A data-key rotation's step for one registered sealed file (PP.10): under
/// its writer lock, an RMS1 file on another epoch than the current one is
/// opened and sealed again under the current epoch, renamed into place only
/// once the written copy opens to the same bytes. Errors as [`open`]: a file
/// that does not open is left as it is.
pub fn reseal_file(data_dir: &Path, path: &Path, kind: Kind) -> Result<Resealed, AtRestError> {
    // Its first bytes, without the lock: a file on the current epoch needs
    // nothing (a writer writes the current epoch, or a stale one the next
    // re-scan finds). 33 bytes: a raw secret's whole plain file, or more.
    let current = keys_cached(data_dir)?.current_epoch();
    let Some(head) = read_head(path, RAW_SECRET_LEN + 1)? else {
        return Ok(Resealed::Missing);
    };
    if is_sealed_as(kind, &head) && sealed_file_epoch(&head) == Some(current) {
        return Ok(Resealed::Current);
    }
    let _lock = lock_file(data_dir, path, kind)?;
    let Some(raw) = read_capped(path, MAX_SEALED_FILE_BYTES)? else {
        return Ok(Resealed::Missing);
    };
    if !is_sealed_as(kind, &raw) {
        return Ok(Resealed::Plain);
    }
    let keys = keys_cached(data_dir)?;
    if sealed_file_epoch(&raw) == Some(keys.current_epoch()) {
        return Ok(Resealed::Current);
    }
    let plain = open(&keys, kind, &raw)?;
    seal_verified_held(data_dir, path, kind, &plain)?;
    Ok(Resealed::Resealed)
}

/// `"RMK1" || 0x01`: a newer format or a foreign file costs no keystore call.
fn key_file_header(bytes: &[u8]) -> Result<(), AtRestError> {
    if bytes.len() < KEY_FILE_MAGIC.len() + 1 {
        return Err(AtRestError::Truncated);
    }
    if bytes[..KEY_FILE_MAGIC.len()] != KEY_FILE_MAGIC[..] {
        return Err(AtRestError::Tampered {
            kind: NOT_A_FILE_KIND,
        });
    }
    match bytes[KEY_FILE_MAGIC.len()] {
        FORMAT_VERSION => Ok(()),
        newer if newer > FORMAT_VERSION => Err(AtRestError::NewerFormat(newer)),
        _ => Err(AtRestError::Tampered {
            kind: NOT_A_FILE_KIND,
        }),
    }
}

fn wrap_key_file(
    hist: &HistKey,
    data_dir: &Path,
    payload: &KeyPayload,
) -> Result<Vec<u8>, AtRestError> {
    let json = payload.to_json();
    let wrapped = DomainProtector::new(META_KEY_DOMAIN)
        .protect_with(hist, data_dir, &json)
        .map_err(|e| AtRestError::KeyUnavailable(e.to_string()))?;
    let mut file = Vec::with_capacity(KEY_FILE_MAGIC.len() + 1 + wrapped.len());
    file.extend_from_slice(KEY_FILE_MAGIC);
    file.push(FORMAT_VERSION);
    file.extend_from_slice(&wrapped);
    Ok(file)
}

fn unwrap_key_file(hist: &HistKey, data_dir: &Path, bytes: &[u8]) -> Result<MetaKeys, AtRestError> {
    key_file_header(bytes)?;
    let json = DomainProtector::new(META_KEY_DOMAIN)
        .unprotect_with(hist, data_dir, &bytes[KEY_FILE_MAGIC.len() + 1..])
        .map_err(|e| match e {
            ChatHistoryError::AuthenticationFailed | ChatHistoryError::Corrupt => {
                AtRestError::Tampered {
                    kind: NOT_A_FILE_KIND,
                }
            }
            other => hist_key_error(other, true),
        })?;
    KeyPayload::parse(&json).map(MetaKeys::from_payload)
}

// ── Sealing ──────────────────────────────────────────────────────────────

/// Whether `bytes` are an RMS1 sealed file (by its magic; plain JSON never
/// starts with it).
pub fn is_sealed(bytes: &[u8]) -> bool {
    bytes.starts_with(SEALED_MAGIC)
}

/// [`is_sealed`] for the contents of a file registered under `kind`: a raw
/// secret's plain file ([`Kind::is_raw_secret`], exactly 32 bytes) is plain
/// whatever its first bytes.
pub fn is_sealed_as(kind: Kind, bytes: &[u8]) -> bool {
    is_sealed(bytes) && !(kind.is_raw_secret() && bytes.len() == RAW_SECRET_LEN)
}

/// Seal a file's bytes under the current epoch (RMS1).
pub fn seal(k: &MetaKeys, kind: Kind, plaintext: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    seal_with(k, kind, k.payload.current, &nonce, plaintext)
}

fn seal_with(
    k: &MetaKeys,
    kind: Kind,
    epoch: u32,
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
) -> Vec<u8> {
    let key = k
        .data_key(epoch, DataUse::MetaFile)
        .expect("the sealing epoch is a loaded epoch");
    let mut out = Vec::with_capacity(SEALED_HEADER_LEN + NONCE_LEN + plaintext.len() + TAG_LEN);
    out.extend_from_slice(SEALED_MAGIC);
    out.push(FORMAT_VERSION);
    out.push(kind.code());
    out.extend_from_slice(&epoch.to_be_bytes());
    out.extend_from_slice(nonce);
    let sealed = XChaCha20Poly1305::new_from_slice(&key[..])
        .expect("XChaCha20-Poly1305 takes a 32-byte key")
        .encrypt(
            XNonce::from_slice(nonce),
            AeadPayload {
                msg: plaintext,
                aad: &file_aad(kind, epoch),
            },
        )
        .expect("XChaCha20-Poly1305 seals any buffer this process holds");
    out.extend_from_slice(&sealed);
    out
}

fn file_aad(kind: Kind, epoch: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(SEAL_AAD.len() + 1 + 4);
    aad.extend_from_slice(SEAL_AAD);
    aad.push(kind.code());
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad
}

/// Open an RMS1 file of `kind`. Typed failures: not RMS1 or a changed byte
/// [`AtRestError::Tampered`], another kind [`AtRestError::WrongKind`], too
/// short [`AtRestError::Truncated`], a newer version
/// [`AtRestError::NewerFormat`], an epoch not loaded
/// [`AtRestError::StaleKeys`]. A [`AtRestError::Tampered`] is also noted as
/// `SEC_LOCAL_ROLLBACK` ([`sense_tampered`]).
pub fn open(k: &MetaKeys, kind: Kind, bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, AtRestError> {
    open_file(k, kind, bytes).inspect_err(sense_tampered)
}

/// Phase 6b (design C sensing point C1, S23): sealed bytes that fail
/// authentication under the loaded keys were changed outside Raven, noted
/// about this computer through
/// [`crate::security_events::classify_at_rest_error`]. Only
/// [`AtRestError::Tampered`]: the open still fails closed, exactly as before.
fn sense_tampered(e: &AtRestError) {
    if matches!(e, AtRestError::Tampered { .. }) {
        if let Some(kind) = crate::security_events::classify_at_rest_error(e) {
            crate::security_sense::local(kind);
        }
    }
}

fn open_file(k: &MetaKeys, kind: Kind, bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, AtRestError> {
    let tampered = AtRestError::Tampered { kind: kind.code() };
    if bytes.len() < SEALED_MAGIC.len() + 1 {
        return Err(AtRestError::Truncated);
    }
    if !is_sealed(bytes) {
        return Err(tampered);
    }
    match bytes[4] {
        FORMAT_VERSION => {}
        newer if newer > FORMAT_VERSION => return Err(AtRestError::NewerFormat(newer)),
        _ => return Err(tampered),
    }
    if bytes.len() < SEALED_HEADER_LEN {
        return Err(AtRestError::Truncated);
    }
    if bytes[5] != kind.code() {
        return Err(AtRestError::WrongKind {
            want: kind.code(),
            got: bytes[5],
        });
    }
    let epoch = u32::from_be_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]);
    if bytes.len() < SEALED_HEADER_LEN + NONCE_LEN + TAG_LEN {
        return Err(AtRestError::Truncated);
    }
    let key = k
        .data_key(epoch, DataUse::MetaFile)
        .ok_or(AtRestError::StaleKeys { epoch })?;
    let nonce = &bytes[SEALED_HEADER_LEN..SEALED_HEADER_LEN + NONCE_LEN];
    XChaCha20Poly1305::new_from_slice(&key[..])
        .expect("XChaCha20-Poly1305 takes a 32-byte key")
        .decrypt(
            XNonce::from_slice(nonce),
            AeadPayload {
                msg: &bytes[SEALED_HEADER_LEN + NONCE_LEN..],
                aad: &file_aad(kind, epoch),
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| tampered)
}

/// Seal a row's clear values under the current epoch: `0x01 || epoch ||
/// nonce[24] || ct || tag[16]`, bound to the table and the row's primary-key
/// bytes exactly as stored.
pub fn seal_row(k: &MetaKeys, table: &str, pk: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    seal_row_with(k, table, pk, k.payload.current, &nonce, plaintext)
}

fn seal_row_with(
    k: &MetaKeys,
    table: &str,
    pk: &[u8],
    epoch: u32,
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
) -> Vec<u8> {
    debug_assert!(!table.contains('\0'), "a table name never holds NUL");
    let key = k
        .data_key(epoch, DataUse::MetaRow)
        .expect("the sealing epoch is a loaded epoch");
    let mut out = Vec::with_capacity(ROW_HEADER_LEN + NONCE_LEN + plaintext.len() + TAG_LEN);
    out.push(FORMAT_VERSION);
    out.extend_from_slice(&epoch.to_be_bytes());
    out.extend_from_slice(nonce);
    let sealed = XChaCha20Poly1305::new_from_slice(&key[..])
        .expect("XChaCha20-Poly1305 takes a 32-byte key")
        .encrypt(
            XNonce::from_slice(nonce),
            AeadPayload {
                msg: plaintext,
                aad: &row_aad(table, pk, epoch),
            },
        )
        .expect("XChaCha20-Poly1305 seals any buffer this process holds");
    out.extend_from_slice(&sealed);
    out
}

fn row_aad(table: &str, pk: &[u8], epoch: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(ROW_AAD.len() + table.len() + 1 + pk.len() + 4);
    aad.extend_from_slice(ROW_AAD);
    aad.extend_from_slice(table.as_bytes());
    aad.push(0);
    aad.extend_from_slice(pk);
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad
}

/// Open a row blob of `table` whose primary key is `pk`. Failures as
/// [`open`] (a [`AtRestError::Tampered`] noted the same way); it carries
/// [`NOT_A_FILE_KIND`].
pub fn open_row(
    k: &MetaKeys,
    table: &str,
    pk: &[u8],
    blob: &[u8],
) -> Result<Zeroizing<Vec<u8>>, AtRestError> {
    open_row_blob(k, table, pk, blob).inspect_err(sense_tampered)
}

fn open_row_blob(
    k: &MetaKeys,
    table: &str,
    pk: &[u8],
    blob: &[u8],
) -> Result<Zeroizing<Vec<u8>>, AtRestError> {
    let tampered = AtRestError::Tampered {
        kind: NOT_A_FILE_KIND,
    };
    let Some(&version) = blob.first() else {
        return Err(AtRestError::Truncated);
    };
    match version {
        FORMAT_VERSION => {}
        newer if newer > FORMAT_VERSION => return Err(AtRestError::NewerFormat(newer)),
        _ => return Err(tampered),
    }
    if blob.len() < ROW_HEADER_LEN + NONCE_LEN + TAG_LEN {
        return Err(AtRestError::Truncated);
    }
    let epoch = u32::from_be_bytes([blob[1], blob[2], blob[3], blob[4]]);
    let key = k
        .data_key(epoch, DataUse::MetaRow)
        .ok_or(AtRestError::StaleKeys { epoch })?;
    XChaCha20Poly1305::new_from_slice(&key[..])
        .expect("XChaCha20-Poly1305 takes a 32-byte key")
        .decrypt(
            XNonce::from_slice(&blob[ROW_HEADER_LEN..ROW_HEADER_LEN + NONCE_LEN]),
            AeadPayload {
                msg: &blob[ROW_HEADER_LEN + NONCE_LEN..],
                aad: &row_aad(table, pk, epoch),
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| tampered)
}

// ── Epoch data: history, outbound stage, app rows (PP.10) ────────────────

/// The bytes an epoch body adds around its plaintext ([`seal_epoch`]): the
/// epoch, the nonce and the tag. The caller's magic or format tag comes on
/// top.
pub const EPOCH_BODY_OVERHEAD: usize = 4 + NONCE_LEN + TAG_LEN;

/// Seal data of `use_` (the chat history, the outbound stage, an app row)
/// under the current epoch: `epoch u32 BE || nonce[24] || ct || tag[16]`,
/// XChaCha20-Poly1305 under `K_data[epoch].use_`, AAD `domain || epoch`. The
/// caller puts its own magic or format tag in front (`RVNHIST2`, `RVNOSTG2`,
/// the app row's `0x02`). The epoch names the key, so a data-key rotation
/// finds what is left on an old one without opening it.
pub(crate) fn seal_epoch(k: &MetaKeys, use_: DataUse, domain: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    seal_epoch_with(k, use_, domain, k.payload.current, &nonce, plaintext)
}

pub(crate) fn seal_epoch_with(
    k: &MetaKeys,
    use_: DataUse,
    domain: &[u8],
    epoch: u32,
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
) -> Vec<u8> {
    let key = k
        .data_key(epoch, use_)
        .expect("the sealing epoch is a loaded epoch");
    let mut out = Vec::with_capacity(EPOCH_BODY_OVERHEAD + plaintext.len());
    out.extend_from_slice(&epoch.to_be_bytes());
    out.extend_from_slice(nonce);
    let sealed = XChaCha20Poly1305::new_from_slice(&key[..])
        .expect("XChaCha20-Poly1305 takes a 32-byte key")
        .encrypt(
            XNonce::from_slice(nonce),
            AeadPayload {
                msg: plaintext,
                aad: &epoch_aad(domain, epoch),
            },
        )
        .expect("XChaCha20-Poly1305 seals any buffer this process holds");
    out.extend_from_slice(&sealed);
    out
}

fn epoch_aad(domain: &[u8], epoch: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(domain.len() + 4);
    aad.extend_from_slice(domain);
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad
}

/// The epoch an epoch body names (`None`: too short to be one).
pub(crate) fn epoch_of(body: &[u8]) -> Option<u32> {
    (body.len() >= EPOCH_BODY_OVERHEAD)
        .then(|| u32::from_be_bytes([body[0], body[1], body[2], body[3]]))
}

/// Open an epoch body ([`seal_epoch`]) of `use_` under `domain`. Typed
/// failures: too short [`AtRestError::Truncated`], an epoch this process has
/// not loaded [`AtRestError::StaleKeys`], a changed byte, another use or
/// another domain [`AtRestError::Tampered`] (kind [`NOT_A_FILE_KIND`]).
pub(crate) fn open_epoch(
    k: &MetaKeys,
    use_: DataUse,
    domain: &[u8],
    body: &[u8],
) -> Result<Zeroizing<Vec<u8>>, AtRestError> {
    let epoch = epoch_of(body).ok_or(AtRestError::Truncated)?;
    let key = k
        .data_key(epoch, use_)
        .ok_or(AtRestError::StaleKeys { epoch })?;
    XChaCha20Poly1305::new_from_slice(&key[..])
        .expect("XChaCha20-Poly1305 takes a 32-byte key")
        .decrypt(
            XNonce::from_slice(&body[4..4 + NONCE_LEN]),
            AeadPayload {
                msg: &body[4 + NONCE_LEN..],
                aad: &epoch_aad(domain, epoch),
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| AtRestError::Tampered {
            kind: NOT_A_FILE_KIND,
        })
}

/// The keyed lookup digest of `value`:
/// HMAC-SHA256(K_index, "rvn1/meta-index/v1" || label || 0x00 || value).
/// The label names the value's type, never the table: equal values give
/// equal digests everywhere in one profile, and nothing links across
/// profiles.
pub fn index(k: &MetaKeys, t: ValueType, value: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&k.index[..]).expect("hmac takes any key");
    mac.update(INDEX_DOMAIN);
    mac.update(t.label().as_bytes());
    mac.update(&[0]);
    mac.update(value);
    mac.finalize().into_bytes().into()
}

/// The per-friend send lock's file name:
/// `.send_<hex(HMAC(K_lock, "rvn1/lock-name/v1" || peer)[0..16])>.lock.sqlite`.
/// From the stable `k_index`, so a rotation never renames a lock and two
/// processes always agree.
pub fn lock_name(k: &MetaKeys, peer: &[u8; 32]) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&k.lock[..]).expect("hmac takes any key");
    mac.update(LOCK_NAME_DOMAIN);
    mac.update(peer);
    let digest = mac.finalize().into_bytes();
    format!(".send_{}.lock.sqlite", hex::encode(&digest[..16]))
}

// ── Registered files ─────────────────────────────────────────────────────

/// A registered sealed file's writer lock, held for a read-modify-write:
/// every writer of the file (and [`migrate_file`]) takes the same lock, so a
/// migration never renames a sealed copy of old bytes over a newer write.
pub struct FileLock {
    data_dir: PathBuf,
    path: PathBuf,
    kind: Kind,
    _lock: DataDirLock,
}

/// Take the writer lock [`FILES`] names for `path`, which must be registered
/// there as sealed under `kind`.
pub fn lock_file(data_dir: &Path, path: &Path, kind: Kind) -> Result<FileLock, AtRestError> {
    let lock = sealed_rule(data_dir, path, kind)?;
    Ok(FileLock {
        data_dir: data_dir.to_path_buf(),
        path: path.to_path_buf(),
        kind,
        _lock: DataDirLock::acquire(data_dir, lock).map_err(AtRestError::Io)?,
    })
}

/// The name [`FILES`] knows `path` by: its path below the data dir with `/`
/// separators, or its file name.
fn registered_name(data_dir: &Path, path: &Path) -> String {
    match path.strip_prefix(data_dir) {
        Ok(relative) => relative
            .components()
            .map(|part| part.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/"),
        Err(_) => file_label(path),
    }
}

/// The writer lock of a file registered as sealed under `kind`.
fn sealed_rule(data_dir: &Path, path: &Path, kind: Kind) -> Result<&'static str, AtRestError> {
    let name = registered_name(data_dir, path);
    match rule_for(&name) {
        Some(FileRule {
            rule: Rule::Sealed(registered),
            lock: Some(lock),
            ..
        }) if *registered == kind => Ok(*lock),
        Some(_) => Err(AtRestError::Io(format!(
            "{name} is not registered as a sealed file of kind {}",
            kind.code()
        ))),
        None => Err(AtRestError::Io(format!(
            "{name} is not in at_rest::FILES; classify it there (docs/design/2026-10-at-rest-metadata.md)"
        ))),
    }
}

impl FileLock {
    pub fn load_bytes(&self) -> Result<Option<Zeroizing<Vec<u8>>>, AtRestError> {
        load_bytes(&self.data_dir, &self.path, self.kind)
    }

    pub fn load_json<T: DeserializeOwned>(&self) -> Result<Option<T>, AtRestError> {
        load_json(&self.data_dir, &self.path, self.kind)
    }

    /// Write the file: RMS1 when the profile is sealed, `plaintext` as it is
    /// otherwise.
    pub fn store_bytes(&self, plaintext: &[u8]) -> Result<(), AtRestError> {
        write_as_mode(&self.data_dir, &self.path, self.kind, plaintext)
    }

    /// [`Self::store_bytes`] of the value as pretty JSON: in a plain profile
    /// exactly the bytes of today's `serde_json::to_vec_pretty` writers.
    pub fn store_json<T: Serialize>(&self, value: &T) -> Result<(), AtRestError> {
        let plaintext = Zeroizing::new(
            serde_json::to_vec_pretty(value)
                .map_err(|e| AtRestError::Json(format!("{}: {e}", file_label(&self.path))))?,
        );
        self.store_bytes(&plaintext)
    }
}

/// `plaintext` in the form the profile's mode says: RMS1 when it is sealed
/// (with the keys this process loaded; none loaded is an error, never a
/// plaintext fallback), as it is otherwise.
fn write_as_mode(
    data_dir: &Path,
    path: &Path,
    kind: Kind,
    plaintext: &[u8],
) -> Result<(), AtRestError> {
    let bytes = match crate::privacy::mode(data_dir) {
        Mode::Sealed => {
            let keys = keys_cached(data_dir)?;
            Zeroizing::new(seal(&keys, kind, plaintext))
        }
        Mode::Plain | Mode::UnsealedByUser => Zeroizing::new(plaintext.to_vec()),
    };
    crate::paths::atomic_write_private(path, &bytes).map_err(AtRestError::Io)
}

/// Write a registered file whose writer lock (the one [`FILES`] names) the
/// caller already holds for its own read-modify-write: the peer cache, the
/// device registry and the noise pins serialise on their lock across a
/// load, a change and a save, and taking it again here would wait on the
/// caller itself. RMS1 in a sealed profile, `plaintext` as it is otherwise.
pub fn write_held(
    data_dir: &Path,
    path: &Path,
    kind: Kind,
    plaintext: &[u8],
) -> Result<(), AtRestError> {
    sealed_rule(data_dir, path, kind)?;
    write_as_mode(data_dir, path, kind, plaintext)
}

/// A file's bytes as they are on disk (capped far above any registered
/// file); `None` when it is missing.
pub(crate) fn read_raw(path: &Path) -> Result<Option<Zeroizing<Vec<u8>>>, AtRestError> {
    read_capped(path, MAX_SEALED_FILE_BYTES)
}

/// A registered file's plaintext: RMS1 opened with the cached keys, plain
/// bytes as they are. A missing file is `None`.
pub fn load_bytes(
    data_dir: &Path,
    path: &Path,
    kind: Kind,
) -> Result<Option<Zeroizing<Vec<u8>>>, AtRestError> {
    let Some(bytes) = read_capped(path, MAX_SEALED_FILE_BYTES)? else {
        return Ok(None);
    };
    if !is_sealed_as(kind, &bytes) {
        return Ok(Some(bytes));
    }
    let keys = keys_cached(data_dir)?;
    open(&keys, kind, &bytes).map(Some)
}

/// What a reader that treats an unreadable file as empty got
/// ([`load_json_advisory`]): the advisory files (route hint state; PP.6's
/// sightings, learned routes, route memory, outbox routes and relay
/// memory), whose writers must never write over a file they could not
/// read, since that would destroy sealed data.
#[derive(Debug)]
pub enum Advisory<T> {
    /// No file: empty, and a write may create it.
    Missing,
    Loaded(T),
    /// Plain bytes that do not parse (an older build's file, a hand edit):
    /// empty, and today's writer may replace it.
    CorruptPlain,
    /// Anything else: a sealed file this process cannot open (the key not
    /// loaded, a changed byte, a newer format) or whose plaintext does not
    /// parse, or an I/O error. Empty for the reader, and never written over:
    /// the writer skips its write and counts it ([`note_skipped_write`]).
    Unreadable(AtRestError),
}

impl<T> Advisory<T> {
    /// Whether a writer may replace the file after this read.
    pub fn writable(&self) -> bool {
        !matches!(self, Advisory::Unreadable(_))
    }

    /// The value read, or `None` (missing, or read as empty).
    pub fn into_loaded(self) -> Option<T> {
        match self {
            Advisory::Loaded(value) => Some(value),
            _ => None,
        }
    }
}

/// Read an advisory file (sealed or plain JSON); see [`Advisory`].
pub fn load_json_advisory<T: DeserializeOwned>(
    data_dir: &Path,
    path: &Path,
    kind: Kind,
) -> Advisory<T> {
    let raw = match read_capped(path, MAX_SEALED_FILE_BYTES) {
        Ok(Some(raw)) => raw,
        Ok(None) => return Advisory::Missing,
        Err(e) => return Advisory::Unreadable(e),
    };
    if !is_sealed_as(kind, &raw) {
        return serde_json::from_slice(&raw).map_or(Advisory::CorruptPlain, Advisory::Loaded);
    }
    let plain = match keys_cached(data_dir).and_then(|keys| open(&keys, kind, &raw)) {
        Ok(plain) => plain,
        Err(e) => return Advisory::Unreadable(e),
    };
    serde_json::from_slice(&plain).map_or_else(
        |e| {
            Advisory::Unreadable(AtRestError::Json(format!(
                "{} corrupt: {e}",
                file_label(path)
            )))
        },
        Advisory::Loaded,
    )
}

/// [`load_json_advisory`] for an advisory file's writer that holds the
/// file's writer lock: the value to change (the default when the file is
/// missing or holds plain bytes that do not parse, which today's writers
/// replace), or why it must not be written over ([`Advisory::Unreadable`];
/// the skip is counted, [`note_skipped_write`]).
pub fn load_json_for_write<T: DeserializeOwned + Default>(
    data_dir: &Path,
    path: &Path,
    kind: Kind,
) -> Result<T, AtRestError> {
    match load_json_advisory(data_dir, path, kind) {
        Advisory::Loaded(value) => Ok(value),
        Advisory::Missing | Advisory::CorruptPlain => Ok(T::default()),
        Advisory::Unreadable(why) => {
            note_skipped_write(data_dir, &why);
            Err(why)
        }
    }
}

/// Writes skipped by advisory writers in this process, per canonical data
/// dir ([`note_skipped_write`]).
static SKIPPED_WRITES: Mutex<BTreeMap<PathBuf, u64>> = Mutex::new(BTreeMap::new());

fn lock_skipped() -> MutexGuard<'static, BTreeMap<PathBuf, u64>> {
    SKIPPED_WRITES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// An advisory writer of `data_dir` skipped its write: the file it would
/// replace could not be read ([`Advisory::Unreadable`] with `why`). Counted
/// for `Status.at_rest`, unless only the key was missing (not loaded yet, or
/// an epoch this process has not loaded): the file is read again once it is,
/// and nothing about it needs a look.
pub fn note_skipped_write(data_dir: &Path, why: &AtRestError) {
    if matches!(
        why,
        AtRestError::KeyUnavailable(_) | AtRestError::KeyLost(_) | AtRestError::StaleKeys { .. }
    ) {
        return;
    }
    let mut skipped = lock_skipped();
    let count = skipped.entry(canonical_dir(data_dir)).or_default();
    *count = count.saturating_add(1);
}

/// How many writes the advisory writers of this process skipped in
/// `data_dir` so far.
pub fn skipped_writes(data_dir: &Path) -> u64 {
    lock_skipped()
        .get(&canonical_dir(data_dir))
        .copied()
        .unwrap_or(0)
}

/// [`load_bytes`] parsed as JSON: RMS1 or plain JSON (an old profile, or an
/// older build wrote it). A missing file is `None`.
pub fn load_json<T: DeserializeOwned>(
    data_dir: &Path,
    path: &Path,
    kind: Kind,
) -> Result<Option<T>, AtRestError> {
    load_bytes(data_dir, path, kind)?
        .map(|plaintext| {
            serde_json::from_slice(&plaintext)
                .map_err(|e| AtRestError::Json(format!("{} corrupt: {e}", file_label(path))))
        })
        .transpose()
}

/// Write a registered file under its writer lock ([`FileLock::store_bytes`]).
/// A caller that reads, changes and writes takes [`lock_file`] itself.
pub fn store_bytes(
    data_dir: &Path,
    path: &Path,
    kind: Kind,
    plaintext: &[u8],
) -> Result<(), AtRestError> {
    lock_file(data_dir, path, kind)?.store_bytes(plaintext)
}

/// Write a registered JSON file under its writer lock
/// ([`FileLock::store_json`]): RMS1 in a sealed profile, today's bytes
/// otherwise.
pub fn store_json<T: Serialize>(
    data_dir: &Path,
    path: &Path,
    kind: Kind,
    value: &T,
) -> Result<(), AtRestError> {
    lock_file(data_dir, path, kind)?.store_json(value)
}

/// Seal one plain file in place: under its writer lock, re-read, seal, check
/// that the sealed temp file opens to exactly the bytes read, then rename.
/// Only in a sealed profile ([`AtRestError::NotSealedMode`] otherwise: the
/// mode flips first, so no writer writes plaintext once sealing began).
pub fn migrate_file(data_dir: &Path, path: &Path, kind: Kind) -> Result<Migrated, AtRestError> {
    if crate::privacy::mode(data_dir) != Mode::Sealed {
        return Err(AtRestError::NotSealedMode);
    }
    let _lock = lock_file(data_dir, path, kind)?;
    migrate_file_held(data_dir, path, kind)
}

/// [`migrate_file`] by a caller that holds the file's writer lock already
/// (and has checked the mode).
pub(crate) fn migrate_file_held(
    data_dir: &Path,
    path: &Path,
    kind: Kind,
) -> Result<Migrated, AtRestError> {
    let Some(plain) = read_capped(path, MAX_SEALED_FILE_BYTES)? else {
        return Ok(Migrated::Missing);
    };
    if is_sealed_as(kind, &plain) {
        return Ok(Migrated::AlreadySealed);
    }
    seal_verified_held(data_dir, path, kind, &plain)?;
    Ok(Migrated::Sealed)
}

/// Write `plaintext` sealed under `kind` to `path`, renamed into place only
/// once the written temp file opens to exactly `plaintext`. The caller holds
/// the file's writer lock, in a sealed profile.
pub(crate) fn seal_verified_held(
    data_dir: &Path,
    path: &Path,
    kind: Kind,
    plaintext: &[u8],
) -> Result<(), AtRestError> {
    let keys = keys_cached(data_dir)?;
    let sealed = seal(&keys, kind, plaintext);
    replace_verified(path, &sealed, |written| {
        #[cfg(test)]
        let written = &tests::seal_fault(written);
        if open(&keys, kind, written)?[..] == plaintext[..] {
            Ok(())
        } else {
            Err(AtRestError::Tampered { kind: kind.code() })
        }
    })
}

/// The way back (`raven privacy unseal`, PP.18): open one sealed file and
/// write its plaintext in place, under its writer lock. A plain or missing
/// file is left as it is.
pub fn unseal_file(data_dir: &Path, path: &Path, kind: Kind) -> Result<(), AtRestError> {
    let _lock = lock_file(data_dir, path, kind)?;
    let Some(bytes) = read_capped(path, MAX_SEALED_FILE_BYTES)? else {
        return Ok(());
    };
    if !is_sealed_as(kind, &bytes) {
        return Ok(());
    }
    let keys = keys_cached(data_dir)?;
    let plain = open(&keys, kind, &bytes)?;
    replace_verified(path, &plain, |written| {
        if written == &plain[..] {
            Ok(())
        } else {
            Err(AtRestError::Io(format!(
                "{}: the written copy differs",
                file_label(path)
            )))
        }
    })
}

/// [`crate::paths::atomic_write_private_verified`] with a typed check of the
/// temp file's bytes; a failed check leaves `path` untouched.
fn replace_verified(
    path: &Path,
    contents: &[u8],
    check: impl FnOnce(&[u8]) -> Result<(), AtRestError>,
) -> Result<(), AtRestError> {
    let mut failure = None;
    crate::paths::atomic_write_private_verified(path, contents, |temp| {
        let written = Zeroizing::new(std::fs::read(temp).map_err(|e| e.to_string())?);
        check(&written).map_err(|e| {
            let text = e.to_string();
            failure = Some(e);
            text
        })
    })
    .map_err(|e| failure.take().unwrap_or(AtRestError::Io(e)))
}
