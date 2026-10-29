//! The session store at rest (privacy pack PP.13 and PP.14;
//! docs/design/2026-10-at-rest-metadata.md sections 4.11, 4.12 and 7.3).
//!
//! In a sealed profile the store is at schema 4 ([`METADATA_SCHEMA_VERSION`]):
//! the heads' rvn1 addresses, device keys and `init_id`, and the device keys
//! (and the message ids) of the reset, re-seal, peer-state and session-end
//! tables, are keyed lookups (`kh_*`: [`crate::at_rest::index`] by value
//! type, so equal values stay equal in every table and the joins keep their
//! shape). The clear values and every time are in each row's sealed `meta`
//! (AAD: the table and the row's primary key as stored). The endpoint tables
//! (receipts, inbox, ACK intents, outstanding messages, ACK receipts, outbox,
//! inbox tombstones) are keyed the same way since schema 3 (PP.14,
//! [`endpoints`]); a PP.13 build's schema 2 ([`HEADS_VERSION`]) keeps them
//! clear, and schema 2 and 3 ([`ENDPOINTS_VERSION`], the pack's builds before
//! review B-sealed-stores-1) keep the heads' `init_id` clear: this build
//! moves either on to schema 4 as it moves a clear store.
//!
//! **`init_id` is keyed (schema 4, review B-sealed-stores-1).** The record
//! key is an unkeyed digest of public values (the constant profile id, both
//! addresses, both device keys) and the `init_id`: with the `init_id` clear
//! beside it, anyone with the file and a list of candidate friends' public
//! keys could tell which friend each session is with. Schema 4 keeps
//! `kh_init_id` ([`ValueType::Nonce`]) where schema 2 and 3 kept the
//! `init_id` (its UNIQUE index under the same name), and the `init_id`
//! itself in the head's `meta` ([`HeadMeta::init_id`]); without it the
//! record key is a 2^128 search.
//!
//! **Kept clear on purpose (review R20):** `record_key` (the heads' key, and
//! every per-session keychain account: changing it would mean re-keying
//! every keychain item outside the SQLite transaction), `session_id`,
//! `binding_digest`, `init_hash` and `generation` (random, or digests of
//! values no file holds in clear). Clear times only where a query needs
//! them, coarsened: `created_hour` (rounded down) for the newest-first
//! order, which Rust finishes from `meta` with the tie-break both nodes
//! share, `(created_at_ms DESC, init_id DESC)` (a node-local order once
//! wedged a pair for good); `prune_after_hour` (rounded up) for the prunes,
//! which then decide with the exact time from `meta`, so nothing goes early
//! or late. The reset table keeps a clear 0/1 flag where a query tests a
//! time for NULL (`confirmed`, `reset_round`, `retired`). What the comments
//! of this module and its siblings say of schema 2's heads and their
//! sidecars holds for schema 3 and 4 as well: PP.14 changed the endpoint
//! tables only, schema 4 the heads' `init_id` only.
//!
//! A profile that is not sealed keeps schema 1, today's columns. A clear (or
//! schema-2 or -3) store in a sealed profile moves to schema 4 with the
//! rebuild recipe of [`crate::sqlite_rebuild`] ([`migrate_forward`]) once
//! the open's journal recovery has finished on its old schema, and never
//! while a journal is still pending (it replays against the schema it was
//! written under): from the open itself, and eagerly from
//! `privacy::migrate_all` and the prune passes ([`migrate`]). [`unseal`] is
//! the way back (`raven privacy unseal`, PP.18). An older build refuses
//! every schema above the one it knows (`UnsupportedMetadataSchema`, fail
//! closed: it cannot send or receive until this build runs again). Without
//! the at-rest key a keyed store does not open
//! ([`IndexedSessionStoreError::MetaKeyUnavailable`]), never a clear
//! fallback. K_meta is not protected session state: the metadata-only reads
//! (expiry, the horizon, custody's heads) open `meta` without any keychain
//! item.

use std::collections::HashMap;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::*;
use crate::at_rest::{self, AtRestError, MetaKeys, Mode, ValueType};
use crate::sqlite_rebuild::{self as rebuild, Migration, RebuildError, RowReseal, Shape, Steps};

/// This store's row in `raven_schema`.
pub(super) const STORE: &str = "indexed_sessions";
/// Schema 1: today's clear columns (a profile that is not sealed, and every
/// older build).
pub(super) const CLEAR_VERSION: i64 = 1;
/// Schema 2 (PP.13): the heads and their sidecars keyed, the endpoint
/// tables clear. A PP.13 build's sealed store; this build moves it to
/// schema 4 ([`METADATA_SCHEMA_VERSION`]) as it moves a clear one.
pub(super) const HEADS_VERSION: i64 = 2;
/// Schema 3 (PP.14): the endpoint tables keyed too, the heads' `init_id`
/// still clear. A sealed store of the pack's builds before review
/// B-sealed-stores-1; this build moves it to schema 4.
pub(super) const ENDPOINTS_VERSION: i64 = 3;
/// The keyed column that tells the two shapes apart.
pub(super) const KEYED_COLUMN: &str = "kh_initiator_device";
/// The heads' keyed `init_id`: the column that tells schema 4 from 2 and 3.
pub(super) const INIT_KEYED_COLUMN: &str = "kh_init_id";

pub(super) const HEADS: &str = "indexed_session_heads";
pub(super) const RESET: &str = "indexed_session_reset";
pub(super) const LEDGER: &str = "endpoint_reseal_ledger";
pub(super) const PEER_STATE: &str = "peer_reset_state";
pub(super) const SESSION_END: &str = "peer_session_end";
pub(super) const ERASED: &str = "peer_session_end_erased";
/// Session renewal's per-contact state (Phase 3 item 4, [`super::renewal`]).
pub(super) const RENEWAL: &str = "peer_session_renewal";

/// Every table of the store, in the order the rebuild counts them: PP.13's
/// six, the endpoint tables (PP.14), session renewal's (Phase 3 item 4),
/// the horizon's parked and inbound-seen tables (Phase 5, P5.4) and the
/// letter sessions' (Phase 5, P5.12; a rebuild creates these first when an
/// older build left them out), every row still there after a move, with a
/// head to refer to.
pub(super) const ALL_TABLES: [&str; 17] = [
    HEADS,
    RESET,
    LEDGER,
    PEER_STATE,
    SESSION_END,
    ERASED,
    "endpoint_receipts",
    "endpoint_inbox",
    "endpoint_ack_intents",
    "endpoint_outstanding_messages",
    "endpoint_ack_receipts",
    "endpoint_outbox",
    "endpoint_inbox_deleted",
    RENEWAL,
    parked::PARKED,
    parked::SEEN,
    letters::LETTER,
];

/// A sealed value of the store: its table, its column, the AAD label it is
/// sealed under (the table for a `meta`, `<table>.<column>` for a sealed
/// wire object) and the columns the AAD binds (the primary key as stored,
/// in this order).
pub(super) type SealedColumn = (
    &'static str,
    &'static str,
    &'static str,
    &'static [&'static str],
);

/// The sealed values of schema 2 (PP.13): one `meta` per row.
const HEAD_SEALED: [SealedColumn; 6] = [
    (HEADS, "meta", HEADS, &["record_key"]),
    (RESET, "meta", RESET, &["session_id"]),
    (
        LEDGER,
        "meta",
        LEDGER,
        &["kh_recipient_device", "kh_message_id"],
    ),
    (PEER_STATE, "meta", PEER_STATE, &["kh_peer_device"]),
    (SESSION_END, "meta", SESSION_END, &["kh_peer_device"]),
    (ERASED, "meta", ERASED, &["kh_peer_device"]),
];

/// Session renewal's sealed value (Phase 3 item 4): one `meta` per row.
const RENEWAL_SEALED: SealedColumn = (RENEWAL, "meta", RENEWAL, &["kh_peer_device"]);

/// Every sealed value of a store in the shape `conn` has (session renewal's
/// once its table is there keyed: a store an older build sealed may not
/// have it yet).
fn sealed_columns(conn: &Connection) -> rusqlite::Result<Vec<SealedColumn>> {
    let mut all = HEAD_SEALED.to_vec();
    if endpoints::keyed(conn)? {
        all.extend_from_slice(&endpoints::SEALED);
    }
    if renewal::keyed(conn)? {
        all.push(RENEWAL_SEALED);
    }
    // The horizon's tables (Phase 5, P5.4), likewise.
    if parked::keyed(conn)? {
        all.extend_from_slice(&parked::SEALED);
    }
    // The letter sessions' (Phase 5, P5.12), likewise.
    if letters::keyed(conn)? {
        all.push(letters::SEALED);
    }
    Ok(all)
}

// ── The layout of an open store ──────────────────────────────────────────

/// How an open store holds the columns that name friends.
#[derive(Clone)]
pub(super) enum Layout {
    /// Schema 1: clear columns.
    Clear,
    /// Schema 2, 3 or 4: keyed lookups and sealed `meta` (the endpoint
    /// tables too since schema 3: [`Layout::endpoints`]; the heads'
    /// `init_id` in schema 4: [`Sealer::init_column`]).
    Keyed(Arc<Sealer>),
}

impl Layout {
    pub(super) fn keyed(&self) -> Option<&Sealer> {
        match self {
            Layout::Clear => None,
            Layout::Keyed(sealer) => Some(sealer),
        }
    }

    /// The sealer of a keyed store, to hold across a `&mut self` call.
    pub(super) fn sealer(&self) -> Option<Arc<Sealer>> {
        match self {
            Layout::Clear => None,
            Layout::Keyed(sealer) => Some(Arc::clone(sealer)),
        }
    }

    pub(super) fn is_keyed(&self) -> bool {
        matches!(self, Layout::Keyed(_))
    }

    /// The sealer of a schema-3 or -4 store, whose endpoint tables are keyed
    /// too (PP.14); `None` in schema 1 and 2.
    pub(super) fn endpoints(&self) -> Option<&Sealer> {
        self.keyed().filter(|sealer| sealer.endpoints)
    }

    /// The store is at schema 4: nothing is left to move.
    pub(super) fn is_current(&self) -> bool {
        self.keyed()
            .is_some_and(|sealer| sealer.endpoints && sealer.init_keyed)
    }
}

/// The at-rest keys a keyed handle seals and opens with. They are the
/// ones this process held when the store opened (one
/// [`at_rest::keys_cached`], never the keystore); a `meta` that names an
/// epoch they lack (a rotation since) is opened with the keys held now. A
/// write with keys a rotation has just replaced seals under the older
/// epoch, which stays readable through the grace and is sealed again before
/// it goes (review R04). The index key never changes, so `kh_*` values
/// survive every rotation.
pub(super) struct Sealer {
    data_dir: PathBuf,
    keys: Arc<MetaKeys>,
    /// The endpoint tables are keyed too (schema 3, PP.14); a schema-2
    /// store keeps them clear until it moves.
    endpoints: bool,
    /// The heads hold `init_id` keyed and in their `meta` (schema 4, review
    /// B-sealed-stores-1); a schema-2 or -3 store keeps it clear until it
    /// moves.
    init_keyed: bool,
}

impl Sealer {
    /// The keys this process loaded for `data_dir` (no keystore call).
    pub(super) fn cached(data_dir: &Path) -> Result<Arc<Self>, IndexedSessionStoreError> {
        let keys = at_rest::keys_cached(data_dir)
            .map_err(|e| IndexedSessionStoreError::MetaKeyUnavailable(e.to_string()))?;
        Ok(Arc::new(Self {
            data_dir: data_dir.to_path_buf(),
            keys,
            endpoints: false,
            init_keyed: false,
        }))
    }

    /// The same keys for a store whose endpoint tables and heads' `init_id`
    /// are keyed or not ([`store_shape`]).
    pub(super) fn with_shape(&self, (endpoints, init_keyed): (bool, bool)) -> Arc<Self> {
        Arc::new(Self {
            data_dir: self.data_dir.clone(),
            keys: Arc::clone(&self.keys),
            endpoints,
            init_keyed,
        })
    }

    /// The heads' `init_id` column in this store's shape: `kh_init_id` in
    /// schema 4, the clear `init_id` in schema 2 and 3.
    pub(super) fn init_column(&self) -> &'static str {
        if self.init_keyed {
            INIT_KEYED_COLUMN
        } else {
            "init_id"
        }
    }

    /// What [`Self::init_column`] holds for `init_id`.
    pub(super) fn init_value(&self, init_id: &[u8; 16]) -> Vec<u8> {
        if self.init_keyed {
            self.nonce(init_id).to_vec()
        } else {
            init_id.to_vec()
        }
    }

    /// Whether the heads keep `init_id` in their `meta` (schema 4).
    pub(super) fn init_keyed(&self) -> bool {
        self.init_keyed
    }

    pub(super) fn device(&self, device: &[u8]) -> [u8; 32] {
        at_rest::index(&self.keys, ValueType::DeviceKey, device)
    }

    pub(super) fn address(&self, address: &str) -> [u8; 32] {
        at_rest::index(&self.keys, ValueType::Rvn1Address, address.as_bytes())
    }

    pub(super) fn message_id(&self, message_id: &[u8]) -> [u8; 32] {
        at_rest::index(&self.keys, ValueType::MessageId, message_id)
    }

    pub(super) fn digest(&self, digest: &[u8]) -> [u8; 32] {
        at_rest::index(&self.keys, ValueType::ObjectDigest, digest)
    }

    pub(super) fn nonce(&self, nonce: &[u8]) -> [u8; 32] {
        at_rest::index(&self.keys, ValueType::Nonce, nonce)
    }

    /// The keyed digest of stored wire bytes (`kh_envelope`, `kh_ack`).
    pub(super) fn object_bytes(&self, bytes: &[u8]) -> [u8; 32] {
        at_rest::index(&self.keys, ValueType::ObjectBytes, bytes)
    }

    /// `bytes` sealed as the column `label` (`<table>.<column>`) of the row
    /// whose key is `pk`.
    pub(super) fn seal_bytes(&self, label: &str, pk: &[u8], bytes: &[u8]) -> Vec<u8> {
        at_rest::seal_row(&self.keys, label, pk, bytes)
    }

    /// [`Self::seal_bytes`] opened, as [`Self::open`] opens a `meta`.
    pub(super) fn open_bytes(
        &self,
        label: &str,
        pk: &[u8],
        blob: &[u8],
    ) -> Result<Vec<u8>, IndexedSessionStoreError> {
        let plain = match at_rest::open_row(&self.keys, label, pk, blob) {
            Err(AtRestError::StaleKeys { .. }) => {
                let now = at_rest::keys_cached(&self.data_dir).map_err(meta_error)?;
                at_rest::open_row(&now, label, pk, blob)
            }
            opened => opened,
        }
        .map_err(meta_error)?;
        Ok(plain.to_vec())
    }

    /// `value` sealed as the `meta` of `table`'s row whose key is `pk`.
    pub(super) fn seal<T: Serialize>(&self, table: &str, pk: &[u8], value: &T) -> Vec<u8> {
        let plain =
            Zeroizing::new(serde_json::to_vec(value).expect("strings and numbers serialize"));
        at_rest::seal_row(&self.keys, table, pk, &plain)
    }

    /// The `meta` of `table`'s row whose key is `pk`. A key this process has
    /// not loaded fails the store ([`IndexedSessionStoreError::MetaKeyUnavailable`]);
    /// a blob that does not open (or names an epoch no key holds) is that
    /// row's corruption ([`IndexedSessionStoreError::CorruptEndpointState`]).
    pub(super) fn open<T: DeserializeOwned>(
        &self,
        table: &str,
        pk: &[u8],
        blob: &[u8],
    ) -> Result<T, IndexedSessionStoreError> {
        let plain = match at_rest::open_row(&self.keys, table, pk, blob) {
            Err(AtRestError::StaleKeys { .. }) => {
                let now = at_rest::keys_cached(&self.data_dir).map_err(meta_error)?;
                at_rest::open_row(&now, table, pk, blob)
            }
            opened => opened,
        }
        .map_err(meta_error)?;
        serde_json::from_slice(&plain).map_err(|_| IndexedSessionStoreError::CorruptEndpointState)
    }

    pub(super) fn meta_keys(&self) -> &MetaKeys {
        &self.keys
    }
}

fn meta_error(error: AtRestError) -> IndexedSessionStoreError {
    match error {
        AtRestError::KeyUnavailable(_) | AtRestError::KeyLost(_) => {
            IndexedSessionStoreError::MetaKeyUnavailable(error.to_string())
        }
        _ => IndexedSessionStoreError::CorruptEndpointState,
    }
}

/// A clear device value from a `meta` (hex).
pub(super) fn device_of(hex_value: &str) -> Result<[u8; 32], IndexedSessionStoreError> {
    exact_array(
        &hex::decode(hex_value).map_err(|_| IndexedSessionStoreError::CorruptEndpointState)?,
    )
}

/// A schema-4 head's `init_id` from its `meta` (hex; a meta without one is
/// corrupt).
pub(super) fn init_id_of(hex_value: &str) -> Result<[u8; 16], IndexedSessionStoreError> {
    exact_array(
        &hex::decode(hex_value).map_err(|_| IndexedSessionStoreError::CorruptEndpointState)?,
    )
}

// ── Sealed values ────────────────────────────────────────────────────────

/// A schema-2 head's clear values (times exactly as schema 1 holds them).
#[derive(Serialize, Deserialize)]
pub(super) struct HeadMeta {
    pub initiator_address: String,
    pub responder_address: String,
    pub initiator_device: String,
    pub responder_device: String,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    /// The `init_id` (hex) in schema 4, whose clear column is gone (review
    /// B-sealed-stores-1); empty, and not written, in schema 2 and 3, which
    /// keep it in their clear column (older builds' metas have no such
    /// field).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub init_id: String,
}

/// A schema-2 reset row's clear values; the flags beside it say which are set.
#[derive(Serialize, Deserialize, Clone, Default)]
pub(super) struct ResetMeta {
    pub peer_device: String,
    pub confirmed_at_ms: Option<i64>,
    pub reset_round_at_ms: Option<i64>,
    pub retired_at_ms: Option<i64>,
}

#[derive(Serialize, Deserialize)]
pub(super) struct LedgerMeta {
    pub recipient_device: String,
    pub message_id: String,
    pub last_reseal_at_ms: i64,
    pub expires_at_ms: i64,
}

#[derive(Serialize, Deserialize, Default)]
pub(super) struct PeerStateMeta {
    pub peer_device: String,
    pub fork_evidence_at_ms: Option<i64>,
    pub user_confirmed_at_ms: Option<i64>,
}

#[derive(Serialize, Deserialize)]
pub(super) struct SessionEndMeta {
    pub peer_device: String,
    pub ended_at_ms: i64,
}

#[derive(Serialize, Deserialize)]
pub(super) struct ErasedMeta {
    pub peer_device: String,
    pub created_to_ms: i64,
}

/// A schema-4 renewal row's values (Phase 3 item 4, [`super::renewal`]):
/// every one but the keyed device, times exactly as schema 1 holds them.
#[derive(Serialize, Deserialize, Default)]
pub(super) struct RenewalMeta {
    pub peer_device: String,
    pub window_start_ms: i64,
    pub attempts_in_window: i64,
    pub last_attempt_at_ms: Option<i64>,
    pub failures: i64,
    pub last_session_expires_at_ms: Option<i64>,
    /// The PairInit as it went on the wire (hex), whose PairResponse was
    /// lost; empty, and not written, when there is none.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub pending_init: String,
    pub pending_expires_at_ms: Option<i64>,
    /// Phase 6b R2 (step P6.27): a pending early re-key, its reason (a
    /// `SecKind` code) and the last one taken; not written while unset, so a
    /// row without them seals as before and older builds ignore them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub early_requested_at_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub early_reason: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_early_ms: Option<i64>,
}

/// The clear hour of a time, rounded down (the heads' `created_hour`).
pub(super) fn hour_down(at_ms: i64) -> i64 {
    rebuild::hour_of(u64::try_from(at_ms).unwrap_or(0))
}

/// `prune_after_hour` of an expiry held as schema 1 holds it.
pub(super) fn prune_hour(expires_at_ms: i64) -> i64 {
    rebuild::prune_after_hour(u64::try_from(expires_at_ms).unwrap_or(0))
}

/// The prune hours whose rows may have expired by `cutoff` (`expires <=
/// cutoff`): a prune looks at these and decides with the exact time.
pub(super) fn may_have_expired(cutoff: i64) -> i64 {
    rebuild::hour_of(u64::try_from(cutoff).unwrap_or(0)).saturating_add(1)
}

/// The prune hours whose rows have expired by `cutoff` for sure (a row whose
/// `meta` does not open goes by its hour alone).
pub(super) fn surely_expired(hour: i64, cutoff: i64) -> bool {
    hour <= rebuild::hour_of(u64::try_from(cutoff).unwrap_or(0))
}

// ── A head, in either layout ─────────────────────────────────────────────

/// A head's identity and times.
#[derive(Clone)]
pub(super) struct Head {
    pub key: IndexedSessionRecordKey,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
}

/// The head columns a query reads (eight in either layout, so the columns
/// after them keep their places), from `alias` (`"h."`, or `""`).
pub(super) fn head_columns(layout: &Layout, alias: &str) -> String {
    let a = alias;
    match layout {
        Layout::Clear => format!(
            "{a}profile_id, {a}initiator_address, {a}responder_address, {a}initiator_device, \
             {a}responder_device, {a}init_id, {a}created_at_ms, {a}expires_at_ms"
        ),
        // Schema 4: the `init_id` is in the meta (no clear column).
        Layout::Keyed(sealer) if sealer.init_keyed => {
            format!("{a}record_key, {a}profile_id, NULL, {a}meta, NULL, NULL, NULL, NULL")
        }
        Layout::Keyed(_) => {
            format!("{a}record_key, {a}profile_id, {a}init_id, {a}meta, NULL, NULL, NULL, NULL")
        }
    }
}

/// [`head_columns`] as read from a row.
pub(super) enum RawHead {
    Clear {
        profile_id: Vec<u8>,
        initiator_address: String,
        responder_address: String,
        initiator_device: Vec<u8>,
        responder_device: Vec<u8>,
        init_id: Vec<u8>,
        created_at_ms: i64,
        expires_at_ms: i64,
    },
    Keyed {
        record_key: Vec<u8>,
        profile_id: Vec<u8>,
        /// The clear column of schema 2 and 3; `None` in schema 4 (the
        /// meta holds it).
        init_id: Option<Vec<u8>>,
        meta: Vec<u8>,
    },
}

/// The eight [`head_columns`] from `row`, starting at column `at`.
pub(super) fn raw_head(
    layout: &Layout,
    row: &rusqlite::Row<'_>,
    at: usize,
) -> rusqlite::Result<RawHead> {
    Ok(match layout {
        Layout::Clear => RawHead::Clear {
            profile_id: row.get(at)?,
            initiator_address: row.get(at + 1)?,
            responder_address: row.get(at + 2)?,
            initiator_device: row.get(at + 3)?,
            responder_device: row.get(at + 4)?,
            init_id: row.get(at + 5)?,
            created_at_ms: row.get(at + 6)?,
            expires_at_ms: row.get(at + 7)?,
        },
        Layout::Keyed(_) => RawHead::Keyed {
            record_key: row.get(at)?,
            profile_id: row.get(at + 1)?,
            init_id: row.get(at + 2)?,
            meta: row.get(at + 3)?,
        },
    })
}

impl RawHead {
    /// The head's record key as stored (schema 2), for a cache.
    pub(super) fn stored_key(&self) -> Option<&[u8]> {
        match self {
            RawHead::Clear { .. } => None,
            RawHead::Keyed { record_key, .. } => Some(record_key),
        }
    }
}

impl Layout {
    /// The head a row names (its `meta` opened in schema 2).
    pub(super) fn head(&self, raw: RawHead) -> Result<Head, IndexedSessionStoreError> {
        match (self, raw) {
            (
                _,
                RawHead::Clear {
                    profile_id,
                    initiator_address,
                    responder_address,
                    initiator_device,
                    responder_device,
                    init_id,
                    created_at_ms,
                    expires_at_ms,
                },
            ) => Ok(Head {
                key: record_key_from_columns(
                    profile_id,
                    initiator_address,
                    responder_address,
                    &initiator_device,
                    &responder_device,
                    &init_id,
                )?,
                created_at_ms,
                expires_at_ms,
            }),
            (
                Layout::Keyed(sealer),
                RawHead::Keyed {
                    record_key,
                    profile_id,
                    init_id,
                    meta,
                },
            ) => {
                let meta: HeadMeta = sealer.open(HEADS, &record_key, &meta)?;
                let init_id = match init_id {
                    Some(clear) => exact_array(&clear)?,
                    None => init_id_of(&meta.init_id)?,
                };
                Ok(Head {
                    key: IndexedSessionRecordKey {
                        profile_id,
                        initiator_address: meta.initiator_address,
                        responder_address: meta.responder_address,
                        initiator_device_ed25519: device_of(&meta.initiator_device)?,
                        responder_device_ed25519: device_of(&meta.responder_device)?,
                        init_id,
                    },
                    created_at_ms: meta.created_at_ms,
                    expires_at_ms: meta.expires_at_ms,
                })
            }
            (Layout::Clear, RawHead::Keyed { .. }) => {
                Err(IndexedSessionStoreError::CorruptEndpointState)
            }
        }
    }

    /// [`Self::head`] through `cache` (one listing opens each head's `meta`
    /// once however many rows name it). A head that cannot be read (a
    /// `meta` that does not open: a changed byte, an epoch no key holds) is
    /// `None`, logged once: the listing goes on past its session's rows,
    /// which that session's prune removes by its hour (review
    /// B-sealed-stores-2: it used to fail `raven inbox` until then). Without
    /// the at-rest key it fails (closed).
    pub(super) fn head_cached(
        &self,
        raw: RawHead,
        cache: &mut HashMap<Vec<u8>, Option<Head>>,
    ) -> Result<Option<Head>, IndexedSessionStoreError> {
        let stored = raw.stored_key().map(<[u8]>::to_vec);
        if let Some(head) = stored.as_ref().and_then(|stored| cache.get(stored)) {
            return Ok(head.clone());
        }
        let head = match self.head(raw) {
            Ok(head) => Some(head),
            Err(error @ IndexedSessionStoreError::MetaKeyUnavailable(_)) => return Err(error),
            Err(error) if is_session_scoped_state_error(&error) => {
                log_skipped_session(stored.as_deref().unwrap_or_default(), &error);
                None
            }
            Err(error) => return Err(error),
        };
        if let Some(stored) = stored {
            cache.insert(stored, head.clone());
        }
        Ok(head)
    }
}

/// Newest first with the tie-break both nodes share (`created_at_ms DESC,
/// init_id DESC`, `key` giving both): the SQL orders by the clear hour at
/// most, Rust finishes it.
pub(super) fn newest_first_by<T>(rows: &mut [T], key: impl Fn(&T) -> (i64, [u8; 16])) {
    rows.sort_by_key(|row| std::cmp::Reverse(key(row)));
}

// ── Schemas ──────────────────────────────────────────────────────────────

/// `indexed_session_heads`'s columns in either shape this build writes:
/// schema 4's keyed ones, or the clear ones exactly as every build before
/// PP.13 creates them.
pub(super) fn heads_columns(keyed: bool) -> &'static str {
    if keyed {
        "record_key BLOB PRIMARY KEY NOT NULL CHECK(length(record_key) = 32),
         binding_digest BLOB NOT NULL CHECK(length(binding_digest) = 32),
         profile_id BLOB NOT NULL,
         kh_initiator_address BLOB NOT NULL CHECK(length(kh_initiator_address) = 32),
         kh_responder_address BLOB NOT NULL CHECK(length(kh_responder_address) = 32),
         kh_initiator_device BLOB NOT NULL CHECK(length(kh_initiator_device) = 32),
         kh_responder_device BLOB NOT NULL CHECK(length(kh_responder_device) = 32),
         kh_init_id BLOB NOT NULL CHECK(length(kh_init_id) = 32),
         init_hash BLOB NOT NULL CHECK(length(init_hash) = 32),
         session_id BLOB NOT NULL UNIQUE CHECK(length(session_id) = 32),
         generation INTEGER NOT NULL CHECK(generation >= 0),
         created_hour INTEGER NOT NULL,
         prune_after_hour INTEGER NOT NULL,
         meta BLOB NOT NULL,
         UNIQUE(profile_id, kh_initiator_address, kh_responder_address,
                kh_initiator_device, kh_responder_device, kh_init_id)"
    } else {
        "record_key BLOB PRIMARY KEY NOT NULL CHECK(length(record_key) = 32),
         binding_digest BLOB NOT NULL CHECK(length(binding_digest) = 32),
         profile_id BLOB NOT NULL,
         initiator_address TEXT NOT NULL,
         responder_address TEXT NOT NULL,
         initiator_device BLOB NOT NULL CHECK(length(initiator_device) = 32),
         responder_device BLOB NOT NULL CHECK(length(responder_device) = 32),
         init_id BLOB NOT NULL CHECK(length(init_id) = 16),
         init_hash BLOB NOT NULL CHECK(length(init_hash) = 32),
         session_id BLOB NOT NULL UNIQUE CHECK(length(session_id) = 32),
         generation INTEGER NOT NULL CHECK(generation >= 0),
         created_at_ms INTEGER NOT NULL,
         expires_at_ms INTEGER NOT NULL,
         UNIQUE(profile_id, initiator_address, responder_address,
                initiator_device, responder_device, init_id)"
    }
}

/// The heads' columns in schema 2 and 3 (the pack's builds before review
/// B-sealed-stores-1): keyed but for the clear `init_id`. This build only
/// moves such a store on (and its tests make one, as those builds did).
pub(super) const HEADS_COLUMNS_INIT_CLEAR: &str =
    "record_key BLOB PRIMARY KEY NOT NULL CHECK(length(record_key) = 32),
     binding_digest BLOB NOT NULL CHECK(length(binding_digest) = 32),
     profile_id BLOB NOT NULL,
     kh_initiator_address BLOB NOT NULL CHECK(length(kh_initiator_address) = 32),
     kh_responder_address BLOB NOT NULL CHECK(length(kh_responder_address) = 32),
     kh_initiator_device BLOB NOT NULL CHECK(length(kh_initiator_device) = 32),
     kh_responder_device BLOB NOT NULL CHECK(length(kh_responder_device) = 32),
     init_id BLOB NOT NULL CHECK(length(init_id) = 16),
     init_hash BLOB NOT NULL CHECK(length(init_hash) = 32),
     session_id BLOB NOT NULL UNIQUE CHECK(length(session_id) = 32),
     generation INTEGER NOT NULL CHECK(generation >= 0),
     created_hour INTEGER NOT NULL,
     prune_after_hour INTEGER NOT NULL,
     meta BLOB NOT NULL,
     UNIQUE(profile_id, kh_initiator_address, kh_responder_address,
            kh_initiator_device, kh_responder_device, init_id)";

/// The heads' index, under the same name in every shape (an older build's
/// `CREATE ... IF NOT EXISTS` batch is then a no-op on a migrated store):
/// on the clear `init_id` in schema 1 to 3 ...
pub(super) const INIT_ID_INDEX: &str =
    "CREATE UNIQUE INDEX IF NOT EXISTS indexed_session_init_id_unique
     ON indexed_session_heads(init_id);";

/// ... and on `kh_init_id` in schema 4.
pub(super) const KH_INIT_ID_INDEX: &str =
    "CREATE UNIQUE INDEX IF NOT EXISTS indexed_session_init_id_unique
     ON indexed_session_heads(kh_init_id);";

/// Whether a store's heads hold `init_id` keyed (schema 4).
pub(super) fn init_keyed(conn: &Connection) -> rusqlite::Result<bool> {
    Ok(rebuild::columns(conn, HEADS)?
        .iter()
        .any(|column| column == INIT_KEYED_COLUMN))
}

/// A keyed store's shape, as [`Sealer::with_shape`] takes it: whether its
/// endpoint tables are keyed (schema 3 on) and whether its heads hold
/// `init_id` keyed (schema 4).
pub(super) fn store_shape(conn: &Connection) -> rusqlite::Result<(bool, bool)> {
    Ok((endpoints::keyed(conn)?, init_keyed(conn)?))
}

/// The reset sidecar's table. `retire_cause` takes 1-7 since step P6.27
/// (7: `LocalSecurityRekey`); a table made with the 1-6 CHECK is widened
/// in place before its first cause-7 row ([`super::reset`]).
pub(super) fn reset_columns(keyed: bool) -> &'static str {
    if keyed {
        "session_id      BLOB PRIMARY KEY NOT NULL CHECK(length(session_id) = 32),
         kh_peer_device  BLOB NOT NULL CHECK(length(kh_peer_device) = 32),
         confirmed       INTEGER NOT NULL DEFAULT 0 CHECK(confirmed IN (0, 1)),
         initiated_local INTEGER NOT NULL DEFAULT 0 CHECK(initiated_local IN (0, 1)),
         reset_round     INTEGER NOT NULL DEFAULT 0 CHECK(reset_round IN (0, 1)),
         retired         INTEGER NOT NULL DEFAULT 0 CHECK(retired IN (0, 1)),
         retire_cause    INTEGER CHECK(retire_cause IS NULL OR retire_cause BETWEEN 1 AND 7),
         meta            BLOB NOT NULL,
         CHECK((retired = 0) = (retire_cause IS NULL)),
         FOREIGN KEY(session_id) REFERENCES indexed_session_heads(session_id) ON DELETE CASCADE"
    } else {
        "session_id        BLOB PRIMARY KEY NOT NULL CHECK(length(session_id) = 32),
         peer_device       BLOB NOT NULL CHECK(length(peer_device) = 32),
         confirmed_at_ms   INTEGER CHECK(confirmed_at_ms IS NULL OR confirmed_at_ms >= 0),
         initiated_local   INTEGER NOT NULL DEFAULT 0 CHECK(initiated_local IN (0, 1)),
         reset_round_at_ms INTEGER CHECK(reset_round_at_ms IS NULL OR reset_round_at_ms >= 0),
         retired_at_ms     INTEGER CHECK(retired_at_ms IS NULL OR retired_at_ms >= 0),
         retire_cause      INTEGER CHECK(retire_cause IS NULL OR retire_cause BETWEEN 1 AND 7),
         CHECK((retired_at_ms IS NULL) = (retire_cause IS NULL)),
         FOREIGN KEY(session_id) REFERENCES indexed_session_heads(session_id) ON DELETE CASCADE"
    }
}

pub(super) fn reset_index(keyed: bool) -> &'static str {
    if keyed {
        "CREATE INDEX IF NOT EXISTS indexed_session_reset_peer
         ON indexed_session_reset(kh_peer_device);"
    } else {
        "CREATE INDEX IF NOT EXISTS indexed_session_reset_peer
         ON indexed_session_reset(peer_device);"
    }
}

pub(super) fn ledger_columns(keyed: bool) -> &'static str {
    if keyed {
        "kh_recipient_device BLOB NOT NULL CHECK(length(kh_recipient_device) = 32),
         kh_message_id       BLOB NOT NULL CHECK(length(kh_message_id) = 32),
         reseals             INTEGER NOT NULL CHECK(reseals BETWEEN 1 AND 255),
         notified            INTEGER NOT NULL DEFAULT 0 CHECK(notified IN (0, 1)),
         prune_after_hour    INTEGER NOT NULL,
         meta                BLOB NOT NULL,
         PRIMARY KEY(kh_recipient_device, kh_message_id)"
    } else {
        "recipient_device  BLOB NOT NULL CHECK(length(recipient_device) = 32),
         message_id        BLOB NOT NULL CHECK(length(message_id) = 16),
         reseals           INTEGER NOT NULL CHECK(reseals BETWEEN 1 AND 255),
         last_reseal_at_ms INTEGER NOT NULL CHECK(last_reseal_at_ms >= 0),
         expires_at_ms     INTEGER NOT NULL CHECK(expires_at_ms >= 0),
         notified          INTEGER NOT NULL DEFAULT 0 CHECK(notified IN (0, 1)),
         PRIMARY KEY(recipient_device, message_id)"
    }
}

pub(super) fn peer_state_columns(keyed: bool) -> &'static str {
    if keyed {
        "kh_peer_device BLOB PRIMARY KEY NOT NULL CHECK(length(kh_peer_device) = 32),
         meta           BLOB NOT NULL"
    } else {
        "peer_device          BLOB PRIMARY KEY NOT NULL CHECK(length(peer_device) = 32),
         fork_evidence_at_ms  INTEGER CHECK(fork_evidence_at_ms IS NULL OR fork_evidence_at_ms >= 0),
         user_confirmed_at_ms INTEGER CHECK(user_confirmed_at_ms IS NULL OR user_confirmed_at_ms >= 0)"
    }
}

pub(super) fn session_end_columns(keyed: bool) -> &'static str {
    if keyed {
        "kh_peer_device   BLOB PRIMARY KEY NOT NULL CHECK(length(kh_peer_device) = 32),
         prune_after_hour INTEGER NOT NULL,
         meta             BLOB NOT NULL"
    } else {
        "peer_device BLOB PRIMARY KEY NOT NULL CHECK(length(peer_device) = 32),
         ended_at_ms INTEGER NOT NULL CHECK(ended_at_ms >= 0)"
    }
}

pub(super) fn erased_columns(keyed: bool) -> &'static str {
    if keyed {
        "kh_peer_device BLOB PRIMARY KEY NOT NULL CHECK(length(kh_peer_device) = 32),
         meta           BLOB NOT NULL"
    } else {
        "peer_device BLOB PRIMARY KEY NOT NULL CHECK(length(peer_device) = 32),
         created_to_ms INTEGER NOT NULL CHECK(created_to_ms >= 0)"
    }
}

/// Session renewal's table (Phase 3 item 4, [`super::renewal`]): schema 1's
/// clear columns, or schema 4's keyed device, a prune hour and a sealed
/// `meta` with every other value (the pending PairInit names both devices).
pub(super) fn renewal_columns(keyed: bool) -> &'static str {
    if keyed {
        "kh_peer_device   BLOB PRIMARY KEY NOT NULL CHECK(length(kh_peer_device) = 32),
         prune_after_hour INTEGER NOT NULL,
         meta             BLOB NOT NULL"
    } else {
        "peer_device                BLOB PRIMARY KEY NOT NULL CHECK(length(peer_device) = 32),
         window_start_ms            INTEGER NOT NULL DEFAULT 0 CHECK(window_start_ms >= 0),
         attempts_in_window         INTEGER NOT NULL DEFAULT 0
                                    CHECK(attempts_in_window BETWEEN 0 AND 255),
         last_attempt_at_ms         INTEGER CHECK(last_attempt_at_ms IS NULL OR last_attempt_at_ms >= 0),
         failures                   INTEGER NOT NULL DEFAULT 0 CHECK(failures BETWEEN 0 AND 255),
         last_session_expires_at_ms INTEGER
                                    CHECK(last_session_expires_at_ms IS NULL
                                          OR last_session_expires_at_ms >= 0),
         pending_init               BLOB CHECK(pending_init IS NULL OR length(pending_init) <= 8192),
         pending_expires_at_ms      INTEGER
                                    CHECK((pending_init IS NULL) = (pending_expires_at_ms IS NULL)),
         early_requested_at_ms INTEGER CHECK(early_requested_at_ms IS NULL OR early_requested_at_ms >= 0),
         early_reason INTEGER CHECK(early_reason IS NULL OR early_reason BETWEEN 0 AND 65535),
         last_early_ms INTEGER CHECK(last_early_ms IS NULL OR last_early_ms >= 0)"
    }
}

/// The clear renewal table's early re-key columns (Phase 6b R2, step P6.27),
/// exactly as [`renewal_columns`] writes them: a table an older build made
/// gets them with `ALTER TABLE ... ADD COLUMN` ([`super::renewal`]).
pub(super) const RENEWAL_EARLY_COLUMNS: [(&str, &str); 3] = [
    (
        "early_requested_at_ms",
        "INTEGER CHECK(early_requested_at_ms IS NULL OR early_requested_at_ms >= 0)",
    ),
    (
        "early_reason",
        "INTEGER CHECK(early_reason IS NULL OR early_reason BETWEEN 0 AND 65535)",
    ),
    (
        "last_early_ms",
        "INTEGER CHECK(last_early_ms IS NULL OR last_early_ms >= 0)",
    ),
];

/// `CREATE TABLE IF NOT EXISTS <table> (<columns>);`
pub(super) fn create_if_missing(table: &str, columns: &str) -> String {
    format!("CREATE TABLE IF NOT EXISTS {table} ({columns});")
}

/// Schema 1, as every build before PP.13 creates it at each open (`CREATE
/// ... IF NOT EXISTS`, outside a transaction: no write lock when the
/// tables are there).
fn create_clear(conn: &Connection) -> Result<(), IndexedSessionStoreError> {
    conn.execute_batch(&create_if_missing(HEADS, heads_columns(false)))?;
    conn.execute_batch(INIT_ID_INDEX)?;
    conn.execute_batch(ENDPOINT_SCHEMA)?;
    // Session-reset sidecar (lost-state recovery), the session ends (CP.6),
    // the user's inbox deletions (PP.8): additive tables of schema 1.
    reset::create_reset_schema(conn)?;
    // Session renewal (Phase 3 item 4): additive in schema 1 too.
    renewal::create_renewal_schema(conn)?;
    // The horizon's parked and inbound-seen tables (Phase 5, P5.4): additive
    // in schema 1 too.
    parked::create_parked_schema(conn)?;
    // The letter sessions (Phase 5, P5.12): additive in schema 1 too.
    letters::create_letter_schema(conn)?;
    horizon::create_horizon_schema(conn)?;
    deleted::create_deleted_schema(conn)?;
    Ok(())
}

/// A sealed profile's first store, at schema 4, in one IMMEDIATE
/// transaction. A racing creator's store is kept as it is.
fn create_keyed(conn: &mut Connection) -> Result<(), IndexedSessionStoreError> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let _in_tx = crate::paths::HeldMark::transaction();
    if table_count(&tx)? == 0 {
        tx.execute_batch(&create_if_missing(HEADS, heads_columns(true)))?;
        tx.execute_batch(KH_INIT_ID_INDEX)?;
        endpoints::create_keyed(&tx)?;
        tx.execute_batch(&create_if_missing(RESET, reset_columns(true)))?;
        tx.execute_batch(reset_index(true))?;
        tx.execute_batch(&create_if_missing(LEDGER, ledger_columns(true)))?;
        tx.execute_batch(&create_if_missing(PEER_STATE, peer_state_columns(true)))?;
        tx.execute_batch(&create_if_missing(SESSION_END, session_end_columns(true)))?;
        tx.execute_batch(&create_if_missing(ERASED, erased_columns(true)))?;
        tx.execute_batch(&create_if_missing(RENEWAL, renewal_columns(true)))?;
        parked::ensure_tables(&tx, true)?;
        letters::ensure_table(&tx, true)?;
        rebuild::record(&tx, STORE, METADATA_SCHEMA_VERSION, false)?;
    }
    tx.commit()?;
    Ok(())
}

fn table_count(conn: &Connection) -> rusqlite::Result<i64> {
    conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'",
        [],
        |r| r.get(0),
    )
}

/// Stamp schema 1 on a store from before versioning (`user_version` 0), in
/// an IMMEDIATE transaction that reads the version and the shape again.
fn stamp_clear(conn: &mut Connection) -> Result<(), IndexedSessionStoreError> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let _in_tx = crate::paths::HeldMark::transaction();
    if rebuild::user_version(&tx)? < CLEAR_VERSION
        && rebuild::shape(&tx, HEADS, KEYED_COLUMN)? != Shape::Keyed
    {
        tx.pragma_update(None, "user_version", CLEAR_VERSION)?;
    }
    tx.commit()?;
    Ok(())
}

/// What one round of [`prepare_schema`] reads.
struct Round {
    version: i64,
    recorded: Option<i64>,
    heads: Shape,
    /// How many tables the file has.
    tables: i64,
    /// [`store_shape`]: whether the endpoint tables are keyed, and (keyed
    /// heads only) whether the heads hold `init_id` keyed.
    store: (bool, bool),
}

/// A round's reads, from one snapshot (one read transaction, ended before
/// any write; review C-1): another opener's create or move commits before
/// or after all of them, never between two (its keyed create seen as
/// "heads missing, tables there, endpoint tables keyed" failed the open).
fn read_round(conn: &mut Connection) -> Result<Round, IndexedSessionStoreError> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let _in_tx = crate::paths::HeldMark::transaction();
    let version = rebuild::user_version(&tx)?;
    let recorded = rebuild::recorded(&tx, STORE)?.map(|(version, _)| version);
    let heads = rebuild::shape(&tx, HEADS, KEYED_COLUMN)?;
    #[cfg(test)]
    schema_hook::run(schema_hook::At::MidRead);
    let tables = table_count(&tx)?;
    let store = if heads == Shape::Keyed {
        store_shape(&tx)?
    } else {
        (endpoints::keyed(&tx)?, false)
    };
    tx.commit()?;
    Ok(Round {
        version,
        recorded,
        heads,
        tables,
        store,
    })
}

/// The open's schema step: read the version, its `raven_schema` row and the
/// heads' and the endpoint tables' shape (review R06: by shape, not by
/// `user_version` alone); refuse a newer schema; create a missing store in
/// the shape the profile's mode asks for (schema 4 in a sealed profile);
/// stamp again a keyed store an older process stamped with its own number.
/// Writes happen in IMMEDIATE transactions that read the version again; an
/// open with nothing to write takes no write lock. A clear, schema-2 or
/// schema-3 store in a sealed profile stays as it is here: the open moves
/// it after its journal recovery ([`IndexedSessionStore`]'s
/// `move_to_keyed`).
pub(super) fn prepare_schema(
    conn: &mut Connection,
    data_dir: &Path,
) -> Result<Layout, IndexedSessionStoreError> {
    let sealed = profile_seals(data_dir);
    // Before anything is created: no key, no store (never a clear one).
    let sealer = if sealed {
        Some(Sealer::cached(data_dir)?)
    } else {
        None
    };
    // Three rounds at most: create, then open what is there (a racing
    // creator may leave either shape, a seal or an unseal may move it).
    for _ in 0..3 {
        let seen = read_round(conn)?;
        let (version, recorded) = (seen.version, seen.recorded);
        let newest = version.max(recorded.unwrap_or(0));
        if newest > METADATA_SCHEMA_VERSION {
            return Err(IndexedSessionStoreError::UnsupportedMetadataSchema(newest));
        }
        match seen.heads {
            Shape::Keyed => {
                // A keyed store opens only with the keys, whatever the mode.
                let sealer = match sealer {
                    Some(ref sealer) => Arc::clone(sealer),
                    None => Sealer::cached(data_dir)?,
                };
                // Schema 4, or an older build's 3 (the heads' `init_id`
                // clear) or a PP.13 build's 2 (the endpoint tables clear
                // too): the open moves those after its journal recovery.
                let shape = seen.store;
                let expected = match shape {
                    (true, true) => METADATA_SCHEMA_VERSION,
                    (true, false) => ENDPOINTS_VERSION,
                    (false, false) => HEADS_VERSION,
                    (false, true) => {
                        return Err(IndexedSessionStoreError::MetadataMigration(
                            "the session store's tables disagree on their schema".into(),
                        ))
                    }
                };
                #[cfg(test)]
                schema_hook::run(schema_hook::At::BeforeWrite);
                if version != expected || recorded != Some(expected) {
                    rebuild::restamp(conn, STORE, expected)?;
                }
                // Session renewal's table (Phase 3 item 4): additive, keyed
                // here (a store an older build sealed gets it now). An
                // unseal that moved the store back since: open what is there.
                if !renewal::ensure_keyed(conn, sealer.meta_keys())? {
                    continue;
                }
                // The horizon's tables (Phase 5, P5.4) the same way.
                if !parked::ensure_keyed(conn, sealer.meta_keys())? {
                    continue;
                }
                // The letter sessions' table (Phase 5, P5.12) too.
                if !letters::ensure_keyed(conn, sealer.meta_keys())? {
                    continue;
                }
                return Ok(Layout::Keyed(sealer.with_shape(shape)));
            }
            Shape::Missing if sealed && !test_switch::creates_clear() && seen.tables == 0 => {
                create_keyed(conn)?;
            }
            Shape::Missing | Shape::Clear => {
                if seen.store.0 {
                    return Err(IndexedSessionStoreError::MetadataMigration(
                        "the session store's tables disagree on their schema".into(),
                    ));
                }
                #[cfg(test)]
                schema_hook::run(schema_hook::At::BeforeWrite);
                create_clear(conn)?;
                // Another opener's move to schema 4 committed since the
                // round's reads (review C-2): open the keyed store.
                if rebuild::shape(conn, HEADS, KEYED_COLUMN)? == Shape::Keyed {
                    continue;
                }
                if version < CLEAR_VERSION {
                    stamp_clear(conn)?;
                }
                return Ok(Layout::Clear);
            }
        }
    }
    Err(IndexedSessionStoreError::MetadataMigration(
        "the session store changed shape while it was opened; try again".into(),
    ))
}

/// Whether this profile's store is sealed: a sealed profile (tests may ask
/// for it, see [`test_switch`]).
pub(super) fn profile_seals(data_dir: &Path) -> bool {
    #[cfg(test)]
    if test_switch::seals(data_dir) {
        return true;
    }
    crate::privacy::mode(data_dir) == Mode::Sealed
}

/// The read-only view's layout ([`SessionMetadataReader`]): by the heads'
/// shape, nothing created, stamped or moved. The heads' shape and the other
/// tables' are read from one snapshot (one read transaction, as
/// [`read_round`]): a move that commits meanwhile is seen whole or not at
/// all, never a keyed layout with the tables of a store moved back.
pub(super) fn reader_layout(
    conn: &Connection,
    data_dir: &Path,
) -> Result<Layout, IndexedSessionStoreError> {
    let shape = {
        let tx = Transaction::new_unchecked(conn, TransactionBehavior::Deferred)?;
        let _in_tx = crate::paths::HeldMark::transaction();
        let heads = rebuild::shape(&tx, HEADS, KEYED_COLUMN)?;
        #[cfg(test)]
        schema_hook::run(schema_hook::At::MidRead);
        let shape = match heads {
            Shape::Keyed => Some(store_shape(&tx)?),
            Shape::Missing | Shape::Clear => None,
        };
        tx.commit()?;
        shape
    };
    match shape {
        Some(shape) => Ok(Layout::Keyed(Sealer::cached(data_dir)?.with_shape(shape))),
        None => Ok(Layout::Clear),
    }
}

/// Run `write` in one IMMEDIATE transaction, or in the caller's when `conn`
/// is in one already: a schema-2 row's `meta` is read, changed and written
/// back (what one UPSERT does in schema 1).
pub(super) fn in_write_tx<T>(
    conn: &Connection,
    write: impl FnOnce(&Connection) -> Result<T, IndexedSessionStoreError>,
) -> Result<T, IndexedSessionStoreError> {
    if !conn.is_autocommit() {
        return write(conn);
    }
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)?;
    let _in_tx = crate::paths::HeldMark::transaction();
    let out = write(&tx)?;
    tx.commit()?;
    Ok(out)
}

// ── Migration (privacy pack PP.13) ───────────────────────────────────────

fn counts(conn: &Connection) -> rusqlite::Result<Vec<(&'static str, i64)>> {
    ALL_TABLES
        .iter()
        .map(|table| Ok((*table, rebuild::count(conn, table)?)))
        .collect()
}

fn hex32(value: &[u8]) -> String {
    hex::encode(value)
}

/// The primary-key bytes `table`'s `meta` is bound to, from `columns` read
/// in [`META_TABLES`] order.
fn pk_of(columns: &[Vec<u8>]) -> Vec<u8> {
    columns.concat()
}

/// Schema 1, 2 or 3 -> 4 with the rebuild recipe ([`crate::sqlite_rebuild`]):
/// in one IMMEDIATE transaction the six tables of PP.13 (from schema 1:
/// the heads first, their reset rows refer to them; from schema 2 and 3
/// only the heads, whose `init_id` is keyed now: [`heads_init_forward`]),
/// the seven endpoint tables of PP.14 ([`endpoints::move_forward`]; already
/// keyed in schema 3) and session renewal's table (Phase 3 item 4,
/// [`renewal::move_forward`], while it is clear) are rebuilt, rowids kept,
/// every table's row count and the foreign keys checked before the commit,
/// then the scrub (the clear
/// `init_id`s leave the file too). The caller has replayed every journal on
/// the schema they were written under (the open).
pub(super) fn migrate_forward(
    path: &Path,
    keys: &MetaKeys,
    free: rebuild::FreeBytes<'_>,
) -> Result<Migration, RebuildError> {
    rebuild::space_ok(path, free).map_err(|needed| RebuildError::NoSpace { needed })?;
    let mut steps = Steps::default();
    let mut conn = rebuild::dedicated(path)?;
    rebuild::arm_disk_full(&conn)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let _in_tx = crate::paths::HeldMark::transaction();
    // Again inside the transaction: another process may have migrated.
    let heads = rebuild::shape(&tx, HEADS, KEYED_COLUMN)?;
    let version = rebuild::user_version(&tx)?;
    let endpoints_keyed = endpoints::keyed(&tx)?;
    let done = match heads {
        Shape::Missing => true,
        Shape::Clear => endpoints_keyed || version > CLEAR_VERSION,
        Shape::Keyed => init_keyed(&tx)? || version > ENDPOINTS_VERSION,
    };
    if done {
        return Ok(Migration::already());
    }
    // Session renewal's table, in the heads' shape when it is missing (an
    // older build created the others but not this one).
    renewal::ensure_table(&tx, heads == Shape::Keyed)?;
    parked::ensure_tables(&tx, heads == Shape::Keyed)?;
    letters::ensure_table(&tx, heads == Shape::Keyed)?;
    // Every table there in its older shape (an open created the sidecars).
    for table in ALL_TABLES {
        if rebuild::columns(&tx, table)?.is_empty() {
            return Ok(Migration::already());
        }
    }
    let before = counts(&tx)?;
    let mut leave_one_out = rebuild::drop_one_row();
    let mut rows = 0u32;
    if heads == Shape::Clear {
        rows += heads_forward(&tx, keys, &mut steps, &mut leave_one_out, true)?;
    } else {
        rows += heads_init_forward(&tx, keys, &mut steps, &mut leave_one_out)?;
    }
    if !endpoints_keyed {
        rows += endpoints::move_forward(&tx, keys, &mut steps, &mut leave_one_out)?;
    }
    // Clear rows, also those an older build of the pack left in a store it
    // moved without knowing this table.
    if !renewal::keyed(&tx)? {
        rows += renewal::move_forward(&tx, keys, &mut steps)?;
    }
    // The horizon's tables (Phase 5, P5.4): each one still clear.
    rows += parked::move_forward(&tx, keys, &mut steps)?;
    // The letter sessions' (Phase 5, P5.12), while it is clear.
    if !letters::keyed(&tx)? {
        rows += letters::move_forward(&tx, keys, &mut steps)?;
    }
    steps.step()?;
    rebuild::verify(&tx, &before)?;
    rebuild::record(&tx, STORE, METADATA_SCHEMA_VERSION, true)?;
    steps.step()?;
    tx.commit()?;
    steps.step()?;
    let scrubbed = rebuild::scrub(&conn, STORE, free)?;
    Ok(Migration {
        rows,
        scrub_pending: !scrubbed.complete,
        ..Migration::default()
    })
}

/// Schema 1 -> 2 alone, as a PP.13 build moves a store (tests: a PP.13
/// build's sealed store, which this build moves on to schema 4).
#[cfg(test)]
pub(super) fn migrate_to_schema_2(path: &Path, keys: &MetaKeys) -> Result<Migration, RebuildError> {
    migrate_as_older_build(path, keys, false)
}

/// Schema 1 -> 3, as the pack's builds before review B-sealed-stores-1
/// moved a store (tests: their sealed store, its heads' `init_id` clear,
/// which this build moves on to schema 4).
#[cfg(test)]
pub(super) fn migrate_to_schema_3(path: &Path, keys: &MetaKeys) -> Result<Migration, RebuildError> {
    migrate_as_older_build(path, keys, true)
}

#[cfg(test)]
fn migrate_as_older_build(
    path: &Path,
    keys: &MetaKeys,
    endpoints: bool,
) -> Result<Migration, RebuildError> {
    let mut steps = Steps::default();
    let mut conn = rebuild::dedicated(path)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let _in_tx = crate::paths::HeldMark::transaction();
    let before = counts(&tx)?;
    let mut rows = heads_forward(&tx, keys, &mut steps, &mut false, false)?;
    if endpoints {
        rows += endpoints::move_forward(&tx, keys, &mut steps, &mut false)?;
    }
    rebuild::verify(&tx, &before)?;
    let version = if endpoints {
        ENDPOINTS_VERSION
    } else {
        HEADS_VERSION
    };
    rebuild::record(&tx, STORE, version, false)?;
    tx.commit()?;
    Ok(Migration {
        rows,
        ..Migration::default()
    })
}

/// Schema 1 -> 2's part of [`migrate_forward`]: the heads, the reset
/// sidecar, the re-seal ledger, the per-peer reset state, the session ends
/// and the removal marks, rebuilt keyed; the heads' `init_id` keyed too and
/// in their meta with `init_keyed` (schema 4; clear as schema 2 and 3 kept
/// it otherwise, for the tests' older stores). The rows moved.
fn heads_forward(
    tx: &Transaction<'_>,
    keys: &MetaKeys,
    steps: &mut Steps,
    leave_one_out: &mut bool,
    init_keyed: bool,
) -> Result<u32, RebuildError> {
    let device = |v: &[u8]| at_rest::index(keys, ValueType::DeviceKey, v);
    let mut rows = 0u32;

    // The heads.
    steps.step()?;
    tx.execute_batch(&format!(
        "CREATE TABLE {HEADS}__new ({});",
        if init_keyed {
            heads_columns(true)
        } else {
            HEADS_COLUMNS_INIT_CLEAR
        }
    ))?;
    type HeadRow = (
        i64,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        String,
        String,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        i64,
        i64,
        i64,
    );
    let heads: Vec<HeadRow> = {
        let mut stmt = tx.prepare(
            "SELECT rowid, record_key, binding_digest, profile_id, initiator_address,
                    responder_address, initiator_device, responder_device, init_id, init_hash,
                    session_id, generation, created_at_ms, expires_at_ms
             FROM indexed_session_heads",
        )?;
        let mapped = stmt.query_map([], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
                r.get(7)?,
                r.get(8)?,
                r.get(9)?,
                r.get(10)?,
                r.get(11)?,
                r.get(12)?,
                r.get(13)?,
            ))
        })?;
        mapped.collect::<Result<_, _>>()?
    };
    for (n, head) in heads.into_iter().enumerate() {
        if *leave_one_out && n == 0 {
            *leave_one_out = false;
            continue;
        }
        let (rowid, record_key, binding, profile, ia, ra, id, rd, init_id, init_hash, sid, gen) = (
            head.0, head.1, head.2, head.3, head.4, head.5, head.6, head.7, head.8, head.9,
            head.10, head.11,
        );
        let (created, expires) = (head.12, head.13);
        steps.step()?;
        let meta = HeadMeta {
            initiator_address: ia.clone(),
            responder_address: ra.clone(),
            initiator_device: hex32(&id),
            responder_device: hex32(&rd),
            created_at_ms: created,
            expires_at_ms: expires,
            init_id: if init_keyed {
                hex::encode(&init_id)
            } else {
                String::new()
            },
        };
        let plain = Zeroizing::new(serde_json::to_vec(&meta).expect("strings and numbers"));
        let (init_column, init_value) = if init_keyed {
            (
                INIT_KEYED_COLUMN,
                at_rest::index(keys, ValueType::Nonce, &init_id).to_vec(),
            )
        } else {
            ("init_id", init_id)
        };
        tx.execute(
            &format!(
                "INSERT INTO indexed_session_heads__new
                   (rowid, record_key, binding_digest, profile_id, kh_initiator_address,
                    kh_responder_address, kh_initiator_device, kh_responder_device,
                    {init_column}, init_hash, session_id, generation, created_hour,
                    prune_after_hour, meta)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)"
            ),
            params![
                rowid,
                record_key,
                binding,
                profile,
                at_rest::index(keys, ValueType::Rvn1Address, ia.as_bytes()).as_slice(),
                at_rest::index(keys, ValueType::Rvn1Address, ra.as_bytes()).as_slice(),
                device(&id).as_slice(),
                device(&rd).as_slice(),
                init_value,
                init_hash,
                sid,
                gen,
                hour_down(created),
                prune_hour(expires),
                at_rest::seal_row(keys, HEADS, &record_key, &plain),
            ],
        )?;
        rows += 1;
    }
    steps.step()?;
    tx.execute_batch("DROP TABLE indexed_session_heads;")?;
    steps.step()?;
    tx.execute_batch("ALTER TABLE indexed_session_heads__new RENAME TO indexed_session_heads;")?;
    steps.step()?;
    tx.execute_batch(if init_keyed {
        KH_INIT_ID_INDEX
    } else {
        INIT_ID_INDEX
    })?;

    // The reset sidecar.
    steps.step()?;
    tx.execute_batch(&format!(
        "CREATE TABLE {RESET}__new ({});",
        reset_columns(true)
    ))?;
    type ResetRow = (
        i64,
        Vec<u8>,
        Vec<u8>,
        Option<i64>,
        i64,
        Option<i64>,
        Option<i64>,
        Option<i64>,
    );
    let resets: Vec<ResetRow> = {
        let mut stmt = tx.prepare(
            "SELECT rowid, session_id, peer_device, confirmed_at_ms, initiated_local,
                    reset_round_at_ms, retired_at_ms, retire_cause
             FROM indexed_session_reset",
        )?;
        let mapped = stmt.query_map([], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
                r.get(7)?,
            ))
        })?;
        mapped.collect::<Result<_, _>>()?
    };
    for (rowid, sid, peer, confirmed, local, round, retired, cause) in resets {
        steps.step()?;
        let meta = ResetMeta {
            peer_device: hex32(&peer),
            confirmed_at_ms: confirmed,
            reset_round_at_ms: round,
            retired_at_ms: retired,
        };
        let plain = Zeroizing::new(serde_json::to_vec(&meta).expect("strings and numbers"));
        tx.execute(
            "INSERT INTO indexed_session_reset__new
               (rowid, session_id, kh_peer_device, confirmed, initiated_local, reset_round,
                retired, retire_cause, meta)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                rowid,
                sid,
                device(&peer).as_slice(),
                i64::from(confirmed.is_some()),
                local,
                i64::from(round.is_some()),
                i64::from(retired.is_some()),
                cause,
                at_rest::seal_row(keys, RESET, &sid, &plain),
            ],
        )?;
        rows += 1;
    }
    steps.step()?;
    tx.execute_batch("DROP TABLE indexed_session_reset;")?;
    steps.step()?;
    tx.execute_batch("ALTER TABLE indexed_session_reset__new RENAME TO indexed_session_reset;")?;
    steps.step()?;
    tx.execute_batch(reset_index(true))?;

    // The re-seal ledger.
    steps.step()?;
    tx.execute_batch(&format!(
        "CREATE TABLE {LEDGER}__new ({});",
        ledger_columns(true)
    ))?;
    type LedgerRow = (i64, Vec<u8>, Vec<u8>, i64, i64, i64, i64);
    let ledger: Vec<LedgerRow> = {
        let mut stmt = tx.prepare(
            "SELECT rowid, recipient_device, message_id, reseals, last_reseal_at_ms,
                    expires_at_ms, notified
             FROM endpoint_reseal_ledger",
        )?;
        let mapped = stmt.query_map([], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
            ))
        })?;
        mapped.collect::<Result<_, _>>()?
    };
    for (rowid, recipient, mid, reseals, last, expires, notified) in ledger {
        steps.step()?;
        let (kr, km) = (
            device(&recipient),
            at_rest::index(keys, ValueType::MessageId, &mid),
        );
        let meta = LedgerMeta {
            recipient_device: hex32(&recipient),
            message_id: hex::encode(&mid),
            last_reseal_at_ms: last,
            expires_at_ms: expires,
        };
        let plain = Zeroizing::new(serde_json::to_vec(&meta).expect("strings and numbers"));
        tx.execute(
            "INSERT INTO endpoint_reseal_ledger__new
               (rowid, kh_recipient_device, kh_message_id, reseals, notified, prune_after_hour,
                meta)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                rowid,
                kr.as_slice(),
                km.as_slice(),
                reseals,
                notified,
                prune_hour(reset::ledger_expiry(expires)),
                at_rest::seal_row(keys, LEDGER, &[kr, km].concat(), &plain),
            ],
        )?;
        rows += 1;
    }
    steps.step()?;
    tx.execute_batch("DROP TABLE endpoint_reseal_ledger;")?;
    steps.step()?;
    tx.execute_batch("ALTER TABLE endpoint_reseal_ledger__new RENAME TO endpoint_reseal_ledger;")?;

    // The per-peer reset state.
    steps.step()?;
    tx.execute_batch(&format!(
        "CREATE TABLE {PEER_STATE}__new ({});",
        peer_state_columns(true)
    ))?;
    type StateRow = (i64, Vec<u8>, Option<i64>, Option<i64>);
    let states: Vec<StateRow> = {
        let mut stmt = tx.prepare(
            "SELECT rowid, peer_device, fork_evidence_at_ms, user_confirmed_at_ms
             FROM peer_reset_state",
        )?;
        let mapped = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?;
        mapped.collect::<Result<_, _>>()?
    };
    for (rowid, peer, fork, confirmed) in states {
        steps.step()?;
        let kp = device(&peer);
        let meta = PeerStateMeta {
            peer_device: hex32(&peer),
            fork_evidence_at_ms: fork,
            user_confirmed_at_ms: confirmed,
        };
        let plain = Zeroizing::new(serde_json::to_vec(&meta).expect("strings and numbers"));
        tx.execute(
            "INSERT INTO peer_reset_state__new (rowid, kh_peer_device, meta) VALUES (?1, ?2, ?3)",
            params![
                rowid,
                kp.as_slice(),
                at_rest::seal_row(keys, PEER_STATE, &kp, &plain)
            ],
        )?;
        rows += 1;
    }
    steps.step()?;
    tx.execute_batch("DROP TABLE peer_reset_state;")?;
    steps.step()?;
    tx.execute_batch("ALTER TABLE peer_reset_state__new RENAME TO peer_reset_state;")?;

    // When each contact's last session ended (CP.6).
    steps.step()?;
    tx.execute_batch(&format!(
        "CREATE TABLE {SESSION_END}__new ({});",
        session_end_columns(true)
    ))?;
    let ends: Vec<(i64, Vec<u8>, i64)> = {
        let mut stmt =
            tx.prepare("SELECT rowid, peer_device, ended_at_ms FROM peer_session_end")?;
        let mapped = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        mapped.collect::<Result<_, _>>()?
    };
    for (rowid, peer, ended) in ends {
        steps.step()?;
        let kp = device(&peer);
        let meta = SessionEndMeta {
            peer_device: hex32(&peer),
            ended_at_ms: ended,
        };
        let plain = Zeroizing::new(serde_json::to_vec(&meta).expect("strings and numbers"));
        tx.execute(
            "INSERT INTO peer_session_end__new (rowid, kh_peer_device, prune_after_hour, meta)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                rowid,
                kp.as_slice(),
                prune_hour(horizon::session_end_expiry(ended)),
                at_rest::seal_row(keys, SESSION_END, &kp, &plain)
            ],
        )?;
        rows += 1;
    }
    steps.step()?;
    tx.execute_batch("DROP TABLE peer_session_end;")?;
    steps.step()?;
    tx.execute_batch("ALTER TABLE peer_session_end__new RENAME TO peer_session_end;")?;

    // The removed contacts' marks (CP.6).
    steps.step()?;
    tx.execute_batch(&format!(
        "CREATE TABLE {ERASED}__new ({});",
        erased_columns(true)
    ))?;
    let marks: Vec<(i64, Vec<u8>, i64)> = {
        let mut stmt =
            tx.prepare("SELECT rowid, peer_device, created_to_ms FROM peer_session_end_erased")?;
        let mapped = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        mapped.collect::<Result<_, _>>()?
    };
    for (rowid, peer, created_to) in marks {
        steps.step()?;
        let kp = device(&peer);
        let meta = ErasedMeta {
            peer_device: hex32(&peer),
            created_to_ms: created_to,
        };
        let plain = Zeroizing::new(serde_json::to_vec(&meta).expect("strings and numbers"));
        tx.execute(
            "INSERT INTO peer_session_end_erased__new (rowid, kh_peer_device, meta)
             VALUES (?1, ?2, ?3)",
            params![
                rowid,
                kp.as_slice(),
                at_rest::seal_row(keys, ERASED, &kp, &plain)
            ],
        )?;
        rows += 1;
    }
    steps.step()?;
    tx.execute_batch("DROP TABLE peer_session_end_erased;")?;
    steps.step()?;
    tx.execute_batch(
        "ALTER TABLE peer_session_end_erased__new RENAME TO peer_session_end_erased;",
    )?;

    Ok(rows)
}

/// Schema 2 or 3 -> 4's part of [`migrate_forward`] (review
/// B-sealed-stores-1): the heads rebuilt with `kh_init_id` in place of the
/// clear `init_id` (the UNIQUE index too), the `init_id` itself in each
/// head's `meta`, sealed again under the current epoch; every other column
/// copied as it is, rowids kept. A `meta` that does not open (a changed
/// byte, an epoch no key holds) keeps its bytes: that head could not be
/// read before either, and the prune removes it by its `prune_after_hour`.
/// The rows moved.
fn heads_init_forward(
    tx: &Transaction<'_>,
    keys: &MetaKeys,
    steps: &mut Steps,
    leave_one_out: &mut bool,
) -> Result<u32, RebuildError> {
    steps.step()?;
    tx.execute_batch(&format!(
        "CREATE TABLE {HEADS}__new ({});",
        heads_columns(true)
    ))?;
    type HeadRow = (
        i64,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        [Vec<u8>; 4],
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        [i64; 3],
        Vec<u8>,
    );
    let heads: Vec<HeadRow> = {
        let mut stmt = tx.prepare(
            "SELECT rowid, record_key, binding_digest, profile_id, kh_initiator_address,
                    kh_responder_address, kh_initiator_device, kh_responder_device, init_id,
                    init_hash, session_id, generation, created_hour, prune_after_hour, meta
             FROM indexed_session_heads",
        )?;
        let mapped = stmt.query_map([], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                [r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?],
                r.get(8)?,
                r.get(9)?,
                r.get(10)?,
                [r.get(11)?, r.get(12)?, r.get(13)?],
                r.get(14)?,
            ))
        })?;
        mapped.collect::<Result<_, _>>()?
    };
    let mut rows = 0u32;
    for (n, head) in heads.into_iter().enumerate() {
        if *leave_one_out && n == 0 {
            *leave_one_out = false;
            continue;
        }
        let (rowid, record_key, binding, profile, keyed, init_id, init_hash, sid, numbers, meta) =
            head;
        let [ia, ra, id, rd] = keyed;
        let [generation, created_hour, prune_after_hour] = numbers;
        steps.step()?;
        let opened = at_rest::open_row(keys, HEADS, &record_key, &meta)
            .ok()
            .and_then(|plain| serde_json::from_slice::<HeadMeta>(&plain).ok());
        let meta = match opened {
            Some(mut head) => {
                head.init_id = hex::encode(&init_id);
                let plain = Zeroizing::new(serde_json::to_vec(&head).expect("strings and numbers"));
                at_rest::seal_row(keys, HEADS, &record_key, &plain)
            }
            None => meta,
        };
        tx.execute(
            "INSERT INTO indexed_session_heads__new
               (rowid, record_key, binding_digest, profile_id, kh_initiator_address,
                kh_responder_address, kh_initiator_device, kh_responder_device, kh_init_id,
                init_hash, session_id, generation, created_hour, prune_after_hour, meta)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            params![
                rowid,
                record_key,
                binding,
                profile,
                ia,
                ra,
                id,
                rd,
                at_rest::index(keys, ValueType::Nonce, &init_id).as_slice(),
                init_hash,
                sid,
                generation,
                created_hour,
                prune_after_hour,
                meta,
            ],
        )?;
        rows += 1;
    }
    steps.step()?;
    tx.execute_batch("DROP TABLE indexed_session_heads;")?;
    steps.step()?;
    tx.execute_batch("ALTER TABLE indexed_session_heads__new RENAME TO indexed_session_heads;")?;
    steps.step()?;
    tx.execute_batch(KH_INIT_ID_INDEX)?;
    Ok(rows)
}

/// Schema 4 (or 3 or 2) -> 1 (`raven privacy unseal`, PP.18): the same
/// recipe. A head whose `meta` does not open here cannot be written back:
/// it goes first, with every row of its session ([`drop_unreadable_heads`];
/// the caller deleted its protected state), each counted (`dropped`). The
/// other tables' rows that do not open are left out and counted too, and
/// the count check expects exactly that.
pub(super) fn migrate_back(
    path: &Path,
    keys: &MetaKeys,
    free: rebuild::FreeBytes<'_>,
) -> Result<Migration, RebuildError> {
    rebuild::space_ok(path, free).map_err(|needed| RebuildError::NoSpace { needed })?;
    let mut steps = Steps::default();
    let mut conn = rebuild::dedicated(path)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let _in_tx = crate::paths::HeldMark::transaction();
    if rebuild::shape(&tx, HEADS, KEYED_COLUMN)? != Shape::Keyed {
        return Ok(Migration::already());
    }
    renewal::ensure_table(&tx, true)?;
    parked::ensure_tables(&tx, true)?;
    letters::ensure_table(&tx, true)?;
    let mut report = Migration::default();
    drop_unreadable_heads(&tx, keys, &mut steps, &mut report)?;
    let mut expected = counts(&tx)?;
    heads_back(&tx, keys, &mut steps, &mut expected, &mut report)?;
    if endpoints::keyed(&tx)? {
        endpoints::move_back(&tx, keys, &mut steps, &mut expected, &mut report)?;
    }
    if renewal::keyed(&tx)? {
        renewal::move_back(&tx, keys, &mut steps, &mut expected, &mut report)?;
    }
    parked::move_back(&tx, keys, &mut steps, &mut expected, &mut report)?;
    if letters::keyed(&tx)? {
        letters::move_back(&tx, keys, &mut steps, &mut expected, &mut report)?;
    }
    steps.step()?;
    rebuild::verify(&tx, &expected)?;
    rebuild::record(&tx, STORE, CLEAR_VERSION, true)?;
    steps.step()?;
    tx.commit()?;
    let scrubbed = rebuild::scrub(&conn, STORE, free)?;
    report.scrub_pending = !scrubbed.complete;
    Ok(report)
}

/// Schema 4 -> 4 under new keys (`raven privacy rotate-meta`, PP.18; a
/// schema-2 or -3 store comes out at 4 as well): in one IMMEDIATE
/// transaction on a connection that writes nothing before the commit
/// ([`rebuild::rekey_connection`]), every table goes back to its clear
/// columns ([`migrate_back`]'s halves) and forward again
/// ([`migrate_forward`]'s), so every keyed value is computed anew and every
/// sealed value sealed under the current epoch, rowids (and with them the
/// inbox's `seq`) kept; the tombstones' `seq` and the inbox counter are put
/// back as they were ([`endpoints::save_order`]). Counts checked, then the
/// scrub. `keys` open every epoch the rows are under. A head whose `meta`
/// does not open goes first with its session's rows, as on the way back
/// (review B-sealed-stores-3: it used to stop the re-key for good).
pub(super) fn rekey_store(
    path: &Path,
    keys: &MetaKeys,
    free: rebuild::FreeBytes<'_>,
) -> Result<Migration, RebuildError> {
    rebuild::space_ok(path, free).map_err(|needed| RebuildError::NoSpace { needed })?;
    let mut steps = Steps::default();
    let mut conn = rebuild::rekey_connection(path)?;
    rebuild::arm_disk_full(&conn)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let _in_tx = crate::paths::HeldMark::transaction();
    if rebuild::shape(&tx, HEADS, KEYED_COLUMN)? != Shape::Keyed {
        return Ok(Migration::already());
    }
    renewal::ensure_table(&tx, true)?;
    parked::ensure_tables(&tx, true)?;
    letters::ensure_table(&tx, true)?;
    for table in ALL_TABLES {
        if rebuild::columns(&tx, table)?.is_empty() {
            return Ok(Migration::already());
        }
    }
    let mut report = Migration::default();
    drop_unreadable_heads(&tx, keys, &mut steps, &mut report)?;
    let had_endpoints = endpoints::keyed(&tx)?;
    let order = if had_endpoints {
        Some(endpoints::save_order(&tx)?)
    } else {
        None
    };
    let mut expected = counts(&tx)?;
    heads_back(&tx, keys, &mut steps, &mut expected, &mut report)?;
    if had_endpoints {
        endpoints::move_back(&tx, keys, &mut steps, &mut expected, &mut report)?;
    }
    if renewal::keyed(&tx)? {
        renewal::move_back(&tx, keys, &mut steps, &mut expected, &mut report)?;
    }
    parked::move_back(&tx, keys, &mut steps, &mut expected, &mut report)?;
    if letters::keyed(&tx)? {
        letters::move_back(&tx, keys, &mut steps, &mut expected, &mut report)?;
    }
    let mut leave_one_out = rebuild::drop_one_row();
    report.rows = heads_forward(&tx, keys, &mut steps, &mut leave_one_out, true)?;
    report.rows += endpoints::move_forward(&tx, keys, &mut steps, &mut leave_one_out)?;
    report.rows += renewal::move_forward(&tx, keys, &mut steps)?;
    report.rows += parked::move_forward(&tx, keys, &mut steps)?;
    report.rows += letters::move_forward(&tx, keys, &mut steps)?;
    if let Some(order) = &order {
        endpoints::restore_order(&tx, order)?;
    }
    rebuild::verify(&tx, &expected)?;
    rebuild::record(&tx, STORE, METADATA_SCHEMA_VERSION, true)?;
    tx.commit()?;
    let scrubbed = rebuild::scrub(&conn, STORE, free)?;
    report.scrub_pending = !scrubbed.complete;
    Ok(report)
}

/// A row the way back leaves out: the count check expects one fewer.
pub(super) fn dropped(expected: &mut [(&'static str, i64)], table: &str, report: &mut Migration) {
    if let Some((_, n)) = expected.iter_mut().find(|(t, _)| *t == table) {
        *n -= 1;
    }
    report.dropped += 1;
}

/// The tables that name a head's session by its `session_id`, the rows that
/// refer to a receipt first. Foreign keys are off on a rebuild's connection:
/// the reset and letter rows do not cascade with their head there.
const SESSION_TABLES: [&str; 9] = [
    "endpoint_inbox",
    "endpoint_ack_intents",
    "endpoint_inbox_deleted",
    "endpoint_receipts",
    "endpoint_outstanding_messages",
    "endpoint_ack_receipts",
    "endpoint_outbox",
    RESET,
    letters::LETTER,
];

/// The heads of a keyed store whose `meta` does not open with `keys` (a
/// changed byte, an epoch no key holds) or does not name a head:
/// `(record_key, session_id)` each (review B-sealed-stores-3). Such a head
/// can be neither written back nor keyed again.
pub(super) fn unreadable_heads(
    conn: &Connection,
    keys: &MetaKeys,
) -> rusqlite::Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let in_meta = init_keyed(conn)?;
    let mut statement =
        conn.prepare("SELECT record_key, session_id, meta FROM indexed_session_heads")?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, Vec<u8>>(2)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (record_key, session_id, meta) = row?;
        let readable = at_rest::open_row(keys, HEADS, &record_key, &meta)
            .ok()
            .and_then(|plain| serde_json::from_slice::<HeadMeta>(&plain).ok())
            .is_some_and(|head| {
                device_of(&head.initiator_device).is_ok()
                    && device_of(&head.responder_device).is_ok()
                    && (!in_meta || init_id_of(&head.init_id).is_ok())
            });
        if !readable {
            out.push((record_key, session_id));
        }
    }
    Ok(out)
}

/// The way back's and the re-key's first step (review B-sealed-stores-3):
/// every head [`unreadable_heads`] names goes, with every row of its session
/// ([`SESSION_TABLES`]), each counted in `dropped`, before the tables'
/// counts are taken. Such a head stopped both for good before, and with
/// them `raven privacy rotate-meta` and `unseal`. The command deleted its
/// protected state before it changed anything ([`forget_unreadable_sessions`]):
/// nothing would find it again.
fn drop_unreadable_heads(
    tx: &Transaction<'_>,
    keys: &MetaKeys,
    steps: &mut Steps,
    report: &mut Migration,
) -> Result<(), RebuildError> {
    for (record_key, session_id) in unreadable_heads(tx, keys)? {
        steps.step()?;
        let mut gone = 0usize;
        for table in SESSION_TABLES {
            gone += tx.execute(
                &format!("DELETE FROM {table} WHERE session_id = ?1"),
                params![session_id],
            )?;
        }
        gone += tx.execute(
            "DELETE FROM indexed_session_heads WHERE record_key = ?1",
            params![record_key],
        )?;
        report.dropped = report
            .dropped
            .saturating_add(u32::try_from(gone).unwrap_or(u32::MAX));
    }
    Ok(())
}

/// Before the way back or a re-key drops them ([`drop_unreadable_heads`]):
/// the protected state (keychain or Secret Service item, vault entry, lab
/// file) of every head whose `meta` does not open is deleted, so no secret
/// is left that nothing names. How many; nothing to do without such a head
/// (no keystore call then). A delete that fails stops the caller, nothing
/// changed in the store: running the command again finishes it.
fn forget_unreadable_heads(data_dir: &Path, keys: &MetaKeys) -> Result<usize, String> {
    let Some(conn) = keyed_connection(data_dir).map_err(|e| e.to_string())? else {
        return Ok(0);
    };
    let heads = unreadable_heads(&conn, keys).map_err(|e| e.to_string())?;
    drop(conn);
    if heads.is_empty() {
        return Ok(0);
    }
    let backend = protected_backend(data_dir).map_err(|e| e.redacted_display())?;
    for (record_key, _) in &heads {
        backend
            .delete(&hex::encode(record_key))
            .map_err(|e| e.redacted_display())?;
    }
    Ok(heads.len())
}

/// Schema 2 -> 1's part of [`migrate_back`]: the six tables of PP.13 (the
/// heads' `init_id` from their `meta` in schema 4, from its clear column in
/// schema 2 and 3).
fn heads_back(
    tx: &Transaction<'_>,
    keys: &MetaKeys,
    steps: &mut Steps,
    expected: &mut [(&'static str, i64)],
    report: &mut Migration,
) -> Result<(), RebuildError> {
    let open = |table: &str, pk: &[u8], blob: &[u8]| -> Option<Zeroizing<Vec<u8>>> {
        at_rest::open_row(keys, table, pk, blob).ok()
    };
    fn parse<T: DeserializeOwned>(plain: Option<Zeroizing<Vec<u8>>>) -> Option<T> {
        serde_json::from_slice(&plain?).ok()
    }
    let clear_device = |hex_value: &str| hex::decode(hex_value).ok().filter(|v| v.len() == 32);
    let tampered = || {
        RebuildError::Key(AtRestError::Tampered {
            kind: at_rest::NOT_A_FILE_KIND,
        })
    };

    // The heads.
    let init_column = if init_keyed(tx)? { "NULL" } else { "init_id" };
    steps.step()?;
    tx.execute_batch(&format!(
        "CREATE TABLE {HEADS}__new ({});",
        heads_columns(false)
    ))?;
    type HeadRow = (
        i64,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Option<Vec<u8>>,
        Vec<u8>,
        Vec<u8>,
        i64,
        Vec<u8>,
    );
    let heads: Vec<HeadRow> = {
        let mut stmt = tx.prepare(&format!(
            "SELECT rowid, record_key, binding_digest, profile_id, {init_column}, init_hash,
                    session_id, generation, meta
             FROM indexed_session_heads"
        ))?;
        let mapped = stmt.query_map([], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
                r.get(7)?,
                r.get(8)?,
            ))
        })?;
        mapped.collect::<Result<_, _>>()?
    };
    for (rowid, record_key, binding, profile, init_id, init_hash, sid, gen, meta) in heads {
        steps.step()?;
        // Every head opens here: one that does not went first
        // (`drop_unreadable_heads`).
        let meta: HeadMeta = parse(open(HEADS, &record_key, &meta)).ok_or_else(tampered)?;
        let (Some(id), Some(rd)) = (
            clear_device(&meta.initiator_device),
            clear_device(&meta.responder_device),
        ) else {
            return Err(tampered());
        };
        let init_id = match init_id {
            Some(clear) => clear,
            None => init_id_of(&meta.init_id).map_err(|_| tampered())?.to_vec(),
        };
        tx.execute(
            "INSERT INTO indexed_session_heads__new
               (rowid, record_key, binding_digest, profile_id, initiator_address,
                responder_address, initiator_device, responder_device, init_id, init_hash,
                session_id, generation, created_at_ms, expires_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                rowid,
                record_key,
                binding,
                profile,
                meta.initiator_address,
                meta.responder_address,
                id,
                rd,
                init_id,
                init_hash,
                sid,
                gen,
                meta.created_at_ms,
                meta.expires_at_ms,
            ],
        )?;
        report.rows += 1;
    }
    steps.step()?;
    tx.execute_batch("DROP TABLE indexed_session_heads;")?;
    steps.step()?;
    tx.execute_batch("ALTER TABLE indexed_session_heads__new RENAME TO indexed_session_heads;")?;
    steps.step()?;
    tx.execute_batch(INIT_ID_INDEX)?;

    // The reset sidecar.
    steps.step()?;
    tx.execute_batch(&format!(
        "CREATE TABLE {RESET}__new ({});",
        reset_columns(false)
    ))?;
    type ResetRow = (i64, Vec<u8>, i64, Option<i64>, Vec<u8>);
    let resets: Vec<ResetRow> = {
        let mut stmt = tx.prepare(
            "SELECT rowid, session_id, initiated_local, retire_cause, meta
             FROM indexed_session_reset",
        )?;
        let mapped = stmt.query_map([], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })?;
        mapped.collect::<Result<_, _>>()?
    };
    for (rowid, sid, local, cause, meta) in resets {
        steps.step()?;
        let Some((meta, peer)) = parse::<ResetMeta>(open(RESET, &sid, &meta))
            .and_then(|meta| clear_device(&meta.peer_device).map(|peer| (meta, peer)))
        else {
            dropped(expected, RESET, report);
            continue;
        };
        tx.execute(
            "INSERT INTO indexed_session_reset__new
               (rowid, session_id, peer_device, confirmed_at_ms, initiated_local,
                reset_round_at_ms, retired_at_ms, retire_cause)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                rowid,
                sid,
                peer,
                meta.confirmed_at_ms,
                local,
                meta.reset_round_at_ms,
                meta.retired_at_ms,
                cause,
            ],
        )?;
        report.rows += 1;
    }
    steps.step()?;
    tx.execute_batch("DROP TABLE indexed_session_reset;")?;
    steps.step()?;
    tx.execute_batch("ALTER TABLE indexed_session_reset__new RENAME TO indexed_session_reset;")?;
    steps.step()?;
    tx.execute_batch(reset_index(false))?;

    // The re-seal ledger.
    steps.step()?;
    tx.execute_batch(&format!(
        "CREATE TABLE {LEDGER}__new ({});",
        ledger_columns(false)
    ))?;
    type LedgerRow = (i64, Vec<u8>, Vec<u8>, i64, i64, Vec<u8>);
    let ledger: Vec<LedgerRow> = {
        let mut stmt = tx.prepare(
            "SELECT rowid, kh_recipient_device, kh_message_id, reseals, notified, meta
             FROM endpoint_reseal_ledger",
        )?;
        let mapped = stmt.query_map([], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
            ))
        })?;
        mapped.collect::<Result<_, _>>()?
    };
    for (rowid, kr, km, reseals, notified, meta) in ledger {
        steps.step()?;
        let pk = pk_of(&[kr, km]);
        let row = parse::<LedgerMeta>(open(LEDGER, &pk, &meta)).and_then(|meta| {
            let recipient = clear_device(&meta.recipient_device)?;
            let mid = hex::decode(&meta.message_id)
                .ok()
                .filter(|v| v.len() == 16)?;
            Some((meta, recipient, mid))
        });
        let Some((meta, recipient, mid)) = row else {
            dropped(expected, LEDGER, report);
            continue;
        };
        tx.execute(
            "INSERT INTO endpoint_reseal_ledger__new
               (rowid, recipient_device, message_id, reseals, last_reseal_at_ms, expires_at_ms,
                notified)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                rowid,
                recipient,
                mid,
                reseals,
                meta.last_reseal_at_ms,
                meta.expires_at_ms,
                notified,
            ],
        )?;
        report.rows += 1;
    }
    steps.step()?;
    tx.execute_batch("DROP TABLE endpoint_reseal_ledger;")?;
    steps.step()?;
    tx.execute_batch("ALTER TABLE endpoint_reseal_ledger__new RENAME TO endpoint_reseal_ledger;")?;

    // The per-peer reset state, the session ends and the removal marks: a
    // device key and a sealed meta each.
    for (table, columns) in [
        (PEER_STATE, peer_state_columns(false)),
        (SESSION_END, session_end_columns(false)),
        (ERASED, erased_columns(false)),
    ] {
        steps.step()?;
        tx.execute_batch(&format!("CREATE TABLE {table}__new ({columns});"))?;
        let marks: Vec<(i64, Vec<u8>, Vec<u8>)> = {
            let mut stmt =
                tx.prepare(&format!("SELECT rowid, kh_peer_device, meta FROM {table}"))?;
            let mapped = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
            mapped.collect::<Result<_, _>>()?
        };
        for (rowid, kp, meta) in marks {
            steps.step()?;
            let plain = open(table, &kp, &meta);
            let inserted = match table {
                PEER_STATE => parse::<PeerStateMeta>(plain).and_then(|m| {
                    let peer = clear_device(&m.peer_device)?;
                    Some(tx.execute(
                        "INSERT INTO peer_reset_state__new
                           (rowid, peer_device, fork_evidence_at_ms, user_confirmed_at_ms)
                         VALUES (?1, ?2, ?3, ?4)",
                        params![rowid, peer, m.fork_evidence_at_ms, m.user_confirmed_at_ms],
                    ))
                }),
                SESSION_END => parse::<SessionEndMeta>(plain).and_then(|m| {
                    let peer = clear_device(&m.peer_device)?;
                    Some(tx.execute(
                        "INSERT INTO peer_session_end__new (rowid, peer_device, ended_at_ms)
                         VALUES (?1, ?2, ?3)",
                        params![rowid, peer, m.ended_at_ms],
                    ))
                }),
                _ => parse::<ErasedMeta>(plain).and_then(|m| {
                    let peer = clear_device(&m.peer_device)?;
                    Some(tx.execute(
                        "INSERT INTO peer_session_end_erased__new
                           (rowid, peer_device, created_to_ms)
                         VALUES (?1, ?2, ?3)",
                        params![rowid, peer, m.created_to_ms],
                    ))
                }),
            };
            match inserted {
                Some(done) => {
                    done?;
                    report.rows += 1;
                }
                None => dropped(expected, table, report),
            }
        }
        steps.step()?;
        tx.execute_batch(&format!("DROP TABLE {table};"))?;
        steps.step()?;
        tx.execute_batch(&format!("ALTER TABLE {table}__new RENAME TO {table};"))?;
    }

    Ok(())
}

// ── The store's part in the privacy passes ───────────────────────────────

/// The store's path in `data_dir`.
fn store_path(data_dir: &Path) -> PathBuf {
    data_dir.join(INDEXED_SESSION_METADATA_FILE)
}

/// Privacy pack PP.13 and PP.14, the eager half of the migration
/// (`privacy::migrate_all`, the prune passes): in a sealed profile with its
/// keys loaded, an existing clear, schema-2 or schema-3 store moves to
/// schema 4 through a full open (its journal recovery first; a store with a
/// journal still pending waits for a later pass). `true` when it moved now.
/// A store that cannot be opened is left as it is.
pub fn migrate(data_dir: &Path) -> Result<bool, String> {
    if !needs_migration(data_dir) || crate::privacy::mode(data_dir) != Mode::Sealed {
        return Ok(false);
    }
    at_rest::keys_cached(data_dir).map_err(|e| e.to_string())?;
    let store = IndexedSessionStore::open(data_dir).map_err(|e| e.redacted_display())?;
    Ok(store.moved_now)
}

/// Whether the store's header says it is still clear or at schema 2 or 3
/// (no SQLite open; a commit still in the WAL is not seen, so `true` may
/// only mean "look").
pub fn needs_migration(data_dir: &Path) -> bool {
    let path = store_path(data_dir);
    path.exists() && rebuild::header_user_version(&path).is_none_or(|v| v < METADATA_SCHEMA_VERSION)
}

/// `raven privacy rotate-meta` and `unseal`, before either changes anything
/// (the record of a key change, the key file, the profile's mode): the
/// protected state of every head whose `meta` does not open with the keys
/// this process loaded is deleted ([`forget_unreadable_heads`]), so that
/// [`rekey`] and [`unseal`] drop such heads ([`drop_unreadable_heads`])
/// without a keystore call. A delete that fails (a locked keychain, a
/// denied access dialog) stops the command while the profile is still as it
/// was and raven-node still starts it; running the command again finishes
/// it (review B-sealed-stores-3: inside rotate-meta it ran after the key
/// change was recorded, so such a failure left raven-node refused). How
/// many; nothing to do without a keyed store or such a head (no keystore
/// call then).
pub fn forget_unreadable_sessions(data_dir: &Path) -> Result<usize, String> {
    if !store_path(data_dir).exists() {
        return Ok(0);
    }
    let keys = at_rest::keys_cached(data_dir).map_err(|e| e.to_string())?;
    forget_unreadable_heads(data_dir, &keys)
        .map_err(|e| format!("{INDEXED_SESSION_METADATA_FILE}: {e}"))
}

/// The way back (`raven privacy unseal`, PP.18): a keyed store moves to
/// schema 1 with the keys this process loaded, through a full open (its
/// journals replayed first; a journal still pending refuses, try again).
/// A head whose `meta` does not open goes ([`drop_unreadable_heads`]); the
/// caller deleted its protected state before it changed anything
/// ([`forget_unreadable_sessions`]). Nothing to do without a store or on a
/// clear one. The profile's mode must already say it is no longer sealed,
/// or the next open moves it again.
pub fn unseal(data_dir: &Path) -> Result<Migration, String> {
    let path = store_path(data_dir);
    if !path.exists() {
        return Ok(Migration::already());
    }
    let keys = at_rest::keys_cached(data_dir).map_err(|e| e.to_string())?;
    let mut store = IndexedSessionStore::open(data_dir).map_err(|e| e.redacted_display())?;
    if !store.layout.is_keyed() {
        return Ok(Migration::already());
    }
    if store.journal_pending().map_err(|e| e.redacted_display())? {
        return Err(
            "a message is still being committed in the session store; try again in a moment".into(),
        );
    }
    let done = migrate_back(&path, &keys, &crate::disk_space::free_bytes)
        .map_err(|e| format!("{INDEXED_SESSION_METADATA_FILE}: {e}"))?;
    store.layout = Layout::Clear;
    Ok(done)
}

/// `raven privacy rotate-meta` (PP.18), before the key file gets its new
/// `k_index`: every journal is replayed (a full open; they replay under the
/// keys they were written with), and none is still pending. Nothing to do
/// without a store.
pub fn settle_journals(data_dir: &Path) -> Result<(), String> {
    if !store_path(data_dir).exists() {
        return Ok(());
    }
    let store = IndexedSessionStore::open(data_dir).map_err(|e| e.redacted_display())?;
    if store.journal_pending().map_err(|e| e.redacted_display())? {
        return Err(
            "a message is still being committed in the session store; try again in a moment".into(),
        );
    }
    Ok(())
}

/// `raven privacy rotate-meta` (PP.18): a keyed store is keyed again with
/// the keys this process holds now (a new `k_index`; the epochs they hold
/// open the old rows), on a metadata-only connection ([`rekey_store`]). A
/// head whose `meta` does not open goes ([`drop_unreadable_heads`]); the
/// caller deleted its protected state before it recorded the key change
/// ([`forget_unreadable_sessions`]). Nothing to do without a store or on a
/// clear one. The caller replayed the journals first ([`settle_journals`]).
pub fn rekey(data_dir: &Path) -> Result<Migration, String> {
    let path = store_path(data_dir);
    if !path.exists() {
        return Ok(Migration::already());
    }
    let keys = at_rest::keys_cached(data_dir).map_err(|e| e.to_string())?;
    rekey_store(&path, &keys, &crate::disk_space::free_bytes)
        .map_err(|e| format!("{INDEXED_SESSION_METADATA_FILE}: {e}"))
}

/// `raven privacy unseal` (PP.18), before the store moves back: where a
/// chat cursor saved in the [`super::InboxOrder::Seq`] order (`seq`) stands
/// for `sender_device` in the order a build before PP.14 reads
/// ([`endpoints::received_position`]). `None` without a store whose
/// endpoint tables are keyed (schema 3 on).
pub fn received_position_of(
    data_dir: &Path,
    sender_device: &[u8; 32],
    seq: u64,
) -> Result<Option<super::InboxPosition>, String> {
    let Some(conn) = keyed_connection(data_dir).map_err(|e| e.to_string())? else {
        return Ok(None);
    };
    if !endpoints::keyed(&conn).map_err(|e| e.to_string())? {
        return Ok(None);
    }
    let keys = at_rest::keys_cached(data_dir).map_err(|e| e.to_string())?;
    endpoints::received_position(&conn, &keys, sender_device, seq).map(Some)
}

/// A pending scrub (a `VACUUM` or checkpoint a reader held up) is done now:
/// the prune passes. `None` when nothing was pending.
pub fn finish_scrub(data_dir: &Path) -> Option<bool> {
    rebuild::finish_scrub(&store_path(data_dir), STORE, &crate::disk_space::free_bytes)
        .ok()
        .flatten()
}

/// Whether a scrub of the store is pending (`raven privacy status`).
pub fn scrub_pending(data_dir: &Path) -> bool {
    rebuild::scrub_pending(&store_path(data_dir), STORE)
}

/// A metadata-only connection to an existing keyed store (rotation): no
/// protected backend, no schema change. `None` without one.
fn keyed_connection(data_dir: &Path) -> rusqlite::Result<Option<Connection>> {
    let path = store_path(data_dir);
    if !path.is_file() {
        return Ok(None);
    }
    let conn = Connection::open_with_flags(
        &path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    conn.busy_timeout(Duration::from_secs(2))?;
    crate::paths::harden_sqlite(&conn)?;
    if rebuild::shape(&conn, HEADS, KEYED_COLUMN)? != Shape::Keyed {
        return Ok(None);
    }
    Ok(Some(conn))
}

/// Sealed values not on epoch `current` (every `meta` and, since schema 3,
/// every sealed wire object, by their first bytes; no key, no lock): the
/// rotation's old-object count. `0` without a keyed store.
pub fn rows_off_epoch(data_dir: &Path, current: u32) -> Result<u32, String> {
    let Some(conn) = keyed_connection(data_dir).map_err(|e| e.to_string())? else {
        return Ok(0);
    };
    let epoch = current.to_be_bytes().to_vec();
    let mut n = 0i64;
    for (table, column, _, _) in sealed_columns(&conn).map_err(|e| e.to_string())? {
        n += conn
            .query_row(
                &format!(
                    "SELECT COUNT(*) FROM {table}
                     WHERE {column} IS NOT NULL AND substr({column}, 2, 4) != ?1"
                ),
                params![epoch],
                |r| r.get::<_, i64>(0),
            )
            .map_err(|e| e.to_string())?;
    }
    Ok(u32::try_from(n).unwrap_or(u32::MAX))
}

/// A data-key rotation's step for this store (PP.10): in one IMMEDIATE
/// transaction every sealed value not on the current epoch (each `meta`,
/// and since schema 3 the sealed wire objects) is opened and sealed again
/// under it, then the WAL is checkpointed. A sealed profile with its keys
/// loaded; nothing to do without a keyed store. Values that do not open are
/// left as they are (`unreadable`).
pub fn reseal_rows(data_dir: &Path) -> Result<RowReseal, String> {
    let mut report = RowReseal::default();
    if crate::privacy::mode(data_dir) != Mode::Sealed {
        return Ok(report);
    }
    let keys = at_rest::keys_cached(data_dir).map_err(|e| e.to_string())?;
    let current = keys.current_epoch();
    if rows_off_epoch(data_dir, current)? == 0 {
        return Ok(report);
    }
    let Some(mut conn) = keyed_connection(data_dir).map_err(|e| e.to_string())? else {
        return Ok(report);
    };
    let epoch = current.to_be_bytes().to_vec();
    let failed = |e: rusqlite::Error| e.to_string();
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(failed)?;
    let _in_tx = crate::paths::HeldMark::transaction();
    for (table, column, label, pk_columns) in sealed_columns(&tx).map_err(failed)? {
        let rows: Vec<(i64, Vec<u8>, Vec<u8>)> = {
            let mut stmt = tx
                .prepare(&format!(
                    "SELECT rowid, {}, {column} FROM {table}
                     WHERE {column} IS NOT NULL AND substr({column}, 2, 4) != ?1",
                    pk_columns.join(", ")
                ))
                .map_err(failed)?;
            let width = pk_columns.len();
            let mapped = stmt
                .query_map(params![epoch], |r| {
                    let mut pk = Vec::new();
                    for at in 0..width {
                        pk.push(r.get::<_, Vec<u8>>(1 + at)?);
                    }
                    Ok((r.get(0)?, pk_of(&pk), r.get(1 + width)?))
                })
                .map_err(failed)?;
            mapped.collect::<Result<_, _>>().map_err(failed)?
        };
        for (rowid, pk, sealed) in rows {
            let Ok(plain) = at_rest::open_row(&keys, label, &pk, &sealed) else {
                report.unreadable += 1;
                continue;
            };
            tx.execute(
                &format!("UPDATE {table} SET {column} = ?2 WHERE rowid = ?1"),
                params![rowid, at_rest::seal_row(&keys, label, &pk, &plain)],
            )
            .map_err(failed)?;
            report.resealed += 1;
        }
    }
    tx.commit().map_err(failed)?;
    if report.resealed > 0 {
        report.scrub_pending =
            crate::paths::checkpoint_truncate(&conn).map_or(true, |checkpoint| checkpoint.busy);
    }
    Ok(report)
}

// ── Tests: the whole suite on a sealed profile's store ───────────────────

/// `RAVEN_TEST_SEALED_SESSIONS` (test builds only; a release or a debug
/// binary never reads it): `keyed` runs every test's session store as a
/// sealed profile's (schema 4 from its creation), `migrated` creates each
/// store at schema 1 and moves it at that first open. The temp folder gets a
/// lab key file (the test build's K_hist, never a keychain item).
pub(crate) mod test_switch {
    #[cfg(test)]
    use std::cell::Cell;
    #[cfg(test)]
    use std::path::Path;

    #[cfg(test)]
    thread_local! {
        /// A test's own sealed profile without a store move at its open
        /// (another instance staging a journal mid-open).
        static NO_MOVE: Cell<bool> = const { Cell::new(false) };
        /// A test that decides the layout itself ignores the switch.
        static OFF: Cell<bool> = const { Cell::new(false) };
    }

    #[cfg(test)]
    fn setting() -> Option<String> {
        if OFF.with(Cell::get) {
            return None;
        }
        std::env::var("RAVEN_TEST_SEALED_SESSIONS")
            .ok()
            .filter(|v| v == "keyed" || v == "migrated")
    }

    /// This thread's tests ignore `RAVEN_TEST_SEALED_SESSIONS`.
    #[cfg(test)]
    pub(crate) fn off() {
        OFF.with(|off| off.set(true));
    }

    /// The suite asks for a sealed store: `data_dir` gets its lab key now.
    #[cfg(test)]
    pub(crate) fn seals(data_dir: &Path) -> bool {
        if setting().is_none() {
            return false;
        }
        if crate::at_rest::keys_cached(data_dir).is_err() {
            // A key is loaded only at a top level (never under a data-dir
            // lock): a store first opened under one stays as it is.
            if crate::paths::thread_holds_raven_lock() {
                return false;
            }
            let marker = data_dir.join(crate::BACKEND_MARKER_NAME);
            if !marker.exists() {
                let _ = std::fs::write(&marker, b"locked-file\n");
            }
            crate::at_rest::tests::expect_key_file(data_dir);
            crate::at_rest::keys_load_with(data_dir, crate::at_rest::MigratePolicy::Allow)
                .expect("a lab key for the sealed test store");
        }
        true
    }

    /// A missing store is created at schema 1 and moved at once.
    pub(crate) fn creates_clear() -> bool {
        #[cfg(test)]
        {
            setting().as_deref() == Some("migrated")
        }
        #[cfg(not(test))]
        {
            false
        }
    }

    /// Run `open` with no store move at its open (this thread).
    #[cfg(test)]
    pub(crate) fn without_move<T>(open: impl FnOnce() -> T) -> T {
        NO_MOVE.with(|flag| flag.set(true));
        let out = open();
        NO_MOVE.with(|flag| flag.set(false));
        out
    }

    pub(crate) fn moves() -> bool {
        #[cfg(test)]
        {
            !NO_MOVE.with(Cell::get)
        }
        #[cfg(not(test))]
        {
            true
        }
    }
}

/// Tests of other modules that set a head's or a reset row's time by hand
/// (either layout).
#[cfg(test)]
impl IndexedSessionStore {
    /// Every reset row's `confirmed_at_ms` is `at_ms`.
    pub(crate) fn set_confirmed_at_for_tests(&mut self, at_ms: i64) {
        let Some(sealer) = self.layout.sealer() else {
            self.conn
                .execute(
                    "UPDATE indexed_session_reset SET confirmed_at_ms = ?1",
                    params![at_ms],
                )
                .unwrap();
            return;
        };
        let rows: Vec<(Vec<u8>, Vec<u8>)> = {
            let mut statement = self
                .conn
                .prepare("SELECT session_id, meta FROM indexed_session_reset")
                .unwrap();
            let mapped = statement
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap();
            mapped.collect::<Result<_, _>>().unwrap()
        };
        for (sid, meta) in rows {
            let mut meta: ResetMeta = sealer.open(RESET, &sid, &meta).unwrap();
            meta.confirmed_at_ms = Some(at_ms);
            self.conn
                .execute(
                    "UPDATE indexed_session_reset SET confirmed = 1, meta = ?2
                     WHERE session_id = ?1",
                    params![sid, sealer.seal(RESET, &sid, &meta)],
                )
                .unwrap();
        }
    }

    /// The head of `session_id` says it was created at `created_at_ms`.
    pub(crate) fn set_head_created_at_for_tests(
        &mut self,
        session_id: &[u8; 32],
        created_at_ms: i64,
    ) {
        let Some(sealer) = self.layout.sealer() else {
            self.conn
                .execute(
                    "UPDATE indexed_session_heads SET created_at_ms = ?1 WHERE session_id = ?2",
                    params![created_at_ms, session_id.as_slice()],
                )
                .unwrap();
            return;
        };
        let (record_key, meta): (Vec<u8>, Vec<u8>) = self
            .conn
            .query_row(
                "SELECT record_key, meta FROM indexed_session_heads WHERE session_id = ?1",
                params![session_id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let mut meta: HeadMeta = sealer.open(HEADS, &record_key, &meta).unwrap();
        meta.created_at_ms = created_at_ms;
        self.conn
            .execute(
                "UPDATE indexed_session_heads SET created_hour = ?2, meta = ?3
                 WHERE session_id = ?1",
                params![
                    session_id.as_slice(),
                    hour_down(created_at_ms),
                    sealer.seal(HEADS, &record_key, &meta)
                ],
            )
            .unwrap();
    }
}

/// Tests: a step that runs once at a point of this thread's next schema step
/// ([`prepare_schema`]), so a test can commit another opener's (or a seal's
/// or an unseal's) write in the window between two reads, or between the
/// reads and the writes.
#[cfg(test)]
pub(crate) mod schema_hook {
    use std::cell::RefCell;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum At {
        /// Right after a round (or the read-only view) has read the heads'
        /// shape.
        MidRead,
        /// After a round's reads, before its first write.
        BeforeWrite,
    }

    type Hook = (At, Box<dyn FnOnce()>);

    thread_local! {
        static HOOK: RefCell<Option<Hook>> = const { RefCell::new(None) };
    }

    /// Run `step` once at `at` in this thread's next schema step.
    pub(crate) fn set(at: At, step: impl FnOnce() + 'static) {
        HOOK.with(|hook| *hook.borrow_mut() = Some((at, Box::new(step))));
    }

    pub(super) fn run(at: At) {
        let step = HOOK.with(|hook| {
            let mut hook = hook.borrow_mut();
            match hook.take() {
                Some((when, step)) if when == at => Some(step),
                other => {
                    *hook = other;
                    None
                }
            }
        });
        if let Some(step) = step {
            step();
        }
    }
}
