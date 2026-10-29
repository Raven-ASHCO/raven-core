//! Durable state for the ATSAM Indexed Session Profile V1.
//!
//! This is the session store behind the LAN-direct and internet-direct
//! indexed-message paths. `lan_dispatch` (PairInit handling, message and ACK
//! acceptance, sending), the preflight of raven-node's `lan_direct` and
//! `internet_direct`, and the ash PairInit, chat-poll and inbox commands all
//! open it, usually once per message or poll. The store itself enforces no
//! live gate. Live use is gated per slice by those callers
//! (`lan_direct_live_enabled`, `internet_direct_live_enabled`, and
//! `RAVEN_LAB_TEST_A` for the lab flows), while
//! [`INDEXED_SESSION_STORE_PRODUCTION_ENABLED`] stays `false`.
//!
//! Secret roots, chain keys, skipped message keys, and the write-ahead
//! acceptance journal live in a platform-protected backend. SQLite contains
//! public binding/dedup metadata plus locally sealed inbox and ACK-intent
//! records.
//!
//! Mutation ordering is deliberately asymmetric: the protected head is
//! replaced first and SQLite commits second. A crash between those operations
//! can burn an outbound index, but reopening only fast-forwards metadata and
//! therefore never rolls a ratchet back or reuses a send key. Inbound endpoint
//! acceptance uses a protected pending journal to bridge the protected-store /
//! SQLite commit boundary without ever journaling plaintext. Journaled
//! mutations write their SQLite rows into the still-open transaction before
//! the protected replacement, so a journal is only ever written for rows that
//! already satisfied every database constraint; the journal is cleared later
//! under a fresh write lock and only if it is still the current one.
//!
//! ACK intent creation, origin-side ACK acceptance, outbound message
//! preparation, and ACK materialization are implemented here. Outbound paths
//! use the same protected-journal ordering and only hand immutable ciphertext
//! to an idempotent durable queue callback.

#[cfg(test)]
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

mod custody;
mod deleted;
mod endpoints;
mod horizon;
mod letters;
mod parked;
mod renewal;
mod reset;
mod sealed;
pub use custody::{fetch_days, register_days, MailboxDirection, QueuedAckRow, SessionHeadMeta};
pub use deleted::InboxDeletion;
pub use endpoints::{InboxOrder, InboxPosition};
#[cfg(test)]
pub(crate) use horizon::test_rows;
pub use horizon::{
    forget_session_end, PeerSessionHorizon, SessionMetadataReader, SESSION_END_KEEP_MS,
};
pub use letters::{LetterRole, LetterSession};
pub use parked::{ParkedOutbound, ParkedPeer};
pub use renewal::{PeerRenewalState, RENEWAL_PENDING_MAX_BYTES};
pub use reset::{
    InboundSessionMatch, MessageCopy, PeerResetState, SessionResetInfo, SessionRetireCause,
};
#[cfg(test)]
pub(crate) use sealed::test_switch;
use sealed::Layout;
pub use sealed::{
    finish_scrub, forget_unreadable_sessions, migrate, needs_migration, received_position_of,
    rekey, reseal_rows, rows_off_epoch, scrub_pending, settle_journals, unseal,
};

use crate::ack::Ack;
use crate::atsam_indexed_session::{
    ack_base_key, decode_signed_ack, derive_route_tag, encode_signed_ack,
    open_indexed_message_with_key, parse_indexed_message_header, seal_indexed_message_with_key,
    session_context, Direction, SignedAck, PROFILE_ID,
};
use crate::atsam_kdf::{advance_chain_key, initial_chain_key, message_key};
use crate::bridge::authenticated_object_digest;
use crate::device_cert::{DeviceCertificate, DeviceRegistry};
use crate::envelope::{EnvType, Envelope};
use crate::identity::Identity;
use crate::pair_init::{
    device_certificate_hash, encode_response as encode_pair_response, init_hash as pair_init_hash,
    session_id as pair_session_id, session_id_from_init_hash,
    transcript_hash as pair_transcript_hash, verify_init, verify_response, PairInit, PairInitError,
    PairInitTrust, PairResponse,
};

/// Global production tripwire; stays `false`. It is not consulted by
/// [`IndexedSessionStore::open`]: callers gate live use per slice
/// (`lan_direct_live_enabled`, `internet_direct_live_enabled`) or through
/// [`live_enabled`] for the Lab Test A flows, and the gate tests assert it
/// stays off.
pub const INDEXED_SESSION_STORE_PRODUCTION_ENABLED: bool = false;

/// True only for the Lab Test A flows (`RAVEN_LAB_TEST_A`, debug builds),
/// unless a security notice holds them (P6.45, close-only).
pub fn live_enabled() -> bool {
    (INDEXED_SESSION_STORE_PRODUCTION_ENABLED || crate::pair_init::lab_test_a_enabled())
        && crate::suite_policy::hold_allows(crate::suite_registry::FEATURE_INDEXED_SESSION_STORE)
}
pub const INDEXED_SESSION_METADATA_FILE: &str = "indexed_sessions.sqlite";
pub const MAX_SKIPPED_KEYS: usize = 256;
pub const MAX_FORWARD_JUMP: u64 = 256;
pub const MAX_ENDPOINT_TEXT_BYTES: usize = 256 * 1024;
pub const MAX_ENDPOINT_FUTURE_SKEW_MS: u64 = 5 * 60 * 1_000;
pub const MAX_ENDPOINT_ENVELOPE_LIFETIME_MS: u64 = 7 * 24 * 60 * 60 * 1_000;

/// `PRAGMA user_version` of the SQLite metadata schema. Databases created
/// before versioning report 0 and were created by these same
/// `CREATE ... IF NOT EXISTS` statements, so they are stamped as version 1.
/// A newer version is refused rather than silently used under old constraints.
///
/// Version 2 (privacy pack PP.13, [`sealed`]): a sealed profile's store, its
/// heads, reset, re-seal and session-end tables keyed and sealed. Raised ON
/// PURPOSE: a build before PP.13 refuses such a store
/// ([`IndexedSessionStoreError::UnsupportedMetadataSchema`], fail closed: it
/// cannot send or receive) instead of reading keyed columns as clear ones,
/// and `raven privacy unseal` moves it back. A profile that is not sealed
/// keeps version 1 ([`sealed::CLEAR_VERSION`]), which every older build
/// opens.
///
/// Version 3 (privacy pack PP.14, [`endpoints`]): the endpoint tables keyed
/// and sealed too, the inbox ordered by an insertion `seq`. Raised ON
/// PURPOSE as well: a PP.13 build refuses it.
///
/// Version 4 (review B-sealed-stores-1, [`sealed`]): the heads' `init_id`
/// keyed (`kh_init_id`) and in their sealed meta, so the clear record key
/// no longer names the friend to anyone holding the file and a candidate's
/// public key. Raised ON PURPOSE too: the pack's earlier builds refuse it;
/// this build moves a schema-2 or schema-3 store to 4 as it moves a clear
/// one.
const METADATA_SCHEMA_VERSION: i64 = 4;
const STORE_MAGIC: &[u8; 8] = b"RVNISS01";
const LEGACY_STORE_VERSION: u8 = 1;
const ACCEPTANCE_STORE_VERSION: u8 = 2;
const STORE_VERSION: u8 = 3;
const STORE_INTEGRITY_LABEL: &[u8] = b"ATSAM/indexed-session/v1/store-integrity";
const LOCAL_STORAGE_LABEL: &[u8] = b"ATSAM/v1/endpoint-local-storage";
const LOCAL_STORAGE_AAD_LABEL: &[u8] = b"ATSAM/v1/endpoint-local-storage/aad";
const LOCAL_ROW_VERSION: u8 = 1;
const MAX_SEALED_LOCAL_ROW_BYTES: usize = MAX_ENDPOINT_TEXT_BYTES + 128;
const MAX_PENDING_OUTBOUND_BYTES: usize = MAX_ENDPOINT_TEXT_BYTES + 512;
const OUTBOUND_FLAGS: u16 = 0;
const OUTBOUND_HOP_LIMIT: u8 = 8;
/// Copies an envelope may be left with; `learning::carry::CARRY_CAP`
/// equals it (a test there pins the two together).
pub(crate) const OUTBOUND_REPLICATION_BUDGET: u8 = 2;
const RECORD_KEY_DOMAIN: &[u8] = b"rvn1/indexed-session/record-key/v1";
const BINDING_DIGEST_DOMAIN: &[u8] = b"rvn1/indexed-session/binding/v1";
/// The per-session keychain / Secret Service service; erase (PP.16) names
/// it on every system.
const PLATFORM_SERVICE: &str = "app.raven.node.atsam-indexed-session";
#[cfg(not(any(
    target_os = "macos",
    windows,
    all(target_os = "linux", target_env = "gnu")
)))]
const PROTECTED_STORE_UNAVAILABLE: &str = "no supported platform-protected secret backend";
const MAX_ADDRESS_BYTES: usize = 128;
const MAX_PROFILE_BYTES: usize = 64;

type EndpointReceiptIdentity = ([u8; 16], [u8; 32], u64);
type EndpointOutboxDbRow = (Vec<u8>, Vec<u8>, i64, Vec<u8>, Vec<u8>, i64, i64, Vec<u8>);
type EndpointOutboxDetailsDbRow = (Option<Vec<u8>>, Option<Vec<u8>>, Vec<u8>, Vec<u8>, i64);

struct AckReceiptIdentity {
    outer_message_id: [u8; 16],
    remote_device: [u8; 32],
    acked_message_id: [u8; 16],
}

fn endpoint_time_window_valid(created_at_ms: u64, expires_at_ms: u64, now_ms: u64) -> bool {
    created_at_ms < expires_at_ms
        && expires_at_ms.saturating_sub(created_at_ms) <= MAX_ENDPOINT_ENVELOPE_LIFETIME_MS
        && created_at_ms <= now_ms.saturating_add(MAX_ENDPOINT_FUTURE_SKEW_MS)
        && expires_at_ms > now_ms
}

fn valid_endpoint_text(plaintext: &[u8]) -> bool {
    if plaintext.is_empty() || plaintext.len() > MAX_ENDPOINT_TEXT_BYTES {
        return false;
    }
    let Ok(text) = std::str::from_utf8(plaintext) else {
        return false;
    };
    text.chars().all(|character| {
        character == '\t'
            || character == '\n'
            || character == '\r'
            || (character >= ' ' && character != '\u{7f}')
    })
}

#[derive(Clone, PartialEq, Eq)]
pub enum EndpointAcceptance {
    Committed {
        session_id: [u8; 32],
        object_digest: [u8; 32],
        message_id: [u8; 16],
        plaintext: Vec<u8>,
        /// The receive time stamped on the inbox row: strictly after the
        /// sender's latest row, so it may be above the caller's `now_ms`.
        /// Receiver dedup (P5.5) noted the message at this time; it tells
        /// this first copy from a later one
        /// ([`IndexedSessionStore::inbound_received_again`]).
        received_at_ms: u64,
    },
    Duplicate {
        session_id: [u8; 32],
        object_digest: [u8; 32],
        message_id: [u8; 16],
    },
}

impl fmt::Debug for EndpointAcceptance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (kind, plaintext) = match self {
            Self::Committed { .. } => ("Committed", Some("<redacted>")),
            Self::Duplicate { .. } => ("Duplicate", None),
        };
        let mut value = formatter.debug_struct("EndpointAcceptance");
        value
            .field("kind", &kind)
            .field("identifiers", &"<redacted>");
        if let Some(plaintext) = plaintext {
            value.field("plaintext", &plaintext);
        }
        value.finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct EndpointInboxRow {
    pub session_id: [u8; 32],
    pub object_digest: [u8; 32],
    pub message_id: [u8; 16],
    pub sender_device: [u8; 32],
    pub created_at_ms: u64,
    pub received_at_ms: u64,
    /// Where the row stands in its sender's inbox, in the store's order
    /// (PP.14): a reader saves it to list only the rows after it.
    pub position: InboxPosition,
    pub plaintext: Vec<u8>,
}

impl fmt::Debug for EndpointInboxRow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EndpointInboxRow")
            .field("identifiers", &"<redacted>")
            .field("created_at_ms", &self.created_at_ms)
            .field("received_at_ms", &self.received_at_ms)
            .field("plaintext", &"<redacted>")
            .finish()
    }
}

/// [`IndexedSessionStore::list_endpoint_inbox_counted`]: the rows that were
/// read, and how many committed rows were left out because they could not
/// be (a session or row that does not open, logged), so a reader never
/// takes "nothing could be read" for "nothing arrived".
#[derive(Debug, Default)]
pub struct EndpointInboxListing {
    pub rows: Vec<EndpointInboxRow>,
    pub unreadable: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EndpointAckIntentState {
    Pending = 0,
    Queued = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum EndpointDeliveryState {
    Sent = 0,
    Delivered = 1,
    Read = 2,
}

impl EndpointDeliveryState {
    fn from_u8(value: u8) -> Result<Self, IndexedSessionStoreError> {
        match value {
            0 => Ok(Self::Sent),
            1 => Ok(Self::Delivered),
            2 => Ok(Self::Read),
            _ => Err(IndexedSessionStoreError::CorruptEndpointState),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndpointAckAcceptance {
    Committed {
        session_id: [u8; 32],
        object_digest: [u8; 32],
        acked_message_id: [u8; 16],
        delivery_state: EndpointDeliveryState,
    },
    Duplicate {
        session_id: [u8; 32],
        object_digest: [u8; 32],
        acked_message_id: [u8; 16],
        delivery_state: EndpointDeliveryState,
    },
}

impl EndpointAckIntentState {
    fn from_u8(value: u8) -> Result<Self, IndexedSessionStoreError> {
        match value {
            0 => Ok(Self::Pending),
            1 => Ok(Self::Queued),
            _ => Err(IndexedSessionStoreError::CorruptEndpointState),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointAckIntent {
    pub session_id: [u8; 32],
    pub object_digest: [u8; 32],
    pub message_id: [u8; 16],
    pub remote_device: [u8; 32],
    pub status: u8,
    pub state: EndpointAckIntentState,
    pub immutable_ack_bytes: Option<Vec<u8>>,
}

/// A local-device signing capability borrowed from the exact current device
/// registry entry. Its fields are private so callers cannot construct a token
/// around an unregistered signer or a lookalike certificate.
pub struct AuthorizedEndpointDevice<'a> {
    certificate: &'a DeviceCertificate,
    signer: &'a Identity,
    registry: &'a DeviceRegistry,
}

impl fmt::Debug for AuthorizedEndpointDevice<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizedEndpointDevice")
            .field("device", &"<redacted>")
            .finish()
    }
}

impl<'a> AuthorizedEndpointDevice<'a> {
    /// Creates a short-lived authorization token. The registry remains
    /// immutably borrowed for the token lifetime, preventing a revoke/update
    /// race inside one outbound transaction.
    pub fn authorize(
        certificate: &'a DeviceCertificate,
        signer: &'a Identity,
        registry: &'a DeviceRegistry,
        now_ms: u64,
    ) -> Result<Self, IndexedSessionStoreError> {
        if signer.public_key_bytes() != certificate.device_ed_pub
            || certificate.verify(now_ms).is_err()
            || registry.revoked.contains(&certificate.device_id)
            || registry.certs.get(&certificate.device_id) != Some(certificate)
        {
            return Err(IndexedSessionStoreError::LocalDeviceUnauthorized);
        }
        Ok(Self {
            certificate,
            signer,
            registry,
        })
    }

    fn validate_current(&self, now_ms: u64) -> Result<(), IndexedSessionStoreError> {
        if self.signer.public_key_bytes() != self.certificate.device_ed_pub
            || self.certificate.verify(now_ms).is_err()
            || self.registry.revoked.contains(&self.certificate.device_id)
            || self.registry.certs.get(&self.certificate.device_id) != Some(self.certificate)
        {
            return Err(IndexedSessionStoreError::LocalDeviceUnauthorized);
        }
        Ok(())
    }

    fn sign_verified(&self, bytes: &[u8]) -> Result<[u8; 64], IndexedSessionStoreError> {
        let signature = self.signer.sign(bytes);
        if !Identity::verify(&self.certificate.device_ed_pub, bytes, &signature) {
            return Err(IndexedSessionStoreError::LocalSignerFailure);
        }
        Ok(signature)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EndpointOutboundKind {
    Message = 1,
    Ack = 2,
}

impl EndpointOutboundKind {
    fn from_u8(value: u8) -> Result<Self, IndexedSessionStoreError> {
        match value {
            1 => Ok(Self::Message),
            2 => Ok(Self::Ack),
            _ => Err(IndexedSessionStoreError::CorruptEndpointState),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EndpointOutboxState {
    Prepared = 0,
    Queued = 1,
}

impl EndpointOutboxState {
    fn from_u8(value: u8) -> Result<Self, IndexedSessionStoreError> {
        match value {
            0 => Ok(Self::Prepared),
            1 => Ok(Self::Queued),
            _ => Err(IndexedSessionStoreError::CorruptEndpointState),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct EndpointOutbound {
    pub kind: EndpointOutboundKind,
    pub session_id: [u8; 32],
    pub object_digest: [u8; 32],
    pub message_id: [u8; 16],
    pub recipient_device: [u8; 32],
    pub ratchet_index: u32,
    pub state: EndpointOutboxState,
    /// Exact signed RVN1 bytes. These contain ciphertext, never application
    /// plaintext or ratchet keys.
    pub immutable_envelope_bytes: Vec<u8>,
}

impl fmt::Debug for EndpointOutbound {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EndpointOutbound")
            .field("kind", &self.kind)
            .field("session", &"<redacted>")
            .field("object", &"<redacted>")
            .field("message", &"<redacted>")
            .field("recipient", &"<redacted>")
            .field("ratchet_index", &self.ratchet_index)
            .field("state", &self.state)
            .field("immutable_envelope_bytes", &"<ciphertext>")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LocalRole {
    Initiator = 0,
    Responder = 1,
}

impl LocalRole {
    fn from_u8(value: u8) -> Result<Self, IndexedSessionStoreError> {
        match value {
            0 => Ok(Self::Initiator),
            1 => Ok(Self::Responder),
            _ => Err(IndexedSessionStoreError::CorruptProtectedState),
        }
    }

    fn outbound_direction(self) -> Direction {
        match self {
            Self::Initiator => Direction::InitiatorToResponder,
            Self::Responder => Direction::ResponderToInitiator,
        }
    }

    fn inbound_direction(self) -> Direction {
        match self {
            Self::Initiator => Direction::ResponderToInitiator,
            Self::Responder => Direction::InitiatorToResponder,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SessionLifecycle {
    Provisional = 0,
    Confirmed = 1,
}

impl SessionLifecycle {
    fn from_u8(value: u8) -> Result<Self, IndexedSessionStoreError> {
        match value {
            0 => Ok(Self::Provisional),
            1 => Ok(Self::Confirmed),
            _ => Err(IndexedSessionStoreError::CorruptProtectedState),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RatchetLane {
    Message = 0,
    Ack = 1,
}

/// Public identity of a session record. The digest of these exact fields is
/// the protected-backend account and SQLite primary key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IndexedSessionRecordKey {
    pub profile_id: Vec<u8>,
    pub initiator_address: String,
    pub responder_address: String,
    pub initiator_device_ed25519: [u8; 32],
    pub responder_device_ed25519: [u8; 32],
    pub init_id: [u8; 16],
}

/// PairInit-bound public metadata. Secret material is never stored in this
/// value or in SQLite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedSessionBinding {
    pub key: IndexedSessionRecordKey,
    pub session_id: [u8; 32],
    pub init_hash: [u8; 32],
    pub transcript_hash: [u8; 32],
    pub initiator_cert_digest: [u8; 32],
    pub responder_cert_digest: [u8; 32],
    pub responder_prekey_bundle_digest: [u8; 32],
    pub signed_prekey_id: u32,
    pub one_time_prekey_id: u32,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    pub local_role: LocalRole,
    pub lifecycle: SessionLifecycle,
    pub response_hash: Option<[u8; 32]>,
}

impl IndexedSessionBinding {
    pub fn validate(&self) -> Result<(), IndexedSessionStoreError> {
        if self.key.profile_id.as_slice() != PROFILE_ID {
            return Err(IndexedSessionStoreError::UnsupportedProfile);
        }
        session_context(&self.key.initiator_address, &self.key.responder_address)
            .map_err(|_| IndexedSessionStoreError::InvalidBinding)?;
        if self.key.initiator_address.len() > MAX_ADDRESS_BYTES
            || self.key.responder_address.len() > MAX_ADDRESS_BYTES
            || self.key.profile_id.len() > MAX_PROFILE_BYTES
            || self.key.init_id == [0; 16]
            || self.created_at_ms >= self.expires_at_ms
            || self.created_at_ms > i64::MAX as u64
            || self.expires_at_ms > i64::MAX as u64
        {
            return Err(IndexedSessionStoreError::InvalidBinding);
        }
        let expected_session_id = session_id_from_init_hash(&self.init_hash);
        if self.session_id != expected_session_id {
            return Err(IndexedSessionStoreError::InvalidBinding);
        }
        match (self.lifecycle, self.response_hash) {
            (SessionLifecycle::Provisional, None) | (SessionLifecycle::Confirmed, Some(_)) => {}
            _ => return Err(IndexedSessionStoreError::InvalidBinding),
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum IndexedSessionStoreError {
    #[error("indexed session SQLite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("protected session store unavailable: {0}")]
    ProtectedStore(String),
    #[error("protected session state is missing")]
    ProtectedStateMissing,
    #[error("protected session state is corrupt")]
    CorruptProtectedState,
    #[error("protected state generation is behind metadata; refusing rollback")]
    RollbackDetected,
    #[error("session record not found")]
    NotFound,
    #[error("unsupported indexed-session profile")]
    UnsupportedProfile,
    #[error("invalid PairInit session binding")]
    InvalidBinding,
    #[error("same init_id is already bound to a different init hash")]
    InitIdConflict,
    #[error("session binding conflicts with an existing record")]
    BindingConflict,
    #[error("session is already confirmed with a different response")]
    ConfirmationConflict,
    #[error("endpoint session has not completed PairResponse key confirmation")]
    SessionNotConfirmed,
    #[error("ratchet index space exhausted")]
    IndexExhausted,
    #[error("receive index is a replay or no longer retained")]
    Replay,
    #[error("receive index jumps more than 256 messages")]
    ForwardJumpTooLarge,
    #[error("ciphertext authentication failed; receive state was not advanced")]
    AuthenticationFailed,
    #[error("endpoint envelope is malformed")]
    InvalidEndpointEnvelope,
    #[error("endpoint envelope is not a message")]
    EndpointTypeMismatch,
    #[error("endpoint envelope or bound session is not currently valid")]
    EndpointNotCurrentlyValid,
    #[error("endpoint indexed-message header is malformed or unsupported")]
    InvalidIndexedMessage,
    #[error("endpoint destination device hint does not match the selected session")]
    DeviceHintMismatch,
    #[error("endpoint route tag does not match the selected session")]
    RouteTagMismatch,
    #[error("endpoint sender device certificate is invalid")]
    InvalidDeviceCertificate,
    #[error("endpoint sender device is locally revoked")]
    RevokedDevice,
    #[error("endpoint sender device is not the PairInit-bound remote device")]
    DeviceBindingMismatch,
    #[error("endpoint outer device signature verification failed")]
    OuterSignatureInvalid,
    #[error("endpoint text payload violates the bounded application policy")]
    InvalidEndpointPayload,
    #[error("local endpoint device is not currently authorized")]
    LocalDeviceUnauthorized,
    #[error("local endpoint device is not the PairInit-bound device certificate")]
    LocalDeviceBindingMismatch,
    #[error("local endpoint signing operation failed verification")]
    LocalSignerFailure,
    #[error("outbound randomness source failed")]
    EndpointRandomnessUnavailable,
    #[error("an earlier outbound object must be retried before reserving another key")]
    OutboundPending,
    #[error("outbound identifier, nonce, or immutable object collides with durable state")]
    OutboundCollision,
    #[error("durable outbound queue handoff failed or returned the wrong object digest")]
    OutboundQueueHandoff,
    #[error("outbound object does not match its protected journal or committed intent")]
    OutboundBindingMismatch,
    #[error("authenticated sender reused a logical message ID for a different object")]
    LogicalMessageConflict,
    #[error("endpoint inbox/receipt/ACK-intent state is corrupt")]
    CorruptEndpointState,
    #[error("local inbox authentication failed")]
    LocalInboxAuthenticationFailed,
    #[error("immutable ACK bytes conflict with a previously prepared retry")]
    AckBytesConflict,
    #[error("ACK enqueue failed")]
    AckEnqueue,
    #[error("ACK does not match an exact outstanding message and recipient device")]
    AckOutstandingMismatch,
    #[error("ACK inner timestamp does not equal the authenticated outer timestamp")]
    AckTimestampMismatch,
    #[error("ACK inner device signature verification failed")]
    AckInnerSignatureInvalid,
    #[error("authenticated ACK nonce was reused for a different object")]
    AckNonceConflict,
    #[error("PairInit verification failed: {0}")]
    PairInit(#[from] PairInitError),
    #[error("indexed session metadata schema version {0} is newer than this build supports")]
    UnsupportedMetadataSchema(i64),
    /// A sealed profile's store, and this process holds no at-rest key: the
    /// store waits for it (never read or written in clear; PP.13).
    #[error("the session store is locked: {0}")]
    MetaKeyUnavailable(String),
    /// The move of the store's metadata to or from its keyed schema stopped
    /// (nothing was changed; PP.13).
    #[error("indexed session metadata: {0}")]
    MetadataMigration(String),
    #[error("session was retired after the contact reset it; a newer session is required")]
    SessionRetired,
    /// The application policy (ATSAM_ENDPOINT_TRANSACTION_V1 §1 step 7)
    /// deferred the message: nothing was committed, and the same bytes are
    /// accepted later as a fresh object.
    #[error("APP_DEFERRED: the message was deferred before commit; nothing was stored")]
    ApplicationDeferred,
    /// A Raven security notice marks the session profile
    /// (`atsam/indexed-session/v1` or `rvna1/3`) BROKEN (P6.45): nothing is
    /// sealed or accepted on the session and nothing changed; it is held
    /// until Raven is updated (this build has no next profile to re-seal
    /// under).
    #[error("SUITE_HELD: a Raven security notice says this session's security method is no longer safe; Raven holds the session until it is updated")]
    SuiteHeld,
    #[cfg(test)]
    #[error("test crash after protected write")]
    InjectedCrashAfterProtectedWrite,
    #[cfg(test)]
    #[error("test endpoint failure at {0:?}")]
    InjectedEndpointFailure(&'static str),
}

/// What the application policy decides about an opened inbound text
/// (`ATSAM_ENDPOINT_TRANSACTION_V1.md` §1 step 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundPolicy {
    Accept,
    /// Commit nothing; the name says why (a counter, never content).
    Defer(&'static str),
}

impl IndexedSessionStoreError {
    /// This intentionally never includes protected bytes, roots, or keys.
    pub fn redacted_display(&self) -> String {
        self.to_string()
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SendKeyReservation {
    #[zeroize(skip)]
    pub session_id: [u8; 32],
    #[zeroize(skip)]
    pub direction: Direction,
    #[zeroize(skip)]
    pub lane: RatchetLane,
    #[zeroize(skip)]
    pub index: u32,
    pub key: [u8; 32],
}

impl fmt::Debug for SendKeyReservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SendKeyReservation")
            .field("session_id", &hex::encode(self.session_id))
            .field("direction", &self.direction)
            .field("lane", &self.lane)
            .field("index", &self.index)
            .field("key", &"<redacted>")
            .finish()
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct SendRatchet {
    next_index: u64,
    chain_key: [u8; 32],
}

struct ReceiveRatchet {
    next_index: u64,
    chain_key: [u8; 32],
    skipped_keys: BTreeMap<u32, [u8; 32]>,
}

impl Zeroize for ReceiveRatchet {
    fn zeroize(&mut self) {
        self.next_index.zeroize();
        self.chain_key.zeroize();
        for key in self.skipped_keys.values_mut() {
            key.zeroize();
        }
        self.skipped_keys.clear();
    }
}

impl Drop for ReceiveRatchet {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct SecretRatchets {
    root: [u8; 32],
    message_send: SendRatchet,
    ack_send: SendRatchet,
    message_receive: ReceiveRatchet,
    ack_receive: ReceiveRatchet,
}

struct ProtectedSessionState {
    generation: u64,
    binding: IndexedSessionBinding,
    ratchets: SecretRatchets,
    pending_acceptance: Option<PendingAcceptance>,
    pending_ack_acceptance: Option<PendingAckAcceptance>,
    pending_outbound: Option<PendingOutbound>,
}

impl Drop for ProtectedSessionState {
    fn drop(&mut self) {
        self.ratchets.zeroize();
    }
}

/// Recoverable write-ahead record stored only in the platform-protected
/// session blob. `sealed_local_inbox_row` is AEAD ciphertext and this type
/// never contains application plaintext.
struct PendingAcceptance {
    session_id: [u8; 32],
    object_digest: [u8; 32],
    message_id: [u8; 16],
    sender_device: [u8; 32],
    sealed_local_inbox_row: Vec<u8>,
    ack_status: u8,
    created_at_ms: u64,
    received_at_ms: u64,
    public_generation: u64,
}

struct PendingAckAcceptance {
    session_id: [u8; 32],
    object_digest: [u8; 32],
    outer_message_id: [u8; 16],
    remote_device: [u8; 32],
    acked_message_id: [u8; 16],
    status: u8,
    ack_nonce: [u8; 12],
    created_at_ms: u64,
    public_generation: u64,
}

/// Protected write-ahead record for one fully materialized outbound object.
/// The immutable bytes contain only an already-sealed, device-signed RVN1
/// envelope. Message plaintext and the reserved ratchet key are never stored.
struct PendingOutbound {
    kind: EndpointOutboundKind,
    session_id: [u8; 32],
    object_digest: [u8; 32],
    message_id: [u8; 16],
    recipient_device: [u8; 32],
    ratchet_index: u32,
    source_ack_intent: Option<[u8; 32]>,
    ack_nonce: Option<[u8; 12]>,
    seal_nonce: [u8; 12],
    anti_replay_nonce: [u8; 12],
    immutable_envelope_bytes: Vec<u8>,
    public_generation: u64,
}

impl fmt::Debug for PendingOutbound {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingOutbound")
            .field("kind", &self.kind)
            .field("identifiers", &"<redacted>")
            .field("ratchet_index", &self.ratchet_index)
            .field("immutable_envelope_bytes", &"<ciphertext>")
            .field("public_generation", &self.public_generation)
            .finish()
    }
}

impl Zeroize for PendingOutbound {
    fn zeroize(&mut self) {
        self.session_id.zeroize();
        self.object_digest.zeroize();
        self.message_id.zeroize();
        self.recipient_device.zeroize();
        self.ratchet_index.zeroize();
        if let Some(value) = self.source_ack_intent.as_mut() {
            value.zeroize();
        }
        if let Some(value) = self.ack_nonce.as_mut() {
            value.zeroize();
        }
        self.seal_nonce.zeroize();
        self.anti_replay_nonce.zeroize();
        self.immutable_envelope_bytes.zeroize();
        self.public_generation.zeroize();
    }
}

impl Drop for PendingOutbound {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl fmt::Debug for PendingAckAcceptance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingAckAcceptance")
            .field("identifiers", &"<redacted>")
            .field("status", &self.status)
            .field("ack_nonce", &"<redacted>")
            .field("created_at_ms", &self.created_at_ms)
            .field("public_generation", &self.public_generation)
            .finish()
    }
}

impl Zeroize for PendingAckAcceptance {
    fn zeroize(&mut self) {
        self.session_id.zeroize();
        self.object_digest.zeroize();
        self.outer_message_id.zeroize();
        self.remote_device.zeroize();
        self.acked_message_id.zeroize();
        self.status.zeroize();
        self.ack_nonce.zeroize();
        self.created_at_ms.zeroize();
        self.public_generation.zeroize();
    }
}

impl Drop for PendingAckAcceptance {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl fmt::Debug for PendingAcceptance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingAcceptance")
            .field("identifiers", &"<redacted>")
            .field("sealed_local_inbox_row", &"<sealed>")
            .field("ack_status", &self.ack_status)
            .field("created_at_ms", &self.created_at_ms)
            .field("received_at_ms", &self.received_at_ms)
            .field("public_generation", &self.public_generation)
            .finish()
    }
}

impl Zeroize for PendingAcceptance {
    fn zeroize(&mut self) {
        self.session_id.zeroize();
        self.object_digest.zeroize();
        self.message_id.zeroize();
        self.sender_device.zeroize();
        self.sealed_local_inbox_row.zeroize();
        self.ack_status.zeroize();
        self.created_at_ms.zeroize();
        self.received_at_ms.zeroize();
        self.public_generation.zeroize();
    }
}

impl Drop for PendingAcceptance {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EndpointFaultPoint {
    BeforeProtectedReplacement,
    AfterProtectedReplacement,
    BeforeDatabaseCommit,
    AfterDatabaseCommit,
    BeforeJournalClear,
    AfterJournalClear,
    #[cfg(test)]
    BeforeAckEnqueue,
    #[cfg(test)]
    AfterAckEnqueue,
    BeforeOutboundQueueHandoff,
    AfterOutboundQueueHandoff,
    AfterPruneSecretDelete,
}

impl EndpointFaultPoint {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::BeforeProtectedReplacement => "before protected replacement",
            Self::AfterProtectedReplacement => "after protected replacement",
            Self::BeforeDatabaseCommit => "before database commit",
            Self::AfterDatabaseCommit => "after database commit",
            Self::BeforeJournalClear => "before journal clear",
            Self::AfterJournalClear => "after journal clear",
            #[cfg(test)]
            Self::BeforeAckEnqueue => "before ACK enqueue",
            #[cfg(test)]
            Self::AfterAckEnqueue => "after ACK enqueue",
            Self::BeforeOutboundQueueHandoff => "before outbound queue handoff",
            Self::AfterOutboundQueueHandoff => "after outbound queue handoff",
            Self::AfterPruneSecretDelete => "after prune secret delete",
        }
    }
}

/// Identity of the single protected write-ahead journal a session may carry:
/// its kind plus the exact object digest it describes. Used to clear only the
/// journal a caller wrote or replayed, never a newer one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProtectedJournal {
    Acceptance([u8; 32]),
    AckAcceptance([u8; 32]),
    Outbound([u8; 32]),
}

fn maybe_injected_endpoint_fault(
    injected: Option<EndpointFaultPoint>,
    point: EndpointFaultPoint,
) -> Result<(), IndexedSessionStoreError> {
    #[cfg(test)]
    if injected == Some(point) {
        return Err(IndexedSessionStoreError::InjectedEndpointFailure(
            point.label(),
        ));
    }
    #[cfg(not(test))]
    let _ = (injected, point);
    Ok(())
}

trait ProtectedSessionBackend: Send + Sync {
    fn get(&self, account: &str) -> Result<Option<Vec<u8>>, IndexedSessionStoreError>;
    fn put(&self, account: &str, value: &[u8]) -> Result<(), IndexedSessionStoreError>;
    fn delete(&self, account: &str) -> Result<(), IndexedSessionStoreError>;
}

#[cfg(test)]
thread_local! {
    /// [`test_use_lab_secret_files`] was called on this thread.
    static LAB_SECRET_FILES: Cell<bool> = const { Cell::new(false) };
}

/// This test thread's stores keep session secrets in the lab `locked-file`
/// backend's files (`indexed-session-secrets/<record key hex>.bin`) whatever
/// the environment asks, for a test that looks at those files or blocks one.
/// A CI job that sets no backend (macOS, Windows) otherwise keeps them in
/// the Keychain, or in DPAPI files of another name.
#[cfg(test)]
pub(crate) fn test_use_lab_secret_files() {
    LAB_SECRET_FILES.with(|on| on.set(true));
}

/// Whether the lab-only plaintext session-secret backend was requested. It
/// stores roots and ratchet keys as plain 0600 files, so, like the identity
/// store, Release builds refuse the override instead of silently honoring it
/// (a stale CI `RAVEN_IDENTITY_BACKEND` must not downgrade a shipped node).
/// Test builds are always allowed.
fn force_locked_file_session_backend() -> Result<bool, IndexedSessionStoreError> {
    #[cfg(test)]
    if LAB_SECRET_FILES.with(Cell::get) {
        return Ok(true);
    }
    let requested = ["RAVEN_SESSION_BACKEND", "RAVEN_IDENTITY_BACKEND"]
        .iter()
        .any(|key| std::env::var_os(key).is_some_and(|v| v == "locked-file"));
    locked_file_session_backend_gate(requested, cfg!(debug_assertions) || cfg!(test))
}

fn locked_file_session_backend_gate(
    requested: bool,
    lab_build: bool,
) -> Result<bool, IndexedSessionStoreError> {
    if requested && !lab_build {
        return Err(IndexedSessionStoreError::ProtectedStore(
            "locked-file session backend is forbidden in Release builds".into(),
        ));
    }
    Ok(requested)
}

struct LockedFileSessionBackend {
    dir: PathBuf,
}

impl LockedFileSessionBackend {
    fn new(data_dir: &Path) -> Result<Self, IndexedSessionStoreError> {
        let dir = data_dir.join("indexed-session-secrets");
        std::fs::create_dir_all(&dir)
            .map_err(|error| IndexedSessionStoreError::ProtectedStore(error.to_string()))?;
        Ok(Self { dir })
    }

    fn path(&self, account: &str) -> PathBuf {
        let safe: String = account
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect();
        self.dir.join(format!("{safe}.bin"))
    }
}

impl ProtectedSessionBackend for LockedFileSessionBackend {
    fn get(&self, account: &str) -> Result<Option<Vec<u8>>, IndexedSessionStoreError> {
        let path = self.path(account);
        if !path.exists() {
            return Ok(None);
        }
        std::fs::read(path)
            .map(Some)
            .map_err(|error| IndexedSessionStoreError::ProtectedStore(error.to_string()))
    }

    fn put(&self, account: &str, value: &[u8]) -> Result<(), IndexedSessionStoreError> {
        crate::paths::atomic_write_private(&self.path(account), value)
            .map_err(IndexedSessionStoreError::ProtectedStore)
    }

    fn delete(&self, account: &str) -> Result<(), IndexedSessionStoreError> {
        let path = self.path(account);
        if path.exists() {
            std::fs::remove_file(&path)
                .map_err(|error| IndexedSessionStoreError::ProtectedStore(error.to_string()))?;
        }
        Ok(())
    }
}

/// Session secrets in the profile's passphrase vault (non-macOS Unix without
/// a reachable Secret Service, docs/design/2026-10-linux-keystore.md; macOS
/// with a Raven passphrase, P6.40). Every
/// test build compiles it so the adapter is exercised on all CI hosts.
#[cfg(any(test, unix))]
struct VaultSessionBackend {
    vault: crate::keystore_vault::Vault,
}

#[cfg(any(test, unix))]
impl VaultSessionBackend {
    fn entry(account: &str) -> String {
        format!("{}{account}", crate::keystore_vault::SESSION_ENTRY_PREFIX)
    }
}

#[cfg(any(test, unix))]
fn vault_session_error(error: crate::keystore_vault::VaultError) -> IndexedSessionStoreError {
    IndexedSessionStoreError::ProtectedStore(format!("passphrase vault: {error}"))
}

#[cfg(any(test, unix))]
impl ProtectedSessionBackend for VaultSessionBackend {
    fn get(&self, account: &str) -> Result<Option<Vec<u8>>, IndexedSessionStoreError> {
        Ok(self
            .vault
            .get(&Self::entry(account))
            .map_err(vault_session_error)?
            .map(|mut value| std::mem::take(&mut *value)))
    }

    fn put(&self, account: &str, value: &[u8]) -> Result<(), IndexedSessionStoreError> {
        self.vault
            .put(&Self::entry(account), value)
            .map_err(vault_session_error)
    }

    fn delete(&self, account: &str) -> Result<(), IndexedSessionStoreError> {
        self.vault
            .delete(&Self::entry(account))
            .map_err(vault_session_error)
    }
}

#[cfg(not(any(
    target_os = "macos",
    windows,
    all(target_os = "linux", target_env = "gnu")
)))]
fn unsupported_protected_store_error() -> IndexedSessionStoreError {
    IndexedSessionStoreError::ProtectedStore(PROTECTED_STORE_UNAVAILABLE.into())
}

/// This data dir's prefix of every per-session keychain / Secret Service
/// account (`<namespace>:<hex(record_key)>`).
fn session_namespace(data_dir: &Path) -> String {
    let canonical = std::fs::canonicalize(data_dir).unwrap_or_else(|_| data_dir.to_path_buf());
    let mut hasher = Sha256::new();
    hasher.update(b"raven/indexed-session-store/v1/");
    hasher.update(canonical.to_string_lossy().as_bytes());
    hex::encode(hasher.finalize())
}

/// `raven erase` (PP.16): the per-session items' service and this data
/// dir's account namespace.
pub(crate) fn erase_namespace(data_dir: &Path) -> (&'static str, String) {
    (PLATFORM_SERVICE, session_namespace(data_dir))
}

/// `raven erase` (PP.16): the record key of every session head in this data
/// dir's store, read without changing it (the column stays clear in every
/// schema, review R20). Each session's keystore account is
/// `<namespace>:<hex(record_key)>`. No store or no heads table: none.
pub(crate) fn erase_record_keys(data_dir: &Path) -> Result<Vec<[u8; 32]>, String> {
    use rusqlite::OpenFlags;
    let path = data_dir.join(INDEXED_SESSION_METADATA_FILE);
    if std::fs::symlink_metadata(&path).is_err() {
        return Ok(Vec::new());
    }
    let conn = Connection::open_with_flags(
        &path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| e.to_string())?;
    let _ = conn.busy_timeout(Duration::from_secs(5));
    let heads: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = \
             'indexed_session_heads')",
            [],
            |row| row.get(0),
        )
        .map_err(|e| e.to_string())?;
    if !heads {
        return Ok(Vec::new());
    }
    let mut stmt = conn
        .prepare("SELECT record_key FROM indexed_session_heads")
        .map_err(|e| e.to_string())?;
    let keys = stmt
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    keys.into_iter()
        .map(|key| {
            <[u8; 32]>::try_from(key.as_slice())
                .map_err(|_| "a session head with a malformed record key".to_owned())
        })
        .collect()
}

/// The protected backend of `data_dir`'s sessions, as [`IndexedSessionStore::open`]
/// picks it: the lab `locked-file` backend when asked for (debug builds),
/// the passphrase vault where the profile records it (Unix; on macOS a Raven
/// passphrase, P6.40), the platform keystore otherwise. No SQLite open.
fn protected_backend(
    data_dir: &Path,
) -> Result<Arc<dyn ProtectedSessionBackend>, IndexedSessionStoreError> {
    // Lock v2 (P6.40): no session key while raven-node holds the profile
    // locked.
    crate::local_lock::refuse(data_dir)
        .map_err(|why| IndexedSessionStoreError::ProtectedStore(why.into()))?;
    if force_locked_file_session_backend()? {
        return Ok(Arc::new(LockedFileSessionBackend::new(data_dir)?));
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    let vault = crate::keystore_select::uses_vault(data_dir, true)
        .map_err(IndexedSessionStoreError::ProtectedStore)?;
    // macOS: a Raven passphrase (Lock v2, P6.40) moved them into the vault.
    #[cfg(target_os = "macos")]
    let vault = crate::keystore_select::has_passphrase(data_dir)
        .map_err(IndexedSessionStoreError::ProtectedStore)?;
    #[cfg(unix)]
    if vault {
        return Ok(Arc::new(VaultSessionBackend {
            vault: crate::keystore_vault::Vault::for_data_dir(data_dir),
        }));
    }
    Ok(Arc::new(PlatformProtectedSessionBackend::new(data_dir)?))
}

struct PlatformProtectedSessionBackend {
    #[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
    namespace: String,
    #[cfg(windows)]
    secret_dir: PathBuf,
}

impl PlatformProtectedSessionBackend {
    #[cfg(any(
        target_os = "macos",
        windows,
        all(target_os = "linux", target_env = "gnu")
    ))]
    fn new(data_dir: &Path) -> Result<Self, IndexedSessionStoreError> {
        std::fs::create_dir_all(data_dir)
            .map_err(|error| IndexedSessionStoreError::ProtectedStore(error.to_string()))?;
        #[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
        let namespace = session_namespace(data_dir);

        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        {
            use secret_service::{EncryptionType, SecretService};
            let service = SecretService::new(EncryptionType::Dh).map_err(|error| {
                IndexedSessionStoreError::ProtectedStore(format!(
                    "secret-service connection failed: {error}"
                ))
            })?;
            let collection = service.get_default_collection().map_err(|error| {
                IndexedSessionStoreError::ProtectedStore(format!(
                    "secret-service collection failed: {error}"
                ))
            })?;
            match collection.is_locked() {
                Ok(false) => {}
                Ok(true) => {
                    return Err(IndexedSessionStoreError::ProtectedStore(
                        "secret-service collection locked".into(),
                    ));
                }
                Err(error) => {
                    return Err(IndexedSessionStoreError::ProtectedStore(format!(
                        "secret-service is_locked failed: {error}"
                    )));
                }
            }
        }

        Ok(Self {
            #[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
            namespace,
            #[cfg(windows)]
            secret_dir: data_dir.join("indexed-session-secrets"),
        })
    }

    #[cfg(not(any(
        target_os = "macos",
        windows,
        all(target_os = "linux", target_env = "gnu")
    )))]
    fn new(_data_dir: &Path) -> Result<Self, IndexedSessionStoreError> {
        Err(unsupported_protected_store_error())
    }

    #[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
    fn scoped_account(&self, account: &str) -> String {
        format!("{}:{account}", self.namespace)
    }
}

/// Unsupported targets deliberately have a backend implementation so the
/// platform constructor remains type-correct when coerced to the backend trait
/// object. Every operation fails closed; this is not a file-backed fallback.
#[cfg(not(any(
    target_os = "macos",
    windows,
    all(target_os = "linux", target_env = "gnu")
)))]
impl ProtectedSessionBackend for PlatformProtectedSessionBackend {
    fn get(&self, _account: &str) -> Result<Option<Vec<u8>>, IndexedSessionStoreError> {
        Err(unsupported_protected_store_error())
    }

    fn put(&self, _account: &str, _value: &[u8]) -> Result<(), IndexedSessionStoreError> {
        Err(unsupported_protected_store_error())
    }

    fn delete(&self, _account: &str) -> Result<(), IndexedSessionStoreError> {
        Err(unsupported_protected_store_error())
    }
}

#[cfg(target_os = "macos")]
impl ProtectedSessionBackend for PlatformProtectedSessionBackend {
    fn get(&self, account: &str) -> Result<Option<Vec<u8>>, IndexedSessionStoreError> {
        use crate::macos_keychain::{guarded, KeychainWhat};
        use security_framework::passwords::get_generic_password;
        let scoped = self.scoped_account(account);
        match guarded(KeychainWhat::SessionSecret, || {
            get_generic_password(PLATFORM_SERVICE, &scoped)
        }) {
            Ok(value) => Ok(Some(value)),
            Err(error) if error.code() == -25_300 => Ok(None),
            Err(error) => Err(IndexedSessionStoreError::ProtectedStore(format!(
                "keychain read failed: {error}"
            ))),
        }
    }

    fn put(&self, account: &str, value: &[u8]) -> Result<(), IndexedSessionStoreError> {
        use crate::macos_keychain::{guarded, KeychainWhat};
        use security_framework::passwords::set_generic_password;
        let scoped = self.scoped_account(account);
        #[cfg(test)]
        crate::macos_keychain::track_new_test_item(PLATFORM_SERVICE, &scoped);
        guarded(KeychainWhat::SessionSecret, || {
            set_generic_password(PLATFORM_SERVICE, &scoped, value)
        })
        .map_err(|error| {
            IndexedSessionStoreError::ProtectedStore(format!("keychain update failed: {error}"))
        })
    }

    fn delete(&self, account: &str) -> Result<(), IndexedSessionStoreError> {
        use crate::macos_keychain::{guarded, KeychainWhat};
        use security_framework::passwords::delete_generic_password;
        let scoped = self.scoped_account(account);
        match guarded(KeychainWhat::SessionSecret, || {
            delete_generic_password(PLATFORM_SERVICE, &scoped)
        }) {
            Ok(()) => Ok(()),
            Err(error) if error.code() == -25_300 => Ok(()),
            Err(error) => Err(IndexedSessionStoreError::ProtectedStore(format!(
                "keychain delete failed: {error}"
            ))),
        }
    }
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
impl ProtectedSessionBackend for PlatformProtectedSessionBackend {
    fn get(&self, account: &str) -> Result<Option<Vec<u8>>, IndexedSessionStoreError> {
        use secret_service::{EncryptionType, SecretService};
        use std::collections::HashMap;
        let service = SecretService::new(EncryptionType::Dh).map_err(|error| {
            IndexedSessionStoreError::ProtectedStore(format!(
                "secret-service connection failed: {error}"
            ))
        })?;
        let collection = service.get_default_collection().map_err(|error| {
            IndexedSessionStoreError::ProtectedStore(format!(
                "secret-service collection failed: {error}"
            ))
        })?;
        match collection.is_locked() {
            Ok(false) => {}
            Ok(true) => {
                return Err(IndexedSessionStoreError::ProtectedStore(
                    "secret-service collection locked".into(),
                ));
            }
            Err(error) => {
                return Err(IndexedSessionStoreError::ProtectedStore(format!(
                    "secret-service is_locked failed: {error}"
                )));
            }
        }
        let scoped = self.scoped_account(account);
        let items = collection
            .search_items(HashMap::from([
                ("service", PLATFORM_SERVICE),
                ("account", scoped.as_str()),
            ]))
            .map_err(|error| {
                IndexedSessionStoreError::ProtectedStore(format!(
                    "secret-service search failed: {error}"
                ))
            })?;
        let Some(item) = items.into_iter().next() else {
            return Ok(None);
        };
        item.get_secret().map(Some).map_err(|error| {
            IndexedSessionStoreError::ProtectedStore(format!("secret-service read failed: {error}"))
        })
    }

    fn put(&self, account: &str, value: &[u8]) -> Result<(), IndexedSessionStoreError> {
        use secret_service::{EncryptionType, SecretService};
        use std::collections::HashMap;
        let service = SecretService::new(EncryptionType::Dh).map_err(|error| {
            IndexedSessionStoreError::ProtectedStore(format!(
                "secret-service connection failed: {error}"
            ))
        })?;
        let collection = service.get_default_collection().map_err(|error| {
            IndexedSessionStoreError::ProtectedStore(format!(
                "secret-service collection failed: {error}"
            ))
        })?;
        match collection.is_locked() {
            Ok(false) => {}
            Ok(true) => {
                return Err(IndexedSessionStoreError::ProtectedStore(
                    "secret-service collection locked".into(),
                ));
            }
            Err(error) => {
                return Err(IndexedSessionStoreError::ProtectedStore(format!(
                    "secret-service is_locked failed: {error}"
                )));
            }
        }
        let scoped = self.scoped_account(account);
        collection
            .create_item(
                "RAVEN ATSAM indexed session state",
                HashMap::from([("service", PLATFORM_SERVICE), ("account", scoped.as_str())]),
                value,
                true,
                "application/octet-stream",
            )
            .map_err(|error| {
                IndexedSessionStoreError::ProtectedStore(format!(
                    "secret-service update failed: {error}"
                ))
            })?;
        Ok(())
    }

    fn delete(&self, account: &str) -> Result<(), IndexedSessionStoreError> {
        use secret_service::{EncryptionType, SecretService};
        use std::collections::HashMap;
        let service = SecretService::new(EncryptionType::Dh).map_err(|error| {
            IndexedSessionStoreError::ProtectedStore(format!(
                "secret-service connection failed: {error}"
            ))
        })?;
        let collection = service.get_default_collection().map_err(|error| {
            IndexedSessionStoreError::ProtectedStore(format!(
                "secret-service collection failed: {error}"
            ))
        })?;
        match collection.is_locked() {
            Ok(false) => {}
            Ok(true) => {
                return Err(IndexedSessionStoreError::ProtectedStore(
                    "secret-service collection locked".into(),
                ));
            }
            Err(error) => {
                return Err(IndexedSessionStoreError::ProtectedStore(format!(
                    "secret-service is_locked failed: {error}"
                )));
            }
        }
        let scoped = self.scoped_account(account);
        let items = collection
            .search_items(HashMap::from([
                ("service", PLATFORM_SERVICE),
                ("account", scoped.as_str()),
            ]))
            .map_err(|error| {
                IndexedSessionStoreError::ProtectedStore(format!(
                    "secret-service search failed: {error}"
                ))
            })?;
        for item in items {
            item.delete().map_err(|error| {
                IndexedSessionStoreError::ProtectedStore(format!(
                    "secret-service delete failed: {error}"
                ))
            })?;
        }
        Ok(())
    }
}

#[cfg(windows)]
impl ProtectedSessionBackend for PlatformProtectedSessionBackend {
    fn get(&self, account: &str) -> Result<Option<Vec<u8>>, IndexedSessionStoreError> {
        let path = self.secret_dir.join(format!("{account}.dpapi"));
        if !path.exists() {
            return Ok(None);
        }
        let mut protected = std::fs::read(path)
            .map_err(|error| IndexedSessionStoreError::ProtectedStore(error.to_string()))?;
        let result = dpapi_unprotect(&protected);
        protected.zeroize();
        result.map(Some)
    }

    fn put(&self, account: &str, value: &[u8]) -> Result<(), IndexedSessionStoreError> {
        use std::io::Write;
        std::fs::create_dir_all(&self.secret_dir)
            .map_err(|error| IndexedSessionStoreError::ProtectedStore(error.to_string()))?;
        let target = self.secret_dir.join(format!("{account}.dpapi"));
        let temp = self
            .secret_dir
            .join(format!(".{account}.{:016x}.tmp", rand::random::<u64>()));
        let mut protected = dpapi_protect(value)?;
        let result = (|| {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp)
                .map_err(|error| IndexedSessionStoreError::ProtectedStore(error.to_string()))?;
            file.write_all(&protected)
                .and_then(|_| file.sync_all())
                .map_err(|error| IndexedSessionStoreError::ProtectedStore(error.to_string()))?;
            replace_file_windows(&temp, &target)
        })();
        protected.zeroize();
        if result.is_err() {
            let _ = std::fs::remove_file(&temp);
        }
        result
    }

    fn delete(&self, account: &str) -> Result<(), IndexedSessionStoreError> {
        let path = self.secret_dir.join(format!("{account}.dpapi"));
        if path.exists() {
            std::fs::remove_file(&path)
                .map_err(|error| IndexedSessionStoreError::ProtectedStore(error.to_string()))?;
        }
        Ok(())
    }
}

#[cfg(windows)]
fn dpapi_protect(value: &[u8]) -> Result<Vec<u8>, IndexedSessionStoreError> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };
    let input = CRYPT_INTEGER_BLOB {
        cbData: value
            .len()
            .try_into()
            .map_err(|_| IndexedSessionStoreError::ProtectedStore("state too large".into()))?,
        pbData: value.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let ok = unsafe {
        CryptProtectData(
            &input,
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 || output.pbData.is_null() {
        return Err(IndexedSessionStoreError::ProtectedStore(
            "CryptProtectData failed".into(),
        ));
    }
    let bytes = unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) };
    let result = bytes.to_vec();
    unsafe {
        LocalFree(output.pbData as _);
    }
    Ok(result)
}

#[cfg(windows)]
fn dpapi_unprotect(value: &[u8]) -> Result<Vec<u8>, IndexedSessionStoreError> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };
    let input = CRYPT_INTEGER_BLOB {
        cbData: value
            .len()
            .try_into()
            .map_err(|_| IndexedSessionStoreError::CorruptProtectedState)?,
        pbData: value.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let ok = unsafe {
        CryptUnprotectData(
            &input,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 || output.pbData.is_null() {
        return Err(IndexedSessionStoreError::ProtectedStore(
            "CryptUnprotectData failed".into(),
        ));
    }
    let bytes = unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) };
    let result = bytes.to_vec();
    unsafe {
        // The output buffer holds the decrypted session state (roots, chain
        // and skipped keys); wipe it before handing it back to the allocator.
        std::ptr::write_bytes(output.pbData, 0, output.cbData as usize);
        LocalFree(output.pbData as _);
    }
    Ok(result)
}

#[cfg(windows)]
fn replace_file_windows(temp: &Path, target: &Path) -> Result<(), IndexedSessionStoreError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };
    let mut from: Vec<u16> = temp.as_os_str().encode_wide().collect();
    from.push(0);
    let mut to: Vec<u16> = target.as_os_str().encode_wide().collect();
    to.push(0);
    let ok = unsafe {
        MoveFileExW(
            from.as_ptr(),
            to.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if ok == 0 {
        return Err(IndexedSessionStoreError::ProtectedStore(
            "atomic DPAPI state replacement failed".into(),
        ));
    }
    Ok(())
}

/// The metadata database holds the public communication graph (addresses,
/// device keys, message IDs, timestamps, delivery states) and outbox
/// ciphertext. Create it owner-only before SQLite does: SQLite gives the
/// `-wal`/`-shm` files it creates the database file's mode.
fn precreate_owner_only_metadata_file(metadata_path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let _ = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(metadata_path);
    }
    #[cfg(not(unix))]
    let _ = metadata_path;
}

/// Tightens a database (and its WAL/SHM side files) that an earlier build
/// created under the process umask. Best effort, like the data-dir lock
/// files: a filesystem without POSIX modes must not make sessions unreachable.
fn restrict_metadata_file_permissions(metadata_path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for suffix in ["", "-wal", "-shm"] {
            let mut candidate = metadata_path.as_os_str().to_owned();
            candidate.push(suffix);
            let candidate = PathBuf::from(candidate);
            if candidate.exists() {
                let _ =
                    std::fs::set_permissions(&candidate, std::fs::Permissions::from_mode(0o600));
            }
        }
    }
    #[cfg(not(unix))]
    let _ = metadata_path;
}

/// The endpoint tables (receipts, inbox, ACK intents, outstanding messages,
/// ACK receipts, outbox): schema 1's columns in both shapes until PP.14.
const ENDPOINT_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS endpoint_receipts (
               session_id BLOB NOT NULL CHECK(length(session_id) = 32),
               object_digest BLOB NOT NULL CHECK(length(object_digest) = 32),
               message_id BLOB NOT NULL CHECK(length(message_id) = 16),
               sender_device BLOB NOT NULL CHECK(length(sender_device) = 32),
               session_generation INTEGER NOT NULL CHECK(session_generation >= 0),
               PRIMARY KEY(session_id, object_digest),
               UNIQUE(session_id, sender_device, message_id),
               FOREIGN KEY(session_id) REFERENCES indexed_session_heads(session_id)
             );
             CREATE TABLE IF NOT EXISTS endpoint_inbox (
               session_id BLOB NOT NULL CHECK(length(session_id) = 32),
               object_digest BLOB NOT NULL CHECK(length(object_digest) = 32),
               message_id BLOB NOT NULL CHECK(length(message_id) = 16),
               sender_device BLOB NOT NULL CHECK(length(sender_device) = 32),
               created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
               received_at_ms INTEGER NOT NULL CHECK(received_at_ms >= 0),
               sealed_local_row BLOB NOT NULL,
               PRIMARY KEY(session_id, object_digest),
               FOREIGN KEY(session_id, object_digest)
                 REFERENCES endpoint_receipts(session_id, object_digest)
             );
             CREATE TABLE IF NOT EXISTS endpoint_ack_intents (
               session_id BLOB NOT NULL CHECK(length(session_id) = 32),
               object_digest BLOB NOT NULL CHECK(length(object_digest) = 32),
               message_id BLOB NOT NULL CHECK(length(message_id) = 16),
               remote_device BLOB NOT NULL CHECK(length(remote_device) = 32),
               status INTEGER NOT NULL CHECK(status IN (1, 2)),
               state INTEGER NOT NULL CHECK(state IN (0, 1)),
               immutable_ack_bytes BLOB,
               PRIMARY KEY(session_id, object_digest),
               FOREIGN KEY(session_id, object_digest)
                 REFERENCES endpoint_receipts(session_id, object_digest)
             );
             CREATE TABLE IF NOT EXISTS endpoint_outstanding_messages (
               session_id BLOB NOT NULL CHECK(length(session_id) = 32),
               message_id BLOB NOT NULL CHECK(length(message_id) = 16),
               recipient_device BLOB NOT NULL CHECK(length(recipient_device) = 32),
               delivery_state INTEGER NOT NULL CHECK(delivery_state IN (0, 1, 2)),
               PRIMARY KEY(session_id, message_id, recipient_device),
               FOREIGN KEY(session_id) REFERENCES indexed_session_heads(session_id)
             );
             CREATE TABLE IF NOT EXISTS endpoint_ack_receipts (
               session_id BLOB NOT NULL CHECK(length(session_id) = 32),
               object_digest BLOB NOT NULL CHECK(length(object_digest) = 32),
               outer_message_id BLOB NOT NULL CHECK(length(outer_message_id) = 16),
               remote_device BLOB NOT NULL CHECK(length(remote_device) = 32),
               acked_message_id BLOB NOT NULL CHECK(length(acked_message_id) = 16),
               status INTEGER NOT NULL CHECK(status IN (1, 2)),
               ack_nonce BLOB NOT NULL CHECK(length(ack_nonce) = 12),
               created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
               session_generation INTEGER NOT NULL CHECK(session_generation >= 0),
               PRIMARY KEY(session_id, object_digest),
               UNIQUE(session_id, remote_device, outer_message_id),
               UNIQUE(session_id, remote_device, ack_nonce),
               FOREIGN KEY(session_id) REFERENCES indexed_session_heads(session_id)
             );
             CREATE TABLE IF NOT EXISTS endpoint_outbox (
               session_id BLOB NOT NULL CHECK(length(session_id) = 32),
               object_digest BLOB NOT NULL CHECK(length(object_digest) = 32),
               kind INTEGER NOT NULL CHECK(kind IN (1, 2)),
               message_id BLOB NOT NULL CHECK(length(message_id) = 16),
               recipient_device BLOB NOT NULL CHECK(length(recipient_device) = 32),
               ratchet_index INTEGER NOT NULL CHECK(ratchet_index >= 0),
               source_ack_intent BLOB CHECK(source_ack_intent IS NULL OR length(source_ack_intent) = 32),
               ack_nonce BLOB CHECK(ack_nonce IS NULL OR length(ack_nonce) = 12),
               seal_nonce BLOB NOT NULL CHECK(length(seal_nonce) = 12),
               anti_replay_nonce BLOB NOT NULL CHECK(length(anti_replay_nonce) = 12),
               immutable_envelope_bytes BLOB NOT NULL
                 CHECK(length(immutable_envelope_bytes) >= 86
                   AND length(immutable_envelope_bytes) <= 262656),
               state INTEGER NOT NULL CHECK(state IN (0, 1)),
               session_generation INTEGER NOT NULL CHECK(session_generation >= 0),
               PRIMARY KEY(session_id, object_digest),
               UNIQUE(session_id, message_id),
               UNIQUE(session_id, seal_nonce),
               UNIQUE(session_id, anti_replay_nonce),
               UNIQUE(session_id, ack_nonce),
               UNIQUE(session_id, source_ack_intent),
               CHECK((kind = 1 AND source_ack_intent IS NULL AND ack_nonce IS NULL)
                  OR (kind = 2 AND source_ack_intent IS NOT NULL AND ack_nonce IS NOT NULL)),
               FOREIGN KEY(session_id) REFERENCES indexed_session_heads(session_id)
             );";

/// A rebuild error as the store reports it (nothing was changed).
fn rebuild_error(error: crate::sqlite_rebuild::RebuildError) -> IndexedSessionStoreError {
    use crate::sqlite_rebuild::RebuildError;
    match error {
        RebuildError::Sqlite(error) => IndexedSessionStoreError::Sqlite(error),
        RebuildError::Key(
            error @ (crate::at_rest::AtRestError::KeyUnavailable(_)
            | crate::at_rest::AtRestError::KeyLost(_)),
        ) => IndexedSessionStoreError::MetaKeyUnavailable(error.to_string()),
        other => IndexedSessionStoreError::MetadataMigration(other.to_string()),
    }
}

/// How often one operation re-runs protected-journal recovery because another
/// store instance staged a journal after the previous recovery finished.
const MAX_JOURNAL_RECOVERY_ATTEMPTS: usize = 5;
/// [`IndexedSessionStore::open`] retries a BUSY first open this many times
/// (10 ms doubling to 200 ms: about 1.5 s in all).
const OPEN_BUSY_RETRIES: usize = 10;

/// SQLite refused for a lock another connection holds (the open race).
fn sqlite_busy(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(e, _)
            if matches!(e.code, rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
    )
}

/// Replays any protected journal for `$record_key`, then opens the operation's
/// IMMEDIATE transaction and loads the session. Evaluates to
/// `(Transaction, ProtectedSessionState)` where the state carries no pending
/// journal.
///
/// Recovery runs in its own transaction, so between it and the operation's
/// transaction the write lock is free. Another store instance can commit a
/// journaled mutation in that window and not yet have run its own journal
/// clear: the journal is healthy, not corruption. Replaying it inline would
/// write the protected backend before this transaction commits, which is not
/// crash-safe, so the transaction is dropped, the journal is replayed by the
/// normal recovery path, and the load is retried. Only a journal that survives
/// `MAX_JOURNAL_RECOVERY_ATTEMPTS` completed recoveries is reported as
/// `CorruptProtectedState`.
///
/// A macro rather than a method because the transaction borrows `$store.conn`:
/// a method that returns it from inside the retry loop cannot re-borrow the
/// store for the next recovery.
macro_rules! begin_journal_free_tx {
    ($store:expr, $backend:expr, $account:expr, $record_key:expr) => {{
        let mut attempt = 1usize;
        loop {
            $store.recover_pending_for_digest(&$record_key)?;
            #[cfg(test)]
            $store.run_after_recovery_hook();
            let tx = $store
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let state = load_and_reconcile(
                &tx,
                &$store.layout,
                $backend.as_ref(),
                &$account,
                &$record_key,
            )?;
            if protected_journal(&state)?.is_none() {
                break (tx, state);
            }
            if attempt >= MAX_JOURNAL_RECOVERY_ATTEMPTS {
                return Err(IndexedSessionStoreError::CorruptProtectedState);
            }
            attempt += 1;
        }
    }};
}

pub struct IndexedSessionStore {
    conn: Connection,
    backend: Arc<dyn ProtectedSessionBackend>,
    /// Schema 1, or the keyed schema 2 (PP.13), 3 (PP.14) or 4 (review
    /// B-sealed-stores-1), and the keys of the latter.
    layout: Layout,
    /// This open moved the store to schema 4 (PP.13, PP.14;
    /// `sealed::migrate`).
    moved_now: bool,
    #[cfg(test)]
    crash_after_protected_write: bool,
    #[cfg(test)]
    endpoint_fault: Cell<Option<EndpointFaultPoint>>,
    /// Runs once after the next journal recovery, in the window before the
    /// caller's own transaction, so a test can interleave a second instance.
    #[cfg(test)]
    after_recovery_hook: RefCell<Option<Box<dyn FnOnce() + Send>>>,
}

impl IndexedSessionStore {
    /// Opens the platform implementation. GNU/Linux uses Secret Service or,
    /// per the profile's recorded keystore, the passphrase vault; musl/other
    /// Unix the vault; unsupported platforms fail closed. There is no
    /// plaintext file fallback:
    /// the lab-only `locked-file` backend (`RAVEN_SESSION_BACKEND` or
    /// `RAVEN_IDENTITY_BACKEND`) is honored in debug builds only and is
    /// refused in Release builds.
    pub fn open(data_dir: &Path) -> Result<Self, IndexedSessionStoreError> {
        // Two first opens of a fresh store (raven-node's LAN preflight and its
        // outbox worker's first scan, at service start) race on
        // `PRAGMA journal_mode=WAL` and the schema. SQLite then answers BUSY at
        // once, past busy_timeout, and the listener stayed down for a retry
        // cycle. Opening is idempotent: retry, briefly and bounded.
        let mut wait = Duration::from_millis(10);
        for _ in 0..OPEN_BUSY_RETRIES {
            match Self::open_once(data_dir) {
                Err(IndexedSessionStoreError::Sqlite(error)) if sqlite_busy(&error) => {
                    std::thread::sleep(wait);
                    wait = (wait * 2).min(Duration::from_millis(200));
                }
                other => return other,
            }
        }
        Self::open_once(data_dir)
    }

    fn open_once(data_dir: &Path) -> Result<Self, IndexedSessionStoreError> {
        // An unfinished erase (PP.16) closed the profile: no new session
        // secret may land in the keystore it is emptying.
        crate::erase::refuse_if_unfinished(data_dir)
            .map_err(IndexedSessionStoreError::ProtectedStore)?;
        let backend = protected_backend(data_dir)?;
        Self::open_with_backend(&data_dir.join(INDEXED_SESSION_METADATA_FILE), backend)
    }

    fn open_with_backend(
        metadata_path: &Path,
        backend: Arc<dyn ProtectedSessionBackend>,
    ) -> Result<Self, IndexedSessionStoreError> {
        let data_dir = metadata_path
            .parent()
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
        if let Some(parent) = metadata_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| IndexedSessionStoreError::ProtectedStore(error.to_string()))?;
        }
        // A sealed profile without its at-rest key opens nothing, and
        // creates nothing (PP.13).
        if sealed::profile_seals(&data_dir) {
            sealed::Sealer::cached(&data_dir)?;
        }
        precreate_owner_only_metadata_file(metadata_path);
        let mut conn = Connection::open(metadata_path)?;
        conn.busy_timeout(Duration::from_secs(10))?;
        // What a prune deletes is overwritten, not left in the file (PP.2).
        crate::paths::harden_sqlite(&conn)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;
             PRAGMA foreign_keys=ON;",
        )?;
        restrict_metadata_file_permissions(metadata_path);
        // The version, the shape and the profile's mode decide the schema;
        // every write there runs in an IMMEDIATE transaction that reads the
        // version again (PP.13).
        let layout = sealed::prepare_schema(&mut conn, &data_dir)?;
        let mut store = Self {
            conn,
            backend,
            layout,
            moved_now: false,
            #[cfg(test)]
            crash_after_protected_write: false,
            #[cfg(test)]
            endpoint_fault: Cell::new(None),
            #[cfg(test)]
            after_recovery_hook: RefCell::new(None),
        };
        // Journals replay against the schema they were written under: a
        // sealed profile's clear store moves only after this.
        store.recover_all_pending_acceptances()?;
        store.move_to_keyed(&data_dir)?;
        Ok(store)
    }

    /// A sealed profile's clear (or schema-2 or -3) store moves to schema 4
    /// (PP.13, PP.14, review B-sealed-stores-1): after the open's journal
    /// recovery, and only while no acceptance, ACK or outbound journal is
    /// pending (another instance may have staged one since; the next open
    /// or prune pass tries again). Too little free disk space defers the
    /// move as well: the store keeps working as it is. Any other failure
    /// fails the open (closed).
    fn move_to_keyed(&mut self, data_dir: &Path) -> Result<(), IndexedSessionStoreError> {
        if self.layout.is_current()
            || !sealed::profile_seals(data_dir)
            || !sealed::test_switch::moves()
        {
            return Ok(());
        }
        let sealer = sealed::Sealer::cached(data_dir)?;
        #[cfg(test)]
        self.run_after_recovery_hook();
        if self.journal_pending()? {
            return Ok(());
        }
        let path = self
            .conn
            .path()
            .map(PathBuf::from)
            .ok_or_else(|| IndexedSessionStoreError::MetadataMigration("no file".into()))?;
        let moved = match sealed::migrate_forward(
            &path,
            sealer.meta_keys(),
            &crate::disk_space::free_bytes,
        ) {
            Ok(done) => !done.already,
            Err(crate::sqlite_rebuild::RebuildError::NoSpace { .. }) => return Ok(()),
            Err(error) => return Err(rebuild_error(error)),
        };
        // Whoever moved it: the shape decides.
        if crate::sqlite_rebuild::shape(&self.conn, sealed::HEADS, sealed::KEYED_COLUMN)?
            == crate::sqlite_rebuild::Shape::Keyed
        {
            let shape = sealed::store_shape(&self.conn)?;
            self.layout = Layout::Keyed(sealer.with_shape(shape));
            self.moved_now = moved;
        }
        Ok(())
    }

    /// Whether any session's protected state holds a journal (a lock-free
    /// peek per session, as the open's recovery does).
    fn journal_pending(&self) -> Result<bool, IndexedSessionStoreError> {
        let record_keys: Vec<[u8; 32]> = {
            let mut statement = self
                .conn
                .prepare("SELECT record_key FROM indexed_session_heads")?;
            let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
            let mut keys = Vec::new();
            for row in rows {
                keys.push(exact_array::<32>(&row?)?);
            }
            keys
        };
        for record_key in record_keys {
            if self.protected_journal_present(&record_key)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Test-only raw fixture creation. Shipping callers must enter through
    /// `create_verified_pair_init_session`; accepting an arbitrary binding and
    /// root would bypass PairInit trust verification.
    #[cfg(test)]
    fn create_session(
        &mut self,
        binding: IndexedSessionBinding,
        root: [u8; 32],
    ) -> Result<(), IndexedSessionStoreError> {
        let root = Zeroizing::new(root);
        self.create_trusted_session(binding, &root)
    }

    fn create_trusted_session(
        &mut self,
        binding: IndexedSessionBinding,
        root: &[u8; 32],
    ) -> Result<(), IndexedSessionStoreError> {
        self.create_session_inner(binding, root)
    }

    /// Verifies the signed PairInit and its exact trust records, derives all
    /// public record identifiers through the frozen PairInit module, and then
    /// persists the supplied already-derived provisional root. Live: the
    /// LAN-direct PairInit initiator and responder (`lan_dispatch`) create
    /// their sessions through it in default builds.
    pub fn create_verified_pair_init_session(
        &mut self,
        init: &PairInit,
        trust: &PairInitTrust<'_>,
        now_ms: u64,
        local_role: LocalRole,
        root: [u8; 32],
    ) -> Result<IndexedSessionRecordKey, IndexedSessionStoreError> {
        // Wiped on every return path, including a refused PairInit.
        let root = Zeroizing::new(root);
        verify_init(init, trust, now_ms)?;
        let key = record_key_for_init(init);
        let binding = IndexedSessionBinding {
            key: key.clone(),
            session_id: pair_session_id(init)?,
            init_hash: pair_init_hash(init)?,
            transcript_hash: pair_transcript_hash(init)?,
            initiator_cert_digest: init.initiator_device_cert_hash,
            responder_cert_digest: init.responder_device_cert_hash,
            responder_prekey_bundle_digest: init.responder_prekey_bundle_hash,
            signed_prekey_id: init.signed_prekey_id,
            one_time_prekey_id: init.one_time_prekey_id,
            created_at_ms: init.created_at_ms,
            expires_at_ms: init.expires_at_ms,
            local_role,
            lifecycle: SessionLifecycle::Provisional,
            response_hash: None,
        };
        self.create_trusted_session(binding, &root)?;
        Ok(key)
    }

    fn create_session_inner(
        &mut self,
        binding: IndexedSessionBinding,
        root: &[u8; 32],
    ) -> Result<(), IndexedSessionStoreError> {
        binding.validate()?;
        let record_key = record_key_digest(&binding.key)?;
        let account = hex::encode(record_key);
        let backend = Arc::clone(&self.backend);
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let _in_tx = crate::paths::HeldMark::transaction();
        let metadata = metadata_head(&tx, &record_key)?;
        let mut protected = backend.get(&account)?;

        if let Some(bytes) = protected.as_mut() {
            let state_result = decode_protected_state(bytes);
            bytes.zeroize();
            let state = state_result?;
            ensure_record_key(&state.binding, &record_key)?;
            if state.binding.key.init_id == binding.key.init_id
                && state.binding.init_hash != binding.init_hash
            {
                return Err(IndexedSessionStoreError::InitIdConflict);
            }
            if !same_initial_binding(&state.binding, &binding) || state.ratchets.root != *root {
                return Err(IndexedSessionStoreError::BindingConflict);
            }
            reconcile_metadata(&tx, &self.layout, metadata, &record_key, &state)?;
            tx.commit()?;
            return Ok(());
        }

        if metadata.is_some() {
            return Err(IndexedSessionStoreError::ProtectedStateMissing);
        }
        if let Some(owner) = metadata_init_owner(&tx, &self.layout, &binding.key.init_id)? {
            if owner.init_hash != binding.init_hash {
                return Err(IndexedSessionStoreError::InitIdConflict);
            }
            if owner.record_key != record_key {
                return Err(IndexedSessionStoreError::BindingConflict);
            }
        }
        if metadata_session_owner(&tx, &binding.session_id)?.is_some() {
            return Err(IndexedSessionStoreError::BindingConflict);
        }

        let state = ProtectedSessionState {
            generation: 0,
            ratchets: initial_ratchets(&binding, root),
            binding,
            pending_acceptance: None,
            pending_ack_acceptance: None,
            pending_outbound: None,
        };
        let mut encoded = encode_protected_state(&state)?;
        let put_result = backend.put(&account, &encoded);
        encoded.zeroize();
        put_result?;
        #[cfg(test)]
        if self.crash_after_protected_write {
            return Err(IndexedSessionStoreError::InjectedCrashAfterProtectedWrite);
        }
        // The blob was proven absent under this IMMEDIATE transaction, so this
        // call created it. If its head cannot be recorded, delete it again:
        // nothing enumerates the keystore, so an unreferenced root would
        // otherwise live there forever. Best effort; a crash cannot clean up.
        if let Err(error) = insert_metadata(&tx, &self.layout, &record_key, &state) {
            drop(tx);
            let _ = backend.delete(&account);
            return Err(error);
        }
        if let Err(error) = tx.commit() {
            // A failed commit can be ambiguous about durability. Deleting the
            // secret of a head that did commit would strand the session on
            // `ProtectedStateMissing`, so delete only when the head is
            // provably absent.
            let head_absent = self
                .conn
                .query_row(
                    "SELECT 1 FROM indexed_session_heads WHERE record_key = ?1",
                    params![record_key.as_slice()],
                    |row| row.get::<_, i64>(0),
                )
                .optional()
                .is_ok_and(|head| head.is_none());
            if head_absent {
                let _ = backend.delete(&account);
            }
            return Err(error.into());
        }
        Ok(())
    }

    #[cfg(test)]
    fn reserve_send_key(
        &mut self,
        key: &IndexedSessionRecordKey,
        lane: RatchetLane,
    ) -> Result<SendKeyReservation, IndexedSessionStoreError> {
        self.recover_pending_for_key(key)?;
        let record_key = record_key_digest(key)?;
        let account = hex::encode(record_key);
        let backend = Arc::clone(&self.backend);
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let _in_tx = crate::paths::HeldMark::transaction();
        let mut state =
            load_and_reconcile(&tx, &self.layout, backend.as_ref(), &account, &record_key)?;
        if &state.binding.key != key {
            return Err(IndexedSessionStoreError::BindingConflict);
        }
        let direction = state.binding.local_role.outbound_direction();
        let (sender, recipient) = endpoints_for_direction(&state.binding, direction);
        let ratchet = match lane {
            RatchetLane::Message => &mut state.ratchets.message_send,
            RatchetLane::Ack => &mut state.ratchets.ack_send,
        };
        if ratchet.next_index > u32::MAX as u64 {
            return Err(IndexedSessionStoreError::IndexExhausted);
        }
        let index = ratchet.next_index as u32;
        let mut reserved_key = message_key(&ratchet.chain_key, sender, recipient);
        ratchet.chain_key = advance_chain_key(&ratchet.chain_key);
        ratchet.next_index += 1;
        state.generation = state
            .generation
            .checked_add(1)
            .ok_or(IndexedSessionStoreError::IndexExhausted)?;
        let result = write_mutation(
            &tx,
            backend.as_ref(),
            &account,
            &record_key,
            &state,
            #[cfg(test)]
            self.crash_after_protected_write,
        );
        if let Err(error) = result {
            reserved_key.zeroize();
            return Err(error);
        }
        tx.commit()?;
        Ok(SendKeyReservation {
            session_id: state.binding.session_id,
            direction,
            lane,
            index,
            key: reserved_key,
        })
    }

    /// Supplies a candidate receive key to `authenticate` while holding the
    /// cross-process mutation lock. State advances only when the callback
    /// returns `Some`, then the protected head is durable before the value is
    /// returned. This does not make a caller's inbox write atomic with this
    /// commit.
    #[cfg(test)]
    fn authenticate_receive<T, F>(
        &mut self,
        key: &IndexedSessionRecordKey,
        lane: RatchetLane,
        index: u32,
        authenticate: F,
    ) -> Result<T, IndexedSessionStoreError>
    where
        F: FnOnce(&[u8; 32]) -> Option<T>,
    {
        self.recover_pending_for_key(key)?;
        let record_key = record_key_digest(key)?;
        let account = hex::encode(record_key);
        let backend = Arc::clone(&self.backend);
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let _in_tx = crate::paths::HeldMark::transaction();
        let mut state =
            load_and_reconcile(&tx, &self.layout, backend.as_ref(), &account, &record_key)?;
        if &state.binding.key != key {
            return Err(IndexedSessionStoreError::BindingConflict);
        }
        let direction = state.binding.local_role.inbound_direction();
        let (sender, recipient) = endpoints_for_direction(&state.binding, direction);
        let ratchet = match lane {
            RatchetLane::Message => &mut state.ratchets.message_receive,
            RatchetLane::Ack => &mut state.ratchets.ack_receive,
        };
        let mut candidate = prepare_receive_key(ratchet, index, sender, recipient)?;
        let Some(value) = authenticate(&candidate) else {
            candidate.zeroize();
            return Err(IndexedSessionStoreError::AuthenticationFailed);
        };
        candidate.zeroize();
        state.generation = state
            .generation
            .checked_add(1)
            .ok_or(IndexedSessionStoreError::IndexExhausted)?;
        write_mutation(
            &tx,
            backend.as_ref(),
            &account,
            &record_key,
            &state,
            #[cfg(test)]
            self.crash_after_protected_write,
        )?;
        tx.commit()?;
        Ok(value)
    }

    /// Seals, journals, commits, and durably hands off one text message. The
    /// API fixes all envelope policy fields and generates every identifier and
    /// nonce from the supplied cryptographic RNG. A failed queue handoff leaves
    /// one prepared outbox row; callers must use `retry_endpoint_outbound`
    /// rather than reserve a second ratchet key.
    #[allow(clippy::too_many_arguments)]
    pub fn send_message_envelope<R, F>(
        &mut self,
        key: &IndexedSessionRecordKey,
        text: &str,
        local_device: &AuthorizedEndpointDevice<'_>,
        created_at_ms: u64,
        expires_at_ms: u64,
        now_ms: u64,
        rng: &mut R,
        enqueue_idempotently: &mut F,
    ) -> Result<EndpointOutbound, IndexedSessionStoreError>
    where
        R: RngCore + CryptoRng,
        F: FnMut(&[u8; 32], &[u8]) -> Result<[u8; 32], ()>,
    {
        self.seal_message_inner(
            key,
            text,
            None,
            false,
            local_device,
            created_at_ms,
            expires_at_ms,
            now_ms,
            rng,
            enqueue_idempotently,
        )
    }

    /// One seal path for new messages (`message_id` None: a fresh random id)
    /// and re-sealed ones (the logical id of the copy in a retired session,
    /// or of a parked message: `unpark`, which must still be parked; its
    /// parked row goes with the outbox row, [`parked::unpark`]).
    #[allow(clippy::too_many_arguments)]
    fn seal_message_inner<R, F>(
        &mut self,
        key: &IndexedSessionRecordKey,
        text: &str,
        fixed_message_id: Option<[u8; 16]>,
        unpark: bool,
        local_device: &AuthorizedEndpointDevice<'_>,
        created_at_ms: u64,
        expires_at_ms: u64,
        now_ms: u64,
        rng: &mut R,
        enqueue_idempotently: &mut F,
    ) -> Result<EndpointOutbound, IndexedSessionStoreError>
    where
        R: RngCore + CryptoRng,
        F: FnMut(&[u8; 32], &[u8]) -> Result<[u8; 32], ()>,
    {
        refuse_held_suite()?;
        if fixed_message_id.is_some_and(|id| id == [0u8; 16]) {
            return Err(IndexedSessionStoreError::OutboundCollision);
        }
        if !valid_endpoint_text(text.as_bytes()) {
            return Err(IndexedSessionStoreError::InvalidEndpointPayload);
        }
        if !endpoint_time_window_valid(created_at_ms, expires_at_ms, now_ms)
            || created_at_ms > i64::MAX as u64
            || expires_at_ms > i64::MAX as u64
            || now_ms > i64::MAX as u64
        {
            return Err(IndexedSessionStoreError::EndpointNotCurrentlyValid);
        }
        #[cfg(test)]
        let endpoint_fault = self.endpoint_fault.take();
        #[cfg(not(test))]
        let endpoint_fault = None;

        let record_key = record_key_digest(key)?;
        let account = hex::encode(record_key);
        let backend = Arc::clone(&self.backend);
        let (tx, mut state) = begin_journal_free_tx!(self, backend, account, record_key);
        let _in_tx = crate::paths::HeldMark::transaction();
        let authorization_index = u32::try_from(state.ratchets.message_send.next_index)
            .map_err(|_| IndexedSessionStoreError::IndexExhausted)?;
        let cap = letters::provisional_message_cap(&tx, &state, EndpointOutboundKind::Message)?;
        validate_outbound_session_and_signer(
            &state,
            key,
            local_device,
            EndpointOutboundKind::Message,
            authorization_index,
            created_at_ms,
            expires_at_ms,
            now_ms,
            cap,
        )?;
        refuse_retired_message_lane(
            &tx,
            &self.layout,
            &state.binding.session_id,
            EndpointOutboundKind::Message,
        )?;
        // A parked message given up (or sealed already) is not brought back.
        if unpark {
            let parked = match &fixed_message_id {
                Some(id) => parked::is_parked(
                    &tx,
                    &self.layout,
                    remote_device_for_binding(&state.binding),
                    id,
                )?,
                None => false,
            };
            if !parked {
                return Err(IndexedSessionStoreError::NotFound);
            }
        }
        ensure_no_pending_protected_mutation(&state)?;
        // One prepared object per lane: a prepared ACK never blocks text and
        // a prepared message never blocks ACKs (independent ratchet lanes).
        if prepared_outbound_exists(
            &tx,
            &state.binding.session_id,
            EndpointOutboundKind::Message,
        )? {
            return Err(IndexedSessionStoreError::OutboundPending);
        }

        let message_id = match fixed_message_id {
            Some(id) => id,
            None => random_nonzero::<16, _>(rng)?,
        };
        let seal_nonce = random_nonzero::<12, _>(rng)?;
        let anti_replay_nonce = random_nonzero::<12, _>(rng)?;
        ensure_fresh_outbound_coordinates(
            &tx,
            &self.layout,
            &state.binding.session_id,
            &message_id,
            &seal_nonce,
            &anti_replay_nonce,
            None,
        )?;

        let direction = state.binding.local_role.outbound_direction();
        let (sender, recipient) = endpoints_for_direction(&state.binding, direction);
        let ratchet = &mut state.ratchets.message_send;
        if ratchet.next_index > u32::MAX as u64 {
            return Err(IndexedSessionStoreError::IndexExhausted);
        }
        let index = ratchet.next_index as u32;
        let mut reserved_key = message_key(&ratchet.chain_key, sender, recipient);
        ratchet.chain_key = advance_chain_key(&ratchet.chain_key);
        ratchet.next_index += 1;
        let sealed_result = seal_indexed_message_with_key(
            &reserved_key,
            &state.binding.key.initiator_address,
            &state.binding.key.responder_address,
            direction,
            index,
            &message_id,
            text.as_bytes(),
            &seal_nonce,
        );
        reserved_key.zeroize();
        let sealed =
            sealed_result.map_err(|_| IndexedSessionStoreError::OutboundBindingMismatch)?;
        let mut envelope = outbound_envelope(
            &state,
            EnvType::Message,
            index,
            message_id,
            anti_replay_nonce,
            created_at_ms,
            expires_at_ms,
            sealed,
        )?;
        sign_outbound_envelope(&mut envelope, local_device)?;
        let immutable_envelope_bytes = envelope.pack();
        validate_materialized_outbound(&envelope, &immutable_envelope_bytes)?;
        let object_digest = authenticated_object_digest(&envelope);
        if endpoint_outbound_by_object(
            &tx,
            &self.layout,
            &state.binding.session_id,
            &object_digest,
        )?
        .is_some()
        {
            return Err(IndexedSessionStoreError::OutboundCollision);
        }

        state.generation = state
            .generation
            .checked_add(1)
            .ok_or(IndexedSessionStoreError::IndexExhausted)?;
        state.pending_outbound = Some(PendingOutbound {
            kind: EndpointOutboundKind::Message,
            session_id: state.binding.session_id,
            object_digest,
            message_id,
            recipient_device: *remote_device_for_binding(&state.binding),
            ratchet_index: index,
            source_ack_intent: None,
            ack_nonce: None,
            seal_nonce,
            anti_replay_nonce,
            immutable_envelope_bytes,
            public_generation: state.generation,
        });

        let journal = stage_journaled_mutation(
            &tx,
            &self.layout,
            backend.as_ref(),
            &account,
            &record_key,
            &state,
            endpoint_fault,
        )?;
        maybe_injected_endpoint_fault(endpoint_fault, EndpointFaultPoint::BeforeDatabaseCommit)?;
        tx.commit()?;
        maybe_injected_endpoint_fault(endpoint_fault, EndpointFaultPoint::AfterDatabaseCommit)?;
        maybe_injected_endpoint_fault(endpoint_fault, EndpointFaultPoint::BeforeJournalClear)?;
        state.pending_outbound = None;
        self.clear_protected_journal(&account, &record_key, state.generation, journal)?;
        maybe_injected_endpoint_fault(endpoint_fault, EndpointFaultPoint::AfterJournalClear)?;
        self.handoff_endpoint_outbound(
            &state,
            &object_digest,
            local_device,
            now_ms,
            endpoint_fault,
            enqueue_idempotently,
        )
    }

    /// Materializes an ACK only from the exact committed inbox intent selected
    /// by `intent_object_digest`. The caller cannot supply an acknowledged ID,
    /// remote device, or status.
    #[allow(clippy::too_many_arguments)]
    pub fn enqueue_committed_ack<R, F>(
        &mut self,
        key: &IndexedSessionRecordKey,
        intent_object_digest: &[u8; 32],
        local_device: &AuthorizedEndpointDevice<'_>,
        created_at_ms: u64,
        expires_at_ms: u64,
        now_ms: u64,
        rng: &mut R,
        enqueue_idempotently: &mut F,
    ) -> Result<EndpointOutbound, IndexedSessionStoreError>
    where
        R: RngCore + CryptoRng,
        F: FnMut(&[u8; 32], &[u8]) -> Result<[u8; 32], ()>,
    {
        refuse_held_suite()?;
        if !endpoint_time_window_valid(created_at_ms, expires_at_ms, now_ms)
            || created_at_ms > i64::MAX as u64
            || expires_at_ms > i64::MAX as u64
            || now_ms > i64::MAX as u64
        {
            return Err(IndexedSessionStoreError::EndpointNotCurrentlyValid);
        }
        #[cfg(test)]
        let endpoint_fault = self.endpoint_fault.take();
        #[cfg(not(test))]
        let endpoint_fault = None;

        let record_key = record_key_digest(key)?;
        let account = hex::encode(record_key);
        let backend = Arc::clone(&self.backend);
        let (tx, mut state) = begin_journal_free_tx!(self, backend, account, record_key);
        let _in_tx = crate::paths::HeldMark::transaction();
        let authorization_index = u32::try_from(state.ratchets.ack_send.next_index)
            .map_err(|_| IndexedSessionStoreError::IndexExhausted)?;
        validate_outbound_session_and_signer(
            &state,
            key,
            local_device,
            EndpointOutboundKind::Ack,
            authorization_index,
            created_at_ms,
            expires_at_ms,
            now_ms,
            letters::provisional_message_cap(&tx, &state, EndpointOutboundKind::Ack)?,
        )?;
        refuse_retired_message_lane(
            &tx,
            &self.layout,
            &state.binding.session_id,
            EndpointOutboundKind::Ack,
        )?;
        ensure_no_pending_protected_mutation(&state)?;

        let intent = committed_ack_intent(
            &tx,
            &self.layout,
            &state.binding.session_id,
            intent_object_digest,
        )?;
        let receipt = endpoint_receipt_by_object(
            &tx,
            &self.layout,
            &state.binding.session_id,
            intent_object_digest,
        )?
        .ok_or(IndexedSessionStoreError::CorruptEndpointState)?;
        if intent.remote_device != *remote_device_for_binding(&state.binding)
            || receipt.0 != intent.message_id
            || receipt.1 != intent.remote_device
        {
            return Err(IndexedSessionStoreError::OutboundBindingMismatch);
        }
        retire_expired_prepared_acks(&tx, &self.layout, &state.binding.session_id, now_ms)?;
        if intent.state == EndpointAckIntentState::Queued {
            let existing = outbound_by_ack_intent(
                &tx,
                &self.layout,
                &state.binding.session_id,
                intent_object_digest,
            )?
            .ok_or(IndexedSessionStoreError::CorruptEndpointState)?;
            validate_committed_outbound(&tx, &self.layout, &state, &existing)?;
            tx.commit()?;
            return Ok(existing);
        }
        if let Some(existing) = outbound_by_ack_intent(
            &tx,
            &self.layout,
            &state.binding.session_id,
            intent_object_digest,
        )? {
            if intent.immutable_ack_bytes.as_deref()
                != Some(existing.immutable_envelope_bytes.as_slice())
            {
                return Err(IndexedSessionStoreError::OutboundBindingMismatch);
            }
            let object_digest = existing.object_digest;
            tx.commit()?;
            return self.handoff_endpoint_outbound(
                &state,
                &object_digest,
                local_device,
                now_ms,
                endpoint_fault,
                enqueue_idempotently,
            );
        }
        if let Some(bytes) = intent.immutable_ack_bytes.as_deref() {
            // Materialized bytes without an outbox row: the object expired
            // while still prepared and was retired. It is never re-materialized
            // under a second object for the same intent.
            if Envelope::unpack(bytes).is_some_and(|envelope| envelope.expires_at <= now_ms) {
                tx.commit()?;
                return Err(IndexedSessionStoreError::EndpointNotCurrentlyValid);
            }
            return Err(IndexedSessionStoreError::OutboundBindingMismatch);
        }
        if prepared_outbound_exists(&tx, &state.binding.session_id, EndpointOutboundKind::Ack)? {
            tx.commit()?;
            return Err(IndexedSessionStoreError::OutboundPending);
        }

        let message_id = random_nonzero::<16, _>(rng)?;
        let seal_nonce = random_nonzero::<12, _>(rng)?;
        let anti_replay_nonce = random_nonzero::<12, _>(rng)?;
        let ack_nonce = random_nonzero::<12, _>(rng)?;
        ensure_fresh_outbound_coordinates(
            &tx,
            &self.layout,
            &state.binding.session_id,
            &message_id,
            &seal_nonce,
            &anti_replay_nonce,
            Some(&ack_nonce),
        )?;

        let direction = state.binding.local_role.outbound_direction();
        let (sender, recipient) = endpoints_for_direction(&state.binding, direction);
        let ratchet = &mut state.ratchets.ack_send;
        if ratchet.next_index > u32::MAX as u64 {
            return Err(IndexedSessionStoreError::IndexExhausted);
        }
        let index = ratchet.next_index as u32;
        let mut reserved_key = message_key(&ratchet.chain_key, sender, recipient);
        ratchet.chain_key = advance_chain_key(&ratchet.chain_key);
        ratchet.next_index += 1;

        let ack_record = Ack {
            acked_message_id: intent.message_id,
            status: intent.status,
            ack_nonce,
            created_at: created_at_ms,
        };
        let signed_ack = SignedAck {
            signature: local_device.sign_verified(&ack_record.signing_bytes())?,
            record: ack_record,
        };
        let mut ack_plaintext = encode_signed_ack(&signed_ack)
            .map_err(|_| IndexedSessionStoreError::OutboundBindingMismatch)?;
        let sealed_result = seal_indexed_message_with_key(
            &reserved_key,
            &state.binding.key.initiator_address,
            &state.binding.key.responder_address,
            direction,
            index,
            &message_id,
            &ack_plaintext,
            &seal_nonce,
        );
        reserved_key.zeroize();
        ack_plaintext.zeroize();
        let sealed =
            sealed_result.map_err(|_| IndexedSessionStoreError::OutboundBindingMismatch)?;
        let mut envelope = outbound_envelope(
            &state,
            EnvType::Ack,
            index,
            message_id,
            anti_replay_nonce,
            created_at_ms,
            expires_at_ms,
            sealed,
        )?;
        sign_outbound_envelope(&mut envelope, local_device)?;
        let immutable_envelope_bytes = envelope.pack();
        validate_materialized_outbound(&envelope, &immutable_envelope_bytes)?;
        let object_digest = authenticated_object_digest(&envelope);
        if endpoint_outbound_by_object(
            &tx,
            &self.layout,
            &state.binding.session_id,
            &object_digest,
        )?
        .is_some()
        {
            return Err(IndexedSessionStoreError::OutboundCollision);
        }

        state.generation = state
            .generation
            .checked_add(1)
            .ok_or(IndexedSessionStoreError::IndexExhausted)?;
        state.pending_outbound = Some(PendingOutbound {
            kind: EndpointOutboundKind::Ack,
            session_id: state.binding.session_id,
            object_digest,
            message_id,
            recipient_device: intent.remote_device,
            ratchet_index: index,
            source_ack_intent: Some(*intent_object_digest),
            ack_nonce: Some(ack_nonce),
            seal_nonce,
            anti_replay_nonce,
            immutable_envelope_bytes,
            public_generation: state.generation,
        });

        let journal = stage_journaled_mutation(
            &tx,
            &self.layout,
            backend.as_ref(),
            &account,
            &record_key,
            &state,
            endpoint_fault,
        )?;
        maybe_injected_endpoint_fault(endpoint_fault, EndpointFaultPoint::BeforeDatabaseCommit)?;
        tx.commit()?;
        maybe_injected_endpoint_fault(endpoint_fault, EndpointFaultPoint::AfterDatabaseCommit)?;
        maybe_injected_endpoint_fault(endpoint_fault, EndpointFaultPoint::BeforeJournalClear)?;
        state.pending_outbound = None;
        self.clear_protected_journal(&account, &record_key, state.generation, journal)?;
        maybe_injected_endpoint_fault(endpoint_fault, EndpointFaultPoint::AfterJournalClear)?;
        self.handoff_endpoint_outbound(
            &state,
            &object_digest,
            local_device,
            now_ms,
            endpoint_fault,
            enqueue_idempotently,
        )
    }

    /// Retries an already prepared immutable object without reserving a key or
    /// invoking a signing operation/RNG. Current authorization of the exact
    /// PairInit-bound local device is still required. The queue callback must
    /// return the exact digest it durably persisted.
    pub fn retry_endpoint_outbound<F>(
        &mut self,
        key: &IndexedSessionRecordKey,
        object_digest: &[u8; 32],
        local_device: &AuthorizedEndpointDevice<'_>,
        now_ms: u64,
        enqueue_idempotently: &mut F,
    ) -> Result<EndpointOutbound, IndexedSessionStoreError>
    where
        F: FnMut(&[u8; 32], &[u8]) -> Result<[u8; 32], ()>,
    {
        self.recover_pending_for_key(key)?;
        let record_key = record_key_digest(key)?;
        let account = hex::encode(record_key);
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let _in_tx = crate::paths::HeldMark::transaction();
        let state = load_and_reconcile(
            &tx,
            &self.layout,
            self.backend.as_ref(),
            &account,
            &record_key,
        )?;
        if &state.binding.key != key {
            return Err(IndexedSessionStoreError::BindingConflict);
        }
        let row = endpoint_outbound_by_object(
            &tx,
            &self.layout,
            &state.binding.session_id,
            object_digest,
        )?
        .ok_or(IndexedSessionStoreError::NotFound)?;
        validate_committed_outbound(&tx, &self.layout, &state, &row)?;
        let envelope = Envelope::unpack(&row.immutable_envelope_bytes)
            .ok_or(IndexedSessionStoreError::InvalidEndpointEnvelope)?;
        let cap = letters::provisional_message_cap(&tx, &state, row.kind)?;
        validate_outbound_session_and_signer(
            &state,
            key,
            local_device,
            row.kind,
            row.ratchet_index,
            envelope.created_at,
            envelope.expires_at,
            now_ms,
            cap,
        )?;
        refuse_retired_message_lane(&tx, &self.layout, &state.binding.session_id, row.kind)?;
        tx.commit()?;
        if row.state == EndpointOutboxState::Queued {
            return Ok(row);
        }
        #[cfg(test)]
        let endpoint_fault = self.endpoint_fault.take();
        #[cfg(not(test))]
        let endpoint_fault = None;
        self.handoff_endpoint_outbound(
            &state,
            object_digest,
            local_device,
            now_ms,
            endpoint_fault,
            enqueue_idempotently,
        )
    }

    /// Returns bounded immutable ciphertext objects that still require queue
    /// handoff. Application plaintext is never exposed by this query.
    pub fn pending_endpoint_outbound(
        &self,
    ) -> Result<Vec<EndpointOutbound>, IndexedSessionStoreError> {
        self.pending_endpoint_outbound_for_recipient(None)
    }

    /// Like [`Self::pending_endpoint_outbound`], optionally limited to one
    /// recipient device so a send to Bob cannot dial Carol's ciphertext.
    pub fn pending_endpoint_outbound_for_recipient(
        &self,
        recipient_device: Option<&[u8; 32]>,
    ) -> Result<Vec<EndpointOutbound>, IndexedSessionStoreError> {
        let rows = endpoints::outbox_rows(
            &self.conn,
            &self.layout,
            &format!(
                "SELECT {} FROM endpoint_outbox WHERE state = 0
                   AND (?1 IS NULL OR kh_recipient_device = ?1)
                 ORDER BY rowid ASC",
                endpoints::outbox_columns(&self.layout, "")
            ),
            params![recipient_device.map(|d| self.layout.ep_device(d))],
        )?;
        rows.into_iter()
            .map(|row| decode_endpoint_outbound_row(row.db_row()))
            .collect()
    }

    /// Queued message envelopes whose outstanding delivery is still `Sent`
    /// (transport handoff happened, application ACK not yet accepted).
    pub fn awaiting_ack_endpoint_outbound(
        &self,
    ) -> Result<Vec<EndpointOutbound>, IndexedSessionStoreError> {
        self.awaiting_ack_endpoint_outbound_for_recipient(None)
    }

    /// Like [`Self::awaiting_ack_endpoint_outbound`], optionally limited to one
    /// recipient device.
    pub fn awaiting_ack_endpoint_outbound_for_recipient(
        &self,
        recipient_device: Option<&[u8; 32]>,
    ) -> Result<Vec<EndpointOutbound>, IndexedSessionStoreError> {
        let rows = endpoints::outbox_rows(
            &self.conn,
            &self.layout,
            &format!(
                "SELECT {} FROM endpoint_outbox o
                 JOIN endpoint_outstanding_messages m
                   ON m.session_id = o.session_id
                  AND m.kh_message_id = o.kh_message_id
                  AND m.kh_recipient_device = o.kh_recipient_device
                 WHERE o.state = 1 AND o.kind = 1 AND m.delivery_state = 0
                   AND (?1 IS NULL OR o.kh_recipient_device = ?1)
                 ORDER BY o.rowid ASC",
                endpoints::outbox_columns(&self.layout, "o.")
            ),
            params![recipient_device.map(|d| self.layout.ep_device(d))],
        )?;
        rows.into_iter()
            .map(|row| decode_endpoint_outbound_row(row.db_row()))
            .collect()
    }

    /// Re-invokes the durable queue/dial callback for an already-Queued message
    /// without changing outbox state. Used when the peer ACK was lost after a
    /// successful transport handoff.
    pub fn resend_queued_endpoint_outbound<F>(
        &mut self,
        key: &IndexedSessionRecordKey,
        object_digest: &[u8; 32],
        local_device: &AuthorizedEndpointDevice<'_>,
        now_ms: u64,
        enqueue_idempotently: &mut F,
    ) -> Result<EndpointOutbound, IndexedSessionStoreError>
    where
        F: FnMut(&[u8; 32], &[u8]) -> Result<[u8; 32], ()>,
    {
        self.recover_pending_for_key(key)?;
        let record_key = record_key_digest(key)?;
        let account = hex::encode(record_key);
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let _in_tx = crate::paths::HeldMark::transaction();
        let state = load_and_reconcile(
            &tx,
            &self.layout,
            self.backend.as_ref(),
            &account,
            &record_key,
        )?;
        if &state.binding.key != key {
            return Err(IndexedSessionStoreError::BindingConflict);
        }
        let row = endpoint_outbound_by_object(
            &tx,
            &self.layout,
            &state.binding.session_id,
            object_digest,
        )?
        .ok_or(IndexedSessionStoreError::NotFound)?;
        if row.state != EndpointOutboxState::Queued || row.kind != EndpointOutboundKind::Message {
            return Err(IndexedSessionStoreError::NotFound);
        }
        validate_committed_outbound(&tx, &self.layout, &state, &row)?;
        let envelope = Envelope::unpack(&row.immutable_envelope_bytes)
            .ok_or(IndexedSessionStoreError::InvalidEndpointEnvelope)?;
        if !endpoint_time_window_valid(envelope.created_at, envelope.expires_at, now_ms)
            || now_ms >= state.binding.expires_at_ms
        {
            tx.commit()?;
            return Err(IndexedSessionStoreError::EndpointNotCurrentlyValid);
        }
        let cap = letters::provisional_message_cap(&tx, &state, row.kind)?;
        validate_outbound_session_and_signer(
            &state,
            key,
            local_device,
            row.kind,
            row.ratchet_index,
            envelope.created_at,
            envelope.expires_at,
            now_ms,
            cap,
        )?;
        refuse_retired_message_lane(&tx, &self.layout, &state.binding.session_id, row.kind)?;
        let delivery = self_delivery_state_in_connection(
            &tx,
            &self.layout,
            &state.binding.session_id,
            &row.message_id,
            &row.recipient_device,
        )?;
        if delivery != Some(EndpointDeliveryState::Sent) {
            tx.commit()?;
            return Ok(row);
        }
        tx.commit()?;
        let persisted = enqueue_idempotently(object_digest, &row.immutable_envelope_bytes)
            .map_err(|_| IndexedSessionStoreError::OutboundQueueHandoff)?;
        if persisted != *object_digest {
            return Err(IndexedSessionStoreError::OutboundQueueHandoff);
        }
        Ok(row)
    }

    fn handoff_endpoint_outbound<F>(
        &mut self,
        state: &ProtectedSessionState,
        object_digest: &[u8; 32],
        local_device: &AuthorizedEndpointDevice<'_>,
        now_ms: u64,
        endpoint_fault: Option<EndpointFaultPoint>,
        enqueue_idempotently: &mut F,
    ) -> Result<EndpointOutbound, IndexedSessionStoreError>
    where
        F: FnMut(&[u8; 32], &[u8]) -> Result<[u8; 32], ()>,
    {
        let session_id = &state.binding.session_id;
        let row = endpoint_outbound_by_object(&self.conn, &self.layout, session_id, object_digest)?
            .ok_or(IndexedSessionStoreError::NotFound)?;
        validate_committed_outbound(&self.conn, &self.layout, state, &row)?;
        let envelope = Envelope::unpack(&row.immutable_envelope_bytes)
            .ok_or(IndexedSessionStoreError::InvalidEndpointEnvelope)?;
        validate_outbound_session_and_signer(
            state,
            &state.binding.key,
            local_device,
            row.kind,
            row.ratchet_index,
            envelope.created_at,
            envelope.expires_at,
            now_ms,
            letters::provisional_message_cap(&self.conn, state, row.kind)?,
        )?;
        refuse_retired_message_lane(&self.conn, &self.layout, session_id, row.kind)?;
        if row.state == EndpointOutboxState::Queued {
            return Ok(row);
        }
        maybe_injected_endpoint_fault(
            endpoint_fault,
            EndpointFaultPoint::BeforeOutboundQueueHandoff,
        )?;
        let persisted = enqueue_idempotently(object_digest, &row.immutable_envelope_bytes)
            .map_err(|_| IndexedSessionStoreError::OutboundQueueHandoff)?;
        if persisted != *object_digest {
            return Err(IndexedSessionStoreError::OutboundQueueHandoff);
        }
        maybe_injected_endpoint_fault(
            endpoint_fault,
            EndpointFaultPoint::AfterOutboundQueueHandoff,
        )?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let _in_tx = crate::paths::HeldMark::transaction();
        let current = endpoint_outbound_by_object(&tx, &self.layout, session_id, object_digest)?
            .ok_or(IndexedSessionStoreError::OutboundBindingMismatch)?;
        validate_committed_outbound(&tx, &self.layout, state, &current)?;
        if current.state == EndpointOutboxState::Queued {
            let mut expected = row.clone();
            expected.state = EndpointOutboxState::Queued;
            if current != expected {
                return Err(IndexedSessionStoreError::OutboundBindingMismatch);
            }
            tx.commit()?;
            return Ok(current);
        }
        if current != row {
            return Err(IndexedSessionStoreError::OutboundBindingMismatch);
        }
        // The exact bytes it handed over (their keyed digest in schema 3).
        let changed = tx.execute(
            &self.layout.ep("UPDATE endpoint_outbox SET state = 1
                 WHERE session_id = ?1 AND kh_object_digest = ?2 AND state = 0
                   AND kh_envelope = ?3"),
            params![
                session_id.as_slice(),
                self.layout.ep_digest(object_digest),
                self.layout.ep_bytes(&row.immutable_envelope_bytes)
            ],
        )?;
        if changed == 0 {
            let current =
                endpoint_outbound_by_object(&tx, &self.layout, session_id, object_digest)?
                    .ok_or(IndexedSessionStoreError::OutboundBindingMismatch)?;
            validate_committed_outbound(&tx, &self.layout, state, &current)?;
            let mut expected = row.clone();
            expected.state = EndpointOutboxState::Queued;
            if current != expected {
                return Err(IndexedSessionStoreError::OutboundBindingMismatch);
            }
            tx.commit()?;
            return Ok(current);
        }
        if changed != 1 {
            return Err(IndexedSessionStoreError::CorruptEndpointState);
        }
        if row.kind == EndpointOutboundKind::Ack {
            let ack_changed = tx.execute(
                &self.layout.ep("UPDATE endpoint_ack_intents SET state = 1
                     WHERE session_id = ?1 AND kh_ack = ?2 AND state = 0"),
                params![
                    session_id.as_slice(),
                    self.layout.ep_bytes(&row.immutable_envelope_bytes)
                ],
            )?;
            if ack_changed != 1 {
                return Err(IndexedSessionStoreError::OutboundBindingMismatch);
            }
        }
        tx.commit()?;
        Ok(EndpointOutbound {
            state: EndpointOutboxState::Queued,
            ..row
        })
    }

    /// Executes the endpoint acceptance transaction from
    /// `ATSAM_ENDPOINT_TRANSACTION_V1.md` with no application policy (every
    /// valid text is accepted). Live: `lan_dispatch` calls the policy variant
    /// for every inbound LAN-direct message in default builds (the generic
    /// [`INDEXED_SESSION_STORE_PRODUCTION_ENABLED`] tripwire stays `false`).
    pub fn accept_message_envelope(
        &mut self,
        key: &IndexedSessionRecordKey,
        packed_envelope: &[u8],
        sender_certificate: &DeviceCertificate,
        sender_revoked: bool,
        now_ms: u64,
    ) -> Result<EndpointAcceptance, IndexedSessionStoreError> {
        self.accept_message_envelope_with_policy(
            key,
            packed_envelope,
            sender_certificate,
            sender_revoked,
            now_ms,
            &mut |_| InboundPolicy::Accept,
        )
    }

    /// [`Self::accept_message_envelope`] with the application policy of
    /// `ATSAM_ENDPOINT_TRANSACTION_V1.md` §1 step 7: `policy` sees the opened,
    /// text-checked plaintext before anything is committed. On
    /// [`InboundPolicy::Defer`] the transaction is dropped (no receipt, inbox
    /// row, ACK intent or ratchet change) and
    /// [`IndexedSessionStoreError::ApplicationDeferred`] is returned. A
    /// duplicate of an already committed object never reaches the policy.
    pub fn accept_message_envelope_with_policy(
        &mut self,
        key: &IndexedSessionRecordKey,
        packed_envelope: &[u8],
        sender_certificate: &DeviceCertificate,
        sender_revoked: bool,
        now_ms: u64,
        policy: &mut dyn FnMut(&[u8]) -> InboundPolicy,
    ) -> Result<EndpointAcceptance, IndexedSessionStoreError> {
        refuse_held_suite()?;
        let env = Envelope::unpack(packed_envelope)
            .ok_or(IndexedSessionStoreError::InvalidEndpointEnvelope)?;
        if env.env_type != EnvType::Message as u8 {
            return Err(IndexedSessionStoreError::EndpointTypeMismatch);
        }
        if !endpoint_time_window_valid(env.created_at, env.expires_at, now_ms)
            || env.created_at > i64::MAX as u64
            || env.expires_at > i64::MAX as u64
            || now_ms > i64::MAX as u64
        {
            return Err(IndexedSessionStoreError::EndpointNotCurrentlyValid);
        }
        let index = parse_indexed_message_header(&env.message_ciphertext)
            .map_err(|_| IndexedSessionStoreError::InvalidIndexedMessage)?;
        #[cfg(test)]
        let endpoint_fault = self.endpoint_fault.take();
        #[cfg(not(test))]
        let endpoint_fault = None;

        let record_key = record_key_digest(key)?;
        let account = hex::encode(record_key);
        let backend = Arc::clone(&self.backend);
        let (tx, mut state) = begin_journal_free_tx!(self, backend, account, record_key);
        let _in_tx = crate::paths::HeldMark::transaction();
        if &state.binding.key != key {
            return Err(IndexedSessionStoreError::BindingConflict);
        }
        if state.binding.lifecycle != SessionLifecycle::Confirmed {
            return Err(IndexedSessionStoreError::SessionNotConfirmed);
        }
        if state.pending_acceptance.is_some()
            || state.pending_ack_acceptance.is_some()
            || state.pending_outbound.is_some()
        {
            return Err(IndexedSessionStoreError::CorruptProtectedState);
        }
        // ATSAM_ENDPOINT_TRANSACTION_V1 §1 step 4: direction, device hint and route
        // tag select the session; only then do this session's own checks apply.
        // A window check first would refuse a valid envelope sealed under another
        // live session with this peer (for example the older of two sessions
        // after crossed pairing) before the caller could try that session.
        let direction = state.binding.local_role.inbound_direction();
        let local_device = local_device_for_binding(&state.binding);
        let expected_hint = endpoint_device_hint(local_device);
        if env.dest_device_hint != 0 && env.dest_device_hint != expected_hint {
            return Err(IndexedSessionStoreError::DeviceHintMismatch);
        }
        let expected_route = derive_route_tag(
            &state.ratchets.root,
            env.created_at,
            index,
            env.env_type,
            direction,
        )
        .map_err(|_| IndexedSessionStoreError::RouteTagMismatch)?;
        if !route_tag_eq(&env.routing_tag, &expected_route) {
            return Err(IndexedSessionStoreError::RouteTagMismatch);
        }
        if before_session_start(now_ms, state.binding.created_at_ms)
            || now_ms >= state.binding.expires_at_ms
            || before_session_start(env.created_at, state.binding.created_at_ms)
            || env.expires_at > state.binding.expires_at_ms
        {
            return Err(IndexedSessionStoreError::EndpointNotCurrentlyValid);
        }

        if sender_revoked {
            return Err(IndexedSessionStoreError::RevokedDevice);
        }
        sender_certificate
            .verify(now_ms)
            .map_err(|_| IndexedSessionStoreError::InvalidDeviceCertificate)?;
        let remote_device = *remote_device_for_binding(&state.binding);
        if sender_certificate.device_ed_pub != remote_device {
            return Err(IndexedSessionStoreError::DeviceBindingMismatch);
        }
        let expected_certificate_digest = *remote_certificate_digest(&state.binding);
        let actual_certificate_digest = device_certificate_hash(sender_certificate)
            .map_err(|_| IndexedSessionStoreError::InvalidDeviceCertificate)?;
        if actual_certificate_digest != expected_certificate_digest {
            return Err(IndexedSessionStoreError::DeviceBindingMismatch);
        }
        if !env.verify(&remote_device) {
            return Err(IndexedSessionStoreError::OuterSignatureInvalid);
        }

        let object_digest = authenticated_object_digest(&env);
        if endpoint_receipt_by_object(&tx, &self.layout, &state.binding.session_id, &object_digest)?
            .is_some()
        {
            ensure_exact_committed_object(
                &tx,
                &self.layout,
                &state.binding.session_id,
                &object_digest,
                &env.message_id,
                &remote_device,
            )?;
            tx.commit()?;
            return Ok(EndpointAcceptance::Duplicate {
                session_id: state.binding.session_id,
                object_digest,
                message_id: env.message_id,
            });
        }
        if let Some(existing_digest) = endpoint_logical_object(
            &tx,
            &self.layout,
            &state.binding.session_id,
            &remote_device,
            &env.message_id,
        )? {
            if existing_digest != object_digest {
                return Err(IndexedSessionStoreError::LogicalMessageConflict);
            }
        } else if !crate::horizon::receiver_dedup_live()
            && parked::seen(&tx, &self.layout, &remote_device, &env.message_id)?
        {
            // ATSAM_ENDPOINT_TRANSACTION_V1 §3: a message id is unique per
            // sender device across sessions. This one was taken under
            // another session of this contact (its inbound-seen row
            // outlives that session), and nothing re-seals a message under
            // a new session while session reset and the long horizon are
            // shut: another object under that id is a conflict, never a
            // second message. While either is live, a copy re-sealed under a
            // new session is taken, and the chat history keeps its first
            // body ([`crate::chat_history::ChatHistory::upsert`]).
            return Err(IndexedSessionStoreError::LogicalMessageConflict);
        }
        // Phase 6b R2 (step P6.27): a session this node retired after an
        // early security re-key takes the contact's new objects for
        // `session_renewal::EARLY_OLD_ACCEPT_MS` more (what it sealed before
        // it saw the new session), then none. A duplicate is still answered.
        if reset::rekey_closed(&tx, &self.layout, &state.binding.session_id, now_ms)? {
            return Err(IndexedSessionStoreError::SessionRetired);
        }

        let (sender, recipient) = endpoints_for_direction(&state.binding, direction);
        let mut candidate = prepare_receive_key(
            &mut state.ratchets.message_receive,
            index,
            sender,
            recipient,
        )?;
        let plaintext_result = open_indexed_message_with_key(
            &candidate,
            &state.binding.key.initiator_address,
            &state.binding.key.responder_address,
            direction,
            &env.message_id,
            &env.message_ciphertext,
        );
        candidate.zeroize();
        let plaintext =
            plaintext_result.map_err(|_| IndexedSessionStoreError::AuthenticationFailed)?;
        if !valid_endpoint_text(&plaintext) {
            return Err(IndexedSessionStoreError::InvalidEndpointPayload);
        }
        if let InboundPolicy::Defer(_) = policy(&plaintext) {
            // `tx` and the in-memory `state` copy are dropped unwritten.
            return Err(IndexedSessionStoreError::ApplicationDeferred);
        }

        state.generation = state
            .generation
            .checked_add(1)
            .ok_or(IndexedSessionStoreError::IndexExhausted)?;
        let sealed_local_inbox_row = seal_local_inbox_row(
            &state.ratchets.root,
            &state.binding.session_id,
            &object_digest,
            &env.message_id,
            &remote_device,
            &plaintext,
        )?;
        let received_at_ms = monotonic_received_at_ms(&tx, &self.layout, &remote_device, now_ms)?;
        state.pending_acceptance = Some(PendingAcceptance {
            session_id: state.binding.session_id,
            object_digest,
            message_id: env.message_id,
            sender_device: remote_device,
            sealed_local_inbox_row,
            ack_status: 1,
            created_at_ms: env.created_at,
            received_at_ms,
            public_generation: state.generation,
        });

        let journal = stage_journaled_mutation(
            &tx,
            &self.layout,
            backend.as_ref(),
            &account,
            &record_key,
            &state,
            endpoint_fault,
        )?;
        maybe_injected_endpoint_fault(endpoint_fault, EndpointFaultPoint::BeforeDatabaseCommit)?;
        tx.commit()?;
        maybe_injected_endpoint_fault(endpoint_fault, EndpointFaultPoint::AfterDatabaseCommit)?;
        maybe_injected_endpoint_fault(endpoint_fault, EndpointFaultPoint::BeforeJournalClear)?;
        state.pending_acceptance = None;
        self.clear_protected_journal(&account, &record_key, state.generation, journal)?;
        maybe_injected_endpoint_fault(endpoint_fault, EndpointFaultPoint::AfterJournalClear)?;

        Ok(EndpointAcceptance::Committed {
            session_id: state.binding.session_id,
            object_digest,
            message_id: env.message_id,
            plaintext,
            received_at_ms,
        })
    }

    /// Reads and authenticates a committed locally sealed inbox row.
    pub fn load_endpoint_inbox(
        &mut self,
        key: &IndexedSessionRecordKey,
        object_digest: &[u8; 32],
    ) -> Result<Option<EndpointInboxRow>, IndexedSessionStoreError> {
        self.recover_pending_for_key(key)?;
        let record_key = record_key_digest(key)?;
        let account = hex::encode(record_key);
        let backend = Arc::clone(&self.backend);
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let _in_tx = crate::paths::HeldMark::transaction();
        let state = load_and_reconcile(&tx, &self.layout, backend.as_ref(), &account, &record_key)?;
        if &state.binding.key != key {
            return Err(IndexedSessionStoreError::BindingConflict);
        }
        let row = read_endpoint_inbox_row(
            &tx,
            &self.layout,
            &state.ratchets.root,
            &state.binding.session_id,
            object_digest,
        )?;
        tx.commit()?;
        Ok(row)
    }

    /// Reads and authenticates several committed inbox rows of one session
    /// with a single journal recovery and a single protected-state read: all
    /// rows of a session open under the same root, so loading it per row costs
    /// two protected-backend reads and two write-lock transactions per message
    /// (Secret Service creates a new D-Bus session for each read).
    ///
    /// The outer error is the session's own state failing to load. Row errors
    /// are returned per row so a caller can tell a poisoned row from a
    /// poisoned session. The write lock is held only while the state loads;
    /// rows are decrypted afterwards, so a long listing never starves writers.
    fn load_endpoint_inbox_rows(
        &mut self,
        key: &IndexedSessionRecordKey,
        digests: &[[u8; 32]],
    ) -> Result<
        Vec<Result<Option<EndpointInboxRow>, IndexedSessionStoreError>>,
        IndexedSessionStoreError,
    > {
        self.recover_pending_for_key(key)?;
        let record_key = record_key_digest(key)?;
        let account = hex::encode(record_key);
        let backend = Arc::clone(&self.backend);
        let (mut root, session_id) = {
            let tx = self
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let _in_tx = crate::paths::HeldMark::transaction();
            let state =
                load_and_reconcile(&tx, &self.layout, backend.as_ref(), &account, &record_key)?;
            if &state.binding.key != key {
                return Err(IndexedSessionStoreError::BindingConflict);
            }
            let loaded = (state.ratchets.root, state.binding.session_id);
            drop(state);
            tx.commit()?;
            loaded
        };
        let rows = digests
            .iter()
            .map(|digest| {
                read_endpoint_inbox_row(&self.conn, &self.layout, &root, &session_id, digest)
            })
            .collect();
        root.zeroize();
        Ok(rows)
    }

    /// Decrypts the inbox rows named by `pending` (digests in listing order)
    /// and returns them in that order. A session whose own state cannot be
    /// read, or a row that fails authentication, is logged and skipped so one
    /// poisoned session or row cannot block the listing for every healthy
    /// session; store-wide failures still propagate.
    ///
    /// `unreadable` holds the record keys of sessions whose state already
    /// failed to load during the current listing. Their rows are dropped
    /// without another journal recovery and protected-state read, and a
    /// session that fails here is added to it, so a paged listing loads a
    /// poisoned session once rather than once per page. `skipped` counts the
    /// rows left out that way.
    fn load_pending_inbox_rows(
        &mut self,
        pending: &[(IndexedSessionRecordKey, [u8; 32])],
        unreadable: &mut BTreeSet<[u8; 32]>,
        skipped: &mut usize,
    ) -> Result<Vec<EndpointInboxRow>, IndexedSessionStoreError> {
        let mut by_session: BTreeMap<[u8; 32], (&IndexedSessionRecordKey, Vec<usize>)> =
            BTreeMap::new();
        for (index, (key, _)) in pending.iter().enumerate() {
            let record_key = record_key_digest(key)?;
            if unreadable.contains(&record_key) {
                *skipped += 1;
                continue;
            }
            by_session
                .entry(record_key)
                .or_insert_with(|| (key, Vec::new()))
                .1
                .push(index);
        }
        let mut slots: Vec<Option<EndpointInboxRow>> = pending.iter().map(|_| None).collect();
        for (record_key, (key, indexes)) in by_session {
            let digests: Vec<[u8; 32]> = indexes.iter().map(|index| pending[*index].1).collect();
            let rows = match self.load_endpoint_inbox_rows(key, &digests) {
                Ok(rows) => rows,
                Err(error) if is_session_scoped_state_error(&error) => {
                    log_skipped_session(&record_key, &error);
                    unreadable.insert(record_key);
                    *skipped += indexes.len();
                    continue;
                }
                Err(error) => return Err(error),
            };
            for (index, row) in indexes.into_iter().zip(rows) {
                match row {
                    Ok(row) => slots[index] = row,
                    Err(error) if is_session_scoped_state_error(&error) => {
                        log_skipped_session(&record_key, &error);
                        *skipped += 1;
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(slots.into_iter().flatten().collect())
    }

    /// Resolve the public PairInit record key for a durable `session_id`.
    pub fn record_key_for_session_id(
        &self,
        session_id: &[u8; 32],
    ) -> Result<Option<IndexedSessionRecordKey>, IndexedSessionStoreError> {
        let raw = self
            .conn
            .query_row(
                &format!(
                    "SELECT {} FROM indexed_session_heads WHERE session_id = ?1",
                    sealed::head_columns(&self.layout, "")
                ),
                params![session_id.as_slice()],
                |row| sealed::raw_head(&self.layout, row, 0),
            )
            .optional()?;
        let Some(raw) = raw else {
            return Ok(None);
        };
        Ok(Some(self.layout.head(raw)?.key))
    }

    /// Drop an undeliverable outbound message (Prepared dial-failure leftover or
    /// Queued envelope that can no longer be resent). Removes outstanding Sent
    /// rows and the outbox ciphertext so later sends are not wedged. Returns
    /// `Ok(false)` and removes nothing when the message was acknowledged in
    /// the meantime (the caller must not report it as dropped).
    ///
    /// Callers decide policy (expired dial vs handoff failure). This API does
    /// not re-check envelope expiry — that belongs at the send/retry boundary.
    pub fn abandon_undelivered_outbound(
        &mut self,
        key: &IndexedSessionRecordKey,
        object_digest: &[u8; 32],
    ) -> Result<bool, IndexedSessionStoreError> {
        self.recover_pending_for_key(key)?;
        let record_key = record_key_digest(key)?;
        let account = hex::encode(record_key);
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let _in_tx = crate::paths::HeldMark::transaction();
        let state = load_and_reconcile(
            &tx,
            &self.layout,
            self.backend.as_ref(),
            &account,
            &record_key,
        )?;
        if &state.binding.key != key {
            return Err(IndexedSessionStoreError::BindingConflict);
        }
        let row = endpoint_outbound_by_object(
            &tx,
            &self.layout,
            &state.binding.session_id,
            object_digest,
        )?
        .ok_or(IndexedSessionStoreError::NotFound)?;
        if row.kind != EndpointOutboundKind::Message {
            return Ok(false);
        }
        if row.state != EndpointOutboxState::Prepared && row.state != EndpointOutboxState::Queued {
            return Ok(false);
        }
        // An ACK accepted since the caller looked at this row has already
        // delivered the message: its ciphertext stays and the caller must not
        // report it as dropped. A missing outstanding row is an orphan and is
        // still cleaned up below.
        if matches!(
            self_delivery_state_in_connection(
                &tx,
                &self.layout,
                &state.binding.session_id,
                &row.message_id,
                &row.recipient_device,
            )?,
            Some(EndpointDeliveryState::Delivered | EndpointDeliveryState::Read)
        ) {
            return Ok(false);
        }
        let _ = tx.execute(
            &self.layout.ep("DELETE FROM endpoint_outstanding_messages
                 WHERE session_id = ?1 AND kh_message_id = ?2 AND kh_recipient_device = ?3
                   AND delivery_state = 0"),
            params![
                state.binding.session_id.as_slice(),
                self.layout.ep_mid(&row.message_id),
                self.layout.ep_device(&row.recipient_device)
            ],
        )?;
        let changed = tx.execute(
            &self.layout.ep("DELETE FROM endpoint_outbox
                 WHERE session_id = ?1 AND kh_object_digest = ?2 AND kind = 1
                   AND state IN (0, 1)"),
            params![
                state.binding.session_id.as_slice(),
                self.layout.ep_digest(object_digest)
            ],
        )?;
        tx.commit()?;
        Ok(changed > 0)
    }

    /// An accepted ACK proved that this message reached its recipient while its
    /// outbox row was still `Prepared` (the dial that carried it ended before
    /// the reply, and the ACK came back another way). Record the handoff, the
    /// same `Prepared -> Queued` step a successful dial records, so no retry
    /// dials a delivered message again. Only when the outstanding row is
    /// `Delivered` or `Read`; `Ok(true)` when a row moved.
    pub fn settle_delivered_outbound(
        &mut self,
        session_id: &[u8; 32],
        message_id: &[u8; 16],
    ) -> Result<bool, IndexedSessionStoreError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let _in_tx = crate::paths::HeldMark::transaction();
        let changed = tx.execute(
            &self.layout.ep("UPDATE endpoint_outbox SET state = 1
                 WHERE session_id = ?1 AND kh_message_id = ?2 AND kind = 1 AND state = 0
                   AND EXISTS (
                     SELECT 1 FROM endpoint_outstanding_messages m
                     WHERE m.session_id = endpoint_outbox.session_id
                       AND m.kh_message_id = endpoint_outbox.kh_message_id
                       AND m.kh_recipient_device = endpoint_outbox.kh_recipient_device
                       AND m.delivery_state IN (1, 2))"),
            params![session_id.as_slice(), self.layout.ep_mid(message_id)],
        )?;
        tx.commit()?;
        Ok(changed > 0)
    }

    pub fn list_record_keys(
        &self,
    ) -> Result<Vec<IndexedSessionRecordKey>, IndexedSessionStoreError> {
        self.record_keys(false)
    }

    /// [`Self::list_record_keys`] without the heads that cannot be read (a
    /// meta that does not open: a changed byte, an epoch no key holds),
    /// each logged once: the archive before a prune (review
    /// B-sealed-stores-2), so one such head stops neither that prune, which
    /// removes it by its hour, nor with it every new session. Without the
    /// at-rest key it fails (closed).
    pub fn list_readable_record_keys(
        &self,
    ) -> Result<Vec<IndexedSessionRecordKey>, IndexedSessionStoreError> {
        self.record_keys(true)
    }

    fn record_keys(
        &self,
        skip_unreadable: bool,
    ) -> Result<Vec<IndexedSessionRecordKey>, IndexedSessionStoreError> {
        // Schema 2 orders by the clear hour, then by the exact time from each
        // meta (a stable sort: equal times keep the row order).
        let order = match self.layout {
            Layout::Clear => "created_at_ms ASC",
            Layout::Keyed(_) => "created_hour ASC, rowid ASC",
        };
        let mut statement = self.conn.prepare(&format!(
            "SELECT {} FROM indexed_session_heads ORDER BY {order}",
            sealed::head_columns(&self.layout, "")
        ))?;
        let rows = statement.query_map([], |row| sealed::raw_head(&self.layout, row, 0))?;
        let mut heads = Vec::new();
        for row in rows {
            let raw = row?;
            let stored = raw.stored_key().map(<[u8]>::to_vec).unwrap_or_default();
            match self.layout.head(raw) {
                Ok(head) => heads.push(head),
                Err(error @ IndexedSessionStoreError::MetaKeyUnavailable(_)) => return Err(error),
                Err(error) if skip_unreadable => log_skipped_session(&stored, &error),
                Err(error) => return Err(error),
            }
        }
        if self.layout.is_keyed() {
            heads.sort_by_key(|head| head.created_at_ms);
        }
        Ok(heads.into_iter().map(|head| head.key).collect())
    }

    pub fn session_lifecycle(
        &mut self,
        key: &IndexedSessionRecordKey,
    ) -> Result<SessionLifecycle, IndexedSessionStoreError> {
        Ok(self.protected_lifecycle_and_expiry(key)?.0)
    }

    pub fn session_expires_at(
        &mut self,
        key: &IndexedSessionRecordKey,
    ) -> Result<u64, IndexedSessionStoreError> {
        Ok(self.protected_lifecycle_and_expiry(key)?.1)
    }

    /// How far behind the peer may be on this session's message lane: the
    /// messages sealed after the newest one it acknowledged. An upper bound
    /// (a commit whose ACK is still on its way counts as behind). The
    /// receiver refuses a jump past [`MAX_FORWARD_JUMP`], so a sender that
    /// lets this grow (messages the peer defers) would block the session.
    pub fn unacknowledged_message_span(
        &mut self,
        key: &IndexedSessionRecordKey,
    ) -> Result<u64, IndexedSessionStoreError> {
        self.recover_pending_for_key(key)?;
        let record_key = record_key_digest(key)?;
        let account = hex::encode(record_key);
        let backend = Arc::clone(&self.backend);
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let _in_tx = crate::paths::HeldMark::transaction();
        let state = load_and_reconcile(&tx, &self.layout, backend.as_ref(), &account, &record_key)?;
        let next = state.ratchets.message_send.next_index;
        let session_id = state.binding.session_id;
        drop(state);
        let acked: Option<i64> = tx.query_row(
            &self
                .layout
                .ep("SELECT MAX(o.ratchet_index) FROM endpoint_outbox o
                 JOIN endpoint_outstanding_messages m
                   ON m.session_id = o.session_id
                  AND m.kh_message_id = o.kh_message_id
                  AND m.kh_recipient_device = o.kh_recipient_device
                 WHERE o.session_id = ?1 AND o.kind = 1 AND m.delivery_state IN (1, 2)"),
            params![session_id.as_slice()],
            |row| row.get(0),
        )?;
        tx.commit()?;
        let base = acked.map_or(0, |i| (i.max(0) as u64).saturating_add(1));
        Ok(next.saturating_sub(base))
    }

    /// Lifecycle and expiry from one protected load.
    fn protected_lifecycle_and_expiry(
        &mut self,
        key: &IndexedSessionRecordKey,
    ) -> Result<(SessionLifecycle, u64), IndexedSessionStoreError> {
        self.recover_pending_for_key(key)?;
        let record_key = record_key_digest(key)?;
        let account = hex::encode(record_key);
        let backend = Arc::clone(&self.backend);
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let _in_tx = crate::paths::HeldMark::transaction();
        let state = load_and_reconcile(&tx, &self.layout, backend.as_ref(), &account, &record_key)?;
        let summary = (state.binding.lifecycle, state.binding.expires_at_ms);
        drop(state);
        tx.commit()?;
        Ok(summary)
    }

    /// PairInit-bound `device_certificate_hash` of the remote device's cert.
    pub fn remote_certificate_digest(
        &mut self,
        key: &IndexedSessionRecordKey,
    ) -> Result<[u8; 32], IndexedSessionStoreError> {
        self.recover_pending_for_key(key)?;
        let record_key = record_key_digest(key)?;
        let account = hex::encode(record_key);
        let backend = Arc::clone(&self.backend);
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let _in_tx = crate::paths::HeldMark::transaction();
        let state = load_and_reconcile(&tx, &self.layout, backend.as_ref(), &account, &record_key)?;
        let digest = *remote_certificate_digest(&state.binding);
        tx.commit()?;
        Ok(digest)
    }

    /// Expiry from SQLite metadata only — does not load protected secrets.
    /// Safe after a crash that deleted the secret but left the head row.
    pub fn head_expires_at_ms(
        &self,
        key: &IndexedSessionRecordKey,
    ) -> Result<u64, IndexedSessionStoreError> {
        if let Some(sealer) = self.layout.keyed() {
            // Equality on the six identity columns, keyed (PP.13; the
            // `init_id` too in schema 4); the exact expiry is in the meta
            // (K_meta is no protected session state).
            let raw = self.conn.query_row(
                &format!(
                    "SELECT {} FROM indexed_session_heads
                     WHERE profile_id = ?1 AND kh_initiator_address = ?2
                       AND kh_responder_address = ?3 AND kh_initiator_device = ?4
                       AND kh_responder_device = ?5 AND {} = ?6",
                    sealed::head_columns(&self.layout, ""),
                    sealer.init_column()
                ),
                params![
                    key.profile_id.as_slice(),
                    sealer.address(&key.initiator_address).as_slice(),
                    sealer.address(&key.responder_address).as_slice(),
                    sealer.device(&key.initiator_device_ed25519).as_slice(),
                    sealer.device(&key.responder_device_ed25519).as_slice(),
                    sealer.init_value(&key.init_id),
                ],
                |row| sealed::raw_head(&self.layout, row, 0),
            )?;
            return Ok(self.layout.head(raw)?.expires_at_ms as u64);
        }
        let expires: i64 = self.conn.query_row(
            "SELECT expires_at_ms FROM indexed_session_heads
             WHERE profile_id = ?1 AND initiator_address = ?2 AND responder_address = ?3
               AND initiator_device = ?4 AND responder_device = ?5 AND init_id = ?6",
            params![
                key.profile_id.as_slice(),
                key.initiator_address,
                key.responder_address,
                key.initiator_device_ed25519.as_slice(),
                key.responder_device_ed25519.as_slice(),
                key.init_id.as_slice(),
            ],
            |row| row.get(0),
        )?;
        Ok(expires as u64)
    }

    pub fn find_confirmed_session_for_peer(
        &mut self,
        peer_device: &[u8; 32],
    ) -> Result<Option<IndexedSessionRecordKey>, IndexedSessionStoreError> {
        self.find_confirmed_session_for_peer_at(peer_device, crate::clock::now_ms())
    }

    /// Newest non-expired Confirmed session for `peer_device`, if any.
    ///
    /// Expired heads are skipped from public metadata before any protected
    /// load, so an expired head whose secret a prune already deleted cannot
    /// break the lookup. Live candidates are still checked (lifecycle and
    /// expiry) against the protected binding. A live candidate whose own
    /// protected state is missing, corrupt or rolled back (a moved data dir or
    /// restored database) is logged and skipped: not selecting it is as safe
    /// as failing, and failing would leave a healthy newer session for the
    /// same peer unreachable. Store-wide failures (SQLite, protected backend)
    /// still fail the lookup.
    pub fn find_confirmed_session_for_peer_at(
        &mut self,
        peer_device: &[u8; 32],
        now_ms: u64,
    ) -> Result<Option<IndexedSessionRecordKey>, IndexedSessionStoreError> {
        Ok(self
            .find_confirmed_sessions_for_peer_at(peer_device, now_ms)?
            .into_iter()
            .next())
    }

    /// Every non-expired Confirmed session for `peer_device`, **newest first**
    /// (the order [`Self::find_confirmed_session_for_peer_at`] takes its answer
    /// from), under the same per-session skipping rules.
    ///
    /// Two peers that pair at the same moment each hold *two* confirmed sessions
    /// with each other, and a message can be sealed under either (a sender uses
    /// the session its own pairing produced). The newest-first order is the same
    /// on both nodes: the head's `created_at_ms` is the init's stamp, equal on
    /// both sides, and ties break on `init_id`, which is also identical on both.
    /// Breaking ties on the node-local `rowid` made the two nodes select
    /// *different* sessions on an exact tie, which wedged the pair for good.
    /// The receive path resolves the session by route tag over this list.
    pub fn find_confirmed_sessions_for_peer_at(
        &mut self,
        peer_device: &[u8; 32],
        now_ms: u64,
    ) -> Result<Vec<IndexedSessionRecordKey>, IndexedSessionStoreError> {
        let cutoff = i64::try_from(now_ms).unwrap_or(i64::MAX);
        // One statement, so the candidate list is a consistent snapshot even
        // while another process prunes. Schema 2 (PP.13) binds the keyed
        // device, takes the hours that may still be live, and finishes the
        // filter and the order from each head's meta.
        let (devices, live, order, bound) = match self.layout.keyed() {
            None => (
                "initiator_device = ?1 OR responder_device = ?1",
                "expires_at_ms > ?2",
                "created_at_ms DESC, init_id DESC",
                (peer_device.to_vec(), cutoff),
            ),
            // The clear hour at most (no `init_id` column in schema 4):
            // Rust finishes the order below.
            Some(sealer) => (
                "kh_initiator_device = ?1 OR kh_responder_device = ?1",
                "prune_after_hour > ?2",
                "created_hour DESC",
                (
                    sealer.device(peer_device).to_vec(),
                    crate::sqlite_rebuild::hour_of(now_ms),
                ),
            ),
        };
        let mut candidates: Vec<(Vec<u8>, Option<sealed::Head>)> = {
            let mut statement = self.conn.prepare(&format!(
                "SELECT record_key, {} FROM indexed_session_heads
                 WHERE ({devices}) AND {live}
                 ORDER BY {order}",
                sealed::head_columns(&self.layout, "")
            ))?;
            let rows = statement.query_map(params![bound.0, bound.1], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    sealed::raw_head(&self.layout, row, 1)?,
                ))
            })?;
            let mut out = Vec::new();
            for row in rows {
                let (record_key, raw) = row?;
                match self.layout.head(raw) {
                    Ok(head) if head.expires_at_ms <= cutoff => {}
                    Ok(head) => out.push((record_key, Some(head))),
                    Err(error @ IndexedSessionStoreError::MetaKeyUnavailable(_)) => {
                        return Err(error)
                    }
                    Err(_) => out.push((record_key, None)),
                }
            }
            out
        };
        if self.layout.is_keyed() {
            candidates.sort_by(|a, b| match (&a.1, &b.1) {
                (Some(a), Some(b)) => {
                    (b.created_at_ms, b.key.init_id).cmp(&(a.created_at_ms, a.key.init_id))
                }
                (a, b) => b.is_some().cmp(&a.is_some()),
            });
        }
        let candidates = candidates
            .into_iter()
            .map(|(record_key, head)| (record_key, head.map(|head| head.key)));
        let mut found = Vec::new();
        for (record_key, key) in candidates {
            let Some(key) = key else {
                log_skipped_session(&record_key, &IndexedSessionStoreError::CorruptEndpointState);
                continue;
            };
            match self.protected_lifecycle_and_expiry(&key) {
                Ok((SessionLifecycle::Confirmed, expires_at_ms)) if expires_at_ms > now_ms => {
                    found.push(key);
                }
                Ok(_) => {}
                Err(error) if is_session_scoped_state_error(&error) => {
                    log_skipped_session(&record_key, &error);
                }
                Err(error) => return Err(error),
            }
        }
        Ok(found)
    }

    /// Delete expired session metadata + protected blobs. Returns removed head count.
    ///
    /// Each session is removed under one IMMEDIATE transaction: its SQLite
    /// rows are deleted, then the protected secret, then the transaction
    /// commits. Deleting the secret before the commit means no failure can
    /// leave a Keychain/Secret Service blob whose metadata is gone (nothing
    /// would ever find it again). A crash or failed commit after the secret
    /// delete leaves an expired head without a secret; that expired head is
    /// the tombstone: `open()` tolerates it, lookups skip it by metadata
    /// expiry, and the next prune selects it again and finishes (the backend
    /// delete is idempotent). Callers must archive inbox plaintext to
    /// ChatHistory before invoking this. It ends with
    /// [`crate::paths::checkpoint_truncate`], so what it deleted leaves the
    /// main file too (PP.2).
    pub fn prune_expired_sessions(
        &mut self,
        now_ms: u64,
    ) -> Result<usize, IndexedSessionStoreError> {
        type ExpiredRow = (Vec<u8>, Vec<u8>);
        let cutoff = i64::try_from(now_ms).unwrap_or(i64::MAX);
        let layout = self.layout.clone();
        // Schema 2 (PP.13): the hours that may have expired, then the exact
        // expiry from each meta, so nothing goes early (or late). A meta
        // that does not open goes by its hour alone.
        let expired = |record_key: &[u8], hour: i64, meta: &[u8]| match layout.keyed() {
            None => Ok(true),
            Some(sealer) => {
                match sealer.open::<sealed::HeadMeta>(sealed::HEADS, record_key, meta) {
                    Ok(head) => Ok(head.expires_at_ms <= cutoff),
                    Err(error @ IndexedSessionStoreError::MetaKeyUnavailable(_)) => Err(error),
                    Err(_) => Ok(sealed::surely_expired(hour, cutoff)),
                }
            }
        };
        let (selected, bound) = match self.layout {
            Layout::Clear => (
                "SELECT record_key, session_id, 0, NULL FROM indexed_session_heads
                 WHERE expires_at_ms <= ?1",
                cutoff,
            ),
            Layout::Keyed(_) => (
                "SELECT record_key, session_id, prune_after_hour, meta FROM indexed_session_heads
                 WHERE prune_after_hour <= ?1",
                sealed::may_have_expired(cutoff),
            ),
        };
        let rows: Vec<ExpiredRow> = {
            let mut statement = self.conn.prepare(selected)?;
            let mapped = statement.query_map(params![bound], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                ))
            })?;
            let mut out = Vec::new();
            for row in mapped {
                let (record_key, session_id, hour, meta) = row?;
                if expired(&record_key, hour, meta.as_deref().unwrap_or_default())? {
                    out.push((record_key, session_id));
                }
            }
            out
        };
        #[cfg(test)]
        let endpoint_fault = self.endpoint_fault.take();
        #[cfg(not(test))]
        let endpoint_fault = None;
        let mut removed = 0usize;
        for (record_key, session_id) in rows {
            let account = hex::encode(&record_key);
            let tx = self
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let _in_tx = crate::paths::HeldMark::transaction();
            // Another store instance may have pruned it since the listing.
            let still_expired = match layout {
                Layout::Clear => tx
                    .query_row(
                        "SELECT 1 FROM indexed_session_heads
                         WHERE record_key = ?1 AND session_id = ?2 AND expires_at_ms <= ?3",
                        params![record_key.as_slice(), session_id.as_slice(), cutoff],
                        |row| row.get::<_, i64>(0),
                    )
                    .optional()?
                    .is_some(),
                Layout::Keyed(_) => {
                    let head: Option<(i64, Vec<u8>)> = tx
                        .query_row(
                            "SELECT prune_after_hour, meta FROM indexed_session_heads
                             WHERE record_key = ?1 AND session_id = ?2",
                            params![record_key.as_slice(), session_id.as_slice()],
                            |row| Ok((row.get(0)?, row.get(1)?)),
                        )
                        .optional()?;
                    match head {
                        Some((hour, meta)) => expired(&record_key, hour, &meta)?,
                        None => false,
                    }
                }
            };
            if !still_expired {
                tx.commit()?;
                continue;
            }
            delete_session_endpoint_rows(&tx, &session_id)?;
            // Before the head (and its sidecar) goes: when it ended.
            horizon::note_session_end(&tx, &layout, &session_id)?;
            let _ = tx.execute(
                "DELETE FROM indexed_session_heads WHERE session_id = ?1",
                params![session_id.as_slice()],
            )?;
            self.backend.delete(&account)?;
            maybe_injected_endpoint_fault(
                endpoint_fault,
                EndpointFaultPoint::AfterPruneSecretDelete,
            )?;
            tx.commit()?;
            removed += 1;
        }
        reset::prune_reseal_ledger(&self.conn, &self.layout, now_ms)?;
        horizon::prune_session_ends(&self.conn, &self.layout, now_ms)?;
        // Parked messages stay (the horizon worker owns their deadlines);
        // the inbound messages seen go once kept long enough (Phase 5, P5.4).
        parked::prune_inbound_seen(&self.conn, &self.layout, now_ms)?;
        deleted::delete_orphan_tombstones(&self.conn)?;
        // What the deletes overwrote reaches the main file and the WAL is
        // emptied (PP.2). A reader in the way makes it busy, and the next
        // prune pass checkpoints again: neither busy nor an error fails the
        // prune, whose deletes are committed.
        let _ = crate::paths::checkpoint_truncate(&self.conn);
        Ok(removed)
    }

    /// Every session with `peer_device` goes now (its contact was removed:
    /// storage rule "real erase"), whatever its lifetime left: its protected
    /// state (the session's root and chains) is deleted from the keystore,
    /// with its head and endpoint rows, one session per transaction as the
    /// prune does. No session-end record is written for it
    /// ([`forget_session_end`] forgets the contact's). How many went.
    pub fn delete_sessions_with_peer(
        &mut self,
        peer_device: &[u8; 32],
    ) -> Result<usize, IndexedSessionStoreError> {
        let (devices, device) = match self.layout.keyed() {
            None => (
                "initiator_device = ?1 OR responder_device = ?1",
                peer_device.to_vec(),
            ),
            Some(sealer) => (
                "kh_initiator_device = ?1 OR kh_responder_device = ?1",
                sealer.device(peer_device).to_vec(),
            ),
        };
        let rows: Vec<(Vec<u8>, Vec<u8>)> = {
            let mut statement = self.conn.prepare(&format!(
                "SELECT record_key, session_id FROM indexed_session_heads WHERE {devices}"
            ))?;
            let mapped = statement.query_map(params![device], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
            })?;
            mapped.collect::<Result<_, _>>()?
        };
        let mut removed = 0usize;
        for (record_key, session_id) in rows {
            let tx = self
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let _in_tx = crate::paths::HeldMark::transaction();
            delete_session_endpoint_rows(&tx, &session_id)?;
            let gone = tx.execute(
                "DELETE FROM indexed_session_heads WHERE record_key = ?1 AND session_id = ?2",
                params![record_key.as_slice(), session_id.as_slice()],
            )?;
            self.backend.delete(&hex::encode(&record_key))?;
            tx.commit()?;
            removed += gone;
        }
        deleted::delete_orphan_tombstones(&self.conn)?;
        // What the deletes overwrote reaches the main file (PP.2), as after
        // a prune; busy is no failure.
        let _ = crate::paths::checkpoint_truncate(&self.conn);
        Ok(removed)
    }

    /// Inbox rows for one record key (decrypts sealed local rows).
    pub fn list_endpoint_inbox_for_record(
        &mut self,
        key: &IndexedSessionRecordKey,
    ) -> Result<Vec<EndpointInboxRow>, IndexedSessionStoreError> {
        let digests: Vec<[u8; 32]> = {
            let record_key = record_key_digest(key)?;
            let account = hex::encode(record_key);
            let tx = self
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let _in_tx = crate::paths::HeldMark::transaction();
            let state = load_and_reconcile(
                &tx,
                &self.layout,
                self.backend.as_ref(),
                &account,
                &record_key,
            )?;
            if &state.binding.key != key {
                return Err(IndexedSessionStoreError::BindingConflict);
            }
            // Oldest first: by the time each row was received (in schema 3
            // from its `meta`, the insertion order breaking ties).
            let mut statement = tx.prepare(&format!(
                "SELECT {} FROM endpoint_inbox i WHERE i.session_id = ?1
                 ORDER BY {}",
                endpoints::inbox_entry_columns(&self.layout, "i."),
                if self.layout.endpoints().is_some() {
                    "i.seq ASC"
                } else {
                    "i.received_at_ms ASC"
                }
            ))?;
            let rows = statement
                .query_map(params![state.binding.session_id.as_slice()], |row| {
                    endpoints::raw(row, 0, endpoints::INBOX_ENTRY_WIDTH)
                })?;
            let mut out = Vec::new();
            for row in rows {
                out.push(endpoints::inbox_entry(&self.layout, row?)?);
            }
            drop(statement);
            tx.commit()?;
            out.sort_by_key(|entry| entry.received_at_ms);
            out.into_iter()
                .map(|entry| entry.object_digest)
                .collect::<Vec<_>>()
        };
        if digests.is_empty() {
            return Ok(Vec::new());
        }
        // One session, strict: an unreadable session or row is an error here
        // (callers such as the expiry archive match on it), never skipped.
        let mut inbox = Vec::new();
        for row in self.load_endpoint_inbox_rows(key, &digests)? {
            if let Some(row) = row? {
                inbox.push(row);
            }
        }
        Ok(inbox)
    }

    /// Every committed inbox row, oldest first. Rows of a session that cannot
    /// be read are logged and skipped rather than failing the whole listing.
    pub fn list_endpoint_inbox(
        &mut self,
    ) -> Result<Vec<EndpointInboxRow>, IndexedSessionStoreError> {
        Ok(self.list_endpoint_inbox_filtered(None)?.rows)
    }

    /// [`Self::list_endpoint_inbox`] with the number of committed rows it
    /// left out because they could not be read (`raven inbox` says so
    /// instead of "No messages yet").
    pub fn list_endpoint_inbox_counted(
        &mut self,
    ) -> Result<EndpointInboxListing, IndexedSessionStoreError> {
        self.list_endpoint_inbox_filtered(None)
    }

    /// Like [`Self::list_endpoint_inbox`], limited to one sender device.
    pub fn list_endpoint_inbox_for_sender(
        &mut self,
        sender_device: &[u8; 32],
    ) -> Result<Vec<EndpointInboxRow>, IndexedSessionStoreError> {
        Ok(self.list_endpoint_inbox_filtered(Some(sender_device))?.rows)
    }

    /// Like [`Self::list_endpoint_inbox_for_sender`], but only rows strictly after
    /// `after` with a hard `limit` (decrypt budget). Each row carries its own
    /// position ([`EndpointInboxRow::position`]): a reader saves the last one
    /// and passes it back. A position of the other order (a cursor saved
    /// before the store moved to schema 3) is placed first
    /// ([`Self::resolve_inbox_position`]).
    ///
    /// Rows of a session that cannot be read are logged and skipped. Paging
    /// continues past them, so a poisoned session at the head of the order
    /// cannot keep the healthy rows behind it from ever being returned. Each
    /// call loads such a session once, however many pages its rows span, and
    /// the log line is written once per process (callers poll this).
    pub fn list_endpoint_inbox_for_sender_after(
        &mut self,
        sender_device: &[u8; 32],
        after: &InboxPosition,
        limit: usize,
    ) -> Result<Vec<EndpointInboxRow>, IndexedSessionStoreError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let after = self.resolve_inbox_position(sender_device, after)?;
        let mut cursor_received_at_ms = after.seq as i64;
        let mut cursor_message_id = after.message_id;
        let mut cursor_seq = after.seq as i64;
        let keyed = self.layout.endpoints().is_some();
        let mut out = Vec::new();
        let mut unreadable = BTreeSet::new();
        let mut heads = std::collections::HashMap::new();
        loop {
            let wanted = limit - out.len();
            let page = {
                let mut statement = self.conn.prepare(&if keyed {
                    format!(
                        "SELECT {}, {}
                         FROM endpoint_inbox i
                         JOIN indexed_session_heads h ON h.session_id = i.session_id
                         WHERE i.kh_sender_device = ?1 AND i.seq > ?2
                         ORDER BY i.seq ASC
                         LIMIT ?4",
                        sealed::head_columns(&self.layout, "h."),
                        endpoints::inbox_entry_columns(&self.layout, "i.")
                    )
                } else {
                    format!(
                        "SELECT {}, {}
                         FROM endpoint_inbox i
                         JOIN indexed_session_heads h ON h.session_id = i.session_id
                         WHERE i.sender_device = ?1
                           AND (
                             i.received_at_ms > ?2
                             OR (?3 IS NULL AND i.received_at_ms >= ?2)
                             OR (?3 IS NOT NULL AND i.received_at_ms = ?2 AND i.message_id > ?3)
                           )
                         ORDER BY i.received_at_ms ASC, i.message_id ASC
                         LIMIT ?4",
                        sealed::head_columns(&self.layout, "h."),
                        endpoints::inbox_entry_columns(&self.layout, "i.")
                    )
                })?;
                let (from, last_id) = if keyed {
                    (cursor_seq, None)
                } else {
                    (cursor_received_at_ms, cursor_message_id)
                };
                let rows = statement.query_map(
                    params![
                        self.layout.ep_device(sender_device),
                        from,
                        last_id.as_ref().map(|id| id.as_slice()),
                        wanted as i64
                    ],
                    |row| {
                        Ok((
                            sealed::raw_head(&self.layout, row, 0)?,
                            endpoints::raw(row, 8, endpoints::INBOX_ENTRY_WIDTH)?,
                        ))
                    },
                )?;
                let mut page = Vec::new();
                for row in rows {
                    let (raw, entry) = row?;
                    // A session whose head does not open: its rows stay in
                    // the page, unread, as rows that do not open do.
                    let Some(head) = self.layout.head_cached(raw, &mut heads)? else {
                        page.push((None, (None, endpoints::listed_seq(&entry))));
                        continue;
                    };
                    let listed = endpoints::listed_entry(&self.layout, &head.key, entry)?;
                    page.push((Some(head.key), listed));
                }
                page
            };
            let Some((_, (_, last_seq))) = page.last() else {
                break;
            };
            // A page moves past every row it named, one that does not open
            // too (its `seq` is clear; a clear store's rows always decode).
            let last_seq = last_seq.unwrap_or(0);
            let exhausted = page.len() < wanted;
            let mut pending = Vec::new();
            for (key, (entry, _)) in page {
                let (Some(key), Some(entry)) = (key, entry) else {
                    continue;
                };
                cursor_received_at_ms = entry.received_at_ms;
                cursor_message_id = Some(entry.message_id);
                pending.push((key, entry.object_digest));
            }
            cursor_seq = last_seq;
            // A clear store's page moves by the rows it read (never none).
            let stuck = !keyed && pending.is_empty();
            out.extend(self.load_pending_inbox_rows(&pending, &mut unreadable, &mut 0)?);
            if exhausted || stuck || out.len() >= limit {
                break;
            }
        }
        Ok(out)
    }

    fn list_endpoint_inbox_filtered(
        &mut self,
        sender_device: Option<&[u8; 32]>,
    ) -> Result<EndpointInboxListing, IndexedSessionStoreError> {
        // Oldest first: by the time each row was received (in schema 3 from
        // its `meta`, the insertion order breaking ties).
        let mut statement = self.conn.prepare(&self.layout.ep(&format!(
            "SELECT {}, {}
             FROM endpoint_inbox i
             JOIN indexed_session_heads h ON h.session_id = i.session_id
             WHERE (?1 IS NULL OR i.kh_sender_device = ?1)
             ORDER BY {}",
            sealed::head_columns(&self.layout, "h."),
            endpoints::inbox_entry_columns(&self.layout, "i."),
            if self.layout.endpoints().is_some() {
                "i.seq ASC"
            } else {
                "i.received_at_ms ASC"
            }
        )))?;
        let bind = sender_device.map(|d| self.layout.ep_device(d));
        let mut unreadable = 0usize;
        let pending = {
            let rows = statement.query_map(params![bind], |row| {
                Ok((
                    sealed::raw_head(&self.layout, row, 0)?,
                    endpoints::raw(row, 8, endpoints::INBOX_ENTRY_WIDTH)?,
                ))
            })?;
            let mut pending = Vec::new();
            let mut heads = std::collections::HashMap::new();
            for row in rows {
                let (raw, entry) = row?;
                // A session whose head does not open is skipped (logged),
                // and counted.
                let Some(head) = self.layout.head_cached(raw, &mut heads)? else {
                    unreadable += 1;
                    continue;
                };
                let key = head.key;
                match endpoints::listed_entry(&self.layout, &key, entry)? {
                    (Some(entry), _) => {
                        pending.push((key, entry.object_digest, entry.received_at_ms))
                    }
                    (None, _) => unreadable += 1,
                }
            }
            pending
        };
        drop(statement);
        let mut pending = pending;
        pending.sort_by_key(|(_, _, received_at_ms)| *received_at_ms);
        let pending: Vec<_> = pending
            .into_iter()
            .map(|(key, digest, _)| (key, digest))
            .collect();
        let rows = self.load_pending_inbox_rows(&pending, &mut BTreeSet::new(), &mut unreadable)?;
        Ok(EndpointInboxListing { rows, unreadable })
    }

    /// Returns only ACK intents in a committed SQLite transaction.
    pub fn pending_endpoint_ack_intents(
        &self,
    ) -> Result<Vec<EndpointAckIntent>, IndexedSessionStoreError> {
        let rows = endpoints::ack_intent_rows(
            &self.conn,
            &self.layout,
            &format!(
                "SELECT {} FROM endpoint_ack_intents WHERE state = 0 ORDER BY rowid ASC",
                endpoints::ack_intent_columns(&self.layout)
            ),
        )?;
        let mut result = Vec::new();
        for row in rows {
            let endpoints::AckIntentRow {
                session_id: session,
                object_digest: digest,
                message_id: message,
                remote_device: remote,
                status,
                state,
                immutable_ack_bytes: bytes,
            } = row;
            if !matches!(status, 1 | 2) || !(0..=u8::MAX as i64).contains(&state) {
                return Err(IndexedSessionStoreError::CorruptEndpointState);
            }
            result.push(EndpointAckIntent {
                session_id: exact_array(&session)?,
                object_digest: exact_array(&digest)?,
                message_id: exact_array(&message)?,
                remote_device: exact_array(&remote)?,
                status: status as u8,
                state: EndpointAckIntentState::from_u8(state as u8)?,
                immutable_ack_bytes: bytes,
            });
        }
        Ok(result)
    }

    /// Persists immutable ACK bytes before invoking an idempotent durable queue
    /// insertion. A crash after insertion leaves the intent pending so retry
    /// reuses exactly the same bytes.
    #[cfg(test)]
    fn enqueue_endpoint_ack<F>(
        &mut self,
        session_id: &[u8; 32],
        object_digest: &[u8; 32],
        immutable_ack_bytes: &[u8],
        enqueue_idempotently: F,
    ) -> Result<(), IndexedSessionStoreError>
    where
        F: FnOnce(&[u8]) -> Result<(), String>,
    {
        if immutable_ack_bytes.is_empty()
            || immutable_ack_bytes.len() > crate::envelope::MAX_WIRE_ENVELOPE_BYTES
        {
            return Err(IndexedSessionStoreError::InvalidEndpointEnvelope);
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let _in_tx = crate::paths::HeldMark::transaction();
        let raw = endpoints::ack_intent_by_object(&tx, &self.layout, session_id, object_digest)?;
        let Some(endpoints::AckIntentRow {
            state,
            immutable_ack_bytes: existing,
            ..
        }) = raw
        else {
            return Err(IndexedSessionStoreError::NotFound);
        };
        if state == EndpointAckIntentState::Queued as i64 {
            if existing.as_deref() != Some(immutable_ack_bytes) {
                return Err(IndexedSessionStoreError::AckBytesConflict);
            }
            tx.commit()?;
            return Ok(());
        }
        if state != EndpointAckIntentState::Pending as i64 {
            return Err(IndexedSessionStoreError::CorruptEndpointState);
        }
        if let Some(existing) = existing {
            if existing != immutable_ack_bytes {
                return Err(IndexedSessionStoreError::AckBytesConflict);
            }
        } else {
            endpoints::set_ack_bytes(
                &tx,
                &self.layout,
                session_id,
                object_digest,
                immutable_ack_bytes,
                false,
            )?;
        }
        tx.commit()?;
        self.maybe_endpoint_fault(EndpointFaultPoint::BeforeAckEnqueue)?;
        enqueue_idempotently(immutable_ack_bytes)
            .map_err(|_| IndexedSessionStoreError::AckEnqueue)?;
        self.maybe_endpoint_fault(EndpointFaultPoint::AfterAckEnqueue)?;
        let changed = self.conn.execute(
            &self.layout.ep("UPDATE endpoint_ack_intents SET state = 1
                 WHERE session_id = ?1 AND kh_object_digest = ?2 AND state = 0
                   AND kh_ack = ?3"),
            params![
                session_id.as_slice(),
                self.layout.ep_digest(object_digest),
                self.layout.ep_bytes(immutable_ack_bytes)
            ],
        )?;
        if changed != 1 {
            return Err(IndexedSessionStoreError::CorruptEndpointState);
        }
        Ok(())
    }

    /// Registers the exact outbound logical row that may later be advanced by
    /// an authenticated ACK. The session's expected remote device is fixed by
    /// PairInit; callers cannot register an arbitrary recipient.
    #[cfg(test)]
    fn register_outstanding_message(
        &mut self,
        key: &IndexedSessionRecordKey,
        message_id: &[u8; 16],
    ) -> Result<(), IndexedSessionStoreError> {
        self.recover_pending_for_key(key)?;
        let record_key = record_key_digest(key)?;
        let account = hex::encode(record_key);
        let backend = Arc::clone(&self.backend);
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let _in_tx = crate::paths::HeldMark::transaction();
        let state = load_and_reconcile(&tx, &self.layout, backend.as_ref(), &account, &record_key)?;
        if &state.binding.key != key {
            return Err(IndexedSessionStoreError::BindingConflict);
        }
        let remote = remote_device_for_binding(&state.binding);
        endpoints::insert_outstanding(
            &tx,
            &self.layout,
            &state.binding.session_id,
            message_id,
            remote,
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Session id for a confirmed/provisional record (loads protected head).
    pub fn session_id_for_record_key(
        &mut self,
        key: &IndexedSessionRecordKey,
    ) -> Result<[u8; 32], IndexedSessionStoreError> {
        self.recover_pending_for_key(key)?;
        let record_key = record_key_digest(key)?;
        let account = hex::encode(record_key);
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let _in_tx = crate::paths::HeldMark::transaction();
        let state = load_and_reconcile(
            &tx,
            &self.layout,
            self.backend.as_ref(),
            &account,
            &record_key,
        )?;
        if &state.binding.key != key {
            return Err(IndexedSessionStoreError::BindingConflict);
        }
        let session_id = state.binding.session_id;
        tx.commit()?;
        Ok(session_id)
    }

    pub fn outstanding_delivery_state(
        &self,
        session_id: &[u8; 32],
        message_id: &[u8; 16],
        recipient_device: &[u8; 32],
    ) -> Result<Option<EndpointDeliveryState>, IndexedSessionStoreError> {
        self_delivery_state_in_connection(
            &self.conn,
            &self.layout,
            session_id,
            message_id,
            recipient_device,
        )
    }

    /// Accepts one sealed proto `0x03` ACK and conditionally advances only the
    /// exact outstanding `(message_id, recipient_device)` row. The ACK receive
    /// ratchet and database update use the same protected journal recovery
    /// pattern as message acceptance.
    pub fn accept_ack_envelope(
        &mut self,
        key: &IndexedSessionRecordKey,
        packed_envelope: &[u8],
        sender_certificate: &DeviceCertificate,
        sender_revoked: bool,
        now_ms: u64,
    ) -> Result<EndpointAckAcceptance, IndexedSessionStoreError> {
        refuse_held_suite()?;
        let env = Envelope::unpack(packed_envelope)
            .ok_or(IndexedSessionStoreError::InvalidEndpointEnvelope)?;
        if env.env_type != EnvType::Ack as u8 {
            return Err(IndexedSessionStoreError::EndpointTypeMismatch);
        }
        if !endpoint_time_window_valid(env.created_at, env.expires_at, now_ms)
            || env.created_at > i64::MAX as u64
            || env.expires_at > i64::MAX as u64
            || now_ms > i64::MAX as u64
        {
            return Err(IndexedSessionStoreError::EndpointNotCurrentlyValid);
        }
        let index = parse_indexed_message_header(&env.message_ciphertext)
            .map_err(|_| IndexedSessionStoreError::InvalidIndexedMessage)?;
        #[cfg(test)]
        let endpoint_fault = self.endpoint_fault.take();
        #[cfg(not(test))]
        let endpoint_fault = None;

        let record_key = record_key_digest(key)?;
        let account = hex::encode(record_key);
        let backend = Arc::clone(&self.backend);
        let (tx, mut state) = begin_journal_free_tx!(self, backend, account, record_key);
        let _in_tx = crate::paths::HeldMark::transaction();
        if &state.binding.key != key {
            return Err(IndexedSessionStoreError::BindingConflict);
        }
        if state.binding.lifecycle != SessionLifecycle::Confirmed {
            return Err(IndexedSessionStoreError::SessionNotConfirmed);
        }
        if state.pending_acceptance.is_some()
            || state.pending_ack_acceptance.is_some()
            || state.pending_outbound.is_some()
        {
            return Err(IndexedSessionStoreError::CorruptProtectedState);
        }
        // Candidate selection first (see accept_message_envelope), then this
        // session's own validity window.
        let direction = state.binding.local_role.inbound_direction();
        let expected_hint = endpoint_device_hint(local_device_for_binding(&state.binding));
        if env.dest_device_hint != 0 && env.dest_device_hint != expected_hint {
            return Err(IndexedSessionStoreError::DeviceHintMismatch);
        }
        let expected_route = derive_route_tag(
            &state.ratchets.root,
            env.created_at,
            index,
            env.env_type,
            direction,
        )
        .map_err(|_| IndexedSessionStoreError::RouteTagMismatch)?;
        if !route_tag_eq(&env.routing_tag, &expected_route) {
            return Err(IndexedSessionStoreError::RouteTagMismatch);
        }
        if before_session_start(now_ms, state.binding.created_at_ms)
            || now_ms >= state.binding.expires_at_ms
            || before_session_start(env.created_at, state.binding.created_at_ms)
            || env.expires_at > state.binding.expires_at_ms
        {
            return Err(IndexedSessionStoreError::EndpointNotCurrentlyValid);
        }
        if sender_revoked {
            return Err(IndexedSessionStoreError::RevokedDevice);
        }
        sender_certificate
            .verify(now_ms)
            .map_err(|_| IndexedSessionStoreError::InvalidDeviceCertificate)?;
        let remote = *remote_device_for_binding(&state.binding);
        if sender_certificate.device_ed_pub != remote
            || device_certificate_hash(sender_certificate)
                .map_err(|_| IndexedSessionStoreError::InvalidDeviceCertificate)?
                != *remote_certificate_digest(&state.binding)
        {
            return Err(IndexedSessionStoreError::DeviceBindingMismatch);
        }
        if !env.verify(&remote) {
            return Err(IndexedSessionStoreError::OuterSignatureInvalid);
        }
        let object_digest = authenticated_object_digest(&env);
        if let Some(existing) =
            endpoint_ack_receipt(&tx, &self.layout, &state.binding.session_id, &object_digest)?
        {
            if existing.outer_message_id != env.message_id || existing.remote_device != remote {
                return Err(IndexedSessionStoreError::CorruptEndpointState);
            }
            let delivery_state = self_delivery_state_in_connection(
                &tx,
                &self.layout,
                &state.binding.session_id,
                &existing.acked_message_id,
                &remote,
            )?
            .ok_or(IndexedSessionStoreError::CorruptEndpointState)?;
            tx.commit()?;
            return Ok(EndpointAckAcceptance::Duplicate {
                session_id: state.binding.session_id,
                object_digest,
                acked_message_id: existing.acked_message_id,
                delivery_state,
            });
        }
        // Mirrors the message lane's logical-ID gate: the outer message ID is
        // unique per (session, remote device) in `endpoint_ack_receipts`, so a
        // different authenticated ACK object reusing it is a sender integrity
        // conflict, rejected before the receive ratchet or any journal moves.
        if let Some(existing_digest) = ack_outer_message_object(
            &tx,
            &self.layout,
            &state.binding.session_id,
            &remote,
            &env.message_id,
        )? {
            if existing_digest != object_digest {
                return Err(IndexedSessionStoreError::LogicalMessageConflict);
            }
        }

        let (sender, recipient) = endpoints_for_direction(&state.binding, direction);
        let mut candidate =
            prepare_receive_key(&mut state.ratchets.ack_receive, index, sender, recipient)?;
        let plaintext_result = open_indexed_message_with_key(
            &candidate,
            &state.binding.key.initiator_address,
            &state.binding.key.responder_address,
            direction,
            &env.message_id,
            &env.message_ciphertext,
        );
        candidate.zeroize();
        let plaintext =
            plaintext_result.map_err(|_| IndexedSessionStoreError::AuthenticationFailed)?;
        let signed = decode_signed_ack(&plaintext)
            .map_err(|_| IndexedSessionStoreError::InvalidIndexedMessage)?;
        if signed.record.created_at != env.created_at {
            return Err(IndexedSessionStoreError::AckTimestampMismatch);
        }
        if !signed.record.verify(&signed.signature, &remote) {
            return Err(IndexedSessionStoreError::AckInnerSignatureInvalid);
        }
        let Some(existing_state) = self_delivery_state_in_connection(
            &tx,
            &self.layout,
            &state.binding.session_id,
            &signed.record.acked_message_id,
            &remote,
        )?
        else {
            return Err(IndexedSessionStoreError::AckOutstandingMismatch);
        };
        if let Some(existing_object) = ack_nonce_object(
            &tx,
            &self.layout,
            &state.binding.session_id,
            &remote,
            &signed.record.ack_nonce,
        )? {
            if existing_object != object_digest {
                return Err(IndexedSessionStoreError::AckNonceConflict);
            }
        }
        let target_state = EndpointDeliveryState::from_u8(signed.record.status)?;
        let delivery_state = std::cmp::max(existing_state, target_state);
        state.generation = state
            .generation
            .checked_add(1)
            .ok_or(IndexedSessionStoreError::IndexExhausted)?;
        state.pending_ack_acceptance = Some(PendingAckAcceptance {
            session_id: state.binding.session_id,
            object_digest,
            outer_message_id: env.message_id,
            remote_device: remote,
            acked_message_id: signed.record.acked_message_id,
            status: signed.record.status,
            ack_nonce: signed.record.ack_nonce,
            created_at_ms: env.created_at,
            public_generation: state.generation,
        });
        let journal = stage_journaled_mutation(
            &tx,
            &self.layout,
            backend.as_ref(),
            &account,
            &record_key,
            &state,
            endpoint_fault,
        )?;
        maybe_injected_endpoint_fault(endpoint_fault, EndpointFaultPoint::BeforeDatabaseCommit)?;
        tx.commit()?;
        maybe_injected_endpoint_fault(endpoint_fault, EndpointFaultPoint::AfterDatabaseCommit)?;
        maybe_injected_endpoint_fault(endpoint_fault, EndpointFaultPoint::BeforeJournalClear)?;
        state.pending_ack_acceptance = None;
        self.clear_protected_journal(&account, &record_key, state.generation, journal)?;
        maybe_injected_endpoint_fault(endpoint_fault, EndpointFaultPoint::AfterJournalClear)?;
        Ok(EndpointAckAcceptance::Committed {
            session_id: state.binding.session_id,
            object_digest,
            acked_message_id: signed.record.acked_message_id,
            delivery_state,
        })
    }

    /// Replays every protected journal before SQLite-only readers run.
    ///
    /// Failures scoped to one session (an expired head whose secret a crashed
    /// prune already deleted, a switched backend or moved data dir, a corrupt
    /// or rolled-back blob) do not fail `open()`: that would make every other
    /// session, and the prune that cleans such heads up, unreachable. Every
    /// per-session operation repeats this recovery first and still fails
    /// closed for that session. Store-wide SQLite and protected-backend
    /// failures still fail `open()`.
    fn recover_all_pending_acceptances(&mut self) -> Result<(), IndexedSessionStoreError> {
        let record_keys = {
            let mut statement = self
                .conn
                .prepare("SELECT record_key FROM indexed_session_heads ORDER BY record_key")?;
            let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
            let mut keys = Vec::new();
            for row in rows {
                keys.push(exact_array::<32>(&row?)?);
            }
            keys
        };
        for record_key in record_keys {
            if !self.protected_journal_present(&record_key)? {
                continue;
            }
            match self.recover_pending_for_digest(&record_key) {
                Ok(()) => {}
                Err(
                    error @ (IndexedSessionStoreError::Sqlite(_)
                    | IndexedSessionStoreError::ProtectedStore(_)),
                ) => return Err(error),
                Err(_) => {}
            }
        }
        Ok(())
    }

    /// Lock-free peek used only by `open()`: most sessions carry no journal,
    /// and taking the database-wide write lock across one protected-backend
    /// read per session would serialize every store user behind Keychain /
    /// Secret Service latency. A journal seen here is replayed under the lock,
    /// which re-reads the blob; one written after this peek belongs to a live
    /// writer that clears it itself, or to the next per-session recovery.
    /// Missing or undecodable blobs have nothing to replay; per-session
    /// operations report them under the lock.
    fn protected_journal_present(
        &self,
        record_key: &[u8; 32],
    ) -> Result<bool, IndexedSessionStoreError> {
        let Some(mut encoded) = self.backend.get(&hex::encode(record_key))? else {
            return Ok(false);
        };
        let decoded = decode_protected_state(&encoded);
        encoded.zeroize();
        Ok(decoded.is_ok_and(|state| {
            state.pending_acceptance.is_some()
                || state.pending_ack_acceptance.is_some()
                || state.pending_outbound.is_some()
        }))
    }

    fn recover_pending_for_key(
        &mut self,
        key: &IndexedSessionRecordKey,
    ) -> Result<(), IndexedSessionStoreError> {
        self.recover_pending_for_digest(&record_key_digest(key)?)
    }

    fn recover_pending_for_digest(
        &mut self,
        record_key: &[u8; 32],
    ) -> Result<(), IndexedSessionStoreError> {
        let account = hex::encode(record_key);
        let backend = Arc::clone(&self.backend);
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let _in_tx = crate::paths::HeldMark::transaction();
        let state = load_and_reconcile(&tx, &self.layout, backend.as_ref(), &account, record_key)?;
        let Some(journal) = protected_journal(&state)? else {
            tx.commit()?;
            return Ok(());
        };
        match apply_protected_journal(&tx, &self.layout, &state) {
            Ok(()) => tx.commit()?,
            Err(error) if journal_replay_is_unrecoverable(&error) => {
                // A journal that deterministically conflicts with committed
                // rows can never replay; keeping it would fail every later
                // operation on this session. Roll the partial replay back and
                // quarantine the journal: the protected ratchet stays advanced
                // (an index is burned, never reused), no row or ACK becomes
                // visible, and the conflicting object is treated as rejected.
                drop(tx);
            }
            Err(error) => return Err(error),
        }
        let generation = state.generation;
        drop(state);
        self.clear_protected_journal(&account, record_key, generation, journal)
    }

    /// Clears a protected journal whose rows are committed (or which was
    /// quarantined). The protected write runs under a fresh IMMEDIATE
    /// transaction, serialized with every other protected writer, and only
    /// clears the exact journal at the exact generation it was written with.
    /// If another store instance already replayed and cleared it, or has since
    /// advanced the session, this is a no-op: writing this instance's stale
    /// in-memory copy instead would roll the protected head behind metadata
    /// and fail every later access with `RollbackDetected`.
    fn clear_protected_journal(
        &mut self,
        account: &str,
        record_key: &[u8; 32],
        generation: u64,
        journal: ProtectedJournal,
    ) -> Result<(), IndexedSessionStoreError> {
        let backend = Arc::clone(&self.backend);
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let _in_tx = crate::paths::HeldMark::transaction();
        let mut state =
            load_and_reconcile(&tx, &self.layout, backend.as_ref(), account, record_key)?;
        if state.generation == generation && protected_journal(&state)? == Some(journal) {
            state.pending_acceptance = None;
            state.pending_ack_acceptance = None;
            state.pending_outbound = None;
            put_protected_state(backend.as_ref(), account, &state)?;
        }
        tx.commit()?;
        Ok(())
    }

    #[cfg(test)]
    fn maybe_endpoint_fault(
        &self,
        point: EndpointFaultPoint,
    ) -> Result<(), IndexedSessionStoreError> {
        #[cfg(test)]
        if self.endpoint_fault.get() == Some(point) {
            self.endpoint_fault.set(None);
            return Err(IndexedSessionStoreError::InjectedEndpointFailure(
                point.label(),
            ));
        }
        #[cfg(not(test))]
        let _ = point;
        Ok(())
    }

    /// Verifies an exact PairResponse against both the accepted PairInit and
    /// the protected provisional root before monotonically confirming state.
    /// Both initiator and responder call this method; responder self-confirm
    /// verifies the exact signed response it generated through the same path.
    pub fn confirm_verified_pair_response(
        &mut self,
        key: &IndexedSessionRecordKey,
        accepted_init: &PairInit,
        response: &PairResponse,
        now_ms: u64,
    ) -> Result<(), IndexedSessionStoreError> {
        let record_key = record_key_digest(key)?;
        let account = hex::encode(record_key);
        let backend = Arc::clone(&self.backend);
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let _in_tx = crate::paths::HeldMark::transaction();
        let state = load_and_reconcile(&tx, &self.layout, backend.as_ref(), &account, &record_key)?;
        if &state.binding.key != key
            || accepted_init.initiator_address != key.initiator_address
            || accepted_init.responder_address != key.responder_address
            || accepted_init.initiator_device_ed_pub != key.initiator_device_ed25519
            || accepted_init.responder_device_ed_pub != key.responder_device_ed25519
            || accepted_init.init_id != key.init_id
            || pair_init_hash(accepted_init)? != state.binding.init_hash
            || pair_session_id(accepted_init)? != state.binding.session_id
            || pair_transcript_hash(accepted_init)? != state.binding.transcript_hash
        {
            return Err(IndexedSessionStoreError::BindingConflict);
        }
        verify_response(response, accepted_init, &state.ratchets.root, now_ms)?;
        let response_hash: [u8; 32] = Sha256::digest(encode_pair_response(response)?).into();
        let session_id = state.binding.session_id;
        let peer = *remote_device_for_binding(&state.binding);
        drop(state);
        tx.commit()?;
        self.confirm_session_inner(key, response_hash)?;
        // Session-reset metadata (both roles, whatever the gate): when this
        // node first saw the session confirmed. Best effort: the confirmation
        // is committed, and a missing stamp only makes the young-responder
        // rule fall back to the head (bounded).
        let _ = reset::note_confirmed(&self.conn, &self.layout, &session_id, &peer, now_ms);
        Ok(())
    }

    /// Test-only state transition; production callers cannot inject an
    /// arbitrary response hash.
    #[cfg(test)]
    fn confirm_session(
        &mut self,
        key: &IndexedSessionRecordKey,
        response_hash: [u8; 32],
    ) -> Result<(), IndexedSessionStoreError> {
        self.confirm_session_inner(key, response_hash)
    }

    fn confirm_session_inner(
        &mut self,
        key: &IndexedSessionRecordKey,
        response_hash: [u8; 32],
    ) -> Result<(), IndexedSessionStoreError> {
        let record_key = record_key_digest(key)?;
        let account = hex::encode(record_key);
        let backend = Arc::clone(&self.backend);
        // `write_mutation` re-encodes the whole state with a bumped generation,
        // so it must never run over another instance's pending journal.
        let (tx, mut state) = begin_journal_free_tx!(self, backend, account, record_key);
        let _in_tx = crate::paths::HeldMark::transaction();
        match (state.binding.lifecycle, state.binding.response_hash) {
            (SessionLifecycle::Confirmed, Some(existing)) if existing == response_hash => {
                tx.commit()?;
                return Ok(());
            }
            (SessionLifecycle::Confirmed, _) => {
                return Err(IndexedSessionStoreError::ConfirmationConflict)
            }
            (SessionLifecycle::Provisional, None) => {}
            _ => return Err(IndexedSessionStoreError::CorruptProtectedState),
        }
        state.binding.lifecycle = SessionLifecycle::Confirmed;
        state.binding.response_hash = Some(response_hash);
        state.generation = state
            .generation
            .checked_add(1)
            .ok_or(IndexedSessionStoreError::IndexExhausted)?;
        write_mutation(
            &tx,
            backend.as_ref(),
            &account,
            &record_key,
            &state,
            #[cfg(test)]
            self.crash_after_protected_write,
        )?;
        tx.commit()?;
        Ok(())
    }

    #[cfg(test)]
    fn inject_crash_after_next_protected_write(&mut self) {
        self.crash_after_protected_write = true;
    }

    #[cfg(test)]
    fn inject_after_recovery_hook(&self, hook: impl FnOnce() + Send + 'static) {
        *self.after_recovery_hook.borrow_mut() = Some(Box::new(hook));
    }

    #[cfg(test)]
    fn run_after_recovery_hook(&self) {
        let hook = self.after_recovery_hook.borrow_mut().take();
        if let Some(hook) = hook {
            hook();
        }
    }

    #[cfg(test)]
    fn inject_endpoint_fault(&self, point: EndpointFaultPoint) {
        self.endpoint_fault.set(Some(point));
    }
}

/// The record key of the session `init` sets up, in either role: what
/// [`IndexedSessionStore::create_verified_pair_init_session`] stores it under
/// (session renewal finds the provisional session of a PairInit it resends
/// by it).
pub fn record_key_for_init(init: &PairInit) -> IndexedSessionRecordKey {
    IndexedSessionRecordKey {
        profile_id: PROFILE_ID.to_vec(),
        initiator_address: init.initiator_address.clone(),
        responder_address: init.responder_address.clone(),
        initiator_device_ed25519: init.initiator_device_ed_pub,
        responder_device_ed25519: init.responder_device_ed_pub,
        init_id: init.init_id,
    }
}

/// The legacy recipient hint `SHA-256("rvn1/device-hint/v1" || device_pub)[:8]`.
///
/// Anyone holding the recipient's public key (its address) can compute it, so
/// a relay, store or bridge holding the envelope would recognise the recipient.
/// New outbound envelopes and ACKs therefore carry [`OUTBOUND_DEST_DEVICE_HINT`]
/// (`0`, "no hint"; ATSAM endpoint transaction erratum 2026-10-08). Receivers
/// and stored-outbound validation still accept this value from senders and
/// outbox rows that predate the change.
pub fn endpoint_device_hint(device_ed25519: &[u8; 32]) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(b"rvn1/device-hint/v1");
    hasher.update(device_ed25519);
    let digest = hasher.finalize();
    u64::from_be_bytes(digest[..8].try_into().expect("fixed SHA-256 prefix"))
}

/// `dest_device_hint` this node writes into every new outbound envelope and
/// sealed ACK: `0` names nobody. The field is outside the envelope signature
/// and the object digest (`RAVEN_ENVELOPE_V1.md` §2), so this changes no
/// signed or digested byte.
pub const OUTBOUND_DEST_DEVICE_HINT: u64 = 0;

/// Stored outbound bytes are valid with the current hint (`0`) or with the
/// legacy recipient hint of rows queued before the 2026-10-08 change (their
/// exact bytes are retried unchanged and must keep validating).
fn stored_outbound_hint_ok(hint: u64, recipient_device: &[u8; 32]) -> bool {
    hint == OUTBOUND_DEST_DEVICE_HINT || hint == endpoint_device_hint(recipient_device)
}

/// Constant-time route-tag equality. The expected tag is derived from the
/// session root, so an early-exit comparison would leak through timing how
/// many leading bytes of an attacker-chosen tag already match.
fn route_tag_eq(received: &[u8; 16], expected: &[u8; 16]) -> bool {
    let mut diff = 0u8;
    for (a, b) in received.iter().zip(expected.iter()) {
        diff |= a ^ b;
    }
    std::hint::black_box(diff) == 0
}

fn local_device_for_binding(binding: &IndexedSessionBinding) -> &[u8; 32] {
    match binding.local_role {
        LocalRole::Initiator => &binding.key.initiator_device_ed25519,
        LocalRole::Responder => &binding.key.responder_device_ed25519,
    }
}

fn remote_device_for_binding(binding: &IndexedSessionBinding) -> &[u8; 32] {
    match binding.local_role {
        LocalRole::Initiator => &binding.key.responder_device_ed25519,
        LocalRole::Responder => &binding.key.initiator_device_ed25519,
    }
}

fn remote_certificate_digest(binding: &IndexedSessionBinding) -> &[u8; 32] {
    match binding.local_role {
        LocalRole::Initiator => &binding.responder_cert_digest,
        LocalRole::Responder => &binding.initiator_cert_digest,
    }
}

fn local_certificate_digest(binding: &IndexedSessionBinding) -> &[u8; 32] {
    match binding.local_role {
        LocalRole::Initiator => &binding.initiator_cert_digest,
        LocalRole::Responder => &binding.responder_cert_digest,
    }
}

fn local_address_for_binding(binding: &IndexedSessionBinding) -> &str {
    match binding.local_role {
        LocalRole::Initiator => &binding.key.initiator_address,
        LocalRole::Responder => &binding.key.responder_address,
    }
}

/// Sealing and accepting (messages and ACKs) on an indexed session: refused,
/// before anything is read or changed, while a Raven security notice marks
/// the session profile BROKEN (P6.45, [`crate::suite_policy::session_allowed`]).
fn refuse_held_suite() -> Result<(), IndexedSessionStoreError> {
    if crate::suite_policy::session_allowed() {
        Ok(())
    } else {
        Err(IndexedSessionStoreError::SuiteHeld)
    }
}

/// A retired session (the contact lost it) never seals, retries or resends a
/// Message again. ACKs are unaffected: the contact may still ACK under it.
fn refuse_retired_message_lane(
    conn: &Connection,
    layout: &Layout,
    session_id: &[u8; 32],
    kind: EndpointOutboundKind,
) -> Result<(), IndexedSessionStoreError> {
    if kind == EndpointOutboundKind::Message && reset::session_is_retired(conn, layout, session_id)?
    {
        return Err(IndexedSessionStoreError::SessionRetired);
    }
    Ok(())
}

// The explicit coordinates are security bindings, not an ergonomic facade:
// grouping them into a caller-constructible request object would make it
// easier to validate one set and materialize another.
//
// `provisional_message_cap`: how many message indices a provisional initiator
// may seal, read in the caller's transaction
// ([`letters::provisional_message_cap`]): 1 (index 0, the PairInit bootstrap)
// except in a session this node started for a letter (Phase 5, P5.12;
// `ATSAM_ENDPOINT_TRANSACTION_V1.md` §4.1).
#[allow(clippy::too_many_arguments)]
fn validate_outbound_session_and_signer(
    state: &ProtectedSessionState,
    key: &IndexedSessionRecordKey,
    local_device: &AuthorizedEndpointDevice<'_>,
    kind: EndpointOutboundKind,
    ratchet_index: u32,
    created_at_ms: u64,
    expires_at_ms: u64,
    now_ms: u64,
    provisional_message_cap: u32,
) -> Result<(), IndexedSessionStoreError> {
    if !endpoint_time_window_valid(created_at_ms, expires_at_ms, now_ms) {
        return Err(IndexedSessionStoreError::EndpointNotCurrentlyValid);
    }
    if &state.binding.key != key {
        return Err(IndexedSessionStoreError::BindingConflict);
    }
    match state.binding.lifecycle {
        SessionLifecycle::Confirmed => {}
        SessionLifecycle::Provisional
            if kind == EndpointOutboundKind::Message
                && state.binding.local_role == LocalRole::Initiator
                && ratchet_index < provisional_message_cap => {}
        SessionLifecycle::Provisional => return Err(IndexedSessionStoreError::SessionNotConfirmed),
    }
    if before_session_start(now_ms, state.binding.created_at_ms)
        || now_ms >= state.binding.expires_at_ms
        || before_session_start(created_at_ms, state.binding.created_at_ms)
        || expires_at_ms > state.binding.expires_at_ms
    {
        return Err(IndexedSessionStoreError::EndpointNotCurrentlyValid);
    }
    local_device.validate_current(now_ms)?;
    let certificate = local_device.certificate;
    let certificate_digest = device_certificate_hash(certificate)
        .map_err(|_| IndexedSessionStoreError::LocalDeviceUnauthorized)?;
    if certificate.device_ed_pub != *local_device_for_binding(&state.binding)
        || certificate_digest != *local_certificate_digest(&state.binding)
        || crate::address::encode_address(&certificate.user_ed_pub)
            != local_address_for_binding(&state.binding)
        || created_at_ms < certificate.not_before_ms
        || expires_at_ms > certificate.not_after_ms
    {
        return Err(IndexedSessionStoreError::LocalDeviceBindingMismatch);
    }
    Ok(())
}

fn ensure_no_pending_protected_mutation(
    state: &ProtectedSessionState,
) -> Result<(), IndexedSessionStoreError> {
    if state.pending_acceptance.is_some()
        || state.pending_ack_acceptance.is_some()
        || state.pending_outbound.is_some()
    {
        return Err(IndexedSessionStoreError::CorruptProtectedState);
    }
    Ok(())
}

fn random_nonzero<const N: usize, R: RngCore + CryptoRng>(
    rng: &mut R,
) -> Result<[u8; N], IndexedSessionStoreError> {
    let mut value = [0u8; N];
    rng.try_fill_bytes(&mut value)
        .map_err(|_| IndexedSessionStoreError::EndpointRandomnessUnavailable)?;
    if value.iter().all(|byte| *byte == 0) {
        value.zeroize();
        return Err(IndexedSessionStoreError::EndpointRandomnessUnavailable);
    }
    Ok(value)
}

fn ensure_fresh_outbound_coordinates(
    conn: &Connection,
    layout: &Layout,
    session_id: &[u8; 32],
    message_id: &[u8; 16],
    seal_nonce: &[u8; 12],
    anti_replay_nonce: &[u8; 12],
    ack_nonce: Option<&[u8; 12]>,
) -> Result<(), IndexedSessionStoreError> {
    let collision: Option<i64> = conn
        .query_row(
            &layout.ep("SELECT 1 FROM endpoint_outbox
                 WHERE session_id = ?1 AND (kh_message_id = ?2
                   OR kh_seal_nonce = ?3
                   OR kh_anti_replay_nonce = ?4
                   OR (?5 IS NOT NULL AND kh_ack_nonce = ?5)) LIMIT 1"),
            params![
                session_id.as_slice(),
                layout.ep_mid(message_id),
                layout.ep_nonce(seal_nonce),
                layout.ep_nonce(anti_replay_nonce),
                ack_nonce.map(|value| layout.ep_nonce(value))
            ],
            |row| row.get(0),
        )
        .optional()?;
    if collision.is_some() {
        return Err(IndexedSessionStoreError::OutboundCollision);
    }
    let historical_id: Option<i64> = conn
        .query_row(
            &layout.ep("SELECT 1 FROM endpoint_outstanding_messages
                 WHERE session_id = ?1 AND kh_message_id = ?2
                 UNION ALL
                 SELECT 1 FROM endpoint_ack_receipts
                 WHERE session_id = ?1 AND kh_outer_message_id = ?2
                 LIMIT 1"),
            params![session_id.as_slice(), layout.ep_mid(message_id)],
            |row| row.get(0),
        )
        .optional()?;
    if historical_id.is_some() {
        return Err(IndexedSessionStoreError::OutboundCollision);
    }
    Ok(())
}

fn prepared_outbound_exists(
    conn: &Connection,
    session_id: &[u8; 32],
    kind: EndpointOutboundKind,
) -> Result<bool, IndexedSessionStoreError> {
    Ok(conn
        .query_row(
            "SELECT 1 FROM endpoint_outbox
             WHERE session_id = ?1 AND kind = ?2 AND state = 0 LIMIT 1",
            params![session_id.as_slice(), kind as u8],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .is_some())
}

/// Retires prepared ACK objects whose envelope expired before a successful
/// queue handoff. Retry refuses expired objects, so such a row could never
/// leave the prepared state and would block the ACK lane until the session
/// expires. The intent keeps its immutable bytes, so it is never
/// re-materialized under a second object (at most one materialized object per
/// intent); the consumed ACK ratchet index stays burned.
fn retire_expired_prepared_acks(
    tx: &Transaction<'_>,
    layout: &Layout,
    session_id: &[u8; 32],
    now_ms: u64,
) -> Result<(), IndexedSessionStoreError> {
    let prepared = endpoints::outbox_rows(
        tx,
        layout,
        &format!(
            "SELECT {} FROM endpoint_outbox WHERE session_id = ?1 AND kind = 2 AND state = 0",
            endpoints::outbox_columns(layout, "")
        ),
        params![session_id.as_slice()],
    )?;
    for row in prepared {
        let envelope = Envelope::unpack(&row.immutable_envelope_bytes)
            .ok_or(IndexedSessionStoreError::CorruptEndpointState)?;
        if envelope.expires_at > now_ms {
            continue;
        }
        tx.execute(
            &layout.ep("DELETE FROM endpoint_outbox
                 WHERE session_id = ?1 AND kh_object_digest = ?2 AND kind = 2 AND state = 0"),
            params![session_id.as_slice(), layout.ep_digest(&row.object_digest)],
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn outbound_envelope(
    state: &ProtectedSessionState,
    env_type: EnvType,
    index: u32,
    message_id: [u8; 16],
    anti_replay_nonce: [u8; 12],
    created_at_ms: u64,
    expires_at_ms: u64,
    message_ciphertext: Vec<u8>,
) -> Result<Envelope, IndexedSessionStoreError> {
    let direction = state.binding.local_role.outbound_direction();
    let routing_tag = derive_route_tag(
        &state.ratchets.root,
        created_at_ms,
        index,
        env_type as u8,
        direction,
    )
    .map_err(|_| IndexedSessionStoreError::OutboundBindingMismatch)?;
    Ok(Envelope {
        env_type: env_type as u8,
        flags: OUTBOUND_FLAGS,
        message_id,
        routing_tag,
        dest_device_hint: OUTBOUND_DEST_DEVICE_HINT,
        created_at: created_at_ms,
        expires_at: expires_at_ms,
        hop_limit: OUTBOUND_HOP_LIMIT,
        replication_budget: OUTBOUND_REPLICATION_BUDGET,
        anti_replay_nonce,
        ratchet_header_ciphertext: Vec::new(),
        message_ciphertext,
        sender_authentication: vec![0; 64],
    })
}

fn sign_outbound_envelope(
    envelope: &mut Envelope,
    local_device: &AuthorizedEndpointDevice<'_>,
) -> Result<(), IndexedSessionStoreError> {
    envelope.sender_authentication = local_device
        .sign_verified(&envelope.signing_bytes())?
        .to_vec();
    if !envelope.verify(&local_device.certificate.device_ed_pub) {
        return Err(IndexedSessionStoreError::LocalSignerFailure);
    }
    Ok(())
}

fn validate_materialized_outbound(
    envelope: &Envelope,
    packed: &[u8],
) -> Result<(), IndexedSessionStoreError> {
    if packed.is_empty()
        || packed.len() > MAX_PENDING_OUTBOUND_BYTES
        || Envelope::unpack(packed).as_ref() != Some(envelope)
        || envelope.flags != OUTBOUND_FLAGS
        || envelope.hop_limit != OUTBOUND_HOP_LIMIT
        || envelope.replication_budget != OUTBOUND_REPLICATION_BUDGET
        || !envelope.ratchet_header_ciphertext.is_empty()
    {
        return Err(IndexedSessionStoreError::InvalidEndpointEnvelope);
    }
    Ok(())
}

fn exact_array<const N: usize>(value: &[u8]) -> Result<[u8; N], IndexedSessionStoreError> {
    value
        .try_into()
        .map_err(|_| IndexedSessionStoreError::CorruptEndpointState)
}

fn record_key_from_columns(
    profile_id: Vec<u8>,
    initiator_address: String,
    responder_address: String,
    initiator_device: &[u8],
    responder_device: &[u8],
    init_id: &[u8],
) -> Result<IndexedSessionRecordKey, IndexedSessionStoreError> {
    Ok(IndexedSessionRecordKey {
        profile_id,
        initiator_address,
        responder_address,
        initiator_device_ed25519: exact_array(initiator_device)?,
        responder_device_ed25519: exact_array(responder_device)?,
        init_id: exact_array(init_id)?,
    })
}

/// Failures scoped to one session's own protected or metadata state (secret
/// gone after a moved data dir or a restored database, corrupt or rolled-back
/// blob, a tampered local row). Operations that span sessions skip such a
/// session instead of failing for every healthy one. Store-wide failures
/// (SQLite, the protected backend being locked or unavailable) are never
/// scoped to a session and are always propagated: skipping them would hide a
/// session that is only temporarily unreadable.
fn is_session_scoped_state_error(error: &IndexedSessionStoreError) -> bool {
    matches!(
        error,
        IndexedSessionStoreError::ProtectedStateMissing
            | IndexedSessionStoreError::CorruptProtectedState
            | IndexedSessionStoreError::RollbackDetected
            | IndexedSessionStoreError::NotFound
            | IndexedSessionStoreError::CorruptEndpointState
            | IndexedSessionStoreError::LocalInboxAuthenticationFailed
            | IndexedSessionStoreError::InvalidBinding
            | IndexedSessionStoreError::UnsupportedProfile
            | IndexedSessionStoreError::BindingConflict
    )
}

/// Upper bound on the skipped-session log lines remembered by the process.
const MAX_LOGGED_SKIPPED_SESSIONS: usize = 256;

/// Which skipped-session log lines this process has already written. The ash
/// chat poller reopens the store every 500 ms and an unreadable session stays
/// unreadable, so without this memory the same line would repeat on the
/// terminal (in the middle of whatever the user is typing) twice a second.
/// Keyed on the record key and the redacted error text, so a session that
/// starts failing differently is reported again.
struct SkippedSessionLog {
    seen: BTreeSet<(Vec<u8>, String)>,
}

impl SkippedSessionLog {
    const fn new() -> Self {
        Self {
            seen: BTreeSet::new(),
        }
    }

    /// True the first time this `(record key, error text)` pair is reported.
    /// The memory is bounded: when full it starts over, which at worst repeats
    /// a line.
    fn first_report(&mut self, record_key: &[u8], error_text: &str) -> bool {
        let entry = (record_key.to_vec(), error_text.to_owned());
        if self.seen.contains(&entry) {
            return false;
        }
        if self.seen.len() >= MAX_LOGGED_SKIPPED_SESSIONS {
            self.seen.clear();
        }
        self.seen.insert(entry);
        true
    }
}

static SKIPPED_SESSION_LOG: Mutex<SkippedSessionLog> = Mutex::new(SkippedSessionLog::new());

/// A skipped session must not be silent, but it is reported once per process
/// rather than once per listing (see [`SkippedSessionLog`]). The record key is
/// a public digest and the error text never carries protected bytes.
fn log_skipped_session(record_key: &[u8], error: &IndexedSessionStoreError) {
    let error_text = error.redacted_display();
    let first = SKIPPED_SESSION_LOG
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .first_report(record_key, &error_text);
    if first {
        let digest = hex::encode(record_key);
        eprintln!(
            "raven: indexed session store: skipping unreadable session {}: {error_text}",
            &digest[..digest.len().min(16)],
        );
    }
}

fn decode_endpoint_outbound_row(
    raw: EndpointOutboxDbRow,
) -> Result<EndpointOutbound, IndexedSessionStoreError> {
    let (session, object, kind, message, recipient, index, state, immutable) = raw;
    if !(0..=u32::MAX as i64).contains(&index)
        || !(0..=u8::MAX as i64).contains(&kind)
        || !(0..=u8::MAX as i64).contains(&state)
        || immutable.len() < crate::envelope::PREFIX_LEN
        || immutable.len() > MAX_PENDING_OUTBOUND_BYTES
    {
        return Err(IndexedSessionStoreError::CorruptEndpointState);
    }
    let result = EndpointOutbound {
        kind: EndpointOutboundKind::from_u8(kind as u8)?,
        session_id: exact_array(&session)?,
        object_digest: exact_array(&object)?,
        message_id: exact_array(&message)?,
        recipient_device: exact_array(&recipient)?,
        ratchet_index: index as u32,
        state: EndpointOutboxState::from_u8(state as u8)?,
        immutable_envelope_bytes: immutable,
    };
    let envelope = Envelope::unpack(&result.immutable_envelope_bytes)
        .ok_or(IndexedSessionStoreError::CorruptEndpointState)?;
    if envelope.message_id != result.message_id
        || parse_indexed_message_header(&envelope.message_ciphertext)
            .map_err(|_| IndexedSessionStoreError::CorruptEndpointState)?
            != result.ratchet_index
        || authenticated_object_digest(&envelope) != result.object_digest
        || envelope.env_type != result.kind as u8
    {
        return Err(IndexedSessionStoreError::CorruptEndpointState);
    }
    Ok(result)
}

fn endpoint_outbound_by_object(
    conn: &Connection,
    layout: &Layout,
    session_id: &[u8; 32],
    object_digest: &[u8; 32],
) -> Result<Option<EndpointOutbound>, IndexedSessionStoreError> {
    endpoints::outbox_by_object(conn, layout, session_id, object_digest)?
        .map(|row| decode_endpoint_outbound_row(row.db_row()))
        .transpose()
}

/// The columns of the outbox row of `(session_id, object_digest)` its
/// binding checks compare.
fn endpoint_outbox_details(
    conn: &Connection,
    layout: &Layout,
    session_id: &[u8; 32],
    object_digest: &[u8; 32],
) -> Result<EndpointOutboxDetailsDbRow, IndexedSessionStoreError> {
    endpoints::outbox_by_object(conn, layout, session_id, object_digest)?
        .map(|row| row.details())
        .ok_or(IndexedSessionStoreError::Sqlite(
            rusqlite::Error::QueryReturnedNoRows,
        ))
}

fn outbound_by_ack_intent(
    conn: &Connection,
    layout: &Layout,
    session_id: &[u8; 32],
    intent_object_digest: &[u8; 32],
) -> Result<Option<EndpointOutbound>, IndexedSessionStoreError> {
    let raw = endpoints::outbox_rows(
        conn,
        layout,
        &format!(
            "SELECT {} FROM endpoint_outbox WHERE session_id = ?1 AND kh_source_ack_intent = ?2",
            endpoints::outbox_columns(layout, "")
        ),
        params![
            session_id.as_slice(),
            layout.ep_digest(intent_object_digest)
        ],
    )?
    .into_iter()
    .next();
    let value = raw
        .map(|row| decode_endpoint_outbound_row(row.db_row()))
        .transpose()?;
    if value
        .as_ref()
        .is_some_and(|row| row.kind != EndpointOutboundKind::Ack)
    {
        return Err(IndexedSessionStoreError::CorruptEndpointState);
    }
    Ok(value)
}

fn committed_ack_intent(
    conn: &Connection,
    layout: &Layout,
    session_id: &[u8; 32],
    object_digest: &[u8; 32],
) -> Result<EndpointAckIntent, IndexedSessionStoreError> {
    let raw = endpoints::ack_intent_by_object(conn, layout, session_id, object_digest)?;
    let Some(endpoints::AckIntentRow {
        message_id: message,
        remote_device: remote,
        status,
        state,
        immutable_ack_bytes: immutable,
        ..
    }) = raw
    else {
        return Err(IndexedSessionStoreError::NotFound);
    };
    if !matches!(status, 1 | 2) || !(0..=u8::MAX as i64).contains(&state) {
        return Err(IndexedSessionStoreError::CorruptEndpointState);
    }
    Ok(EndpointAckIntent {
        session_id: *session_id,
        object_digest: *object_digest,
        message_id: exact_array(&message)?,
        remote_device: exact_array(&remote)?,
        status: status as u8,
        state: EndpointAckIntentState::from_u8(state as u8)?,
        immutable_ack_bytes: immutable,
    })
}

fn insert_pending_outbound(
    tx: &Transaction<'_>,
    layout: &Layout,
    state: &ProtectedSessionState,
    pending: &PendingOutbound,
) -> Result<(), IndexedSessionStoreError> {
    let binding = &state.binding;
    validate_pending_outbound_shape(pending)?;
    if pending.session_id != binding.session_id
        || pending.recipient_device != *remote_device_for_binding(binding)
        || pending.public_generation > i64::MAX as u64
    {
        return Err(IndexedSessionStoreError::OutboundBindingMismatch);
    }
    let envelope = Envelope::unpack(&pending.immutable_envelope_bytes)
        .ok_or(IndexedSessionStoreError::InvalidEndpointEnvelope)?;
    let direction = binding.local_role.outbound_direction();
    let expected_route = derive_route_tag(
        &state.ratchets.root,
        envelope.created_at,
        pending.ratchet_index,
        envelope.env_type,
        direction,
    )
    .map_err(|_| IndexedSessionStoreError::OutboundBindingMismatch)?;
    if !envelope.verify(local_device_for_binding(binding))
        || !stored_outbound_hint_ok(
            envelope.dest_device_hint,
            remote_device_for_binding(binding),
        )
        || !route_tag_eq(&envelope.routing_tag, &expected_route)
        || before_session_start(envelope.created_at, binding.created_at_ms)
        || envelope.expires_at > binding.expires_at_ms
    {
        return Err(IndexedSessionStoreError::OutboundBindingMismatch);
    }
    let metadata_generation: i64 = tx.query_row(
        "SELECT generation FROM indexed_session_heads WHERE session_id = ?1",
        params![pending.session_id.as_slice()],
        |row| row.get(0),
    )?;
    if metadata_generation < 0 || metadata_generation as u64 != pending.public_generation {
        return Err(IndexedSessionStoreError::CorruptEndpointState);
    }

    let existing =
        endpoint_outbound_by_object(tx, layout, &pending.session_id, &pending.object_digest)?;
    if existing.is_none() {
        ensure_fresh_outbound_coordinates(
            tx,
            layout,
            &pending.session_id,
            &pending.message_id,
            &pending.seal_nonce,
            &pending.anti_replay_nonce,
            pending.ack_nonce.as_ref(),
        )?;
        endpoints::insert_outbox(tx, layout, pending)?;
    }
    let existing =
        endpoint_outbound_by_object(tx, layout, &pending.session_id, &pending.object_digest)?
            .ok_or(IndexedSessionStoreError::CorruptEndpointState)?;
    let details = endpoint_outbox_details(tx, layout, &pending.session_id, &pending.object_digest)?;
    if existing.kind != pending.kind
        || existing.message_id != pending.message_id
        || existing.recipient_device != pending.recipient_device
        || existing.ratchet_index != pending.ratchet_index
        || existing.immutable_envelope_bytes != pending.immutable_envelope_bytes
        || details.0.as_deref() != pending.source_ack_intent.as_ref().map(|v| v.as_slice())
        || details.1.as_deref() != pending.ack_nonce.as_ref().map(|v| v.as_slice())
        || details.2.as_slice() != pending.seal_nonce
        || details.3.as_slice() != pending.anti_replay_nonce
        || details.4 != pending.public_generation as i64
    {
        return Err(IndexedSessionStoreError::OutboundBindingMismatch);
    }

    match pending.kind {
        EndpointOutboundKind::Message => {
            endpoints::insert_outstanding(
                tx,
                layout,
                &pending.session_id,
                &pending.message_id,
                &pending.recipient_device,
            )?;
            if self_delivery_state_in_connection(
                tx,
                layout,
                &pending.session_id,
                &pending.message_id,
                &pending.recipient_device,
            )? != Some(EndpointDeliveryState::Sent)
            {
                return Err(IndexedSessionStoreError::OutboundBindingMismatch);
            }
            // A parked copy of the same message is sealed now (Phase 5,
            // P5.4): unparked with this row, also when it is replayed.
            parked::unpark(tx, layout, &pending.recipient_device, &pending.message_id)?;
        }
        EndpointOutboundKind::Ack => {
            let source = pending
                .source_ack_intent
                .as_ref()
                .ok_or(IndexedSessionStoreError::OutboundBindingMismatch)?;
            let intent = committed_ack_intent(tx, layout, &pending.session_id, source)?;
            let receipt = endpoint_receipt_by_object(tx, layout, &pending.session_id, source)?
                .ok_or(IndexedSessionStoreError::CorruptEndpointState)?;
            if intent.state != EndpointAckIntentState::Pending
                || intent.remote_device != pending.recipient_device
                || receipt.0 != intent.message_id
                || receipt.1 != intent.remote_device
                || intent
                    .immutable_ack_bytes
                    .as_deref()
                    .is_some_and(|bytes| bytes != pending.immutable_envelope_bytes.as_slice())
            {
                return Err(IndexedSessionStoreError::OutboundBindingMismatch);
            }
            let changed = endpoints::set_ack_bytes(
                tx,
                layout,
                &pending.session_id,
                source,
                &pending.immutable_envelope_bytes,
                true,
            )?;
            if changed != 1 {
                return Err(IndexedSessionStoreError::OutboundBindingMismatch);
            }
        }
    }
    Ok(())
}

fn validate_committed_outbound(
    conn: &Connection,
    layout: &Layout,
    state: &ProtectedSessionState,
    row: &EndpointOutbound,
) -> Result<(), IndexedSessionStoreError> {
    if row.session_id != state.binding.session_id
        || row.recipient_device != *remote_device_for_binding(&state.binding)
    {
        return Err(IndexedSessionStoreError::OutboundBindingMismatch);
    }
    let envelope = Envelope::unpack(&row.immutable_envelope_bytes)
        .ok_or(IndexedSessionStoreError::InvalidEndpointEnvelope)?;
    let direction = state.binding.local_role.outbound_direction();
    let expected_route = derive_route_tag(
        &state.ratchets.root,
        envelope.created_at,
        row.ratchet_index,
        envelope.env_type,
        direction,
    )
    .map_err(|_| IndexedSessionStoreError::OutboundBindingMismatch)?;
    let ratchet_next = match row.kind {
        EndpointOutboundKind::Message => state.ratchets.message_send.next_index,
        EndpointOutboundKind::Ack => state.ratchets.ack_send.next_index,
    };
    if envelope.flags != OUTBOUND_FLAGS
        || envelope.message_id != row.message_id
        || !route_tag_eq(&envelope.routing_tag, &expected_route)
        || !stored_outbound_hint_ok(
            envelope.dest_device_hint,
            remote_device_for_binding(&state.binding),
        )
        || before_session_start(envelope.created_at, state.binding.created_at_ms)
        || envelope.expires_at > state.binding.expires_at_ms
        || !endpoint_time_window_valid(
            envelope.created_at,
            envelope.expires_at,
            envelope.created_at,
        )
        || envelope.hop_limit != OUTBOUND_HOP_LIMIT
        || envelope.replication_budget != OUTBOUND_REPLICATION_BUDGET
        || envelope.anti_replay_nonce == [0; 12]
        || !envelope.ratchet_header_ciphertext.is_empty()
        || !envelope.verify(local_device_for_binding(&state.binding))
        || authenticated_object_digest(&envelope) != row.object_digest
        || parse_indexed_message_header(&envelope.message_ciphertext)
            .map_err(|_| IndexedSessionStoreError::OutboundBindingMismatch)?
            != row.ratchet_index
        || ratchet_next <= row.ratchet_index as u64
        || (row.kind == EndpointOutboundKind::Ack
            && envelope.message_ciphertext.len()
                != crate::atsam_indexed_session::ACK_SEALED_WIRE_LEN)
    {
        return Err(IndexedSessionStoreError::OutboundBindingMismatch);
    }

    let details = endpoint_outbox_details(conn, layout, &row.session_id, &row.object_digest)?;
    if details.2.as_slice()
        != &envelope.message_ciphertext[crate::atsam_indexed_session::INDEXED_SEALED_HEADER_LEN - 12
            ..crate::atsam_indexed_session::INDEXED_SEALED_HEADER_LEN]
        || details.3.as_slice() != envelope.anti_replay_nonce
        || details.4 < 0
        || details.4 as u64 > state.generation
    {
        return Err(IndexedSessionStoreError::CorruptEndpointState);
    }
    match row.kind {
        EndpointOutboundKind::Message => {
            if details.0.is_some()
                || details.1.is_some()
                || self_delivery_state_in_connection(
                    conn,
                    layout,
                    &row.session_id,
                    &row.message_id,
                    &row.recipient_device,
                )?
                .is_none()
            {
                return Err(IndexedSessionStoreError::OutboundBindingMismatch);
            }
        }
        EndpointOutboundKind::Ack => {
            let source: [u8; 32] = exact_array(
                details
                    .0
                    .as_deref()
                    .ok_or(IndexedSessionStoreError::OutboundBindingMismatch)?,
            )?;
            let ack_nonce: [u8; 12] = exact_array(
                details
                    .1
                    .as_deref()
                    .ok_or(IndexedSessionStoreError::OutboundBindingMismatch)?,
            )?;
            if ack_nonce == [0; 12] {
                return Err(IndexedSessionStoreError::OutboundBindingMismatch);
            }
            let intent = committed_ack_intent(conn, layout, &row.session_id, &source)?;
            let receipt = endpoint_receipt_by_object(conn, layout, &row.session_id, &source)?
                .ok_or(IndexedSessionStoreError::CorruptEndpointState)?;
            let expected_state = match row.state {
                EndpointOutboxState::Prepared => EndpointAckIntentState::Pending,
                EndpointOutboxState::Queued => EndpointAckIntentState::Queued,
            };
            if intent.remote_device != row.recipient_device
                || receipt.0 != intent.message_id
                || receipt.1 != intent.remote_device
                || intent.state != expected_state
                || intent.immutable_ack_bytes.as_deref()
                    != Some(row.immutable_envelope_bytes.as_slice())
            {
                return Err(IndexedSessionStoreError::OutboundBindingMismatch);
            }
        }
    }
    Ok(())
}

fn self_delivery_state_in_connection(
    conn: &Connection,
    layout: &Layout,
    session_id: &[u8; 32],
    message_id: &[u8; 16],
    recipient_device: &[u8; 32],
) -> Result<Option<EndpointDeliveryState>, IndexedSessionStoreError> {
    let raw: Option<i64> = conn
        .query_row(
            &layout.ep("SELECT delivery_state FROM endpoint_outstanding_messages
                 WHERE session_id = ?1 AND kh_message_id = ?2 AND kh_recipient_device = ?3"),
            params![
                session_id.as_slice(),
                layout.ep_mid(message_id),
                layout.ep_device(recipient_device)
            ],
            |row| row.get(0),
        )
        .optional()?;
    raw.map(|value| {
        u8::try_from(value)
            .map_err(|_| IndexedSessionStoreError::CorruptEndpointState)
            .and_then(EndpointDeliveryState::from_u8)
    })
    .transpose()
}

fn endpoint_receipt_by_object(
    conn: &Connection,
    layout: &Layout,
    session_id: &[u8; 32],
    object_digest: &[u8; 32],
) -> Result<Option<EndpointReceiptIdentity>, IndexedSessionStoreError> {
    let raw = endpoints::receipt_by_object(conn, layout, session_id, object_digest)?;
    let Some((message_id, sender_device, generation)) = raw else {
        return Ok(None);
    };
    if generation < 0 {
        return Err(IndexedSessionStoreError::CorruptEndpointState);
    }
    Ok(Some((
        exact_array(&message_id)?,
        exact_array(&sender_device)?,
        generation as u64,
    )))
}

fn endpoint_ack_receipt(
    tx: &Transaction<'_>,
    layout: &Layout,
    session_id: &[u8; 32],
    object_digest: &[u8; 32],
) -> Result<Option<AckReceiptIdentity>, IndexedSessionStoreError> {
    endpoints::ack_receipt_by_object(tx, layout, session_id, object_digest)
}

fn ack_nonce_object(
    tx: &Transaction<'_>,
    layout: &Layout,
    session_id: &[u8; 32],
    remote_device: &[u8; 32],
    ack_nonce: &[u8; 12],
) -> Result<Option<[u8; 32]>, IndexedSessionStoreError> {
    endpoints::ack_receipt_object(
        tx,
        layout,
        session_id,
        remote_device,
        "kh_ack_nonce",
        layout.ep_nonce(ack_nonce),
    )
}

fn ack_outer_message_object(
    tx: &Transaction<'_>,
    layout: &Layout,
    session_id: &[u8; 32],
    remote_device: &[u8; 32],
    outer_message_id: &[u8; 16],
) -> Result<Option<[u8; 32]>, IndexedSessionStoreError> {
    endpoints::ack_receipt_object(
        tx,
        layout,
        session_id,
        remote_device,
        "kh_outer_message_id",
        layout.ep_mid(outer_message_id),
    )
}

fn insert_pending_ack_acceptance(
    tx: &Transaction<'_>,
    layout: &Layout,
    binding: &IndexedSessionBinding,
    pending: &PendingAckAcceptance,
) -> Result<(), IndexedSessionStoreError> {
    if pending.session_id != binding.session_id
        || pending.remote_device != *remote_device_for_binding(binding)
        || !matches!(pending.status, 1 | 2)
        || pending.created_at_ms > i64::MAX as u64
        || pending.public_generation > i64::MAX as u64
    {
        return Err(IndexedSessionStoreError::CorruptProtectedState);
    }
    let metadata_generation: i64 = tx.query_row(
        "SELECT generation FROM indexed_session_heads WHERE session_id = ?1",
        params![pending.session_id.as_slice()],
        |row| row.get(0),
    )?;
    if metadata_generation < 0 || metadata_generation as u64 != pending.public_generation {
        return Err(IndexedSessionStoreError::CorruptEndpointState);
    }
    let existing_state = self_delivery_state_in_connection(
        tx,
        layout,
        &pending.session_id,
        &pending.acked_message_id,
        &pending.remote_device,
    )?
    .ok_or(IndexedSessionStoreError::AckOutstandingMismatch)?;
    let target = EndpointDeliveryState::from_u8(pending.status)?;
    let final_state = std::cmp::max(existing_state, target);
    if let Some(existing_object) = ack_nonce_object(
        tx,
        layout,
        &pending.session_id,
        &pending.remote_device,
        &pending.ack_nonce,
    )? {
        if existing_object != pending.object_digest {
            return Err(IndexedSessionStoreError::AckNonceConflict);
        }
    }
    if let Some(existing_object) = ack_outer_message_object(
        tx,
        layout,
        &pending.session_id,
        &pending.remote_device,
        &pending.outer_message_id,
    )? {
        if existing_object != pending.object_digest {
            return Err(IndexedSessionStoreError::LogicalMessageConflict);
        }
    }
    if endpoint_ack_receipt(tx, layout, &pending.session_id, &pending.object_digest)?.is_none() {
        endpoints::insert_ack_receipt(tx, layout, pending)?;
    }
    let identity = endpoint_ack_receipt(tx, layout, &pending.session_id, &pending.object_digest)?
        .ok_or(IndexedSessionStoreError::CorruptEndpointState)?;
    if identity.outer_message_id != pending.outer_message_id
        || identity.remote_device != pending.remote_device
        || identity.acked_message_id != pending.acked_message_id
    {
        return Err(IndexedSessionStoreError::CorruptEndpointState);
    }
    let changed = tx.execute(
        &layout.ep(
            "UPDATE endpoint_outstanding_messages SET delivery_state = ?1
             WHERE session_id = ?2 AND kh_message_id = ?3 AND kh_recipient_device = ?4
               AND delivery_state <= ?1",
        ),
        params![
            final_state as u8,
            pending.session_id.as_slice(),
            layout.ep_mid(&pending.acked_message_id),
            layout.ep_device(&pending.remote_device)
        ],
    )?;
    if changed != 1 {
        return Err(IndexedSessionStoreError::AckOutstandingMismatch);
    }
    Ok(())
}

fn endpoint_logical_object(
    tx: &Transaction<'_>,
    layout: &Layout,
    session_id: &[u8; 32],
    sender_device: &[u8; 32],
    message_id: &[u8; 16],
) -> Result<Option<[u8; 32]>, IndexedSessionStoreError> {
    endpoints::logical_object(tx, layout, session_id, sender_device, message_id)
}

fn ensure_exact_committed_object(
    tx: &Transaction<'_>,
    layout: &Layout,
    session_id: &[u8; 32],
    object_digest: &[u8; 32],
    message_id: &[u8; 16],
    sender_device: &[u8; 32],
) -> Result<(), IndexedSessionStoreError> {
    let Some((existing_message, existing_sender, _)) =
        endpoint_receipt_by_object(tx, layout, session_id, object_digest)?
    else {
        return Err(IndexedSessionStoreError::CorruptEndpointState);
    };
    if existing_message != *message_id || existing_sender != *sender_device {
        return Err(IndexedSessionStoreError::CorruptEndpointState);
    }
    let logical = endpoint_logical_object(tx, layout, session_id, sender_device, message_id)?
        .ok_or(IndexedSessionStoreError::CorruptEndpointState)?;
    if logical != *object_digest {
        return Err(IndexedSessionStoreError::LogicalMessageConflict);
    }
    Ok(())
}

fn insert_pending_acceptance(
    tx: &Transaction<'_>,
    layout: &Layout,
    binding: &IndexedSessionBinding,
    pending: &PendingAcceptance,
) -> Result<(), IndexedSessionStoreError> {
    if pending.session_id != binding.session_id
        || pending.sender_device != *remote_device_for_binding(binding)
        || !matches!(pending.ack_status, 1 | 2)
        || pending.sealed_local_inbox_row.len() < 1 + 12 + 16
        || pending.sealed_local_inbox_row.len() > MAX_SEALED_LOCAL_ROW_BYTES
        || pending.created_at_ms
            > pending
                .received_at_ms
                .saturating_add(MAX_ENDPOINT_FUTURE_SKEW_MS)
        || pending.created_at_ms > i64::MAX as u64
        || pending.received_at_ms > i64::MAX as u64
        || pending.public_generation > i64::MAX as u64
    {
        return Err(IndexedSessionStoreError::CorruptProtectedState);
    }
    let metadata_generation: i64 = tx.query_row(
        "SELECT generation FROM indexed_session_heads WHERE session_id = ?1",
        params![pending.session_id.as_slice()],
        |row| row.get(0),
    )?;
    if metadata_generation < 0 || metadata_generation as u64 != pending.public_generation {
        return Err(IndexedSessionStoreError::CorruptEndpointState);
    }
    if let Some(existing) = endpoint_logical_object(
        tx,
        layout,
        &pending.session_id,
        &pending.sender_device,
        &pending.message_id,
    )? {
        if existing != pending.object_digest {
            return Err(IndexedSessionStoreError::LogicalMessageConflict);
        }
    }

    if endpoint_receipt_by_object(tx, layout, &pending.session_id, &pending.object_digest)?
        .is_none()
    {
        endpoints::insert_acceptance(tx, layout, pending)?;
    }
    ensure_exact_committed_object(
        tx,
        layout,
        &pending.session_id,
        &pending.object_digest,
        &pending.message_id,
        &pending.sender_device,
    )?;
    // The values the sealed local row's AAD binds (from `meta` in schema 3),
    // and its exact bytes.
    let inbox =
        endpoints::inbox_by_object(tx, layout, &pending.session_id, &pending.object_digest)?;
    match inbox {
        Some(row) => {
            if row.object_digest != pending.object_digest
                || exact_array::<16>(&row.message_id)? != pending.message_id
                || exact_array::<32>(&row.sender_device)? != pending.sender_device
                || row.created_at_ms != pending.created_at_ms as i64
                || row.received_at_ms != pending.received_at_ms as i64
                || row.sealed_local_row != pending.sealed_local_inbox_row
            {
                return Err(IndexedSessionStoreError::CorruptEndpointState);
            }
        }
        // The user deleted the row after it was committed (PP.8): the
        // object stays accepted, its receipt and ACK intent are checked below.
        None if deleted::is_deleted(tx, layout, &pending.session_id, &pending.object_digest)? => {}
        None => return Err(IndexedSessionStoreError::CorruptEndpointState),
    }
    let ack =
        endpoints::ack_intent_by_object(tx, layout, &pending.session_id, &pending.object_digest)?;
    let Some(endpoints::AckIntentRow {
        message_id: message,
        remote_device: remote,
        status,
        state,
        ..
    }) = ack
    else {
        return Err(IndexedSessionStoreError::CorruptEndpointState);
    };
    if exact_array::<16>(&message)? != pending.message_id
        || exact_array::<32>(&remote)? != pending.sender_device
        || status != pending.ack_status as i64
        || !matches!(state, 0 | 1)
    {
        return Err(IndexedSessionStoreError::CorruptEndpointState);
    }
    // The message id is seen from its receive time until the sender's
    // horizon has surely passed, whatever the gates (ATSAM_ENDPOINT_TRANSACTION_V1
    // §3): another object under that id from this device under a later
    // session is a conflict while nothing re-seals, and a copy re-sealed
    // under a new session is known as one (receiver dedup, P5.5) after the
    // first copy's inbox row and history entry are gone. Also when the
    // journal is replayed (idempotent).
    parked::note_seen(
        tx,
        layout,
        &pending.sender_device,
        &pending.message_id,
        pending.received_at_ms,
        inbound_seen_keep_until(pending.received_at_ms),
    )?;
    Ok(())
}

/// A session's endpoint rows (outbox, ACK receipts and intents, outstanding
/// messages, inbox, its tombstones, receipts), in the caller's transaction,
/// before its head goes (the prune, a removed contact).
fn delete_session_endpoint_rows(
    tx: &Transaction<'_>,
    session_id: &[u8],
) -> Result<(), IndexedSessionStoreError> {
    for table in [
        "endpoint_outbox",
        "endpoint_ack_receipts",
        "endpoint_outstanding_messages",
        "endpoint_ack_intents",
        "endpoint_inbox",
    ] {
        tx.execute(
            &format!("DELETE FROM {table} WHERE session_id = ?1"),
            params![session_id],
        )?;
    }
    // No foreign key: the user's inbox tombstones go before the receipts
    // they stand for (PP.8).
    deleted::delete_session_tombstones(tx, session_id)?;
    tx.execute(
        "DELETE FROM endpoint_receipts WHERE session_id = ?1",
        params![session_id],
    )?;
    Ok(())
}

/// How long the accept path keeps a message id it saw at `received_at_ms`:
/// the horizon ([`crate::horizon::MESSAGE_HORIZON_MS`]) plus a day, so a
/// copy the sender re-seals up to its deadline is still caught.
fn inbound_seen_keep_until(received_at_ms: u64) -> u64 {
    received_at_ms
        .saturating_add(crate::horizon::MESSAGE_HORIZON_MS)
        .saturating_add(crate::horizon::DAY_MS)
        .min(i64::MAX as u64)
}

/// `received_at_ms` is the paging cursor of
/// `list_endpoint_inbox_for_sender_after` in a clear store. `now_ms` is
/// captured by each handler before it queues for the write lock (and wall
/// clocks can step back), so commit order does not follow it: a row
/// committed after a poll advanced the cursor could carry a smaller value
/// and never be returned. Stamping inside the IMMEDIATE transaction,
/// strictly after the sender's latest row, makes the cursor monotonic per
/// sender. Every validity check still uses the caller's `now_ms`; only the
/// stored stamp is raised. Rows the user deleted keep their floor in their
/// tombstones (PP.8): a cursor saved over them stays behind every later
/// row. A schema-3 store pages by `seq` (PP.14) and stamps the same way, so
/// its insertion order and its stamps agree per sender (the way back to a
/// clear store, and a cursor saved before the move, rely on it); the times
/// come from `meta`, the newest row by `seq` holding the newest stamp.
fn monotonic_received_at_ms(
    conn: &Connection,
    layout: &Layout,
    sender_device: &[u8; 32],
    now_ms: u64,
) -> Result<u64, IndexedSessionStoreError> {
    let (live, newest_seq) = endpoints::newest_received(conn, layout, sender_device)?;
    let deleted = deleted::deleted_received_floor(conn, layout, sender_device, newest_seq)?;
    let Some(latest) = live.max(deleted) else {
        return Ok(now_ms);
    };
    let floor = u64::try_from(latest)
        .map_err(|_| IndexedSessionStoreError::CorruptEndpointState)?
        .saturating_add(1);
    Ok(now_ms.max(floor).min(i64::MAX as u64))
}

fn local_storage_key(root: &[u8; 32], session_id: &[u8; 32]) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(None, root);
    let mut info = Vec::with_capacity(LOCAL_STORAGE_LABEL.len() + 1 + session_id.len());
    info.extend_from_slice(LOCAL_STORAGE_LABEL);
    info.push(0);
    info.extend_from_slice(session_id);
    let mut output = [0u8; 32];
    hkdf.expand(&info, &mut output)
        .expect("fixed local storage key length");
    info.zeroize();
    output
}

fn local_storage_aad(
    session_id: &[u8; 32],
    object_digest: &[u8; 32],
    message_id: &[u8; 16],
    sender_device: &[u8; 32],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(LOCAL_STORAGE_AAD_LABEL.len() + 1 + 32 + 32 + 16 + 32);
    aad.extend_from_slice(LOCAL_STORAGE_AAD_LABEL);
    aad.push(0);
    aad.extend_from_slice(session_id);
    aad.extend_from_slice(object_digest);
    aad.extend_from_slice(message_id);
    aad.extend_from_slice(sender_device);
    aad
}

fn seal_local_inbox_row(
    root: &[u8; 32],
    session_id: &[u8; 32],
    object_digest: &[u8; 32],
    message_id: &[u8; 16],
    sender_device: &[u8; 32],
    plaintext: &[u8],
) -> Result<Vec<u8>, IndexedSessionStoreError> {
    let mut key = local_storage_key(root, session_id);
    let aad = local_storage_aad(session_id, object_digest, message_id, sender_device);
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let result = ChaCha20Poly1305::new((&key).into())
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| IndexedSessionStoreError::LocalInboxAuthenticationFailed);
    key.zeroize();
    let ciphertext = result?;
    let mut sealed = Vec::with_capacity(1 + nonce.len() + ciphertext.len());
    sealed.push(LOCAL_ROW_VERSION);
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&ciphertext);
    Ok(sealed)
}

fn open_local_inbox_row(
    root: &[u8; 32],
    session_id: &[u8; 32],
    object_digest: &[u8; 32],
    message_id: &[u8; 16],
    sender_device: &[u8; 32],
    sealed: &[u8],
) -> Result<Vec<u8>, IndexedSessionStoreError> {
    if sealed.len() < 1 + 12 + 16
        || sealed.len() > MAX_SEALED_LOCAL_ROW_BYTES
        || sealed[0] != LOCAL_ROW_VERSION
    {
        return Err(IndexedSessionStoreError::CorruptEndpointState);
    }
    let mut key = local_storage_key(root, session_id);
    let aad = local_storage_aad(session_id, object_digest, message_id, sender_device);
    let result = ChaCha20Poly1305::new((&key).into()).decrypt(
        Nonce::from_slice(&sealed[1..13]),
        Payload {
            msg: &sealed[13..],
            aad: &aad,
        },
    );
    key.zeroize();
    result.map_err(|_| IndexedSessionStoreError::LocalInboxAuthenticationFailed)
}

/// Reads and authenticates one committed inbox row of a session whose `root`
/// the caller already loaded. `Ok(None)` means no such row.
///
/// The values the sealed local row's AAD binds (the object digest, the
/// message id and the sender device) come from the row's `meta` in schema 3
/// (PP.14): a `meta` that names another object fails the check below, one
/// that names another message or sender fails the AAD.
fn read_endpoint_inbox_row(
    conn: &Connection,
    layout: &Layout,
    root: &[u8; 32],
    session_id: &[u8; 32],
    object_digest: &[u8; 32],
) -> Result<Option<EndpointInboxRow>, IndexedSessionStoreError> {
    let Some(record) = endpoints::inbox_by_object(conn, layout, session_id, object_digest)? else {
        return Ok(None);
    };
    let message_id = exact_array::<16>(&record.message_id)?;
    let sender_device = exact_array::<32>(&record.sender_device)?;
    let stored_digest = exact_array::<32>(&record.object_digest)?;
    if stored_digest != *object_digest || record.created_at_ms < 0 || record.received_at_ms < 0 {
        return Err(IndexedSessionStoreError::CorruptEndpointState);
    }
    let position = record.position()?;
    let plaintext = open_local_inbox_row(
        root,
        session_id,
        object_digest,
        &message_id,
        &sender_device,
        &record.sealed_local_row,
    )?;
    Ok(Some(EndpointInboxRow {
        session_id: *session_id,
        object_digest: *object_digest,
        message_id,
        sender_device,
        created_at_ms: record.created_at_ms as u64,
        received_at_ms: record.received_at_ms as u64,
        position,
        plaintext,
    }))
}

fn put_protected_state(
    backend: &dyn ProtectedSessionBackend,
    account: &str,
    state: &ProtectedSessionState,
) -> Result<(), IndexedSessionStoreError> {
    let mut encoded = encode_protected_state(state)?;
    let result = backend.put(account, &encoded);
    encoded.zeroize();
    result
}

fn endpoints_for_direction(binding: &IndexedSessionBinding, direction: Direction) -> (&str, &str) {
    match direction {
        Direction::InitiatorToResponder => (
            binding.key.initiator_address.as_str(),
            binding.key.responder_address.as_str(),
        ),
        Direction::ResponderToInitiator => (
            binding.key.responder_address.as_str(),
            binding.key.initiator_address.as_str(),
        ),
    }
}

/// Compares the immutable PairInit-derived binding. Confirmation lifecycle and
/// response hash are intentionally excluded so replaying the exact signed
/// PairInit remains idempotent after a session has been confirmed.
fn same_initial_binding(
    existing: &IndexedSessionBinding,
    candidate: &IndexedSessionBinding,
) -> bool {
    existing.key == candidate.key
        && existing.session_id == candidate.session_id
        && existing.init_hash == candidate.init_hash
        && existing.transcript_hash == candidate.transcript_hash
        && existing.initiator_cert_digest == candidate.initiator_cert_digest
        && existing.responder_cert_digest == candidate.responder_cert_digest
        && existing.responder_prekey_bundle_digest == candidate.responder_prekey_bundle_digest
        && existing.signed_prekey_id == candidate.signed_prekey_id
        && existing.one_time_prekey_id == candidate.one_time_prekey_id
        && existing.created_at_ms == candidate.created_at_ms
        && existing.expires_at_ms == candidate.expires_at_ms
        && existing.local_role == candidate.local_role
        && candidate.lifecycle == SessionLifecycle::Provisional
        && candidate.response_hash.is_none()
}

fn initial_ratchets(binding: &IndexedSessionBinding, root: &[u8; 32]) -> SecretRatchets {
    let outbound = binding.local_role.outbound_direction();
    let inbound = binding.local_role.inbound_direction();
    let (out_sender, out_recipient) = endpoints_for_direction(binding, outbound);
    let (in_sender, in_recipient) = endpoints_for_direction(binding, inbound);
    let mut ack_root = ack_base_key(root);
    let result = SecretRatchets {
        root: *root,
        message_send: SendRatchet {
            next_index: 0,
            chain_key: initial_chain_key(root, out_sender, out_recipient),
        },
        ack_send: SendRatchet {
            next_index: 0,
            chain_key: initial_chain_key(&ack_root, out_sender, out_recipient),
        },
        message_receive: ReceiveRatchet {
            next_index: 0,
            chain_key: initial_chain_key(root, in_sender, in_recipient),
            skipped_keys: BTreeMap::new(),
        },
        ack_receive: ReceiveRatchet {
            next_index: 0,
            chain_key: initial_chain_key(&ack_root, in_sender, in_recipient),
            skipped_keys: BTreeMap::new(),
        },
    };
    ack_root.zeroize();
    result
}

fn prepare_receive_key(
    ratchet: &mut ReceiveRatchet,
    index: u32,
    sender: &str,
    recipient: &str,
) -> Result<[u8; 32], IndexedSessionStoreError> {
    let index_u64 = index as u64;
    if index_u64 < ratchet.next_index {
        return ratchet
            .skipped_keys
            .remove(&index)
            .ok_or(IndexedSessionStoreError::Replay);
    }
    let gap = index_u64 - ratchet.next_index;
    if gap > MAX_FORWARD_JUMP {
        return Err(IndexedSessionStoreError::ForwardJumpTooLarge);
    }
    let mut cursor = ratchet.next_index;
    while cursor < index_u64 {
        let skipped = message_key(&ratchet.chain_key, sender, recipient);
        ratchet.skipped_keys.insert(cursor as u32, skipped);
        ratchet.chain_key = advance_chain_key(&ratchet.chain_key);
        cursor += 1;
    }
    while ratchet.skipped_keys.len() > MAX_SKIPPED_KEYS {
        let Some(oldest) = ratchet.skipped_keys.keys().next().copied() else {
            break;
        };
        if let Some(mut evicted) = ratchet.skipped_keys.remove(&oldest) {
            evicted.zeroize();
        }
    }
    let candidate = message_key(&ratchet.chain_key, sender, recipient);
    ratchet.chain_key = advance_chain_key(&ratchet.chain_key);
    ratchet.next_index = index_u64 + 1;
    Ok(candidate)
}

fn record_key_digest(key: &IndexedSessionRecordKey) -> Result<[u8; 32], IndexedSessionStoreError> {
    if key.profile_id.as_slice() != PROFILE_ID
        || key.profile_id.len() > MAX_PROFILE_BYTES
        || key.initiator_address.len() > MAX_ADDRESS_BYTES
        || key.responder_address.len() > MAX_ADDRESS_BYTES
        || key.init_id == [0; 16]
    {
        return Err(IndexedSessionStoreError::InvalidBinding);
    }
    session_context(&key.initiator_address, &key.responder_address)
        .map_err(|_| IndexedSessionStoreError::InvalidBinding)?;
    let mut hasher = Sha256::new();
    hasher.update(RECORD_KEY_DOMAIN);
    hash_len_prefixed(&mut hasher, &key.profile_id);
    hash_len_prefixed(&mut hasher, key.initiator_address.as_bytes());
    hash_len_prefixed(&mut hasher, key.responder_address.as_bytes());
    hasher.update(key.initiator_device_ed25519);
    hasher.update(key.responder_device_ed25519);
    hasher.update(key.init_id);
    Ok(hasher.finalize().into())
}

/// Review B-sealed-stores-1, for the harnesses (carrier_matrix C87): the
/// `init_id`s a copy of a data dir offers someone holding only its files,
/// for the record-key check ([`record_key_names_friend`]): every 16-byte
/// value of a clear column of its session store (raw, or as 32 hex digits)
/// and every 32-hex run of a file name below `copy`.
#[cfg(any(test, feature = "test-helpers"))]
pub fn init_id_candidates(copy: &Path) -> Vec<[u8; 16]> {
    use rusqlite::types::ValueRef;
    let mut out = std::collections::BTreeSet::new();
    // Read-write, never created: a copied WAL database opens without its
    // `-shm` (a copy, so nothing of the profile's changes).
    let path = copy.join(INDEXED_SESSION_METADATA_FILE);
    if let Ok(conn) =
        Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)
    {
        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
            .and_then(|mut statement| {
                statement
                    .query_map([], |row| row.get(0))?
                    .collect::<rusqlite::Result<_>>()
            })
            .unwrap_or_default();
        for table in tables {
            let Ok(mut statement) = conn.prepare(&format!("SELECT * FROM \"{table}\"")) else {
                continue;
            };
            let width = statement.column_count();
            let Ok(mut rows) = statement.query([]) else {
                continue;
            };
            while let Ok(Some(row)) = rows.next() {
                for at in 0..width {
                    let value = match row.get_ref(at) {
                        Ok(ValueRef::Blob(blob)) => blob.to_vec(),
                        Ok(ValueRef::Text(text)) => hex::decode(text).unwrap_or_default(),
                        _ => continue,
                    };
                    if let Ok(init_id) = <[u8; 16]>::try_from(value.as_slice()) {
                        out.insert(init_id);
                    }
                }
            }
        }
    }
    let mut stack = vec![copy.to_path_buf()];
    while let Some(folder) = stack.pop() {
        for entry in std::fs::read_dir(&folder).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let name = path
                .strip_prefix(copy)
                .unwrap_or(&path)
                .to_string_lossy()
                .into_owned();
            for start in 0..name.len().saturating_sub(31) {
                let run = name.get(start..start + 32).unwrap_or_default();
                if let Ok(Ok(init_id)) = hex::decode(run).map(<[u8; 16]>::try_from) {
                    out.insert(init_id);
                }
            }
        }
    }
    out.into_iter().collect()
}

/// Review B-sealed-stores-1, for the harnesses: whether `init_id`, with
/// `own` and `friend` as a session's two sides in either role (primary
/// devices: each side's address and device key come from its key), gives a
/// record key `copy`'s session store holds. The record key is an unkeyed
/// digest of public values and the `init_id`: a match tells which friend
/// that session is with.
#[cfg(any(test, feature = "test-helpers"))]
pub fn record_key_names_friend(
    copy: &Path,
    own: &[u8; 32],
    friend: &[u8; 32],
    init_id: &[u8; 16],
) -> bool {
    let Ok(conn) = Connection::open_with_flags(
        copy.join(INDEXED_SESSION_METADATA_FILE),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
    ) else {
        return false;
    };
    [(own, friend), (friend, own)]
        .iter()
        .any(|(initiator, responder)| {
            let key = IndexedSessionRecordKey {
                profile_id: PROFILE_ID.to_vec(),
                initiator_address: crate::encode_address(initiator),
                responder_address: crate::encode_address(responder),
                initiator_device_ed25519: **initiator,
                responder_device_ed25519: **responder,
                init_id: *init_id,
            };
            record_key_digest(&key).is_ok_and(|record_key| {
                conn.query_row(
                    "SELECT 1 FROM indexed_session_heads WHERE record_key = ?1",
                    params![record_key.as_slice()],
                    |row| row.get::<_, i64>(0),
                )
                .is_ok()
            })
        })
}

fn binding_digest(binding: &IndexedSessionBinding) -> Result<[u8; 32], IndexedSessionStoreError> {
    binding.validate()?;
    let mut hasher = Sha256::new();
    hasher.update(BINDING_DIGEST_DOMAIN);
    hasher.update(record_key_digest(&binding.key)?);
    hasher.update(binding.session_id);
    hasher.update(binding.init_hash);
    hasher.update(binding.transcript_hash);
    hasher.update(binding.initiator_cert_digest);
    hasher.update(binding.responder_cert_digest);
    hasher.update(binding.responder_prekey_bundle_digest);
    hasher.update(binding.signed_prekey_id.to_be_bytes());
    hasher.update(binding.one_time_prekey_id.to_be_bytes());
    hasher.update(binding.created_at_ms.to_be_bytes());
    hasher.update(binding.expires_at_ms.to_be_bytes());
    hasher.update([binding.local_role as u8, binding.lifecycle as u8]);
    match binding.response_hash {
        Some(hash) => {
            hasher.update([1]);
            hasher.update(hash);
        }
        None => {
            hasher.update([0]);
        }
    }
    Ok(hasher.finalize().into())
}

fn hash_len_prefixed(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u32).to_be_bytes());
    hasher.update(value);
}

#[derive(Debug, Clone, Copy)]
struct MetadataHead {
    binding_digest: [u8; 32],
    generation: u64,
}

struct MetadataInitOwner {
    record_key: [u8; 32],
    init_hash: [u8; 32],
}

fn metadata_head(
    tx: &Transaction<'_>,
    record_key: &[u8; 32],
) -> Result<Option<MetadataHead>, IndexedSessionStoreError> {
    let raw: Option<(Vec<u8>, i64)> = tx
        .query_row(
            "SELECT binding_digest, generation FROM indexed_session_heads
             WHERE record_key = ?1",
            params![record_key.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((digest, generation)) = raw else {
        return Ok(None);
    };
    if digest.len() != 32 || generation < 0 {
        return Err(IndexedSessionStoreError::CorruptProtectedState);
    }
    let mut binding_digest = [0u8; 32];
    binding_digest.copy_from_slice(&digest);
    Ok(Some(MetadataHead {
        binding_digest,
        generation: generation as u64,
    }))
}

fn metadata_session_owner(
    tx: &Transaction<'_>,
    session_id: &[u8; 32],
) -> Result<Option<[u8; 32]>, IndexedSessionStoreError> {
    let raw: Option<Vec<u8>> = tx
        .query_row(
            "SELECT record_key FROM indexed_session_heads WHERE session_id = ?1",
            params![session_id.as_slice()],
            |row| row.get(0),
        )
        .optional()?;
    let Some(raw) = raw else {
        return Ok(None);
    };
    if raw.len() != 32 {
        return Err(IndexedSessionStoreError::CorruptProtectedState);
    }
    let mut result = [0u8; 32];
    result.copy_from_slice(&raw);
    Ok(Some(result))
}

fn metadata_init_owner(
    tx: &Transaction<'_>,
    layout: &Layout,
    init_id: &[u8; 16],
) -> Result<Option<MetadataInitOwner>, IndexedSessionStoreError> {
    // Schema 4 binds the keyed `init_id` (review B-sealed-stores-1).
    let (column, value) = match layout.keyed() {
        Some(sealer) => (sealer.init_column(), sealer.init_value(init_id)),
        None => ("init_id", init_id.to_vec()),
    };
    let raw: Option<(Vec<u8>, Vec<u8>)> = tx
        .query_row(
            &format!("SELECT record_key, init_hash FROM indexed_session_heads WHERE {column} = ?1"),
            params![value],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((record_key, init_hash)) = raw else {
        return Ok(None);
    };
    if record_key.len() != 32 || init_hash.len() != 32 {
        return Err(IndexedSessionStoreError::CorruptProtectedState);
    }
    let mut owner = [0u8; 32];
    owner.copy_from_slice(&record_key);
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&init_hash);
    Ok(Some(MetadataInitOwner {
        record_key: owner,
        init_hash: digest,
    }))
}

fn insert_metadata(
    tx: &Transaction<'_>,
    layout: &Layout,
    record_key: &[u8; 32],
    state: &ProtectedSessionState,
) -> Result<(), IndexedSessionStoreError> {
    let binding = &state.binding;
    let digest = binding_digest(binding)?;
    if let Some(sealer) = layout.keyed() {
        // Schema 2 (PP.13): the addresses and devices keyed, their clear
        // values and the times in the sealed meta; schema 4 the `init_id`
        // too (review B-sealed-stores-1).
        let (created, expires) = (binding.created_at_ms as i64, binding.expires_at_ms as i64);
        let meta = sealer.seal(
            sealed::HEADS,
            record_key,
            &sealed::HeadMeta {
                initiator_address: binding.key.initiator_address.clone(),
                responder_address: binding.key.responder_address.clone(),
                initiator_device: hex::encode(binding.key.initiator_device_ed25519),
                responder_device: hex::encode(binding.key.responder_device_ed25519),
                created_at_ms: created,
                expires_at_ms: expires,
                init_id: if sealer.init_keyed() {
                    hex::encode(binding.key.init_id)
                } else {
                    String::new()
                },
            },
        );
        tx.execute(
            &format!(
                "INSERT INTO indexed_session_heads
                 (record_key, binding_digest, profile_id, kh_initiator_address,
                  kh_responder_address, kh_initiator_device, kh_responder_device, {},
                  init_hash, session_id, generation, created_hour, prune_after_hour, meta)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                sealer.init_column()
            ),
            params![
                record_key.as_slice(),
                digest.as_slice(),
                binding.key.profile_id.as_slice(),
                sealer.address(&binding.key.initiator_address).as_slice(),
                sealer.address(&binding.key.responder_address).as_slice(),
                sealer
                    .device(&binding.key.initiator_device_ed25519)
                    .as_slice(),
                sealer
                    .device(&binding.key.responder_device_ed25519)
                    .as_slice(),
                sealer.init_value(&binding.key.init_id),
                binding.init_hash.as_slice(),
                binding.session_id.as_slice(),
                state.generation as i64,
                sealed::hour_down(created),
                sealed::prune_hour(expires),
                meta,
            ],
        )?;
        return Ok(());
    }
    tx.execute(
        "INSERT INTO indexed_session_heads
         (record_key, binding_digest, profile_id, initiator_address,
          responder_address, initiator_device, responder_device, init_id,
          init_hash, session_id, generation, created_at_ms, expires_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![
            record_key.as_slice(),
            digest.as_slice(),
            binding.key.profile_id.as_slice(),
            binding.key.initiator_address,
            binding.key.responder_address,
            binding.key.initiator_device_ed25519.as_slice(),
            binding.key.responder_device_ed25519.as_slice(),
            binding.key.init_id.as_slice(),
            binding.init_hash.as_slice(),
            binding.session_id.as_slice(),
            state.generation as i64,
            binding.created_at_ms as i64,
            binding.expires_at_ms as i64,
        ],
    )?;
    Ok(())
}

fn update_metadata(
    tx: &Transaction<'_>,
    record_key: &[u8; 32],
    state: &ProtectedSessionState,
) -> Result<(), IndexedSessionStoreError> {
    if state.generation > i64::MAX as u64 {
        return Err(IndexedSessionStoreError::IndexExhausted);
    }
    let digest = binding_digest(&state.binding)?;
    let changed = tx.execute(
        "UPDATE indexed_session_heads
         SET binding_digest = ?1, generation = ?2
         WHERE record_key = ?3",
        params![
            digest.as_slice(),
            state.generation as i64,
            record_key.as_slice()
        ],
    )?;
    if changed != 1 {
        return Err(IndexedSessionStoreError::NotFound);
    }
    Ok(())
}

fn ensure_record_key(
    binding: &IndexedSessionBinding,
    expected: &[u8; 32],
) -> Result<(), IndexedSessionStoreError> {
    if record_key_digest(&binding.key)? != *expected {
        return Err(IndexedSessionStoreError::CorruptProtectedState);
    }
    Ok(())
}

fn reconcile_metadata(
    tx: &Transaction<'_>,
    layout: &Layout,
    metadata: Option<MetadataHead>,
    record_key: &[u8; 32],
    state: &ProtectedSessionState,
) -> Result<(), IndexedSessionStoreError> {
    let protected_digest = binding_digest(&state.binding)?;
    match metadata {
        None => insert_metadata(tx, layout, record_key, state),
        Some(head) if head.generation > state.generation => {
            Err(IndexedSessionStoreError::RollbackDetected)
        }
        Some(head) if head.generation == state.generation => {
            if head.binding_digest != protected_digest {
                return Err(IndexedSessionStoreError::CorruptProtectedState);
            }
            Ok(())
        }
        Some(_) => update_metadata(tx, record_key, state),
    }
}

fn load_and_reconcile(
    tx: &Transaction<'_>,
    layout: &Layout,
    backend: &dyn ProtectedSessionBackend,
    account: &str,
    record_key: &[u8; 32],
) -> Result<ProtectedSessionState, IndexedSessionStoreError> {
    let metadata = metadata_head(tx, record_key)?;
    let mut encoded = backend.get(account)?.ok_or_else(|| {
        if metadata.is_some() {
            IndexedSessionStoreError::ProtectedStateMissing
        } else {
            IndexedSessionStoreError::NotFound
        }
    })?;
    let result = decode_protected_state(&encoded);
    encoded.zeroize();
    let state = result?;
    ensure_record_key(&state.binding, record_key)?;
    reconcile_metadata(tx, layout, metadata, record_key, &state).inspect_err(|e| {
        // The protected head is older than the public generation: rolled
        // back outside Raven (Phase 6b S23). Refused exactly as before.
        if matches!(e, IndexedSessionStoreError::RollbackDetected) {
            crate::security_sense::local(crate::security_events::SecKind::LocalRollback);
        }
    })?;
    Ok(state)
}

#[allow(clippy::too_many_arguments)]
fn write_mutation(
    tx: &Transaction<'_>,
    backend: &dyn ProtectedSessionBackend,
    account: &str,
    record_key: &[u8; 32],
    state: &ProtectedSessionState,
    #[cfg(test)] crash_after_protected_write: bool,
) -> Result<(), IndexedSessionStoreError> {
    let mut encoded = encode_protected_state(state)?;
    let result = backend.put(account, &encoded);
    encoded.zeroize();
    result?;
    #[cfg(test)]
    if crash_after_protected_write {
        return Err(IndexedSessionStoreError::InjectedCrashAfterProtectedWrite);
    }
    update_metadata(tx, record_key, state)
}

/// Stages one journaled endpoint mutation in the still-open IMMEDIATE
/// transaction. The public metadata advance and every SQLite row the journal
/// describes are written first, so any deterministic UNIQUE/CHECK/binding
/// failure rejects the operation before anything durable changes; only then
/// is the protected head (carrying the journal) replaced. The caller's commit
/// stays the durability point after the protected replacement, so a crash in
/// between is recovered by replaying the journal.
fn stage_journaled_mutation(
    tx: &Transaction<'_>,
    layout: &Layout,
    backend: &dyn ProtectedSessionBackend,
    account: &str,
    record_key: &[u8; 32],
    state: &ProtectedSessionState,
    endpoint_fault: Option<EndpointFaultPoint>,
) -> Result<ProtectedJournal, IndexedSessionStoreError> {
    let journal =
        protected_journal(state)?.ok_or(IndexedSessionStoreError::CorruptProtectedState)?;
    update_metadata(tx, record_key, state)?;
    apply_protected_journal(tx, layout, state)?;
    maybe_injected_endpoint_fault(
        endpoint_fault,
        EndpointFaultPoint::BeforeProtectedReplacement,
    )?;
    put_protected_state(backend, account, state)?;
    maybe_injected_endpoint_fault(
        endpoint_fault,
        EndpointFaultPoint::AfterProtectedReplacement,
    )?;
    Ok(journal)
}

fn protected_journal(
    state: &ProtectedSessionState,
) -> Result<Option<ProtectedJournal>, IndexedSessionStoreError> {
    match (
        &state.pending_acceptance,
        &state.pending_ack_acceptance,
        &state.pending_outbound,
    ) {
        (None, None, None) => Ok(None),
        (Some(pending), None, None) => {
            Ok(Some(ProtectedJournal::Acceptance(pending.object_digest)))
        }
        (None, Some(pending), None) => {
            Ok(Some(ProtectedJournal::AckAcceptance(pending.object_digest)))
        }
        (None, None, Some(pending)) => Ok(Some(ProtectedJournal::Outbound(pending.object_digest))),
        _ => Err(IndexedSessionStoreError::CorruptProtectedState),
    }
}

/// Idempotently writes the SQLite rows described by the session's journal.
fn apply_protected_journal(
    tx: &Transaction<'_>,
    layout: &Layout,
    state: &ProtectedSessionState,
) -> Result<(), IndexedSessionStoreError> {
    match (
        &state.pending_acceptance,
        &state.pending_ack_acceptance,
        &state.pending_outbound,
    ) {
        (None, None, None) => Ok(()),
        (Some(pending), None, None) => {
            insert_pending_acceptance(tx, layout, &state.binding, pending)
        }
        (None, Some(pending), None) => {
            insert_pending_ack_acceptance(tx, layout, &state.binding, pending)
        }
        (None, None, Some(pending)) => insert_pending_outbound(tx, layout, state, pending),
        _ => Err(IndexedSessionStoreError::CorruptProtectedState),
    }
}

/// Replay failures that are a deterministic conflict with committed rows and
/// can never succeed on retry. Transient SQLite/backend failures and
/// corruption signals are deliberately excluded and keep failing closed.
fn journal_replay_is_unrecoverable(error: &IndexedSessionStoreError) -> bool {
    match error {
        IndexedSessionStoreError::Sqlite(error) => {
            error.sqlite_error_code() == Some(rusqlite::ErrorCode::ConstraintViolation)
        }
        IndexedSessionStoreError::LogicalMessageConflict
        | IndexedSessionStoreError::AckNonceConflict
        | IndexedSessionStoreError::AckOutstandingMismatch
        | IndexedSessionStoreError::OutboundCollision
        | IndexedSessionStoreError::OutboundBindingMismatch => true,
        _ => false,
    }
}

fn store_integrity_key(root: &[u8; 32], session_id: &[u8; 32]) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(None, root);
    let mut info = Vec::with_capacity(STORE_INTEGRITY_LABEL.len() + 1 + session_id.len());
    info.extend_from_slice(STORE_INTEGRITY_LABEL);
    info.push(0);
    info.extend_from_slice(session_id);
    let mut output = [0u8; 32];
    hkdf.expand(&info, &mut output)
        .expect("fixed 32-byte store integrity key");
    info.zeroize();
    output
}

fn encode_protected_state(
    state: &ProtectedSessionState,
) -> Result<Vec<u8>, IndexedSessionStoreError> {
    state.binding.validate()?;
    if state.ratchets.message_receive.skipped_keys.len() > MAX_SKIPPED_KEYS
        || state.ratchets.ack_receive.skipped_keys.len() > MAX_SKIPPED_KEYS
        || usize::from(state.pending_acceptance.is_some())
            + usize::from(state.pending_ack_acceptance.is_some())
            + usize::from(state.pending_outbound.is_some())
            > 1
    {
        return Err(IndexedSessionStoreError::CorruptProtectedState);
    }
    let mut writer = BinaryWriter::new();
    writer.bytes(STORE_MAGIC);
    writer.u8(STORE_VERSION);
    writer.u64(state.generation);
    encode_binding(&mut writer, &state.binding)?;
    writer.bytes(&state.ratchets.root);
    encode_send_ratchet(&mut writer, &state.ratchets.message_send);
    encode_send_ratchet(&mut writer, &state.ratchets.ack_send);
    encode_receive_ratchet(&mut writer, &state.ratchets.message_receive)?;
    encode_receive_ratchet(&mut writer, &state.ratchets.ack_receive)?;
    encode_pending_acceptance(&mut writer, state.pending_acceptance.as_ref())?;
    encode_pending_ack_acceptance(&mut writer, state.pending_ack_acceptance.as_ref())?;
    encode_pending_outbound(&mut writer, state.pending_outbound.as_ref())?;
    let mut integrity_key = store_integrity_key(&state.ratchets.root, &state.binding.session_id);
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&integrity_key)
        .map_err(|_| IndexedSessionStoreError::CorruptProtectedState)?;
    mac.update(&writer.value);
    writer.bytes(&mac.finalize().into_bytes());
    integrity_key.zeroize();
    Ok(writer.into_bytes())
}

fn decode_protected_state(
    encoded: &[u8],
) -> Result<ProtectedSessionState, IndexedSessionStoreError> {
    if encoded.len() < STORE_MAGIC.len() + 1 + 8 + 32 {
        return Err(IndexedSessionStoreError::CorruptProtectedState);
    }
    let content_len = encoded
        .len()
        .checked_sub(32)
        .ok_or(IndexedSessionStoreError::CorruptProtectedState)?;
    let (content, tag) = encoded.split_at(content_len);
    let mut reader = BinaryReader::new(content);
    if reader.take(STORE_MAGIC.len())? != STORE_MAGIC {
        return Err(IndexedSessionStoreError::CorruptProtectedState);
    }
    let version = reader.u8()?;
    if !matches!(
        version,
        LEGACY_STORE_VERSION | ACCEPTANCE_STORE_VERSION | STORE_VERSION
    ) {
        return Err(IndexedSessionStoreError::CorruptProtectedState);
    }
    let generation = reader.u64()?;
    let binding = decode_binding(&mut reader)?;
    binding.validate()?;
    let mut root = reader.array::<32>()?;
    let decoded_tail = (|| {
        let message_send = decode_send_ratchet(&mut reader)?;
        let ack_send = decode_send_ratchet(&mut reader)?;
        let message_receive = decode_receive_ratchet(&mut reader)?;
        let ack_receive = decode_receive_ratchet(&mut reader)?;
        let pending_acceptance = if version >= ACCEPTANCE_STORE_VERSION {
            decode_pending_acceptance(&mut reader, &binding)?
        } else {
            None
        };
        let pending_ack_acceptance = if version >= ACCEPTANCE_STORE_VERSION {
            decode_pending_ack_acceptance(&mut reader, &binding)?
        } else {
            None
        };
        let pending_outbound = if version == STORE_VERSION {
            decode_pending_outbound(&mut reader, &binding)?
        } else {
            None
        };
        Ok::<_, IndexedSessionStoreError>((
            message_send,
            ack_send,
            message_receive,
            ack_receive,
            pending_acceptance,
            pending_ack_acceptance,
            pending_outbound,
        ))
    })();
    let (
        message_send,
        ack_send,
        message_receive,
        ack_receive,
        pending_acceptance,
        pending_ack_acceptance,
        pending_outbound,
    ) = match decoded_tail {
        Ok(value) => value,
        Err(error) => {
            root.zeroize();
            return Err(error);
        }
    };
    if usize::from(pending_acceptance.is_some())
        + usize::from(pending_ack_acceptance.is_some())
        + usize::from(pending_outbound.is_some())
        > 1
    {
        root.zeroize();
        return Err(IndexedSessionStoreError::CorruptProtectedState);
    }
    if !reader.is_empty() {
        root.zeroize();
        return Err(IndexedSessionStoreError::CorruptProtectedState);
    }
    let mut integrity_key = store_integrity_key(&root, &binding.session_id);
    let mut mac = match <Hmac<Sha256> as Mac>::new_from_slice(&integrity_key) {
        Ok(value) => value,
        Err(_) => {
            integrity_key.zeroize();
            root.zeroize();
            return Err(IndexedSessionStoreError::CorruptProtectedState);
        }
    };
    mac.update(content);
    let verified = mac.verify_slice(tag).is_ok();
    integrity_key.zeroize();
    if !verified {
        root.zeroize();
        return Err(IndexedSessionStoreError::CorruptProtectedState);
    }
    Ok(ProtectedSessionState {
        generation,
        binding,
        ratchets: SecretRatchets {
            root,
            message_send,
            ack_send,
            message_receive,
            ack_receive,
        },
        pending_acceptance,
        pending_ack_acceptance,
        pending_outbound,
    })
}

fn encode_pending_acceptance(
    writer: &mut BinaryWriter,
    pending: Option<&PendingAcceptance>,
) -> Result<(), IndexedSessionStoreError> {
    let Some(pending) = pending else {
        writer.u8(0);
        return Ok(());
    };
    if pending.sealed_local_inbox_row.len() < 1 + 12 + 16
        || pending.sealed_local_inbox_row.len() > MAX_SEALED_LOCAL_ROW_BYTES
        || !matches!(pending.ack_status, 1 | 2)
        || pending.created_at_ms
            > pending
                .received_at_ms
                .saturating_add(MAX_ENDPOINT_FUTURE_SKEW_MS)
    {
        return Err(IndexedSessionStoreError::CorruptProtectedState);
    }
    writer.u8(1);
    writer.bytes(&pending.session_id);
    writer.bytes(&pending.object_digest);
    writer.bytes(&pending.message_id);
    writer.bytes(&pending.sender_device);
    writer.length_prefixed_u32(&pending.sealed_local_inbox_row, MAX_SEALED_LOCAL_ROW_BYTES)?;
    writer.u8(pending.ack_status);
    writer.u64(pending.created_at_ms);
    writer.u64(pending.received_at_ms);
    writer.u64(pending.public_generation);
    Ok(())
}

fn decode_pending_acceptance(
    reader: &mut BinaryReader<'_>,
    binding: &IndexedSessionBinding,
) -> Result<Option<PendingAcceptance>, IndexedSessionStoreError> {
    match reader.u8()? {
        0 => Ok(None),
        1 => {
            let pending = PendingAcceptance {
                session_id: reader.array()?,
                object_digest: reader.array()?,
                message_id: reader.array()?,
                sender_device: reader.array()?,
                sealed_local_inbox_row: reader.length_prefixed_u32(MAX_SEALED_LOCAL_ROW_BYTES)?,
                ack_status: reader.u8()?,
                created_at_ms: reader.u64()?,
                received_at_ms: reader.u64()?,
                public_generation: reader.u64()?,
            };
            if pending.session_id != binding.session_id
                || pending.sender_device != *remote_device_for_binding(binding)
                || pending.sealed_local_inbox_row.len() < 1 + 12 + 16
                || !matches!(pending.ack_status, 1 | 2)
                || pending.created_at_ms
                    > pending
                        .received_at_ms
                        .saturating_add(MAX_ENDPOINT_FUTURE_SKEW_MS)
            {
                return Err(IndexedSessionStoreError::CorruptProtectedState);
            }
            Ok(Some(pending))
        }
        _ => Err(IndexedSessionStoreError::CorruptProtectedState),
    }
}

fn encode_pending_ack_acceptance(
    writer: &mut BinaryWriter,
    pending: Option<&PendingAckAcceptance>,
) -> Result<(), IndexedSessionStoreError> {
    let Some(pending) = pending else {
        writer.u8(0);
        return Ok(());
    };
    if !matches!(pending.status, 1 | 2) {
        return Err(IndexedSessionStoreError::CorruptProtectedState);
    }
    writer.u8(1);
    writer.bytes(&pending.session_id);
    writer.bytes(&pending.object_digest);
    writer.bytes(&pending.outer_message_id);
    writer.bytes(&pending.remote_device);
    writer.bytes(&pending.acked_message_id);
    writer.u8(pending.status);
    writer.bytes(&pending.ack_nonce);
    writer.u64(pending.created_at_ms);
    writer.u64(pending.public_generation);
    Ok(())
}

fn decode_pending_ack_acceptance(
    reader: &mut BinaryReader<'_>,
    binding: &IndexedSessionBinding,
) -> Result<Option<PendingAckAcceptance>, IndexedSessionStoreError> {
    match reader.u8()? {
        0 => Ok(None),
        1 => {
            let pending = PendingAckAcceptance {
                session_id: reader.array()?,
                object_digest: reader.array()?,
                outer_message_id: reader.array()?,
                remote_device: reader.array()?,
                acked_message_id: reader.array()?,
                status: reader.u8()?,
                ack_nonce: reader.array()?,
                created_at_ms: reader.u64()?,
                public_generation: reader.u64()?,
            };
            if pending.session_id != binding.session_id
                || pending.remote_device != *remote_device_for_binding(binding)
                || !matches!(pending.status, 1 | 2)
            {
                return Err(IndexedSessionStoreError::CorruptProtectedState);
            }
            Ok(Some(pending))
        }
        _ => Err(IndexedSessionStoreError::CorruptProtectedState),
    }
}

fn encode_pending_outbound(
    writer: &mut BinaryWriter,
    pending: Option<&PendingOutbound>,
) -> Result<(), IndexedSessionStoreError> {
    let Some(pending) = pending else {
        writer.u8(0);
        return Ok(());
    };
    validate_pending_outbound_shape(pending)?;
    writer.u8(1);
    writer.u8(pending.kind as u8);
    writer.bytes(&pending.session_id);
    writer.bytes(&pending.object_digest);
    writer.bytes(&pending.message_id);
    writer.bytes(&pending.recipient_device);
    writer.u32(pending.ratchet_index);
    match pending.source_ack_intent {
        Some(value) => {
            writer.u8(1);
            writer.bytes(&value);
        }
        None => writer.u8(0),
    }
    match pending.ack_nonce {
        Some(value) => {
            writer.u8(1);
            writer.bytes(&value);
        }
        None => writer.u8(0),
    }
    writer.bytes(&pending.seal_nonce);
    writer.bytes(&pending.anti_replay_nonce);
    writer.length_prefixed_u32(
        &pending.immutable_envelope_bytes,
        MAX_PENDING_OUTBOUND_BYTES,
    )?;
    writer.u64(pending.public_generation);
    Ok(())
}

fn decode_pending_outbound(
    reader: &mut BinaryReader<'_>,
    binding: &IndexedSessionBinding,
) -> Result<Option<PendingOutbound>, IndexedSessionStoreError> {
    match reader.u8()? {
        0 => Ok(None),
        1 => {
            let kind = EndpointOutboundKind::from_u8(reader.u8()?)?;
            let session_id = reader.array()?;
            let object_digest = reader.array()?;
            let message_id = reader.array()?;
            let recipient_device = reader.array()?;
            let ratchet_index = reader.u32()?;
            let source_ack_intent = match reader.u8()? {
                0 => None,
                1 => Some(reader.array()?),
                _ => return Err(IndexedSessionStoreError::CorruptProtectedState),
            };
            let ack_nonce = match reader.u8()? {
                0 => None,
                1 => Some(reader.array()?),
                _ => return Err(IndexedSessionStoreError::CorruptProtectedState),
            };
            let pending = PendingOutbound {
                kind,
                session_id,
                object_digest,
                message_id,
                recipient_device,
                ratchet_index,
                source_ack_intent,
                ack_nonce,
                seal_nonce: reader.array()?,
                anti_replay_nonce: reader.array()?,
                immutable_envelope_bytes: reader.length_prefixed_u32(MAX_PENDING_OUTBOUND_BYTES)?,
                public_generation: reader.u64()?,
            };
            validate_pending_outbound_shape(&pending)?;
            if pending.session_id != binding.session_id
                || pending.recipient_device != *remote_device_for_binding(binding)
            {
                return Err(IndexedSessionStoreError::CorruptProtectedState);
            }
            Ok(Some(pending))
        }
        _ => Err(IndexedSessionStoreError::CorruptProtectedState),
    }
}

fn validate_pending_outbound_shape(
    pending: &PendingOutbound,
) -> Result<(), IndexedSessionStoreError> {
    if pending.message_id == [0; 16]
        || pending.seal_nonce == [0; 12]
        || pending.anti_replay_nonce == [0; 12]
        || pending.immutable_envelope_bytes.len() < crate::envelope::PREFIX_LEN
        || pending.immutable_envelope_bytes.len() > MAX_PENDING_OUTBOUND_BYTES
        || match pending.kind {
            EndpointOutboundKind::Message => {
                pending.source_ack_intent.is_some() || pending.ack_nonce.is_some()
            }
            EndpointOutboundKind::Ack => {
                pending.source_ack_intent.is_none()
                    || pending.ack_nonce.is_none()
                    || pending.ack_nonce == Some([0; 12])
            }
        }
    {
        return Err(IndexedSessionStoreError::CorruptProtectedState);
    }
    let envelope = Envelope::unpack(&pending.immutable_envelope_bytes)
        .ok_or(IndexedSessionStoreError::CorruptProtectedState)?;
    let expected_type = match pending.kind {
        EndpointOutboundKind::Message => EnvType::Message,
        EndpointOutboundKind::Ack => EnvType::Ack,
    };
    let sealed_index = parse_indexed_message_header(&envelope.message_ciphertext)
        .map_err(|_| IndexedSessionStoreError::CorruptProtectedState)?;
    if envelope.env_type != expected_type as u8
        || envelope.flags != OUTBOUND_FLAGS
        || envelope.message_id != pending.message_id
        || envelope.message_ciphertext[crate::atsam_indexed_session::INDEXED_SEALED_HEADER_LEN - 12
            ..crate::atsam_indexed_session::INDEXED_SEALED_HEADER_LEN]
            != pending.seal_nonce
        || envelope.anti_replay_nonce != pending.anti_replay_nonce
        || envelope.hop_limit != OUTBOUND_HOP_LIMIT
        || envelope.replication_budget != OUTBOUND_REPLICATION_BUDGET
        || !envelope.ratchet_header_ciphertext.is_empty()
        || sealed_index != pending.ratchet_index
        || authenticated_object_digest(&envelope) != pending.object_digest
    {
        return Err(IndexedSessionStoreError::CorruptProtectedState);
    }
    Ok(())
}

fn encode_binding(
    writer: &mut BinaryWriter,
    binding: &IndexedSessionBinding,
) -> Result<(), IndexedSessionStoreError> {
    writer.length_prefixed(&binding.key.profile_id, MAX_PROFILE_BYTES)?;
    writer.length_prefixed(binding.key.initiator_address.as_bytes(), MAX_ADDRESS_BYTES)?;
    writer.length_prefixed(binding.key.responder_address.as_bytes(), MAX_ADDRESS_BYTES)?;
    writer.bytes(&binding.key.initiator_device_ed25519);
    writer.bytes(&binding.key.responder_device_ed25519);
    writer.bytes(&binding.key.init_id);
    writer.bytes(&binding.session_id);
    writer.bytes(&binding.init_hash);
    writer.bytes(&binding.transcript_hash);
    writer.bytes(&binding.initiator_cert_digest);
    writer.bytes(&binding.responder_cert_digest);
    writer.bytes(&binding.responder_prekey_bundle_digest);
    writer.u32(binding.signed_prekey_id);
    writer.u32(binding.one_time_prekey_id);
    writer.u64(binding.created_at_ms);
    writer.u64(binding.expires_at_ms);
    writer.u8(binding.local_role as u8);
    writer.u8(binding.lifecycle as u8);
    match binding.response_hash {
        Some(hash) => {
            writer.u8(1);
            writer.bytes(&hash);
        }
        None => writer.u8(0),
    }
    Ok(())
}

fn decode_binding(
    reader: &mut BinaryReader<'_>,
) -> Result<IndexedSessionBinding, IndexedSessionStoreError> {
    let profile_id = reader.length_prefixed(MAX_PROFILE_BYTES)?;
    let initiator_address = String::from_utf8(reader.length_prefixed(MAX_ADDRESS_BYTES)?)
        .map_err(|_| IndexedSessionStoreError::CorruptProtectedState)?;
    let responder_address = String::from_utf8(reader.length_prefixed(MAX_ADDRESS_BYTES)?)
        .map_err(|_| IndexedSessionStoreError::CorruptProtectedState)?;
    let initiator_device_ed25519 = reader.array::<32>()?;
    let responder_device_ed25519 = reader.array::<32>()?;
    let init_id = reader.array::<16>()?;
    let session_id = reader.array::<32>()?;
    let init_hash = reader.array::<32>()?;
    let transcript_hash = reader.array::<32>()?;
    let initiator_cert_digest = reader.array::<32>()?;
    let responder_cert_digest = reader.array::<32>()?;
    let responder_prekey_bundle_digest = reader.array::<32>()?;
    let signed_prekey_id = reader.u32()?;
    let one_time_prekey_id = reader.u32()?;
    let created_at_ms = reader.u64()?;
    let expires_at_ms = reader.u64()?;
    let local_role = LocalRole::from_u8(reader.u8()?)?;
    let lifecycle = SessionLifecycle::from_u8(reader.u8()?)?;
    let response_hash = match reader.u8()? {
        0 => None,
        1 => Some(reader.array::<32>()?),
        _ => return Err(IndexedSessionStoreError::CorruptProtectedState),
    };
    Ok(IndexedSessionBinding {
        key: IndexedSessionRecordKey {
            profile_id,
            initiator_address,
            responder_address,
            initiator_device_ed25519,
            responder_device_ed25519,
            init_id,
        },
        session_id,
        init_hash,
        transcript_hash,
        initiator_cert_digest,
        responder_cert_digest,
        responder_prekey_bundle_digest,
        signed_prekey_id,
        one_time_prekey_id,
        created_at_ms,
        expires_at_ms,
        local_role,
        lifecycle,
        response_hash,
    })
}

fn encode_send_ratchet(writer: &mut BinaryWriter, ratchet: &SendRatchet) {
    writer.u64(ratchet.next_index);
    writer.bytes(&ratchet.chain_key);
}

fn decode_send_ratchet(
    reader: &mut BinaryReader<'_>,
) -> Result<SendRatchet, IndexedSessionStoreError> {
    let next_index = reader.u64()?;
    if next_index > u32::MAX as u64 + 1 {
        return Err(IndexedSessionStoreError::CorruptProtectedState);
    }
    Ok(SendRatchet {
        next_index,
        chain_key: reader.array::<32>()?,
    })
}

fn encode_receive_ratchet(
    writer: &mut BinaryWriter,
    ratchet: &ReceiveRatchet,
) -> Result<(), IndexedSessionStoreError> {
    if ratchet.next_index > u32::MAX as u64 + 1 || ratchet.skipped_keys.len() > MAX_SKIPPED_KEYS {
        return Err(IndexedSessionStoreError::CorruptProtectedState);
    }
    writer.u64(ratchet.next_index);
    writer.bytes(&ratchet.chain_key);
    writer.u16(ratchet.skipped_keys.len() as u16);
    for (index, key) in &ratchet.skipped_keys {
        if *index as u64 >= ratchet.next_index {
            return Err(IndexedSessionStoreError::CorruptProtectedState);
        }
        writer.u32(*index);
        writer.bytes(key);
    }
    Ok(())
}

fn decode_receive_ratchet(
    reader: &mut BinaryReader<'_>,
) -> Result<ReceiveRatchet, IndexedSessionStoreError> {
    let next_index = reader.u64()?;
    if next_index > u32::MAX as u64 + 1 {
        return Err(IndexedSessionStoreError::CorruptProtectedState);
    }
    let chain_key = reader.array::<32>()?;
    let count = reader.u16()? as usize;
    if count > MAX_SKIPPED_KEYS {
        return Err(IndexedSessionStoreError::CorruptProtectedState);
    }
    let mut skipped_keys = BTreeMap::new();
    for _ in 0..count {
        let index = reader.u32()?;
        if index as u64 >= next_index || skipped_keys.insert(index, reader.array::<32>()?).is_some()
        {
            return Err(IndexedSessionStoreError::CorruptProtectedState);
        }
    }
    Ok(ReceiveRatchet {
        next_index,
        chain_key,
        skipped_keys,
    })
}

/// Encoder for protected session state. The buffer holds roots, chain keys
/// and skipped keys, so it never lets `Vec` reallocate on its own (which would
/// free earlier copies unwiped) and is zeroized on drop, including on error
/// paths that abandon a partial encoding.
struct BinaryWriter {
    value: Vec<u8>,
}

impl BinaryWriter {
    fn new() -> Self {
        Self {
            value: Vec::with_capacity(1024),
        }
    }

    fn bytes(&mut self, value: &[u8]) {
        let required = self.value.len().saturating_add(value.len());
        if required > self.value.capacity() {
            let mut grown =
                Vec::with_capacity(required.max(self.value.capacity().saturating_mul(2)));
            grown.extend_from_slice(&self.value);
            self.value.zeroize();
            self.value = grown;
        }
        self.value.extend_from_slice(value);
    }

    fn u8(&mut self, value: u8) {
        self.bytes(&[value]);
    }

    fn into_bytes(mut self) -> Vec<u8> {
        std::mem::take(&mut self.value)
    }

    fn u16(&mut self, value: u16) {
        self.bytes(&value.to_be_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.bytes(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes(&value.to_be_bytes());
    }

    fn length_prefixed(
        &mut self,
        value: &[u8],
        maximum: usize,
    ) -> Result<(), IndexedSessionStoreError> {
        if value.len() > maximum || value.len() > u16::MAX as usize {
            return Err(IndexedSessionStoreError::InvalidBinding);
        }
        self.u16(value.len() as u16);
        self.bytes(value);
        Ok(())
    }

    fn length_prefixed_u32(
        &mut self,
        value: &[u8],
        maximum: usize,
    ) -> Result<(), IndexedSessionStoreError> {
        if value.len() > maximum || value.len() > u32::MAX as usize {
            return Err(IndexedSessionStoreError::CorruptProtectedState);
        }
        self.u32(value.len() as u32);
        self.bytes(value);
        Ok(())
    }
}

impl Drop for BinaryWriter {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

struct BinaryReader<'a> {
    value: &'a [u8],
    offset: usize,
}

impl<'a> BinaryReader<'a> {
    fn new(value: &'a [u8]) -> Self {
        Self { value, offset: 0 }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], IndexedSessionStoreError> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(IndexedSessionStoreError::CorruptProtectedState)?;
        if end > self.value.len() {
            return Err(IndexedSessionStoreError::CorruptProtectedState);
        }
        let result = &self.value[self.offset..end];
        self.offset = end;
        Ok(result)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], IndexedSessionStoreError> {
        self.take(N)?
            .try_into()
            .map_err(|_| IndexedSessionStoreError::CorruptProtectedState)
    }

    fn u8(&mut self) -> Result<u8, IndexedSessionStoreError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, IndexedSessionStoreError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, IndexedSessionStoreError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, IndexedSessionStoreError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn length_prefixed(&mut self, maximum: usize) -> Result<Vec<u8>, IndexedSessionStoreError> {
        let length = self.u16()? as usize;
        if length > maximum {
            return Err(IndexedSessionStoreError::CorruptProtectedState);
        }
        Ok(self.take(length)?.to_vec())
    }

    fn length_prefixed_u32(&mut self, maximum: usize) -> Result<Vec<u8>, IndexedSessionStoreError> {
        let length = usize::try_from(self.u32()?)
            .map_err(|_| IndexedSessionStoreError::CorruptProtectedState)?;
        if length > maximum {
            return Err(IndexedSessionStoreError::CorruptProtectedState);
        }
        Ok(self.take(length)?.to_vec())
    }

    fn is_empty(&self) -> bool {
        self.offset == self.value.len()
    }
}

/// True when `t_ms` lies before the session's start, its signed PairInit
/// `created_at_ms`. That instant comes from the INITIATOR's clock, and PairInit
/// and PairResponse verification already tolerate `MAX_PREKEY_FUTURE_SKEW_MS`
/// of peer clock skew; the session windows use the same bound for their start,
/// or a peer whose clock is a little behind would accept and confirm the session
/// and then be unable to send, receive or acknowledge in it until its clock
/// caught up. Expiry bounds stay exact.
fn before_session_start(t_ms: u64, session_created_at_ms: u64) -> bool {
    t_ms.saturating_add(crate::prekey_lifecycle::MAX_PREKEY_FUTURE_SKEW_MS) < session_created_at_ms
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ack::Ack;
    use crate::atsam_indexed_session::{
        ack_key_at_index, encode_signed_ack, message_key_at_index, seal_indexed_message_with_key,
        SignedAck,
    };
    use crate::identity::Identity;
    use crate::pair_init::device_certificate_hash;
    use crate::pair_init::{
        decode_init as decode_pair_init, decode_response as decode_pair_response,
    };
    use rand::rngs::StdRng;
    use rand::Error as RandError;
    use rand::SeedableRng;
    use serde_json::Value;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{mpsc, Condvar, Mutex};
    use std::thread;
    use tempfile::tempdir;

    /// Upper bound on every test rendezvous. A peer that never arrives (an
    /// early error, a changed number of protected writes) fails the test with
    /// a message instead of hanging `cargo test` forever.
    const RENDEZVOUS_TIMEOUT: Duration = Duration::from_secs(30);

    /// A reader's place in the clear order (the store places it in its own
    /// order: every test's positions work on a keyed store too).
    fn after(received_at_ms: u64, message_id: Option<&[u8; 16]>) -> InboxPosition {
        InboxPosition::received(received_at_ms, message_id.copied())
    }

    #[test]
    fn route_tag_comparison_checks_every_bit() {
        let tag: [u8; 16] = std::array::from_fn(|i| (i as u8).wrapping_mul(37) ^ 0xA5);
        assert!(route_tag_eq(&tag, &tag));
        for byte in 0..16 {
            for bit in 0..8 {
                let mut other = tag;
                other[byte] ^= 1 << bit;
                assert!(!route_tag_eq(&other, &tag), "byte {byte} bit {bit}");
                assert!(!route_tag_eq(&tag, &other), "byte {byte} bit {bit}");
            }
        }
    }

    /// Single-use start barrier whose `wait` panics on timeout.
    struct TimedBarrier {
        parties: usize,
        arrived: Mutex<usize>,
        all_arrived: Condvar,
    }

    impl TimedBarrier {
        fn new(parties: usize) -> Arc<Self> {
            Arc::new(Self {
                parties,
                arrived: Mutex::new(0),
                all_arrived: Condvar::new(),
            })
        }

        fn wait(&self, what: &str) {
            self.wait_for(what, RENDEZVOUS_TIMEOUT);
        }

        fn wait_for(&self, what: &str, timeout: Duration) {
            let mut arrived = self.arrived.lock().expect("barrier lock");
            *arrived += 1;
            self.all_arrived.notify_all();
            let (_arrived, result) = self
                .all_arrived
                .wait_timeout_while(arrived, timeout, |arrived| *arrived < self.parties)
                .expect("barrier lock");
            assert!(
                !result.timed_out(),
                "{what}: peers never arrived within {timeout:?}"
            );
        }
    }

    struct ScriptedCryptoRng {
        bytes: Vec<u8>,
        offset: usize,
    }

    impl ScriptedCryptoRng {
        fn outbound(message_id: [u8; 16], seal_nonce: [u8; 12], anti_replay: [u8; 12]) -> Self {
            let mut bytes = Vec::with_capacity(40);
            bytes.extend_from_slice(&message_id);
            bytes.extend_from_slice(&seal_nonce);
            bytes.extend_from_slice(&anti_replay);
            Self { bytes, offset: 0 }
        }

        fn ack(
            message_id: [u8; 16],
            seal_nonce: [u8; 12],
            anti_replay: [u8; 12],
            ack_nonce: [u8; 12],
        ) -> Self {
            let mut value = Self::outbound(message_id, seal_nonce, anti_replay);
            value.bytes.extend_from_slice(&ack_nonce);
            value
        }
    }

    impl RngCore for ScriptedCryptoRng {
        fn next_u32(&mut self) -> u32 {
            let mut value = [0u8; 4];
            self.fill_bytes(&mut value);
            u32::from_le_bytes(value)
        }

        fn next_u64(&mut self) -> u64 {
            let mut value = [0u8; 8];
            self.fill_bytes(&mut value);
            u64::from_le_bytes(value)
        }

        fn fill_bytes(&mut self, destination: &mut [u8]) {
            self.try_fill_bytes(destination)
                .expect("scripted RNG has enough bytes");
        }

        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RandError> {
            let end = self.offset.saturating_add(destination.len());
            if end > self.bytes.len() {
                return Err(RandError::new(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "scripted RNG exhausted",
                )));
            }
            destination.copy_from_slice(&self.bytes[self.offset..end]);
            self.offset = end;
            Ok(())
        }
    }

    impl CryptoRng for ScriptedCryptoRng {}

    #[cfg(not(any(
        target_os = "macos",
        windows,
        all(target_os = "linux", target_env = "gnu")
    )))]
    #[test]
    fn unsupported_platform_backend_fails_closed_without_creating_metadata() {
        let temp = tempdir().unwrap();
        let expected =
            format!("protected session store unavailable: {PROTECTED_STORE_UNAVAILABLE}");

        let open_error = match IndexedSessionStore::open(temp.path()) {
            Ok(_) => panic!("unsupported platform unexpectedly opened a session store"),
            Err(error) => error,
        };
        assert_eq!(open_error.redacted_display(), expected);
        assert!(!temp.path().join(INDEXED_SESSION_METADATA_FILE).exists());

        let backend = PlatformProtectedSessionBackend {};
        let get_error = backend.get("account").unwrap_err();
        let put_error = backend.put("account", b"secret").unwrap_err();
        assert_eq!(get_error.redacted_display(), expected);
        assert_eq!(put_error.redacted_display(), expected);
        assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 0);
    }

    /// Busy-handler invocations of the connection `count_busy_wait` is
    /// installed on, so a test can observe a store instance waiting for the
    /// write lock instead of guessing how long that takes. Only the
    /// late-journal-clear test installs it, one instance at a time.
    static SECOND_INSTANCE_BUSY_WAITS: AtomicUsize = AtomicUsize::new(0);

    /// Same bound as the store's own 10 s busy timeout, plus the count.
    fn count_busy_wait(attempt: i32) -> bool {
        SECOND_INSTANCE_BUSY_WAITS.fetch_add(1, Ordering::SeqCst);
        thread::sleep(Duration::from_millis(1));
        attempt < 10_000
    }

    /// Backend half of a scheduled put pause: the put number it parks, the
    /// channel that announces the parked writer and the one that releases it.
    type PutPause = (usize, mpsc::Sender<()>, mpsc::Receiver<()>);

    /// Test half of a scheduled put pause.
    struct PutPauseHandle {
        parked: mpsc::Receiver<()>,
        resume: mpsc::Sender<()>,
    }

    impl PutPauseHandle {
        /// Waits until the writer parks on the paused put. A worker that
        /// finishes first never reached it (it failed or the number of
        /// protected writes changed), which is reported instead of waited for.
        fn wait_until_parked<T>(&self, worker: &thread::JoinHandle<T>) {
            self.wait_until_parked_for(worker, RENDEZVOUS_TIMEOUT);
        }

        fn wait_until_parked_for<T>(&self, worker: &thread::JoinHandle<T>, timeout: Duration) {
            let started = std::time::Instant::now();
            loop {
                match self.parked.recv_timeout(Duration::from_millis(20)) {
                    Ok(()) => return,
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        assert!(
                            !worker.is_finished(),
                            "the worker finished without reaching the paused protected write"
                        );
                        assert!(
                            started.elapsed() < timeout,
                            "the worker never reached the paused protected write"
                        );
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        panic!("the paused protected write was dropped")
                    }
                }
            }
        }

        fn resume(&self) {
            self.resume.send(()).expect("the parked writer is gone");
        }
    }

    #[derive(Default)]
    struct MemoryProtectedBackend {
        values: Mutex<HashMap<String, Vec<u8>>>,
        fail_next_put: AtomicBool,
        put_count: AtomicUsize,
        fail_on_put: Mutex<Option<usize>>,
        pause_on_put: Mutex<Option<PutPause>>,
    }

    impl MemoryProtectedBackend {
        fn fail_next_put(&self) {
            self.fail_next_put.store(true, Ordering::SeqCst);
        }

        /// Blocks the `offset`-th future put before it lands: the writer
        /// announces itself on the handle (so the test knows it is parked) and
        /// then waits, bounded by `RENDEZVOUS_TIMEOUT`, for `resume`.
        fn pause_nth_future_put(&self, offset: usize) -> PutPauseHandle {
            assert!(offset > 0);
            let target = self.put_count.load(Ordering::SeqCst) + offset;
            let (parked_tx, parked) = mpsc::channel();
            let (resume, resume_rx) = mpsc::channel();
            *self.pause_on_put.lock().expect("pause lock") = Some((target, parked_tx, resume_rx));
            PutPauseHandle { parked, resume }
        }

        fn fail_nth_future_put(&self, offset: usize) {
            assert!(offset > 0);
            let target = self.put_count.load(Ordering::SeqCst) + offset;
            *self.fail_on_put.lock().expect("failure lock") = Some(target);
        }

        fn corrupt(&self, account: &str) {
            let mut values = self.values.lock().expect("memory backend lock");
            let value = values.get_mut(account).expect("protected value");
            let offset = value.len() / 2;
            value[offset] ^= 0x80;
        }
    }

    impl ProtectedSessionBackend for MemoryProtectedBackend {
        fn get(&self, account: &str) -> Result<Option<Vec<u8>>, IndexedSessionStoreError> {
            Ok(self
                .values
                .lock()
                .map_err(|_| IndexedSessionStoreError::ProtectedStore("test lock poisoned".into()))?
                .get(account)
                .cloned())
        }

        fn put(&self, account: &str, value: &[u8]) -> Result<(), IndexedSessionStoreError> {
            let put_number = self.put_count.fetch_add(1, Ordering::SeqCst) + 1;
            let pause = {
                let mut pause_on_put = self.pause_on_put.lock().expect("pause lock");
                if pause_on_put
                    .as_ref()
                    .is_some_and(|(target, _, _)| *target == put_number)
                {
                    pause_on_put.take()
                } else {
                    None
                }
            };
            if let Some((_, parked, resume)) = pause {
                // A vanished test (dropped handle) or a missed resume fails
                // the parked put instead of blocking the writer forever.
                let _ = parked.send(());
                if resume.recv_timeout(RENDEZVOUS_TIMEOUT).is_err() {
                    return Err(IndexedSessionStoreError::ProtectedStore(
                        "paused write was never resumed".into(),
                    ));
                }
            }
            let scheduled_failure = {
                let mut fail_on_put = self.fail_on_put.lock().expect("failure lock");
                if *fail_on_put == Some(put_number) {
                    *fail_on_put = None;
                    true
                } else {
                    false
                }
            };
            if scheduled_failure || self.fail_next_put.swap(false, Ordering::SeqCst) {
                return Err(IndexedSessionStoreError::ProtectedStore(
                    "injected write failure".into(),
                ));
            }
            self.values
                .lock()
                .map_err(|_| IndexedSessionStoreError::ProtectedStore("test lock poisoned".into()))?
                .insert(account.to_owned(), value.to_vec());
            Ok(())
        }

        fn delete(&self, account: &str) -> Result<(), IndexedSessionStoreError> {
            self.values
                .lock()
                .map_err(|_| IndexedSessionStoreError::ProtectedStore("test lock poisoned".into()))?
                .remove(account);
            Ok(())
        }
    }

    fn session_id(init_hash: &[u8; 32]) -> [u8; 32] {
        session_id_from_init_hash(init_hash)
    }

    fn fixture_binding() -> IndexedSessionBinding {
        let init_hash = [0x41; 32];
        IndexedSessionBinding {
            key: IndexedSessionRecordKey {
                profile_id: PROFILE_ID.to_vec(),
                initiator_address: "rvn1qysluvwl5922yctzd0u9gpr06gn3k7ldfvecule0".into(),
                responder_address: "rvn1qyulwy7s5ezz20cy222zrw04rwds39uapqakqskn".into(),
                initiator_device_ed25519: [0x11; 32],
                responder_device_ed25519: [0x22; 32],
                init_id: [0x33; 16],
            },
            session_id: session_id(&init_hash),
            init_hash,
            transcript_hash: [0x42; 32],
            initiator_cert_digest: [0x43; 32],
            responder_cert_digest: [0x44; 32],
            responder_prekey_bundle_digest: [0x45; 32],
            signed_prekey_id: 7,
            one_time_prekey_id: 9,
            created_at_ms: 1_700_000_000_000,
            expires_at_ms: 1_700_086_400_000,
            local_role: LocalRole::Initiator,
            lifecycle: SessionLifecycle::Provisional,
            response_hash: None,
        }
    }

    fn open_test_store(path: &Path, backend: Arc<MemoryProtectedBackend>) -> IndexedSessionStore {
        IndexedSessionStore::open_with_backend(path, backend).expect("open test store")
    }

    fn pair_init_vector() -> (PairInit, PairResponse, [u8; 32]) {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../shared-vectors/rvn1/atsam/pair_init_v1_001.json");
        let vector: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let init = decode_pair_init(
            &hex::decode(vector["expected"]["pair_init_wire_hex"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        let response = decode_pair_response(
            &hex::decode(
                vector["expected"]["pair_response_wire_hex"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        let root: [u8; 32] = hex::decode(
            vector["expected"]["provisional_k_root_hex"]
                .as_str()
                .unwrap(),
        )
        .unwrap()
        .try_into()
        .unwrap();
        (init, response, root)
    }

    fn vector_binding(init: &PairInit) -> IndexedSessionBinding {
        IndexedSessionBinding {
            key: IndexedSessionRecordKey {
                profile_id: PROFILE_ID.to_vec(),
                initiator_address: init.initiator_address.clone(),
                responder_address: init.responder_address.clone(),
                initiator_device_ed25519: init.initiator_device_ed_pub,
                responder_device_ed25519: init.responder_device_ed_pub,
                init_id: init.init_id,
            },
            session_id: pair_session_id(init).unwrap(),
            init_hash: pair_init_hash(init).unwrap(),
            transcript_hash: pair_transcript_hash(init).unwrap(),
            initiator_cert_digest: init.initiator_device_cert_hash,
            responder_cert_digest: init.responder_device_cert_hash,
            responder_prekey_bundle_digest: init.responder_prekey_bundle_hash,
            signed_prekey_id: init.signed_prekey_id,
            one_time_prekey_id: init.one_time_prekey_id,
            created_at_ms: init.created_at_ms,
            expires_at_ms: init.expires_at_ms,
            local_role: LocalRole::Initiator,
            lifecycle: SessionLifecycle::Provisional,
            response_hash: None,
        }
    }

    struct EndpointFixture {
        binding: IndexedSessionBinding,
        key: IndexedSessionRecordKey,
        root: [u8; 32],
        local_identity: Identity,
        local_certificate: DeviceCertificate,
        local_registry: DeviceRegistry,
        remote_identity: Identity,
        remote_certificate: DeviceCertificate,
        now_ms: u64,
    }

    fn endpoint_fixture() -> EndpointFixture {
        let local_identity = Identity::from_seed(&[0x11; 32]);
        let remote_identity = Identity::from_seed(&[0x22; 32]);
        let remote_user = Identity::from_seed(&[0x23; 32]);
        let now_ms = 1_700_000_100_000;
        let remote_certificate = DeviceCertificate::issue(
            &remote_user,
            remote_identity.public_key_bytes(),
            [0x24; 32],
            "remote-device",
            1_699_999_000_000,
            1_700_200_000_000,
            1,
        )
        .unwrap();
        let local_certificate = DeviceCertificate::issue(
            &local_identity,
            local_identity.public_key_bytes(),
            [0x14; 32],
            "local-device",
            1_699_999_000_000,
            1_700_200_000_000,
            1,
        )
        .unwrap();
        let mut local_registry = DeviceRegistry::default();
        local_registry
            .add(local_certificate.clone(), now_ms)
            .unwrap();
        let init_hash = [0x41; 32];
        let binding = IndexedSessionBinding {
            key: IndexedSessionRecordKey {
                profile_id: PROFILE_ID.to_vec(),
                initiator_address: local_identity.address(),
                responder_address: remote_user.address(),
                initiator_device_ed25519: local_identity.public_key_bytes(),
                responder_device_ed25519: remote_identity.public_key_bytes(),
                init_id: [0x33; 16],
            },
            session_id: session_id(&init_hash),
            init_hash,
            transcript_hash: [0x42; 32],
            initiator_cert_digest: device_certificate_hash(&local_certificate).unwrap(),
            responder_cert_digest: device_certificate_hash(&remote_certificate).unwrap(),
            responder_prekey_bundle_digest: [0x45; 32],
            signed_prekey_id: 7,
            one_time_prekey_id: 9,
            created_at_ms: 1_699_999_000_000,
            expires_at_ms: 1_700_200_000_000,
            local_role: LocalRole::Initiator,
            lifecycle: SessionLifecycle::Confirmed,
            response_hash: Some([0x46; 32]),
        };
        EndpointFixture {
            key: binding.key.clone(),
            binding,
            root: [0xA7; 32],
            local_identity,
            local_certificate,
            local_registry,
            remote_identity,
            remote_certificate,
            now_ms,
        }
    }

    fn authorized_local_device(fixture: &EndpointFixture) -> AuthorizedEndpointDevice<'_> {
        AuthorizedEndpointDevice::authorize(
            &fixture.local_certificate,
            &fixture.local_identity,
            &fixture.local_registry,
            fixture.now_ms,
        )
        .unwrap()
    }

    fn inbound_message_envelope(
        fixture: &EndpointFixture,
        index: u32,
        message_id: [u8; 16],
        plaintext: &[u8],
    ) -> Envelope {
        let direction = Direction::ResponderToInitiator;
        let created_at = fixture.now_ms + MAX_ENDPOINT_FUTURE_SKEW_MS;
        let key = message_key_at_index(
            &fixture.root,
            &fixture.key.initiator_address,
            &fixture.key.responder_address,
            direction,
            index,
        )
        .unwrap();
        let sealed = seal_indexed_message_with_key(
            &key,
            &fixture.key.initiator_address,
            &fixture.key.responder_address,
            direction,
            index,
            &message_id,
            plaintext,
            &[0xA0; 12],
        )
        .unwrap();
        let mut envelope = Envelope {
            env_type: EnvType::Message as u8,
            flags: 0,
            message_id,
            routing_tag: derive_route_tag(
                &fixture.root,
                created_at,
                index,
                EnvType::Message as u8,
                direction,
            )
            .unwrap(),
            dest_device_hint: 0,
            created_at,
            expires_at: created_at + 60_000,
            hop_limit: 8,
            replication_budget: 2,
            anti_replay_nonce: [0xA1; 12],
            ratchet_header_ciphertext: Vec::new(),
            message_ciphertext: sealed,
            sender_authentication: vec![0; 64],
        };
        envelope.sign_with(&fixture.remote_identity);
        envelope
    }

    fn inbound_ack_envelope(
        fixture: &EndpointFixture,
        index: u32,
        outer_message_id: [u8; 16],
        acked_message_id: [u8; 16],
        status: u8,
        ack_nonce: [u8; 12],
    ) -> Envelope {
        inbound_ack_envelope_in_window(
            fixture,
            index,
            outer_message_id,
            acked_message_id,
            status,
            ack_nonce,
            fixture.now_ms,
            fixture.now_ms + 60_000,
        )
    }

    /// Like `inbound_ack_envelope`, with an explicit validity window. The
    /// signed inner record carries the same `created_at` as the outer envelope.
    #[allow(clippy::too_many_arguments)]
    fn inbound_ack_envelope_in_window(
        fixture: &EndpointFixture,
        index: u32,
        outer_message_id: [u8; 16],
        acked_message_id: [u8; 16],
        status: u8,
        ack_nonce: [u8; 12],
        created_at: u64,
        expires_at: u64,
    ) -> Envelope {
        let direction = Direction::ResponderToInitiator;
        let record = Ack {
            acked_message_id,
            status,
            ack_nonce,
            created_at,
        };
        let signed = SignedAck {
            signature: record.sign(&fixture.remote_identity),
            record,
        };
        let plaintext = encode_signed_ack(&signed).unwrap();
        let key = ack_key_at_index(
            &fixture.root,
            &fixture.key.initiator_address,
            &fixture.key.responder_address,
            direction,
            index,
        )
        .unwrap();
        let sealed = seal_indexed_message_with_key(
            &key,
            &fixture.key.initiator_address,
            &fixture.key.responder_address,
            direction,
            index,
            &outer_message_id,
            &plaintext,
            &[0xB0; 12],
        )
        .unwrap();
        let mut envelope = Envelope {
            env_type: EnvType::Ack as u8,
            flags: 0,
            message_id: outer_message_id,
            routing_tag: derive_route_tag(
                &fixture.root,
                created_at,
                index,
                EnvType::Ack as u8,
                direction,
            )
            .unwrap(),
            dest_device_hint: endpoint_device_hint(&fixture.key.initiator_device_ed25519),
            created_at,
            expires_at,
            hop_limit: 8,
            replication_budget: 2,
            anti_replay_nonce: [0xB1; 12],
            ratchet_header_ciphertext: Vec::new(),
            message_ciphertext: sealed,
            sender_authentication: vec![0; 64],
        };
        envelope.sign_with(&fixture.remote_identity);
        envelope
    }

    #[allow(clippy::too_many_arguments)]
    fn custom_inbound_ack_envelope(
        fixture: &EndpointFixture,
        index: u32,
        outer_message_id: [u8; 16],
        acked_message_id: [u8; 16],
        status: u8,
        ack_nonce: [u8; 12],
        inner_created_at: u64,
        inner_signer: Option<&Identity>,
    ) -> Envelope {
        let direction = Direction::ResponderToInitiator;
        let record = Ack {
            acked_message_id,
            status,
            ack_nonce,
            created_at: inner_created_at,
        };
        let mut plaintext = [0u8; crate::atsam_indexed_session::ACK_PLAINTEXT_LEN];
        plaintext[..16].copy_from_slice(&record.acked_message_id);
        plaintext[16] = status;
        plaintext[17..29].copy_from_slice(&record.ack_nonce);
        plaintext[29..37].copy_from_slice(&record.created_at.to_be_bytes());
        if let Some(signer) = inner_signer {
            plaintext[37..].copy_from_slice(&record.sign(signer));
        }
        let key = ack_key_at_index(
            &fixture.root,
            &fixture.key.initiator_address,
            &fixture.key.responder_address,
            direction,
            index,
        )
        .unwrap();
        let sealed = seal_indexed_message_with_key(
            &key,
            &fixture.key.initiator_address,
            &fixture.key.responder_address,
            direction,
            index,
            &outer_message_id,
            &plaintext,
            &[0xB0; 12],
        )
        .unwrap();
        let mut envelope = Envelope {
            env_type: EnvType::Ack as u8,
            flags: 0,
            message_id: outer_message_id,
            routing_tag: derive_route_tag(
                &fixture.root,
                fixture.now_ms,
                index,
                EnvType::Ack as u8,
                direction,
            )
            .unwrap(),
            dest_device_hint: endpoint_device_hint(&fixture.key.initiator_device_ed25519),
            created_at: fixture.now_ms,
            expires_at: fixture.now_ms + 60_000,
            hop_limit: 8,
            replication_budget: 2,
            anti_replay_nonce: [0xB1; 12],
            ratchet_header_ciphertext: Vec::new(),
            message_ciphertext: sealed,
            sender_authentication: vec![0; 64],
        };
        envelope.sign_with(&fixture.remote_identity);
        envelope
    }

    #[test]
    fn crash_relaunch_preserves_send_and_authenticated_receive_state() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let binding = fixture_binding();
        let key = binding.key.clone();
        let root = [0xA7; 32];
        {
            let mut store = open_test_store(&path, Arc::clone(&backend));
            store.create_session(binding.clone(), root).unwrap();
            let reservation = store.reserve_send_key(&key, RatchetLane::Message).unwrap();
            assert_eq!(reservation.index, 0);
            assert_eq!(
                reservation.key,
                message_key_at_index(
                    &root,
                    &key.initiator_address,
                    &key.responder_address,
                    Direction::InitiatorToResponder,
                    0,
                )
                .unwrap()
            );
        }
        {
            let mut reopened = open_test_store(&path, Arc::clone(&backend));
            assert_eq!(
                reopened
                    .reserve_send_key(&key, RatchetLane::Message)
                    .unwrap()
                    .index,
                1
            );
            let expected = message_key_at_index(
                &root,
                &key.initiator_address,
                &key.responder_address,
                Direction::ResponderToInitiator,
                2,
            )
            .unwrap();
            let authenticated = reopened
                .authenticate_receive(&key, RatchetLane::Message, 2, |candidate| {
                    (candidate == &expected).then_some("plaintext committed separately")
                })
                .unwrap();
            assert_eq!(authenticated, "plaintext committed separately");
        }
        let mut reopened = open_test_store(&path, backend);
        let expected_zero = message_key_at_index(
            &root,
            &key.initiator_address,
            &key.responder_address,
            Direction::ResponderToInitiator,
            0,
        )
        .unwrap();
        reopened
            .authenticate_receive(&key, RatchetLane::Message, 0, |candidate| {
                (candidate == &expected_zero).then_some(())
            })
            .unwrap();
        assert!(matches!(
            reopened.authenticate_receive(&key, RatchetLane::Message, 2, |_| Some(())),
            Err(IndexedSessionStoreError::Replay)
        ));
    }

    #[test]
    fn concurrent_reservations_are_unique_and_monotonic() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let binding = fixture_binding();
        let key = binding.key.clone();
        let root = [0x91; 32];
        let mut creator = open_test_store(&path, Arc::clone(&backend));
        creator.create_session(binding, root).unwrap();
        drop(creator);

        const WORKERS: usize = 24;
        let barrier = TimedBarrier::new(WORKERS);
        let mut stores = Vec::new();
        for _ in 0..WORKERS {
            stores.push(open_test_store(&path, Arc::clone(&backend)));
        }
        let mut handles = Vec::new();
        for mut store in stores {
            let barrier = Arc::clone(&barrier);
            let key = key.clone();
            handles.push(thread::spawn(move || {
                barrier.wait("reservation workers");
                let reservation = store.reserve_send_key(&key, RatchetLane::Message).unwrap();
                (reservation.index, reservation.key)
            }));
        }
        let mut reservations: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        reservations.sort_by_key(|(index, _)| *index);
        assert_eq!(
            reservations
                .iter()
                .map(|(index, _)| *index)
                .collect::<Vec<_>>(),
            (0..WORKERS as u32).collect::<Vec<_>>()
        );
        for (index, reserved) in reservations {
            assert_eq!(
                reserved,
                message_key_at_index(
                    &root,
                    &key.initiator_address,
                    &key.responder_address,
                    Direction::InitiatorToResponder,
                    index,
                )
                .unwrap()
            );
        }
    }

    #[test]
    fn forward_jump_over_256_and_failed_auth_do_not_advance() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let binding = fixture_binding();
        let key = binding.key.clone();
        let root = [0x81; 32];
        let mut store = open_test_store(&path, backend);
        store.create_session(binding, root).unwrap();
        assert!(matches!(
            store.authenticate_receive(&key, RatchetLane::Message, 257, |_| Some(())),
            Err(IndexedSessionStoreError::ForwardJumpTooLarge)
        ));
        assert!(matches!(
            store.authenticate_receive::<(), _>(&key, RatchetLane::Message, 0, |_| None),
            Err(IndexedSessionStoreError::AuthenticationFailed)
        ));
        let expected = message_key_at_index(
            &root,
            &key.initiator_address,
            &key.responder_address,
            Direction::ResponderToInitiator,
            0,
        )
        .unwrap();
        store
            .authenticate_receive(&key, RatchetLane::Message, 0, |candidate| {
                (candidate == &expected).then_some(())
            })
            .unwrap();
    }

    #[test]
    fn skipped_key_cache_is_bounded_and_ack_lane_is_independent() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let binding = fixture_binding();
        let key = binding.key.clone();
        let root = [0x71; 32];
        let mut store = open_test_store(&path, Arc::clone(&backend));
        store.create_session(binding, root).unwrap();
        let expected = message_key_at_index(
            &root,
            &key.initiator_address,
            &key.responder_address,
            Direction::ResponderToInitiator,
            256,
        )
        .unwrap();
        store
            .authenticate_receive(&key, RatchetLane::Message, 256, |candidate| {
                (candidate == &expected).then_some(())
            })
            .unwrap();
        let account = hex::encode(record_key_digest(&key).unwrap());
        let encoded = backend.get(&account).unwrap().unwrap();
        let state = decode_protected_state(&encoded).unwrap();
        assert_eq!(state.ratchets.message_receive.skipped_keys.len(), 256);
        assert_eq!(state.ratchets.ack_receive.skipped_keys.len(), 0);
        drop(state);

        let ack = store.reserve_send_key(&key, RatchetLane::Ack).unwrap();
        assert_eq!(ack.index, 0);
        assert_eq!(
            ack.key,
            ack_key_at_index(
                &root,
                &key.initiator_address,
                &key.responder_address,
                Direction::InitiatorToResponder,
                0,
            )
            .unwrap()
        );
    }

    #[test]
    fn corrupt_protected_blob_fails_closed_without_metadata_advance() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let binding = fixture_binding();
        let key = binding.key.clone();
        let mut store = open_test_store(&path, Arc::clone(&backend));
        store.create_session(binding, [0x61; 32]).unwrap();
        let account = hex::encode(record_key_digest(&key).unwrap());
        backend.corrupt(&account);
        assert!(matches!(
            store.reserve_send_key(&key, RatchetLane::Message),
            Err(IndexedSessionStoreError::CorruptProtectedState)
        ));
        let generation: i64 = Connection::open(&path)
            .unwrap()
            .query_row("SELECT generation FROM indexed_session_heads", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(generation, 0);
    }

    #[test]
    fn protected_write_failure_rolls_back_without_consuming_index() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let binding = fixture_binding();
        let key = binding.key.clone();
        let mut store = open_test_store(&path, Arc::clone(&backend));
        store.create_session(binding, [0x51; 32]).unwrap();
        backend.fail_next_put();
        assert!(matches!(
            store.reserve_send_key(&key, RatchetLane::Message),
            Err(IndexedSessionStoreError::ProtectedStore(_))
        ));
        assert_eq!(
            store
                .reserve_send_key(&key, RatchetLane::Message)
                .unwrap()
                .index,
            0
        );
    }

    #[test]
    fn crash_after_protected_write_fast_forwards_and_never_reuses_key() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let binding = fixture_binding();
        let key = binding.key.clone();
        let mut store = open_test_store(&path, Arc::clone(&backend));
        store.create_session(binding, [0x31; 32]).unwrap();
        store.inject_crash_after_next_protected_write();
        assert!(matches!(
            store.reserve_send_key(&key, RatchetLane::Message),
            Err(IndexedSessionStoreError::InjectedCrashAfterProtectedWrite)
        ));
        drop(store);

        let mut reopened = open_test_store(&path, backend);
        let reservation = reopened
            .reserve_send_key(&key, RatchetLane::Message)
            .unwrap();
        assert_eq!(reservation.index, 1, "index zero was burned, never reused");
    }

    #[test]
    fn exact_pairinit_is_idempotent_but_init_id_hash_conflict_is_rejected() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let binding = fixture_binding();
        let mut store = open_test_store(&path, backend);
        store.create_session(binding.clone(), [0x21; 32]).unwrap();
        store.create_session(binding.clone(), [0x21; 32]).unwrap();

        let mut conflict = binding;
        conflict.init_hash[0] ^= 1;
        conflict.session_id = session_id(&conflict.init_hash);
        assert!(matches!(
            store.create_session(conflict.clone(), [0x21; 32]),
            Err(IndexedSessionStoreError::InitIdConflict)
        ));

        // The init ID is replay protection for this local identity, not merely
        // for one address/device tuple. Changing a device key must not evade
        // the signed-PairInit conflict check.
        conflict.key.responder_device_ed25519[0] ^= 1;
        assert!(matches!(
            store.create_session(conflict, [0x21; 32]),
            Err(IndexedSessionStoreError::InitIdConflict)
        ));
    }

    #[test]
    fn confirmation_is_monotonic_and_idempotent() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let binding = fixture_binding();
        let key = binding.key.clone();
        let mut store = open_test_store(&path, backend);
        store.create_session(binding.clone(), [0x12; 32]).unwrap();
        store.confirm_session(&key, [0x99; 32]).unwrap();
        store.confirm_session(&key, [0x99; 32]).unwrap();
        store
            .create_session(binding, [0x12; 32])
            .expect("exact PairInit replay remains idempotent after confirmation");
        assert!(matches!(
            store.confirm_session(&key, [0x98; 32]),
            Err(IndexedSessionStoreError::ConfirmationConflict)
        ));
    }

    #[test]
    fn verified_pairresponse_confirmation_rejects_forgery_mismatch_and_staleness() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let (init, response, root) = pair_init_vector();
        let binding = vector_binding(&init);
        let key = binding.key.clone();
        let mut store = open_test_store(&path, backend);
        store.create_session(binding, root).unwrap();
        let now = response.created_at_ms + 1;

        let mut bad_tag = response.clone();
        bad_tag.confirmation_tag[0] ^= 1;
        assert!(matches!(
            store.confirm_verified_pair_response(&key, &init, &bad_tag, now),
            Err(IndexedSessionStoreError::PairInit(
                PairInitError::ConfirmationMismatch
            ))
        ));
        let mut bad_signature = response.clone();
        bad_signature.signature[0] ^= 1;
        assert!(matches!(
            store.confirm_verified_pair_response(&key, &init, &bad_signature, now),
            Err(IndexedSessionStoreError::PairInit(
                PairInitError::BadSignature
            ))
        ));
        let mut wrong_init = init.clone();
        wrong_init.init_id[0] ^= 1;
        assert!(matches!(
            store.confirm_verified_pair_response(&key, &wrong_init, &response, now),
            Err(IndexedSessionStoreError::BindingConflict)
        ));
        assert!(matches!(
            store.confirm_verified_pair_response(&key, &init, &response, response.expires_at_ms,),
            Err(IndexedSessionStoreError::PairInit(
                PairInitError::ConfirmationMismatch
            ))
        ));

        store
            .confirm_verified_pair_response(&key, &init, &response, now)
            .unwrap();
        store
            .confirm_verified_pair_response(&key, &init, &response, now)
            .unwrap();
        let mut different = response.clone();
        different.expires_at_ms -= 1;
        assert!(store
            .confirm_verified_pair_response(&key, &init, &different, now)
            .is_err());
    }

    #[test]
    fn endpoint_message_flags_zero_skew_hint_replay_and_local_sealing() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let fixture = endpoint_fixture();
        let mut store = open_test_store(&path, Arc::clone(&backend));
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();
        let envelope =
            inbound_message_envelope(&fixture, 0, [0xC0; 16], b"future-skew\taccepted\n");
        assert_eq!(envelope.flags, 0);
        assert_eq!(envelope.dest_device_hint, 0);
        let packed = envelope.pack();
        let accepted = store
            .accept_message_envelope(
                &fixture.key,
                &packed,
                &fixture.remote_certificate,
                false,
                fixture.now_ms,
            )
            .unwrap();
        let digest = match accepted {
            EndpointAcceptance::Committed {
                object_digest,
                plaintext,
                ..
            } => {
                assert_eq!(plaintext, b"future-skew\taccepted\n");
                object_digest
            }
            _ => panic!("first acceptance must commit"),
        };
        assert!(matches!(
            store
                .accept_message_envelope(
                    &fixture.key,
                    &packed,
                    &fixture.remote_certificate,
                    false,
                    fixture.now_ms,
                )
                .unwrap(),
            EndpointAcceptance::Duplicate { .. }
        ));
        let inbox = store
            .load_endpoint_inbox(&fixture.key, &digest)
            .unwrap()
            .unwrap();
        assert_eq!(inbox.plaintext, b"future-skew\taccepted\n");
        assert_eq!(store.pending_endpoint_ack_intents().unwrap().len(), 1);

        store
            .conn
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .unwrap();
        let sqlite = std::fs::read(&path).unwrap();
        assert!(!sqlite
            .windows(inbox.plaintext.len())
            .any(|window| window == inbox.plaintext));
        for protected in backend.values.lock().unwrap().values() {
            assert!(!protected
                .windows(inbox.plaintext.len())
                .any(|window| window == inbox.plaintext));
        }
    }

    #[test]
    fn endpoint_message_negatives_do_not_advance_or_create_ack() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let fixture = endpoint_fixture();
        let mut store = open_test_store(&path, backend);
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();

        let mut wrong_route = inbound_message_envelope(&fixture, 0, [0xD0; 16], b"valid");
        wrong_route.routing_tag[0] ^= 1;
        wrong_route.sign_with(&fixture.remote_identity);
        assert!(matches!(
            store.accept_message_envelope(
                &fixture.key,
                &wrong_route.pack(),
                &fixture.remote_certificate,
                false,
                fixture.now_ms,
            ),
            Err(IndexedSessionStoreError::RouteTagMismatch)
        ));

        let mut wrong_hint = inbound_message_envelope(&fixture, 0, [0xD1; 16], b"valid");
        wrong_hint.dest_device_hint =
            endpoint_device_hint(&fixture.key.initiator_device_ed25519) ^ 1;
        assert!(matches!(
            store.accept_message_envelope(
                &fixture.key,
                &wrong_hint.pack(),
                &fixture.remote_certificate,
                false,
                fixture.now_ms,
            ),
            Err(IndexedSessionStoreError::DeviceHintMismatch)
        ));

        let mut tampered = inbound_message_envelope(&fixture, 0, [0xD2; 16], b"valid");
        let last = tampered.message_ciphertext.len() - 1;
        tampered.message_ciphertext[last] ^= 1;
        tampered.sign_with(&fixture.remote_identity);
        assert!(matches!(
            store.accept_message_envelope(
                &fixture.key,
                &tampered.pack(),
                &fixture.remote_certificate,
                false,
                fixture.now_ms,
            ),
            Err(IndexedSessionStoreError::AuthenticationFailed)
        ));

        let invalid_text = inbound_message_envelope(&fixture, 0, [0xD3; 16], b"bad\0text");
        assert!(matches!(
            store.accept_message_envelope(
                &fixture.key,
                &invalid_text.pack(),
                &fixture.remote_certificate,
                false,
                fixture.now_ms,
            ),
            Err(IndexedSessionStoreError::InvalidEndpointPayload)
        ));
        assert!(store.pending_endpoint_ack_intents().unwrap().is_empty());

        let valid = inbound_message_envelope(&fixture, 0, [0xD4; 16], b"ratchet-not-advanced");
        store
            .accept_message_envelope(
                &fixture.key,
                &valid.pack(),
                &fixture.remote_certificate,
                false,
                fixture.now_ms,
            )
            .unwrap();
    }

    #[test]
    fn endpoint_time_and_text_boundaries_are_exact() {
        let now = 1_700_000_000_000;
        assert!(endpoint_time_window_valid(
            now + MAX_ENDPOINT_FUTURE_SKEW_MS,
            now + MAX_ENDPOINT_FUTURE_SKEW_MS + 1,
            now,
        ));
        assert!(!endpoint_time_window_valid(
            now + MAX_ENDPOINT_FUTURE_SKEW_MS + 1,
            now + MAX_ENDPOINT_FUTURE_SKEW_MS + 2,
            now,
        ));
        assert!(endpoint_time_window_valid(
            now,
            now + MAX_ENDPOINT_ENVELOPE_LIFETIME_MS,
            now,
        ));
        assert!(!endpoint_time_window_valid(
            now,
            now + MAX_ENDPOINT_ENVELOPE_LIFETIME_MS + 1,
            now,
        ));
        // The expiry instant itself is already expired; the next millisecond
        // is the last valid one.
        assert!(!endpoint_time_window_valid(now - 1, now, now));
        assert!(endpoint_time_window_valid(now - 1, now + 1, now));
        // An envelope must expire strictly after it was created (checked in the
        // future so the not-yet-expired clause cannot reject it first).
        assert!(!endpoint_time_window_valid(now + 1, now + 1, now));
        assert!(endpoint_time_window_valid(now + 1, now + 2, now));
        assert!(!endpoint_time_window_valid(now + 2, now + 1, now));
        // Cutoff pack CP.7: the side value of this refusal is measured past
        // exactly the same instant.
        for created in [
            now + MAX_ENDPOINT_FUTURE_SKEW_MS,
            now + MAX_ENDPOINT_FUTURE_SKEW_MS + 1,
        ] {
            assert_eq!(
                crate::clock_skew::future_by_ms(created, now).is_some(),
                !endpoint_time_window_valid(created, created + 1, now),
                "created={created}"
            );
        }
        assert!(valid_endpoint_text(b"space tab\tline\nreturn\r"));
        assert!(!valid_endpoint_text(b"nul\0"));
        assert!(!valid_endpoint_text(b"escape\x1b"));
        assert!(!valid_endpoint_text(b"delete\x7f"));
        assert!(!valid_endpoint_text(&[0xFF]));
        assert!(!valid_endpoint_text(b""));
        assert!(valid_endpoint_text(&vec![b'a'; MAX_ENDPOINT_TEXT_BYTES]));
        assert!(!valid_endpoint_text(&vec![
            b'a';
            MAX_ENDPOINT_TEXT_BYTES + 1
        ]));
    }

    #[test]
    fn endpoint_rejects_provisional_session_until_pairresponse_confirmation() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let fixture = endpoint_fixture();
        let mut provisional = fixture.binding.clone();
        provisional.lifecycle = SessionLifecycle::Provisional;
        provisional.response_hash = None;
        let mut store = open_test_store(&path, backend);
        store.create_session(provisional, fixture.root).unwrap();
        let envelope = inbound_message_envelope(&fixture, 0, [0x70; 16], b"confirmed-only");
        assert!(matches!(
            store.accept_message_envelope(
                &fixture.key,
                &envelope.pack(),
                &fixture.remote_certificate,
                false,
                fixture.now_ms,
            ),
            Err(IndexedSessionStoreError::SessionNotConfirmed)
        ));
        store.confirm_session(&fixture.key, [0x46; 32]).unwrap();
        store
            .accept_message_envelope(
                &fixture.key,
                &envelope.pack(),
                &fixture.remote_certificate,
                false,
                fixture.now_ms,
            )
            .unwrap();
    }

    #[test]
    fn endpoint_out_of_order_collision_jump_revocation_and_wrong_session_fail_closed() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let fixture = endpoint_fixture();
        let mut store = open_test_store(&path, backend);
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();

        let index_two = inbound_message_envelope(&fixture, 2, [0x71; 16], b"index-two");
        store
            .accept_message_envelope(
                &fixture.key,
                &index_two.pack(),
                &fixture.remote_certificate,
                false,
                fixture.now_ms,
            )
            .unwrap();
        let index_zero = inbound_message_envelope(&fixture, 0, [0x72; 16], b"index-zero");
        store
            .accept_message_envelope(
                &fixture.key,
                &index_zero.pack(),
                &fixture.remote_certificate,
                false,
                fixture.now_ms,
            )
            .unwrap();

        let logical_first = inbound_message_envelope(&fixture, 1, [0x73; 16], b"first");
        store
            .accept_message_envelope(
                &fixture.key,
                &logical_first.pack(),
                &fixture.remote_certificate,
                false,
                fixture.now_ms,
            )
            .unwrap();
        let logical_conflict = inbound_message_envelope(&fixture, 3, [0x73; 16], b"second");
        assert!(matches!(
            store.accept_message_envelope(
                &fixture.key,
                &logical_conflict.pack(),
                &fixture.remote_certificate,
                false,
                fixture.now_ms,
            ),
            Err(IndexedSessionStoreError::LogicalMessageConflict)
        ));

        let jump = inbound_message_envelope(&fixture, 260, [0x74; 16], b"too-far");
        assert!(matches!(
            store.accept_message_envelope(
                &fixture.key,
                &jump.pack(),
                &fixture.remote_certificate,
                false,
                fixture.now_ms,
            ),
            Err(IndexedSessionStoreError::ForwardJumpTooLarge)
        ));
        let revoked = inbound_message_envelope(&fixture, 3, [0x75; 16], b"revoked");
        assert!(matches!(
            store.accept_message_envelope(
                &fixture.key,
                &revoked.pack(),
                &fixture.remote_certificate,
                true,
                fixture.now_ms,
            ),
            Err(IndexedSessionStoreError::RevokedDevice)
        ));
        let mut wrong_session_key = fixture.key.clone();
        wrong_session_key.init_id[0] ^= 1;
        assert!(matches!(
            store.accept_message_envelope(
                &wrong_session_key,
                &revoked.pack(),
                &fixture.remote_certificate,
                false,
                fixture.now_ms,
            ),
            Err(IndexedSessionStoreError::NotFound)
        ));
        assert_eq!(store.pending_endpoint_ack_intents().unwrap().len(), 3);
    }

    #[test]
    fn endpoint_message_crash_journal_recovers_before_ack_visibility() {
        {
            let temp = tempdir().unwrap();
            let path = temp.path().join("sessions.sqlite");
            let backend = Arc::new(MemoryProtectedBackend::default());
            let fixture = endpoint_fixture();
            let mut store = open_test_store(&path, Arc::clone(&backend));
            store
                .create_session(fixture.binding.clone(), fixture.root)
                .unwrap();
            let envelope = inbound_message_envelope(&fixture, 0, [0x59; 16], b"not-yet-durable");
            store.inject_endpoint_fault(EndpointFaultPoint::BeforeProtectedReplacement);
            assert!(matches!(
                store.accept_message_envelope(
                    &fixture.key,
                    &envelope.pack(),
                    &fixture.remote_certificate,
                    false,
                    fixture.now_ms,
                ),
                Err(IndexedSessionStoreError::InjectedEndpointFailure(_))
            ));
            drop(store);
            let mut reopened = open_test_store(&path, backend);
            assert!(reopened.pending_endpoint_ack_intents().unwrap().is_empty());
            reopened
                .accept_message_envelope(
                    &fixture.key,
                    &envelope.pack(),
                    &fixture.remote_certificate,
                    false,
                    fixture.now_ms,
                )
                .unwrap();
        }
        for point in [
            EndpointFaultPoint::AfterProtectedReplacement,
            EndpointFaultPoint::BeforeDatabaseCommit,
            EndpointFaultPoint::AfterDatabaseCommit,
            EndpointFaultPoint::BeforeJournalClear,
        ] {
            let temp = tempdir().unwrap();
            let path = temp.path().join("sessions.sqlite");
            let backend = Arc::new(MemoryProtectedBackend::default());
            let fixture = endpoint_fixture();
            let mut store = open_test_store(&path, Arc::clone(&backend));
            store
                .create_session(fixture.binding.clone(), fixture.root)
                .unwrap();
            let envelope = inbound_message_envelope(&fixture, 0, [point as u8; 16], b"recover-me");
            store.inject_endpoint_fault(point);
            assert!(matches!(
                store.accept_message_envelope(
                    &fixture.key,
                    &envelope.pack(),
                    &fixture.remote_certificate,
                    false,
                    fixture.now_ms,
                ),
                Err(IndexedSessionStoreError::InjectedEndpointFailure(_))
            ));
            drop(store);
            let reopened = open_test_store(&path, backend);
            assert_eq!(reopened.pending_endpoint_ack_intents().unwrap().len(), 1);
            let receipts: i64 = reopened
                .conn
                .query_row("SELECT COUNT(*) FROM endpoint_receipts", [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(receipts, 1);
        }

        {
            let temp = tempdir().unwrap();
            let path = temp.path().join("sessions.sqlite");
            let backend = Arc::new(MemoryProtectedBackend::default());
            let fixture = endpoint_fixture();
            let mut store = open_test_store(&path, Arc::clone(&backend));
            store
                .create_session(fixture.binding.clone(), fixture.root)
                .unwrap();
            let envelope = inbound_message_envelope(&fixture, 0, [0x5A; 16], b"protected-fail");
            backend.fail_next_put();
            assert!(matches!(
                store.accept_message_envelope(
                    &fixture.key,
                    &envelope.pack(),
                    &fixture.remote_certificate,
                    false,
                    fixture.now_ms,
                ),
                Err(IndexedSessionStoreError::ProtectedStore(_))
            ));
            assert!(store.pending_endpoint_ack_intents().unwrap().is_empty());
            store
                .accept_message_envelope(
                    &fixture.key,
                    &envelope.pack(),
                    &fixture.remote_certificate,
                    false,
                    fixture.now_ms,
                )
                .unwrap();
        }
    }

    #[test]
    fn ack_acceptance_binds_outstanding_row_and_is_monotonic() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let fixture = endpoint_fixture();
        let mut store = open_test_store(&path, Arc::clone(&backend));
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();
        let outbound_id = [0xE0; 16];
        store
            .register_outstanding_message(&fixture.key, &outbound_id)
            .unwrap();
        let delivered = inbound_ack_envelope(&fixture, 0, [0xE1; 16], outbound_id, 1, [0xE2; 12]);
        assert_eq!(delivered.flags, 0);
        assert!(matches!(
            store
                .accept_ack_envelope(
                    &fixture.key,
                    &delivered.pack(),
                    &fixture.remote_certificate,
                    false,
                    fixture.now_ms,
                )
                .unwrap(),
            EndpointAckAcceptance::Committed {
                delivery_state: EndpointDeliveryState::Delivered,
                ..
            }
        ));
        assert!(matches!(
            store
                .accept_ack_envelope(
                    &fixture.key,
                    &delivered.pack(),
                    &fixture.remote_certificate,
                    false,
                    fixture.now_ms,
                )
                .unwrap(),
            EndpointAckAcceptance::Duplicate { .. }
        ));
        let read = inbound_ack_envelope(&fixture, 1, [0xE3; 16], outbound_id, 2, [0xE4; 12]);
        store
            .accept_ack_envelope(
                &fixture.key,
                &read.pack(),
                &fixture.remote_certificate,
                false,
                fixture.now_ms,
            )
            .unwrap();
        let delivery_state = |store: &IndexedSessionStore| {
            store
                .outstanding_delivery_state(
                    &fixture.binding.session_id,
                    &outbound_id,
                    &fixture.key.responder_device_ed25519,
                )
                .unwrap()
        };
        assert_eq!(delivery_state(&store), Some(EndpointDeliveryState::Read));

        // A late, reordered "delivered" ACK (fresh outer id, nonce and ACK
        // index) is authentic and accepted, but must not regress a message
        // that was already read.
        let late_delivered =
            inbound_ack_envelope(&fixture, 2, [0xE5; 16], outbound_id, 1, [0xE6; 12]);
        assert!(matches!(
            store
                .accept_ack_envelope(
                    &fixture.key,
                    &late_delivered.pack(),
                    &fixture.remote_certificate,
                    false,
                    fixture.now_ms,
                )
                .unwrap(),
            EndpointAckAcceptance::Committed {
                delivery_state: EndpointDeliveryState::Read,
                ..
            }
        ));
        assert_eq!(delivery_state(&store), Some(EndpointDeliveryState::Read));
        assert!(matches!(
            store
                .accept_ack_envelope(
                    &fixture.key,
                    &late_delivered.pack(),
                    &fixture.remote_certificate,
                    false,
                    fixture.now_ms,
                )
                .unwrap(),
            EndpointAckAcceptance::Duplicate {
                delivery_state: EndpointDeliveryState::Read,
                ..
            }
        ));
        assert_eq!(delivery_state(&store), Some(EndpointDeliveryState::Read));
    }

    #[test]
    fn ack_acceptance_journal_recovers_and_nonce_conflict_does_not_advance() {
        {
            let temp = tempdir().unwrap();
            let path = temp.path().join("sessions.sqlite");
            let backend = Arc::new(MemoryProtectedBackend::default());
            let fixture = endpoint_fixture();
            let mut store = open_test_store(&path, Arc::clone(&backend));
            store
                .create_session(fixture.binding.clone(), fixture.root)
                .unwrap();
            let outbound = [0x5B; 16];
            store
                .register_outstanding_message(&fixture.key, &outbound)
                .unwrap();
            let ack = inbound_ack_envelope(&fixture, 0, [0x5C; 16], outbound, 1, [0x5D; 12]);
            store.inject_endpoint_fault(EndpointFaultPoint::BeforeProtectedReplacement);
            assert!(matches!(
                store.accept_ack_envelope(
                    &fixture.key,
                    &ack.pack(),
                    &fixture.remote_certificate,
                    false,
                    fixture.now_ms,
                ),
                Err(IndexedSessionStoreError::InjectedEndpointFailure(_))
            ));
            drop(store);
            let mut reopened = open_test_store(&path, backend);
            assert_eq!(
                reopened
                    .outstanding_delivery_state(
                        &fixture.binding.session_id,
                        &outbound,
                        &fixture.key.responder_device_ed25519,
                    )
                    .unwrap(),
                Some(EndpointDeliveryState::Sent)
            );
            reopened
                .accept_ack_envelope(
                    &fixture.key,
                    &ack.pack(),
                    &fixture.remote_certificate,
                    false,
                    fixture.now_ms,
                )
                .unwrap();
        }
        for point in [
            EndpointFaultPoint::AfterProtectedReplacement,
            EndpointFaultPoint::BeforeDatabaseCommit,
            EndpointFaultPoint::AfterDatabaseCommit,
            EndpointFaultPoint::BeforeJournalClear,
            EndpointFaultPoint::AfterJournalClear,
        ] {
            let temp = tempdir().unwrap();
            let path = temp.path().join("sessions.sqlite");
            let backend = Arc::new(MemoryProtectedBackend::default());
            let fixture = endpoint_fixture();
            let mut store = open_test_store(&path, Arc::clone(&backend));
            store
                .create_session(fixture.binding.clone(), fixture.root)
                .unwrap();
            let outbound = [point as u8; 16];
            store
                .register_outstanding_message(&fixture.key, &outbound)
                .unwrap();
            let ack = inbound_ack_envelope(&fixture, 0, [0x61; 16], outbound, 1, [0x62; 12]);
            store.inject_endpoint_fault(point);
            assert!(matches!(
                store.accept_ack_envelope(
                    &fixture.key,
                    &ack.pack(),
                    &fixture.remote_certificate,
                    false,
                    fixture.now_ms,
                ),
                Err(IndexedSessionStoreError::InjectedEndpointFailure(_))
            ));
            drop(store);
            let reopened = open_test_store(&path, backend);
            assert_eq!(
                reopened
                    .outstanding_delivery_state(
                        &fixture.binding.session_id,
                        &outbound,
                        &fixture.key.responder_device_ed25519,
                    )
                    .unwrap(),
                Some(EndpointDeliveryState::Delivered)
            );
        }

        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let fixture = endpoint_fixture();
        let mut store = open_test_store(&path, backend);
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();
        let outbound = [0x63; 16];
        store
            .register_outstanding_message(&fixture.key, &outbound)
            .unwrap();
        let first = inbound_ack_envelope(&fixture, 0, [0x64; 16], outbound, 1, [0x65; 12]);
        store
            .accept_ack_envelope(
                &fixture.key,
                &first.pack(),
                &fixture.remote_certificate,
                false,
                fixture.now_ms,
            )
            .unwrap();
        let conflict = inbound_ack_envelope(&fixture, 1, [0x66; 16], outbound, 2, [0x65; 12]);
        assert!(matches!(
            store.accept_ack_envelope(
                &fixture.key,
                &conflict.pack(),
                &fixture.remote_certificate,
                false,
                fixture.now_ms,
            ),
            Err(IndexedSessionStoreError::AckNonceConflict)
        ));
        let valid = inbound_ack_envelope(&fixture, 1, [0x67; 16], outbound, 2, [0x68; 12]);
        store
            .accept_ack_envelope(
                &fixture.key,
                &valid.pack(),
                &fixture.remote_certificate,
                false,
                fixture.now_ms,
            )
            .unwrap();
    }

    #[test]
    fn ack_negatives_do_not_advance_and_enqueue_reuses_immutable_bytes() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let fixture = endpoint_fixture();
        let mut store = open_test_store(&path, backend);
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();
        let outbound_id = [0xF0; 16];
        let unknown = inbound_ack_envelope(&fixture, 0, [0xF1; 16], outbound_id, 1, [0xF2; 12]);
        assert!(matches!(
            store.accept_ack_envelope(
                &fixture.key,
                &unknown.pack(),
                &fixture.remote_certificate,
                false,
                fixture.now_ms,
            ),
            Err(IndexedSessionStoreError::AckOutstandingMismatch)
        ));
        store
            .register_outstanding_message(&fixture.key, &outbound_id)
            .unwrap();
        store
            .accept_ack_envelope(
                &fixture.key,
                &unknown.pack(),
                &fixture.remote_certificate,
                false,
                fixture.now_ms,
            )
            .unwrap();

        let message = inbound_message_envelope(&fixture, 0, [0xF3; 16], b"ack-intent");
        let accepted = store
            .accept_message_envelope(
                &fixture.key,
                &message.pack(),
                &fixture.remote_certificate,
                false,
                fixture.now_ms,
            )
            .unwrap();
        let digest = match accepted {
            EndpointAcceptance::Committed { object_digest, .. } => object_digest,
            _ => unreachable!(),
        };
        let layout = store.layout.clone();
        let sid = fixture.binding.session_id;
        let persisted = |digest: &[u8; 32]| -> (i64, Option<Vec<u8>>) {
            let row = endpoints::ack_intent_by_object(
                &Connection::open(&path).unwrap(),
                &layout,
                &sid,
                digest,
            )
            .unwrap()
            .unwrap();
            (row.state, row.immutable_ack_bytes)
        };
        const ACK_BYTES: &[u8] = b"immutable-ack-envelope";
        const OTHER_BYTES: &[u8] = b"a different ack envelope";
        let pending_state = EndpointAckIntentState::Pending as i64;
        let queued_state = EndpointAckIntentState::Queued as i64;

        store.inject_endpoint_fault(EndpointFaultPoint::AfterAckEnqueue);
        let mut enqueued = Vec::new();
        assert!(matches!(
            store.enqueue_endpoint_ack(&fixture.binding.session_id, &digest, ACK_BYTES, |bytes| {
                enqueued.push(bytes.to_vec());
                Ok(())
            }),
            Err(IndexedSessionStoreError::InjectedEndpointFailure(_))
        ));
        assert_eq!(
            persisted(&digest),
            (pending_state, Some(ACK_BYTES.to_vec())),
            "the bytes are persisted before the queue is invoked"
        );
        assert!(matches!(
            store.enqueue_endpoint_ack(&fixture.binding.session_id, &digest, ACK_BYTES, |_| Err(
                "injected queue failure".into()
            )),
            Err(IndexedSessionStoreError::AckEnqueue)
        ));
        store
            .enqueue_endpoint_ack(&fixture.binding.session_id, &digest, ACK_BYTES, |bytes| {
                enqueued.push(bytes.to_vec());
                Ok(())
            })
            .unwrap();
        assert_eq!(
            enqueued,
            vec![ACK_BYTES.to_vec(), ACK_BYTES.to_vec()],
            "every retry hands the queue the exact persisted bytes"
        );
        assert_eq!(persisted(&digest), (queued_state, Some(ACK_BYTES.to_vec())));

        // A Queued intent is immutable: different bytes conflict, never reach
        // the queue and never overwrite the stored ones.
        let mut queue_invoked = false;
        assert!(matches!(
            store.enqueue_endpoint_ack(&fixture.binding.session_id, &digest, OTHER_BYTES, |_| {
                queue_invoked = true;
                Ok(())
            }),
            Err(IndexedSessionStoreError::AckBytesConflict)
        ));
        assert!(!queue_invoked);
        assert_eq!(persisted(&digest), (queued_state, Some(ACK_BYTES.to_vec())));

        // The same holds while the intent is still Pending with its bytes
        // already persisted (a crash before the queue call).
        let second = inbound_message_envelope(&fixture, 1, [0xF4; 16], b"second ack-intent");
        let second_digest = match store
            .accept_message_envelope(
                &fixture.key,
                &second.pack(),
                &fixture.remote_certificate,
                false,
                fixture.now_ms,
            )
            .unwrap()
        {
            EndpointAcceptance::Committed { object_digest, .. } => object_digest,
            _ => unreachable!(),
        };
        store.inject_endpoint_fault(EndpointFaultPoint::BeforeAckEnqueue);
        assert!(matches!(
            store.enqueue_endpoint_ack(
                &fixture.binding.session_id,
                &second_digest,
                ACK_BYTES,
                |_| {
                    queue_invoked = true;
                    Ok(())
                }
            ),
            Err(IndexedSessionStoreError::InjectedEndpointFailure(_))
        ));
        assert!(!queue_invoked);
        assert_eq!(
            persisted(&second_digest),
            (pending_state, Some(ACK_BYTES.to_vec()))
        );
        assert!(matches!(
            store.enqueue_endpoint_ack(
                &fixture.binding.session_id,
                &second_digest,
                OTHER_BYTES,
                |_| {
                    queue_invoked = true;
                    Ok(())
                }
            ),
            Err(IndexedSessionStoreError::AckBytesConflict)
        ));
        assert!(!queue_invoked);
        assert_eq!(
            persisted(&second_digest),
            (pending_state, Some(ACK_BYTES.to_vec()))
        );
        let mut retried = Vec::new();
        store
            .enqueue_endpoint_ack(
                &fixture.binding.session_id,
                &second_digest,
                ACK_BYTES,
                |bytes| {
                    retried.push(bytes.to_vec());
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(retried, vec![ACK_BYTES.to_vec()]);
        assert_eq!(
            persisted(&second_digest),
            (queued_state, Some(ACK_BYTES.to_vec()))
        );
    }

    #[test]
    fn ack_authentication_negatives_never_advance_the_ratchet_or_delivery_row() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let fixture = endpoint_fixture();
        let mut store = open_test_store(&path, backend);
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();
        let outbound = [0x31; 16];
        store
            .register_outstanding_message(&fixture.key, &outbound)
            .unwrap();

        let mut bad_outer = inbound_ack_envelope(&fixture, 0, [0x32; 16], outbound, 1, [0x33; 12]);
        bad_outer.sender_authentication[0] ^= 1;
        assert!(matches!(
            store.accept_ack_envelope(
                &fixture.key,
                &bad_outer.pack(),
                &fixture.remote_certificate,
                false,
                fixture.now_ms,
            ),
            Err(IndexedSessionStoreError::OuterSignatureInvalid)
        ));

        let valid = inbound_ack_envelope(&fixture, 0, [0x34; 16], outbound, 1, [0x35; 12]);
        assert!(matches!(
            store.accept_ack_envelope(
                &fixture.key,
                &valid.pack(),
                &fixture.remote_certificate,
                true,
                fixture.now_ms,
            ),
            Err(IndexedSessionStoreError::RevokedDevice)
        ));
        let wrong_identity = Identity::from_seed(&[0x36; 32]);
        let wrong_user = Identity::from_seed(&[0x37; 32]);
        let wrong_certificate = DeviceCertificate::issue(
            &wrong_user,
            wrong_identity.public_key_bytes(),
            [0x38; 32],
            "wrong-device",
            fixture.now_ms - 1,
            fixture.now_ms + 60_000,
            1,
        )
        .unwrap();
        assert!(matches!(
            store.accept_ack_envelope(
                &fixture.key,
                &valid.pack(),
                &wrong_certificate,
                false,
                fixture.now_ms,
            ),
            Err(IndexedSessionStoreError::DeviceBindingMismatch)
        ));

        let mut wrong_route = valid.clone();
        wrong_route.routing_tag[0] ^= 1;
        wrong_route.sign_with(&fixture.remote_identity);
        assert!(matches!(
            store.accept_ack_envelope(
                &fixture.key,
                &wrong_route.pack(),
                &fixture.remote_certificate,
                false,
                fixture.now_ms,
            ),
            Err(IndexedSessionStoreError::RouteTagMismatch)
        ));
        let mut wrong_hint = valid.clone();
        wrong_hint.dest_device_hint ^= 1;
        assert!(matches!(
            store.accept_ack_envelope(
                &fixture.key,
                &wrong_hint.pack(),
                &fixture.remote_certificate,
                false,
                fixture.now_ms,
            ),
            Err(IndexedSessionStoreError::DeviceHintMismatch)
        ));
        let mut tampered_aead = valid.clone();
        let last = tampered_aead.message_ciphertext.len() - 1;
        tampered_aead.message_ciphertext[last] ^= 1;
        tampered_aead.sign_with(&fixture.remote_identity);
        assert!(matches!(
            store.accept_ack_envelope(
                &fixture.key,
                &tampered_aead.pack(),
                &fixture.remote_certificate,
                false,
                fixture.now_ms,
            ),
            Err(IndexedSessionStoreError::AuthenticationFailed)
        ));
        let mut wrong_aad = valid.clone();
        wrong_aad.message_id[0] ^= 1;
        wrong_aad.sign_with(&fixture.remote_identity);
        assert!(matches!(
            store.accept_ack_envelope(
                &fixture.key,
                &wrong_aad.pack(),
                &fixture.remote_certificate,
                false,
                fixture.now_ms,
            ),
            Err(IndexedSessionStoreError::AuthenticationFailed)
        ));

        let zero_inner = custom_inbound_ack_envelope(
            &fixture,
            0,
            [0x38; 16],
            outbound,
            1,
            [0x39; 12],
            fixture.now_ms,
            None,
        );
        assert!(matches!(
            store.accept_ack_envelope(
                &fixture.key,
                &zero_inner.pack(),
                &fixture.remote_certificate,
                false,
                fixture.now_ms,
            ),
            Err(IndexedSessionStoreError::AckInnerSignatureInvalid)
        ));

        let wrong_inner = custom_inbound_ack_envelope(
            &fixture,
            0,
            [0x39; 16],
            outbound,
            1,
            [0x3A; 12],
            fixture.now_ms,
            Some(&wrong_identity),
        );
        assert!(matches!(
            store.accept_ack_envelope(
                &fixture.key,
                &wrong_inner.pack(),
                &fixture.remote_certificate,
                false,
                fixture.now_ms,
            ),
            Err(IndexedSessionStoreError::AckInnerSignatureInvalid)
        ));
        let wrong_timestamp = custom_inbound_ack_envelope(
            &fixture,
            0,
            [0x3B; 16],
            outbound,
            1,
            [0x3C; 12],
            fixture.now_ms - 1,
            Some(&fixture.remote_identity),
        );
        assert!(matches!(
            store.accept_ack_envelope(
                &fixture.key,
                &wrong_timestamp.pack(),
                &fixture.remote_certificate,
                false,
                fixture.now_ms,
            ),
            Err(IndexedSessionStoreError::AckTimestampMismatch)
        ));
        let invalid_status = custom_inbound_ack_envelope(
            &fixture,
            0,
            [0x3D; 16],
            outbound,
            3,
            [0x3E; 12],
            fixture.now_ms,
            Some(&fixture.remote_identity),
        );
        assert!(matches!(
            store.accept_ack_envelope(
                &fixture.key,
                &invalid_status.pack(),
                &fixture.remote_certificate,
                false,
                fixture.now_ms,
            ),
            Err(IndexedSessionStoreError::InvalidIndexedMessage)
        ));
        let jump = inbound_ack_envelope(&fixture, 257, [0x3F; 16], outbound, 1, [0x40; 12]);
        assert!(matches!(
            store.accept_ack_envelope(
                &fixture.key,
                &jump.pack(),
                &fixture.remote_certificate,
                false,
                fixture.now_ms,
            ),
            Err(IndexedSessionStoreError::ForwardJumpTooLarge)
        ));
        let mut stale = valid.clone();
        stale.created_at = fixture.now_ms - 120_000;
        stale.expires_at = fixture.now_ms - 60_000;
        stale.routing_tag = derive_route_tag(
            &fixture.root,
            stale.created_at,
            0,
            EnvType::Ack as u8,
            Direction::ResponderToInitiator,
        )
        .unwrap();
        stale.sign_with(&fixture.remote_identity);
        assert!(matches!(
            store.accept_ack_envelope(
                &fixture.key,
                &stale.pack(),
                &fixture.remote_certificate,
                false,
                fixture.now_ms,
            ),
            Err(IndexedSessionStoreError::EndpointNotCurrentlyValid)
        ));
        assert_eq!(
            store
                .outstanding_delivery_state(
                    &fixture.binding.session_id,
                    &outbound,
                    &fixture.key.responder_device_ed25519,
                )
                .unwrap(),
            Some(EndpointDeliveryState::Sent)
        );
        store
            .accept_ack_envelope(
                &fixture.key,
                &valid.pack(),
                &fixture.remote_certificate,
                false,
                fixture.now_ms,
            )
            .unwrap();
        assert!(matches!(
            store.accept_ack_envelope(
                &fixture.key,
                &inbound_ack_envelope(&fixture, 0, [0x41; 16], outbound, 1, [0x42; 12],).pack(),
                &fixture.remote_certificate,
                false,
                fixture.now_ms,
            ),
            Err(IndexedSessionStoreError::Replay)
        ));
    }

    #[test]
    fn outbound_message_commits_exact_ciphertext_and_outstanding_binding() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let fixture = endpoint_fixture();
        let local_device = authorized_local_device(&fixture);
        let mut store = open_test_store(&path, backend.clone());
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();
        let mut rng = StdRng::from_seed([0x61; 32]);
        let mut queued = Vec::new();
        let outbound = {
            let mut queue = |digest: &[u8; 32], bytes: &[u8]| {
                queued.push((*digest, bytes.to_vec()));
                Ok(*digest)
            };
            store
                .send_message_envelope(
                    &fixture.key,
                    "outbound exact text",
                    &local_device,
                    fixture.now_ms,
                    fixture.now_ms + 60_000,
                    fixture.now_ms,
                    &mut rng,
                    &mut queue,
                )
                .unwrap()
        };

        assert_eq!(outbound.kind, EndpointOutboundKind::Message);
        assert_eq!(outbound.state, EndpointOutboxState::Queued);
        assert_eq!(outbound.ratchet_index, 0);
        assert_eq!(
            queued,
            vec![(
                outbound.object_digest,
                outbound.immutable_envelope_bytes.clone()
            )]
        );
        let envelope = Envelope::unpack(&outbound.immutable_envelope_bytes).unwrap();
        assert_eq!(envelope.env_type, EnvType::Message as u8);
        assert_eq!(envelope.flags, OUTBOUND_FLAGS);
        // F1: no recipient-identifying hint on new outbound envelopes.
        assert_eq!(envelope.dest_device_hint, OUTBOUND_DEST_DEVICE_HINT);
        assert_eq!(envelope.dest_device_hint, 0);
        assert!(envelope.verify(&fixture.local_identity.public_key_bytes()));
        let key = message_key_at_index(
            &fixture.root,
            &fixture.key.initiator_address,
            &fixture.key.responder_address,
            Direction::InitiatorToResponder,
            0,
        )
        .unwrap();
        assert_eq!(
            open_indexed_message_with_key(
                &key,
                &fixture.key.initiator_address,
                &fixture.key.responder_address,
                Direction::InitiatorToResponder,
                &envelope.message_id,
                &envelope.message_ciphertext,
            )
            .unwrap(),
            b"outbound exact text"
        );
        assert_eq!(
            store
                .outstanding_delivery_state(
                    &fixture.binding.session_id,
                    &outbound.message_id,
                    &fixture.key.responder_device_ed25519,
                )
                .unwrap(),
            Some(EndpointDeliveryState::Sent)
        );
        assert!(store.pending_endpoint_outbound().unwrap().is_empty());
        let protected = backend
            .get(&hex::encode(record_key_digest(&fixture.key).unwrap()))
            .unwrap()
            .unwrap();
        assert!(!protected
            .windows(b"outbound exact text".len())
            .any(|window| window == b"outbound exact text"));
    }

    #[test]
    fn awaiting_ack_resend_uses_session_key_and_abandon_clears_expired() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let fixture = endpoint_fixture();
        let local_device = authorized_local_device(&fixture);
        let mut store = open_test_store(&path, backend);
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();
        let mut rng = StdRng::from_seed([0x62; 32]);
        let mut dials = 0u32;
        let outbound = store
            .send_message_envelope(
                &fixture.key,
                "awaiting ack",
                &local_device,
                fixture.now_ms,
                fixture.now_ms + 60_000,
                fixture.now_ms,
                &mut rng,
                &mut |digest, bytes| {
                    dials += 1;
                    assert!(!bytes.is_empty());
                    Ok(*digest)
                },
            )
            .unwrap();
        assert_eq!(dials, 1);
        let awaiting = store.awaiting_ack_endpoint_outbound().unwrap();
        assert_eq!(awaiting.len(), 1);
        assert_eq!(awaiting[0].object_digest, outbound.object_digest);
        let resolved = store
            .record_key_for_session_id(&awaiting[0].session_id)
            .unwrap()
            .unwrap();
        assert_eq!(resolved, fixture.key);

        let resent = store
            .resend_queued_endpoint_outbound(
                &resolved,
                &outbound.object_digest,
                &local_device,
                fixture.now_ms,
                &mut |digest, bytes| {
                    dials += 1;
                    assert_eq!(bytes, outbound.immutable_envelope_bytes.as_slice());
                    Ok(*digest)
                },
            )
            .unwrap();
        assert_eq!(dials, 2);
        assert_eq!(
            resent.immutable_envelope_bytes,
            outbound.immutable_envelope_bytes
        );

        assert!(matches!(
            store.resend_queued_endpoint_outbound(
                &fixture.key,
                &outbound.object_digest,
                &local_device,
                fixture.now_ms + 120_000,
                &mut |digest, _| Ok(*digest),
            ),
            Err(IndexedSessionStoreError::EndpointNotCurrentlyValid)
        ));
        assert!(store
            .abandon_undelivered_outbound(&fixture.key, &outbound.object_digest)
            .unwrap());
        assert!(store.awaiting_ack_endpoint_outbound().unwrap().is_empty());
        assert!(store.pending_endpoint_outbound().unwrap().is_empty());
        let conn = Connection::open(&path).unwrap();
        let outbox_left: i64 = conn
            .query_row(
                &store
                    .layout
                    .ep("SELECT COUNT(*) FROM endpoint_outbox WHERE kh_object_digest = ?1"),
                params![store.layout.ep_digest(&outbound.object_digest)],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(outbox_left, 0);
        assert_eq!(
            store
                .outstanding_delivery_state(
                    &fixture.binding.session_id,
                    &outbound.message_id,
                    &fixture.key.responder_device_ed25519,
                )
                .unwrap(),
            None
        );
        assert_eq!(outbound.ratchet_index, 0);
        let mut next_queue = |digest: &[u8; 32], _bytes: &[u8]| Ok(*digest);
        let next = store
            .send_message_envelope(
                &fixture.key,
                "after queued abandon",
                &local_device,
                fixture.now_ms,
                fixture.now_ms + 60_000,
                fixture.now_ms,
                &mut rng,
                &mut next_queue,
            )
            .unwrap();
        assert_eq!(
            next.ratchet_index,
            outbound.ratchet_index + 1,
            "an abandoned index stays consumed; its message key is never reused"
        );
    }

    #[test]
    fn pending_outbound_filter_is_recipient_scoped() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let fixture = endpoint_fixture();
        let local_device = authorized_local_device(&fixture);
        let mut store = open_test_store(&path, backend);
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();
        let mut rng = StdRng::from_seed([0x63; 32]);
        let mut fail_queue = |_digest: &[u8; 32], _bytes: &[u8]| Err(());
        assert!(matches!(
            store.send_message_envelope(
                &fixture.key,
                "bob pending",
                &local_device,
                fixture.now_ms,
                fixture.now_ms + 60_000,
                fixture.now_ms,
                &mut rng,
                &mut fail_queue,
            ),
            Err(IndexedSessionStoreError::OutboundQueueHandoff)
        ));
        let bob = fixture.key.responder_device_ed25519;
        let carol = [0xCAu8; 32];
        assert_eq!(
            store
                .pending_endpoint_outbound_for_recipient(Some(&bob))
                .unwrap()
                .len(),
            1
        );
        assert!(store
            .pending_endpoint_outbound_for_recipient(Some(&carol))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn abandon_prepared_outbound_unblocks_next_send() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let fixture = endpoint_fixture();
        let local_device = authorized_local_device(&fixture);
        let mut store = open_test_store(&path, backend);
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();
        let mut rng = StdRng::from_seed([0x64; 32]);
        let mut fail_queue = |_digest: &[u8; 32], _bytes: &[u8]| Err(());
        assert!(matches!(
            store.send_message_envelope(
                &fixture.key,
                "prepared leftover",
                &local_device,
                fixture.now_ms,
                fixture.now_ms + 60_000,
                fixture.now_ms,
                &mut rng,
                &mut fail_queue,
            ),
            Err(IndexedSessionStoreError::OutboundQueueHandoff)
        ));
        let pending = store.pending_endpoint_outbound().unwrap().remove(0);
        assert_eq!(pending.state, EndpointOutboxState::Prepared);
        let abandoned_index = pending.ratchet_index;
        assert_eq!(abandoned_index, 0);
        assert!(store
            .abandon_undelivered_outbound(&fixture.key, &pending.object_digest)
            .unwrap());
        assert!(store.pending_endpoint_outbound().unwrap().is_empty());
        let mut ok_queue = |digest: &[u8; 32], _bytes: &[u8]| Ok(*digest);
        let next = store
            .send_message_envelope(
                &fixture.key,
                "after abandon",
                &local_device,
                fixture.now_ms,
                fixture.now_ms + 60_000,
                fixture.now_ms,
                &mut rng,
                &mut ok_queue,
            )
            .unwrap();
        assert_eq!(next.state, EndpointOutboxState::Queued);
        assert_ne!(next.object_digest, pending.object_digest);
        assert_eq!(
            next.ratchet_index,
            abandoned_index + 1,
            "an abandoned index stays consumed; its message key is never reused"
        );
    }

    #[test]
    fn abandon_propagates_protected_corruption() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let fixture = endpoint_fixture();
        let local_device = authorized_local_device(&fixture);
        let mut store = open_test_store(&path, Arc::clone(&backend));
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();
        let mut rng = StdRng::from_seed([0x65; 32]);
        let mut fail_queue = |_digest: &[u8; 32], _bytes: &[u8]| Err(());
        assert!(matches!(
            store.send_message_envelope(
                &fixture.key,
                "corrupt abandon",
                &local_device,
                fixture.now_ms,
                fixture.now_ms + 60_000,
                fixture.now_ms,
                &mut rng,
                &mut fail_queue,
            ),
            Err(IndexedSessionStoreError::OutboundQueueHandoff)
        ));
        let pending = store.pending_endpoint_outbound().unwrap().remove(0);
        let message_id = pending.message_id;
        let account = hex::encode(record_key_digest(&fixture.key).unwrap());
        backend.corrupt(&account);
        assert!(matches!(
            store.abandon_undelivered_outbound(&fixture.key, &pending.object_digest),
            Err(IndexedSessionStoreError::CorruptProtectedState)
        ));
        // The refusal happens before any delete: the prepared object and its
        // outstanding row are still there for a later, healthy retry.
        assert_eq!(store.pending_endpoint_outbound().unwrap(), vec![pending]);
        assert_eq!(
            store
                .outstanding_delivery_state(
                    &fixture.binding.session_id,
                    &message_id,
                    &fixture.key.responder_device_ed25519,
                )
                .unwrap(),
            Some(EndpointDeliveryState::Sent)
        );
    }

    #[test]
    fn ack_worker_uses_only_committed_intent_and_independent_lane() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let fixture = endpoint_fixture();
        let local_device = authorized_local_device(&fixture);
        let mut store = open_test_store(&path, backend);
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();
        let inbound_id = [0x71; 16];
        let inbound = inbound_message_envelope(&fixture, 0, inbound_id, b"please acknowledge");
        let accepted = store
            .accept_message_envelope(
                &fixture.key,
                &inbound.pack(),
                &fixture.remote_certificate,
                false,
                fixture.now_ms,
            )
            .unwrap();
        let intent_digest = match accepted {
            EndpointAcceptance::Committed { object_digest, .. } => object_digest,
            _ => unreachable!(),
        };

        let mut message_rng = StdRng::from_seed([0x72; 32]);
        let mut discard_queue = |digest: &[u8; 32], _bytes: &[u8]| Ok(*digest);
        let message = store
            .send_message_envelope(
                &fixture.key,
                "message lane zero",
                &local_device,
                fixture.now_ms,
                fixture.now_ms + 60_000,
                fixture.now_ms,
                &mut message_rng,
                &mut discard_queue,
            )
            .unwrap();
        assert_eq!(message.ratchet_index, 0);

        let mut ack_rng = StdRng::from_seed([0x73; 32]);
        let mut ack_queue = |digest: &[u8; 32], _bytes: &[u8]| Ok(*digest);
        let ack = store
            .enqueue_committed_ack(
                &fixture.key,
                &intent_digest,
                &local_device,
                fixture.now_ms,
                fixture.now_ms + 60_000,
                fixture.now_ms,
                &mut ack_rng,
                &mut ack_queue,
            )
            .unwrap();
        assert_eq!(ack.kind, EndpointOutboundKind::Ack);
        assert_eq!(
            ack.ratchet_index, 0,
            "ACK lane must not consume message lane"
        );
        let envelope = Envelope::unpack(&ack.immutable_envelope_bytes).unwrap();
        assert_eq!(envelope.env_type, EnvType::Ack as u8);
        assert_eq!(
            envelope.message_ciphertext.len(),
            crate::atsam_indexed_session::ACK_SEALED_WIRE_LEN
        );
        assert!(envelope.verify(&fixture.local_identity.public_key_bytes()));
        let ack_key = ack_key_at_index(
            &fixture.root,
            &fixture.key.initiator_address,
            &fixture.key.responder_address,
            Direction::InitiatorToResponder,
            0,
        )
        .unwrap();
        let plaintext = open_indexed_message_with_key(
            &ack_key,
            &fixture.key.initiator_address,
            &fixture.key.responder_address,
            Direction::InitiatorToResponder,
            &envelope.message_id,
            &envelope.message_ciphertext,
        )
        .unwrap();
        assert_eq!(
            plaintext.len(),
            crate::atsam_indexed_session::ACK_PLAINTEXT_LEN
        );
        let signed = decode_signed_ack(&plaintext).unwrap();
        assert_eq!(signed.record.acked_message_id, inbound_id);
        assert_eq!(signed.record.status, 1);
        assert_eq!(signed.record.created_at, fixture.now_ms);
        assert!(signed.record.verify(
            &signed.signature,
            &fixture.local_identity.public_key_bytes()
        ));
        assert!(store.pending_endpoint_ack_intents().unwrap().is_empty());

        let mut unused_rng = StdRng::from_seed([0x74; 32]);
        let mut unexpected_callback = |_digest: &[u8; 32], _bytes: &[u8]| -> Result<[u8; 32], ()> {
            panic!("queued ACK replay must not call the queue")
        };
        assert_eq!(
            store
                .enqueue_committed_ack(
                    &fixture.key,
                    &intent_digest,
                    &local_device,
                    fixture.now_ms,
                    fixture.now_ms + 60_000,
                    fixture.now_ms,
                    &mut unused_rng,
                    &mut unexpected_callback,
                )
                .unwrap()
                .immutable_envelope_bytes,
            ack.immutable_envelope_bytes
        );
    }

    #[test]
    fn ack_worker_retries_exact_bytes_after_queue_boundary_and_rejects_arbitrary_intent() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let fixture = endpoint_fixture();
        let local_device = authorized_local_device(&fixture);
        let mut store = open_test_store(&path, backend);
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();
        let inbound = inbound_message_envelope(&fixture, 0, [0x75; 16], b"ack retry");
        let intent_digest = match store
            .accept_message_envelope(
                &fixture.key,
                &inbound.pack(),
                &fixture.remote_certificate,
                false,
                fixture.now_ms,
            )
            .unwrap()
        {
            EndpointAcceptance::Committed { object_digest, .. } => object_digest,
            _ => unreachable!(),
        };

        let mut arbitrary_rng = StdRng::from_seed([0x76; 32]);
        let mut no_queue = |digest: &[u8; 32], _bytes: &[u8]| Ok(*digest);
        assert!(matches!(
            store.enqueue_committed_ack(
                &fixture.key,
                &[0xFF; 32],
                &local_device,
                fixture.now_ms,
                fixture.now_ms + 60_000,
                fixture.now_ms,
                &mut arbitrary_rng,
                &mut no_queue,
            ),
            Err(IndexedSessionStoreError::NotFound)
        ));

        store.inject_endpoint_fault(EndpointFaultPoint::AfterOutboundQueueHandoff);
        let mut rng = StdRng::from_seed([0x77; 32]);
        let mut first = Vec::new();
        {
            let mut queue = |digest: &[u8; 32], bytes: &[u8]| {
                first.push((*digest, bytes.to_vec()));
                Ok(*digest)
            };
            assert!(matches!(
                store.enqueue_committed_ack(
                    &fixture.key,
                    &intent_digest,
                    &local_device,
                    fixture.now_ms,
                    fixture.now_ms + 60_000,
                    fixture.now_ms,
                    &mut rng,
                    &mut queue,
                ),
                Err(IndexedSessionStoreError::InjectedEndpointFailure(_))
            ));
        }
        let pending = store.pending_endpoint_outbound().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].kind, EndpointOutboundKind::Ack);
        assert_eq!(pending[0].ratchet_index, 0);
        assert_eq!(pending[0].immutable_envelope_bytes, first[0].1);

        let mut retried = Vec::new();
        let mut retry_queue = |digest: &[u8; 32], bytes: &[u8]| {
            retried.push((*digest, bytes.to_vec()));
            Ok(*digest)
        };
        let queued = store
            .retry_endpoint_outbound(
                &fixture.key,
                &pending[0].object_digest,
                &local_device,
                fixture.now_ms,
                &mut retry_queue,
            )
            .unwrap();
        assert_eq!(queued.state, EndpointOutboxState::Queued);
        assert_eq!(retried, first);
        assert!(store.pending_endpoint_ack_intents().unwrap().is_empty());
    }

    #[test]
    fn ack_worker_rejects_intent_not_exactly_bound_to_its_committed_receipt() {
        // Schema 1 only (a clear column changed by hand; a schema-3 row's values are in its authenticated `meta`).
        sealed::test_switch::off();
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let fixture = endpoint_fixture();
        let local_device = authorized_local_device(&fixture);
        let mut store = open_test_store(&path, backend);
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();
        let inbound_id = [0x78; 16];
        let inbound = inbound_message_envelope(&fixture, 0, inbound_id, b"bound ACK intent");
        let intent_digest = match store
            .accept_message_envelope(
                &fixture.key,
                &inbound.pack(),
                &fixture.remote_certificate,
                false,
                fixture.now_ms,
            )
            .unwrap()
        {
            EndpointAcceptance::Committed { object_digest, .. } => object_digest,
            _ => unreachable!(),
        };
        store
            .conn
            .execute(
                "UPDATE endpoint_ack_intents SET message_id = ?1
                 WHERE session_id = ?2 AND object_digest = ?3",
                params![
                    [0x79u8; 16].as_slice(),
                    fixture.binding.session_id.as_slice(),
                    intent_digest.as_slice()
                ],
            )
            .unwrap();
        let mut rejected_rng = StdRng::from_seed([0x7A; 32]);
        let mut queue = |digest: &[u8; 32], _bytes: &[u8]| Ok(*digest);
        assert!(matches!(
            store.enqueue_committed_ack(
                &fixture.key,
                &intent_digest,
                &local_device,
                fixture.now_ms,
                fixture.now_ms + 60_000,
                fixture.now_ms,
                &mut rejected_rng,
                &mut queue,
            ),
            Err(IndexedSessionStoreError::OutboundBindingMismatch)
        ));
        assert!(store.pending_endpoint_outbound().unwrap().is_empty());

        store
            .conn
            .execute(
                "UPDATE endpoint_ack_intents SET message_id = ?1
                 WHERE session_id = ?2 AND object_digest = ?3",
                params![
                    inbound_id.as_slice(),
                    fixture.binding.session_id.as_slice(),
                    intent_digest.as_slice()
                ],
            )
            .unwrap();
        let mut valid_rng = StdRng::from_seed([0x7B; 32]);
        let ack = store
            .enqueue_committed_ack(
                &fixture.key,
                &intent_digest,
                &local_device,
                fixture.now_ms,
                fixture.now_ms + 60_000,
                fixture.now_ms,
                &mut valid_rng,
                &mut queue,
            )
            .unwrap();
        assert_eq!(
            ack.ratchet_index, 0,
            "rejection must not reserve an ACK key"
        );
    }

    #[test]
    fn ack_nonce_collision_does_not_advance_the_independent_ack_lane() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let fixture = endpoint_fixture();
        let local_device = authorized_local_device(&fixture);
        let mut store = open_test_store(&path, backend);
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();
        let mut intent_digests = Vec::new();
        for (index, message_id) in [(0, [0x7C; 16]), (1, [0x7D; 16])] {
            let inbound = inbound_message_envelope(&fixture, index, message_id, b"ACK collision");
            let accepted = store
                .accept_message_envelope(
                    &fixture.key,
                    &inbound.pack(),
                    &fixture.remote_certificate,
                    false,
                    fixture.now_ms,
                )
                .unwrap();
            let EndpointAcceptance::Committed { object_digest, .. } = accepted else {
                unreachable!()
            };
            intent_digests.push(object_digest);
        }
        let reused_ack_nonce = [0x7E; 12];
        let mut queue = |digest: &[u8; 32], _bytes: &[u8]| Ok(*digest);
        let mut first_rng =
            ScriptedCryptoRng::ack([0x7F; 16], [0x80; 12], [0x81; 12], reused_ack_nonce);
        let first = store
            .enqueue_committed_ack(
                &fixture.key,
                &intent_digests[0],
                &local_device,
                fixture.now_ms,
                fixture.now_ms + 60_000,
                fixture.now_ms,
                &mut first_rng,
                &mut queue,
            )
            .unwrap();
        assert_eq!(first.ratchet_index, 0);

        let mut collision_rng =
            ScriptedCryptoRng::ack([0x82; 16], [0x83; 12], [0x84; 12], reused_ack_nonce);
        assert!(matches!(
            store.enqueue_committed_ack(
                &fixture.key,
                &intent_digests[1],
                &local_device,
                fixture.now_ms,
                fixture.now_ms + 60_000,
                fixture.now_ms,
                &mut collision_rng,
                &mut queue,
            ),
            Err(IndexedSessionStoreError::OutboundCollision)
        ));

        let mut fresh_rng = ScriptedCryptoRng::ack([0x85; 16], [0x86; 12], [0x87; 12], [0x88; 12]);
        let second = store
            .enqueue_committed_ack(
                &fixture.key,
                &intent_digests[1],
                &local_device,
                fixture.now_ms,
                fixture.now_ms + 60_000,
                fixture.now_ms,
                &mut fresh_rng,
                &mut queue,
            )
            .unwrap();
        assert_eq!(second.ratchet_index, 1);
    }

    #[test]
    fn outbound_queue_failure_and_collision_retry_exact_bytes_without_key_reuse() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let fixture = endpoint_fixture();
        let local_device = authorized_local_device(&fixture);
        let mut store = open_test_store(&path, backend);
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();
        let seed = [0x81; 32];
        let mut rng = StdRng::from_seed(seed);
        let mut first_attempt = Vec::new();
        {
            let mut failing_queue = |digest: &[u8; 32], bytes: &[u8]| {
                first_attempt.push((*digest, bytes.to_vec()));
                Err(())
            };
            assert!(matches!(
                store.send_message_envelope(
                    &fixture.key,
                    "retry exact",
                    &local_device,
                    fixture.now_ms,
                    fixture.now_ms + 60_000,
                    fixture.now_ms,
                    &mut rng,
                    &mut failing_queue,
                ),
                Err(IndexedSessionStoreError::OutboundQueueHandoff)
            ));
        }
        let pending = store.pending_endpoint_outbound().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].immutable_envelope_bytes, first_attempt[0].1);

        let mut forbidden_rng = StdRng::from_seed([0x82; 32]);
        let mut no_queue = |digest: &[u8; 32], _bytes: &[u8]| Ok(*digest);
        assert!(matches!(
            store.send_message_envelope(
                &fixture.key,
                "must retry first",
                &local_device,
                fixture.now_ms,
                fixture.now_ms + 60_000,
                fixture.now_ms,
                &mut forbidden_rng,
                &mut no_queue,
            ),
            Err(IndexedSessionStoreError::OutboundPending)
        ));

        let mut wrong_receipt = |_digest: &[u8; 32], _bytes: &[u8]| Ok([0xFF; 32]);
        assert!(matches!(
            store.retry_endpoint_outbound(
                &fixture.key,
                &pending[0].object_digest,
                &local_device,
                fixture.now_ms,
                &mut wrong_receipt,
            ),
            Err(IndexedSessionStoreError::OutboundQueueHandoff)
        ));
        let mut retried = Vec::new();
        let queued = {
            let mut success = |digest: &[u8; 32], bytes: &[u8]| {
                retried.push((*digest, bytes.to_vec()));
                Ok(*digest)
            };
            store
                .retry_endpoint_outbound(
                    &fixture.key,
                    &pending[0].object_digest,
                    &local_device,
                    fixture.now_ms,
                    &mut success,
                )
                .unwrap()
        };
        assert_eq!(retried, first_attempt);
        assert_eq!(queued.state, EndpointOutboxState::Queued);

        let mut collision_rng = StdRng::from_seed(seed);
        assert!(matches!(
            store.send_message_envelope(
                &fixture.key,
                "collision is rejected",
                &local_device,
                fixture.now_ms,
                fixture.now_ms + 60_000,
                fixture.now_ms,
                &mut collision_rng,
                &mut no_queue,
            ),
            Err(IndexedSessionStoreError::OutboundCollision)
        ));
        let mut fresh_rng = StdRng::from_seed([0x83; 32]);
        let next = store
            .send_message_envelope(
                &fixture.key,
                "next valid key",
                &local_device,
                fixture.now_ms,
                fixture.now_ms + 60_000,
                fixture.now_ms,
                &mut fresh_rng,
                &mut no_queue,
            )
            .unwrap();
        assert_eq!(next.ratchet_index, 1, "collision must not burn another key");
    }

    #[test]
    fn outbound_crash_boundaries_recover_or_leave_index_unconsumed() {
        for point in [
            EndpointFaultPoint::BeforeProtectedReplacement,
            EndpointFaultPoint::AfterProtectedReplacement,
            EndpointFaultPoint::BeforeDatabaseCommit,
            EndpointFaultPoint::AfterDatabaseCommit,
            EndpointFaultPoint::BeforeJournalClear,
            EndpointFaultPoint::AfterJournalClear,
            EndpointFaultPoint::BeforeOutboundQueueHandoff,
            EndpointFaultPoint::AfterOutboundQueueHandoff,
        ] {
            let temp = tempdir().unwrap();
            let path = temp.path().join("sessions.sqlite");
            let backend = Arc::new(MemoryProtectedBackend::default());
            let fixture = endpoint_fixture();
            let local_device = authorized_local_device(&fixture);
            let mut store = open_test_store(&path, backend.clone());
            store
                .create_session(fixture.binding.clone(), fixture.root)
                .unwrap();
            store.inject_endpoint_fault(point);
            let mut rng = StdRng::from_seed([point as u8 + 0x91; 32]);
            let mut handed_off = Vec::new();
            let mut queue = |digest: &[u8; 32], bytes: &[u8]| {
                handed_off.push((*digest, bytes.to_vec()));
                Ok(*digest)
            };
            assert!(matches!(
                store.send_message_envelope(
                    &fixture.key,
                    "crash recovery",
                    &local_device,
                    fixture.now_ms,
                    fixture.now_ms + 60_000,
                    fixture.now_ms,
                    &mut rng,
                    &mut queue,
                ),
                Err(IndexedSessionStoreError::InjectedEndpointFailure(_))
            ));
            if point == EndpointFaultPoint::AfterOutboundQueueHandoff {
                assert_eq!(handed_off.len(), 1);
            } else {
                assert!(handed_off.is_empty(), "fault {point:?}");
            }
            drop(store);

            let mut reopened = open_test_store(&path, backend);
            let pending = reopened.pending_endpoint_outbound().unwrap();
            if point == EndpointFaultPoint::BeforeProtectedReplacement {
                assert!(pending.is_empty());
                let mut retry_rng = StdRng::from_seed([0xA1; 32]);
                let mut queue = |digest: &[u8; 32], _bytes: &[u8]| Ok(*digest);
                let sent = reopened
                    .send_message_envelope(
                        &fixture.key,
                        "index remains zero",
                        &local_device,
                        fixture.now_ms,
                        fixture.now_ms + 60_000,
                        fixture.now_ms,
                        &mut retry_rng,
                        &mut queue,
                    )
                    .unwrap();
                assert_eq!(sent.ratchet_index, 0);
            } else {
                assert_eq!(pending.len(), 1, "fault {point:?}");
                assert_eq!(pending[0].ratchet_index, 0);
                let expected = pending[0].immutable_envelope_bytes.clone();
                let mut replayed = Vec::new();
                let mut queue = |digest: &[u8; 32], bytes: &[u8]| {
                    replayed.push((*digest, bytes.to_vec()));
                    Ok(*digest)
                };
                reopened
                    .retry_endpoint_outbound(
                        &fixture.key,
                        &pending[0].object_digest,
                        &local_device,
                        fixture.now_ms,
                        &mut queue,
                    )
                    .unwrap();
                assert_eq!(replayed[0].1, expected);
                if point == EndpointFaultPoint::AfterOutboundQueueHandoff {
                    assert_eq!(replayed, handed_off);
                }
            }
        }
    }

    #[test]
    fn outbound_protected_and_database_failures_recover_without_resealing() {
        // A protected replacement that definitely did not occur leaves the
        // ratchet index reusable because no bytes could have reached a queue.
        {
            let temp = tempdir().unwrap();
            let path = temp.path().join("sessions.sqlite");
            let backend = Arc::new(MemoryProtectedBackend::default());
            let fixture = endpoint_fixture();
            let local_device = authorized_local_device(&fixture);
            let mut store = open_test_store(&path, backend.clone());
            store
                .create_session(fixture.binding.clone(), fixture.root)
                .unwrap();
            backend.fail_next_put();
            let seed = [0xC1; 32];
            let mut rng = StdRng::from_seed(seed);
            let mut queue = |digest: &[u8; 32], _bytes: &[u8]| Ok(*digest);
            assert!(matches!(
                store.send_message_envelope(
                    &fixture.key,
                    "protected failure",
                    &local_device,
                    fixture.now_ms,
                    fixture.now_ms + 60_000,
                    fixture.now_ms,
                    &mut rng,
                    &mut queue,
                ),
                Err(IndexedSessionStoreError::ProtectedStore(_))
            ));
            assert!(store.pending_endpoint_outbound().unwrap().is_empty());
            let mut retry_rng = StdRng::from_seed(seed);
            let sent = store
                .send_message_envelope(
                    &fixture.key,
                    "protected failure",
                    &local_device,
                    fixture.now_ms,
                    fixture.now_ms + 60_000,
                    fixture.now_ms,
                    &mut retry_rng,
                    &mut queue,
                )
                .unwrap();
            assert_eq!(sent.ratchet_index, 0);
        }

        // A database failure while staging the outbox rows happens before the
        // protected replacement: no journal is written and the ratchet index
        // is not consumed, because no bytes could have reached a queue.
        // (Previously the journal was written first and replayed on reopen;
        // that ordering let a deterministically failing insert strand an
        // unreplayable journal.)
        {
            let temp = tempdir().unwrap();
            let path = temp.path().join("sessions.sqlite");
            let backend = Arc::new(MemoryProtectedBackend::default());
            let fixture = endpoint_fixture();
            let local_device = authorized_local_device(&fixture);
            let mut store = open_test_store(&path, backend.clone());
            store
                .create_session(fixture.binding.clone(), fixture.root)
                .unwrap();
            let account = hex::encode(record_key_digest(&fixture.key).unwrap());
            let before = backend.get(&account).unwrap().unwrap();
            store
                .conn
                .execute_batch(
                    "CREATE TRIGGER fail_endpoint_outbox_insert
                     BEFORE INSERT ON endpoint_outbox
                     BEGIN SELECT RAISE(ABORT, 'injected outbox failure'); END;",
                )
                .unwrap();
            let seed = [0xC2; 32];
            let mut rng = StdRng::from_seed(seed);
            let mut no_queue = |_digest: &[u8; 32], _bytes: &[u8]| -> Result<[u8; 32], ()> {
                panic!("database failure must not queue")
            };
            assert!(matches!(
                store.send_message_envelope(
                    &fixture.key,
                    "database failure",
                    &local_device,
                    fixture.now_ms,
                    fixture.now_ms + 60_000,
                    fixture.now_ms,
                    &mut rng,
                    &mut no_queue,
                ),
                Err(IndexedSessionStoreError::Sqlite(_))
            ));
            assert_eq!(backend.get(&account).unwrap().unwrap(), before);
            store
                .conn
                .execute("DROP TRIGGER fail_endpoint_outbox_insert", [])
                .unwrap();
            drop(store);
            let mut reopened = open_test_store(&path, backend);
            assert!(reopened.pending_endpoint_outbound().unwrap().is_empty());
            let mut retry_rng = StdRng::from_seed(seed);
            let mut queue = |digest: &[u8; 32], _bytes: &[u8]| Ok(*digest);
            let sent = reopened
                .send_message_envelope(
                    &fixture.key,
                    "database failure",
                    &local_device,
                    fixture.now_ms,
                    fixture.now_ms + 60_000,
                    fixture.now_ms,
                    &mut retry_rng,
                    &mut queue,
                )
                .unwrap();
            assert_eq!(sent.ratchet_index, 0);
        }

        // A failure while clearing the protected journal occurs only after the
        // exact outbox/outstanding commit. Reopen repeats that commit and then
        // clears the same journal.
        {
            let temp = tempdir().unwrap();
            let path = temp.path().join("sessions.sqlite");
            let backend = Arc::new(MemoryProtectedBackend::default());
            let fixture = endpoint_fixture();
            let local_device = authorized_local_device(&fixture);
            let mut store = open_test_store(&path, backend.clone());
            store
                .create_session(fixture.binding.clone(), fixture.root)
                .unwrap();
            backend.fail_nth_future_put(2);
            let mut rng = StdRng::from_seed([0xC3; 32]);
            let mut no_queue = |_digest: &[u8; 32], _bytes: &[u8]| -> Result<[u8; 32], ()> {
                panic!("journal-clear failure must not queue")
            };
            assert!(matches!(
                store.send_message_envelope(
                    &fixture.key,
                    "journal clear failure",
                    &local_device,
                    fixture.now_ms,
                    fixture.now_ms + 60_000,
                    fixture.now_ms,
                    &mut rng,
                    &mut no_queue,
                ),
                Err(IndexedSessionStoreError::ProtectedStore(_))
            ));
            drop(store);
            let reopened = open_test_store(&path, backend);
            let pending = reopened.pending_endpoint_outbound().unwrap();
            assert_eq!(pending.len(), 1);
            assert_eq!(pending[0].ratchet_index, 0);
        }
    }

    #[test]
    fn outbound_allows_only_initial_provisional_initiator_message_then_requires_confirmation() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let fixture = endpoint_fixture();
        let local_device = authorized_local_device(&fixture);
        let mut provisional = fixture.binding.clone();
        provisional.lifecycle = SessionLifecycle::Provisional;
        provisional.response_hash = None;
        let mut store = open_test_store(&path, backend);
        store.create_session(provisional, fixture.root).unwrap();
        let mut rng = StdRng::from_seed([0xB1; 32]);
        let mut queue = |digest: &[u8; 32], _bytes: &[u8]| Ok(*digest);
        let initial = store
            .send_message_envelope(
                &fixture.key,
                "provisional message zero",
                &local_device,
                fixture.now_ms,
                fixture.now_ms + 60_000,
                fixture.now_ms,
                &mut rng,
                &mut queue,
            )
            .unwrap();
        assert_eq!(initial.ratchet_index, 0);
        let mut second_rng = StdRng::from_seed([0xB8; 32]);
        assert!(matches!(
            store.send_message_envelope(
                &fixture.key,
                "provisional message one is forbidden",
                &local_device,
                fixture.now_ms,
                fixture.now_ms + 60_000,
                fixture.now_ms,
                &mut second_rng,
                &mut queue,
            ),
            Err(IndexedSessionStoreError::SessionNotConfirmed)
        ));
        let mut ack_rng = StdRng::from_seed([0xB9; 32]);
        assert!(matches!(
            store.enqueue_committed_ack(
                &fixture.key,
                &[0xBA; 32],
                &local_device,
                fixture.now_ms,
                fixture.now_ms + 60_000,
                fixture.now_ms,
                &mut ack_rng,
                &mut queue,
            ),
            Err(IndexedSessionStoreError::SessionNotConfirmed)
        ));

        store.confirm_session(&fixture.key, [0x46; 32]).unwrap();
        let mut confirmed_rng = StdRng::from_seed([0xBB; 32]);
        let confirmed = store
            .send_message_envelope(
                &fixture.key,
                "confirmed message one",
                &local_device,
                fixture.now_ms,
                fixture.now_ms + 60_000,
                fixture.now_ms,
                &mut confirmed_rng,
                &mut queue,
            )
            .unwrap();
        assert_eq!(confirmed.ratchet_index, 1);
        for invalid in ["", "bad\u{0001}text", "\u{007f}"] {
            let mut rng = StdRng::from_seed([0xB2; 32]);
            assert!(matches!(
                store.send_message_envelope(
                    &fixture.key,
                    invalid,
                    &local_device,
                    fixture.now_ms,
                    fixture.now_ms + 60_000,
                    fixture.now_ms,
                    &mut rng,
                    &mut queue,
                ),
                Err(IndexedSessionStoreError::InvalidEndpointPayload)
            ));
        }
        let oversized = "x".repeat(MAX_ENDPOINT_TEXT_BYTES + 1);
        let mut oversized_rng = StdRng::from_seed([0xB2; 32]);
        assert!(matches!(
            store.send_message_envelope(
                &fixture.key,
                &oversized,
                &local_device,
                fixture.now_ms,
                fixture.now_ms + 60_000,
                fixture.now_ms,
                &mut oversized_rng,
                &mut queue,
            ),
            Err(IndexedSessionStoreError::InvalidEndpointPayload)
        ));
        let mut rng = StdRng::from_seed([0xB3; 32]);
        assert!(matches!(
            store.send_message_envelope(
                &fixture.key,
                "bad time",
                &local_device,
                fixture.now_ms + MAX_ENDPOINT_FUTURE_SKEW_MS + 1,
                fixture.now_ms + MAX_ENDPOINT_FUTURE_SKEW_MS + 60_000,
                fixture.now_ms,
                &mut rng,
                &mut queue,
            ),
            Err(IndexedSessionStoreError::EndpointNotCurrentlyValid)
        ));

        let wrong_identity = Identity::from_seed(&[0xB4; 32]);
        assert!(matches!(
            AuthorizedEndpointDevice::authorize(
                &fixture.local_certificate,
                &wrong_identity,
                &fixture.local_registry,
                fixture.now_ms,
            ),
            Err(IndexedSessionStoreError::LocalDeviceUnauthorized)
        ));
        let mut revoked_registry = fixture.local_registry.clone();
        revoked_registry.revoke(&fixture.local_certificate.device_id);
        assert!(matches!(
            AuthorizedEndpointDevice::authorize(
                &fixture.local_certificate,
                &fixture.local_identity,
                &revoked_registry,
                fixture.now_ms,
            ),
            Err(IndexedSessionStoreError::LocalDeviceUnauthorized)
        ));
        let wrong_user = Identity::from_seed(&[0xB5; 32]);
        let wrong_certificate = DeviceCertificate::issue(
            &wrong_user,
            wrong_identity.public_key_bytes(),
            [0xB6; 32],
            "wrong-local",
            fixture.now_ms - 1,
            fixture.now_ms + 120_000,
            1,
        )
        .unwrap();
        let mut wrong_registry = DeviceRegistry::default();
        wrong_registry
            .add(wrong_certificate.clone(), fixture.now_ms)
            .unwrap();
        let wrong_device = AuthorizedEndpointDevice::authorize(
            &wrong_certificate,
            &wrong_identity,
            &wrong_registry,
            fixture.now_ms,
        )
        .unwrap();
        let mut rng = StdRng::from_seed([0xB7; 32]);
        assert!(matches!(
            store.send_message_envelope(
                &fixture.key,
                "wrong device",
                &wrong_device,
                fixture.now_ms,
                fixture.now_ms + 60_000,
                fixture.now_ms,
                &mut rng,
                &mut queue,
            ),
            Err(IndexedSessionStoreError::LocalDeviceBindingMismatch)
        ));
        let mut final_rng = StdRng::from_seed([0xBD; 32]);
        let after_negatives = store
            .send_message_envelope(
                &fixture.key,
                "all negative checks preserved the next key",
                &local_device,
                fixture.now_ms,
                fixture.now_ms + 60_000,
                fixture.now_ms,
                &mut final_rng,
                &mut queue,
            )
            .unwrap();
        assert_eq!(after_negatives.ratchet_index, 2);
    }

    #[test]
    fn provisional_responder_cannot_send() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let fixture = endpoint_fixture();
        let mut binding = fixture.binding.clone();
        binding.local_role = LocalRole::Responder;
        binding.lifecycle = SessionLifecycle::Provisional;
        binding.response_hash = None;
        let mut registry = DeviceRegistry::default();
        registry
            .add(fixture.remote_certificate.clone(), fixture.now_ms)
            .unwrap();
        let local_device = AuthorizedEndpointDevice::authorize(
            &fixture.remote_certificate,
            &fixture.remote_identity,
            &registry,
            fixture.now_ms,
        )
        .unwrap();
        let mut store = open_test_store(&path, backend);
        store.create_session(binding, fixture.root).unwrap();
        let mut rng = StdRng::from_seed([0xBC; 32]);
        let mut queue = |digest: &[u8; 32], _bytes: &[u8]| Ok(*digest);
        assert!(matches!(
            store.send_message_envelope(
                &fixture.key,
                "responder must confirm first",
                &local_device,
                fixture.now_ms,
                fixture.now_ms + 60_000,
                fixture.now_ms,
                &mut rng,
                &mut queue,
            ),
            Err(IndexedSessionStoreError::SessionNotConfirmed)
        ));
        assert!(store.pending_endpoint_outbound().unwrap().is_empty());
    }

    #[test]
    fn retry_rejects_expired_object_before_queue_callback() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let fixture = endpoint_fixture();
        let local_device = authorized_local_device(&fixture);
        let mut store = open_test_store(&path, backend);
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();
        let mut rng = StdRng::from_seed([0xBD; 32]);
        let mut fail_queue = |_digest: &[u8; 32], _bytes: &[u8]| Err(());
        assert!(matches!(
            store.send_message_envelope(
                &fixture.key,
                "short lived",
                &local_device,
                fixture.now_ms,
                fixture.now_ms + 1,
                fixture.now_ms,
                &mut rng,
                &mut fail_queue,
            ),
            Err(IndexedSessionStoreError::OutboundQueueHandoff)
        ));
        let pending = store.pending_endpoint_outbound().unwrap();
        assert_eq!(pending.len(), 1);
        let callback_invoked = AtomicBool::new(false);
        let mut forbidden_queue = |digest: &[u8; 32], _bytes: &[u8]| {
            callback_invoked.store(true, Ordering::SeqCst);
            Ok(*digest)
        };
        assert!(matches!(
            store.retry_endpoint_outbound(
                &fixture.key,
                &pending[0].object_digest,
                &local_device,
                fixture.now_ms + 2,
                &mut forbidden_queue,
            ),
            Err(IndexedSessionStoreError::EndpointNotCurrentlyValid)
        ));
        assert!(!callback_invoked.load(Ordering::SeqCst));
        assert_eq!(store.pending_endpoint_outbound().unwrap(), pending);
    }

    #[test]
    fn seal_nonce_collision_with_distinct_coordinates_does_not_advance_ratchet() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let fixture = endpoint_fixture();
        let local_device = authorized_local_device(&fixture);
        let mut store = open_test_store(&path, backend);
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();
        let reused_seal_nonce = [0xC1; 12];
        let mut first_rng = ScriptedCryptoRng::outbound([0xC2; 16], reused_seal_nonce, [0xC3; 12]);
        let mut queue = |digest: &[u8; 32], _bytes: &[u8]| Ok(*digest);
        let first = store
            .send_message_envelope(
                &fixture.key,
                "first nonce owner",
                &local_device,
                fixture.now_ms,
                fixture.now_ms + 60_000,
                fixture.now_ms,
                &mut first_rng,
                &mut queue,
            )
            .unwrap();
        assert_eq!(first.ratchet_index, 0);

        let mut collision_rng =
            ScriptedCryptoRng::outbound([0xC4; 16], reused_seal_nonce, [0xC5; 12]);
        assert!(matches!(
            store.send_message_envelope(
                &fixture.key,
                "different coordinates same seal nonce",
                &local_device,
                fixture.now_ms + 1,
                fixture.now_ms + 60_001,
                fixture.now_ms,
                &mut collision_rng,
                &mut queue,
            ),
            Err(IndexedSessionStoreError::OutboundCollision)
        ));

        let mut fresh_rng = ScriptedCryptoRng::outbound([0xC6; 16], [0xC7; 12], [0xC8; 12]);
        let next = store
            .send_message_envelope(
                &fixture.key,
                "fresh nonce keeps index one",
                &local_device,
                fixture.now_ms + 1,
                fixture.now_ms + 60_001,
                fixture.now_ms,
                &mut fresh_rng,
                &mut queue,
            )
            .unwrap();
        assert_eq!(next.ratchet_index, 1);
    }

    #[test]
    fn concurrent_retries_converge_on_one_queued_exact_object() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let fixture = endpoint_fixture();
        let local_device = authorized_local_device(&fixture);
        let mut store = open_test_store(&path, backend.clone());
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();
        let mut rng = StdRng::from_seed([0xC9; 32]);
        let mut fail_queue = |_digest: &[u8; 32], _bytes: &[u8]| Err(());
        assert!(matches!(
            store.send_message_envelope(
                &fixture.key,
                "concurrent retry",
                &local_device,
                fixture.now_ms,
                fixture.now_ms + 60_000,
                fixture.now_ms,
                &mut rng,
                &mut fail_queue,
            ),
            Err(IndexedSessionStoreError::OutboundQueueHandoff)
        ));
        let pending = store.pending_endpoint_outbound().unwrap().remove(0);
        drop(store);

        let barrier = TimedBarrier::new(2);
        let observations = Arc::new(Mutex::new(Vec::new()));
        let mut handles = Vec::new();
        for _ in 0..2 {
            let path = path.clone();
            let backend = backend.clone();
            let barrier = barrier.clone();
            let observations = observations.clone();
            let object_digest = pending.object_digest;
            handles.push(thread::spawn(move || {
                let fixture = endpoint_fixture();
                let local_device = authorized_local_device(&fixture);
                let mut store = open_test_store(&path, backend);
                let mut queue = |digest: &[u8; 32], bytes: &[u8]| {
                    observations
                        .lock()
                        .expect("observation lock")
                        .push((*digest, bytes.to_vec()));
                    // Both instances must still see the object as Prepared and
                    // hand it off before either one marks it Queued.
                    barrier.wait("both retries reach the queue callback");
                    Ok(*digest)
                };
                store
                    .retry_endpoint_outbound(
                        &fixture.key,
                        &object_digest,
                        &local_device,
                        fixture.now_ms,
                        &mut queue,
                    )
                    .unwrap()
            }));
        }
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert!(results
            .iter()
            .all(|row| row.state == EndpointOutboxState::Queued));
        assert_eq!(
            results[0].immutable_envelope_bytes,
            pending.immutable_envelope_bytes
        );
        assert_eq!(
            results[1].immutable_envelope_bytes,
            pending.immutable_envelope_bytes
        );
        let observations = observations.lock().expect("observation lock");
        assert_eq!(observations.len(), 2);
        assert!(observations.iter().all(|(digest, bytes)| {
            *digest == pending.object_digest && *bytes == pending.immutable_envelope_bytes
        }));
        drop(observations);
        let reopened = open_test_store(&path, backend);
        assert!(reopened.pending_endpoint_outbound().unwrap().is_empty());
    }

    #[test]
    fn malicious_queue_callback_cannot_commit_mutated_outbox_bindings() {
        // Schema 1 only (a clear column changed by hand; a schema-3 row's values are in its authenticated `meta`).
        sealed::test_switch::off();
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let fixture = endpoint_fixture();
        let local_device = authorized_local_device(&fixture);
        let mut store = open_test_store(&path, backend);
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();
        let mut rng = StdRng::from_seed([0xCA; 32]);
        let mut fail_queue = |_digest: &[u8; 32], _bytes: &[u8]| Err(());
        assert!(matches!(
            store.send_message_envelope(
                &fixture.key,
                "callback mutation",
                &local_device,
                fixture.now_ms,
                fixture.now_ms + 60_000,
                fixture.now_ms,
                &mut rng,
                &mut fail_queue,
            ),
            Err(IndexedSessionStoreError::OutboundQueueHandoff)
        ));
        let pending = store.pending_endpoint_outbound().unwrap().remove(0);
        let callback_path = path.clone();
        let mut malicious_queue = |digest: &[u8; 32], _bytes: &[u8]| {
            let conn = Connection::open(&callback_path).map_err(|_| ())?;
            conn.execute(
                "UPDATE endpoint_outbox SET recipient_device = ?1
                 WHERE object_digest = ?2",
                params![[0xDDu8; 32].as_slice(), digest.as_slice()],
            )
            .map_err(|_| ())?;
            Ok(*digest)
        };
        assert!(matches!(
            store.retry_endpoint_outbound(
                &fixture.key,
                &pending.object_digest,
                &local_device,
                fixture.now_ms,
                &mut malicious_queue,
            ),
            Err(IndexedSessionStoreError::OutboundBindingMismatch)
        ));
        let conn = Connection::open(&path).unwrap();
        let state: i64 = conn
            .query_row(
                "SELECT state FROM endpoint_outbox WHERE object_digest = ?1",
                params![pending.object_digest.as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(state, EndpointOutboxState::Prepared as i64);
    }

    /// F1 migration: a row queued before the hint change carries the legacy
    /// recipient hint. Its exact bytes must keep validating (and be retried
    /// unchanged); any other non-zero hint is still a binding mismatch. The
    /// hint is outside the signature and the object digest, so both rows share
    /// one digest.
    #[test]
    fn stored_outbound_accepts_zero_and_legacy_hint_only() {
        // Schema 1 only (a clear envelope written by hand).
        sealed::test_switch::off();
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let fixture = endpoint_fixture();
        let local_device = authorized_local_device(&fixture);
        let mut store = open_test_store(&path, backend);
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();
        let mut rng = StdRng::from_seed([0xCE; 32]);
        let mut ok_queue = |digest: &[u8; 32], _bytes: &[u8]| Ok(*digest);
        let outbound = store
            .send_message_envelope(
                &fixture.key,
                "legacy hint row",
                &local_device,
                fixture.now_ms,
                fixture.now_ms + 60_000,
                fixture.now_ms,
                &mut rng,
                &mut ok_queue,
            )
            .unwrap();
        let current = Envelope::unpack(&outbound.immutable_envelope_bytes).unwrap();
        assert_eq!(current.dest_device_hint, 0);
        let legacy_hint = endpoint_device_hint(&fixture.key.responder_device_ed25519);
        let rewrite = |hint: u64| {
            let mut env = current.clone();
            env.dest_device_hint = hint;
            assert!(env.verify(&fixture.local_identity.public_key_bytes()));
            assert_eq!(
                crate::bridge::authenticated_object_digest(&env),
                outbound.object_digest
            );
            let packed = env.pack();
            Connection::open(&path)
                .unwrap()
                .execute(
                    "UPDATE endpoint_outbox SET immutable_envelope_bytes = ?1
                     WHERE object_digest = ?2",
                    params![packed.as_slice(), outbound.object_digest.as_slice()],
                )
                .unwrap();
            packed
        };
        let legacy = rewrite(legacy_hint);
        let mut seen = Vec::new();
        let mut record = |digest: &[u8; 32], bytes: &[u8]| {
            seen.push(bytes.to_vec());
            Ok(*digest)
        };
        let retried = store
            .retry_endpoint_outbound(
                &fixture.key,
                &outbound.object_digest,
                &local_device,
                fixture.now_ms,
                &mut record,
            )
            .expect("a pre-upgrade row with the legacy hint still validates");
        assert_eq!(retried.immutable_envelope_bytes, legacy, "exact bytes");
        rewrite(legacy_hint ^ 1);
        assert!(matches!(
            store.retry_endpoint_outbound(
                &fixture.key,
                &outbound.object_digest,
                &local_device,
                fixture.now_ms,
                &mut ok_queue,
            ),
            Err(IndexedSessionStoreError::OutboundBindingMismatch)
        ));
        assert!(stored_outbound_hint_ok(0, &[7; 32]));
        assert!(stored_outbound_hint_ok(
            endpoint_device_hint(&[7; 32]),
            &[7; 32]
        ));
        assert!(!stored_outbound_hint_ok(
            endpoint_device_hint(&[8; 32]),
            &[7; 32]
        ));
    }

    #[test]
    fn pending_outbound_rejects_short_sealed_body_without_panicking() {
        let message_id = [0xCB; 16];
        let envelope = Envelope {
            env_type: EnvType::Message as u8,
            flags: OUTBOUND_FLAGS,
            message_id,
            routing_tag: [0xCC; 16],
            dest_device_hint: 1,
            created_at: 1,
            expires_at: 2,
            hop_limit: OUTBOUND_HOP_LIMIT,
            replication_budget: OUTBOUND_REPLICATION_BUDGET,
            anti_replay_nonce: [0xCD; 12],
            ratchet_header_ciphertext: Vec::new(),
            message_ciphertext: Vec::new(),
            sender_authentication: vec![0; 64],
        };
        let pending = PendingOutbound {
            kind: EndpointOutboundKind::Message,
            session_id: [0xCE; 32],
            object_digest: authenticated_object_digest(&envelope),
            message_id,
            recipient_device: [0xCF; 32],
            ratchet_index: 0,
            source_ack_intent: None,
            ack_nonce: None,
            seal_nonce: [0xD0; 12],
            anti_replay_nonce: envelope.anti_replay_nonce,
            immutable_envelope_bytes: envelope.pack(),
            public_generation: 1,
        };
        assert!(matches!(
            validate_pending_outbound_shape(&pending),
            Err(IndexedSessionStoreError::CorruptProtectedState)
        ));
    }

    #[test]
    fn endpoint_plaintext_debug_output_is_redacted() {
        let acceptance = EndpointAcceptance::Committed {
            session_id: [1; 32],
            object_digest: [2; 32],
            message_id: [3; 16],
            plaintext: b"debug must not leak this plaintext".to_vec(),
            received_at_ms: 4,
        };
        let inbox = EndpointInboxRow {
            session_id: [1; 32],
            object_digest: [2; 32],
            message_id: [3; 16],
            sender_device: [4; 32],
            created_at_ms: 5,
            received_at_ms: 6,
            position: InboxPosition::received(6, Some([3; 16])),
            plaintext: b"or this inbox plaintext".to_vec(),
        };
        let acceptance_debug = format!("{acceptance:?}");
        let inbox_debug = format!("{inbox:?}");
        assert!(acceptance_debug.contains("<redacted>"));
        assert!(inbox_debug.contains("<redacted>"));
        assert!(!acceptance_debug.contains("debug must not leak"));
        assert!(!inbox_debug.contains("inbox plaintext"));
    }

    #[test]
    fn sqlite_and_json_never_contain_root_or_chain_material() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let binding = fixture_binding();
        let root = [0xA7; 32];
        let mut store = open_test_store(&path, backend);
        store.create_session(binding, root).unwrap();
        store
            .conn
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .unwrap();
        drop(store);

        // The main file must be readable and non-empty: an unreadable database
        // is a failure here, never a clean scan.
        assert_eq!(
            secrets_found_in_sqlite_files(&path, &[("root".to_string(), root)]),
            Vec::<String>::new()
        );
        assert!(std::fs::read_dir(temp.path())
            .unwrap()
            .filter_map(Result::ok)
            .all(|entry| entry.path().extension().and_then(|v| v.to_str()) != Some("json")));
    }

    /// (protected generation, protected journal present, metadata generation)
    fn protected_and_metadata_generation(
        path: &Path,
        backend: &MemoryProtectedBackend,
        key: &IndexedSessionRecordKey,
    ) -> (u64, bool, u64) {
        let record_key = record_key_digest(key).unwrap();
        let encoded = backend.get(&hex::encode(record_key)).unwrap().unwrap();
        let state = decode_protected_state(&encoded).unwrap();
        let summary = (
            state.generation,
            state.pending_acceptance.is_some()
                || state.pending_ack_acceptance.is_some()
                || state.pending_outbound.is_some(),
        );
        drop(state);
        let metadata: i64 = Connection::open(path)
            .unwrap()
            .query_row(
                "SELECT generation FROM indexed_session_heads WHERE record_key = ?1",
                params![record_key.as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        (summary.0, summary.1, metadata as u64)
    }

    #[test]
    fn ack_outer_message_id_reuse_is_rejected_before_any_protected_write() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let fixture = endpoint_fixture();
        let mut store = open_test_store(&path, Arc::clone(&backend));
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();
        let first_outbound = [0xA1; 16];
        let second_outbound = [0xA2; 16];
        for outbound in [first_outbound, second_outbound] {
            store
                .register_outstanding_message(&fixture.key, &outbound)
                .unwrap();
        }
        let reused_outer = [0xA3; 16];
        let first = inbound_ack_envelope(&fixture, 0, reused_outer, first_outbound, 1, [0xA4; 12]);
        store
            .accept_ack_envelope(
                &fixture.key,
                &first.pack(),
                &fixture.remote_certificate,
                false,
                fixture.now_ms,
            )
            .unwrap();
        let account = hex::encode(record_key_digest(&fixture.key).unwrap());
        let before = backend.get(&account).unwrap().unwrap();

        // Next ACK-lane index, fresh ACK nonce, valid AEAD and both device
        // signatures, but the outer message ID of the ACK accepted above.
        let reused =
            inbound_ack_envelope(&fixture, 1, reused_outer, second_outbound, 1, [0xA5; 12]);
        assert!(matches!(
            store.accept_ack_envelope(
                &fixture.key,
                &reused.pack(),
                &fixture.remote_certificate,
                false,
                fixture.now_ms,
            ),
            Err(IndexedSessionStoreError::LogicalMessageConflict)
        ));
        assert_eq!(
            backend.get(&account).unwrap().unwrap(),
            before,
            "a rejected ACK must not write protected state or a journal"
        );
        assert_eq!(
            store
                .outstanding_delivery_state(
                    &fixture.binding.session_id,
                    &second_outbound,
                    &fixture.key.responder_device_ed25519,
                )
                .unwrap(),
            Some(EndpointDeliveryState::Sent)
        );
        drop(store);

        // The store still opens and the rejected ACK did not consume index 1.
        let mut reopened = open_test_store(&path, Arc::clone(&backend));
        let valid = inbound_ack_envelope(&fixture, 1, [0xA6; 16], second_outbound, 1, [0xA5; 12]);
        assert!(matches!(
            reopened
                .accept_ack_envelope(
                    &fixture.key,
                    &valid.pack(),
                    &fixture.remote_certificate,
                    false,
                    fixture.now_ms,
                )
                .unwrap(),
            EndpointAckAcceptance::Committed {
                delivery_state: EndpointDeliveryState::Delivered,
                ..
            }
        ));
    }

    #[test]
    fn unreplayable_protected_journal_is_quarantined_instead_of_failing_open() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let fixture = endpoint_fixture();
        let first_outbound = [0xB1; 16];
        let second_outbound = [0xB2; 16];
        let reused_outer = [0xB3; 16];
        {
            let mut store = open_test_store(&path, Arc::clone(&backend));
            store
                .create_session(fixture.binding.clone(), fixture.root)
                .unwrap();
            for outbound in [first_outbound, second_outbound] {
                store
                    .register_outstanding_message(&fixture.key, &outbound)
                    .unwrap();
            }
            let first =
                inbound_ack_envelope(&fixture, 0, reused_outer, first_outbound, 1, [0xB4; 12]);
            store
                .accept_ack_envelope(
                    &fixture.key,
                    &first.pack(),
                    &fixture.remote_certificate,
                    false,
                    fixture.now_ms,
                )
                .unwrap();
        }

        // What an earlier build could leave behind: a protected head one
        // generation ahead of metadata (crash before commit) whose ACK journal
        // reuses that outer message ID for a different object, so its replay
        // can never satisfy UNIQUE(session_id, remote_device, outer_message_id).
        let account = hex::encode(record_key_digest(&fixture.key).unwrap());
        let mut state = decode_protected_state(&backend.get(&account).unwrap().unwrap()).unwrap();
        let generation = state.generation + 1;
        state.generation = generation;
        state.pending_ack_acceptance = Some(PendingAckAcceptance {
            session_id: fixture.binding.session_id,
            object_digest: [0xB5; 32],
            outer_message_id: reused_outer,
            remote_device: fixture.key.responder_device_ed25519,
            acked_message_id: second_outbound,
            status: 1,
            ack_nonce: [0xB6; 12],
            created_at_ms: fixture.now_ms,
            public_generation: generation,
        });
        // The journaled ACK had consumed ACK index 1 before the crash: the
        // ratchet advances before the journal is staged. Advance the real
        // ratchet (the chain key moves with the index) so the crafted head is
        // what a crashed acceptance would have left.
        let (sender, recipient) =
            endpoints_for_direction(&state.binding, state.binding.local_role.inbound_direction());
        let mut consumed =
            prepare_receive_key(&mut state.ratchets.ack_receive, 1, sender, recipient).unwrap();
        consumed.zeroize();
        backend
            .put(&account, &encode_protected_state(&state).unwrap())
            .unwrap();
        drop(state);

        let mut reopened = open_test_store(&path, Arc::clone(&backend));
        assert_eq!(
            protected_and_metadata_generation(&path, &backend, &fixture.key),
            (generation, false, generation)
        );
        assert_eq!(
            reopened
                .outstanding_delivery_state(
                    &fixture.binding.session_id,
                    &second_outbound,
                    &fixture.key.responder_device_ed25519,
                )
                .unwrap(),
            Some(EndpointDeliveryState::Sent)
        );
        // Quarantine keeps the protected ratchet advanced: the burned index is
        // never accepted again, the next one is.
        let burned = inbound_ack_envelope(&fixture, 1, [0xB7; 16], second_outbound, 2, [0xB8; 12]);
        assert!(matches!(
            reopened.accept_ack_envelope(
                &fixture.key,
                &burned.pack(),
                &fixture.remote_certificate,
                false,
                fixture.now_ms,
            ),
            Err(IndexedSessionStoreError::Replay)
        ));
        let valid = inbound_ack_envelope(&fixture, 2, [0xB9; 16], second_outbound, 2, [0xBA; 12]);
        assert!(matches!(
            reopened
                .accept_ack_envelope(
                    &fixture.key,
                    &valid.pack(),
                    &fixture.remote_certificate,
                    false,
                    fixture.now_ms,
                )
                .unwrap(),
            EndpointAckAcceptance::Committed {
                delivery_state: EndpointDeliveryState::Read,
                ..
            }
        ));
    }

    #[test]
    fn only_deterministic_replay_conflicts_quarantine_a_journal() {
        let sqlite = |code| {
            IndexedSessionStoreError::Sqlite(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(code),
                None,
            ))
        };
        assert!(journal_replay_is_unrecoverable(&sqlite(
            rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE
        )));
        assert!(journal_replay_is_unrecoverable(
            &IndexedSessionStoreError::LogicalMessageConflict
        ));
        assert!(journal_replay_is_unrecoverable(
            &IndexedSessionStoreError::AckOutstandingMismatch
        ));
        assert!(!journal_replay_is_unrecoverable(&sqlite(
            rusqlite::ffi::SQLITE_BUSY
        )));
        assert!(!journal_replay_is_unrecoverable(&sqlite(
            rusqlite::ffi::SQLITE_IOERR
        )));
        assert!(!journal_replay_is_unrecoverable(
            &IndexedSessionStoreError::ProtectedStore("unavailable".into())
        ));
        assert!(!journal_replay_is_unrecoverable(
            &IndexedSessionStoreError::CorruptEndpointState
        ));
        assert!(!journal_replay_is_unrecoverable(
            &IndexedSessionStoreError::CorruptProtectedState
        ));
    }

    #[test]
    fn prune_crash_after_secret_delete_keeps_store_open_and_is_finished_later() {
        for injected in [false, true] {
            let temp = tempdir().unwrap();
            let path = temp.path().join("sessions.sqlite");
            let backend = Arc::new(MemoryProtectedBackend::default());
            let fixture = endpoint_fixture();
            let mut expired = fixture.binding.clone();
            expired.key.init_id = [0x34; 16];
            expired.init_hash = [0x52; 32];
            expired.session_id = session_id(&expired.init_hash);
            expired.expires_at_ms = fixture.now_ms - 1;
            let expired_account = hex::encode(record_key_digest(&expired.key).unwrap());
            {
                let mut store = open_test_store(&path, Arc::clone(&backend));
                store.create_session(expired.clone(), [0xB9; 32]).unwrap();
                store
                    .create_session(fixture.binding.clone(), fixture.root)
                    .unwrap();
                store
                    .register_outstanding_message(&expired.key, &[0xBA; 16])
                    .unwrap();
                if injected {
                    store.inject_endpoint_fault(EndpointFaultPoint::AfterPruneSecretDelete);
                    assert!(matches!(
                        store.prune_expired_sessions(fixture.now_ms),
                        Err(IndexedSessionStoreError::InjectedEndpointFailure(_))
                    ));
                } else {
                    // The durable state an earlier prune left when it died
                    // between deleting the secret and deleting the rows.
                    backend.delete(&expired_account).unwrap();
                }
            }
            assert!(backend.get(&expired_account).unwrap().is_none());

            let mut reopened = open_test_store(&path, Arc::clone(&backend));
            assert_eq!(reopened.list_record_keys().unwrap().len(), 2);
            assert!(matches!(
                reopened.session_lifecycle(&expired.key),
                Err(IndexedSessionStoreError::ProtectedStateMissing)
            ));
            assert_eq!(
                reopened
                    .find_confirmed_session_for_peer_at(
                        &fixture.key.responder_device_ed25519,
                        fixture.now_ms,
                    )
                    .unwrap(),
                Some(fixture.key.clone())
            );
            assert_eq!(reopened.prune_expired_sessions(fixture.now_ms).unwrap(), 1);
            assert_eq!(
                reopened.list_record_keys().unwrap(),
                vec![fixture.key.clone()]
            );
            let leftover: i64 = reopened
                .conn
                .query_row(
                    "SELECT COUNT(*) FROM endpoint_outstanding_messages WHERE session_id = ?1",
                    params![expired.session_id.as_slice()],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(leftover, 0);
            assert_eq!(reopened.prune_expired_sessions(fixture.now_ms).unwrap(), 0);
            let inbound = inbound_message_envelope(&fixture, 0, [0xBB; 16], b"after prune");
            reopened
                .accept_message_envelope(
                    &fixture.key,
                    &inbound.pack(),
                    &fixture.remote_certificate,
                    false,
                    fixture.now_ms,
                )
                .unwrap();
        }
    }

    #[test]
    fn prepared_objects_only_gate_their_own_lane() {
        let fixture = endpoint_fixture();
        let local_device = authorized_local_device(&fixture);
        let now = fixture.now_ms;
        let accept = |store: &mut IndexedSessionStore, index: u32, message_id: [u8; 16]| {
            let inbound = inbound_message_envelope(&fixture, index, message_id, b"acknowledge me");
            match store
                .accept_message_envelope(
                    &fixture.key,
                    &inbound.pack(),
                    &fixture.remote_certificate,
                    false,
                    now,
                )
                .unwrap()
            {
                EndpointAcceptance::Committed { object_digest, .. } => object_digest,
                _ => unreachable!(),
            }
        };
        let mut queue = |digest: &[u8; 32], _bytes: &[u8]| Ok(*digest);

        // A reply left prepared because the peer was unreachable must not
        // stop inbound messages from being acknowledged.
        {
            let temp = tempdir().unwrap();
            let mut store = open_test_store(
                &temp.path().join("sessions.sqlite"),
                Arc::new(MemoryProtectedBackend::default()),
            );
            store
                .create_session(fixture.binding.clone(), fixture.root)
                .unwrap();
            let mut rng = StdRng::from_seed([0xD1; 32]);
            let mut offline = |_digest: &[u8; 32], _bytes: &[u8]| Err(());
            assert!(matches!(
                store.send_message_envelope(
                    &fixture.key,
                    "peer offline",
                    &local_device,
                    now,
                    now + 60_000,
                    now,
                    &mut rng,
                    &mut offline,
                ),
                Err(IndexedSessionStoreError::OutboundQueueHandoff)
            ));
            let intent = accept(&mut store, 0, [0xD2; 16]);
            let mut ack_rng = StdRng::from_seed([0xD3; 32]);
            let ack = store
                .enqueue_committed_ack(
                    &fixture.key,
                    &intent,
                    &local_device,
                    now,
                    now + 60_000,
                    now,
                    &mut ack_rng,
                    &mut queue,
                )
                .unwrap();
            assert_eq!(ack.kind, EndpointOutboundKind::Ack);
            assert_eq!(ack.state, EndpointOutboxState::Queued);
            let mut second_rng = StdRng::from_seed([0xD4; 32]);
            assert!(matches!(
                store.send_message_envelope(
                    &fixture.key,
                    "message lane still gated",
                    &local_device,
                    now,
                    now + 60_000,
                    now,
                    &mut second_rng,
                    &mut queue,
                ),
                Err(IndexedSessionStoreError::OutboundPending)
            ));
        }

        // A prepared ACK must not block text.
        {
            let temp = tempdir().unwrap();
            let mut store = open_test_store(
                &temp.path().join("sessions.sqlite"),
                Arc::new(MemoryProtectedBackend::default()),
            );
            store
                .create_session(fixture.binding.clone(), fixture.root)
                .unwrap();
            let intent = accept(&mut store, 0, [0xD5; 16]);
            store.inject_endpoint_fault(EndpointFaultPoint::AfterOutboundQueueHandoff);
            let mut ack_rng = StdRng::from_seed([0xD6; 32]);
            assert!(matches!(
                store.enqueue_committed_ack(
                    &fixture.key,
                    &intent,
                    &local_device,
                    now,
                    now + 60_000,
                    now,
                    &mut ack_rng,
                    &mut queue,
                ),
                Err(IndexedSessionStoreError::InjectedEndpointFailure(_))
            ));
            assert_eq!(store.pending_endpoint_outbound().unwrap().len(), 1);
            let mut rng = StdRng::from_seed([0xD7; 32]);
            let sent = store
                .send_message_envelope(
                    &fixture.key,
                    "text after a prepared ACK",
                    &local_device,
                    now,
                    now + 60_000,
                    now,
                    &mut rng,
                    &mut queue,
                )
                .unwrap();
            assert_eq!(sent.state, EndpointOutboxState::Queued);
        }

        // An ACK that expired while prepared can never be retried. It is
        // retired instead of wedging the ACK lane, and is never re-materialized.
        {
            let temp = tempdir().unwrap();
            let mut store = open_test_store(
                &temp.path().join("sessions.sqlite"),
                Arc::new(MemoryProtectedBackend::default()),
            );
            store
                .create_session(fixture.binding.clone(), fixture.root)
                .unwrap();
            let first_intent = accept(&mut store, 0, [0xD8; 16]);
            let second_intent = accept(&mut store, 1, [0xD9; 16]);
            store.inject_endpoint_fault(EndpointFaultPoint::AfterOutboundQueueHandoff);
            let mut ack_rng = StdRng::from_seed([0xDA; 32]);
            assert!(matches!(
                store.enqueue_committed_ack(
                    &fixture.key,
                    &first_intent,
                    &local_device,
                    now,
                    now + 1,
                    now,
                    &mut ack_rng,
                    &mut queue,
                ),
                Err(IndexedSessionStoreError::InjectedEndpointFailure(_))
            ));
            let later = now + 2;
            let mut forbidden = |_digest: &[u8; 32], _bytes: &[u8]| -> Result<[u8; 32], ()> {
                panic!("an expired ACK must never reach the queue")
            };
            for _ in 0..2 {
                let mut unused_rng = StdRng::from_seed([0xDB; 32]);
                assert!(matches!(
                    store.enqueue_committed_ack(
                        &fixture.key,
                        &first_intent,
                        &local_device,
                        later,
                        later + 60_000,
                        later,
                        &mut unused_rng,
                        &mut forbidden,
                    ),
                    Err(IndexedSessionStoreError::EndpointNotCurrentlyValid)
                ));
                assert!(store.pending_endpoint_outbound().unwrap().is_empty());
            }
            let mut next_rng = StdRng::from_seed([0xDC; 32]);
            let next = store
                .enqueue_committed_ack(
                    &fixture.key,
                    &second_intent,
                    &local_device,
                    later,
                    later + 60_000,
                    later,
                    &mut next_rng,
                    &mut queue,
                )
                .unwrap();
            assert_eq!(next.state, EndpointOutboxState::Queued);
            assert_eq!(
                next.ratchet_index, 1,
                "the retired ACK's index stays consumed"
            );
        }
    }

    #[test]
    fn late_journal_clear_never_rolls_back_a_concurrent_instance() {
        #[derive(Debug, Clone, Copy)]
        enum FirstMutation {
            AcceptMessage,
            AcceptAck,
            SendMessage,
        }
        for first in [
            FirstMutation::AcceptMessage,
            FirstMutation::AcceptAck,
            FirstMutation::SendMessage,
        ] {
            let temp = tempdir().unwrap();
            let path = temp.path().join("sessions.sqlite");
            let backend = Arc::new(MemoryProtectedBackend::default());
            let fixture = endpoint_fixture();
            let outstanding = [0xE0; 16];
            {
                let mut store = open_test_store(&path, Arc::clone(&backend));
                store
                    .create_session(fixture.binding.clone(), fixture.root)
                    .unwrap();
                store
                    .register_outstanding_message(&fixture.key, &outstanding)
                    .unwrap();
            }

            // The second instance is opened while no journal exists, so its
            // open takes no write lock, and its busy handler is counted: a
            // journal-clearing writer that holds the write lock makes the
            // second instance observably wait for it.
            let mut second_store = open_test_store(&path, Arc::clone(&backend));
            second_store
                .conn
                .busy_handler(Some(count_busy_wait))
                .unwrap();
            SECOND_INSTANCE_BUSY_WAITS.store(0, Ordering::SeqCst);

            // Park the first instance on its second protected write, which is
            // its journal clear, after its database commit.
            let pause = backend.pause_nth_future_put(2);
            let first_handle = {
                let path = path.clone();
                let backend = Arc::clone(&backend);
                thread::spawn(move || {
                    let fixture = endpoint_fixture();
                    let local_device = authorized_local_device(&fixture);
                    let mut store = open_test_store(&path, backend);
                    let now = fixture.now_ms;
                    match first {
                        FirstMutation::AcceptMessage => {
                            let inbound =
                                inbound_message_envelope(&fixture, 0, [0xE1; 16], b"first");
                            store
                                .accept_message_envelope(
                                    &fixture.key,
                                    &inbound.pack(),
                                    &fixture.remote_certificate,
                                    false,
                                    now,
                                )
                                .map(|_| ())
                        }
                        FirstMutation::AcceptAck => {
                            let ack = inbound_ack_envelope(
                                &fixture,
                                0,
                                [0xE2; 16],
                                outstanding,
                                1,
                                [0xE3; 12],
                            );
                            store
                                .accept_ack_envelope(
                                    &fixture.key,
                                    &ack.pack(),
                                    &fixture.remote_certificate,
                                    false,
                                    now,
                                )
                                .map(|_| ())
                        }
                        FirstMutation::SendMessage => {
                            let mut rng = StdRng::from_seed([0xE4; 32]);
                            let mut queue = |digest: &[u8; 32], _bytes: &[u8]| Ok(*digest);
                            store
                                .send_message_envelope(
                                    &fixture.key,
                                    "first",
                                    &local_device,
                                    now,
                                    now + 60_000,
                                    now,
                                    &mut rng,
                                    &mut queue,
                                )
                                .map(|_| ())
                        }
                    }
                })
            };
            pause.wait_until_parked(&first_handle);

            // A second instance runs a complete mutation of the same session
            // while the first one is parked.
            let (second_done_tx, second_done) = mpsc::channel();
            let second_handle = {
                thread::spawn(move || {
                    let fixture = endpoint_fixture();
                    let inbound = inbound_message_envelope(&fixture, 1, [0xE5; 16], b"second");
                    let result = second_store
                        .accept_message_envelope(
                            &fixture.key,
                            &inbound.pack(),
                            &fixture.remote_certificate,
                            false,
                            fixture.now_ms,
                        )
                        .map(|_| ());
                    let _ = second_done_tx.send(());
                    result
                })
            };
            // Release the parked journal clear only once the second instance
            // is observed either waiting for the write lock the parked writer
            // holds (the expected, serialized outcome) or already finished
            // (a writer that parks outside the lock): the late clear is then
            // really late, with no sleep standing in for that ordering.
            let started = std::time::Instant::now();
            while SECOND_INSTANCE_BUSY_WAITS.load(Ordering::SeqCst) == 0 {
                if second_done.recv_timeout(Duration::from_millis(5)).is_ok() {
                    break;
                }
                assert!(
                    started.elapsed() < RENDEZVOUS_TIMEOUT,
                    "{first:?}: the second instance neither waited for the lock nor finished"
                );
            }
            pause.resume();
            first_handle.join().unwrap().unwrap();
            second_handle.join().unwrap().unwrap();

            let (protected_generation, journal, metadata_generation) =
                protected_and_metadata_generation(&path, &backend, &fixture.key);
            assert!(!journal, "{first:?}");
            assert_eq!(
                protected_generation, metadata_generation,
                "{first:?}: a late journal clear rolled the protected head back"
            );
            let mut reopened = open_test_store(&path, Arc::clone(&backend));
            let inbound = inbound_message_envelope(&fixture, 2, [0xE6; 16], b"still usable");
            reopened
                .accept_message_envelope(
                    &fixture.key,
                    &inbound.pack(),
                    &fixture.remote_certificate,
                    false,
                    fixture.now_ms,
                )
                .unwrap();
        }
    }

    #[test]
    fn passphrase_vault_backend_keeps_session_secrets_across_handles() {
        use crate::keystore_vault::test_support::test_vault;
        const PASS: &str = "session vault passphrase";
        let temp = tempdir().unwrap();
        let dir = temp.path();
        let path = dir.join("sessions.sqlite");
        let vault_backend = |passphrase: &str| {
            Arc::new(VaultSessionBackend {
                vault: test_vault(dir, passphrase).0,
            })
        };
        let binding = fixture_binding();
        let key = binding.key.clone();
        {
            let mut store = IndexedSessionStore::open_with_backend(&path, vault_backend(PASS))
                .expect("open vault-backed store");
            store.create_session(binding, [0xA7; 32]).unwrap();
        }
        let names = test_vault(dir, PASS).0.entry_names().unwrap();
        assert!(
            names
                .iter()
                .all(|name| name.starts_with(crate::keystore_vault::SESSION_ENTRY_PREFIX)),
            "{names:?}"
        );
        assert!(!names.is_empty());
        {
            let mut store =
                IndexedSessionStore::open_with_backend(&path, vault_backend(PASS)).unwrap();
            assert_eq!(
                store.session_lifecycle(&key).unwrap(),
                SessionLifecycle::Provisional
            );
        }
        // A wrong passphrase fails closed as soon as protected state is read.
        let error = match IndexedSessionStore::open_with_backend(
            &path,
            vault_backend("a wrong passphrase"),
        ) {
            Err(error) => error,
            Ok(mut wrong) => wrong.session_lifecycle(&key).unwrap_err(),
        };
        assert!(error.to_string().contains("passphrase"), "{error}");
        let backend = vault_backend(PASS);
        backend.delete("00").unwrap();
        backend.put("00", b"x").unwrap();
        assert_eq!(backend.get("00").unwrap().as_deref(), Some(&b"x"[..]));
        backend.delete("00").unwrap();
        assert!(backend.get("00").unwrap().is_none());
    }

    #[test]
    fn open_does_not_take_the_write_lock_for_sessions_without_a_journal() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        {
            let mut store = open_test_store(&path, Arc::clone(&backend));
            store.create_session(fixture_binding(), [0xA7; 32]).unwrap();
        }
        let writer = Connection::open(&path).unwrap();
        writer.execute_batch("BEGIN IMMEDIATE;").unwrap();
        let started = std::time::Instant::now();
        let store = IndexedSessionStore::open_with_backend(&path, backend)
            .expect("open must not wait for another writer when nothing needs recovery");
        assert!(started.elapsed() < Duration::from_secs(5));
        drop(store);
        writer.execute_batch("ROLLBACK;").unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn metadata_database_and_side_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |file: &Path| std::fs::metadata(file).unwrap().permissions().mode() & 0o777;
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let mut store = open_test_store(&path, Arc::clone(&backend));
        store.create_session(fixture_binding(), [0xA7; 32]).unwrap();
        for suffix in ["", "-wal", "-shm"] {
            let file = PathBuf::from(format!("{}{suffix}", path.display()));
            assert_eq!(mode(&file), 0o600, "{}", file.display());
        }
        drop(store);
        // A database an earlier build left world-readable is tightened.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let _reopened = open_test_store(&path, backend);
        assert_eq!(mode(&path), 0o600);
    }

    #[test]
    fn metadata_schema_is_versioned_and_newer_versions_are_refused() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let binding = fixture_binding();
        let key = binding.key.clone();
        {
            let mut store = open_test_store(&path, Arc::clone(&backend));
            store.create_session(binding, [0xA7; 32]).unwrap();
        }
        let version = |path: &Path| -> i64 {
            Connection::open(path)
                .unwrap()
                .query_row("PRAGMA user_version", [], |row| row.get(0))
                .unwrap()
        };
        // Schema 1 in a profile that is not sealed, 2 in a sealed one (PP.13).
        let current = if open_test_store(&path, Arc::clone(&backend))
            .layout
            .is_keyed()
        {
            METADATA_SCHEMA_VERSION
        } else {
            sealed::CLEAR_VERSION
        };
        assert_eq!(version(&path), current);

        // A database from before versioning keeps its sessions and is stamped.
        Connection::open(&path)
            .unwrap()
            .execute_batch("PRAGMA user_version = 0;")
            .unwrap();
        {
            let mut store = open_test_store(&path, Arc::clone(&backend));
            assert_eq!(
                store.session_lifecycle(&key).unwrap(),
                SessionLifecycle::Provisional
            );
        }
        assert_eq!(version(&path), current);

        // A database written by a newer schema is refused, not reinterpreted.
        Connection::open(&path)
            .unwrap()
            .execute_batch(&format!(
                "PRAGMA user_version = {};",
                METADATA_SCHEMA_VERSION + 1
            ))
            .unwrap();
        assert!(matches!(
            IndexedSessionStore::open_with_backend(&path, backend),
            Err(IndexedSessionStoreError::UnsupportedMetadataSchema(found))
                if found == METADATA_SCHEMA_VERSION + 1
        ));
    }

    #[test]
    fn protected_state_writer_growth_preserves_every_byte() {
        let chunk: Vec<u8> = (0..=u8::MAX).collect();
        let mut writer = BinaryWriter::new();
        for _ in 0..40 {
            writer.bytes(&chunk);
        }
        writer.u8(0x5A);
        let bytes = writer.into_bytes();
        assert_eq!(bytes.len(), 40 * chunk.len() + 1);
        assert!(bytes[..40 * chunk.len()]
            .chunks(chunk.len())
            .all(|part| part == chunk.as_slice()));
        assert_eq!(bytes[bytes.len() - 1], 0x5A);
    }

    #[test]
    fn one_unreadable_session_does_not_make_the_store_unopenable() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let fixture = endpoint_fixture();
        let mut other = fixture.binding.clone();
        other.key.init_id = [0x35; 16];
        other.init_hash = [0x53; 32];
        other.session_id = session_id(&other.init_hash);
        {
            let mut store = open_test_store(&path, Arc::clone(&backend));
            store.create_session(other.clone(), [0xC7; 32]).unwrap();
            store
                .create_session(fixture.binding.clone(), fixture.root)
                .unwrap();
        }
        backend.corrupt(&hex::encode(record_key_digest(&other.key).unwrap()));

        let mut reopened = open_test_store(&path, Arc::clone(&backend));
        assert!(matches!(
            reopened.session_lifecycle(&other.key),
            Err(IndexedSessionStoreError::CorruptProtectedState)
        ));
        let inbound = inbound_message_envelope(&fixture, 0, [0xC8; 16], b"healthy session");
        reopened
            .accept_message_envelope(
                &fixture.key,
                &inbound.pack(),
                &fixture.remote_certificate,
                false,
                fixture.now_ms,
            )
            .unwrap();
    }

    #[test]
    fn inbox_listings_are_ordered_filtered_and_bounded() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let fixture = endpoint_fixture();
        let mut store = open_test_store(&path, backend);
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();
        let message_ids = [[0xF1; 16], [0xF2; 16], [0xF3; 16]];
        for (offset, message_id) in message_ids.iter().enumerate() {
            let inbound = inbound_message_envelope(&fixture, offset as u32, *message_id, b"listed");
            store
                .accept_message_envelope(
                    &fixture.key,
                    &inbound.pack(),
                    &fixture.remote_certificate,
                    false,
                    fixture.now_ms + offset as u64,
                )
                .unwrap();
        }
        let ids = |rows: Vec<EndpointInboxRow>| {
            rows.into_iter()
                .map(|row| row.message_id)
                .collect::<Vec<_>>()
        };
        let remote = fixture.key.responder_device_ed25519;
        assert_eq!(ids(store.list_endpoint_inbox().unwrap()), message_ids);
        assert_eq!(
            ids(store.list_endpoint_inbox_for_sender(&remote).unwrap()),
            message_ids
        );
        assert!(store
            .list_endpoint_inbox_for_sender(&[0xF4; 32])
            .unwrap()
            .is_empty());
        assert_eq!(
            ids(store.list_endpoint_inbox_for_record(&fixture.key).unwrap()),
            message_ids
        );
        assert_eq!(
            ids(store
                .list_endpoint_inbox_for_sender_after(
                    &remote,
                    &after(fixture.now_ms, Some(&message_ids[0])),
                    1
                )
                .unwrap()),
            vec![message_ids[1]]
        );
        assert_eq!(
            ids(store
                .list_endpoint_inbox_for_sender_after(&remote, &after(fixture.now_ms + 1, None), 10)
                .unwrap()),
            vec![message_ids[1], message_ids[2]]
        );
        assert!(store
            .list_endpoint_inbox_for_sender_after(&remote, &after(0, None), 0)
            .unwrap()
            .is_empty());
        assert!(store
            .list_endpoint_inbox()
            .unwrap()
            .iter()
            .all(|row| row.plaintext == b"listed" && row.sender_device == remote));
    }
    // --- Regression tests for the connection/reliability fixes ---

    /// Delegates to a memory backend, counting reads and optionally failing
    /// them, so a test can tell a store-wide failure from a per-session one
    /// and bound the number of protected-backend reads an operation makes.
    struct ObservedBackend {
        inner: Arc<MemoryProtectedBackend>,
        gets: AtomicUsize,
        fail_gets: AtomicBool,
    }

    impl ObservedBackend {
        fn new(inner: Arc<MemoryProtectedBackend>) -> Arc<Self> {
            Arc::new(Self {
                inner,
                gets: AtomicUsize::new(0),
                fail_gets: AtomicBool::new(false),
            })
        }
    }

    impl ProtectedSessionBackend for ObservedBackend {
        fn get(&self, account: &str) -> Result<Option<Vec<u8>>, IndexedSessionStoreError> {
            self.gets.fetch_add(1, Ordering::SeqCst);
            if self.fail_gets.load(Ordering::SeqCst) {
                return Err(IndexedSessionStoreError::ProtectedStore(
                    "keystore locked".into(),
                ));
            }
            self.inner.get(account)
        }

        fn put(&self, account: &str, value: &[u8]) -> Result<(), IndexedSessionStoreError> {
            self.inner.put(account, value)
        }

        fn delete(&self, account: &str) -> Result<(), IndexedSessionStoreError> {
            self.inner.delete(account)
        }
    }

    /// A second session with the same peer: same remote device, its own
    /// init_id, root and session id. `created_at_ms` is shifted so the order
    /// between the two sessions is explicit.
    fn second_session_fixture(created_at_shift_ms: i64) -> EndpointFixture {
        let mut other = endpoint_fixture();
        other.binding.key.init_id = [0x35; 16];
        other.binding.init_hash = [0x53; 32];
        other.binding.session_id = session_id(&other.binding.init_hash);
        other.binding.created_at_ms =
            (other.binding.created_at_ms as i64 + created_at_shift_ms) as u64;
        other.key = other.binding.key.clone();
        other.root = [0xC7; 32];
        other
    }

    fn accept_text(
        store: &mut IndexedSessionStore,
        fixture: &EndpointFixture,
        index: u32,
        message_id: [u8; 16],
        now_ms: u64,
    ) -> [u8; 32] {
        let inbound = inbound_message_envelope(fixture, index, message_id, b"listed");
        match store
            .accept_message_envelope(
                &fixture.key,
                &inbound.pack(),
                &fixture.remote_certificate,
                false,
                now_ms,
            )
            .unwrap()
        {
            EndpointAcceptance::Committed { object_digest, .. } => object_digest,
            other => panic!("unexpected acceptance {other:?}"),
        }
    }

    #[test]
    fn journal_staged_between_recovery_and_operation_is_replayed_not_reported_corrupt() {
        #[derive(Debug, Clone, Copy)]
        enum Operation {
            AcceptMessage,
            AcceptAck,
            SendMessage,
            EnqueueAck,
            Confirm,
        }
        for operation in [
            Operation::AcceptMessage,
            Operation::AcceptAck,
            Operation::SendMessage,
            Operation::EnqueueAck,
            Operation::Confirm,
        ] {
            let temp = tempdir().unwrap();
            let path = temp.path().join("sessions.sqlite");
            let backend = Arc::new(MemoryProtectedBackend::default());
            let fixture = endpoint_fixture();
            let local_device = authorized_local_device(&fixture);
            let now = fixture.now_ms;
            let outstanding = [0xE0; 16];
            let mut binding = fixture.binding.clone();
            if matches!(operation, Operation::Confirm) {
                binding.lifecycle = SessionLifecycle::Provisional;
                binding.response_hash = None;
            }
            let mut store = open_test_store(&path, Arc::clone(&backend));
            store.create_session(binding, fixture.root).unwrap();
            store
                .register_outstanding_message(&fixture.key, &outstanding)
                .unwrap();
            let intent = matches!(operation, Operation::EnqueueAck)
                .then(|| accept_text(&mut store, &fixture, 0, [0xE8; 16], now));

            // Right after this instance finishes its journal recovery, a second
            // instance commits a journaled mutation of the same session and
            // dies before clearing its journal. The write lock is free in
            // that window, so this instance's own transaction sees a healthy
            // committed-but-uncleared journal.
            let racing_send = matches!(operation, Operation::Confirm);
            store.inject_after_recovery_hook({
                let path = path.clone();
                let backend = Arc::clone(&backend);
                move || {
                    let fixture = endpoint_fixture();
                    let mut other = open_test_store(&path, backend);
                    other.inject_endpoint_fault(EndpointFaultPoint::BeforeJournalClear);
                    let raced = if racing_send {
                        let local_device = authorized_local_device(&fixture);
                        let mut rng = StdRng::from_seed([0xE7; 32]);
                        let mut queue = |digest: &[u8; 32], _bytes: &[u8]| Ok(*digest);
                        other
                            .send_message_envelope(
                                &fixture.key,
                                "racing",
                                &local_device,
                                fixture.now_ms,
                                fixture.now_ms + 60_000,
                                fixture.now_ms,
                                &mut rng,
                                &mut queue,
                            )
                            .map(|_| ())
                    } else {
                        let inbound = inbound_message_envelope(&fixture, 1, [0xE5; 16], b"racing");
                        other
                            .accept_message_envelope(
                                &fixture.key,
                                &inbound.pack(),
                                &fixture.remote_certificate,
                                false,
                                fixture.now_ms,
                            )
                            .map(|_| ())
                    };
                    assert!(
                        matches!(raced, Err(IndexedSessionStoreError::InjectedEndpointFailure(_))),
                        "the racing writer must stop between its commit and its journal clear: {raced:?}"
                    );
                }
            });

            let mut rng = StdRng::from_seed([0xE9; 32]);
            let mut queue = |digest: &[u8; 32], _bytes: &[u8]| Ok(*digest);
            let result = match operation {
                Operation::AcceptMessage => {
                    let inbound = inbound_message_envelope(&fixture, 2, [0xE6; 16], b"mine");
                    store
                        .accept_message_envelope(
                            &fixture.key,
                            &inbound.pack(),
                            &fixture.remote_certificate,
                            false,
                            now,
                        )
                        .map(|_| ())
                }
                Operation::AcceptAck => {
                    let ack =
                        inbound_ack_envelope(&fixture, 0, [0xE2; 16], outstanding, 1, [0xE3; 12]);
                    store
                        .accept_ack_envelope(
                            &fixture.key,
                            &ack.pack(),
                            &fixture.remote_certificate,
                            false,
                            now,
                        )
                        .map(|_| ())
                }
                Operation::SendMessage => store
                    .send_message_envelope(
                        &fixture.key,
                        "mine",
                        &local_device,
                        now,
                        now + 60_000,
                        now,
                        &mut rng,
                        &mut queue,
                    )
                    .map(|_| ()),
                Operation::EnqueueAck => store
                    .enqueue_committed_ack(
                        &fixture.key,
                        &intent.unwrap(),
                        &local_device,
                        now,
                        now + 60_000,
                        now,
                        &mut rng,
                        &mut queue,
                    )
                    .map(|_| ()),
                Operation::Confirm => store.confirm_session(&fixture.key, [0x46; 32]),
            };
            result.unwrap_or_else(|error| panic!("{operation:?}: {error:?}"));

            let (protected_generation, journal, metadata_generation) =
                protected_and_metadata_generation(&path, &backend, &fixture.key);
            assert!(!journal, "{operation:?}");
            assert_eq!(protected_generation, metadata_generation, "{operation:?}");
            if let Operation::Confirm = operation {
                // The racing optimistic send survived the confirmation and
                // its object is still retryable: the session is not wedged.
                assert_eq!(
                    store.session_lifecycle(&fixture.key).unwrap(),
                    SessionLifecycle::Confirmed
                );
                let prepared = store.pending_endpoint_outbound().unwrap();
                assert_eq!(prepared.len(), 1);
                let retried = store
                    .retry_endpoint_outbound(
                        &fixture.key,
                        &prepared[0].object_digest,
                        &local_device,
                        now,
                        &mut queue,
                    )
                    .unwrap();
                assert_eq!(retried.state, EndpointOutboxState::Queued);
            } else {
                // The racing writer's committed message is not lost.
                assert!(
                    store
                        .list_endpoint_inbox()
                        .unwrap()
                        .iter()
                        .any(|row| row.message_id == [0xE5; 16]),
                    "{operation:?}"
                );
            }
        }
    }

    #[test]
    fn peer_lookup_skips_an_unreadable_live_session_but_not_a_store_wide_failure() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let memory = Arc::new(MemoryProtectedBackend::default());
        let observed = ObservedBackend::new(Arc::clone(&memory));
        let fixture = endpoint_fixture();
        let old = second_session_fixture(-1_000);
        let peer = fixture.key.responder_device_ed25519;
        let mut store =
            IndexedSessionStore::open_with_backend(&path, observed.clone()).expect("open");
        store.create_session(old.binding.clone(), old.root).unwrap();
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();
        let old_account = hex::encode(record_key_digest(&old.key).unwrap());
        let newest = |store: &mut IndexedSessionStore| {
            store.find_confirmed_session_for_peer_at(&peer, fixture.now_ms)
        };
        assert_eq!(newest(&mut store).unwrap(), Some(fixture.key.clone()));

        // Only the newer session is healthy: the older head is oldest-first, so
        // it used to abort the lookup before the newer one was considered. A
        // missing secret and a corrupt blob are both per-session failures.
        memory.corrupt(&old_account);
        assert_eq!(newest(&mut store).unwrap(), Some(fixture.key.clone()));
        memory.delete(&old_account).unwrap();
        assert_eq!(newest(&mut store).unwrap(), Some(fixture.key.clone()));

        // With the newer session unreadable too there is nothing usable.
        memory
            .delete(&hex::encode(record_key_digest(&fixture.key).unwrap()))
            .unwrap();
        assert_eq!(newest(&mut store).unwrap(), None);
        memory
            .put(
                &hex::encode(record_key_digest(&fixture.key).unwrap()),
                b"garbage",
            )
            .unwrap();
        assert_eq!(newest(&mut store).unwrap(), None);

        // A locked or unavailable keystore is store-wide and still fails: the
        // newest session is only temporarily unreadable, so falling back to an
        // older one would be wrong.
        observed.fail_gets.store(true, Ordering::SeqCst);
        assert!(matches!(
            newest(&mut store),
            Err(IndexedSessionStoreError::ProtectedStore(_))
        ));
        assert!(!is_session_scoped_state_error(
            &IndexedSessionStoreError::ProtectedStore("locked".into())
        ));
        assert!(is_session_scoped_state_error(
            &IndexedSessionStoreError::ProtectedStateMissing
        ));
    }

    /// Peers that pair at the same moment hold two confirmed sessions with each
    /// other, and both nodes must select the *same* one. The head's
    /// `created_at_ms` is the init's stamp (identical on both sides); on an exact
    /// tie the order used to fall to the node-local `rowid`, so the two nodes
    /// picked different sessions and every message was refused as a route-tag
    /// mismatch. The tie now breaks on `init_id`, identical on both nodes.
    #[test]
    fn crossed_sessions_are_selected_identically_on_both_nodes() {
        let fixture = endpoint_fixture();
        let other = second_session_fixture(0); // same stamp, init_id 0x35 > 0x33
        let peer = fixture.key.responder_device_ed25519;
        assert_eq!(fixture.binding.created_at_ms, other.binding.created_at_ms);
        assert!(other.key.init_id > fixture.key.init_id);

        // Node 1 learned the sessions in one order, node 2 in the other.
        let mut answers = Vec::new();
        for order in [[&fixture, &other], [&other, &fixture]] {
            let temp = tempdir().unwrap();
            let backend = Arc::new(MemoryProtectedBackend::default());
            let mut store = open_test_store(&temp.path().join("sessions.sqlite"), backend);
            for f in order {
                store.create_session(f.binding.clone(), f.root).unwrap();
            }
            let all = store
                .find_confirmed_sessions_for_peer_at(&peer, fixture.now_ms)
                .unwrap();
            // Newest first, the answer of the single-session lookup is the head.
            assert_eq!(all, vec![other.key.clone(), fixture.key.clone()]);
            assert_eq!(
                store
                    .find_confirmed_session_for_peer_at(&peer, fixture.now_ms)
                    .unwrap(),
                Some(other.key.clone())
            );
            answers.push(all);
        }
        assert_eq!(answers[0], answers[1], "both nodes agree on the order");
    }

    /// ATSAM_ENDPOINT_TRANSACTION_V1 §1 step 4: the route tag selects the session
    /// BEFORE that session's own lifetime window applies. A message sealed under
    /// an older live session, at a time before a newer session with the same peer
    /// even existed, must be refused by the newer session as "not this session"
    /// (RouteTagMismatch, so the caller goes on to the older one), never as "not
    /// currently valid", which used to end the search and lose the message.
    #[test]
    fn an_older_sessions_message_is_not_refused_by_a_newer_sessions_window() {
        let older = endpoint_fixture();
        let skew = crate::prekey_lifecycle::MAX_PREKEY_FUTURE_SKEW_MS;
        let newer = second_session_fixture((skew + 60_000) as i64);
        let temp = tempdir().unwrap();
        let backend = Arc::new(MemoryProtectedBackend::default());
        let mut store = open_test_store(&temp.path().join("sessions.sqlite"), backend);
        store
            .create_session(older.binding.clone(), older.root)
            .unwrap();
        store
            .create_session(newer.binding.clone(), newer.root)
            .unwrap();
        let start = older.binding.created_at_ms;
        let sealed_under_older =
            retimed_message_envelope(&older, 0, [0x61; 16], start + 1_000, start + 3_600_000);
        assert!(
            sealed_under_older.created_at + skew < newer.binding.created_at_ms,
            "the message predates the newer session beyond any clock skew"
        );
        let now = newer.binding.created_at_ms + 1_000;
        assert!(matches!(
            store.accept_message_envelope(
                &newer.key,
                &sealed_under_older.pack(),
                &newer.remote_certificate,
                false,
                now,
            ),
            Err(IndexedSessionStoreError::RouteTagMismatch)
        ));
        assert!(matches!(
            store.accept_message_envelope(
                &older.key,
                &sealed_under_older.pack(),
                &older.remote_certificate,
                false,
                now,
            ),
            Ok(EndpointAcceptance::Committed { .. })
        ));
    }

    /// A strictly newer stamp still wins over a larger `init_id`.
    #[test]
    fn newer_stamp_beats_a_larger_init_id() {
        let fixture = endpoint_fixture();
        let older_but_larger_id = second_session_fixture(-1_000);
        assert!(older_but_larger_id.key.init_id > fixture.key.init_id);
        let peer = fixture.key.responder_device_ed25519;
        let temp = tempdir().unwrap();
        let backend = Arc::new(MemoryProtectedBackend::default());
        let mut store = open_test_store(&temp.path().join("sessions.sqlite"), backend);
        store
            .create_session(
                older_but_larger_id.binding.clone(),
                older_but_larger_id.root,
            )
            .unwrap();
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();
        assert_eq!(
            store
                .find_confirmed_sessions_for_peer_at(&peer, fixture.now_ms)
                .unwrap(),
            vec![fixture.key.clone(), older_but_larger_id.key.clone()]
        );
    }

    #[test]
    fn inbox_listings_skip_an_unreadable_session_and_read_each_session_once() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let memory = Arc::new(MemoryProtectedBackend::default());
        let observed = ObservedBackend::new(Arc::clone(&memory));
        let fixture = endpoint_fixture();
        let poisoned = second_session_fixture(-1_000);
        let remote = fixture.key.responder_device_ed25519;
        let mut store =
            IndexedSessionStore::open_with_backend(&path, observed.clone()).expect("open");
        store
            .create_session(poisoned.binding.clone(), poisoned.root)
            .unwrap();
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();
        let now = fixture.now_ms;
        // Interleaved in time so a per-session listing would reorder them.
        accept_text(&mut store, &poisoned, 0, [0xA1; 16], now);
        accept_text(&mut store, &fixture, 0, [0xA2; 16], now + 1);
        accept_text(&mut store, &poisoned, 1, [0xA3; 16], now + 2);
        accept_text(&mut store, &fixture, 1, [0xA4; 16], now + 3);
        accept_text(&mut store, &fixture, 2, [0xA5; 16], now + 4);
        let ids = |rows: Vec<EndpointInboxRow>| {
            rows.into_iter()
                .map(|row| row.message_id)
                .collect::<Vec<_>>()
        };
        let everything = [[0xA1; 16], [0xA2; 16], [0xA3; 16], [0xA4; 16], [0xA5; 16]];
        assert_eq!(ids(store.list_endpoint_inbox().unwrap()), everything);
        assert_eq!(store.list_endpoint_inbox_counted().unwrap().unreadable, 0);

        // The protected-backend reads do not scale with the number of rows.
        let before = observed.gets.load(Ordering::SeqCst);
        store.list_endpoint_inbox().unwrap();
        let reads = observed.gets.load(Ordering::SeqCst) - before;
        assert!(
            reads <= 2 * 2,
            "{reads} protected reads for 5 rows in 2 sessions"
        );

        // A session whose secret is gone (a prune that died after deleting it)
        // is skipped by every cross-session listing; the healthy session's
        // rows keep flowing, in order.
        memory
            .delete(&hex::encode(record_key_digest(&poisoned.key).unwrap()))
            .unwrap();
        let healthy = [[0xA2; 16], [0xA4; 16], [0xA5; 16]];
        assert_eq!(ids(store.list_endpoint_inbox().unwrap()), healthy);
        // ... and its rows are counted, never taken for "nothing arrived"
        // (`raven inbox`, E2 round 7).
        let counted = store.list_endpoint_inbox_counted().unwrap();
        assert_eq!(
            (ids(counted.rows), counted.unreadable),
            (healthy.to_vec(), 2)
        );
        assert_eq!(
            ids(store.list_endpoint_inbox_for_sender(&remote).unwrap()),
            healthy
        );
        // The poisoned row is first in order: the page of one must not stall on
        // it but continue to the first healthy row after it.
        assert_eq!(
            ids(store
                .list_endpoint_inbox_for_sender_after(&remote, &after(0, None), 1)
                .unwrap()),
            vec![[0xA2; 16]]
        );
        assert_eq!(
            ids(store
                .list_endpoint_inbox_for_sender_after(&remote, &after(0, None), 2)
                .unwrap()),
            vec![[0xA2; 16], [0xA4; 16]]
        );
        assert_eq!(
            ids(store
                .list_endpoint_inbox_for_sender_after(
                    &remote,
                    &after(now + 1, Some(&[0xA2; 16])),
                    10
                )
                .unwrap()),
            vec![[0xA4; 16], [0xA5; 16]]
        );
        // The per-record listing stays strict: the expiry archive matches on
        // this exact error.
        assert!(matches!(
            store.list_endpoint_inbox_for_record(&poisoned.key),
            Err(IndexedSessionStoreError::ProtectedStateMissing)
        ));
        assert_eq!(
            ids(store.list_endpoint_inbox_for_record(&fixture.key).unwrap()),
            healthy
        );

        // A keystore that is locked is store-wide, never skipped.
        observed.fail_gets.store(true, Ordering::SeqCst);
        assert!(matches!(
            store.list_endpoint_inbox(),
            Err(IndexedSessionStoreError::ProtectedStore(_))
        ));
    }

    #[test]
    fn paged_inbox_listing_loads_an_unreadable_session_once_per_call() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let memory = Arc::new(MemoryProtectedBackend::default());
        let observed = ObservedBackend::new(Arc::clone(&memory));
        let fixture = endpoint_fixture();
        let poisoned = second_session_fixture(-1_000);
        let remote = fixture.key.responder_device_ed25519;
        let mut store =
            IndexedSessionStore::open_with_backend(&path, observed.clone()).expect("open");
        store
            .create_session(poisoned.binding.clone(), poisoned.root)
            .unwrap();
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();
        let now = fixture.now_ms;
        // Several unreadable rows in front of the healthy ones: a poll with a
        // small decrypt budget crosses one page per row.
        for index in 0..3u8 {
            accept_text(
                &mut store,
                &poisoned,
                u32::from(index),
                [0xC1 + index; 16],
                now + u64::from(index),
            );
        }
        accept_text(&mut store, &fixture, 0, [0xC8; 16], now + 3);
        accept_text(&mut store, &fixture, 1, [0xC9; 16], now + 4);
        memory
            .delete(&hex::encode(record_key_digest(&poisoned.key).unwrap()))
            .unwrap();
        let poll = |store: &mut IndexedSessionStore, limit: usize| {
            let before = observed.gets.load(Ordering::SeqCst);
            let rows = store
                .list_endpoint_inbox_for_sender_after(&remote, &after(0, None), limit)
                .unwrap();
            let reads = observed.gets.load(Ordering::SeqCst) - before;
            (
                rows.iter().map(|row| row.message_id).collect::<Vec<_>>(),
                reads,
            )
        };

        // One page covers every row, so each session is loaded exactly once.
        let (all, single_page_reads) = poll(&mut store, 10);
        assert_eq!(all, vec![[0xC8; 16], [0xC9; 16]]);
        assert!(single_page_reads > 0);

        // One row per page walks past three unreadable rows, yet the
        // unreadable session costs no more than it did in the single page.
        let (first, paged_reads) = poll(&mut store, 1);
        assert_eq!(first, vec![[0xC8; 16]]);
        assert_eq!(paged_reads, single_page_reads);
    }

    #[test]
    fn skipped_session_log_reports_each_failure_once_and_stays_bounded() {
        let mut log = SkippedSessionLog::new();
        assert!(log.first_report(b"session-a", "missing"));
        assert!(!log.first_report(b"session-a", "missing"));
        // Another session, or the same one failing differently, is news.
        assert!(log.first_report(b"session-b", "missing"));
        assert!(log.first_report(b"session-a", "corrupt"));
        assert!(!log.first_report(b"session-a", "corrupt"));

        // The memory never grows past its bound; a full one starts over.
        let mut log = SkippedSessionLog::new();
        for index in 0..(MAX_LOGGED_SKIPPED_SESSIONS * 3) {
            assert!(log.first_report(&index.to_be_bytes(), "missing"));
            assert!(log.seen.len() <= MAX_LOGGED_SKIPPED_SESSIONS);
        }
    }

    #[test]
    fn received_stamp_is_strictly_increasing_per_sender_in_commit_order() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let fixture = endpoint_fixture();
        let remote = fixture.key.responder_device_ed25519;
        let mut store = open_test_store(&path, backend);
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();
        let now = fixture.now_ms;
        // The first handler captured its clock late (or the clock stepped
        // back): the second commit carries an earlier `now_ms`.
        accept_text(&mut store, &fixture, 0, [0xB1; 16], now + 10);
        let polled = store
            .list_endpoint_inbox_for_sender_after(&remote, &after(0, None), 10)
            .unwrap();
        assert_eq!(polled.len(), 1);
        let cursor = (polled[0].received_at_ms, polled[0].message_id);
        accept_text(&mut store, &fixture, 1, [0xB2; 16], now);
        accept_text(&mut store, &fixture, 2, [0xB3; 16], now);
        let after = store
            .list_endpoint_inbox_for_sender_after(&remote, &after(cursor.0, Some(&cursor.1)), 10)
            .unwrap();
        assert_eq!(
            after.iter().map(|row| row.message_id).collect::<Vec<_>>(),
            vec![[0xB2; 16], [0xB3; 16]],
            "a late-committed row must stay reachable by a cursor that already advanced"
        );
        let stamps: Vec<u64> = store
            .list_endpoint_inbox_for_sender(&remote)
            .unwrap()
            .iter()
            .map(|row| row.received_at_ms)
            .collect();
        assert_eq!(stamps, vec![now + 10, now + 11, now + 12]);
        // A sender with no earlier rows keeps the caller's clock.
        assert_eq!(
            monotonic_received_at_ms(&store.conn, &store.layout, &[0x62; 32], now).unwrap(),
            now
        );
    }

    #[test]
    fn abandon_never_deletes_the_ciphertext_of_an_acknowledged_message() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let fixture = endpoint_fixture();
        let local_device = authorized_local_device(&fixture);
        let now = fixture.now_ms;
        let mut store = open_test_store(&path, backend);
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();
        let mut queue = |digest: &[u8; 32], _bytes: &[u8]| Ok(*digest);
        let mut rng = StdRng::from_seed([0xC1; 32]);
        let outbound = store
            .send_message_envelope(
                &fixture.key,
                "delivered meanwhile",
                &local_device,
                now,
                now + 60_000,
                now,
                &mut rng,
                &mut queue,
            )
            .unwrap();
        let outbox_rows = |store: &IndexedSessionStore| -> i64 {
            store
                .conn
                .query_row(
                    &store
                        .layout
                        .ep("SELECT COUNT(*) FROM endpoint_outbox WHERE kh_object_digest = ?1"),
                    params![store.layout.ep_digest(&outbound.object_digest)],
                    |row| row.get(0),
                )
                .unwrap()
        };
        let remote = fixture.key.responder_device_ed25519;

        // The caller listed the row as awaiting an ACK, then an ACK was accepted.
        assert_eq!(store.awaiting_ack_endpoint_outbound().unwrap().len(), 1);
        let ack = inbound_ack_envelope(&fixture, 0, [0xC2; 16], outbound.message_id, 1, [0xC3; 12]);
        store
            .accept_ack_envelope(
                &fixture.key,
                &ack.pack(),
                &fixture.remote_certificate,
                false,
                now,
            )
            .unwrap();
        assert!(!store
            .abandon_undelivered_outbound(&fixture.key, &outbound.object_digest)
            .unwrap());
        assert_eq!(outbox_rows(&store), 1, "delivered ciphertext must survive");
        assert_eq!(
            store
                .outstanding_delivery_state(
                    &fixture.binding.session_id,
                    &outbound.message_id,
                    &remote
                )
                .unwrap(),
            Some(EndpointDeliveryState::Delivered)
        );

        // An outbox row whose outstanding row is gone is an orphan: still cleaned.
        store
            .conn
            .execute(
                &store
                    .layout
                    .ep("DELETE FROM endpoint_outstanding_messages WHERE kh_message_id = ?1"),
                params![store.layout.ep_mid(&outbound.message_id)],
            )
            .unwrap();
        assert!(store
            .abandon_undelivered_outbound(&fixture.key, &outbound.object_digest)
            .unwrap());
        assert_eq!(outbox_rows(&store), 0);
    }

    #[test]
    fn locked_file_session_backend_is_refused_in_release_builds() {
        assert!(matches!(
            locked_file_session_backend_gate(true, false),
            Err(IndexedSessionStoreError::ProtectedStore(message))
                if message == "locked-file session backend is forbidden in Release builds"
        ));
        assert!(locked_file_session_backend_gate(true, true).unwrap());
        assert!(!locked_file_session_backend_gate(false, false).unwrap());
        assert!(!locked_file_session_backend_gate(false, true).unwrap());
    }

    #[test]
    fn failed_session_creation_does_not_leave_an_orphaned_secret() {
        // Both a failing insert and a failing commit happen after the secret
        // was written; neither may leave a root nothing will ever find again.
        for (label, setup) in [
            (
                "insert",
                "CREATE TRIGGER fail_head BEFORE INSERT ON indexed_session_heads
                 BEGIN SELECT RAISE(ABORT, 'simulated insert failure'); END;",
            ),
            (
                "commit",
                "CREATE TABLE commit_guard(
                   x INTEGER REFERENCES commit_anchor(x) DEFERRABLE INITIALLY DEFERRED);
                 CREATE TABLE commit_anchor(x INTEGER PRIMARY KEY);
                 CREATE TRIGGER fail_commit AFTER INSERT ON indexed_session_heads
                 BEGIN INSERT INTO commit_guard VALUES (1); END;",
            ),
        ] {
            let temp = tempdir().unwrap();
            let path = temp.path().join("sessions.sqlite");
            let backend = Arc::new(MemoryProtectedBackend::default());
            let fixture = endpoint_fixture();
            let account = hex::encode(record_key_digest(&fixture.key).unwrap());
            let mut store = open_test_store(&path, Arc::clone(&backend));
            Connection::open(&path)
                .unwrap()
                .execute_batch(setup)
                .unwrap();
            assert!(
                matches!(
                    store.create_session(fixture.binding.clone(), fixture.root),
                    Err(IndexedSessionStoreError::Sqlite(_))
                ),
                "{label}"
            );
            assert!(
                backend.get(&account).unwrap().is_none(),
                "{label}: orphaned protected root"
            );
            assert!(store.list_record_keys().unwrap().is_empty(), "{label}");

            // Once the fault clears, the same PairInit creates the session.
            Connection::open(&path)
                .unwrap()
                .execute_batch(
                    "DROP TRIGGER IF EXISTS fail_head; DROP TRIGGER IF EXISTS fail_commit;",
                )
                .unwrap();
            store
                .create_session(fixture.binding.clone(), fixture.root)
                .unwrap();
            assert!(backend.get(&account).unwrap().is_some(), "{label}");
        }
    }

    // --- Rollback, certificate pin, session window and ordering coverage ---

    /// A session whose send ratchet sits at index 2, with the protected blob
    /// captured after index 1 (stale) and after index 2 (current).
    struct AdvancedSession {
        _temp: tempfile::TempDir,
        path: PathBuf,
        backend: Arc<MemoryProtectedBackend>,
        store: IndexedSessionStore,
        fixture: EndpointFixture,
        account: String,
        stale_blob: Vec<u8>,
        current_blob: Vec<u8>,
    }

    fn advanced_session() -> AdvancedSession {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let fixture = endpoint_fixture();
        let account = hex::encode(record_key_digest(&fixture.key).unwrap());
        let mut store = open_test_store(&path, Arc::clone(&backend));
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();
        let reserve = |store: &mut IndexedSessionStore| {
            store
                .reserve_send_key(&fixture.key, RatchetLane::Message)
                .unwrap()
                .index
        };
        assert_eq!(reserve(&mut store), 0);
        let stale_blob = backend.get(&account).unwrap().unwrap();
        assert_eq!(reserve(&mut store), 1);
        let current_blob = backend.get(&account).unwrap().unwrap();
        assert_ne!(stale_blob, current_blob);
        AdvancedSession {
            _temp: temp,
            path,
            backend,
            store,
            fixture,
            account,
            stale_blob,
            current_blob,
        }
    }

    /// Public head columns of the session: (generation, binding digest).
    fn head_columns(path: &Path, key: &IndexedSessionRecordKey) -> (i64, Vec<u8>) {
        let record_key = record_key_digest(key).unwrap();
        Connection::open(path)
            .unwrap()
            .query_row(
                "SELECT generation, binding_digest FROM indexed_session_heads
                 WHERE record_key = ?1",
                params![record_key.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap()
    }

    /// The error each entry point that loads the protected head returns
    /// (reserve, receive, message acceptance, ACK acceptance).
    fn entry_point_errors(session: &mut AdvancedSession) -> [Option<IndexedSessionStoreError>; 4] {
        let fixture = &session.fixture;
        let message = inbound_message_envelope(fixture, 0, [0xB0; 16], b"after the fault");
        let ack = inbound_ack_envelope(fixture, 0, [0xB1; 16], [0xB2; 16], 1, [0xB3; 12]);
        [
            session
                .store
                .reserve_send_key(&fixture.key, RatchetLane::Message)
                .err(),
            session
                .store
                .authenticate_receive::<(), _>(&fixture.key, RatchetLane::Message, 0, |_| Some(()))
                .err(),
            session
                .store
                .accept_message_envelope(
                    &fixture.key,
                    &message.pack(),
                    &fixture.remote_certificate,
                    false,
                    fixture.now_ms,
                )
                .err(),
            session
                .store
                .accept_ack_envelope(
                    &fixture.key,
                    &ack.pack(),
                    &fixture.remote_certificate,
                    false,
                    fixture.now_ms,
                )
                .err(),
        ]
    }

    #[test]
    fn restored_older_protected_blob_is_refused_as_rollback_and_never_adopted() {
        let mut session = advanced_session();
        let head = head_columns(&session.path, &session.fixture.key);

        // A backup restore or replayed keychain item puts an older protected
        // blob back: the public head is ahead of it.
        session
            .backend
            .put(&session.account, &session.stale_blob)
            .unwrap();
        let cap = crate::security_sense::tests::Capture::start();
        let errors = entry_point_errors(&mut session);
        for error in &errors {
            assert!(
                matches!(error, Some(IndexedSessionStoreError::RollbackDetected)),
                "{error:?}"
            );
        }
        // Phase 6b S23: each refusal is SEC_LOCAL_ROLLBACK about this
        // computer, noted where the store finds it.
        if let Some(cap) = cap {
            use crate::security_events::{Attribution, SecKind, Via};
            let local = (SecKind::LocalRollback, Attribution::Local, Via::Local);
            assert_eq!(cap.kinds(), vec![local; errors.len()]);
        }
        assert_eq!(
            head_columns(&session.path, &session.fixture.key),
            head,
            "the public head must not be rewound to the stale blob"
        );
        assert_eq!(
            session.backend.get(&session.account).unwrap().unwrap(),
            session.stale_blob,
            "the stale blob must not be repaired or rewritten"
        );

        // The refusal survives a reopen ...
        let AdvancedSession {
            _temp,
            path,
            backend,
            store,
            fixture,
            account,
            current_blob,
            ..
        } = session;
        drop(store);
        let mut reopened = open_test_store(&path, Arc::clone(&backend));
        assert!(matches!(
            reopened.reserve_send_key(&fixture.key, RatchetLane::Message),
            Err(IndexedSessionStoreError::RollbackDetected)
        ));
        // ... and lifts once the current blob is back, resuming after the
        // indexes already handed out (no send key is reused).
        backend.put(&account, &current_blob).unwrap();
        assert_eq!(
            reopened
                .reserve_send_key(&fixture.key, RatchetLane::Message)
                .unwrap()
                .index,
            2
        );
    }

    #[test]
    fn metadata_generation_ahead_of_the_protected_head_is_rollback() {
        let mut session = advanced_session();
        let (generation, digest) = head_columns(&session.path, &session.fixture.key);
        let metadata_path = session.path.clone();
        let set_generation = |value: i64| {
            Connection::open(&metadata_path)
                .unwrap()
                .execute(
                    "UPDATE indexed_session_heads SET generation = ?1",
                    params![value],
                )
                .unwrap();
        };
        set_generation(generation + 1);
        for error in entry_point_errors(&mut session) {
            assert!(
                matches!(error, Some(IndexedSessionStoreError::RollbackDetected)),
                "{error:?}"
            );
        }
        assert_eq!(
            head_columns(&session.path, &session.fixture.key),
            (generation + 1, digest),
            "a refused access must not touch the public head"
        );
        assert_eq!(
            session.backend.get(&session.account).unwrap().unwrap(),
            session.current_blob
        );
        set_generation(generation);
        assert_eq!(
            session
                .store
                .reserve_send_key(&session.fixture.key, RatchetLane::Message)
                .unwrap()
                .index,
            2
        );
    }

    #[test]
    fn binding_digest_mismatch_at_equal_generation_is_corruption_not_rollback() {
        let mut session = advanced_session();
        let (generation, digest) = head_columns(&session.path, &session.fixture.key);
        let tampered = [0xEE_u8; 32];
        assert_ne!(digest.as_slice(), tampered.as_slice());
        let metadata_path = session.path.clone();
        let set_digest = |value: &[u8]| {
            Connection::open(&metadata_path)
                .unwrap()
                .execute(
                    "UPDATE indexed_session_heads SET binding_digest = ?1",
                    params![value],
                )
                .unwrap();
        };
        set_digest(&tampered);
        for error in entry_point_errors(&mut session) {
            assert!(
                matches!(error, Some(IndexedSessionStoreError::CorruptProtectedState)),
                "{error:?}"
            );
        }
        assert_eq!(
            head_columns(&session.path, &session.fixture.key),
            (generation, tampered.to_vec()),
            "a refused access must not touch the public head"
        );
        set_digest(&digest);
        assert_eq!(
            session
                .store
                .reserve_send_key(&session.fixture.key, RatchetLane::Message)
                .unwrap()
                .index,
            2
        );
    }

    #[test]
    fn sender_certificate_pin_is_enforced_on_message_and_ack_ingress() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let fixture = endpoint_fixture();
        let mut store = open_test_store(&path, backend);
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();
        let outstanding = [0xC0; 16];
        store
            .register_outstanding_message(&fixture.key, &outstanding)
            .unwrap();

        // Every imposter is a valid, currently valid certificate. Three carry
        // the pinned device key but hash differently from the PairInit-bound
        // certificate, so only the digest clause can reject them; the fourth
        // certifies another device key.
        let remote_user = Identity::from_seed(&[0x23; 32]);
        let pinned_device = fixture.remote_identity.public_key_bytes();
        let issue = |issuer: &Identity, device: [u8; 32], label: &str, window: (u64, u64)| {
            DeviceCertificate::issue(issuer, device, [0x24; 32], label, window.0, window.1, 1)
                .unwrap()
        };
        let pinned_window = (1_699_999_000_000, 1_700_200_000_000);
        let imposters = [
            (
                "other issuing user",
                issue(
                    &Identity::from_seed(&[0x66; 32]),
                    pinned_device,
                    "remote-device",
                    pinned_window,
                ),
            ),
            (
                "other device label",
                issue(
                    &remote_user,
                    pinned_device,
                    "remote-device-2",
                    pinned_window,
                ),
            ),
            (
                "other validity window",
                issue(
                    &remote_user,
                    pinned_device,
                    "remote-device",
                    (fixture.now_ms - 1_000, fixture.now_ms + 1_000_000),
                ),
            ),
            (
                "other device key",
                issue(
                    &remote_user,
                    Identity::from_seed(&[0x67; 32]).public_key_bytes(),
                    "remote-device",
                    pinned_window,
                ),
            ),
        ];
        let message = inbound_message_envelope(&fixture, 0, [0xC1; 16], b"pinned sender");
        let ack = inbound_ack_envelope(&fixture, 0, [0xC2; 16], outstanding, 1, [0xC3; 12]);
        for (label, certificate) in &imposters {
            certificate.verify(fixture.now_ms).unwrap();
            assert_ne!(
                device_certificate_hash(certificate).unwrap(),
                fixture.binding.responder_cert_digest,
                "{label}"
            );
            assert!(
                matches!(
                    store.accept_message_envelope(
                        &fixture.key,
                        &message.pack(),
                        certificate,
                        false,
                        fixture.now_ms,
                    ),
                    Err(IndexedSessionStoreError::DeviceBindingMismatch)
                ),
                "{label}: message"
            );
            assert!(
                matches!(
                    store.accept_ack_envelope(
                        &fixture.key,
                        &ack.pack(),
                        certificate,
                        false,
                        fixture.now_ms,
                    ),
                    Err(IndexedSessionStoreError::DeviceBindingMismatch)
                ),
                "{label}: ack"
            );
        }
        // Nothing was consumed or recorded ...
        assert!(store.pending_endpoint_ack_intents().unwrap().is_empty());
        assert_eq!(
            store
                .outstanding_delivery_state(
                    &fixture.binding.session_id,
                    &outstanding,
                    &fixture.key.responder_device_ed25519,
                )
                .unwrap(),
            Some(EndpointDeliveryState::Sent)
        );
        // ... so the pinned certificate still opens the same envelopes at index 0.
        assert!(matches!(
            store
                .accept_message_envelope(
                    &fixture.key,
                    &message.pack(),
                    &fixture.remote_certificate,
                    false,
                    fixture.now_ms,
                )
                .unwrap(),
            EndpointAcceptance::Committed { .. }
        ));
        assert!(matches!(
            store
                .accept_ack_envelope(
                    &fixture.key,
                    &ack.pack(),
                    &fixture.remote_certificate,
                    false,
                    fixture.now_ms,
                )
                .unwrap(),
            EndpointAckAcceptance::Committed { .. }
        ));
    }

    #[test]
    fn expired_or_not_yet_valid_pinned_certificate_is_rejected_on_message_and_ack_ingress() {
        // The pinned certificate itself is outside its validity window at the
        // rejected time and inside it (inclusively) at the control time.
        let now = endpoint_fixture().now_ms;
        for (label, window, rejected_at, accepted_at) in [
            (
                "expired",
                (now - 1_000_000, now + 10_000),
                now + 10_001,
                now + 10_000,
            ),
            (
                "not yet valid",
                (now + 10_000, now + 1_000_000),
                now + 9_999,
                now + 10_000,
            ),
        ] {
            let temp = tempdir().unwrap();
            let path = temp.path().join("sessions.sqlite");
            let backend = Arc::new(MemoryProtectedBackend::default());
            let mut fixture = endpoint_fixture();
            fixture.remote_certificate = DeviceCertificate::issue(
                &Identity::from_seed(&[0x23; 32]),
                fixture.remote_identity.public_key_bytes(),
                [0x24; 32],
                "remote-device",
                window.0,
                window.1,
                1,
            )
            .unwrap();
            fixture.binding.responder_cert_digest =
                device_certificate_hash(&fixture.remote_certificate).unwrap();
            let mut store = open_test_store(&path, backend);
            store
                .create_session(fixture.binding.clone(), fixture.root)
                .unwrap();
            let outstanding = [0xC4; 16];
            store
                .register_outstanding_message(&fixture.key, &outstanding)
                .unwrap();
            let message = inbound_message_envelope(&fixture, 0, [0xC5; 16], b"cert window");
            let ack = inbound_ack_envelope(&fixture, 0, [0xC6; 16], outstanding, 1, [0xC7; 12]);

            assert!(
                matches!(
                    store.accept_message_envelope(
                        &fixture.key,
                        &message.pack(),
                        &fixture.remote_certificate,
                        false,
                        rejected_at,
                    ),
                    Err(IndexedSessionStoreError::InvalidDeviceCertificate)
                ),
                "{label}: message"
            );
            assert!(
                matches!(
                    store.accept_ack_envelope(
                        &fixture.key,
                        &ack.pack(),
                        &fixture.remote_certificate,
                        false,
                        rejected_at,
                    ),
                    Err(IndexedSessionStoreError::InvalidDeviceCertificate)
                ),
                "{label}: ack"
            );
            assert!(
                store.pending_endpoint_ack_intents().unwrap().is_empty(),
                "{label}"
            );
            assert!(matches!(
                store
                    .accept_message_envelope(
                        &fixture.key,
                        &message.pack(),
                        &fixture.remote_certificate,
                        false,
                        accepted_at,
                    )
                    .unwrap(),
                EndpointAcceptance::Committed { .. }
            ));
            assert!(matches!(
                store
                    .accept_ack_envelope(
                        &fixture.key,
                        &ack.pack(),
                        &fixture.remote_certificate,
                        false,
                        accepted_at,
                    )
                    .unwrap(),
                EndpointAckAcceptance::Committed { .. }
            ));
        }
    }

    /// Re-times a valid inbound message envelope. The route tag is bound to
    /// `created_at`, so it is re-derived before the envelope is re-signed; the
    /// sealed body does not cover either timestamp.
    fn retimed_message_envelope(
        fixture: &EndpointFixture,
        index: u32,
        message_id: [u8; 16],
        created_at: u64,
        expires_at: u64,
    ) -> Envelope {
        let mut envelope = inbound_message_envelope(fixture, index, message_id, b"windowed");
        envelope.created_at = created_at;
        envelope.expires_at = expires_at;
        envelope.routing_tag = derive_route_tag(
            &fixture.root,
            created_at,
            index,
            EnvType::Message as u8,
            Direction::ResponderToInitiator,
        )
        .unwrap();
        envelope.sign_with(&fixture.remote_identity);
        envelope
    }

    /// One case of the session-lifetime gate that message acceptance, ACK
    /// acceptance and sending share:
    /// `binding.created <= now < binding.expires`, `created >= binding.created`
    /// and `expires <= binding.expires`.
    struct SessionWindowCase {
        label: &'static str,
        /// The session's `(created_at_ms, expires_at_ms)`.
        session: (u64, u64),
        /// `(now, envelope created_at, envelope expires_at)` that must be rejected.
        rejected: (u64, u64, u64),
        /// The same envelope shape moved to the nearest accepted boundary.
        accepted: Option<(u64, u64, u64)>,
    }

    /// Every rejected input passes the generic endpoint time window (lifetime,
    /// skew, not yet expired), so a session clause is what rejects it.
    /// `now >= binding.expires_at_ms` is the one clause no input can isolate: an
    /// envelope that is unexpired at `now` and ends within the session already
    /// implies `now < binding.expires_at_ms`. The last case pins the behaviour
    /// that clause stands for (a session accepts nothing at its expiry
    /// instant), which the envelope-end clause currently enforces on its own.
    /// The start of a session window tolerates exactly the peer clock skew that
    /// PairInit/PairResponse verification tolerates (`before_session_start`): the
    /// session's `created_at_ms` comes from the initiator's clock. Expiry bounds
    /// stay exact.
    fn session_window_cases(now: u64) -> Vec<SessionWindowCase> {
        let skew = crate::prekey_lifecycle::MAX_PREKEY_FUTURE_SKEW_MS;
        vec![
            SessionWindowCase {
                label: "session has not started yet, even allowing for clock skew",
                session: (now + skew + 1, now + 3_600_000),
                rejected: (now, now, now + 60_000),
                accepted: Some((now + 1, now + 1, now + 60_001)),
            },
            SessionWindowCase {
                label: "envelope predates the session by more than the clock skew",
                session: (now, now + 3_600_000),
                rejected: (now, now - skew - 1, now + 60_000),
                accepted: Some((now, now - skew, now + 60_000)),
            },
            SessionWindowCase {
                label: "envelope outlives the session",
                session: (now, now + 120_000),
                rejected: (now, now, now + 120_001),
                accepted: Some((now, now, now + 120_000)),
            },
            SessionWindowCase {
                label: "session expires at this instant",
                session: (now - 3_600_000, now),
                rejected: (now, now, now + 60_000),
                accepted: None,
            },
        ]
    }

    struct WindowedSession {
        _temp: tempfile::TempDir,
        path: PathBuf,
        backend: Arc<MemoryProtectedBackend>,
        store: IndexedSessionStore,
        fixture: EndpointFixture,
    }

    fn windowed_session(window: (u64, u64)) -> WindowedSession {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let mut fixture = endpoint_fixture();
        fixture.binding.created_at_ms = window.0;
        fixture.binding.expires_at_ms = window.1;
        let mut store = open_test_store(&path, Arc::clone(&backend));
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();
        WindowedSession {
            _temp: temp,
            path,
            backend,
            store,
            fixture,
        }
    }

    #[test]
    fn message_acceptance_enforces_the_session_lifetime_window() {
        for case in session_window_cases(endpoint_fixture().now_ms) {
            let WindowedSession {
                _temp,
                path,
                backend,
                mut store,
                fixture,
            } = windowed_session(case.session);
            let head = protected_and_metadata_generation(&path, &backend, &fixture.key);
            let (now, created, expires) = case.rejected;
            let envelope = retimed_message_envelope(&fixture, 0, [0x91; 16], created, expires);
            assert!(
                matches!(
                    store.accept_message_envelope(
                        &fixture.key,
                        &envelope.pack(),
                        &fixture.remote_certificate,
                        false,
                        now,
                    ),
                    Err(IndexedSessionStoreError::EndpointNotCurrentlyValid)
                ),
                "{}",
                case.label
            );
            assert_eq!(
                protected_and_metadata_generation(&path, &backend, &fixture.key),
                head,
                "{}: a rejected envelope must not write",
                case.label
            );
            assert!(store.pending_endpoint_ack_intents().unwrap().is_empty());
            if let Some((now, created, expires)) = case.accepted {
                let envelope = retimed_message_envelope(&fixture, 0, [0x91; 16], created, expires);
                assert!(
                    matches!(
                        store
                            .accept_message_envelope(
                                &fixture.key,
                                &envelope.pack(),
                                &fixture.remote_certificate,
                                false,
                                now,
                            )
                            .unwrap_or_else(|error| panic!("{}: {error:?}", case.label)),
                        EndpointAcceptance::Committed { .. }
                    ),
                    "{}: index 0 must still be unconsumed",
                    case.label
                );
            }
        }
    }

    #[test]
    fn ack_acceptance_enforces_the_session_lifetime_window() {
        for case in session_window_cases(endpoint_fixture().now_ms) {
            let WindowedSession {
                _temp,
                path,
                backend,
                mut store,
                fixture,
            } = windowed_session(case.session);
            let outstanding = [0x92; 16];
            store
                .register_outstanding_message(&fixture.key, &outstanding)
                .unwrap();
            let head = protected_and_metadata_generation(&path, &backend, &fixture.key);
            let ack = |(_, created, expires): (u64, u64, u64)| {
                inbound_ack_envelope_in_window(
                    &fixture,
                    0,
                    [0x93; 16],
                    outstanding,
                    1,
                    [0x94; 12],
                    created,
                    expires,
                )
            };
            assert!(
                matches!(
                    store.accept_ack_envelope(
                        &fixture.key,
                        &ack(case.rejected).pack(),
                        &fixture.remote_certificate,
                        false,
                        case.rejected.0,
                    ),
                    Err(IndexedSessionStoreError::EndpointNotCurrentlyValid)
                ),
                "{}",
                case.label
            );
            assert_eq!(
                protected_and_metadata_generation(&path, &backend, &fixture.key),
                head,
                "{}: a rejected ACK must not write",
                case.label
            );
            assert_eq!(
                store
                    .outstanding_delivery_state(
                        &fixture.binding.session_id,
                        &outstanding,
                        &fixture.key.responder_device_ed25519,
                    )
                    .unwrap(),
                Some(EndpointDeliveryState::Sent),
                "{}",
                case.label
            );
            if let Some(accepted) = case.accepted {
                assert!(
                    matches!(
                        store
                            .accept_ack_envelope(
                                &fixture.key,
                                &ack(accepted).pack(),
                                &fixture.remote_certificate,
                                false,
                                accepted.0,
                            )
                            .unwrap_or_else(|error| panic!("{}: {error:?}", case.label)),
                        EndpointAckAcceptance::Committed { .. }
                    ),
                    "{}: ACK index 0 must still be unconsumed",
                    case.label
                );
            }
        }
    }

    #[test]
    fn send_enforces_the_session_lifetime_window() {
        for case in session_window_cases(endpoint_fixture().now_ms) {
            let WindowedSession {
                _temp,
                path,
                backend,
                mut store,
                fixture,
            } = windowed_session(case.session);
            let local_device = authorized_local_device(&fixture);
            let head = protected_and_metadata_generation(&path, &backend, &fixture.key);
            let mut queue = |digest: &[u8; 32], _bytes: &[u8]| Ok(*digest);
            let mut rng = StdRng::from_seed([0x95; 32]);
            let (now, created, expires) = case.rejected;
            assert!(
                matches!(
                    store.send_message_envelope(
                        &fixture.key,
                        "windowed send",
                        &local_device,
                        created,
                        expires,
                        now,
                        &mut rng,
                        &mut queue,
                    ),
                    Err(IndexedSessionStoreError::EndpointNotCurrentlyValid)
                ),
                "{}",
                case.label
            );
            assert_eq!(
                protected_and_metadata_generation(&path, &backend, &fixture.key),
                head,
                "{}: a rejected send must not write",
                case.label
            );
            assert!(store.pending_endpoint_outbound().unwrap().is_empty());
            if let Some((now, created, expires)) = case.accepted {
                let sent = store
                    .send_message_envelope(
                        &fixture.key,
                        "windowed send",
                        &local_device,
                        created,
                        expires,
                        now,
                        &mut rng,
                        &mut queue,
                    )
                    .unwrap_or_else(|error| panic!("{}: {error:?}", case.label));
                assert_eq!(
                    sent.ratchet_index, 0,
                    "{}: the rejected send must not have consumed an index",
                    case.label
                );
            }
        }
    }

    #[test]
    fn skipped_key_eviction_is_oldest_first_and_evicted_indices_are_replays() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let binding = fixture_binding();
        let key = binding.key.clone();
        let root = [0x72; 32];
        let mut store = open_test_store(&path, Arc::clone(&backend));
        store.create_session(binding, root).unwrap();
        let expected = |index: u32| {
            message_key_at_index(
                &root,
                &key.initiator_address,
                &key.responder_address,
                Direction::ResponderToInitiator,
                index,
            )
            .unwrap()
        };
        let accept = |store: &mut IndexedSessionStore, index: u32| {
            let wanted = expected(index);
            store.authenticate_receive(&key, RatchetLane::Message, index, |candidate| {
                (candidate == &wanted).then_some(())
            })
        };
        // 256 skipped keys (indexes 0..=255): the cache is exactly full.
        accept(&mut store, 256).unwrap();
        // A two-step jump caches index 257 as the 257th key, so the oldest
        // (index 0) must be evicted to stay at the bound.
        accept(&mut store, 258).unwrap();

        let account = hex::encode(record_key_digest(&key).unwrap());
        let state = decode_protected_state(&backend.get(&account).unwrap().unwrap())
            .expect("a state with an evicted cache still re-encodes and decodes");
        let cached: Vec<u32> = state
            .ratchets
            .message_receive
            .skipped_keys
            .keys()
            .copied()
            .collect();
        drop(state);
        assert_eq!(cached.len(), MAX_SKIPPED_KEYS);
        assert_eq!(cached.first(), Some(&1), "the oldest key goes first");
        assert_eq!(cached.last(), Some(&257), "the newest key is kept");

        assert!(matches!(
            accept(&mut store, 0),
            Err(IndexedSessionStoreError::Replay)
        ));
        accept(&mut store, 257).expect("the newest cached key still opens");
        accept(&mut store, 1).expect("the oldest surviving key still opens");
        assert!(matches!(
            accept(&mut store, 1),
            Err(IndexedSessionStoreError::Replay)
        ));
    }

    #[test]
    fn inbound_text_at_the_cap_is_accepted_and_one_byte_over_is_rejected() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let fixture = endpoint_fixture();
        let mut store = open_test_store(&path, backend);
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();
        let accept = |store: &mut IndexedSessionStore, envelope: &Envelope| {
            store.accept_message_envelope(
                &fixture.key,
                &envelope.pack(),
                &fixture.remote_certificate,
                false,
                fixture.now_ms,
            )
        };
        let oversized = inbound_message_envelope(
            &fixture,
            0,
            [0xD5; 16],
            &vec![b'a'; MAX_ENDPOINT_TEXT_BYTES + 1],
        );
        assert!(matches!(
            accept(&mut store, &oversized),
            Err(IndexedSessionStoreError::InvalidEndpointPayload)
        ));
        assert!(store.pending_endpoint_ack_intents().unwrap().is_empty());
        // The rejection consumed nothing: the maximal message takes index 0.
        let exact = inbound_message_envelope(
            &fixture,
            0,
            [0xD6; 16],
            &vec![b'a'; MAX_ENDPOINT_TEXT_BYTES],
        );
        match accept(&mut store, &exact).unwrap() {
            EndpointAcceptance::Committed { plaintext, .. } => {
                assert_eq!(plaintext.len(), MAX_ENDPOINT_TEXT_BYTES)
            }
            other => panic!("unexpected acceptance {other:?}"),
        }
        let listed = store.list_endpoint_inbox().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].plaintext.len(), MAX_ENDPOINT_TEXT_BYTES);
    }

    #[test]
    fn inbox_listings_order_by_received_time_then_message_id() {
        // Schema 1 only (the clear order; a schema-3 store lists by `seq` (sealed_store::cursor_v1_maps_to_seq_and_nothing_is_shown_twice)).
        sealed::test_switch::off();
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let fixture = endpoint_fixture();
        let mut store = open_test_store(&path, backend);
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();
        let now = fixture.now_ms;
        // Insertion order, message-id order and received-time order all
        // differ, so none of them can stand in for the documented order.
        let (p, q, r) = ([0xF2; 16], [0xF3; 16], [0xF1; 16]);
        for (index, id) in [p, q, r].into_iter().enumerate() {
            accept_text(&mut store, &fixture, index as u32, id, now);
        }
        let set_received = |id: [u8; 16], received_at_ms: u64| {
            Connection::open(&path)
                .unwrap()
                .execute(
                    "UPDATE endpoint_inbox SET received_at_ms = ?1 WHERE message_id = ?2",
                    params![received_at_ms as i64, id.as_slice()],
                )
                .unwrap();
        };
        let ids = |rows: Vec<EndpointInboxRow>| {
            rows.into_iter()
                .map(|row| row.message_id)
                .collect::<Vec<_>>()
        };
        let remote = fixture.key.responder_device_ed25519;

        set_received(q, now);
        set_received(r, now + 1);
        set_received(p, now + 2);
        let by_time = vec![q, r, p];
        assert_eq!(ids(store.list_endpoint_inbox().unwrap()), by_time);
        assert_eq!(
            ids(store.list_endpoint_inbox_for_sender(&remote).unwrap()),
            by_time
        );
        assert_eq!(
            ids(store.list_endpoint_inbox_for_record(&fixture.key).unwrap()),
            by_time
        );
        assert_eq!(
            ids(store
                .list_endpoint_inbox_for_sender_after(&remote, &after(0, None), 10)
                .unwrap()),
            by_time
        );
        assert_eq!(
            ids(store
                .list_endpoint_inbox_for_sender_after(&remote, &after(0, None), 1)
                .unwrap()),
            vec![q]
        );
        assert_eq!(
            ids(store
                .list_endpoint_inbox_for_sender_after(&remote, &after(now, Some(&q)), 10)
                .unwrap()),
            vec![r, p]
        );

        // Two rows in the same millisecond: the paged listing orders them by
        // message id, and its cursor must split the tie without skipping or
        // repeating either row.
        set_received(r, now + 2);
        let tied_order = vec![q, r, p];
        assert_eq!(
            ids(store
                .list_endpoint_inbox_for_sender_after(&remote, &after(0, None), 10)
                .unwrap()),
            tied_order
        );
        assert_eq!(
            ids(store
                .list_endpoint_inbox_for_sender_after(&remote, &after(now + 2, None), 10)
                .unwrap()),
            vec![r, p]
        );
        assert_eq!(
            ids(store
                .list_endpoint_inbox_for_sender_after(&remote, &after(now + 2, Some(&r)), 10)
                .unwrap()),
            vec![p]
        );
        assert!(store
            .list_endpoint_inbox_for_sender_after(&remote, &after(now + 2, Some(&p)), 10)
            .unwrap()
            .is_empty());
        let mut walked = Vec::new();
        let (mut cursor_ms, mut cursor_id) = (0, None);
        // One more page than rows: the last one must come back empty. A bound
        // keeps a cursor that never advances an assertion failure, not a hang.
        for _ in 0..=tied_order.len() {
            let page = store
                .list_endpoint_inbox_for_sender_after(
                    &remote,
                    &after(cursor_ms, cursor_id.as_ref()),
                    1,
                )
                .unwrap();
            let Some(row) = page.into_iter().next() else {
                break;
            };
            walked.push(row.message_id);
            cursor_ms = row.received_at_ms;
            cursor_id = Some(row.message_id);
        }
        assert_eq!(walked, tied_order);

        // The unpaged listings carry no tiebreaker: within a tie their order
        // is unspecified, but they list every row, oldest first.
        for rows in [
            store.list_endpoint_inbox().unwrap(),
            store.list_endpoint_inbox_for_sender(&remote).unwrap(),
            store.list_endpoint_inbox_for_record(&fixture.key).unwrap(),
        ] {
            assert!(rows
                .windows(2)
                .all(|pair| pair[0].received_at_ms <= pair[1].received_at_ms));
            let mut listed = ids(rows);
            listed.sort();
            assert_eq!(listed, vec![r, p, q]);
        }
    }

    /// Names of the secrets (raw bytes or hex, either case) found in the
    /// metadata database or its WAL and shared-memory side files. The main file
    /// must be readable and non-empty; only a missing side file is tolerated.
    fn secrets_found_in_sqlite_files(path: &Path, secrets: &[(String, [u8; 32])]) -> Vec<String> {
        let mut found = Vec::new();
        let candidates = [
            path.to_path_buf(),
            PathBuf::from(format!("{}-wal", path.display())),
            PathBuf::from(format!("{}-shm", path.display())),
        ];
        for (position, candidate) in candidates.iter().enumerate() {
            let bytes = match std::fs::read(candidate) {
                Ok(bytes) => bytes,
                Err(error) if position > 0 && error.kind() == std::io::ErrorKind::NotFound => {
                    continue
                }
                Err(error) => panic!("cannot read {}: {error}", candidate.display()),
            };
            if position == 0 {
                assert!(!bytes.is_empty(), "the metadata database is empty");
            }
            let text = String::from_utf8_lossy(&bytes).to_ascii_lowercase();
            for (name, secret) in secrets {
                if bytes.windows(secret.len()).any(|window| window == secret)
                    || text.contains(&hex::encode(secret))
                {
                    found.push(format!("{name} in {}", candidate.display()));
                }
            }
        }
        found
    }

    #[test]
    fn sqlite_never_contains_derived_ratchet_or_storage_keys() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let fixture = endpoint_fixture();
        let mut store = open_test_store(&path, Arc::clone(&backend));
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();
        // Advance every ratchet so derived material exists: a send key per
        // lane, receive jumps that cache skipped message and ACK keys, and an
        // accepted message whose body is sealed into the local inbox row.
        let reserved_message = store
            .reserve_send_key(&fixture.key, RatchetLane::Message)
            .unwrap();
        let reserved_ack = store
            .reserve_send_key(&fixture.key, RatchetLane::Ack)
            .unwrap();
        store
            .authenticate_receive(&fixture.key, RatchetLane::Message, 3, |_| Some(()))
            .unwrap();
        store
            .authenticate_receive(&fixture.key, RatchetLane::Ack, 2, |_| Some(()))
            .unwrap();
        let inbound = inbound_message_envelope(&fixture, 5, [0xD7; 16], b"sealed into the row");
        store
            .accept_message_envelope(
                &fixture.key,
                &inbound.pack(),
                &fixture.remote_certificate,
                false,
                fixture.now_ms,
            )
            .unwrap();
        store
            .conn
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .unwrap();
        drop(store);

        let account = hex::encode(record_key_digest(&fixture.key).unwrap());
        let blob = backend.get(&account).unwrap().unwrap();
        let state = decode_protected_state(&blob).unwrap();
        let initial = initial_ratchets(&fixture.binding, &fixture.root);
        let mut secrets: Vec<(String, [u8; 32])> = vec![
            ("root".into(), fixture.root),
            ("ack base key".into(), ack_base_key(&fixture.root)),
            (
                "local storage key".into(),
                local_storage_key(&fixture.root, &fixture.binding.session_id),
            ),
            ("reserved message key".into(), reserved_message.key),
            ("reserved ack key".into(), reserved_ack.key),
            (
                "initial message send chain".into(),
                initial.message_send.chain_key,
            ),
            ("initial ack send chain".into(), initial.ack_send.chain_key),
            (
                "initial message receive chain".into(),
                initial.message_receive.chain_key,
            ),
            (
                "initial ack receive chain".into(),
                initial.ack_receive.chain_key,
            ),
            (
                "message send chain".into(),
                state.ratchets.message_send.chain_key,
            ),
            ("ack send chain".into(), state.ratchets.ack_send.chain_key),
            (
                "message receive chain".into(),
                state.ratchets.message_receive.chain_key,
            ),
            (
                "ack receive chain".into(),
                state.ratchets.ack_receive.chain_key,
            ),
        ];
        for (index, skipped) in &state.ratchets.message_receive.skipped_keys {
            secrets.push((format!("skipped message key {index}"), *skipped));
        }
        for (index, skipped) in &state.ratchets.ack_receive.skipped_keys {
            secrets.push((format!("skipped ack key {index}"), *skipped));
        }
        assert!(
            state.ratchets.message_receive.skipped_keys.len() == 4
                && state.ratchets.ack_receive.skipped_keys.len() == 2,
            "the receive jumps must have cached skipped keys to look for"
        );
        drop(state);
        // Control: the grep would find these in the protected blob, so an empty
        // result for SQLite is meaningful.
        assert!(blob
            .windows(fixture.root.len())
            .any(|window| window == fixture.root));

        assert_eq!(
            secrets_found_in_sqlite_files(&path, &secrets),
            Vec::<String>::new()
        );

        // The detector sees a chain key that did land in SQLite.
        let leaked = secrets
            .iter()
            .find(|(name, _)| name == "message send chain")
            .unwrap();
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("CREATE TABLE leak(x BLOB);").unwrap();
        conn.execute("INSERT INTO leak VALUES (?1)", params![leaked.1.as_slice()])
            .unwrap();
        drop(conn);
        assert!(secrets_found_in_sqlite_files(&path, &secrets)
            .iter()
            .any(|found| found.starts_with("message send chain in")));
    }

    #[test]
    fn quarantined_ack_journal_from_a_real_crash_keeps_its_index_burned() {
        // Schema 1 only (a clear ACK receipt written by hand).
        sealed::test_switch::off();
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let fixture = endpoint_fixture();
        let (first_outbound, second_outbound) = ([0xB1; 16], [0xB2; 16]);
        let crashed_outer = [0xB5; 16];
        {
            let mut store = open_test_store(&path, Arc::clone(&backend));
            store
                .create_session(fixture.binding.clone(), fixture.root)
                .unwrap();
            for outbound in [first_outbound, second_outbound] {
                store
                    .register_outstanding_message(&fixture.key, &outbound)
                    .unwrap();
            }
            let first =
                inbound_ack_envelope(&fixture, 0, [0xB3; 16], first_outbound, 1, [0xB4; 12]);
            store
                .accept_ack_envelope(
                    &fixture.key,
                    &first.pack(),
                    &fixture.remote_certificate,
                    false,
                    fixture.now_ms,
                )
                .unwrap();
            // ACK index 1 crashes right before its database commit: the
            // protected head already carries the advanced ratchet and the
            // journal, SQLite does not.
            let crashed =
                inbound_ack_envelope(&fixture, 1, crashed_outer, second_outbound, 2, [0xB6; 12]);
            store.inject_endpoint_fault(EndpointFaultPoint::BeforeDatabaseCommit);
            assert!(matches!(
                store.accept_ack_envelope(
                    &fixture.key,
                    &crashed.pack(),
                    &fixture.remote_certificate,
                    false,
                    fixture.now_ms,
                ),
                Err(IndexedSessionStoreError::InjectedEndpointFailure(_))
            ));
        }
        // Another ACK object has meanwhile taken the crashed ACK's outer
        // message id, so replaying the journal can never succeed.
        Connection::open(&path)
            .unwrap()
            .execute(
                "INSERT INTO endpoint_ack_receipts
                 (session_id, object_digest, outer_message_id, remote_device,
                  acked_message_id, status, ack_nonce, created_at_ms, session_generation)
                 VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?7, 0)",
                params![
                    fixture.binding.session_id.as_slice(),
                    [0xC9_u8; 32].as_slice(),
                    crashed_outer.as_slice(),
                    fixture.key.responder_device_ed25519.as_slice(),
                    first_outbound.as_slice(),
                    [0xCA_u8; 12].as_slice(),
                    fixture.now_ms as i64,
                ],
            )
            .unwrap();

        let mut reopened = open_test_store(&path, Arc::clone(&backend));
        let (protected, journal, metadata) =
            protected_and_metadata_generation(&path, &backend, &fixture.key);
        assert!(!journal, "the unreplayable journal is quarantined");
        assert_eq!(protected, metadata);
        assert_eq!(
            reopened
                .outstanding_delivery_state(
                    &fixture.binding.session_id,
                    &second_outbound,
                    &fixture.key.responder_device_ed25519,
                )
                .unwrap(),
            Some(EndpointDeliveryState::Sent),
            "the quarantined ACK never became visible"
        );
        // The ratchet stayed advanced: index 1 is burned, index 2 is next.
        let burned = inbound_ack_envelope(&fixture, 1, [0xB7; 16], second_outbound, 2, [0xB8; 12]);
        assert!(matches!(
            reopened.accept_ack_envelope(
                &fixture.key,
                &burned.pack(),
                &fixture.remote_certificate,
                false,
                fixture.now_ms,
            ),
            Err(IndexedSessionStoreError::Replay)
        ));
        let next = inbound_ack_envelope(&fixture, 2, [0xB9; 16], second_outbound, 2, [0xBA; 12]);
        assert!(matches!(
            reopened
                .accept_ack_envelope(
                    &fixture.key,
                    &next.pack(),
                    &fixture.remote_certificate,
                    false,
                    fixture.now_ms,
                )
                .unwrap(),
            EndpointAckAcceptance::Committed {
                delivery_state: EndpointDeliveryState::Read,
                ..
            }
        ));
    }

    #[test]
    fn debug_output_never_prints_keys_sealed_bytes_or_identifiers() {
        // `{:?}` of a byte array is the decimal list a derived Debug would
        // print, so its absence shows the redacting impl is still in use.
        fn assert_redacted(name: &str, output: &str, markers: &[&str], leaks: &[(&str, String)]) {
            for marker in markers {
                assert!(
                    output.contains(marker),
                    "{name}: missing {marker} in {output}"
                );
            }
            for (field, value) in leaks {
                assert!(
                    !output.contains(value.as_str()),
                    "{name}: {field} leaked into {output}"
                );
            }
        }
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let fixture = endpoint_fixture();
        let local_device = authorized_local_device(&fixture);
        let mut store = open_test_store(&path, backend);
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();

        let reservation = store
            .reserve_send_key(&fixture.key, RatchetLane::Message)
            .unwrap();
        assert_redacted(
            "SendKeyReservation",
            &format!("{reservation:?}"),
            &["<redacted>"],
            &[
                ("key", format!("{:?}", reservation.key)),
                ("key hex", hex::encode(reservation.key)),
            ],
        );

        let mut rng = StdRng::from_seed([0x96; 32]);
        let mut queue = |digest: &[u8; 32], _bytes: &[u8]| Ok(*digest);
        let outbound = store
            .send_message_envelope(
                &fixture.key,
                "debug output",
                &local_device,
                fixture.now_ms,
                fixture.now_ms + 60_000,
                fixture.now_ms,
                &mut rng,
                &mut queue,
            )
            .unwrap();
        assert_redacted(
            "EndpointOutbound",
            &format!("{outbound:?}"),
            &["<redacted>", "<ciphertext>"],
            &[
                ("bytes", format!("{:?}", outbound.immutable_envelope_bytes)),
                ("session", format!("{:?}", outbound.session_id)),
                ("object", format!("{:?}", outbound.object_digest)),
                ("message", format!("{:?}", outbound.message_id)),
                ("recipient", format!("{:?}", outbound.recipient_device)),
            ],
        );

        assert_redacted(
            "AuthorizedEndpointDevice",
            &format!("{local_device:?}"),
            &["<redacted>"],
            &[
                (
                    "device key",
                    format!("{:?}", fixture.local_certificate.device_ed_pub),
                ),
                ("device label", fixture.local_certificate.device_id.clone()),
            ],
        );

        let pending_outbound = PendingOutbound {
            kind: EndpointOutboundKind::Message,
            session_id: [0x51; 32],
            object_digest: [0x52; 32],
            message_id: [0x53; 16],
            recipient_device: [0x54; 32],
            ratchet_index: 7,
            source_ack_intent: Some([0x55; 32]),
            ack_nonce: Some([0x56; 12]),
            seal_nonce: [0x57; 12],
            anti_replay_nonce: [0x58; 12],
            immutable_envelope_bytes: vec![0x59; 48],
            public_generation: 9,
        };
        assert_redacted(
            "PendingOutbound",
            &format!("{pending_outbound:?}"),
            &["<redacted>", "<ciphertext>"],
            &[
                (
                    "bytes",
                    format!("{:?}", pending_outbound.immutable_envelope_bytes),
                ),
                ("session", format!("{:?}", pending_outbound.session_id)),
                ("object", format!("{:?}", pending_outbound.object_digest)),
                ("message", format!("{:?}", pending_outbound.message_id)),
                (
                    "recipient",
                    format!("{:?}", pending_outbound.recipient_device),
                ),
                ("seal nonce", format!("{:?}", pending_outbound.seal_nonce)),
                (
                    "anti-replay nonce",
                    format!("{:?}", pending_outbound.anti_replay_nonce),
                ),
            ],
        );

        let pending_acceptance = PendingAcceptance {
            session_id: [0x61; 32],
            object_digest: [0x62; 32],
            message_id: [0x63; 16],
            sender_device: [0x64; 32],
            sealed_local_inbox_row: vec![0x65; 48],
            ack_status: 1,
            created_at_ms: 10,
            received_at_ms: 11,
            public_generation: 12,
        };
        assert_redacted(
            "PendingAcceptance",
            &format!("{pending_acceptance:?}"),
            &["<redacted>", "<sealed>"],
            &[
                (
                    "sealed row",
                    format!("{:?}", pending_acceptance.sealed_local_inbox_row),
                ),
                ("session", format!("{:?}", pending_acceptance.session_id)),
                ("object", format!("{:?}", pending_acceptance.object_digest)),
                ("message", format!("{:?}", pending_acceptance.message_id)),
                ("sender", format!("{:?}", pending_acceptance.sender_device)),
            ],
        );

        let pending_ack = PendingAckAcceptance {
            session_id: [0x71; 32],
            object_digest: [0x72; 32],
            outer_message_id: [0x73; 16],
            remote_device: [0x74; 32],
            acked_message_id: [0x75; 16],
            status: 2,
            ack_nonce: [0x76; 12],
            created_at_ms: 20,
            public_generation: 21,
        };
        assert_redacted(
            "PendingAckAcceptance",
            &format!("{pending_ack:?}"),
            &["<redacted>"],
            &[
                ("session", format!("{:?}", pending_ack.session_id)),
                ("object", format!("{:?}", pending_ack.object_digest)),
                ("outer id", format!("{:?}", pending_ack.outer_message_id)),
                ("remote", format!("{:?}", pending_ack.remote_device)),
                ("acked id", format!("{:?}", pending_ack.acked_message_id)),
                ("ack nonce", format!("{:?}", pending_ack.ack_nonce)),
            ],
        );
    }

    fn panic_message(result: Result<(), Box<dyn std::any::Any + Send>>) -> String {
        let payload = result.expect_err("expected a panic");
        payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| payload.downcast_ref::<&str>().map(|text| text.to_string()))
            .unwrap_or_default()
    }

    #[test]
    fn rendezvous_helpers_fail_with_a_message_instead_of_hanging() {
        // A missing peer fails the barrier wait ...
        let lonely = TimedBarrier::new(2);
        let message = panic_message(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || lonely.wait_for("lonely party", Duration::from_millis(50)),
        )));
        assert!(message.contains("lonely party"), "{message}");
        // ... while two parties release each other.
        let pair = TimedBarrier::new(2);
        let peer = {
            let pair = Arc::clone(&pair);
            thread::spawn(move || pair.wait_for("peer", RENDEZVOUS_TIMEOUT))
        };
        pair.wait_for("main", RENDEZVOUS_TIMEOUT);
        peer.join().unwrap();

        // A worker that ends without reaching the paused put is reported ...
        let backend = Arc::new(MemoryProtectedBackend::default());
        let pause = backend.pause_nth_future_put(1);
        let idle = thread::spawn(|| ());
        let message = panic_message(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || pause.wait_until_parked_for(&idle, Duration::from_secs(10)),
        )));
        assert!(message.contains("finished without reaching"), "{message}");
        idle.join().unwrap();

        // ... a worker that never finishes is reported once the bound expires ...
        let pause = backend.pause_nth_future_put(1);
        let (release, released) = mpsc::channel::<()>();
        let stuck = thread::spawn(move || {
            let _ = released.recv();
        });
        let message = panic_message(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || pause.wait_until_parked_for(&stuck, Duration::from_millis(60)),
        )));
        assert!(message.contains("never reached"), "{message}");
        release.send(()).unwrap();
        stuck.join().unwrap();

        // ... and a parked writer whose test went away fails its put instead
        // of blocking the writer.
        drop(backend.pause_nth_future_put(1));
        assert!(matches!(
            backend.put("account", b"value"),
            Err(IndexedSessionStoreError::ProtectedStore(_))
        ));
        assert!(backend.get("account").unwrap().is_none());
    }

    #[test]
    fn a_stale_journal_clear_never_clears_a_newer_journal() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let fixture = endpoint_fixture();
        let record_key = record_key_digest(&fixture.key).unwrap();
        let account = hex::encode(record_key);
        let mut stale = open_test_store(&path, Arc::clone(&backend));
        stale
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();

        // The first writer commits to SQLite but stops before its journal clear.
        let first = inbound_message_envelope(&fixture, 0, [0xE7; 16], b"first");
        stale.inject_endpoint_fault(EndpointFaultPoint::BeforeJournalClear);
        assert!(matches!(
            stale.accept_message_envelope(
                &fixture.key,
                &first.pack(),
                &fixture.remote_certificate,
                false,
                fixture.now_ms,
            ),
            Err(IndexedSessionStoreError::InjectedEndpointFailure(_))
        ));
        let (stale_generation, stale_journal) = {
            let state = decode_protected_state(&backend.get(&account).unwrap().unwrap()).unwrap();
            (
                state.generation,
                protected_journal(&state)
                    .unwrap()
                    .expect("the first writer's journal is still staged"),
            )
        };

        // Another instance replays and clears it on open, then stages a newer
        // journal and stops before committing it: the protected head is one
        // generation ahead of SQLite and carries that newer journal.
        let mut other = open_test_store(&path, Arc::clone(&backend));
        assert_eq!(
            protected_and_metadata_generation(&path, &backend, &fixture.key),
            (stale_generation, false, stale_generation)
        );
        let second = inbound_message_envelope(&fixture, 1, [0xE8; 16], b"second");
        other.inject_endpoint_fault(EndpointFaultPoint::BeforeDatabaseCommit);
        assert!(matches!(
            other.accept_message_envelope(
                &fixture.key,
                &second.pack(),
                &fixture.remote_certificate,
                false,
                fixture.now_ms,
            ),
            Err(IndexedSessionStoreError::InjectedEndpointFailure(_))
        ));
        assert_eq!(
            protected_and_metadata_generation(&path, &backend, &fixture.key),
            (stale_generation + 1, true, stale_generation)
        );

        // The first writer's late clear names the journal and generation it
        // staged. Neither matches the head any more, so it must leave the newer
        // journal alone: clearing it would lose a message whose rows were never
        // committed.
        stale
            .clear_protected_journal(&account, &record_key, stale_generation, stale_journal)
            .unwrap();
        let (protected_generation, journal_present, _) =
            protected_and_metadata_generation(&path, &backend, &fixture.key);
        assert_eq!(protected_generation, stale_generation + 1);
        assert!(journal_present, "a stale clear dropped a newer journal");

        // The newer journal is still replayed by the next open.
        drop(other);
        let mut reopened = open_test_store(&path, Arc::clone(&backend));
        assert_eq!(
            protected_and_metadata_generation(&path, &backend, &fixture.key),
            (stale_generation + 1, false, stale_generation + 1)
        );
        assert_eq!(reopened.list_endpoint_inbox().unwrap().len(), 2);
    }

    // ---- session reset (lost-state recovery §10) ----

    fn send_text(
        store: &mut IndexedSessionStore,
        fixture: &EndpointFixture,
        text: &str,
        handoff_ok: bool,
    ) -> Result<EndpointOutbound, IndexedSessionStoreError> {
        let local_device = authorized_local_device(fixture);
        let mut rng = StdRng::from_seed([text.len() as u8; 32]);
        let mut queue = |digest: &[u8; 32], _bytes: &[u8]| {
            if handoff_ok {
                Ok(*digest)
            } else {
                Err(())
            }
        };
        store.send_message_envelope(
            &fixture.key,
            text,
            &local_device,
            fixture.now_ms,
            fixture.now_ms + 60_000,
            fixture.now_ms,
            &mut rng,
            &mut queue,
        )
    }

    fn reseal_text(
        store: &mut IndexedSessionStore,
        target: &EndpointFixture,
        text: &str,
        mid: &[u8; 16],
    ) -> Result<EndpointOutbound, IndexedSessionStoreError> {
        let local_device = authorized_local_device(target);
        let mut rng = StdRng::from_seed([0x5e; 32]);
        let mut queue = |digest: &[u8; 32], _bytes: &[u8]| Ok(*digest);
        store.reseal_message_envelope(
            &target.key,
            text,
            mid,
            &local_device,
            target.now_ms,
            target.now_ms + 60_000,
            target.now_ms,
            &mut rng,
            &mut queue,
        )
    }

    fn peer_of(fixture: &EndpointFixture) -> [u8; 32] {
        fixture.key.responder_device_ed25519
    }

    #[test]
    fn retire_is_idempotent_and_send_side_only() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let fixture = endpoint_fixture();
        let peer = peer_of(&fixture);
        let mut store = open_test_store(&path, Arc::new(MemoryProtectedBackend::default()));
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();
        assert_eq!(
            store
                .find_sendable_sessions_for_peer_at(&peer, fixture.now_ms)
                .unwrap(),
            vec![fixture.key.clone()]
        );
        assert!(store
            .retire_session(
                &fixture.key,
                &peer,
                SessionRetireCause::PeerNoSession,
                fixture.now_ms
            )
            .unwrap());
        assert!(!store
            .retire_session(
                &fixture.key,
                &peer,
                SessionRetireCause::PeerCertRenewed,
                fixture.now_ms + 5
            )
            .unwrap());
        let info = store
            .session_reset_info(&fixture.binding.session_id)
            .unwrap()
            .unwrap();
        assert_eq!(info.retire_cause, Some(SessionRetireCause::PeerNoSession));
        assert_eq!(info.retired_at_ms, Some(fixture.now_ms));
        assert!(store
            .find_sendable_sessions_for_peer_at(&peer, fixture.now_ms)
            .unwrap()
            .is_empty());
        assert_eq!(
            store
                .find_confirmed_sessions_for_peer_at(&peer, fixture.now_ms)
                .unwrap(),
            vec![fixture.key.clone()]
        );
        // A stranger device cannot be named as the peer.
        assert!(matches!(
            store.retire_session(
                &fixture.key,
                &[0x99; 32],
                SessionRetireCause::PeerNoSession,
                1
            ),
            Err(IndexedSessionStoreError::DeviceBindingMismatch)
        ));
        // Inbound messages and ACKs are still accepted, and ACKs still go out.
        let intent = accept_text(&mut store, &fixture, 0, [0x71; 16], fixture.now_ms);
        let local_device = authorized_local_device(&fixture);
        let mut rng = StdRng::from_seed([0x72; 32]);
        let mut queue = |digest: &[u8; 32], _bytes: &[u8]| Ok(*digest);
        let ack = store
            .enqueue_committed_ack(
                &fixture.key,
                &intent,
                &local_device,
                fixture.now_ms,
                fixture.now_ms + 60_000,
                fixture.now_ms,
                &mut rng,
                &mut queue,
            )
            .unwrap();
        assert_eq!(ack.kind, EndpointOutboundKind::Ack);
    }

    #[test]
    fn message_seal_retry_resend_under_retired_session_fail_with_session_retired() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let fixture = endpoint_fixture();
        let peer = peer_of(&fixture);
        let mut store = open_test_store(&path, Arc::new(MemoryProtectedBackend::default()));
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();
        let queued = send_text(&mut store, &fixture, "queued one", true).unwrap();
        assert_eq!(queued.state, EndpointOutboxState::Queued);
        let prepared = send_text(&mut store, &fixture, "prepared two", false);
        assert!(prepared.is_err());
        let prepared = store
            .pending_endpoint_outbound_for_recipient(Some(&peer))
            .unwrap()
            .pop()
            .unwrap();
        store
            .retire_session(
                &fixture.key,
                &peer,
                SessionRetireCause::PeerNoSession,
                fixture.now_ms,
            )
            .unwrap();
        let local_device = authorized_local_device(&fixture);
        let mut queue = |digest: &[u8; 32], _bytes: &[u8]| Ok(*digest);
        assert!(matches!(
            send_text(&mut store, &fixture, "new three", true),
            Err(IndexedSessionStoreError::SessionRetired)
        ));
        assert!(matches!(
            store.retry_endpoint_outbound(
                &fixture.key,
                &prepared.object_digest,
                &local_device,
                fixture.now_ms,
                &mut queue
            ),
            Err(IndexedSessionStoreError::SessionRetired)
        ));
        assert!(matches!(
            store.resend_queued_endpoint_outbound(
                &fixture.key,
                &queued.object_digest,
                &local_device,
                fixture.now_ms,
                &mut queue
            ),
            Err(IndexedSessionStoreError::SessionRetired)
        ));
        // Both rows are reported as waiting in the retired session, oldest first.
        let held = store
            .retired_undelivered_messages_for_recipient(&peer)
            .unwrap();
        assert_eq!(held.len(), 2);
        assert_eq!(held[0].message_id, queued.message_id);
        assert_eq!(held[1].message_id, prepared.message_id);
        // ACKs are unaffected (exercised in retire_is_idempotent_and_send_side_only).
        assert!(!is_session_scoped_state_error(
            &IndexedSessionStoreError::SessionRetired
        ));
    }

    #[test]
    fn reseal_keeps_message_id_new_session_new_digest() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let old = endpoint_fixture();
        let new = second_session_fixture(1_000);
        let peer = peer_of(&old);
        let mut store = open_test_store(&path, Arc::new(MemoryProtectedBackend::default()));
        store.create_session(old.binding.clone(), old.root).unwrap();
        store.create_session(new.binding.clone(), new.root).unwrap();
        let original = send_text(&mut store, &old, "carry me over", true).unwrap();
        store
            .retire_session(
                &old.key,
                &peer,
                SessionRetireCause::PeerNoSession,
                old.now_ms,
            )
            .unwrap();
        let resealed =
            reseal_text(&mut store, &new, "carry me over", &original.message_id).unwrap();
        assert_eq!(resealed.message_id, original.message_id);
        assert_eq!(resealed.session_id, new.binding.session_id);
        assert_ne!(resealed.object_digest, original.object_digest);
        assert!(store
            .retire_outbound_copy(&old.key, &original.object_digest)
            .unwrap());
        assert!(!store
            .retire_outbound_copy(&old.key, &original.object_digest)
            .unwrap());
        let mut copies = store
            .message_copies_for_recipient(&peer, &original.message_id)
            .unwrap();
        copies.sort_by_key(|c| c.retired);
        assert_eq!(copies.len(), 2);
        assert!(!copies[0].retired && copies[0].has_outbox_row);
        assert!(copies[1].retired && !copies[1].has_outbox_row);
        assert_eq!(copies[1].delivery_state, Some(EndpointDeliveryState::Sent));
        assert!(store
            .live_copy_elsewhere(&peer, &original.message_id, &old.binding.session_id)
            .unwrap());
        assert!(!store
            .live_copy_elsewhere(&peer, &original.message_id, &new.binding.session_id)
            .unwrap());
        assert!(store
            .retired_undelivered_messages_for_recipient(&peer)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn reseal_into_session_that_already_has_the_id_is_refused() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let old = endpoint_fixture();
        let new = second_session_fixture(1_000);
        let mut store = open_test_store(&path, Arc::new(MemoryProtectedBackend::default()));
        store.create_session(old.binding.clone(), old.root).unwrap();
        store.create_session(new.binding.clone(), new.root).unwrap();
        let original = send_text(&mut store, &old, "once only", true).unwrap();
        reseal_text(&mut store, &new, "once only", &original.message_id).unwrap();
        assert!(matches!(
            reseal_text(&mut store, &new, "once only", &original.message_id),
            Err(IndexedSessionStoreError::OutboundCollision)
        ));
        assert!(matches!(
            reseal_text(&mut store, &new, "zero id", &[0u8; 16]),
            Err(IndexedSessionStoreError::OutboundCollision)
        ));
    }

    #[test]
    fn retire_outbound_copy_keeps_outstanding_so_a_late_ack_settles() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let fixture = endpoint_fixture();
        let peer = peer_of(&fixture);
        let mut store = open_test_store(&path, Arc::new(MemoryProtectedBackend::default()));
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();
        let sent = send_text(&mut store, &fixture, "late ack", true).unwrap();
        store
            .retire_session(
                &fixture.key,
                &peer,
                SessionRetireCause::PeerCertRenewed,
                fixture.now_ms,
            )
            .unwrap();
        assert!(store
            .retire_outbound_copy(&fixture.key, &sent.object_digest)
            .unwrap());
        let ack = inbound_ack_envelope(&fixture, 0, [0xE5; 16], sent.message_id, 1, [0xE6; 12]);
        assert!(matches!(
            store
                .accept_ack_envelope(
                    &fixture.key,
                    &ack.pack(),
                    &fixture.remote_certificate,
                    false,
                    fixture.now_ms
                )
                .unwrap(),
            EndpointAckAcceptance::Committed {
                delivery_state: EndpointDeliveryState::Delivered,
                ..
            }
        ));
        let copies = store
            .message_copies_for_recipient(&peer, &sent.message_id)
            .unwrap();
        assert_eq!(copies.len(), 1);
        assert_eq!(
            copies[0].delivery_state,
            Some(EndpointDeliveryState::Delivered)
        );
    }

    #[test]
    fn reseal_ledger_survives_prune_of_the_original_session() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let fixture = endpoint_fixture();
        let peer = peer_of(&fixture);
        let mut store = open_test_store(&path, Arc::new(MemoryProtectedBackend::default()));
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();
        let mid = [0x7a; 16];
        let deadline = fixture.binding.expires_at_ms + 10_000;
        assert_eq!(
            store.bump_reseal_ledger(&peer, &mid, deadline, 1).unwrap(),
            1
        );
        assert_eq!(
            store.bump_reseal_ledger(&peer, &mid, deadline, 2).unwrap(),
            2
        );
        assert_eq!(store.take_unnotified_reseals(&peer).unwrap(), (1, 2));
        assert_eq!(store.take_unnotified_reseals(&peer).unwrap(), (0, 0));
        assert_eq!(
            store
                .prune_expired_sessions(fixture.binding.expires_at_ms)
                .unwrap(),
            1
        );
        assert_eq!(store.reseal_count(&peer, &mid).unwrap(), 2);
        assert_eq!(store.resealed_message_ids(&peer).unwrap(), vec![mid]);
        store.prune_expired_sessions(deadline + 86_400_000).unwrap();
        assert_eq!(store.reseal_count(&peer, &mid).unwrap(), 0);
    }

    /// An older build prunes heads by session id and knows nothing of the
    /// sidecar: the cascade keeps it consistent.
    #[test]
    fn retired_sidecar_cascades_on_raw_head_delete() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let fixture = endpoint_fixture();
        let peer = peer_of(&fixture);
        let mut store = open_test_store(&path, Arc::new(MemoryProtectedBackend::default()));
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();
        store
            .retire_session(&fixture.key, &peer, SessionRetireCause::PeerNoSession, 1)
            .unwrap();
        let raw = Connection::open(&path).unwrap();
        raw.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
        raw.execute(
            "DELETE FROM indexed_session_heads WHERE session_id = ?1",
            params![fixture.binding.session_id.as_slice()],
        )
        .unwrap();
        assert!(store
            .session_reset_info(&fixture.binding.session_id)
            .unwrap()
            .is_none());
    }

    /// Privacy pack PP.13 raised the version ON PURPOSE, to 2 for a sealed
    /// profile's keyed store only, PP.14 to 3 (the endpoint tables keyed
    /// too) and review B-sealed-stores-1 to 4 (the heads' `init_id` keyed):
    /// a profile that is not sealed stays at 1, which every older build
    /// opens (the session-reset, horizon and inbox tombstone sidecars are
    /// additive there).
    #[test]
    fn metadata_schema_version_is_4_sealed_and_stays_1_plain() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let store = open_test_store(&path, Arc::new(MemoryProtectedBackend::default()));
        let version: i64 = Connection::open(&path)
            .unwrap()
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        let expected = if store.layout.is_keyed() {
            METADATA_SCHEMA_VERSION
        } else {
            sealed::CLEAR_VERSION
        };
        assert_eq!(version, expected);
        assert_eq!(METADATA_SCHEMA_VERSION, 4);
        assert_eq!(sealed::ENDPOINTS_VERSION, 3);
        assert_eq!(sealed::HEADS_VERSION, 2);
        assert_eq!(sealed::CLEAR_VERSION, 1);
    }

    #[test]
    fn confirmed_at_written_for_both_roles() {
        for role in [LocalRole::Initiator, LocalRole::Responder] {
            let temp = tempdir().unwrap();
            let path = temp.path().join("sessions.sqlite");
            let (init, response, root) = pair_init_vector();
            let mut binding = vector_binding(&init);
            binding.local_role = role;
            let session = binding.session_id;
            let key = binding.key.clone();
            let mut store = open_test_store(&path, Arc::new(MemoryProtectedBackend::default()));
            store.create_session(binding, root).unwrap();
            let now = response.created_at_ms + 1;
            store
                .confirm_verified_pair_response(&key, &init, &response, now)
                .unwrap();
            store
                .confirm_verified_pair_response(&key, &init, &response, now + 50)
                .unwrap();
            let info = store.session_reset_info(&session).unwrap().unwrap();
            assert_eq!(info.confirmed_at_ms, Some(now), "{role:?}");
            let peer = match role {
                LocalRole::Initiator => init.responder_device_ed_pub,
                LocalRole::Responder => init.initiator_device_ed_pub,
            };
            assert_eq!(info.peer_device, peer);
            assert!(!info.retired() && !info.initiated_local);
        }
    }

    #[test]
    fn find_sendable_newest_first_matches_confirmed_order() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let old = endpoint_fixture();
        let new = second_session_fixture(1_000);
        let peer = peer_of(&old);
        let mut store = open_test_store(&path, Arc::new(MemoryProtectedBackend::default()));
        store.create_session(old.binding.clone(), old.root).unwrap();
        store.create_session(new.binding.clone(), new.root).unwrap();
        let confirmed = store
            .find_confirmed_sessions_for_peer_at(&peer, old.now_ms)
            .unwrap();
        assert_eq!(confirmed, vec![new.key.clone(), old.key.clone()]);
        assert_eq!(
            store
                .find_sendable_sessions_for_peer_at(&peer, old.now_ms)
                .unwrap(),
            confirmed
        );
        store
            .retire_session(&new.key, &peer, SessionRetireCause::PeerNoSession, 1)
            .unwrap();
        assert_eq!(
            store
                .find_sendable_sessions_for_peer_at(&peer, old.now_ms)
                .unwrap(),
            vec![old.key.clone()]
        );
        // Target selection: only a session newer than the retired one holding
        // undelivered rows, and (automatically) only one we initiated locally.
        send_text(&mut store, &old, "held", true).unwrap();
        store
            .retire_session(&old.key, &peer, SessionRetireCause::PeerNoSession, 1)
            .unwrap();
        let newer = second_session_fixture(2_000);
        let mut newer = newer;
        newer.binding.key.init_id = [0x36; 16];
        newer.binding.init_hash = [0x54; 32];
        newer.binding.session_id = session_id(&newer.binding.init_hash);
        newer.key = newer.binding.key.clone();
        store
            .create_session(newer.binding.clone(), newer.root)
            .unwrap();
        assert_eq!(
            store
                .reseal_target_for_peer(&peer, false, old.now_ms)
                .unwrap(),
            None
        );
        assert_eq!(
            store
                .reseal_target_for_peer(&peer, true, old.now_ms)
                .unwrap(),
            Some(newer.key.clone())
        );
        store
            .mark_session_initiated(&newer.key, &peer, true, true, old.now_ms)
            .unwrap();
        assert_eq!(
            store
                .reseal_target_for_peer(&peer, false, old.now_ms)
                .unwrap(),
            Some(newer.key.clone())
        );
        assert_eq!(store.reset_rounds_since(&peer, old.now_ms).unwrap(), 1);
        assert_eq!(store.reset_rounds_since(&peer, old.now_ms + 1).unwrap(), 0);
        assert_eq!(store.last_reset_round_at(&peer).unwrap(), Some(old.now_ms));
        // Too little time left on the target.
        assert_eq!(
            store
                .reseal_target_for_peer(
                    &peer,
                    true,
                    newer.binding.expires_at_ms
                        - crate::session_reset::RESET_TARGET_MIN_REMAINING_MS
                        + 1
                )
                .unwrap(),
            None
        );
    }

    #[test]
    fn match_inbound_session_is_read_only() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let fixture = endpoint_fixture();
        let peer = peer_of(&fixture);
        let mut store = open_test_store(&path, Arc::clone(&backend));
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();
        let before = protected_and_metadata_generation(&path, &backend, &fixture.key);
        let inbound = inbound_message_envelope(&fixture, 3, [0x7b; 16], b"probe");
        assert_eq!(
            store
                .match_inbound_session(&peer, &inbound.pack(), fixture.now_ms)
                .unwrap(),
            Some(fixture.key.clone())
        );
        let ack = inbound_ack_envelope(&fixture, 2, [0x7c; 16], [0x7d; 16], 1, [0x7e; 12]);
        assert_eq!(
            store
                .match_inbound_session(&peer, &ack.pack(), fixture.now_ms)
                .unwrap(),
            Some(fixture.key.clone())
        );
        assert_eq!(
            protected_and_metadata_generation(&path, &backend, &fixture.key),
            before
        );
        let rows: i64 = Connection::open(&path)
            .unwrap()
            .query_row(
                "SELECT (SELECT COUNT(*) FROM endpoint_receipts)
                      + (SELECT COUNT(*) FROM endpoint_inbox)
                      + (SELECT COUNT(*) FROM endpoint_ack_receipts)",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(rows, 0);
        // Another session's envelope does not match this one.
        let other = second_session_fixture(1_000);
        let foreign = inbound_message_envelope(&other, 0, [0x7f; 16], b"other");
        assert_eq!(
            store
                .match_inbound_session(&peer, &foreign.pack(), fixture.now_ms)
                .unwrap(),
            None
        );
    }

    #[test]
    fn missing_protected_state_answers_no_session() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let fixture = endpoint_fixture();
        let peer = peer_of(&fixture);
        let mut store = open_test_store(&path, Arc::clone(&backend));
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();
        backend
            .delete(&hex::encode(record_key_digest(&fixture.key).unwrap()))
            .unwrap();
        let inbound = inbound_message_envelope(&fixture, 0, [0x7b; 16], b"probe");
        assert_eq!(
            store
                .match_inbound_session(&peer, &inbound.pack(), fixture.now_ms)
                .unwrap(),
            None
        );
    }

    /// FE1 (and Phase 6 review sensing-1: only an object made after the
    /// retirement counts, by at least the accepted clock skew; one made
    /// before and delivered late is no evidence, however late it arrives).
    #[test]
    fn fork_evidence_only_for_initiator_role_after_grace() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let fixture = endpoint_fixture();
        let peer = peer_of(&fixture);
        let sid = fixture.binding.session_id;
        let grace = crate::session_reset::RESET_FORK_GRACE_MS;
        let after = 1_000 + crate::session_reset::RESET_FORK_MADE_AFTER_MS;
        let mut store = open_test_store(&path, Arc::new(MemoryProtectedBackend::default()));
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();
        // Not retired: nothing.
        assert!(!store
            .note_inbound_on_retired(&sid, true, after, 10 * grace)
            .unwrap());
        store
            .retire_session(
                &fixture.key,
                &peer,
                SessionRetireCause::PeerNoSession,
                1_000,
            )
            .unwrap();
        assert!(!store
            .note_inbound_on_retired(&sid, false, after, 10 * grace)
            .unwrap());
        assert!(!store
            .note_inbound_on_retired(&sid, true, after, 1_000 + grace - 1)
            .unwrap());
        // Made before the retirement (or within the skew after it), and
        // delivered late: nothing.
        for made in [900, 1_000, after - 1] {
            assert!(!store
                .note_inbound_on_retired(&sid, true, made, 100 * grace)
                .unwrap());
        }
        assert_eq!(
            store.peer_reset_state(&peer).unwrap(),
            PeerResetState::default()
        );
        assert!(store
            .note_inbound_on_retired(&sid, true, after, 1_000 + grace)
            .unwrap());
        assert_eq!(
            store.peer_reset_state(&peer).unwrap().fork_evidence_at_ms,
            Some(1_000 + grace)
        );
        store.confirm_peer_reset(&peer, 5 * grace).unwrap();
        assert_eq!(
            store.peer_reset_state(&peer).unwrap(),
            PeerResetState {
                fork_evidence_at_ms: Some(1_000 + grace),
                user_confirmed_at_ms: Some(5 * grace),
            }
        );
        // A cert-renewal retirement is never fork evidence.
        let other = second_session_fixture(1_000);
        store
            .create_session(other.binding.clone(), other.root)
            .unwrap();
        store
            .retire_session(
                &other.key,
                &peer,
                SessionRetireCause::PeerCertRenewed,
                1_000,
            )
            .unwrap();
        assert!(!store
            .note_inbound_on_retired(&other.binding.session_id, true, after, 10 * grace)
            .unwrap());
    }

    #[test]
    fn secure_delete_is_on_after_open() {
        let temp = tempdir().unwrap();
        let store = open_test_store(
            &temp.path().join("sessions.sqlite"),
            Arc::new(MemoryProtectedBackend::default()),
        );
        assert_eq!(crate::paths::scrub_test::secure_delete(&store.conn), 1);
    }

    /// An expired session whose `init_hash` (a clear column of its head) is
    /// `marker`.
    fn expired_session_marked(
        fixture: &EndpointFixture,
        marker: [u8; 32],
    ) -> IndexedSessionBinding {
        let mut expired = fixture.binding.clone();
        expired.key.init_id = [0x35; 16];
        expired.init_hash = marker;
        expired.session_id = session_id(&marker);
        expired.expires_at_ms = fixture.now_ms - 1;
        expired
    }

    /// PP.2: a pruned session's head is overwritten, and the prune's own
    /// checkpoint takes that into the main file and empties the WAL.
    #[test]
    fn a_deleted_row_leaves_no_bytes_after_checkpoint() {
        use crate::paths::scrub_test;
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let fixture = endpoint_fixture();
        let marker = scrub_test::marker();
        let mut store = open_test_store(&path, Arc::new(MemoryProtectedBackend::default()));
        store
            .create_session(expired_session_marked(&fixture, marker), [0xB9; 32])
            .unwrap();
        scrub_test::assert_written(&store.conn, &path, &marker);
        assert_eq!(store.prune_expired_sessions(fixture.now_ms).unwrap(), 1);
        scrub_test::assert_scrubbed(&path, &marker);
    }

    /// Review R19: a reader holding a snapshot (another raven process) makes
    /// the prune's checkpoint busy. The prune still succeeds, and the next
    /// prune pass completes the scrub.
    #[test]
    fn a_prune_with_an_open_reader_is_scrubbed_by_the_next_pass() {
        use crate::paths::scrub_test;
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let fixture = endpoint_fixture();
        let marker = scrub_test::marker();
        let mut store = open_test_store(&path, Arc::new(MemoryProtectedBackend::default()));
        store
            .create_session(expired_session_marked(&fixture, marker), [0xB9; 32])
            .unwrap();
        scrub_test::assert_written(&store.conn, &path, &marker);

        let reader = Connection::open(&path).unwrap();
        reader
            .execute_batch("BEGIN; SELECT count(*) FROM indexed_session_heads;")
            .unwrap();
        assert_eq!(store.prune_expired_sessions(fixture.now_ms).unwrap(), 1);
        assert!(scrub_test::main_file_holds(&path, &marker));
        assert!(scrub_test::wal_len(&path) > 0);

        reader.execute_batch("COMMIT;").unwrap();
        assert_eq!(store.prune_expired_sessions(fixture.now_ms).unwrap(), 0);
        scrub_test::assert_scrubbed(&path, &marker);
    }

    // --- Privacy pack PP.8: deleted inbox rows (a clear that sticks) ---

    fn inbox_ids(store: &mut IndexedSessionStore) -> Vec<[u8; 16]> {
        store
            .list_endpoint_inbox()
            .unwrap()
            .into_iter()
            .map(|row| row.message_id)
            .collect()
    }

    fn tombstones(store: &IndexedSessionStore) -> i64 {
        store
            .conn
            .query_row("SELECT COUNT(*) FROM endpoint_inbox_deleted", [], |row| {
                row.get(0)
            })
            .unwrap()
    }

    fn accept_plain(
        store: &mut IndexedSessionStore,
        fixture: &EndpointFixture,
        index: u32,
        message_id: [u8; 16],
        plaintext: &[u8],
        now_ms: u64,
    ) -> Result<EndpointAcceptance, IndexedSessionStoreError> {
        let inbound = inbound_message_envelope(fixture, index, message_id, plaintext);
        store.accept_message_envelope(
            &fixture.key,
            &inbound.pack(),
            &fixture.remote_certificate,
            false,
            now_ms,
        )
    }

    /// A deletion removes the chat rows, leaves one tombstone each, keeps the
    /// receipts and ACK intents, and the deleted object stays a duplicate.
    /// `received_up_to_ms` bounds it; a second run changes nothing.
    #[test]
    fn deleted_rows_leave_tombstones_and_stay_duplicates() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let fixture = endpoint_fixture();
        let remote = fixture.key.responder_device_ed25519;
        let mut store = open_test_store(&path, Arc::new(MemoryProtectedBackend::default()));
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();
        let now = fixture.now_ms;
        let first = accept_text(&mut store, &fixture, 0, [0xD1; 16], now);
        accept_text(&mut store, &fixture, 1, [0xD2; 16], now + 1);
        let up_to = store.list_endpoint_inbox().unwrap()[0].position;

        let report = store
            .delete_inbox_for_sender(&remote, Some(&up_to))
            .unwrap();
        assert_eq!((report.deleted, report.skipped), (1, 0));
        assert!(report.scrubbed);
        assert_eq!(inbox_ids(&mut store), vec![[0xD2; 16]]);
        let sid = fixture.binding.session_id;
        assert!(store.inbox_row_deleted(&sid, &first).unwrap());
        assert_eq!(
            store.load_endpoint_inbox(&fixture.key, &first).unwrap(),
            None
        );
        let receipts: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM endpoint_receipts", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(receipts, 2);
        assert_eq!(store.pending_endpoint_ack_intents().unwrap().len(), 2);
        assert!(matches!(
            accept_plain(&mut store, &fixture, 0, [0xD1; 16], b"listed", now).unwrap(),
            EndpointAcceptance::Duplicate { object_digest, .. } if object_digest == first
        ));

        let rest = store.delete_inbox_for_sender(&remote, None).unwrap();
        assert_eq!(rest.deleted, 1);
        assert!(inbox_ids(&mut store).is_empty());
        assert_eq!(tombstones(&store), 2);
        let again = store.delete_inbox_for_sender(&remote, None).unwrap();
        assert_eq!(
            again,
            InboxDeletion {
                deleted: 0,
                skipped: 0,
                scrubbed: true
            }
        );
        assert_eq!(tombstones(&store), 2);
        // Another sender's deletion finds nothing of this one.
        assert_eq!(
            store
                .delete_inbox_for_sender(&[0xF4; 32], None)
                .unwrap()
                .deleted,
            0
        );
    }

    /// `delete_inbox_older_than` (the retention pass, PP.9): rows received
    /// strictly before the cutoff, whoever sent them.
    #[test]
    fn delete_inbox_older_than_takes_only_older_rows() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let fixture = endpoint_fixture();
        let mut store = open_test_store(&path, Arc::new(MemoryProtectedBackend::default()));
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();
        let now = fixture.now_ms;
        for (index, id) in [[0xC1; 16], [0xC2; 16], [0xC3; 16]].iter().enumerate() {
            accept_text(
                &mut store,
                &fixture,
                index as u32,
                *id,
                now + 10 * index as u64,
            );
        }
        let stamps: Vec<u64> = store
            .list_endpoint_inbox()
            .unwrap()
            .iter()
            .map(|row| row.received_at_ms)
            .collect();
        assert_eq!(store.delete_inbox_older_than(0).unwrap().deleted, 0);
        assert_eq!(store.delete_inbox_older_than(stamps[0]).unwrap().deleted, 0);
        assert_eq!(store.delete_inbox_older_than(stamps[2]).unwrap().deleted, 2);
        assert_eq!(inbox_ids(&mut store), vec![[0xC3; 16]]);
    }

    /// An agent payload is RDAP's (the app channel's inbox): deleting a chat
    /// never touches it, only the chat rows of the same sender go.
    #[test]
    fn app_frames_are_not_touched() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let fixture = endpoint_fixture();
        let remote = fixture.key.responder_device_ed25519;
        let mut store = open_test_store(&path, Arc::new(MemoryProtectedBackend::default()));
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();
        let frame = crate::app_channel::encode_frame(
            crate::app_channel::CT_A2A_REQUEST,
            &[0x5A; 16],
            "{\"task\":1}",
            false,
        )
        .unwrap();
        assert!(matches!(
            crate::app_channel::classify(frame.as_bytes()),
            crate::app_channel::PayloadClass::App(_)
        ));
        accept_plain(
            &mut store,
            &fixture,
            0,
            [0xA1; 16],
            frame.as_bytes(),
            fixture.now_ms,
        )
        .unwrap();
        accept_plain(&mut store, &fixture, 1, [0xA2; 16], b"chat", fixture.now_ms).unwrap();
        let report = store.delete_inbox_for_sender(&remote, None).unwrap();
        assert_eq!((report.deleted, report.skipped), (1, 0));
        let left = store.list_endpoint_inbox().unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].plaintext, frame.as_bytes());
        assert_eq!(store.delete_inbox_older_than(u64::MAX).unwrap().deleted, 0);
        assert_eq!(tombstones(&store), 1);
    }

    /// Review R05: a row whose acceptance journal is still pending (a second
    /// store instance committed it and has not cleared its journal yet) is
    /// skipped and counted, so the journal's replay still finds it; the next
    /// deletion takes it.
    #[test]
    fn delete_skips_rows_with_a_pending_acceptance_journal() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let fixture = endpoint_fixture();
        let remote = fixture.key.responder_device_ed25519;
        let mut store = open_test_store(&path, Arc::clone(&backend));
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();
        accept_text(&mut store, &fixture, 0, [0xB1; 16], fixture.now_ms);
        store.inject_after_recovery_hook({
            let path = path.clone();
            let backend = Arc::clone(&backend);
            move || {
                let fixture = endpoint_fixture();
                let mut other = open_test_store(&path, backend);
                other.inject_endpoint_fault(EndpointFaultPoint::BeforeJournalClear);
                let raced = accept_plain(
                    &mut other,
                    &fixture,
                    1,
                    [0xB2; 16],
                    b"racing",
                    fixture.now_ms,
                );
                assert!(
                    matches!(
                        raced,
                        Err(IndexedSessionStoreError::InjectedEndpointFailure(_))
                    ),
                    "{raced:?}"
                );
            }
        });
        let report = store.delete_inbox_for_sender(&remote, None).unwrap();
        assert_eq!((report.deleted, report.skipped), (1, 1));
        drop(store);

        let mut reopened = open_test_store(&path, backend);
        assert_eq!(inbox_ids(&mut reopened), vec![[0xB2; 16]]);
        let next = reopened.delete_inbox_for_sender(&remote, None).unwrap();
        assert_eq!((next.deleted, next.skipped), (1, 0));
        assert!(inbox_ids(&mut reopened).is_empty());
    }

    /// A journal replayed for a row the user deleted (the guard above makes
    /// it rare; an interrupted older run could leave it) treats the object as
    /// accepted: never `CorruptEndpointState`, the session keeps working and
    /// the object stays a duplicate.
    #[test]
    fn recovery_after_delete_is_not_corrupt_endpoint_state() {
        // Schema 1 only (an older build's clear tombstone written by hand).
        sealed::test_switch::off();
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let backend = Arc::new(MemoryProtectedBackend::default());
        let fixture = endpoint_fixture();
        let mut store = open_test_store(&path, Arc::clone(&backend));
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();
        store.inject_endpoint_fault(EndpointFaultPoint::BeforeJournalClear);
        assert!(matches!(
            accept_plain(&mut store, &fixture, 0, [0x9A; 16], b"cut", fixture.now_ms),
            Err(IndexedSessionStoreError::InjectedEndpointFailure(_))
        ));
        let (digest, received): (Vec<u8>, i64) = store
            .conn
            .query_row(
                "SELECT object_digest, received_at_ms FROM endpoint_inbox",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let sid = fixture.binding.session_id;
        store
            .conn
            .execute(
                "INSERT INTO endpoint_inbox_deleted VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    sid.as_slice(),
                    digest.as_slice(),
                    fixture.key.responder_device_ed25519.as_slice(),
                    fixture.now_ms as i64,
                    received
                ],
            )
            .unwrap();
        store
            .conn
            .execute("DELETE FROM endpoint_inbox", [])
            .unwrap();
        drop(store);

        let mut reopened = open_test_store(&path, backend);
        assert!(matches!(
            accept_plain(
                &mut reopened,
                &fixture,
                1,
                [0x9B; 16],
                b"next",
                fixture.now_ms
            ),
            Ok(EndpointAcceptance::Committed { .. })
        ));
        assert!(matches!(
            accept_plain(
                &mut reopened,
                &fixture,
                0,
                [0x9A; 16],
                b"cut",
                fixture.now_ms
            ),
            Ok(EndpointAcceptance::Duplicate { .. })
        ));
        assert_eq!(inbox_ids(&mut reopened), vec![[0x9B; 16]]);
    }

    /// Every reader of a deleted object takes it as deleted by the user: the
    /// row reads as missing, the tombstone says why, the committed ACK is
    /// enqueued and re-enqueued unchanged, the per-session listing and the
    /// journal-recovering operations succeed. A row missing without a
    /// tombstone is not "deleted" (its callers keep their error).
    #[test]
    fn reconcile_treats_tombstoned_rows_as_deleted() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let fixture = endpoint_fixture();
        let local_device = authorized_local_device(&fixture);
        let remote = fixture.key.responder_device_ed25519;
        let mut store = open_test_store(&path, Arc::new(MemoryProtectedBackend::default()));
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();
        let deleted = accept_text(&mut store, &fixture, 0, [0x8A; 16], fixture.now_ms);
        let kept = accept_text(&mut store, &fixture, 1, [0x8B; 16], fixture.now_ms);
        let report = store
            .delete_inbox_for_sender(&remote, None)
            .map(|r| r.deleted)
            .unwrap();
        assert_eq!(report, 2);
        let sid = fixture.binding.session_id;
        // Put one row back without its tombstone: a row lost some other way.
        store
            .conn
            .execute(
                &store
                    .layout
                    .ep("DELETE FROM endpoint_inbox_deleted WHERE kh_object_digest = ?1"),
                params![store.layout.ep_digest(&kept)],
            )
            .unwrap();
        assert!(store.inbox_row_deleted(&sid, &deleted).unwrap());
        assert!(!store.inbox_row_deleted(&sid, &kept).unwrap());
        assert_eq!(
            store.load_endpoint_inbox(&fixture.key, &deleted).unwrap(),
            None
        );
        assert!(store
            .list_endpoint_inbox_for_record(&fixture.key)
            .unwrap()
            .is_empty());
        let mut rng = StdRng::from_seed([0x8C; 32]);
        let mut queue = |digest: &[u8; 32], _bytes: &[u8]| Ok(*digest);
        let ack = store
            .enqueue_committed_ack(
                &fixture.key,
                &deleted,
                &local_device,
                fixture.now_ms,
                fixture.now_ms + 60_000,
                fixture.now_ms,
                &mut rng,
                &mut queue,
            )
            .unwrap();
        let mut other_rng = StdRng::from_seed([0x8D; 32]);
        let again = store
            .enqueue_committed_ack(
                &fixture.key,
                &deleted,
                &local_device,
                fixture.now_ms,
                fixture.now_ms + 60_000,
                fixture.now_ms,
                &mut other_rng,
                &mut queue,
            )
            .unwrap();
        assert_eq!(again.immutable_envelope_bytes, ack.immutable_envelope_bytes);
        assert!(matches!(
            accept_plain(
                &mut store,
                &fixture,
                2,
                [0x8E; 16],
                b"later",
                fixture.now_ms
            ),
            Ok(EndpointAcceptance::Committed { .. })
        ));
    }

    /// The paging cursor's floor survives a deletion: a row received after
    /// it (with the wall clock stepped back) still sorts after every row
    /// that went, so a chat cursor saved over them never hides it.
    #[test]
    fn monotonic_floor_survives_delete() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let fixture = endpoint_fixture();
        let remote = fixture.key.responder_device_ed25519;
        let mut store = open_test_store(&path, Arc::new(MemoryProtectedBackend::default()));
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();
        let now = fixture.now_ms;
        accept_text(&mut store, &fixture, 0, [0x7A; 16], now + 5_000);
        let cursor = store.list_endpoint_inbox().unwrap()[0].received_at_ms;
        assert_eq!(cursor, now + 5_000);
        store.delete_inbox_for_sender(&remote, None).unwrap();
        // The clock stepped back 5 s.
        accept_text(&mut store, &fixture, 1, [0x7B; 16], now);
        let rows = store.list_endpoint_inbox().unwrap();
        assert_eq!(rows.len(), 1);
        assert!(
            rows[0].received_at_ms > cursor,
            "{}",
            rows[0].received_at_ms
        );
        assert_eq!(
            store
                .list_endpoint_inbox_for_sender_after(
                    &remote,
                    &after(cursor, Some(&[0x7A; 16])),
                    10
                )
                .unwrap()
                .len(),
            1
        );
    }

    /// The prune deletes a session's tombstones before its receipts (no
    /// foreign key), and those an older build's prune left without a session;
    /// a live session keeps its own.
    #[test]
    fn prune_removes_tombstones_before_receipts() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("sessions.sqlite");
        let fixture = endpoint_fixture();
        let remote = fixture.key.responder_device_ed25519;
        let mut store = open_test_store(&path, Arc::new(MemoryProtectedBackend::default()));
        store
            .create_session(fixture.binding.clone(), fixture.root)
            .unwrap();
        accept_text(&mut store, &fixture, 0, [0x6A; 16], fixture.now_ms);
        store.delete_inbox_for_sender(&remote, None).unwrap();
        // An orphan, as an older build's prune leaves it.
        store
            .conn
            .execute(
                "INSERT INTO endpoint_inbox_deleted VALUES (?1, ?2, ?3, 1, 1)",
                params![
                    [0x01u8; 32].as_slice(),
                    [0x02u8; 32].as_slice(),
                    remote.as_slice()
                ],
            )
            .unwrap();
        assert_eq!(tombstones(&store), 2);
        assert_eq!(store.prune_expired_sessions(fixture.now_ms).unwrap(), 0);
        assert_eq!(
            tombstones(&store),
            1,
            "the live session keeps its tombstone"
        );

        assert_eq!(
            store
                .prune_expired_sessions(fixture.binding.expires_at_ms)
                .unwrap(),
            1
        );
        assert_eq!(tombstones(&store), 0);
        let receipts: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM endpoint_receipts", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(receipts, 0);
    }

    mod letters_store;
    mod parked_store;
    mod renewal_store;
    mod sealed_store;
}
