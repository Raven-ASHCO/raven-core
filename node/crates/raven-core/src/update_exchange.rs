//! RAVEN Update Exchange V1 (RUP1, `protocol/RAVEN_UPDATE_EXCHANGE_V1.md`;
//! `docs/roadmap/plans/phase6-design.json` step P6.48, design D §6 and wire
//! spec W-D4; owner decisions OD6b-23, OD6b-24): how friends pass security
//! advisories, transparency log snapshots and release bundles to each other
//! over their authenticated Raven links, without any server.
//!
//! ```text
//! header = "RUP1" || 0x01 || op u8 || req_id[4]                   (10 bytes)
//! 0x01 HAVE          adv_serial u64 || adv_digest[32] || log_size u32
//!                    || log_root[32] || n u8 (0..=4) || offer x n  one-way
//!      offer       = build_serial u64 || target_len u8 (1..=64) || target
//!                    || manifest_digest[32] || payload_len u64
//! 0x02 GET_ADVISORY  (empty)                    answered ADVISORY or ERROR
//! 0x03 GET_LOG       (empty)                    answered LOG or ERROR
//! 0x04 GET_MANIFEST  manifest_digest[32]        answered MANIFEST or ERROR
//! 0x05 GET_CHUNKS    manifest_digest[32] || first u32 || count u8 (1..=8)
//!                                    answered CHUNK x n, CHUNKS_END, or ERROR
//! 0x06 GET_ROTATION  key_set_digest[32]         answered ADVISORY or ERROR
//! 0x82 ADVISORY      rad1_len u16 || RAD1 || RTL1 snapshot          terminal
//! 0x83 LOG           RTL1 snapshot                                  terminal
//! 0x84 MANIFEST      manifest_len u16 || RRB1 manifest || RTL1 snapshot
//!                                                                   terminal
//! 0x85 CHUNK         index u32 || len u32 || bytes || path_len u8 (0..=11)
//!                    || path[32] x path_len                     non-terminal
//! 0x86 CHUNKS_END    code u8 (0 OK, else an ERROR code) || sent u8  terminal
//! 0xFF ERROR         code u8 (1 UNSUPPORTED, 2 NOT_FOUND, 3 BUSY,
//!                    4 RATE_LIMITED, 5 POLICY_DENIED, 6 MALFORMED)  terminal
//! ```
//!
//! Raw Noise-transport frames on authenticated direct links after RLB1 (and
//! RRH1), like RSR1 and RFC1: never RVN1, never stored for others or
//! forwarded as frames (only the artifacts they carry are kept, once
//! verified). Negotiated per link with caps bit 10
//! ([`CAP_LINK_RUP1`](crate::CAP_LINK_RUP1)); old peers never set it and
//! never receive RUP1. Only the dialer sends requests and the listener
//! answers them (the RFC1 pattern), so raven-node's reply collector ends a
//! dial on [`frame_is_terminal_reply`]; HAVE goes both ways and is never
//! answered. Every frame is at most [`MAX_FRAME_LEN`] bytes, PAD1's inner
//! limit, so it fits one padded link frame whether or not the link pads.
//!
//! Every length is checked against its cap and against the frame before
//! anything is copied: [`decode`] never allocates more than the caps allow
//! (4 offers of at most 64-byte targets, 11 path hashes) plus the frame's
//! own payload bytes, and a refused frame allocates nothing. The artifacts
//! inside (RAD1, RTL1, RRB1) are only bounded here; their own codecs check
//! them when the update state verifies them.
//!
//! Pure: no I/O, no clock, no randomness. raven-node runs the exchange
//! (P6.49) only while [`notices_live`], and passes bundles only while
//! [`live`] (`MESH_UPDATE_PRODUCTION_ENABLED = false`).

use thiserror::Error;

use crate::advisory::MAX_RAD1_LEN;
use crate::link_padding::PAD1_MAX_INNER;
use crate::release_bundle::{
    target_well_formed, ChunkTree, CHUNK_SIZE, MAX_CHUNKS, MAX_CHUNK_PATH_LEN, MAX_MANIFEST_LEN,
    MAX_PAYLOAD_LEN, MAX_TARGET_LEN,
};
use crate::security_gate::{self, SecGate};
use crate::tlog::{MAX_LOG_ENTRIES, MAX_SNAPSHOT_LEN};

/// The frame magic.
pub const RUP1_MAGIC: &[u8; 4] = b"RUP1";
/// The version byte this revision writes and reads.
pub const RUP1_VERSION: u8 = 0x01;
/// Magic, version, op and request id.
pub const HEADER_LEN: usize = 10;
/// The longest frame: PAD1's inner limit, so every RUP1 frame fits one
/// padded link frame (and one Noise transport message without padding).
pub const MAX_FRAME_LEN: usize = PAD1_MAX_INNER;
/// The request id of a HAVE, which is never answered.
pub const NO_REQ_ID: [u8; 4] = [0; 4];

/// One-way: what this side holds (both directions, never answered).
pub const OP_HAVE: u8 = 0x01;
/// Request: the newest advisory and the log snapshot that lists it.
pub const OP_GET_ADVISORY: u8 = 0x02;
/// Request: the log snapshot.
pub const OP_GET_LOG: u8 = 0x03;
/// Request: a manifest by its digest, with the log snapshot that lists it.
pub const OP_GET_MANIFEST: u8 = 0x04;
/// Request: up to 8 chunks of a manifest's payload.
pub const OP_GET_CHUNKS: u8 = 0x05;
/// Request: the advisory that rotated away from a key set, signed by it,
/// with the log it was accepted with (added under version 1 by the Phase 6
/// review, updates-protocol-3: how a node that missed a rotation catches
/// up; a listener built before it answers ERROR UNSUPPORTED).
pub const OP_GET_ROTATION: u8 = 0x06;
/// Reply to GET_ADVISORY (terminal).
pub const OP_ADVISORY: u8 = 0x82;
/// Reply to GET_LOG (terminal).
pub const OP_LOG: u8 = 0x83;
/// Reply to GET_MANIFEST (terminal).
pub const OP_MANIFEST: u8 = 0x84;
/// Reply to GET_CHUNKS, one per chunk (non-terminal).
pub const OP_CHUNK: u8 = 0x85;
/// Reply to GET_CHUNKS after its chunks (terminal).
pub const OP_CHUNKS_END: u8 = 0x86;
/// Reply to any request the listener does not serve (terminal).
pub const OP_ERROR: u8 = 0xFF;

/// The most bundle offers one HAVE carries.
pub const MAX_OFFERS: usize = 4;
/// The most chunks one GET_CHUNKS asks for.
pub const MAX_CHUNKS_PER_REQUEST: u8 = 8;
/// The most chunks a fetcher asks for in one dial (two full requests).
pub const MAX_CHUNKS_PER_DIAL: usize = 16;
/// HAVE's fixed fields: serial, digest, log size, root and the offer count.
pub const HAVE_FIXED_LEN: usize = 8 + 32 + 4 + 32 + 1;
/// An offer's fixed fields: build serial, target length, digest and length.
pub const OFFER_FIXED_LEN: usize = 8 + 1 + 32 + 8;
/// The longest HAVE: four offers with 64-byte targets (539 bytes).
pub const MAX_HAVE_LEN: usize =
    HEADER_LEN + HAVE_FIXED_LEN + MAX_OFFERS * (OFFER_FIXED_LEN + MAX_TARGET_LEN);
/// GET_CHUNKS: digest, first index and count (47 bytes).
pub const GET_CHUNKS_LEN: usize = HEADER_LEN + 32 + 4 + 1;
/// GET_ROTATION: a key set digest (42 bytes).
pub const GET_ROTATION_LEN: usize = HEADER_LEN + 32;
/// The longest CHUNK: a full chunk and an 11-hash path (61,811 bytes).
pub const MAX_CHUNK_FRAME_LEN: usize =
    HEADER_LEN + 4 + 4 + CHUNK_SIZE as usize + 1 + 32 * MAX_CHUNK_PATH_LEN;
/// The longest MANIFEST: the longest manifest and snapshot (63,233 bytes).
pub const MAX_MANIFEST_FRAME_LEN: usize = HEADER_LEN + 2 + MAX_MANIFEST_LEN + MAX_SNAPSHOT_LEN;
/// The longest LOG: the longest snapshot (58,033 bytes).
pub const MAX_LOG_FRAME_LEN: usize = HEADER_LEN + MAX_SNAPSHOT_LEN;
/// An advisory of at most this many bytes fits one ADVISORY beside any
/// version 1 snapshot (7,476). A longer one fits only beside a shorter
/// log; when it does not, the listener answers ERROR NOT_FOUND and the
/// advisory travels as a file instead (spec §8).
pub const ADVISORY_ALWAYS_FITS: usize = MAX_FRAME_LEN - HEADER_LEN - 2 - MAX_SNAPSHOT_LEN;

const _: () = assert!(MAX_CHUNK_FRAME_LEN == 61_811 && MAX_CHUNK_FRAME_LEN <= MAX_FRAME_LEN);
const _: () = assert!(MAX_MANIFEST_FRAME_LEN == 63_233 && MAX_MANIFEST_FRAME_LEN <= MAX_FRAME_LEN);
const _: () = assert!(MAX_HAVE_LEN == 539 && ADVISORY_ALWAYS_FITS == 7_476);
const _: () = assert!(MAX_RAD1_LEN <= u16::MAX as usize);
const _: () = assert!(MAX_MANIFEST_LEN <= u16::MAX as usize);
const _: () = assert!(MAX_CHUNKS_PER_DIAL == 2 * MAX_CHUNKS_PER_REQUEST as usize);

/// Serving (spec §7, raven-node P6.49): requests one friend may make a
/// minute.
pub const SERVE_REQUESTS_PER_MINUTE: u32 = 6;
/// Serving: payload bytes one friend may fetch a day (128 MiB).
pub const SERVE_BYTES_PER_DAY: u64 = 128 * 1024 * 1024;
/// Serving: requests answered at once, over every friend.
pub const SERVE_AT_ONCE: usize = 2;

/// Is the whole update exchange on, release bundles included
/// (`MESH_UPDATE_PRODUCTION_ENABLED`, or its lab switch in a debug build,
/// with the release bundle and advisory gates, and no advisory hold on any
/// of them)? Bundle offers, GET_MANIFEST, GET_CHUNKS and download rows
/// follow it.
pub fn live() -> bool {
    security_gate::live(SecGate::MeshUpdate)
}

/// Do notices (advisories and logs: HAVE's claims, GET_ADVISORY, GET_LOG,
/// GET_ROTATION) pass between friends? [`live`] apart from a hold on
/// `feature/release-bundle` (Phase 6 review updates-protocol-4): a node
/// without an uplink gets notices only this way, so a hold on bundles must
/// not stop the notice that lifts it. A hold on `feature/mesh-update`, or a
/// BROKEN `rup1/1` (the consult point of `rup1/1`), still stops the whole
/// exchange: only a new build or a file import lifts those.
pub fn notices_live() -> bool {
    security_gate::live_despite_hold_on(SecGate::MeshUpdate, SecGate::ReleaseBundle)
}

/// An ERROR code (spec §3.4). CHUNKS_END uses the same codes for why it
/// stopped early, and `0` for "every chunk asked for was sent".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// `1`: an op or version the listener does not serve.
    Unsupported,
    /// `2`: the listener does not hold what was asked for (or it does not
    /// fit one frame).
    NotFound,
    /// `3`: the listener is serving as many requests as it will.
    Busy,
    /// `4`: this friend asked too often or fetched too much today.
    RateLimited,
    /// `5`: the listener does not serve this friend or this artifact.
    PolicyDenied,
    /// `6`: a known request whose body breaks a rule.
    Malformed,
    /// `7..=255`: a code this version does not know (a failure all the same).
    Other(u8),
}

impl ErrorCode {
    /// The code of a code byte; `None` for `0`, which is not an error.
    pub fn from_byte(b: u8) -> Option<Self> {
        Some(match b {
            0 => return None,
            1 => Self::Unsupported,
            2 => Self::NotFound,
            3 => Self::Busy,
            4 => Self::RateLimited,
            5 => Self::PolicyDenied,
            6 => Self::Malformed,
            other => Self::Other(other),
        })
    }

    /// The code byte.
    pub fn byte(self) -> u8 {
        match self {
            Self::Unsupported => 1,
            Self::NotFound => 2,
            Self::Busy => 3,
            Self::RateLimited => 4,
            Self::PolicyDenied => 5,
            Self::Malformed => 6,
            Self::Other(b) => b,
        }
    }

    /// The name the spec and the vectors use.
    pub fn name(self) -> &'static str {
        match self {
            Self::Unsupported => "UNSUPPORTED",
            Self::NotFound => "NOT_FOUND",
            Self::Busy => "BUSY",
            Self::RateLimited => "RATE_LIMITED",
            Self::PolicyDenied => "POLICY_DENIED",
            Self::Malformed => "MALFORMED",
            Self::Other(_) => "UNKNOWN",
        }
    }
}

/// One bundle a friend serves (spec §3.1): enough to decide whether to ask
/// the user, never trusted until the manifest it names verifies.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Offer {
    /// The release's build serial (`>= 1`).
    pub build_serial: u64,
    /// The release's target triple (well formed as in RRB1).
    pub target: String,
    /// The manifest's `manifest_digest`: GET_MANIFEST and GET_CHUNKS name
    /// the bundle by it.
    pub manifest_digest: [u8; 32],
    /// The payload's length (`1..=67,108,864`).
    pub payload_len: u64,
}

/// What one side holds (spec §3.1). Unsigned claims: they only decide what
/// to fetch.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Have {
    /// The newest accepted advisory's serial; `0`: none.
    pub adv_serial: u64,
    /// Its `advisory_digest`; all zero exactly when `adv_serial` is `0`.
    pub adv_digest: [u8; 32],
    /// The stored log's size (`0..=1,400`); `0`: no log.
    pub log_size: u32,
    /// The stored log's root; all zero exactly when `log_size` is `0`.
    pub log_root: [u8; 32],
    /// The bundles this side serves, each manifest digest once.
    pub offers: Vec<Offer>,
}

impl Have {
    /// Holding nothing: no advisory, no log, no bundle.
    pub fn nothing() -> Self {
        Self::default()
    }
}

/// One chunk of a bundle's payload with its audit path (spec §3.3).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Chunk {
    /// The chunk's index (`< 1,093`).
    pub index: u32,
    /// The chunk (`1..=61,440` bytes).
    pub bytes: Vec<u8>,
    /// Its RFC 6962 audit path to the chunk root, from the leaf's sibling up
    /// (`0..=11` hashes).
    pub path: Vec<[u8; 32]>,
}

impl Chunk {
    /// Chunk `index` of `payload` with its path in `tree` (the payload's
    /// [`ChunkTree`]); `None` past the last chunk.
    pub fn of_payload(payload: &[u8], tree: &ChunkTree, index: u32) -> Option<Self> {
        let size = CHUNK_SIZE as usize;
        let start = usize::try_from(index).ok()?.checked_mul(size)?;
        if start >= payload.len() {
            return None;
        }
        Some(Self {
            index,
            bytes: payload[start..payload.len().min(start + size)].to_vec(),
            path: tree.chunk_path(index as usize)?,
        })
    }

    /// Is this chunk `index` of the manifest's payload, by its path to the
    /// manifest's chunk root? Checked before a chunk is written.
    pub fn check(&self, manifest: &crate::release_bundle::Manifest) -> bool {
        manifest.check_chunk(u64::from(self.index), &self.bytes, &self.path)
    }
}

/// One RUP1 frame's content (spec §3).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Rup1Msg {
    /// `0x01`: what this side holds; one-way.
    Have(Have),
    /// `0x02`: ask for the newest advisory.
    GetAdvisory,
    /// `0x03`: ask for the log snapshot.
    GetLog,
    /// `0x04`: ask for a manifest.
    GetManifest { manifest_digest: [u8; 32] },
    /// `0x05`: ask for chunks `first .. first + count` of a payload.
    GetChunks {
        manifest_digest: [u8; 32],
        first: u32,
        count: u8,
    },
    /// `0x06`: ask for the advisory that rotated away from the key set of
    /// this digest (the dialer's current set), answered ADVISORY with the
    /// log it was accepted with, both under that set.
    GetRotation { key_set_digest: [u8; 32] },
    /// `0x82`: the advisory (RAD1) and the log snapshot (RTL1) that lists it.
    Advisory { rad1: Vec<u8>, snapshot: Vec<u8> },
    /// `0x83`: the log snapshot.
    Log { snapshot: Vec<u8> },
    /// `0x84`: the manifest (RRB1) and the log snapshot that lists it.
    Manifest {
        manifest: Vec<u8>,
        snapshot: Vec<u8>,
    },
    /// `0x85`: one chunk.
    Chunk(Chunk),
    /// `0x86`: the chunks of a GET_CHUNKS are done: `sent` were sent, and
    /// `stopped` says why the listener stopped early (`None`: it did not).
    ChunksEnd {
        stopped: Option<ErrorCode>,
        sent: u8,
    },
    /// `0xFF`: the request is not served.
    Error(ErrorCode),
}

/// What a frame is for (spec §5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// HAVE: sent by both sides, never answered.
    OneWay,
    /// Sent by the dialer only; answered by one terminal reply.
    Request,
    /// Sent by the listener only, to a request; `true`: it ends the request.
    Reply { terminal: bool },
}

impl Rup1Msg {
    /// The op byte.
    pub fn op(&self) -> u8 {
        match self {
            Self::Have(_) => OP_HAVE,
            Self::GetAdvisory => OP_GET_ADVISORY,
            Self::GetLog => OP_GET_LOG,
            Self::GetManifest { .. } => OP_GET_MANIFEST,
            Self::GetChunks { .. } => OP_GET_CHUNKS,
            Self::GetRotation { .. } => OP_GET_ROTATION,
            Self::Advisory { .. } => OP_ADVISORY,
            Self::Log { .. } => OP_LOG,
            Self::Manifest { .. } => OP_MANIFEST,
            Self::Chunk(_) => OP_CHUNK,
            Self::ChunksEnd { .. } => OP_CHUNKS_END,
            Self::Error(_) => OP_ERROR,
        }
    }

    /// What this frame is for.
    pub fn role(&self) -> Role {
        match self {
            Self::Have(_) => Role::OneWay,
            Self::GetAdvisory
            | Self::GetLog
            | Self::GetManifest { .. }
            | Self::GetChunks { .. }
            | Self::GetRotation { .. } => Role::Request,
            Self::Chunk(_) => Role::Reply { terminal: false },
            _ => Role::Reply { terminal: true },
        }
    }

    /// Does this reply end its request? Only CHUNK does not.
    pub fn is_terminal(&self) -> bool {
        self.role() == Role::Reply { terminal: true }
    }

    /// Can `reply` answer this request (spec §5)? ERROR answers any
    /// request; each request has its own reply; a CHUNK must be one asked
    /// for, and CHUNKS_END cannot count more chunks than were asked for.
    pub fn answered_by(&self, reply: &Rup1Msg) -> bool {
        match (self, reply) {
            (_, Self::Error(_)) => self.role() == Role::Request,
            (Self::GetAdvisory | Self::GetRotation { .. }, Self::Advisory { .. })
            | (Self::GetLog, Self::Log { .. })
            | (Self::GetManifest { .. }, Self::Manifest { .. }) => true,
            (Self::GetChunks { first, count, .. }, Self::Chunk(c)) => {
                c.index >= *first && u64::from(c.index) < u64::from(*first) + u64::from(*count)
            }
            (Self::GetChunks { count, .. }, Self::ChunksEnd { sent, .. }) => sent <= count,
            _ => false,
        }
    }
}

/// Why RUP1 bytes are refused (spec §4), in the order they are checked.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum Rup1Error {
    /// Not an RUP1 frame: shorter than the magic, or another magic.
    #[error("RUP1 NOT_RUP1")]
    NotRup1,
    /// The frame ends inside its header or inside a field.
    #[error("RUP1 TRUNCATED")]
    Truncated,
    /// Longer than [`MAX_FRAME_LEN`].
    #[error("RUP1 TOO_LONG")]
    TooLong,
    #[error("RUP1 BAD_VERSION")]
    BadVersion,
    /// An op this version does not define.
    #[error("RUP1 UNKNOWN_OP")]
    UnknownOp,
    /// Bytes after the last field.
    #[error("RUP1 TRAILING_BYTES")]
    TrailingBytes,
    /// A HAVE with a request id other than zero.
    #[error("RUP1 NONZERO_REQ_ID")]
    NonzeroReqId,
    /// `adv_serial` 0 with a digest, or a serial without one.
    #[error("RUP1 BAD_ADVISORY_REF")]
    BadAdvisoryRef,
    /// `log_size` above 1,400, 0 with a root, or a size without one.
    #[error("RUP1 BAD_LOG_REF")]
    BadLogRef,
    /// More than 4 offers.
    #[error("RUP1 TOO_MANY_OFFERS")]
    TooManyOffers,
    /// An offer's build serial is 0.
    #[error("RUP1 BAD_SERIAL")]
    BadSerial,
    /// An offer's target is empty, longer than 64 bytes or not well formed.
    #[error("RUP1 BAD_TARGET")]
    BadTarget,
    /// An offer's payload length is 0 or above 64 MiB.
    #[error("RUP1 BAD_PAYLOAD_LEN")]
    BadPayloadLen,
    /// Two offers name the same manifest.
    #[error("RUP1 DUPLICATE_OFFER")]
    DuplicateOffer,
    /// `rad1_len` is 0 or above 32,768.
    #[error("RUP1 BAD_RAD1_LEN")]
    BadRad1Len,
    /// `manifest_len` is 0 or above 5,198.
    #[error("RUP1 BAD_MANIFEST_LEN")]
    BadManifestLen,
    /// The snapshot is empty or longer than 58,023 bytes.
    #[error("RUP1 BAD_SNAPSHOT_LEN")]
    BadSnapshotLen,
    /// A chunk count of 0 or above 8.
    #[error("RUP1 BAD_COUNT")]
    BadCount,
    /// A chunk index no version 1 payload has (1,093 chunks at most).
    #[error("RUP1 BAD_INDEX")]
    BadIndex,
    /// A chunk of 0 bytes or more than 61,440.
    #[error("RUP1 BAD_CHUNK_LEN")]
    BadChunkLen,
    /// An audit path of more than 11 hashes.
    #[error("RUP1 BAD_PATH_LEN")]
    BadPathLen,
    /// An ERROR with code 0.
    #[error("RUP1 BAD_CODE")]
    BadCode,
}

impl Rup1Error {
    /// The name the spec and the vectors use.
    pub fn code(self) -> &'static str {
        match self {
            Self::NotRup1 => "NOT_RUP1",
            Self::Truncated => "TRUNCATED",
            Self::TooLong => "TOO_LONG",
            Self::BadVersion => "BAD_VERSION",
            Self::UnknownOp => "UNKNOWN_OP",
            Self::TrailingBytes => "TRAILING_BYTES",
            Self::NonzeroReqId => "NONZERO_REQ_ID",
            Self::BadAdvisoryRef => "BAD_ADVISORY_REF",
            Self::BadLogRef => "BAD_LOG_REF",
            Self::TooManyOffers => "TOO_MANY_OFFERS",
            Self::BadSerial => "BAD_SERIAL",
            Self::BadTarget => "BAD_TARGET",
            Self::BadPayloadLen => "BAD_PAYLOAD_LEN",
            Self::DuplicateOffer => "DUPLICATE_OFFER",
            Self::BadRad1Len => "BAD_RAD1_LEN",
            Self::BadManifestLen => "BAD_MANIFEST_LEN",
            Self::BadSnapshotLen => "BAD_SNAPSHOT_LEN",
            Self::BadCount => "BAD_COUNT",
            Self::BadIndex => "BAD_INDEX",
            Self::BadChunkLen => "BAD_CHUNK_LEN",
            Self::BadPathLen => "BAD_PATH_LEN",
            Self::BadCode => "BAD_CODE",
        }
    }
}

// ── Classifiers (spec §5) ───────────────────────────────────────────

/// Does the frame start with the RUP1 magic?
pub fn is_rup1(frame: &[u8]) -> bool {
    frame.len() >= 4 && frame[..4] == *RUP1_MAGIC
}

/// The op of a complete version 1 header.
fn v1_op(frame: &[u8]) -> Option<u8> {
    (is_rup1(frame) && frame.len() >= HEADER_LEN && frame[4] == RUP1_VERSION).then(|| frame[5])
}

/// RUP1 requests expect replies in the same dial (raven-node's dial
/// classifier). HAVE never does.
pub fn frame_expects_reply(frame: &[u8]) -> bool {
    matches!(
        v1_op(frame),
        Some(OP_GET_ADVISORY | OP_GET_LOG | OP_GET_MANIFEST | OP_GET_CHUNKS | OP_GET_ROTATION)
    )
}

/// Terminal RUP1 replies end a request (raven-node's dial classifier).
/// CHUNK never does.
pub fn frame_is_terminal_reply(frame: &[u8]) -> bool {
    matches!(
        v1_op(frame),
        Some(OP_ADVISORY | OP_LOG | OP_MANIFEST | OP_CHUNKS_END | OP_ERROR)
    )
}

// ── Rules shared by encode and decode (spec §3, §4) ─────────────────

fn check_refs(have: &Have) -> Result<(), Rup1Error> {
    if (have.adv_serial == 0) != (have.adv_digest == [0; 32]) {
        return Err(Rup1Error::BadAdvisoryRef);
    }
    if have.log_size as usize > MAX_LOG_ENTRIES
        || (have.log_size == 0) != (have.log_root == [0; 32])
    {
        return Err(Rup1Error::BadLogRef);
    }
    Ok(())
}

fn target_len_ok(len: usize) -> bool {
    (1..=MAX_TARGET_LEN).contains(&len)
}

fn payload_len_ok(len: u64) -> bool {
    (1..=MAX_PAYLOAD_LEN).contains(&len)
}

fn snapshot_len_ok(len: usize) -> bool {
    (1..=MAX_SNAPSHOT_LEN).contains(&len)
}

fn check_offer(offer: &Offer) -> Result<(), Rup1Error> {
    if offer.build_serial == 0 {
        return Err(Rup1Error::BadSerial);
    }
    if !target_len_ok(offer.target.len()) || !target_well_formed(&offer.target) {
        return Err(Rup1Error::BadTarget);
    }
    if !payload_len_ok(offer.payload_len) {
        return Err(Rup1Error::BadPayloadLen);
    }
    Ok(())
}

fn check_chunks_range(first: u32, count: u8) -> Result<(), Rup1Error> {
    if count == 0 || count > MAX_CHUNKS_PER_REQUEST {
        return Err(Rup1Error::BadCount);
    }
    if u64::from(first) + u64::from(count) > MAX_CHUNKS {
        return Err(Rup1Error::BadIndex);
    }
    Ok(())
}

fn check_chunk(chunk: &Chunk) -> Result<(), Rup1Error> {
    if u64::from(chunk.index) >= MAX_CHUNKS {
        return Err(Rup1Error::BadIndex);
    }
    if chunk.bytes.is_empty() || chunk.bytes.len() > CHUNK_SIZE as usize {
        return Err(Rup1Error::BadChunkLen);
    }
    if chunk.path.len() > MAX_CHUNK_PATH_LEN {
        return Err(Rup1Error::BadPathLen);
    }
    Ok(())
}

// ── Encode ──────────────────────────────────────────────────────────

/// The frame of `msg` with request id `req_id` (a HAVE's must be
/// [`NO_REQ_ID`]). Refuses exactly what [`decode`] refuses, so every frame
/// it writes decodes to `msg` again; an ADVISORY whose advisory and snapshot
/// do not fit one frame is `TOO_LONG` (answer ERROR NOT_FOUND instead).
pub fn encode(req_id: &[u8; 4], msg: &Rup1Msg) -> Result<Vec<u8>, Rup1Error> {
    let mut out = Vec::with_capacity(HEADER_LEN + 64);
    out.extend_from_slice(RUP1_MAGIC);
    out.push(RUP1_VERSION);
    out.push(msg.op());
    out.extend_from_slice(req_id);
    match msg {
        Rup1Msg::Have(have) => {
            if *req_id != NO_REQ_ID {
                return Err(Rup1Error::NonzeroReqId);
            }
            check_refs(have)?;
            if have.offers.len() > MAX_OFFERS {
                return Err(Rup1Error::TooManyOffers);
            }
            out.extend_from_slice(&have.adv_serial.to_be_bytes());
            out.extend_from_slice(&have.adv_digest);
            out.extend_from_slice(&have.log_size.to_be_bytes());
            out.extend_from_slice(&have.log_root);
            out.push(have.offers.len() as u8);
            for (i, offer) in have.offers.iter().enumerate() {
                check_offer(offer)?;
                if have.offers[..i]
                    .iter()
                    .any(|o| o.manifest_digest == offer.manifest_digest)
                {
                    return Err(Rup1Error::DuplicateOffer);
                }
                out.extend_from_slice(&offer.build_serial.to_be_bytes());
                out.push(offer.target.len() as u8);
                out.extend_from_slice(offer.target.as_bytes());
                out.extend_from_slice(&offer.manifest_digest);
                out.extend_from_slice(&offer.payload_len.to_be_bytes());
            }
        }
        Rup1Msg::GetAdvisory | Rup1Msg::GetLog => {}
        Rup1Msg::GetManifest { manifest_digest } => out.extend_from_slice(manifest_digest),
        Rup1Msg::GetRotation { key_set_digest } => out.extend_from_slice(key_set_digest),
        Rup1Msg::GetChunks {
            manifest_digest,
            first,
            count,
        } => {
            check_chunks_range(*first, *count)?;
            out.extend_from_slice(manifest_digest);
            out.extend_from_slice(&first.to_be_bytes());
            out.push(*count);
        }
        Rup1Msg::Advisory { rad1, snapshot } => {
            if rad1.is_empty() || rad1.len() > MAX_RAD1_LEN {
                return Err(Rup1Error::BadRad1Len);
            }
            if !snapshot_len_ok(snapshot.len()) {
                return Err(Rup1Error::BadSnapshotLen);
            }
            if HEADER_LEN + 2 + rad1.len() + snapshot.len() > MAX_FRAME_LEN {
                return Err(Rup1Error::TooLong);
            }
            out.extend_from_slice(&(rad1.len() as u16).to_be_bytes());
            out.extend_from_slice(rad1);
            out.extend_from_slice(snapshot);
        }
        Rup1Msg::Log { snapshot } => {
            if !snapshot_len_ok(snapshot.len()) {
                return Err(Rup1Error::BadSnapshotLen);
            }
            out.extend_from_slice(snapshot);
        }
        Rup1Msg::Manifest { manifest, snapshot } => {
            if manifest.is_empty() || manifest.len() > MAX_MANIFEST_LEN {
                return Err(Rup1Error::BadManifestLen);
            }
            if !snapshot_len_ok(snapshot.len()) {
                return Err(Rup1Error::BadSnapshotLen);
            }
            out.extend_from_slice(&(manifest.len() as u16).to_be_bytes());
            out.extend_from_slice(manifest);
            out.extend_from_slice(snapshot);
        }
        Rup1Msg::Chunk(chunk) => {
            check_chunk(chunk)?;
            out.reserve(8 + chunk.bytes.len() + 1 + 32 * chunk.path.len());
            out.extend_from_slice(&chunk.index.to_be_bytes());
            out.extend_from_slice(&(chunk.bytes.len() as u32).to_be_bytes());
            out.extend_from_slice(&chunk.bytes);
            out.push(chunk.path.len() as u8);
            for hash in &chunk.path {
                out.extend_from_slice(hash);
            }
        }
        Rup1Msg::ChunksEnd { stopped, sent } => {
            if *sent > MAX_CHUNKS_PER_REQUEST {
                return Err(Rup1Error::BadCount);
            }
            out.push(stopped.map_or(0, ErrorCode::byte));
            out.push(*sent);
        }
        Rup1Msg::Error(code) => {
            if code.byte() == 0 {
                return Err(Rup1Error::BadCode);
            }
            out.push(code.byte());
        }
    }
    debug_assert!(out.len() <= MAX_FRAME_LEN);
    Ok(out)
}

// ── Decode ──────────────────────────────────────────────────────────

/// Reads fields front to back; nothing is copied until the caller has
/// checked the lengths.
struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Rup1Error> {
        if self.bytes.len() < n {
            return Err(Rup1Error::Truncated);
        }
        let (head, rest) = self.bytes.split_at(n);
        self.bytes = rest;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], Rup1Error> {
        Ok(self.take(N)?.try_into().expect("N bytes"))
    }

    fn u8(&mut self) -> Result<u8, Rup1Error> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, Rup1Error> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, Rup1Error> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, Rup1Error> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn rest(&mut self) -> &'a [u8] {
        std::mem::take(&mut self.bytes)
    }

    fn end(&self) -> Result<(), Rup1Error> {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err(Rup1Error::TrailingBytes)
        }
    }
}

/// The request id and content of one RUP1 frame, strictly (spec §4, in
/// that order): the magic, the frame length (`10..=65,511`), the version,
/// the op, then the op's fields with their caps, and nothing after them.
pub fn decode(frame: &[u8]) -> Result<([u8; 4], Rup1Msg), Rup1Error> {
    if !is_rup1(frame) {
        return Err(Rup1Error::NotRup1);
    }
    if frame.len() < HEADER_LEN {
        return Err(Rup1Error::Truncated);
    }
    if frame.len() > MAX_FRAME_LEN {
        return Err(Rup1Error::TooLong);
    }
    if frame[4] != RUP1_VERSION {
        return Err(Rup1Error::BadVersion);
    }
    let op = frame[5];
    let req_id: [u8; 4] = frame[6..HEADER_LEN].try_into().expect("4 bytes");
    let mut r = Reader {
        bytes: &frame[HEADER_LEN..],
    };
    let msg = match op {
        OP_HAVE => {
            if req_id != NO_REQ_ID {
                return Err(Rup1Error::NonzeroReqId);
            }
            Rup1Msg::Have(decode_have(&mut r)?)
        }
        OP_GET_ADVISORY => Rup1Msg::GetAdvisory,
        OP_GET_LOG => Rup1Msg::GetLog,
        OP_GET_MANIFEST => Rup1Msg::GetManifest {
            manifest_digest: r.array()?,
        },
        OP_GET_ROTATION => Rup1Msg::GetRotation {
            key_set_digest: r.array()?,
        },
        OP_GET_CHUNKS => {
            let manifest_digest = r.array()?;
            let first = r.u32()?;
            let count = r.u8()?;
            check_chunks_range(first, count)?;
            Rup1Msg::GetChunks {
                manifest_digest,
                first,
                count,
            }
        }
        OP_ADVISORY => {
            let n = usize::from(r.u16()?);
            if n == 0 || n > MAX_RAD1_LEN {
                return Err(Rup1Error::BadRad1Len);
            }
            let rad1 = r.take(n)?;
            let snapshot = r.rest();
            if !snapshot_len_ok(snapshot.len()) {
                return Err(Rup1Error::BadSnapshotLen);
            }
            Rup1Msg::Advisory {
                rad1: rad1.to_vec(),
                snapshot: snapshot.to_vec(),
            }
        }
        OP_LOG => {
            let snapshot = r.rest();
            if !snapshot_len_ok(snapshot.len()) {
                return Err(Rup1Error::BadSnapshotLen);
            }
            Rup1Msg::Log {
                snapshot: snapshot.to_vec(),
            }
        }
        OP_MANIFEST => {
            let n = usize::from(r.u16()?);
            if n == 0 || n > MAX_MANIFEST_LEN {
                return Err(Rup1Error::BadManifestLen);
            }
            let manifest = r.take(n)?;
            let snapshot = r.rest();
            if !snapshot_len_ok(snapshot.len()) {
                return Err(Rup1Error::BadSnapshotLen);
            }
            Rup1Msg::Manifest {
                manifest: manifest.to_vec(),
                snapshot: snapshot.to_vec(),
            }
        }
        OP_CHUNK => {
            let index = r.u32()?;
            if u64::from(index) >= MAX_CHUNKS {
                return Err(Rup1Error::BadIndex);
            }
            let len = r.u32()? as usize;
            if len == 0 || len > CHUNK_SIZE as usize {
                return Err(Rup1Error::BadChunkLen);
            }
            let bytes = r.take(len)?;
            let path_len = usize::from(r.u8()?);
            if path_len > MAX_CHUNK_PATH_LEN {
                return Err(Rup1Error::BadPathLen);
            }
            let hashes = r.take(32 * path_len)?;
            r.end()?;
            Rup1Msg::Chunk(Chunk {
                index,
                bytes: bytes.to_vec(),
                path: hashes.as_chunks::<32>().0.to_vec(),
            })
        }
        OP_CHUNKS_END => {
            let code = r.u8()?;
            let sent = r.u8()?;
            if sent > MAX_CHUNKS_PER_REQUEST {
                return Err(Rup1Error::BadCount);
            }
            Rup1Msg::ChunksEnd {
                stopped: ErrorCode::from_byte(code),
                sent,
            }
        }
        OP_ERROR => Rup1Msg::Error(ErrorCode::from_byte(r.u8()?).ok_or(Rup1Error::BadCode)?),
        _ => return Err(Rup1Error::UnknownOp),
    };
    r.end()?;
    Ok((req_id, msg))
}

/// HAVE's body: the references, then each offer, then nothing. Every offer
/// is checked before any is copied.
fn decode_have(r: &mut Reader<'_>) -> Result<Have, Rup1Error> {
    let mut have = Have {
        adv_serial: r.u64()?,
        adv_digest: r.array()?,
        ..Have::default()
    };
    if (have.adv_serial == 0) != (have.adv_digest == [0; 32]) {
        return Err(Rup1Error::BadAdvisoryRef);
    }
    have.log_size = r.u32()?;
    have.log_root = r.array()?;
    check_refs(&have)?;
    let n = usize::from(r.u8()?);
    if n > MAX_OFFERS {
        return Err(Rup1Error::TooManyOffers);
    }
    let mut seen: [(u64, &str, [u8; 32], u64); MAX_OFFERS] = [(0, "", [0; 32], 0); MAX_OFFERS];
    for i in 0..n {
        let build_serial = r.u64()?;
        if build_serial == 0 {
            return Err(Rup1Error::BadSerial);
        }
        let target_len = usize::from(r.u8()?);
        if !target_len_ok(target_len) {
            return Err(Rup1Error::BadTarget);
        }
        let target = std::str::from_utf8(r.take(target_len)?)
            .ok()
            .filter(|t| target_well_formed(t))
            .ok_or(Rup1Error::BadTarget)?;
        let manifest_digest = r.array()?;
        let payload_len = r.u64()?;
        if !payload_len_ok(payload_len) {
            return Err(Rup1Error::BadPayloadLen);
        }
        if seen[..i].iter().any(|o| o.2 == manifest_digest) {
            return Err(Rup1Error::DuplicateOffer);
        }
        seen[i] = (build_serial, target, manifest_digest, payload_len);
    }
    r.end()?;
    have.offers = seen[..n]
        .iter()
        .map(
            |&(build_serial, target, manifest_digest, payload_len)| Offer {
                build_serial,
                target: target.to_owned(),
                manifest_digest,
                payload_len,
            },
        )
        .collect();
    Ok(have)
}

/// What a listener does with a frame from its dialer (spec §6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ListenerDecode {
    /// A request to serve (or refuse with an ERROR of its own choosing).
    Request([u8; 4], Rup1Msg),
    /// The dialer's HAVE.
    Have(Have),
    /// Answer ERROR with this code and request id: UNSUPPORTED for an op or
    /// version this version does not serve, MALFORMED for a known request
    /// that breaks a rule.
    Refuse([u8; 4], ErrorCode),
    /// Answer nothing: not a complete RUP1 header, a reply sent to a
    /// listener, or a HAVE that breaks a rule.
    Drop,
}

/// The listener's reading of a frame (spec §6): it never answers a reply
/// or a HAVE, so two nodes cannot answer each other forever.
pub fn decode_for_listener(frame: &[u8]) -> ListenerDecode {
    if !is_rup1(frame) || frame.len() < HEADER_LEN {
        return ListenerDecode::Drop;
    }
    let req_id: [u8; 4] = frame[6..HEADER_LEN].try_into().expect("4 bytes");
    if frame[4] != RUP1_VERSION {
        return ListenerDecode::Refuse(req_id, ErrorCode::Unsupported);
    }
    match frame[5] {
        OP_HAVE => match decode(frame) {
            Ok((_, Rup1Msg::Have(have))) => ListenerDecode::Have(have),
            _ => ListenerDecode::Drop,
        },
        OP_GET_ADVISORY | OP_GET_LOG | OP_GET_MANIFEST | OP_GET_CHUNKS | OP_GET_ROTATION => {
            match decode(frame) {
                Ok((req_id, msg)) => ListenerDecode::Request(req_id, msg),
                Err(_) => ListenerDecode::Refuse(req_id, ErrorCode::Malformed),
            }
        }
        // A reply op (0x80 and up), well formed or not, is never answered
        // (nor read).
        0x80..=0xFF => ListenerDecode::Drop,
        // An op this version does not define (0x00, 0x07..=0x7F).
        _ => ListenerDecode::Refuse(req_id, ErrorCode::Unsupported),
    }
}

#[cfg(test)]
mod tests;
