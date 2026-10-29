//! Friend custody V1: encrypted store-and-forward through a mutual friend's
//! node (`docs/design/2026-10-friend-custody.md`, revision 2).
//!
//! RFC1 custody frames ride the existing authenticated Raven link (Noise XX,
//! signed bind, RLB1, contact-gated responder). They carry RSO1 Store Object V1
//! records holding the exact sealed envelope. No new port, handshake or crypto.
//!
//! This module holds the codec (§5), the custodian's store and limits (§6.2,
//! §6.3) and the custodian's request handler (§6.1, §6.4, §6.5). Everything is
//! behind [`crate::custody_gate`].
//!
//! **Letters (Phase 5 P5.13, spec §10)**: the ops 0x04 DEPOSIT_LETTER, 0x05
//! FETCH_LETTERS and 0x06 WITHDRAW_LETTERS hold RAL1 letters
//! (`protocol/RAVEN_ASYNC_LETTER_V1.md`) in `custody_letters_v1`, under the
//! same caps and at-rest rules as the objects. They are served only while
//! the letter gate is open ([`crate::horizon::letter_live_enabled`]) and the
//! lab knob [`LAB_BASE_OPS_ONLY`] is off; otherwise they answer UNSUPPORTED,
//! exactly as a listener built before them.
//!
//! **Custody handoff (Phase 5 P5.18, `protocol/RAVEN_CUSTODY_HANDOFF_V1.md`)**:
//! the ops 0x07 HANDOFF (an RHW1 record, [`crate::custody_handoff`]) and 0x08
//! TAGS, answered HANDOFF_RESULT 0x87 and TAGS_RESULT 0x88. They are decoded
//! here and served only while the handoff gate is open
//! ([`crate::custody_gate::handoff_live`]) and [`LAB_BASE_OPS_ONLY`] is off;
//! otherwise they answer UNSUPPORTED, as a listener built before them.
//!
//! **Privacy pack PP.17** (behind the same gate; the spec text is the unsigned
//! `docs/SECURITY_ERRATA_RULE9_CUSTODY_RELEASE_AMENDMENT_DRAFT.md`): RELEASE
//! by the authenticated recipient deletes the object's payload and pair
//! columns and keeps only its digest until expiry, for dedup; in a sealed
//! profile the open rows' digest and parties are keyed and their payload and
//! clear values sealed ([`CustodyStore`]).

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::async_letter::{MAX_RAL1_LEN, MIN_RAL1_LEN};
use crate::at_rest::{self, MetaKeys, Mode, ValueType};
use crate::custody_handoff::{Rhw1, TagsAction, MAX_TAG_ENTRIES};
use crate::envelope::Envelope;
use crate::identity::Identity;
use crate::outbox::OutboxCarrier;
use crate::sqlite_rebuild::{self as rebuild, Migration, RebuildError, RowReseal, Shape, Steps};
use crate::store_object::StoreObject;

// ---------------------------------------------------------------------------
// Wire (§5)
// ---------------------------------------------------------------------------

pub const RFC1_MAGIC: [u8; 4] = *b"RFC1";
pub const RFC1_VERSION: u8 = 1;
pub const RFC1_HEADER_LEN: usize = 14;

pub const OP_DEPOSIT: u8 = 0x01;
pub const OP_FETCH: u8 = 0x02;
pub const OP_RELEASE: u8 = 0x03;
/// The letter ops (§10): answered DEPOSIT_RESULT, LETTER_ITEM x n then
/// FETCH_END, and WITHDRAW_RESULT.
pub const OP_DEPOSIT_LETTER: u8 = 0x04;
pub const OP_FETCH_LETTERS: u8 = 0x05;
pub const OP_WITHDRAW_LETTERS: u8 = 0x06;
/// The handoff ops (`RAVEN_CUSTODY_HANDOFF_V1`): answered HANDOFF_RESULT and
/// TAGS_RESULT, both terminal.
pub const OP_HANDOFF: u8 = 0x07;
pub const OP_TAGS: u8 = 0x08;
pub const OP_DEPOSIT_RESULT: u8 = 0x81;
pub const OP_FETCH_ITEM: u8 = 0x82;
pub const OP_FETCH_END: u8 = 0x83;
pub const OP_RELEASE_RESULT: u8 = 0x84;
/// Non-terminal, like FETCH_ITEM.
pub const OP_LETTER_ITEM: u8 = 0x85;
pub const OP_WITHDRAW_RESULT: u8 = 0x86;
pub const OP_HANDOFF_RESULT: u8 = 0x87;
pub const OP_TAGS_RESULT: u8 = 0x88;
pub const OP_UNSUPPORTED: u8 = 0xFE;

/// The ops a listener serves only while letters are on (§10); a listener
/// with them off answers each `UNSUPPORTED`, as one built before them.
pub fn is_letter_op(op: u8) -> bool {
    matches!(
        op,
        OP_DEPOSIT_LETTER | OP_FETCH_LETTERS | OP_WITHDRAW_LETTERS
    )
}

/// TAGS entries: `(store_tag, expires_at_ms)`, sorted by tag, each tag once.
pub type TagEntries = Vec<([u8; 16], u64)>;

/// The ops a listener serves only while the handoff gate is open; a
/// listener with it closed answers each `UNSUPPORTED`, as one built before
/// them.
pub fn is_handoff_op(op: u8) -> bool {
    matches!(op, OP_HANDOFF | OP_TAGS)
}

/// The frame is an RFC1 v1 HANDOFF request (op 0x07).
pub fn is_handoff_request(frame: &[u8]) -> bool {
    is_rfc1(frame)
        && frame.len() >= RFC1_HEADER_LEN
        && frame[4] == RFC1_VERSION
        && frame[5] == OP_HANDOFF
}

/// DEPOSIT bound; a FETCH_ITEM of it then always fits one transport message.
pub const MAX_RFC1_RSO1: usize = crate::lan_noise::MAX_TRANSPORT_PLAINTEXT - 50;
pub const MAX_RFC1_ENVELOPE: usize = MAX_RFC1_RSO1 - RSO1_FIXED_LEN;
/// RSO1 header without a custody signature.
const RSO1_FIXED_LEN: usize = 59;
pub(crate) const MIN_RFC1_RSO1: usize = RSO1_FIXED_LEN + crate::envelope::PREFIX_LEN;
/// The largest LAN send (text cap + sealed overhead + RVN1 prefix + signature)
/// always fits custody.
const _: () =
    assert!(crate::lan_noise::MAX_LAN_ENDPOINT_TEXT + 26 + 16 + 86 + 64 <= MAX_RFC1_ENVELOPE);

pub const MAX_FETCH_TAGS: usize = 32;
pub const MAX_RELEASE_DIGESTS: usize = 32;
pub const MAX_WITHDRAW_DIGESTS: usize = 32;
/// FETCH_LETTERS: `has_after || after_token[32] || max_items`.
const FETCH_LETTERS_FRAME_LEN: usize = RFC1_HEADER_LEN + 34;
pub const MAX_FETCH_ITEMS: u8 = 16;
/// RSO1 bytes in one FETCH page (at least one object if any matches).
pub const MAX_FETCH_PAGE_BYTES: usize = 128 * 1024;

const PAGE_TOKEN_DOMAIN: &[u8] = b"raven/offline-mailbox/page-token/v1";

/// Custody reply codes (§5 table).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CustodyCode {
    Ok = 0,
    Duplicate = 1,
    PolicyDenied = 2,
    Hold = 3,
    NotVerified = 4,
    RefusedObject = 5,
    Expired = 6,
    StoreFull = 7,
    Quota = 8,
    RateLimited = 9,
    Persistence = 10,
    Malformed = 11,
    RecipientNotAccepted = 12,
    Conflict = 13,
    /// HANDOFF FORWARD: the next hop is not a pinned, unblocked contact of
    /// this custodian, or it is the depositor or the custodian itself.
    NextHopUnknown = 14,
    /// HANDOFF DELIVER: the RSO1 store tag has no live registration.
    TagUnknown = 15,
    /// HANDOFF FORWARD from a link peer that is not the envelope's outer
    /// signer.
    HopRefused = 16,
}

impl CustodyCode {
    /// Unknown codes are handled as PERSISTENCE (transient).
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Ok,
            1 => Self::Duplicate,
            2 => Self::PolicyDenied,
            3 => Self::Hold,
            4 => Self::NotVerified,
            5 => Self::RefusedObject,
            6 => Self::Expired,
            7 => Self::StoreFull,
            8 => Self::Quota,
            9 => Self::RateLimited,
            11 => Self::Malformed,
            12 => Self::RecipientNotAccepted,
            13 => Self::Conflict,
            14 => Self::NextHopUnknown,
            15 => Self::TagUnknown,
            16 => Self::HopRefused,
            _ => Self::Persistence,
        }
    }

    /// The registry string (`protocol/RAVEN_ERROR_CODES_V1.md`).
    pub fn registry(self) -> &'static str {
        match self {
            Self::Ok | Self::Duplicate => "IN_CUSTODY",
            Self::PolicyDenied => "POLICY_DENIED",
            Self::Hold => "CUSTODY_HOLD",
            Self::NotVerified => "CONTACT_NOT_VERIFIED",
            Self::RefusedObject => "CUSTODY_REFUSED",
            Self::Expired => "ENVELOPE_EXPIRED",
            Self::StoreFull => "STORE_FULL",
            Self::Quota => "CUSTODY_QUOTA",
            Self::RateLimited => "RATE_LIMITED",
            Self::Persistence => "CUSTODY_UNAVAILABLE",
            Self::Malformed => "CUSTODY_MALFORMED",
            Self::RecipientNotAccepted => "CUSTODY_RECIPIENT_REFUSED",
            Self::Conflict => "CUSTODY_CONFLICT",
            Self::NextHopUnknown => "CUSTODY_NEXT_HOP_UNKNOWN",
            Self::TagUnknown => "CUSTODY_TAG_UNKNOWN",
            Self::HopRefused => "CUSTODY_HOP_REFUSED",
        }
    }

    /// The object is held by this custodian (STORED or DUPLICATE).
    pub fn held(self) -> bool {
        matches!(self, Self::Ok | Self::Duplicate)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rfc1Request {
    Deposit {
        recipient: [u8; 32],
        rso1: Vec<u8>,
    },
    Fetch {
        tags: Vec<[u8; 16]>,
        after: Option<[u8; 32]>,
        max_items: u8,
    },
    Release {
        digests: Vec<[u8; 32]>,
    },
    /// §10: one RAL1 letter for `recipient`.
    DepositLetter {
        recipient: [u8; 32],
        letter: Vec<u8>,
    },
    /// §10: the link peer's letters, after the cursor.
    FetchLetters {
        after: Option<[u8; 32]>,
        max_items: u8,
    },
    /// §10: letters the link peer deposited, by `letter_digest`.
    WithdrawLetters {
        digests: Vec<[u8; 32]>,
    },
    /// Handoff: one RHW1 record (FORWARD or DELIVER).
    Handoff {
        record: Rhw1,
    },
    /// Handoff: register or withdraw the link peer's store tags, sorted,
    /// each once (repeats merged to their latest expiry).
    Tags {
        action: TagsAction,
        entries: TagEntries,
    },
}

impl Rfc1Request {
    fn op(&self) -> u8 {
        match self {
            Self::Deposit { .. } => OP_DEPOSIT,
            Self::Fetch { .. } => OP_FETCH,
            Self::Release { .. } => OP_RELEASE,
            Self::DepositLetter { .. } => OP_DEPOSIT_LETTER,
            Self::FetchLetters { .. } => OP_FETCH_LETTERS,
            Self::WithdrawLetters { .. } => OP_WITHDRAW_LETTERS,
            Self::Handoff { .. } => OP_HANDOFF,
            Self::Tags { .. } => OP_TAGS,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rfc1Reply {
    DepositResult {
        code: CustodyCode,
        digest: [u8; 32],
    },
    FetchItem {
        rso1: Vec<u8>,
    },
    FetchEnd {
        code: CustodyCode,
        returned: u8,
        next: Option<[u8; 32]>,
    },
    ReleaseResult {
        code: CustodyCode,
        released: u8,
    },
    /// §10, non-terminal: one letter of a FETCH_LETTERS page.
    LetterItem {
        letter: Vec<u8>,
    },
    /// §10: the letters WITHDRAW_LETTERS deleted.
    WithdrawResult {
        code: CustodyCode,
        withdrawn: u8,
    },
    /// Handoff: the answer to a HANDOFF (digest zero if unparsable).
    HandoffResult {
        code: CustodyCode,
        digest: [u8; 32],
    },
    /// Handoff: the answer to TAGS.
    TagsResult {
        code: CustodyCode,
        accepted: u8,
        conflicts: u8,
    },
    Unsupported {
        max_version: u8,
    },
}

impl Rfc1Reply {
    fn op(&self) -> u8 {
        match self {
            Self::DepositResult { .. } => OP_DEPOSIT_RESULT,
            Self::FetchItem { .. } => OP_FETCH_ITEM,
            Self::FetchEnd { .. } => OP_FETCH_END,
            Self::ReleaseResult { .. } => OP_RELEASE_RESULT,
            Self::LetterItem { .. } => OP_LETTER_ITEM,
            Self::WithdrawResult { .. } => OP_WITHDRAW_RESULT,
            Self::HandoffResult { .. } => OP_HANDOFF_RESULT,
            Self::TagsResult { .. } => OP_TAGS_RESULT,
            Self::Unsupported { .. } => OP_UNSUPPORTED,
        }
    }

    /// One terminal reply ends each request.
    pub fn is_terminal(&self) -> bool {
        !matches!(self, Self::FetchItem { .. } | Self::LetterItem { .. })
    }
}

/// What a listener makes of a request frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestDecode {
    Request([u8; 8], Rfc1Request),
    /// Unknown version or op, or a reply op sent as a request.
    Unsupported([u8; 8]),
    /// A known request op whose body breaks the rules: reply MALFORMED.
    Malformed([u8; 8], u8),
}

pub fn is_rfc1(frame: &[u8]) -> bool {
    frame.len() >= 4 && frame[..4] == RFC1_MAGIC
}

/// RFC1 requests expect replies in the same dial (dial classifier).
pub fn frame_expects_reply(frame: &[u8]) -> bool {
    is_rfc1(frame)
        && frame.len() >= RFC1_HEADER_LEN
        && frame[4] == RFC1_VERSION
        && matches!(
            frame[5],
            OP_DEPOSIT
                | OP_FETCH
                | OP_RELEASE
                | OP_DEPOSIT_LETTER
                | OP_FETCH_LETTERS
                | OP_WITHDRAW_LETTERS
                | OP_HANDOFF
                | OP_TAGS
        )
}

/// Terminal RFC1 replies end a request (dial classifier). FETCH_ITEM and
/// LETTER_ITEM never do.
pub fn frame_is_terminal_reply(frame: &[u8]) -> bool {
    is_rfc1(frame)
        && frame.len() >= RFC1_HEADER_LEN
        && matches!(
            frame[5],
            OP_DEPOSIT_RESULT
                | OP_FETCH_END
                | OP_RELEASE_RESULT
                | OP_WITHDRAW_RESULT
                | OP_HANDOFF_RESULT
                | OP_TAGS_RESULT
                | OP_UNSUPPORTED
        )
}

fn header(op: u8, req_id: &[u8; 8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&RFC1_MAGIC);
    out.push(RFC1_VERSION);
    out.push(op);
    out.extend_from_slice(req_id);
    out
}

fn arr<const N: usize>(bytes: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes[..N]);
    out
}

fn be_u32(bytes: &[u8]) -> usize {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize
}

pub fn encode_request(req_id: &[u8; 8], request: &Rfc1Request) -> Vec<u8> {
    let mut out = header(request.op(), req_id);
    match request {
        Rfc1Request::Deposit { recipient, rso1 } => {
            out.extend_from_slice(recipient);
            out.extend_from_slice(&(rso1.len() as u32).to_be_bytes());
            out.extend_from_slice(rso1);
        }
        Rfc1Request::Fetch {
            tags,
            after,
            max_items,
        } => {
            out.push(tags.len() as u8);
            for tag in tags {
                out.extend_from_slice(tag);
            }
            out.push(u8::from(after.is_some()));
            out.extend_from_slice(&after.unwrap_or([0u8; 32]));
            out.push(*max_items);
        }
        Rfc1Request::Release { digests } | Rfc1Request::WithdrawLetters { digests } => {
            out.push(digests.len() as u8);
            for digest in digests {
                out.extend_from_slice(digest);
            }
        }
        Rfc1Request::DepositLetter { recipient, letter } => {
            out.extend_from_slice(recipient);
            out.extend_from_slice(&(letter.len() as u32).to_be_bytes());
            out.extend_from_slice(letter);
        }
        Rfc1Request::FetchLetters { after, max_items } => {
            out.push(u8::from(after.is_some()));
            out.extend_from_slice(&after.unwrap_or([0u8; 32]));
            out.push(*max_items);
        }
        Rfc1Request::Handoff { record } => out.extend_from_slice(&record.encode()),
        Rfc1Request::Tags { action, entries } => {
            out.push(*action as u8);
            out.push(entries.len() as u8);
            for (tag, expires_at_ms) in entries {
                out.extend_from_slice(tag);
                out.extend_from_slice(&expires_at_ms.to_be_bytes());
            }
        }
    }
    out
}

pub fn encode_reply(req_id: &[u8; 8], reply: &Rfc1Reply) -> Vec<u8> {
    let mut out = header(reply.op(), req_id);
    match reply {
        Rfc1Reply::DepositResult { code, digest } | Rfc1Reply::HandoffResult { code, digest } => {
            out.push(*code as u8);
            out.extend_from_slice(digest);
        }
        Rfc1Reply::FetchItem { rso1: bytes } | Rfc1Reply::LetterItem { letter: bytes } => {
            out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            out.extend_from_slice(bytes);
        }
        Rfc1Reply::FetchEnd {
            code,
            returned,
            next,
        } => {
            out.push(*code as u8);
            out.push(*returned);
            out.push(u8::from(next.is_some()));
            out.extend_from_slice(&next.unwrap_or([0u8; 32]));
        }
        Rfc1Reply::ReleaseResult {
            code,
            released: count,
        }
        | Rfc1Reply::WithdrawResult {
            code,
            withdrawn: count,
        } => {
            out.push(*code as u8);
            out.push(*count);
        }
        Rfc1Reply::TagsResult {
            code,
            accepted,
            conflicts,
        } => {
            out.push(*code as u8);
            out.push(*accepted);
            out.push(*conflicts);
        }
        Rfc1Reply::Unsupported { max_version } => out.push(*max_version),
    }
    out
}

/// Strict request decoder (§4, §10, and the handoff spec). `Err`: not RFC1
/// at all (the link closes).
pub fn decode_request(frame: &[u8]) -> Result<RequestDecode, &'static str> {
    if frame.len() < RFC1_HEADER_LEN || !is_rfc1(frame) {
        return Err("RFC1_MALFORMED_HEADER");
    }
    let req_id = arr::<8>(&frame[6..14]);
    let op = frame[5];
    if frame[4] != RFC1_VERSION {
        return Ok(RequestDecode::Unsupported(req_id));
    }
    let body = &frame[RFC1_HEADER_LEN..];
    let malformed = Ok(RequestDecode::Malformed(req_id, op));
    let request = match op {
        OP_DEPOSIT => {
            if body.len() < 36 {
                return malformed;
            }
            let n = be_u32(&body[32..36]);
            if !(MIN_RFC1_RSO1..=MAX_RFC1_RSO1).contains(&n) || frame.len() != 50 + n {
                return malformed;
            }
            Rfc1Request::Deposit {
                recipient: arr::<32>(&body[..32]),
                rso1: body[36..].to_vec(),
            }
        }
        OP_FETCH => {
            if body.is_empty() {
                return malformed;
            }
            let count = body[0] as usize;
            if !(1..=MAX_FETCH_TAGS).contains(&count) || frame.len() != 49 + 16 * count {
                return malformed;
            }
            let mut set = BTreeSet::new();
            for i in 0..count {
                set.insert(arr::<16>(&body[1 + 16 * i..]));
            }
            let Some((after, max_items)) = page_request(&body[1 + 16 * count..]) else {
                return malformed;
            };
            Rfc1Request::Fetch {
                tags: set.into_iter().collect(),
                after,
                max_items,
            }
        }
        OP_RELEASE => {
            let Some(digests) = digest_list(frame, MAX_RELEASE_DIGESTS) else {
                return malformed;
            };
            Rfc1Request::Release { digests }
        }
        OP_DEPOSIT_LETTER => {
            if body.len() < 36 {
                return malformed;
            }
            let n = be_u32(&body[32..36]);
            if !(MIN_RAL1_LEN..=MAX_RAL1_LEN).contains(&n) || frame.len() != 50 + n {
                return malformed;
            }
            Rfc1Request::DepositLetter {
                recipient: arr::<32>(&body[..32]),
                letter: body[36..].to_vec(),
            }
        }
        OP_FETCH_LETTERS => {
            if frame.len() != FETCH_LETTERS_FRAME_LEN {
                return malformed;
            }
            let Some((after, max_items)) = page_request(body) else {
                return malformed;
            };
            Rfc1Request::FetchLetters { after, max_items }
        }
        OP_WITHDRAW_LETTERS => {
            let Some(digests) = digest_list(frame, MAX_WITHDRAW_DIGESTS) else {
                return malformed;
            };
            Rfc1Request::WithdrawLetters { digests }
        }
        OP_HANDOFF => match Rhw1::decode(body) {
            Ok(record) => Rfc1Request::Handoff { record },
            Err(_) => return malformed,
        },
        OP_TAGS => {
            let Some((action, entries)) = tags_body(frame) else {
                return malformed;
            };
            Rfc1Request::Tags { action, entries }
        }
        // An unknown op (0x09-0x7F) or a reply op sent as a request.
        _ => return Ok(RequestDecode::Unsupported(req_id)),
    };
    Ok(RequestDecode::Request(req_id, request))
}

/// TAGS: `action u8 (1 REGISTER, 2 WITHDRAW) || count u8 (1..=32) ||
/// (store_tag[16] || expires_at_ms u64) x count`, the whole frame exact
/// (`16 + 24 count`). REGISTER: every expiry non-zero; WITHDRAW: every
/// expiry zero. Repeated tags merge to their latest expiry, sorted.
fn tags_body(frame: &[u8]) -> Option<(TagsAction, TagEntries)> {
    let body = &frame[RFC1_HEADER_LEN..];
    if body.len() < 2 {
        return None;
    }
    let count = usize::from(body[1]);
    if !(1..=MAX_TAG_ENTRIES).contains(&count) || frame.len() != 16 + 24 * count {
        return None;
    }
    let action = TagsAction::from_u8(body[0])?;
    let mut merged = BTreeMap::new();
    for i in 0..count {
        let entry = &body[2 + 24 * i..2 + 24 * (i + 1)];
        let expires_at_ms = u64::from_be_bytes(arr::<8>(&entry[16..]));
        if (action == TagsAction::Withdraw) != (expires_at_ms == 0) {
            return None;
        }
        let slot = merged.entry(arr::<16>(entry)).or_insert(expires_at_ms);
        *slot = (*slot).max(expires_at_ms);
    }
    Some((action, merged.into_iter().collect()))
}

/// A page request's tail, exactly 34 bytes: `has_after u8 (0|1) ||
/// after_token[32] (all zero iff has_after = 0) || max_items u8 (1..=16)`.
fn page_request(rest: &[u8]) -> Option<(Option<[u8; 32]>, u8)> {
    if rest.len() != 34 {
        return None;
    }
    let token = arr::<32>(&rest[1..33]);
    let after = match rest[0] {
        0 if token == [0u8; 32] => None,
        1 => Some(token),
        _ => return None,
    };
    let max_items = rest[33];
    if max_items == 0 || max_items > MAX_FETCH_ITEMS {
        return None;
    }
    Some((after, max_items))
}

/// `count u8 (1..=max) || digest[32] x count`, the whole frame exact;
/// repeated digests deduplicated.
fn digest_list(frame: &[u8], max: usize) -> Option<Vec<[u8; 32]>> {
    let body = &frame[RFC1_HEADER_LEN..];
    let count = usize::from(*body.first()?);
    if !(1..=max).contains(&count) || frame.len() != 15 + 32 * count {
        return None;
    }
    let mut set = BTreeSet::new();
    for i in 0..count {
        set.insert(arr::<32>(&body[1 + 32 * i..]));
    }
    Some(set.into_iter().collect())
}

/// Strict reply decoder (requester side). Any error fails that request.
pub fn decode_reply(frame: &[u8]) -> Result<([u8; 8], Rfc1Reply), &'static str> {
    if frame.len() < RFC1_HEADER_LEN || !is_rfc1(frame) || frame[4] != RFC1_VERSION {
        return Err("RFC1_BAD_REPLY");
    }
    let req_id = arr::<8>(&frame[6..14]);
    let body = &frame[RFC1_HEADER_LEN..];
    let reply = match frame[5] {
        OP_DEPOSIT_RESULT if body.len() == 33 => Rfc1Reply::DepositResult {
            code: CustodyCode::from_u8(body[0]),
            digest: arr::<32>(&body[1..]),
        },
        OP_FETCH_ITEM if body.len() >= 4 && body.len() == 4 + be_u32(body) => {
            Rfc1Reply::FetchItem {
                rso1: body[4..].to_vec(),
            }
        }
        OP_FETCH_END if body.len() == 35 => {
            let token = arr::<32>(&body[3..]);
            let next = match body[2] {
                0 if token == [0u8; 32] => None,
                1 => Some(token),
                _ => return Err("RFC1_BAD_REPLY"),
            };
            Rfc1Reply::FetchEnd {
                code: CustodyCode::from_u8(body[0]),
                returned: body[1],
                next,
            }
        }
        OP_RELEASE_RESULT if body.len() == 2 => Rfc1Reply::ReleaseResult {
            code: CustodyCode::from_u8(body[0]),
            released: body[1],
        },
        OP_LETTER_ITEM
            if body.len() >= 4
                && body.len() == 4 + be_u32(body)
                && (MIN_RAL1_LEN..=MAX_RAL1_LEN).contains(&(body.len() - 4)) =>
        {
            Rfc1Reply::LetterItem {
                letter: body[4..].to_vec(),
            }
        }
        OP_WITHDRAW_RESULT if body.len() == 2 => Rfc1Reply::WithdrawResult {
            code: CustodyCode::from_u8(body[0]),
            withdrawn: body[1],
        },
        OP_HANDOFF_RESULT if body.len() == 33 => Rfc1Reply::HandoffResult {
            code: CustodyCode::from_u8(body[0]),
            digest: arr::<32>(&body[1..]),
        },
        OP_TAGS_RESULT if body.len() == 3 => Rfc1Reply::TagsResult {
            code: CustodyCode::from_u8(body[0]),
            accepted: body[1],
            conflicts: body[2],
        },
        OP_UNSUPPORTED if body.len() == 1 => Rfc1Reply::Unsupported {
            max_version: body[0],
        },
        _ => return Err("RFC1_BAD_REPLY"),
    };
    Ok((req_id, reply))
}

/// `SHA-256(packed envelope)`: the custody identity of an object
/// (Conformance §2.2 object digest).
pub fn custody_digest(packed_envelope: &[u8]) -> [u8; 32] {
    Sha256::digest(packed_envelope).into()
}

/// Mailbox V1 page token, reused verbatim.
pub fn page_token(rso1: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(PAGE_TOKEN_DOMAIN);
    h.update(rso1);
    h.finalize().into()
}

/// RSO1 inside RFC1 is stricter than Store Object V1 (§5): no custody
/// signature, lifetime equal to the envelope's, bounded envelope.
pub fn check_rfc1_rso1(rso1: &[u8]) -> Result<(StoreObject, Envelope), &'static str> {
    if rso1.len() > MAX_RFC1_RSO1 {
        return Err("RFC1_RSO1_TOO_LARGE");
    }
    let object = StoreObject::unpack(rso1).map_err(|_| "RFC1_RSO1_INVALID")?;
    if object.flags != 0 || object.custody_sig.is_some() {
        return Err("RFC1_RSO1_FLAGS");
    }
    if object.packed_envelope.len() > MAX_RFC1_ENVELOPE {
        return Err("RFC1_RSO1_TOO_LARGE");
    }
    let env = Envelope::unpack(&object.packed_envelope).ok_or("RFC1_RSO1_INVALID")?;
    if object.created_at_ms != env.created_at || object.expires_at_ms != env.expires_at {
        return Err("RFC1_RSO1_LIFETIME");
    }
    Ok((object, env))
}

/// Build the RSO1 a sender deposits for `packed_envelope` under `store_tag`.
pub fn rfc1_rso1(store_tag: [u8; 16], packed_envelope: &[u8]) -> Result<Vec<u8>, String> {
    let env = Envelope::unpack(packed_envelope).ok_or_else(|| "not RVN1".to_string())?;
    let object = StoreObject {
        store_tag,
        message_id: env.message_id,
        created_at_ms: env.created_at,
        expires_at_ms: env.expires_at,
        flags: 0,
        packed_envelope: packed_envelope.to_vec(),
        custody_sig: None,
    };
    let rso1 = object.pack()?;
    check_rfc1_rso1(&rso1).map_err(str::to_string)?;
    Ok(rso1)
}

/// Canonical outbound hop fields of a sender's own envelope (§6.4 step 5):
/// what this build's endpoint sealer always writes.
pub fn canonical_outbound_fields(env: &Envelope) -> bool {
    env.flags == 0
        && env.dest_device_hint == crate::indexed_session_store::OUTBOUND_DEST_DEVICE_HINT
        && env.hop_limit == 8
        && env.replication_budget == 2
        && env.ratchet_header_ciphertext.is_empty()
}

// ---------------------------------------------------------------------------
// Limits (§6.3)
// ---------------------------------------------------------------------------

pub const MAX_NODE_ROWS: i64 = 4_096;
pub const MAX_NODE_BYTES: i64 = 64 * 1024 * 1024;
pub const MAX_DEPOSITOR_ROWS: i64 = 512;
pub const MAX_DEPOSITOR_BYTES: i64 = 16 * 1024 * 1024;
pub const MAX_PAIR_ROWS: i64 = 128;
/// Letters one depositor holds for one recipient (§10; owner decision O5-4).
pub const MAX_PAIR_LETTERS: i64 = 32;
pub const MAX_DEPOSITS_PER_MINUTE: u32 = 120;
pub const MAX_DEPOSITOR_BYTES_PER_MINUTE: i64 = 2 * 1024 * 1024;
pub const MAX_FETCHES_PER_MINUTE: u32 = 30;
const WINDOW_MS: u64 = 60_000;
const PURGE_PER_DEPOSIT: i64 = 64;

pub const CUSTODY_DB_FILE: &str = "friend_custody.sqlite";
/// Schema 2 (privacy pack PP.17): keyed lookups, sealed `meta` and sealed
/// payloads, in a sealed profile.
const SCHEMA_VERSION: i64 = 2;
/// Schema 1: the clear columns (a profile that is not sealed, and every
/// older build).
const CLEAR_VERSION: i64 = 1;
/// This store's row in `raven_schema`.
const STORE: &str = "friend_custody";
const OBJECTS: &str = "custody_objects_v1";
/// The digests their recipient released: kept until the object would have
/// expired, so a replay is still a duplicate (PP.17).
const RELEASED: &str = "custody_released_v1";
/// The keyed column that tells the two shapes apart.
const KEYED_COLUMN: &str = "kh_object_digest";
/// The AAD label of a row's sealed payload (its `meta` uses the table).
const RSO1_LABEL: &str = "custody_objects_v1.rso1";
/// The letters (§10, Phase 5 P5.13): additive in either schema (the version
/// stays), always in the shape of the objects.
const LETTERS: &str = "custody_letters_v1";
/// The keyed column that tells the letters' two shapes apart.
const LETTERS_KEYED_COLUMN: &str = "kh_letter_digest";
/// The AAD label of a letter row's sealed letter (its `meta` uses the
/// table).
const LETTER_LABEL: &str = "custody_letters_v1.letter";

pub(crate) struct Window {
    start_ms: u64,
    count: u32,
}

/// In-memory per-key rate windows (reset on restart: a throttle, not a quota).
pub(crate) fn charge(
    windows: &Mutex<Option<HashMap<[u8; 32], Window>>>,
    key: [u8; 32],
    limit: u32,
    now: u64,
) -> bool {
    let mut guard = windows.lock().unwrap_or_else(|e| e.into_inner());
    let map = guard.get_or_insert_with(HashMap::new);
    if map.len() > 4_096 {
        map.retain(|_, w| now.saturating_sub(w.start_ms) < WINDOW_MS);
    }
    let w = map.entry(key).or_insert(Window {
        start_ms: now,
        count: 0,
    });
    if now.saturating_sub(w.start_ms) >= WINDOW_MS {
        *w = Window {
            start_ms: now,
            count: 0,
        };
    }
    w.count = w.count.saturating_add(1);
    w.count <= limit
}

/// The per-depositor attempt window; the handoff FORWARD charges it too.
pub(crate) static DEPOSIT_WINDOWS: Mutex<Option<HashMap<[u8; 32], Window>>> = Mutex::new(None);
static FETCH_WINDOWS: Mutex<Option<HashMap<[u8; 32], Window>>> = Mutex::new(None);

// ---- Depositor throttle (Phase 6b design A R7, step P6.28) ----

/// Refused objects (REFUSED_OBJECT or MALFORMED) from one depositor within
/// [`DEPOSITOR_BAD_WINDOW_MS`] that throttle its deposits.
pub const DEPOSITOR_BAD_OBJECTS: u32 = 10;
pub const DEPOSITOR_BAD_WINDOW_MS: u64 = 60 * 60 * 1000;
/// How long a throttled depositor's deposits (plain, letters, handoff
/// FORWARDs) are answered RATE_LIMITED.
pub const DEPOSITOR_THROTTLE_MS: u64 = 60 * 60 * 1000;
/// Depositors whose refused objects or throttle are remembered at most.
const MAX_BAD_DEPOSITORS: usize = 4_096;

/// Per depositor, its refused objects in the current window; and the
/// throttled depositors with their end. In memory only (a throttle, not a
/// verdict: a restart forgets it), and only while the responses gate is
/// live.
#[derive(Default)]
struct BadDeposits {
    windows: HashMap<[u8; 32], Window>,
    throttled: HashMap<[u8; 32], u64>,
}

static BAD_DEPOSITS: Mutex<Option<BadDeposits>> = Mutex::new(None);

fn with_bad_deposits<T>(f: impl FnOnce(&mut BadDeposits) -> T) -> T {
    f(BAD_DEPOSITS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get_or_insert_with(BadDeposits::default))
}

/// One object from `depositor` refused at `now_ms` (design A R7): the
/// [`DEPOSITOR_BAD_OBJECTS`]-th within the window throttles its deposits
/// for [`DEPOSITOR_THROTTLE_MS`]. Messaging with that contact is untouched.
fn note_bad_deposit(depositor: &[u8; 32], now_ms: u64) {
    use crate::security_gate::{live, SecGate};
    if !live(SecGate::Responses) {
        return;
    }
    with_bad_deposits(|b| {
        if b.windows.len() >= MAX_BAD_DEPOSITORS {
            b.windows
                .retain(|_, w| now_ms.saturating_sub(w.start_ms) < DEPOSITOR_BAD_WINDOW_MS);
        }
        let w = b.windows.entry(*depositor).or_insert(Window {
            start_ms: now_ms,
            count: 0,
        });
        if now_ms.saturating_sub(w.start_ms) >= DEPOSITOR_BAD_WINDOW_MS {
            *w = Window {
                start_ms: now_ms,
                count: 0,
            };
        }
        w.count = w.count.saturating_add(1);
        if w.count < DEPOSITOR_BAD_OBJECTS {
            return;
        }
        b.windows.remove(depositor);
        if b.throttled.len() >= MAX_BAD_DEPOSITORS {
            b.throttled.retain(|_, until| *until > now_ms);
        }
        b.throttled
            .insert(*depositor, now_ms + DEPOSITOR_THROTTLE_MS);
    });
}

/// Are `depositor`'s deposits answered RATE_LIMITED at `now_ms` (design A
/// R7)? Never while the responses gate is shut.
pub fn depositor_throttled(depositor: &[u8; 32], now_ms: u64) -> bool {
    use crate::security_gate::{live, SecGate};
    live(SecGate::Responses)
        && with_bad_deposits(|b| b.throttled.get(depositor).is_some_and(|t| *t > now_ms))
}

// ---------------------------------------------------------------------------
// Custodian store (§6.2)
// ---------------------------------------------------------------------------

pub fn custody_db_path(data_dir: &Path) -> PathBuf {
    data_dir.join(CUSTODY_DB_FILE)
}

/// Schema 1 exactly as every build before PP.17 creates it (and this one in
/// a profile that is not sealed), plus the released digests: a table older
/// builds never read, so the version stays 1.
const CLEAR_SCHEMA: &str = "PRAGMA auto_vacuum=INCREMENTAL;
     PRAGMA journal_mode=WAL;
     PRAGMA synchronous=FULL;
     CREATE TABLE IF NOT EXISTS custody_objects_v1 (
       object_digest  BLOB PRIMARY KEY NOT NULL CHECK(length(object_digest)=32),
       recipient      BLOB NOT NULL CHECK(length(recipient)=32),
       depositor      BLOB NOT NULL CHECK(length(depositor)=32),
       store_tag      BLOB NOT NULL CHECK(length(store_tag)=16),
       page_token     BLOB NOT NULL CHECK(length(page_token)=32),
       rso1           BLOB NOT NULL,
       bytes          INTEGER NOT NULL,
       admitted_at_ms INTEGER NOT NULL,
       expires_at_ms  INTEGER NOT NULL,
       released_at_ms INTEGER
     );
     CREATE INDEX IF NOT EXISTS idx_custody_fetch ON custody_objects_v1(recipient, page_token);
     CREATE INDEX IF NOT EXISTS idx_custody_pair  ON custody_objects_v1(depositor, recipient);
     CREATE INDEX IF NOT EXISTS idx_custody_exp   ON custody_objects_v1(expires_at_ms);
     CREATE TABLE IF NOT EXISTS custody_released_v1 (
       object_digest    BLOB PRIMARY KEY NOT NULL CHECK(length(object_digest)=32),
       prune_after_hour INTEGER NOT NULL
     );
     PRAGMA user_version = 1;";

/// `custody_objects_v1` named `name`, in either shape. Schema 2 keys the
/// digest and both parties, seals the payload whole (its clear header names
/// devices) and keeps the clear values and both times in `meta`; the tag
/// and the page token a fetch names on the wire, the size (the quota) and
/// the expiry hour (the prune) stay clear.
fn objects_table(name: &str, keyed: bool) -> String {
    if keyed {
        format!(
            "CREATE TABLE {name} (
               kh_object_digest BLOB PRIMARY KEY NOT NULL CHECK(length(kh_object_digest)=32),
               kh_recipient     BLOB NOT NULL CHECK(length(kh_recipient)=32),
               kh_depositor     BLOB NOT NULL CHECK(length(kh_depositor)=32),
               store_tag        BLOB NOT NULL CHECK(length(store_tag)=16),
               page_token       BLOB NOT NULL CHECK(length(page_token)=32),
               rso1             BLOB NOT NULL,
               bytes            INTEGER NOT NULL,
               meta             BLOB NOT NULL,
               prune_after_hour INTEGER NOT NULL);"
        )
    } else {
        format!(
            "CREATE TABLE {name} (
               object_digest  BLOB PRIMARY KEY NOT NULL CHECK(length(object_digest)=32),
               recipient      BLOB NOT NULL CHECK(length(recipient)=32),
               depositor      BLOB NOT NULL CHECK(length(depositor)=32),
               store_tag      BLOB NOT NULL CHECK(length(store_tag)=16),
               page_token     BLOB NOT NULL CHECK(length(page_token)=32),
               rso1           BLOB NOT NULL,
               bytes          INTEGER NOT NULL,
               admitted_at_ms INTEGER NOT NULL,
               expires_at_ms  INTEGER NOT NULL,
               released_at_ms INTEGER
             );"
        )
    }
}

/// The released digests named `name`: the digest (keyed in schema 2) and
/// the hour the object would have expired in, nothing else.
fn released_table(name: &str, keyed: bool) -> String {
    let digest = if keyed {
        "kh_object_digest"
    } else {
        "object_digest"
    };
    format!(
        "CREATE TABLE {name} (
           {digest}         BLOB PRIMARY KEY NOT NULL CHECK(length({digest})=32),
           prune_after_hour INTEGER NOT NULL);"
    )
}

/// The three indexes under the names every build uses, so an older build's
/// `CREATE INDEX IF NOT EXISTS` is a no-op on a migrated store.
fn object_indexes(keyed: bool) -> &'static str {
    if keyed {
        "CREATE INDEX idx_custody_fetch ON custody_objects_v1(kh_recipient, page_token);
         CREATE INDEX idx_custody_pair  ON custody_objects_v1(kh_depositor, kh_recipient);
         CREATE INDEX idx_custody_exp   ON custody_objects_v1(prune_after_hour);"
    } else {
        "CREATE INDEX idx_custody_fetch ON custody_objects_v1(recipient, page_token);
         CREATE INDEX idx_custody_pair  ON custody_objects_v1(depositor, recipient);
         CREATE INDEX idx_custody_exp   ON custody_objects_v1(expires_at_ms);"
    }
}

/// `custody_letters_v1` named `name`, in either shape (§10): schema 1 with
/// clear columns, schema 2 like the objects (keyed digest and parties, the
/// letter sealed whole, the clear values and both times in `meta`; the page
/// token a fetch names on the wire, the size and the expiry hour clear).
/// Nothing is released in place: a RELEASE or WITHDRAW deletes the row.
fn letters_table(name: &str, keyed: bool) -> String {
    if keyed {
        format!(
            "CREATE TABLE {name} (
               kh_letter_digest BLOB PRIMARY KEY NOT NULL CHECK(length(kh_letter_digest)=32),
               kh_recipient     BLOB NOT NULL CHECK(length(kh_recipient)=32),
               kh_depositor     BLOB NOT NULL CHECK(length(kh_depositor)=32),
               page_token       BLOB NOT NULL CHECK(length(page_token)=32),
               letter           BLOB NOT NULL,
               bytes            INTEGER NOT NULL,
               meta             BLOB NOT NULL,
               prune_after_hour INTEGER NOT NULL);"
        )
    } else {
        format!(
            "CREATE TABLE {name} (
               letter_digest  BLOB PRIMARY KEY NOT NULL CHECK(length(letter_digest)=32),
               recipient      BLOB NOT NULL CHECK(length(recipient)=32),
               depositor      BLOB NOT NULL CHECK(length(depositor)=32),
               page_token     BLOB NOT NULL CHECK(length(page_token)=32),
               letter         BLOB NOT NULL,
               bytes          INTEGER NOT NULL,
               admitted_at_ms INTEGER NOT NULL,
               expires_at_ms  INTEGER NOT NULL);"
        )
    }
}

/// The letters' three indexes, as the objects' (their own names).
fn letter_indexes(keyed: bool) -> &'static str {
    if keyed {
        "CREATE INDEX IF NOT EXISTS idx_custody_letters_fetch
           ON custody_letters_v1(kh_recipient, page_token);
         CREATE INDEX IF NOT EXISTS idx_custody_letters_pair
           ON custody_letters_v1(kh_depositor, kh_recipient);
         CREATE INDEX IF NOT EXISTS idx_custody_letters_exp
           ON custody_letters_v1(prune_after_hour);"
    } else {
        "CREATE INDEX IF NOT EXISTS idx_custody_letters_fetch
           ON custody_letters_v1(recipient, page_token);
         CREATE INDEX IF NOT EXISTS idx_custody_letters_pair
           ON custody_letters_v1(depositor, recipient);
         CREATE INDEX IF NOT EXISTS idx_custody_letters_exp
           ON custody_letters_v1(expires_at_ms);"
    }
}

fn create_letters(conn: &Connection, keyed: bool) -> rusqlite::Result<()> {
    conn.execute_batch(&letters_table(LETTERS, keyed))?;
    conn.execute_batch(letter_indexes(keyed))
}

/// The letters table in the shape of the store's objects, at every open
/// (§10). The common case reads one shape and changes nothing. Otherwise,
/// in one IMMEDIATE transaction that reads both shapes again (review C-2):
/// a missing table is created; a keyed one in a clear store (an older build
/// of the pack unsealed the store without knowing the letters; nothing here
/// may open its rows) is dropped and created clear, only while the objects
/// are clear; a clear one in a keyed store (an older build of the pack
/// sealed it without knowing the letters) moves forward with the keys.
/// `false`: the objects' shape is no longer `layout` (another opener moved
/// the store since this one read it), nothing is changed and the open reads
/// the store again.
fn ensure_letters(
    conn: &mut Connection,
    layout: Layout,
    keys: Option<&MetaKeys>,
) -> Result<bool, String> {
    let want = match layout {
        Layout::Clear => Shape::Clear,
        Layout::Keyed => Shape::Keyed,
    };
    if rebuild::shape(conn, LETTERS, LETTERS_KEYED_COLUMN).map_err(text)? == want {
        return Ok(true);
    }
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(text)?;
    let _in_tx = crate::paths::HeldMark::transaction();
    if rebuild::shape(&tx, OBJECTS, KEYED_COLUMN).map_err(text)? != want {
        tx.commit().map_err(text)?;
        return Ok(false);
    }
    match rebuild::shape(&tx, LETTERS, LETTERS_KEYED_COLUMN).map_err(text)? {
        have if have == want => {}
        Shape::Missing => create_letters(&tx, want == Shape::Keyed).map_err(text)?,
        Shape::Keyed => {
            tx.execute_batch(&format!("DROP TABLE {LETTERS};"))
                .map_err(text)?;
            create_letters(&tx, false).map_err(text)?;
        }
        Shape::Clear => {
            let keys = keys.ok_or("friend custody store: a keyed store opened without its keys")?;
            letters_forward(&tx, keys, &mut Steps::default())
                .map_err(|e| format!("{CUSTODY_DB_FILE}: {e}"))?;
        }
    }
    tx.commit().map_err(text)?;
    Ok(true)
}

// ── Sealed values (PP.17) ────────────────────────────────────────────────

/// A schema-2 row's clear values (byte values as hex).
#[derive(Serialize, Deserialize)]
struct ObjectMeta {
    object_digest: String,
    recipient: String,
    depositor: String,
    admitted_at_ms: u64,
    expires_at_ms: u64,
}

fn kh_digest(keys: &MetaKeys, digest: &[u8]) -> [u8; 32] {
    at_rest::index(keys, ValueType::ObjectDigest, digest)
}

fn kh_device(keys: &MetaKeys, device: &[u8]) -> [u8; 32] {
    at_rest::index(keys, ValueType::DeviceKey, device)
}

fn seal_meta(keys: &MetaKeys, kd: &[u8], meta: &ObjectMeta) -> Vec<u8> {
    seal_meta_in(keys, OBJECTS, kd, meta)
}

/// A row's `meta` sealed for `table` (the objects', or a letter row's, whose
/// `object_digest` is the letter digest).
fn seal_meta_in(keys: &MetaKeys, table: &str, kd: &[u8], meta: &ObjectMeta) -> Vec<u8> {
    let plain =
        zeroize::Zeroizing::new(serde_json::to_vec(meta).expect("strings and numbers serialize"));
    at_rest::seal_row(keys, table, kd, &plain)
}

/// A schema-2 row's `meta`, or `None` when it does not open here.
fn open_meta(keys: &MetaKeys, kd: &[u8], blob: &[u8]) -> Option<ObjectMeta> {
    open_meta_in(keys, OBJECTS, kd, blob)
}

/// [`open_meta`] of a row of `table`.
fn open_meta_in(keys: &MetaKeys, table: &str, kd: &[u8], blob: &[u8]) -> Option<ObjectMeta> {
    let plain = at_rest::open_row(keys, table, kd, blob).ok()?;
    serde_json::from_slice(&plain).ok()
}

fn unhex32(text: &str) -> Option<[u8; 32]> {
    hex::decode(text).ok()?.try_into().ok()
}

/// The at-rest keys this process loaded (never a keystore call).
fn cached_keys(data_dir: &Path) -> Result<Arc<MetaKeys>, String> {
    at_rest::keys_cached(data_dir).map_err(|e| format!("friend custody store: {e}"))
}

/// A schema-2 row's exact expiry decides the hour that may not have passed
/// yet (`prune_after_hour == hour(now) + 1`); a `meta` that does not open
/// goes by its hour alone (live: the conservative answer).
fn live_by_meta(meta: Option<&ObjectMeta>, now_ms: u64) -> bool {
    meta.is_none_or(|meta| meta.expires_at_ms > now_ms)
}

/// Which schema the open store is at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Layout {
    /// Schema 1: clear columns.
    Clear,
    /// Schema 2: keyed lookups, sealed `meta` and payloads.
    Keyed,
}

/// Carol's custody store: `<data_dir>/friend_custody.sqlite`.
///
/// **At rest (privacy pack PP.17; docs/design/2026-10-at-rest-metadata.md
/// section 7.4).** In a sealed profile the store is at schema 2: the object
/// digest, the recipient and the depositor are keyed lookups
/// (`kh_object_digest`, `kh_recipient`, `kh_depositor`), the payload is
/// sealed whole and the clear values and both times are in each row's
/// sealed `meta`; only the store tag and the page token (named on the
/// wire), the size (the quota) and `prune_after_hour` stay clear. A profile
/// that is not sealed keeps schema 1. A clear store in a sealed profile
/// moves to schema 2 with the rebuild recipe of [`crate::sqlite_rebuild`]
/// (from `privacy::migrate_all`, the prune passes and the open); [`unseal`]
/// is the way back. A handle takes the keys this process holds when it
/// opens (one `at_rest::keys_cached`); without them a sealed profile's
/// store does not open, never a clear fallback.
///
/// **RELEASE deletes (PP.17).** The authenticated recipient's RELEASE
/// deletes the object's row (its payload and both parties, its size and
/// times) in the same transaction that keeps its digest and expiry hour in
/// `custody_released_v1`, so a replay is still a duplicate until the
/// object would have expired, and nothing else of it is left.
pub struct CustodyStore {
    conn: Connection,
    layout: Layout,
    /// A schema-2 store's keys (`None`: schema 1).
    keys: Option<Arc<MetaKeys>>,
}

/// One FETCH page.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct FetchPage {
    pub items: Vec<Vec<u8>>,
    pub next: Option<[u8; 32]>,
}

fn ms(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// What the deposit caps count (live objects only).
#[derive(Debug, Default)]
struct Counts {
    node_rows: i64,
    node_bytes: i64,
    depositor_rows: i64,
    depositor_bytes: i64,
    /// The depositor's bytes admitted in the last minute.
    recent: i64,
    pair_rows: i64,
    /// The depositor's letters for the recipient (§10).
    pair_letters: i64,
}

impl Counts {
    /// Objects and letters together: the node, depositor and byte caps
    /// count both; each keeps its own pair cap.
    fn with_letters(self, letters: Counts) -> Self {
        Self {
            node_rows: self.node_rows + letters.node_rows,
            node_bytes: self.node_bytes + letters.node_bytes,
            depositor_rows: self.depositor_rows + letters.depositor_rows,
            depositor_bytes: self.depositor_bytes + letters.depositor_bytes,
            recent: self.recent + letters.recent,
            pair_rows: self.pair_rows,
            pair_letters: letters.pair_rows,
        }
    }
}

fn text(e: impl std::fmt::Display) -> String {
    e.to_string()
}

impl CustodyStore {
    /// Open an existing store; `Ok(None)` when there is no file (FETCH and
    /// RELEASE then answer empty, and nothing is created).
    pub fn open_existing(data_dir: &Path) -> Result<Option<Self>, String> {
        let path = custody_db_path(data_dir);
        if !path.exists() {
            return Ok(None);
        }
        Self::open_at(data_dir, &path).map(|(store, _)| Some(store))
    }

    /// Open, creating the store (first admitted DEPOSIT).
    pub fn open_or_create(data_dir: &Path) -> Result<Self, String> {
        Self::open_at(data_dir, &custody_db_path(data_dir)).map(|(store, _)| store)
    }

    /// Open the store at `path`, bringing it to the schema the profile's mode
    /// asks for: schema 2 in a sealed profile (created so, or migrated from a
    /// clear store, then `true`), schema 1 otherwise. A schema-2 store opens
    /// only with the keys loaded, whatever the mode. Too little free disk
    /// space to migrate leaves a clear store as it is until a later pass.
    fn open_at(data_dir: &Path, path: &Path) -> Result<(Self, bool), String> {
        let sealed = crate::privacy::mode(data_dir) == Mode::Sealed;
        // Before anything is created: no key, no store (never a clear one).
        if sealed {
            cached_keys(data_dir)?;
        }
        let mut conn = crate::paths::open_private_data_dir_sqlite(path).map_err(text)?;
        conn.busy_timeout(std::time::Duration::from_secs(10))
            .map_err(text)?;
        // An expired, released or purged object is overwritten, not left in
        // the file (PP.2).
        crate::paths::harden_sqlite(&conn).map_err(text)?;
        let mut migrated = false;
        // Three rounds at most: create or migrate, then open what is there
        // (a racing creator may leave either shape).
        for _ in 0..3 {
            let version = rebuild::user_version(&conn).map_err(text)?;
            let recorded = rebuild::recorded(&conn, STORE)
                .map_err(text)?
                .map(|(version, _)| version);
            if version > SCHEMA_VERSION || recorded.is_some_and(|v| v > SCHEMA_VERSION) {
                return Err("friend custody store is newer than this build".into());
            }
            let (layout, keys) = match rebuild::shape(&conn, OBJECTS, KEYED_COLUMN).map_err(text)? {
                Shape::Keyed => {
                    let keys = cached_keys(data_dir)?;
                    // Stamped again where an older process stamped its own
                    // number after its CREATE batch (review R06): never
                    // migrated twice.
                    if version != SCHEMA_VERSION || recorded != Some(SCHEMA_VERSION) {
                        rebuild::restamp(&mut conn, STORE, SCHEMA_VERSION).map_err(text)?;
                    }
                    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")
                        .map_err(text)?;
                    (Layout::Keyed, Some(keys))
                }
                Shape::Missing if sealed => {
                    create_keyed(&mut conn)?;
                    continue;
                }
                Shape::Clear if sealed => {
                    let keys = cached_keys(data_dir)?;
                    match migrate_forward(path, &keys, &crate::disk_space::free_bytes) {
                        Ok(done) => {
                            migrated |= !done.already;
                            continue;
                        }
                        // Deferred: the store keeps working as it is, and
                        // the next pass (or open) tries again.
                        Err(RebuildError::NoSpace { .. }) => {
                            conn.execute_batch(CLEAR_SCHEMA).map_err(text)?;
                            (Layout::Clear, None)
                        }
                        Err(e) => return Err(format!("{CUSTODY_DB_FILE}: {e}")),
                    }
                }
                Shape::Missing | Shape::Clear => {
                    conn.execute_batch(CLEAR_SCHEMA).map_err(text)?;
                    (Layout::Clear, None)
                }
            };
            if !ensure_letters(&mut conn, layout, keys.as_deref())? {
                continue;
            }
            return Ok((Self { conn, layout, keys }, migrated));
        }
        Err("friend_custody.sqlite changed shape while it was opened; try again".into())
    }

    /// `(digest, recipient, depositor)` column names.
    fn cols(&self) -> (&'static str, &'static str, &'static str) {
        match self.layout {
            Layout::Clear => ("object_digest", "recipient", "depositor"),
            Layout::Keyed => ("kh_object_digest", "kh_recipient", "kh_depositor"),
        }
    }

    /// The letters' `(digest, recipient, depositor)` column names.
    fn letter_cols(&self) -> (&'static str, &'static str, &'static str) {
        match self.layout {
            Layout::Clear => ("letter_digest", "recipient", "depositor"),
            Layout::Keyed => (LETTERS_KEYED_COLUMN, "kh_recipient", "kh_depositor"),
        }
    }

    /// What the digest column holds for `digest`.
    fn digest_value(&self, digest: &[u8; 32]) -> Vec<u8> {
        self.keys
            .as_deref()
            .map_or_else(|| digest.to_vec(), |keys| kh_digest(keys, digest).to_vec())
    }

    /// What a party column (recipient, depositor) holds for `device`.
    fn device_value(&self, device: &[u8; 32]) -> Vec<u8> {
        self.keys
            .as_deref()
            .map_or_else(|| device.to_vec(), |keys| kh_device(keys, device).to_vec())
    }

    /// Store one admitted object (§6.4 step 8). Reply code.
    #[allow(clippy::too_many_arguments)]
    pub fn deposit(
        &mut self,
        digest: &[u8; 32],
        recipient: &[u8; 32],
        depositor: &[u8; 32],
        store_tag: &[u8; 16],
        rso1: &[u8],
        expires_at_ms: u64,
        now_ms: u64,
    ) -> Result<CustodyCode, String> {
        let (digest_col, recipient_col, _) = self.cols();
        let (digest_key, recipient_key, depositor_key) = (
            self.digest_value(digest),
            self.device_value(recipient),
            self.device_value(depositor),
        );
        let layout = self.layout;
        let keys = self.keys.clone();
        // Sealed before the write transaction (no keystore call either way).
        let sealed = keys.as_deref().map(|keys| {
            let meta = ObjectMeta {
                object_digest: hex::encode(digest),
                recipient: hex::encode(recipient),
                depositor: hex::encode(depositor),
                admitted_at_ms: now_ms,
                expires_at_ms,
            };
            (
                seal_meta(keys, &digest_key, &meta),
                at_rest::seal_row(keys, RSO1_LABEL, &digest_key, rso1),
            )
        });
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(text)?;
        let _in_tx = crate::paths::HeldMark::transaction();
        purge_some_expired(&tx, layout, now_ms)?;
        let existing: Option<(Vec<u8>, Vec<u8>)> = tx
            .query_row(
                &format!(
                    "SELECT store_tag, {recipient_col} FROM custody_objects_v1
                     WHERE {digest_col} = ?1"
                ),
                params![digest_key],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(text)?;
        if let Some((tag, held_for)) = existing {
            tx.commit().map_err(text)?;
            return Ok(
                if tag.as_slice() == store_tag.as_slice() && held_for == recipient_key {
                    CustodyCode::Duplicate
                } else {
                    eprintln!("raven-node custody: deposit refused (CUSTODY_CONFLICT)");
                    CustodyCode::Conflict
                },
            );
        }
        // Released by its recipient: still a duplicate until it would have
        // expired, never stored again (PP.17).
        let released: Option<i64> = tx
            .query_row(
                &format!("SELECT 1 FROM custody_released_v1 WHERE {digest_col} = ?1"),
                params![digest_key],
                |row| row.get(0),
            )
            .optional()
            .map_err(text)?;
        if released.is_some() {
            tx.commit().map_err(text)?;
            return Ok(CustodyCode::Duplicate);
        }
        let bytes = rso1.len() as i64;
        let counts = match keys.as_deref() {
            None => clear_counts(&tx, recipient, depositor, now_ms)?,
            Some(keys) => keyed_counts(&tx, keys, &recipient_key, &depositor_key, now_ms)?,
        };
        if let Some(code) = cap_refusal(&counts, bytes, counts.pair_rows >= MAX_PAIR_ROWS) {
            // Keep the expiry purge above: a refusal must not roll it back.
            tx.commit().map_err(text)?;
            return Ok(code);
        }
        match sealed {
            None => tx.execute(
                "INSERT INTO custody_objects_v1
                   (object_digest, recipient, depositor, store_tag, page_token, rso1, bytes,
                    admitted_at_ms, expires_at_ms, released_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL)",
                params![
                    digest.as_slice(),
                    recipient.as_slice(),
                    depositor.as_slice(),
                    store_tag.as_slice(),
                    page_token(rso1).as_slice(),
                    rso1,
                    bytes,
                    ms(now_ms),
                    ms(expires_at_ms),
                ],
            ),
            Some((meta, sealed_rso1)) => tx.execute(
                "INSERT INTO custody_objects_v1
                   (kh_object_digest, kh_recipient, kh_depositor, store_tag, page_token, rso1,
                    bytes, meta, prune_after_hour)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    digest_key,
                    recipient_key,
                    depositor_key,
                    store_tag.as_slice(),
                    page_token(rso1).as_slice(),
                    sealed_rso1,
                    bytes,
                    meta,
                    rebuild::prune_after_hour(expires_at_ms),
                ],
            ),
        }
        .map_err(text)?;
        tx.commit().map_err(text)?;
        Ok(CustodyCode::Ok)
    }

    /// One page of `recipient`'s unreleased, unexpired objects under `tags`,
    /// after `after`, in page-token order (§6.5). Read-only.
    pub fn fetch(
        &self,
        recipient: &[u8; 32],
        tags: &[[u8; 16]],
        after: Option<[u8; 32]>,
        max_items: u8,
        now_ms: u64,
    ) -> Result<FetchPage, String> {
        if tags.is_empty() {
            return Ok(FetchPage::default());
        }
        let placeholders = (0..tags.len())
            .map(|i| format!("?{}", i + 5))
            .collect::<Vec<_>>()
            .join(",");
        let keys = self.keys.as_deref();
        let hour = rebuild::hour_of(now_ms);
        // Schema 2: the rows whose hour has not passed, each payload opened
        // here; the hour that may not have passed yet is decided by each
        // row's exact expiry. No SQL limit: the page stops reading where it
        // is full.
        let sql = match keys {
            None => format!(
                "SELECT rso1, page_token, NULL, NULL, NULL FROM custody_objects_v1
                 WHERE recipient = ?1 AND released_at_ms IS NULL AND expires_at_ms > ?2
                   AND (?3 = 0 OR page_token > ?4) AND store_tag IN ({placeholders})
                 ORDER BY page_token LIMIT 17"
            ),
            Some(_) => format!(
                "SELECT rso1, page_token, kh_object_digest, meta, prune_after_hour
                 FROM custody_objects_v1
                 WHERE kh_recipient = ?1 AND prune_after_hour > ?2
                   AND (?3 = 0 OR page_token > ?4) AND store_tag IN ({placeholders})
                 ORDER BY page_token"
            ),
        };
        let mut values: Vec<Box<dyn rusqlite::ToSql>> = vec![
            Box::new(self.device_value(recipient)),
            Box::new(if keys.is_some() { hour } else { ms(now_ms) }),
            Box::new(i64::from(after.is_some())),
            Box::new(after.unwrap_or([0u8; 32]).to_vec()),
        ];
        for tag in tags {
            values.push(Box::new(tag.to_vec()));
        }
        self.read_page(&sql, &values, (OBJECTS, RSO1_LABEL), max_items, now_ms)
    }

    /// One page from `sql` (its rows: the stored payload, the page token,
    /// and in schema 2 the keyed digest, `meta` and the hour), in its order:
    /// at most `max_items` (<= 16) and [`MAX_FETCH_PAGE_BYTES`], at least one
    /// if any. `labels` are the table (its `meta`) and the payload's AAD
    /// label; a schema-2 payload that does not open here is never served.
    fn read_page(
        &self,
        sql: &str,
        values: &[Box<dyn rusqlite::ToSql>],
        (table, payload_label): (&str, &str),
        max_items: u8,
        now_ms: u64,
    ) -> Result<FetchPage, String> {
        let keys = self.keys.as_deref();
        let hour = rebuild::hour_of(now_ms);
        let mut stmt = self.conn.prepare(sql).map_err(text)?;
        type Row = (
            Vec<u8>,
            Vec<u8>,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
            Option<i64>,
        );
        let rows = stmt
            .query_map(rusqlite::params_from_iter(values.iter()), |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })
            .map_err(text)?;
        let limit = usize::from(max_items.clamp(1, MAX_FETCH_ITEMS));
        let mut page = FetchPage::default();
        let mut bytes = 0usize;
        let mut last = None;
        let mut more = false;
        for row in rows {
            let (stored, token, kd, meta, row_hour): Row = row.map_err(text)?;
            let payload = match (keys, kd, meta) {
                (Some(keys), Some(kd), Some(meta)) => {
                    if row_hour == Some(hour + 1)
                        && !open_meta_in(keys, table, &kd, &meta)
                            .is_some_and(|meta| meta.expires_at_ms > now_ms)
                    {
                        continue;
                    }
                    match at_rest::open_row(keys, payload_label, &kd, &stored) {
                        Ok(plain) => plain.to_vec(),
                        Err(_) => continue,
                    }
                }
                _ => stored,
            };
            let full = page.items.len() >= limit
                || (!page.items.is_empty() && bytes + payload.len() > MAX_FETCH_PAGE_BYTES);
            if full {
                more = true;
                break;
            }
            bytes += payload.len();
            last = Some(arr::<32>(&token));
            page.items.push(payload);
        }
        page.next = if more { last } else { None };
        Ok(page)
    }

    /// Store one admitted letter (§10): the caps count it with the objects
    /// (node, depositor, byte rate) and against [`MAX_PAIR_LETTERS`], in one
    /// IMMEDIATE transaction with the expiry purge. The same digest again,
    /// held or released, is a duplicate. Reply code.
    pub fn deposit_letter(
        &mut self,
        digest: &[u8; 32],
        recipient: &[u8; 32],
        depositor: &[u8; 32],
        letter: &[u8],
        expires_at_ms: u64,
        now_ms: u64,
    ) -> Result<CustodyCode, String> {
        let (digest_col, ..) = self.letter_cols();
        let released_col = self.cols().0;
        let (digest_key, recipient_key, depositor_key) = (
            self.digest_value(digest),
            self.device_value(recipient),
            self.device_value(depositor),
        );
        let layout = self.layout;
        let keys = self.keys.clone();
        // Sealed before the write transaction (no keystore call either way).
        let sealed = keys.as_deref().map(|keys| {
            let meta = ObjectMeta {
                object_digest: hex::encode(digest),
                recipient: hex::encode(recipient),
                depositor: hex::encode(depositor),
                admitted_at_ms: now_ms,
                expires_at_ms,
            };
            (
                seal_meta_in(keys, LETTERS, &digest_key, &meta),
                at_rest::seal_row(keys, LETTER_LABEL, &digest_key, letter),
            )
        });
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(text)?;
        let _in_tx = crate::paths::HeldMark::transaction();
        purge_some_expired(&tx, layout, now_ms)?;
        // The digest names the bytes, recipient and depositor included.
        let held: Option<i64> = tx
            .query_row(
                &format!("SELECT 1 FROM custody_letters_v1 WHERE {digest_col} = ?1"),
                params![digest_key],
                |row| row.get(0),
            )
            .optional()
            .map_err(text)?;
        let released: Option<i64> = tx
            .query_row(
                &format!("SELECT 1 FROM custody_released_v1 WHERE {released_col} = ?1"),
                params![digest_key],
                |row| row.get(0),
            )
            .optional()
            .map_err(text)?;
        if held.is_some() || released.is_some() {
            tx.commit().map_err(text)?;
            return Ok(CustodyCode::Duplicate);
        }
        let bytes = letter.len() as i64;
        let counts = match keys.as_deref() {
            None => clear_counts(&tx, recipient, depositor, now_ms)?,
            Some(keys) => keyed_counts(&tx, keys, &recipient_key, &depositor_key, now_ms)?,
        };
        if let Some(code) = cap_refusal(&counts, bytes, counts.pair_letters >= MAX_PAIR_LETTERS) {
            tx.commit().map_err(text)?;
            return Ok(code);
        }
        let token = crate::async_letter::page_token(letter);
        match sealed {
            None => tx.execute(
                "INSERT INTO custody_letters_v1
                   (letter_digest, recipient, depositor, page_token, letter, bytes,
                    admitted_at_ms, expires_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    digest.as_slice(),
                    recipient.as_slice(),
                    depositor.as_slice(),
                    token.as_slice(),
                    letter,
                    bytes,
                    ms(now_ms),
                    ms(expires_at_ms),
                ],
            ),
            Some((meta, sealed_letter)) => tx.execute(
                "INSERT INTO custody_letters_v1
                   (kh_letter_digest, kh_recipient, kh_depositor, page_token, letter, bytes,
                    meta, prune_after_hour)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    digest_key,
                    recipient_key,
                    depositor_key,
                    token.as_slice(),
                    sealed_letter,
                    bytes,
                    meta,
                    rebuild::prune_after_hour(expires_at_ms),
                ],
            ),
        }
        .map_err(text)?;
        tx.commit().map_err(text)?;
        Ok(CustodyCode::Ok)
    }

    /// One page of `recipient`'s unexpired letters after `after`, in page
    /// token order (§10 FETCH_LETTERS). Read-only.
    pub fn fetch_letters(
        &self,
        recipient: &[u8; 32],
        after: Option<[u8; 32]>,
        max_items: u8,
        now_ms: u64,
    ) -> Result<FetchPage, String> {
        let keyed = self.keys.is_some();
        let sql = if keyed {
            "SELECT letter, page_token, kh_letter_digest, meta, prune_after_hour
             FROM custody_letters_v1
             WHERE kh_recipient = ?1 AND prune_after_hour > ?2 AND (?3 = 0 OR page_token > ?4)
             ORDER BY page_token"
        } else {
            "SELECT letter, page_token, NULL, NULL, NULL FROM custody_letters_v1
             WHERE recipient = ?1 AND expires_at_ms > ?2 AND (?3 = 0 OR page_token > ?4)
             ORDER BY page_token LIMIT 17"
        };
        let values: Vec<Box<dyn rusqlite::ToSql>> = vec![
            Box::new(self.device_value(recipient)),
            Box::new(if keyed {
                rebuild::hour_of(now_ms)
            } else {
                ms(now_ms)
            }),
            Box::new(i64::from(after.is_some())),
            Box::new(after.unwrap_or([0u8; 32]).to_vec()),
        ];
        self.read_page(sql, &values, (LETTERS, LETTER_LABEL), max_items, now_ms)
    }

    /// WITHDRAW_LETTERS by the authenticated depositor (§10): each of
    /// `digests` it deposited is deleted, nothing of it kept (it signed the
    /// letter, so nobody else can leave it again); one IMMEDIATE transaction,
    /// then a checkpoint. Another depositor's digest or an unknown one
    /// changes nothing. Count withdrawn.
    pub fn withdraw_letters(
        &mut self,
        depositor: &[u8; 32],
        digests: &[[u8; 32]],
    ) -> Result<u8, String> {
        let (digest_col, _, depositor_col) = self.letter_cols();
        let depositor_key = self.device_value(depositor);
        let digest_keys: Vec<Vec<u8>> = digests.iter().map(|d| self.digest_value(d)).collect();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(text)?;
        let _in_tx = crate::paths::HeldMark::transaction();
        let mut changed = 0usize;
        for digest_key in &digest_keys {
            changed += tx
                .execute(
                    &format!(
                        "DELETE FROM custody_letters_v1
                         WHERE {digest_col} = ?1 AND {depositor_col} = ?2"
                    ),
                    params![digest_key, depositor_key],
                )
                .map_err(text)?;
        }
        tx.commit().map_err(text)?;
        if changed > 0 {
            let _ = crate::paths::checkpoint_truncate(&self.conn);
        }
        Ok(u8::try_from(changed).unwrap_or(u8::MAX))
    }

    /// (letters, bytes) currently held (§10).
    pub fn letter_usage(&self) -> Result<(i64, i64), String> {
        self.conn
            .query_row(
                "SELECT COUNT(*), COALESCE(SUM(bytes), 0) FROM custody_letters_v1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(text)
    }

    /// RELEASE by the authenticated recipient (§6.5; privacy pack PP.17):
    /// each of `digests` held for `recipient` is deleted, its payload and
    /// both parties with it, and only its digest and expiry hour stay (a
    /// replay is then still a duplicate); one IMMEDIATE transaction, then a
    /// checkpoint so what the delete overwrote reaches the main file. Another
    /// recipient's digest, an unknown or an already released one changes
    /// nothing. A letter digest releases that letter the same way (§10).
    /// Count released.
    pub fn release(&mut self, recipient: &[u8; 32], digests: &[[u8; 32]]) -> Result<u8, String> {
        let recipient_key = self.device_value(recipient);
        let digest_keys: Vec<Vec<u8>> = digests.iter().map(|d| self.digest_value(d)).collect();
        let layout = self.layout;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(text)?;
        let _in_tx = crate::paths::HeldMark::transaction();
        let mut changed = 0usize;
        for digest_key in &digest_keys {
            changed += match layout {
                Layout::Clear => release_clear(&tx, digest_key, &recipient_key)?,
                Layout::Keyed => release_keyed(&tx, digest_key, &recipient_key)?,
            };
            changed += release_letter(&tx, layout, digest_key, &recipient_key)?;
        }
        tx.commit().map_err(text)?;
        if changed > 0 {
            // Busy (a reader in the way) is left to the next durable prune.
            let _ = crate::paths::checkpoint_truncate(&self.conn);
        }
        Ok(u8::try_from(changed).unwrap_or(u8::MAX))
    }

    /// Expired rows, and rows of parties that are no longer current pinned
    /// contacts, go, and the released digests of objects that have expired;
    /// then incremental vacuum (§6.6) and a checkpoint, so what went leaves
    /// the main file too (PP.2). Rows removed.
    pub fn maintain(
        &mut self,
        now_ms: u64,
        still_allowed: &dyn Fn(&[u8; 32]) -> bool,
    ) -> Result<usize, String> {
        let removed = match self.keys.clone() {
            None => self.maintain_clear(now_ms, still_allowed)?,
            Some(keys) => self.maintain_keyed(&keys, now_ms, still_allowed)?,
        };
        let _ = self.conn.execute_batch("PRAGMA incremental_vacuum;");
        // Busy (a reader in the way) is left to the next durable prune.
        let _ = crate::paths::checkpoint_truncate(&self.conn);
        Ok(removed)
    }

    fn maintain_clear(
        &mut self,
        now_ms: u64,
        still_allowed: &dyn Fn(&[u8; 32]) -> bool,
    ) -> Result<usize, String> {
        let mut removed = self
            .conn
            .execute(
                "DELETE FROM custody_objects_v1 WHERE expires_at_ms <= ?1",
                params![ms(now_ms)],
            )
            .map_err(text)?;
        // Objects an older build released (it kept the payload until they
        // expired): only the digest stays (PP.17).
        {
            let tx = self
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(text)?;
            let _in_tx = crate::paths::HeldMark::transaction();
            tx.execute(
                "INSERT OR IGNORE INTO custody_released_v1 (object_digest, prune_after_hour)
                 SELECT object_digest, (expires_at_ms + ?1 - 1) / ?1 FROM custody_objects_v1
                 WHERE released_at_ms IS NOT NULL",
                params![ms(rebuild::HOUR_MS)],
            )
            .map_err(text)?;
            removed += tx
                .execute(
                    "DELETE FROM custody_objects_v1 WHERE released_at_ms IS NOT NULL",
                    [],
                )
                .map_err(text)?;
            tx.commit().map_err(text)?;
        }
        self.conn
            .execute(
                "DELETE FROM custody_released_v1 WHERE prune_after_hour <= ?1",
                params![rebuild::hour_of(now_ms)],
            )
            .map_err(text)?;
        removed += self
            .conn
            .execute(
                "DELETE FROM custody_letters_v1 WHERE expires_at_ms <= ?1",
                params![ms(now_ms)],
            )
            .map_err(text)?;
        for table in [OBJECTS, LETTERS] {
            let parties: Vec<(Vec<u8>, Vec<u8>)> = {
                let mut stmt = self
                    .conn
                    .prepare(&format!(
                        "SELECT DISTINCT depositor, recipient FROM {table}"
                    ))
                    .map_err(text)?;
                let rows = stmt
                    .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                    .map_err(text)?;
                rows.collect::<Result<_, _>>().map_err(text)?
            };
            for (depositor, recipient) in parties {
                let (d, r) = (arr::<32>(&depositor), arr::<32>(&recipient));
                if !still_allowed(&d) || !still_allowed(&r) {
                    removed += self
                        .conn
                        .execute(
                            &format!("DELETE FROM {table} WHERE depositor = ?1 AND recipient = ?2"),
                            params![depositor, recipient],
                        )
                        .map_err(text)?;
                }
            }
        }
        Ok(removed)
    }

    /// [`Self::maintain`] of a schema-2 store: the prune deletes by the
    /// coarse hour, the hour that may not have passed yet goes by each row's
    /// exact expiry, and one `meta` per (depositor, recipient) names the
    /// parties.
    fn maintain_keyed(
        &mut self,
        keys: &MetaKeys,
        now_ms: u64,
        still_allowed: &dyn Fn(&[u8; 32]) -> bool,
    ) -> Result<usize, String> {
        let hour = rebuild::hour_of(now_ms);
        self.conn
            .execute(
                "DELETE FROM custody_released_v1 WHERE prune_after_hour <= ?1",
                params![hour],
            )
            .map_err(text)?;
        let mut removed = 0;
        for table in [(OBJECTS, KEYED_COLUMN), (LETTERS, LETTERS_KEYED_COLUMN)] {
            removed += maintain_keyed_table(&self.conn, keys, table, now_ms, still_allowed)?;
        }
        Ok(removed)
    }

    /// `raven node custody off --purge`: every row (objects and letters) and
    /// every released digest, then a checkpoint as after [`Self::maintain`].
    /// Objects and letters deleted.
    pub fn purge(&mut self) -> Result<usize, String> {
        let purged = self
            .conn
            .execute("DELETE FROM custody_objects_v1", [])
            .map_err(text)?
            + self
                .conn
                .execute("DELETE FROM custody_letters_v1", [])
                .map_err(text)?;
        self.conn
            .execute("DELETE FROM custody_released_v1", [])
            .map_err(text)?;
        let _ = crate::paths::checkpoint_truncate(&self.conn);
        Ok(purged)
    }

    /// (rows, bytes) currently held. A released object is gone: only its
    /// digest is kept, counted nowhere (PP.17).
    pub fn usage(&self) -> Result<(i64, i64), String> {
        self.conn
            .query_row(
                "SELECT COUNT(*), COALESCE(SUM(bytes), 0) FROM custody_objects_v1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(text)
    }

    /// [`held_recipients`] on this store.
    pub fn held_recipients(&self, now_ms: u64) -> Result<Vec<[u8; 32]>, String> {
        if let Some(keys) = self.keys.as_deref() {
            return self.held_keyed(keys, OBJECTS, KEYED_COLUMN, now_ms);
        }
        self.held_clear(
            "SELECT recipient FROM custody_objects_v1
             WHERE released_at_ms IS NULL AND expires_at_ms > ?1
             GROUP BY recipient
             ORDER BY MAX(admitted_at_ms) DESC, recipient
             LIMIT ?2",
            now_ms,
        )
    }

    /// [`held_letter_recipients`] on this store.
    pub fn held_letter_recipients(&self, now_ms: u64) -> Result<Vec<[u8; 32]>, String> {
        if let Some(keys) = self.keys.as_deref() {
            return self.held_keyed(keys, LETTERS, LETTERS_KEYED_COLUMN, now_ms);
        }
        // A released letter is deleted (§10): every row is held.
        self.held_clear(
            "SELECT recipient FROM custody_letters_v1
             WHERE expires_at_ms > ?1
             GROUP BY recipient
             ORDER BY MAX(admitted_at_ms) DESC, recipient
             LIMIT ?2",
            now_ms,
        )
    }

    /// The recipients `sql` (schema 1, `?1` now, `?2` the limit) names.
    fn held_clear(&self, sql: &str, now_ms: u64) -> Result<Vec<[u8; 32]>, String> {
        let mut stmt = self.conn.prepare(sql).map_err(text)?;
        let limit = i64::try_from(MAX_HELD_RECIPIENTS).unwrap_or(i64::MAX);
        let rows = stmt
            .query_map(params![ms(now_ms), limit], |row| row.get::<_, Vec<u8>>(0))
            .map_err(text)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(arr::<32>(&row.map_err(text)?));
        }
        Ok(out)
    }

    /// The held recipients of `table` (the objects', or the letters' with
    /// `digest_col`) in a schema-2 store: every live row's `meta` names its
    /// recipient and admission time; the same order (newest deposit first,
    /// then the key).
    fn held_keyed(
        &self,
        keys: &MetaKeys,
        table: &str,
        digest_col: &str,
        now_ms: u64,
    ) -> Result<Vec<[u8; 32]>, String> {
        let rows: Vec<(Vec<u8>, Vec<u8>)> = {
            let mut stmt = self
                .conn
                .prepare(&format!(
                    "SELECT {digest_col}, meta FROM {table}
                     WHERE prune_after_hour > ?1"
                ))
                .map_err(text)?;
            let rows = stmt
                .query_map(params![rebuild::hour_of(now_ms)], |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })
                .map_err(text)?;
            rows.collect::<Result<_, _>>().map_err(text)?
        };
        let mut newest: HashMap<[u8; 32], u64> = HashMap::new();
        for (kd, meta) in rows {
            let Some(meta) = open_meta_in(keys, table, &kd, &meta) else {
                continue;
            };
            let Some(recipient) = unhex32(&meta.recipient) else {
                continue;
            };
            if meta.expires_at_ms <= now_ms {
                continue;
            }
            let at = newest.entry(recipient).or_insert(meta.admitted_at_ms);
            *at = (*at).max(meta.admitted_at_ms);
        }
        let mut held: Vec<([u8; 32], u64)> = newest.into_iter().collect();
        held.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        Ok(held
            .into_iter()
            .take(MAX_HELD_RECIPIENTS)
            .map(|(recipient, _)| recipient)
            .collect())
    }
}

/// The caps a deposit of `bytes` meets (§6, §10), in order: the node's, the
/// depositor's and the pair's (`pair_full`: objects and letters each have
/// their own), then the byte rate. `None`: room.
fn cap_refusal(counts: &Counts, bytes: i64, pair_full: bool) -> Option<CustodyCode> {
    if counts.node_rows >= MAX_NODE_ROWS || counts.node_bytes + bytes > MAX_NODE_BYTES {
        return Some(CustodyCode::StoreFull);
    }
    if counts.depositor_rows >= MAX_DEPOSITOR_ROWS
        || counts.depositor_bytes + bytes > MAX_DEPOSITOR_BYTES
        || pair_full
    {
        return Some(CustodyCode::Quota);
    }
    if counts.recent + bytes > MAX_DEPOSITOR_BYTES_PER_MINUTE {
        return Some(CustodyCode::RateLimited);
    }
    None
}

/// The deposit's expiry purge: at most [`PURGE_PER_DEPOSIT`] expired objects
/// and letters (schema 2: by the hour that has passed) and released digests.
fn purge_some_expired(conn: &Connection, layout: Layout, now_ms: u64) -> Result<(), String> {
    let hour = rebuild::hour_of(now_ms);
    let objects = match layout {
        Layout::Clear => (
            "DELETE FROM custody_objects_v1 WHERE rowid IN (
               SELECT rowid FROM custody_objects_v1 WHERE expires_at_ms <= ?1 LIMIT ?2)",
            ms(now_ms),
        ),
        Layout::Keyed => (
            "DELETE FROM custody_objects_v1 WHERE rowid IN (
               SELECT rowid FROM custody_objects_v1 WHERE prune_after_hour <= ?1 LIMIT ?2)",
            hour,
        ),
    };
    conn.execute(objects.0, params![objects.1, PURGE_PER_DEPOSIT])
        .map_err(text)?;
    let letters = match layout {
        Layout::Clear => {
            "DELETE FROM custody_letters_v1 WHERE rowid IN (
               SELECT rowid FROM custody_letters_v1 WHERE expires_at_ms <= ?1 LIMIT ?2)"
        }
        Layout::Keyed => {
            "DELETE FROM custody_letters_v1 WHERE rowid IN (
               SELECT rowid FROM custody_letters_v1 WHERE prune_after_hour <= ?1 LIMIT ?2)"
        }
    };
    conn.execute(letters, params![objects.1, PURGE_PER_DEPOSIT])
        .map_err(text)?;
    conn.execute(
        "DELETE FROM custody_released_v1 WHERE rowid IN (
           SELECT rowid FROM custody_released_v1 WHERE prune_after_hour <= ?1 LIMIT ?2)",
        params![hour, PURGE_PER_DEPOSIT],
    )
    .map_err(text)?;
    Ok(())
}

/// The caps' counts of a schema-1 store: its objects and letters.
fn clear_counts(
    conn: &Connection,
    recipient: &[u8; 32],
    depositor: &[u8; 32],
    now_ms: u64,
) -> Result<Counts, String> {
    let objects = clear_table_counts(conn, OBJECTS, recipient, depositor, now_ms)?;
    let letters = clear_table_counts(conn, LETTERS, recipient, depositor, now_ms)?;
    Ok(objects.with_letters(letters))
}

/// The caps' counts of one schema-1 table (`pair_rows`: its own pair).
fn clear_table_counts(
    conn: &Connection,
    table: &str,
    recipient: &[u8; 32],
    depositor: &[u8; 32],
    now_ms: u64,
) -> Result<Counts, String> {
    let mut counts = Counts::default();
    (counts.node_rows, counts.node_bytes) = conn
        .query_row(
            &format!(
                "SELECT COUNT(*), COALESCE(SUM(bytes), 0) FROM {table}
                 WHERE expires_at_ms > ?1"
            ),
            params![ms(now_ms)],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(text)?;
    (counts.depositor_rows, counts.depositor_bytes, counts.recent) = conn
        .query_row(
            &format!(
                "SELECT COUNT(*), COALESCE(SUM(bytes), 0),
                        COALESCE(SUM(CASE WHEN admitted_at_ms >= ?2 THEN bytes ELSE 0 END), 0)
                 FROM {table} WHERE depositor = ?1 AND expires_at_ms > ?3"
            ),
            params![
                depositor.as_slice(),
                ms(now_ms.saturating_sub(WINDOW_MS)),
                ms(now_ms)
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(text)?;
    counts.pair_rows = conn
        .query_row(
            &format!(
                "SELECT COUNT(*) FROM {table}
                 WHERE depositor = ?1 AND recipient = ?2 AND expires_at_ms > ?3"
            ),
            params![depositor.as_slice(), recipient.as_slice(), ms(now_ms)],
            |row| row.get(0),
        )
        .map_err(text)?;
    Ok(counts)
}

/// The caps' counts of a schema-2 store, as exact as schema 1's: rows whose
/// hour is past are expired, rows two hours ahead live, and the hour in
/// between, and every one of the depositor's rows (its admission time for
/// the byte rate), is read from `meta`. A `meta` that does not open counts
/// by its hour, never as recent. Objects and letters.
fn keyed_counts(
    conn: &Connection,
    keys: &MetaKeys,
    recipient_key: &[u8],
    depositor_key: &[u8],
    now_ms: u64,
) -> Result<Counts, String> {
    let objects = keyed_table_counts(
        conn,
        keys,
        (OBJECTS, KEYED_COLUMN),
        recipient_key,
        depositor_key,
        now_ms,
    )?;
    let letters = keyed_table_counts(
        conn,
        keys,
        (LETTERS, LETTERS_KEYED_COLUMN),
        recipient_key,
        depositor_key,
        now_ms,
    )?;
    Ok(objects.with_letters(letters))
}

/// [`keyed_counts`] of one schema-2 table `(name, keyed digest column)`.
fn keyed_table_counts(
    conn: &Connection,
    keys: &MetaKeys,
    (table, digest_col): (&str, &str),
    recipient_key: &[u8],
    depositor_key: &[u8],
    now_ms: u64,
) -> Result<Counts, String> {
    let hour = rebuild::hour_of(now_ms);
    let mut counts = Counts::default();
    (counts.node_rows, counts.node_bytes) = conn
        .query_row(
            &format!(
                "SELECT COUNT(*), COALESCE(SUM(bytes), 0) FROM {table}
                 WHERE prune_after_hour > ?1"
            ),
            params![hour + 1],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(text)?;
    {
        let mut stmt = conn
            .prepare(&format!(
                "SELECT {digest_col}, bytes, meta FROM {table}
                 WHERE prune_after_hour = ?1"
            ))
            .map_err(text)?;
        let rows = stmt
            .query_map(params![hour + 1], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            })
            .map_err(text)?;
        for row in rows {
            let (kd, bytes, meta) = row.map_err(text)?;
            if live_by_meta(open_meta_in(keys, table, &kd, &meta).as_ref(), now_ms) {
                counts.node_rows += 1;
                counts.node_bytes += bytes;
            }
        }
    }
    let mut stmt = conn
        .prepare(&format!(
            "SELECT {digest_col}, kh_recipient, bytes, meta FROM {table}
             WHERE kh_depositor = ?1 AND prune_after_hour > ?2"
        ))
        .map_err(text)?;
    let rows = stmt
        .query_map(params![depositor_key, hour], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        })
        .map_err(text)?;
    let recent_from = now_ms.saturating_sub(WINDOW_MS);
    for row in rows {
        let (kd, kr, bytes, meta) = row.map_err(text)?;
        let meta = open_meta_in(keys, table, &kd, &meta);
        if !live_by_meta(meta.as_ref(), now_ms) {
            continue;
        }
        counts.depositor_rows += 1;
        counts.depositor_bytes += bytes;
        if meta.is_some_and(|meta| meta.admitted_at_ms >= recent_from) {
            counts.recent += bytes;
        }
        if kr == recipient_key {
            counts.pair_rows += 1;
        }
    }
    Ok(counts)
}

/// RELEASE of one digest in a schema-1 store: the row goes and its digest
/// stays with its expiry hour. An object an older build already released is
/// deleted too, but not counted.
fn release_clear(conn: &Connection, digest: &[u8], recipient: &[u8]) -> Result<usize, String> {
    let row: Option<(i64, bool)> = conn
        .query_row(
            "SELECT expires_at_ms, released_at_ms IS NULL FROM custody_objects_v1
             WHERE object_digest = ?1 AND recipient = ?2",
            params![digest, recipient],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(text)?;
    let Some((expires_at_ms, unreleased)) = row else {
        return Ok(0);
    };
    conn.execute(
        "DELETE FROM custody_objects_v1 WHERE object_digest = ?1",
        params![digest],
    )
    .map_err(text)?;
    conn.execute(
        "INSERT OR IGNORE INTO custody_released_v1 (object_digest, prune_after_hour)
         VALUES (?1, ?2)",
        params![
            digest,
            rebuild::prune_after_hour(u64::try_from(expires_at_ms).unwrap_or(0))
        ],
    )
    .map_err(text)?;
    Ok(usize::from(unreleased))
}

/// RELEASE of one keyed digest in a schema-2 store.
fn release_keyed(conn: &Connection, kd: &[u8], kr: &[u8]) -> Result<usize, String> {
    let hour: Option<i64> = conn
        .query_row(
            "SELECT prune_after_hour FROM custody_objects_v1
             WHERE kh_object_digest = ?1 AND kh_recipient = ?2",
            params![kd, kr],
            |row| row.get(0),
        )
        .optional()
        .map_err(text)?;
    let Some(hour) = hour else {
        return Ok(0);
    };
    conn.execute(
        "DELETE FROM custody_objects_v1 WHERE kh_object_digest = ?1",
        params![kd],
    )
    .map_err(text)?;
    conn.execute(
        "INSERT OR IGNORE INTO custody_released_v1 (kh_object_digest, prune_after_hour)
         VALUES (?1, ?2)",
        params![kd, hour],
    )
    .map_err(text)?;
    Ok(1)
}

/// [`CustodyStore::maintain`] of one schema-2 table `(name, keyed digest
/// column)`: the prune deletes by the coarse hour, the hour that may not have
/// passed yet goes by each row's exact expiry, and one `meta` per
/// (depositor, recipient) names the parties.
fn maintain_keyed_table(
    conn: &Connection,
    keys: &MetaKeys,
    (table, digest_col): (&str, &str),
    now_ms: u64,
    still_allowed: &dyn Fn(&[u8; 32]) -> bool,
) -> Result<usize, String> {
    let hour = rebuild::hour_of(now_ms);
    let mut removed = conn
        .execute(
            &format!("DELETE FROM {table} WHERE prune_after_hour <= ?1"),
            params![hour],
        )
        .map_err(text)?;
    let edge: Vec<(Vec<u8>, Vec<u8>)> = {
        let mut stmt = conn
            .prepare(&format!(
                "SELECT {digest_col}, meta FROM {table} WHERE prune_after_hour = ?1"
            ))
            .map_err(text)?;
        let rows = stmt
            .query_map(params![hour + 1], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(text)?;
        rows.collect::<Result<_, _>>().map_err(text)?
    };
    for (kd, meta) in edge {
        if !live_by_meta(open_meta_in(keys, table, &kd, &meta).as_ref(), now_ms) {
            removed += conn
                .execute(
                    &format!("DELETE FROM {table} WHERE {digest_col} = ?1"),
                    params![kd],
                )
                .map_err(text)?;
        }
    }
    type Row = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);
    let rows: Vec<Row> = {
        let mut stmt = conn
            .prepare(&format!(
                "SELECT kh_depositor, kh_recipient, {digest_col}, meta FROM {table}"
            ))
            .map_err(text)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .map_err(text)?;
        rows.collect::<Result<_, _>>().map_err(text)?
    };
    // Per pair: still allowed or not, once a `meta` of it opened (a pair
    // none of whose rows opens is left to expire).
    let mut pairs: HashMap<(Vec<u8>, Vec<u8>), Option<bool>> = HashMap::new();
    for (kp, kr, kd, meta) in rows {
        let decided = pairs.entry((kp, kr)).or_insert(None);
        if decided.is_some() {
            continue;
        }
        let parties = open_meta_in(keys, table, &kd, &meta)
            .and_then(|meta| Some((unhex32(&meta.depositor)?, unhex32(&meta.recipient)?)));
        if let Some((depositor, recipient)) = parties {
            *decided = Some(still_allowed(&depositor) && still_allowed(&recipient));
        }
    }
    for ((kp, kr), allowed) in pairs {
        if allowed == Some(false) {
            removed += conn
                .execute(
                    &format!("DELETE FROM {table} WHERE kh_depositor = ?1 AND kh_recipient = ?2"),
                    params![kp, kr],
                )
                .map_err(text)?;
        }
    }
    Ok(removed)
}

/// RELEASE of one digest's letter (§10), in either schema: the row goes and
/// its digest stays with its expiry hour, as an object's. Count (0 or 1).
fn release_letter(
    conn: &Connection,
    layout: Layout,
    digest: &[u8],
    recipient: &[u8],
) -> Result<usize, String> {
    let (digest_col, recipient_col, when) = match layout {
        Layout::Clear => ("letter_digest", "recipient", "expires_at_ms"),
        Layout::Keyed => (LETTERS_KEYED_COLUMN, "kh_recipient", "prune_after_hour"),
    };
    let when: Option<i64> = conn
        .query_row(
            &format!(
                "SELECT {when} FROM custody_letters_v1
                 WHERE {digest_col} = ?1 AND {recipient_col} = ?2"
            ),
            params![digest, recipient],
            |row| row.get(0),
        )
        .optional()
        .map_err(text)?;
    let Some(when) = when else {
        return Ok(0);
    };
    let (released, hour) = match layout {
        Layout::Clear => (
            "INSERT OR IGNORE INTO custody_released_v1 (object_digest, prune_after_hour)
             VALUES (?1, ?2)",
            rebuild::prune_after_hour(u64::try_from(when).unwrap_or(0)),
        ),
        Layout::Keyed => (
            "INSERT OR IGNORE INTO custody_released_v1 (kh_object_digest, prune_after_hour)
             VALUES (?1, ?2)",
            when,
        ),
    };
    conn.execute(
        &format!("DELETE FROM custody_letters_v1 WHERE {digest_col} = ?1"),
        params![digest],
    )
    .map_err(text)?;
    conn.execute(released, params![digest, hour])
        .map_err(text)?;
    Ok(1)
}

/// A schema-2 store created in one IMMEDIATE transaction (a sealed profile's
/// first store). A racing creator's store is kept as it is.
fn create_keyed(conn: &mut Connection) -> Result<(), String> {
    // Before the first table: the store frees pages as §6.6 expects.
    conn.execute_batch(
        "PRAGMA auto_vacuum=INCREMENTAL; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;",
    )
    .map_err(text)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(text)?;
    let _in_tx = crate::paths::HeldMark::transaction();
    if rebuild::shape(&tx, OBJECTS, KEYED_COLUMN).map_err(text)? == Shape::Missing {
        tx.execute_batch(&objects_table(OBJECTS, true))
            .map_err(text)?;
        tx.execute_batch(object_indexes(true)).map_err(text)?;
        if rebuild::shape(&tx, LETTERS, LETTERS_KEYED_COLUMN).map_err(text)? == Shape::Missing {
            create_letters(&tx, true).map_err(text)?;
        }
        if rebuild::columns(&tx, RELEASED).map_err(text)?.is_empty() {
            tx.execute_batch(&released_table(RELEASED, true))
                .map_err(text)?;
        }
        rebuild::record(&tx, STORE, SCHEMA_VERSION, false).map_err(text)?;
    }
    tx.commit().map_err(text)
}

// ── Migration (privacy pack PP.17) ───────────────────────────────────────

/// Schema 1 -> 2 with the rebuild recipe ([`crate::sqlite_rebuild`]): both
/// tables rebuilt in one IMMEDIATE transaction, rowids kept, counts checked
/// before the commit, then the scrub. An object an older build released
/// (payload kept until it expired) becomes a released digest: its row and
/// payload go now.
fn migrate_forward(
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
    if rebuild::shape(&tx, OBJECTS, KEYED_COLUMN)? != Shape::Clear {
        return Ok(Migration::already());
    }
    let (moved, expected) = forward_tables(&tx, keys, &mut steps)?;
    steps.step()?;
    rebuild::verify(&tx, &expected)?;
    rebuild::record(&tx, STORE, SCHEMA_VERSION, true)?;
    steps.step()?;
    tx.commit()?;
    steps.step()?;
    let scrubbed = rebuild::scrub(&conn, STORE, free)?;
    Ok(Migration {
        rows: moved,
        scrub_pending: !scrubbed.complete,
        ..Migration::default()
    })
}

/// What each table holds after a rebuild's tables moved (its count check).
type Expected = [(&'static str, i64); 3];

/// Schema 1 -> 2's tables inside the caller's transaction (the migration,
/// and the second half of a re-key): the objects, the released digests and
/// the letters rebuilt keyed, rowids kept (a store without letters gets an
/// empty keyed table). The rows moved, and what each table must hold
/// afterwards.
fn forward_tables(
    tx: &rusqlite::Transaction<'_>,
    keys: &MetaKeys,
    steps: &mut Steps,
) -> Result<(u32, Expected), RebuildError> {
    // A store an older build created has no released digests yet.
    let had_released = !rebuild::columns(tx, RELEASED)?.is_empty();
    type Row = (
        i64,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        i64,
        i64,
        i64,
        Option<i64>,
    );
    let objects: Vec<Row> = {
        let mut stmt = tx.prepare(
            "SELECT rowid, object_digest, recipient, depositor, store_tag, page_token, rso1,
                    bytes, admitted_at_ms, expires_at_ms, released_at_ms
             FROM custody_objects_v1",
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
            ))
        })?;
        mapped.collect::<Result<_, _>>()?
    };
    let released: Vec<(i64, Vec<u8>, i64)> = if had_released {
        let mut stmt =
            tx.prepare("SELECT rowid, object_digest, prune_after_hour FROM custody_released_v1")?;
        let mapped = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        mapped.collect::<Result<_, _>>()?
    } else {
        Vec::new()
    };
    // What the two tables must hold afterwards, from the rows read.
    let open_objects = objects.iter().filter(|row| row.10.is_none()).count();
    let released_digests: HashSet<[u8; 32]> = released
        .iter()
        .map(|(_, digest, _)| kh_digest(keys, digest))
        .chain(
            objects
                .iter()
                .filter(|row| row.10.is_some())
                .map(|row| kh_digest(keys, &row.1)),
        )
        .collect();
    let mut moved = 0u32;
    let mut older_released = Vec::new();
    steps.step()?;
    tx.execute_batch(&objects_table("custody_objects_v1__new", true))?;
    let leave_one_out = rebuild::drop_one_row();
    for (n, row) in objects.into_iter().enumerate() {
        let (rowid, digest, recipient, depositor, tag, token, rso1, bytes, admitted, expires, at) =
            row;
        if leave_one_out && n == 0 {
            continue;
        }
        steps.step()?;
        let kd = kh_digest(keys, &digest);
        let expires_at_ms = u64::try_from(expires).unwrap_or(0);
        if at.is_some() {
            older_released.push((kd, rebuild::prune_after_hour(expires_at_ms)));
            continue;
        }
        let meta = ObjectMeta {
            object_digest: hex::encode(&digest),
            recipient: hex::encode(&recipient),
            depositor: hex::encode(&depositor),
            admitted_at_ms: u64::try_from(admitted).unwrap_or(0),
            expires_at_ms,
        };
        tx.execute(
            "INSERT INTO custody_objects_v1__new
               (rowid, kh_object_digest, kh_recipient, kh_depositor, store_tag, page_token, rso1,
                bytes, meta, prune_after_hour)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                rowid,
                kd.as_slice(),
                kh_device(keys, &recipient).as_slice(),
                kh_device(keys, &depositor).as_slice(),
                tag,
                token,
                at_rest::seal_row(keys, RSO1_LABEL, &kd, &rso1),
                bytes,
                seal_meta(keys, &kd, &meta),
                rebuild::prune_after_hour(expires_at_ms),
            ],
        )?;
        moved += 1;
    }
    steps.step()?;
    tx.execute_batch("DROP TABLE custody_objects_v1;")?;
    steps.step()?;
    tx.execute_batch("ALTER TABLE custody_objects_v1__new RENAME TO custody_objects_v1;")?;
    steps.step()?;
    tx.execute_batch(object_indexes(true))?;
    steps.step()?;
    tx.execute_batch(&released_table("custody_released_v1__new", true))?;
    for (rowid, digest, hour) in released {
        steps.step()?;
        tx.execute(
            "INSERT OR IGNORE INTO custody_released_v1__new (rowid, kh_object_digest, prune_after_hour)
             VALUES (?1, ?2, ?3)",
            params![rowid, kh_digest(keys, &digest).as_slice(), hour],
        )?;
        moved += 1;
    }
    for (kd, hour) in older_released {
        steps.step()?;
        let inserted = tx.execute(
            "INSERT OR IGNORE INTO custody_released_v1__new (kh_object_digest, prune_after_hour)
             VALUES (?1, ?2)",
            params![kd.as_slice(), hour],
        )?;
        moved += u32::try_from(inserted).unwrap_or(0);
    }
    if had_released {
        steps.step()?;
        tx.execute_batch("DROP TABLE custody_released_v1;")?;
    }
    steps.step()?;
    tx.execute_batch("ALTER TABLE custody_released_v1__new RENAME TO custody_released_v1;")?;
    let letters = match rebuild::shape(tx, LETTERS, LETTERS_KEYED_COLUMN)? {
        Shape::Clear => letters_forward(tx, keys, steps)?,
        Shape::Missing => {
            steps.step()?;
            create_letters(tx, true)?;
            (0, 0)
        }
        // An older build of the pack unsealed the objects only: the letters
        // stay as they are.
        Shape::Keyed => (0, rebuild::count(tx, LETTERS)?),
    };
    moved += letters.0;
    let expected = [
        (OBJECTS, i64::try_from(open_objects).unwrap_or(i64::MAX)),
        (
            RELEASED,
            i64::try_from(released_digests.len()).unwrap_or(i64::MAX),
        ),
        (LETTERS, letters.1),
    ];
    Ok((moved, expected))
}

/// The letters moved to schema 2 inside the caller's transaction (the
/// rebuilds, and a keyed store's open that finds a clear table an older
/// build of the pack left): rowids kept, each letter sealed whole and its
/// clear values in `meta`. (moved, the table's count afterwards).
fn letters_forward(
    tx: &rusqlite::Transaction<'_>,
    keys: &MetaKeys,
    steps: &mut Steps,
) -> Result<(u32, i64), RebuildError> {
    type Row = (
        i64,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        i64,
        i64,
        i64,
    );
    let letters: Vec<Row> = {
        let mut stmt = tx.prepare(
            "SELECT rowid, letter_digest, recipient, depositor, page_token, letter, bytes,
                    admitted_at_ms, expires_at_ms
             FROM custody_letters_v1",
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
            ))
        })?;
        mapped.collect::<Result<_, _>>()?
    };
    let expected = i64::try_from(letters.len()).unwrap_or(i64::MAX);
    steps.step()?;
    tx.execute_batch(&letters_table("custody_letters_v1__new", true))?;
    let mut moved = 0u32;
    for (rowid, digest, recipient, depositor, token, letter, bytes, admitted, expires) in letters {
        steps.step()?;
        let kd = kh_digest(keys, &digest);
        let expires_at_ms = u64::try_from(expires).unwrap_or(0);
        let meta = ObjectMeta {
            object_digest: hex::encode(&digest),
            recipient: hex::encode(&recipient),
            depositor: hex::encode(&depositor),
            admitted_at_ms: u64::try_from(admitted).unwrap_or(0),
            expires_at_ms,
        };
        tx.execute(
            "INSERT INTO custody_letters_v1__new
               (rowid, kh_letter_digest, kh_recipient, kh_depositor, page_token, letter, bytes,
                meta, prune_after_hour)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                rowid,
                kd.as_slice(),
                kh_device(keys, &recipient).as_slice(),
                kh_device(keys, &depositor).as_slice(),
                token,
                at_rest::seal_row(keys, LETTER_LABEL, &kd, &letter),
                bytes,
                seal_meta_in(keys, LETTERS, &kd, &meta),
                rebuild::prune_after_hour(expires_at_ms),
            ],
        )?;
        moved += 1;
    }
    steps.step()?;
    tx.execute_batch("DROP TABLE custody_letters_v1;")?;
    steps.step()?;
    tx.execute_batch("ALTER TABLE custody_letters_v1__new RENAME TO custody_letters_v1;")?;
    steps.step()?;
    tx.execute_batch(letter_indexes(true))?;
    Ok((moved, expected))
}

/// The letters moved back to schema 1 inside the caller's transaction (the
/// way back, and the first half of a re-key): letters whose sealed values
/// do not open with `keys` are left out and counted in `report` (a store
/// without letters gets an empty clear table). The table's count
/// afterwards.
fn letters_back(
    tx: &rusqlite::Transaction<'_>,
    keys: &MetaKeys,
    steps: &mut Steps,
    report: &mut Migration,
) -> Result<i64, RebuildError> {
    match rebuild::shape(tx, LETTERS, LETTERS_KEYED_COLUMN)? {
        Shape::Missing => {
            steps.step()?;
            create_letters(tx, false)?;
            return Ok(0);
        }
        // An older build of the pack sealed the objects only: the letters
        // are clear already.
        Shape::Clear => return Ok(rebuild::count(tx, LETTERS)?),
        Shape::Keyed => {}
    }
    let before = rebuild::count(tx, LETTERS)?;
    steps.step()?;
    tx.execute_batch(&letters_table("custody_letters_v1__new", false))?;
    type Row = (i64, Vec<u8>, Vec<u8>, Vec<u8>, i64, Vec<u8>);
    let letters: Vec<Row> = {
        let mut stmt = tx.prepare(
            "SELECT rowid, kh_letter_digest, page_token, letter, bytes, meta
             FROM custody_letters_v1",
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
    let mut dropped = 0i64;
    for (rowid, kd, token, letter, bytes, meta) in letters {
        steps.step()?;
        let opened = open_meta_in(keys, LETTERS, &kd, &meta).and_then(|meta| {
            let values = (
                hex::decode(&meta.object_digest).ok()?,
                hex::decode(&meta.recipient).ok()?,
                hex::decode(&meta.depositor).ok()?,
            );
            Some((meta, values))
        });
        let payload = at_rest::open_row(keys, LETTER_LABEL, &kd, &letter).ok();
        let (Some((meta, (digest, recipient, depositor))), Some(payload)) = (opened, payload)
        else {
            dropped += 1;
            continue;
        };
        tx.execute(
            "INSERT INTO custody_letters_v1__new
               (rowid, letter_digest, recipient, depositor, page_token, letter, bytes,
                admitted_at_ms, expires_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                rowid,
                digest,
                recipient,
                depositor,
                token,
                &payload[..],
                bytes,
                ms(meta.admitted_at_ms),
                ms(meta.expires_at_ms),
            ],
        )?;
        report.rows += 1;
    }
    steps.step()?;
    tx.execute_batch("DROP TABLE custody_letters_v1;")?;
    steps.step()?;
    tx.execute_batch("ALTER TABLE custody_letters_v1__new RENAME TO custody_letters_v1;")?;
    steps.step()?;
    tx.execute_batch(letter_indexes(false))?;
    report.dropped = report
        .dropped
        .saturating_add(u32::try_from(dropped).unwrap_or(u32::MAX));
    Ok(before - dropped)
}

/// Schema 2 -> 1 (`raven privacy unseal`, PP.18): the same recipe; objects
/// whose sealed values do not open with the keys loaded here are left out
/// and counted (`dropped`), and so is every released digest (only its keyed
/// form is kept, which names nothing once the profile's key is gone: a
/// replay of a released object can then be stored again until it expires,
/// and the recipient's receipts answer it as a duplicate). The count check
/// expects exactly that.
fn migrate_back(
    path: &Path,
    keys: &MetaKeys,
    free: rebuild::FreeBytes<'_>,
) -> Result<Migration, RebuildError> {
    rebuild::space_ok(path, free).map_err(|needed| RebuildError::NoSpace { needed })?;
    let mut steps = Steps::default();
    let mut conn = rebuild::dedicated(path)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let _in_tx = crate::paths::HeldMark::transaction();
    if rebuild::shape(&tx, OBJECTS, KEYED_COLUMN)? != Shape::Keyed {
        return Ok(Migration::already());
    }
    let mut report = Migration::default();
    let expected = back_tables(&tx, keys, &mut steps, &mut report)?;
    steps.step()?;
    rebuild::verify(&tx, &expected)?;
    rebuild::record(&tx, STORE, CLEAR_VERSION, true)?;
    steps.step()?;
    tx.commit()?;
    let scrubbed = rebuild::scrub(&conn, STORE, free)?;
    report.scrub_pending = !scrubbed.complete;
    Ok(report)
}

/// Schema 2 -> 1's tables inside the caller's transaction (the way back,
/// and the first half of a re-key): objects and letters whose sealed values
/// do not open with `keys` are left out and counted in `report`, and so is
/// every released digest. What each table must hold afterwards.
fn back_tables(
    tx: &rusqlite::Transaction<'_>,
    keys: &MetaKeys,
    steps: &mut Steps,
    report: &mut Migration,
) -> Result<Expected, RebuildError> {
    let had_released = !rebuild::columns(tx, RELEASED)?.is_empty();
    let objects_before = rebuild::count(tx, OBJECTS)?;
    let released_before = if had_released {
        rebuild::count(tx, RELEASED)?
    } else {
        0
    };
    steps.step()?;
    tx.execute_batch(&objects_table("custody_objects_v1__new", false))?;
    type Row = (i64, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, i64, Vec<u8>);
    let objects: Vec<Row> = {
        let mut stmt = tx.prepare(
            "SELECT rowid, kh_object_digest, store_tag, page_token, rso1, bytes, meta
             FROM custody_objects_v1",
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
    let mut dropped = 0i64;
    for (rowid, kd, tag, token, rso1, bytes, meta) in objects {
        steps.step()?;
        let opened = open_meta(keys, &kd, &meta).and_then(|meta| {
            let values = (
                hex::decode(&meta.object_digest).ok()?,
                hex::decode(&meta.recipient).ok()?,
                hex::decode(&meta.depositor).ok()?,
            );
            Some((meta, values))
        });
        let payload = at_rest::open_row(keys, RSO1_LABEL, &kd, &rso1).ok();
        let (Some((meta, (digest, recipient, depositor))), Some(payload)) = (opened, payload)
        else {
            dropped += 1;
            continue;
        };
        tx.execute(
            "INSERT INTO custody_objects_v1__new
               (rowid, object_digest, recipient, depositor, store_tag, page_token, rso1, bytes,
                admitted_at_ms, expires_at_ms, released_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, NULL)",
            params![
                rowid,
                digest,
                recipient,
                depositor,
                tag,
                token,
                &payload[..],
                bytes,
                ms(meta.admitted_at_ms),
                ms(meta.expires_at_ms),
            ],
        )?;
        report.rows += 1;
    }
    steps.step()?;
    tx.execute_batch("DROP TABLE custody_objects_v1;")?;
    steps.step()?;
    tx.execute_batch("ALTER TABLE custody_objects_v1__new RENAME TO custody_objects_v1;")?;
    steps.step()?;
    tx.execute_batch(object_indexes(false))?;
    if had_released {
        steps.step()?;
        tx.execute_batch("DROP TABLE custody_released_v1;")?;
    }
    steps.step()?;
    tx.execute_batch(&released_table(RELEASED, false))?;
    report.dropped = u32::try_from(dropped + released_before).unwrap_or(u32::MAX);
    let letters = letters_back(tx, keys, steps, report)?;
    Ok([
        (OBJECTS, objects_before - dropped),
        (RELEASED, 0),
        (LETTERS, letters),
    ])
}

/// Privacy pack PP.17, the eager half of the migration
/// (`privacy::migrate_all`, and the prune passes): in a sealed profile with
/// its keys loaded, an existing clear store moves to schema 2. `true` when
/// it moved now.
pub fn migrate(data_dir: &Path) -> Result<bool, String> {
    if !needs_migration(data_dir) || crate::privacy::mode(data_dir) != Mode::Sealed {
        return Ok(false);
    }
    let (_, migrated) = CustodyStore::open_at(data_dir, &custody_db_path(data_dir))?;
    Ok(migrated)
}

/// Whether the store's header says it is still clear (no SQLite open; a
/// commit still in the WAL is not seen, so `true` may only mean "look").
pub fn needs_migration(data_dir: &Path) -> bool {
    let path = custody_db_path(data_dir);
    path.exists() && rebuild::header_user_version(&path).is_none_or(|v| v < SCHEMA_VERSION)
}

/// The way back (`raven privacy unseal`, PP.18): a schema-2 store moves to
/// schema 1 with the keys this process loaded. Nothing to do without a
/// store or on a clear one.
pub fn unseal(data_dir: &Path) -> Result<Migration, String> {
    let path = custody_db_path(data_dir);
    if !path.exists() {
        return Ok(Migration::already());
    }
    let keys = cached_keys(data_dir)?;
    migrate_back(&path, &keys, &crate::disk_space::free_bytes).map_err(|e| match e {
        RebuildError::Key(key) => format!("friend custody store: {key}"),
        other => format!("{CUSTODY_DB_FILE}: {other}"),
    })
}

/// Schema 2 -> 2 under new keys (`raven privacy rotate-meta`, PP.18): in
/// one IMMEDIATE transaction on a connection that writes nothing before the
/// commit ([`rebuild::rekey_connection`]), both tables go back to their
/// clear columns and forward again, so every keyed value is computed anew
/// and every sealed value sealed under the current epoch; counts checked,
/// then the scrub. Released digests cannot be keyed again (only their keyed
/// form is kept) and are left out, counted (`dropped`), as on the way back.
fn rekey_store(
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
    if rebuild::shape(&tx, OBJECTS, KEYED_COLUMN)? != Shape::Keyed {
        return Ok(Migration::already());
    }
    let mut report = Migration::default();
    back_tables(&tx, keys, &mut steps, &mut report)?;
    let (moved, expected) = forward_tables(&tx, keys, &mut steps)?;
    report.rows = moved;
    rebuild::verify(&tx, &expected)?;
    rebuild::record(&tx, STORE, SCHEMA_VERSION, true)?;
    tx.commit()?;
    let scrubbed = rebuild::scrub(&conn, STORE, free)?;
    report.scrub_pending = !scrubbed.complete;
    Ok(report)
}

/// `raven privacy rotate-meta` (PP.18): a schema-2 store is keyed again
/// with the keys this process holds now (a new `k_index`; the epochs they
/// hold open the old rows). Nothing to do without a store or on a clear
/// one.
pub fn rekey(data_dir: &Path) -> Result<Migration, String> {
    let path = custody_db_path(data_dir);
    if !path.exists() {
        return Ok(Migration::already());
    }
    let keys = cached_keys(data_dir)?;
    rekey_store(&path, &keys, &crate::disk_space::free_bytes).map_err(|e| match e {
        RebuildError::Key(key) => format!("friend custody store: {key}"),
        other => format!("{CUSTODY_DB_FILE}: {other}"),
    })
}

/// A pending scrub (a `VACUUM` or checkpoint a reader held up) is done now:
/// the prune passes. `None` when nothing was pending.
pub fn finish_scrub(data_dir: &Path) -> Option<bool> {
    rebuild::finish_scrub(
        &custody_db_path(data_dir),
        STORE,
        &crate::disk_space::free_bytes,
    )
    .ok()
    .flatten()
}

/// Whether a scrub of the store is pending (`raven privacy status`).
pub fn scrub_pending(data_dir: &Path) -> bool {
    rebuild::scrub_pending(&custody_db_path(data_dir), STORE)
}

// ── Data-key rotation (PP.10 hand-off) ───────────────────────────────────

/// Objects and letters whose sealed values are not on epoch `current` (by
/// their first bytes; no key, no lock): the rotation's old-object count. `0`
/// without a schema-2 store. Released digests hold nothing sealed.
pub fn rows_off_epoch(data_dir: &Path, current: u32) -> Result<u32, String> {
    let path = custody_db_path(data_dir);
    if !path.exists() {
        return Ok(0);
    }
    let conn = Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)
        .map_err(text)?;
    conn.busy_timeout(std::time::Duration::from_secs(2))
        .map_err(text)?;
    if rebuild::shape(&conn, OBJECTS, KEYED_COLUMN).map_err(text)? != Shape::Keyed {
        return Ok(0);
    }
    let epoch = current.to_be_bytes().to_vec();
    let mut n: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM custody_objects_v1
             WHERE substr(meta, 2, 4) != ?1 OR substr(rso1, 2, 4) != ?1",
            params![epoch],
            |r| r.get(0),
        )
        .map_err(text)?;
    if rebuild::shape(&conn, LETTERS, LETTERS_KEYED_COLUMN).map_err(text)? == Shape::Keyed {
        n += conn
            .query_row(
                "SELECT COUNT(*) FROM custody_letters_v1
                 WHERE substr(meta, 2, 4) != ?1 OR substr(letter, 2, 4) != ?1",
                params![epoch],
                |r| r.get::<_, i64>(0),
            )
            .map_err(text)?;
    }
    Ok(u32::try_from(n).unwrap_or(u32::MAX))
}

/// A data-key rotation's step for this store (PP.10): in one IMMEDIATE
/// transaction every sealed value not on the current epoch is opened and
/// sealed again under it, then the WAL is checkpointed. A sealed profile
/// with its keys loaded; nothing to do without a schema-2 store. Values that
/// do not open are left as they are (`unreadable`).
pub fn reseal_rows(data_dir: &Path) -> Result<RowReseal, String> {
    let mut report = RowReseal::default();
    let path = custody_db_path(data_dir);
    if !path.exists() || crate::privacy::mode(data_dir) != Mode::Sealed {
        return Ok(report);
    }
    let keys = cached_keys(data_dir)?;
    let current = keys.current_epoch();
    if rows_off_epoch(data_dir, current)? == 0 {
        return Ok(report);
    }
    let (mut store, _) = CustodyStore::open_at(data_dir, &path)?;
    if store.layout != Layout::Keyed {
        return Ok(report);
    }
    let epoch = current.to_be_bytes().to_vec();
    let tx = store
        .conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(text)?;
    let _in_tx = crate::paths::HeldMark::transaction();
    // (table, keyed digest column, payload column, payload label)
    for (table, digest_col, payload_col, label) in [
        (OBJECTS, KEYED_COLUMN, "rso1", RSO1_LABEL),
        (LETTERS, LETTERS_KEYED_COLUMN, "letter", LETTER_LABEL),
    ] {
        let rows: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = {
            let mut stmt = tx
                .prepare(&format!(
                    "SELECT {digest_col}, {payload_col}, meta FROM {table}
                     WHERE substr(meta, 2, 4) != ?1 OR substr({payload_col}, 2, 4) != ?1"
                ))
                .map_err(text)?;
            let mapped = stmt
                .query_map(params![epoch], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
                .map_err(text)?;
            mapped.collect::<Result<_, _>>().map_err(text)?
        };
        for (kd, payload, meta) in rows {
            let (Ok(plain_meta), Ok(plain_payload)) = (
                at_rest::open_row(&keys, table, &kd, &meta),
                at_rest::open_row(&keys, label, &kd, &payload),
            ) else {
                report.unreadable += 1;
                continue;
            };
            tx.execute(
                &format!(
                    "UPDATE {table} SET {payload_col} = ?2, meta = ?3 WHERE {digest_col} = ?1"
                ),
                params![
                    kd,
                    at_rest::seal_row(&keys, label, &kd, &plain_payload),
                    at_rest::seal_row(&keys, table, &kd, &plain_meta)
                ],
            )
            .map_err(text)?;
            report.resealed += 1;
        }
    }
    tx.commit().map_err(text)?;
    if report.resealed > 0 {
        report.scrub_pending = crate::paths::checkpoint_truncate(&store.conn)
            .map_or(true, |checkpoint| checkpoint.busy);
    }
    Ok(report)
}

/// [`held_recipients`] returns at most this many.
pub const MAX_HELD_RECIPIENTS: usize = 64;

/// The recipients this custodian holds unreleased, unexpired objects for,
/// newest deposit first, at most [`MAX_HELD_RECIPIENTS`]: the contacts a
/// custodian that moved tells (cutoff F8, raven-node's route-hints
/// announcer). Reads only the recipient and the row times (from `meta` in a
/// sealed profile); no store is no recipient (nothing is created).
pub fn held_recipients(data_dir: &Path, now_ms: u64) -> Result<Vec<[u8; 32]>, String> {
    match CustodyStore::open_existing(data_dir)? {
        Some(store) => store.held_recipients(now_ms),
        None => Ok(Vec::new()),
    }
}

/// The recipients this custodian holds unexpired letters for (§10), newest
/// deposit first, at most [`MAX_HELD_RECIPIENTS`]: [`held_recipients`] for
/// the letters (nearby's background advertising, Phase 5 F11d). Reads only
/// the recipient and the row times (from `meta` in a sealed profile); no
/// store is no recipient (nothing is created).
pub fn held_letter_recipients(data_dir: &Path, now_ms: u64) -> Result<Vec<[u8; 32]>, String> {
    match CustodyStore::open_existing(data_dir)? {
        Some(store) => store.held_letter_recipients(now_ms),
        None => Ok(Vec::new()),
    }
}

// ---------------------------------------------------------------------------
// Custodian handler (§6.1, §6.4, §6.5)
// ---------------------------------------------------------------------------

/// Where an inbound frame arrived: the custodian applies the gate per link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InboundLink {
    pub carrier: OutboxCarrier,
    pub source: Option<std::net::IpAddr>,
}

/// The terminal reply that answers request `op` with `code` alone (§4: a
/// letter op's are DEPOSIT_RESULT, FETCH_END and WITHDRAW_RESULT; HANDOFF's
/// HANDOFF_RESULT and TAGS's TAGS_RESULT). Every request op has its own
/// arm: a refusal must never come back as another op's reply.
fn terminal_for(op: u8, code: CustodyCode) -> Rfc1Reply {
    match op {
        OP_DEPOSIT | OP_DEPOSIT_LETTER => Rfc1Reply::DepositResult {
            code,
            digest: [0u8; 32],
        },
        OP_FETCH | OP_FETCH_LETTERS => Rfc1Reply::FetchEnd {
            code,
            returned: 0,
            next: None,
        },
        OP_RELEASE => Rfc1Reply::ReleaseResult { code, released: 0 },
        OP_WITHDRAW_LETTERS => Rfc1Reply::WithdrawResult { code, withdrawn: 0 },
        OP_HANDOFF => Rfc1Reply::HandoffResult {
            code,
            digest: [0u8; 32],
        },
        OP_TAGS => Rfc1Reply::TagsResult {
            code,
            accepted: 0,
            conflicts: 0,
        },
        // Only decoded request ops come here; anything else is unknown.
        _ => Rfc1Reply::Unsupported {
            max_version: RFC1_VERSION,
        },
    }
}

pub(crate) fn pinned_contact(data_dir: &Path, key: &[u8; 32]) -> Result<bool, ()> {
    match crate::outbox::contact_admission(data_dir, key) {
        crate::outbox::ContactAdmission::Allowed(c) => Ok(c.pinned),
        crate::outbox::ContactAdmission::Unreadable => Err(()),
        _ => Ok(false),
    }
}

/// The parties whose custody rows may stay (a depositor, a recipient, a
/// next hop, a tag's registrant): this node's pinned, unblocked contacts,
/// from one read of the contact book and the block list
/// ([`crate::outbox::pinned_unblocked_contacts`]). `None` while either
/// cannot be read (the book held while the profile's key loads, a corrupt
/// file, an I/O error): nobody is known to be gone then, and the prunes
/// drop rows by their expiry only ([`party_stays`]; review handoff-2: every
/// party read as no contact, and every row went).
pub fn custody_parties(data_dir: &Path) -> Option<HashSet<[u8; 32]>> {
    crate::outbox::pinned_unblocked_contacts(data_dir)
        .ok()
        .map(|keys| keys.into_iter().collect())
}

/// A prune's verdict on `key` over [`custody_parties`]: it stays while it
/// is one of `parties`, and everybody stays while they are not known.
pub fn party_stays(parties: Option<&HashSet<[u8; 32]>>, key: &[u8; 32]) -> bool {
    parties.is_none_or(|p| p.contains(key))
}

fn lab_pretend_old() -> bool {
    crate::pair_init::lab_test_a_enabled()
        && std::env::var("RAVEN_LAB_CUSTODY_PRETEND_OLD").as_deref() == Ok("1")
}

/// Debug lab knob (with `RAVEN_LAB_TEST_A=1`; release builds never read it):
/// this listener serves the base ops 0x01-0x03 only and answers every later
/// op `UNSUPPORTED`, as a build from before them (the harness's old
/// custodian). `RAVEN_LAB_CUSTODY_PRETEND_OLD` stays the custodian from
/// before RFC1.
pub const LAB_BASE_OPS_ONLY: &str = "RAVEN_LAB_CUSTODY_BASE_OPS_ONLY";

thread_local! {
    static BASE_OPS_ONLY: Cell<Option<bool>> = const { Cell::new(None) };
}

/// [`LAB_BASE_OPS_ONLY`]: in a debug build this thread's override, else the
/// variable with the Lab Test A unlock.
fn lab_base_ops_only() -> bool {
    if cfg!(debug_assertions) {
        if let Some(on) = BASE_OPS_ONLY.with(Cell::get) {
            return on;
        }
    }
    crate::pair_init::lab_switch(LAB_BASE_OPS_ONLY)
}

/// In-process tests switch [`LAB_BASE_OPS_ONLY`] for the current thread
/// only. Ignored in release builds.
#[doc(hidden)]
pub fn set_lab_base_ops_only_for_this_thread(on: Option<bool>) {
    BASE_OPS_ONLY.with(|cell| cell.set(on));
}

/// Whether this listener serves the letter ops (§10): the letter gate is
/// open ([`crate::horizon::letter_live_enabled`], which needs the friend
/// custody gate) and [`LAB_BASE_OPS_ONLY`] is off.
pub fn letter_ops_served() -> bool {
    crate::horizon::letter_live_enabled() && !lab_base_ops_only()
}

/// Whether this listener serves the handoff ops 0x07-0x08: the handoff gate
/// is open ([`crate::custody_gate::handoff_live`], which needs the friend
/// custody gate) and [`LAB_BASE_OPS_ONLY`] is off.
pub fn handoff_ops_served() -> bool {
    crate::custody_gate::handoff_live() && !lab_base_ops_only()
}

/// An op family this listener does not serve now is unknown here (§4).
fn op_served(op: u8) -> bool {
    if is_letter_op(op) {
        letter_ops_served()
    } else if is_handoff_op(op) {
        handoff_ops_served()
    } else {
        true
    }
}

fn unsupported(req_id: &[u8; 8]) -> Vec<u8> {
    encode_reply(
        req_id,
        &Rfc1Reply::Unsupported {
            max_version: RFC1_VERSION,
        },
    )
}

/// The keeper's own line when it hands sealed mail over (E2 r9: only the
/// count changed): raven-node's, set once at start; `(recipient, released)`.
static HANDED_OVER: std::sync::OnceLock<fn(&[u8; 32], usize)> = std::sync::OnceLock::new();

/// Set raven-node's hook for [`handed_over`] (later calls are ignored).
pub fn set_handover_hook(hook: fn(&[u8; 32], usize)) {
    let _ = HANDED_OVER.set(hook);
}

/// The recipient `to` released `released` objects it collected here: they
/// are handed over and gone from this keeper.
fn handed_over(to: &[u8; 32], released: usize) {
    if let Some(hook) = HANDED_OVER.get() {
        hook(to, released);
    }
}

/// Serve one RFC1 frame from the link peer `noise_ed` (Carol's side). `Err`
/// closes the link (not RFC1 at all); everything else is answered with exactly
/// one terminal reply (FETCH: items first).
pub fn handle_frame(
    data_dir: &Path,
    identity: &Identity,
    noise_ed: &[u8; 32],
    link: &InboundLink,
    frame: &[u8],
    now_ms: u64,
) -> Result<Vec<Vec<u8>>, String> {
    if lab_pretend_old() {
        return Err("lan frame is not RavenEnvelopeV1".into());
    }
    let (req_id, request) = match decode_request(frame).map_err(str::to_string)? {
        RequestDecode::Unsupported(req_id) => return Ok(vec![unsupported(&req_id)]),
        // Letters or handoff off: that op is unknown here, malformed or not
        // (§4, §10).
        RequestDecode::Malformed(req_id, op) if !op_served(op) => {
            return Ok(vec![unsupported(&req_id)])
        }
        RequestDecode::Request(req_id, request) if !op_served(request.op()) => {
            return Ok(vec![unsupported(&req_id)])
        }
        RequestDecode::Malformed(req_id, op) => {
            // The gate and the contact rule still come first.
            let code = gate_and_peer(data_dir, noise_ed, link).unwrap_or(CustodyCode::Malformed);
            let reply = terminal_for(op, code);
            note_depositor(noise_ed, link, std::slice::from_ref(&reply), now_ms);
            return Ok(vec![encode_reply(&req_id, &reply)]);
        }
        RequestDecode::Request(req_id, request) => (req_id, request),
    };
    let op = request.op();
    if let Some(code) = gate_and_peer(data_dir, noise_ed, link) {
        return Ok(vec![encode_reply(&req_id, &terminal_for(op, code))]);
    }
    // A deposit refused only for the depositor's clock (Phase 6 review
    // sensing-5): noted as such, never as a bad object.
    let mut clock_ahead = false;
    let replies = match request {
        Rfc1Request::Deposit { recipient, rso1 } => {
            let (code, digest, ahead) =
                deposit(data_dir, identity, noise_ed, &recipient, &rso1, now_ms);
            clock_ahead = ahead;
            vec![Rfc1Reply::DepositResult { code, digest }]
        }
        Rfc1Request::Fetch {
            tags,
            after,
            max_items,
        } => fetch(data_dir, noise_ed, &tags, after, max_items, now_ms),
        Rfc1Request::Release { digests } => {
            let (code, released) = match CustodyStore::open_existing(data_dir) {
                Ok(None) => (CustodyCode::Ok, 0),
                Ok(Some(mut store)) => match store.release(noise_ed, &digests) {
                    Ok(n) => (CustodyCode::Ok, n),
                    Err(_) => (CustodyCode::Persistence, 0),
                },
                Err(_) => (CustodyCode::Persistence, 0),
            };
            if released > 0 {
                handed_over(noise_ed, usize::from(released));
            }
            vec![Rfc1Reply::ReleaseResult { code, released }]
        }
        Rfc1Request::DepositLetter { recipient, letter } => {
            let (code, digest, ahead) =
                deposit_letter(data_dir, identity, noise_ed, &recipient, &letter, now_ms);
            clock_ahead = ahead;
            vec![Rfc1Reply::DepositResult { code, digest }]
        }
        Rfc1Request::FetchLetters { after, max_items } => {
            fetch_letters(data_dir, noise_ed, after, max_items, now_ms)
        }
        Rfc1Request::WithdrawLetters { digests } => {
            let (code, withdrawn) = match CustodyStore::open_existing(data_dir) {
                Ok(None) => (CustodyCode::Ok, 0),
                Ok(Some(mut store)) => match store.withdraw_letters(noise_ed, &digests) {
                    Ok(n) => (CustodyCode::Ok, n),
                    Err(_) => (CustodyCode::Persistence, 0),
                },
                Err(_) => (CustodyCode::Persistence, 0),
            };
            vec![Rfc1Reply::WithdrawResult { code, withdrawn }]
        }
        // Custody handoff (P5.19): FORWARD or DELIVER, and TAGS; the
        // policy check is the handlers' own.
        Rfc1Request::Handoff { record } => vec![crate::custody_handoff::handoff(
            data_dir, identity, noise_ed, &record, now_ms,
        )],
        Rfc1Request::Tags { action, entries } => vec![crate::custody_handoff::tags(
            data_dir, noise_ed, action, &entries, now_ms,
        )],
    };
    if clock_ahead {
        note_depositor_clock(noise_ed, link);
    } else {
        note_depositor(noise_ed, link, &replies, now_ms);
    }
    Ok(replies.iter().map(|r| encode_reply(&req_id, r)).collect())
}

/// A deposit of the contact's own object (or letter) dated further ahead
/// than the clock skew allows (Phase 6 review sensing-5): its clock runs
/// ahead, most likely (a dual-boot computer keeping local time, a wrong
/// time zone). Noted as `SEC_CLOCK_SKEW` about it, never as a bad object,
/// and never counted towards its throttle ([`note_bad_deposit`]); the
/// answer on the wire stays `REFUSED_OBJECT`.
fn note_depositor_clock(depositor: &[u8; 32], link: &InboundLink) {
    use crate::security_events::{SecKind, Via};
    crate::security_sense::contact(SecKind::ClockSkew, depositor, Via::DirectLink(link.carrier));
}

/// What a contact's request to this custodian was refused for (Phase 6b
/// S19, S20): over its rate or quota (`SEC_DEPOSITOR_FLOOD`), refused or
/// malformed objects (`SEC_DEPOSITOR_BAD_OBJECT`), about the contact as
/// depositor; a forward it had no right to ask (`SEC_HANDOFF_REFUSED`),
/// about it as the forwarder. Only past the gate and the contact rule. Each
/// refused object also counts towards the depositor's throttle (design A
/// R7, [`depositor_throttled`]) before its event is noted.
fn note_depositor(depositor: &[u8; 32], link: &InboundLink, replies: &[Rfc1Reply], now_ms: u64) {
    use crate::security_events::{classify_custody_code, CarrierRole, SecKind, Side, Via};
    if !crate::security_sense::live() {
        return;
    }
    let via = Via::DirectLink(link.carrier);
    for reply in replies {
        let code = match reply {
            Rfc1Reply::DepositResult { code, .. }
            | Rfc1Reply::FetchEnd { code, .. }
            | Rfc1Reply::ReleaseResult { code, .. }
            | Rfc1Reply::WithdrawResult { code, .. }
            | Rfc1Reply::HandoffResult { code, .. }
            | Rfc1Reply::TagsResult { code, .. } => *code,
            Rfc1Reply::FetchItem { .. }
            | Rfc1Reply::LetterItem { .. }
            | Rfc1Reply::Unsupported { .. } => continue,
        };
        match classify_custody_code(code, Side::Custodian) {
            None => {}
            Some(SecKind::HandoffRefused) => crate::security_sense::carrier(
                SecKind::HandoffRefused,
                depositor,
                CarrierRole::Depositor,
                via,
            ),
            Some(kind) => {
                if kind == SecKind::DepositorBadObject {
                    note_bad_deposit(depositor, now_ms);
                }
                crate::security_sense::contact(kind, depositor, via)
            }
        }
    }
}

/// §6.1 steps 2-3: the gate for this link, then a pinned contact. `None`: go on.
fn gate_and_peer(data_dir: &Path, noise_ed: &[u8; 32], link: &InboundLink) -> Option<CustodyCode> {
    use crate::custody_gate::{carrier_gates_now, custody_link_allowed, CustodyGates};
    if !custody_link_allowed(
        CustodyGates::current(),
        carrier_gates_now(),
        link.carrier,
        link.source,
    ) {
        return Some(CustodyCode::Hold);
    }
    match pinned_contact(data_dir, noise_ed) {
        Ok(true) => None,
        Ok(false) => Some(CustodyCode::NotVerified),
        Err(()) => Some(CustodyCode::Persistence),
    }
}

/// §6.4. The answer, the object's digest, and whether the refusal was
/// only the depositor's clock running ahead: its own signed object dated
/// past the clock skew (Phase 6 review sensing-5; the wire answer is
/// `REFUSED_OBJECT` either way).
fn deposit(
    data_dir: &Path,
    identity: &Identity,
    depositor: &[u8; 32],
    recipient: &[u8; 32],
    rso1: &[u8],
    now_ms: u64,
) -> (CustodyCode, [u8; 32], bool) {
    use crate::carrier_admission::CustodyRefusal;
    let zero = [0u8; 32];
    match crate::node_policy::try_load_policy(data_dir) {
        Ok(policy) if policy.custody => {}
        _ => return (CustodyCode::PolicyDenied, zero, false),
    }
    if depositor_throttled(depositor, now_ms)
        || !charge(
            &DEPOSIT_WINDOWS,
            *depositor,
            MAX_DEPOSITS_PER_MINUTE,
            now_ms,
        )
    {
        return (CustodyCode::RateLimited, zero, false);
    }
    let Ok((object, env)) = check_rfc1_rso1(rso1) else {
        return (CustodyCode::Malformed, zero, false);
    };
    let digest = custody_digest(&object.packed_envelope);
    match crate::carrier_admission::admit_relayable(&object.packed_envelope, now_ms) {
        Ok(_) => {}
        Err(CustodyRefusal::Expired) => return (CustodyCode::Expired, digest, false),
        Err(CustodyRefusal::FromTheFuture) => {
            let ahead = canonical_outbound_fields(&env) && env.verify(depositor);
            return (CustodyCode::RefusedObject, digest, ahead);
        }
        Err(_) => return (CustodyCode::RefusedObject, digest, false),
    }
    if !canonical_outbound_fields(&env) || !env.verify(depositor) {
        return (CustodyCode::RefusedObject, digest, false);
    }
    if recipient == depositor
        || *recipient == identity.public_key_bytes()
        || !matches!(pinned_contact(data_dir, recipient), Ok(true))
    {
        return (CustodyCode::RecipientNotAccepted, digest, false);
    }
    let code = CustodyStore::open_or_create(data_dir).and_then(|mut store| {
        store.deposit(
            &digest,
            recipient,
            depositor,
            &object.store_tag,
            rso1,
            env.expires_at,
            now_ms,
        )
    });
    (code.unwrap_or(CustodyCode::Persistence), digest, false)
}

/// §10 DEPOSIT_LETTER, after the gate and the contact rule: custody on, the
/// depositor's rate window, letter admission (the header only), the
/// depositor is the letter's signer, the letter names the DEPOSIT's
/// recipient, which is a pinned contact other than the depositor and this
/// node, then the caps. The letter itself stays opaque. As [`deposit`]: the
/// answer, the digest, and whether the refusal was only the depositor's
/// clock (its own signed letter dated past the clock skew).
fn deposit_letter(
    data_dir: &Path,
    identity: &Identity,
    depositor: &[u8; 32],
    recipient: &[u8; 32],
    letter: &[u8],
    now_ms: u64,
) -> (CustodyCode, [u8; 32], bool) {
    use crate::async_letter::{decode_header, letter_digest, verify_signature};
    use crate::carrier_admission::{admit_letter, CustodyRefusal};
    let zero = [0u8; 32];
    match crate::node_policy::try_load_policy(data_dir) {
        Ok(policy) if policy.custody => {}
        _ => return (CustodyCode::PolicyDenied, zero, false),
    }
    if depositor_throttled(depositor, now_ms)
        || !charge(
            &DEPOSIT_WINDOWS,
            *depositor,
            MAX_DEPOSITS_PER_MINUTE,
            now_ms,
        )
    {
        return (CustodyCode::RateLimited, zero, false);
    }
    let signed_by_depositor = |header: &crate::async_letter::Ral1Header| {
        header.sender_device == *depositor && verify_signature(letter, header).is_ok()
    };
    let header = match admit_letter(letter, now_ms) {
        Ok(header) => header,
        Err(CustodyRefusal::Malformed | CustodyRefusal::TooLarge) => {
            return (CustodyCode::Malformed, zero, false)
        }
        Err(CustodyRefusal::Expired) => {
            return (CustodyCode::Expired, letter_digest(letter), false)
        }
        Err(CustodyRefusal::FromTheFuture) => {
            let ahead = decode_header(letter).is_ok_and(|h| signed_by_depositor(&h));
            return (CustodyCode::RefusedObject, letter_digest(letter), ahead);
        }
        Err(_) => return (CustodyCode::RefusedObject, letter_digest(letter), false),
    };
    let digest = letter_digest(letter);
    if !signed_by_depositor(&header) || header.recipient_device != *recipient {
        return (CustodyCode::RefusedObject, digest, false);
    }
    if recipient == depositor
        || *recipient == identity.public_key_bytes()
        || !matches!(pinned_contact(data_dir, recipient), Ok(true))
    {
        return (CustodyCode::RecipientNotAccepted, digest, false);
    }
    let code = CustodyStore::open_or_create(data_dir).and_then(|mut store| {
        store.deposit_letter(
            &digest,
            recipient,
            depositor,
            letter,
            header.expires_at_ms,
            now_ms,
        )
    });
    (code.unwrap_or(CustodyCode::Persistence), digest, false)
}

/// §10 FETCH_LETTERS: the link peer's letters (items), then FETCH_END.
fn fetch_letters(
    data_dir: &Path,
    fetcher: &[u8; 32],
    after: Option<[u8; 32]>,
    max_items: u8,
    now_ms: u64,
) -> Vec<Rfc1Reply> {
    let end = |code, returned, next| Rfc1Reply::FetchEnd {
        code,
        returned,
        next,
    };
    if !charge(&FETCH_WINDOWS, *fetcher, MAX_FETCHES_PER_MINUTE, now_ms) {
        return vec![end(CustodyCode::RateLimited, 0, None)];
    }
    let page = match CustodyStore::open_existing(data_dir) {
        Ok(None) => FetchPage::default(),
        Ok(Some(store)) => match store.fetch_letters(fetcher, after, max_items, now_ms) {
            Ok(page) => page,
            Err(_) => return vec![end(CustodyCode::Persistence, 0, None)],
        },
        Err(_) => return vec![end(CustodyCode::Persistence, 0, None)],
    };
    let returned = page.items.len() as u8;
    let mut out: Vec<Rfc1Reply> = page
        .items
        .into_iter()
        .map(|letter| Rfc1Reply::LetterItem { letter })
        .collect();
    out.push(end(CustodyCode::Ok, returned, page.next));
    out
}

/// §6.5 FETCH: items, then FETCH_END.
fn fetch(
    data_dir: &Path,
    fetcher: &[u8; 32],
    tags: &[[u8; 16]],
    after: Option<[u8; 32]>,
    max_items: u8,
    now_ms: u64,
) -> Vec<Rfc1Reply> {
    let end = |code, returned, next| Rfc1Reply::FetchEnd {
        code,
        returned,
        next,
    };
    if !charge(&FETCH_WINDOWS, *fetcher, MAX_FETCHES_PER_MINUTE, now_ms) {
        return vec![end(CustodyCode::RateLimited, 0, None)];
    }
    let page = match CustodyStore::open_existing(data_dir) {
        Ok(None) => FetchPage::default(),
        Ok(Some(store)) => match store.fetch(fetcher, tags, after, max_items, now_ms) {
            Ok(page) => page,
            Err(_) => return vec![end(CustodyCode::Persistence, 0, None)],
        },
        Err(_) => return vec![end(CustodyCode::Persistence, 0, None)],
    };
    let returned = page.items.len() as u8;
    let mut out: Vec<Rfc1Reply> = page
        .items
        .into_iter()
        .map(|rso1| Rfc1Reply::FetchItem { rso1 })
        .collect();
    out.push(end(CustodyCode::Ok, returned, page.next));
    out
}

/// §6.6 maintenance (every durable prune), only if the store exists:
/// expired objects go, and those of a party that is no longer a pinned,
/// unblocked contact, the latter only while the contact book and the block
/// list can be read ([`custody_parties`]).
pub fn maintain(data_dir: &Path, now_ms: u64) -> Result<usize, String> {
    let Some(mut store) = CustodyStore::open_existing(data_dir)? else {
        return Ok(0);
    };
    let parties = custody_parties(data_dir);
    store.maintain(now_ms, &|key| party_stays(parties.as_ref(), key))
}

#[cfg(test)]
mod tests;
