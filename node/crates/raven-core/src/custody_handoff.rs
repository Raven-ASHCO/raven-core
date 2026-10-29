//! Custody handoff V1 (`protocol/RAVEN_CUSTODY_HANDOFF_V1.md`): multi-hop
//! friend custody, A -> F1 -> F2 -> B, inside RFC1 version byte 1.
//!
//! This module holds the RHW1 record ("Raven Hop Wrapper" v1), the body of
//! the RFC1 op 0x07 HANDOFF, and the TAGS action of op 0x08
//! ([`crate::friend_custody`] frames both). A FORWARD asks the origin's
//! custodian to hand the object on to the named final custodian; a DELIVER
//! hands it to the final custodian, which stores it for the recipient that
//! registered its tag (TAGS REGISTER). The record carries no recipient key,
//! no path and no hop counter: only the outer signer may FORWARD and a
//! DELIVER never creates a forward, so a path has at most two custodians.
//!
//! Everything is behind [`crate::custody_gate::handoff_live`]: a listener
//! with that gate closed answers both ops `UNSUPPORTED`, as one built before
//! them.
//!
//! **The custodian (Phase 5 P5.19, spec §3.1, §3.3, §3.4)**: [`handoff`]
//! serves a HANDOFF (FORWARD into the handoff store, DELIVER into the RFC1
//! custody store for the tag's registered recipient) and [`tags`] a TAGS
//! frame, both after `friend_custody::handle_frame`'s gate and contact
//! checks; [`maintain`] runs with every durable prune. The store is
//! [`HandoffStore`] (`custody_handoff.sqlite`).

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use crate::envelope::Envelope;
use crate::friend_custody::{
    canonical_outbound_fields, charge, check_rfc1_rso1, custody_digest, custody_parties,
    party_stays, pinned_contact, CustodyCode, CustodyStore, Rfc1Reply, Window, DEPOSIT_WINDOWS,
    MAX_DEPOSITS_PER_MINUTE, MIN_RFC1_RSO1, RFC1_HEADER_LEN,
};
use crate::identity::Identity;
use crate::store_object::StoreObject;

mod store;

pub use store::{
    finish_scrub, handoff_db_path, migrate, needs_migration, rekey, reseal_rows, rows_off_epoch,
    scrub_pending, unseal, DueForward, HandoffStore, HandoffUsage, TagState, TagsOutcome,
    HANDOFF_DB_FILE, MAX_FORWARD_BYTES_PER_MINUTE, MAX_FORWARD_DEPOSITOR_BYTES,
    MAX_FORWARD_DEPOSITOR_ROWS, MAX_FORWARD_NODE_BYTES, MAX_FORWARD_NODE_ROWS,
    MAX_FORWARD_PAIR_ROWS, MAX_NEXT_HOPS_PER_DIGEST, MAX_NODE_TAGS, MAX_TAGS_PER_RECIPIENT,
    MAX_TAG_TTL_MS, STATE_HANDED, STATE_PENDING, STATE_REFUSED,
};

pub const RHW1_MAGIC: [u8; 4] = *b"RHW1";
pub const RHW1_VERSION: u8 = 1;
/// `magic[4] | version | kind | flags | reserved | next_hop[32] | rso1_len u32`.
pub const RHW1_FIXED_LEN: usize = 44;
/// A HANDOFF frame (RFC1 header + RHW1) is one transport plaintext.
pub const MAX_RHW1_RSO1: usize =
    crate::lan_noise::MAX_TRANSPORT_PLAINTEXT - RFC1_HEADER_LEN - RHW1_FIXED_LEN;
/// RSO1 header without a custody signature (Store Object V1).
const RSO1_FIXED_LEN: usize = 59;
pub const MAX_RHW1_ENVELOPE: usize = MAX_RHW1_RSO1 - RSO1_FIXED_LEN;
/// The largest LAN send (text cap + sealed overhead + RVN1 prefix + signature)
/// always fits a handoff, as it fits RFC1 custody.
const _: () =
    assert!(crate::lan_noise::MAX_LAN_ENDPOINT_TEXT + 26 + 16 + 86 + 64 <= MAX_RHW1_ENVELOPE);
const _: () = assert!(MAX_RHW1_RSO1 == 65_461 && MAX_RHW1_ENVELOPE == 65_402);
const _: () = assert!(MAX_RHW1_ENVELOPE <= crate::friend_custody::MAX_RFC1_ENVELOPE);

/// TAGS: `count u8 (1..=32)` entries per frame.
pub const MAX_TAG_ENTRIES: usize = 32;

/// What a HANDOFF asks of its custodian.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Rhw1Kind {
    /// Origin -> first custodian: hand the object on to `next_hop`.
    Forward = 1,
    /// First -> final custodian: hold it for the tag's registered recipient.
    Deliver = 2,
}

/// One RHW1 record (§1 of the spec).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rhw1 {
    pub kind: Rhw1Kind,
    /// FORWARD: the final custodian's Ed25519 contact key (non-zero);
    /// DELIVER: 32 zero bytes.
    pub next_hop: [u8; 32],
    /// The RSO1 object, by RFC1's rules ([`check_rhw1_rso1`]).
    pub rso1: Vec<u8>,
}

impl Rhw1 {
    /// A FORWARD to `next_hop`.
    pub fn forward(next_hop: [u8; 32], rso1: Vec<u8>) -> Self {
        Self {
            kind: Rhw1Kind::Forward,
            next_hop,
            rso1,
        }
    }

    /// A DELIVER (no next hop).
    pub fn deliver(rso1: Vec<u8>) -> Self {
        Self {
            kind: Rhw1Kind::Deliver,
            next_hop: [0u8; 32],
            rso1,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(RHW1_FIXED_LEN + self.rso1.len());
        out.extend_from_slice(&RHW1_MAGIC);
        out.push(RHW1_VERSION);
        out.push(self.kind as u8);
        out.push(0); // flags
        out.push(0); // reserved
        out.extend_from_slice(&self.next_hop);
        out.extend_from_slice(&(self.rso1.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.rso1);
        out
    }

    /// Strict decode: every rule broken is an error (the HANDOFF is then
    /// answered `MALFORMED`). The RSO1 inside is only bounded here; its
    /// own rules are [`check_rhw1_rso1`].
    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < RHW1_FIXED_LEN || bytes[..4] != RHW1_MAGIC {
            return Err("RHW1_MALFORMED_HEADER");
        }
        if bytes[4] != RHW1_VERSION {
            return Err("RHW1_VERSION");
        }
        let kind = match bytes[5] {
            1 => Rhw1Kind::Forward,
            2 => Rhw1Kind::Deliver,
            _ => return Err("RHW1_KIND"),
        };
        if bytes[6] != 0 || bytes[7] != 0 {
            return Err("RHW1_FLAGS");
        }
        let mut next_hop = [0u8; 32];
        next_hop.copy_from_slice(&bytes[8..40]);
        let zero = next_hop == [0u8; 32];
        if kind == Rhw1Kind::Forward && zero {
            return Err("RHW1_FORWARD_NO_HOP");
        }
        if kind == Rhw1Kind::Deliver && !zero {
            return Err("RHW1_DELIVER_HOP");
        }
        let n = u32::from_be_bytes([bytes[40], bytes[41], bytes[42], bytes[43]]) as usize;
        if !(MIN_RFC1_RSO1..=MAX_RHW1_RSO1).contains(&n) {
            return Err("RHW1_RSO1_LEN");
        }
        if bytes.len() != RHW1_FIXED_LEN + n {
            return Err("RHW1_LENGTH");
        }
        Ok(Self {
            kind,
            next_hop,
            rso1: bytes[RHW1_FIXED_LEN..].to_vec(),
        })
    }
}

/// RSO1 inside RHW1: RFC1's rules ([`check_rfc1_rso1`]: no custody
/// signature, lifetime equal to the envelope's) with the tighter handoff
/// bounds.
pub fn check_rhw1_rso1(rso1: &[u8]) -> Result<(StoreObject, Envelope), &'static str> {
    if rso1.len() > MAX_RHW1_RSO1 {
        return Err("RHW1_RSO1_TOO_LARGE");
    }
    let (object, env) = check_rfc1_rso1(rso1)?;
    if object.packed_envelope.len() > MAX_RHW1_ENVELOPE {
        return Err("RHW1_RSO1_TOO_LARGE");
    }
    Ok((object, env))
}

/// The action of a TAGS frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TagsAction {
    /// Register (or extend) the link peer's inbound store tags; every
    /// entry carries a non-zero expiry.
    Register = 1,
    /// Withdraw the link peer's own tags; every expiry is zero.
    Withdraw = 2,
}

impl TagsAction {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Register),
            2 => Some(Self::Withdraw),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Custodian handlers (spec §3.1, §3.3, §3.4)
// ---------------------------------------------------------------------------

/// TAGS frames one registrant may send per minute (its own window).
pub const MAX_TAGS_PER_MINUTE: u32 = 30;

/// The per-registrant TAGS window (in memory: a throttle, not a quota).
pub(crate) static TAGS_WINDOWS: Mutex<Option<HashMap<[u8; 32], Window>>> = Mutex::new(None);

/// Custody and custody handoff are both on in this node's policy.
fn handoff_allowed(data_dir: &Path) -> bool {
    crate::node_policy::try_load_policy(data_dir)
        .is_ok_and(|policy| policy.custody && policy.custody_handoff)
}

/// An admitted object: its RSO1, its envelope and its custody digest.
type Admitted = (StoreObject, Envelope, [u8; 32]);

/// The checks a FORWARD and a DELIVER share (spec §3.1 steps 3-7, after
/// the gate and the contact rule): the policy, the attempt window shared
/// with DEPOSIT, the RSO1 rules, custody admission and the canonical hop
/// fields. The object, its envelope and its digest; or the refusal.
fn admit(
    data_dir: &Path,
    depositor: &[u8; 32],
    rso1: &[u8],
    now_ms: u64,
) -> Result<Admitted, (CustodyCode, [u8; 32])> {
    let zero = [0u8; 32];
    if !handoff_allowed(data_dir) {
        return Err((CustodyCode::PolicyDenied, zero));
    }
    // Phase 6b R7: a depositor whose objects kept being refused.
    if crate::friend_custody::depositor_throttled(depositor, now_ms) {
        return Err((CustodyCode::RateLimited, zero));
    }
    if !charge(
        &DEPOSIT_WINDOWS,
        *depositor,
        MAX_DEPOSITS_PER_MINUTE,
        now_ms,
    ) {
        return Err((CustodyCode::RateLimited, zero));
    }
    let Ok((object, env)) = check_rhw1_rso1(rso1) else {
        return Err((CustodyCode::Malformed, zero));
    };
    let digest = custody_digest(&object.packed_envelope);
    match crate::carrier_admission::admit_relayable(&object.packed_envelope, now_ms) {
        Ok(_) => {}
        Err(crate::carrier_admission::CustodyRefusal::Expired) => {
            return Err((CustodyCode::Expired, digest))
        }
        Err(_) => return Err((CustodyCode::RefusedObject, digest)),
    }
    if !canonical_outbound_fields(&env) {
        return Err((CustodyCode::RefusedObject, digest));
    }
    Ok((object, env, digest))
}

/// HANDOFF/FORWARD from the link peer `depositor` (spec §3.1): only the
/// envelope's outer signer may ask for a further hop (`HOP_REFUSED`); the
/// next hop is a pinned, unblocked contact other than the depositor and
/// this node (`NEXT_HOP_UNKNOWN`); then the store's transaction. The store
/// is created by the first FORWARD that gets this far.
pub fn forward(
    data_dir: &Path,
    identity: &Identity,
    depositor: &[u8; 32],
    record: &Rhw1,
    now_ms: u64,
) -> (CustodyCode, [u8; 32]) {
    let (object, env, digest) = match admit(data_dir, depositor, &record.rso1, now_ms) {
        Ok(admitted) => admitted,
        Err(refusal) => return refusal,
    };
    if !env.verify(depositor) {
        return (CustodyCode::HopRefused, digest);
    }
    let next_hop = record.next_hop;
    if next_hop == *depositor
        || next_hop == identity.public_key_bytes()
        || !matches!(pinned_contact(data_dir, &next_hop), Ok(true))
    {
        return (CustodyCode::NextHopUnknown, digest);
    }
    let code = HandoffStore::open_or_create(data_dir).and_then(|mut store| {
        store.forward(
            &digest,
            &next_hop,
            depositor,
            &object.store_tag,
            &record.rso1,
            env.expires_at,
            now_ms,
        )
    });
    (code.unwrap_or(CustodyCode::Persistence), digest)
}

/// HANDOFF/DELIVER from the link peer `depositor` (spec §3.3): no signer
/// check (the recipient's ingest checks the outer signature against its
/// own session peer); the RSO1 store tag's live, unconflicted registration
/// names the recipient (`TAG_UNKNOWN`, creating nothing, or `CONFLICT`),
/// which is neither the depositor (a forwarder squatting a tag) nor this
/// node and is a pinned contact (`RECIPIENT_NOT_ACCEPTED`); then the object
/// is stored exactly as an RFC1 DEPOSIT, every RFC1 cap with depositor =
/// the forwarder.
pub fn deliver(
    data_dir: &Path,
    identity: &Identity,
    depositor: &[u8; 32],
    record: &Rhw1,
    now_ms: u64,
) -> (CustodyCode, [u8; 32]) {
    let (object, env, digest) = match admit(data_dir, depositor, &record.rso1, now_ms) {
        Ok(admitted) => admitted,
        Err(refusal) => return refusal,
    };
    let held = match HandoffStore::open_existing(data_dir) {
        Ok(None) => Ok(TagState::Unknown),
        Ok(Some(store)) => store.tag_recipient(&object.store_tag, now_ms),
        Err(e) => Err(e),
    };
    let recipient = match held {
        Ok(TagState::Live(recipient)) => recipient,
        Ok(TagState::Unknown) => return (CustodyCode::TagUnknown, digest),
        Ok(TagState::Conflicted) => return (CustodyCode::Conflict, digest),
        Err(_) => return (CustodyCode::Persistence, digest),
    };
    if recipient == *depositor
        || recipient == identity.public_key_bytes()
        || !matches!(pinned_contact(data_dir, &recipient), Ok(true))
    {
        return (CustodyCode::RecipientNotAccepted, digest);
    }
    let code = CustodyStore::open_or_create(data_dir).and_then(|mut store| {
        store.deposit(
            &digest,
            &recipient,
            depositor,
            &object.store_tag,
            &record.rso1,
            env.expires_at,
            now_ms,
        )
    });
    (code.unwrap_or(CustodyCode::Persistence), digest)
}

/// One HANDOFF (either kind), answered HANDOFF_RESULT.
pub fn handoff(
    data_dir: &Path,
    identity: &Identity,
    depositor: &[u8; 32],
    record: &Rhw1,
    now_ms: u64,
) -> Rfc1Reply {
    let (code, digest) = match record.kind {
        Rhw1Kind::Forward => forward(data_dir, identity, depositor, record, now_ms),
        Rhw1Kind::Deliver => deliver(data_dir, identity, depositor, record, now_ms),
    };
    Rfc1Reply::HandoffResult { code, digest }
}

/// TAGS from the link peer `registrant` (spec §3.4): the policy, its own
/// window of [`MAX_TAGS_PER_MINUTE`], then REGISTER
/// ([`HandoffStore::register`]; the store is created only for an entry
/// that is still live) or WITHDRAW of its own unconflicted tags. Answered
/// TAGS_RESULT (`accepted`: registered or extended, or withdrawn).
pub fn tags(
    data_dir: &Path,
    registrant: &[u8; 32],
    action: TagsAction,
    entries: &[([u8; 16], u64)],
    now_ms: u64,
) -> Rfc1Reply {
    let result = |code, accepted, conflicts| Rfc1Reply::TagsResult {
        code,
        accepted,
        conflicts,
    };
    if !handoff_allowed(data_dir) {
        return result(CustodyCode::PolicyDenied, 0, 0);
    }
    if !charge(&TAGS_WINDOWS, *registrant, MAX_TAGS_PER_MINUTE, now_ms) {
        return result(CustodyCode::RateLimited, 0, 0);
    }
    match action {
        TagsAction::Register => {
            if !entries.iter().any(|(_, expires)| *expires > now_ms) {
                return result(CustodyCode::Ok, 0, 0);
            }
            match HandoffStore::open_or_create(data_dir)
                .and_then(|mut store| store.register(registrant, entries, now_ms))
            {
                Ok(outcome) => result(outcome.code, outcome.accepted, outcome.conflicts),
                Err(_) => result(CustodyCode::Persistence, 0, 0),
            }
        }
        TagsAction::Withdraw => {
            let tags: Vec<[u8; 16]> = entries.iter().map(|(tag, _)| *tag).collect();
            match HandoffStore::open_existing(data_dir) {
                Ok(None) => result(CustodyCode::Ok, 0, 0),
                Ok(Some(mut store)) => match store.withdraw(registrant, &tags) {
                    Ok(n) => result(CustodyCode::Ok, n, 0),
                    Err(_) => result(CustodyCode::Persistence, 0, 0),
                },
                Err(_) => result(CustodyCode::Persistence, 0, 0),
            }
        }
    }
}

/// Every durable prune, only if the store exists: expired rows, and those
/// of parties that are no longer pinned, unblocked contacts, go (and old
/// quarantined copies). Who is still a contact is read once
/// ([`custody_parties`]); while the contact book or the block list cannot
/// be read, only expired rows go (review handoff-2).
pub fn maintain(data_dir: &Path, now_ms: u64) -> Result<usize, String> {
    store::drop_old_quarantine(data_dir, now_ms);
    let Some(mut store) = HandoffStore::open_existing(data_dir)? else {
        return Ok(0);
    };
    let parties = custody_parties(data_dir);
    store.maintain(now_ms, &|key| party_stays(parties.as_ref(), key))
}

#[cfg(test)]
mod tests;
