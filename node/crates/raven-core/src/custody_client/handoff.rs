//! The requester and forwarder side of custody handoff (Phase 5 P5.20;
//! `protocol/RAVEN_CUSTODY_HANDOFF_V1.md` §3.2, §3.5): which custodian gets
//! an RFC1 DEPOSIT and which a HANDOFF/FORWARD ([`custody_plan`], pure, over
//! the peer's RRH1 custodian entries read by [`announced_custodians`]), and
//! the forwarder's DELIVER dial to the final custodian ([`forward_round`]),
//! pure over a `dial` closure like the base ops. The batch that carries the
//! plan's FORWARDs is [`super::custody_batch`]; the recipient's tag
//! registration rides [`super::fetch_round_with`].
//!
//! Nothing here sends a handoff frame while the handoff gate is closed
//! ([`crate::custody_gate::handoff_live`]), and an `UNSUPPORTED` answer is
//! kept in the one per-custodian [`CapabilityCache`] (24 h: the handoff
//! park of spec §2).

use std::path::Path;

use super::{
    deposit_chunks, index_of, req_id, CapabilityCache, CustodianCapability, CustodianDial,
    ItemAnswer,
};
use crate::custody_handoff::{DueForward, Rhw1};
use crate::friend_custody::{decode_reply, encode_request, Rfc1Reply, Rfc1Request};
use crate::learned_routes::LearnedCustody;
use crate::route_hints::{custodian_tag, CUSTODIAN_FLAG_HANDOFF_INBOX};

/// One custodian a peer announced to this node (RRH1 §12, resolved against
/// this node's own contacts), and whether it takes custody handoffs for
/// that peer (`HANDOFF_INBOX`, [`CUSTODIAN_FLAG_HANDOFF_INBOX`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Announced {
    pub key: [u8; 32],
    pub handoff_inbox: bool,
}

/// Whether handoff is parked at a custodian (`None`: every handoff there)
/// or for a pair (custodian, next hop).
pub type HandoffParked<'a> = dyn Fn(&[u8; 32], Option<&[u8; 32]>) -> bool + 'a;

/// The forwarder's answer per row sent: `(digest, answer)`.
pub type ForwardAnswers = Vec<([u8; 32], Option<ItemAnswer>)>;

/// What to do with an object at one listed custodian.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanStep {
    /// RFC1 DEPOSIT at this custodian.
    Deposit([u8; 32]),
    /// HANDOFF/FORWARD at `via`, which hands the object on to `next_hop`.
    Forward { via: [u8; 32], next_hop: [u8; 32] },
}

/// Where an object for `peer` goes, per listed custodian C (spec §3.5),
/// pure:
/// - no fresh announcement from `peer` (`announced` is `None`): DEPOSIT at
///   every C (Phase 3);
/// - C is in the announced set: DEPOSIT;
/// - otherwise, while handoff is live and C is not handoff-parked: FORWARD
///   at C to the first announced H with `HANDOFF_INBOX` that is neither C,
///   `local` nor `peer` and whose pair (C, H) is not parked (one next hop
///   per C);
/// - when no FORWARD is possible there (the gate is closed, C or every
///   (C, H) is handoff-parked, no H): DEPOSIT, as before handoff, so this
///   plan is Phase 3's whenever handoff is off.
///
/// `plain_parked(C)` (the RFC1 park of C for this peer, as
/// RECIPIENT_NOT_ACCEPTED's) blocks only DEPOSIT steps; `handoff_parked(C,
/// None)` parks every handoff at C and `handoff_parked(C, Some(H))` the pair.
pub fn custody_plan(
    listed: &[[u8; 32]],
    announced: Option<&[Announced]>,
    handoff_live: bool,
    peer: &[u8; 32],
    local: &[u8; 32],
    plain_parked: &dyn Fn(&[u8; 32]) -> bool,
    handoff_parked: &HandoffParked<'_>,
) -> Vec<PlanStep> {
    let deposit = |c: &[u8; 32]| (!plain_parked(c)).then_some(PlanStep::Deposit(*c));
    let Some(ann) = announced else {
        return listed.iter().filter_map(deposit).collect();
    };
    listed
        .iter()
        .filter_map(|c| {
            if ann.iter().any(|a| a.key == *c) {
                return deposit(c);
            }
            let next_hop = if handoff_live && !handoff_parked(c, None) {
                ann.iter()
                    .filter(|a| a.handoff_inbox && a.key != *c && a.key != *local && a.key != *peer)
                    .map(|a| a.key)
                    .find(|h| !handoff_parked(c, Some(h)))
            } else {
                None
            };
            match next_hop {
                Some(next_hop) => Some(PlanStep::Forward { via: *c, next_hop }),
                None => deposit(c),
            }
        })
        .collect()
}

/// The custodians `peer` announced to this node, from its live RRH1
/// snapshot (Phase 3's custodian entries, the learned-routes cache): each
/// CUSTODIAN_TAG matched against this node's pinned, unblocked contacts (§12.1,
/// in the peer's order), with its `HANDOFF_INBOX` bit, then Phase 2's plain
/// keys that are such contacts (no flags: no handoff inbox). `None` when
/// there is no fresh announcement: learned custody is off
/// ([`crate::custody_gate::custody_hints_live`]), `peer` has no live
/// snapshot, or that snapshot names no custodian.
pub fn announced_custodians(
    data_dir: &Path,
    local: &[u8; 32],
    peer: &[u8; 32],
    now_ms: u64,
) -> Option<Vec<Announced>> {
    if !crate::custody_gate::custody_hints_live() {
        return None;
    }
    let told = crate::learned_routes::learned_custody(data_dir, peer, now_ms)?;
    if told.tags.is_empty() && told.plain.is_empty() {
        return None;
    }
    let book = crate::outbox::pinned_unblocked_contacts(data_dir).unwrap_or_default();
    Some(announced_from(&told, &book, local, peer))
}

/// [`announced_custodians`] from a snapshot's custody fields and the book
/// (pinned, unblocked contacts), pure. Never `peer` or `local`; each
/// custodian once (a tag and a plain key naming the same one: the tag's
/// flags).
pub fn announced_from(
    told: &LearnedCustody,
    book: &[[u8; 32]],
    local: &[u8; 32],
    peer: &[u8; 32],
) -> Vec<Announced> {
    let candidates: Vec<&[u8; 32]> = book.iter().filter(|c| *c != peer && *c != local).collect();
    let mut out: Vec<Announced> = Vec::new();
    for (i, tag) in told.tags.iter().enumerate() {
        let Some(c) = candidates
            .iter()
            .find(|c| custodian_tag(peer, local, c) == *tag)
        else {
            continue; // a custodian this node does not know: nothing learned
        };
        if out.iter().any(|a| a.key == **c) {
            continue;
        }
        let flags = told.tag_flags.get(i).copied().unwrap_or(0);
        out.push(Announced {
            key: **c,
            handoff_inbox: flags & CUSTODIAN_FLAG_HANDOFF_INBOX != 0,
        });
    }
    for key in &told.plain {
        if candidates.contains(&key) && !out.iter().any(|a| a.key == *key) {
            out.push(Announced {
                key: *key,
                handoff_inbox: false,
            });
        }
    }
    out
}

/// The refusal [`forward_round`] gives without dialling while this node's
/// handoff gate is closed: not a dial error (no strike).
pub fn handoff_gate_closed() -> String {
    crate::custody_gate::HANDOFF_HOLD.to_string()
}

/// Request-id salt of the forwarder's HANDOFF/DELIVER frames.
const SALT_DELIVER: u8 = 0xB0;

/// One forwarder dial to the final custodian `next_hop` (spec §3.2): the
/// first run of `rows` held for it (others are skipped), at most
/// [`super::MAX_DEPOSITS_PER_DIAL`] objects and
/// [`super::MAX_DEPOSIT_BYTES_PER_DIAL`] bytes ([`deposit_chunks`]), each a
/// HANDOFF with `Rhw1 { DELIVER, [0; 32], rso1 }` (salt 0xB0). The answer
/// per row sent, in order: `(digest, HANDOFF_RESULT code or UNSUPPORTED)`,
/// `None` when no answer came back. A custodian the cache knows without
/// the handoff ops is not dialled (every answer
/// [`ItemAnswer::Unsupported`]); the answers are kept in the cache. The
/// rows' marks (handed, refused, back off) and the depositor's re-check are
/// the caller's. `Err`: the dial error, or [`handoff_gate_closed`]
/// (nothing dialled).
pub fn forward_round(
    next_hop: &[u8; 32],
    rows: &[DueForward],
    caps: &mut CapabilityCache,
    now_ms: u64,
    dial: &mut CustodianDial<'_>,
) -> Result<ForwardAnswers, String> {
    if !crate::custody_gate::handoff_live() {
        return Err(handoff_gate_closed());
    }
    let rows: Vec<&DueForward> = rows.iter().filter(|r| r.next_hop == *next_hop).collect();
    let sizes: Vec<usize> = rows.iter().map(|r| r.rso1.len()).collect();
    let Some(first) = deposit_chunks(&sizes).into_iter().next() else {
        return Ok(Vec::new());
    };
    let rows = &rows[first];
    if caps.handoff(next_hop, now_ms) == Some(false) {
        return Ok(rows
            .iter()
            .map(|r| (r.digest, Some(ItemAnswer::Unsupported)))
            .collect());
    }
    let frames: Vec<Vec<u8>> = rows
        .iter()
        .enumerate()
        .map(|(i, r)| {
            encode_request(
                &req_id(i, SALT_DELIVER),
                &Rfc1Request::Handoff {
                    record: Rhw1::deliver(r.rso1.clone()),
                },
            )
        })
        .collect();
    let replies = dial(&frames)?;
    let mut answers: Vec<Option<ItemAnswer>> = vec![None; rows.len()];
    for raw in &replies {
        let Ok((id, reply)) = decode_reply(raw) else {
            continue;
        };
        let Some(i) = index_of(&id, SALT_DELIVER).filter(|i| *i < rows.len()) else {
            continue;
        };
        let answer = match reply {
            Rfc1Reply::HandoffResult { code, .. } => ItemAnswer::Code(code),
            Rfc1Reply::Unsupported { .. } => ItemAnswer::Unsupported,
            _ => continue,
        };
        let supported = answer != ItemAnswer::Unsupported;
        caps.note(next_hop, CustodianCapability::Handoff, supported, now_ms);
        answers[i] = Some(answer);
    }
    Ok(rows.iter().map(|r| r.digest).zip(answers).collect())
}

#[cfg(test)]
mod tests;
