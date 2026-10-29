//! The requester side of the letter ops (Phase 5b, P5.14;
//! `protocol/RAVEN_FRIEND_CUSTODY_V1.md` §10.4): DEPOSIT_LETTER, one letter
//! fetch round (RELEASE + FETCH_LETTERS pages, the RAL1 intake of
//! [`crate::async_letter::intake`]) and WITHDRAW_LETTERS, pure over a `dial`
//! closure like the base ops, plus the one per-custodian capability cache
//! the letter and handoff ops share.
//!
//! None of them dials while this node's letter gate is closed
//! ([`crate::horizon::letter_live_enabled`]; a requester sends the letter
//! ops only then), nor a custodian the cache knows without letters.

use std::collections::HashMap;
use std::path::Path;

use super::{req_id, taken_at, CustodianDial, MAX_DEPOSITS_PER_DIAL, MAX_PENDING_RELEASES};
use crate::async_letter::intake::{intake_letter_sensed, BadLetter, LetterOutcome};
use crate::async_letter::{decode_header, letter_digest, Ral1Error};
use crate::friend_custody::{
    decode_reply, encode_request, CustodyCode, Rfc1Reply, Rfc1Request, MAX_FETCH_ITEMS,
    MAX_RELEASE_DIGESTS, MAX_WITHDRAW_DIGESTS, OP_DEPOSIT_LETTER, OP_FETCH_LETTERS, OP_HANDOFF,
    OP_TAGS, OP_WITHDRAW_LETTERS,
};
use crate::identity::Identity;
use crate::relayed_ingest::RetryScope;

// ---------------------------------------------------------------------------
// Capability cache
// ---------------------------------------------------------------------------

/// How long what a custodian's answers showed about an optional op family
/// is believed (RFC1 §10.5: an `UNSUPPORTED` is cached for 24 h).
pub const CAPABILITY_TTL_MS: u64 = 24 * 60 * 60 * 1000;

/// An optional RFC1 op family a custodian may lack (RFC1 §4 registry).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CustodianCapability {
    /// The letter ops 0x04-0x06 (§10).
    Letters,
    /// The custody handoff ops 0x07-0x08 (`RAVEN_CUSTODY_HANDOFF_V1`).
    Handoff,
}

impl CustodianCapability {
    /// The family a request op belongs to; `None` for the base ops
    /// 0x01-0x03, which every custodian serves.
    pub fn of_op(op: u8) -> Option<Self> {
        match op {
            OP_DEPOSIT_LETTER | OP_FETCH_LETTERS | OP_WITHDRAW_LETTERS => Some(Self::Letters),
            OP_HANDOFF | OP_TAGS => Some(Self::Handoff),
            _ => None,
        }
    }
}

/// One answer learned, and when.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Learned {
    supported: bool,
    at_ms: u64,
}

impl Learned {
    /// Believed at `now_ms`: younger than [`CAPABILITY_TTL_MS`] (a clock
    /// set back by more than that forgets it too).
    fn current(self, now_ms: u64) -> Option<bool> {
        let fresh = now_ms.saturating_sub(self.at_ms) < CAPABILITY_TTL_MS
            && self.at_ms.saturating_sub(now_ms) < CAPABILITY_TTL_MS;
        fresh.then_some(self.supported)
    }
}

/// What one custodian's answers showed: `None` per family is unknown (never
/// asked, or learned more than [`CAPABILITY_TTL_MS`] ago).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Capabilities {
    letters: Option<Learned>,
    handoff: Option<Learned>,
}

impl Capabilities {
    fn slot(&mut self, capability: CustodianCapability) -> &mut Option<Learned> {
        match capability {
            CustodianCapability::Letters => &mut self.letters,
            CustodianCapability::Handoff => &mut self.handoff,
        }
    }

    fn get(&self, capability: CustodianCapability) -> Option<Learned> {
        match capability {
            CustodianCapability::Letters => self.letters,
            CustodianCapability::Handoff => self.handoff,
        }
    }
}

/// The one per-custodian cache of the optional op families (`{letters,
/// handoff}`, each `Option<bool>` for [`CAPABILITY_TTL_MS`]), in memory:
/// learned from an `UNSUPPORTED` answer to an op of the family (no) or any
/// other answer to one (yes; served, whatever its code). A process that
/// starts again learns it again with one request. The letter ops and the
/// custody handoff share it.
#[derive(Debug, Clone, Default)]
pub struct CapabilityCache {
    by_custodian: HashMap<[u8; 32], Capabilities>,
}

impl CapabilityCache {
    /// Whether `custodian` serves `capability`, as believed at `now_ms`.
    pub fn get(
        &self,
        custodian: &[u8; 32],
        capability: CustodianCapability,
        now_ms: u64,
    ) -> Option<bool> {
        self.by_custodian
            .get(custodian)
            .and_then(|caps| caps.get(capability))
            .and_then(|learned| learned.current(now_ms))
    }

    /// [`Self::get`] for the letter ops.
    pub fn letters(&self, custodian: &[u8; 32], now_ms: u64) -> Option<bool> {
        self.get(custodian, CustodianCapability::Letters, now_ms)
    }

    /// [`Self::get`] for the custody handoff ops.
    pub fn handoff(&self, custodian: &[u8; 32], now_ms: u64) -> Option<bool> {
        self.get(custodian, CustodianCapability::Handoff, now_ms)
    }

    /// Remember that `custodian` does (or does not) serve `capability`.
    pub fn note(
        &mut self,
        custodian: &[u8; 32],
        capability: CustodianCapability,
        supported: bool,
        now_ms: u64,
    ) {
        *self
            .by_custodian
            .entry(*custodian)
            .or_default()
            .slot(capability) = Some(Learned {
            supported,
            at_ms: now_ms,
        });
    }

    /// Learn from `reply`, `custodian`'s answer to a request of `op`:
    /// `UNSUPPORTED` says the family is absent there, any other answer that
    /// it is served. A base op teaches nothing.
    pub fn learn(&mut self, custodian: &[u8; 32], op: u8, reply: &Rfc1Reply, now_ms: u64) {
        if let Some(capability) = CustodianCapability::of_op(op) {
            let supported = !matches!(reply, Rfc1Reply::Unsupported { .. });
            self.note(custodian, capability, supported, now_ms);
        }
    }

    /// A copy holding only `custodian`'s entry, with the times it was
    /// learned at: a caller's working copy for one exchange, so no lock is
    /// held across a dial ([`Self::absorb`] takes back what it learned).
    pub fn only(&self, custodian: &[u8; 32]) -> Self {
        let mut out = Self::default();
        if let Some(caps) = self.by_custodian.get(custodian) {
            out.by_custodian.insert(*custodian, *caps);
        }
        out
    }

    /// Take what `other` learned: per custodian and family, the answer
    /// learned last (a copy handed back unchanged changes nothing, so an
    /// answer is never made younger than it is).
    pub fn absorb(&mut self, other: Self) {
        for (custodian, theirs) in other.by_custodian {
            let mine = self.by_custodian.entry(custodian).or_default();
            for capability in [CustodianCapability::Letters, CustodianCapability::Handoff] {
                if let Some(learned) = theirs.get(capability) {
                    let slot = mine.slot(capability);
                    if slot.is_none_or(|held| held.at_ms <= learned.at_ms) {
                        *slot = Some(learned);
                    }
                }
            }
        }
    }

    /// Forget `custodian` (no longer a contact, say).
    pub fn forget(&mut self, custodian: &[u8; 32]) {
        self.by_custodian.remove(custodian);
    }

    /// Drop the custodians nothing is believed of at `now_ms` any more.
    pub fn prune(&mut self, now_ms: u64) {
        self.by_custodian.retain(|_, caps| {
            [caps.letters, caps.handoff]
                .iter()
                .flatten()
                .any(|learned| learned.current(now_ms).is_some())
        });
    }

    /// Custodians with an entry.
    pub fn len(&self) -> usize {
        self.by_custodian.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_custodian.is_empty()
    }
}

// ---------------------------------------------------------------------------
// The letter ops
// ---------------------------------------------------------------------------

/// Request-id salts of the letter ops (the base ops use 0xD0, 0xE0, 0xF0).
const SALT_DEPOSIT_LETTER: u8 = 0xD1;
const SALT_RELEASE_LETTERS: u8 = 0xE1;
const SALT_FETCH_LETTERS: u8 = 0xF1;
const SALT_WITHDRAW_LETTERS: u8 = 0xC1;

fn index_of(id: &[u8; 8], salt: u8) -> Option<usize> {
    (id[0] == salt)
        .then(|| u64::from_be_bytes([0, id[1], id[2], id[3], id[4], id[5], id[6], id[7]]) as usize)
}

/// The refusal a letter op gives without dialling while this node's letter
/// gate is closed: not a dial error (no strike).
pub fn letter_gate_closed() -> String {
    format!("{}: letters are off on this node", Ral1Error::Gate.code())
}

/// A custodian's answer to one letter op.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LetterAnswer {
    /// The op was served and answered with this code.
    Code(CustodyCode),
    /// The custodian has no letter ops (§10.5): use the base deposit.
    Unsupported,
}

impl LetterAnswer {
    /// The custodian holds the letter (STORED or DUPLICATE).
    pub fn held(self) -> bool {
        matches!(self, Self::Code(code) if code.held())
    }
}

/// One RAL1 letter to leave with a custodian for `recipient`.
#[derive(Debug, Clone)]
pub struct LetterDeposit {
    pub recipient: [u8; 32],
    pub letter: Vec<u8>,
}

/// DEPOSIT_LETTER up to [`MAX_DEPOSITS_PER_DIAL`] letters in one dial to
/// `custodian` (a longer list is cut; the caller splits by bytes with
/// [`super::deposit_chunks`]). The answer per letter, in input order;
/// `None`: no answer came back (transient). A custodian the cache knows
/// without letters is not dialled: every answer is
/// [`LetterAnswer::Unsupported`]. `Err`: the dial error, or
/// [`letter_gate_closed`] (nothing dialled).
pub fn deposit_letters(
    custodian: &[u8; 32],
    items: &[LetterDeposit],
    caps: &mut CapabilityCache,
    now_ms: u64,
    dial: &mut CustodianDial<'_>,
) -> Result<Vec<Option<LetterAnswer>>, String> {
    if !crate::horizon::letter_live_enabled() {
        return Err(letter_gate_closed());
    }
    let items = &items[..items.len().min(MAX_DEPOSITS_PER_DIAL)];
    if caps.letters(custodian, now_ms) == Some(false) {
        return Ok(vec![Some(LetterAnswer::Unsupported); items.len()]);
    }
    let frames: Vec<Vec<u8>> = items
        .iter()
        .enumerate()
        .map(|(i, item)| {
            encode_request(
                &req_id(i, SALT_DEPOSIT_LETTER),
                &Rfc1Request::DepositLetter {
                    recipient: item.recipient,
                    letter: item.letter.clone(),
                },
            )
        })
        .collect();
    let replies = dial(&frames)?;
    let mut answers = vec![None; items.len()];
    for raw in &replies {
        let Ok((id, reply)) = decode_reply(raw) else {
            continue;
        };
        let Some(slot) = index_of(&id, SALT_DEPOSIT_LETTER).and_then(|i| answers.get_mut(i)) else {
            continue;
        };
        let answer = match reply {
            Rfc1Reply::DepositResult { code, .. } => LetterAnswer::Code(code),
            Rfc1Reply::Unsupported { .. } => LetterAnswer::Unsupported,
            _ => continue,
        };
        caps.learn(custodian, OP_DEPOSIT_LETTER, &reply, now_ms);
        *slot = Some(answer);
    }
    Ok(answers)
}

/// What one WITHDRAW_LETTERS dial did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WithdrawReport {
    /// Letters the custodian deleted.
    pub withdrawn: usize,
    /// The answer per frame of at most [`MAX_WITHDRAW_DIGESTS`] digests, in
    /// order; `None`: no answer came back.
    pub answers: Vec<Option<LetterAnswer>>,
}

/// WITHDRAW_LETTERS the letters (by `letter_digest`) this node left with
/// `custodian`, in one dial: one frame per [`MAX_WITHDRAW_DIGESTS`] digests,
/// repeated digests once. Not dialled for a custodian the cache knows
/// without letters (every answer [`LetterAnswer::Unsupported`]); `Err` as
/// [`deposit_letters`].
pub fn withdraw_letters(
    custodian: &[u8; 32],
    digests: &[[u8; 32]],
    caps: &mut CapabilityCache,
    now_ms: u64,
    dial: &mut CustodianDial<'_>,
) -> Result<WithdrawReport, String> {
    if !crate::horizon::letter_live_enabled() {
        return Err(letter_gate_closed());
    }
    let mut unique: Vec<[u8; 32]> = Vec::with_capacity(digests.len());
    for digest in digests {
        if !unique.contains(digest) {
            unique.push(*digest);
        }
    }
    let chunks: Vec<&[[u8; 32]]> = unique.chunks(MAX_WITHDRAW_DIGESTS).collect();
    let mut report = WithdrawReport {
        withdrawn: 0,
        answers: vec![None; chunks.len()],
    };
    if chunks.is_empty() {
        return Ok(report);
    }
    if caps.letters(custodian, now_ms) == Some(false) {
        report.answers = vec![Some(LetterAnswer::Unsupported); chunks.len()];
        return Ok(report);
    }
    let frames: Vec<Vec<u8>> = chunks
        .iter()
        .enumerate()
        .map(|(i, chunk)| {
            encode_request(
                &req_id(i, SALT_WITHDRAW_LETTERS),
                &Rfc1Request::WithdrawLetters {
                    digests: chunk.to_vec(),
                },
            )
        })
        .collect();
    let replies = dial(&frames)?;
    for raw in &replies {
        let Ok((id, reply)) = decode_reply(raw) else {
            continue;
        };
        let Some(i) = index_of(&id, SALT_WITHDRAW_LETTERS).filter(|i| *i < chunks.len()) else {
            continue;
        };
        let answer = match reply {
            Rfc1Reply::WithdrawResult { code, withdrawn } => {
                if code == CustodyCode::Ok {
                    report.withdrawn += usize::from(withdrawn);
                }
                LetterAnswer::Code(code)
            }
            Rfc1Reply::Unsupported { .. } => LetterAnswer::Unsupported,
            _ => continue,
        };
        caps.learn(custodian, OP_WITHDRAW_LETTERS, &reply, now_ms);
        report.answers[i] = Some(answer);
    }
    Ok(report)
}

/// Per-custodian letter fetch state kept in memory between triggers.
#[derive(Debug, Default)]
pub struct LetterFetchState {
    /// Letters whose intake committed, or that can never succeed: released
    /// on the next dial (never before their intake committed).
    pub pending_release: Vec<[u8; 32]>,
    /// Where the next FETCH_LETTERS page starts (an unfinished listing).
    pub cursor: Option<[u8; 32]>,
}

/// What one letter fetch round did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct LetterFetchReport {
    pub dials: usize,
    /// LETTER_ITEMs received.
    pub letters: usize,
    /// Letters whose intake committed (LETTERs and REPLYs).
    pub accepted: usize,
    /// ... of which REPLYs.
    pub replies: usize,
    /// Messages taken for the first time, and ACKs that settled a message.
    pub messages: usize,
    pub acks: usize,
    /// Letters left at the custodian for a later fetch (claim limit, a
    /// local store error, an envelope to be tried again).
    pub kept: usize,
    /// Letters refused for good (released).
    pub refused: usize,
    /// Letters the custodian released (its count).
    pub released: usize,
    /// The refusal codes seen, each once.
    pub codes: Vec<Ral1Error>,
    /// The custodian answered FETCH_LETTERS `UNSUPPORTED` (now cached).
    pub unsupported: bool,
    /// The custodian answered with a non-OK code (park / back off).
    pub custodian_code: Option<CustodyCode>,
    /// A store-wide problem stopped the round.
    pub store_trouble: Option<&'static str>,
    /// Senders to back off (an envelope asked for it), with why.
    pub peer_backoff: Vec<([u8; 32], &'static str)>,
    /// Senders whose letters were taken: kick their outbox (a REPLY or
    /// ACKs are owed, or a letter session was confirmed).
    pub touched: Vec<[u8; 32]>,
}

/// One letter fetch trigger at `custodian` (§10.4): FETCH_LETTERS the pages
/// from the saved cursor (each dial also RELEASEs what is pending), then run
/// the RAL1 intake on every letter listed (in the order they were written,
/// across pages, each at its own receive time), and queue each one whose
/// intake committed or that can never succeed for release on the next
/// dial: a letter is released only after its intake committed. Letters
/// kept (claim limit, store, an envelope to retry) stay at the custodian
/// and come back on a later listing. At most `max_pages` dials. Nothing is
/// dialled while the letter gate is closed or the cache knows `custodian`
/// without letters; an `UNSUPPORTED` answer is cached.
#[allow(clippy::too_many_arguments)]
pub fn fetch_letters_round(
    data_dir: &Path,
    identity: &Identity,
    custodian: &[u8; 32],
    state: &mut LetterFetchState,
    caps: &mut CapabilityCache,
    now_ms: u64,
    max_pages: usize,
    dial: &mut CustodianDial<'_>,
) -> LetterFetchReport {
    let mut report = LetterFetchReport::default();
    if !crate::horizon::letter_live_enabled() || caps.letters(custodian, now_ms) == Some(false) {
        return report;
    }
    // The listing first: the pages this trigger may fetch, each dial also
    // releasing what earlier rounds took. Then the intake of all of them at
    // once, in the order their senders wrote them: pages come in page-token
    // (hash) order, and a session whose letters fall on two pages still
    // reaches the inbox in order (review letters-4). What it committed is
    // released on the dial after it.
    let start = state.cursor;
    let mut letters: Vec<Vec<u8>> = Vec::new();
    let mut listing_ended = false;
    while report.dials < max_pages {
        let releasing: Vec<[u8; 32]> = state
            .pending_release
            .iter()
            .take(MAX_RELEASE_DIGESTS)
            .copied()
            .collect();
        let mut frames = Vec::new();
        if !releasing.is_empty() {
            frames.push(encode_request(
                &req_id(0, SALT_RELEASE_LETTERS),
                &Rfc1Request::Release {
                    digests: releasing.clone(),
                },
            ));
        }
        frames.push(encode_request(
            &req_id(0, SALT_FETCH_LETTERS),
            &Rfc1Request::FetchLetters {
                after: state.cursor,
                max_items: MAX_FETCH_ITEMS,
            },
        ));
        report.dials += 1;
        let Ok(replies) = dial(&frames) else {
            break;
        };
        let mut fetch_end: Option<(CustodyCode, Option<[u8; 32]>)> = None;
        for raw in &replies {
            let Ok((id, reply)) = decode_reply(raw) else {
                continue; // the RLB1 offer, or anything else
            };
            if id == req_id(0, SALT_RELEASE_LETTERS) {
                released_from(state, &mut report, &releasing, &reply);
                continue;
            }
            if id != req_id(0, SALT_FETCH_LETTERS) {
                continue;
            }
            match &reply {
                Rfc1Reply::LetterItem { letter } => letters.push(letter.clone()),
                Rfc1Reply::FetchEnd { code, next, .. } => fetch_end = Some((*code, *next)),
                Rfc1Reply::Unsupported { .. } => report.unsupported = true,
                _ => continue,
            }
            caps.learn(custodian, OP_FETCH_LETTERS, &reply, now_ms);
        }
        if report.unsupported {
            break;
        }
        match fetch_end {
            Some((CustodyCode::Ok, Some(next))) => state.cursor = Some(next),
            Some((CustodyCode::Ok, None)) => {
                state.cursor = None;
                listing_ended = true;
                break;
            }
            Some((code, _)) => {
                report.custodian_code = Some(code);
                break;
            }
            None => break,
        }
    }
    report.letters = letters.len();
    letters.sort_by_key(|letter| decode_header(letter).map_or(0, |h| h.created_at_ms));
    let mut last_taken = 0;
    for letter in letters {
        let digest = letter_digest(&letter);
        let at = taken_at(now_ms, &mut last_taken);
        let (outcome, bad) = intake_letter_sensed(data_dir, identity, &letter, at);
        note_bad_letter(custodian, bad);
        tally(&mut report, &outcome);
        if outcome.releases()
            && state.pending_release.len() < MAX_PENDING_RELEASES
            && !state.pending_release.contains(&digest)
        {
            state.pending_release.push(digest);
        }
        if report.store_trouble.is_some() {
            // What was listed and not taken comes back: the next round
            // lists again from where this one started.
            state.cursor = start;
            break;
        }
    }
    // Release what the intake committed once the listing came to its end,
    // in what is left of the budget (else on the next trigger's first dial).
    while listing_ended
        && report.store_trouble.is_none()
        && report.dials < max_pages
        && !state.pending_release.is_empty()
    {
        let releasing: Vec<[u8; 32]> = state
            .pending_release
            .iter()
            .take(MAX_RELEASE_DIGESTS)
            .copied()
            .collect();
        let frame = encode_request(
            &req_id(0, SALT_RELEASE_LETTERS),
            &Rfc1Request::Release {
                digests: releasing.clone(),
            },
        );
        report.dials += 1;
        let Ok(replies) = dial(std::slice::from_ref(&frame)) else {
            break;
        };
        let before = state.pending_release.len();
        for raw in &replies {
            if let Ok((id, reply)) = decode_reply(raw) {
                if id == req_id(0, SALT_RELEASE_LETTERS) {
                    released_from(state, &mut report, &releasing, &reply);
                }
            }
        }
        if state.pending_release.len() == before {
            break;
        }
    }
    report.codes.sort_by_key(|code| code.code());
    report.codes.dedup();
    report.touched.sort_unstable();
    report.touched.dedup();
    report
}

/// The custodian's answer to a RELEASE of `releasing`: served OK, they are
/// no longer pending.
fn released_from(
    state: &mut LetterFetchState,
    report: &mut LetterFetchReport,
    releasing: &[[u8; 32]],
    reply: &Rfc1Reply,
) {
    if let Rfc1Reply::ReleaseResult {
        code: CustodyCode::Ok,
        released,
    } = reply
    {
        state.pending_release.retain(|d| !releasing.contains(d));
        report.released += usize::from(*released);
    }
}

/// A letter `custodian` served that was bad (Phase 6b S20,
/// `SEC_LETTER_BAD`): about the custodian when its signature failed, about
/// its sender when the signature verified but what it carries did not.
fn note_bad_letter(custodian: &[u8; 32], bad: Option<BadLetter>) {
    use crate::security_events::{CarrierRole, SecKind, Via};
    let via = Via::Custodian(*custodian);
    match bad {
        None => {}
        Some(BadLetter::Carrier) => crate::security_sense::carrier(
            SecKind::LetterBad,
            custodian,
            CarrierRole::Custodian,
            via,
        ),
        Some(BadLetter::Sender(sender)) => {
            crate::security_sense::contact(SecKind::LetterBad, &sender, via)
        }
    }
}

/// Count one intake outcome into `report`.
fn tally(report: &mut LetterFetchReport, outcome: &LetterOutcome) {
    if let Some(taken) = outcome.report() {
        report.messages += taken.messages;
        report.acks += taken.acks;
        report.touched.push(taken.peer);
    }
    match outcome {
        LetterOutcome::Letter(_) => report.accepted += 1,
        LetterOutcome::Reply(_) => {
            report.accepted += 1;
            report.replies += 1;
        }
        LetterOutcome::Refused(code) => {
            report.codes.push(*code);
            if code.releases_letter() {
                report.refused += 1;
            } else {
                report.kept += 1;
                if *code == Ral1Error::Store {
                    report.store_trouble = Some(Ral1Error::Store.code());
                }
            }
        }
        LetterOutcome::Kept {
            report: taken,
            scope,
            why,
        } => {
            report.kept += 1;
            match scope {
                RetryScope::Item => {}
                RetryScope::Peer => report.peer_backoff.push((taken.peer, why)),
                RetryScope::Store => report.store_trouble = Some(why),
            }
        }
    }
}

#[cfg(test)]
mod tests;
