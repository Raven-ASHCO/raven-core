//! Sealed letters in raven-node (Phase 5b, P5.15; `raven_core::horizon::letters`
//! for the store work, `raven_core::custody_client`'s letter ops for the
//! wire): the outbox worker's letter step and direct completion, and the
//! fetcher's letter round.
//!
//! - **Letter step** ([`letter_branch`], the worker's custody phase, before
//!   the base deposit): only with custodians the capability cache knows to
//!   serve letters. What could not go directly (and what is parked) moves
//!   into a letter session under the contact's send lock, and the letter is
//!   left with each such custodian without it; REPLY letters carry the
//!   PairResponse and owed ACKs of letter sessions this node accepted.
//!   Letters every custodian refused stay `unplaced` and are offered again
//!   on a backoff (1 h doubling to 24 h), and at once after a custodian's
//!   RELEASE or a fresh capability answer. Letters whose messages all
//!   settled are withdrawn. Custodians without letters get the base deposit,
//!   and then nothing is moved. A custodian that answers a letter op
//!   `UNSUPPORTED` (it no longer serves them) leaves every letter's holders.
//! - **Direct completion** ([`settle_letter_rows`]): a message in a letter
//!   session that is still provisional never goes out directly as it is.
//!   When the contact turns out to be reachable, the session's exact PairInit
//!   is replayed; its PairResponse confirms the session and the messages go
//!   out in the same attempt. No PairResponse (an older peer, a rotated
//!   bundle): the letter copies are parked again for the horizon's
//!   synchronous re-pair, and the letters are withdrawn. Unreachable while
//!   no shared custodian serves letters and none holds a letter of the
//!   session: its copies are parked again the same way.
//! - **Fetcher** ([`fetch_at`]): FETCH_LETTERS at each custodian, with or
//!   without a live session (a letter brings its own).
//!
//! The send lock is held for store work only, never across a dial. The
//! capability cache and the fetch cursors live in memory, one per process.
//! Logs carry counts only.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Mutex, MutexGuard, OnceLock};

use raven_core::custody_client::{
    custodian_routes, deposit_chunks, deposit_letters, fetch_letters_round, withdraw_letters,
    CapabilityCache, CustodianDial, LetterAnswer, LetterFetchReport, LetterFetchState,
};
use raven_core::friend_custody::CustodyCode;
use raven_core::horizon::letter_live_enabled;
use raven_core::horizon::letters::{
    abandon_letter_session, build_letters, build_replies, has_unlettered,
    provisional_letter_session, reletter, DirectCopy, OwedAckRef,
};
use raven_core::identity::Identity;
use raven_core::indexed_session_store::{
    EndpointDeliveryState, EndpointOutboundKind, IndexedSessionRecordKey, IndexedSessionStore,
    LetterRole,
};
use raven_core::letter_deposits::{self, DepositKind, LetterBook, MAX_LETTER_CARRIERS};
use raven_core::outbox::{OutboxCarrier, OutboxRoute, PeerSendLock};
use raven_core::pair_init::PairInit;

use crate::outbox::code::{CARRIER_FULL, NO_SHARED_CARRIER, WAITING_FOR_CARRIER};
use crate::outbox::{
    custody_find_failed, dial_error_code, AttemptCtx, Entry, Outcome, PeerReport, UnsentAck,
};

/// How long the worker waits for a contact's send lock (as its own).
const LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

/// A custodian dial's replies.
type Replies = Result<Vec<Vec<u8>>, String>;
/// A dial to any custodian: its key, the custody offer it announced, the
/// frames.
type OfferDial<'a> = dyn FnMut(&[u8; 32], Option<u8>, &[Vec<u8>]) -> Replies + 'a;
/// A dial to any custodian that holds a letter: its key, the frames.
pub(crate) type HolderDial<'a> = dyn FnMut(&[u8; 32], &[Vec<u8>]) -> Replies + 'a;

// ---------------------------------------------------------------------------
// Process state: the capability cache and the letter fetch cursors
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Shared {
    caps: CapabilityCache,
    fetch: HashMap<[u8; 32], LetterFetchState>,
}

fn lock() -> MutexGuard<'static, Shared> {
    static SHARED: OnceLock<Mutex<Shared>> = OnceLock::new();
    SHARED
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// Whether `custodian` serves the letter ops, as the cache believes at
/// `now_ms`.
#[cfg(test)]
pub(crate) fn letters_supported(custodian: &[u8; 32], now_ms: u64) -> Option<bool> {
    lock().caps.letters(custodian, now_ms)
}

/// Remember what `custodian` serves (tests, and a custodian that is no
/// contact any more: [`forget`]).
#[cfg(test)]
pub(crate) fn note_letters(custodian: &[u8; 32], supported: bool, now_ms: u64) {
    lock().caps.note(
        custodian,
        raven_core::custody_client::CustodianCapability::Letters,
        supported,
        now_ms,
    );
}

/// Run `op` on a working copy of `custodian`'s cache entry, never holding
/// the lock across its dial, and keep what it learned at the time it was
/// learned: only an answer renews an entry, so an `UNSUPPORTED` lapses 24 h
/// after the custodian said it however often it is read meanwhile, and the
/// fetcher's FETCH_LETTERS asks again (review letters-1). `true`: the
/// custodian is known to serve letters now and was not before (a fresh
/// capability answer).
fn with_caps<R>(
    custodian: &[u8; 32],
    now_ms: u64,
    op: impl FnOnce(&mut CapabilityCache) -> R,
) -> (R, bool) {
    let mut local = lock().caps.only(custodian);
    let before = local.letters(custodian, now_ms);
    let out = op(&mut local);
    let after = local.letters(custodian, now_ms);
    lock().caps.absorb(local);
    (out, before != Some(true) && after == Some(true))
}

/// `custodian` answered a letter op `UNSUPPORTED` (an older build, letters
/// off there): what it holds can be neither fetched nor withdrawn, so it
/// leaves every letter's holders, and the contacts concerned are kicked so
/// their status and placement are worked out again (review letters-2).
fn custodian_lost_letters(data_dir: &Path, custodian: &[u8; 32], wall: u64) {
    let Ok(peers) = letter_deposits::forget_holder(data_dir, custodian, wall) else {
        return;
    };
    if !peers.is_empty() {
        eprintln!(
            "raven-node custody: letters: a friend serves no letters now, contacts={}",
            peers.len()
        );
    }
    for peer in peers {
        crate::outbox::kick(Some(&peer), false, false);
    }
}

/// Run `op` with a working copy of `custodian`'s entry of the one capability
/// cache (custody handoff, P5.21: the letter ops and the handoff ops share
/// it), never holding the lock across its dial, and keep what it learned at
/// the time it was learned (an UNSUPPORTED still lapses after 24 h).
pub(crate) fn with_handoff_caps<R>(
    custodian: &[u8; 32],
    op: impl FnOnce(&mut CapabilityCache) -> R,
) -> R {
    let mut local = lock().caps.only(custodian);
    let out = op(&mut local);
    lock().caps.absorb(local);
    out
}

/// Whether `custodian` serves the custody handoff ops, as the cache believes
/// at `now_ms` (`None`: not known).
pub(crate) fn handoff_supported(custodian: &[u8; 32], now_ms: u64) -> Option<bool> {
    lock().caps.handoff(custodian, now_ms)
}

/// The custodians among `custodians` the cache knows to serve letters.
fn capable(custodians: &[([u8; 32], Option<u8>)], now_ms: u64) -> Vec<([u8; 32], Option<u8>)> {
    let s = lock();
    custodians
        .iter()
        .filter(|(c, _)| s.caps.letters(c, now_ms) == Some(true))
        .copied()
        .collect()
}

/// A dial to `custodian` as the worker's deposits make it: the resolver's
/// on-link filter and the LAN beacon's finds first (`None`: no route).
fn worker_dial<'a>(
    ctx: &'a AttemptCtx,
    custodian: [u8; 32],
    offer: Option<u8>,
) -> Option<impl FnMut(&[Vec<u8>]) -> Replies + 'a> {
    let data_dir = ctx.data_dir.as_path();
    let finds = (ctx.lan_beacon_routes)(&custodian);
    let mut routes = custodian_routes(data_dir, &custodian, offer, &finds, |ip| {
        (ctx.on_link)(ip) != Some(false)
    });
    // Phase 5: over a nearby pipe too (last), under the custody gates, as
    // the worker's other deposits.
    routes.extend(crate::nearby::custodian_route(&custodian));
    if routes.is_empty() {
        return None;
    }
    let expected = hex::encode(custodian);
    Some(move |frames: &[Vec<u8>]| {
        let mut last = Err("no custodian route".to_string());
        for (planned, route) in &routes {
            last = ctx
                .dialer
                .dial_path(data_dir, route, &expected, frames)
                .map(|(replies, path)| {
                    if let Some(path) = path {
                        crate::custody::note_path(&custodian, path);
                    }
                    replies
                });
            match &last {
                Ok(_) => break,
                // A find that does not lead to the custodian is one no
                // longer (§7, review A-5).
                Err(e) if custody_find_failed(&finds, planned, e) => {
                    (ctx.lan_beacon_failed)(&custodian, &planned.dial);
                }
                Err(_) => {}
            }
        }
        last
    })
}

// ---------------------------------------------------------------------------
// The letter step (the worker's custody phase)
// ---------------------------------------------------------------------------

/// What the letter step did to the attempt's candidates and owed ACKs.
#[derive(Debug, Default)]
pub(crate) struct LetterBranch {
    /// Messages moved into a letter session (`Resealed`: the new copy is
    /// tracked from the next scan) and direct copies parked for one
    /// (`Parked`), each with whether a custodian now holds its letter.
    pub(crate) moved: HashMap<[u8; 16], (Outcome, bool)>,
}

/// The letter step for `peer` (see the module), with `custodians` the
/// contact's deposit custodians (not parked), `direct` the direct copies
/// this attempt could not deliver that custody may carry, and `owed` the
/// ACKs owed to `peer`. Without the letter gate, or without a custodian
/// known to serve letters: nothing (the base deposit carries what it can).
pub(crate) fn letter_branch(
    ctx: &AttemptCtx,
    store: &mut IndexedSessionStore,
    peer: &[u8; 32],
    custodians: &[([u8; 32], Option<u8>)],
    direct: &[DirectCopy],
    owed: &[&([u8; 32], UnsentAck)],
    wall: u64,
) -> LetterBranch {
    let mut out = LetterBranch::default();
    if !letter_live_enabled() {
        return out;
    }
    let data_dir = ctx.data_dir.as_path();
    let mut dial_for =
        |custodian: &[u8; 32], offer: Option<u8>, frames: &[Vec<u8>]| match worker_dial(
            ctx, *custodian, offer,
        ) {
            Some(mut dial) => dial(frames),
            None => Err("no custodian route".to_string()),
        };
    // Settled letters leave their custodians first (any custodian that
    // holds one, letters-capable now or not).
    let offers: HashMap<[u8; 32], Option<u8>> = custodians.iter().copied().collect();
    withdraw_settled(
        data_dir,
        store,
        peer,
        None,
        wall,
        &mut |c: &[u8; 32], frames: &[Vec<u8>]| {
            dial_for(c, offers.get(c).copied().flatten(), frames)
        },
    );
    let capable = capable(custodians, wall);
    if capable.is_empty() {
        return out;
    }
    // REPLY letters for the ACKs owed on letter sessions this node accepted.
    let refs: Vec<OwedAckRef<'_>> = owed
        .iter()
        .map(|entry| OwedAckRef {
            digest: entry.0,
            session_id: entry.1.session_id,
            bytes: &entry.1.bytes,
            expires_at_ms: entry.1.expires_at_ms,
        })
        .collect();
    if let Err(e) = build_replies(data_dir, &ctx.identity, store, peer, &refs, wall) {
        eprintln!("raven-node custody: letters: {}", redact(&e));
    }
    // LETTERs: what waits moves into a letter session, under the lock. While
    // `raven send` holds the contact nothing moves now; what is sealed
    // already is still offered.
    let parked_any = store
        .parked_for_recipient(peer)
        .is_ok_and(|rows| !rows.is_empty());
    // Copies an earlier build moved into a letter session but recorded no
    // letter for (it stopped between the two writes) are lettered first
    // (review letters-3).
    let unlettered = has_unlettered(data_dir, store, peer, wall);
    if !direct.is_empty() || parked_any || unlettered {
        if let Ok(_lock) = PeerSendLock::acquire_within(data_dir, peer, LOCK_WAIT) {
            if unlettered {
                match reletter(data_dir, &ctx.identity, store, peer, wall) {
                    Ok(rows) if !rows.is_empty() => {
                        eprintln!("raven-node custody: letters: relettered={}", rows.len());
                    }
                    Ok(_) => {}
                    Err(e) => eprintln!("raven-node custody: letters: {}", redact(&e)),
                }
            }
            if !direct.is_empty() || parked_any {
                match build_letters(data_dir, &ctx.identity, store, peer, direct, wall) {
                    Ok(build) => {
                        if !build.letters.is_empty() {
                            eprintln!(
                                "raven-node custody: letters: sealed={} moved={} parked={}",
                                build.letters.len(),
                                build.moved.len(),
                                build.parked.len()
                            );
                        }
                        for mid in &build.moved {
                            out.moved.insert(*mid, (Outcome::Resealed, false));
                        }
                        for mid in &build.parked {
                            out.moved.entry(*mid).or_insert((Outcome::Parked, false));
                        }
                    }
                    Err(e) => eprintln!("raven-node custody: letters: {}", redact(&e)),
                }
            }
        }
    }
    let placed = place(data_dir, peer, &capable, wall, &mut dial_for);
    for (mid, (_, held)) in out.moved.iter_mut() {
        *held = placed.contains(mid);
    }
    out
}

/// Error texts in the log carry no key or address: the code part only.
fn redact(e: &str) -> &str {
    e.split(':').next().unwrap_or("error")
}

/// Offer `peer`'s due letters (LETTER and REPLY) to each custodian of
/// `capable` that does not hold them, without any lock but the book's;
/// record the answers (and, for a LETTER, the route records' custodians:
/// "left with a friend"). The messages whose letter a custodian now holds.
fn place(
    data_dir: &Path,
    peer: &[u8; 32],
    capable: &[([u8; 32], Option<u8>)],
    wall: u64,
    dial_for: &mut OfferDial<'_>,
) -> Vec<[u8; 16]> {
    let Ok(book) = letter_deposits::load(data_dir, wall) else {
        return Vec::new();
    };
    let keys: Vec<[u8; 32]> = capable.iter().map(|(c, _)| *c).collect();
    let due: Vec<letter_deposits::LetterDeposit> = book
        .letters
        .iter()
        .filter(|row| row.peer == *peer && row.placement_due(&keys, wall))
        .cloned()
        .collect();
    if due.is_empty() {
        return Vec::new();
    }
    let mut answers: Vec<([u8; 32], [u8; 32], CustodyCode)> = Vec::new();
    let mut lost: Vec<[u8; 32]> = Vec::new();
    for (custodian, offer) in capable {
        let todo: Vec<&letter_deposits::LetterDeposit> = due
            .iter()
            .filter(|row| {
                !row.held_by.contains(custodian) && row.held_by.len() < MAX_LETTER_CARRIERS
            })
            .collect();
        if todo.is_empty() {
            continue;
        }
        let sizes: Vec<usize> = todo.iter().map(|row| row.letter.len() + 64).collect();
        for range in deposit_chunks(&sizes) {
            let chunk = &todo[range];
            let items: Vec<raven_core::custody_client::LetterDeposit> = chunk
                .iter()
                .map(|row| raven_core::custody_client::LetterDeposit {
                    recipient: *peer,
                    letter: row.letter.clone(),
                })
                .collect();
            let (result, _) = with_caps(custodian, wall, |caps| {
                let mut dial = |frames: &[Vec<u8>]| dial_for(custodian, *offer, frames);
                deposit_letters(custodian, &items, caps, wall, &mut dial)
            });
            match result {
                Ok(got) => {
                    let mut unsupported = false;
                    for (row, answer) in chunk.iter().zip(got) {
                        match answer {
                            Some(LetterAnswer::Code(code)) => {
                                answers.push((row.digest, *custodian, code));
                            }
                            Some(LetterAnswer::Unsupported) => unsupported = true,
                            None => {}
                        }
                    }
                    if unsupported {
                        lost.push(*custodian);
                        break;
                    }
                }
                Err(e) => {
                    if dial_error_code(&e) == crate::outbox::code::PEER_REFUSED {
                        crate::custody::strike(custodian);
                    }
                    break;
                }
            }
        }
    }
    let held_now = answers.iter().filter(|(_, _, code)| code.held()).count();
    let digests: Vec<[u8; 32]> = due.iter().map(|row| row.digest).collect();
    let recorded = letter_deposits::update(data_dir, wall, |book| {
        let mut placed: Vec<([u8; 16], [u8; 32])> = Vec::new();
        for row in book
            .letters
            .iter_mut()
            .filter(|row| digests.contains(&row.digest))
        {
            for (digest, custodian, code) in &answers {
                if *digest == row.digest {
                    row.note_answer(custodian, *code);
                    if code.held() && row.kind == DepositKind::Letter {
                        placed.extend(row.message_ids.iter().map(|mid| (*mid, *custodian)));
                    }
                }
            }
            let target = keys.len().min(MAX_LETTER_CARRIERS);
            if row.held_by.len() < target {
                row.end_round(wall);
            } else {
                row.tries = 0;
            }
        }
        // A letter forgotten while it was being offered (the fetcher
        // withdrew it elsewhere once its messages settled): a custodian
        // that took it meanwhile keeps a row of its own, marked to be
        // withdrawn, so no letter stays there untracked (review letters-9).
        for row in &due {
            if book.letters.iter().any(|r| r.digest == row.digest) {
                continue;
            }
            let takers: Vec<[u8; 32]> = answers
                .iter()
                .filter(|(digest, _, code)| *digest == row.digest && code.held())
                .map(|(_, custodian, _)| *custodian)
                .collect();
            if takers.is_empty() {
                continue;
            }
            let mut left = row.clone();
            left.held_by = takers;
            left.refused.clear();
            left.withdraw = true;
            book.letters.push(left);
        }
        placed
    });
    for custodian in &lost {
        custodian_lost_letters(data_dir, custodian, wall);
    }
    let placed = recorded.unwrap_or_default();
    for (mid, custodian) in &placed {
        let _ = raven_core::outbox::add_object_custodians(data_dir, mid, &[*custodian], wall);
        let _ = raven_core::outbox::set_object_unsent(data_dir, mid, false, wall);
    }
    if held_now > 0 {
        eprintln!("raven-node custody: left {held_now} letters with a friend");
        for (custodian, _) in capable {
            if answers
                .iter()
                .any(|(_, c, code)| c == custodian && code.held())
            {
                crate::custody::note_deposit(custodian);
            }
        }
    }
    placed.into_iter().map(|(mid, _)| mid).collect()
}

/// Has `mid` to `peer` settled: a copy delivered, or no copy left in any
/// outbox and not parked (given up)?
fn settled(
    store: &IndexedSessionStore,
    peer: &[u8; 32],
    mid: &[u8; 16],
    parked: &[[u8; 16]],
) -> bool {
    let Ok(copies) = store.message_copies_for_recipient(peer, mid) else {
        return false;
    };
    copies.iter().any(|c| {
        matches!(
            c.delivery_state,
            Some(EndpointDeliveryState::Delivered | EndpointDeliveryState::Read)
        )
    }) || (!copies.iter().any(|c| c.has_outbox_row) && !parked.contains(mid))
}

/// The contacts whose LETTERs `custodian` holds (from the book; none when
/// it cannot be read or the gate is closed): the fetcher withdraws the
/// settled ones there (P5.16: a letter session completed directly leaves
/// its letter behind, and the worker's custody phase may not run again for
/// that contact).
pub(crate) fn letter_peers_at(data_dir: &Path, custodian: &[u8; 32], wall: u64) -> Vec<[u8; 32]> {
    if !letter_live_enabled() {
        return Vec::new();
    }
    let Ok(book) = letter_deposits::load(data_dir, wall) else {
        return Vec::new();
    };
    let mut peers: Vec<[u8; 32]> = Vec::new();
    for row in &book.letters {
        if row.kind == DepositKind::Letter
            && row.held_by.contains(custodian)
            && !peers.contains(&row.peer)
        {
            peers.push(row.peer);
        }
    }
    peers
}

/// WITHDRAW `peer`'s LETTERs whose messages all settled (or whose session
/// was given up) from the custodians that hold them (`only`: that one
/// custodian), then forget them; one never placed is just forgotten. One
/// still held where it was not withdrawn now (not asked, not reached, a
/// refusal) stays, marked to be withdrawn: tried again on the next call,
/// never placed again. Nothing is locked but the book.
pub(crate) fn withdraw_settled(
    data_dir: &Path,
    store: &IndexedSessionStore,
    peer: &[u8; 32],
    only: Option<&[u8; 32]>,
    wall: u64,
    dial_for: &mut HolderDial<'_>,
) -> usize {
    if !letter_live_enabled() {
        return 0;
    }
    let Ok(book) = letter_deposits::load(data_dir, wall) else {
        return 0;
    };
    let parked: Vec<[u8; 16]> = store
        .parked_for_recipient(peer)
        .map(|rows| rows.iter().map(|r| r.message_id).collect())
        .unwrap_or_default();
    let done: Vec<&letter_deposits::LetterDeposit> = book
        .for_peer(peer, DepositKind::Letter)
        .filter(|row| {
            row.withdraw
                || row
                    .message_ids
                    .iter()
                    .all(|mid| settled(store, peer, mid, &parked))
        })
        .collect();
    if done.is_empty() {
        return 0;
    }
    let mut holders: Vec<[u8; 32]> = Vec::new();
    for row in &done {
        for c in &row.held_by {
            if !holders.contains(c) && only.is_none_or(|o| o == c) {
                holders.push(*c);
            }
        }
    }
    let mut cleared: Vec<[u8; 32]> = Vec::new();
    let mut lost: Vec<[u8; 32]> = Vec::new();
    let mut withdrawn = 0;
    for custodian in holders {
        let digests: Vec<[u8; 32]> = done
            .iter()
            .filter(|row| row.held_by.contains(&custodian))
            .map(|row| row.digest)
            .collect();
        let (result, _) = with_caps(&custodian, wall, |caps| {
            let mut dial = |frames: &[Vec<u8>]| dial_for(&custodian, frames);
            withdraw_letters(&custodian, &digests, caps, wall, &mut dial)
        });
        let Ok(report) = result else {
            continue;
        };
        withdrawn += report.withdrawn;
        let answered = |want: LetterAnswer| report.answers.contains(&Some(want));
        // Cleared there only once every frame was served OK (review
        // letters-8): a refusal (PERSISTENCE, HOLD, ...) or no answer keeps
        // the letter there, withdrawn again on the next pass. A custodian
        // that serves no letter ops, or no longer takes this node as a
        // contact, never will: forgotten there.
        if report
            .answers
            .iter()
            .all(|a| *a == Some(LetterAnswer::Code(CustodyCode::Ok)))
        {
            cleared.push(custodian);
        } else if answered(LetterAnswer::Unsupported) {
            cleared.push(custodian);
            lost.push(custodian);
        } else if answered(LetterAnswer::Code(CustodyCode::NotVerified)) {
            cleared.push(custodian);
        }
    }
    let gone: Vec<[u8; 32]> = done.iter().map(|row| row.digest).collect();
    let _ = letter_deposits::update(data_dir, wall, |book| {
        for row in book
            .letters
            .iter_mut()
            .filter(|row| gone.contains(&row.digest))
        {
            row.held_by.retain(|c| !cleared.contains(c));
            // Settled, yet still held where this call did not clear it (a
            // custodian not asked, not reached or refusing): withdrawn
            // again later, and never offered to anybody again (review
            // letters-9).
            if !row.held_by.is_empty() {
                row.withdraw = true;
            }
        }
        book.letters
            .retain(|row| !(gone.contains(&row.digest) && row.held_by.is_empty()));
    });
    for custodian in &lost {
        custodian_lost_letters(data_dir, custodian, wall);
    }
    if withdrawn > 0 {
        eprintln!("raven-node custody: letters: withdrawn={withdrawn}");
    }
    withdrawn
}

// ---------------------------------------------------------------------------
// Direct completion (the worker, before the lock)
// ---------------------------------------------------------------------------

/// What replaying a letter session's PairInit directly came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DirectCompletion {
    /// Its PairResponse came back and confirmed the session.
    Confirmed,
    /// The contact answered without a PairResponse.
    NoResponse,
    /// No route reached the contact (the last dial error).
    Unreachable(String),
}

/// The first PairResponse among `replies`.
fn first_pair_response(replies: &[Vec<u8>]) -> Option<raven_core::pair_init::PairResponse> {
    replies
        .iter()
        .find_map(|f| match raven_core::classify_packed_envelope(f) {
            raven_core::PairInitOobClassify::PairResponse(wire) => {
                raven_core::pair_init::decode_response(&wire).ok()
            }
            _ => None,
        })
}

/// Replay `init` (the letter session `key`'s exact PairInit) on `routes`,
/// the contact's own, without the lock; a PairResponse is confirmed under
/// it.
fn complete_directly(
    ctx: &AttemptCtx,
    store: &mut IndexedSessionStore,
    peer: &[u8; 32],
    routes: &[(OutboxRoute, OutboxRoute)],
    key: &IndexedSessionRecordKey,
    init: &PairInit,
) -> DirectCompletion {
    let data_dir = ctx.data_dir.as_path();
    let Ok(frame) = raven_core::lan_dispatch::wrap_pair_init(&ctx.identity, init) else {
        return DirectCompletion::Unreachable("PAIR_INIT".into());
    };
    let peer_hex = hex::encode(peer);
    let mut last = "no route".to_string();
    for (planned, dial) in routes {
        if planned.carrier == OutboxCarrier::Lan && !(ctx.lan_live)() {
            continue;
        }
        let replies =
            match ctx
                .dialer
                .dial_path(data_dir, dial, &peer_hex, std::slice::from_ref(&frame))
            {
                Ok((replies, _)) => replies,
                Err(e) => {
                    last = e;
                    continue;
                }
            };
        let Some(response) = first_pair_response(&replies) else {
            return DirectCompletion::NoResponse;
        };
        let Ok(_lock) = PeerSendLock::acquire_within(data_dir, peer, LOCK_WAIT) else {
            return DirectCompletion::Unreachable("SEND_IN_PROGRESS".into());
        };
        return match store.confirm_verified_pair_response(
            key,
            init,
            &response,
            raven_core::clock::now_ms(),
        ) {
            Ok(()) => DirectCompletion::Confirmed,
            Err(_) => DirectCompletion::NoResponse,
        };
    }
    DirectCompletion::Unreachable(last)
}

/// What a waiting letter message shows (`book` read once): held by friends
/// (`Deposited`), or why not ([`WAITING_FOR_CARRIER`], [`CARRIER_FULL`],
/// [`NO_SHARED_CARRIER`]).
fn letter_status(book: &LetterBook, peer: &[u8; 32], mid: &[u8; 16], shared: bool) -> Outcome {
    let rows = book.carrying(peer, mid);
    let held = rows.iter().map(|row| row.held_by.len()).max().unwrap_or(0);
    if held > 0 {
        return Outcome::Deposited {
            held: u8::try_from(held).unwrap_or(u8::MAX),
        };
    }
    if !shared {
        return Outcome::Held(NO_SHARED_CARRIER);
    }
    let full = !rows.is_empty()
        && rows
            .iter()
            .all(|row| row.waiting_code() == Some(CARRIER_FULL));
    Outcome::Held(if full {
        CARRIER_FULL
    } else {
        WAITING_FOR_CARRIER
    })
}

/// Messages of `due` in letter sessions this node started that are still
/// provisional (see the module): each such session's PairInit is replayed
/// on `routes` (the contact's own; none: not tried). Confirmed: its rows go
/// out in this attempt as usual. No PairResponse: its copies are parked
/// again (`Resealed` for their entries; `true`: run the horizon step now).
/// Unreachable: its rows wait for their letter (their status, no dial).
/// Expired rows are left to the usual expiry. Gate closed: nothing.
pub(crate) fn settle_letter_rows(
    ctx: &AttemptCtx,
    store: &mut IndexedSessionStore,
    peer: &[u8; 32],
    routes: &[(OutboxRoute, OutboxRoute)],
    due: &[Entry],
    report: &mut PeerReport,
    wall: u64,
) -> bool {
    if !letter_live_enabled() {
        return false;
    }
    let mut sessions: Vec<([u8; 32], IndexedSessionRecordKey, PairInit)> = Vec::new();
    let mut rows: Vec<&Entry> = Vec::new();
    for e in due.iter().filter(|e| {
        !e.is_probe()
            && e.kind == EndpointOutboundKind::Message
            && e.expires_at_ms > wall
            && !report.outcomes.contains_key(&e.object_digest)
    }) {
        if !sessions.iter().any(|(sid, _, _)| *sid == e.session_id) {
            match provisional_letter_session(store, &e.session_id) {
                Ok(Some((key, init))) => sessions.push((e.session_id, key, init)),
                _ => continue,
            }
        }
        rows.push(e);
    }
    if sessions.is_empty() {
        return false;
    }
    let data_dir = ctx.data_dir.as_path();
    let mut repair = false;
    let mut waiting: Vec<[u8; 32]> = Vec::new();
    for (sid, key, init) in &sessions {
        let outcome = if routes.is_empty() {
            DirectCompletion::Unreachable("no route".into())
        } else {
            complete_directly(ctx, store, peer, routes, key, init)
        };
        match outcome {
            DirectCompletion::Confirmed => {
                eprintln!("raven-node outbox: letters: session completed directly");
            }
            DirectCompletion::NoResponse => {
                let parked = PeerSendLock::acquire_within(data_dir, peer, LOCK_WAIT)
                    .and_then(|_lock| abandon_letter_session(data_dir, store, peer, key, wall));
                match parked {
                    Ok(parked) => {
                        eprintln!(
                            "raven-node outbox: letters: no direct completion, parked={}",
                            parked.len()
                        );
                        for e in rows.iter().filter(|e| e.session_id == *sid) {
                            report.outcomes.insert(e.object_digest, Outcome::Resealed);
                        }
                        report.rescan = true;
                        repair = true;
                    }
                    Err(_) => waiting.push(*sid),
                }
            }
            DirectCompletion::Unreachable(_) => waiting.push(*sid),
        }
    }
    if !waiting.is_empty() {
        let book = letter_deposits::load(data_dir, wall).unwrap_or_default();
        let carriers = raven_core::custody_client::deposit_custodians(
            data_dir,
            &ctx.identity.public_key_bytes(),
            peer,
            wall,
        );
        let shared = !carriers.is_empty();
        // Every shared custodian answered that it serves no letter ops (an
        // older build, letters off there) and none holds a letter of the
        // session: no letter of it can reach the contact. Its copies are
        // parked again (the horizon re-pairs once the contact is reached; a
        // later letter session takes them once a custodian serves letters
        // again) instead of waiting for a carrier that cannot come (review
        // letters-2).
        let none_serve = shared && {
            let s = lock();
            carriers
                .iter()
                .all(|(c, _)| s.caps.letters(c, wall) == Some(false))
        };
        if none_serve {
            let held = |sid: &[u8; 32]| {
                book.for_peer(peer, DepositKind::Letter)
                    .any(|row| row.session_id == *sid && !row.held_by.is_empty())
            };
            let mut stranded: Vec<[u8; 32]> = Vec::new();
            for (sid, key, _) in sessions.iter().filter(|(sid, _, _)| waiting.contains(sid)) {
                if held(sid) {
                    continue;
                }
                let parked = PeerSendLock::acquire_within(data_dir, peer, LOCK_WAIT)
                    .and_then(|_lock| abandon_letter_session(data_dir, store, peer, key, wall));
                if let Ok(parked) = parked {
                    eprintln!(
                        "raven-node outbox: letters: no friend serves letters, parked={}",
                        parked.len()
                    );
                    for e in rows.iter().filter(|e| e.session_id == *sid) {
                        report.outcomes.insert(e.object_digest, Outcome::Parked);
                    }
                    report.rescan = true;
                    stranded.push(*sid);
                }
            }
            waiting.retain(|sid| !stranded.contains(sid));
        }
        for e in rows.iter().filter(|e| waiting.contains(&e.session_id)) {
            report.outcomes.insert(
                e.object_digest,
                letter_status(&book, peer, &e.message_id, shared),
            );
        }
    }
    repair
}

/// After the custody phase placed letters: a waiting letter message of
/// `due` whose letter a custodian now holds shows it (`Deposited`).
pub(crate) fn restatus(data_dir: &Path, peer: &[u8; 32], due: &[Entry], report: &mut PeerReport) {
    if !letter_live_enabled() {
        return;
    }
    let waiting: Vec<&Entry> = due
        .iter()
        .filter(|e| {
            matches!(
                report.outcomes.get(&e.object_digest),
                Some(Outcome::Held(code)) if *code == WAITING_FOR_CARRIER || *code == CARRIER_FULL
            )
        })
        .collect();
    if waiting.is_empty() {
        return;
    }
    let Ok(book) = letter_deposits::load(data_dir, raven_core::clock::now_ms()) else {
        return;
    };
    for e in waiting {
        let status = letter_status(&book, peer, &e.message_id, true);
        if matches!(status, Outcome::Deposited { .. }) {
            report.outcomes.insert(e.object_digest, status);
        }
    }
}

/// Whether the owed ACK `ack` belongs to a letter session this node
/// accepted: a REPLY letter carries it, never the base deposit (its
/// initiator can take it only once the REPLY confirmed the session).
pub(crate) fn rides_reply(store: &IndexedSessionStore, ack: &UnsentAck) -> bool {
    letter_live_enabled()
        && ack.session_id.is_some_and(|sid| {
            store.letter_role(&sid).ok().flatten() == Some(LetterRole::Responder)
        })
}

// ---------------------------------------------------------------------------
// The fetcher's letter round
// ---------------------------------------------------------------------------

/// One letter fetch trigger at `custodian` (the fetcher's pass, through its
/// `dial`): RELEASE what is pending, FETCH_LETTERS from the saved cursor,
/// the intake ([`fetch_letters_round`]). A RELEASE, or a fresh answer that
/// it serves letters, offers what waits for a carrier there again at once
/// (the peers whose letters wait are kicked). `None` with the gate closed.
pub(crate) fn fetch_at(
    data_dir: &Path,
    identity: &Identity,
    custodian: &[u8; 32],
    wall: u64,
    max_pages: usize,
    dial: &mut CustodianDial<'_>,
) -> Option<LetterFetchReport> {
    if !letter_live_enabled() {
        return None;
    }
    let mut state = lock().fetch.remove(custodian).unwrap_or_default();
    let (report, fresh) = with_caps(custodian, wall, |caps| {
        fetch_letters_round(
            data_dir, identity, custodian, &mut state, caps, wall, max_pages, dial,
        )
    });
    lock().fetch.insert(*custodian, state);
    if report.unsupported {
        custodian_lost_letters(data_dir, custodian, wall);
    }
    if report.released > 0 || fresh {
        if let Ok(peers) = letter_deposits::retry_now(data_dir, custodian, wall) {
            for peer in peers {
                crate::outbox::kick(Some(&peer), false, false);
            }
        }
    }
    if report.letters > 0 || report.released > 0 {
        eprintln!(
            "raven-node custody: letters fetched={} accepted={} kept={} refused={}",
            report.letters, report.accepted, report.kept, report.refused
        );
    }
    Some(report)
}

#[cfg(test)]
pub(crate) mod tests;
