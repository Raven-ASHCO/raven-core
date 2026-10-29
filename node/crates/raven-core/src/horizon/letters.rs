//! Sealed letters in the worker (Phase 5b, P5.15): the store work of the
//! letter step, under the contact's send lock and never across a dial.
//!
//! - [`build_letters`]: what waits for an unreachable contact (its parked
//!   messages, and direct copies the worker could not deliver) moves into a
//!   letter session, one this node started that still has a day and room
//!   for them ([`crate::horizon::LETTER_SESSION_MAX_MESSAGES`] provisional
//!   indices), or a new one (at most
//!   [`crate::horizon::LETTER_SESSIONS_PER_PEER_PER_DAY`] a day): each is
//!   parked, then sealed again into it in send order (the horizon's re-seal,
//!   under the same message id and the same copy cap), and the new copies
//!   are sealed into RAL1 letters with the session's exact PairInit, to the
//!   contact's cached bundle, recorded in [`crate::letter_deposits`].
//! - [`reletter`]: copies a build moved into a letter session but never
//!   recorded a letter for (it stopped between the two writes) are sealed
//!   into letters of their own.
//! - [`build_replies`]: the REPLY letters a letter session this node
//!   accepted owes: its kept PairResponse and up to 32 of the ACKs owed on
//!   it, sealed to the initiator's cached bundle.
//! - [`abandon_letter_session`]: the contact was reached but no
//!   PairResponse came back for the PairInit replayed directly: the letter
//!   copies are parked again (the horizon's synchronous re-pair takes them)
//!   and the letters are withdrawn.
//!
//! The worker (raven-node) decides when: only with custodians that serve
//! letters, and places the letters itself.

use std::path::Path;

use super::{
    deadline_for, letter_live_enabled, reseal_parked_with, settle_parked, HorizonReport,
    ResealInto, LETTER_MIN_SESSION_LIFETIME_MS, LETTER_SESSIONS_PER_PEER_PER_DAY,
    LETTER_SESSION_LIFETIME_MS, LETTER_SESSION_MAX_MESSAGES,
};
use crate::async_letter::{
    encode_letter_inner, encode_reply_inner, seal, LetterInner, Ral1Error, Ral1Kind, ReplyInner,
    SealInput, MAX_LETTER_ENVELOPES, MAX_LETTER_LIFETIME_MS, MAX_REPLY_ACKS,
};
use crate::envelope::Envelope;
use crate::identity::Identity;
use crate::indexed_session_store::{
    EndpointOutboundKind, IndexedSessionRecordKey, IndexedSessionStore, LetterRole,
    SessionLifecycle,
};
use crate::lan_rlb1::LanBundle;
use crate::letter_deposits::{self, DepositKind, LetterDeposit};
use crate::pair_init::{decode_init, prekey_bundle_hash, PairInit};
use crate::session_reset::{store_err, RESET_RESEAL_MIN_REMAINING_MS};

/// Why [`build_letters`] moved nothing (raven-node's log only).
pub mod code {
    /// No cached bundle of the contact with a day left to seal to.
    pub const LETTER_NO_BUNDLE: &str = "LETTER_NO_BUNDLE";
    /// Today's letter session is full (or could not be started): the rest
    /// stays parked for tomorrow's, or for a re-pair.
    pub const LETTER_DAY_CAP: &str = "LETTER_DAY_CAP";
}

/// A message's direct copy the worker could not deliver in this attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectCopy {
    pub message_id: [u8; 16],
    pub session_id: [u8; 32],
}

/// What [`build_letters`] did.
#[derive(Debug, Default)]
pub struct LetterBuild {
    /// The letters sealed now, recorded and due for placement.
    pub letters: Vec<LetterDeposit>,
    /// Direct copies parked for the letter (moved into it, or left parked
    /// when it had no room).
    pub parked: Vec<[u8; 16]>,
    /// Messages sealed again into the letter session.
    pub moved: Vec<[u8; 16]>,
    /// The horizon's settling and re-seal (given up, delivered, ...).
    pub report: HorizonReport,
    /// Why nothing moved, when nothing did ([`code`]).
    pub held: Option<&'static str>,
}

const DAY_MS: u64 = 24 * 60 * 60 * 1000;

/// The letter session `peer`'s messages go into at `now_ms`, and how many
/// more it takes.
struct LetterTarget {
    key: IndexedSessionRecordKey,
    init: PairInit,
    wire: Vec<u8>,
    room: usize,
}

/// Move what waits for `peer` into a letter session and seal it into RAL1
/// letters (see the module). Run under `peer`'s send lock; nothing is
/// dialled. `direct`: copies the worker could not deliver now, oldest first.
/// With the letter gate closed: nothing.
pub fn build_letters(
    data_dir: &Path,
    identity: &Identity,
    store: &mut IndexedSessionStore,
    peer: &[u8; 32],
    direct: &[DirectCopy],
    now_ms: u64,
) -> Result<LetterBuild, String> {
    let mut out = LetterBuild::default();
    if !letter_live_enabled() {
        return Ok(out);
    }
    settle_parked(data_dir, identity, store, peer, now_ms, &mut out.report)?;
    let parked = store.parked_for_recipient(peer).map_err(store_err)?;
    if parked.is_empty() && direct.is_empty() {
        return Ok(out);
    }
    let Some(bundle) = crate::lan_dispatch::load_cached_peer_bundle(data_dir, peer)?.filter(|b| {
        b.prekey.expires_at_ms >= now_ms.saturating_add(LETTER_MIN_SESSION_LIFETIME_MS)
    }) else {
        out.held = Some(code::LETTER_NO_BUNDLE);
        return Ok(out);
    };
    let book = letter_deposits::load(data_dir, now_ms)?;
    let Some(target) = letter_target(data_dir, identity, store, peer, &bundle, &book, now_ms)?
    else {
        out.held = Some(code::LETTER_DAY_CAP);
        return Ok(out);
    };
    // Parked messages are older: they go first. Direct copies follow, as
    // many as the session still takes.
    let room_left = target.room.saturating_sub(parked.len());
    for copy in direct.iter().take(room_left) {
        let parked_now = crate::outbox::park_expired_message(
            data_dir,
            store,
            peer,
            &copy.message_id,
            Some(&copy.session_id),
            false,
            now_ms,
        )?;
        if parked_now.is_some() {
            out.parked.push(copy.message_id);
        }
    }
    let into = ResealInto {
        limit: target.room,
        validity_ms: LETTER_SESSION_LIFETIME_MS,
    };
    reseal_parked_with(
        data_dir,
        identity,
        store,
        peer,
        &target.key,
        into,
        now_ms,
        &mut out.report,
    )?;
    out.moved = out.report.resealed.iter().map(|r| r.message_id).collect();
    let sealed: Vec<SealedCopy> = out
        .report
        .resealed
        .iter()
        .filter_map(|r| {
            let bytes = r.new.immutable_envelope_bytes.clone();
            let expires = Envelope::unpack(&bytes)?.expires_at;
            Some((r.message_id, bytes, expires))
        })
        .collect();
    if sealed.is_empty() {
        return Ok(out);
    }
    let rows = seal_letters(
        identity,
        &bundle,
        peer,
        &target.init,
        &target.wire,
        &sealed,
        &book,
        now_ms,
    )?;
    let recorded = rows.clone();
    letter_deposits::update(data_dir, now_ms, |book| book.letters.extend(recorded))?;
    out.letters = rows;
    Ok(out)
}

/// `sealed` (copies in the letter session `init` started, in send order)
/// sealed into LETTER rows to `bundle`, not recorded yet. `book`: the
/// letters recorded so far (read under `peer`'s send lock, like every
/// write of a LETTER).
#[allow(clippy::too_many_arguments)]
fn seal_letters(
    identity: &Identity,
    bundle: &LanBundle,
    peer: &[u8; 32],
    init: &PairInit,
    wire: &[u8],
    sealed: &[SealedCopy],
    book: &letter_deposits::LetterBook,
    now_ms: u64,
) -> Result<Vec<LetterDeposit>, String> {
    let session_id = crate::pair_init::session_id(init).map_err(|e| e.to_string())?;
    // Written no earlier than its PairInit (a session started just now
    // stamps its own clock, after this step's `now_ms`), and after every
    // letter already recorded for `peer`: a re-letter and a new build in
    // one worker attempt run at the same wall time, and the recipient
    // orders letters by this stamp (re-verify of letters-3 x letters-4).
    let after_last = book
        .for_peer(peer, DepositKind::Letter)
        .map(|row| row.created_at_ms.saturating_add(1))
        .max()
        .unwrap_or(0);
    let created = now_ms.max(init.created_at_ms).max(after_last);
    let mut rows = Vec::new();
    for (i, chunk) in letter_chunks(wire, sealed)?.into_iter().enumerate() {
        // Each letter a millisecond after the one before: the recipient
        // takes them in that order, so the session's messages reach its
        // inbox in send order (review letters-4).
        let written = created.saturating_add(i as u64);
        let expires = chunk
            .iter()
            .map(|(_, _, expires)| *expires)
            .max()
            .unwrap_or(written)
            .min(init.expires_at_ms);
        let inner = encode_letter_inner(&LetterInner {
            pair_init: wire.to_vec(),
            envelopes: chunk.iter().map(|(_, bytes, _)| bytes.clone()).collect(),
        })
        .map_err(|e| e.code().to_string())?;
        let letter = seal_letter(identity, Ral1Kind::Letter, bundle, &inner, written, expires)?;
        rows.push(LetterDeposit::new(
            DepositKind::Letter,
            *peer,
            session_id,
            letter,
            written,
            expires,
            chunk.iter().map(|(mid, _, _)| *mid).collect(),
            Vec::new(),
        ));
    }
    Ok(rows)
}

/// The copies waiting in `peer`'s provisional letter sessions (this node
/// started them; not given up; to the bundle cached now) that no letter
/// carries, per session with its PairInit (decoded and exact), in send
/// order, and that bundle: a build that sealed them into the session and
/// stopped before its letters were recorded (an error, a kill, a book write
/// that failed: the two stores are not written together).
fn unlettered(
    data_dir: &Path,
    store: &mut IndexedSessionStore,
    peer: &[u8; 32],
    now_ms: u64,
) -> Result<Option<(LanBundle, Vec<Unlettered>)>, String> {
    let book = letter_deposits::load(data_dir, now_ms)?;
    let open = store
        .live_letter_sessions_for_peer(peer, LetterRole::Initiator, now_ms)
        .map_err(store_err)?;
    if open
        .iter()
        .all(|(_, row)| book.is_abandoned(&row.session_id))
    {
        return Ok(None);
    }
    let Some(bundle) = crate::lan_dispatch::load_cached_peer_bundle(data_dir, peer)?
        .filter(|b| b.prekey.expires_at_ms > now_ms)
    else {
        return Ok(None);
    };
    let bundle_hash = prekey_bundle_hash(&bundle.prekey).map_err(|e| format!("{e:?}"))?;
    let mut rows = store
        .pending_endpoint_outbound_for_recipient(Some(peer))
        .map_err(store_err)?;
    rows.extend(
        store
            .awaiting_ack_endpoint_outbound_for_recipient(Some(peer))
            .map_err(store_err)?,
    );
    let mut out = Vec::new();
    for (_, session) in open {
        if book.is_abandoned(&session.session_id) {
            continue;
        }
        let mut copies: Vec<&crate::indexed_session_store::EndpointOutbound> = rows
            .iter()
            .filter(|r| {
                r.session_id == session.session_id
                    && r.kind == EndpointOutboundKind::Message
                    && book.carrying(peer, &r.message_id).is_empty()
            })
            .collect();
        if copies.is_empty() {
            continue;
        }
        let (Some((_, init)), Some(wire)) = (
            provisional_letter_session(store, &session.session_id)?,
            session.pair_init,
        ) else {
            continue;
        };
        if init.responder_prekey_bundle_hash != bundle_hash {
            continue;
        }
        copies.sort_by_key(|r| r.ratchet_index);
        let sealed: Vec<SealedCopy> = copies
            .iter()
            .filter_map(|r| {
                let expires = Envelope::unpack(&r.immutable_envelope_bytes)?.expires_at;
                (expires > now_ms)
                    .then(|| (r.message_id, r.immutable_envelope_bytes.clone(), expires))
            })
            .collect();
        if !sealed.is_empty() {
            out.push((init, wire, sealed));
        }
    }
    Ok(Some((bundle, out)))
}

/// Whether some copy waits in a letter session of `peer`'s with no letter
/// to carry it ([`reletter`] has work). Read-only; gate closed: no.
pub fn has_unlettered(
    data_dir: &Path,
    store: &mut IndexedSessionStore,
    peer: &[u8; 32],
    now_ms: u64,
) -> bool {
    letter_live_enabled()
        && unlettered(data_dir, store, peer, now_ms)
            .is_ok_and(|found| found.is_some_and(|(_, found)| !found.is_empty()))
}

/// Letter the copies a build left in `peer`'s letter sessions without a
/// letter (review letters-3): their envelopes, sealed already, go into new
/// LETTERs with their session's exact PairInit, to the cached bundle that
/// PairInit names, recorded and due for placement. Run under `peer`'s send
/// lock (as [`build_letters`]); nothing is dialled. The letters recorded.
pub fn reletter(
    data_dir: &Path,
    identity: &Identity,
    store: &mut IndexedSessionStore,
    peer: &[u8; 32],
    now_ms: u64,
) -> Result<Vec<LetterDeposit>, String> {
    if !letter_live_enabled() {
        return Ok(Vec::new());
    }
    let Some((bundle, found)) = unlettered(data_dir, store, peer, now_ms)? else {
        return Ok(Vec::new());
    };
    let mut book = letter_deposits::load(data_dir, now_ms)?;
    let mut rows = Vec::new();
    for (init, wire, sealed) in found {
        let sealed = seal_letters(
            identity, &bundle, peer, &init, &wire, &sealed, &book, now_ms,
        )?;
        // The next session's letters stamp after these.
        book.letters.extend(sealed.iter().cloned());
        rows.extend(sealed);
    }
    if !rows.is_empty() {
        let recorded = rows.clone();
        letter_deposits::update(data_dir, now_ms, |book| book.letters.extend(recorded))?;
    }
    Ok(rows)
}

/// The open letter session for `peer` (newest first: one this node started,
/// not given up, with at least a day left, room, and a PairInit to the
/// bundle cached now), else a new one when none was started in the last
/// day. `None`: today's is full.
fn letter_target(
    data_dir: &Path,
    identity: &Identity,
    store: &mut IndexedSessionStore,
    peer: &[u8; 32],
    bundle: &LanBundle,
    book: &letter_deposits::LetterBook,
    now_ms: u64,
) -> Result<Option<LetterTarget>, String> {
    let bundle_hash = prekey_bundle_hash(&bundle.prekey).map_err(|e| format!("{e:?}"))?;
    let open = store
        .live_letter_sessions_for_peer(peer, LetterRole::Initiator, now_ms)
        .map_err(store_err)?;
    for (key, row) in &open {
        let Some(wire) = &row.pair_init else {
            continue;
        };
        let Ok(init) = decode_init(wire) else {
            continue;
        };
        if book.is_abandoned(&row.session_id)
            || init.responder_prekey_bundle_hash != bundle_hash
            || init.expires_at_ms.saturating_sub(now_ms) < LETTER_MIN_SESSION_LIFETIME_MS
        {
            continue;
        }
        let next = store.message_send_next_index(key).map_err(store_err)?;
        let room = u64::from(LETTER_SESSION_MAX_MESSAGES).saturating_sub(next);
        if room > 0 {
            return Ok(Some(LetterTarget {
                key: key.clone(),
                init,
                wire: wire.clone(),
                room: usize::try_from(room).unwrap_or(0),
            }));
        }
    }
    let today = open
        .iter()
        .filter(|(_, row)| now_ms.saturating_sub(row.created_at_ms) < DAY_MS)
        .count();
    if today >= LETTER_SESSIONS_PER_PEER_PER_DAY {
        return Ok(None);
    }
    let (init, key) = match crate::lan_dispatch::create_letter_pair_init(data_dir, identity, bundle)
    {
        Ok(created) => created,
        // A bundle or certificate ending within a day, a one-time
        // prekey, a pin that refuses it: no letter session now.
        Err(e) if e.contains("refused") => return Ok(None),
        Err(e) => return Err(e),
    };
    let wire = crate::pair_init::encode_init(&init).map_err(|e| format!("{e:?}"))?;
    Ok(Some(LetterTarget {
        key,
        init,
        wire,
        room: LETTER_SESSION_MAX_MESSAGES as usize,
    }))
}

/// One copy sealed into the letter session: its message id, the packed
/// envelope and when it expires.
type SealedCopy = ([u8; 16], Vec<u8>, u64);

/// Copies of one letter session that no letter carries: its PairInit
/// (decoded, and the exact bytes it keeps) and the copies.
type Unlettered = (PairInit, Vec<u8>, Vec<SealedCopy>);

/// Split the sealed copies into letters whose inner fits
/// ([`crate::async_letter::MAX_RAL1_INNER`], at most
/// [`MAX_LETTER_ENVELOPES`] each), in order.
fn letter_chunks<'a>(
    pair_init: &[u8],
    sealed: &'a [SealedCopy],
) -> Result<Vec<&'a [SealedCopy]>, String> {
    let fits = |chunk: &[SealedCopy]| {
        encode_letter_inner(&LetterInner {
            pair_init: pair_init.to_vec(),
            envelopes: chunk.iter().map(|(_, bytes, _)| bytes.clone()).collect(),
        })
        .is_ok()
    };
    let mut chunks = Vec::new();
    let mut start = 0;
    while start < sealed.len() {
        let mut end = (start + MAX_LETTER_ENVELOPES).min(sealed.len());
        while end > start + 1 && !fits(&sealed[start..end]) {
            end -= 1;
        }
        if !fits(&sealed[start..end]) {
            return Err(Ral1Error::TooLarge.code().to_string());
        }
        chunks.push(&sealed[start..end]);
        start = end;
    }
    Ok(chunks)
}

/// Seal and sign `inner` to `to`'s signed prekey (its bundle hash names it),
/// with a fresh ephemeral key and letter id.
fn seal_letter(
    from: &Identity,
    kind: Ral1Kind,
    to: &LanBundle,
    inner: &[u8],
    created_at_ms: u64,
    expires_at_ms: u64,
) -> Result<Vec<u8>, String> {
    use rand::RngCore;
    let mut ephemeral = zeroize::Zeroizing::new([0u8; 32]);
    let mut letter_id = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut *ephemeral);
    while letter_id == [0u8; 16] {
        rand::rngs::OsRng.fill_bytes(&mut letter_id);
    }
    seal(
        from,
        &ephemeral,
        &SealInput {
            kind,
            letter_id,
            recipient_device: to.cert.device_ed_pub,
            created_at_ms,
            expires_at_ms,
            wrap_bundle_hash: prekey_bundle_hash(&to.prekey).map_err(|e| format!("{e:?}"))?,
            recipient_signed_prekey: to.prekey.x25519_pub,
            inner,
        },
    )
    .map_err(|e| e.code().to_string())
}

/// An ACK this node owes `peer`, as the worker holds it.
#[derive(Debug, Clone, Copy)]
pub struct OwedAckRef<'a> {
    pub digest: [u8; 32],
    pub session_id: Option<[u8; 32]>,
    pub bytes: &'a [u8],
    pub expires_at_ms: u64,
}

/// The REPLY letters owed to `peer` at `now_ms` (see the module): one per
/// letter session this node accepted from `peer` with owed ACKs no REPLY
/// carries yet (32 a letter), with the PairResponse its row keeps, sealed
/// to `peer`'s cached bundle and recorded. Nothing is dialled; no session
/// state is written (no lock needed). Gate closed, no bundle: nothing.
pub fn build_replies(
    data_dir: &Path,
    identity: &Identity,
    store: &mut IndexedSessionStore,
    peer: &[u8; 32],
    owed: &[OwedAckRef<'_>],
    now_ms: u64,
) -> Result<Vec<LetterDeposit>, String> {
    if !letter_live_enabled() || owed.is_empty() {
        return Ok(Vec::new());
    }
    let book = letter_deposits::load(data_dir, now_ms)?;
    let carried: Vec<[u8; 32]> = book
        .for_peer(peer, DepositKind::Reply)
        .flat_map(|row| row.acks.iter().copied())
        .collect();
    let mut by_session: Vec<([u8; 32], Vec<OwedAckRef<'_>>)> = Vec::new();
    for ack in owed {
        let Some(sid) = ack.session_id else {
            continue;
        };
        if carried.contains(&ack.digest) || ack.expires_at_ms <= now_ms {
            continue;
        }
        if store.letter_role(&sid).map_err(store_err)? != Some(LetterRole::Responder) {
            continue;
        }
        match by_session.iter_mut().find(|(s, _)| *s == sid) {
            Some((_, acks)) => acks.push(*ack),
            None => by_session.push((sid, vec![*ack])),
        }
    }
    if by_session.is_empty() {
        return Ok(Vec::new());
    }
    let Some(bundle) = crate::lan_dispatch::load_cached_peer_bundle(data_dir, peer)?
        .filter(|b| b.prekey.expires_at_ms > now_ms)
    else {
        return Ok(Vec::new());
    };
    let mut rows = Vec::new();
    for (sid, acks) in by_session {
        let Some(pair_response) = store.letter_reply(&sid).map_err(store_err)? else {
            continue;
        };
        let Some(key) = store.record_key_for_session_id(&sid).map_err(store_err)? else {
            continue;
        };
        let expires = store
            .session_expires_at(&key)
            .map_err(store_err)?
            .min(now_ms.saturating_add(MAX_LETTER_LIFETIME_MS));
        if expires <= now_ms {
            continue;
        }
        for chunk in acks.chunks(MAX_REPLY_ACKS) {
            let inner = encode_reply_inner(&ReplyInner {
                pair_response: pair_response.clone(),
                acks: chunk.iter().map(|ack| ack.bytes.to_vec()).collect(),
            })
            .map_err(|e| e.code().to_string())?;
            let letter = seal_letter(identity, Ral1Kind::Reply, &bundle, &inner, now_ms, expires)?;
            rows.push(LetterDeposit::new(
                DepositKind::Reply,
                *peer,
                sid,
                letter,
                now_ms,
                expires,
                Vec::new(),
                chunk.iter().map(|ack| ack.digest).collect(),
            ));
        }
    }
    if !rows.is_empty() {
        let recorded = rows.clone();
        letter_deposits::update(data_dir, now_ms, |book| book.letters.extend(recorded))?;
    }
    Ok(rows)
}

/// `session_id`'s session when it is a letter session this node started
/// that is still provisional: its key and the exact PairInit it keeps.
pub fn provisional_letter_session(
    store: &mut IndexedSessionStore,
    session_id: &[u8; 32],
) -> Result<Option<(IndexedSessionRecordKey, PairInit)>, String> {
    if store.letter_role(session_id).map_err(store_err)? != Some(LetterRole::Initiator) {
        return Ok(None);
    }
    let Some(key) = store
        .record_key_for_session_id(session_id)
        .map_err(store_err)?
    else {
        return Ok(None);
    };
    if store.session_lifecycle(&key).map_err(store_err)? != SessionLifecycle::Provisional {
        return Ok(None);
    }
    let Some(wire) = store
        .letter_session(session_id)
        .map_err(store_err)?
        .and_then(|row| row.pair_init)
    else {
        return Ok(None);
    };
    Ok(decode_init(&wire).ok().map(|init| (key, init)))
}

/// The contact was reached and the letter session `key` (with `peer`) got no
/// PairResponse for its replayed PairInit (an older peer, a rotated
/// bundle): park its copies again for the horizon's re-pair (their deadlines
/// and the copy cap stand), and give the session up, so its letters are
/// withdrawn and no new letter goes into it. Run under `peer`'s send lock.
/// The messages parked.
pub fn abandon_letter_session(
    data_dir: &Path,
    store: &mut IndexedSessionStore,
    peer: &[u8; 32],
    key: &IndexedSessionRecordKey,
    now_ms: u64,
) -> Result<Vec<[u8; 16]>, String> {
    let sid = store.session_id_for_record_key(key).map_err(store_err)?;
    let until = store.session_expires_at(key).map_err(store_err)?;
    let mut rows = store
        .pending_endpoint_outbound_for_recipient(Some(peer))
        .map_err(store_err)?;
    rows.extend(
        store
            .awaiting_ack_endpoint_outbound_for_recipient(Some(peer))
            .map_err(store_err)?,
    );
    let mut parked = Vec::new();
    for row in rows
        .iter()
        .filter(|r| r.session_id == sid && r.kind == EndpointOutboundKind::Message)
    {
        if crate::outbox::park_expired_message(
            data_dir,
            store,
            peer,
            &row.message_id,
            Some(&sid),
            false,
            now_ms,
        )?
        .is_some()
        {
            parked.push(row.message_id);
        }
    }
    letter_deposits::update(data_dir, now_ms, |book| book.abandon(&sid, until))?;
    Ok(parked)
}

/// When `message_id` to `peer` may still wait for a letter: its deadline is
/// more than the re-seal margin away.
pub fn may_wait_for_letter(
    data_dir: &Path,
    peer: &[u8; 32],
    message_id: &[u8; 16],
    now_ms: u64,
) -> bool {
    deadline_for(data_dir, peer, message_id).is_some_and(|(_, deadline)| {
        deadline > now_ms.saturating_add(RESET_RESEAL_MIN_REMAINING_MS)
    })
}

#[cfg(test)]
mod tests;
