//! The requester side of friend custody (`docs/design/2026-10-friend-custody.md`
//! §7.3 step 3 and §8.1): DEPOSIT batches for a custodian, and one fetch round
//! (RELEASE + FETCH pages, relayed ingest). Pure over a `dial` closure, so the
//! worker, the fetcher task and in-process tests share it. The letter ops
//! (Phase 5b) and the custodian capability cache are in [`letters`].
//!
//! **Custody handoff (Phase 5 P5.20, `protocol/RAVEN_CUSTODY_HANDOFF_V1.md`
//! §3.2, §3.5, §3.6)**: [`custody_batch`] mixes DEPOSITs and HANDOFF/FORWARDs
//! in one dial ([`deposit_batch`] is its DEPOSIT-only form),
//! [`fetch_round_with`] registers the recipient's inbound tags (TAGS
//! REGISTER, [`inbound_register_tags`]) ahead of RELEASE and FETCH, and
//! [`handoff`] holds the plan ([`custody_plan`] over
//! [`announced_custodians`]) and the forwarder's [`forward_round`]. Handoff
//! frames go out only while [`crate::custody_gate::handoff_live`]; what a
//! custodian's answers show about the handoff ops lives in the one
//! [`CapabilityCache`].

use std::collections::{BTreeMap, HashMap};
use std::ops::Range;
use std::path::Path;

use crate::custody_handoff::{Rhw1, TagsAction, MAX_TAG_ENTRIES, MAX_TAG_TTL_MS};
use crate::friend_custody::{
    check_rfc1_rso1, custody_digest, decode_reply, encode_request, CustodyCode, Rfc1Reply,
    Rfc1Request, MAX_FETCH_ITEMS, MAX_FETCH_TAGS, MAX_RELEASE_DIGESTS, OP_TAGS,
};
use crate::identity::Identity;
use crate::indexed_session_store::{
    fetch_days, register_days, IndexedSessionRecordKey, IndexedSessionStore, MailboxDirection,
    SessionHeadMeta,
};
use crate::relayed_ingest::{ingest_relayed_object_sensed, RelayHint, RelayedOutcome, RetryScope};
use crate::security_events::SecKind;

/// A message goes to custody only once it is this old (the direct path had
/// its chance). Lab override: `RAVEN_LAB_CUSTODY_AFTER_MS` (debug + lab A).
pub const CUSTODY_AFTER_MS: u64 = 60_000;
/// ... and only with at least this much validity left.
pub const CUSTODY_MIN_REMAINING_MS: u64 = 60_000;

pub fn custody_after_ms() -> u64 {
    if crate::pair_init::lab_test_a_enabled() {
        if let Some(v) = std::env::var("RAVEN_LAB_CUSTODY_AFTER_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
        {
            return v;
        }
    }
    CUSTODY_AFTER_MS
}

/// A worker custody dial carries at most this many DEPOSITs.
pub const MAX_DEPOSITS_PER_DIAL: usize = 16;
/// ... and at most this many bytes of RSO1 (a lone larger object gets a dial
/// of its own): [`deposit_chunks`].
pub const MAX_DEPOSIT_BYTES_PER_DIAL: usize = 512 * 1024;
/// Pages per fetch trigger and custodian.
pub const MAX_PAGES_PER_TRIGGER: usize = 8;
/// Pages per fetch trigger while the custodian's last path was relayed: at
/// most 512 KiB a trigger inside a friend relay's 2 MiB / 5 min circuit
/// budget.
pub const MAX_PAGES_PER_TRIGGER_RELAYED: usize = 4;
/// Pending releases kept per custodian.
pub const MAX_PENDING_RELEASES: usize = 256;

/// One object to leave with a custodian: the RSO1 (with its deposit tag) for
/// `recipient`.
#[derive(Debug, Clone)]
pub struct DepositItem {
    pub recipient: [u8; 32],
    pub rso1: Vec<u8>,
}

/// The custodian's answer per deposited object, in input order. `None`: no
/// answer came back (a missing reply is transient).
pub type DepositAnswers = Vec<Option<CustodyCode>>;

mod letters;
pub use letters::{
    deposit_letters, fetch_letters_round, letter_gate_closed, withdraw_letters, CapabilityCache,
    CustodianCapability, LetterAnswer, LetterDeposit, LetterFetchReport, LetterFetchState,
    WithdrawReport, CAPABILITY_TTL_MS,
};

pub mod handoff;
pub use handoff::{
    announced_custodians, custody_plan, forward_round, handoff_gate_closed, Announced,
    ForwardAnswers, HandoffParked, PlanStep,
};

/// One dial to a custodian: frames out, every reply frame back.
pub type CustodianDial<'a> = dyn FnMut(&[Vec<u8>]) -> Result<Vec<Vec<u8>>, String> + 'a;

/// Custodians to fetch from, each with the contacts that list it.
pub type FetchTargets = Vec<([u8; 32], Vec<[u8; 32]>)>;

fn req_id(i: usize, salt: u8) -> [u8; 8] {
    let mut id = [0u8; 8];
    id[0] = salt;
    id[1..8].copy_from_slice(&(i as u64).to_be_bytes()[1..]);
    id
}

/// Request-id salt of a DEPOSIT or HANDOFF/FORWARD in a worker's dial.
const SALT_DEPOSIT: u8 = 0xD0;

/// The index a reply's `req_id` carries, when it has `salt`.
fn index_of(id: &[u8; 8], salt: u8) -> Option<usize> {
    (id[0] == salt)
        .then(|| u64::from_be_bytes([0, id[1], id[2], id[3], id[4], id[5], id[6], id[7]]) as usize)
}

/// DEPOSIT up to [`MAX_DEPOSITS_PER_DIAL`] items in one dial. `Err` is the
/// dial error (the caller classifies it, e.g. a strike on PEER_CLOSED).
/// [`custody_batch`] with DEPOSITs only: the same frames and answers.
pub fn deposit_batch(
    items: &[DepositItem],
    dial: &mut CustodianDial<'_>,
) -> Result<DepositAnswers, String> {
    let items: Vec<CustodyItem> = items
        .iter()
        .take(MAX_DEPOSITS_PER_DIAL)
        .map(|it| CustodyItem::Deposit {
            recipient: it.recipient,
            rso1: it.rso1.clone(),
        })
        .collect();
    let answers = exchange(&items, false, dial)?;
    Ok(answers
        .into_iter()
        .map(|answer| match answer {
            Some(ItemAnswer::Code(code)) => Some(code),
            _ => None,
        })
        .collect())
}

/// One object for a custodian C's dial (`RAVEN_CUSTODY_HANDOFF_V1.md`
/// §3.5): an RFC1 DEPOSIT for `recipient`, or a HANDOFF/FORWARD asking C to
/// hand it on to the final custodian `next_hop` (no recipient on the wire).
#[derive(Debug, Clone)]
pub enum CustodyItem {
    Deposit { recipient: [u8; 32], rso1: Vec<u8> },
    Forward { next_hop: [u8; 32], rso1: Vec<u8> },
}

/// A custodian's answer to one DEPOSIT or HANDOFF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemAnswer {
    /// DEPOSIT_RESULT or HANDOFF_RESULT with this code.
    Code(CustodyCode),
    /// The custodian does not serve the handoff ops (built before them, or
    /// its handoff gate is closed): park handoff there for
    /// [`CAPABILITY_TTL_MS`] (the cache does), plain custody unaffected.
    Unsupported,
}

impl ItemAnswer {
    /// The custodian holds the object (STORED or DUPLICATE): for a FORWARD,
    /// held by that custodian (forwarded, never delivered).
    pub fn held(self) -> bool {
        matches!(self, Self::Code(code) if code.held())
    }
}

/// DEPOSIT and HANDOFF/FORWARD up to [`MAX_DEPOSITS_PER_DIAL`] items in one
/// dial to `custodian` (salt 0xD0, the item's index in bytes 1..8), the
/// answer per item in input order: DEPOSIT_RESULT, HANDOFF_RESULT or
/// `UNSUPPORTED`, matched by `req_id` (`None`: no answer came back, which is
/// transient). FORWARDs go out only while the handoff gate is open
/// ([`crate::custody_gate::handoff_live`]; otherwise they are not sent and
/// answer `None`) and not to a custodian the cache knows without the
/// handoff ops (answered [`ItemAnswer::Unsupported`] without being sent).
/// What the answers to FORWARDs show is kept in `caps`. Nothing is dialled
/// when nothing is to be sent. `Err`: the dial error.
pub fn custody_batch(
    custodian: &[u8; 32],
    items: &[CustodyItem],
    caps: &mut CapabilityCache,
    now_ms: u64,
    dial: &mut CustodianDial<'_>,
) -> Result<Vec<Option<ItemAnswer>>, String> {
    let items = &items[..items.len().min(MAX_DEPOSITS_PER_DIAL)];
    let forwards = items
        .iter()
        .any(|it| matches!(it, CustodyItem::Forward { .. }));
    let known_without = caps.handoff(custodian, now_ms) == Some(false);
    let send_forwards = forwards && !known_without && crate::custody_gate::handoff_live();
    let sent = |it: &CustodyItem| send_forwards || matches!(it, CustodyItem::Deposit { .. });
    if !items.iter().any(sent) {
        return Ok(items
            .iter()
            .map(|_| known_without.then_some(ItemAnswer::Unsupported))
            .collect());
    }
    let mut answers = exchange(items, send_forwards, dial)?;
    for (item, answer) in items.iter().zip(answers.iter_mut()) {
        if !matches!(item, CustodyItem::Forward { .. }) {
            continue;
        }
        match answer {
            Some(ItemAnswer::Code(_)) => {
                caps.note(custodian, CustodianCapability::Handoff, true, now_ms);
            }
            Some(ItemAnswer::Unsupported) => {
                caps.note(custodian, CustodianCapability::Handoff, false, now_ms);
            }
            None if known_without => *answer = Some(ItemAnswer::Unsupported),
            None => {}
        }
    }
    Ok(answers)
}

/// One dial with `items` (FORWARDs only when `forwards`), the answers by
/// `req_id`: a DEPOSIT takes only DEPOSIT_RESULT and a FORWARD only
/// HANDOFF_RESULT or `UNSUPPORTED` (a refusal never comes back as another
/// op's reply).
fn exchange(
    items: &[CustodyItem],
    forwards: bool,
    dial: &mut CustodianDial<'_>,
) -> Result<Vec<Option<ItemAnswer>>, String> {
    let frames: Vec<Vec<u8>> = items
        .iter()
        .enumerate()
        .filter_map(|(i, it)| {
            let request = match it {
                CustodyItem::Deposit { recipient, rso1 } => Rfc1Request::Deposit {
                    recipient: *recipient,
                    rso1: rso1.clone(),
                },
                CustodyItem::Forward { next_hop, rso1 } if forwards => Rfc1Request::Handoff {
                    record: Rhw1::forward(*next_hop, rso1.clone()),
                },
                CustodyItem::Forward { .. } => return None,
            };
            Some(encode_request(&req_id(i, SALT_DEPOSIT), &request))
        })
        .collect();
    let replies = dial(&frames)?;
    let mut answers: Vec<Option<ItemAnswer>> = vec![None; items.len()];
    for reply in &replies {
        let Ok((id, reply)) = decode_reply(reply) else {
            continue;
        };
        let Some(i) = index_of(&id, SALT_DEPOSIT).filter(|i| *i < items.len()) else {
            continue;
        };
        let forward = matches!(items[i], CustodyItem::Forward { .. });
        let answer = match reply {
            Rfc1Reply::DepositResult { code, .. } if !forward => ItemAnswer::Code(code),
            Rfc1Reply::HandoffResult { code, .. } if forward => ItemAnswer::Code(code),
            // A base DEPOSIT is never unsupported by a custodian: as before
            // the handoff ops, such a reply is no answer.
            Rfc1Reply::Unsupported { .. } if forward => ItemAnswer::Unsupported,
            _ => continue,
        };
        answers[i] = Some(answer);
    }
    Ok(answers)
}

/// The dials a list of objects (RSO1 sizes `sizes`, in order) takes: runs
/// of consecutive objects, each at most [`MAX_DEPOSITS_PER_DIAL`] objects
/// and [`MAX_DEPOSIT_BYTES_PER_DIAL`] bytes. A lone object larger than the
/// byte budget gets a dial of its own.
pub fn deposit_chunks(sizes: &[usize]) -> Vec<Range<usize>> {
    let mut out = Vec::new();
    let (mut start, mut bytes) = (0, 0usize);
    for (i, &size) in sizes.iter().enumerate() {
        let count = i - start;
        if count > 0
            && (count == MAX_DEPOSITS_PER_DIAL
                || bytes.saturating_add(size) > MAX_DEPOSIT_BYTES_PER_DIAL)
        {
            out.push(start..i);
            (start, bytes) = (i, 0);
        }
        bytes = bytes.saturating_add(size);
    }
    if start < sizes.len() {
        out.push(start..sizes.len());
    }
    out
}

/// Per-custodian fetch state kept in memory between triggers.
#[derive(Debug, Default)]
pub struct FetchState {
    /// Digests accepted, refused or duplicate: released on the next dial.
    pub pending_release: Vec<[u8; 32]>,
    /// Saved cursors by chunk (the first tag of the sorted chunk).
    pub cursors: HashMap<[u8; 16], [u8; 32]>,
    /// The chunk the next trigger starts with (its index among the sorted
    /// chunks, taken modulo their number).
    pub next_chunk: usize,
    /// Inbound tags registered at this custodian (TAGS REGISTER answered
    /// OK), each with the expiry it was registered with and when the
    /// custodian answered that OK ([`fetch_round_with`]).
    pub registered: HashMap<[u8; 16], Registered>,
    /// Digests this custodian answered a RELEASE for with OK (the latest
    /// [`MAX_PENDING_RELEASES`]): one served again is a replay
    /// ([`FetchReport::misbehaviour`]).
    pub released: Vec<[u8; 32]>,
}

/// One tag registered at a custodian ([`FetchState::registered`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Registered {
    /// The expiry it was registered with.
    pub expiry: u64,
    /// When the custodian answered that registration OK (wall ms).
    pub confirmed_ms: u64,
}

/// What one fetch round did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct FetchReport {
    pub dials: usize,
    pub items: usize,
    /// Messages taken, group copies included.
    pub accepted_messages: usize,
    /// Of those, group copies (a group frame): the fetch line counts them
    /// apart (E2 r9).
    pub accepted_group_copies: usize,
    pub accepted_acks: usize,
    pub refused: usize,
    /// Of `refused`: objects under this node's tags that the contact the tag
    /// names did not sign (someone else left them with the custodian).
    /// Released; never the custodian's misbehaviour.
    pub foreign: usize,
    pub retried: usize,
    pub released: usize,
    /// Peers to back off (`Retry(Peer)`), with why.
    pub peer_backoff: Vec<([u8; 32], &'static str)>,
    /// A store-wide problem stopped the round.
    pub store_trouble: Option<&'static str>,
    /// The custodian answered with a non-OK code (park / back off).
    pub custodian_code: Option<CustodyCode>,
    /// Peers whose objects were accepted (kick their outbox).
    pub touched: Vec<[u8; 32]>,
    /// TAGS REGISTER frames went out and every one was answered OK.
    pub tags_ok: bool,
    /// The first non-OK code a TAGS_RESULT carried.
    pub tags_code: Option<CustodyCode>,
    /// The custodian answered TAGS `UNSUPPORTED` (now cached).
    pub tags_unsupported: bool,
    /// Registered tags the custodian found held by another recipient (both
    /// lose them): counts only.
    pub tag_conflicts: usize,
    /// What the custodian did wrong this round (Phase 6b S18), one entry
    /// per occurrence: an item that does not decode or an object refused
    /// before its sender's signature vouched for it
    /// ([`SecKind::CustodianBadObject`]), an item under a tag this round
    /// did not ask for ([`SecKind::CustodianUnrequested`]), an object it
    /// serves again after answering its RELEASE, or one the store refuses
    /// as a replay ([`SecKind::CustodianReplay`]). The fetcher notes them
    /// about the custodian.
    pub misbehaviour: Vec<SecKind>,
    /// Refusals of objects their sender's signature vouched for (S6-S11):
    /// the contact and the kind, noted about the contact.
    pub sender_events: Vec<([u8; 32], SecKind)>,
}

impl FetchReport {
    /// The custodian turned this node away this round: it answered TAGS or
    /// the FETCH `POLICY_DENIED`, `HOLD` or `NOT_VERIFIED` (custody or
    /// handoff off there, its link gate closed, this node no longer its
    /// verified contact), or TAGS `UNSUPPORTED`. It may hold none of this
    /// node's registrations now (review handoff-1).
    pub fn custodian_refused(&self) -> bool {
        let refusal = |code: Option<CustodyCode>| {
            matches!(
                code,
                Some(CustodyCode::PolicyDenied | CustodyCode::Hold | CustodyCode::NotVerified)
            )
        };
        self.tags_unsupported || refusal(self.tags_code) || refusal(self.custodian_code)
    }
}

/// The inbound store tags for `peers` (contacts listing this custodian), with
/// the hint each one maps to. Live sessions only; one protected load per
/// session ([`inbound_tags_cached`] keeps them between rounds).
pub fn inbound_tags(
    data_dir: &Path,
    identity: &Identity,
    peers: &[[u8; 32]],
    now_ms: u64,
) -> Result<BTreeMap<[u8; 16], RelayHint>, String> {
    inbound_tags_cached(data_dir, identity, peers, now_ms, &mut TagCache::default())
}

/// Inbound store tags already derived (§8.1), in memory only: by (session
/// record key, day). A tag is a frozen derivation of the session's root and
/// the day, so an entry stays right for as long as the session is live; the
/// entries of a session no longer live (or of a day it can no longer be
/// fetched for) are dropped on the next [`inbound_tags_cached`].
#[derive(Debug, Default)]
pub struct TagCache {
    /// Inbound tags by session and day.
    inbound: HashMap<IndexedSessionRecordKey, BTreeMap<u64, [u8; 16]>>,
    loads: usize,
}

impl TagCache {
    /// Protected session loads made to fill the cache so far.
    pub fn protected_loads(&self) -> usize {
        self.loads
    }

    /// Cached tags.
    pub fn len(&self) -> usize {
        self.inbound.values().map(BTreeMap::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.inbound.is_empty()
    }
}

/// [`inbound_tags`] through `cache`: the session heads come from metadata
/// only, and a session's protected state is loaded only when a day it can
/// be fetched for is not cached yet (once for all its missing days).
pub fn inbound_tags_cached(
    data_dir: &Path,
    identity: &Identity,
    peers: &[[u8; 32]],
    now_ms: u64,
    cache: &mut TagCache,
) -> Result<BTreeMap<[u8; 16], RelayHint>, String> {
    let mut map = BTreeMap::new();
    visit_inbound_tags(
        data_dir,
        identity,
        peers,
        now_ms,
        cache,
        fetch_days,
        |head, _, tag| {
            map.entry(tag).or_insert_with(|| RelayHint {
                record_key: head.key.clone(),
                peer_device: head.peer_device,
                store_tag: tag,
            });
        },
    )?;
    Ok(map)
}

const DAY_MS: u64 = 86_400_000;

/// The expiry a recipient registers a tag of `day` with
/// (`RAVEN_CUSTODY_HANDOFF_V1.md` §3.6): the end of that day plus the
/// custody validity bound, so it outlives every object filed under it
/// ([`crate::carrier_admission::MAX_CUSTODY_VALIDITY_MS`]). The custodian
/// clamps it to [`MAX_TAG_TTL_MS`] from its own clock.
pub fn register_expiry(day: u64) -> u64 {
    day.saturating_add(1)
        .saturating_mul(DAY_MS)
        .saturating_add(crate::carrier_admission::MAX_CUSTODY_VALIDITY_MS)
}

/// The inbound store tags this node registers at a handoff custodian for
/// `peers` (contacts listing that custodian), each with its expiry
/// ([`register_expiry`]): like [`inbound_tags`], over
/// [`register_days`] (yesterday..tomorrow within each live session).
pub fn inbound_register_tags(
    data_dir: &Path,
    identity: &Identity,
    peers: &[[u8; 32]],
    now_ms: u64,
) -> Result<BTreeMap<[u8; 16], u64>, String> {
    inbound_register_tags_cached(data_dir, identity, peers, now_ms, &mut TagCache::default())
}

/// [`inbound_register_tags`] through `cache` (one kept for registration
/// only: its days are not [`inbound_tags_cached`]'s).
pub fn inbound_register_tags_cached(
    data_dir: &Path,
    identity: &Identity,
    peers: &[[u8; 32]],
    now_ms: u64,
    cache: &mut TagCache,
) -> Result<BTreeMap<[u8; 16], u64>, String> {
    let mut map: BTreeMap<[u8; 16], u64> = BTreeMap::new();
    visit_inbound_tags(
        data_dir,
        identity,
        peers,
        now_ms,
        cache,
        register_days,
        |_, day, tag| {
            let expiry = map.entry(tag).or_insert(0);
            *expiry = (*expiry).max(register_expiry(day));
        },
    )?;
    Ok(map)
}

/// Every inbound store tag of `peers`' live sessions for the days `days_of`
/// gives each (`(created_at_ms, expires_at_ms, now_ms)`), through `cache`:
/// `visit(head, day, tag)` per session (newest first) and day (in order).
/// The cache keeps only those days of the live sessions.
fn visit_inbound_tags(
    data_dir: &Path,
    identity: &Identity,
    peers: &[[u8; 32]],
    now_ms: u64,
    cache: &mut TagCache,
    days_of: fn(u64, u64, u64) -> Vec<u64>,
    mut visit: impl FnMut(&SessionHeadMeta, u64, [u8; 16]),
) -> Result<(), String> {
    let local = crate::device_cert::ensure_local_device_certificate(
        data_dir,
        identity,
        crate::paths::PRIMARY_DEVICE_ID,
    )?
    .0
    .device_ed_pub;
    let mut store = IndexedSessionStore::open(data_dir).map_err(|e| e.redacted_display())?;
    let heads = store
        .live_session_heads(&local, now_ms)
        .map_err(|e| e.redacted_display())?;
    // What may stay: every live session's wanted days, whoever asks now.
    let wanted: HashMap<&IndexedSessionRecordKey, Vec<u64>> = heads
        .iter()
        .map(|h| {
            let days = days_of(h.created_at_ms, h.expires_at_ms, now_ms);
            (&h.key, days)
        })
        .collect();
    cache.inbound.retain(|key, days| {
        let Some(live) = wanted.get(key) else {
            return false;
        };
        days.retain(|day, _| live.contains(day));
        !days.is_empty()
    });
    for head in heads.iter().filter(|h| peers.contains(&h.peer_device)) {
        let days = &wanted[&head.key];
        let cached = cache.inbound.get(&head.key);
        let missing: Vec<u64> = days
            .iter()
            .copied()
            .filter(|day| !cached.is_some_and(|c| c.contains_key(day)))
            .collect();
        if !missing.is_empty() {
            cache.loads += 1;
            // Provisional or unreadable sessions have no tags this round.
            let Ok(tags) =
                store.mailbox_store_tags(&head.key, MailboxDirection::Inbound, &missing, now_ms)
            else {
                continue;
            };
            cache
                .inbound
                .entry(head.key.clone())
                .or_default()
                .extend(missing.iter().copied().zip(tags));
        }
        let Some(cached) = cache.inbound.get(&head.key) else {
            continue;
        };
        for &day in days {
            if let Some(tag) = cached.get(&day) {
                visit(head, day, *tag);
            }
        }
    }
    Ok(())
}

/// One fetch trigger at one custodian (§8.1): RELEASE pending digests, FETCH
/// each 32-tag chunk from its saved cursor, ingest every item (a page's in
/// the order they were written, [`taken_at`]), classify. At most
/// `max_pages` dials ([`MAX_PAGES_PER_TRIGGER`], or
/// [`MAX_PAGES_PER_TRIGGER_RELAYED`] while the custodian's last path was a
/// relayed one); the chunks are visited from [`FetchState::next_chunk`] on,
/// wrapping around, and the first one left unfinished is saved there.
pub fn fetch_round(
    data_dir: &Path,
    identity: &Identity,
    tags: &BTreeMap<[u8; 16], RelayHint>,
    state: &mut FetchState,
    now_ms: u64,
    max_pages: usize,
    dial: &mut CustodianDial<'_>,
) -> FetchReport {
    fetch_round_with(
        data_dir, identity, tags, None, state, now_ms, max_pages, dial,
    )
}

/// Remember `digests` as released (the latest [`MAX_PENDING_RELEASES`]).
fn note_released(released: &mut Vec<[u8; 32]>, digests: &[[u8; 32]]) {
    for digest in digests {
        if !released.contains(digest) {
            released.push(*digest);
        }
    }
    let over = released.len().saturating_sub(MAX_PENDING_RELEASES);
    released.drain(..over);
}

/// TAGS REGISTER frames one fetch round sends at most (before RELEASE and
/// FETCH, in its first dial).
pub const MAX_TAGS_FRAMES_PER_ROUND: usize = 2;
/// A registered tag is registered again once less than this is left of the
/// expiry it was registered with, when a later one is wanted.
pub const TAG_REFRESH_MS: u64 = 24 * 60 * 60 * 1000;
/// A registered tag is registered again, with the same expiry, once the
/// custodian's OK for it is this old (`RAVEN_CUSTODY_HANDOFF_V1.md` §3.6;
/// review handoff-1). A custodian that lost the registrations (custody
/// turned off and on with `--purge`, its store set aside) says nothing,
/// since FETCH works by tag whatever is registered; registering one's own
/// tag again only extends it (§3.4), so it holds them again within this.
pub const TAG_CONFIRM_MS: u64 = 6 * 60 * 60 * 1000;
/// Request-id salt of the TAGS frames.
const SALT_TAGS: u8 = 0xA0;

/// What a fetch round registers at a handoff custodian
/// (`RAVEN_CUSTODY_HANDOFF_V1.md` §3.6): `tags` ([`inbound_register_tags`]:
/// the expiry wanted per inbound store tag) at `custodian`, whose handoff
/// capability `caps` holds.
pub struct TagRegistration<'a> {
    pub custodian: [u8; 32],
    pub tags: &'a BTreeMap<[u8; 16], u64>,
    pub caps: &'a mut CapabilityCache,
}

/// Whether a tag wanted until `wanted` is to be registered (again): never
/// registered here; registered with an OK at least [`TAG_CONFIRM_MS`] old
/// (or that far ahead, the clock set back): the custodian may have lost it;
/// or registered until less than [`TAG_REFRESH_MS`] from now while a later
/// expiry is wanted (one cut by the TTL clamp). A tag's wanted expiry is
/// fixed by its day, so a registered one is not sent again just because
/// its day is ending.
fn registration_due(registered: Option<Registered>, wanted: u64, now_ms: u64) -> bool {
    match registered {
        None => true,
        Some(r) => {
            now_ms.abs_diff(r.confirmed_ms) >= TAG_CONFIRM_MS
                || (r.expiry < wanted && r.expiry.saturating_sub(now_ms) < TAG_REFRESH_MS)
        }
    }
}

/// Whether a fetch round with `tags` ([`inbound_register_tags`]) would
/// register anything at a custodian whose state is `state`: a tag still
/// live that was never registered there, or is due again
/// ([`registration_due`]). The fetcher dials for it even with nothing to
/// fetch or release. The gate and the capability cache are the round's.
pub fn registration_wanted(
    state: &FetchState,
    tags: &BTreeMap<[u8; 16], u64>,
    now_ms: u64,
) -> bool {
    tags.iter().any(|(tag, wanted)| {
        let held = state
            .registered
            .get(tag)
            .copied()
            .filter(|r| r.expiry > now_ms);
        *wanted > now_ms && registration_due(held, *wanted, now_ms)
    })
}

/// The TAGS REGISTER chunks this round sends: the due tags still live,
/// each with its wanted expiry clamped to [`MAX_TAG_TTL_MS`] from now, at
/// most [`MAX_TAGS_FRAMES_PER_ROUND`] frames of [`MAX_TAG_ENTRIES`]. None
/// while the handoff gate is closed or the cache knows the custodian
/// without the handoff ops. The registered map keeps only the tags still
/// wanted and live.
fn registration_chunks(
    register: Option<&TagRegistration<'_>>,
    registered: &mut HashMap<[u8; 16], Registered>,
    now_ms: u64,
) -> Vec<Vec<([u8; 16], u64)>> {
    let Some(register) = register else {
        return Vec::new();
    };
    registered.retain(|tag, r| r.expiry > now_ms && register.tags.contains_key(tag));
    if register.caps.handoff(&register.custodian, now_ms) == Some(false)
        || !crate::custody_gate::handoff_live()
    {
        return Vec::new();
    }
    let due: Vec<([u8; 16], u64)> = register
        .tags
        .iter()
        .filter(|(_, wanted)| **wanted > now_ms)
        .filter(|(tag, wanted)| registration_due(registered.get(*tag).copied(), **wanted, now_ms))
        .map(|(tag, wanted)| (*tag, (*wanted).min(now_ms.saturating_add(MAX_TAG_TTL_MS))))
        .take(MAX_TAGS_FRAMES_PER_ROUND * MAX_TAG_ENTRIES)
        .collect();
    due.chunks(MAX_TAG_ENTRIES).map(<[_]>::to_vec).collect()
}

/// [`fetch_round`] that first registers this node's inbound tags at the
/// custodian (`register`, `RAVEN_CUSTODY_HANDOFF_V1.md` §3.6): at most
/// [`MAX_TAGS_FRAMES_PER_ROUND`] TAGS REGISTER frames (salt 0xA0) ride the
/// first dial ahead of RELEASE and FETCH, for the tags not registered yet
/// or due again ([`registration_due`]: also once the custodian's OK is
/// [`TAG_CONFIRM_MS`] old), and each frame answered OK marks its tags
/// registered, confirmed now ([`FetchState::registered`]). A round the
/// custodian refused ([`FetchReport::custodian_refused`]) forgets every
/// registration there: all of them go again once it takes this node
/// (review handoff-1). Only while the handoff gate is open and not at a
/// custodian the cache knows without the handoff ops; its TAGS answers are
/// kept in the cache. `None` registers nothing.
#[allow(clippy::too_many_arguments)]
pub fn fetch_round_with(
    data_dir: &Path,
    identity: &Identity,
    tags: &BTreeMap<[u8; 16], RelayHint>,
    mut register: Option<TagRegistration<'_>>,
    state: &mut FetchState,
    now_ms: u64,
    max_pages: usize,
    dial: &mut CustodianDial<'_>,
) -> FetchReport {
    let mut report = FetchReport::default();
    let mut last_taken = 0;
    let all: Vec<[u8; 16]> = tags.keys().copied().collect();
    let chunks: Vec<&[[u8; 16]]> = all.chunks(MAX_FETCH_TAGS).collect();
    // Rotated: this trigger starts where the last one stopped, so a chunk
    // past the page budget is not starved by the ones before it.
    let n = chunks.len();
    let start = if n == 0 { 0 } else { state.next_chunk % n };
    let order: Vec<usize> = (start..n).chain(0..start).collect();
    let mut pos = 0;
    let mut tagging = registration_chunks(register.as_ref(), &mut state.registered, now_ms);
    let (mut tags_sent, mut tags_answered) = (0, 0);
    while report.dials < max_pages {
        let chunk = order.get(pos).map(|&i| chunks[i]);
        let mut frames = Vec::new();
        // Registration rides the first dial only, ahead of RELEASE and FETCH.
        let registering = std::mem::take(&mut tagging);
        for (i, entries) in registering.iter().enumerate() {
            frames.push(encode_request(
                &req_id(i, SALT_TAGS),
                &Rfc1Request::Tags {
                    action: TagsAction::Register,
                    entries: entries.clone(),
                },
            ));
        }
        let releasing: Vec<[u8; 32]> = state
            .pending_release
            .iter()
            .take(MAX_RELEASE_DIGESTS)
            .copied()
            .collect();
        if !releasing.is_empty() {
            frames.push(encode_request(
                &req_id(0, 0xE0),
                &Rfc1Request::Release {
                    digests: releasing.clone(),
                },
            ));
        }
        if let Some(chunk) = chunk {
            frames.push(encode_request(
                &req_id(0, 0xF0),
                &Rfc1Request::Fetch {
                    tags: chunk.to_vec(),
                    after: state.cursors.get(&chunk[0]).copied(),
                    max_items: MAX_FETCH_ITEMS,
                },
            ));
        }
        if frames.is_empty() {
            break;
        }
        report.dials += 1;
        tags_sent += registering.len();
        let replies = match dial(&frames) {
            Ok(r) => r,
            Err(_) => break,
        };
        let mut fetch_end: Option<(CustodyCode, Option<[u8; 32]>)> = None;
        let mut objects = Vec::new();
        let mut answered = vec![false; registering.len()];
        for raw in &replies {
            let Ok((id, reply)) = decode_reply(raw) else {
                continue; // the RLB1 offer, or anything else
            };
            if let Some(i) = index_of(&id, SALT_TAGS).filter(|i| *i < registering.len()) {
                let Some(register) = register.as_mut() else {
                    continue;
                };
                if std::mem::replace(&mut answered[i], true) {
                    continue; // one terminal reply per request
                }
                match &reply {
                    Rfc1Reply::TagsResult {
                        code, conflicts, ..
                    } => {
                        tags_answered += 1;
                        report.tag_conflicts += usize::from(*conflicts);
                        if *code == CustodyCode::Ok {
                            state
                                .registered
                                .extend(registering[i].iter().map(|(tag, expiry)| {
                                    (
                                        *tag,
                                        Registered {
                                            expiry: *expiry,
                                            confirmed_ms: now_ms,
                                        },
                                    )
                                }));
                        } else {
                            report.tags_code.get_or_insert(*code);
                        }
                    }
                    Rfc1Reply::Unsupported { .. } => report.tags_unsupported = true,
                    _ => {
                        answered[i] = false;
                        continue;
                    }
                }
                register
                    .caps
                    .learn(&register.custodian, OP_TAGS, &reply, now_ms);
                continue;
            }
            match reply {
                Rfc1Reply::ReleaseResult { code, released } if id[0] == 0xE0 => {
                    if code == CustodyCode::Ok {
                        state.pending_release.retain(|d| !releasing.contains(d));
                        report.released += usize::from(released);
                        note_released(&mut state.released, &releasing);
                    }
                }
                Rfc1Reply::FetchItem { rso1 } if id[0] == 0xF0 => {
                    report.items += 1;
                    match check_rfc1_rso1(&rso1) {
                        Ok((object, _)) => objects.push(object),
                        Err(_) => report.misbehaviour.push(SecKind::CustodianBadObject),
                    }
                }
                Rfc1Reply::FetchEnd { code, next, .. } if id[0] == 0xF0 => {
                    fetch_end = Some((code, next));
                }
                _ => {}
            }
        }
        // A page comes in page-token order, which says nothing about when
        // its objects were written: they are taken in the order their
        // contact wrote them, each at its own receive time, so the inbox
        // lists them in that order.
        objects.sort_by_key(|o| o.created_at_ms);
        for object in objects {
            let Some(hint) = chunk
                .filter(|c| c.contains(&object.store_tag))
                .and_then(|_| tags.get(&object.store_tag))
            else {
                // Not a tag we asked for: dropped, and noted.
                report.misbehaviour.push(SecKind::CustodianUnrequested);
                continue;
            };
            let digest = custody_digest(&object.packed_envelope);
            if state.released.contains(&digest) {
                // Released with OK, then served again. Taken as before (a
                // duplicate is answered and released again).
                report.misbehaviour.push(SecKind::CustodianReplay);
            }
            let at = taken_at(now_ms, &mut last_taken);
            let (outcome, event) =
                ingest_relayed_object_sensed(data_dir, identity, &object, hint, at);
            match event {
                None => {}
                Some(kind @ (SecKind::CustodianBadObject | SecKind::CustodianReplay)) => {
                    report.misbehaviour.push(kind);
                }
                Some(SecKind::LocalRollback) => {
                    crate::security_sense::local(SecKind::LocalRollback);
                }
                Some(kind) => report.sender_events.push((hint.peer_device, kind)),
            }
            match &outcome {
                RelayedOutcome::MessageAccepted { peer, group, .. } => {
                    report.accepted_messages += 1;
                    report.accepted_group_copies += usize::from(*group);
                    report.touched.push(*peer);
                }
                RelayedOutcome::AckAccepted { peer, .. } => {
                    report.accepted_acks += 1;
                    report.touched.push(*peer);
                }
                RelayedOutcome::Refused(code) => {
                    report.refused += 1;
                    if *code == crate::relayed_ingest::FOREIGN_SIGNATURE {
                        report.foreign += 1;
                    }
                }
                RelayedOutcome::Retry(RetryScope::Item, _) => report.retried += 1,
                RelayedOutcome::Retry(RetryScope::Peer, why) => {
                    report.retried += 1;
                    report.peer_backoff.push((hint.peer_device, why));
                }
                RelayedOutcome::Retry(RetryScope::Store, why) => {
                    report.retried += 1;
                    report.store_trouble = Some(why);
                }
            }
            if outcome.releases()
                && state.pending_release.len() < MAX_PENDING_RELEASES
                && !state.pending_release.contains(&digest)
            {
                state.pending_release.push(digest);
            }
        }
        if report.store_trouble.is_some() {
            break;
        }
        let Some(chunk) = chunk else {
            break; // a release-only dial
        };
        match fetch_end {
            Some((CustodyCode::Ok, Some(next))) => {
                state.cursors.insert(chunk[0], next);
            }
            Some((CustodyCode::Ok, None)) => {
                state.cursors.remove(&chunk[0]);
                pos += 1;
            }
            Some((code, _)) => {
                report.custodian_code = Some(code);
                break;
            }
            None => break,
        }
        if pos >= order.len() && state.pending_release.is_empty() {
            break;
        }
    }
    // The first chunk not finished this trigger: the next one starts there.
    state.next_chunk = order.get(pos).copied().unwrap_or(start);
    // Turned away (custody or handoff off there, perhaps with its store
    // purged; this node no longer its contact): what was registered there
    // may be gone, so all of it goes again once the custodian takes it.
    if report.custodian_refused() {
        state.registered.clear();
    }
    report.tags_ok = tags_answered > 0
        && report.tags_code.is_none()
        && !report.tags_unsupported
        && tags_answered == tags_sent;
    report.touched.sort_unstable();
    report.touched.dedup();
    report
}

/// The receive time of the next fetched object: the clock (at least
/// `now_ms`), after the previous object's (`last`). One taken in the same
/// millisecond as the previous waits a millisecond; with the clock set back
/// meanwhile (or a caller's `now_ms` ahead of it) it is one past the last.
fn taken_at(now_ms: u64, last: &mut u64) -> u64 {
    let mut at = now_ms.max(crate::clock::now_ms());
    if at <= *last {
        std::thread::sleep(std::time::Duration::from_millis(1));
        at = now_ms
            .max(crate::clock::now_ms())
            .max(last.saturating_add(1));
    }
    *last = at;
    at
}

/// At most this many custodians per contact (design §4.1).
pub const MAX_CUSTODIANS_PER_CONTACT: usize = 2;

#[derive(serde::Deserialize)]
struct CustodyContactRow {
    #[serde(default)]
    pub_hex: String,
    #[serde(default)]
    custodians: Vec<String>,
}

fn parse_key(hex_key: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(hex_key.trim(), &mut out).ok()?;
    Some(out)
}

/// The custodians this node listed for `peer` (contact row `custodians`):
/// valid keys only, deduplicated, never the peer or this node, at most two.
/// Use-time admission (pinned, unblocked) is the caller's check.
pub fn listed_custodians(
    data_dir: &Path,
    peer: &[u8; 32],
    local: &[u8; 32],
) -> Result<Vec<[u8; 32]>, String> {
    let Some(rows) = crate::contact_book::read_rows::<CustodyContactRow>(data_dir)? else {
        return Ok(Vec::new());
    };
    Ok(listed_in(&rows, peer, local))
}

/// [`listed_custodians`] from the contact book's `rows`.
fn listed_in(rows: &[CustodyContactRow], peer: &[u8; 32], local: &[u8; 32]) -> Vec<[u8; 32]> {
    let key = hex::encode(peer);
    let mut out: Vec<[u8; 32]> = Vec::new();
    for row in rows
        .iter()
        .filter(|r| r.pub_hex.trim().eq_ignore_ascii_case(&key))
    {
        for c in row.custodians.iter().filter_map(|c| parse_key(c)) {
            if c != *peer
                && c != *local
                && !out.contains(&c)
                && out.len() < MAX_CUSTODIANS_PER_CONTACT
            {
                out.push(c);
            }
        }
    }
    out
}

/// A custodian usable right now: a current, unblocked, pinned contact that is
/// neither this node nor `peer`.
pub fn custodian_usable(
    data_dir: &Path,
    custodian: &[u8; 32],
    peer: &[u8; 32],
    local: &[u8; 32],
) -> bool {
    custodian != peer
        && custodian != local
        && matches!(
            crate::outbox::contact_admission(data_dir, custodian),
            crate::outbox::ContactAdmission::Allowed(c) if c.pinned
        )
}

/// The custodian tags this node announces to `peer` (RRH1 `CUSTODIAN_TAG`,
/// Phase 3): its home custodians while it uses friends as mailboxes
/// ([`crate::custody_home::home`], consent on), then the custodians it
/// listed for `peer` ([`listed_custodians`]) that are usable now
/// ([`custodian_usable`]: verified, unblocked contacts); never `peer` or
/// this node, at most [`MAX_CUSTODIANS_PER_CONTACT`]. Each is
/// [`crate::route_hints::custodian_tag`]`(local, peer, custodian)`: only
/// `peer` can tell which of its own contacts it names. The caller checks
/// [`crate::custody_gate::custody_hints_live`].
pub fn announced_custodian_tags(
    data_dir: &Path,
    local: &[u8; 32],
    peer: &[u8; 32],
    now_ms: u64,
) -> Vec<[u8; 32]> {
    announced_custodian_keys(data_dir, local, peer, now_ms)
        .iter()
        .map(|c| crate::route_hints::custodian_tag(local, peer, c))
        .collect()
}

/// The custodians whose tags [`announced_custodian_tags`] announces to
/// `peer`, in the same order (Phase 5: the snapshot builder sets each one's
/// `HANDOFF_INBOX` flag by its key).
pub fn announced_custodian_keys(
    data_dir: &Path,
    local: &[u8; 32],
    peer: &[u8; 32],
    now_ms: u64,
) -> Vec<[u8; 32]> {
    let mut cs: Vec<[u8; 32]> = Vec::new();
    if consent(data_dir) {
        cs.extend(crate::custody_home::home(data_dir, local, now_ms));
    }
    for c in listed_custodians(data_dir, peer, local).unwrap_or_default() {
        if !cs.contains(&c) && custodian_usable(data_dir, &c, peer, local) {
            cs.push(c);
        }
    }
    cs.retain(|c| c != peer && c != local);
    cs.truncate(MAX_CUSTODIANS_PER_CONTACT);
    cs
}

/// The user uses friends as mailboxes (`raven custody use on`,
/// [`crate::node_policy::NodePolicy::custody_use`]). An unreadable policy
/// is no consent.
fn consent(data_dir: &Path) -> bool {
    crate::node_policy::try_load_policy(data_dir).is_ok_and(|p| p.custody_use == Some(true))
}

/// At most this many custodians are candidates for one contact's mail
/// ([`custodian_candidates`]; Phase 6a carry choice picks among them). A
/// bound only: an announcement names at most two by tag and two by plain
/// key (RRH1), and at most two are listed.
pub const MAX_CUSTODIAN_CANDIDATES: usize = 8;
const _: () = assert!(
    MAX_CUSTODIAN_CANDIDATES >= 2 * crate::route_hints::MAX_CUSTODIANS + MAX_CUSTODIANS_PER_CONTACT
);

/// Where an object for `peer` may be left, each with the custody offer its
/// custodian announced (`None`: a custodian this node listed itself): the
/// first [`MAX_CUSTODIANS_PER_CONTACT`] of [`custodian_candidates`]. First,
/// while this node uses friends as mailboxes and learned custody is live
/// ([`crate::custody_gate::custody_hints_live`]): the custodians `peer`
/// announced (its tags, matched against this node's verified, unblocked
/// contacts in book order with `custodian_tag(peer, local, c)`, or Phase 2's
/// plain keys) that offer custody themselves; then the custodians this node
/// listed for `peer` ([`listed_custodians`], explicit consent). Each is
/// [`custodian_usable`].
pub fn deposit_custodians(
    data_dir: &Path,
    local: &[u8; 32],
    peer: &[u8; 32],
    now_ms: u64,
) -> Vec<([u8; 32], Option<u8>)> {
    deposit_custodians_with(
        data_dir,
        local,
        peer,
        now_ms,
        crate::custody_gate::custody_hints_live(),
    )
}

/// [`deposit_custodians`] for each of `peers` (in their order), with what
/// it reads read once for all of them: the node policy, the learned
/// snapshots, the contact book and each listed custodian's admission. A
/// nearby encounter with a custodian looks through every waiting contact
/// this way (review nearby-7).
pub fn deposit_custodians_for(
    data_dir: &Path,
    local: &[u8; 32],
    peers: &[[u8; 32]],
    now_ms: u64,
) -> Vec<Vec<([u8; 32], Option<u8>)>> {
    let book = DepositBook::read(data_dir, now_ms, crate::custody_gate::custody_hints_live());
    peers
        .iter()
        .map(|peer| book.custodians(data_dir, local, peer))
        .collect()
}

/// [`deposit_custodians`] with the learned-custody gate as an argument.
fn deposit_custodians_with(
    data_dir: &Path,
    local: &[u8; 32],
    peer: &[u8; 32],
    now_ms: u64,
    hints_live: bool,
) -> Vec<([u8; 32], Option<u8>)> {
    DepositBook::read(data_dir, now_ms, hints_live).custodians(data_dir, local, peer)
}

/// Every custodian an object for `peer` may be left with, in the order of
/// [`deposit_custodians`] (the same sources, the same usability rule), at
/// most [`MAX_CUSTODIAN_CANDIDATES`]: what Phase 6a's carry choice
/// (`learning::carry`, raven-node) picks at most
/// [`MAX_CUSTODIANS_PER_CONTACT`] from. An announced one carries its offer
/// (`Some`), a listed one `None`.
pub fn custodian_candidates(
    data_dir: &Path,
    local: &[u8; 32],
    peer: &[u8; 32],
    now_ms: u64,
) -> Vec<([u8; 32], Option<u8>)> {
    custodian_candidates_with(
        data_dir,
        local,
        peer,
        now_ms,
        crate::custody_gate::custody_hints_live(),
    )
}

/// [`custodian_candidates`] for each of `peers` (in their order), with what
/// it reads read once for all of them, as [`deposit_custodians_for`]: a
/// nearby encounter looks through every waiting contact this way while
/// carry choice is live.
pub fn custodian_candidates_for(
    data_dir: &Path,
    local: &[u8; 32],
    peers: &[[u8; 32]],
    now_ms: u64,
) -> Vec<Vec<([u8; 32], Option<u8>)>> {
    let book = DepositBook::read(data_dir, now_ms, crate::custody_gate::custody_hints_live());
    peers
        .iter()
        .map(|peer| book.up_to(data_dir, local, peer, MAX_CUSTODIAN_CANDIDATES))
        .collect()
}

/// [`custodian_candidates`] with the learned-custody gate as an argument.
fn custodian_candidates_with(
    data_dir: &Path,
    local: &[u8; 32],
    peer: &[u8; 32],
    now_ms: u64,
    hints_live: bool,
) -> Vec<([u8; 32], Option<u8>)> {
    DepositBook::read(data_dir, now_ms, hints_live).up_to(
        data_dir,
        local,
        peer,
        MAX_CUSTODIAN_CANDIDATES,
    )
}

/// What [`deposit_custodians`] and [`custodian_candidates`] read, once for
/// any number of contacts.
struct DepositBook {
    /// The learned snapshots, while learned custody is live and this node
    /// uses friends as mailboxes.
    learned: Option<HashMap<[u8; 32], crate::learned_routes::LearnedCustody>>,
    /// The verified, unblocked contacts in book order, read at the first
    /// contact that announced custodians.
    pinned: std::cell::OnceCell<Vec<[u8; 32]>>,
    /// The contact book's custodian lists (none when it cannot be read).
    rows: Vec<CustodyContactRow>,
    /// Custodian -> a verified, unblocked contact now (the
    /// [`custodian_usable`] admission, asked once per custodian).
    admitted: std::cell::RefCell<HashMap<[u8; 32], bool>>,
}

impl DepositBook {
    fn read(data_dir: &Path, now_ms: u64, hints_live: bool) -> Self {
        Self {
            learned: (hints_live && consent(data_dir))
                .then(|| crate::learned_routes::learned_custody_all(data_dir, now_ms)),
            pinned: std::cell::OnceCell::new(),
            rows: crate::contact_book::read_rows::<CustodyContactRow>(data_dir)
                .ok()
                .flatten()
                .unwrap_or_default(),
            admitted: std::cell::RefCell::default(),
        }
    }

    /// [`deposit_custodians`] of `peer`.
    fn custodians(
        &self,
        data_dir: &Path,
        local: &[u8; 32],
        peer: &[u8; 32],
    ) -> Vec<([u8; 32], Option<u8>)> {
        self.up_to(data_dir, local, peer, MAX_CUSTODIANS_PER_CONTACT)
    }

    /// The first `cap` custodians of `peer` in [`deposit_custodians`]'
    /// order: `MAX_CUSTODIANS_PER_CONTACT` for a deposit,
    /// `MAX_CUSTODIAN_CANDIDATES` for Phase 6a's carry choice. Both read
    /// the same sources in the same order, so a deposit's list is always
    /// the head of the candidates.
    fn up_to(
        &self,
        data_dir: &Path,
        local: &[u8; 32],
        peer: &[u8; 32],
        cap: usize,
    ) -> Vec<([u8; 32], Option<u8>)> {
        let mut out: Vec<([u8; 32], Option<u8>)> = Vec::new();
        if let Some(learned) = &self.learned {
            if let Some(told) = learned.get(peer) {
                let pinned = self.pinned.get_or_init(|| {
                    crate::outbox::pinned_unblocked_contacts(data_dir).unwrap_or_default()
                });
                for c in pinned {
                    if out.len() == cap {
                        break;
                    }
                    if c == peer || c == local {
                        continue;
                    }
                    let named = told
                        .tags
                        .contains(&crate::route_hints::custodian_tag(peer, local, c))
                        || told.plain.contains(c);
                    let offer = learned.get(c).and_then(|o| o.offer);
                    if named && offer.is_some() {
                        out.push((*c, offer));
                    }
                }
            }
        }
        // The learned ones are usable by construction (verified, unblocked,
        // neither `peer` nor this node); a listed one is checked before it
        // takes a place, so an unusable one never pushes out a usable one.
        for c in listed_in(&self.rows, peer, local) {
            if out.len() < cap
                && !out.iter().any(|(k, _)| *k == c)
                && c != *peer
                && c != *local
                && *self
                    .admitted
                    .borrow_mut()
                    .entry(c)
                    .or_insert_with(|| custodian_usable(data_dir, &c, peer, local))
            {
                out.push((c, None));
            }
        }
        out
    }
}

/// Fetch targets (§8.1): every usable custodian with the pinned, unblocked
/// contacts that list it. While learned custody is live
/// ([`crate::custody_gate::custody_hints_live`]), each custodian this node
/// collects its own mail from ([`crate::custody_home::fetch_from`]: its home
/// custodians while it uses friends as mailboxes, and the dropped ones
/// still draining) is asked for every verified, unblocked contact but
/// itself, and each custodian a pinned contact announced to this node (its
/// tags, or Phase 2's plain keys: where that contact may leave mail for it,
/// [`deposit_custodians`] on its side) that is a verified, unblocked
/// contact here too and offers custody to this node itself (its own
/// CUSTODY_OFFER), for that contact (P5.14; review handoff-5). None of this
/// needs a live session with the contact: a letter brings its own.
pub fn fetch_targets(
    data_dir: &Path,
    local: &[u8; 32],
    now_ms: u64,
) -> Result<FetchTargets, String> {
    fetch_targets_with(
        data_dir,
        local,
        now_ms,
        crate::custody_gate::custody_hints_live(),
    )
}

/// [`fetch_targets`] with the learned-custody gate as an argument.
fn fetch_targets_with(
    data_dir: &Path,
    local: &[u8; 32],
    now_ms: u64,
    hints_live: bool,
) -> Result<FetchTargets, String> {
    let mut map: BTreeMap<[u8; 32], Vec<[u8; 32]>> = BTreeMap::new();
    if let Some(rows) = crate::contact_book::read_rows::<CustodyContactRow>(data_dir)? {
        for row in &rows {
            let Some(peer) = parse_key(&row.pub_hex) else {
                continue;
            };
            if !matches!(
                crate::outbox::contact_admission(data_dir, &peer),
                crate::outbox::ContactAdmission::Allowed(c) if c.pinned
            ) {
                continue;
            }
            for c in listed_custodians(data_dir, &peer, local)? {
                if custodian_usable(data_dir, &c, &peer, local) {
                    let peers = map.entry(c).or_default();
                    if !peers.contains(&peer) {
                        peers.push(peer);
                    }
                }
            }
        }
    }
    if hints_live {
        let home = crate::custody_home::fetch_from(data_dir, local, now_ms);
        let learned = crate::learned_routes::learned_custody_all(data_dir, now_ms);
        let told_any = learned
            .values()
            .any(|told| !told.tags.is_empty() || !told.plain.is_empty());
        if !home.is_empty() || told_any {
            let pinned = crate::outbox::pinned_unblocked_contacts(data_dir)?;
            for c in home {
                if c == *local || !pinned.contains(&c) {
                    continue;
                }
                for peer in pinned.iter().filter(|p| **p != c && *p != local) {
                    let peers = map.entry(c).or_default();
                    if !peers.contains(peer) {
                        peers.push(*peer);
                    }
                }
            }
            // Where each pinned contact said it leaves mail for this node:
            // only at a custodian that offers custody to this node itself (a
            // learned CUSTODY_OFFER, as the depositor's side asks of a
            // learned custodian; one this node lists for that contact is a
            // target above). A friend of the contact's that does not take
            // this node (the far friend of a custody handoff, pinned here
            // only to name it as the next hop) is never dialled: the dial
            // alone would show it this node's identity (review handoff-5).
            for peer in pinned.iter().filter(|p| *p != local) {
                let Some(told) = learned.get(peer) else {
                    continue;
                };
                for c in pinned.iter().filter(|c| *c != peer && *c != local) {
                    let named = told
                        .tags
                        .contains(&crate::route_hints::custodian_tag(peer, local, c))
                        || told.plain.contains(c);
                    let offers = learned.get(c).is_some_and(|own| own.offer.is_some());
                    if named && offers {
                        let peers = map.entry(*c).or_default();
                        if !peers.contains(peer) {
                            peers.push(*peer);
                        }
                    }
                }
            }
        }
    }
    Ok(map.into_iter().collect())
}

/// Where a custodian can be dialled (§7.2): its planned routes allowed by the
/// custody gate, LAN routes localized (local-network only while WAN custody
/// is off). `(as planned, as dialled)`; empty = `CUSTODIAN_NOT_USABLE`.
/// Planned as the delivery planners plan a contact
/// ([`crate::outbox::with_learned_routes_where`]): a learned local-network
/// address that `keep` refuses (the caller's on-link filter: one on none of
/// this computer's networks) is not dialled, so the signed bind never goes to
/// whoever holds it now. While route hints are live that includes the LAN
/// port the custodian last announced (RRH1), so a custodian that came back
/// on another port is fetched from there (cutoff F8), and the p2p route its
/// route hints name (a custodian known only by RRH1 or card v3).
///
/// `extra_lan`: where the LAN beacon found the custodian just now (raven-node
/// hands them over): they lead the LAN routes
/// ([`crate::outbox::with_beacon_lan_routes`]), and the learned LAN routes
/// are then left out, as for a contact. `offer`: the custody offer the
/// custodian announced ([`deposit_custodians`]); one without
/// [`crate::custody_gate::OFFER_WAN`] serves custody on LAN links only, so
/// its Internet and p2p routes are dropped (`None`: no offer known, nothing
/// dropped). LAN routes follow the LAN carrier gate, closed while `raven lan
/// off` is in effect ([`crate::custody_gate::carrier_gates_now`]). The
/// custodian's Tor onion route comes last while the Tor helper is ready
/// ([`crate::onion_gate::onion_usable_now`]; lab), for WAN custody only.
pub fn custodian_routes(
    data_dir: &Path,
    custodian: &[u8; 32],
    offer: Option<u8>,
    extra_lan: &[String],
    keep: impl Fn(std::net::IpAddr) -> bool,
) -> Vec<(crate::outbox::OutboxRoute, crate::outbox::OutboxRoute)> {
    use crate::custody_gate::{carrier_gates_now, CustodyGates};
    custodian_routes_with(
        data_dir,
        custodian,
        offer,
        extra_lan,
        carrier_gates_now(),
        CustodyGates::current(),
        crate::outbox::LearnedGates::now(),
        keep,
        crate::onion_gate::onion_usable_now(),
    )
}

/// [`custodian_routes`] with the carrier, custody and learned-route gates
/// as arguments. A custodian this node hides its IP from
/// ([`crate::outbox::may_share_ip`]: its row's or the node policy's
/// `hide_ip`) gets no Internet direct route, as in every other planner.
#[allow(clippy::too_many_arguments)]
fn custodian_routes_with(
    data_dir: &Path,
    custodian: &[u8; 32],
    offer: Option<u8>,
    extra_lan: &[String],
    gates: crate::outbox::CarrierGates,
    custody: crate::custody_gate::CustodyGates,
    learned: crate::outbox::LearnedGates,
    keep: impl Fn(std::net::IpAddr) -> bool,
    onion_ready: bool,
) -> Vec<(crate::outbox::OutboxRoute, crate::outbox::OutboxRoute)> {
    use crate::custody_gate::{custody_route_allowed, OFFER_WAN};
    use crate::outbox::{
        beacon_lan_dials, contact_admission, localize_lan_route, may_share_ip, plan_object_routes,
        with_beacon_lan_routes, with_learned_routes_gated, CarrierChoice, ContactAdmission,
        ObjectRoutes, OutboxCarrier, LOCALIZE_RESOLVE_TIMEOUT,
    };
    let ContactAdmission::Allowed(contact) = contact_admission(data_dir, custodian) else {
        return Vec::new();
    };
    if !contact.pinned {
        return Vec::new();
    }
    let beacon = beacon_lan_dials(extra_lan);
    let mut contact = if beacon.is_empty() {
        with_learned_routes_gated(data_dir, custodian, contact, keep, learned)
    } else {
        with_beacon_lan_routes(
            with_learned_routes_gated(data_dir, custodian, contact, |_| false, learned),
            &beacon,
        )
    };
    contact.hide_ip |= !may_share_ip(data_dir, custodian);
    // The custodian's Tor onion route (lab), last, as for a contact
    // ([`crate::outbox::with_onion_route`]: its signed binding from the
    // book, only while the Tor helper is ready): custody over Tor is WAN
    // custody (`custody_route_allowed`), and a LAN-only offer drops it.
    let contact = crate::outbox::with_onion_route(
        contact,
        custodian,
        None,
        onion_ready,
        crate::onion::now_s(),
    );
    let lan_only = offer.is_some_and(|f| f & OFFER_WAN == 0);
    let any = ObjectRoutes {
        peer_pub_hex: hex::encode(custodian),
        choice: CarrierChoice::Auto,
        routes: Vec::new(),
        expires_at_ms: u64::MAX,
        unsent: false,
        written: false,
        custodians_held: Vec::new(),
        custody_forwarded: false,
        custody: false,
    };
    plan_object_routes(Some(&any), &contact, gates)
        .routes
        .into_iter()
        .filter(|r| custody_route_allowed(custody, gates, r))
        .filter(|r| !lan_only || r.carrier == OutboxCarrier::Lan)
        .filter_map(|r| {
            // A card's LAN route keeps the local-network rule
            // ([`crate::outbox::ContactRoutes::lan_local_only`]).
            let wan = custody.wan && !contact.lan_local_only(&r);
            localize_lan_route(&r, wan, LOCALIZE_RESOLVE_TIMEOUT)
                .ok()
                .map(|d| (r, d))
        })
        .collect()
}

#[cfg(test)]
mod tests;
