//! Automatic relay choice (any-network plan C7): the relays this node
//! reserves on, among the ones set by hand and the friend relays its
//! contacts offer it (RRH1 RELAY_OFFER, [`crate::learned_routes::offers`]).
//!
//! raven-node's p2p host asks [`select`] every few seconds and applies the
//! answer in place: one slot's reservation goes, another comes, the other
//! slot keeps its own. [`select`] is pure: times are wall-clock milliseconds
//! the caller passes, and the caller clamps loss clocks to the current host
//! generation, so this node's own sleep or a network change never counts as
//! a relay's loss.
//!
//! - **Relays set by hand are authoritative.** They come first, always;
//!   offered relays fill the slots left (at most [`crate::p2p_route::MAX_VIA`]
//!   relays in all). With automatic choice off nothing else is used.
//! - **Sticky.** A picked relay is replaced only after [`REPLACE_AFTER_MS`]
//!   of continuous loss while another path proves this node online, or when
//!   it accepted no reservation within [`PROBATION_MS`] of being picked (an
//!   empty slot that was tried). At most one replacement per [`MIN_GAP_MS`];
//!   empty slots fill at once. A relay replaced is not taken back as a
//!   replacement for [`SWAP_BACK_COOLDOWN_MS`], and a relay with no other
//!   offered relay to take its place is kept, never dropped for being down.
//!   With every slot down nothing else may show this node online: raven-node
//!   then dials the relay that would take a slot as that proof ([`probe`]).
//! - **Failed probations back off.** A relay that failed its probation here
//!   takes no slot back as a replacement for a back-off that doubles with
//!   each failure (1 h, 2 h ... [`MAX_PROBATION_BACKOFF_MS`]), and never
//!   replaces another relay that failed its probation while its own failure
//!   is that recent: two relays this node cannot reach are not swapped back
//!   and forth. A reservation accepted ends it.
//! - **Dropped at once** when its offer is withdrawn (or expired and its
//!   reservation lost), its operator is no longer a verified contact, this
//!   node hides its IP from that operator (the relay would see it), or the
//!   relay turned this node away as a non-member ([`note_not_member`]).
//! - **Score** of a standby: a recent success, a CONFIRMED offer, its
//!   availability (an EWMA with a [`AVAIL_HALF_LIFE_MS`] half-life, sampled
//!   only while it is picked), another operator and another network (/24,
//!   /48) than the relays held, learning connectivity's term for it (Phase
//!   6a, [`Input::learned`]: at most ±[`RELAY_TERM_MAX`], nothing while
//!   learning is off), and a tie-break of each node's own. The score only
//!   picks among the relays that may take a slot (a fill, or a replacement
//!   already due): it never starts a change.
//!
//! The timers are the constants here (owner decision); only the debug lab
//! switch `RAVEN_LAB_RELAY_SELECT` changes three of them ([`Timing::current`]).
//!
//! The memory ([`RELAY_MEMORY_FILE`]) is advisory and owner-only: relay
//! PeerIds and times, no address and no contact's key. Only raven-node
//! writes it; a missing or corrupt file, or another version's, is an empty
//! memory. Bounded: [`MAX_REMEMBERED`] relays, the picked ones and the most
//! recently used. Privacy pack PP.6: RMS1 kind 29 in a sealed profile
//! ([`crate::at_rest`]), today's JSON otherwise; a file the writer could not
//! read (a sealed one whose key is not loaded, a changed byte) is never
//! written over.

use std::collections::{BTreeMap, HashSet};
use std::net::IpAddr;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::learned_routes::StoredOffer;
use crate::learning::relay::RELAY_TERM_MAX;
use crate::p2p_route::{
    embedded_ipv4, group_relays, is_global_ip, normalize_peer_id, parse_via, ViaAddr, MAX_VIA,
};
use crate::route_hints::FLAG_CONFIRMED;

/// A picked relay that lost its reservation is replaced after this much
/// continuous loss while this node is online (10 min).
pub const REPLACE_AFTER_MS: u64 = 600_000;
/// A picked relay that accepted no reservation within this while this node
/// is online is replaced (2 min).
pub const PROBATION_MS: u64 = 120_000;
/// After a change of the picked relays, the next replacement for loss
/// waits this long (5 min). Empty slots do not wait.
pub const MIN_GAP_MS: u64 = 300_000;
/// A relay replaced is not taken back as a replacement for this long (30 min).
pub const SWAP_BACK_COOLDOWN_MS: u64 = 1_800_000;
/// A relay that turned this node away as a non-member is skipped this long
/// while it is offered to us (10 min: its member list may be catching up) ...
pub const NOT_MEMBER_OFFERED_MS: u64 = 600_000;
/// ... and this long otherwise (6 h).
pub const NOT_MEMBER_OTHER_MS: u64 = 6 * 3_600_000;
/// Half-life of a relay's availability (3 days).
pub const AVAIL_HALF_LIFE_MS: u64 = 3 * 86_400_000;
/// Relays remembered: the picked ones, then the most recently used.
pub const MAX_REMEMBERED: usize = 32;
/// The file in the data dir.
pub const RELAY_MEMORY_FILE: &str = "relay_memory.json";
/// The memory's format; a file of another version reads as an empty memory.
pub const RELAY_MEMORY_VERSION: u32 = 1;
/// Availability 1 (reserved at every sample), in billionths: fine enough
/// that a 10 s sample still moves a 3-day EWMA.
pub const AVAIL_ONE: u32 = 1_000_000_000;
/// One availability sample counts for at most this long (10 min), so a
/// wall-clock jump never moves it further.
pub const MAX_SAMPLE_MS: u64 = 600_000;
/// Where a relay never sampled starts: 1/2 ...
const AVAIL_PRIOR: u32 = AVAIL_ONE / 2;
/// ... or 4/5 when its offer is CONFIRMED.
const AVAIL_PRIOR_CONFIRMED: u32 = AVAIL_ONE / 5 * 4;
/// A failed probation keeps a relay from replacing another this long (1 h),
/// doubled with each further failure ([`probation_backoff_ms`]) ...
const PROBATION_PENALTY_MS: u64 = 3_600_000;
/// ... up to this (24 h); a relay that failed its probation within it never
/// replaces another that failed its own.
pub const MAX_PROBATION_BACKOFF_MS: u64 = 24 * 3_600_000;
/// A reservation accepted within this is a recent success (24 h).
const RECENT_OK_MS: u64 = 86_400_000;
/// A time stamped further than this in the future means the clock went
/// back: it counts as nothing.
const CLOCK_SLACK_MS: u64 = 5 * 60 * 1000;

// ── Inputs ───────────────────────────────────────────────────────────────────

/// The timers [`select`] uses, in milliseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timing {
    pub replace_after_ms: u64,
    pub probation_ms: u64,
    pub min_gap_ms: u64,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            replace_after_ms: REPLACE_AFTER_MS,
            probation_ms: PROBATION_MS,
            min_gap_ms: MIN_GAP_MS,
        }
    }
}

impl Timing {
    /// The constants, or in a debug build the three timers
    /// `RAVEN_LAB_RELAY_SELECT=<replace_after_s>,<probation_s>,<min_gap_s>`
    /// sets ([`crate::p2p_gate::lab_relay_select`]). Release builds never read
    /// the switch.
    pub fn current() -> Self {
        Self::from_lab(crate::p2p_gate::lab_relay_select())
    }

    fn from_lab(lab: Option<(u64, u64, u64)>) -> Self {
        match lab {
            Some((replace_after_s, probation_s, min_gap_s)) => Self {
                replace_after_ms: replace_after_s * 1000,
                probation_ms: probation_s * 1000,
                min_gap_ms: min_gap_s * 1000,
            },
            None => Self::default(),
        }
    }
}

/// Where a relay comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    /// Set by hand (`--p2p-relay`, `RAVEN_P2P_RELAYS`, node policy).
    Manual,
    /// Offered by a contact (its device key, hex).
    Offer { operator_pub_hex: String },
}

impl Source {
    /// The operator's device key (hex), for an offered relay.
    pub fn operator(&self) -> Option<&str> {
        match self {
            Self::Manual => None,
            Self::Offer { operator_pub_hex } => Some(operator_pub_hex),
        }
    }
}

/// What this node says of the contact that offered a relay, now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operator {
    /// A verified (pinned), unblocked contact this node may show its IP.
    Verified,
    /// A verified contact this node hides its IP from (D4: per contact or
    /// for everyone). Its relay would see our IP: never used.
    IpHidden,
    /// Not, or no longer, a verified and unblocked contact.
    Unverified,
    /// Several contacts offer this relay key ([`candidates`]): a mistake or
    /// a lie, and nothing tells which of them its traffic reaches. Never
    /// used while that lasts.
    Disputed,
}

/// An offered relay [`select`] may pick ([`candidates`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    /// Its first address (`<host+transport>/p2p/<relay>`).
    pub via: ViaAddr,
    /// Every address it was offered at, as `via=` text, [`Self::via`] first:
    /// the others are fallbacks of one reservation.
    pub addrs: Vec<String>,
    pub source: Source,
    /// The offer is CONFIRMED (a member reserved on it from a global IP
    /// within 24 h, or UPnP mapped it).
    pub confirmed: bool,
    /// The network of its first IP address ([`net_group`]).
    pub group: Option<String>,
    /// When the snapshot that carried the offer expires: past, it is a
    /// tombstone's, usable only while its slot holds a reservation.
    pub expires_at_ms: u64,
    /// Its operator now (the worst, when several contacts offer it).
    pub operator: Operator,
}

/// One relay slot of the p2p host, as [`select`] sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlotNow {
    /// The relay's PeerId.
    pub peer_id: String,
    /// A relay set by hand: [`Input::manual`] keeps it, whatever happens
    /// here.
    pub manual: bool,
    /// It holds our reservation now.
    pub active: bool,
    /// Since when it has lost a reservation it held (`None` while it holds
    /// one, or when it held none yet). Clamped by the caller to the start of
    /// the current host generation.
    pub lost_since_ms: Option<u64>,
    /// When it was picked, clamped the same way.
    pub selected_at_ms: u64,
    /// It accepted a reservation since it was picked.
    pub ever_reserved: bool,
}

/// What [`select`] decides from.
pub struct Input<'a> {
    /// This node's own PeerId.
    pub me: &'a str,
    /// The relays set by hand, every address of each.
    pub manual: &'a [ViaAddr],
    /// The offered relays ([`candidates`]).
    pub offers: &'a [Candidate],
    /// The host's relay slots now.
    pub slots: &'a [SlotNow],
    pub mem: &'a RelayMemory,
    /// Another slot holds a reservation, or a connection of ours succeeded
    /// within the last 2 minutes: this node is online, so a relay that
    /// does not answer is the relay's fault.
    pub online: bool,
    /// Automatic choice is on (node policy, inside the friend relay gate).
    pub auto: bool,
    pub now_ms: u64,
    /// Relays at most ([`crate::p2p_route::MAX_VIA`]).
    pub max: usize,
    pub t: Timing,
    /// Learning connectivity's term of each relay (its PeerId, the term:
    /// Phase 6a, [`crate::learning::relay::term`]), added to its score as a
    /// standby, clamped to ±[`RELAY_TERM_MAX`]; a relay not listed adds 0.
    /// Empty while learning is off: today's score.
    pub learned: &'a [(String, i64)],
}

// ── The decision ─────────────────────────────────────────────────────────────

/// Why a picked relay was replaced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LossWhy {
    /// It lost its reservation and stayed without one for
    /// [`Timing::replace_after_ms`].
    NotAnswering,
    /// It accepted no reservation within [`Timing::probation_ms`] of being
    /// picked.
    NeverReserved,
}

/// Why a picked relay was dropped without waiting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DropWhy {
    /// Its operator no longer offers it, or the offer expired and the
    /// reservation that outlived it was lost.
    OfferWithdrawn,
    /// Its operator is no longer a verified, unblocked contact.
    OperatorGone,
    /// This node hides its IP from its operator.
    IpHidden,
    /// It turned this node away as a non-member ([`note_not_member`]).
    NotMember,
    /// Several contacts offer it ([`Operator::Disputed`]).
    Disputed,
    /// Automatic relay choice is off.
    AutoOff,
    /// The relays set by hand take every slot.
    ManualFirst,
}

impl DropWhy {
    /// The reason as a log line names it (no peer, no address).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OfferWithdrawn => "offer withdrawn",
            Self::OperatorGone => "its operator is no longer a verified contact",
            Self::IpHidden => "this node hides its IP from its operator",
            Self::NotMember => "it does not admit this node",
            Self::Disputed => "two contacts offer it under one key",
            Self::AutoOff => "automatic relay choice is off",
            Self::ManualFirst => "relays set by hand take every slot",
        }
    }
}

/// One change [`select`] made to the slots (relay PeerIds).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change {
    /// An empty slot took this relay.
    Filled(String),
    Replaced {
        old: String,
        new: String,
        why: LossWhy,
    },
    Dropped {
        old: String,
        why: DropWhy,
    },
    /// Due for replacement, but no other offered relay may take its place:
    /// kept.
    Kept(String),
}

/// The relays to hold: one entry per relay (its first address), the ones
/// set by hand first, then the picked ones in slot order (a replacement
/// takes its predecessor's place), then the slots filled now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
    pub relays: Vec<(ViaAddr, Source)>,
    pub changes: Vec<Change>,
}

/// What [`select`] does with an automatic slot.
enum Plan<'c> {
    Keep(&'c Candidate),
    Due(&'c Candidate, LossWhy),
    Drop(DropWhy),
}

/// A relay held (or about to be): what diversity compares.
struct Held<'c> {
    peer: &'c str,
    operator: Option<&'c str>,
    group: Option<String>,
}

impl<'c> Held<'c> {
    fn manual(via: &'c ViaAddr) -> Self {
        Self {
            peer: &via.peer_id,
            operator: None,
            group: net_group(&via.text),
        }
    }

    fn offered(c: &'c Candidate) -> Self {
        Self {
            peer: &c.via.peer_id,
            operator: c.source.operator(),
            group: c.group.clone(),
        }
    }
}

/// Which relays to hold now (see the module doc). Pure.
pub fn select(i: &Input) -> Decision {
    let ctx = Ctx::new(i);
    let mut relays: Vec<(ViaAddr, Source)> = ctx
        .manual
        .iter()
        .map(|v| (v.clone(), Source::Manual))
        .collect();
    let mut changes = Vec::new();
    // The automatic slots, once each; a relay also set by hand is the
    // manual slot's.
    let mut slots: Vec<&SlotNow> = Vec::new();
    for s in i.slots.iter().filter(|s| !s.manual) {
        if !ctx.is_manual(&s.peer_id) && !slots.iter().any(|o| o.peer_id == s.peer_id) {
            slots.push(s);
        }
    }
    if !i.auto {
        changes.extend(slots.iter().map(|s| Change::Dropped {
            old: s.peer_id.clone(),
            why: DropWhy::AutoOff,
        }));
        return Decision { relays, changes };
    }

    // Which slots stay, are due for replacement, or go now.
    let mut room = i.max.saturating_sub(relays.len());
    let mut plans: Vec<(&SlotNow, Plan)> = Vec::new();
    for s in slots {
        let offer = ctx.offer(&s.peer_id).filter(|c| ctx.usable(c, Some(s)));
        let plan = match offer {
            None => Plan::Drop(ctx.drop_why(s)),
            Some(_) if room == 0 => Plan::Drop(DropWhy::ManualFirst),
            Some(c) => {
                room -= 1;
                let lost_ms = match (s.active, s.lost_since_ms) {
                    (false, Some(since)) => i.now_ms.saturating_sub(since),
                    _ => 0,
                };
                let untried = !s.active && !s.ever_reserved;
                if i.online
                    && untried
                    && i.now_ms.saturating_sub(s.selected_at_ms) >= i.t.probation_ms
                {
                    Plan::Due(c, LossWhy::NeverReserved)
                } else if i.online && lost_ms >= i.t.replace_after_ms {
                    Plan::Due(c, LossWhy::NotAnswering)
                } else {
                    Plan::Keep(c)
                }
            }
        };
        plans.push((s, plan));
    }

    // What is held, for diversity: every relay set by hand and every slot
    // that stays or is due.
    let mut held: Vec<Held> = ctx
        .manual
        .iter()
        .map(Held::manual)
        .chain(plans.iter().filter_map(|(_, plan)| match *plan {
            Plan::Keep(c) | Plan::Due(c, _) => Some(Held::offered(c)),
            Plan::Drop(_) => None,
        }))
        .collect();
    // One replacement for loss per gap. A relay that never reserved is an
    // empty slot that was tried: it does not wait.
    let mut gap_ok = !recent(i.mem.last_change_ms, i.now_ms, i.t.min_gap_ms);
    for (s, plan) in plans {
        match plan {
            Plan::Drop(why) => changes.push(Change::Dropped {
                old: s.peer_id.clone(),
                why,
            }),
            Plan::Keep(c) => relays.push((c.via.clone(), c.source.clone())),
            Plan::Due(c, why) => {
                if why == LossWhy::NotAnswering && !gap_ok {
                    relays.push((c.via.clone(), c.source.clone()));
                    continue;
                }
                held.retain(|h| h.peer != s.peer_id);
                match ctx.best_standby(&held, Some(why)) {
                    Some(n) => {
                        changes.push(Change::Replaced {
                            old: s.peer_id.clone(),
                            new: n.via.peer_id.clone(),
                            why,
                        });
                        relays.push((n.via.clone(), n.source.clone()));
                        held.push(Held::offered(n));
                        if why == LossWhy::NotAnswering {
                            gap_ok = false;
                        }
                    }
                    None => {
                        // Never drop the only relay there is: none other
                        // offered may take its place now.
                        changes.push(Change::Kept(s.peer_id.clone()));
                        relays.push((c.via.clone(), c.source.clone()));
                        held.push(Held::offered(c));
                    }
                }
            }
        }
    }
    // Empty slots fill at once.
    while relays.len() < i.max {
        let Some(n) = ctx.best_standby(&held, None) else {
            break;
        };
        changes.push(Change::Filled(n.via.peer_id.clone()));
        relays.push((n.via.clone(), n.source.clone()));
        held.push(Held::offered(n));
    }
    Decision { relays, changes }
}

/// The offered relay to dial, without a reservation, as the proof that
/// this node is online: while no slot (set by hand or picked) holds a
/// reservation and nothing else proves it (`i.online` false), [`select`]
/// replaces no relay however long they are lost, so a circle whose picked
/// relays all sleep would wait for unrelated traffic. It is the relay
/// [`select`] would put in a slot's place were this node online: a
/// connection to it proves both that this node is online and that the
/// relay answers. `None` when a slot holds a reservation, this node is known
/// to be online, automatic choice is off, or no replacement is due. Pure.
pub fn probe<'i>(i: &Input<'i>) -> Option<&'i Candidate> {
    if !i.auto || i.online || i.slots.iter().any(|s| s.active) {
        return None;
    }
    let online = Input { online: true, ..*i };
    select(&online).changes.iter().find_map(|c| match c {
        Change::Replaced { new, .. } => i.offers.iter().find(|o| o.via.peer_id == *new),
        _ => None,
    })
}

/// The offered relays automatic choice could take now beside the slots
/// `i` describes (status: spare relays, used when one stops answering):
/// usable, with a live offer, and in no slot. 0 while automatic choice is
/// off. Pure.
pub fn standby(i: &Input) -> usize {
    if !i.auto {
        return 0;
    }
    let ctx = Ctx::new(i);
    i.offers
        .iter()
        .filter(|c| ctx.usable(c, None))
        .filter(|c| !i.slots.iter().any(|s| s.peer_id == c.via.peer_id))
        .count()
}

/// [`select`]'s input with the relays set by hand that count.
struct Ctx<'a, 'i> {
    i: &'a Input<'i>,
    manual: Vec<ViaAddr>,
}

impl<'a, 'i> Ctx<'a, 'i> {
    fn new(i: &'a Input<'i>) -> Self {
        Self {
            i,
            manual: group_relays(i.manual)
                .into_iter()
                .take(i.max)
                .filter_map(|(_, addrs)| addrs.into_iter().next())
                .collect(),
        }
    }

    fn is_manual(&self, peer: &str) -> bool {
        self.manual.iter().any(|v| v.peer_id == peer)
    }

    fn offer(&self, peer: &str) -> Option<&'i Candidate> {
        self.i.offers.iter().find(|c| c.via.peer_id == peer)
    }

    /// May automatic choice hold `c`, in `slot` (or pick it for one)? Its
    /// operator is verified and shown our IP, it is neither us nor set by
    /// hand, it did not turn us away lately, and its offer is live, or
    /// expired while its slot still holds a reservation (the relay's
    /// acceptance is its operator's live consent).
    fn usable(&self, c: &Candidate, slot: Option<&SlotNow>) -> bool {
        let i = self.i;
        c.operator == Operator::Verified
            && c.via.peer_id != i.me
            && !self.is_manual(&c.via.peer_id)
            && !i.mem.is_not_member(&c.via.peer_id, i.now_ms)
            && (c.expires_at_ms > i.now_ms || slot.is_some_and(|s| s.active))
    }

    fn drop_why(&self, s: &SlotNow) -> DropWhy {
        if self.i.mem.is_not_member(&s.peer_id, self.i.now_ms) {
            return DropWhy::NotMember;
        }
        match self.offer(&s.peer_id).map(|c| c.operator) {
            Some(Operator::Unverified) => DropWhy::OperatorGone,
            Some(Operator::IpHidden) => DropWhy::IpHidden,
            Some(Operator::Disputed) => DropWhy::Disputed,
            // No offer any more, or an expired one whose reservation is lost.
            _ => DropWhy::OfferWithdrawn,
        }
    }

    /// The best offered relay to take a slot: usable with a live offer, not
    /// held, not in any slot now (a slot's relay is that slot's business),
    /// and for a replacement (`replacing`: why the slot's relay goes) not
    /// one replaced within the cooldown, nor one in its failed-probation
    /// back-off; and to replace a relay that failed its probation, none
    /// that failed its own within [`MAX_PROBATION_BACKOFF_MS`] (one this
    /// node could not reach either). An empty slot takes the best there is.
    fn best_standby(&self, held: &[Held], replacing: Option<LossWhy>) -> Option<&'i Candidate> {
        let i = self.i;
        i.offers
            .iter()
            .filter(|c| self.usable(c, None))
            .filter(|c| !held.iter().any(|h| h.peer == c.via.peer_id))
            .filter(|c| !i.slots.iter().any(|s| s.peer_id == c.via.peer_id))
            .filter(|c| {
                let m = i.mem.memo(&c.via.peer_id);
                match replacing {
                    None => true,
                    Some(why) => {
                        !recent(m.replaced_at_ms, i.now_ms, SWAP_BACK_COOLDOWN_MS)
                            && !in_probation_backoff(m, i.now_ms)
                            && !(why == LossWhy::NeverReserved
                                && recent(
                                    m.probation_failed_at_ms,
                                    i.now_ms,
                                    MAX_PROBATION_BACKOFF_MS,
                                ))
                    }
                }
            })
            .max_by_key(|c| {
                let tie = tie(i.me, &c.via.peer_id);
                (
                    self.score(c, held, tie[0]),
                    std::cmp::Reverse(tie),
                    std::cmp::Reverse(c.via.peer_id.clone()),
                )
            })
    }

    fn score(&self, c: &Candidate, held: &[Held], tie: u8) -> i64 {
        let now = self.i.now_ms;
        let m = self.i.mem.memo(&c.via.peer_id);
        let mut s = 0i64;
        if in_probation_backoff(m, now) {
            s -= 1000;
        }
        if recent(m.replaced_at_ms, now, SWAP_BACK_COOLDOWN_MS) {
            s -= 400;
        }
        if recent(m.last_ok_ms, now, RECENT_OK_MS) {
            s += 300;
        }
        if c.confirmed {
            s += 100;
        }
        s += i64::from(avail_now(m, c.confirmed) / (AVAIL_ONE / 200));
        let operator = c.source.operator();
        if !held
            .iter()
            .any(|h| h.operator.is_some() && h.operator == operator)
        {
            s += 50;
        }
        if c.group.is_some() && !held.iter().any(|h| h.group == c.group) {
            s += 50;
        }
        s += self.learned(&c.via.peer_id);
        s - i64::from(tie % 10)
    }

    /// Learning connectivity's term of `peer` ([`Input::learned`]), within
    /// ±[`RELAY_TERM_MAX`] whatever the caller passed: smaller than every
    /// penalty above, so it reorders comparable relays only.
    fn learned(&self, peer: &str) -> i64 {
        self.i
            .learned
            .iter()
            .find(|(p, _)| p == peer)
            .map_or(0, |(_, t)| *t)
            .clamp(-RELAY_TERM_MAX, RELAY_TERM_MAX)
    }
}

/// How long a relay that failed its probation `fails` times in a row (since
/// it last accepted a reservation here) is held back: 1 h, doubled with
/// each failure, at most [`MAX_PROBATION_BACKOFF_MS`].
pub fn probation_backoff_ms(fails: u32) -> u64 {
    let doublings = fails.max(1).saturating_sub(1).min(16);
    PROBATION_PENALTY_MS
        .saturating_mul(1u64 << doublings)
        .min(MAX_PROBATION_BACKOFF_MS)
}

/// Is `m` within the back-off of its last failed probation? (A memo from
/// before failures were counted counts one.)
fn in_probation_backoff(m: &RelayMemo, now: u64) -> bool {
    recent(
        m.probation_failed_at_ms,
        now,
        probation_backoff_ms(m.probation_fails),
    )
}

/// SHA-256(me || relay): each node orders equal relays its own way, so a
/// circle spreads over them.
fn tie(me: &str, relay: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(me.as_bytes());
    h.update(relay.as_bytes());
    h.finalize().into()
}

/// Did `at` happen within `span` before `now`? Never (0) is not; a stamp
/// further in the future than the clock slack means the clock went back,
/// and is not either.
fn recent(at: u64, now: u64, span: u64) -> bool {
    at != 0 && at <= now.saturating_add(CLOCK_SLACK_MS) && now.saturating_sub(at) < span
}

// ── Candidates ───────────────────────────────────────────────────────────────

/// The offers [`crate::learned_routes::offers`] lists (newest sender first:
/// the operator's device key hex, the PeerId its snapshot named, the offer,
/// the snapshot's expiry) as candidates, one per relay. `operator` says
/// what each operator is now; `own` holds the PeerIds that are never a
/// relay here: this node's own, its own friend relay's, and its contacts'
/// p2p PeerIds (a contact is no relay key another contact may name). A
/// relay several contacts offer is [`Operator::Disputed`]: two operators of
/// one relay key are a mistake or a lie, only one of them may be the
/// operator its traffic reaches, and nothing here tells which; its
/// addresses are never taken from either.
pub fn candidates(
    offers: &[(String, String, StoredOffer, u64)],
    operator: impl Fn(&str) -> Operator,
    own: &[&str],
) -> Vec<Candidate> {
    let mut out: Vec<Candidate> = Vec::new();
    for (operator_pub_hex, operator_peer_id, offer, expires_at_ms) in offers {
        let Ok(relay) = normalize_peer_id(&offer.relay_peer_id) else {
            continue;
        };
        // Never under a profile PeerId: the operator's own, or ours.
        if own.contains(&relay.as_str()) || relay == *operator_peer_id {
            continue;
        }
        let standing = operator(operator_pub_hex);
        if let Some(seen) = out.iter_mut().find(|c| c.via.peer_id == relay) {
            seen.operator = if seen.source.operator() == Some(operator_pub_hex.as_str()) {
                worst(seen.operator, standing)
            } else {
                Operator::Disputed
            };
            continue;
        }
        let addrs: Vec<ViaAddr> = offer
            .addrs
            .iter()
            .filter_map(|a| parse_via(&format!("{a}/p2p/{relay}")).ok())
            .collect();
        let Some(via) = addrs.first().cloned() else {
            continue;
        };
        out.push(Candidate {
            group: addrs.iter().find_map(|v| net_group(&v.text)),
            addrs: addrs.into_iter().map(|v| v.text).collect(),
            via,
            source: Source::Offer {
                operator_pub_hex: operator_pub_hex.clone(),
            },
            confirmed: offer.flags & FLAG_CONFIRMED != 0,
            expires_at_ms: *expires_at_ms,
            operator: standing,
        });
    }
    out
}

fn worst(a: Operator, b: Operator) -> Operator {
    let rank = |o| match o {
        Operator::Verified => 0,
        Operator::IpHidden => 1,
        Operator::Unverified => 2,
        Operator::Disputed => 3,
    };
    if rank(b) > rank(a) {
        b
    } else {
        a
    }
}

/// The network an address (`/ip4/…` or `/ip6/…`, any transport after it)
/// is on, for diversity: the /24 of a globally routable IPv4 address, the
/// /48 of an IPv6 one, an IPv6 address that carries an IPv4 one as that
/// IPv4 address (the rule of the reachability checks, raven-swarm
/// `net_group`). `None` for a DNS name and anything not globally routable.
pub fn net_group(addr: &str) -> Option<String> {
    let mut parts = addr.split('/');
    let (Some(""), Some("ip4" | "ip6"), Some(host)) = (parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    let ip: IpAddr = host.parse().ok()?;
    if !is_global_ip(ip) {
        return None;
    }
    let v4 = |o: [u8; 4]| format!("{}.{}.{}.0/24", o[0], o[1], o[2]);
    Some(match ip {
        IpAddr::V4(a) => v4(a.octets()),
        IpAddr::V6(a) => match embedded_ipv4(a) {
            Some(m) => v4(m.octets()),
            None => {
                let s = a.segments();
                format!("{:x}:{:x}:{:x}::/48", s[0], s[1], s[2])
            }
        },
    })
}

// ── Memory ───────────────────────────────────────────────────────────────────

/// What this node remembers of one relay. Times are wall-clock ms; 0 is
/// never.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayMemo {
    /// When it last accepted a reservation of ours.
    #[serde(default)]
    pub last_ok_ms: u64,
    /// Its availability, 0..=[`AVAIL_ONE`]: an EWMA of "it holds our
    /// reservation" over the samples taken while it was picked
    /// ([`observe`]).
    #[serde(default)]
    pub avail_ppb: u32,
    /// The last sample (0: none yet; it then reads its prior).
    #[serde(default)]
    pub avail_at_ms: u64,
    /// Skipped until then: it turned us away as a non-member.
    #[serde(default)]
    pub not_member_until_ms: u64,
    /// When it turned us away ([`note_not_member`]): a contact naming it
    /// again after that ends the skip ([`named_again`]).
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub not_member_at_ms: u64,
    /// When it last failed probation.
    #[serde(default)]
    pub probation_failed_at_ms: u64,
    /// Probations it failed since it last accepted a reservation here (its
    /// back-off, [`probation_backoff_ms`]).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub probation_fails: u32,
    /// When automatic choice last replaced it.
    #[serde(default)]
    pub replaced_at_ms: u64,
}

impl RelayMemo {
    /// Its latest time: what bounding keeps the most recent by. A
    /// not-member window counts until it ends, so it is kept while it holds.
    fn last_use_ms(&self) -> u64 {
        self.last_ok_ms
            .max(self.avail_at_ms)
            .max(self.not_member_until_ms)
            .max(self.probation_failed_at_ms)
            .max(self.replaced_at_ms)
    }
}

/// [`RELAY_MEMORY_FILE`].
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayMemory {
    pub version: u32,
    /// Bumped by every [`commit`] that changed which relays are picked.
    #[serde(default)]
    pub generation: u64,
    /// The relays automatic choice holds (PeerIds, at most
    /// [`crate::p2p_route::MAX_VIA`]): a restart takes them again while they
    /// are offered.
    #[serde(default)]
    pub selected: Vec<String>,
    /// When the picked relays last changed.
    #[serde(default)]
    pub last_change_ms: u64,
    #[serde(default)]
    pub relays: BTreeMap<String, RelayMemo>,
}

impl Default for RelayMemory {
    fn default() -> Self {
        Self {
            version: RELAY_MEMORY_VERSION,
            generation: 0,
            selected: Vec::new(),
            last_change_ms: 0,
            relays: BTreeMap::new(),
        }
    }
}

/// The memo of a relay never seen.
static NEVER_SEEN: RelayMemo = RelayMemo {
    last_ok_ms: 0,
    avail_ppb: 0,
    avail_at_ms: 0,
    not_member_until_ms: 0,
    not_member_at_ms: 0,
    probation_failed_at_ms: 0,
    probation_fails: 0,
    replaced_at_ms: 0,
};

fn is_zero(n: &u32) -> bool {
    *n == 0
}

fn is_zero_u64(n: &u64) -> bool {
    *n == 0
}

impl RelayMemory {
    /// What is remembered of `peer` (all zero when nothing is).
    pub fn memo(&self, peer: &str) -> &RelayMemo {
        self.relays.get(peer).unwrap_or(&NEVER_SEEN)
    }

    /// Did `peer` turn this node away as a non-member lately? A window
    /// longer than the longest one means the clock went back: it is over.
    pub fn is_not_member(&self, peer: &str, now_ms: u64) -> bool {
        let until = self.memo(peer).not_member_until_ms;
        until > now_ms && until - now_ms <= NOT_MEMBER_OTHER_MS + CLOCK_SLACK_MS
    }

    fn entry(&mut self, peer: &str) -> &mut RelayMemo {
        self.relays.entry(peer.to_string()).or_default()
    }
}

/// `m`'s availability now: its last value, or its prior while it was
/// never sampled.
fn avail_now(m: &RelayMemo, confirmed: bool) -> u32 {
    match (m.avail_at_ms, confirmed) {
        (0, false) => AVAIL_PRIOR,
        (0, true) => AVAIL_PRIOR_CONFIRMED,
        _ => m.avail_ppb,
    }
}

/// One availability sample of a picked relay (every 10 s; standby relays
/// get none): the EWMA moves toward 1 when it holds our reservation
/// (`active`), else toward 0, by the time since the last sample, at most
/// [`MAX_SAMPLE_MS`] (a clock that went back counts nothing). The first
/// sample starts from the prior (`confirmed`: its offer is CONFIRMED).
pub fn observe(mem: &mut RelayMemory, peer: &str, active: bool, confirmed: bool, now_ms: u64) {
    let m = mem.entry(peer);
    if m.avail_at_ms == 0 {
        m.avail_ppb = avail_now(m, confirmed);
    } else {
        let dt = now_ms.saturating_sub(m.avail_at_ms).min(MAX_SAMPLE_MS);
        let keep = (-(dt as f64) / AVAIL_HALF_LIFE_MS as f64).exp2();
        let target = if active { f64::from(AVAIL_ONE) } else { 0.0 };
        let value = target + (f64::from(m.avail_ppb) - target) * keep;
        m.avail_ppb = value.round().clamp(0.0, f64::from(AVAIL_ONE)) as u32;
    }
    m.avail_at_ms = now_ms;
    trim(mem);
}

/// `peer` accepted our reservation: a success, and whatever it refused
/// before is over.
pub fn note_ok(mem: &mut RelayMemory, peer: &str, now_ms: u64) {
    let m = mem.entry(peer);
    m.last_ok_ms = now_ms;
    m.not_member_until_ms = 0;
    m.not_member_at_ms = 0;
    m.probation_failed_at_ms = 0;
    m.probation_fails = 0;
    trim(mem);
}

/// `peer` closed our connection at once without a reservation or circuit
/// (it does not count us a member): skip it for [`NOT_MEMBER_OFFERED_MS`]
/// when `short` (a contact offers it to us, or it is a relay a contact's
/// route names, which its operator may admit us to any moment), else for
/// [`NOT_MEMBER_OTHER_MS`] (a relay set by hand that nobody offers).
pub fn note_not_member(mem: &mut RelayMemory, peer: &str, short: bool, now_ms: u64) {
    let span = if short {
        NOT_MEMBER_OFFERED_MS
    } else {
        NOT_MEMBER_OTHER_MS
    };
    let m = mem.entry(peer);
    m.not_member_until_ms = now_ms.saturating_add(span);
    m.not_member_at_ms = now_ms;
    trim(mem);
}

/// A circuit through `peer` came up: it admits this node, whatever it
/// refused before. `true` when that ended a skip.
pub fn clear_not_member(mem: &mut RelayMemory, peer: &str) -> bool {
    match mem.relays.get_mut(peer) {
        Some(m) if m.not_member_until_ms != 0 => {
            m.not_member_until_ms = 0;
            m.not_member_at_ms = 0;
            true
        }
        _ => false,
    }
}

/// A contact's card or route hints named `peer` at `named_at_ms`: when that
/// is after it turned this node away, its operator may have admitted this
/// node since, so the skip ends. `true` when it ended one.
pub fn named_again(mem: &mut RelayMemory, peer: &str, named_at_ms: u64) -> bool {
    let after = mem
        .relays
        .get(peer)
        .is_some_and(|m| m.not_member_until_ms != 0 && named_at_ms > m.not_member_at_ms);
    after && clear_not_member(mem, peer)
}

/// `peer` was picked and accepted no reservation within its probation: one
/// more failure, and its back-off starts now. [`commit`] notes it for every
/// relay replaced for that.
pub fn note_probation_failed(mem: &mut RelayMemory, peer: &str, now_ms: u64) {
    let m = mem.entry(peer);
    m.probation_failed_at_ms = now_ms;
    m.probation_fails = m.probation_fails.saturating_add(1);
    trim(mem);
}

/// Remember decision `d`: every relay it replaced (when, and a failed
/// probation), and the relays automatic choice now holds. `true` when
/// those changed (in any order): the generation moves on and the gap clock
/// restarts.
pub fn commit(mem: &mut RelayMemory, d: &Decision, now_ms: u64) -> bool {
    for c in &d.changes {
        if let Change::Replaced { old, why, .. } = c {
            mem.entry(old).replaced_at_ms = now_ms;
            if *why == LossWhy::NeverReserved {
                note_probation_failed(mem, old, now_ms);
            }
        }
    }
    let picked: Vec<String> = d
        .relays
        .iter()
        .filter(|(_, source)| *source != Source::Manual)
        .map(|(via, _)| via.peer_id.clone())
        .collect();
    let changed =
        picked.iter().collect::<HashSet<_>>() != mem.selected.iter().collect::<HashSet<_>>();
    if changed {
        mem.selected = picked;
        mem.last_change_ms = now_ms;
        mem.generation += 1;
    }
    trim(mem);
    changed
}

/// Keep at most [`MAX_REMEMBERED`] relays: the picked ones, then the most
/// recently used.
fn trim(mem: &mut RelayMemory) {
    if mem.relays.len() <= MAX_REMEMBERED {
        return;
    }
    let mut order: Vec<(bool, u64, &String)> = mem
        .relays
        .iter()
        .map(|(peer, m)| (mem.selected.contains(peer), m.last_use_ms(), peer))
        .collect();
    order.sort_unstable_by(|a, b| b.cmp(a));
    let keep: HashSet<String> = order
        .into_iter()
        .take(MAX_REMEMBERED)
        .map(|(_, _, peer)| peer.clone())
        .collect();
    mem.relays.retain(|peer, _| keep.contains(peer));
}

/// The memory in `data_dir`. Advisory: a missing, unreadable or corrupt
/// file, or one of another version, is an empty memory; PeerIds that are
/// not canonical are dropped, and the rest is bounded.
pub fn load_memory(data_dir: &Path) -> RelayMemory {
    let Some(mut mem) = crate::at_rest::load_json_advisory::<RelayMemory>(
        data_dir,
        &data_dir.join(RELAY_MEMORY_FILE),
        crate::at_rest::Kind::RelayMemory,
    )
    .into_loaded()
    .filter(|m| m.version == RELAY_MEMORY_VERSION) else {
        return RelayMemory::default();
    };
    let canonical = |p: &str| normalize_peer_id(p).is_ok_and(|n| n == p);
    mem.relays.retain(|peer, _| canonical(peer));
    for m in mem.relays.values_mut() {
        m.avail_ppb = m.avail_ppb.min(AVAIL_ONE);
    }
    let mut selected: Vec<String> = Vec::new();
    for peer in std::mem::take(&mut mem.selected) {
        if canonical(&peer) && !selected.contains(&peer) && selected.len() < MAX_VIA {
            selected.push(peer);
        }
    }
    mem.selected = selected;
    trim(&mut mem);
    mem
}

/// Write `mem` (bounded) to `data_dir`, owner-only, under the file's writer
/// lock: sealed in a sealed profile. A file that could not be read (a sealed
/// one whose key is not loaded, a changed byte) is never written over: an
/// error, counted ([`crate::at_rest::note_skipped_write`]).
pub fn save_memory(data_dir: &Path, mem: &RelayMemory) -> Result<(), String> {
    use crate::at_rest::{self, Advisory, Kind};
    let mut mem = mem.clone();
    mem.version = RELAY_MEMORY_VERSION;
    trim(&mut mem);
    let raw = serde_json::to_vec_pretty(&mem).map_err(|e| e.to_string())?;
    let path = data_dir.join(RELAY_MEMORY_FILE);
    let lock = at_rest::lock_file(data_dir, &path, Kind::RelayMemory).map_err(|e| e.to_string())?;
    if let Advisory::Unreadable(why) =
        at_rest::load_json_advisory::<serde_json::Value>(data_dir, &path, Kind::RelayMemory)
    {
        at_rest::note_skipped_write(data_dir, &why);
        return Err(format!("{RELAY_MEMORY_FILE} kept as it is: {why}"));
    }
    lock.store_bytes(&raw).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use crate::p2p_route::local_peer_id;
    use crate::route_hints::FLAG_AUTONAT;

    const S: u64 = 1000;
    const MIN: u64 = 60 * S;
    const HOUR: u64 = 60 * MIN;
    /// Day 20 000 of the epoch: far from 0 (never).
    const NOW: u64 = 20_000 * 24 * HOUR;

    /// The PeerId of key `seed`: a relay, or this node (0x01).
    fn pid(seed: u8) -> String {
        local_peer_id(&Identity::from_seed(&[seed; 32]))
    }

    fn me() -> String {
        pid(0x01)
    }

    /// Contact `n`'s device key (hex): an operator.
    fn op(n: u8) -> String {
        hex::encode([n; 32])
    }

    /// Relay `seed` on network 11.`net`.0.0/24 (TCP and QUIC), offered by
    /// contact `operator`, live for a day.
    fn offer(seed: u8, operator: u8, net: u8) -> Candidate {
        let relay = pid(seed);
        let tcp = parse_via(&format!("/ip4/11.{net}.0.{seed}/tcp/7427/p2p/{relay}")).unwrap();
        let quic = format!("/ip4/11.{net}.0.{seed}/udp/7427/quic-v1/p2p/{relay}");
        Candidate {
            addrs: vec![tcp.text.clone(), quic],
            group: net_group(&tcp.text),
            via: tcp,
            source: Source::Offer {
                operator_pub_hex: op(operator),
            },
            confirmed: false,
            expires_at_ms: NOW + 24 * HOUR,
            operator: Operator::Verified,
        }
    }

    /// Relay `seed` set by hand, on network 11.200.0.0/24, at `port`.
    fn manual(seed: u8, port: u16) -> ViaAddr {
        parse_via(&format!(
            "/ip4/11.200.0.{seed}/tcp/{port}/p2p/{}",
            pid(seed)
        ))
        .unwrap()
    }

    /// The slot of relay `seed`, picked an hour ago, holding our reservation.
    fn holding(seed: u8) -> SlotNow {
        SlotNow {
            peer_id: pid(seed),
            manual: false,
            active: true,
            lost_since_ms: None,
            selected_at_ms: NOW - HOUR,
            ever_reserved: true,
        }
    }

    /// ... that lost its reservation `ago`.
    fn lost(seed: u8, ago: u64) -> SlotNow {
        SlotNow {
            active: false,
            lost_since_ms: Some(NOW - ago),
            ..holding(seed)
        }
    }

    /// ... picked `ago`, with no reservation yet.
    fn untried(seed: u8, ago: u64) -> SlotNow {
        SlotNow {
            active: false,
            selected_at_ms: NOW - ago,
            ever_reserved: false,
            ..holding(seed)
        }
    }

    fn manual_slot(seed: u8) -> SlotNow {
        SlotNow {
            manual: true,
            ..holding(seed)
        }
    }

    /// What one [`select`] sees: by default automatic choice on, online,
    /// two slots, the real timers.
    struct World {
        manual: Vec<ViaAddr>,
        offers: Vec<Candidate>,
        slots: Vec<SlotNow>,
        mem: RelayMemory,
        online: bool,
        auto: bool,
        now: u64,
        t: Timing,
        /// Learning connectivity's terms (empty: learning off).
        learned: Vec<(String, i64)>,
    }

    impl World {
        fn new(offers: Vec<Candidate>, slots: Vec<SlotNow>) -> Self {
            Self {
                manual: Vec::new(),
                offers,
                slots,
                mem: RelayMemory::default(),
                online: true,
                auto: true,
                now: NOW,
                t: Timing::default(),
                learned: Vec::new(),
            }
        }

        /// Relay `seed`'s learned term is `term`.
        fn learn(&mut self, seed: u8, term: i64) {
            self.learned.retain(|(p, _)| *p != pid(seed));
            self.learned.push((pid(seed), term));
        }

        fn select(&self) -> Decision {
            select(&Input {
                me: &me(),
                manual: &self.manual,
                offers: &self.offers,
                slots: &self.slots,
                mem: &self.mem,
                online: self.online,
                auto: self.auto,
                now_ms: self.now,
                max: MAX_VIA,
                t: self.t,
                learned: &self.learned,
            })
        }

        fn standby(&self) -> usize {
            standby(&Input {
                me: &me(),
                manual: &self.manual,
                offers: &self.offers,
                slots: &self.slots,
                mem: &self.mem,
                online: self.online,
                auto: self.auto,
                now_ms: self.now,
                max: MAX_VIA,
                t: self.t,
                learned: &self.learned,
            })
        }

        fn probe(&self) -> Option<String> {
            probe(&Input {
                me: &me(),
                manual: &self.manual,
                offers: &self.offers,
                slots: &self.slots,
                mem: &self.mem,
                online: self.online,
                auto: self.auto,
                now_ms: self.now,
                max: MAX_VIA,
                t: self.t,
                learned: &self.learned,
            })
            .map(|c| c.via.peer_id.clone())
        }

        /// The relays the slots hold now are the ones picked.
        fn picked_now(mut self) -> Self {
            self.mem.selected = self
                .slots
                .iter()
                .filter(|s| !s.manual)
                .map(|s| s.peer_id.clone())
                .collect();
            self
        }
    }

    /// The relays a decision holds, in order.
    fn held(d: &Decision) -> Vec<String> {
        d.relays.iter().map(|(v, _)| v.peer_id.clone()).collect()
    }

    fn replaced(old: u8, new: u8, why: LossWhy) -> Change {
        Change::Replaced {
            old: pid(old),
            new: pid(new),
            why,
        }
    }

    fn dropped(old: u8, why: DropWhy) -> Change {
        Change::Dropped { old: pid(old), why }
    }

    #[test]
    fn sticky_while_healthy() {
        // A better relay is offered: confirmed, a recent success, another
        // operator and network. Two relays that hold our reservations stay,
        // and so does one that loses its reservation for five minutes in
        // every ten.
        let mut better = offer(0x13, 3, 3);
        better.confirmed = true;
        let mut w = World::new(
            vec![offer(0x11, 1, 1), offer(0x12, 1, 1), better],
            vec![holding(0x11), holding(0x12)],
        )
        .picked_now();
        note_ok(&mut w.mem, &pid(0x13), NOW - MIN);
        for round in 0..360u64 {
            w.now = NOW + round * 10 * S;
            w.slots[1] = if round % 60 < 30 {
                holding(0x12)
            } else {
                SlotNow {
                    active: false,
                    lost_since_ms: Some(NOW + (round - round % 60 + 30) * 10 * S),
                    ..holding(0x12)
                }
            };
            let d = w.select();
            assert_eq!(held(&d), [pid(0x11), pid(0x12)], "round {round}");
            assert!(d.changes.is_empty(), "round {round}: {d:?}");
            assert!(!commit(&mut w.mem, &d, w.now));
        }
        assert_eq!(w.mem.generation, 0);
    }

    #[test]
    fn replace_only_after_ten_minutes_of_loss_while_online() {
        let offers = vec![offer(0x11, 1, 1), offer(0x12, 2, 2), offer(0x13, 3, 3)];
        let mut w = World::new(
            offers.clone(),
            vec![lost(0x11, REPLACE_AFTER_MS - 1), holding(0x12)],
        )
        .picked_now();
        let d = w.select();
        assert_eq!(held(&d), [pid(0x11), pid(0x12)]);
        assert!(d.changes.is_empty(), "{d:?}");

        w.slots[0] = lost(0x11, REPLACE_AFTER_MS);
        let d = w.select();
        assert_eq!(held(&d), [pid(0x13), pid(0x12)], "in its place");
        assert_eq!(d.changes, [replaced(0x11, 0x13, LossWhy::NotAnswering)]);
        assert!(commit(&mut w.mem, &d, NOW));
        assert_eq!(w.mem.selected, [pid(0x13), pid(0x12)]);
        assert_eq!((w.mem.generation, w.mem.last_change_ms), (1, NOW));
        assert_eq!(w.mem.memo(&pid(0x11)).replaced_at_ms, NOW);
        assert_eq!(w.mem.memo(&pid(0x11)).probation_failed_at_ms, 0);
        // The same answer again changes nothing.
        assert!(!commit(&mut w.mem, &d, NOW + 10 * S));
        assert_eq!(w.mem.generation, 1);

        // The lab timers (RAVEN_LAB_RELAY_SELECT=6,4,2): six seconds.
        let mut w = World::new(offers, vec![lost(0x11, 5 * S), holding(0x12)]);
        w.t = Timing::from_lab(Some((6, 4, 2)));
        assert!(w.select().changes.is_empty());
        w.slots[0] = lost(0x11, 6 * S);
        assert_eq!(
            w.select().changes,
            [replaced(0x11, 0x13, LossWhy::NotAnswering)]
        );
    }

    #[test]
    fn no_replacement_while_offline_or_when_every_slot_is_lost() {
        let mut first = offer(0x13, 3, 3);
        first.confirmed = true;
        let offers = vec![
            offer(0x11, 1, 1),
            offer(0x12, 2, 2),
            first,
            offer(0x14, 4, 4),
        ];
        // Offline: nothing shows the relays are at fault, and a pick that
        // never reserved fails no probation.
        let mut w = World::new(offers, vec![lost(0x11, HOUR), untried(0x12, HOUR)]);
        w.online = false;
        let d = w.select();
        assert_eq!(held(&d), [pid(0x11), pid(0x12)]);
        assert!(d.changes.is_empty(), "{d:?}");
        // Every slot lost and no connection of ours succeeded lately: the
        // caller says offline, and the relays stay.
        w.slots = vec![lost(0x11, HOUR), lost(0x12, HOUR)];
        let d = w.select();
        assert_eq!(held(&d), [pid(0x11), pid(0x12)]);
        assert!(d.changes.is_empty(), "{d:?}");
        // A connection of ours succeeded: the relays are at fault, and one
        // is replaced (one per gap).
        w.online = true;
        let d = w.select();
        assert_eq!(d.changes, [replaced(0x11, 0x13, LossWhy::NotAnswering)]);
        assert_eq!(held(&d), [pid(0x13), pid(0x12)]);
    }

    /// Every slot lost and nothing proves this node online: nothing is
    /// replaced, however long; the relay that would take a slot is the one
    /// to dial as the proof, and once it answers it takes the slot.
    #[test]
    fn with_every_slot_down_the_relay_to_take_a_slot_is_dialled_as_the_proof() {
        let offers = vec![offer(0x11, 1, 1), offer(0x12, 2, 2), offer(0x13, 3, 3)];
        let mut w =
            World::new(offers, vec![lost(0x11, 8 * HOUR), lost(0x12, 8 * HOUR)]).picked_now();
        w.online = false;
        assert!(w.select().changes.is_empty());
        assert_eq!(w.probe(), Some(pid(0x13)));
        // The connection to it came up: this node is online.
        w.online = true;
        assert_eq!(w.probe(), None, "online: nothing to prove");
        assert_eq!(
            w.select().changes,
            [replaced(0x11, 0x13, LossWhy::NotAnswering)]
        );
        w.online = false;
        // Picks that never reserved (as after a restart while they sleep)
        // are due once their probation is over.
        w.slots = vec![
            untried(0x11, PROBATION_MS - 1),
            untried(0x12, PROBATION_MS - 1),
        ];
        assert_eq!(w.probe(), None, "still on probation");
        w.slots = vec![untried(0x11, PROBATION_MS), untried(0x12, PROBATION_MS)];
        assert_eq!(w.probe(), Some(pid(0x13)));
        // A slot holding a reservation proves it already.
        w.slots = vec![lost(0x11, 8 * HOUR), holding(0x12)];
        assert_eq!(w.probe(), None);
        // Within the loss window, no standby, or automatic choice off:
        // nothing to dial.
        w.slots = vec![
            lost(0x11, REPLACE_AFTER_MS - 1),
            lost(0x12, REPLACE_AFTER_MS - 1),
        ];
        assert_eq!(w.probe(), None);
        w.slots = vec![lost(0x11, 8 * HOUR), lost(0x12, 8 * HOUR)];
        w.offers.truncate(2);
        assert_eq!(w.probe(), None, "no standby");
        w.offers.push(offer(0x13, 3, 3));
        w.auto = false;
        assert_eq!(w.probe(), None);
    }

    /// X answers; Y and Z (offered too) never accept a reservation from
    /// this node. Six hours of rounds every 10 s replace the second slot
    /// once (the first pick that failed its probation): never back and
    /// forth between Y and Z.
    #[test]
    fn two_relays_this_node_cannot_reach_are_not_swapped_back_and_forth() {
        let mut x = offer(0x11, 1, 1);
        x.confirmed = true;
        let mut w = World::new(vec![x, offer(0x12, 2, 2), offer(0x13, 3, 3)], vec![]);
        let mut replaced = Vec::new();
        for round in 0..(6 * 360u64) {
            w.now = NOW + round * 10 * S;
            let d = w.select();
            commit(&mut w.mem, &d, w.now);
            replaced.extend(
                d.changes
                    .iter()
                    .filter(|c| matches!(c, Change::Replaced { .. }))
                    .cloned(),
            );
            let now = w.now;
            let before = std::mem::take(&mut w.slots);
            w.slots = d
                .relays
                .iter()
                .map(|(v, _)| {
                    before
                        .iter()
                        .find(|s| s.peer_id == v.peer_id)
                        .cloned()
                        .unwrap_or_else(|| {
                            let reserves = v.peer_id == pid(0x11);
                            SlotNow {
                                peer_id: v.peer_id.clone(),
                                manual: false,
                                active: reserves,
                                lost_since_ms: None,
                                selected_at_ms: now,
                                ever_reserved: reserves,
                            }
                        })
                })
                .collect();
            assert!(
                w.slots.iter().any(|s| s.peer_id == pid(0x11)),
                "round {round}"
            );
        }
        assert_eq!(replaced.len(), 1, "{replaced:?}");
        assert!(
            matches!(
                &replaced[0],
                Change::Replaced {
                    why: LossWhy::NeverReserved,
                    ..
                }
            ),
            "{replaced:?}"
        );
        // A reservation accepted ends the back-off.
        let failed = match &replaced[0] {
            Change::Replaced { old, .. } => old.clone(),
            _ => unreachable!(),
        };
        assert_eq!(w.mem.memo(&failed).probation_fails, 1);
        note_ok(&mut w.mem, &failed, w.now);
        assert_eq!(w.mem.memo(&failed).probation_fails, 0);
    }

    /// The back-off of a relay that failed its probation doubles with each
    /// failure, up to a day; within it the relay takes no slot back as a
    /// replacement, but an empty slot still may take it.
    #[test]
    fn a_failed_probation_backs_off_longer_each_time() {
        assert_eq!(
            probation_backoff_ms(0),
            HOUR,
            "a memo from before counts one"
        );
        assert_eq!(probation_backoff_ms(1), HOUR);
        assert_eq!(probation_backoff_ms(2), 2 * HOUR);
        assert_eq!(probation_backoff_ms(3), 4 * HOUR);
        assert_eq!(probation_backoff_ms(6), MAX_PROBATION_BACKOFF_MS);
        assert_eq!(probation_backoff_ms(u32::MAX), MAX_PROBATION_BACKOFF_MS);
        // R13 failed its probation twice, the last time 90 min ago; R11
        // stopped answering (it worked before).
        let mut w = World::new(
            vec![offer(0x11, 1, 1), offer(0x12, 2, 2), offer(0x13, 3, 3)],
            vec![lost(0x11, HOUR), holding(0x12)],
        )
        .picked_now();
        note_probation_failed(&mut w.mem, &pid(0x13), NOW - 3 * HOUR);
        note_probation_failed(&mut w.mem, &pid(0x13), NOW - 90 * MIN);
        assert_eq!(w.mem.memo(&pid(0x13)).probation_fails, 2);
        assert_eq!(w.select().changes, [Change::Kept(pid(0x11))]);
        w.now = NOW + 30 * MIN;
        assert_eq!(
            w.select().changes,
            [replaced(0x11, 0x13, LossWhy::NotAnswering)],
            "two hours after its last failure"
        );
        // An empty slot takes it within its back-off all the same.
        w.now = NOW;
        w.slots = vec![holding(0x12)];
        assert_eq!(w.select().changes, [Change::Filled(pid(0x11))]);
        w.offers.remove(0);
        assert_eq!(w.select().changes, [Change::Filled(pid(0x13))]);
    }

    #[test]
    fn never_drop_the_only_candidate_and_say_kept() {
        // The only relay offered stopped answering: kept, and said so.
        let mut w = World::new(vec![offer(0x11, 1, 1)], vec![lost(0x11, HOUR)]).picked_now();
        let d = w.select();
        assert_eq!(held(&d), [pid(0x11)]);
        assert_eq!(d.changes, [Change::Kept(pid(0x11))]);
        assert!(!commit(&mut w.mem, &d, NOW));
        assert_eq!(w.mem.memo(&pid(0x11)).replaced_at_ms, 0);
        // Every other relay offered is held by the other slot: kept too.
        w.offers.push(offer(0x12, 2, 2));
        w.slots.push(holding(0x12));
        let d = w.select();
        assert_eq!(held(&d), [pid(0x11), pid(0x12)]);
        assert_eq!(d.changes, [Change::Kept(pid(0x11))]);
        // A pick that never reserved, with nothing to take its place.
        let w = World::new(vec![offer(0x11, 1, 1)], vec![untried(0x11, HOUR)]);
        let d = w.select();
        assert_eq!(held(&d), [pid(0x11)]);
        assert_eq!(d.changes, [Change::Kept(pid(0x11))]);
    }

    #[test]
    fn a_never_reserved_pick_fails_probation_after_two_minutes() {
        let offers = vec![offer(0x11, 1, 1), offer(0x12, 2, 2), offer(0x13, 3, 3)];
        let mut w =
            World::new(offers, vec![untried(0x11, PROBATION_MS - 1), holding(0x12)]).picked_now();
        // A change a minute ago does not hold it: a relay that never
        // reserved is an empty slot that was tried.
        w.mem.last_change_ms = NOW - MIN;
        assert!(w.select().changes.is_empty());
        w.slots[0] = untried(0x11, PROBATION_MS);
        let d = w.select();
        assert_eq!(d.changes, [replaced(0x11, 0x13, LossWhy::NeverReserved)]);
        assert_eq!(held(&d), [pid(0x13), pid(0x12)]);
        assert!(commit(&mut w.mem, &d, NOW));
        let memo = w.mem.memo(&pid(0x11));
        assert_eq!(
            (memo.probation_failed_at_ms, memo.replaced_at_ms),
            (NOW, NOW)
        );
        // Offline, no pick fails probation.
        w.online = false;
        w.slots[0] = untried(0x11, HOUR);
        assert!(w.select().changes.is_empty());

        // A relay that failed probation within the hour ranks below one
        // that did not, however good it looks otherwise.
        let mut failed = offer(0x11, 1, 1);
        failed.confirmed = true;
        let mut w = World::new(vec![failed, offer(0x12, 2, 2), offer(0x13, 3, 3)], vec![]);
        note_probation_failed(&mut w.mem, &pid(0x11), NOW - 59 * MIN);
        let d = w.select();
        assert_eq!(d.changes.len(), 2, "{d:?}");
        assert!(!held(&d).contains(&pid(0x11)), "{d:?}");
        w.now = NOW + MIN;
        assert!(held(&w.select()).contains(&pid(0x11)), "an hour later");
        // A reservation accepted ends it.
        w.now = NOW;
        note_ok(&mut w.mem, &pid(0x11), NOW - MIN);
        assert!(held(&w.select()).contains(&pid(0x11)));
    }

    #[test]
    fn offer_withdrawn_operator_unpinned_or_not_member_drops_at_once() {
        // Both slots hold their reservations, and the last change was a
        // minute ago: drops do not wait, and the empty slot fills at once.
        let base = || {
            let mut w = World::new(
                vec![offer(0x11, 1, 1), offer(0x12, 2, 2), offer(0x13, 3, 3)],
                vec![holding(0x11), holding(0x12)],
            )
            .picked_now();
            w.mem.last_change_ms = NOW - MIN;
            w
        };
        let fill = Change::Filled(pid(0x13));

        let mut w = base();
        w.offers.remove(0);
        let d = w.select();
        assert_eq!(
            d.changes,
            [dropped(0x11, DropWhy::OfferWithdrawn), fill.clone()]
        );
        assert_eq!(held(&d), [pid(0x12), pid(0x13)]);

        let mut w = base();
        w.offers[0].operator = Operator::Unverified;
        assert_eq!(
            w.select().changes,
            [dropped(0x11, DropWhy::OperatorGone), fill.clone()]
        );

        // This node now hides its IP from that operator (D4).
        let mut w = base();
        w.offers[0].operator = Operator::IpHidden;
        assert_eq!(
            w.select().changes,
            [dropped(0x11, DropWhy::IpHidden), fill.clone()]
        );

        // It closed our reservation at once as a non-member while offered:
        // dropped, and skipped for ten minutes.
        let mut w = base();
        w.slots[0] = lost(0x11, S);
        note_not_member(&mut w.mem, &pid(0x11), true, NOW);
        assert_eq!(
            w.select().changes,
            [dropped(0x11, DropWhy::NotMember), fill.clone()]
        );
        w.slots = vec![holding(0x12)];
        w.offers.truncate(2);
        w.now = NOW + NOT_MEMBER_OFFERED_MS - 1;
        let d = w.select();
        assert!(d.changes.is_empty(), "{d:?}");
        assert_eq!(held(&d), [pid(0x12)]);
        w.now = NOW + NOT_MEMBER_OFFERED_MS;
        assert_eq!(w.select().changes, [Change::Filled(pid(0x11))]);

        // One nobody offered: six hours. An accepted reservation ends it.
        let mut mem = RelayMemory::default();
        let r = pid(0x31);
        note_not_member(&mut mem, &r, false, NOW);
        assert!(mem.is_not_member(&r, NOW + NOT_MEMBER_OTHER_MS - 1));
        assert!(!mem.is_not_member(&r, NOW + NOT_MEMBER_OTHER_MS));
        note_ok(&mut mem, &r, NOW + S);
        assert!(!mem.is_not_member(&r, NOW + S));
        // A window longer than the longest one means the clock went back.
        mem.entry(&r).not_member_until_ms = NOW + NOT_MEMBER_OTHER_MS + HOUR;
        assert!(!mem.is_not_member(&r, NOW));
        // A contact naming it again after the refusal ends the skip; a name
        // from before does not. A circuit through it ends it too.
        note_not_member(&mut mem, &r, true, NOW);
        assert_eq!(mem.memo(&r).not_member_at_ms, NOW);
        assert!(!named_again(&mut mem, &r, NOW));
        assert!(mem.is_not_member(&r, NOW + S));
        assert!(named_again(&mut mem, &r, NOW + 1));
        assert!(!mem.is_not_member(&r, NOW + S));
        assert!(!named_again(&mut mem, &r, NOW + 2), "nothing to end");
        note_not_member(&mut mem, &r, false, NOW);
        assert!(clear_not_member(&mut mem, &r));
        assert!(!mem.is_not_member(&r, NOW + S));
        assert!(!clear_not_member(&mut mem, &pid(0x32)), "never noted");
        assert!(!mem.relays.contains_key(&pid(0x32)));

        // The reasons as raven-node logs them.
        assert_eq!(DropWhy::OfferWithdrawn.as_str(), "offer withdrawn");
        assert_eq!(
            DropWhy::OperatorGone.as_str(),
            "its operator is no longer a verified contact"
        );
        assert_eq!(DropWhy::NotMember.as_str(), "it does not admit this node");
    }

    #[test]
    fn at_most_one_change_per_gap_but_empty_slots_fill_at_once() {
        let mut first = offer(0x13, 3, 3);
        first.confirmed = true;
        let offers = vec![
            offer(0x11, 1, 1),
            offer(0x12, 2, 2),
            first,
            offer(0x14, 4, 4),
        ];
        // A change just under a gap ago: the lost relay waits, the empty
        // slot fills at once.
        let mut w = World::new(offers.clone(), vec![lost(0x11, HOUR)]).picked_now();
        w.mem.last_change_ms = NOW - (MIN_GAP_MS - 1);
        let d = w.select();
        assert_eq!(d.changes, [Change::Filled(pid(0x13))]);
        assert_eq!(held(&d), [pid(0x11), pid(0x13)]);

        // A gap ago, both relays lost: one is replaced now ...
        let mut w = World::new(offers, vec![lost(0x11, HOUR), lost(0x12, HOUR)]).picked_now();
        w.mem.last_change_ms = NOW - MIN_GAP_MS;
        let d = w.select();
        assert_eq!(d.changes, [replaced(0x11, 0x13, LossWhy::NotAnswering)]);
        assert_eq!(held(&d), [pid(0x13), pid(0x12)]);
        assert!(commit(&mut w.mem, &d, NOW));
        // ... and the other a gap later.
        w.slots = vec![holding(0x13), lost(0x12, HOUR)];
        w.now = NOW + 10 * S;
        assert!(w.select().changes.is_empty());
        w.now = NOW + MIN_GAP_MS - 1;
        assert!(w.select().changes.is_empty());
        w.now = NOW + MIN_GAP_MS;
        let d = w.select();
        assert_eq!(d.changes, [replaced(0x12, 0x14, LossWhy::NotAnswering)]);
        assert_eq!(held(&d), [pid(0x13), pid(0x14)]);
    }

    #[test]
    fn swap_back_is_held_for_the_cooldown() {
        // R13 replaced R11 15 minutes ago, then stopped answering too.
        let replaced_at = NOW - 15 * MIN;
        let mut w = World::new(
            vec![offer(0x11, 1, 1), offer(0x12, 2, 2), offer(0x13, 3, 3)],
            vec![lost(0x13, 10 * MIN), holding(0x12)],
        )
        .picked_now();
        w.mem.entry(&pid(0x11)).replaced_at_ms = replaced_at;
        w.mem.last_change_ms = replaced_at;
        // R11 is not taken back within the cooldown: R13 is kept.
        assert_eq!(w.select().changes, [Change::Kept(pid(0x13))]);
        // Another offered relay takes the slot.
        w.offers.push(offer(0x14, 4, 4));
        assert_eq!(
            w.select().changes,
            [replaced(0x13, 0x14, LossWhy::NotAnswering)]
        );
        w.offers.pop();
        // After the cooldown R11 may come back.
        w.now = replaced_at + SWAP_BACK_COOLDOWN_MS - 1;
        assert_eq!(w.select().changes, [Change::Kept(pid(0x13))]);
        w.now = replaced_at + SWAP_BACK_COOLDOWN_MS;
        assert_eq!(
            w.select().changes,
            [replaced(0x13, 0x11, LossWhy::NotAnswering)]
        );

        // An empty slot is no swap back: within the cooldown it may take
        // R11, as the last choice.
        w.now = NOW;
        w.slots = vec![holding(0x12)];
        w.offers = vec![offer(0x11, 1, 1), offer(0x12, 2, 2)];
        assert_eq!(w.select().changes, [Change::Filled(pid(0x11))]);
        w.offers.push(offer(0x14, 4, 4));
        assert_eq!(w.select().changes, [Change::Filled(pid(0x14))]);
    }

    #[test]
    fn manual_relays_are_authoritative_and_auto_off_keeps_only_manual() {
        let offers = vec![offer(0x11, 1, 1), offer(0x12, 2, 2)];
        // Two relays set by hand take both slots: the automatic one goes.
        let mut w = World::new(
            offers.clone(),
            vec![manual_slot(0x21), manual_slot(0x22), holding(0x11)],
        );
        w.manual = vec![manual(0x21, 7423), manual(0x21, 443), manual(0x22, 7423)];
        let d = w.select();
        assert_eq!(
            d.relays,
            [
                (manual(0x21, 7423), Source::Manual),
                (manual(0x22, 7423), Source::Manual)
            ]
        );
        assert_eq!(d.changes, [dropped(0x11, DropWhy::ManualFirst)]);

        // One relay set by hand at two addresses is one relay.
        w.manual = vec![manual(0x21, 7423), manual(0x21, 443)];
        w.slots = vec![manual_slot(0x21), holding(0x11)];
        let d = w.select();
        assert_eq!(held(&d), [pid(0x21), pid(0x11)]);
        assert_eq!(d.relays[1].1, offers[0].source);
        assert!(d.changes.is_empty(), "{d:?}");

        // A relay set by hand that a contact offers too is the manual one,
        // never held twice.
        w.offers = vec![offer(0x21, 3, 3), offers[0].clone()];
        w.slots = vec![manual_slot(0x21)];
        let d = w.select();
        assert_eq!(held(&d), [pid(0x21), pid(0x11)]);
        assert_eq!(d.changes, [Change::Filled(pid(0x11))]);

        // Automatic choice off: only the relays set by hand.
        w.auto = false;
        w.offers = offers;
        w.slots = vec![manual_slot(0x21), holding(0x11)];
        w.mem.selected = vec![pid(0x11)];
        let d = w.select();
        assert_eq!(d.relays, [(manual(0x21, 7423), Source::Manual)]);
        assert_eq!(d.changes, [dropped(0x11, DropWhy::AutoOff)]);
        assert!(commit(&mut w.mem, &d, NOW));
        assert!(w.mem.selected.is_empty());
        // Nothing is filled either.
        w.slots = vec![manual_slot(0x21)];
        let d = w.select();
        assert_eq!(held(&d), [pid(0x21)]);
        assert!(d.changes.is_empty(), "{d:?}");
        assert_eq!(DropWhy::AutoOff.as_str(), "automatic relay choice is off");
    }

    #[test]
    fn diversity_prefers_another_operator_and_netgroup() {
        // R11 (operator 1, network 1) is held; the other slot is empty.
        let fill = |standby: Vec<Candidate>| {
            let mut offers = vec![offer(0x11, 1, 1)];
            offers.extend(standby);
            let d = World::new(offers, vec![holding(0x11)]).select();
            assert_eq!(d.changes.len(), 1, "{d:?}");
            held(&d)[1].clone()
        };
        // Another operator on another network beats either alone.
        assert_eq!(
            fill(vec![
                offer(0x12, 1, 2),
                offer(0x13, 2, 1),
                offer(0x14, 2, 2)
            ]),
            pid(0x14)
        );
        // Another operator beats the same one (both on new networks) ...
        assert_eq!(fill(vec![offer(0x12, 1, 2), offer(0x15, 3, 3)]), pid(0x15));
        assert_eq!(fill(vec![offer(0x15, 3, 3), offer(0x12, 1, 2)]), pid(0x15));
        // ... and another network the same one (both from a new operator).
        assert_eq!(fill(vec![offer(0x13, 2, 1), offer(0x16, 2, 4)]), pid(0x16));
        assert_eq!(fill(vec![offer(0x16, 2, 4), offer(0x13, 2, 1)]), pid(0x16));

        // A relay set by hand holds its network too.
        let mut w = World::new(
            vec![offer(0x17, 4, 200), offer(0x18, 4, 5)],
            vec![manual_slot(0x21)],
        );
        w.manual = vec![manual(0x21, 7423)];
        assert_eq!(w.select().changes, [Change::Filled(pid(0x18))]);
    }

    #[test]
    fn availability_ewma_decays_with_half_life_and_clamps_clock_jumps() {
        let r = pid(0x11);
        let near = |got: u32, want: u32| {
            assert!(got.abs_diff(want) <= AVAIL_ONE / 1000, "{got} != {want}");
        };
        let mut mem = RelayMemory::default();
        // Never sampled: the prior, higher for a CONFIRMED offer.
        assert_eq!(avail_now(mem.memo(&r), false), AVAIL_ONE / 2);
        assert_eq!(avail_now(mem.memo(&r), true), AVAIL_ONE / 5 * 4);
        // The first sample starts there.
        observe(&mut mem, &r, false, false, NOW);
        assert_eq!(mem.memo(&r).avail_ppb, AVAIL_ONE / 2);
        // One half-life of 10 s samples without a reservation halves it ...
        let mut t = NOW;
        let mut sample = |mem: &mut RelayMemory, active: bool| {
            let end = t + AVAIL_HALF_LIFE_MS;
            while t < end {
                t += 10 * S;
                observe(mem, &r, active, false, t);
            }
            t
        };
        sample(&mut mem, false);
        near(mem.memo(&r).avail_ppb, AVAIL_ONE / 4);
        // ... and one with it takes it half the way back to 1.
        let t = sample(&mut mem, true);
        near(mem.memo(&r).avail_ppb, AVAIL_ONE / 8 * 5);

        // A wall-clock jump of three days counts as ten minutes ...
        let before = mem.memo(&r).avail_ppb;
        let t = t + AVAIL_HALF_LIFE_MS;
        observe(&mut mem, &r, false, false, t);
        let keep = (-(MAX_SAMPLE_MS as f64) / AVAIL_HALF_LIFE_MS as f64).exp2();
        assert_eq!(
            mem.memo(&r).avail_ppb,
            (f64::from(before) * keep).round() as u32
        );
        assert!(mem.memo(&r).avail_ppb > before / 100 * 99);
        // ... and a clock that went back counts nothing; the next sample is
        // measured from the new reading.
        let before = mem.memo(&r).avail_ppb;
        observe(&mut mem, &r, true, false, t - 24 * HOUR);
        assert_eq!(mem.memo(&r).avail_ppb, before);
        assert_eq!(mem.memo(&r).avail_at_ms, t - 24 * HOUR);

        // A standby that always held our reservation beats one never
        // sampled, and one that never did loses to it.
        let mut w = World::new(
            vec![offer(0x11, 1, 1), offer(0x12, 2, 2), offer(0x13, 3, 3)],
            vec![holding(0x11)],
        );
        for (seed, avail_ppb) in [(0x12, AVAIL_ONE), (0x13, 0)] {
            w.mem.relays.insert(
                pid(seed),
                RelayMemo {
                    avail_ppb,
                    avail_at_ms: NOW - 2 * 24 * HOUR,
                    ..RelayMemo::default()
                },
            );
        }
        assert_eq!(w.select().changes, [Change::Filled(pid(0x12))]);
        w.offers.remove(1);
        w.offers.push(offer(0x14, 4, 4));
        assert_eq!(w.select().changes, [Change::Filled(pid(0x14))]);
    }

    #[test]
    fn tie_break_is_deterministic_per_node() {
        // Two relays alike but for their keys.
        let (a, b) = (offer(0x11, 1, 1), offer(0x12, 2, 2));
        let mut picks = HashSet::new();
        for n in 0..32u8 {
            let me = pid(0x80 + n);
            let pick = |offers: &[Candidate]| {
                let d = select(&Input {
                    me: &me,
                    manual: &[],
                    offers,
                    slots: &[],
                    mem: &RelayMemory::default(),
                    online: true,
                    auto: true,
                    now_ms: NOW,
                    max: 1,
                    t: Timing::default(),
                    learned: &[],
                });
                held(&d)
            };
            let first = pick(&[a.clone(), b.clone()]);
            assert_eq!(first.len(), 1);
            assert_eq!(pick(&[b.clone(), a.clone()]), first, "in any order");
            assert_eq!(pick(&[a.clone(), b.clone()]), first, "every time");
            picks.insert(first[0].clone());
        }
        assert_eq!(picks.len(), 2, "a circle spreads over equal relays");
    }

    #[test]
    fn an_expired_offer_stays_while_its_slot_is_reserved() {
        // R11's offer came in a snapshot that has expired (a tombstone's).
        let mut tombstone = offer(0x11, 1, 1);
        tombstone.expires_at_ms = NOW - HOUR;
        let mut w = World::new(
            vec![tombstone, offer(0x12, 2, 2), offer(0x13, 3, 3)],
            vec![holding(0x11), holding(0x12)],
        )
        .picked_now();
        w.mem.last_change_ms = NOW - MIN;
        // Its reservation outlives the offer: the relay's acceptance is its
        // operator's live consent.
        let d = w.select();
        assert_eq!(held(&d), [pid(0x11), pid(0x12)]);
        assert!(d.changes.is_empty(), "{d:?}");
        // Once the reservation is lost it goes at once, without the ten
        // minutes and the gap.
        w.slots[0] = lost(0x11, S);
        let d = w.select();
        assert_eq!(
            d.changes,
            [
                dropped(0x11, DropWhy::OfferWithdrawn),
                Change::Filled(pid(0x13))
            ]
        );
        assert_eq!(held(&d), [pid(0x12), pid(0x13)]);
        // An expired offer never takes a slot.
        w.slots = vec![holding(0x12)];
        w.offers.truncate(2);
        let d = w.select();
        assert_eq!(held(&d), [pid(0x12)]);
        assert!(d.changes.is_empty(), "{d:?}");
    }

    #[test]
    fn memory_round_trips_bounded_and_corrupt_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        assert_eq!(load_memory(dd), RelayMemory::default(), "no file");

        let mut mem = RelayMemory::default();
        note_ok(&mut mem, &pid(0x11), NOW);
        observe(&mut mem, &pid(0x11), true, true, NOW);
        note_not_member(&mut mem, &pid(0x12), false, NOW);
        let d = Decision {
            relays: vec![(offer(0x11, 1, 1).via, offer(0x11, 1, 1).source)],
            changes: vec![replaced(0x13, 0x11, LossWhy::NeverReserved)],
        };
        assert!(commit(&mut mem, &d, NOW));
        save_memory(dd, &mem).unwrap();
        assert_eq!(load_memory(dd), mem);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dd.join(RELAY_MEMORY_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let raw = std::fs::read_to_string(dd.join(RELAY_MEMORY_FILE)).unwrap();
        assert!(!raw.contains("/ip4/") && !raw.contains(&op(1)), "{raw}");

        // Bounded: the picked relays, then the most recently used.
        let mut mem = RelayMemory {
            selected: vec![pid(0x40), pid(0x41)],
            ..RelayMemory::default()
        };
        for n in 0..40u8 {
            note_ok(&mut mem, &pid(0x40 + n), NOW + u64::from(n));
        }
        assert_eq!(mem.relays.len(), MAX_REMEMBERED);
        for n in 0..40u8 {
            let kept = !(2..10).contains(&n);
            assert_eq!(mem.relays.contains_key(&pid(0x40 + n)), kept, "{n}");
        }
        save_memory(dd, &mem).unwrap();
        assert_eq!(load_memory(dd), mem);

        // A file written by hand is checked and bounded on read.
        let mut big = RelayMemory::default();
        for n in 0..40u8 {
            let memo = RelayMemo {
                last_ok_ms: NOW + u64::from(n),
                ..RelayMemo::default()
            };
            big.relays.insert(pid(0x40 + n), memo);
        }
        big.relays.get_mut(&pid(0x67)).unwrap().avail_ppb = u32::MAX;
        big.relays
            .insert("12D3KooWnot-a-peer-id".into(), RelayMemo::default());
        big.selected = vec![pid(0x40), pid(0x40), pid(0x41), pid(0x42), "x".into()];
        std::fs::write(
            dd.join(RELAY_MEMORY_FILE),
            serde_json::to_vec(&big).unwrap(),
        )
        .unwrap();
        let read = load_memory(dd);
        assert_eq!(read.selected, [pid(0x40), pid(0x41)]);
        assert_eq!(read.relays.len(), MAX_REMEMBERED);
        assert!(read.relays.contains_key(&pid(0x40)) && read.relays.contains_key(&pid(0x41)));
        assert!(!read.relays.contains_key("12D3KooWnot-a-peer-id"));
        assert_eq!(read.memo(&pid(0x67)).avail_ppb, AVAIL_ONE);

        // Corrupt, not an object, or another version: an empty memory.
        for bad in [
            &b"{not json"[..],
            b"",
            b"[]",
            br#"{"selected":[]}"#,
            br#"{"version":2,"selected":[],"relays":{}}"#,
        ] {
            std::fs::write(dd.join(RELAY_MEMORY_FILE), bad).unwrap();
            assert_eq!(
                load_memory(dd),
                RelayMemory::default(),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
        // An older or partial memo reads its missing times as never.
        std::fs::write(
            dd.join(RELAY_MEMORY_FILE),
            format!(
                r#"{{"version":1,"relays":{{"{}":{{"last_ok_ms":5}}}}}}"#,
                pid(0x11)
            ),
        )
        .unwrap();
        let read = load_memory(dd);
        assert_eq!(read.memo(&pid(0x11)).last_ok_ms, 5);
        assert_eq!(read.memo(&pid(0x11)).avail_at_ms, 0);
    }

    #[test]
    fn candidates_come_from_offers_without_our_own_relays() {
        let stored = |seed: u8, addrs: &[&str], flags: u8| StoredOffer {
            relay_peer_id: pid(seed),
            addrs: addrs.iter().map(|a| a.to_string()).collect(),
            flags,
        };
        let offers = vec![
            (
                op(1),
                pid(0x51),
                stored(
                    0x11,
                    &[
                        "/dns/relay.example.org/tcp/7427",
                        "/ip4/11.1.0.17/tcp/7427",
                        "/ip4/11.1.0.17/udp/7427/quic-v1",
                    ],
                    FLAG_CONFIRMED | FLAG_AUTONAT,
                ),
                NOW + HOUR,
            ),
            // A tombstone's: no PeerId, a past expiry.
            (
                op(2),
                String::new(),
                stored(0x12, &["/ip6/2606:4700:10::1/tcp/443"], FLAG_AUTONAT),
                NOW - HOUR,
            ),
            // The same relay key from another contact, at its own address:
            // disputed.
            (
                op(3),
                pid(0x53),
                stored(0x11, &["/ip4/11.9.0.1/tcp/7427"], 0),
                NOW + HOUR,
            ),
            // Under its operator's own PeerId, this node's, or our own
            // friend relay's; one with no address left.
            (
                op(4),
                pid(0x54),
                stored(0x54, &["/ip4/11.4.0.1/tcp/7427"], 0),
                NOW + HOUR,
            ),
            (
                op(4),
                pid(0x54),
                stored(0x01, &["/ip4/11.4.0.2/tcp/7427"], 0),
                NOW + HOUR,
            ),
            (
                op(5),
                pid(0x55),
                stored(0x02, &["/ip4/11.5.0.1/tcp/7427"], 0),
                NOW + HOUR,
            ),
            (op(6), pid(0x56), stored(0x16, &["garbage"], 0), NOW + HOUR),
        ];
        let standing = |_: &str| Operator::Verified;
        let c = candidates(&offers, standing, &[&me(), &pid(0x02)]);
        assert_eq!(c.len(), 2, "{c:?}");
        assert_eq!(
            c[0].via.text,
            format!("/dns/relay.example.org/tcp/7427/p2p/{}", pid(0x11))
        );
        assert_eq!(c[0].addrs.len(), 3);
        assert_eq!(c[0].addrs[0], c[0].via.text);
        assert_eq!(c[0].group.as_deref(), Some("11.1.0.0/24"), "its first IP");
        assert!(c[0].confirmed);
        assert_eq!(
            c[0].source,
            Source::Offer {
                operator_pub_hex: op(1)
            }
        );
        // Two verified contacts offer one relay key: never used, and its
        // addresses are the first offer's, never the other's.
        assert_eq!(c[0].operator, Operator::Disputed, "two operators");
        assert!(!c[0].addrs.iter().any(|a| a.contains("11.9.0.1")));
        assert_eq!(c[1].via.peer_id, pid(0x12));
        assert_eq!(c[1].group.as_deref(), Some("2606:4700:10::/48"));
        assert!(!c[1].confirmed);
        assert_eq!(c[1].expires_at_ms, NOW - HOUR);
        assert_eq!(c[1].operator, Operator::Verified);
        assert_eq!(
            worst(Operator::Unverified, Operator::IpHidden),
            Operator::Unverified
        );
        // Alone, each operator's offer is its own.
        let c = candidates(&offers[..1], standing, &[&me()]);
        assert_eq!(c[0].operator, Operator::Verified);
        let c = candidates(&offers[2..3], standing, &[&me()]);
        assert_eq!(c[0].operator, Operator::Verified);
        assert_eq!(
            c[0].addrs,
            [format!("/ip4/11.9.0.1/tcp/7427/p2p/{}", pid(0x11))]
        );
        // A contact's own p2p PeerId (in `own`) is never a relay.
        let c = candidates(&offers[2..3], standing, &[&me(), &pid(0x11)]);
        assert!(c.is_empty(), "{c:?}");
    }

    /// A relay key a second contact offers too is dropped from its slot at
    /// once and never picked: nothing tells which operator its traffic
    /// reaches (a contact re-offering another's relay at its own addresses).
    #[test]
    fn a_relay_key_offered_by_two_contacts_is_not_used() {
        let mut disputed = offer(0x11, 1, 1);
        disputed.operator = Operator::Disputed;
        let mut w = World::new(
            vec![disputed, offer(0x12, 2, 2), offer(0x13, 3, 3)],
            vec![holding(0x11), holding(0x12)],
        )
        .picked_now();
        let d = w.select();
        assert_eq!(
            d.changes,
            [dropped(0x11, DropWhy::Disputed), Change::Filled(pid(0x13))]
        );
        w.slots = vec![holding(0x12)];
        assert_eq!(w.standby(), 1, "only 0x13");
        assert_eq!(
            DropWhy::Disputed.as_str(),
            "two contacts offer it under one key"
        );
    }

    #[test]
    fn timers_are_the_constants_unless_the_lab_switch_says_otherwise() {
        // Owner decision: the hysteresis constants.
        assert_eq!(
            (
                REPLACE_AFTER_MS,
                PROBATION_MS,
                MIN_GAP_MS,
                SWAP_BACK_COOLDOWN_MS
            ),
            (10 * MIN, 2 * MIN, 5 * MIN, 30 * MIN)
        );
        assert_eq!(
            (
                NOT_MEMBER_OFFERED_MS,
                NOT_MEMBER_OTHER_MS,
                AVAIL_HALF_LIFE_MS
            ),
            (10 * MIN, 6 * HOUR, 72 * HOUR)
        );
        assert_eq!(
            Timing::default(),
            Timing {
                replace_after_ms: REPLACE_AFTER_MS,
                probation_ms: PROBATION_MS,
                min_gap_ms: MIN_GAP_MS,
            }
        );
        assert_eq!(Timing::from_lab(None), Timing::default());
        assert_eq!(
            Timing::from_lab(Some((6, 4, 2))),
            Timing {
                replace_after_ms: 6 * S,
                probation_ms: 4 * S,
                min_gap_ms: 2 * S,
            }
        );
        // This process: the switch as p2p_gate reads it (never in release).
        assert_eq!(
            Timing::current(),
            Timing::from_lab(crate::p2p_gate::lab_relay_select())
        );
    }

    #[test]
    fn net_group_is_the_reachability_checks_rule() {
        for addr in [
            "/ip4/127.0.0.1/tcp/7427",
            "/ip4/10.1.2.3/tcp/7427",
            "/ip4/192.168.1.2/udp/7427/quic-v1",
            "/ip4/100.64.0.1/tcp/7427",
            "/ip4/203.0.113.7/tcp/7427",
            "/ip6/::1/tcp/7427",
            "/ip6/fd00::1/tcp/7427",
            "/ip6/2001:db8::1/tcp/7427",
            "/ip6/::ffff:192.168.1.1/tcp/7427",
            "/dns/relay.example.org/tcp/7427",
            "/dns4/11.1.0.1/tcp/7427",
            "ip4/11.1.0.1/tcp/7427",
            "/ip4/11.1.0/tcp/7427",
            "",
            "garbage",
        ] {
            assert_eq!(net_group(addr), None, "{addr}");
        }
        let g = |a: &str| net_group(a).unwrap();
        assert_eq!(g("/ip4/11.1.0.1/tcp/7427"), "11.1.0.0/24");
        assert_eq!(
            g("/ip4/11.1.0.1/tcp/7427"),
            g(&format!(
                "/ip4/11.1.0.200/udp/7427/quic-v1/p2p/{}",
                pid(0x11)
            ))
        );
        assert_ne!(g("/ip4/11.1.0.1/tcp/7427"), g("/ip4/11.1.1.1/tcp/7427"));
        assert_eq!(g("/ip6/2606:4700:10::1/tcp/443"), "2606:4700:10::/48");
        assert_eq!(
            g("/ip6/2606:4700:10::1/tcp/443"),
            g("/ip6/2606:4700:10:ffff::2/tcp/7427")
        );
        assert_ne!(
            g("/ip6/2606:4700:10::1/tcp/443"),
            g("/ip6/2606:4700:11::1/tcp/443")
        );
        // An IPv6 address carrying an IPv4 one is that IPv4 network.
        for carried in [
            "/ip6/::ffff:11.1.0.9/tcp/7427",
            "/ip6/64:ff9b::b01:1/tcp/7427",
            "/ip6/2002:b01:1::1/tcp/7427",
        ] {
            assert_eq!(g(carried), "11.1.0.0/24", "{carried}");
        }
    }

    // ── Learning connectivity's relay term (Phase 6a, P6.15) ──────────────

    /// The worlds of the relay term tests: healthy slots, a slot lost or
    /// untried for less than its timer, offline, within the gap, and the
    /// fill and replacement cases.
    fn term_worlds() -> Vec<World> {
        let offers = || {
            vec![
                offer(0x11, 1, 1),
                offer(0x12, 2, 2),
                offer(0x13, 3, 3),
                offer(0x14, 4, 4),
            ]
        };
        let mut gap = World::new(offers(), vec![lost(0x11, HOUR), holding(0x12)]).picked_now();
        gap.mem.last_change_ms = NOW - (MIN_GAP_MS - 1);
        let mut offline =
            World::new(offers(), vec![lost(0x11, HOUR), lost(0x12, HOUR)]).picked_now();
        offline.online = false;
        vec![
            World::new(offers(), vec![holding(0x11), holding(0x12)]).picked_now(),
            World::new(
                offers(),
                vec![lost(0x11, REPLACE_AFTER_MS - 1), holding(0x12)],
            )
            .picked_now(),
            World::new(
                offers(),
                vec![untried(0x11, PROBATION_MS - 1), holding(0x12)],
            )
            .picked_now(),
            gap,
            offline,
            World::new(offers(), vec![holding(0x11)]).picked_now(),
            World::new(offers(), Vec::new()),
            World::new(offers(), vec![lost(0x11, HOUR), holding(0x12)]).picked_now(),
            World::new(offers(), vec![untried(0x11, PROBATION_MS), holding(0x12)]).picked_now(),
        ]
    }

    /// The term only picks among the relays that may take a slot: with
    /// healthy slots, a loss or a probation shorter than its timer, this
    /// node offline or a change within the gap, the largest terms (out of
    /// range ones included) change nothing.
    #[test]
    fn a_learned_term_never_starts_a_change() {
        for (n, mut w) in term_worlds().into_iter().take(5).enumerate() {
            let today = w.select();
            assert!(today.changes.is_empty(), "world {n}: {today:?}");
            for (good, bad) in [(150, -150), (i64::MAX, i64::MIN)] {
                w.learn(0x13, good);
                w.learn(0x14, good);
                w.learn(0x11, bad);
                w.learn(0x12, bad);
                assert_eq!(w.select(), today, "world {n}, {good}");
                assert_eq!(w.standby(), 2, "world {n}");
            }
        }
    }

    /// A relay in its failed-probation back-off (-1000) or replaced within
    /// the cooldown (-400) does not win a fill with the largest term, and
    /// takes no replacement at all.
    #[test]
    fn a_learned_term_cannot_beat_probation_or_cooldown() {
        let offers = vec![offer(0x11, 1, 1), offer(0x12, 2, 2), offer(0x13, 3, 3)];
        for backed_off in [false, true] {
            let mut w = World::new(offers.clone(), vec![holding(0x11)]).picked_now();
            if backed_off {
                let m = w.mem.entry(&pid(0x12));
                m.probation_failed_at_ms = NOW - MIN;
                m.probation_fails = 1;
            } else {
                w.mem.entry(&pid(0x12)).replaced_at_ms = NOW - MIN;
            }
            // Without terms the fresh relay fills the slot ...
            assert_eq!(w.select().changes, [Change::Filled(pid(0x13))]);
            // ... and still does when the other has the best term there is
            // and it the worst (an out-of-range term is clamped).
            for (good, bad) in [(150, -150), (i64::MAX, i64::MIN)] {
                w.learn(0x12, good);
                w.learn(0x13, bad);
                assert_eq!(
                    w.select().changes,
                    [Change::Filled(pid(0x13))],
                    "back-off {backed_off}, {good}"
                );
            }
            // A slot due for replacement: never by that relay, whatever its
            // term; the fresh one takes it.
            w.offers.push(offer(0x14, 4, 4));
            w.slots = vec![lost(0x11, HOUR), holding(0x14)];
            assert_eq!(
                w.select().changes,
                [replaced(0x11, 0x13, LossWhy::NotAnswering)],
                "back-off {backed_off}"
            );
            w.offers.retain(|c| c.via.peer_id != pid(0x13));
            assert_eq!(
                w.select().changes,
                [Change::Kept(pid(0x11))],
                "back-off {backed_off}"
            );
        }
    }

    /// Among relays alike but for their keys, the higher term fills a slot
    /// (and takes a replacement already due); a stronger reason (a recent
    /// success, +300) still beats the largest term.
    #[test]
    fn fills_prefer_the_higher_term_among_equals() {
        let offers = vec![offer(0x10, 0, 0), offer(0x11, 1, 1), offer(0x12, 2, 2)];
        let filled = |w: &World| match w.select().changes.as_slice() {
            [Change::Filled(p)] => p.clone(),
            other => panic!("{other:?}"),
        };
        let mut w = World::new(offers.clone(), vec![holding(0x10)]).picked_now();
        let by_tie = filled(&w);
        let (winner, loser) = if by_tie == pid(0x11) {
            (0x11, 0x12)
        } else {
            (0x12, 0x11)
        };
        // A term larger than any tie-break (0..9) decides it.
        w.learn(loser, 10);
        assert_eq!(filled(&w), pid(loser));
        w.learned.clear();
        w.learn(winner, -10);
        assert_eq!(filled(&w), pid(loser));
        w.learn(loser, -20);
        assert_eq!(filled(&w), pid(winner), "the higher of two negatives");
        // A recent success outweighs it.
        w.learned.clear();
        w.learn(loser, 150);
        note_ok(&mut w.mem, &pid(winner), NOW - MIN);
        assert_eq!(filled(&w), pid(winner));

        // A replacement already due goes to the higher term too.
        let mut w = World::new(offers, vec![lost(0x10, HOUR), holding(0x13)]).picked_now();
        w.offers.push(offer(0x13, 3, 3));
        assert_eq!(
            w.select().changes,
            [replaced(0x10, winner, LossWhy::NotAnswering)]
        );
        w.learn(loser, 10);
        assert_eq!(
            w.select().changes,
            [replaced(0x10, loser, LossWhy::NotAnswering)]
        );
    }

    /// With no terms (learning off), zero terms, or terms only for relays
    /// nobody offers, every decision is today's (the tables above run with
    /// `learned = &[]`).
    #[test]
    fn empty_learned_is_todays_score() {
        for (n, mut w) in term_worlds().into_iter().enumerate() {
            assert!(w.learned.is_empty());
            let (today, standby, probe) = (w.select(), w.standby(), w.probe());
            for seed in [0x11, 0x12, 0x13, 0x14] {
                w.learn(seed, 0);
            }
            w.learn(0x7f, 150);
            w.learned.push(("not a relay".into(), -150));
            assert_eq!(w.select(), today, "world {n}");
            assert_eq!((w.standby(), w.probe()), (standby, probe), "world {n}");
        }
    }

    /// Status's spare relays: the offers automatic choice could take now,
    /// beside the slots: usable, live and in no slot; none while it is off.
    #[test]
    fn standby_counts_usable_offers_outside_the_slots() {
        let mut gone = offer(0x15, 5, 5);
        gone.operator = Operator::Unverified;
        let mut hidden = offer(0x16, 6, 6);
        hidden.operator = Operator::IpHidden;
        let mut expired = offer(0x17, 7, 7);
        expired.expires_at_ms = NOW - MIN;
        let mut w = World::new(
            vec![
                offer(0x11, 1, 1),
                offer(0x12, 2, 2),
                offer(0x13, 3, 3),
                offer(0x14, 4, 4),
                gone,
                hidden,
                expired,
            ],
            vec![holding(0x11), lost(0x12, MIN)],
        );
        assert_eq!(w.standby(), 2, "0x13 and 0x14");
        note_not_member(&mut w.mem, &pid(0x13), true, NOW);
        assert_eq!(w.standby(), 1);
        w.manual = vec![manual(0x14, 7423)];
        assert_eq!(w.standby(), 0, "a relay set by hand is no spare");
        w.manual.clear();
        w.auto = false;
        assert_eq!(w.standby(), 0);
    }
}
