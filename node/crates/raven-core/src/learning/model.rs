//! The in-memory learning model (design "Phase 6a", data model `Model`):
//! one arm per (contact, network, carrier), relay rows, encounter rows, carry
//! rows, the carrier order last applied per contact-network (the ranker's
//! hysteresis) and the contradiction pins.
//!
//! - [`Model::observe`] applies one [`Observation`] (algorithms §2): a
//!   receipt or a link is a success of its weight and moves `ok_ms` (α 1/4),
//!   while `fail_ms` relaxes 1/8 toward the carrier's static wait; silence
//!   and failures are failures and move `fail_ms`. Round-trip samples come
//!   from the dial's timing only, and a Karn-excluded dial gives no reply
//!   sample. A receipt over a relayed path also counts for that relay
//!   (`learning::relay`, algorithms §6).
//! - Nothing is kept for an observation that is not evidence (E0), whose
//!   network changed during the dial, or for the nearby carrier (it keeps
//!   its static place and is never ranked).
//! - Encounters (when this node last met a contact, and how predictably)
//!   and carry rows (how well a custodian delivered for a recipient) are
//!   the carry choice's (`learning::carry`, algorithms §7).
//! - The contact, the network tag and the relay are kept only as
//!   HMAC-SHA256 keys under the model's secret (`c`/`r` ‖ id → 16 bytes,
//!   `n` ‖ tag → 8 bytes; no tag and an empty tag are the one "none"
//!   bucket); an encounter's or a carry row's contacts are `c` keys too.
//!   `Debug` prints counts only.
//! - Bounded (oldest first): [`MAX_CONTACTS`] contacts with arms,
//!   [`MAX_NETS_PER_CONTACT`] networks per contact (both by last
//!   observation), three ranked carriers, [`MAX_RELAYS`] relays,
//!   [`MAX_ENCOUNTERS`] encounters (by last link) and [`MAX_CARRY_ROWS`]
//!   carry rows (by last update). [`Model::prune`] also drops rows not
//!   updated for [`RETAIN_MS`] (OD6a-8) or with less than [`MIN_EVIDENCE_M`]
//!   of evidence left.
//! - No row has a time-of-day field (a schema test in `learning::carry`).
//!
//! Pure: no I/O and no clock read (`now_ms` comes from `raven_core::clock`
//! at the caller); [`Model::forget_all`] draws a new secret from the OS.
//! The file is `learning::store`'s (LRN1).

use std::collections::{BTreeMap, BTreeSet};

use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::estimate::{
    decay_q16, ewma_ms, Beta, Encounter, Rtt, CARRY_HALF_LIFE_MS, DAY_MS, HALF_LIFE_MS,
};
use super::explain::State;
use super::observe::{Evidence, FrameKind, Observation, Weight, RECEIPT_W_M};
use super::rank::Order;
use super::wait::WaitKind;
use crate::outbox::{DeliveryPath, OutboxCarrier};

/// A contact's or a relay's key in the model.
type Key16 = [u8; 16];
/// A network's key in the model.
type Key8 = [u8; 8];

/// Contacts with arms; the one observed longest ago goes first.
pub const MAX_CONTACTS: usize = 64;
/// Networks per contact; the one observed longest ago goes first.
pub const MAX_NETS_PER_CONTACT: usize = 8;
/// Relay rows; the one updated longest ago goes first.
pub const MAX_RELAYS: usize = 32;
/// Encounter rows; the contact met longest ago goes first.
pub const MAX_ENCOUNTERS: usize = 64;
/// Carry rows (custodian, recipient); the one updated longest ago goes
/// first.
pub const MAX_CARRY_ROWS: usize = 128;
/// A row not updated for this long is dropped (OD6a-8).
pub const RETAIN_MS: u64 = 30 * DAY_MS;
/// A row whose decayed evidence `a + b` falls below this is dropped.
pub const MIN_EVIDENCE_M: u32 = 50;
/// A contact-network whose learned order failed the plan's invariant keeps
/// the static order this long ([`Model::note_contradiction`]).
pub const CONTRADICTION_PIN_MS: u64 = 3_600_000;
/// The tries an arm's [`Arm::tries`] tally covers (the reason's `k/n`).
pub const RECENT_MAX: u8 = 8;

/// `ok_ms` shift: α = 1/4.
const COST_SHIFT: u8 = 2;
/// `fail_ms` relaxes this much (1/8) toward the static wait on a success.
const RELAX_SHIFT: u8 = 3;

/// What a successful dial on `carrier` costs before one is seen (ms).
pub fn ok_prior_ms(carrier: OutboxCarrier) -> u32 {
    match carrier {
        OutboxCarrier::Lan => 300,
        OutboxCarrier::Internet => 1_500,
        OutboxCarrier::P2p | OutboxCarrier::Nearby => 3_000,
        // A Tor rendezvous: first contact is typically 10-30 s (design
        // 2026-10-tor-fallback §3.5); never ranked.
        OutboxCarrier::Onion => 15_000,
    }
}

/// What a failed dial on `carrier` costs before one is seen: the carrier's
/// static connect wait ([`super::wait::statics`]: 5 s per address, p2p
/// 20 s; nearby, never ranked, 12 s).
pub fn fail_prior_ms(carrier: OutboxCarrier) -> u32 {
    let connect = super::wait::statics(carrier).connect;
    u32::try_from(connect.as_millis()).unwrap_or(u32::MAX)
}

/// The carrier's byte in a key and in a remembered order.
pub(super) fn carrier_code(carrier: OutboxCarrier) -> u8 {
    match carrier {
        OutboxCarrier::Lan => 0,
        OutboxCarrier::Internet => 1,
        OutboxCarrier::P2p => 2,
        OutboxCarrier::Nearby => 3,
        OutboxCarrier::Onion => 4,
    }
}

pub(super) fn carrier_of(code: u8) -> Option<OutboxCarrier> {
    [
        OutboxCarrier::Lan,
        OutboxCarrier::Internet,
        OutboxCarrier::P2p,
        OutboxCarrier::Nearby,
        OutboxCarrier::Onion,
    ]
    .into_iter()
    .find(|c| carrier_code(*c) == code)
}

/// What the model knows of one (contact, network, carrier).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Arm {
    /// Success estimate (milli-observations, 1 d half-life, cap 8).
    pub beta: Beta,
    /// EWMA (α 1/4) of the successful dials' totals.
    pub ok_ms: u32,
    /// EWMA (α 1/4) of the failed dials' totals, relaxing 1/8 toward the
    /// static wait on each success.
    pub fail_ms: u32,
    /// Dial start → the peer's offer read.
    pub connect: Rtt,
    /// Frames written → first terminal reply.
    pub reply: Rtt,
    /// Receipts per [`DeliveryPath`] (in [`DeliveryPath::ALL`] order).
    pub paths: [u16; 4],
    pub last_obs_ms: u64,
    pub last_receipt_ms: u64,
    pub last_probe_ms: u64,
    /// The last [`RECENT_MAX`] tries, newest in bit 0 (1 = success).
    pub recent: u8,
    /// How many bits of `recent` hold a try.
    pub recent_n: u8,
}

impl Arm {
    /// No evidence, the carrier's cost priors.
    pub fn new(carrier: OutboxCarrier) -> Self {
        Self {
            beta: Beta::default(),
            ok_ms: ok_prior_ms(carrier),
            fail_ms: fail_prior_ms(carrier),
            connect: Rtt::default(),
            reply: Rtt::default(),
            paths: [0; 4],
            last_obs_ms: 0,
            last_receipt_ms: 0,
            last_probe_ms: 0,
            recent: 0,
            recent_n: 0,
        }
    }

    /// The success estimate aged to `now_ms` (a copy; the arm is unchanged).
    pub fn beta_at(&self, now_ms: u64) -> Beta {
        let mut beta = self.beta;
        beta.age(now_ms, HALF_LIFE_MS);
        beta
    }

    /// `(successes, tries)` over the last [`RECENT_MAX`] tries.
    pub fn tries(&self) -> (u8, u8) {
        let n = self.recent_n.min(RECENT_MAX);
        let mask = u8::MAX.checked_shr(u32::from(RECENT_MAX - n)).unwrap_or(0);
        ((self.recent & mask).count_ones() as u8, n)
    }

    fn push_try(&mut self, ok: bool) {
        self.recent = (self.recent << 1) | u8::from(ok);
        self.recent_n = self.recent_n.saturating_add(1).min(RECENT_MAX);
    }
}

/// What the model knows of one relay (algorithms §6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayRow {
    pub beta: Beta,
    /// EWMA (α 1/4) of the receipts' totals through it.
    pub ok_ms: u32,
}

impl RelayRow {
    /// No evidence, the p2p carrier's cost prior.
    fn new() -> Self {
        Self {
            beta: Beta::default(),
            ok_ms: ok_prior_ms(OutboxCarrier::P2p),
        }
    }
}

/// How well one custodian delivered what it held for one recipient
/// (algorithms §7): verified receipts and expiries, shared among the
/// holders, 7 d half-life. The prior is not stored: it depends on whether
/// the recipient announced the custodian (`learning::carry`).
///
/// The design's data model also lists a `median_h`; no algorithm, step or
/// test defines or reads it, and the outcome carries no deposit time, so it
/// is left out rather than kept as a constant field in the file.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CarryRow {
    pub beta: Beta,
}

/// Memory-only counts since the model was made.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    /// Observations that were evidence.
    pub observations: u32,
    /// Learned orders that failed the plan's invariant.
    pub contradictions: u32,
}

/// What the model holds ([`Model::sizes`]): distinct contacts and networks
/// with arms, relay rows, arms and carry rows (custodian, recipient).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sizes {
    pub contacts: u32,
    pub networks: u32,
    pub relays: u32,
    pub arms: u32,
    pub carry: u32,
}

/// One arm's address before hashing ([`Model::arm`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArmKey {
    pub contact: [u8; 32],
    pub net: Option<String>,
    pub carrier: OutboxCarrier,
}

/// The learning model (module doc).
#[derive(Clone)]
pub struct Model {
    /// HMAC key of every row key; kept only inside the sealed file
    /// (`learning::store` reads and writes it with the rows).
    pub(super) secret: Zeroizing<[u8; 32]>,
    pub(super) arms: BTreeMap<(Key16, Key8, u8), Arm>,
    pub(super) relays: BTreeMap<Key16, RelayRow>,
    pub(super) encounters: BTreeMap<Key16, Encounter>,
    /// Keyed (custodian, recipient).
    pub(super) carry: BTreeMap<(Key16, Key16), CarryRow>,
    /// The order last applied per contact-network (memory only).
    current: BTreeMap<(Key16, Key8), Vec<u8>>,
    /// Static until this time, after a contradiction (memory only).
    pins: BTreeMap<(Key16, Key8), u64>,
    counters: Counters,
    pub state: State,
}

impl std::fmt::Debug for Model {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Model")
            .field("arms", &self.arms.len())
            .field("relays", &self.relays.len())
            .field("encounters", &self.encounters.len())
            .field("carry", &self.carry.len())
            .field("current", &self.current.len())
            .field("pins", &self.pins.len())
            .field("counters", &self.counters)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

/// One contact-network as the ranker reads it ([`Model::view`]).
pub(crate) struct View<'a> {
    model: &'a Model,
    slot: (Key16, Key8),
}

impl<'a> View<'a> {
    pub(crate) fn arm(&self, carrier: OutboxCarrier) -> Option<&'a Arm> {
        let (c, n) = self.slot;
        self.model.arms.get(&(c, n, carrier_code(carrier)))
    }

    /// The order last applied ([`Model::remember_order`]).
    pub(crate) fn current(&self) -> Option<Vec<OutboxCarrier>> {
        let codes = self.model.current.get(&self.slot)?;
        Some(codes.iter().filter_map(|c| carrier_of(*c)).collect())
    }

    /// Pinned to the static order at `now_ms` ([`Model::note_contradiction`]).
    pub(crate) fn pinned(&self, now_ms: u64) -> bool {
        self.model
            .pins
            .get(&self.slot)
            .is_some_and(|until| now_ms < *until)
    }
}

impl Model {
    /// No rows, state on, keyed by `secret`.
    pub fn new_empty(secret: [u8; 32]) -> Self {
        Self {
            secret: Zeroizing::new(secret),
            arms: BTreeMap::new(),
            relays: BTreeMap::new(),
            encounters: BTreeMap::new(),
            carry: BTreeMap::new(),
            current: BTreeMap::new(),
            pins: BTreeMap::new(),
            counters: Counters::default(),
            state: State::On,
        }
    }

    fn mac(&self, label: &[u8], id: &[u8]) -> [u8; 32] {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(self.secret.as_slice()).expect("hmac takes any key");
        mac.update(label);
        mac.update(id);
        mac.finalize().into_bytes().into()
    }

    fn key16(&self, label: &[u8], id: &[u8]) -> Key16 {
        let mut key = [0; 16];
        key.copy_from_slice(&self.mac(label, id)[..16]);
        key
    }

    fn net_key(&self, net: Option<&str>) -> Key8 {
        let mut key = [0; 8];
        key.copy_from_slice(&self.mac(b"n", net.unwrap_or_default().as_bytes())[..8]);
        key
    }

    fn slot(&self, contact: &[u8; 32], net: Option<&str>) -> (Key16, Key8) {
        (self.key16(b"c", contact), self.net_key(net))
    }

    pub(crate) fn view(&self, contact: &[u8; 32], net: Option<&str>) -> View<'_> {
        View {
            model: self,
            slot: self.slot(contact, net),
        }
    }

    /// The arm of `k`, if any was observed.
    pub fn arm(&self, k: &ArmKey) -> Option<&Arm> {
        self.view(&k.contact, k.net.as_deref()).arm(k.carrier)
    }

    /// The row of the relay with PeerId bytes `relay`.
    pub fn relay(&self, relay: &[u8]) -> Option<&RelayRow> {
        self.relays.get(&self.key16(b"r", relay))
    }

    /// The encounter row of contact `peer`, if this node met it.
    pub fn encounter_of(&self, peer: &[u8; 32]) -> Option<&Encounter> {
        self.encounters.get(&self.key16(b"c", peer))
    }

    /// The carry row of custodian `carrier` for `recipient`, if any outcome
    /// was recorded.
    pub fn carry_of(&self, carrier: &[u8; 32], recipient: &[u8; 32]) -> Option<&CarryRow> {
        self.carry
            .get(&(self.key16(b"c", carrier), self.key16(b"c", recipient)))
    }

    pub fn counters(&self) -> Counters {
        self.counters
    }

    /// Distinct contacts and networks with arms, relay rows and arms (counts
    /// only, for `Status.learning`).
    pub fn sizes(&self) -> Sizes {
        let count = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
        let contacts: BTreeSet<&Key16> = self.arms.keys().map(|(c, _, _)| c).collect();
        let networks: BTreeSet<&Key8> = self.arms.keys().map(|(_, n, _)| n).collect();
        Sizes {
            contacts: count(contacts.len()),
            networks: count(networks.len()),
            relays: count(self.relays.len()),
            arms: count(self.arms.len()),
            carry: count(self.carry.len()),
        }
    }

    /// The contact reached this node from a new address on the local
    /// network (raven-node's inbound LAN link, the analogue of
    /// `route_memory::forget_remote`): the failure evidence of its arm on
    /// `carrier` on this network, aged to `now_ms`, is halved. No arm, no
    /// change; nothing is made.
    pub fn halve_doubt(
        &mut self,
        contact: &[u8; 32],
        net: Option<&str>,
        carrier: OutboxCarrier,
        now_ms: u64,
    ) {
        let (c, n) = self.slot(contact, net);
        if let Some(arm) = self.arms.get_mut(&(c, n, carrier_code(carrier))) {
            arm.beta.age(now_ms, HALF_LIFE_MS);
            arm.beta.b_m /= 2;
        }
    }

    /// The `which` wait of the arm on `carrier` on this network ran out (no
    /// connect, or no first reply to frames that get one, in time) and no
    /// sample of it followed in the same dial: that wait backs off one
    /// doubling, at most ×8 ([`Rtt::expired`]; design §4); its next sample
    /// clears it. No arm, no change: nothing is made (a new arm's waits are
    /// today's anyway).
    pub fn rtt_expired(
        &mut self,
        contact: &[u8; 32],
        net: Option<&str>,
        carrier: OutboxCarrier,
        which: WaitKind,
    ) {
        let (c, n) = self.slot(contact, net);
        if let Some(arm) = self.arms.get_mut(&(c, n, carrier_code(carrier))) {
            match which {
                WaitKind::Connect => arm.connect.expired(),
                WaitKind::Reply => arm.reply.expired(),
            }
        }
    }

    /// Applies one observation at `now_ms` (module doc).
    pub fn observe(&mut self, o: &Observation, now_ms: u64) {
        if o.net_changed || o.carrier == OutboxCarrier::Nearby {
            return;
        }
        let Some(weight) = o.evidence.weight() else {
            return;
        };
        let (c, n) = self.slot(&o.contact, o.net.as_deref());
        let key = (c, n, carrier_code(o.carrier));
        let created = !self.arms.contains_key(&key);
        let arm = self.arms.entry(key).or_insert_with(|| Arm::new(o.carrier));
        let total = o.timing.total_ms;
        match weight {
            Weight::Success(w) => {
                arm.beta.success(w, now_ms, HALF_LIFE_MS);
                arm.ok_ms = ewma_ms(arm.ok_ms, total, COST_SHIFT);
                arm.fail_ms = ewma_ms(arm.fail_ms, fail_prior_ms(o.carrier), RELAX_SHIFT);
                arm.push_try(true);
            }
            Weight::Failure(w) => {
                arm.beta.failure(w, now_ms, HALF_LIFE_MS);
                arm.fail_ms = ewma_ms(arm.fail_ms, total, COST_SHIFT);
                arm.push_try(false);
            }
        }
        if let Some(ms) = o.timing.connect_ms {
            arm.connect.sample(ms, now_ms);
        }
        if let (Some(ms), false) = (o.timing.reply_ms, o.karn_exclude) {
            arm.reply.sample(ms, now_ms);
        }
        let receipt = o.evidence == Evidence::Receipt;
        if receipt {
            arm.last_receipt_ms = arm.last_receipt_ms.max(now_ms);
            if let Some(i) = o
                .path
                .and_then(|p| DeliveryPath::ALL.iter().position(|q| *q == p))
            {
                arm.paths[i] = arm.paths[i].saturating_add(1);
            }
        }
        if o.kind == FrameKind::Probe {
            arm.last_probe_ms = arm.last_probe_ms.max(now_ms);
        }
        arm.last_obs_ms = arm.last_obs_ms.max(now_ms);
        // `Model::relay_receipt`, with the dial's total for the relay's cost.
        if let (true, Some(DeliveryPath::Relayed), Some(relay)) = (receipt, o.path, &o.relay) {
            self.relay_apply(relay, Weight::Success(RECEIPT_W_M), Some(total), now_ms);
        }
        self.counters.observations = self.counters.observations.saturating_add(1);
        if created {
            self.enforce_caps(Some((c, n)));
        }
    }

    /// Applies `weight` to the row of relay `relay` (made on first use, the
    /// relay cap kept); `total_ms`, a receipt's dial total, moves its cost.
    pub(super) fn relay_apply(
        &mut self,
        relay: &[u8],
        weight: Weight,
        total_ms: Option<u32>,
        now_ms: u64,
    ) {
        let rk = self.key16(b"r", relay);
        let created = !self.relays.contains_key(&rk);
        let row = self.relays.entry(rk).or_insert_with(RelayRow::new);
        match weight {
            Weight::Success(w) => row.beta.success(w, now_ms, HALF_LIFE_MS),
            Weight::Failure(w) => row.beta.failure(w, now_ms, HALF_LIFE_MS),
        }
        if let Some(ms) = total_ms {
            row.ok_ms = ewma_ms(row.ok_ms, ms, COST_SHIFT);
        }
        if created {
            evict_oldest(&mut self.relays, MAX_RELAYS, |r| r.beta.at_ms, &[rk]);
        }
    }

    /// An authenticated link with contact `peer` at `now_ms`
    /// ([`Encounter::meet`], the row made on first use and the encounter cap
    /// kept): `false` when it merged into the last encounter.
    pub(super) fn encounter_apply(&mut self, peer: &[u8; 32], now_ms: u64) -> bool {
        let k = self.key16(b"c", peer);
        let created = !self.encounters.contains_key(&k);
        let new = self.encounters.entry(k).or_default().meet(now_ms);
        if created {
            evict_oldest(&mut self.encounters, MAX_ENCOUNTERS, |e| e.last_ms, &[k]);
        }
        new
    }

    /// Applies `weight` to the carry row of each of `holders` (distinct) for
    /// `recipient`, rows made on first use and the carry cap kept (never
    /// one of these rows).
    pub(super) fn carry_apply(
        &mut self,
        recipient: &[u8; 32],
        holders: &[[u8; 32]],
        weight: Weight,
        now_ms: u64,
    ) {
        let b = self.key16(b"c", recipient);
        let keys: Vec<(Key16, Key16)> = holders.iter().map(|f| (self.key16(b"c", f), b)).collect();
        let mut created = false;
        for k in &keys {
            created |= !self.carry.contains_key(k);
            let row = self.carry.entry(*k).or_default();
            match weight {
                Weight::Success(w) => row.beta.success(w, now_ms, CARRY_HALF_LIFE_MS),
                Weight::Failure(w) => row.beta.failure(w, now_ms, CARRY_HALF_LIFE_MS),
            }
        }
        if created {
            evict_oldest(&mut self.carry, MAX_CARRY_ROWS, |r| r.beta.at_ms, &keys);
        }
    }

    /// Takes back the receipt an observation at `at_ms` credited, once the
    /// worker refused every ACK of that dial: the receipt's weight, decayed
    /// to the arm's time, leaves the success evidence, the streak ends and
    /// the newest successful try counts as failed. Its cost sample and path
    /// count stay (the link itself worked).
    pub fn retract(
        &mut self,
        contact: &[u8; 32],
        net: Option<&str>,
        carrier: OutboxCarrier,
        at_ms: u64,
    ) {
        let (c, n) = self.slot(contact, net);
        let Some(arm) = self.arms.get_mut(&(c, n, carrier_code(carrier))) else {
            return;
        };
        let f = decay_q16(arm.beta.at_ms.saturating_sub(at_ms), HALF_LIFE_MS);
        let w = ((u64::from(RECEIPT_W_M) * u64::from(f)) >> 16) as u32;
        arm.beta.a_m = arm.beta.a_m.saturating_sub(w);
        arm.beta.streak = 0;
        let (_, tries) = arm.tries();
        if let Some(bit) = (0..tries).find(|b| arm.recent & (1 << b) != 0) {
            arm.recent &= !(1 << bit);
        }
    }

    /// Remembers `order` as applied for this contact-network (the
    /// hysteresis start of the next [`super::rank::order`]). Kept only
    /// while the contact-network has an arm, so it is bounded with them.
    pub fn remember_order(&mut self, contact: &[u8; 32], net: Option<&str>, order: &Order) {
        let slot = self.slot(contact, net);
        if self.has_arms(slot) {
            let codes = order.carriers.iter().map(|c| carrier_code(*c)).collect();
            self.current.insert(slot, codes);
        } else {
            self.current.remove(&slot);
        }
    }

    /// A learned order for this contact-network failed the plan's
    /// invariant (`RoutePlan::learning_contradiction`): counted, and the
    /// static order is used for [`CONTRADICTION_PIN_MS`].
    pub fn note_contradiction(&mut self, contact: &[u8; 32], net: Option<&str>, now_ms: u64) {
        let slot = self.slot(contact, net);
        self.counters.contradictions = self.counters.contradictions.saturating_add(1);
        self.current.remove(&slot);
        if self.has_arms(slot) {
            self.pins
                .insert(slot, now_ms.saturating_add(CONTRADICTION_PIN_MS));
        }
    }

    /// Forgets every row of `contact` (its arms, its encounter, and the carry
    /// rows that name it as custodian or recipient); the rows removed.
    pub fn forget_contact(&mut self, contact: &[u8; 32]) -> u32 {
        let c = self.key16(b"c", contact);
        let before = self.arms.len() + self.encounters.len() + self.carry.len();
        self.arms.retain(|(k, _, _), _| *k != c);
        self.encounters.remove(&c);
        self.carry.retain(|(f, b), _| *f != c && *b != c);
        self.current.retain(|(k, _), _| *k != c);
        self.pins.retain(|(k, _), _| *k != c);
        (before - self.arms.len() - self.encounters.len() - self.carry.len()) as u32
    }

    /// Forgets every row and draws a new secret, so no old key matches
    /// again; the rows removed (arms, relays, encounters and carry rows).
    pub fn forget_all(&mut self) -> u32 {
        let removed =
            self.arms.len() + self.relays.len() + self.encounters.len() + self.carry.len();
        self.arms.clear();
        self.relays.clear();
        self.encounters.clear();
        self.carry.clear();
        self.current.clear();
        self.pins.clear();
        rand::rngs::OsRng.fill_bytes(self.secret.as_mut_slice());
        removed as u32
    }

    /// Retention, then the caps: drops arms not observed for
    /// [`RETAIN_MS`], relay and carry rows not updated for it and encounters
    /// whose last link is older, rows whose evidence aged to `now_ms` (with
    /// their own half-life) is below [`MIN_EVIDENCE_M`], then the oldest past
    /// each cap; forgets remembered orders and pins without arms and pins
    /// that ran out.
    pub fn prune(&mut self, now_ms: u64) {
        let fresh = |at: u64| now_ms.saturating_sub(at) <= RETAIN_MS;
        let enough = |beta: &Beta, half_ms: u64| {
            let mut beta = *beta;
            beta.age(now_ms, half_ms);
            beta.evidence_m() >= MIN_EVIDENCE_M
        };
        self.arms
            .retain(|_, arm| fresh(arm.last_obs_ms) && enough(&arm.beta, HALF_LIFE_MS));
        self.relays
            .retain(|_, row| fresh(row.beta.at_ms) && enough(&row.beta, HALF_LIFE_MS));
        self.encounters.retain(|_, e| fresh(e.last_ms));
        self.carry
            .retain(|_, row| fresh(row.beta.at_ms) && enough(&row.beta, CARRY_HALF_LIFE_MS));
        self.pins.retain(|_, until| now_ms < *until);
        self.enforce_caps(None);
    }

    fn has_arms(&self, (c, n): (Key16, Key8)) -> bool {
        self.arms
            .range((c, n, 0)..=(c, n, u8::MAX))
            .next()
            .is_some()
    }

    /// The caps of the module doc, oldest first (ties: the smaller key).
    /// `keep` (the contact-network just made) is never the one evicted; a
    /// relay, encounter or carry row just made keeps its cap where it is
    /// made ([`evict_oldest`]). Remembered orders and pins without arms go
    /// with them.
    fn enforce_caps(&mut self, keep: Option<(Key16, Key8)>) {
        // The newest observation per contact-network, per contact.
        let mut per_contact: BTreeMap<Key16, BTreeMap<Key8, u64>> = BTreeMap::new();
        for ((c, n, _), arm) in &self.arms {
            let t = per_contact.entry(*c).or_default().entry(*n).or_default();
            *t = (*t).max(arm.last_obs_ms);
        }
        let mut gone_nets: BTreeSet<(Key16, Key8)> = BTreeSet::new();
        for (c, nets) in &mut per_contact {
            let excess = nets.len().saturating_sub(MAX_NETS_PER_CONTACT);
            let mut oldest: Vec<(u64, Key8)> = nets
                .iter()
                .filter(|(n, _)| keep != Some((*c, **n)))
                .map(|(n, t)| (*t, *n))
                .collect();
            oldest.sort_unstable();
            for (_, n) in oldest.into_iter().take(excess) {
                nets.remove(&n);
                gone_nets.insert((*c, n));
            }
        }
        let mut oldest: Vec<(u64, Key16)> = per_contact
            .iter()
            .filter(|(c, _)| keep.map(|(k, _)| k) != Some(**c))
            .map(|(c, nets)| (nets.values().copied().max().unwrap_or(0), *c))
            .collect();
        oldest.sort_unstable();
        let excess = per_contact.len().saturating_sub(MAX_CONTACTS);
        let gone: BTreeSet<Key16> = oldest.into_iter().take(excess).map(|(_, c)| c).collect();
        if !gone.is_empty() || !gone_nets.is_empty() {
            self.arms
                .retain(|(c, n, _), _| !gone.contains(c) && !gone_nets.contains(&(*c, *n)));
        }
        evict_oldest(&mut self.relays, MAX_RELAYS, |r| r.beta.at_ms, &[]);
        evict_oldest(&mut self.encounters, MAX_ENCOUNTERS, |e| e.last_ms, &[]);
        evict_oldest(&mut self.carry, MAX_CARRY_ROWS, |r| r.beta.at_ms, &[]);
        let arms = &self.arms;
        let has_arms =
            |(c, n): &(Key16, Key8)| arms.range((*c, *n, 0)..=(*c, *n, u8::MAX)).next().is_some();
        self.current.retain(|slot, _| has_arms(slot));
        self.pins.retain(|slot, _| has_arms(slot));
    }

    /// Test hook: sets one arm as given.
    #[cfg(test)]
    pub(crate) fn put_arm(&mut self, k: &ArmKey, arm: Arm) {
        let (c, n) = self.slot(&k.contact, k.net.as_deref());
        self.arms.insert((c, n, carrier_code(k.carrier)), arm);
    }
}

/// Removes the oldest rows of `rows` past `cap` by `at` (ties: the smaller
/// key), never one of `keep`.
fn evict_oldest<K: Ord + Copy, V>(
    rows: &mut BTreeMap<K, V>,
    cap: usize,
    at: impl Fn(&V) -> u64,
    keep: &[K],
) {
    let excess = rows.len().saturating_sub(cap);
    if excess == 0 {
        return;
    }
    let mut oldest: Vec<(u64, K)> = rows
        .iter()
        .filter(|(k, _)| !keep.contains(k))
        .map(|(k, v)| (at(v), *k))
        .collect();
    oldest.sort_unstable();
    for (_, k) in oldest.into_iter().take(excess) {
        rows.remove(&k);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::learning::estimate::N_CAP_M;
    use crate::learning::explain::Why;
    use crate::learning::observe::{DialTiming, PROBE_W_M, SILENT_W_M};

    const NOW: u64 = 1_800_000_000_000;
    const BOB: [u8; 32] = [0xB0; 32];

    fn obs(carrier: OutboxCarrier, evidence: Evidence, total_ms: u32) -> Observation {
        Observation {
            contact: BOB,
            net: Some("home".into()),
            net_changed: false,
            carrier,
            path: None,
            relay: None,
            kind: FrameKind::Message,
            evidence,
            timing: DialTiming {
                connect_ms: Some(40),
                reply_ms: Some(90),
                total_ms,
            },
            karn_exclude: false,
            at_ms: NOW,
        }
    }

    fn key(carrier: OutboxCarrier) -> ArmKey {
        ArmKey {
            contact: BOB,
            net: Some("home".into()),
            carrier,
        }
    }

    fn fail(code: &'static str) -> Evidence {
        Evidence::Fail {
            code,
            weight_milli: 1_000,
        }
    }

    #[test]
    fn observe_applies_weights_costs_and_samples() {
        let mut m = Model::new_empty([1; 32]);
        m.observe(&obs(OutboxCarrier::Lan, Evidence::Receipt, 100), NOW);
        let arm = *m.arm(&key(OutboxCarrier::Lan)).unwrap();
        assert_eq!((arm.beta.a_m, arm.beta.b_m, arm.beta.streak), (1_000, 0, 1));
        // ok_ms: 300 → 300 − (200 >> 2); fail_ms relaxes toward 5 s (there).
        assert_eq!((arm.ok_ms, arm.fail_ms), (250, 5_000));
        assert_eq!((arm.connect.n, arm.reply.n), (1, 1));
        assert_eq!((arm.connect.srtt_ms, arm.reply.srtt_ms), (40, 90));
        assert_eq!(
            (arm.last_obs_ms, arm.last_receipt_ms, arm.last_probe_ms),
            (NOW, NOW, 0)
        );
        assert_eq!(arm.tries(), (1, 1));
        // A fast failure pulls fail_ms down, a link's success relaxes it
        // back 1/8 toward the static wait.
        m.observe(&obs(OutboxCarrier::Lan, fail("NOT_REACHABLE"), 1_000), NOW);
        let arm = *m.arm(&key(OutboxCarrier::Lan)).unwrap();
        assert_eq!(
            (arm.beta.a_m, arm.beta.b_m, arm.beta.streak),
            (1_000, 1_000, 0)
        );
        assert_eq!(arm.fail_ms, 4_000);
        let mut probe = obs(OutboxCarrier::Lan, Evidence::Link, 60);
        probe.kind = FrameKind::Probe;
        m.observe(&probe, NOW);
        let arm = *m.arm(&key(OutboxCarrier::Lan)).unwrap();
        assert_eq!(arm.beta.a_m, 1_000 + PROBE_W_M);
        assert_eq!(arm.fail_ms, 4_125);
        assert_eq!(arm.last_probe_ms, NOW);
        assert_eq!(arm.tries(), (2, 3));
        // Silence is a failure of its weight.
        m.observe(&obs(OutboxCarrier::Lan, Evidence::Silent, 30_000), NOW);
        let arm = *m.arm(&key(OutboxCarrier::Lan)).unwrap();
        assert_eq!(arm.beta.b_m, 1_000 + SILENT_W_M);
        assert_eq!(m.counters().observations, 4);
    }

    /// Karn: a resend of an object that went silent gives no reply sample;
    /// the connect sample is still taken.
    #[test]
    fn karn_excluded_dial_gives_no_reply_sample() {
        let mut m = Model::new_empty([1; 32]);
        let mut o = obs(OutboxCarrier::Internet, Evidence::Receipt, 500);
        o.karn_exclude = true;
        m.observe(&o, NOW);
        let arm = m.arm(&key(OutboxCarrier::Internet)).unwrap();
        assert_eq!((arm.connect.n, arm.reply.n), (1, 0));
    }

    /// An expiry doubles that one wait's backoff (at most ×8) on the arm of
    /// this network only, the other wait untouched; the next sample clears
    /// it; with no arm nothing is made.
    #[test]
    fn rtt_expired_backs_off_one_wait_and_makes_no_arm() {
        let mut m = Model::new_empty([1; 32]);
        m.rtt_expired(&BOB, Some("home"), OutboxCarrier::Lan, WaitKind::Reply);
        assert!(m.arms.is_empty(), "no arm, nothing made");
        m.observe(&obs(OutboxCarrier::Lan, Evidence::Receipt, 100), NOW);
        m.observe(&obs(OutboxCarrier::Internet, Evidence::Receipt, 100), NOW);
        for _ in 0..5 {
            m.rtt_expired(&BOB, Some("home"), OutboxCarrier::Lan, WaitKind::Reply);
        }
        m.rtt_expired(&BOB, Some("home"), OutboxCarrier::Lan, WaitKind::Connect);
        m.rtt_expired(
            &BOB,
            Some("office"),
            OutboxCarrier::Internet,
            WaitKind::Reply,
        );
        let backoffs = |m: &Model, c| {
            let a = m.arm(&key(c)).unwrap();
            (a.connect.backoff, a.reply.backoff)
        };
        assert_eq!(
            backoffs(&m, OutboxCarrier::Lan),
            (1, crate::learning::wait::MAX_BACKOFF)
        );
        assert_eq!(backoffs(&m, OutboxCarrier::Internet), (0, 0), "other net");
        assert_eq!(m.arms.len(), 2);
        m.observe(&obs(OutboxCarrier::Lan, Evidence::Receipt, 100), NOW);
        assert_eq!(
            backoffs(&m, OutboxCarrier::Lan),
            (0, 0),
            "a sample clears it"
        );
    }

    #[test]
    fn not_evidence_network_change_and_nearby_keep_nothing() {
        let mut m = Model::new_empty([1; 32]);
        m.observe(&obs(OutboxCarrier::Lan, Evidence::None, 10), NOW);
        let mut moved = obs(OutboxCarrier::Lan, Evidence::Receipt, 10);
        moved.net_changed = true;
        m.observe(&moved, NOW);
        m.observe(&obs(OutboxCarrier::Nearby, Evidence::Receipt, 10), NOW);
        assert!(m.arms.is_empty() && m.relays.is_empty());
        assert_eq!(m.counters(), Counters::default());
    }

    /// Keys are HMACs under the secret: the contact and tag appear nowhere,
    /// another secret gives other keys, `None` and an empty tag share the
    /// "none" bucket, and `Debug` prints counts only.
    #[test]
    fn keys_are_hashed_and_debug_prints_counts() {
        let mut m = Model::new_empty([7; 32]);
        m.observe(&obs(OutboxCarrier::Lan, Evidence::Receipt, 10), NOW);
        let ((c, n, _), _) = m.arms.iter().next().unwrap();
        assert!(!BOB.windows(16).any(|w| w == c.as_slice()));
        let other = Model::new_empty([8; 32]);
        assert_ne!(other.slot(&BOB, Some("home")), m.slot(&BOB, Some("home")));
        assert_ne!(m.net_key(Some("office")), *n);
        assert_eq!(m.net_key(None), m.net_key(Some("")));
        let shown = format!("{m:?}");
        assert!(shown.contains("arms: 1"), "{shown}");
        assert!(!shown.contains("home") && !shown.contains("176"), "{shown}");
    }

    #[test]
    fn relayed_receipts_feed_the_relay_row() {
        let mut m = Model::new_empty([1; 32]);
        let mut o = obs(OutboxCarrier::P2p, Evidence::Receipt, 2_000);
        o.path = Some(DeliveryPath::Relayed);
        o.relay = Some(b"relay-peer-id".to_vec());
        m.observe(&o, NOW);
        let row = m.relay(b"relay-peer-id").unwrap();
        assert_eq!(row.beta.a_m, RECEIPT_W_M);
        assert_eq!(row.ok_ms, 2_750);
        let arm = m.arm(&key(OutboxCarrier::P2p)).unwrap();
        assert_eq!(arm.paths, [0, 0, 1, 0]);
        // A link or a direct receipt does not.
        let mut link = o.clone();
        link.evidence = Evidence::Link;
        link.relay = Some(b"other".to_vec());
        m.observe(&link, NOW);
        assert!(m.relay(b"other").is_none());
    }

    #[test]
    fn retract_takes_the_receipt_back() {
        let mut m = Model::new_empty([1; 32]);
        m.observe(&obs(OutboxCarrier::Lan, fail("NOT_REACHABLE"), 10), NOW);
        m.observe(&obs(OutboxCarrier::Lan, Evidence::Receipt, 10), NOW + 1);
        m.retract(&BOB, Some("home"), OutboxCarrier::Lan, NOW + 1);
        let arm = m.arm(&key(OutboxCarrier::Lan)).unwrap();
        assert_eq!((arm.beta.a_m, arm.beta.streak), (0, 0));
        assert_eq!(arm.tries(), (0, 2));
        // Unknown arm: nothing happens.
        m.retract(&BOB, Some("office"), OutboxCarrier::Lan, NOW);
        assert_eq!(m.arms.len(), 1);
    }

    /// An inbound link from a new local address halves the doubt of that
    /// one arm (aged first); the success evidence and other arms stay, and
    /// no arm is made.
    #[test]
    fn halve_doubt_touches_only_that_arm() {
        let mut m = Model::new_empty([1; 32]);
        for _ in 0..2 {
            m.observe(&obs(OutboxCarrier::Lan, fail("NOT_REACHABLE"), 10), NOW);
            m.observe(
                &obs(OutboxCarrier::Internet, fail("NOT_REACHABLE"), 10),
                NOW,
            );
        }
        m.observe(&obs(OutboxCarrier::Lan, Evidence::Receipt, 10), NOW);
        let before = m.arm(&key(OutboxCarrier::Lan)).unwrap().beta;
        m.halve_doubt(&BOB, Some("home"), OutboxCarrier::Lan, NOW);
        let lan = m.arm(&key(OutboxCarrier::Lan)).unwrap().beta;
        assert_eq!((lan.a_m, lan.b_m), (before.a_m, before.b_m / 2));
        assert_eq!(
            m.arm(&key(OutboxCarrier::Internet)).unwrap().beta.b_m,
            2_000
        );
        m.halve_doubt(&BOB, Some("office"), OutboxCarrier::Lan, NOW);
        m.halve_doubt(&BOB, Some("home"), OutboxCarrier::P2p, NOW);
        assert_eq!(m.arms.len(), 2);
        assert_eq!(
            m.sizes(),
            Sizes {
                contacts: 1,
                networks: 1,
                relays: 0,
                arms: 2,
                carry: 0,
            }
        );
    }

    #[test]
    fn tries_cover_the_last_eight() {
        let mut arm = Arm::new(OutboxCarrier::Lan);
        assert_eq!(arm.tries(), (0, 0));
        for i in 0..20 {
            arm.push_try(i % 4 == 0);
        }
        // Tries 12..20: successes at 12 and 16.
        assert_eq!(arm.tries(), (2, RECENT_MAX));
    }

    #[test]
    fn caps_evict_the_oldest() {
        let mut m = Model::new_empty([1; 32]);
        let mut t = NOW;
        for i in 0..(MAX_CONTACTS + 5) {
            let mut o = obs(OutboxCarrier::Lan, Evidence::Receipt, 10);
            o.contact = [i as u8; 32];
            m.observe(&o, t);
            t += 1;
        }
        let contacts: BTreeSet<Key16> = m.arms.keys().map(|(c, _, _)| *c).collect();
        assert_eq!(contacts.len(), MAX_CONTACTS);
        // The first five went.
        for i in 0..5 {
            assert!(!contacts.contains(&m.key16(b"c", &[i as u8; 32])));
        }
        for i in 5..(MAX_CONTACTS + 5) {
            assert!(contacts.contains(&m.key16(b"c", &[i as u8; 32])));
        }
        for i in 0..(MAX_NETS_PER_CONTACT + 3) {
            let mut o = obs(OutboxCarrier::Internet, Evidence::Receipt, 10);
            o.net = Some(format!("net{i}"));
            m.observe(&o, t);
            t += 1;
        }
        let c = m.key16(b"c", &BOB);
        let nets: BTreeSet<Key8> = m
            .arms
            .keys()
            .filter(|(k, _, _)| *k == c)
            .map(|(_, n, _)| *n)
            .collect();
        assert_eq!(nets.len(), MAX_NETS_PER_CONTACT);
        assert!(!nets.contains(&m.net_key(Some("net0"))));
        assert!(nets.contains(&m.net_key(Some("net10"))));
        for i in 0..(MAX_RELAYS + 4) {
            let mut o = obs(OutboxCarrier::P2p, Evidence::Receipt, 10);
            o.path = Some(DeliveryPath::Relayed);
            o.relay = Some(vec![i as u8; 8]);
            m.observe(&o, t);
            t += 1;
        }
        assert_eq!(m.relays.len(), MAX_RELAYS);
        assert!(m.relay(&[0; 8]).is_none());
        assert!(m.relay(&[(MAX_RELAYS + 3) as u8; 8]).is_some());
    }

    #[test]
    fn prune_drops_stale_and_thin_rows() {
        let mut m = Model::new_empty([1; 32]);
        m.observe(&obs(OutboxCarrier::Lan, Evidence::Receipt, 10), NOW);
        m.observe(
            &obs(OutboxCarrier::Internet, Evidence::Receipt, 10),
            NOW + 20 * DAY_MS,
        );
        let mut relayed = obs(OutboxCarrier::P2p, Evidence::Receipt, 10);
        relayed.path = Some(DeliveryPath::Relayed);
        relayed.relay = Some(vec![9; 8]);
        m.observe(&relayed, NOW + 25 * DAY_MS);
        // 4 days after the LAN receipt its evidence is 1000/16 = 62: kept.
        m.prune(NOW + 4 * DAY_MS);
        assert!(m.arm(&key(OutboxCarrier::Lan)).is_some());
        // 5 days: 31 < 50, dropped.
        m.prune(NOW + 5 * DAY_MS);
        assert!(m.arm(&key(OutboxCarrier::Lan)).is_none());
        assert!(m.arm(&key(OutboxCarrier::Internet)).is_some());
        // Retention: the Internet row is fresh enough by evidence when the
        // clock jumps, but 30 days without an update drop it.
        let mut evidence = m.arm(&key(OutboxCarrier::Internet)).unwrap().beta;
        evidence.age(NOW + 21 * DAY_MS, HALF_LIFE_MS);
        assert!(evidence.evidence_m() >= MIN_EVIDENCE_M);
        m.prune(NOW + 51 * DAY_MS);
        assert!(m.arm(&key(OutboxCarrier::Internet)).is_none());
        assert!(m.relay(&[9; 8]).is_none());
        assert!(m.arms.is_empty() && m.relays.is_empty());
    }

    #[test]
    fn forget_contact_and_all() {
        let mut m = Model::new_empty([1; 32]);
        m.observe(&obs(OutboxCarrier::Lan, Evidence::Receipt, 10), NOW);
        m.observe(&obs(OutboxCarrier::Internet, Evidence::Receipt, 10), NOW);
        let mut carol = obs(OutboxCarrier::Lan, Evidence::Receipt, 10);
        carol.contact = [0xCA; 32];
        m.observe(&carol, NOW);
        let order = Order::fixed(&[OutboxCarrier::Lan], Why::Kept, State::On);
        m.remember_order(&BOB, Some("home"), &order);
        m.note_contradiction(&BOB, Some("home"), NOW);
        assert_eq!(m.forget_contact(&BOB), 2);
        assert!(m.current.is_empty() && m.pins.is_empty());
        assert_eq!(m.forget_contact(&BOB), 0);
        let mut relayed = obs(OutboxCarrier::P2p, Evidence::Receipt, 10);
        relayed.path = Some(DeliveryPath::Relayed);
        relayed.relay = Some(vec![9; 8]);
        m.observe(&relayed, NOW);
        let before = m.slot(&BOB, Some("home"));
        assert_eq!(m.forget_all(), 3);
        assert!(m.arms.is_empty() && m.relays.is_empty());
        assert_ne!(m.slot(&BOB, Some("home")), before, "a new secret");
    }

    /// The remembered order and the pin exist only while the
    /// contact-network has arms, and the pin runs out.
    #[test]
    fn remembered_orders_and_pins_are_bounded() {
        let mut m = Model::new_empty([1; 32]);
        let order = Order::fixed(
            &[OutboxCarrier::Internet, OutboxCarrier::Lan],
            Why::Faster,
            State::On,
        );
        m.remember_order(&BOB, Some("home"), &order);
        m.note_contradiction(&BOB, Some("home"), NOW);
        assert!(m.current.is_empty() && m.pins.is_empty());
        assert_eq!(m.counters().contradictions, 1);
        m.observe(&obs(OutboxCarrier::Lan, Evidence::Receipt, 10), NOW);
        m.remember_order(&BOB, Some("home"), &order);
        assert_eq!(
            m.view(&BOB, Some("home")).current(),
            Some(vec![OutboxCarrier::Internet, OutboxCarrier::Lan])
        );
        m.note_contradiction(&BOB, Some("home"), NOW);
        assert_eq!(m.view(&BOB, Some("home")).current(), None);
        assert!(m
            .view(&BOB, Some("home"))
            .pinned(NOW + CONTRADICTION_PIN_MS - 1));
        assert!(!m
            .view(&BOB, Some("home"))
            .pinned(NOW + CONTRADICTION_PIN_MS));
        m.prune(NOW + CONTRADICTION_PIN_MS);
        assert!(m.pins.is_empty());
    }

    #[test]
    fn encounter_and_carry_rows_are_bounded() {
        let mut m = Model::new_empty([1; 32]);
        for i in 0..(MAX_ENCOUNTERS + 3) {
            assert!(m.encounter_apply(&[i as u8; 32], NOW + i as u64));
        }
        assert_eq!(m.encounters.len(), MAX_ENCOUNTERS);
        for i in 0..3 {
            assert!(m.encounter_of(&[i as u8; 32]).is_none());
        }
        assert!(m.encounter_of(&[(MAX_ENCOUNTERS + 2) as u8; 32]).is_some());
        // Merging into a known row never evicts.
        m.encounter_apply(&[3; 32], NOW + 10);
        assert_eq!(m.encounters.len(), MAX_ENCOUNTERS);
        let recipient = [0xEE; 32];
        for i in 0..(MAX_CARRY_ROWS + 2) {
            let f = [i as u8; 32];
            m.carry_apply(&recipient, &[f], Weight::Success(1_000), NOW + i as u64);
        }
        assert_eq!(m.carry.len(), MAX_CARRY_ROWS);
        assert!(m.carry_of(&[0; 32], &recipient).is_none());
        assert!(m.carry_of(&[1; 32], &recipient).is_none());
        // Two rows made at once at the cap, both older than the rest by
        // the clock: both kept, the two oldest others go.
        let pair = [[0xF0; 32], [0xF1; 32]];
        m.carry_apply(&recipient, &pair, Weight::Failure(500), NOW - 1);
        assert_eq!(m.carry.len(), MAX_CARRY_ROWS);
        assert!(pair.iter().all(|f| m.carry_of(f, &recipient).is_some()));
        assert!(m.carry_of(&[2; 32], &recipient).is_none());
        assert!(m.carry_of(&[3; 32], &recipient).is_none());
        let shown = format!("{m:?}");
        assert!(shown.contains("encounters: 64") && shown.contains("carry: 128"));
    }

    #[test]
    fn prune_drops_stale_encounters_and_thin_carry_rows() {
        let mut m = Model::new_empty([1; 32]);
        let carol = [0xCA; 32];
        m.encounter_apply(&BOB, NOW);
        m.carry_apply(&BOB, &[carol], Weight::Success(500), NOW);
        // 21 days at a 7 d half-life: 500/8 = 62, kept; the encounter is
        // fresh.
        m.prune(NOW + 21 * DAY_MS);
        assert!(m.carry_of(&carol, &BOB).is_some());
        assert!(m.encounter_of(&BOB).is_some());
        // 25 days: 41 < 50, dropped.
        m.prune(NOW + 25 * DAY_MS);
        assert!(m.carry_of(&carol, &BOB).is_none());
        assert!(m.encounter_of(&BOB).is_some());
        // An encounter goes 30 days after its last link.
        m.prune(NOW + RETAIN_MS);
        assert!(m.encounter_of(&BOB).is_some());
        m.prune(NOW + RETAIN_MS + 1);
        assert!(m.encounter_of(&BOB).is_none());
    }

    /// `forget_contact` takes the contact's encounter and every carry row
    /// naming it; `forget_all` everything.
    #[test]
    fn forget_takes_encounters_and_carry_rows() {
        let mut m = Model::new_empty([1; 32]);
        let (carol, dave) = ([0xCA; 32], [0xDA; 32]);
        m.observe(&obs(OutboxCarrier::Lan, Evidence::Receipt, 10), NOW);
        m.encounter_apply(&BOB, NOW);
        m.encounter_apply(&carol, NOW);
        m.carry_apply(&carol, &[BOB], Weight::Success(1_000), NOW);
        m.carry_apply(&BOB, &[carol, dave], Weight::Success(500), NOW);
        m.carry_apply(&dave, &[carol], Weight::Success(1_000), NOW);
        // One arm, one encounter, three carry rows.
        assert_eq!(m.forget_contact(&BOB), 5);
        assert!(m.encounter_of(&BOB).is_none());
        assert!(m.encounter_of(&carol).is_some());
        assert!(m.carry_of(&carol, &dave).is_some());
        assert_eq!(m.carry.len(), 1);
        assert_eq!(m.forget_all(), 2);
        assert!(m.encounters.is_empty() && m.carry.is_empty());
    }

    #[test]
    fn evidence_stays_under_the_cap() {
        let mut m = Model::new_empty([1; 32]);
        for i in 0..50 {
            let e = if i % 3 == 0 {
                fail("NOT_REACHABLE")
            } else {
                Evidence::Receipt
            };
            m.observe(&obs(OutboxCarrier::Lan, e, 10), NOW + i);
        }
        assert!(m.arm(&key(OutboxCarrier::Lan)).unwrap().beta.evidence_m() <= N_CAP_M);
    }
}
