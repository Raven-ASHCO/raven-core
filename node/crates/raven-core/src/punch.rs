//! Serverless hole punching between friends (auto-reach,
//! `docs/design/2026-10-auto-reach.md` §5): when two friends dial each
//! other, and how often, with nothing exchanged to agree on it. Pure: no
//! socket and no clock of its own; raven-node's p2p host asks it every tick
//! and dials.
//!
//! **Meeting in time.** Unix time is cut into slots ([`SLOT_MS`]). A pair's
//! phase and offset come from a secret the two friends share (their R2 pair
//! root, a static Diffie-Hellman of their identity keys:
//! [`crate::lan_beacon::pair_root`]) and the UTC day ([`pair_phase`]), so
//! both friends compute the same ones, they change every day, and nobody
//! who only knows the two public keys can (holding both cards does not tell
//! when the pair will punch). A side at level `L`
//! takes part in slot `n` when `(n + phase) mod 2^L == 0` ([`takes_part`]),
//! and dials at the slot's start plus the offset. The sets are nested, so two
//! sides at levels `a` and `b` meet in every `2^max(a, b)`-th slot.
//!
//! **Levels** ([`level`]). A friend this node has something waiting for is
//! at level 0 for its first [`FAST_TRIES`] attempts, then one level up per
//! two failed attempts, up to [`MAX_LEVEL`]; a friend with nothing waiting
//! stays at [`MAX_LEVEL`] (every 16 minutes with 30 s slots), so a friend
//! that wants to deliver meets it within that time.
//!
//! **Limits** ([`Book::due`]). At most [`PER_SLOT`] attempts per slot (lowest
//! level first, then the one tried longest ago), at most [`IDLE_TARGETS`]
//! friends at the idle level (the most recently heard), at most
//! [`DAILY_PER_CONTACT`] attempts per friend per 24 h, and a rest of
//! [`REST_MS`] after [`REST_AFTER`] failures in a row. Whether a friend may
//! be punched at all (verified, NAT classes, addresses, not connected) is
//! the caller's.

use std::collections::{HashMap, VecDeque};

/// The slot length (a harness sets another, `RAVEN_LAB_PUNCH_SLOT_S`).
pub const SLOT_MS: u64 = 30_000;
/// The idle level: every `2^MAX_LEVEL` slots.
pub const MAX_LEVEL: u8 = 5;
/// Attempts a wanted friend gets at level 0 before backing off.
pub const FAST_TRIES: u32 = 2;
/// Attempts per slot, all friends together.
pub const PER_SLOT: usize = 4;
/// Friends punched while nothing waits for them (the most recently heard).
pub const IDLE_TARGETS: usize = 8;
/// Attempts per friend per 24 h.
pub const DAILY_PER_CONTACT: u32 = 200;
/// Failed attempts in a row after which a friend rests.
pub const REST_AFTER: u32 = 32;
/// How long a friend rests.
pub const REST_MS: u64 = 6 * 3_600_000;
/// The longest a tick may come after the dial moment and still dial in that
/// slot (the friend's QUIC Initials are retransmitted for about 5 s).
pub const LATE_MS: u64 = 4_000;
const DAY_MS: u64 = 24 * 3_600_000;
/// The domain of [`pair_phase`].
const PHASE_DOMAIN: &[u8] = b"raven/punch/v2";

/// A pair's place in the schedule ([`pair_phase`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PairPhase {
    pub phase: u32,
    /// Milliseconds after a slot's start, within its first third.
    pub offset_ms: u64,
}

/// The phase and offset of the pair of identity keys `a` and `b` (in either
/// order) sharing `secret` (their pair root), on UTC day `day` (Unix ms /
/// one day), for slots of `slot_ms`: SHA-256 of the domain, the secret, the
/// day (u64 BE) and both keys in bytewise order; the phase from its first
/// 4 bytes, the offset from the next 2, reduced to the first third of a
/// slot.
pub fn pair_phase(
    a: &[u8; 32],
    b: &[u8; 32],
    secret: &[u8; 32],
    day: u64,
    slot_ms: u64,
) -> PairPhase {
    use sha2::{Digest, Sha256};
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    let mut h = Sha256::new();
    h.update(PHASE_DOMAIN);
    h.update(secret);
    h.update(day.to_be_bytes());
    h.update(lo);
    h.update(hi);
    let d = h.finalize();
    let phase = u32::from_be_bytes([d[0], d[1], d[2], d[3]]);
    let third = (slot_ms / 3).max(1);
    PairPhase {
        phase,
        offset_ms: u64::from(u16::from_be_bytes([d[4], d[5]])) % third,
    }
}

/// The slot `unix_ms` falls in.
pub fn slot_of(unix_ms: u64, slot_ms: u64) -> u64 {
    unix_ms / slot_ms.max(1)
}

/// Does a side at `level` take part in `slot` for a pair of `phase`?
pub fn takes_part(slot: u64, phase: u32, level: u8) -> bool {
    let period = 1u64 << level.min(MAX_LEVEL);
    (slot.wrapping_add(u64::from(phase))) % period == 0
}

/// The level of a friend: `wanted` (something waits for it) starts at 0 and
/// rises one level per two failed attempts after [`FAST_TRIES`], up to
/// [`MAX_LEVEL`]; otherwise [`MAX_LEVEL`].
pub fn level(wanted: bool, failures: u32) -> u8 {
    if !wanted {
        return MAX_LEVEL;
    }
    let up = failures.saturating_sub(FAST_TRIES).div_ceil(2);
    u8::try_from(up.min(u32::from(MAX_LEVEL))).unwrap_or(MAX_LEVEL)
}

/// When the next attempt at `level` is due at or after `now_ms`: the dial
/// moment (slot start plus offset) of the next slot this side takes part
/// in, the current one included while it is not more than [`LATE_MS`]
/// past.
pub fn next_attempt_ms(now_ms: u64, slot_ms: u64, pp: PairPhase, level: u8) -> u64 {
    let slot_ms = slot_ms.max(1);
    let first = slot_of(now_ms, slot_ms);
    (first..=first + (1u64 << MAX_LEVEL))
        .map(|slot| (slot, slot * slot_ms + pp.offset_ms))
        .find(|(slot, at)| takes_part(*slot, pp.phase, level) && at + late_ms(slot_ms) >= now_ms)
        .map_or(now_ms, |(_, at)| at.max(now_ms.min(at + late_ms(slot_ms))))
}

/// How late after the dial moment a tick may still dial: [`LATE_MS`], at
/// least 1.5 s (the p2p host ticks every second) and at most half a slot
/// (a short lab slot).
fn late_ms(slot_ms: u64) -> u64 {
    LATE_MS
        .min((slot_ms / 4).max(1_500))
        .min(slot_ms / 2)
        .max(1)
}

/// One friend the caller may punch now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Target {
    /// Its identity key.
    pub key: [u8; 32],
    /// The secret this node shares with it (their pair root): the pair's
    /// phase is made from it ([`pair_phase`]).
    pub secret: [u8; 32],
    /// Something waits for it in this node's outbox.
    pub wanted: bool,
    /// When its newest route hints came (wall ms): the idle level keeps the
    /// most recently heard.
    pub heard_ms: u64,
}

/// What one friend's punching did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Entry {
    /// Failed attempts in a row.
    failures: u32,
    /// The dial moment of the last attempt (wall ms).
    last_at: Option<u64>,
    /// Attempt times in the last 24 h.
    day: VecDeque<u64>,
    rest_until: Option<u64>,
}

/// What [`Book::due`] decided for one tick.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Due {
    /// The friends to dial now, at most [`PER_SLOT`].
    pub dial: Vec<[u8; 32]>,
    /// Attempts due now that the per-slot or daily limit left out.
    pub deferred: u64,
}

/// Every friend's punching state, on one network (the caller clears it on a
/// network change, [`Book::reset`]).
#[derive(Clone, Debug, Default)]
pub struct Book {
    entries: HashMap<[u8; 32], Entry>,
    /// Attempts made in each slot (for [`PER_SLOT`]): the slot and its count.
    slot_used: (u64, usize),
}

impl Book {
    pub fn new() -> Self {
        Self::default()
    }

    /// The friends whose dial moment is now (module doc, "Limits"), as seen
    /// by the node of identity key `own` at `now_ms` with slots of
    /// `slot_ms`. Each one returned counts as tried.
    pub fn due(&mut self, own: &[u8; 32], targets: &[Target], now_ms: u64, slot_ms: u64) -> Due {
        let slot_ms = slot_ms.max(1);
        let slot = slot_of(now_ms, slot_ms);
        if self.slot_used.0 != slot {
            self.slot_used = (slot, 0);
        }
        // The idle level: only the most recently heard.
        let mut idle: Vec<&Target> = targets.iter().filter(|t| !t.wanted).collect();
        idle.sort_by_key(|t| std::cmp::Reverse(t.heard_ms));
        let idle_kept: Vec<[u8; 32]> = idle.iter().take(IDLE_TARGETS).map(|t| t.key).collect();
        let mut ready: Vec<(u8, u64, [u8; 32])> = Vec::new();
        let mut deferred = 0u64;
        for t in targets {
            if t.key == *own || (!t.wanted && !idle_kept.contains(&t.key)) {
                continue;
            }
            let e = self.entries.entry(t.key).or_default();
            while e
                .day
                .front()
                .is_some_and(|at| now_ms.saturating_sub(*at) >= DAY_MS)
            {
                e.day.pop_front();
            }
            if e.rest_until.is_some_and(|until| now_ms < until) {
                continue;
            }
            let pp = pair_phase(own, &t.key, &t.secret, now_ms / DAY_MS, slot_ms);
            let lvl = level(t.wanted, e.failures);
            let at = slot * slot_ms + pp.offset_ms;
            let in_window = now_ms >= at && now_ms <= at + late_ms(slot_ms);
            if !in_window || !takes_part(slot, pp.phase, lvl) || e.last_at == Some(at) {
                continue;
            }
            if e.day.len() >= DAILY_PER_CONTACT as usize {
                deferred += 1;
                continue;
            }
            ready.push((lvl, e.last_at.unwrap_or(0), t.key));
        }
        ready.sort();
        let room = PER_SLOT.saturating_sub(self.slot_used.1);
        let mut dial = Vec::new();
        for (i, (_, _, key)) in ready.into_iter().enumerate() {
            if i >= room {
                deferred += 1;
                continue;
            }
            let Some(t) = targets.iter().find(|t| t.key == key) else {
                continue;
            };
            let pp = pair_phase(own, &key, &t.secret, now_ms / DAY_MS, slot_ms);
            let e = self.entries.entry(key).or_default();
            let at = slot * slot_ms + pp.offset_ms;
            e.last_at = Some(at);
            e.day.push_back(now_ms);
            dial.push(key);
        }
        self.slot_used.1 += dial.len();
        Due { dial, deferred }
    }

    /// How the attempt toward `key` ended (`connected`: a connection to it
    /// came up). A failure counts toward its level and rest; a success
    /// starts it over.
    pub fn result(&mut self, key: &[u8; 32], connected: bool, now_ms: u64) {
        let e = self.entries.entry(*key).or_default();
        if connected {
            e.failures = 0;
            e.rest_until = None;
        } else {
            e.failures = e.failures.saturating_add(1);
            if e.failures >= REST_AFTER {
                e.failures = 0;
                e.rest_until = Some(now_ms.saturating_add(REST_MS));
            }
        }
    }

    /// Something new about `key` (its route hints changed, it just became
    /// wanted): its failures and rest start over.
    pub fn fresh(&mut self, key: &[u8; 32]) {
        if let Some(e) = self.entries.get_mut(key) {
            e.failures = 0;
            e.rest_until = None;
        }
    }

    /// A network change or a re-home: every failure and rest starts over
    /// (the daily counts stay).
    pub fn reset(&mut self) {
        for e in self.entries.values_mut() {
            e.failures = 0;
            e.rest_until = None;
            e.last_at = None;
        }
    }

    /// Keep only the friends in `keys` (the others are no targets any more).
    pub fn retain(&mut self, keys: &[[u8; 32]]) {
        self.entries.retain(|k, _| keys.contains(k));
    }

    /// Failed attempts in a row toward `key` (tests, status).
    pub fn failures(&self, key: &[u8; 32]) -> u32 {
        self.entries.get(key).map_or(0, |e| e.failures)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: [u8; 32] = [0xA1; 32];
    const B: [u8; 32] = [0xB2; 32];
    const C: [u8; 32] = [0xC3; 32];
    /// The tests' pair secret (both sides hold the same one).
    const S: [u8; 32] = [0x5E; 32];

    /// The phase needs the pair's secret, not only the two public keys, and
    /// changes every day.
    #[test]
    fn the_phase_needs_the_pairs_secret_and_changes_daily() {
        let ab = pair_phase(&A, &B, &S, 20_000, SLOT_MS);
        assert_eq!(ab, pair_phase(&B, &A, &S, 20_000, SLOT_MS));
        let others: Vec<PairPhase> = (0u8..8)
            .map(|i| pair_phase(&A, &B, &[i; 32], 20_000, SLOT_MS))
            .collect();
        assert!(others.iter().all(|p| p.phase != ab.phase), "{others:?}");
        assert_ne!(ab.phase, pair_phase(&A, &B, &S, 20_001, SLOT_MS).phase);
    }

    #[test]
    fn both_friends_compute_the_same_phase_and_others_another() {
        let ab = pair_phase(&A, &B, &S, 0, SLOT_MS);
        assert_eq!(ab, pair_phase(&B, &A, &S, 0, SLOT_MS), "symmetric");
        assert_ne!(ab, pair_phase(&A, &C, &S, 0, SLOT_MS));
        assert!(ab.offset_ms < SLOT_MS / 3);
        for slot_ms in [2_000, 5_000, 300_000] {
            assert!(pair_phase(&A, &B, &S, 0, slot_ms).offset_ms < slot_ms / 3);
        }
    }

    #[test]
    fn levels_are_nested_so_two_sides_meet_at_the_higher_period() {
        let phase = 12_345;
        for la in 0..=MAX_LEVEL {
            for lb in 0..=MAX_LEVEL {
                let both: Vec<u64> = (0..256)
                    .filter(|n| takes_part(*n, phase, la) && takes_part(*n, phase, lb))
                    .collect();
                let period = 1u64 << la.max(lb);
                assert_eq!(both.len() as u64, 256 / period, "la={la} lb={lb}");
                assert!(both.windows(2).all(|w| w[1] - w[0] == period));
            }
        }
    }

    #[test]
    fn a_wanted_friend_starts_fast_and_backs_off_to_the_idle_level() {
        assert_eq!(level(false, 0), MAX_LEVEL);
        assert_eq!(level(true, 0), 0);
        assert_eq!(level(true, 1), 0);
        assert_eq!(level(true, 2), 0);
        assert_eq!(level(true, 3), 1);
        assert_eq!(level(true, 4), 1);
        assert_eq!(level(true, 5), 2);
        assert_eq!(level(true, 1000), MAX_LEVEL);
    }

    #[test]
    fn next_attempt_is_the_next_dial_moment() {
        let pp = PairPhase {
            phase: 3,
            offset_ms: 1_000,
        };
        // Level 0: every slot.
        assert_eq!(next_attempt_ms(60_000, SLOT_MS, pp, 0), 61_000);
        assert_eq!(
            next_attempt_ms(61_500, SLOT_MS, pp, 0),
            61_500,
            "a little late"
        );
        assert_eq!(next_attempt_ms(66_000, SLOT_MS, pp, 0), 91_000, "too late");
        // Level 2: slots where (n + 3) % 4 == 0, i.e. n = 1, 5, 9, ...
        assert_eq!(next_attempt_ms(60_000, SLOT_MS, pp, 2), 5 * SLOT_MS + 1_000);
    }

    fn sweep(
        book: &mut Book,
        own: &[u8; 32],
        targets: &[Target],
        from: u64,
        to: u64,
        slot: u64,
    ) -> Vec<(u64, [u8; 32])> {
        let mut out = Vec::new();
        let mut t = from;
        while t < to {
            for key in book.due(own, targets, t, slot).dial {
                out.push((t, key));
            }
            t += 500;
        }
        out
    }

    #[test]
    fn two_friends_dial_in_the_same_slots() {
        let slot = 5_000;
        let mut a = Book::new();
        let mut b = Book::new();
        // A wants to deliver to B; B has nothing for A (idle).
        let at_a = sweep(
            &mut a,
            &A,
            &[Target {
                secret: S,
                key: B,
                wanted: true,
                heard_ms: 1,
            }],
            1_000_000,
            1_000_000 + 64 * slot,
            slot,
        );
        let at_b = sweep(
            &mut b,
            &B,
            &[Target {
                secret: S,
                key: A,
                wanted: false,
                heard_ms: 1,
            }],
            1_000_000,
            1_000_000 + 64 * slot,
            slot,
        );
        let slots =
            |v: &[(u64, [u8; 32])]| -> Vec<u64> { v.iter().map(|(t, _)| t / slot).collect() };
        let (sa, sb) = (slots(&at_a), slots(&at_b));
        assert!(!sb.is_empty(), "the idle side takes part every 32 slots");
        assert!(sb.len() >= 2 && sb.len() <= 3, "{sb:?}");
        for s in &sb {
            assert!(sa.contains(s), "A dials in B's slot {s}: {sa:?}");
        }
        // Each side dials at the pair's offset within the slot (to the 500 ms
        // tick).
        let pp = pair_phase(&A, &B, &S, 0, slot);
        for (t, _) in at_a.iter().chain(&at_b) {
            let into = t % slot;
            assert!(
                into >= pp.offset_ms && into < pp.offset_ms + 500,
                "{into} {pp:?}"
            );
        }
    }

    #[test]
    fn failures_back_off_and_rest_success_starts_over() {
        let slot = 5_000;
        let mut a = Book::new();
        let t = [Target {
            secret: S,
            key: B,
            wanted: true,
            heard_ms: 1,
        }];
        let first = sweep(&mut a, &A, &t, 0, 20 * slot, slot).len();
        assert_eq!(first, 20, "level 0: every slot while nothing failed");
        for _ in 0..3 {
            a.result(&B, false, 0);
        }
        assert_eq!(level(true, a.failures(&B)), 1);
        let after = sweep(&mut a, &A, &t, 20 * slot, 40 * slot, slot).len();
        assert_eq!(after, 10, "level 1: every other slot");
        a.result(&B, true, 0);
        assert_eq!(a.failures(&B), 0);
        for _ in 0..REST_AFTER {
            a.result(&B, false, 1_000);
        }
        assert!(
            sweep(&mut a, &A, &t, 40 * slot, 60 * slot, slot).is_empty(),
            "resting"
        );
        assert!(!sweep(
            &mut a,
            &A,
            &t,
            REST_MS + 1_000,
            REST_MS + 1_000 + 2 * slot,
            slot
        )
        .is_empty());
        a.fresh(&B);
        assert_eq!(a.failures(&B), 0);
    }

    #[test]
    fn limits_per_slot_per_day_and_idle_targets() {
        let slot = 5_000;
        // Twelve wanted friends: at most PER_SLOT per slot, the rest deferred.
        let many: Vec<Target> = (1..=12u8)
            .map(|i| Target {
                secret: S,
                key: [i; 32],
                wanted: true,
                heard_ms: u64::from(i),
            })
            .collect();
        let mut book = Book::new();
        let mut per_slot: HashMap<u64, usize> = HashMap::new();
        let mut deferred = 0;
        let mut t = 0;
        while t < 10 * slot {
            let d = book.due(&A, &many, t, slot);
            *per_slot.entry(t / slot).or_default() += d.dial.len();
            deferred += d.deferred;
            t += 250;
        }
        assert!(per_slot.values().all(|n| *n <= PER_SLOT), "{per_slot:?}");
        assert!(deferred > 0);
        // Idle: only the IDLE_TARGETS most recently heard ever dial.
        let idle: Vec<Target> = (1..=12u8)
            .map(|i| Target {
                secret: S,
                key: [i; 32],
                wanted: false,
                heard_ms: u64::from(i),
            })
            .collect();
        let mut book = Book::new();
        let dialled: std::collections::HashSet<[u8; 32]> =
            sweep(&mut book, &A, &idle, 0, 200 * slot, slot)
                .into_iter()
                .map(|(_, k)| k)
                .collect();
        assert!(dialled.len() <= IDLE_TARGETS, "{}", dialled.len());
        assert!(dialled.iter().all(|k| k[0] > 12 - IDLE_TARGETS as u8));
        // Per day: a wanted friend at level 0 stops at DAILY_PER_CONTACT.
        let mut book = Book::new();
        let one = [Target {
            secret: S,
            key: B,
            wanted: true,
            heard_ms: 1,
        }];
        let n = sweep(&mut book, &A, &one, 0, 300 * slot, slot).len();
        assert_eq!(n, DAILY_PER_CONTACT as usize);
        // Never toward itself.
        let mut book = Book::new();
        let me = [Target {
            secret: S,
            key: A,
            wanted: true,
            heard_ms: 1,
        }];
        assert!(sweep(&mut book, &A, &me, 0, 10 * slot, slot).is_empty());
    }

    #[test]
    fn reset_lets_the_current_slot_dial_again() {
        let slot = 5_000;
        let mut book = Book::new();
        let t = [Target {
            secret: S,
            key: B,
            wanted: true,
            heard_ms: 1,
        }];
        let pp = pair_phase(&A, &B, &S, 0, slot);
        let now = 10 * slot + pp.offset_ms;
        assert_eq!(book.due(&A, &t, now, slot).dial, vec![B]);
        assert!(
            book.due(&A, &t, now + 100, slot).dial.is_empty(),
            "once per slot"
        );
        book.reset();
        assert_eq!(book.due(&A, &t, now + 200, slot).dial, vec![B]);
        book.retain(&[]);
        assert_eq!(book.failures(&B), 0);
    }
}
