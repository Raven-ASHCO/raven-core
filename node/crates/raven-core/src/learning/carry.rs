//! The carry choice (design "Phase 6a", algorithms §7): which custodians an
//! object is left with for a recipient, from this node's own encounters and
//! its own receipts. Nothing about who meets whom is ever shared (OD6a-9).
//!
//! - **Encounters** ([`Model::encounter`]): an authenticated link with a
//!   pinned contact (either direction), a beacon answer or a nearby pipe up.
//!   Links within `ENC_GAP` (30 min) of the last one are one encounter, so
//!   a chatty link does not inflate it; the predictability ages with a 3 d
//!   half-life and gains half the rest per encounter (PRoPHET without
//!   transitivity, [`super::estimate::Encounter`]). The caller records them
//!   only while carry choice is live (P6.16).
//! - **Carry rows** ([`Model::carry_outcome`]), per (custodian, recipient),
//!   7 d half-life: a verified receipt for an object held by the set `H`
//!   gives each holder +1000/|H|, an expiry or park without a receipt
//!   −1000/|H|. The prior depends on the candidate: [`PRIOR_ANNOUNCED_M`]
//!   when the recipient announced the custodian, [`PRIOR_LISTED_M`] when only
//!   this node listed it.
//! - **Pick** ([`Model::carry_pick`]): utility `U = predict × carry_mean`
//!   (Q16 × ppm), sorted descending with ties in the static order, the top
//!   `cap` (never more than [`CARRY_CAP`], the envelope's replication
//!   budget). With no encounter for any candidate and no carry evidence for
//!   the recipient it is the static choice (`cold`). The result is always a
//!   subset of the candidates.
//! - **Forwarding** ([`Model::forward_order`]): the next hops in the order
//!   of this node's own predictability of meeting them (order only).
//!
//! Known limit (OD6a-9): a custodian this node meets often but who never
//! meets the recipient looks good until its receipts fail.
//!
//! Pure: no I/O and no clock read, integers only.

use super::estimate::CARRY_HALF_LIFE_MS;
use super::explain::Why;
use super::model::Model;
use super::observe::Weight;

/// At most this many custodians hold one object: today's per-contact limit,
/// equal to the envelope's replication budget (a test pins the two).
pub const CARRY_CAP: usize = crate::custody_client::MAX_CUSTODIANS_PER_CONTACT;
/// Carry prior `(A0, B0)` of a custodian the recipient announced (mean 0.7).
pub const PRIOR_ANNOUNCED_M: (u32, u32) = (1_400, 600);
/// Carry prior of a custodian only this node listed (mean 0.4).
pub const PRIOR_LISTED_M: (u32, u32) = (800, 1_200);
/// One outcome's weight, shared among the holders.
pub const CARRY_W_M: u32 = 1_000;

/// One custodian the static rules allow, in their order (Phase 3
/// `custodian_candidates`): `announced` when the recipient announced it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub key: [u8; 32],
    pub announced: bool,
}

impl Candidate {
    /// A custodian of [`crate::custody_client::custodian_candidates`] with
    /// the custody offer it came with: one the recipient announced has an
    /// offer, one only this node listed has none.
    pub fn of(key: [u8; 32], offer: Option<u8>) -> Self {
        Self {
            key,
            announced: offer.is_some(),
        }
    }
}

/// The reason token of a carry choice (P6.16: raven-node's custody log and
/// `LearningPlan`'s carry rows): `carry=cold` for the static choice
/// ([`Why::Cold`]), `carry=ranked` for a learned one, kept or another.
pub fn carry_token(why: Why) -> &'static str {
    if why == Why::Cold {
        "carry=cold"
    } else {
        "carry=ranked"
    }
}

/// How often this node meets a contact, in the user's words, from its
/// predictability ([`Model::predict_q16`]): `often` from 1/2 (two
/// encounters a few days apart, or one today), `sometimes` from 1/8,
/// `rarely` above 0, `never` (not lately) at 0.
pub fn met_word(p_q16: u32) -> &'static str {
    use super::estimate::Q16_ONE;
    if p_q16 >= Q16_ONE / 2 {
        "often"
    } else if p_q16 >= Q16_ONE / 8 {
        "sometimes"
    } else if p_q16 > 0 {
        "rarely"
    } else {
        "never"
    }
}

impl Model {
    /// What `custodian`'s carry row for `recipient` holds at `now_ms`, in
    /// whole outcomes (its aged, shared weights rounded): (delivered, all).
    /// (0, 0) without a row. For the user's words only ("delivered 3 of 4
    /// before"); the pick reads the row itself.
    pub fn carry_record(
        &self,
        custodian: &[u8; 32],
        recipient: &[u8; 32],
        now_ms: u64,
    ) -> (u32, u32) {
        let Some(row) = self.carry_of(custodian, recipient) else {
            return (0, 0);
        };
        let mut beta = row.beta;
        beta.age(now_ms, CARRY_HALF_LIFE_MS);
        let whole = |m: u32| m.saturating_add(CARRY_W_M / 2) / CARRY_W_M;
        let all = whole(beta.a_m.saturating_add(beta.b_m));
        (whole(beta.a_m).min(all), all)
    }

    /// An encounter with contact `peer` at `now_ms`; `false` when it merged
    /// into the last one (within `ENC_GAP`).
    pub fn encounter(&mut self, peer: &[u8; 32], now_ms: u64) -> bool {
        self.encounter_apply(peer, now_ms)
    }

    /// This node's predictability of meeting `peer` at `now_ms`, Q16; 0 for
    /// a contact never met.
    pub fn predict_q16(&self, peer: &[u8; 32], now_ms: u64) -> u32 {
        self.encounter_of(peer).map_or(0, |e| e.predict_q16(now_ms))
    }

    /// How well `c` delivers for `recipient` at `now_ms` (ppm): its carry
    /// row aged to `now_ms` with the candidate's prior; the prior's mean
    /// without a row.
    pub fn carry_mean_ppm(&self, c: &Candidate, recipient: &[u8; 32], now_ms: u64) -> u32 {
        let prior = if c.announced {
            PRIOR_ANNOUNCED_M
        } else {
            PRIOR_LISTED_M
        };
        let mut beta = self
            .carry_of(&c.key, recipient)
            .map(|r| r.beta)
            .unwrap_or_default();
        beta.age(now_ms, CARRY_HALF_LIFE_MS);
        beta.mean_ppm(prior)
    }

    /// `U = predict × carry_mean` of `c` for `recipient` (Q16 × ppm).
    fn utility(&self, c: &Candidate, recipient: &[u8; 32], now_ms: u64) -> u64 {
        u64::from(self.predict_q16(&c.key, now_ms))
            * u64::from(self.carry_mean_ppm(c, recipient, now_ms))
    }

    /// What became of an object for `recipient` held by `holders`: a
    /// verified receipt (`delivered`) or an expiry or park without one.
    /// Each distinct holder (never the recipient) gets [`CARRY_W_M`]/|H| of
    /// success or failure; no holder is a no-op.
    pub fn carry_outcome(
        &mut self,
        recipient: &[u8; 32],
        holders: &[[u8; 32]],
        delivered: bool,
        now_ms: u64,
    ) {
        let mut held: Vec<[u8; 32]> = Vec::with_capacity(holders.len());
        for h in holders {
            if h != recipient && !held.contains(h) {
                held.push(*h);
            }
        }
        let w = u32::try_from(held.len())
            .ok()
            .filter(|n| *n > 0)
            .map_or(0, |n| CARRY_W_M / n);
        if w == 0 {
            return;
        }
        let weight = if delivered {
            Weight::Success(w)
        } else {
            Weight::Failure(w)
        };
        self.carry_apply(recipient, &held, weight, now_ms);
    }

    /// The custodians to leave an object for `recipient` with, from `cands`
    /// (static order; a repeated key counts once, at its first place): the
    /// top `min(cap, CARRY_CAP)` by utility, ties in static order, and why:
    /// [`Why::Cold`] (the static choice: nothing learned about these
    /// candidates), [`Why::Kept`] (learned, the static choice still) or
    /// [`Why::Faster`] (learned, another choice). Always a subset of
    /// `cands`.
    pub fn carry_pick(
        &self,
        recipient: &[u8; 32],
        cands: &[Candidate],
        cap: usize,
        now_ms: u64,
    ) -> (Vec<[u8; 32]>, Why) {
        let cap = cap.min(CARRY_CAP);
        let mut distinct: Vec<Candidate> = Vec::with_capacity(cands.len());
        for c in cands {
            if !distinct.iter().any(|d| d.key == c.key) {
                distinct.push(*c);
            }
        }
        let static_pick: Vec<[u8; 32]> = distinct.iter().take(cap).map(|c| c.key).collect();
        let cold = distinct.iter().all(|c| {
            self.encounter_of(&c.key).is_none()
                && !self
                    .carry_of(&c.key, recipient)
                    .is_some_and(|r| r.beta.evidence_m() > 0)
        });
        if cold {
            return (static_pick, Why::Cold);
        }
        let mut ranked: Vec<(u64, [u8; 32])> = distinct
            .iter()
            .map(|c| (self.utility(c, recipient, now_ms), c.key))
            .collect();
        // Stable: equal utilities keep the static order.
        ranked.sort_by_key(|(u, _)| std::cmp::Reverse(*u));
        let pick: Vec<[u8; 32]> = ranked.into_iter().take(cap).map(|(_, k)| k).collect();
        let why = if pick == static_pick {
            Why::Kept
        } else {
            Why::Faster
        };
        (pick, why)
    }

    /// `next_hops` in the order of this node's predictability of meeting
    /// each, highest first, ties in the given order: the same hops, only
    /// reordered.
    pub fn forward_order(&self, next_hops: &[[u8; 32]], now_ms: u64) -> Vec<[u8; 32]> {
        let mut hops: Vec<(u32, [u8; 32])> = next_hops
            .iter()
            .map(|h| (self.predict_q16(h, now_ms), *h))
            .collect();
        hops.sort_by_key(|(p, _)| std::cmp::Reverse(*p));
        hops.into_iter().map(|(_, h)| h).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::learning::estimate::{Encounter, ENC_GAP_MS, P_ENC_Q16, Q16_ONE};
    use crate::learning::model::{Arm, CarryRow};
    use crate::outbox::OutboxCarrier;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    const NOW: u64 = 1_800_000_000_000;
    const HOUR: u64 = 3_600_000;
    const BOB: [u8; 32] = [0xB0; 32];
    const CAROL: [u8; 32] = [0xCA; 32];
    const DAVE: [u8; 32] = [0xDA; 32];
    const ERIN: [u8; 32] = [0xE1; 32];

    fn announced(key: [u8; 32]) -> Candidate {
        Candidate {
            key,
            announced: true,
        }
    }

    fn listed(key: [u8; 32]) -> Candidate {
        Candidate {
            key,
            announced: false,
        }
    }

    #[test]
    fn carry_cap_equals_the_envelope_replication_budget() {
        assert_eq!(
            CARRY_CAP,
            usize::from(crate::indexed_session_store::OUTBOUND_REPLICATION_BUDGET)
        );
        assert_eq!(CARRY_CAP, 2);
    }

    #[test]
    fn cold_is_static() {
        let mut m = Model::new_empty([1; 32]);
        let cands = [listed(CAROL), announced(DAVE), announced(ERIN)];
        let want = (vec![CAROL, DAVE], Why::Cold);
        assert_eq!(m.carry_pick(&BOB, &cands, CARRY_CAP, NOW), want);
        // What was learned about others, or about these for another
        // recipient, leaves it cold.
        m.encounter(&[0x55; 32], NOW);
        m.carry_outcome(&[0x66; 32], &[CAROL, ERIN], true, NOW);
        assert_eq!(m.carry_pick(&BOB, &cands, CARRY_CAP, NOW), want);
        assert_eq!(m.carry_pick(&BOB, &cands, 1, NOW), (vec![CAROL], Why::Cold));
        // No candidates, or a cap of 0: nothing.
        assert_eq!(m.carry_pick(&BOB, &[], CARRY_CAP, NOW), (vec![], Why::Cold));
        assert_eq!(m.carry_pick(&BOB, &cands, 0, NOW).0, Vec::<[u8; 32]>::new());
        // A carry row for this recipient ends the cold start; with no
        // encounter every utility is 0, so the order stays static.
        m.carry_outcome(&BOB, &[ERIN], false, NOW);
        assert_eq!(
            m.carry_pick(&BOB, &cands, CARRY_CAP, NOW),
            (vec![CAROL, DAVE], Why::Kept)
        );
    }

    #[test]
    fn frequently_met_announced_carrier_wins() {
        let mut m = Model::new_empty([1; 32]);
        let cands = [announced(CAROL), announced(DAVE), announced(ERIN)];
        for i in 0..3 {
            assert!(m.encounter(&ERIN, NOW + i * HOUR));
        }
        let t = NOW + 3 * HOUR;
        assert_eq!(
            m.carry_pick(&BOB, &cands, CARRY_CAP, t),
            (vec![ERIN, CAROL], Why::Faster)
        );
        assert_eq!(
            m.forward_order(&[CAROL, DAVE, ERIN], t),
            [ERIN, CAROL, DAVE]
        );
        // Met equally often, the one the recipient announced goes before the
        // one only this node listed, whatever the static order.
        let mut m = Model::new_empty([1; 32]);
        m.encounter(&CAROL, NOW);
        m.encounter(&DAVE, NOW);
        let cands = [listed(CAROL), announced(DAVE)];
        assert_eq!(
            m.carry_pick(&BOB, &cands, 1, NOW),
            (vec![DAVE], Why::Faster)
        );
        assert_eq!(
            m.carry_pick(&BOB, &cands, CARRY_CAP, NOW),
            (vec![DAVE, CAROL], Why::Faster)
        );
    }

    /// OD6a-9's worst case: a custodian this node meets often but who never
    /// meets the recipient wins first, then loses once its copies expire
    /// without a receipt.
    #[test]
    fn a_carrier_that_never_delivers_loses_after_receipts_fail() {
        let mut m = Model::new_empty([1; 32]);
        // Carol is first in the static order and met once; Dave four times.
        m.encounter(&CAROL, NOW);
        for i in 0..4 {
            m.encounter(&DAVE, NOW + i * HOUR);
        }
        let cands = [announced(CAROL), announced(DAVE)];
        let mut t = NOW + 4 * HOUR;
        assert_eq!(m.carry_pick(&BOB, &cands, 1, t), (vec![DAVE], Why::Faster));
        let mut failures = 0;
        while m.carry_pick(&BOB, &cands, 1, t).0 == [DAVE] {
            assert!(failures < 4, "Dave never lost");
            m.carry_outcome(&BOB, &[DAVE], false, t);
            failures += 1;
            t += 60_000;
        }
        assert_eq!(failures, 2);
        assert_eq!(m.carry_pick(&BOB, &cands, 1, t), (vec![CAROL], Why::Kept));
        assert!(m.carry_mean_ppm(&announced(DAVE), &BOB, t) < 700_000);
        // Carol delivers: she keeps her place.
        m.carry_outcome(&BOB, &[CAROL], true, t);
        assert_eq!(
            m.carry_pick(&BOB, &cands, CARRY_CAP, t),
            (vec![CAROL, DAVE], Why::Kept)
        );
    }

    #[test]
    fn carry_outcome_splits_the_weight() {
        let mut m = Model::new_empty([1; 32]);
        m.carry_outcome(&BOB, &[], true, NOW);
        m.carry_outcome(&BOB, &[BOB], true, NOW);
        assert!(m.carry_of(&BOB, &BOB).is_none());
        m.carry_outcome(&BOB, &[CAROL, DAVE, CAROL], true, NOW);
        for f in [CAROL, DAVE] {
            let beta = m.carry_of(&f, &BOB).unwrap().beta;
            assert_eq!((beta.a_m, beta.b_m), (500, 0));
        }
        m.carry_outcome(&BOB, &[CAROL], false, NOW);
        let beta = m.carry_of(&CAROL, &BOB).unwrap().beta;
        assert_eq!((beta.a_m, beta.b_m), (500, 1_000));
        // Rows are per recipient.
        assert!(m.carry_of(&CAROL, &ERIN).is_none());
        // 7 d half-life.
        let mut aged = m.carry_of(&DAVE, &BOB).unwrap().beta;
        aged.age(NOW + 7 * 24 * HOUR, CARRY_HALF_LIFE_MS);
        assert_eq!(aged.a_m, 250);
    }

    #[test]
    fn pick_is_a_subset_and_capped() {
        let mut rng = StdRng::seed_from_u64(0xca_77);
        let pool: Vec<[u8; 32]> = (1..=10u8).map(|i| [i; 32]).collect();
        for round in 0..300 {
            let mut m = Model::new_empty([round as u8; 32]);
            let mut t = NOW;
            for _ in 0..rng.gen_range(0..40) {
                t += rng.gen_range(0..12 * HOUR);
                let f = pool[rng.gen_range(0..pool.len())];
                if rng.gen_bool(0.6) {
                    m.encounter(&f, t);
                } else {
                    let g = pool[rng.gen_range(0..pool.len())];
                    m.carry_outcome(&BOB, &[f, g], rng.gen_bool(0.5), t);
                }
            }
            let cands: Vec<Candidate> = (0..rng.gen_range(0..9))
                .map(|_| Candidate {
                    key: pool[rng.gen_range(0..pool.len())],
                    announced: rng.gen_bool(0.5),
                })
                .collect();
            let mut distinct: Vec<[u8; 32]> = Vec::new();
            for c in &cands {
                if !distinct.contains(&c.key) {
                    distinct.push(c.key);
                }
            }
            for cap in 0..=4 {
                let (pick, why) = m.carry_pick(&BOB, &cands, cap, t);
                assert_eq!(pick.len(), cap.min(CARRY_CAP).min(distinct.len()));
                assert!(pick.iter().all(|k| distinct.contains(k)), "{round}");
                let mut unique = pick.clone();
                unique.sort_unstable();
                unique.dedup();
                assert_eq!(unique.len(), pick.len(), "{round}");
                let static_pick: Vec<[u8; 32]> =
                    distinct.iter().take(pick.len()).copied().collect();
                match why {
                    Why::Cold | Why::Kept => assert_eq!(pick, static_pick),
                    Why::Faster => assert_ne!(pick, static_pick),
                    other => panic!("{other:?}"),
                }
            }
        }
    }

    /// P6.16's words for the user: the meeting word by predictability, the
    /// whole outcomes of a carry row (shared weights rounded, aged), and
    /// the reason token of each pick.
    #[test]
    fn met_words_carry_records_and_tokens() {
        assert_eq!(met_word(0), "never");
        assert_eq!(met_word(1), "rarely");
        assert_eq!(met_word(Q16_ONE / 8 - 1), "rarely");
        assert_eq!(met_word(Q16_ONE / 8), "sometimes");
        assert_eq!(met_word(Q16_ONE / 2), "often");
        assert_eq!(met_word(Q16_ONE), "often");
        let mut m = Model::new_empty([1; 32]);
        m.encounter(&CAROL, NOW);
        assert_eq!(met_word(m.predict_q16(&CAROL, NOW)), "often");
        assert_eq!(
            met_word(m.predict_q16(&CAROL, NOW + 3 * 72 * HOUR)),
            "rarely"
        );
        assert_eq!(met_word(m.predict_q16(&DAVE, NOW)), "never");
        assert_eq!(m.carry_record(&CAROL, &BOB, NOW), (0, 0));
        for delivered in [true, true, true, false] {
            m.carry_outcome(&BOB, &[CAROL], delivered, NOW);
        }
        // The recovery streak halves the doubt of a second delivery in a
        // row: the record is the evidence, rounded.
        let beta = m.carry_of(&CAROL, &BOB).unwrap().beta;
        let all = (beta.a_m + beta.b_m + 500) / 1_000;
        assert_eq!(m.carry_record(&CAROL, &BOB, NOW), (3, all));
        assert_eq!(all, 4);
        // Shared with Dave: half each, rounded.
        m.carry_outcome(&BOB, &[DAVE, ERIN], true, NOW);
        assert_eq!(m.carry_record(&DAVE, &BOB, NOW), (1, 1));
        // `Status.learning.carriers` counts these rows.
        assert_eq!(m.sizes().carry, 3);
        // A week on, half of it.
        assert_eq!(m.carry_record(&CAROL, &BOB, NOW + 7 * 24 * HOUR), (2, 2));
        // Per recipient.
        assert_eq!(m.carry_record(&CAROL, &ERIN, NOW), (0, 0));
        assert_eq!(carry_token(Why::Cold), "carry=cold");
        for why in [Why::Kept, Why::Faster] {
            assert_eq!(carry_token(why), "carry=ranked");
        }
        assert_eq!(
            Candidate::of(CAROL, Some(1)),
            Candidate {
                key: CAROL,
                announced: true
            }
        );
        assert!(!Candidate::of(CAROL, None).announced);
    }

    #[test]
    fn merged_encounters_do_not_inflate() {
        let mut m = Model::new_empty([1; 32]);
        assert!(m.encounter(&CAROL, NOW));
        // A link every 10 minutes for 8 hours is one encounter.
        let mut t = NOW;
        for _ in 0..48 {
            t += 10 * 60_000;
            assert!(!m.encounter(&CAROL, t));
        }
        let e = *m.encounter_of(&CAROL).unwrap();
        assert_eq!((e.p_q16, e.at_ms, e.last_ms), (P_ENC_Q16, NOW, t));
        // A link after the gap is a second one.
        assert!(m.encounter(&CAROL, t + ENC_GAP_MS));
        let p = m.encounter_of(&CAROL).unwrap().p_q16;
        assert!(p > P_ENC_Q16 && p < Q16_ONE, "{p}");
        // Many separate encounters approach but never pass 1.0.
        for i in 1..200 {
            m.encounter(&DAVE, NOW + i * ENC_GAP_MS);
        }
        assert!(m.predict_q16(&DAVE, NOW + 200 * ENC_GAP_MS) <= Q16_ONE);
    }

    #[test]
    fn forward_order_is_a_permutation() {
        let mut rng = StdRng::seed_from_u64(0xf0_4d);
        let pool: Vec<[u8; 32]> = (1..=6u8).map(|i| [i; 32]).collect();
        for _ in 0..200 {
            let mut m = Model::new_empty([1; 32]);
            let mut t = NOW;
            for _ in 0..rng.gen_range(0..20) {
                t += rng.gen_range(0..6 * HOUR);
                m.encounter(&pool[rng.gen_range(0..pool.len())], t);
            }
            let hops: Vec<[u8; 32]> = (0..rng.gen_range(0..8))
                .map(|_| pool[rng.gen_range(0..pool.len())])
                .collect();
            let order = m.forward_order(&hops, t);
            let (mut a, mut b) = (hops.clone(), order.clone());
            a.sort_unstable();
            b.sort_unstable();
            assert_eq!(a, b);
            // Highest predictability first; equal ones in the given order.
            let p = |k: &[u8; 32]| m.predict_q16(k, t);
            assert!(order.windows(2).all(|w| p(&w[0]) >= p(&w[1])));
            for v in order.iter().map(p) {
                let with = |hs: &[[u8; 32]]| -> Vec<[u8; 32]> {
                    hs.iter().filter(|h| p(h) == v).copied().collect()
                };
                assert_eq!(with(&order), with(&hops));
            }
        }
        let m = Model::new_empty([1; 32]);
        assert_eq!(m.forward_order(&[DAVE, CAROL], NOW), [DAVE, CAROL]);
        assert!(m.forward_order(&[], NOW).is_empty());
    }

    /// The rows' serialized fields are exactly the design's lists (the arm
    /// also keeps its last tries, P6.5): no hour, weekday or other
    /// time-of-day feature anywhere.
    #[test]
    fn no_time_of_day_feature() {
        fn fields<T: serde::Serialize>(v: &T) -> Vec<String> {
            let value = serde_json::to_value(v).unwrap();
            let mut keys: Vec<String> = value.as_object().unwrap().keys().cloned().collect();
            keys.sort_unstable();
            keys
        }
        fn list(names: &[&str]) -> Vec<String> {
            let mut v: Vec<String> = names.iter().map(|s| s.to_string()).collect();
            v.sort_unstable();
            v
        }
        let rows = [
            (
                fields(&Encounter::default()),
                list(&["p_q16", "at_ms", "last_ms"]),
            ),
            (fields(&CarryRow::default()), list(&["beta"])),
            (
                fields(&Arm::new(OutboxCarrier::Lan)),
                list(&[
                    "beta",
                    "ok_ms",
                    "fail_ms",
                    "connect",
                    "reply",
                    "paths",
                    "last_obs_ms",
                    "last_receipt_ms",
                    "last_probe_ms",
                    "recent",
                    "recent_n",
                ]),
            ),
            (
                fields(&crate::learning::estimate::Beta::default()),
                list(&["a_m", "b_m", "at_ms", "streak"]),
            ),
            (
                fields(&crate::learning::estimate::Rtt::default()),
                list(&["srtt_ms", "rttvar_ms", "n", "backoff", "at_ms"]),
            ),
        ];
        for (got, want) in &rows {
            assert_eq!(got, want);
            for name in got {
                for banned in ["hour", "day", "week", "dow", "tod", "time_of", "median"] {
                    assert!(!name.contains(banned), "{name}");
                }
            }
        }
    }
}
