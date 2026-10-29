//! Deterministic estimators of the learning core (design "Phase 6a",
//! algorithms §1, §2 and the `Rtt`/`Encounter` parts of §4 and §7):
//!
//! - [`decay_q16`]: `2^(−Δ/H)` in Q16 from a 64-entry table, Δ clamped to
//!   [0, [`MAX_DT_MS`]], so a clock jump forward only forgets and a step back
//!   forgets nothing;
//! - [`Beta`]: a decayed Beta estimate in milli-observations with a count
//!   cap (about 8 observations) and a recovery streak;
//! - [`Rtt`]: RFC 6298 smoothing (first sample `srtt = R, rttvar = R/2`)
//!   with an expiry backoff of at most ×8; `wait.rs` turns it into a wait;
//! - [`Encounter`]: PRoPHET-style predictability of meeting a contact again
//!   (own encounters only, no transitivity), links within [`ENC_GAP_MS`]
//!   merged;
//! - [`ewma_ms`]: the integer EWMA of the dial costs.
//!
//! Pure: no I/O and no clock read (`now_ms` is passed in, from
//! `raven_core::clock` at the caller), integers only (the parent module
//! denies float arithmetic), so the simulator and every platform give the
//! same numbers.

use serde::{Deserialize, Serialize};

/// One day in milliseconds.
pub const DAY_MS: u64 = 86_400_000;
/// The longest Δ any estimate ages by: a forward clock jump beyond it
/// forgets no more than 30 days would.
pub const MAX_DT_MS: u64 = 30 * DAY_MS;
/// Half-life of the route arms (OD6a-3 option (a)).
pub const HALF_LIFE_MS: u64 = DAY_MS;
/// Half-life of the carry rows: receipts for carried copies come late.
pub const CARRY_HALF_LIFE_MS: u64 = 7 * DAY_MS;
/// Half-life of encounter predictability (PRoPHET's γ = 2^(−1/72) per hour).
pub const ENC_HALF_LIFE_MS: u64 = 3 * DAY_MS;
/// Count cap of a [`Beta`] in milli-observations: `a + b` above it is scaled
/// back, keeping the ratio (an effective window of about 8 observations).
pub const N_CAP_M: u32 = 8_000;
/// The route arms' prior `(A0, B0)` in milli-observations (mean 0.5).
pub const PRIOR_M: (u32, u32) = (1_000, 1_000);
/// Lowest success probability the ranker's index uses (`rank.rs`); the
/// prior keeps [`Beta::mean_ppm`] above it for [`PRIOR_M`] rows anyway.
pub const P_FLOOR_PPM: u32 = 20_000;
/// Links with the same contact within this gap of the last one are one
/// encounter.
pub const ENC_GAP_MS: u64 = 30 * 60_000;
/// Predictability added by one encounter: `p ← p + (1 − p)·P_ENC`, 0.5.
pub const P_ENC_Q16: u32 = 32_768;
/// 1.0 in Q16.
pub const Q16_ONE: u32 = 65_536;
/// RFC 6298's clock-granularity floor of the variance term:
/// `RTO = srtt + max(RTO_G_MS, 4·rttvar)`.
pub const RTO_G_MS: u32 = 200;
/// [`Rtt::expired`] doubles the wait at most three times (×8).
pub const MAX_BACKOFF: u8 = 3;

/// `round(65536 · 2^(−i/64))`, i = 0..63 (design §1; the KAT in the tests).
const POW2_NEG_Q16: [u32; 64] = [
    65536, 64830, 64132, 63441, 62757, 62081, 61413, 60751, 60097, 59449, 58809, 58176, 57549,
    56929, 56316, 55709, 55109, 54515, 53928, 53347, 52773, 52204, 51642, 51085, 50535, 49991,
    49452, 48920, 48393, 47871, 47356, 46846, 46341, 45842, 45348, 44859, 44376, 43898, 43425,
    42958, 42495, 42037, 41584, 41136, 40693, 40255, 39821, 39392, 38968, 38548, 38133, 37722,
    37316, 36914, 36516, 36123, 35734, 35349, 34968, 34591, 34219, 33850, 33486, 33125,
];

/// `2^(−dt/half)` in Q16 (65536 = 1.0): whole half-lives shift, the rest
/// steps through [`POW2_NEG_Q16`] in 1/64 of a half-life. `dt` is clamped
/// to [`MAX_DT_MS`]; 32 half-lives or more give 0. Monotone non-increasing
/// in `dt`. A zero `half` is read as 1 ms (no panic).
pub fn decay_q16(dt_ms: u64, half_ms: u64) -> u32 {
    let half = half_ms.max(1);
    let dt = dt_ms.min(MAX_DT_MS);
    let halvings = dt / half;
    if halvings >= 32 {
        return 0;
    }
    // (dt % half) < half, so the step is in 0..64.
    let step = u128::from(dt % half) * 64 / u128::from(half);
    POW2_NEG_Q16[step as usize] >> halvings
}

/// `x · f` for a Q16 factor `f` ≤ 1.0 (rounded down).
fn mul_q16(x: u32, f: u32) -> u32 {
    ((u64::from(x) * u64::from(f)) >> 16) as u32
}

/// A decayed Beta estimate of a success probability (design §2). `a_m` and
/// `b_m` are success and failure evidence in milli-observations, `at_ms`
/// the time they were last aged to, `streak` the successes in a row.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Beta {
    pub a_m: u32,
    pub b_m: u32,
    pub at_ms: u64,
    pub streak: u8,
}

impl Beta {
    /// Ages both counts by `decay_q16(now − at, half)`; a time before `at`
    /// (clock stepped back) ages nothing, and `at` never moves back.
    pub fn age(&mut self, now_ms: u64, half_ms: u64) {
        let f = decay_q16(now_ms.saturating_sub(self.at_ms), half_ms);
        self.a_m = mul_q16(self.a_m, f);
        self.b_m = mul_q16(self.b_m, f);
        self.at_ms = self.at_ms.max(now_ms);
    }

    /// A success of weight `w_m`, after ageing: a second success in a row
    /// halves the failure evidence (recovery), then `a += w`, then the cap.
    pub fn success(&mut self, w_m: u32, now_ms: u64, half_ms: u64) {
        self.age(now_ms, half_ms);
        if self.streak >= 1 {
            self.b_m /= 2;
        }
        self.streak = self.streak.saturating_add(1);
        self.a_m = self.a_m.saturating_add(w_m);
        self.cap();
    }

    /// A failure of weight `w_m`, after ageing: the streak ends, `b += w`,
    /// then the cap.
    pub fn failure(&mut self, w_m: u32, now_ms: u64, half_ms: u64) {
        self.age(now_ms, half_ms);
        self.streak = 0;
        self.b_m = self.b_m.saturating_add(w_m);
        self.cap();
    }

    /// Count-based forgetting: above [`N_CAP_M`] both counts are scaled by
    /// `N_CAP / (a + b)` (rounded down), so the ratio is kept.
    fn cap(&mut self) {
        let n = u64::from(self.a_m) + u64::from(self.b_m);
        let cap = u64::from(N_CAP_M);
        if n > cap {
            self.a_m = (u64::from(self.a_m) * cap / n) as u32;
            self.b_m = (u64::from(self.b_m) * cap / n) as u32;
        }
    }

    /// Posterior mean in parts per million, `(a + A0)·10⁶ / (a + b + A0 +
    /// B0)`. No floor here: [`P_FLOOR_PPM`] is applied by the ranker's
    /// index. No evidence and a zero prior give 500 000.
    pub fn mean_ppm(&self, prior: (u32, u32)) -> u32 {
        let num = u64::from(self.a_m) + u64::from(prior.0);
        let den = num + u64::from(self.b_m) + u64::from(prior.1);
        if den == 0 {
            return 500_000;
        }
        (num * 1_000_000 / den) as u32
    }

    /// Total evidence `a + b` in milli-observations.
    pub fn evidence_m(&self) -> u32 {
        self.a_m.saturating_add(self.b_m)
    }

    /// Load-time clamp of a stored row: an `at_ms` in the future becomes
    /// `now_ms` (it could otherwise hold off ageing) and counts above the cap
    /// are scaled back. `false`: nothing is left to learn from (`a + b` is
    /// 0) and the caller drops the row.
    pub fn sanitize(&mut self, now_ms: u64) -> bool {
        self.at_ms = self.at_ms.min(now_ms);
        self.cap();
        self.evidence_m() > 0
    }
}

/// RFC 6298 round-trip estimate of one wait (design §4): `srtt` and
/// `rttvar` in ms, `n` samples, `backoff` expiries since the last sample
/// (0..=[`MAX_BACKOFF`]), `at_ms` the time of the last sample.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rtt {
    pub srtt_ms: u32,
    pub rttvar_ms: u32,
    pub n: u16,
    pub backoff: u8,
    pub at_ms: u64,
}

impl Rtt {
    /// One sample `r_ms`: the first gives `srtt = R, rttvar = R/2`; later
    /// ones `rttvar = (3·rttvar + |srtt − R|)/4` (with the old `srtt`), then
    /// `srtt = (7·srtt + R)/8`. A sample clears the backoff.
    pub fn sample(&mut self, r_ms: u32, now_ms: u64) {
        if self.n == 0 {
            self.srtt_ms = r_ms;
            self.rttvar_ms = r_ms / 2;
        } else {
            let (srtt, r) = (u64::from(self.srtt_ms), u64::from(r_ms));
            self.rttvar_ms = ((3 * u64::from(self.rttvar_ms) + srtt.abs_diff(r)) / 4) as u32;
            self.srtt_ms = ((7 * srtt + r) / 8) as u32;
        }
        self.n = self.n.saturating_add(1);
        self.backoff = 0;
        self.at_ms = now_ms;
    }

    /// The wait ran out (no connect or no reply in time): one more doubling,
    /// at most [`MAX_BACKOFF`].
    pub fn expired(&mut self) {
        self.backoff = self.backoff.saturating_add(1).min(MAX_BACKOFF);
    }

    /// `RTO = srtt + max(RTO_G_MS, 4·rttvar)`, saturating.
    pub fn rto_ms(&self) -> u32 {
        self.srtt_ms
            .saturating_add(RTO_G_MS.max(self.rttvar_ms.saturating_mul(4)))
    }
}

/// Predictability of meeting a contact again (design §7): `p_q16` as of
/// `at_ms`, `last_ms` the last link seen (for the merge gap).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Encounter {
    pub p_q16: u32,
    pub at_ms: u64,
    pub last_ms: u64,
}

impl Encounter {
    /// An authenticated link with the contact at `now_ms`. Within
    /// [`ENC_GAP_MS`] of the last link (or before it: clock stepped back) it
    /// is the same encounter: only `last_ms` moves and the result is
    /// `false`. Otherwise `p` ages by [`ENC_HALF_LIFE_MS`] and then gains
    /// `(1 − p)·P_ENC`, so it never exceeds 1.0.
    pub fn meet(&mut self, now_ms: u64) -> bool {
        let met_before = self.p_q16 > 0;
        if met_before && now_ms.saturating_sub(self.last_ms) < ENC_GAP_MS {
            self.last_ms = self.last_ms.max(now_ms);
            return false;
        }
        let p = self.predict_q16(now_ms);
        self.p_q16 = p + mul_q16(Q16_ONE - p, P_ENC_Q16);
        self.at_ms = self.at_ms.max(now_ms);
        self.last_ms = self.last_ms.max(now_ms);
        true
    }

    /// `p · decay(now − at, ENC_HALF_LIFE_MS)`, at most 1.0 (65536).
    pub fn predict_q16(&self, now_ms: u64) -> u32 {
        let f = decay_q16(now_ms.saturating_sub(self.at_ms), ENC_HALF_LIFE_MS);
        mul_q16(self.p_q16.min(Q16_ONE), f)
    }
}

/// `old + (sample − old) / 2^shift` toward `sample` (rounded toward `old`),
/// never past `sample` and never overflowing: shift 2 is α = 1/4, shift 3
/// the 1/8 relaxation. A shift of 32 or more leaves `old`.
pub fn ewma_ms(old: u32, sample: u32, shift: u8) -> u32 {
    let step = |d: u32| d.checked_shr(u32::from(shift)).unwrap_or(0);
    if sample >= old {
        old + step(sample - old)
    } else {
        old - step(old - sample)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    const H: u64 = HALF_LIFE_MS;
    const T0: u64 = 1_000 * DAY_MS;

    fn beta(a_m: u32, b_m: u32, at_ms: u64, streak: u8) -> Beta {
        Beta {
            a_m,
            b_m,
            at_ms,
            streak,
        }
    }

    #[test]
    fn decay_table_is_the_kat() {
        assert_eq!(decay_q16(0, H), 65_536);
        assert_eq!(decay_q16(H, H), 32_768);
        assert_eq!(decay_q16(2 * H, H), 16_384);
        assert_eq!(decay_q16(32 * H, H), 0);
        // 32 half-lives of a short half-life, inside the 30 d clamp.
        assert_eq!(decay_q16(32 * 60_000, 60_000), 0);
        assert_eq!(decay_q16(16 * 60_000, 60_000), 1);
        assert_eq!(decay_q16(17 * 60_000, 60_000), 0);
        // Fractions step through the table: 1/64 and 1/2 of a half-life.
        assert_eq!(decay_q16(H / 64, H), 64_830);
        assert_eq!(decay_q16(H / 2, H), 46_341);
        assert_eq!(decay_q16(H + H / 2, H), 46_341 >> 1);
        // Three days at the encounter half-life is one halving.
        assert_eq!(decay_q16(3 * DAY_MS, ENC_HALF_LIFE_MS), 32_768);
        // No panic at the edges: zero half-life, the largest Δ.
        assert_eq!(decay_q16(0, 0), 65_536);
        assert_eq!(decay_q16(1, 0), 32_768);
        assert_eq!(decay_q16(u64::MAX, 0), 0);
        assert_eq!(
            decay_q16(u64::MAX, u64::MAX),
            decay_q16(MAX_DT_MS, u64::MAX)
        );
        assert_eq!(decay_q16(u64::MAX, H), 0);

        // The design's list, entry by entry (round(65536 · 2^(−i/64))).
        let design: [u32; 64] = [
            65536, 64830, 64132, 63441, 62757, 62081, 61413, 60751, 60097, 59449, 58809, 58176,
            57549, 56929, 56316, 55709, 55109, 54515, 53928, 53347, 52773, 52204, 51642, 51085,
            50535, 49991, 49452, 48920, 48393, 47871, 47356, 46846, 46341, 45842, 45348, 44859,
            44376, 43898, 43425, 42958, 42495, 42037, 41584, 41136, 40693, 40255, 39821, 39392,
            38968, 38548, 38133, 37722, 37316, 36914, 36516, 36123, 35734, 35349, 34968, 34591,
            34219, 33850, 33486, 33125,
        ];
        assert_eq!(POW2_NEG_Q16, design);
        // Strictly decreasing, and the step after the last entry is the
        // next half-life (32768), so the curve has no jump up at H.
        assert!(POW2_NEG_Q16.windows(2).all(|w| w[0] > w[1]));
        assert!(POW2_NEG_Q16[63] > 32_768);
        // Each step is 2^(−1/64) ≈ 0.98923 to within table rounding.
        for w in POW2_NEG_Q16.windows(2) {
            let ratio = u64::from(w[1]) * 100_000 / u64::from(w[0]);
            assert!((98_910..=98_935).contains(&ratio), "{w:?} {ratio}");
        }

        // Monotone non-increasing over 10 000 seeded points per half-life.
        let mut rng = StdRng::seed_from_u64(0x5236_4c52_4e31);
        for half in [H, CARRY_HALF_LIFE_MS, ENC_HALF_LIFE_MS, 7_777, 1] {
            let mut dts: Vec<u64> = (0..10_000)
                .map(|_| rng.gen_range(0..=33 * half.min(MAX_DT_MS)))
                .collect();
            dts.extend([0, half - 1, half, half + 1, MAX_DT_MS, MAX_DT_MS + 1]);
            dts.sort_unstable();
            let ys: Vec<u32> = dts.iter().map(|&dt| decay_q16(dt, half)).collect();
            assert!(ys.iter().all(|&y| y <= 65_536));
            for (i, w) in ys.windows(2).enumerate() {
                assert!(w[0] >= w[1], "half {half}: {} -> {}", dts[i], dts[i + 1]);
            }
        }
    }

    #[test]
    fn beta_update_table() {
        // (start, success?, weight, want); every row at the row's own `at`,
        // so ageing is the identity and only the update rule shows.
        let rows: [(Beta, bool, u32, Beta); 9] = [
            // First success: no streak yet, so b stays; streak 1.
            (beta(0, 0, T0, 0), true, 1_000, beta(1_000, 0, T0, 1)),
            // A failure ends the streak and adds to b.
            (
                beta(1_000, 0, T0, 1),
                false,
                1_000,
                beta(1_000, 1_000, T0, 0),
            ),
            // Weighted failures (E3 −500, offline −250).
            (
                beta(1_000, 1_000, T0, 0),
                false,
                500,
                beta(1_000, 1_500, T0, 0),
            ),
            (
                beta(1_000, 1_500, T0, 0),
                false,
                250,
                beta(1_000, 1_750, T0, 0),
            ),
            // A success after a failure: streak 0, so b is kept.
            (
                beta(1_000, 1_000, T0, 0),
                true,
                1_000,
                beta(2_000, 1_000, T0, 1),
            ),
            // The second success in a row halves b (recovery streak).
            (
                beta(2_000, 1_000, T0, 1),
                true,
                1_000,
                beta(3_000, 500, T0, 2),
            ),
            (
                beta(3_000, 3_000, T0, 2),
                true,
                500,
                beta(3_500, 1_500, T0, 3),
            ),
            // Cap: 6000 + 3000 > 8000 scales both by 8000/9000 (ratio 2:1).
            (
                beta(6_000, 2_000, T0, 0),
                false,
                1_000,
                beta(5_333, 2_666, T0, 0),
            ),
            // Cap on a success: b halved first, then 8500 + 500 > 8000.
            (
                beta(7_500, 1_000, T0, 1),
                true,
                1_000,
                beta(7_555, 444, T0, 2),
            ),
        ];
        for (i, (start, ok, w, want)) in rows.into_iter().enumerate() {
            let mut b = start;
            if ok {
                b.success(w, T0, H);
            } else {
                b.failure(w, T0, H);
            }
            assert_eq!(b, want, "row {i}");
            assert!(b.evidence_m() <= N_CAP_M, "row {i}");
        }
        // The cap keeps the ratio: many successes against a fixed failure
        // share never push a + b past the cap.
        let mut b = Beta::default();
        for i in 0..100u32 {
            if i % 4 == 0 {
                b.failure(1_000, T0, H);
            } else {
                b.success(1_000, T0, H);
            }
            assert!(b.evidence_m() <= N_CAP_M);
        }
        // The streak saturates instead of wrapping.
        let mut b = beta(0, 0, T0, u8::MAX);
        b.success(1_000, T0, H);
        assert_eq!(b.streak, u8::MAX);
        // Ageing by one half-life halves both counts, then the update.
        let mut b = beta(4_000, 2_000, T0, 0);
        b.failure(1_000, T0 + H, H);
        assert_eq!(b, beta(2_000, 2_000, T0 + H, 0));
    }

    #[test]
    fn beta_clock_back_never_extends() {
        // `at` in the future (the clock stepped back): Δ = 0, `at` kept.
        let start = beta(4_000, 2_000, T0 + 10 * DAY_MS, 1);
        let mut b = start;
        b.age(T0, H);
        assert_eq!(b, start);
        b.failure(1_000, T0 + DAY_MS, H);
        assert_eq!(b, beta(4_000, 3_000, T0 + 10 * DAY_MS, 0));
        // Once the clock passes `at`, ageing runs from `at`, not from the
        // earlier readings.
        b.age(T0 + 11 * DAY_MS, H);
        assert_eq!(b, beta(2_000, 1_500, T0 + 11 * DAY_MS, 0));
        // A mean is never raised by a step back.
        let mean = b.mean_ppm(PRIOR_M);
        b.age(T0, H);
        assert_eq!(b.mean_ppm(PRIOR_M), mean);
    }

    #[test]
    fn beta_forward_jump_clamps_to_30_days() {
        let start = beta(8_000, 0, T0, 0);
        let aged = |dt: u64, half: u64| {
            let mut b = start;
            b.age(T0 + dt, half);
            b
        };
        // Carry half-life (7 d): 30 d = 4 halvings + 2 d, table step 18.
        let thirty = aged(MAX_DT_MS, CARRY_HALF_LIFE_MS);
        assert_eq!(decay_q16(MAX_DT_MS, CARRY_HALF_LIFE_MS), 53_928 >> 4);
        assert_eq!(thirty.a_m, 411);
        assert_eq!(thirty.at_ms, T0 + MAX_DT_MS);
        for jump in [MAX_DT_MS + 1, 365 * DAY_MS, u64::MAX - T0] {
            let b = aged(jump, CARRY_HALF_LIFE_MS);
            assert_eq!((b.a_m, b.b_m), (thirty.a_m, thirty.b_m), "{jump}");
            assert_eq!(b.at_ms, T0 + jump);
        }
        // At the arm half-life a 30 d jump forgets everything (2^-30).
        assert_eq!(aged(365 * DAY_MS, H).evidence_m(), 0);
        // A jump only forgets: the mean moves toward the prior, never past.
        let mut b = beta(1_000, 7_000, T0, 0);
        let before = b.mean_ppm(PRIOR_M);
        b.age(T0 + 365 * DAY_MS, CARRY_HALF_LIFE_MS);
        let after = b.mean_ppm(PRIOR_M);
        assert!(before < after && after <= 500_000, "{before} {after}");
    }

    #[test]
    fn mean_floor_and_prior() {
        // No evidence: the prior's mean.
        assert_eq!(Beta::default().mean_ppm(PRIOR_M), 500_000);
        assert_eq!(Beta::default().mean_ppm((1_400, 600)), 700_000);
        assert_eq!(Beta::default().mean_ppm((800, 1_200)), 400_000);
        assert_eq!(Beta::default().mean_ppm((0, 0)), 500_000);
        // (a + A0)·10⁶ / (a + b + A0 + B0).
        assert_eq!(beta(3_000, 1_000, T0, 0).mean_ppm(PRIOR_M), 666_666);
        assert_eq!(beta(8_000, 0, T0, 0).mean_ppm(PRIOR_M), 900_000);
        // The worst row under the cap: the prior keeps the mean at 0.1, far
        // above the index floor, for both arm and carry priors.
        let worst = beta(0, N_CAP_M, T0, 0);
        assert_eq!(worst.mean_ppm(PRIOR_M), 100_000);
        assert_eq!(worst.mean_ppm((800, 1_200)), 80_000);
        assert!(worst.mean_ppm(PRIOR_M) > P_FLOOR_PPM);
        // Without a prior the raw mean reaches 0, which is why the ranker
        // floors its index at P_FLOOR_PPM.
        assert_eq!(worst.mean_ppm((0, 0)), 0);
        assert_eq!(worst.mean_ppm((0, 0)).max(P_FLOOR_PPM), P_FLOOR_PPM);
        // Never above 10⁶, even from out-of-range counts.
        assert_eq!(beta(u32::MAX, 0, T0, 0).mean_ppm((u32::MAX, 0)), 1_000_000);
        assert_eq!(
            beta(u32::MAX, u32::MAX, T0, 0).evidence_m(),
            u32::MAX,
            "evidence saturates"
        );
    }

    #[test]
    fn beta_sanitize_clamps_on_load() {
        // A future `at` and counts over the cap are clamped, ratio kept.
        let mut b = beta(u32::MAX, u32::MAX, T0 + DAY_MS, 9);
        assert!(b.sanitize(T0));
        assert_eq!(b, beta(4_000, 4_000, T0, 9));
        // An in-range row is left as it is.
        let mut b = beta(3_000, 1_000, T0 - DAY_MS, 2);
        assert!(b.sanitize(T0));
        assert_eq!(b, beta(3_000, 1_000, T0 - DAY_MS, 2));
        // Nothing to learn from: the caller drops it.
        let mut b = beta(0, 0, T0 + DAY_MS, 0);
        assert!(!b.sanitize(T0));
        assert_eq!(b.at_ms, T0);
    }

    #[test]
    fn rtt_follows_rfc6298() {
        let mut r = Rtt::default();
        // (sample, srtt, rttvar, rto), integer RFC 6298 step by step.
        for (i, (sample, srtt, rttvar, rto)) in [
            (100, 100, 50, 300),
            (120, 102, 42, 302),
            (80, 99, 37, 299),
            (300, 124, 78, 436),
        ]
        .into_iter()
        .enumerate()
        {
            r.sample(sample, T0 + i as u64);
            assert_eq!((r.srtt_ms, r.rttvar_ms), (srtt, rttvar), "sample {i}");
            assert_eq!(r.rto_ms(), rto, "sample {i}");
            assert_eq!(r.n, i as u16 + 1);
            assert_eq!(r.at_ms, T0 + i as u64);
        }
        // Steady samples shrink the variance to the 200 ms granularity
        // floor.
        for _ in 0..64 {
            r.sample(124, T0);
        }
        assert_eq!(r.srtt_ms, 124);
        assert_eq!(r.rto_ms(), 124 + RTO_G_MS);
        // Extremes saturate instead of overflowing.
        let mut r = Rtt::default();
        r.sample(u32::MAX, T0);
        r.sample(0, T0);
        r.sample(u32::MAX, T0);
        assert_eq!(r.rto_ms(), u32::MAX);
        let mut r = Rtt {
            n: u16::MAX,
            ..Rtt::default()
        };
        r.sample(10, T0);
        assert_eq!(r.n, u16::MAX);
    }

    #[test]
    fn rtt_backoff_caps_at_three() {
        let mut r = Rtt::default();
        r.sample(500, T0);
        for want in [1, 2, 3, 3, 3] {
            r.expired();
            assert_eq!(r.backoff, want);
        }
        // Expiry leaves the estimate itself alone.
        assert_eq!((r.srtt_ms, r.rttvar_ms, r.n), (500, 250, 1));
        // A sample clears the backoff.
        r.sample(500, T0 + 1);
        assert_eq!(r.backoff, 0);
        // A corrupt stored backoff is still held at the cap.
        let mut r = Rtt {
            backoff: u8::MAX,
            ..Rtt::default()
        };
        r.expired();
        assert_eq!(r.backoff, MAX_BACKOFF);
    }

    #[test]
    fn encounter_merge_aging_and_bound() {
        let mut e = Encounter::default();
        assert_eq!(e.predict_q16(T0), 0);
        // First link counts; a second 10 min later is the same encounter.
        assert!(e.meet(T0));
        assert_eq!(e.p_q16, P_ENC_Q16);
        assert!(!e.meet(T0 + 10 * 60_000));
        assert_eq!(e.p_q16, P_ENC_Q16);
        assert_eq!((e.at_ms, e.last_ms), (T0, T0 + 10 * 60_000));
        // The gap runs from the last link, so a session of links every
        // 20 min stays one encounter.
        assert!(!e.meet(T0 + 30 * 60_000));
        assert_eq!(e.p_q16, P_ENC_Q16);
        // A clock step back is merged too, and moves nothing back.
        assert!(!e.meet(T0 - DAY_MS));
        assert_eq!((e.at_ms, e.last_ms), (T0, T0 + 30 * 60_000));
        // After 3 d the value halves.
        assert_eq!(e.predict_q16(T0 + ENC_HALF_LIFE_MS), P_ENC_Q16 / 2);
        assert_eq!(e.predict_q16(T0 + 2 * ENC_HALF_LIFE_MS), P_ENC_Q16 / 4);
        // A meeting after the gap ages first, then adds (1 − p)·0.5.
        assert!(e.meet(T0 + ENC_HALF_LIFE_MS));
        assert_eq!(e.p_q16, 16_384 + (65_536 - 16_384) / 2);
        assert_eq!(e.at_ms, T0 + ENC_HALF_LIFE_MS);
        // A first meeting early on the lab clock is still counted.
        let mut early = Encounter::default();
        assert!(early.meet(0));
        assert!(early.meet(ENC_GAP_MS));
        // p never exceeds 1.0, however often and however fast they meet.
        let mut e = Encounter::default();
        let mut t = T0;
        for _ in 0..1_000 {
            assert!(e.meet(t));
            assert!(e.p_q16 <= Q16_ONE);
            assert!(e.predict_q16(t) <= Q16_ONE);
            t += ENC_GAP_MS;
        }
        assert!(e.p_q16 > 65_000);
        // An out-of-range stored value is still read as at most 1.0, and a
        // meeting brings it back into range.
        let mut e = Encounter {
            p_q16: u32::MAX,
            at_ms: T0,
            last_ms: T0,
        };
        assert_eq!(e.predict_q16(T0), Q16_ONE);
        assert!(e.meet(T0 + DAY_MS));
        assert!(e.p_q16 <= Q16_ONE);
    }

    #[test]
    fn ewma_steps_and_saturates() {
        // α = 1/4 up and down, rounded toward the old value.
        assert_eq!(ewma_ms(300, 700, 2), 400);
        assert_eq!(ewma_ms(700, 300, 2), 600);
        assert_eq!(ewma_ms(300, 302, 2), 300);
        assert_eq!(ewma_ms(1_500, 5_000, 3), 1_937);
        // Shift 0 jumps to the sample; 32 or more keeps the old value.
        assert_eq!(ewma_ms(300, 700, 0), 700);
        assert_eq!(ewma_ms(300, 700, 32), 300);
        assert_eq!(ewma_ms(300, 700, u8::MAX), 300);
        // Never overflows, never passes the sample.
        assert_eq!(ewma_ms(0, u32::MAX, 1), u32::MAX / 2);
        assert_eq!(ewma_ms(u32::MAX, 0, 1), u32::MAX - u32::MAX / 2);
        let mut v = 0;
        for _ in 0..200 {
            v = ewma_ms(v, u32::MAX, 2);
        }
        assert!(v > u32::MAX - 4);
    }

    #[test]
    fn no_float_in_learning() {
        // The lint itself is the check (the module would not compile with
        // float arithmetic); this keeps it from being dropped and also
        // rejects float types, which the lint does not see.
        let parent = include_str!("../learning.rs");
        assert!(parent.contains("#![deny(clippy::float_arithmetic)]"));
        for (name, src) in [
            ("estimate.rs", include_str!("estimate.rs")),
            ("observe.rs", include_str!("observe.rs")),
            ("model.rs", include_str!("model.rs")),
            ("rank.rs", include_str!("rank.rs")),
            ("explain.rs", include_str!("explain.rs")),
            ("wait.rs", include_str!("wait.rs")),
        ] {
            for ty in [concat!("f", "32"), concat!("f", "64")] {
                let typed = src
                    .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                    .any(|token| token == ty);
                assert!(!typed, "float type {ty} in learning/{name}");
            }
        }
    }
}
