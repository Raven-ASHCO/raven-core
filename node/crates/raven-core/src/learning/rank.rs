//! The learned carrier order (design "Phase 6a", algorithms §3): which of
//! the carriers the static plan already holds is tried first for one
//! contact on this network.
//!
//! - The expected time of trying a carrier is `c = p·ok + (1 − p)·fail`
//!   ([`super::model::Arm`]); the expected time to the first success over
//!   independent tries is smallest when the carriers are sorted by `p / c`
//!   descending. In integers: [`index`] = `p_ppm·10⁶ / max(c_ms, 1)`, with
//!   `p` floored at [`P_FLOOR_PPM`].
//! - Until the contact-network's arms hold [`N_MIN_M`] of evidence the
//!   order is the static one (`cold`).
//! - Otherwise bubble passes start from the order last applied
//!   ([`Model::remember_order`]) and swap neighbours when the later one's
//!   index beats the earlier one's by the margin: 0 when the swap moves
//!   toward the static order, [`MARGIN_PCT`] when it moves away. Ties keep
//!   the current order. This bias toward the static order is the main
//!   "never worse than static" rail.
//! - Nearby is never ranked: [`order`] leaves it out and [`apply`] keeps
//!   its routes in their slots.
//! - [`apply`] is a stable sort of a plan's routes by their carrier's rank,
//!   before the per-object cap (`outbox::plan_object_routes_ranked`); the
//!   plan must still pass [`same_set_as_static`], or the static plan is used
//!   and the contact-network is pinned to it ([`Model::note_contradiction`]).
//!
//! Pure: no I/O and no clock read, integers only.

use super::estimate::{PRIOR_M, P_FLOOR_PPM};
use super::explain::{Detail, State, Tally, Why};
use super::model::{fail_prior_ms, ok_prior_ms, Arm, Model};
use crate::outbox::{OutboxCarrier, OutboxRoute};

/// A swap away from the static order needs the later carrier's index to be
/// this much (percent) above the earlier one's.
pub const MARGIN_PCT: u64 = 25;
/// Evidence (milli-observations) over a contact-network's ranked arms
/// before the order may leave the static one.
pub const N_MIN_M: u32 = 1_500;

const PPM: u64 = 1_000_000;

/// A carrier order and why ([`order`]); `render` gives its reason block
/// (`learning::explain`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Order {
    /// The ranked carriers (never nearby), best first.
    pub carriers: Vec<OutboxCarrier>,
    pub why: Why,
    pub detail: Detail,
}

impl Order {
    /// The static order of `static_carriers` ([`carriers_of`] rules), with
    /// `why` and `state` only: cold, a contradiction pin, or the caller's
    /// off / held / shadow.
    pub fn fixed(static_carriers: &[OutboxCarrier], why: Why, state: State) -> Self {
        Self {
            carriers: groups(static_carriers),
            why,
            detail: Detail {
                state,
                ..Detail::default()
            },
        }
    }

    /// Distinct carriers, none of them nearby: what [`order`] gives. A plan
    /// is never ranked by anything else.
    pub fn well_formed(&self) -> bool {
        self.carriers
            .iter()
            .enumerate()
            .all(|(i, c)| *c != OutboxCarrier::Nearby && !self.carriers[..i].contains(c))
    }
}

/// The distinct carriers of `carriers` in their order, nearby left out.
fn groups(carriers: &[OutboxCarrier]) -> Vec<OutboxCarrier> {
    let mut out: Vec<OutboxCarrier> = Vec::with_capacity(3);
    for c in carriers {
        if *c != OutboxCarrier::Nearby && !out.contains(c) {
            out.push(*c);
        }
    }
    out
}

/// The static carrier order of a plan: its routes' distinct carriers in
/// plan order, nearby left out.
pub fn carriers_of(routes: &[OutboxRoute]) -> Vec<OutboxCarrier> {
    let carriers: Vec<OutboxCarrier> = routes.iter().map(|r| r.carrier).collect();
    groups(&carriers)
}

/// `p_ppm·10⁶ / max(c_ms, 1)` with `c = p·ok + (1 − p)·fail` and `p`
/// clamped to [[`P_FLOOR_PPM`], 10⁶]: larger is better.
pub fn index(p_ppm: u32, ok_ms: u32, fail_ms: u32) -> u64 {
    let p = u64::from(p_ppm).clamp(u64::from(P_FLOOR_PPM), PPM);
    let cost = (p * u64::from(ok_ms) + (PPM - p) * u64::from(fail_ms)) / PPM;
    p * PPM / cost.max(1)
}

/// Should the later carrier (index `lo`) go before the earlier one (`hi`)?
/// By any margin toward the static order, by [`MARGIN_PCT`] away from it.
fn beats(lo: u64, hi: u64, toward_static: bool) -> bool {
    let margin = if toward_static { 0 } else { MARGIN_PCT };
    u128::from(lo) * 100 > u128::from(hi) * u128::from(100 + margin)
}

/// One ranked carrier at `now_ms`.
struct Stat<'a> {
    arm: Option<&'a Arm>,
    p_ppm: u32,
    index: u64,
    evidence_m: u32,
}

impl<'a> Stat<'a> {
    fn of(arm: Option<&'a Arm>, carrier: OutboxCarrier, now_ms: u64) -> Self {
        let (p_ppm, evidence_m, ok, fail) = match arm {
            Some(a) => {
                let beta = a.beta_at(now_ms);
                (
                    beta.mean_ppm(PRIOR_M),
                    beta.evidence_m(),
                    a.ok_ms,
                    a.fail_ms,
                )
            }
            None => (500_000, 0, ok_prior_ms(carrier), fail_prior_ms(carrier)),
        };
        Self {
            arm,
            p_ppm,
            index: index(p_ppm, ok, fail),
            evidence_m,
        }
    }

    /// Failed (`failed`) or successful tries of the last ones.
    fn tally(&self, carrier: OutboxCarrier, failed: bool) -> Option<Tally> {
        let (ok, n) = self.arm?.tries();
        (n > 0).then_some(Tally {
            carrier,
            k: if failed { n - ok } else { ok },
            n,
        })
    }
}

/// Pairs out of static order (static positions).
fn inversions(order: &[usize]) -> usize {
    let mut n = 0;
    for (i, a) in order.iter().enumerate() {
        n += order[i + 1..].iter().filter(|b| *b < a).count();
    }
    n
}

/// The carrier order for `contact` on network `net` (design §3, module
/// doc). `static_carriers` is the static plan's carrier order
/// ([`carriers_of`]); `current` replaces the order the model remembers
/// (callers pass `None`). Returns the static order while cold or pinned.
/// Reads only: callers apply the order and then call
/// [`Model::remember_order`].
pub fn order(
    model: &Model,
    contact: &[u8; 32],
    net: Option<&str>,
    static_carriers: &[OutboxCarrier],
    current: Option<&[OutboxCarrier]>,
    now_ms: u64,
) -> Order {
    let groups = groups(static_carriers);
    let state = model.state;
    let view = model.view(contact, net);
    if view.pinned(now_ms) {
        return Order::fixed(&groups, Why::Contradiction, state);
    }
    let stats: Vec<Stat> = groups
        .iter()
        .map(|c| Stat::of(view.arm(*c), *c, now_ms))
        .collect();
    let evidence: u64 = stats.iter().map(|s| u64::from(s.evidence_m)).sum();
    if evidence < u64::from(N_MIN_M) {
        let why = if state == State::ResetAfterUnreadable {
            Why::Unreadable
        } else {
            Why::Cold
        };
        return Order::fixed(&groups, why, state);
    }
    // Static positions: the current order restricted to the groups, the
    // missing ones appended in static order.
    let remembered = view.current();
    let mut start: Vec<usize> = Vec::with_capacity(groups.len());
    for c in current.or(remembered.as_deref()).unwrap_or_default() {
        if let Some(i) = groups.iter().position(|g| g == c) {
            if !start.contains(&i) {
                start.push(i);
            }
        }
    }
    for i in 0..groups.len() {
        if !start.contains(&i) {
            start.push(i);
        }
    }
    let mut ord = start.clone();
    let n = ord.len();
    for _ in 0..n * n {
        let mut swapped = false;
        for i in 1..n {
            let (hi, lo) = (ord[i - 1], ord[i]);
            if beats(stats[lo].index, stats[hi].index, lo < hi) {
                ord.swap(i - 1, i);
                swapped = true;
            }
        }
        if !swapped {
            break;
        }
    }
    let newest = stats
        .iter()
        .filter_map(|s| s.arm.map(|a| a.last_obs_ms))
        .max();
    let mut detail = Detail {
        state,
        age_s: newest.map(|t| now_ms.saturating_sub(t) / 1_000),
        ..Detail::default()
    };
    let why = if inversions(&ord) < inversions(&start) {
        // Moved back toward the static order: name the carrier that rose.
        if let Some(i) = (0..n).find(|i| ord[*i] != start[*i]) {
            detail.ok = stats[ord[i]].tally(groups[ord[i]], false);
        }
        Why::Recovering
    } else if let Some(i) = (0..n).find(|i| ord[*i] != *i) {
        // Away from it: the static carrier that lost place i, and the one
        // that took it. Failing only when the one that lost failed some of
        // its last tries: with fewer successes alone its estimate is lower
        // too, and "did not answer 0 of the last 2 tries" is no reason.
        let (lost, took) = (i, ord[i]);
        detail.ok = stats[took].tally(groups[took], false);
        let failed = stats[lost].tally(groups[lost], true).filter(|t| t.k > 0);
        if stats[lost].p_ppm < stats[took].p_ppm && failed.is_some() {
            detail.fail = failed;
            Why::Failing
        } else {
            Why::Faster
        }
    } else {
        Why::Kept
    };
    Order {
        carriers: ord.into_iter().map(|i| groups[i]).collect(),
        why,
        detail,
    }
}

/// Reorders `routes` by their carrier's rank in `order` (a stable sort:
/// within a carrier the plan's order stays). Nearby routes keep their
/// slots; a carrier the order does not name goes after the named ones.
pub fn apply(routes: &mut [OutboxRoute], order: &Order) {
    let rank = |c: OutboxCarrier| {
        order
            .carriers
            .iter()
            .position(|o| *o == c)
            .unwrap_or(order.carriers.len())
    };
    // Nearby and onion are never ranked: they keep their places (last).
    let slots: Vec<usize> = (0..routes.len())
        .filter(|i| {
            !matches!(
                routes[*i].carrier,
                OutboxCarrier::Nearby | OutboxCarrier::Onion
            )
        })
        .collect();
    let mut ranked: Vec<OutboxRoute> = slots.iter().map(|i| routes[*i].clone()).collect();
    ranked.sort_by_key(|r| rank(r.carrier));
    for (slot, route) in slots.into_iter().zip(ranked) {
        routes[slot] = route;
    }
}

/// The plan's invariant (design §3): the learned plan has the static plan's
/// length, no route twice, and only routes the rules planned before the cap
/// (`static_uncapped`), so no carrier outside the gates.
pub fn same_set_as_static(
    learned: &[OutboxRoute],
    static_uncapped: &[OutboxRoute],
    static_len: usize,
) -> bool {
    learned.len() == static_len
        && learned
            .iter()
            .enumerate()
            .all(|(i, r)| static_uncapped.contains(r) && !learned[..i].contains(r))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::learning::estimate::Beta;
    use crate::learning::model::ArmKey;
    use crate::learning::observe::{evidence, DialTiming, Evidence, FrameKind, Observation};
    use OutboxCarrier::{Internet, Lan, Nearby, P2p};

    const NOW: u64 = 1_800_000_000_000;
    const BOB: [u8; 32] = [0xB0; 32];
    const ALL3: [OutboxCarrier; 3] = [Lan, Internet, P2p];

    fn obs(carrier: OutboxCarrier, ev: Evidence, total_ms: u32) -> Observation {
        Observation {
            contact: BOB,
            net: Some("home".into()),
            net_changed: false,
            carrier,
            path: None,
            relay: None,
            kind: FrameKind::Message,
            evidence: ev,
            timing: DialTiming {
                connect_ms: None,
                reply_ms: None,
                total_ms,
            },
            karn_exclude: false,
            at_ms: NOW,
        }
    }

    fn rank(m: &Model, carriers: &[OutboxCarrier], current: Option<&[OutboxCarrier]>) -> Order {
        order(m, &BOB, Some("home"), carriers, current, NOW)
    }

    /// An arm with `p` = 5/6 and cost `cost_ms` either way.
    fn arm_costing(carrier: OutboxCarrier, cost_ms: u32) -> (ArmKey, Arm) {
        let mut arm = Arm::new(carrier);
        arm.beta = Beta {
            a_m: 4_000,
            b_m: 0,
            at_ms: NOW,
            streak: 1,
        };
        arm.ok_ms = cost_ms;
        arm.fail_ms = cost_ms;
        arm.last_obs_ms = NOW;
        let key = ArmKey {
            contact: BOB,
            net: Some("home".into()),
            carrier,
        };
        (key, arm)
    }

    fn costs(m: &mut Model, lan_ms: u32, internet_ms: u32) {
        for (c, ms) in [(Lan, lan_ms), (Internet, internet_ms)] {
            let (k, a) = arm_costing(c, ms);
            m.put_arm(&k, a);
        }
    }

    #[test]
    fn cold_start_is_static() {
        let mut m = Model::new_empty([3; 32]);
        let o = rank(&m, &ALL3, None);
        assert_eq!(o.carriers, ALL3);
        assert_eq!((o.why, o.detail), (Why::Cold, Detail::default()));
        assert_eq!(
            o.render(),
            "learn: state=on order=lan,internet,p2p why=cold"
        );
        // Below N_MIN_M (1000 of 1500): still static, even with Internet
        // clearly better.
        m.observe(&obs(Internet, Evidence::Receipt, 200), NOW);
        let o = rank(&m, &ALL3, None);
        assert_eq!((o.carriers.as_slice(), o.why), (ALL3.as_slice(), Why::Cold));
        // Another network or contact is its own (cold) bucket.
        m.observe(&obs(Internet, Evidence::Receipt, 200), NOW);
        m.observe(&obs(Lan, Evidence::Silent, 30_000), NOW);
        assert_eq!(rank(&m, &ALL3, None).carriers, [Internet, Lan, P2p]);
        let elsewhere = order(&m, &BOB, Some("office"), &ALL3, None, NOW);
        assert_eq!(
            (elsewhere.carriers.as_slice(), elsewhere.why),
            (ALL3.as_slice(), Why::Cold)
        );
        let carol = order(&m, &[0xCA; 32], Some("home"), &ALL3, None, NOW);
        assert_eq!(carol.why, Why::Cold);
        // A store that was started over says so.
        let mut reset = Model::new_empty([3; 32]);
        reset.state = State::ResetAfterUnreadable;
        assert_eq!(rank(&reset, &ALL3, None).why, Why::Unreadable);
    }

    /// LAN gets two "no answer"s (the soft row, 250 each) and Internet one
    /// receipt: after the first the evidence (1250) is still cold, after
    /// the second LAN is demoted, and the reason says why.
    #[test]
    fn a_failing_first_carrier_is_demoted_after_two_failures() {
        let mut m = Model::new_empty([3; 32]);
        let static_order = [Lan, Internet];
        m.observe(&obs(Internet, Evidence::Receipt, 800), NOW);
        let no_answer = evidence(
            FrameKind::Message,
            None,
            false,
            Some("lan_no_answer"),
            false,
        );
        m.observe(&obs(Lan, no_answer, 2_000), NOW);
        assert_eq!(rank(&m, &static_order, None).carriers, static_order);
        m.observe(&obs(Lan, no_answer, 2_000), NOW);
        let o = rank(&m, &static_order, None);
        assert_eq!(o.carriers, [Internet, Lan]);
        assert_eq!(o.why, Why::Failing);
        assert_eq!(
            o.render(),
            "learn: state=on order=internet,lan why=failing fail=lan:2/2 ok=internet:1/1 age=0s"
        );
        // Applied and remembered, it stays while nothing changes.
        m.remember_order(&BOB, Some("home"), &o);
        assert_eq!(rank(&m, &static_order, None), o);
    }

    /// Review learning-4: LAN delivered twice, Internet five times and
    /// faster. Internet goes first, but LAN failed none of its tries, so the
    /// reason is that Internet answered sooner, never "LAN did not answer 0
    /// of the last 2 tries".
    #[test]
    fn a_carrier_that_never_failed_is_never_shown_as_failing() {
        let mut m = Model::new_empty([3; 32]);
        let static_order = [Lan, Internet];
        for _ in 0..2 {
            m.observe(&obs(Lan, Evidence::Receipt, 900), NOW);
        }
        for _ in 0..5 {
            m.observe(&obs(Internet, Evidence::Receipt, 300), NOW);
        }
        let o = rank(&m, &static_order, None);
        assert_eq!(o.carriers, [Internet, Lan], "{}", o.render());
        assert_eq!(
            (o.why, o.detail.fail),
            (Why::Faster, None),
            "{}",
            o.render()
        );
        assert!(!o.render().contains("fail="), "{}", o.render());
        assert!(o.render().contains("ok=internet:5/5"), "{}", o.render());
        // One LAN failure among its tries: failing, and it says so.
        m.observe(
            &obs(
                Lan,
                evidence(
                    FrameKind::Message,
                    None,
                    false,
                    Some("NOT_REACHABLE"),
                    false,
                ),
                5_000,
            ),
            NOW,
        );
        let o = rank(&m, &static_order, None);
        assert_eq!(o.carriers, [Internet, Lan], "{}", o.render());
        assert_eq!(o.why, Why::Failing, "{}", o.render());
        assert!(o.render().contains("fail=lan:1/3"), "{}", o.render());
    }

    #[test]
    fn moving_away_needs_25_percent_moving_back_needs_none() {
        let both = [Lan, Internet];
        // Internet exactly 25 % better (1000 ms vs 800 ms): not enough.
        let mut m = Model::new_empty([3; 32]);
        costs(&mut m, 1_000, 800);
        let o = rank(&m, &both, None);
        assert_eq!((o.carriers.as_slice(), o.why), (both.as_slice(), Why::Kept));
        // 28 % better (780 ms): Internet first, as faster (same p).
        costs(&mut m, 1_000, 780);
        let o = rank(&m, &both, None);
        assert_eq!(
            (o.carriers.as_slice(), o.why),
            ([Internet, Lan].as_slice(), Why::Faster)
        );
        assert_eq!(o.detail.fail, None);
        m.remember_order(&BOB, Some("home"), &o);
        // Equal again: the current order stays (a tie keeps it).
        costs(&mut m, 1_000, 1_000);
        assert_eq!(rank(&m, &both, None).carriers, [Internet, Lan]);
        // LAN 1 % better: back to static at once, as recovering.
        costs(&mut m, 1_000, 1_010);
        let back = rank(&m, &both, None);
        assert_eq!(
            (back.carriers.as_slice(), back.why),
            (both.as_slice(), Why::Recovering)
        );
        // The `current` argument overrides what the model remembers.
        costs(&mut m, 1_000, 1_000);
        assert_eq!(rank(&m, &both, Some(&[Lan, Internet])).carriers, both);
        // The pure rule.
        assert!(!beats(125, 100, false) && beats(126, 100, false));
        assert!(!beats(100, 100, true) && beats(101, 100, true));
    }

    #[test]
    fn nearby_keeps_its_static_place() {
        let mut m = Model::new_empty([3; 32]);
        costs(&mut m, 1_000, 100);
        let o = rank(&m, &[Lan, Nearby, Internet, Nearby], None);
        assert_eq!(o.carriers, [Internet, Lan]);
        assert!(o.well_formed());
        let r = |carrier, dial: &str| OutboxRoute {
            carrier,
            dial: dial.into(),
        };
        let mut routes = vec![
            r(Lan, "10.0.0.9:7420"),
            r(Nearby, "nearby:aa"),
            r(Lan, "10.0.0.2:7420"),
            r(Internet, "203.0.113.7:7422"),
        ];
        apply(&mut routes, &o);
        assert_eq!(
            routes,
            vec![
                r(Internet, "203.0.113.7:7422"),
                r(Nearby, "nearby:aa"),
                r(Lan, "10.0.0.9:7420"),
                r(Lan, "10.0.0.2:7420"),
            ]
        );
        // An order naming nearby is not well formed.
        let mut bad = o.clone();
        bad.carriers.push(Nearby);
        assert!(!bad.well_formed());
        bad.carriers = vec![Lan, Lan];
        assert!(!bad.well_formed());
    }

    /// Equal arms keep the order they start from (static, or the current
    /// one), every time, whatever the model's secret.
    #[test]
    fn order_is_deterministic_on_ties() {
        for secret in [[1; 32], [2; 32]] {
            let mut m = Model::new_empty(secret);
            for c in ALL3 {
                let (k, a) = arm_costing(c, 700);
                m.put_arm(&k, a);
            }
            let first = rank(&m, &ALL3, Some(&[P2p, Lan, Internet]));
            for _ in 0..100 {
                let o = rank(&m, &ALL3, None);
                assert_eq!((o.carriers.as_slice(), o.why), (ALL3.as_slice(), Why::Kept));
                let o = rank(&m, &ALL3, Some(&[P2p, Lan, Internet]));
                assert_eq!(o.carriers, [P2p, Lan, Internet]);
                assert_eq!(o, first);
            }
            // The static order decides between equal carriers, not the
            // carriers' own order.
            assert_eq!(
                rank(&m, &[P2p, Internet, Lan], None).carriers,
                [P2p, Internet, Lan]
            );
        }
    }

    #[test]
    fn index_is_p_over_cost() {
        // p = 1: cost is ok_ms.
        assert_eq!(index(1_000_000, 500, 9_000), 2_000_000_000);
        // p floored at 2 %: cost 0.02·100 + 0.98·1000 = 982.
        assert_eq!(index(0, 100, 1_000), 20_000_000_000 / 982);
        // A zero cost cannot divide by zero.
        assert_eq!(index(1_000_000, 0, 0), 1_000_000_000_000);
        // Huge costs do not overflow.
        assert!(index(500_000, u32::MAX, u32::MAX) > 0);
    }

    #[test]
    fn invariant_check() {
        let r = |d: &str| OutboxRoute {
            carrier: Lan,
            dial: d.into(),
        };
        let uncapped = [r("a"), r("b"), r("c")];
        assert!(same_set_as_static(&[r("c"), r("a")], &uncapped, 2));
        assert!(!same_set_as_static(&[r("c")], &uncapped, 2));
        assert!(!same_set_as_static(&[r("c"), r("c")], &uncapped, 2));
        assert!(!same_set_as_static(&[r("c"), r("x")], &uncapped, 2));
        assert!(same_set_as_static(&[], &uncapped, 0));
    }
}
