//! The relay term (design "Phase 6a", algorithms §6): how well each relay
//! has carried this node's p2p traffic, as a small bounded number that relay
//! selection adds to its score (P6.15).
//!
//! - A relay's row ([`super::model::RelayRow`], 1 d half-life) collects a
//!   receipt over a relayed path through it (+[`RECEIPT_W_M`];
//!   [`Model::observe`] drives it too), each circuit outcome of a contact
//!   dial through it ([`circuit_weight`]: no answer, refused or not a relay
//!   −1000, busy −500, the contact not on the relay nothing: the contact is
//!   offline, not the relay at fault), and an authenticated inbound link
//!   that arrived over our reservation on it (+[`RELAY_INBOUND_W_M`]), and
//!   (Phase 6b R8, P6.28's merge amendment) a security event about it, a
//!   `SEC_RELAY_LINK_BROKEN` or a Suspicious `SEC_RELAY_NO_RECEIPT`: −1000,
//!   negative only ([`Model::relay_security`]).
//! - [`term`] is 0 until the row holds [`RELAY_MIN_EVIDENCE_M`] of evidence,
//!   then `clamp((p_ppm − 500 000)·300 / 10⁶, −150, +150)` (±
//!   [`RELAY_TERM_MAX`]). Selection's own terms (probation −1000, cooldown −400, last ok +300,
//!   confirmed +100, availability 0..200, diversity +50 +50) are much
//!   larger, so the term only reorders comparable candidates; it never
//!   starts a change by itself (P6.15 adds it inside `best_standby` only).
//!
//! Pure: no I/O and no clock read, integers only. Relays are kept only as
//! HMAC keys of their PeerId bytes (`learning::model`).

use super::estimate::{HALF_LIFE_MS, PRIOR_M};
use super::model::{Model, RelayRow};
use super::observe::{Weight, FULL_FAIL_W_M, RECEIPT_W_M};
use crate::reach_diag::CircuitOutcome;

/// The term's bound either way, in relay-selection score points.
pub const RELAY_TERM_MAX: i64 = 150;
/// Evidence (milli-observations, aged) a relay row needs before its term
/// is not 0.
pub const RELAY_MIN_EVIDENCE_M: u32 = 3_000;
/// An authenticated inbound link over our reservation on the relay: half a
/// receipt.
pub const RELAY_INBOUND_W_M: u32 = 500;
/// The relay answered that it is full or does not relay for us.
pub const RELAY_BUSY_W_M: u32 = 500;

const PPM: i64 = 1_000_000;

/// What one circuit outcome does to the relay's row: no answer, a refused
/// circuit and a peer that does not relay are full failures, a busy relay
/// half of one, and a contact that holds no reservation there (offline) is
/// no evidence about the relay.
pub fn circuit_weight(outcome: CircuitOutcome) -> Option<Weight> {
    match outcome {
        CircuitOutcome::NoAnswer | CircuitOutcome::Refused | CircuitOutcome::NotARelay => {
            Some(Weight::Failure(FULL_FAIL_W_M))
        }
        CircuitOutcome::Busy => Some(Weight::Failure(RELAY_BUSY_W_M)),
        CircuitOutcome::NotOnRelay => None,
    }
}

/// The relay's term at `now_ms` (module doc): 0 without a row or below
/// [`RELAY_MIN_EVIDENCE_M`] of evidence aged to `now_ms`, otherwise the
/// posterior mean (prior [`PRIOR_M`]) mapped to ±[`RELAY_TERM_MAX`].
pub fn term(row: Option<&RelayRow>, now_ms: u64) -> i64 {
    let Some(row) = row else {
        return 0;
    };
    let mut beta = row.beta;
    beta.age(now_ms, HALF_LIFE_MS);
    if beta.evidence_m() < RELAY_MIN_EVIDENCE_M {
        return 0;
    }
    let p = i64::from(beta.mean_ppm(PRIOR_M));
    ((p - PPM / 2) * 2 * RELAY_TERM_MAX / PPM).clamp(-RELAY_TERM_MAX, RELAY_TERM_MAX)
}

impl Model {
    /// A verified receipt over a relayed path through `relay_peer` (its
    /// PeerId bytes): +[`RECEIPT_W_M`].
    pub fn relay_receipt(&mut self, relay_peer: &[u8], now_ms: u64) {
        self.relay_apply(relay_peer, Weight::Success(RECEIPT_W_M), None, now_ms);
    }

    /// One circuit outcome of a contact dial through `relay_peer`
    /// ([`circuit_weight`]); a contact not on the relay changes nothing and
    /// makes no row.
    pub fn relay_circuit(&mut self, relay_peer: &[u8], outcome: CircuitOutcome, now_ms: u64) {
        if let Some(weight) = circuit_weight(outcome) {
            self.relay_apply(relay_peer, weight, None, now_ms);
        }
    }

    /// An authenticated inbound link that arrived over our reservation on
    /// `relay_peer`: +[`RELAY_INBOUND_W_M`].
    pub fn relay_inbound(&mut self, relay_peer: &[u8], now_ms: u64) {
        self.relay_apply(relay_peer, Weight::Success(RELAY_INBOUND_W_M), None, now_ms);
    }

    /// A security event about `relay_peer` (Phase 6b R8 for a profile that
    /// learns, P6.28's merge amendment): a full failure. Negative only and
    /// bounded like every other evidence: the term stays within
    /// ±[`RELAY_TERM_MAX`] and ages with the row.
    pub fn relay_security(&mut self, relay_peer: &[u8], now_ms: u64) {
        self.relay_apply(relay_peer, Weight::Failure(FULL_FAIL_W_M), None, now_ms);
    }

    /// [`term`] of each of `relays` (PeerId bytes), in the same order.
    pub fn relay_terms(&self, relays: &[Vec<u8>], now_ms: u64) -> Vec<i64> {
        relays.iter().map(|r| term(self.relay(r), now_ms)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::learning::estimate::{Beta, DAY_MS};
    use crate::learning::observe::{DialTiming, Evidence, FrameKind, Observation};
    use crate::outbox::{DeliveryPath, OutboxCarrier};
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    const NOW: u64 = 1_800_000_000_000;
    const R1: &[u8] = b"relay-one";
    const R2: &[u8] = b"relay-two";

    fn row(a_m: u32, b_m: u32) -> RelayRow {
        RelayRow {
            beta: Beta {
                a_m,
                b_m,
                at_ms: NOW,
                streak: 0,
            },
            ok_ms: 3_000,
        }
    }

    #[test]
    fn circuit_weights_table() {
        use CircuitOutcome::*;
        for (outcome, want) in [
            (NoAnswer, Some(Weight::Failure(1_000))),
            (Refused, Some(Weight::Failure(1_000))),
            (NotARelay, Some(Weight::Failure(1_000))),
            (Busy, Some(Weight::Failure(500))),
            (NotOnRelay, None),
        ] {
            assert_eq!(circuit_weight(outcome), want, "{outcome:?}");
        }
    }

    #[test]
    fn term_is_zero_below_evidence() {
        assert_eq!(term(None, NOW), 0);
        let mut m = Model::new_empty([1; 32]);
        m.relay_receipt(R1, NOW);
        m.relay_receipt(R1, NOW);
        assert_eq!(m.relay(R1).unwrap().beta.evidence_m(), 2_000);
        assert_eq!(term(m.relay(R1), NOW), 0);
        // The third receipt reaches the threshold: p = 4000/5000.
        m.relay_receipt(R1, NOW);
        assert_eq!(term(m.relay(R1), NOW), 90);
        // A day later half of it is left: below again.
        assert_eq!(term(m.relay(R1), NOW + DAY_MS), 0);
        // Failures the same way: p = 1000/5000.
        for _ in 0..3 {
            m.relay_circuit(R2, CircuitOutcome::NoAnswer, NOW);
        }
        assert_eq!(term(m.relay(R2), NOW), -90);
        assert_eq!(
            m.relay_terms(&[R2.to_vec(), b"unknown".to_vec(), R1.to_vec()], NOW),
            vec![-90, 0, 90]
        );
        // Just below and at the threshold, by hand.
        assert_eq!(term(Some(&row(2_999, 0)), NOW), 0);
        assert_eq!(term(Some(&row(3_000, 0)), NOW), 90);
    }

    /// P6.28's merge amendment: a relay's security events only lower its
    /// term (three of them make it −90, like three unanswered circuits), a
    /// relay the events never named keeps its own, and the term stays
    /// bounded however many there are.
    #[test]
    fn security_events_only_lower_a_relays_term() {
        let mut m = Model::new_empty([1; 32]);
        for _ in 0..3 {
            m.relay_receipt(R1, NOW);
        }
        assert_eq!(term(m.relay(R1), NOW), 90);
        for _ in 0..3 {
            m.relay_security(R2, NOW);
        }
        assert_eq!(term(m.relay(R2), NOW), -90);
        assert_eq!(term(m.relay(R1), NOW), 90, "another relay's own term");
        let before = term(m.relay(R1), NOW);
        m.relay_security(R1, NOW);
        assert!(term(m.relay(R1), NOW) < before, "never raises it");
        for _ in 0..10_000 {
            m.relay_security(R2, NOW);
        }
        let floor = term(m.relay(R2), NOW);
        assert!((-RELAY_TERM_MAX..=-90).contains(&floor), "{floor}");
    }

    #[test]
    fn term_is_bounded() {
        // The extremes a corrupt row could hold.
        for (a, b) in [
            (u32::MAX, 0),
            (0, u32::MAX),
            (u32::MAX, u32::MAX),
            (8_000, 0),
            (0, 8_000),
        ] {
            let t = term(Some(&row(a, b)), NOW);
            assert!(t.abs() <= RELAY_TERM_MAX, "{a} {b}: {t}");
        }
        // Capped evidence keeps it well inside: 9000/10000 → 120.
        let mut m = Model::new_empty([1; 32]);
        for _ in 0..20 {
            m.relay_receipt(R1, NOW);
            m.relay_circuit(R2, CircuitOutcome::Refused, NOW);
        }
        assert_eq!(term(m.relay(R1), NOW), 120);
        assert_eq!(term(m.relay(R2), NOW), -120);
        // Any mix of events at any times stays bounded.
        let mut rng = StdRng::seed_from_u64(0x7e1a);
        let mut t = NOW;
        for _ in 0..5_000 {
            t += rng.gen_range(0..4 * 3_600_000);
            match rng.gen_range(0..4) {
                0 => m.relay_receipt(R1, t),
                1 => m.relay_inbound(R1, t),
                2 => m.relay_circuit(R1, CircuitOutcome::Busy, t),
                _ => m.relay_circuit(R1, CircuitOutcome::NoAnswer, t),
            }
            let got = term(m.relay(R1), t);
            assert!(got.abs() <= RELAY_TERM_MAX, "{got}");
        }
    }

    /// A circuit the relay could not hand to the contact says the contact is
    /// offline: no row is made and an existing one does not move.
    #[test]
    fn contact_offline_circuits_do_not_count() {
        let mut m = Model::new_empty([1; 32]);
        for _ in 0..10 {
            m.relay_circuit(R1, CircuitOutcome::NotOnRelay, NOW);
        }
        assert!(m.relay(R1).is_none());
        for _ in 0..3 {
            m.relay_receipt(R1, NOW);
        }
        let before = *m.relay(R1).unwrap();
        for _ in 0..10 {
            m.relay_circuit(R1, CircuitOutcome::NotOnRelay, NOW + DAY_MS);
        }
        assert_eq!(*m.relay(R1).unwrap(), before);
        assert_eq!(term(m.relay(R1), NOW), 90);
        // A busy relay counts half a failure.
        m.relay_circuit(R1, CircuitOutcome::Busy, NOW);
        assert_eq!(m.relay(R1).unwrap().beta.b_m, RELAY_BUSY_W_M);
    }

    #[test]
    fn inbound_over_our_relay_counts_half() {
        let mut m = Model::new_empty([1; 32]);
        m.relay_inbound(R1, NOW);
        let row = *m.relay(R1).unwrap();
        assert_eq!((row.beta.a_m, row.beta.b_m), (RECEIPT_W_M / 2, 0));
        // It carries no dial time.
        assert_eq!(row.ok_ms, 3_000);
        m.relay_inbound(R1, NOW);
        m.relay_receipt(R2, NOW);
        assert_eq!(m.relay(R1).unwrap().beta.a_m, m.relay(R2).unwrap().beta.a_m);
        // Six inbound links are three receipts' evidence.
        for _ in 0..4 {
            m.relay_inbound(R1, NOW);
        }
        assert_eq!(term(m.relay(R1), NOW), 90);
    }

    /// `observe` drives `relay_receipt` for a relayed receipt, with the
    /// dial's total as the relay's cost sample.
    #[test]
    fn observe_drives_the_relay_receipt() {
        let mut m = Model::new_empty([1; 32]);
        let o = Observation {
            contact: [0xB0; 32],
            net: None,
            net_changed: false,
            carrier: OutboxCarrier::P2p,
            path: Some(DeliveryPath::Relayed),
            relay: Some(R1.to_vec()),
            kind: FrameKind::Message,
            evidence: Evidence::Receipt,
            timing: DialTiming {
                connect_ms: None,
                reply_ms: None,
                total_ms: 1_000,
            },
            karn_exclude: false,
            at_ms: NOW,
        };
        m.observe(&o, NOW);
        m.relay_receipt(R2, NOW);
        let (one, two) = (*m.relay(R1).unwrap(), *m.relay(R2).unwrap());
        assert_eq!(one.beta, two.beta);
        assert_eq!((one.ok_ms, two.ok_ms), (2_500, 3_000));
    }
}
