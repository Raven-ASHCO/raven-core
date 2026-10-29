//! Phase 6a learning connectivity (`docs/roadmap/plans/phase6-design.json`,
//! design "Phase 6a"): Raven learns only from its own delivery outcomes, on
//! this computer, inside fixed bounds, and only reorders what the static
//! planner already allows (and shortens a few waits). It never sends what it
//! learned anywhere.
//!
//! This module holds the gate and the switches; the learning core lands in
//! submodules under `learning/` (same layout as `custody_client`):
//! [`estimate`] has the deterministic estimators (decay, decayed Beta, RTT,
//! encounter predictability); [`observe`] the observation record and its
//! classifier (frame kind, evidence, failure weights); [`model`] the
//! in-memory model (arms, relay, encounter and carry rows, bounds); [`rank`]
//! the learned carrier order that `outbox::plan_object_routes_ranked`
//! applies; [`explain`] its reason grammar; [`wait`] the adaptive connect
//! and first-reply waits (never above today's); [`relay`] the bounded relay
//! term for relay selection; [`carry`] the choice of custodians from own
//! encounters and receipts; [`store`] the encrypted file the model lives in
//! (LRN1, `learning.bin`, sealed at rest).
//!
//! - [`LEARNING_PRODUCTION_ENABLED`] stays `false`; a debug build opens it
//!   with `RAVEN_LAB_LEARNING=1` ([`learning_live`]). A release build never
//!   reads the variable.
//! - The user's switch is `node_policy.learning` ([`learning_on`]): `None`
//!   is on while the gate is live, `Some(false)` off (the value a policy that
//!   fails closed keeps).
//! - [`lab_tune`] (debug `RAVEN_LAB_LEARNING_TUNE`) shortens the exploration
//!   gaps and the half-life for the harness, never in release.
//! - [`crate::lan_gate::lab_sealer_unavailable`] (debug
//!   `RAVEN_LAB_LEARNING_SEALER=unavailable`) forces the keystore-unavailable
//!   path of the learning store for the harness (C73).
//!
//! No float arithmetic anywhere under this module: every estimate is integer
//! or fixed-point, so the simulator and both builds give the same numbers.
#![deny(clippy::float_arithmetic)]

pub mod carry;
pub mod estimate;
pub mod explain;
pub mod model;
pub mod observe;
pub mod rank;
pub mod relay;
pub mod store;
pub mod wait;

/// Phase 6a hold: no learned order, wait or relay term outside a debug lab
/// run until the learning waiver is signed. Asserted with the other holds in
/// `lan_gate::tests::global_production_flags_stay_false`.
pub const LEARNING_PRODUCTION_ENABLED: bool = false;

/// Status text while the gate is shut (`raven learning status`, IPC, doctor).
pub const LEARNING_HOLD: &str = "LEARNING_HOLD: learning connectivity is lab-only \
    (debug RAVEN_LAB_LEARNING=1); LEARNING_PRODUCTION_ENABLED=false";

/// `=1`: a debug build opens the learning gate ([`learning_live`]).
pub const LAB_LEARNING: &str = "RAVEN_LAB_LEARNING";
/// `=<probe_gap_s>,<recover_gap_s>,<half_life_s>`: debug-only timings for
/// the harness ([`lab_tune`]).
pub const LAB_LEARNING_TUNE: &str = "RAVEN_LAB_LEARNING_TUNE";
/// `=unavailable`: the learning store's sealer fails as an unreadable
/// keystore would (debug only; [`crate::lan_gate::lab_sealer_unavailable`]).
pub const LAB_LEARNING_SEALER: &str = "RAVEN_LAB_LEARNING_SEALER";

/// Every learning lab switch (the harnesses scrub these).
pub const LEARNING_LAB_SWITCHES: [&str; 3] = [LAB_LEARNING, LAB_LEARNING_TUNE, LAB_LEARNING_SEALER];

/// Each [`LAB_LEARNING_TUNE`] field is a whole number of seconds in
/// `1..=LAB_TUNE_MAX_S` (7 days).
pub const LAB_TUNE_MAX_S: u64 = 604_800;

/// Learning is live: [`LEARNING_PRODUCTION_ENABLED`], or in a debug build
/// `RAVEN_LAB_LEARNING=1` (a release build never reads it); unless a
/// security notice holds it (P6.45, close-only).
pub fn learning_live() -> bool {
    live_with(cfg!(debug_assertions), || std::env::var(LAB_LEARNING).ok())
        && crate::suite_policy::hold_allows(crate::suite_registry::FEATURE_LEARNING)
}

/// [`learning_live`] with the build passed in; `value` (the switch) is not
/// called in a release build.
fn live_with(debug: bool, value: impl FnOnce() -> Option<String>) -> bool {
    LEARNING_PRODUCTION_ENABLED || crate::p2p_gate::lab_flag(debug, value)
}

/// The user's switch (node_policy.learning): None = on while live.
pub fn learning_on(policy: &crate::node_policy::NodePolicy) -> bool {
    on_with(learning_live(), policy)
}

/// [`learning_on`] with the gate passed in.
fn on_with(live: bool, policy: &crate::node_policy::NodePolicy) -> bool {
    live && policy.learning != Some(false)
}

/// The harness timings [`lab_tune`] returns, in milliseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tune {
    /// Replaces the gap between two exploration probes of one arm.
    pub probe_gap_ms: u64,
    /// Replaces the shorter gap for an arm that is recovering.
    pub recover_gap_ms: u64,
    /// Replaces the estimators' half-life.
    pub half_life_ms: u64,
}

/// `RAVEN_LAB_LEARNING_TUNE=<probe_gap_s>,<recover_gap_s>,<half_life_s>`,
/// each `1..=604800`. Debug only (harness speed): a release build never
/// reads it.
pub fn lab_tune() -> Option<Tune> {
    crate::p2p_gate::lab_value(
        cfg!(debug_assertions),
        || std::env::var(LAB_LEARNING_TUNE).ok(),
        parse_tune,
    )
}

/// Exactly three whole seconds, each `1..=`[`LAB_TUNE_MAX_S`] (blanks
/// around a field ignored); anything else is `None`.
pub(crate) fn parse_tune(v: &str) -> Option<Tune> {
    let mut secs = v.split(',').map(|s| {
        s.trim()
            .parse::<u64>()
            .ok()
            .filter(|s| (1..=LAB_TUNE_MAX_S).contains(s))
            .map(|s| s * 1000)
    });
    let tune = Tune {
        probe_gap_ms: secs.next()??,
        recover_gap_ms: secs.next()??,
        half_life_ms: secs.next()??,
    };
    secs.next().is_none().then_some(tune)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_policy::NodePolicy;

    #[test]
    fn production_flag_stays_false() {
        const {
            assert!(!LEARNING_PRODUCTION_ENABLED);
        }
        assert!(!live_with(false, || panic!("release read the variable")));
    }

    #[test]
    fn hold_text_names_the_switch() {
        assert!(LEARNING_HOLD.starts_with("LEARNING_HOLD: "));
        assert!(LEARNING_HOLD.contains("RAVEN_LAB_LEARNING=1"));
        assert!(LEARNING_HOLD.contains("LEARNING_PRODUCTION_ENABLED=false"));
        assert!(LEARNING_HOLD.contains(LAB_LEARNING));
        let mut names = LEARNING_LAB_SWITCHES.to_vec();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), LEARNING_LAB_SWITCHES.len());
        assert!(names.iter().all(|n| n.starts_with("RAVEN_LAB_LEARNING")));
    }

    #[test]
    fn lab_tune_parse_table() {
        let tune = |p: u64, r: u64, h: u64| Tune {
            probe_gap_ms: p * 1000,
            recover_gap_ms: r * 1000,
            half_life_ms: h * 1000,
        };
        for (text, want) in [
            ("60,15,3600", Some(tune(60, 15, 3600))),
            (" 1 , 1 , 1 ", Some(tune(1, 1, 1))),
            (
                "604800,604800,604800",
                Some(tune(604_800, 604_800, 604_800)),
            ),
            ("0,15,3600", None),
            ("60,0,3600", None),
            ("60,15,0", None),
            ("604801,15,3600", None),
            ("60,15,604801", None),
            ("60,15", None),
            ("60,15,3600,1", None),
            ("60,15,3600,", None),
            ("-1,15,3600", None),
            ("1.5,15,3600", None),
            ("a,b,c", None),
            ("", None),
            ("junk", None),
        ] {
            assert_eq!(parse_tune(text), want, "{text:?}");
        }
        // The debug path parses exactly what is set; a release build never
        // reads the variable.
        let unread = || -> Option<String> { panic!("release read the variable") };
        assert_eq!(crate::p2p_gate::lab_value(false, unread, parse_tune), None);
        assert_eq!(
            crate::p2p_gate::lab_value(true, || Some("60,15,3600".into()), parse_tune),
            Some(tune(60, 15, 3600))
        );
        assert_eq!(
            crate::p2p_gate::lab_value(true, || Some("0,1,1".into()), parse_tune),
            None
        );
        assert_eq!(crate::p2p_gate::lab_value(true, || None, parse_tune), None);
        if cfg!(debug_assertions) {
            let set = std::env::var(LAB_LEARNING_TUNE).ok();
            assert_eq!(lab_tune(), set.as_deref().and_then(parse_tune));
        } else {
            assert_eq!(lab_tune(), None);
        }
    }

    #[test]
    fn learning_on_respects_the_policy() {
        // Debug with the lab switch set: the gate is live.
        let live = live_with(true, || Some("1".into()));
        assert!(live || LEARNING_PRODUCTION_ENABLED);
        for (value, open) in [
            (None, false),
            (Some(""), false),
            (Some("0"), false),
            (Some("true"), false),
            (Some(" 1"), false),
            (Some("1"), true),
        ] {
            assert_eq!(
                live_with(true, || value.map(str::to_owned)),
                open || LEARNING_PRODUCTION_ENABLED,
                "{value:?}"
            );
        }
        let with = |learning: Option<bool>| NodePolicy {
            learning,
            ..NodePolicy::default()
        };
        assert!(on_with(live, &with(None)));
        assert!(on_with(live, &with(Some(true))));
        assert!(!on_with(live, &with(Some(false))));
        assert!(on_with(live, &NodePolicy::default()));
        assert!(!on_with(live, &NodePolicy::fail_closed()));
        // A shut gate is off whatever the user says.
        for learning in [None, Some(true), Some(false)] {
            assert!(!on_with(false, &with(learning)), "{learning:?}");
        }
        // The process's own switch, as set.
        for learning in [None, Some(true), Some(false)] {
            let p = with(learning);
            assert_eq!(learning_on(&p), learning_live() && learning != Some(false));
        }
    }
}
