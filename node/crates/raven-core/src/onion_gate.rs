//! Tor onion carrier (`protocol/RAVEN_ONION_CARRIER_V1.md`) gate.
//!
//! Independent of the LAN, Internet direct, p2p, nearby and custody gates.
//! Switched on in release builds in 2026-10, after the three-machine field
//! test (debug builds with the lab switches on: messages over Tor between a
//! phone hotspot and a home network, every direction); not independently
//! reviewed (design `docs/design/2026-10-tor-fallback.md` §9, OD-T5, asked
//! for a waiver and an external review first: neither exists yet). Tor relays
//! are the only third party it talks to; Tor is only a carrier (the Raven
//! link inside is end-to-end as on every other carrier). A node runs the Tor
//! helper only when one sits next to raven-node (a build with the `tor`
//! feature); otherwise it says "Tor: not built in this raven".
//!
//! A debug build closes it again with `RAVEN_LAB_TOR=0`
//! ([`crate::pair_init::lab_gate`]): every lab run and test that must not
//! touch the Tor network sets that, so none of them touches it by accident.
//!
//! **Tor speed, Stage A** (security and speed report 2026-11-05 §7, speed
//! design M1 to M10): five more gates, every one false, on top of this one.
//! Each opens only while the onion carrier itself is live
//! ([`onion_live_enabled`]), then with its const or, in a debug build with
//! the Lab Test A unlock, its own lab switch
//! ([`crate::pair_init::lab_switch`]; a release build reads neither), and a
//! security notice can hold each (its `FEATURE_ONION_*` id in
//! [`crate::suite_registry`]; close only):
//! - [`ONION_WARM_PRODUCTION_ENABLED`] (`RAVEN_LAB_TOR_WARM`): the dialer
//!   keeps a link open after a send's check or message for the next batch
//!   (W1, M1), and the later warm-ups and pipelined sends (M2, M3, M8, M10);
//! - [`ONION_HEDGE_PRODUCTION_ENABLED`] (`RAVEN_LAB_TOR_HEDGE`): connect and
//!   batch hedges, fresh-first (M5);
//! - [`ONION_EARLY_PRODUCTION_ENABLED`] (`RAVEN_LAB_TOR_EARLY`): a message
//!   in the link's first flight (M7);
//! - [`ONION_OPTIMISTIC_PRODUCTION_ENABLED`] (`RAVEN_LAB_TOR_OPTIMISTIC`):
//!   optimistic data on onion streams (M6);
//! - [`ONION_WARM_LINK_PRODUCTION_ENABLED`] (`RAVEN_LAB_TOR_WARM_LINK`):
//!   the two-way warm link RWL1 (W2, M4), a wire change: lab only until it
//!   is reviewed.

use std::sync::atomic::{AtomicBool, Ordering};

/// Hard enable for the Tor onion carrier. Switched on 2026-10 after the
/// three-machine field test; not independently reviewed.
pub const ONION_PRODUCTION_ENABLED: bool = true;

/// The Tor onion carrier's debug lab switch: "0" closes it.
pub const LAB_TOR: &str = "RAVEN_LAB_TOR";

/// The one refusal every onion entry point (the service task, an onion dial,
/// `raven status`) prints while the gate is closed: since the 2026-10
/// switch-on only a debug build closes it, or a security notice.
pub const ONION_HOLD: &str = "ONION_HOLD: the Tor onion carrier is closed in this process (a \
    debug build with RAVEN_LAB_TOR=0 or RAVEN_LAB_NEARBY_ONLY=1, or a security notice); release \
    builds have it on (ONION_PRODUCTION_ENABLED=true)";

/// Live Tor onion carrier: the production const (a debug build: `RAVEN_LAB_TOR=0`
/// closes it; a release build reads no variable); unless a security notice
/// holds `feature/onion` (close-only) or a debug lab run carries over
/// Bluetooth nearby alone ([`crate::nearby_gate::nearby_only`]).
pub fn onion_live_enabled() -> bool {
    crate::nearby_gate::unless_nearby_only(
        crate::pair_init::lab_gate(ONION_PRODUCTION_ENABLED, LAB_TOR)
            && crate::suite_policy::hold_allows(crate::suite_registry::FEATURE_ONION),
    )
}

// ── Tor speed, Stage A (all held) ────────────────────────────────────────

/// W1 (speed design M1): an app's send over Tor leaves its link open for
/// the next batch to the same friend, within `WARM_IDLE` 20 s of the last
/// batch and `WARM_AGE` 120 s of the link (raven-node `onion::warm`); also
/// the keep-warm probes, the warm-ups and pipelined sends that build on it
/// (M2, M3, M8, M10). Held until the D1 measurement and a review.
pub const ONION_WARM_PRODUCTION_ENABLED: bool = false;
/// Connect and batch hedges and fresh-first (speed design M5). Held.
pub const ONION_HEDGE_PRODUCTION_ENABLED: bool = false;
/// The message in the link's first flight: early frames with F4 (speed
/// design M7). Held.
pub const ONION_EARLY_PRODUCTION_ENABLED: bool = false;
/// Optimistic data on onion streams, a delta of the Arti fork (speed design
/// M6). Held: not now (owner decision pending).
pub const ONION_OPTIMISTIC_PRODUCTION_ENABLED: bool = false;
/// The two-way warm link RWL1 (W2, speed design M4): a wire change, lab only
/// until it is reviewed.
pub const ONION_WARM_LINK_PRODUCTION_ENABLED: bool = false;

/// [`ONION_WARM_PRODUCTION_ENABLED`]'s lab switch.
pub const LAB_TOR_WARM: &str = "RAVEN_LAB_TOR_WARM";
/// [`ONION_HEDGE_PRODUCTION_ENABLED`]'s lab switch.
pub const LAB_TOR_HEDGE: &str = "RAVEN_LAB_TOR_HEDGE";
/// [`ONION_EARLY_PRODUCTION_ENABLED`]'s lab switch.
pub const LAB_TOR_EARLY: &str = "RAVEN_LAB_TOR_EARLY";
/// [`ONION_OPTIMISTIC_PRODUCTION_ENABLED`]'s lab switch.
pub const LAB_TOR_OPTIMISTIC: &str = "RAVEN_LAB_TOR_OPTIMISTIC";
/// [`ONION_WARM_LINK_PRODUCTION_ENABLED`]'s lab switch.
pub const LAB_TOR_WARM_LINK: &str = "RAVEN_LAB_TOR_WARM_LINK";

/// A Stage A gate: the onion carrier live, then `production` or (a debug
/// build with the Lab Test A unlock) the lab switch `switch`, then no hold
/// on `feature` (close only).
fn speed_gate(production: bool, switch: &str, feature: &str) -> bool {
    speed_gate_value(
        production,
        onion_live_enabled(),
        || crate::pair_init::lab_switch(switch),
        || crate::suite_policy::hold_allows(feature),
    )
}

/// [`speed_gate`] from its inputs: the switch is asked only below a live
/// carrier with the const off, the hold only for a gate that is open.
fn speed_gate_value(
    production: bool,
    onion: bool,
    switch: impl FnOnce() -> bool,
    hold_allows: impl FnOnce() -> bool,
) -> bool {
    crate::p2p_gate::gate_value(production, onion, switch) && hold_allows()
}

/// Live W1 warm links ([`ONION_WARM_PRODUCTION_ENABLED`]).
pub fn onion_warm_live() -> bool {
    speed_gate(
        ONION_WARM_PRODUCTION_ENABLED,
        LAB_TOR_WARM,
        crate::suite_registry::FEATURE_ONION_WARM,
    )
}

/// Live hedges ([`ONION_HEDGE_PRODUCTION_ENABLED`]).
pub fn onion_hedge_live() -> bool {
    speed_gate(
        ONION_HEDGE_PRODUCTION_ENABLED,
        LAB_TOR_HEDGE,
        crate::suite_registry::FEATURE_ONION_HEDGE,
    )
}

/// Live early frames ([`ONION_EARLY_PRODUCTION_ENABLED`]).
pub fn onion_early_live() -> bool {
    speed_gate(
        ONION_EARLY_PRODUCTION_ENABLED,
        LAB_TOR_EARLY,
        crate::suite_registry::FEATURE_ONION_EARLY,
    )
}

/// Live optimistic data ([`ONION_OPTIMISTIC_PRODUCTION_ENABLED`]).
pub fn onion_optimistic_live() -> bool {
    speed_gate(
        ONION_OPTIMISTIC_PRODUCTION_ENABLED,
        LAB_TOR_OPTIMISTIC,
        crate::suite_registry::FEATURE_ONION_OPTIMISTIC,
    )
}

/// Live W2 warm links ([`ONION_WARM_LINK_PRODUCTION_ENABLED`]).
pub fn onion_warm_link_live() -> bool {
    speed_gate(
        ONION_WARM_LINK_PRODUCTION_ENABLED,
        LAB_TOR_WARM_LINK,
        crate::suite_registry::FEATURE_ONION_WARM_LINK,
    )
}

static ONION_READY: AtomicBool = AtomicBool::new(false);

/// raven-node's onion service task has a Tor helper whose client finished
/// bootstrapping and whose connect port is known: an onion dial can start
/// now. Only raven-node's onion task sets it; it is false in every other
/// process. Whether it changed.
pub fn set_onion_ready(on: bool) -> bool {
    ONION_READY.swap(on, Ordering::Relaxed) != on
}

/// Whether this process can dial over Tor now ([`set_onion_ready`]).
pub fn onion_ready() -> bool {
    ONION_READY.load(Ordering::Relaxed)
}

/// The onion carrier can carry something now: its gate is live and the Tor
/// helper is ready ([`onion_ready`]).
pub fn onion_usable_now() -> bool {
    onion_live_enabled() && onion_ready()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_flag_is_on() {
        const {
            assert!(ONION_PRODUCTION_ENABLED);
        }
    }

    /// The gate follows its const and `RAVEN_LAB_TOR` in this process: on
    /// as in a release build unless the switch says "0" (the test harnesses
    /// set it, so no test touches the Tor network); the Lab Test A unlock
    /// alone changes nothing.
    #[test]
    fn the_gate_follows_the_const_and_the_close_switch() {
        let set = std::env::var(LAB_TOR).ok();
        let want = crate::pair_init::lab_gate_value(
            cfg!(debug_assertions),
            ONION_PRODUCTION_ENABLED,
            crate::pair_init::lab_test_a_enabled(),
            set.as_deref(),
        ) && !crate::nearby_gate::nearby_only();
        assert_eq!(onion_live_enabled(), want);
        if !want {
            assert!(!onion_usable_now());
        }
        assert!(!crate::pair_init::lab_gate_value(
            true,
            true,
            true,
            Some("0")
        ));
        assert!(crate::pair_init::lab_gate_value(
            false,
            true,
            true,
            Some("0")
        ));
    }

    #[test]
    fn hold_names_the_flag_and_the_close_switch() {
        assert!(ONION_HOLD.starts_with("ONION_HOLD:"));
        assert!(ONION_HOLD.contains("ONION_PRODUCTION_ENABLED=true"));
        assert!(ONION_HOLD.contains("RAVEN_LAB_TOR=0"));
        assert!(!ONION_HOLD.contains("lab-only"));
    }

    // ── Tor speed, Stage A ──────────────────────────────────────────────

    #[test]
    fn onion_warm_production_flag_is_off() {
        const {
            assert!(!ONION_WARM_PRODUCTION_ENABLED);
        }
    }

    #[test]
    fn onion_hedge_production_flag_is_off() {
        const {
            assert!(!ONION_HEDGE_PRODUCTION_ENABLED);
        }
    }

    #[test]
    fn onion_early_production_flag_is_off() {
        const {
            assert!(!ONION_EARLY_PRODUCTION_ENABLED);
        }
    }

    #[test]
    fn onion_optimistic_production_flag_is_off() {
        const {
            assert!(!ONION_OPTIMISTIC_PRODUCTION_ENABLED);
        }
    }

    #[test]
    fn onion_warm_link_production_flag_is_off() {
        const {
            assert!(!ONION_WARM_LINK_PRODUCTION_ENABLED);
        }
    }

    /// Runs in both builds: the release test jobs set the Lab Test A unlock
    /// and the gate's switch (CI's "every switch set" step sets them all),
    /// and the gate stays shut, as neither is read; a debug build follows
    /// exactly its environment and changes none of it (the other tests
    /// share it).
    fn speed_gate_is_inert(switch: &str, live: fn() -> bool, feature: &str) {
        if !cfg!(debug_assertions) {
            // Edition 2021: plain calls. No release test needs them unset.
            std::env::set_var(crate::pair_init::LAB_TEST_A, "1");
            std::env::set_var(switch, "1");
            assert!(!live(), "{switch} opened its gate in a release build");
            return;
        }
        let set = std::env::var(switch).ok();
        let want = onion_live_enabled()
            && crate::pair_init::lab_switch_value(
                true,
                crate::pair_init::lab_test_a_enabled(),
                set.as_deref(),
            )
            && crate::suite_policy::hold_allows(feature);
        assert_eq!(live(), want, "{switch}");
    }

    #[test]
    fn onion_warm_is_inert_in_release_builds() {
        speed_gate_is_inert(
            LAB_TOR_WARM,
            onion_warm_live,
            crate::suite_registry::FEATURE_ONION_WARM,
        );
    }

    #[test]
    fn onion_hedge_is_inert_in_release_builds() {
        speed_gate_is_inert(
            LAB_TOR_HEDGE,
            onion_hedge_live,
            crate::suite_registry::FEATURE_ONION_HEDGE,
        );
    }

    #[test]
    fn onion_early_is_inert_in_release_builds() {
        speed_gate_is_inert(
            LAB_TOR_EARLY,
            onion_early_live,
            crate::suite_registry::FEATURE_ONION_EARLY,
        );
    }

    #[test]
    fn onion_optimistic_is_inert_in_release_builds() {
        speed_gate_is_inert(
            LAB_TOR_OPTIMISTIC,
            onion_optimistic_live,
            crate::suite_registry::FEATURE_ONION_OPTIMISTIC,
        );
    }

    #[test]
    fn onion_warm_link_is_inert_in_release_builds() {
        speed_gate_is_inert(
            LAB_TOR_WARM_LINK,
            onion_warm_link_live,
            crate::suite_registry::FEATURE_ONION_WARM_LINK,
        );
    }

    /// A Stage A gate opens only on a live onion carrier, with its const or
    /// its switch, and a hold closes it; nothing opens it over a hold or a
    /// closed carrier, and the switch is never asked while the const is on
    /// or the carrier is closed.
    #[test]
    fn speed_gates_need_the_carrier_their_switch_and_no_hold() {
        for production in [false, true] {
            for onion in [false, true] {
                for switch in [false, true] {
                    for allows in [false, true] {
                        let mut asked = false;
                        let got = speed_gate_value(
                            production,
                            onion,
                            || {
                                asked = true;
                                switch
                            },
                            || allows,
                        );
                        let case = format!("{production} {onion} {switch} {allows}");
                        assert_eq!(got, onion && (production || switch) && allows, "{case}");
                        assert_eq!(asked, onion && !production, "{case}");
                    }
                }
            }
        }
    }

    /// Each Stage A gate has its own switch and its own hold id, named after
    /// its const, and the switches are distinct from the carrier's own.
    #[test]
    fn every_speed_gate_has_its_switch_and_hold() {
        use crate::suite_registry::feature_for_gate;
        let gates = [
            (
                "ONION_WARM_PRODUCTION_ENABLED",
                LAB_TOR_WARM,
                "feature/onion-warm",
            ),
            (
                "ONION_HEDGE_PRODUCTION_ENABLED",
                LAB_TOR_HEDGE,
                "feature/onion-hedge",
            ),
            (
                "ONION_EARLY_PRODUCTION_ENABLED",
                LAB_TOR_EARLY,
                "feature/onion-early",
            ),
            (
                "ONION_OPTIMISTIC_PRODUCTION_ENABLED",
                LAB_TOR_OPTIMISTIC,
                "feature/onion-optimistic",
            ),
            (
                "ONION_WARM_LINK_PRODUCTION_ENABLED",
                LAB_TOR_WARM_LINK,
                "feature/onion-warm-link",
            ),
        ];
        let mut switches = std::collections::BTreeSet::new();
        for (gate, switch, id) in gates {
            let feature = feature_for_gate(gate).unwrap_or_else(|| panic!("{gate}: no feature"));
            assert_eq!(feature.id, id);
            assert!(!feature.production, "{gate}");
            assert!(feature.holdable(), "{gate}");
            assert!(switch.starts_with("RAVEN_LAB_TOR_"), "{switch}");
            assert_ne!(switch, LAB_TOR);
            assert!(switches.insert(switch), "{switch} twice");
        }
    }
}
