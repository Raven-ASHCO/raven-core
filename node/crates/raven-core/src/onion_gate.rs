//! Tor onion carrier (`protocol/RAVEN_ONION_CARRIER_V1.md`) lab gate.
//!
//! Independent of the LAN, Internet direct, p2p, nearby and custody gates.
//! Stays false until the owner signs a Tor carrier waiver after the field
//! test and an external review (design `docs/design/2026-10-tor-fallback.md`
//! §9, OD-T5). With it off a node starts no Tor helper, publishes no onion
//! service, dials nothing over Tor, prints no `onion=` card field, sends no
//! RRH1 ONION entry and plans exactly what it planned before the carrier
//! existed.
//!
//! The debug unlock is its own switch, `RAVEN_LAB_TOR=1`, read through
//! [`crate::pair_init::lab_switch`] and so only with the Lab Test A unlock
//! (`RAVEN_LAB_TEST_A=1`): that one alone never opens Tor, so every other
//! carrier's lab run keeps testing what it tested, and none of them touches
//! the Tor network by accident.

use std::sync::atomic::{AtomicBool, Ordering};

/// Hard enable for the Tor onion carrier. Lab runs use the debug switch
/// [`LAB_TOR`] instead of flipping this.
pub const ONION_PRODUCTION_ENABLED: bool = false;

/// The Tor onion carrier's debug lab switch (with `RAVEN_LAB_TEST_A=1`).
pub const LAB_TOR: &str = "RAVEN_LAB_TOR";

/// The one refusal every onion entry point (the service task, an onion dial,
/// `raven status`) prints while the gate is closed.
pub const ONION_HOLD: &str = "ONION_HOLD: the Tor onion carrier is lab-only \
    (debug RAVEN_LAB_TEST_A=1 with RAVEN_LAB_TOR=1); ONION_PRODUCTION_ENABLED=false";

/// Live Tor onion carrier: the production const, or in a debug build
/// `RAVEN_LAB_TOR` with the Lab Test A unlock (a release build reads neither
/// variable); unless a security notice holds `feature/onion` (close-only) or
/// a debug lab run carries over Bluetooth nearby alone
/// ([`crate::nearby_gate::nearby_only`]).
pub fn onion_live_enabled() -> bool {
    crate::nearby_gate::unless_nearby_only(
        (ONION_PRODUCTION_ENABLED || crate::pair_init::lab_switch(LAB_TOR))
            && crate::suite_policy::hold_allows(crate::suite_registry::FEATURE_ONION),
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
    fn production_flag_stays_false() {
        const {
            assert!(!ONION_PRODUCTION_ENABLED);
        }
    }

    #[test]
    fn lab_test_a_alone_never_opens_tor() {
        // RAVEN_LAB_TOR is never set by the test harness: the gate reads
        // closed whatever Lab Test A says.
        if std::env::var(LAB_TOR).is_ok() {
            return;
        }
        assert!(!onion_live_enabled());
        assert!(!onion_usable_now());
    }

    #[test]
    fn hold_names_the_flag_and_both_switches() {
        assert!(ONION_HOLD.starts_with("ONION_HOLD:"));
        assert!(ONION_HOLD.contains("ONION_PRODUCTION_ENABLED=false"));
        assert!(ONION_HOLD.contains("RAVEN_LAB_TEST_A=1"));
        assert!(ONION_HOLD.contains(LAB_TOR));
    }
}
