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
}
