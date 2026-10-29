//! InternetTransport indexed-delivery gate.
//!
//! Independent of the four global `PRODUCTION_ENABLED` tripwires and of
//! [`crate::LAN_DIRECT_PRODUCTION_ENABLED`]. Switched on in release builds in
//! 2026-10, after the three-machine field test (debug builds with the lab
//! switches on: three computers on a home network and a phone hotspot); not
//! independently reviewed.

/// Hard enable for indexed InternetTransport (RIH1 + PairInit + sealed ACK).
/// Switched on 2026-10 after the three-machine field test; not independently
/// reviewed. A debug build closes it again with `RAVEN_LAB_TEST_A=0`
/// ([`crate::pair_init::test_a_gate`]). Listening stays opt-in (`raven node
/// internet on`); dialling a contact's address needs no listener.
pub const INTERNET_DIRECT_PRODUCTION_ENABLED: bool = true;

/// Live InternetTransport indexed path: the slice gate (a debug build: the
/// Lab Test A switch, [`crate::pair_init::test_a_gate`]), unless a security
/// notice holds it (P6.45, close-only) or a debug lab run carries over
/// nearby alone ([`crate::nearby_gate::nearby_only`]).
pub fn internet_direct_live_enabled() -> bool {
    crate::nearby_gate::unless_nearby_only(
        crate::pair_init::test_a_gate(INTERNET_DIRECT_PRODUCTION_ENABLED)
            && crate::suite_policy::hold_allows(crate::suite_registry::FEATURE_INTERNET_DIRECT),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-10: Internet direct is on in release builds; the four generic
    /// PairInit tripwires (the legacy contact request) stay off.
    #[test]
    fn production_flag_is_on_and_the_generic_tripwires_stay_off() {
        const {
            assert!(INTERNET_DIRECT_PRODUCTION_ENABLED);
            assert!(!crate::pair_init::PRODUCTION_ENABLED);
            assert!(!crate::INDEXED_SESSION_STORE_PRODUCTION_ENABLED);
            assert!(!crate::PREKEY_LIFECYCLE_PRODUCTION_ENABLED);
            assert!(!crate::atsam_indexed_session::PRODUCTION_ENABLED);
        }
    }

    /// The gate follows its const and the Lab Test A switch in this process
    /// (nothing holds it in a test process); it never opens the generic
    /// tripwires, which only the Lab Test A unlock opens.
    #[test]
    fn gate_does_not_open_generic_live_enabled() {
        let test_a = std::env::var(crate::pair_init::LAB_TEST_A).ok();
        let want = crate::pair_init::test_a_gate_value(
            cfg!(debug_assertions),
            INTERNET_DIRECT_PRODUCTION_ENABLED,
            test_a.as_deref(),
        ) && !crate::nearby_gate::nearby_only();
        assert_eq!(internet_direct_live_enabled(), want);
        if crate::pair_init::lab_test_a_enabled() {
            return;
        }
        assert!(!crate::pair_init::live_enabled());
        assert!(!crate::indexed_session_store::live_enabled());
        assert!(!crate::prekey_lifecycle::live_enabled());
        assert!(!crate::atsam_indexed_session::live_enabled());
    }
}
