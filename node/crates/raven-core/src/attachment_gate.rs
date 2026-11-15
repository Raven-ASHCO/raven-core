//! The attachments gate (`docs/design/2026-11-attachments.md` §22, phase
//! 1b): sending and opening photos, voice notes and files, with their
//! chunks on live links (`RVNATT/1` offers a node makes, `RAX1` frames,
//! link caps bit 12, the attachment store, the app operations).
//!
//! Off in release builds until the owner flips it; phase 1a (every build
//! keeps an offer and shows a line of words, [`crate::attachment::shown`])
//! has no gate and ships first. A debug build opens it with the Lab Test A
//! unlock and `RAVEN_LAB_ATTACHMENTS=1` ([`crate::pair_init::lab_gate`]); a
//! release build reads no variable. A security notice can hold
//! `feature/attachments` (close only).

/// Hard enable for attachments (phase 1b). False: not field tested, not
/// reviewed.
pub const ATTACHMENTS_PRODUCTION_ENABLED: bool = false;

/// The attachments gate's debug lab switch.
pub const LAB_ATTACHMENTS: &str = "RAVEN_LAB_ATTACHMENTS";

/// The refusal every attachment entry point gives while the gate is closed.
pub const ATTACHMENTS_HOLD: &str = "ATTACHMENTS_HOLD: photos, voice messages and files are \
    lab-only (debug RAVEN_LAB_TEST_A=1 RAVEN_LAB_ATTACHMENTS=1); \
    ATTACHMENTS_PRODUCTION_ENABLED=false";

/// Attachments are live: the const (a release build follows it alone), or
/// in a debug build the lab switch with the Lab Test A unlock; unless a
/// security notice holds `feature/attachments`.
pub fn attachments_live() -> bool {
    crate::pair_init::lab_gate(ATTACHMENTS_PRODUCTION_ENABLED, LAB_ATTACHMENTS)
        && crate::suite_policy::hold_allows(crate::suite_registry::FEATURE_ATTACHMENTS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attachments_production_flag_is_off() {
        const {
            assert!(!ATTACHMENTS_PRODUCTION_ENABLED);
        }
    }

    #[test]
    fn hold_names_the_flag_and_the_switch() {
        assert!(ATTACHMENTS_HOLD.starts_with("ATTACHMENTS_HOLD:"));
        assert!(ATTACHMENTS_HOLD.contains("ATTACHMENTS_PRODUCTION_ENABLED=false"));
        assert!(ATTACHMENTS_HOLD.contains("RAVEN_LAB_ATTACHMENTS=1"));
    }

    /// Runs in both builds: the release test jobs set the Lab Test A unlock
    /// and the gate's switch (CI's "every switch set" step sets them all),
    /// and the gate stays shut, as neither is read; a debug build follows
    /// exactly its environment and changes none of it (the other tests
    /// share it).
    #[test]
    fn attachments_is_inert_in_release_builds() {
        if !cfg!(debug_assertions) {
            // Edition 2021: plain calls. No release test needs them unset.
            std::env::set_var(crate::pair_init::LAB_TEST_A, "1");
            std::env::set_var(LAB_ATTACHMENTS, "1");
            assert!(
                !attachments_live(),
                "the switch opened the gate in a release build"
            );
            return;
        }
        let set = std::env::var(LAB_ATTACHMENTS).ok();
        let want =
            crate::pair_init::lab_switch_value(
                true,
                crate::pair_init::lab_test_a_enabled(),
                set.as_deref(),
            ) && crate::suite_policy::hold_allows(crate::suite_registry::FEATURE_ATTACHMENTS);
        assert_eq!(attachments_live(), want);
    }
}
