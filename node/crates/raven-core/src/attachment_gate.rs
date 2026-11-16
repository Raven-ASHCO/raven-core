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

thread_local! {
    static ATTACHMENTS_LAB: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

/// Attachments are live: the const (a release build follows it alone), or
/// in a debug build this thread's override, else the lab switch with the
/// Lab Test A unlock; unless a security notice holds `feature/attachments`.
pub fn attachments_live() -> bool {
    let over = if cfg!(debug_assertions) {
        ATTACHMENTS_LAB.with(std::cell::Cell::get)
    } else {
        None
    };
    over.unwrap_or_else(|| {
        crate::pair_init::lab_gate(ATTACHMENTS_PRODUCTION_ENABLED, LAB_ATTACHMENTS)
    }) && crate::suite_policy::hold_allows(crate::suite_registry::FEATURE_ATTACHMENTS)
}

/// In-process tests switch attachments on or off for the current thread
/// only; `None` goes back to the const and the environment. Ignored in
/// release builds.
#[doc(hidden)]
pub fn set_lab_attachments_for_this_thread(on: Option<bool>) {
    ATTACHMENTS_LAB.with(|c| c.set(on));
}

/// This thread's override ([`set_lab_attachments_for_this_thread`]), for a
/// test that hands work to another thread.
#[doc(hidden)]
pub fn lab_attachments_for_this_thread() -> Option<bool> {
    ATTACHMENTS_LAB.with(std::cell::Cell::get)
}

/// Hard enable for profile pictures
/// (`docs/design/2026-11-profile-pictures.md` §23): setting one, sending it
/// to verified friends, and taking and showing theirs. False: not field
/// tested, not reviewed. A picture travels as an attachment, so this gate
/// is never open while the attachments gate is shut.
pub const PROFILE_PICTURES_PRODUCTION_ENABLED: bool = false;

const _: () = assert!(ATTACHMENTS_PRODUCTION_ENABLED || !PROFILE_PICTURES_PRODUCTION_ENABLED);

/// The profile pictures gate's debug lab switch.
pub const LAB_PROFILE_PICTURES: &str = "RAVEN_LAB_PROFILE_PICTURES";

/// The refusal every profile picture entry point gives while the gate is
/// closed.
pub const PROFILE_PICTURES_HOLD: &str = "PROFILE_PICTURES_HOLD: profile pictures are \
    lab-only (debug RAVEN_LAB_TEST_A=1 RAVEN_LAB_ATTACHMENTS=1 RAVEN_LAB_PROFILE_PICTURES=1); \
    PROFILE_PICTURES_PRODUCTION_ENABLED=false";

thread_local! {
    static PICTURES_LAB: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

/// Profile pictures are live: attachments are ([`attachments_live`]), and
/// the const (a release build follows it alone), or in a debug build this
/// thread's override, else the lab switch with the Lab Test A unlock;
/// unless a security notice holds `feature/profile-pictures`.
pub fn pictures_live() -> bool {
    let over = if cfg!(debug_assertions) {
        PICTURES_LAB.with(std::cell::Cell::get)
    } else {
        None
    };
    attachments_live()
        && over.unwrap_or_else(|| {
            crate::pair_init::lab_gate(PROFILE_PICTURES_PRODUCTION_ENABLED, LAB_PROFILE_PICTURES)
        })
        && crate::suite_policy::hold_allows(crate::suite_registry::FEATURE_PROFILE_PICTURES)
}

/// In-process tests switch profile pictures on or off for the current
/// thread only; `None` goes back to the const and the environment. Ignored
/// in release builds.
#[doc(hidden)]
pub fn set_lab_pictures_for_this_thread(on: Option<bool>) {
    PICTURES_LAB.with(|c| c.set(on));
}

/// This thread's override ([`set_lab_pictures_for_this_thread`]), for a
/// test that hands work to another thread.
#[doc(hidden)]
pub fn lab_pictures_for_this_thread() -> Option<bool> {
    PICTURES_LAB.with(std::cell::Cell::get)
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

    #[test]
    fn profile_pictures_production_flag_is_off() {
        const {
            assert!(!PROFILE_PICTURES_PRODUCTION_ENABLED);
        }
    }

    #[test]
    fn the_pictures_hold_names_the_flag_and_the_switches() {
        assert!(PROFILE_PICTURES_HOLD.starts_with("PROFILE_PICTURES_HOLD:"));
        assert!(PROFILE_PICTURES_HOLD.contains("PROFILE_PICTURES_PRODUCTION_ENABLED=false"));
        assert!(PROFILE_PICTURES_HOLD.contains("RAVEN_LAB_PROFILE_PICTURES=1"));
        assert!(PROFILE_PICTURES_HOLD.contains("RAVEN_LAB_ATTACHMENTS=1"));
    }

    /// Runs in both builds, as [`attachments_is_inert_in_release_builds`]
    /// does: a release build reads neither switch.
    #[test]
    fn profile_pictures_is_inert_in_release_builds() {
        if !cfg!(debug_assertions) {
            std::env::set_var(crate::pair_init::LAB_TEST_A, "1");
            std::env::set_var(LAB_ATTACHMENTS, "1");
            std::env::set_var(LAB_PROFILE_PICTURES, "1");
            assert!(
                !pictures_live(),
                "the switches opened the gate in a release build"
            );
            return;
        }
        let set = std::env::var(LAB_PROFILE_PICTURES).ok();
        let want = attachments_live()
            && crate::pair_init::lab_switch_value(
                true,
                crate::pair_init::lab_test_a_enabled(),
                set.as_deref(),
            )
            && crate::suite_policy::hold_allows(crate::suite_registry::FEATURE_PROFILE_PICTURES);
        assert_eq!(pictures_live(), want);
    }

    /// A picture travels as an attachment: with attachments off for this
    /// thread no switch of its own opens the pictures gate.
    #[test]
    fn pictures_are_never_live_while_attachments_are_not() {
        if !cfg!(debug_assertions) {
            return;
        }
        set_lab_attachments_for_this_thread(Some(false));
        set_lab_pictures_for_this_thread(Some(true));
        let live = pictures_live();
        set_lab_attachments_for_this_thread(Some(true));
        let both = pictures_live();
        set_lab_pictures_for_this_thread(Some(false));
        let off = pictures_live();
        set_lab_attachments_for_this_thread(None);
        set_lab_pictures_for_this_thread(None);
        assert!(!live);
        assert_eq!(
            both,
            crate::suite_policy::hold_allows(crate::suite_registry::FEATURE_PROFILE_PICTURES)
                && crate::suite_policy::hold_allows(crate::suite_registry::FEATURE_ATTACHMENTS)
        );
        assert!(!off);
    }
}
