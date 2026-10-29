//! Bluetooth LE nearby carrier (RNL1, `protocol/RAVEN_NEARBY_LINK_V1.md`)
//! gate.
//!
//! Independent of the LAN, Internet direct, p2p and custody gates. Switched
//! on in release builds for macOS only in 2026-10, after the three-machine
//! field test (a Bluetooth chain between two Macs, both ways); not
//! independently reviewed, and the physical rows N1-N12 are not all signed
//! (owner decision O5-13 asked for them first). Windows and Linux have no
//! release Bluetooth backend: there it stays lab-only, and a release build
//! never advertises, scans, knocks or dials over Bluetooth. On macOS the
//! radio runs only after `raven nearby enable` (verified contacts only), in
//! a build with the `nearby-radio` feature and the RavenNearby.app helper.
//!
//! The debug switch is `RAVEN_LAB_NEARBY` ([`crate::pair_init::lab_gate`]):
//! "0" closes the gate; on Windows and Linux "1" opens it with the Lab Test
//! A unlock (`RAVEN_LAB_TEST_A=1`), which alone never opens nearby.

/// Hard enable for the nearby carrier: on in release builds for macOS
/// (switched on 2026-10 after the three-machine field test; not
/// independently reviewed), off on Windows and Linux, which have no release
/// Bluetooth backend.
pub const NEARBY_PRODUCTION_ENABLED: bool = cfg!(target_os = "macos");

/// The nearby carrier's debug lab switch: "0" closes it; on Windows and
/// Linux "1" opens it with `RAVEN_LAB_TEST_A=1`.
pub const LAB_NEARBY: &str = "RAVEN_LAB_NEARBY";

/// The one refusal every nearby entry point (the service task, a nearby
/// dial, IPC, `raven nearby`, `raven send --carrier nearby`) prints while
/// the gate is closed: on macOS only a debug build closes it (or a security
/// notice); on Windows and Linux release builds have no Bluetooth nearby.
pub const NEARBY_HOLD: &str = if NEARBY_PRODUCTION_ENABLED {
    "NEARBY_HOLD: the Bluetooth nearby carrier is closed in this process (a debug build with \
     RAVEN_LAB_NEARBY=0, or a security notice); release builds on macOS have it on \
     (NEARBY_PRODUCTION_ENABLED=true)"
} else {
    "NEARBY_HOLD: Bluetooth nearby is in release builds on macOS only; on this system it is \
     lab-only (debug RAVEN_LAB_TEST_A=1 with RAVEN_LAB_NEARBY=1); NEARBY_PRODUCTION_ENABLED=false"
};

/// Live nearby carrier: the production const (a debug build: `RAVEN_LAB_NEARBY=0`
/// closes it; on Windows and Linux `RAVEN_LAB_NEARBY=1` with the Lab Test A
/// unlock opens it; a release build reads neither variable); unless a
/// security notice holds it or marks `rnl1/1` BROKEN (P6.45, close-only).
pub fn nearby_live_enabled() -> bool {
    crate::pair_init::lab_gate(NEARBY_PRODUCTION_ENABLED, LAB_NEARBY)
        && crate::suite_policy::hold_allows(crate::suite_registry::FEATURE_NEARBY)
}

/// The debug lab switch (with `RAVEN_LAB_TEST_A=1`) that makes this process
/// carry over Bluetooth nearby alone ([`nearby_only`]).
pub const LAB_NEARBY_ONLY: &str = "RAVEN_LAB_NEARBY_ONLY";

/// What a process under [`LAB_NEARBY_ONLY`] says once at its start (the
/// field test's proof that a node used nothing but Bluetooth starts here).
pub const NEARBY_ONLY_NOTE: &str = "lab nearby-only (RAVEN_LAB_NEARBY_ONLY=1): no LAN listener, \
    LAN dial or LAN beacon, no Internet direct, no p2p host, relay or port mapping in this \
    process; only Bluetooth nearby carries";

/// A debug lab run that simulates a computer with no network at all for
/// Raven, without cutting the computer's network (the field test's
/// Bluetooth-only node C; offline mesh carry research, Phase 0): with
/// [`LAB_NEARBY_ONLY`] the LAN ([`crate::lan_direct_live_enabled`]),
/// Internet direct ([`crate::internet_direct_live_enabled`]), p2p
/// ([`crate::p2p_live_enabled`], and with it the friend relay, port
/// mapping, WSS and the NAT class) and LAN beacon
/// ([`crate::lan_beacon_live`]) gates read closed in this process, so
/// nothing listens or dials on them; the nearby carrier is untouched. Close
/// only: it never opens a gate. A release build never reads the variable,
/// and it needs the Lab Test A unlock like every per-feature switch.
pub fn nearby_only() -> bool {
    crate::pair_init::lab_switch(LAB_NEARBY_ONLY)
}

/// `open` unless this process carries over nearby alone ([`nearby_only`]):
/// the LAN, Internet direct, p2p and LAN beacon gates go through it.
pub fn unless_nearby_only(open: bool) -> bool {
    open && !nearby_only()
}

static NEARBY_RUNNING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// raven-node's nearby service runs an engine in this process now that can
/// go on the air: the user enabled nearby, the radio started, the engine has
/// not ended, and its radio does not use the adapter's fixed public address
/// (owner decision O5-12, row N7w: such an engine neither advertises,
/// scans nor connects, unless a debug lab run allows the public address).
/// Only raven-node's nearby service sets it; it is false in every other
/// process. Whether it changed.
pub fn set_nearby_running(on: bool) -> bool {
    NEARBY_RUNNING.swap(on, std::sync::atomic::Ordering::Relaxed) != on
}

/// Whether this process runs a nearby engine that can go on the air
/// ([`set_nearby_running`]).
pub fn nearby_running() -> bool {
    NEARBY_RUNNING.load(std::sync::atomic::Ordering::Relaxed)
}

/// The nearby carrier can carry something now: its gate is live and this
/// process runs a nearby engine that can go on the air. A node whose user
/// never enabled nearby, whose build has no Bluetooth backend, whose radio
/// did not start, or whose radio would use its fixed public address (Windows
/// today, Linux without `Privacy = device`; offline mesh carry research,
/// Phase 0) serves nothing over nearby, so custody must not count the
/// carrier for it ([`crate::custody_gate::carrier_gates_now`]; review
/// nearby-2), as it does not count LAN under `raven lan off`
/// ([`crate::lan_usable_now`]).
pub fn nearby_usable_now() -> bool {
    nearby_usable(nearby_live_enabled(), nearby_running())
}

/// [`nearby_usable_now`] from its inputs.
pub fn nearby_usable(live: bool, running: bool) -> bool {
    live && running
}

/// Module test lock for [`NEARBY_RUNNING`] (one flag per process), as for
/// `raven lan off`: a test that sets it holds the lock for writing
/// ([`nearby_running_for_test`]); a test that reads the carrier gates as
/// the process sets them holds it for reading
/// ([`nearby_running_untouched`]).
#[cfg(test)]
static NEARBY_RUNNING_TEST_LOCK: std::sync::RwLock<()> = std::sync::RwLock::new(());

/// Test-only: the engine flag set to `on` while the guard lives, under the
/// module test lock; dropping it clears the flag.
#[cfg(test)]
pub(crate) fn nearby_running_for_test(on: bool) -> NearbyRunningForTest {
    let lock = NEARBY_RUNNING_TEST_LOCK
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    set_nearby_running(on);
    NearbyRunningForTest { _lock: lock }
}

/// [`nearby_running_for_test`]'s guard.
#[cfg(test)]
pub(crate) struct NearbyRunningForTest {
    _lock: std::sync::RwLockWriteGuard<'static, ()>,
}

#[cfg(test)]
impl Drop for NearbyRunningForTest {
    fn drop(&mut self) {
        set_nearby_running(false);
    }
}

/// Test-only: no test changes the engine flag while the guard lives.
#[cfg(test)]
pub(crate) fn nearby_running_untouched() -> std::sync::RwLockReadGuard<'static, ()> {
    NEARBY_RUNNING_TEST_LOCK
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// What a nearby dial answers in a raven-node that runs no nearby engine:
/// [`NEARBY_HOLD`] while the gate is closed, else that nearby is not
/// running. Nothing is dialled either way.
pub fn nearby_dial_unavailable() -> String {
    if nearby_live_enabled() {
        "nearby not running: this raven-node has no nearby engine".into()
    } else {
        NEARBY_HOLD.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-10: on in release builds for macOS only; the generic PairInit
    /// tripwire stays off.
    #[test]
    fn production_flag_is_on_for_macos_only() {
        const {
            assert!(NEARBY_PRODUCTION_ENABLED == cfg!(target_os = "macos"));
            assert!(!crate::pair_init::PRODUCTION_ENABLED);
        }
    }

    /// The Lab Test A unlock alone never opens nearby where it is held; the
    /// switch alone does not either; "0" closes it in a debug build. Runs in
    /// both builds: a release build follows the const alone, whatever the
    /// environment says.
    #[test]
    fn lab_test_a_alone_does_not_open_nearby() {
        use crate::pair_init::{lab_gate_value, lab_switch_value, lab_test_a_enabled};
        for v in ["1", "true", "TRUE", "yes"] {
            assert!(!lab_switch_value(true, false, Some(v)), "no TEST_A: {v}");
            assert!(lab_switch_value(true, true, Some(v)), "{v}");
            assert!(!lab_switch_value(false, true, Some(v)), "release: {v}");
        }
        for v in [None, Some(""), Some("0"), Some(" 1"), Some("on")] {
            assert!(!lab_switch_value(true, true, v), "{v:?}");
        }
        assert!(!lab_gate_value(true, true, true, Some("0")));
        assert!(!lab_gate_value(true, false, true, None), "the unlock alone");
        // This process: exactly what its build and environment say.
        let set = std::env::var(LAB_NEARBY).ok();
        let want = lab_gate_value(
            cfg!(debug_assertions),
            NEARBY_PRODUCTION_ENABLED,
            lab_test_a_enabled(),
            set.as_deref(),
        );
        assert_eq!(nearby_live_enabled(), want);
        if set.is_none() {
            assert_eq!(nearby_live_enabled(), NEARBY_PRODUCTION_ENABLED, "unset");
        }
        if !cfg!(debug_assertions) {
            assert_eq!(nearby_live_enabled(), NEARBY_PRODUCTION_ENABLED, "release");
        }
    }

    /// Review nearby-2: the carrier is usable only with the gate live and an
    /// engine running in this process; the engine flag alone never opens
    /// the gate.
    #[test]
    fn nearby_usable_needs_the_gate_and_a_running_engine() {
        assert!(nearby_usable(true, true));
        assert!(!nearby_usable(true, false));
        assert!(!nearby_usable(false, true));
        assert!(!nearby_usable(false, false));
        {
            let _idle = nearby_running_for_test(false);
            assert!(!nearby_running() && !nearby_usable_now());
        }
        {
            let _running = nearby_running_for_test(true);
            assert!(nearby_running());
            assert_eq!(nearby_usable_now(), nearby_live_enabled());
        }
        let _untouched = nearby_running_untouched();
        assert!(!nearby_running(), "the guard cleared it");
    }

    /// The nearby-only lab switch only closes: off, every gate reads as it
    /// would; on (debug, Lab Test A, `RAVEN_LAB_NEARBY_ONLY=1`), the gates
    /// it covers read closed and nothing reads open that was closed. A
    /// release build never reads it.
    #[test]
    fn nearby_only_closes_and_never_opens() {
        use crate::pair_init::lab_switch_value;
        for v in ["1", "true", "TRUE", "yes"] {
            assert!(lab_switch_value(true, true, Some(v)), "{v}");
            assert!(!lab_switch_value(true, false, Some(v)), "no TEST_A: {v}");
            assert!(!lab_switch_value(false, true, Some(v)), "release: {v}");
        }
        let switch = cfg!(debug_assertions)
            && crate::pair_init::lab_test_a_enabled()
            && matches!(
                std::env::var(LAB_NEARBY_ONLY).ok().as_deref(),
                Some("1" | "true" | "TRUE" | "yes")
            );
        assert_eq!(nearby_only(), switch);
        if !cfg!(debug_assertions) || std::env::var(LAB_NEARBY_ONLY).is_err() {
            assert!(!nearby_only());
        }
        assert!(!unless_nearby_only(false), "it never opens a gate");
        assert_eq!(unless_nearby_only(true), !switch);
        if switch {
            assert!(!crate::lan_direct_live_enabled());
            assert!(!crate::internet_direct_live_enabled());
            assert!(!crate::p2p_live_enabled());
            assert!(!crate::lan_beacon_live());
        }
        assert!(NEARBY_ONLY_NOTE.contains(LAB_NEARBY_ONLY));
        assert!(NEARBY_ONLY_NOTE.contains("only Bluetooth nearby carries"));
    }

    #[test]
    fn gate_does_not_open_generic_live_enabled() {
        if nearby_live_enabled() {
            return;
        }
        assert!(nearby_dial_unavailable().starts_with("NEARBY_HOLD:"));
        assert_eq!(nearby_dial_unavailable(), NEARBY_HOLD);
    }

    /// macOS: the hold names the const (on) and the close switch; Windows
    /// and Linux: it says release builds have nearby on macOS only, and
    /// names the lab unlock.
    #[test]
    fn hold_text_names_the_flag_and_the_switch() {
        assert!(NEARBY_HOLD.starts_with("NEARBY_HOLD:"));
        assert!(NEARBY_HOLD.contains(LAB_NEARBY));
        if cfg!(target_os = "macos") {
            assert!(NEARBY_HOLD.contains("NEARBY_PRODUCTION_ENABLED=true"));
            assert!(NEARBY_HOLD.contains("RAVEN_LAB_NEARBY=0"));
            assert!(!NEARBY_HOLD.contains("lab-only"));
        } else {
            assert!(NEARBY_HOLD.contains("NEARBY_PRODUCTION_ENABLED=false"));
            assert!(NEARBY_HOLD.contains("macOS only"));
            assert!(NEARBY_HOLD.contains("RAVEN_LAB_TEST_A=1"));
            assert!(NEARBY_HOLD.contains("RAVEN_LAB_NEARBY=1"));
        }
    }
}
