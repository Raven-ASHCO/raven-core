//! Phase 6b gates and lab switches (`docs/roadmap/plans/phase6-design.json`,
//! step P6.21; designs A, B, C (remainder) and D).
//!
//! Every gate here stays `false` until the owner approves its own flip and
//! signs its own waiver (owner decision OD6b-1). A debug build opens one with
//! its lab switch, and only with the Lab Test A unlock: `RAVEN_LAB_TEST_A=1`
//! ([`crate::pair_init::lab_test_a_enabled`]) and the switch set to exactly
//! `1` ([`crate::p2p_gate::lab_flag`]), the Phase 4 pattern. A debug build
//! also closes one whose const is set: its switch set to exactly `0` (no Lab
//! Test A needed), as the LAN gates do ([`crate::lan_gate`]'s `gate_live`),
//! so the gate-closed paths and the harnesses' "old side" stay testable
//! after a flip. A release build reads neither variable: it follows the
//! const alone. A gate that sits on another one is live only while that one
//! is ([`SecGate::requires`]):
//!
//! | Gate ([`SecGate`]) | Lab switch | Requires | Holds |
//! |---|---|---|---|
//! | `Events` | `RAVEN_LAB_SECURITY_EVENTS` | | the `SEC_*` events (`docs/SECURITY_EVENTS.md`), the security ledger and IPC `Status.security` (design A) |
//! | `Responses` | `RAVEN_LAB_SECURITY_RESPONSES` | `Events` | the automatic responses R1-R9 (design A) |
//! | `SuiteFloor` | `RAVEN_LAB_SUITE_FLOOR` | `Events` | refusing a session profile below a contact's floor (design A R9) |
//! | `LinkPadding` | `RAVEN_LAB_LINK_PADDING` | | PAD1 link padding (design B) |
//! | `LinkKnock` | `RAVEN_LAB_LINK_KNOCK` | | the RLK1 link knock, per-connection Noise statics and silent mode (design B) |
//! | `RandomPort` | `RAVEN_LAB_RANDOM_PORT` | | a random LAN listen port for new profiles (design B, OD6b-10) |
//! | `PairSeed` | `RAVEN_LAB_PAIR_SEED` | route hints live | pair-seed rotation (`T_PAIR_SEED`, design B) |
//! | `LocalProtection` | `RAVEN_LAB_LOCAL_PROTECTION` | | Lock v2, auto-lock on sleep and the Raven passphrase (P6.40) |
//! | `Advisory` | `RAVEN_LAB_ADVISORY` | | threshold-signed security advisories (design D) |
//! | `ReleaseBundle` | `RAVEN_LAB_RELEASE_BUNDLE` | `Advisory` | verified release bundles (design D) |
//! | `MeshUpdate` | `RAVEN_LAB_MESH_UPDATE` | `ReleaseBundle` | passing advisories and bundles along between pinned contacts (RUP1, design D) |
//!
//! The merged Phase 6 retired 6b's `AT_REST_SEAL` gate: its content shipped
//! ungated in the privacy pack, so `LOCAL_PROTECTION` holds only Lock v2,
//! auto-lock on sleep and the Raven passphrase.
//!
//! One more debug switch is no gate: `RAVEN_LAB_SEC_PENALTY_LOOPBACK=1`
//! ([`lab_penalty_loopback`], step P6.26) lets the stranger penalty box ban
//! loopback too, which it never does otherwise (other local profiles and
//! every harness use it).
//!
//! In-process tests open or shut one gate for the current thread only
//! ([`set_lab_for_this_thread`]: in a debug build `Some(false)` shuts it
//! whatever its const says); a release build ignores that too. The
//! `node_policy` settings these gates guard are read only while the
//! matching gate is live (the `NodePolicy` accessors), so no build changes
//! behaviour before a flip.

use std::cell::Cell;

/// Design A: the `SEC_*` events, the security ledger and IPC
/// `Status.security`. While shut, nothing is noted or written.
pub const SECURITY_EVENTS_PRODUCTION_ENABLED: bool = false;
/// Design A: the automatic responses R1-R9 (on top of the events).
pub const SECURITY_RESPONSES_PRODUCTION_ENABLED: bool = false;
/// Design A R9: refuse a session profile below a contact's floor (on top of
/// the events).
pub const SUITE_FLOOR_PRODUCTION_ENABLED: bool = false;
/// Design B: PAD1 link padding.
pub const LINK_PADDING_PRODUCTION_ENABLED: bool = false;
/// Design B: the RLK1 link knock, per-connection Noise statics and silent
/// mode.
pub const LINK_KNOCK_PRODUCTION_ENABLED: bool = false;
/// Design B (OD6b-10): a random LAN listen port for new profiles.
pub const LISTEN_PORT_RANDOM_PRODUCTION_ENABLED: bool = false;
/// Design B: pair-seed rotation over route hints (on top of route hints).
pub const PAIR_SEED_PRODUCTION_ENABLED: bool = false;
/// Design C (remainder, P6.40): Lock v2, auto-lock on sleep and the Raven
/// passphrase.
pub const LOCAL_PROTECTION_PRODUCTION_ENABLED: bool = false;
/// Design D: threshold-signed security advisories.
pub const ADVISORY_PRODUCTION_ENABLED: bool = false;
/// Design D: verified release bundles (on top of advisories).
pub const RELEASE_BUNDLE_PRODUCTION_ENABLED: bool = false;
/// Design D: mesh pass-along of advisories and bundles (on top of bundles).
pub const MESH_UPDATE_PRODUCTION_ENABLED: bool = false;

// A const flipped on top of a shut one would still leave its feature shut
// in a release build: refuse to build instead.
const _: () = {
    assert!(!SECURITY_RESPONSES_PRODUCTION_ENABLED || SECURITY_EVENTS_PRODUCTION_ENABLED);
    assert!(!SUITE_FLOOR_PRODUCTION_ENABLED || SECURITY_EVENTS_PRODUCTION_ENABLED);
    assert!(!PAIR_SEED_PRODUCTION_ENABLED || crate::route_hints::ROUTE_HINTS_PRODUCTION_ENABLED);
    assert!(!RELEASE_BUNDLE_PRODUCTION_ENABLED || ADVISORY_PRODUCTION_ENABLED);
    assert!(!MESH_UPDATE_PRODUCTION_ENABLED || RELEASE_BUNDLE_PRODUCTION_ENABLED);
};

/// `=1` (debug, with `RAVEN_LAB_TEST_A=1`): [`SecGate::Events`].
pub const LAB_SECURITY_EVENTS: &str = "RAVEN_LAB_SECURITY_EVENTS";
/// `=1` (debug, with `RAVEN_LAB_TEST_A=1`): [`SecGate::Responses`].
pub const LAB_SECURITY_RESPONSES: &str = "RAVEN_LAB_SECURITY_RESPONSES";
/// `=1` (debug, with `RAVEN_LAB_TEST_A=1`): [`SecGate::SuiteFloor`].
pub const LAB_SUITE_FLOOR: &str = "RAVEN_LAB_SUITE_FLOOR";
/// `=1` (debug, with `RAVEN_LAB_TEST_A=1`): [`SecGate::LinkPadding`].
pub const LAB_LINK_PADDING: &str = "RAVEN_LAB_LINK_PADDING";
/// `=1` (debug, with `RAVEN_LAB_TEST_A=1`): [`SecGate::LinkKnock`].
pub const LAB_LINK_KNOCK: &str = "RAVEN_LAB_LINK_KNOCK";
/// `=1` (debug, with `RAVEN_LAB_TEST_A=1`): [`SecGate::RandomPort`].
pub const LAB_RANDOM_PORT: &str = "RAVEN_LAB_RANDOM_PORT";
/// `=1` (debug, with `RAVEN_LAB_TEST_A=1`): [`SecGate::PairSeed`].
pub const LAB_PAIR_SEED: &str = "RAVEN_LAB_PAIR_SEED";
/// `=1` (debug, with `RAVEN_LAB_TEST_A=1`): [`SecGate::LocalProtection`].
pub const LAB_LOCAL_PROTECTION: &str = "RAVEN_LAB_LOCAL_PROTECTION";
/// `=1` (debug, with `RAVEN_LAB_TEST_A=1`): [`SecGate::Advisory`].
pub const LAB_ADVISORY: &str = "RAVEN_LAB_ADVISORY";
/// `=1` (debug, with `RAVEN_LAB_TEST_A=1`): [`SecGate::ReleaseBundle`].
pub const LAB_RELEASE_BUNDLE: &str = "RAVEN_LAB_RELEASE_BUNDLE";
/// `=1` (debug, with `RAVEN_LAB_TEST_A=1`): [`SecGate::MeshUpdate`].
pub const LAB_MESH_UPDATE: &str = "RAVEN_LAB_MESH_UPDATE";

/// How many Phase 6b gates there are.
const GATES: usize = 11;

/// Every Phase 6b lab switch, in [`SecGate::ALL`] order (the harnesses
/// scrub these). In a debug build each also closes its gate when set to
/// exactly `0`, whatever the const says ([`live`]).
pub const SECURITY_LAB_SWITCHES: [&str; GATES] = [
    LAB_SECURITY_EVENTS,
    LAB_SECURITY_RESPONSES,
    LAB_SUITE_FLOOR,
    LAB_LINK_PADDING,
    LAB_LINK_KNOCK,
    LAB_RANDOM_PORT,
    LAB_PAIR_SEED,
    LAB_LOCAL_PROTECTION,
    LAB_ADVISORY,
    LAB_RELEASE_BUNDLE,
    LAB_MESH_UPDATE,
];

/// One Phase 6b gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SecGate {
    Events,
    Responses,
    SuiteFloor,
    LinkPadding,
    LinkKnock,
    RandomPort,
    PairSeed,
    LocalProtection,
    Advisory,
    ReleaseBundle,
    MeshUpdate,
}

/// What a gate sits on ([`SecGate::requires`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Requires {
    /// Nothing: the gate alone decides.
    Nothing,
    /// Another Phase 6b gate, which must be live too.
    Gate(SecGate),
    /// Route hints (RRH1) live ([`crate::route_hints::route_hints_live`]).
    RouteHints,
}

impl SecGate {
    /// Every gate, each once, in declaration order.
    pub const ALL: [SecGate; GATES] = [
        SecGate::Events,
        SecGate::Responses,
        SecGate::SuiteFloor,
        SecGate::LinkPadding,
        SecGate::LinkKnock,
        SecGate::RandomPort,
        SecGate::PairSeed,
        SecGate::LocalProtection,
        SecGate::Advisory,
        SecGate::ReleaseBundle,
        SecGate::MeshUpdate,
    ];

    /// The gate's production const.
    pub const fn production(self) -> bool {
        match self {
            SecGate::Events => SECURITY_EVENTS_PRODUCTION_ENABLED,
            SecGate::Responses => SECURITY_RESPONSES_PRODUCTION_ENABLED,
            SecGate::SuiteFloor => SUITE_FLOOR_PRODUCTION_ENABLED,
            SecGate::LinkPadding => LINK_PADDING_PRODUCTION_ENABLED,
            SecGate::LinkKnock => LINK_KNOCK_PRODUCTION_ENABLED,
            SecGate::RandomPort => LISTEN_PORT_RANDOM_PRODUCTION_ENABLED,
            SecGate::PairSeed => PAIR_SEED_PRODUCTION_ENABLED,
            SecGate::LocalProtection => LOCAL_PROTECTION_PRODUCTION_ENABLED,
            SecGate::Advisory => ADVISORY_PRODUCTION_ENABLED,
            SecGate::ReleaseBundle => RELEASE_BUNDLE_PRODUCTION_ENABLED,
            SecGate::MeshUpdate => MESH_UPDATE_PRODUCTION_ENABLED,
        }
    }

    /// The production const's name, as status and doctor output print it.
    pub const fn const_name(self) -> &'static str {
        match self {
            SecGate::Events => "SECURITY_EVENTS_PRODUCTION_ENABLED",
            SecGate::Responses => "SECURITY_RESPONSES_PRODUCTION_ENABLED",
            SecGate::SuiteFloor => "SUITE_FLOOR_PRODUCTION_ENABLED",
            SecGate::LinkPadding => "LINK_PADDING_PRODUCTION_ENABLED",
            SecGate::LinkKnock => "LINK_KNOCK_PRODUCTION_ENABLED",
            SecGate::RandomPort => "LISTEN_PORT_RANDOM_PRODUCTION_ENABLED",
            SecGate::PairSeed => "PAIR_SEED_PRODUCTION_ENABLED",
            SecGate::LocalProtection => "LOCAL_PROTECTION_PRODUCTION_ENABLED",
            SecGate::Advisory => "ADVISORY_PRODUCTION_ENABLED",
            SecGate::ReleaseBundle => "RELEASE_BUNDLE_PRODUCTION_ENABLED",
            SecGate::MeshUpdate => "MESH_UPDATE_PRODUCTION_ENABLED",
        }
    }

    /// The gate's debug lab switch (with `RAVEN_LAB_TEST_A=1`).
    pub const fn lab_switch(self) -> &'static str {
        SECURITY_LAB_SWITCHES[self as usize]
    }

    /// What the gate sits on.
    pub const fn requires(self) -> Requires {
        match self {
            SecGate::Responses | SecGate::SuiteFloor => Requires::Gate(SecGate::Events),
            SecGate::PairSeed => Requires::RouteHints,
            SecGate::ReleaseBundle => Requires::Gate(SecGate::Advisory),
            SecGate::MeshUpdate => Requires::Gate(SecGate::ReleaseBundle),
            SecGate::Events
            | SecGate::LinkPadding
            | SecGate::LinkKnock
            | SecGate::RandomPort
            | SecGate::LocalProtection
            | SecGate::Advisory => Requires::Nothing,
        }
    }
}

/// The gate is live: its production const, or in a debug build its lab
/// switch with the Lab Test A unlock (or this thread's override), and what
/// it sits on is live too. In a debug build the switch at `0` (or the
/// override at `Some(false)`) closes a gate whose const is set. A release
/// build reads no variable and no override. A security notice's hold on a
/// gate's feature (P6.45, [`crate::suite_policy::hold_allows`]) closes it,
/// and so every gate that sits on it; it can never open one, and
/// `Advisory` itself is never held.
pub fn live(g: SecGate) -> bool {
    live_from(g, &own_held, &crate::route_hints::route_hints_live)
}

/// [`live`] apart from a security notice's hold on `g`'s own feature: its
/// const or lab unlock, and what it sits on (their holds included). Only
/// the RLK1 listener asks it (raven-node, Phase 6 review traffic-4): a hold
/// on `feature/link-knock` (or a BROKEN `rlk1/1`) stops this node's knocks
/// and keeps its capability floors from noting the knock, while its
/// listener still proves itself to a contact that knocks. A contact whose
/// notice has not come yet would otherwise take it for an impostor at its
/// own address (no proof where its floor shows the knock) until the notice
/// reaches it. A release build reads no variable here either.
pub fn live_despite_own_hold(g: SecGate) -> bool {
    live_despite_hold_on(g, g)
}

/// [`live`] apart from a security notice's hold on the feature of `held`
/// (`g` itself or a gate it sits on): every const and lab unlock, and every
/// other hold. Besides [`live_despite_own_hold`], only the update exchange
/// asks it (Phase 6 review updates-protocol-4): notices pass between
/// friends while release bundles are held (`feature/release-bundle`), or a
/// hold on bundles would stop the notice that lifts it.
pub fn live_despite_hold_on(g: SecGate, held: SecGate) -> bool {
    live_from(
        g,
        &|x| if x == held { own_open(x) } else { own_held(x) },
        &crate::route_hints::route_hints_live,
    )
}

/// [`own_open`], then the gate's feature hold (asked only while the gate
/// is open).
fn own_held(g: SecGate) -> bool {
    own_open(g) && (g == SecGate::Advisory || crate::suite_policy::hold_allows_gate(g.const_name()))
}

/// [`live`] with the gates' own state (`own`, before what they sit on) and
/// route hints passed in.
fn live_from(g: SecGate, own: &dyn Fn(SecGate) -> bool, route_hints: &dyn Fn() -> bool) -> bool {
    own(g)
        && match g.requires() {
            Requires::Nothing => true,
            Requires::Gate(below) => live_from(below, own, route_hints),
            Requires::RouteHints => route_hints(),
        }
}

/// The gate on its own: the const, or in a debug build its lab switch
/// ([`lab_gate`]).
fn own_open(g: SecGate) -> bool {
    lab_gate(
        cfg!(debug_assertions),
        production(g),
        lab_override(g),
        crate::pair_init::lab_test_a_enabled,
        || std::env::var(g.lab_switch()).ok(),
    )
}

/// The gate's production const ([`SecGate::production`]).
#[cfg(not(test))]
fn production(g: SecGate) -> bool {
    g.production()
}

/// raven-core's own unit tests: the const, or one this thread pretends is
/// set (`tests::Flipped`), so the debug close of a flipped gate is proven
/// before any const is flipped.
#[cfg(test)]
fn production(g: SecGate) -> bool {
    g.production() || tests::pretends_flipped(g)
}

/// A gate on its own from its inputs. A release build: exactly the const
/// (`production`); `test_a` and `value` are not called and `over` is
/// ignored, so nothing a user sets opens or closes a gate. A debug build:
/// this thread's override when one is set (`Some(false)` closes even a gate
/// whose const is set); else a set const unless the switch is exactly `0`,
/// and a const that is not set only with the Lab Test A unlock and the
/// switch exactly `1` (the variable is not read without the unlock).
fn lab_gate(
    debug: bool,
    production: bool,
    over: Option<bool>,
    test_a: impl FnOnce() -> bool,
    value: impl FnOnce() -> Option<String>,
) -> bool {
    if !debug {
        return production;
    }
    if let Some(open) = over {
        return open;
    }
    if production {
        value().as_deref() != Some("0")
    } else {
        test_a() && crate::p2p_gate::lab_flag(true, value)
    }
}

thread_local! {
    static LAB_OVERRIDE: Cell<[Option<bool>; GATES]> = const { Cell::new([None; GATES]) };
}

/// This thread's override of `g`'s lab unlock (`None`: the variables).
fn lab_override(g: SecGate) -> Option<bool> {
    LAB_OVERRIDE.with(|cell| cell.get()[g as usize])
}

/// In-process tests open (`Some(true)`) or shut (`Some(false)`) one gate
/// for the current thread only, in place of the variables (which would leak
/// into every other test of the binary); `None` goes back to the variables.
/// `Some(false)` shuts the gate even when its const is set (the debug close:
/// a test that wants the gate shut keeps testing it shut after a flip). What
/// the gate sits on still applies, and so does a security notice's hold.
/// Ignored in release builds, like the variables: there the const decides.
#[doc(hidden)]
pub fn set_lab_for_this_thread(g: SecGate, on: Option<bool>) {
    LAB_OVERRIDE.with(|cell| {
        let mut all = cell.get();
        all[g as usize] = on;
        cell.set(all);
    });
}

/// Every gate's override on this thread ([`set_lab_for_this_thread`]), to
/// carry into a blocking thread an in-process test's work moves to (P6.49,
/// raven-node's update exchange). All `None` outside such a test; ignored in
/// release builds, like the overrides themselves.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LabOverrides([Option<bool>; GATES]);

/// This thread's overrides ([`LabOverrides`]).
#[doc(hidden)]
pub fn lab_overrides_for_this_thread() -> LabOverrides {
    LabOverrides(LAB_OVERRIDE.with(Cell::get))
}

/// Replace this thread's overrides with `overrides`; the ones before are
/// returned (to put back when the borrowed thread is done).
#[doc(hidden)]
pub fn set_lab_overrides_for_this_thread(overrides: LabOverrides) -> LabOverrides {
    LabOverrides(LAB_OVERRIDE.with(|cell| cell.replace(overrides.0)))
}

/// `=1` (debug only): the penalty box bans loopback like any source.
pub const LAB_SEC_PENALTY_LOOPBACK: &str = "RAVEN_LAB_SEC_PENALTY_LOOPBACK";

/// Debug only (step P6.26): [`LAB_SEC_PENALTY_LOOPBACK`] is exactly `1`, so
/// raven-node's penalty box (design A R1) does not spare loopback and a
/// one-computer test can watch it ban. It acts only while
/// [`SecGate::Responses`] is live. A release build never reads the variable.
pub fn lab_penalty_loopback() -> bool {
    crate::p2p_gate::lab_flag(cfg!(debug_assertions), || {
        std::env::var(LAB_SEC_PENALTY_LOOPBACK).ok()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_flags_stay_false() {
        const {
            assert!(!SECURITY_EVENTS_PRODUCTION_ENABLED);
            assert!(!SECURITY_RESPONSES_PRODUCTION_ENABLED);
            assert!(!SUITE_FLOOR_PRODUCTION_ENABLED);
            assert!(!LINK_PADDING_PRODUCTION_ENABLED);
            assert!(!LINK_KNOCK_PRODUCTION_ENABLED);
            assert!(!LISTEN_PORT_RANDOM_PRODUCTION_ENABLED);
            assert!(!PAIR_SEED_PRODUCTION_ENABLED);
            assert!(!LOCAL_PROTECTION_PRODUCTION_ENABLED);
            assert!(!ADVISORY_PRODUCTION_ENABLED);
            assert!(!RELEASE_BUNDLE_PRODUCTION_ENABLED);
            assert!(!MESH_UPDATE_PRODUCTION_ENABLED);
        }
        assert!(SecGate::ALL.iter().all(|g| !g.production()));
    }

    #[test]
    fn every_gate_has_its_own_names() {
        for (i, g) in SecGate::ALL.iter().enumerate() {
            assert_eq!(*g as usize, i, "{g:?}");
            assert_eq!(g.lab_switch(), SECURITY_LAB_SWITCHES[i]);
            assert!(g.lab_switch().starts_with("RAVEN_LAB_"), "{g:?}");
            assert!(g.const_name().ends_with("_PRODUCTION_ENABLED"), "{g:?}");
        }
        for names in [
            SecGate::ALL.map(SecGate::lab_switch),
            SecGate::ALL.map(SecGate::const_name),
        ] {
            let mut sorted = names.to_vec();
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(sorted.len(), GATES, "{names:?}");
        }
        // No switch is another gate's or Phase 6a's.
        for name in SECURITY_LAB_SWITCHES {
            assert!(!crate::learning::LEARNING_LAB_SWITCHES.contains(&name));
            assert!(!crate::lan_gate::PRIVACY_LAB_SWITCHES.contains(&name));
        }
        assert_eq!(SecGate::Events.lab_switch(), "RAVEN_LAB_SECURITY_EVENTS");
        assert_eq!(SecGate::RandomPort.lab_switch(), "RAVEN_LAB_RANDOM_PORT");
        assert_eq!(
            SecGate::RandomPort.const_name(),
            "LISTEN_PORT_RANDOM_PRODUCTION_ENABLED"
        );
    }

    /// The requirement table, written out on its own (not from
    /// `requires`), checked for every combination of the gates' own state
    /// and route hints.
    #[test]
    fn requirement_table() {
        use SecGate::*;
        let expect = |g: SecGate, own: &dyn Fn(SecGate) -> bool, hints: bool| match g {
            Events | LinkPadding | LinkKnock | RandomPort | LocalProtection | Advisory => own(g),
            Responses | SuiteFloor => own(g) && own(Events),
            PairSeed => own(g) && hints,
            ReleaseBundle => own(g) && own(Advisory),
            MeshUpdate => own(g) && own(ReleaseBundle) && own(Advisory),
        };
        for bits in 0u32..(1 << GATES) {
            let own = move |g: SecGate| bits & (1 << g as usize) != 0;
            for hints in [false, true] {
                for g in SecGate::ALL {
                    assert_eq!(
                        live_from(g, &own, &|| hints),
                        expect(g, &own, hints),
                        "{g:?} bits={bits:#013b} hints={hints}"
                    );
                }
            }
        }
        // The named rows.
        let only = |on: &'static [SecGate]| move |g: SecGate| on.contains(&g);
        let yes = || true;
        let no = || false;
        assert!(!live_from(Responses, &only(&[Responses]), &yes));
        assert!(live_from(Responses, &only(&[Responses, Events]), &no));
        assert!(!live_from(SuiteFloor, &only(&[SuiteFloor]), &yes));
        assert!(!live_from(MeshUpdate, &only(&[MeshUpdate, Advisory]), &yes));
        assert!(!live_from(
            MeshUpdate,
            &only(&[MeshUpdate, ReleaseBundle]),
            &yes
        ));
        assert!(live_from(
            MeshUpdate,
            &only(&[MeshUpdate, ReleaseBundle, Advisory]),
            &no
        ));
        assert!(!live_from(ReleaseBundle, &only(&[ReleaseBundle]), &yes));
        assert!(!live_from(PairSeed, &only(&[PairSeed]), &no));
        assert!(live_from(PairSeed, &only(&[PairSeed]), &yes));
        // A gate below never opens the one above it.
        assert!(!live_from(Responses, &only(&[Events]), &yes));
        assert!(!live_from(PairSeed, &only(&[]), &yes));
    }

    thread_local! {
        static FLIPPED: Cell<[bool; GATES]> = const { Cell::new([false; GATES]) };
    }

    /// This thread pretends the gate's const is set ([`Flipped`]).
    pub(super) fn pretends_flipped(g: SecGate) -> bool {
        FLIPPED.with(|cell| cell.get()[g as usize])
    }

    /// This thread pretends some gates' consts are set until dropped (the
    /// real consts stay as they are: `production_flags_stay_false`).
    struct Flipped;

    impl Flipped {
        fn set(gates: &[SecGate]) -> Self {
            FLIPPED.with(|cell| {
                let mut all = cell.get();
                for g in gates {
                    all[*g as usize] = true;
                }
                cell.set(all);
            });
            Flipped
        }
    }

    impl Drop for Flipped {
        fn drop(&mut self) {
            FLIPPED.with(|cell| cell.set([false; GATES]));
        }
    }

    #[test]
    fn lab_unlock_needs_debug_test_a_and_exactly_one() {
        let unread = || -> Option<String> { panic!("read the variable") };
        let no_test_a = || -> bool { panic!("read RAVEN_LAB_TEST_A") };
        // Release: nothing is read and the override is ignored.
        for over in [None, Some(true), Some(false)] {
            assert!(!lab_gate(false, false, over, no_test_a, unread), "{over:?}");
        }
        // Debug: the override wins over the variables.
        assert!(lab_gate(true, false, Some(true), no_test_a, unread));
        assert!(!lab_gate(true, false, Some(false), no_test_a, unread));
        // Debug without an override: Lab Test A first, then exactly "1".
        assert!(!lab_gate(true, false, None, || false, unread));
        for value in [
            None,
            Some(""),
            Some("0"),
            Some(" 1"),
            Some("true"),
            Some("yes"),
        ] {
            let read = || value.map(str::to_owned);
            assert!(!lab_gate(true, false, None, || true, read), "{value:?}");
        }
        assert!(lab_gate(true, false, None, || true, || Some("1".into())));
    }

    /// The debug close (cross-cutting finding 4 of the 0.1.1 protections
    /// report, before any flip): a gate whose const is set is closed in a
    /// debug build by its switch at exactly `0` (no Lab Test A needed) or
    /// by this thread's `Some(false)`, and by nothing else; a release build
    /// follows the const and reads nothing (the LAN gates' rule,
    /// `lan_gate::debug_zero_closes_an_open_gate`).
    #[test]
    fn debug_zero_closes_a_flipped_gate() {
        let unread = || -> Option<String> { panic!("read the variable") };
        let no_test_a = || -> bool { panic!("read RAVEN_LAB_TEST_A") };
        // Release: exactly the const, whatever is set.
        for over in [None, Some(true), Some(false)] {
            assert!(lab_gate(false, true, over, no_test_a, unread), "{over:?}");
            assert!(!lab_gate(false, false, over, no_test_a, unread), "{over:?}");
        }
        // Debug: the override first, both ways.
        assert!(!lab_gate(true, true, Some(false), no_test_a, unread));
        assert!(lab_gate(true, true, Some(true), no_test_a, unread));
        // Debug, no override: only exactly "0" closes it; Lab Test A is
        // never asked.
        assert!(!lab_gate(true, true, None, no_test_a, || Some("0".into())));
        for value in [
            None,
            Some(""),
            Some("1"),
            Some(" 0"),
            Some("false"),
            Some("no"),
        ] {
            let read = || value.map(str::to_owned);
            assert!(lab_gate(true, true, None, no_test_a, read), "{value:?}");
        }
    }

    /// The same through the gates themselves: with every const pretended
    /// set on this thread (the real consts stay false), `Some(false)` shuts
    /// each gate in a debug build, and with it every gate that sits on it;
    /// a release build ignores the override and follows the const. The
    /// in-process tests' `Some(false)` (and raven-node's `PaddingForTest` /
    /// `KnockForTest`) therefore keep testing a shut gate after a flip.
    #[test]
    fn some_false_shuts_a_flipped_gate_in_debug_only() {
        let debug = cfg!(debug_assertions);
        // Every const as if flipped: what each gate sits on is open too.
        let flipped = Flipped::set(&SecGate::ALL);
        let own = &own_open;
        let hints = || true;
        for g in SecGate::ALL {
            // No override: open, unless this debug process's own switch
            // for it is exactly "0".
            let zero = debug && std::env::var(g.lab_switch()).ok().as_deref() == Some("0");
            assert_eq!(own_open(g), !zero, "{g:?}");
            set_lab_for_this_thread(g, Some(false));
            assert_eq!(own_open(g), !debug, "{g:?} shut by Some(false)");
            assert_eq!(live_from(g, own, &hints), !debug, "{g:?}");
            set_lab_for_this_thread(g, Some(true));
            assert!(own_open(g), "{g:?}");
            set_lab_for_this_thread(g, None);
        }
        // A gate below that is shut shuts the one above it.
        set_lab_for_this_thread(SecGate::Events, Some(false));
        set_lab_for_this_thread(SecGate::Responses, Some(true));
        assert_eq!(live_from(SecGate::Responses, own, &hints), !debug);
        set_lab_for_this_thread(SecGate::Advisory, Some(false));
        assert_eq!(live_from(SecGate::MeshUpdate, own, &hints), !debug);
        for g in SecGate::ALL {
            set_lab_for_this_thread(g, None);
        }
        drop(flipped);
        // Nothing pretended any more: every real const is false.
        assert!(SecGate::ALL.iter().all(|g| !production(*g)));
    }

    #[test]
    fn the_override_is_per_thread_and_debug_only() {
        let debug = cfg!(debug_assertions);
        for g in SecGate::ALL {
            set_lab_for_this_thread(g, Some(false));
            assert!(!live(g), "{g:?} shut by the override");
        }
        set_lab_for_this_thread(SecGate::Responses, Some(true));
        assert!(!live(SecGate::Responses), "events still shut");
        set_lab_for_this_thread(SecGate::Events, Some(true));
        assert_eq!(live(SecGate::Events), debug);
        assert_eq!(live(SecGate::Responses), debug);
        set_lab_for_this_thread(SecGate::MeshUpdate, Some(true));
        set_lab_for_this_thread(SecGate::ReleaseBundle, Some(true));
        assert!(!live(SecGate::MeshUpdate), "advisory still shut");
        set_lab_for_this_thread(SecGate::Advisory, Some(true));
        assert_eq!(live(SecGate::MeshUpdate), debug);
        // Another thread sees none of it.
        std::thread::spawn(|| {
            assert!(SecGate::ALL.iter().all(|g| lab_override(*g).is_none()));
        })
        .join()
        .unwrap();
        for g in SecGate::ALL {
            set_lab_for_this_thread(g, None);
            assert_eq!(lab_override(g), None);
        }
    }
}
