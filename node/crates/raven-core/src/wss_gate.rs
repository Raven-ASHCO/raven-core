//! Phase 4 (restrictive networks) gates: relays over WebSocket/TLS on TCP
//! 443 and dialling them through an HTTPS proxy (HTTP CONNECT).
//!
//! Both sit on the p2p carrier ([`crate::P2P_PRODUCTION_ENABLED`]), the proxy
//! gate also on the WSS gate (the const asserts below), and both stay false
//! until the owner signs the WSS/proxy waiver (real rows R8w and R8p). A
//! debug build opens each with the p2p lab unlock (`RAVEN_LAB_TEST_A=1`) and
//! its own switch ([`crate::pair_init::lab_switch`]); the lab unlock alone
//! opens neither, so the Phase 1-3 lab runs keep testing what they test.
//! Release builds read neither switch. A security notice's hold on either
//! feature closes it after its own gate (P6.45, close-only). The proxy gate
//! is named WSS_PROXY (owner decision O4-8), never to be mistaken for the
//! `HTTP_PROXY` environment variable, which Raven does not read.

use crate::p2p_gate::gate_value;
use crate::pair_init::lab_switch;

/// Relays over WebSocket/TLS: a relay's two-protocol TCP 443 listener and
/// the WSS forms of a relay address a node dials.
pub const WSS_PRODUCTION_ENABLED: bool = false;

/// Dialling relays over WSS through an HTTPS proxy (HTTP CONNECT).
pub const WSS_PROXY_PRODUCTION_ENABLED: bool = false;

const _: () = assert!(!WSS_PRODUCTION_ENABLED || crate::P2P_PRODUCTION_ENABLED);
const _: () = assert!(!WSS_PROXY_PRODUCTION_ENABLED || WSS_PRODUCTION_ENABLED);

/// The refusal every WSS entry point prints while its gate is closed.
pub const WSS_HOLD: &str = "WSS_HOLD: relays over WebSocket/TLS (port 443) are lab-only \
    (debug RAVEN_LAB_TEST_A=1 RAVEN_LAB_WSS=1); WSS_PRODUCTION_ENABLED=false";

/// The refusal every proxy entry point prints while its gate is closed.
pub const WSS_PROXY_HOLD: &str = "WSS_PROXY_HOLD: dialling relays through an HTTPS proxy is \
    lab-only (debug RAVEN_LAB_TEST_A=1 RAVEN_LAB_WSS=1 RAVEN_LAB_WSS_PROXY=1); \
    WSS_PROXY_PRODUCTION_ENABLED=false";

/// Live WSS: the p2p carrier is live, and either [`WSS_PRODUCTION_ENABLED`]
/// or the debug switch `RAVEN_LAB_WSS`.
pub fn wss_live_enabled() -> bool {
    gate_value(WSS_PRODUCTION_ENABLED, crate::p2p_live_enabled(), || {
        lab_switch("RAVEN_LAB_WSS")
    }) && crate::suite_policy::hold_allows(crate::suite_registry::FEATURE_WSS)
}

/// Live proxy dials: WSS is live, and either [`WSS_PROXY_PRODUCTION_ENABLED`]
/// or the debug switch `RAVEN_LAB_WSS_PROXY`.
pub fn wss_proxy_live_enabled() -> bool {
    gate_value(WSS_PROXY_PRODUCTION_ENABLED, wss_live_enabled(), || {
        lab_switch("RAVEN_LAB_WSS_PROXY")
    }) && crate::suite_policy::hold_allows(crate::suite_registry::FEATURE_WSS_PROXY)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// WSS and its proxy stay off; the p2p carrier they sit on was switched
    /// on in 2026-10.
    #[test]
    fn production_flags_stay_false() {
        const {
            assert!(!WSS_PRODUCTION_ENABLED);
            assert!(!WSS_PROXY_PRODUCTION_ENABLED);
            assert!(crate::P2P_PRODUCTION_ENABLED);
        }
    }

    /// WSS needs the p2p carrier and its own switch; proxy dials need WSS
    /// and theirs. The lab unlock alone (p2p live, no switch) opens neither.
    #[test]
    fn gates_need_p2p_and_their_own_switch() {
        for p2p in [false, true] {
            for wss_switch in [false, true] {
                for proxy_switch in [false, true] {
                    let wss = gate_value(WSS_PRODUCTION_ENABLED, p2p, || wss_switch);
                    let proxy = gate_value(WSS_PROXY_PRODUCTION_ENABLED, wss, || proxy_switch);
                    let case = format!("p2p={p2p} wss={wss_switch} proxy={proxy_switch}");
                    assert_eq!(wss, p2p && wss_switch, "{case}");
                    assert_eq!(proxy, p2p && wss_switch && proxy_switch, "{case}");
                }
            }
        }
        // The lab unlock alone: a debug build with `RAVEN_LAB_TEST_A=1` (the
        // gate below live) and the gate's own switch unset.
        let unset = || crate::pair_init::lab_switch_value(true, true, None);
        assert!(!gate_value(WSS_PRODUCTION_ENABLED, true, unset));
        assert!(!gate_value(WSS_PROXY_PRODUCTION_ENABLED, true, unset));
    }

    #[test]
    fn hold_texts_name_flag_and_unlock() {
        for (hold, name, flag, switches) in [
            (
                WSS_HOLD,
                "WSS_HOLD:",
                "WSS_PRODUCTION_ENABLED=false",
                &["RAVEN_LAB_WSS=1"][..],
            ),
            (
                WSS_PROXY_HOLD,
                "WSS_PROXY_HOLD:",
                "WSS_PROXY_PRODUCTION_ENABLED=false",
                &["RAVEN_LAB_WSS=1", "RAVEN_LAB_WSS_PROXY=1"][..],
            ),
        ] {
            assert!(hold.starts_with(name), "{hold}");
            assert!(hold.contains(flag), "{hold}");
            assert!(hold.contains("RAVEN_LAB_TEST_A=1"), "{hold}");
            for switch in switches {
                assert!(hold.contains(switch), "{hold}: {switch}");
            }
        }
    }

    /// Runs in both builds: the release test jobs set the lab unlock and
    /// both switches, and both gates stay shut; a debug build follows exactly
    /// its environment and changes none of it (the other tests share it).
    #[test]
    fn lab_switches_are_inert_in_release() {
        if !cfg!(debug_assertions) {
            // Edition 2021: a plain call. No release test needs them unset.
            for name in ["RAVEN_LAB_TEST_A", "RAVEN_LAB_WSS", "RAVEN_LAB_WSS_PROXY"] {
                std::env::set_var(name, "1");
            }
            assert!(!wss_live_enabled());
            assert!(!wss_proxy_live_enabled());
            return;
        }
        let on = |name: &str| {
            crate::pair_init::lab_switch_value(
                true,
                crate::pair_init::lab_test_a_enabled(),
                std::env::var(name).ok().as_deref(),
            )
        };
        let wss = crate::p2p_live_enabled() && on("RAVEN_LAB_WSS");
        assert_eq!(wss_live_enabled(), wss);
        assert_eq!(wss_proxy_live_enabled(), wss && on("RAVEN_LAB_WSS_PROXY"));
    }
}
