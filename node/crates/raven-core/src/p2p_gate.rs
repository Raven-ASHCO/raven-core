//! libp2p carrier (P3: direct TCP/QUIC, Circuit Relay v2, DCUtR) lab gate.
//!
//! Independent of the four global `PRODUCTION_ENABLED` tripwires, of
//! [`crate::LAN_DIRECT_PRODUCTION_ENABLED`], of
//! [`crate::INTERNET_DIRECT_PRODUCTION_ENABLED`] and of the separate
//! `raven-swarm` NAT experiment (`PRODUCTION_NAT_CONNECTIVITY_ENABLED`). Stays
//! false until a founder GO after the relay and DCUtR physical rows (R7b, R8)
//! and the waiver (docs/WAIVER_P2P_RELAY_DRAFT.md). With it off a release
//! build never listens, dials, reserves or advertises libp2p. Not a WAN /
//! multi-NAT claim.
//!
//! Phase 2 friend relays (any-network plan C6/C7) sit behind a gate of their
//! own on top of this one, [`FRIEND_RELAY_PRODUCTION_ENABLED`], with their
//! own debug switch: the Phase 1 lab unlock (`RAVEN_LAB_TEST_A=1`) alone
//! never opens them, so the Phase 1 lab runs keep testing Phase 1.

/// Hard enable for the libp2p carrier and the relay role.
/// Lab smoke uses debug `RAVEN_LAB_TEST_A=1` instead of flipping this.
pub const P2P_PRODUCTION_ENABLED: bool = false;

/// The one refusal every p2p entry point (service host, relay, dial, IPC,
/// `raven send --carrier p2p`) prints while the gate is closed.
pub const P2P_HOLD: &str = "P2P_HOLD: the libp2p carrier (relay + hole punching) is lab-only \
    (debug RAVEN_LAB_TEST_A=1); P2P_PRODUCTION_ENABLED=false; localhost ≠ WAN Proven";

/// Live libp2p carrier: compile-time slice gate or debug lab, unless a
/// security notice holds it (P6.45, close-only) or a debug lab run carries
/// over nearby alone ([`crate::nearby_gate::nearby_only`]; the friend relay,
/// port mapping, WSS and the NAT class sit on this gate and close with it).
pub fn p2p_live_enabled() -> bool {
    crate::nearby_gate::unless_nearby_only(
        (P2P_PRODUCTION_ENABLED || crate::pair_init::lab_test_a_enabled())
            && crate::suite_policy::hold_allows(crate::suite_registry::FEATURE_P2P),
    )
}

/// Phase 2 friend relays (any-network plan C6/C7): the relay role inside
/// `raven-node service` with its own relay key, relay offers in route hints
/// (RRH1) and automatic relay choice. Separate from P2P, so P2P can be
/// flipped at Phase 1 exit while this stays held until the WAIVER_P2P_RELAY
/// Phase 2 amendment is signed.
pub const FRIEND_RELAY_PRODUCTION_ENABLED: bool = false;

/// The one refusal the friend relay's entry points (relaying for contacts,
/// automatic relay choice) print while its gate is closed.
pub const FRIEND_RELAY_HOLD: &str = "FRIEND_RELAY_HOLD: relaying for your contacts and \
    automatic relay choice are lab-only (debug RAVEN_LAB_TEST_A=1 with RAVEN_LAB_FRIEND_RELAY=1); \
    FRIEND_RELAY_PRODUCTION_ENABLED=false";

/// Live friend relays: the p2p carrier is live, and either the Phase 2 gate
/// or the debug switch `RAVEN_LAB_FRIEND_RELAY=1`. Not `RAVEN_LAB_TEST_A`
/// alone, so carrier_matrix C6 and C12-C16 and fault scenarios s35-s38 keep
/// testing Phase 1. Release builds never read the switch. A security
/// notice's hold closes it (P6.45).
pub fn friend_relay_live_enabled() -> bool {
    friend_relay_gate(p2p_live_enabled(), || {
        std::env::var("RAVEN_LAB_FRIEND_RELAY").ok()
    }) && crate::suite_policy::hold_allows(crate::suite_registry::FEATURE_FRIEND_RELAY)
}

/// [`friend_relay_live_enabled`] from its inputs: `lab` is read only while
/// the p2p carrier is live, and only in a debug build.
fn friend_relay_gate(p2p_live: bool, lab: impl FnOnce() -> Option<String>) -> bool {
    p2p_live && (FRIEND_RELAY_PRODUCTION_ENABLED || lab_flag(cfg!(debug_assertions), lab))
}

/// Relay offers ride route hints (RRH1) and automatic relay choice reads
/// them, so both need the friend relay gate and
/// [`crate::route_hints::route_hints_live`].
pub fn relay_offers_live() -> bool {
    friend_relay_live_enabled() && crate::route_hints::route_hints_live()
}

/// `RAVEN_LAB_FRIEND_RELAY_LISTEN=IP:PORT` (debug builds only): the friend
/// relay listens there instead of on every interface at its port
/// (harnesses: `127.0.0.1:0`). Anything but an `IP:PORT` is ignored.
/// Release builds never read the variable.
pub fn lab_friend_relay_listen() -> Option<std::net::SocketAddr> {
    lab_value(
        cfg!(debug_assertions),
        || std::env::var("RAVEN_LAB_FRIEND_RELAY_LISTEN").ok(),
        parse_lab_listen,
    )
}

/// `RAVEN_LAB_RELAY_SELECT=<replace_after_s>,<probation_s>,<min_gap_s>`
/// (debug builds only): automatic relay choice's timers in whole seconds,
/// each 1..=[`LAB_RELAY_SELECT_MAX_S`], so a harness sees a relay replaced
/// in seconds. Anything else is ignored (the real timers). Release builds
/// never read the variable.
pub fn lab_relay_select() -> Option<(u64, u64, u64)> {
    lab_value(
        cfg!(debug_assertions),
        || std::env::var("RAVEN_LAB_RELAY_SELECT").ok(),
        parse_lab_relay_select,
    )
}

/// The longest timer [`lab_relay_select`] accepts, in seconds.
pub const LAB_RELAY_SELECT_MAX_S: u64 = 600;

/// `RAVEN_LAB_P2P_PROFILE_RELAY=1` (debug builds only): `raven-node service
/// --relay` keeps relaying under the profile's own PeerId, the Phase 1 role
/// that the friend relay (its own relay key) replaces, so a harness still
/// covers that code. Release builds never read the variable.
pub fn p2p_profile_relay_test_enabled() -> bool {
    lab_flag(cfg!(debug_assertions), || {
        std::env::var("RAVEN_LAB_P2P_PROFILE_RELAY").ok()
    })
}

/// `RAVEN_LAB_P2P_LOCAL_CANDIDATES=1` (debug builds only): hole punching may
/// offer and dial loopback and private addresses (one-machine harnesses).
/// Never set by the netns harness or by real-world rows. Release builds never
/// read the variable.
pub fn p2p_local_candidates_enabled() -> bool {
    lab_flag(cfg!(debug_assertions), || {
        std::env::var("RAVEN_LAB_P2P_LOCAL_CANDIDATES").ok()
    })
}

/// `RAVEN_LAB_P2P_RELAY_ONLY=1` (debug builds only): honour the retired
/// `--p2p-listen relay` (no listener at all), so a harness can still show a
/// node that is reachable only through its relays and never hole-punches
/// (carrier_matrix C6). Release builds never read the variable.
pub fn p2p_relay_only_test_enabled() -> bool {
    lab_flag(cfg!(debug_assertions), || {
        std::env::var("RAVEN_LAB_P2P_RELAY_ONLY").ok()
    })
}

/// A debug-only lab switch: on only in a debug build and only for exactly
/// "1". `value` is not called in a release build. Shared by every
/// `RAVEN_LAB_*` on/off switch (here, `route_hints`).
pub(crate) fn lab_flag(debug: bool, value: impl FnOnce() -> Option<String>) -> bool {
    debug && value().as_deref() == Some("1")
}

/// A debug-only lab value: `parse`d only in a debug build; `value` is not
/// called in a release build. Shared by the `RAVEN_LAB_*` switches here that
/// carry a value (and `lan_gate`'s default LAN port).
pub(crate) fn lab_value<T>(
    debug: bool,
    value: impl FnOnce() -> Option<String>,
    parse: impl FnOnce(&str) -> Option<T>,
) -> Option<T> {
    if !debug {
        return None;
    }
    parse(&value()?)
}

/// A gate on top of another one (Phase 4's gates sit on the p2p carrier, or
/// on another Phase 4 gate): open only while the gate `below` is, and then
/// with its production const `prod` or its debug `switch`
/// ([`crate::pair_init::lab_switch`]). `switch` is not called while the
/// gate below is shut or the const is set.
pub(crate) fn gate_value(prod: bool, below: bool, switch: impl FnOnce() -> bool) -> bool {
    below && (prod || switch())
}

/// A debug-only lab switch `name` (`RAVEN_LAB_*`) as set, for ash and
/// raven-node, which parse it themselves: `None` in a release build (the
/// variable is never read), and when it is unset or blank.
pub fn lab_switch(name: &str) -> Option<String> {
    lab_value(
        cfg!(debug_assertions),
        || std::env::var(name).ok(),
        lab_switch_text,
    )
}

/// [`lab_switch`]'s value: anything but blank.
pub(crate) fn lab_switch_text(v: &str) -> Option<String> {
    (!v.trim().is_empty()).then(|| v.to_owned())
}

/// `IP:PORT` (port 0: the OS picks one); anything else is `None`.
fn parse_lab_listen(v: &str) -> Option<std::net::SocketAddr> {
    v.trim().parse().ok()
}

/// `<replace_after_s>,<probation_s>,<min_gap_s>`: exactly three whole
/// seconds, each 1..=[`LAB_RELAY_SELECT_MAX_S`]; anything else is `None`.
fn parse_lab_relay_select(v: &str) -> Option<(u64, u64, u64)> {
    let mut secs = v.split(',').map(|s| {
        s.trim()
            .parse::<u64>()
            .ok()
            .filter(|s| (1..=LAB_RELAY_SELECT_MAX_S).contains(s))
    });
    let timers = (secs.next()??, secs.next()??, secs.next()??);
    secs.next().is_none().then_some(timers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_flag_stays_false() {
        const {
            assert!(!P2P_PRODUCTION_ENABLED);
            assert!(!FRIEND_RELAY_PRODUCTION_ENABLED);
            assert!(!crate::INTERNET_DIRECT_PRODUCTION_ENABLED);
            assert!(!crate::pair_init::PRODUCTION_ENABLED);
            assert!(!crate::INDEXED_SESSION_STORE_PRODUCTION_ENABLED);
            assert!(!crate::PREKEY_LIFECYCLE_PRODUCTION_ENABLED);
            assert!(!crate::atsam_indexed_session::PRODUCTION_ENABLED);
            assert!(!crate::horizon::LONG_HORIZON_PRODUCTION_ENABLED);
            assert!(!crate::horizon::ASYNC_LETTER_PRODUCTION_ENABLED);
            assert!(!crate::custody_gate::CUSTODY_HANDOFF_PRODUCTION_ENABLED);
            // Phase 4 (P4.1): every one of its gates sits on this one.
            assert!(!crate::wss_gate::WSS_PRODUCTION_ENABLED);
            assert!(!crate::wss_gate::WSS_PROXY_PRODUCTION_ENABLED);
            assert!(!crate::portmap_gate::PORT_MAP_PRODUCTION_ENABLED);
            assert!(!crate::portmap_gate::V6_PINHOLE_PRODUCTION_ENABLED);
            assert!(!crate::portmap_gate::NAT_CLASS_PRODUCTION_ENABLED);
            assert!(!crate::portmap_gate::PEER_ROTATION_PRODUCTION_ENABLED);
            // Phase 5 (P5.25): the Bluetooth nearby carrier.
            assert!(!crate::NEARBY_PRODUCTION_ENABLED);
        }
    }

    /// Phase 4 (P4.1): the rule every Phase 4 gate follows, over all its
    /// inputs; a shut gate below and a set const never read the switch.
    #[test]
    fn gate_value_needs_the_gate_below_and_its_const_or_switch() {
        for below in [false, true] {
            for prod in [false, true] {
                for switch in [false, true] {
                    assert_eq!(
                        gate_value(prod, below, || switch),
                        below && (prod || switch),
                        "below={below} prod={prod} switch={switch}"
                    );
                }
            }
        }
        for prod in [false, true] {
            assert!(!gate_value(prod, false, || panic!(
                "a shut gate below read the switch"
            )));
        }
        assert!(gate_value(true, true, || panic!(
            "a set const read the switch"
        )));
    }

    #[test]
    fn gate_does_not_open_generic_live_enabled() {
        if crate::pair_init::lab_test_a_enabled() {
            return;
        }
        assert!(!p2p_live_enabled());
        assert!(!friend_relay_live_enabled());
        assert!(!relay_offers_live());
        assert!(!crate::internet_direct_live_enabled());
        assert!(!crate::pair_init::live_enabled());
        assert!(!crate::indexed_session_store::live_enabled());
        assert!(!crate::prekey_lifecycle::live_enabled());
        assert!(!crate::atsam_indexed_session::live_enabled());
    }

    /// Runs in both builds: the release test job proves the wiring (the
    /// switch is off whatever the environment says); a debug build follows
    /// exactly the variable.
    #[test]
    fn lab_switches_are_inert_without_debug_assertions() {
        for value in [
            None,
            Some(""),
            Some("0"),
            Some("1"),
            Some("true"),
            Some(" 1"),
        ] {
            let read = || value.map(str::to_owned);
            assert!(!lab_flag(false, read), "{value:?}");
            assert_eq!(lab_flag(true, read), value == Some("1"), "{value:?}");
        }
        assert!(!lab_flag(false, || panic!(
            "a release build read the variable"
        )));
        for (name, enabled) in [
            (
                "RAVEN_LAB_P2P_LOCAL_CANDIDATES",
                p2p_local_candidates_enabled as fn() -> bool,
            ),
            ("RAVEN_LAB_P2P_RELAY_ONLY", p2p_relay_only_test_enabled),
            (
                "RAVEN_LAB_P2P_PROFILE_RELAY",
                p2p_profile_relay_test_enabled,
            ),
        ] {
            let set = std::env::var(name).ok();
            if cfg!(debug_assertions) {
                assert_eq!(enabled(), set.as_deref() == Some("1"), "{name}");
            } else {
                assert!(!enabled(), "{name}={set:?}");
            }
        }
    }

    #[test]
    fn hold_text_names_the_flag_and_the_lab_unlock() {
        assert!(P2P_HOLD.starts_with("P2P_HOLD:"));
        assert!(P2P_HOLD.contains("P2P_PRODUCTION_ENABLED=false"));
        assert!(P2P_HOLD.contains("RAVEN_LAB_TEST_A=1"));
    }

    #[test]
    fn friend_relay_hold_text_names_its_flag_and_both_lab_switches() {
        assert!(FRIEND_RELAY_HOLD.starts_with("FRIEND_RELAY_HOLD:"));
        assert!(FRIEND_RELAY_HOLD.contains("FRIEND_RELAY_PRODUCTION_ENABLED=false"));
        assert!(FRIEND_RELAY_HOLD.contains("RAVEN_LAB_TEST_A=1"));
        assert!(FRIEND_RELAY_HOLD.contains("RAVEN_LAB_FRIEND_RELAY=1"));
    }

    /// Exactly "1" in a debug build, like every on/off lab switch.
    fn switch_on(name: &str) -> bool {
        cfg!(debug_assertions) && std::env::var(name).ok().as_deref() == Some("1")
    }

    /// The friend relay needs the p2p carrier and its own switch: the p2p
    /// lab unlock (`RAVEN_LAB_TEST_A=1`) alone leaves it shut, and a shut
    /// p2p gate never reads the switch. Runs in both builds (a release build
    /// keeps it shut whatever the switch says).
    #[test]
    fn friend_relay_gate_needs_p2p_and_its_own_lab_switch() {
        for value in [
            None,
            Some(""),
            Some("0"),
            Some("1"),
            Some("true"),
            Some(" 1"),
        ] {
            let read = || value.map(str::to_owned);
            assert_eq!(
                friend_relay_gate(true, read),
                cfg!(debug_assertions) && value == Some("1"),
                "{value:?}"
            );
        }
        assert!(!friend_relay_gate(false, || panic!(
            "a shut p2p gate read the friend relay switch"
        )));
        // This process: exactly what its environment says (shut in the
        // Phase 1 lab runs, which set `RAVEN_LAB_TEST_A=1` only).
        assert_eq!(
            friend_relay_live_enabled(),
            p2p_live_enabled() && switch_on("RAVEN_LAB_FRIEND_RELAY"),
            "p2p={} RAVEN_LAB_FRIEND_RELAY={:?}",
            p2p_live_enabled(),
            std::env::var("RAVEN_LAB_FRIEND_RELAY").ok()
        );
    }

    /// Offers ride RRH1 and automatic relay choice reads them: they need the
    /// friend relay gate and route hints, each with its own switch. Which
    /// case a run sees is up to its environment (the lab runs set the
    /// switches); every case's answer is pinned.
    #[test]
    fn relay_offers_live_needs_route_hints() {
        const {
            assert!(!crate::route_hints::ROUTE_HINTS_PRODUCTION_ENABLED);
        }
        let friend = p2p_live_enabled() && switch_on("RAVEN_LAB_FRIEND_RELAY");
        let hints = switch_on("RAVEN_LAB_ROUTE_HINTS");
        assert_eq!(friend_relay_live_enabled(), friend);
        assert_eq!(crate::route_hints::route_hints_live(), hints);
        assert_eq!(
            relay_offers_live(),
            friend && hints,
            "friend relay {friend}, route hints {hints}"
        );
    }

    /// The value switches take bounded values only, and a release build
    /// never reads them: the release test job runs this with the variables
    /// set.
    #[test]
    fn lab_relay_select_and_friend_listen_parse_bounded_values_and_are_inert_in_release() {
        assert_eq!(parse_lab_relay_select("10,5,3"), Some((10, 5, 3)));
        assert_eq!(parse_lab_relay_select(" 1 , 600,1 "), Some((1, 600, 1)));
        for bad in [
            "",
            "10",
            "10,5",
            "10,5,3,1",
            "10,5,3,",
            "0,5,3",
            "10,601,3",
            "10,5,-1",
            "10,,3",
            "a,b,c",
            "10;5;3",
            "1.5,5,3",
            "18446744073709551616,5,3",
        ] {
            assert_eq!(parse_lab_relay_select(bad), None, "{bad:?}");
        }
        let at = |s: &str| s.parse::<std::net::SocketAddr>().unwrap();
        assert_eq!(parse_lab_listen("127.0.0.1:0"), Some(at("127.0.0.1:0")));
        assert_eq!(parse_lab_listen(" [::1]:7427 "), Some(at("[::1]:7427")));
        for bad in [
            "",
            "127.0.0.1",
            "localhost:0",
            "127.0.0.1:65536",
            ":0",
            "0",
            "on",
        ] {
            assert_eq!(parse_lab_listen(bad), None, "{bad:?}");
        }
        // A release build never calls the reader; a debug build parses what
        // it reads.
        let unread = || -> Option<String> { panic!("a release build read the variable") };
        assert_eq!(lab_value(false, unread, parse_lab_listen), None);
        assert_eq!(lab_value(false, unread, parse_lab_relay_select), None);
        assert_eq!(
            lab_value(true, || Some("127.0.0.1:0".into()), parse_lab_listen),
            Some(at("127.0.0.1:0"))
        );
        assert_eq!(lab_value(true, || None, parse_lab_relay_select), None);
        assert_eq!(
            lab_value(true, || Some("0,0,0".into()), parse_lab_relay_select),
            None
        );
        if !cfg!(debug_assertions) {
            // Edition 2021: a plain call. No other test reads these two.
            std::env::set_var("RAVEN_LAB_RELAY_SELECT", "1,1,1");
            std::env::set_var("RAVEN_LAB_FRIEND_RELAY_LISTEN", "127.0.0.1:0");
            assert_eq!(lab_relay_select(), None);
            assert_eq!(lab_friend_relay_listen(), None);
            return;
        }
        let read = |name: &str| std::env::var(name).ok();
        assert_eq!(
            lab_relay_select(),
            read("RAVEN_LAB_RELAY_SELECT").and_then(|v| parse_lab_relay_select(&v))
        );
        assert_eq!(
            lab_friend_relay_listen(),
            read("RAVEN_LAB_FRIEND_RELAY_LISTEN").and_then(|v| parse_lab_listen(&v))
        );
    }
}
