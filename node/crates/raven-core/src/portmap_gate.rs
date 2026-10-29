//! Phase 4 (part B) gates: router port mapping (NAT-PMP, RFC 6886, and PCP,
//! RFC 6887), IPv6 pinholes on the router, acting on the NAT mapping class,
//! and PeerId rotation per epoch; and the auto-reach gates
//! (`docs/design/2026-10-auto-reach.md`): asking public STUN servers for this
//! computer's public address, and serverless hole punching between friends.
//!
//! Six gates, each on the p2p carrier ([`crate::P2P_PRODUCTION_ENABLED`]),
//! IPv6 pinholes also on port mapping, serverless punching on STUN discovery
//! and the NAT class (the const asserts below). Port mapping, IPv6 pinholes,
//! the NAT class, STUN discovery and serverless punching were switched on in
//! release builds in 2026-10, after the three-machine field test (debug
//! builds with the lab switches on); not independently reviewed. PeerId
//! rotation stays off (a privacy option, not in the field-tested set). A
//! debug build closes a switched-on gate with its switch set to "0" and
//! opens a held one with the p2p lab unlock (`RAVEN_LAB_TEST_A=1`) and its
//! own switch ([`crate::pair_init::lab_gate`]); the lab unlock alone opens
//! none. Release builds read no switch. A security notice's hold on a gate's
//! feature closes it after its own gate (P6.45, close-only). The user's
//! choices stay theirs: `raven node upnp`, `raven node stun off`, hide my
//! IP.
//!
//! The harness values (`lab_*`) are read only in a debug build with the lab
//! unlock, and only within their bounds; anything else is `None`, as is
//! every one of them in a release build (which never reads them).

use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::ops::RangeInclusive;

use crate::p2p_gate::gate_value;
use crate::pair_init::{lab_gate, lab_switch};

/// NAT-PMP (RFC 6886) and PCP (RFC 6887) IPv4 MAP on the default router.
/// Switched on 2026-10 after the three-machine field test; not independently
/// reviewed.
pub const PORT_MAP_PRODUCTION_ENABLED: bool = true;
/// IPv6 firewall pinholes on the router (PCP MAP over IPv6). Switched on
/// 2026-10 after the three-machine field test; not independently reviewed.
pub const V6_PINHOLE_PRODUCTION_ENABLED: bool = true;
/// Acting on the NAT mapping class: the NAT class in route hints (RRH1) and
/// skipping hole punches that cannot work. Switched on 2026-10 after the
/// three-machine field test; not independently reviewed.
pub const NAT_CLASS_PRODUCTION_ENABLED: bool = true;
/// PeerIds rotated per epoch, and the schedule contacts and relays learn
/// through route hints (RRH1).
pub const PEER_ROTATION_PRODUCTION_ENABLED: bool = false;
/// Auto-reach (design §3-§4): STUN Binding requests to public STUN servers
/// for this computer's public address, and that address in route hints and
/// the friend relay's offer (never in a card: addresses travel only inside
/// encrypted links between verified friends). Owner-approved as a query only
/// (2026-10-28): Cloudflare and Google only; D1 and D13 stand. Switched on
/// 2026-10 after the three-machine field test; not independently reviewed.
pub const STUN_DISCOVERY_PRODUCTION_ENABLED: bool = true;
/// Auto-reach (design §5): two verified friends with endpoint-independent
/// NATs dial each other's mapped QUIC endpoint at the same moments, on a
/// clock schedule both derive from their keys; no relay, no coordinator, no
/// port prediction. Switched on 2026-10 after the three-machine field test;
/// not independently reviewed.
pub const SERVERLESS_PUNCH_PRODUCTION_ENABLED: bool = true;

const _: () = assert!(!PORT_MAP_PRODUCTION_ENABLED || crate::P2P_PRODUCTION_ENABLED);
const _: () = assert!(!V6_PINHOLE_PRODUCTION_ENABLED || PORT_MAP_PRODUCTION_ENABLED);
const _: () = assert!(!NAT_CLASS_PRODUCTION_ENABLED || crate::P2P_PRODUCTION_ENABLED);
const _: () = assert!(!PEER_ROTATION_PRODUCTION_ENABLED || crate::P2P_PRODUCTION_ENABLED);
const _: () = assert!(!STUN_DISCOVERY_PRODUCTION_ENABLED || crate::P2P_PRODUCTION_ENABLED);
const _: () = assert!(
    !SERVERLESS_PUNCH_PRODUCTION_ENABLED
        || (STUN_DISCOVERY_PRODUCTION_ENABLED && NAT_CLASS_PRODUCTION_ENABLED)
);

/// The refusal every port-mapping entry point prints while its gate is
/// closed.
pub const PORT_MAP_HOLD: &str = "PORT_MAP_HOLD: router port mapping (NAT-PMP and PCP) is \
    closed in this process (a debug build with RAVEN_LAB_PORT_MAP=0 or RAVEN_LAB_TEST_A=0, or a \
    security notice); release builds have it on (PORT_MAP_PRODUCTION_ENABLED=true)";

/// The refusal every IPv6 pinhole entry point prints while its gate is
/// closed.
pub const V6_PINHOLE_HOLD: &str = "V6_PINHOLE_HOLD: IPv6 pinholes on the router are closed in \
    this process (a debug build with RAVEN_LAB_V6_PINHOLE=0, RAVEN_LAB_PORT_MAP=0 or \
    RAVEN_LAB_TEST_A=0, or a security notice); release builds have them on \
    (V6_PINHOLE_PRODUCTION_ENABLED=true)";

/// The refusal every NAT-class entry point prints while its gate is closed.
pub const NAT_CLASS_HOLD: &str = "NAT_CLASS_HOLD: acting on the NAT mapping class (skipping \
    hole punches that cannot work) is closed in this process (a debug build with \
    RAVEN_LAB_NAT_CLASS=0 or RAVEN_LAB_TEST_A=0, or a security notice); release builds have it on \
    (NAT_CLASS_PRODUCTION_ENABLED=true)";

/// The refusal every rotation entry point prints while its gate is closed.
pub const PEER_ROTATION_HOLD: &str = "PEER_ROTATION_HOLD: rotating the network ID (PeerId) is \
    lab-only (debug RAVEN_LAB_TEST_A=1 RAVEN_LAB_PEER_ROTATION=1); \
    PEER_ROTATION_PRODUCTION_ENABLED=false";

/// The refusal every STUN discovery entry point prints while its gate is
/// closed.
pub const STUN_DISCOVERY_HOLD: &str = "STUN_DISCOVERY_HOLD: asking public STUN servers for this \
    computer's public address is closed in this process (a debug build with \
    RAVEN_LAB_STUN_DISCOVERY=0 or RAVEN_LAB_TEST_A=0, or a security notice); release builds have \
    it on (STUN_DISCOVERY_PRODUCTION_ENABLED=true; `raven node stun off` stops it)";

/// The refusal every serverless punch entry point prints while its gate is
/// closed.
pub const SERVERLESS_PUNCH_HOLD: &str = "SERVERLESS_PUNCH_HOLD: hole punching between friends \
    without a relay is closed in this process (a debug build with RAVEN_LAB_SERVERLESS_PUNCH=0, \
    RAVEN_LAB_STUN_DISCOVERY=0, RAVEN_LAB_NAT_CLASS=0 or RAVEN_LAB_TEST_A=0, or a security notice); \
    release builds have it on (SERVERLESS_PUNCH_PRODUCTION_ENABLED=true)";

/// Live port mapping: the p2p carrier is live, and
/// [`PORT_MAP_PRODUCTION_ENABLED`] (a debug build: `RAVEN_LAB_PORT_MAP=0`
/// closes it, [`lab_gate`]).
pub fn port_map_live_enabled() -> bool {
    crate::p2p_live_enabled()
        && lab_gate(PORT_MAP_PRODUCTION_ENABLED, "RAVEN_LAB_PORT_MAP")
        && crate::suite_policy::hold_allows(crate::suite_registry::FEATURE_PORT_MAP)
}

/// Live IPv6 pinholes: port mapping is live, and
/// [`V6_PINHOLE_PRODUCTION_ENABLED`] (a debug build:
/// `RAVEN_LAB_V6_PINHOLE=0` closes it).
pub fn v6_pinhole_live_enabled() -> bool {
    port_map_live_enabled()
        && lab_gate(V6_PINHOLE_PRODUCTION_ENABLED, "RAVEN_LAB_V6_PINHOLE")
        && crate::suite_policy::hold_allows(crate::suite_registry::FEATURE_V6_PINHOLE)
}

/// Live NAT class: the p2p carrier is live, and
/// [`NAT_CLASS_PRODUCTION_ENABLED`] (a debug build: `RAVEN_LAB_NAT_CLASS=0`
/// closes it).
pub fn nat_class_live_enabled() -> bool {
    crate::p2p_live_enabled()
        && lab_gate(NAT_CLASS_PRODUCTION_ENABLED, "RAVEN_LAB_NAT_CLASS")
        && crate::suite_policy::hold_allows(crate::suite_registry::FEATURE_NAT_CLASS)
}

/// Live PeerId rotation: the p2p carrier is live, and either
/// [`PEER_ROTATION_PRODUCTION_ENABLED`] or the debug switch
/// `RAVEN_LAB_PEER_ROTATION`.
pub fn peer_rotation_live_enabled() -> bool {
    gate_value(
        PEER_ROTATION_PRODUCTION_ENABLED,
        crate::p2p_live_enabled(),
        || lab_switch("RAVEN_LAB_PEER_ROTATION"),
    ) && crate::suite_policy::hold_allows(crate::suite_registry::FEATURE_PEER_ROTATION)
}

/// Live STUN discovery: the p2p carrier is live, and
/// [`STUN_DISCOVERY_PRODUCTION_ENABLED`] (a debug build:
/// `RAVEN_LAB_STUN_DISCOVERY=0` closes it). The user's `raven node stun off`
/// and hide my IP for everyone are raven-node's part.
pub fn stun_discovery_live_enabled() -> bool {
    crate::p2p_live_enabled()
        && lab_gate(
            STUN_DISCOVERY_PRODUCTION_ENABLED,
            "RAVEN_LAB_STUN_DISCOVERY",
        )
        && crate::suite_policy::hold_allows(crate::suite_registry::FEATURE_STUN_DISCOVERY)
}

/// Live serverless punching: STUN discovery and the NAT class are live (a
/// punch needs this node's class and the friend's), and
/// [`SERVERLESS_PUNCH_PRODUCTION_ENABLED`] (a debug build:
/// `RAVEN_LAB_SERVERLESS_PUNCH=0` closes it).
pub fn serverless_punch_live_enabled() -> bool {
    stun_discovery_live_enabled()
        && nat_class_live_enabled()
        && lab_gate(
            SERVERLESS_PUNCH_PRODUCTION_ENABLED,
            "RAVEN_LAB_SERVERLESS_PUNCH",
        )
        && crate::suite_policy::hold_allows(crate::suite_registry::FEATURE_SERVERLESS_PUNCH)
}

/// The most STUN servers a harness may name ([`lab_stun_servers`]).
pub const LAB_STUN_SERVERS_MAX: usize = 8;

/// `RAVEN_LAB_STUN_SERVERS=IP:PORT[,IP:PORT]...`: STUN discovery asks these
/// servers instead of the public list (harnesses: a fake server on
/// loopback; distinct ports then count as distinct servers). IP literals
/// only, IPv4 or IPv6, port 1-65535, no unspecified, multicast or broadcast
/// address, 1 to [`LAB_STUN_SERVERS_MAX`] distinct entries. Anything else is
/// `None` (the public list).
pub fn lab_stun_servers() -> Option<Vec<SocketAddr>> {
    lab_parsed("RAVEN_LAB_STUN_SERVERS", parse_lab_stun_servers)
}

/// The refresh intervals [`lab_stun_refresh_s`] accepts, in seconds.
pub const LAB_STUN_REFRESH_S: RangeInclusive<u64> = 2..=3600;

/// `RAVEN_LAB_STUN_REFRESH_S=<seconds>`: STUN discovery refreshes this often
/// instead of every 20 minutes (and backs off from it), whole seconds in
/// [`LAB_STUN_REFRESH_S`]. Anything else is `None`.
pub fn lab_stun_refresh_s() -> Option<u64> {
    lab_parsed("RAVEN_LAB_STUN_REFRESH_S", |v| {
        lab_whole(v, &LAB_STUN_REFRESH_S)
    })
}

/// The punch slot lengths [`lab_punch_slot_s`] accepts, in seconds.
pub const LAB_PUNCH_SLOT_S: RangeInclusive<u64> = 2..=300;

/// `RAVEN_LAB_PUNCH_SLOT_S=<seconds>`: the serverless punch schedule's slot
/// instead of 30 s, whole seconds in [`LAB_PUNCH_SLOT_S`], so a harness sees
/// a punch within seconds. Anything else is `None`.
pub fn lab_punch_slot_s() -> Option<u64> {
    lab_parsed("RAVEN_LAB_PUNCH_SLOT_S", |v| {
        lab_whole(v, &LAB_PUNCH_SLOT_S)
    })
}

/// The routers a harness names for port mapping
/// ([`lab_portmap_gateway`]): at most one IPv4 and one IPv6 router, each with
/// the port its NAT-PMP/PCP server listens on; at least one is set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LabGateway {
    pub v4: Option<SocketAddrV4>,
    pub v6: Option<SocketAddrV6>,
}

/// `RAVEN_LAB_PORTMAP_GATEWAY=IP:PORT[,IP:PORT]`: port mapping talks to
/// these routers and ports instead of the OS default gateways
/// ([`crate::gateway::default_gateways`] returns these routers) and the
/// NAT-PMP/PCP port (harnesses: a fake gateway on loopback). One IPv4 entry,
/// one IPv6 entry (`[ADDR]:PORT`, a numeric scope allowed) or one of each;
/// port 1-65535; no unspecified, multicast, broadcast or IPv4-mapped
/// address. Anything else is `None`.
pub fn lab_portmap_gateway() -> Option<LabGateway> {
    lab_parsed("RAVEN_LAB_PORTMAP_GATEWAY", parse_lab_portmap_gateway)
}

/// The leases [`lab_portmap_lifetime`] accepts, in seconds.
pub const LAB_PORTMAP_LIFETIME_S: RangeInclusive<u32> = 8..=7200;

/// `RAVEN_LAB_PORTMAP_LIFETIME=<seconds>`: the lease port mapping asks the
/// router for (renewed at half), whole seconds in
/// [`LAB_PORTMAP_LIFETIME_S`], so a harness sees renewals within seconds.
/// Anything else is `None` (the real lease).
pub fn lab_portmap_lifetime() -> Option<u32> {
    lab_parsed("RAVEN_LAB_PORTMAP_LIFETIME", |v| {
        lab_whole(v, &LAB_PORTMAP_LIFETIME_S)
    })
}

/// A NAT mapping class a harness forces on a node
/// ([`lab_nat_class_force`]), named by the word the variable takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LabNatClass {
    /// `varies`: the external address depends on the destination.
    Varies,
    /// `stable_kept`: one external address for every destination, on the
    /// listen port.
    StableKept,
    /// `stable_shifted`: one external address for every destination, on
    /// another port.
    StableShifted,
    /// `no_nat`: the node's own address is its external address.
    NoNat,
}

/// `RAVEN_LAB_NAT_CLASS_FORCE=varies|stable_kept|stable_shifted|no_nat`:
/// the node's own NAT mapping class, whatever it observes (harnesses on one
/// computer). Anything else is `None` (the observed class).
pub fn lab_nat_class_force() -> Option<LabNatClass> {
    lab_parsed("RAVEN_LAB_NAT_CLASS_FORCE", parse_lab_nat_class)
}

/// The epochs [`lab_peer_epoch_s`] accepts, in seconds.
pub const LAB_PEER_EPOCH_S: RangeInclusive<u64> = 10..=86_400;

/// `RAVEN_LAB_PEER_EPOCH_S=<seconds>`: the PeerId rotation epoch, whole
/// seconds in [`LAB_PEER_EPOCH_S`], so a harness sees a rotation within a
/// minute. Anything else is `None` (the real epoch).
pub fn lab_peer_epoch_s() -> Option<u64> {
    lab_parsed("RAVEN_LAB_PEER_EPOCH_S", |v| {
        lab_whole(v, &LAB_PEER_EPOCH_S)
    })
}

/// The harness value `name`, `parse`d: read only in a debug build with the
/// lab unlock (a release build never reads it); `None` otherwise.
fn lab_parsed<T>(name: &str, parse: impl FnOnce(&str) -> Option<T>) -> Option<T> {
    crate::p2p_gate::lab_value(
        cfg!(debug_assertions) && crate::pair_init::lab_test_a_enabled(),
        || std::env::var(name).ok(),
        parse,
    )
}

/// A whole number in `range`; anything else is `None`.
fn lab_whole<T>(v: &str, range: &RangeInclusive<T>) -> Option<T>
where
    T: std::str::FromStr + PartialOrd,
{
    v.trim().parse().ok().filter(|n| range.contains(n))
}

/// [`lab_portmap_gateway`]'s value; anything but its grammar is `None`.
fn parse_lab_portmap_gateway(v: &str) -> Option<LabGateway> {
    let mut gw = LabGateway { v4: None, v6: None };
    for (i, entry) in v.split(',').enumerate() {
        if i > 1 {
            return None;
        }
        match entry.trim().parse::<SocketAddr>().ok()? {
            SocketAddr::V4(a)
                if gw.v4.is_none()
                    && a.port() != 0
                    && !a.ip().is_unspecified()
                    && !a.ip().is_multicast()
                    && !a.ip().is_broadcast() =>
            {
                gw.v4 = Some(a)
            }
            SocketAddr::V6(a)
                if gw.v6.is_none()
                    && a.port() != 0
                    && !a.ip().is_unspecified()
                    && !a.ip().is_multicast()
                    && a.ip().to_ipv4_mapped().is_none() =>
            {
                gw.v6 = Some(a)
            }
            _ => return None,
        }
    }
    Some(gw)
}

/// [`lab_stun_servers`]' value; anything but its grammar is `None`.
fn parse_lab_stun_servers(v: &str) -> Option<Vec<SocketAddr>> {
    let mut out: Vec<SocketAddr> = Vec::new();
    for entry in v.split(',') {
        let a: SocketAddr = entry.trim().parse().ok()?;
        let ok = a.port() != 0
            && match a.ip() {
                std::net::IpAddr::V4(ip) => {
                    !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast()
                }
                std::net::IpAddr::V6(ip) => {
                    !ip.is_unspecified() && !ip.is_multicast() && ip.to_ipv4_mapped().is_none()
                }
            };
        if !ok || out.contains(&a) || out.len() == LAB_STUN_SERVERS_MAX {
            return None;
        }
        out.push(a);
    }
    (!out.is_empty()).then_some(out)
}

/// [`lab_nat_class_force`]'s value: one of its four words.
fn parse_lab_nat_class(v: &str) -> Option<LabNatClass> {
    Some(match v.trim() {
        "varies" => LabNatClass::Varies,
        "stable_kept" => LabNatClass::StableKept,
        "stable_shifted" => LabNatClass::StableShifted,
        "no_nat" => LabNatClass::NoNat,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p2p_gate::lab_value;

    const SWITCHES: [&str; 6] = [
        "RAVEN_LAB_PORT_MAP",
        "RAVEN_LAB_V6_PINHOLE",
        "RAVEN_LAB_NAT_CLASS",
        "RAVEN_LAB_PEER_ROTATION",
        "RAVEN_LAB_STUN_DISCOVERY",
        "RAVEN_LAB_SERVERLESS_PUNCH",
    ];

    /// 2026-10: the field-tested five are on in release builds, on the p2p
    /// carrier (also on); PeerId rotation stays off.
    #[test]
    fn switched_on_flags_and_rotation_stays_off() {
        const {
            assert!(PORT_MAP_PRODUCTION_ENABLED);
            assert!(V6_PINHOLE_PRODUCTION_ENABLED);
            assert!(NAT_CLASS_PRODUCTION_ENABLED);
            assert!(STUN_DISCOVERY_PRODUCTION_ENABLED);
            assert!(SERVERLESS_PUNCH_PRODUCTION_ENABLED);
            assert!(!PEER_ROTATION_PRODUCTION_ENABLED);
            assert!(crate::P2P_PRODUCTION_ENABLED);
        }
    }

    /// The switch values a debug run may see: unset, the close "0", the open
    /// "1".
    const VALUES: [Option<&str>; 3] = [None, Some("0"), Some("1")];

    /// Serverless punching needs STUN discovery and the NAT class (a punch
    /// needs both classes), and its own gate; STUN discovery needs the p2p
    /// carrier and its gate. Each switched-on gate closes on its own "0" in
    /// a debug build; a release build follows the consts (all on).
    #[test]
    fn auto_reach_gates_stack() {
        use crate::pair_init::lab_gate_value;
        for debug in [false, true] {
            for test_a in [false, true] {
                for p2p in [false, true] {
                    for stun in VALUES {
                        for nat in VALUES {
                            for punch in VALUES {
                                let gate = |prod, v| lab_gate_value(debug, prod, test_a, v);
                                let s = p2p && gate(STUN_DISCOVERY_PRODUCTION_ENABLED, stun);
                                let n = p2p && gate(NAT_CLASS_PRODUCTION_ENABLED, nat);
                                let p = s && n && gate(SERVERLESS_PUNCH_PRODUCTION_ENABLED, punch);
                                let open = |v: Option<&str>| !debug || v != Some("0");
                                let case = format!(
                                    "debug={debug} test_a={test_a} p2p={p2p} stun={stun:?} \
                                     nat={nat:?} punch={punch:?}"
                                );
                                assert_eq!(s, p2p && open(stun), "{case}");
                                assert_eq!(
                                    p,
                                    p2p && open(stun) && open(nat) && open(punch),
                                    "{case}"
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    /// Each gate needs the p2p carrier; IPv6 pinholes also need port
    /// mapping. A switched-on gate closes only on its own "0" (a debug
    /// build); PeerId rotation, still held, needs its own switch, and the lab
    /// unlock alone (p2p live, no switch) never opens it.
    #[test]
    fn gates_need_p2p_and_close_on_their_own_switch() {
        use crate::pair_init::lab_gate_value;
        for p2p in [false, true] {
            for map in VALUES {
                for pin in VALUES {
                    let port_map =
                        p2p && lab_gate_value(true, PORT_MAP_PRODUCTION_ENABLED, true, map);
                    let v6 =
                        port_map && lab_gate_value(true, V6_PINHOLE_PRODUCTION_ENABLED, true, pin);
                    let case = format!("p2p={p2p} port_map={map:?} v6_pinhole={pin:?}");
                    assert_eq!(port_map, p2p && map != Some("0"), "{case}");
                    assert_eq!(v6, port_map && pin != Some("0"), "{case}");
                    // A release build: the consts.
                    assert!(lab_gate_value(
                        false,
                        PORT_MAP_PRODUCTION_ENABLED,
                        true,
                        map
                    ));
                    assert!(lab_gate_value(
                        false,
                        V6_PINHOLE_PRODUCTION_ENABLED,
                        true,
                        pin
                    ));
                }
            }
            for nat in VALUES {
                assert_eq!(
                    p2p && lab_gate_value(true, NAT_CLASS_PRODUCTION_ENABLED, false, nat),
                    p2p && nat != Some("0")
                );
            }
            for switch in [false, true] {
                assert_eq!(
                    gate_value(PEER_ROTATION_PRODUCTION_ENABLED, p2p, || switch),
                    p2p && switch
                );
            }
        }
        // The lab unlock alone: a debug build with `RAVEN_LAB_TEST_A=1` (the
        // gate below live) and rotation's own switch unset.
        let unset = || crate::pair_init::lab_switch_value(true, true, None);
        assert!(!gate_value(PEER_ROTATION_PRODUCTION_ENABLED, true, unset));
    }

    #[test]
    fn hold_texts_name_flag_and_switches() {
        for (hold, name, flag, switches) in [
            (
                PORT_MAP_HOLD,
                "PORT_MAP_HOLD:",
                "PORT_MAP_PRODUCTION_ENABLED=true",
                &["RAVEN_LAB_PORT_MAP=0", "RAVEN_LAB_TEST_A=0"][..],
            ),
            (
                V6_PINHOLE_HOLD,
                "V6_PINHOLE_HOLD:",
                "V6_PINHOLE_PRODUCTION_ENABLED=true",
                &["RAVEN_LAB_PORT_MAP=0", "RAVEN_LAB_V6_PINHOLE=0"][..],
            ),
            (
                NAT_CLASS_HOLD,
                "NAT_CLASS_HOLD:",
                "NAT_CLASS_PRODUCTION_ENABLED=true",
                &["RAVEN_LAB_NAT_CLASS=0"][..],
            ),
            (
                STUN_DISCOVERY_HOLD,
                "STUN_DISCOVERY_HOLD:",
                "STUN_DISCOVERY_PRODUCTION_ENABLED=true",
                &["RAVEN_LAB_STUN_DISCOVERY=0"][..],
            ),
            (
                SERVERLESS_PUNCH_HOLD,
                "SERVERLESS_PUNCH_HOLD:",
                "SERVERLESS_PUNCH_PRODUCTION_ENABLED=true",
                &[
                    "RAVEN_LAB_STUN_DISCOVERY=0",
                    "RAVEN_LAB_NAT_CLASS=0",
                    "RAVEN_LAB_SERVERLESS_PUNCH=0",
                ][..],
            ),
        ] {
            assert!(hold.starts_with(name), "{hold}");
            assert!(hold.contains(flag), "{hold}");
            assert!(!hold.contains("lab-only"), "{hold}");
            for switch in switches {
                assert!(hold.contains(switch), "{hold}: {switch}");
            }
        }
        // Rotation is still held: its refusal names the flag and the unlock.
        assert!(PEER_ROTATION_HOLD.starts_with("PEER_ROTATION_HOLD:"));
        assert!(PEER_ROTATION_HOLD.contains("PEER_ROTATION_PRODUCTION_ENABLED=false"));
        assert!(PEER_ROTATION_HOLD.contains("RAVEN_LAB_TEST_A=1"));
        assert!(PEER_ROTATION_HOLD.contains("RAVEN_LAB_PEER_ROTATION=1"));
    }

    /// Runs in both builds: the release test jobs set the lab unlock and
    /// every switch to "1" and then to "0", and every gate stays at its
    /// const (the five on, rotation off); a debug build follows exactly its
    /// environment and changes none of it.
    #[test]
    fn lab_switches_are_inert_in_release() {
        if !cfg!(debug_assertions) {
            for value in ["1", "0"] {
                // Edition 2021: a plain call. No release test needs them unset.
                std::env::set_var("RAVEN_LAB_TEST_A", value);
                for name in SWITCHES {
                    std::env::set_var(name, value);
                }
                assert!(port_map_live_enabled(), "{value}");
                assert!(v6_pinhole_live_enabled(), "{value}");
                assert!(nat_class_live_enabled(), "{value}");
                assert!(!peer_rotation_live_enabled(), "{value}");
                assert!(stun_discovery_live_enabled(), "{value}");
                assert!(serverless_punch_live_enabled(), "{value}");
            }
            for name in SWITCHES {
                std::env::set_var(name, "1");
            }
            std::env::set_var("RAVEN_LAB_TEST_A", "1");
            return;
        }
        let test_a = crate::pair_init::lab_test_a_enabled();
        let gate = |prod: bool, name: &str| {
            crate::pair_init::lab_gate_value(
                true,
                prod,
                test_a,
                std::env::var(name).ok().as_deref(),
            )
        };
        let p2p = crate::p2p_live_enabled();
        let port_map = p2p && gate(PORT_MAP_PRODUCTION_ENABLED, "RAVEN_LAB_PORT_MAP");
        assert_eq!(port_map_live_enabled(), port_map);
        assert_eq!(
            v6_pinhole_live_enabled(),
            port_map && gate(V6_PINHOLE_PRODUCTION_ENABLED, "RAVEN_LAB_V6_PINHOLE")
        );
        let nat = p2p && gate(NAT_CLASS_PRODUCTION_ENABLED, "RAVEN_LAB_NAT_CLASS");
        assert_eq!(nat_class_live_enabled(), nat);
        let on = |name: &str| {
            crate::pair_init::lab_switch_value(true, test_a, std::env::var(name).ok().as_deref())
        };
        assert_eq!(
            peer_rotation_live_enabled(),
            p2p && on("RAVEN_LAB_PEER_ROTATION")
        );
        let stun = p2p
            && gate(
                STUN_DISCOVERY_PRODUCTION_ENABLED,
                "RAVEN_LAB_STUN_DISCOVERY",
            );
        assert_eq!(stun_discovery_live_enabled(), stun);
        assert_eq!(
            serverless_punch_live_enabled(),
            stun && nat
                && gate(
                    SERVERLESS_PUNCH_PRODUCTION_ENABLED,
                    "RAVEN_LAB_SERVERLESS_PUNCH"
                )
        );
    }

    /// The harness values take bounded values only.
    #[test]
    fn lab_parsers_are_bounded() {
        let lifetime = |v: &str| lab_whole(v, &LAB_PORTMAP_LIFETIME_S);
        assert_eq!(lifetime("8"), Some(8));
        assert_eq!(lifetime(" 60 "), Some(60));
        assert_eq!(lifetime("7200"), Some(7200));
        for bad in [
            "",
            "0",
            "7",
            "7201",
            "-8",
            "1.5",
            "60s",
            "8,9",
            "4294967296",
        ] {
            assert_eq!(lifetime(bad), None, "{bad:?}");
        }
        let epoch = |v: &str| lab_whole(v, &LAB_PEER_EPOCH_S);
        assert_eq!(epoch("10"), Some(10));
        assert_eq!(epoch("30"), Some(30));
        assert_eq!(epoch("86400"), Some(86_400));
        for bad in [
            "",
            "0",
            "9",
            "86401",
            "-30",
            "30.0",
            "1e3",
            "18446744073709551616",
        ] {
            assert_eq!(epoch(bad), None, "{bad:?}");
        }

        let refresh = |v: &str| lab_whole(v, &LAB_STUN_REFRESH_S);
        assert_eq!(refresh("2"), Some(2));
        assert_eq!(refresh("3600"), Some(3600));
        for bad in ["", "0", "1", "3601", "-5", "5s", "1.5"] {
            assert_eq!(refresh(bad), None, "{bad:?}");
        }
        let slot = |v: &str| lab_whole(v, &LAB_PUNCH_SLOT_S);
        assert_eq!(slot("2"), Some(2));
        assert_eq!(slot("300"), Some(300));
        for bad in ["", "0", "1", "301", "-5", "5s"] {
            assert_eq!(slot(bad), None, "{bad:?}");
        }
        let sa = |s: &str| s.parse::<SocketAddr>().unwrap();
        assert_eq!(
            parse_lab_stun_servers("127.0.0.1:3478"),
            Some(vec![sa("127.0.0.1:3478")])
        );
        assert_eq!(
            parse_lab_stun_servers(" 127.0.0.1:3478 , 127.0.0.1:3479,[::1]:3478 "),
            Some(vec![
                sa("127.0.0.1:3478"),
                sa("127.0.0.1:3479"),
                sa("[::1]:3478")
            ])
        );
        let nine = (1..=9)
            .map(|p| format!("127.0.0.1:{}", 3000 + p))
            .collect::<Vec<_>>()
            .join(",");
        for bad in [
            "",
            ",",
            "127.0.0.1",
            "127.0.0.1:0",
            "localhost:3478",
            "stun.l.google.com:19302",
            "0.0.0.0:3478",
            "224.0.0.1:3478",
            "255.255.255.255:3478",
            "[::]:3478",
            "[ff02::1]:3478",
            "[::ffff:127.0.0.1]:3478",
            "127.0.0.1:3478,127.0.0.1:3478",
            "127.0.0.1:3478,",
            nine.as_str(),
        ] {
            assert_eq!(parse_lab_stun_servers(bad), None, "{bad:?}");
        }

        for (word, class) in [
            ("varies", LabNatClass::Varies),
            ("stable_kept", LabNatClass::StableKept),
            ("stable_shifted", LabNatClass::StableShifted),
            (" no_nat ", LabNatClass::NoNat),
        ] {
            assert_eq!(parse_lab_nat_class(word), Some(class), "{word:?}");
        }
        for bad in [
            "",
            "VARIES",
            "Varies",
            "stable",
            "stable-kept",
            "stable kept",
            "no-nat",
            "unknown",
            "varies,no_nat",
        ] {
            assert_eq!(parse_lab_nat_class(bad), None, "{bad:?}");
        }

        let v4 = |s: &str| s.parse::<SocketAddrV4>().unwrap();
        let v6 = |s: &str| s.parse::<SocketAddrV6>().unwrap();
        let gw =
            |a: Option<SocketAddrV4>, b: Option<SocketAddrV6>| Some(LabGateway { v4: a, v6: b });
        assert_eq!(
            parse_lab_portmap_gateway("127.0.0.1:5351"),
            gw(Some(v4("127.0.0.1:5351")), None)
        );
        assert_eq!(
            parse_lab_portmap_gateway("[::1]:40001"),
            gw(None, Some(v6("[::1]:40001")))
        );
        assert_eq!(
            parse_lab_portmap_gateway(" [::1]:40002 , 127.0.0.1:40001 "),
            gw(Some(v4("127.0.0.1:40001")), Some(v6("[::1]:40002")))
        );
        let scoped = parse_lab_portmap_gateway("192.168.1.1:5351,[fe80::1%4]:5351").unwrap();
        assert_eq!(scoped.v6.map(|a| a.scope_id()), Some(4));
        for bad in [
            "",
            ",",
            "127.0.0.1",
            "127.0.0.1:",
            "127.0.0.1:0",
            "127.0.0.1:65536",
            "localhost:5351",
            "0.0.0.0:5351",
            "224.0.0.1:5351",
            "255.255.255.255:5351",
            "[::]:5351",
            "[ff02::1]:5351",
            "[::ffff:127.0.0.1]:5351",
            "[fe80::1%en0]:5351",
            "::1:5351",
            "127.0.0.1:5351,",
            ",127.0.0.1:5351",
            "127.0.0.1:5351,127.0.0.2:5351",
            "[::1]:5351,[::2]:5351",
            "127.0.0.1:5351,[::1]:5351,10.0.0.1:5351",
            "127.0.0.1:5351;[::1]:5351",
        ] {
            assert_eq!(parse_lab_portmap_gateway(bad), None, "{bad:?}");
        }
    }

    /// Runs in both builds: the release test jobs set the lab unlock and a
    /// valid value for each, and every one stays `None` (nothing is read); a
    /// debug build parses exactly its environment, and only with the lab
    /// unlock.
    #[test]
    fn lab_parsers_are_inert_in_release() {
        let unread = || -> Option<String> { panic!("a closed lab value was read") };
        assert_eq!(lab_value(false, unread, parse_lab_portmap_gateway), None);
        assert_eq!(lab_value(false, unread, parse_lab_nat_class), None);
        assert_eq!(lab_value(false, unread, parse_lab_stun_servers), None);
        if !cfg!(debug_assertions) {
            // Edition 2021: a plain call. No release test needs them unset.
            for (name, value) in [
                ("RAVEN_LAB_TEST_A", "1"),
                ("RAVEN_LAB_PORTMAP_GATEWAY", "127.0.0.1:5351"),
                ("RAVEN_LAB_PORTMAP_LIFETIME", "8"),
                ("RAVEN_LAB_NAT_CLASS_FORCE", "varies"),
                ("RAVEN_LAB_PEER_EPOCH_S", "10"),
                ("RAVEN_LAB_STUN_SERVERS", "127.0.0.1:3478"),
                ("RAVEN_LAB_STUN_REFRESH_S", "5"),
                ("RAVEN_LAB_PUNCH_SLOT_S", "5"),
            ] {
                std::env::set_var(name, value);
            }
            assert_eq!(lab_portmap_gateway(), None);
            assert_eq!(lab_portmap_lifetime(), None);
            assert_eq!(lab_nat_class_force(), None);
            assert_eq!(lab_peer_epoch_s(), None);
            assert_eq!(lab_stun_servers(), None);
            assert_eq!(lab_stun_refresh_s(), None);
            assert_eq!(lab_punch_slot_s(), None);
            return;
        }
        let read = |name: &str| {
            crate::pair_init::lab_test_a_enabled()
                .then(|| std::env::var(name).ok())
                .flatten()
        };
        assert_eq!(
            lab_portmap_gateway(),
            read("RAVEN_LAB_PORTMAP_GATEWAY").and_then(|v| parse_lab_portmap_gateway(&v))
        );
        assert_eq!(
            lab_portmap_lifetime(),
            read("RAVEN_LAB_PORTMAP_LIFETIME").and_then(|v| lab_whole(&v, &LAB_PORTMAP_LIFETIME_S))
        );
        assert_eq!(
            lab_nat_class_force(),
            read("RAVEN_LAB_NAT_CLASS_FORCE").and_then(|v| parse_lab_nat_class(&v))
        );
        assert_eq!(
            lab_peer_epoch_s(),
            read("RAVEN_LAB_PEER_EPOCH_S").and_then(|v| lab_whole(&v, &LAB_PEER_EPOCH_S))
        );
        assert_eq!(
            lab_stun_servers(),
            read("RAVEN_LAB_STUN_SERVERS").and_then(|v| parse_lab_stun_servers(&v))
        );
        assert_eq!(
            lab_stun_refresh_s(),
            read("RAVEN_LAB_STUN_REFRESH_S").and_then(|v| lab_whole(&v, &LAB_STUN_REFRESH_S))
        );
        assert_eq!(
            lab_punch_slot_s(),
            read("RAVEN_LAB_PUNCH_SLOT_S").and_then(|v| lab_whole(&v, &LAB_PUNCH_SLOT_S))
        );
    }
}
