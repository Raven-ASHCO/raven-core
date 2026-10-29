//! Friend custody gate (`docs/design/2026-10-friend-custody.md` §14).
//!
//! Independent of the global `PRODUCTION_ENABLED` tripwires and of the carrier
//! gates. Both flags stay false until the owner signs the custody waiver; the
//! lab unlock is debug `RAVEN_LAB_TEST_A=1` (WAN custody additionally needs
//! `RAVEN_LAB_CUSTODY_WAN=1`). Both ends enforce the gate per link.
//!
//! Phase 5 multi-hop custody (RHW1 handoffs between two custodians, and the
//! recipient's tag registration) has its own held gate on top,
//! [`CUSTODY_HANDOFF_PRODUCTION_ENABLED`] (debug `RAVEN_LAB_CUSTODY_HANDOFF`
//! with the Lab Test A unlock): [`handoff_live`] needs custody live first.

use std::net::IpAddr;

use crate::outbox::{CarrierGates, OutboxCarrier, OutboxRoute};

/// Friend custody over LAN links from local-network sources.
pub const FRIEND_CUSTODY_PRODUCTION_ENABLED: bool = false;
/// Friend custody over Internet direct / p2p links and from any source.
pub const FRIEND_CUSTODY_WAN_ENABLED: bool = false;
const _: () = assert!(!FRIEND_CUSTODY_WAN_ENABLED || FRIEND_CUSTODY_PRODUCTION_ENABLED);
// WAN custody rides libp2p (Phase 3 D5): never open it while p2p is held.
const _: () = assert!(!FRIEND_CUSTODY_WAN_ENABLED || crate::p2p_gate::P2P_PRODUCTION_ENABLED);

/// RRH1 `CUSTODY_OFFER` flag bits (RAVEN_ROUTE_HINTS_V1 §12). WAN: the
/// sender serves RFC1 on Internet and p2p links too.
pub const OFFER_WAN: u8 = 0x01;
/// REACHABLE: the sender's libp2p endpoint is confirmed reachable (Phase 1
/// reach class public or mapped).
pub const OFFER_REACHABLE: u8 = 0x02;

/// The refusal every custody entry point prints while the gate is closed.
pub const CUSTODY_HOLD: &str = "CUSTODY_HOLD: friend custody is lab-only (debug \
    RAVEN_LAB_TEST_A=1); FRIEND_CUSTODY_PRODUCTION_ENABLED=false";

/// Phase 5 multi-hop custody (RHW1 handoffs A -> F1 -> F2 -> B, tag
/// registration): only together with friend custody, and it follows every
/// carrier custody admits ([`custody_link_allowed`] stays the per-link rule).
pub const CUSTODY_HANDOFF_PRODUCTION_ENABLED: bool = false;
const _: () = assert!(!CUSTODY_HANDOFF_PRODUCTION_ENABLED || FRIEND_CUSTODY_PRODUCTION_ENABLED);

/// Multi-hop custody's debug lab switch (with `RAVEN_LAB_TEST_A=1`).
pub const LAB_CUSTODY_HANDOFF: &str = "RAVEN_LAB_CUSTODY_HANDOFF";

/// The refusal every handoff entry point prints while its gate is closed.
pub const HANDOFF_HOLD: &str = "CUSTODY_HANDOFF_HOLD: multi-hop custody is lab-only (debug \
    RAVEN_LAB_TEST_A=1 RAVEN_LAB_CUSTODY_HANDOFF=1); CUSTODY_HANDOFF_PRODUCTION_ENABLED=false";

thread_local! {
    static HANDOFF_OVERRIDE: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

/// In-process tests set the handoff switch ([`handoff_live`]) for the
/// current thread only; the custody gate still applies. Ignored in release
/// builds.
#[doc(hidden)]
pub fn set_handoff_gate_for_this_thread(on: Option<bool>) {
    HANDOFF_OVERRIDE.with(|cell| cell.set(on));
}

/// Multi-hop custody (RHW1 handoffs, tag registration) is live: the custody
/// gate is live ([`CustodyGates::current`]), and
/// [`CUSTODY_HANDOFF_PRODUCTION_ENABLED`] or in a debug build this thread's
/// override, else [`LAB_CUSTODY_HANDOFF`] with the Lab Test A unlock. No new
/// [`CustodyGates`] field, so every existing gates literal stays as it is.
/// A security notice's hold, or a BROKEN `rhw1/1`, closes it (P6.45).
pub fn handoff_live() -> bool {
    handoff_gate(
        CustodyGates::current().live,
        CUSTODY_HANDOFF_PRODUCTION_ENABLED,
        || {
            let over = if cfg!(debug_assertions) {
                HANDOFF_OVERRIDE.with(std::cell::Cell::get)
            } else {
                None
            };
            over.unwrap_or_else(|| crate::pair_init::lab_switch(LAB_CUSTODY_HANDOFF))
        },
    ) && crate::suite_policy::hold_allows(crate::suite_registry::FEATURE_CUSTODY_HANDOFF)
}

/// [`handoff_live`] from its inputs: `lab` is read only while custody is
/// live.
fn handoff_gate(custody_live: bool, production: bool, lab: impl FnOnce() -> bool) -> bool {
    custody_live && (production || lab())
}

fn env_flag(name: &str) -> bool {
    matches!(
        std::env::var(name).as_deref(),
        Ok("1" | "true" | "TRUE" | "yes")
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CustodyGates {
    pub live: bool,
    pub wan: bool,
}

thread_local! {
    static TEST_OVERRIDE: std::cell::Cell<Option<CustodyGates>> = const { std::cell::Cell::new(None) };
}

/// In-process tests set the gates for the current thread only. Ignored in
/// release builds.
#[doc(hidden)]
pub fn set_custody_gates_for_this_thread(gates: Option<CustodyGates>) {
    TEST_OVERRIDE.with(|cell| cell.set(gates));
}

impl CustodyGates {
    /// The gates now; a security notice's hold on friend custody, or a
    /// BROKEN `rfc1/1`, closes both (P6.45, close-only).
    pub fn current() -> Self {
        if cfg!(debug_assertions) {
            if let Some(gates) = TEST_OVERRIDE.with(std::cell::Cell::get) {
                return gates.held();
            }
        }
        let lab = crate::pair_init::lab_test_a_enabled();
        Self {
            live: FRIEND_CUSTODY_PRODUCTION_ENABLED || lab,
            wan: FRIEND_CUSTODY_WAN_ENABLED || (lab && env_flag("RAVEN_LAB_CUSTODY_WAN")),
        }
        .held()
    }

    /// These gates under the friend custody hold (asked only while `live`):
    /// both shut when it closes custody, else as they are.
    fn held(self) -> Self {
        if self.live
            && !crate::suite_policy::hold_allows(crate::suite_registry::FEATURE_FRIEND_CUSTODY)
        {
            return Self {
                live: false,
                wan: false,
            };
        }
        self
    }
}

/// Learned custody (RRH1 custody entries, announced home custodians) runs
/// only while both the custody gate and the route-hints gate are open.
pub fn custody_hints_live() -> bool {
    if cfg!(debug_assertions) {
        if let Some(live) = HINTS_OVERRIDE.with(std::cell::Cell::get) {
            return live;
        }
    }
    CustodyGates::current().live && crate::route_hints::route_hints_live()
}

thread_local! {
    static HINTS_OVERRIDE: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

/// In-process tests set [`custody_hints_live`] for the current thread only
/// (the route-hints gate is a process-wide lab switch). Ignored in release
/// builds.
#[doc(hidden)]
pub fn set_custody_hints_for_this_thread(live: Option<bool>) {
    HINTS_OVERRIDE.with(|cell| cell.set(live));
}

/// The `CUSTODY_OFFER` flags this node announces: `None` (no offer) unless
/// the custody gate is live, the user turned custody on (`policy_custody`,
/// [`crate::node_policy::NodePolicy::custody`]) and some carrier can serve
/// custody now ([`custody_servable_now`]: a friend's automatic choice keeps
/// an offer, so one this node cannot serve, under `raven lan off` with WAN
/// custody held, say, would leave that friend's mail nowhere).
/// [`OFFER_WAN`] needs the WAN custody gate and a live p2p carrier;
/// [`OFFER_REACHABLE`] is the caller's `reachable`.
pub fn offer_flags(policy_custody: bool, reachable: bool) -> Option<u8> {
    let g = CustodyGates::current();
    (g.live && policy_custody && custody_servable_now(g, carrier_gates_now())).then(|| {
        (if g.wan && crate::p2p_live_enabled() {
            OFFER_WAN
        } else {
            0
        }) | (if reachable { OFFER_REACHABLE } else { 0 })
    })
}

thread_local! {
    static CARRIER_OVERRIDE: std::cell::Cell<Option<CarrierGates>> = const { std::cell::Cell::new(None) };
}

/// In-process tests set the carrier gates [`carrier_gates_now`] reads for
/// the current thread only (the p2p carrier gate has no switch of its own
/// besides `RAVEN_LAB_TEST_A`). Ignored in release builds.
#[doc(hidden)]
pub fn set_carrier_gates_for_this_thread(gates: Option<CarrierGates>) {
    CARRIER_OVERRIDE.with(|cell| cell.set(gates));
}

/// The carrier gates as this process reads them now; the LAN carrier is
/// also closed while `raven lan off` is in effect ([`crate::lan_usable_now`]),
/// and the nearby carrier while this process runs no nearby engine
/// ([`crate::nearby_gate::nearby_usable_now`]: the user never enabled it, the
/// build has no Bluetooth backend, the radio did not start; review
/// nearby-2), so [`offer_flags`] never counts a carrier this node cannot
/// serve custody on.
pub fn carrier_gates_now() -> CarrierGates {
    if cfg!(debug_assertions) {
        if let Some(gates) = CARRIER_OVERRIDE.with(std::cell::Cell::get) {
            return gates;
        }
    }
    CarrierGates {
        lan: crate::lan_usable_now(),
        internet: crate::internet_direct_live_enabled(),
        p2p: crate::p2p_live_enabled(),
        nearby: crate::nearby_gate::nearby_usable_now(),
        onion: crate::onion_gate::onion_usable_now(),
    }
}

/// Some link could be served custody now ([`custody_link_allowed`] for at
/// least one carrier): the LAN or nearby carrier is open (local-network
/// sources; a one-hop radio link to a pinned contact), or WAN custody is
/// live with the Internet or p2p carrier open.
pub fn custody_servable_now(g: CustodyGates, c: CarrierGates) -> bool {
    g.live && (c.lan || c.nearby || (g.wan && (c.internet || c.p2p || c.onion)))
}

/// Custodian side, per inbound link: custody is served on this link. A
/// nearby link (a one-hop radio link to a pinned contact) is local, like LAN
/// from a local-network source (owner decision O5-13: custody over nearby
/// under the existing custody gates); it still needs the custody gate and
/// the nearby carrier's.
pub fn custody_link_allowed(
    g: CustodyGates,
    c: CarrierGates,
    carrier: OutboxCarrier,
    source: Option<IpAddr>,
) -> bool {
    g.live
        && c.allows(carrier)
        && match carrier {
            OutboxCarrier::Lan => g.wan || source.is_some_and(crate::outbox::is_local_network_ip),
            OutboxCarrier::Internet | OutboxCarrier::P2p | OutboxCarrier::Onion => g.wan,
            OutboxCarrier::Nearby => true,
        }
}

/// Requester side, per planned custodian route. A LAN route is then dialled
/// only after `localize_lan_route(route, pinned = g.wan, ..)`. A nearby
/// route is local, as on the custodian side ([`custody_link_allowed`]).
pub fn custody_route_allowed(g: CustodyGates, c: CarrierGates, route: &OutboxRoute) -> bool {
    g.live
        && c.allows(route.carrier)
        && match route.carrier {
            OutboxCarrier::Lan => true,
            OutboxCarrier::Internet | OutboxCarrier::P2p | OutboxCarrier::Onion => g.wan,
            OutboxCarrier::Nearby => true,
        }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_flags_stay_false() {
        const {
            assert!(!FRIEND_CUSTODY_PRODUCTION_ENABLED);
            assert!(!FRIEND_CUSTODY_WAN_ENABLED);
            assert!(!crate::pair_init::PRODUCTION_ENABLED);
            // The WAN => P2P tripwire (Phase 3 P3.16) holds today's values.
            assert!(!FRIEND_CUSTODY_WAN_ENABLED || crate::p2p_gate::P2P_PRODUCTION_ENABLED);
            // Phase 5 (P5.17): multi-hop custody is held, and sits on custody.
            assert!(!CUSTODY_HANDOFF_PRODUCTION_ENABLED);
            assert!(!CUSTODY_HANDOFF_PRODUCTION_ENABLED || FRIEND_CUSTODY_PRODUCTION_ENABLED);
        }
    }

    /// Phase 5 P5.17: multi-hop custody needs the custody gate and its own
    /// switch. Which case a run sees is up to its environment (the lab runs
    /// set the switches; the release test job sets them all and they are
    /// never read); every case's answer is pinned.
    #[test]
    fn handoff_live_needs_custody_and_its_own_switch() {
        // The rule from its inputs: the switch is read only while custody is
        // live, and never opens the gate without custody.
        for production in [false, true] {
            let mut read = false;
            assert!(!handoff_gate(false, production, || {
                read = true;
                true
            }));
            assert!(!read, "the switch is not read while custody is held");
            assert!(handoff_gate(true, true, || false));
        }
        assert!(handoff_gate(true, false, || true));
        assert!(!handoff_gate(true, false, || false));

        // Lab-free (or a release build): closed.
        let switch = crate::pair_init::lab_switch(LAB_CUSTODY_HANDOFF);
        assert_eq!(
            handoff_live(),
            CustodyGates::current().live && switch,
            "follows the custody gate and RAVEN_LAB_CUSTODY_HANDOFF"
        );
        if !switch {
            assert!(!handoff_live(), "no lab switch: closed");
        }
        if !crate::pair_init::lab_test_a_enabled() {
            assert!(!handoff_live() && !switch, "lab-free: closed");
        }
        // The switch alone needs the Lab Test A unlock and a debug build.
        assert!(!crate::pair_init::lab_switch_value(true, false, Some("1")));
        assert!(!crate::pair_init::lab_switch_value(false, true, Some("1")));
        assert!(crate::pair_init::lab_switch_value(true, true, Some("1")));

        // Custody held: closed even with the switch on (the thread's
        // override stands in for the environment variable). A release build
        // ignores both overrides: closed whatever they say.
        set_handoff_gate_for_this_thread(Some(true));
        for wan in [false, true] {
            set_custody_gates_for_this_thread(Some(CustodyGates { live: false, wan }));
            assert!(!handoff_live(), "custody held, wan={wan}");
            set_custody_gates_for_this_thread(Some(CustodyGates { live: true, wan }));
            assert_eq!(
                handoff_live(),
                cfg!(debug_assertions),
                "custody live, switch on, wan={wan}"
            );
        }
        set_handoff_gate_for_this_thread(Some(false));
        assert!(!handoff_live(), "custody live, switch off");
        set_handoff_gate_for_this_thread(None);
        set_custody_gates_for_this_thread(None);
        if !crate::pair_init::lab_test_a_enabled() {
            assert!(!handoff_live());
        }
    }

    #[test]
    fn handoff_hold_names_the_flag_and_both_switches() {
        assert!(HANDOFF_HOLD.starts_with("CUSTODY_HANDOFF_HOLD:"));
        assert!(HANDOFF_HOLD.contains("CUSTODY_HANDOFF_PRODUCTION_ENABLED=false"));
        assert!(HANDOFF_HOLD.contains("RAVEN_LAB_TEST_A=1"));
        assert!(HANDOFF_HOLD.contains(&format!("{LAB_CUSTODY_HANDOFF}=1")));
    }

    /// Phase 3 P3.16: no offer while the gate holds or custody is off; the
    /// WAN bit needs the WAN gate and a live p2p carrier; REACHABLE is the
    /// caller's.
    #[test]
    fn offer_flags_table() {
        let p2p = crate::p2p_live_enabled();
        let wan_bit = if p2p { OFFER_WAN } else { 0 };
        assert_eq!(OFFER_WAN & OFFER_REACHABLE, 0);
        let cases = [
            // (live, wan, policy custody, reachable) -> flags
            ((false, false, true, true), None),
            ((false, true, true, true), None),
            ((true, false, false, true), None),
            ((true, true, false, false), None),
            ((true, false, true, false), Some(0)),
            ((true, false, true, true), Some(OFFER_REACHABLE)),
            ((true, true, true, false), Some(wan_bit)),
            ((true, true, true, true), Some(wan_bit | OFFER_REACHABLE)),
        ];
        // The LAN carrier open: custody can be served.
        set_carrier_gates_for_this_thread(Some(CarrierGates {
            lan: true,
            internet: false,
            p2p: false,
            nearby: false,
            onion: false,
        }));
        for ((live, wan, custody, reachable), want) in cases {
            set_custody_gates_for_this_thread(Some(CustodyGates { live, wan }));
            assert_eq!(
                offer_flags(custody, reachable),
                want,
                "live={live} wan={wan} custody={custody} reachable={reachable} p2p={p2p}"
            );
        }
        set_custody_gates_for_this_thread(None);
        set_carrier_gates_for_this_thread(None);
    }

    /// Review D-3: no offer while no carrier can serve custody (`raven lan
    /// off`, or no LAN, with WAN custody held), so a friend's automatic
    /// choice never keeps this node as a mail friend it cannot be. With
    /// WAN custody live an open Internet or p2p carrier serves it.
    #[test]
    fn offer_flags_none_while_no_carrier_can_serve_custody() {
        let gates = |lan, internet, p2p| {
            set_carrier_gates_for_this_thread(Some(CarrierGates {
                lan,
                internet,
                p2p,
                nearby: false,
                onion: false,
            }));
        };
        set_custody_gates_for_this_thread(Some(CustodyGates {
            live: true,
            wan: false,
        }));
        gates(false, true, true);
        assert_eq!(offer_flags(true, true), None, "LAN off, WAN custody held");
        gates(false, false, false);
        assert_eq!(offer_flags(true, false), None);
        gates(true, false, false);
        assert_eq!(offer_flags(true, false), Some(0), "LAN open");
        set_custody_gates_for_this_thread(Some(CustodyGates {
            live: true,
            wan: true,
        }));
        gates(false, false, false);
        assert_eq!(offer_flags(true, false), None, "no carrier at all");
        for (internet, p2p) in [(true, false), (false, true)] {
            gates(false, internet, p2p);
            assert!(offer_flags(true, false).is_some(), "{internet} {p2p}");
        }
        // The rule is custody_link_allowed's, carrier by carrier (P5.25:
        // nearby too).
        for live in [false, true] {
            for wan in [false, true] {
                let g = CustodyGates { live, wan };
                for bits in 0..16u8 {
                    let c = CarrierGates {
                        lan: bits & 1 != 0,
                        internet: bits & 2 != 0,
                        p2p: bits & 4 != 0,
                        nearby: bits & 8 != 0,
                        onion: false,
                    };
                    let local = Some("192.168.1.5".parse().unwrap());
                    let any = [
                        OutboxCarrier::Lan,
                        OutboxCarrier::Internet,
                        OutboxCarrier::P2p,
                        OutboxCarrier::Nearby,
                    ]
                    .into_iter()
                    .any(|carrier| custody_link_allowed(g, c, carrier, local));
                    assert_eq!(custody_servable_now(g, c), any, "{g:?} {c:?}");
                }
            }
        }
        set_custody_gates_for_this_thread(None);
        set_carrier_gates_for_this_thread(None);
    }

    #[test]
    fn custody_hints_live_needs_both_gates() {
        let hints = crate::route_hints::route_hints_live();
        for wan in [false, true] {
            set_custody_gates_for_this_thread(Some(CustodyGates { live: false, wan }));
            assert!(!custody_hints_live(), "custody gate closed");
            set_custody_gates_for_this_thread(Some(CustodyGates { live: true, wan }));
            assert_eq!(custody_hints_live(), hints, "follows the route-hints gate");
        }
        set_custody_gates_for_this_thread(None);
        if !crate::route_hints::route_hints_live() {
            assert!(!custody_hints_live());
        }
        if !crate::pair_init::lab_test_a_enabled() {
            assert!(!custody_hints_live(), "lab-free: closed");
        }
        // The per-thread test override, and back to the gates.
        set_custody_hints_for_this_thread(Some(true));
        assert!(custody_hints_live());
        set_custody_hints_for_this_thread(Some(false));
        assert!(!custody_hints_live());
        set_custody_hints_for_this_thread(None);
        if !crate::pair_init::lab_test_a_enabled() {
            assert!(!custody_hints_live());
        }
    }

    #[test]
    fn lab_free_gate_is_closed() {
        if crate::pair_init::lab_test_a_enabled() {
            return;
        }
        let g = CustodyGates::current();
        assert!(!g.live && !g.wan);
        assert!(!crate::pair_init::live_enabled());
    }

    #[test]
    fn hold_text_names_the_flag_and_the_unlock() {
        assert!(CUSTODY_HOLD.starts_with("CUSTODY_HOLD:"));
        assert!(CUSTODY_HOLD.contains("FRIEND_CUSTODY_PRODUCTION_ENABLED=false"));
        assert!(CUSTODY_HOLD.contains("RAVEN_LAB_TEST_A=1"));
    }

    #[test]
    fn link_rule_keeps_custody_on_the_local_network_without_wan() {
        let all = CarrierGates {
            lan: true,
            internet: true,
            p2p: true,
            nearby: true,
            onion: false,
        };
        let lan_only = CustodyGates {
            live: true,
            wan: false,
        };
        let local: IpAddr = "192.168.1.9".parse().unwrap();
        let public: IpAddr = "203.0.113.5".parse().unwrap();
        assert!(custody_link_allowed(
            lan_only,
            all,
            OutboxCarrier::Lan,
            Some(local)
        ));
        assert!(!custody_link_allowed(
            lan_only,
            all,
            OutboxCarrier::Lan,
            Some(public)
        ));
        assert!(!custody_link_allowed(
            lan_only,
            all,
            OutboxCarrier::Lan,
            None
        ));
        assert!(!custody_link_allowed(
            lan_only,
            all,
            OutboxCarrier::Internet,
            Some(local)
        ));
        assert!(!custody_link_allowed(
            lan_only,
            all,
            OutboxCarrier::P2p,
            None
        ));
        let wan = CustodyGates {
            live: true,
            wan: true,
        };
        assert!(custody_link_allowed(
            wan,
            all,
            OutboxCarrier::Lan,
            Some(public)
        ));
        assert!(custody_link_allowed(
            wan,
            all,
            OutboxCarrier::Internet,
            None
        ));
        let off = CustodyGates {
            live: false,
            wan: true,
        };
        assert!(!custody_link_allowed(
            off,
            all,
            OutboxCarrier::Lan,
            Some(local)
        ));
        // A closed carrier gate wins.
        let no_lan = CarrierGates { lan: false, ..all };
        assert!(!custody_link_allowed(
            wan,
            no_lan,
            OutboxCarrier::Lan,
            Some(local)
        ));
        let route = OutboxRoute {
            carrier: OutboxCarrier::Internet,
            dial: "203.0.113.5:7422".into(),
        };
        assert!(!custody_route_allowed(lan_only, all, &route));
        assert!(custody_route_allowed(wan, all, &route));
    }

    /// Phase 5 (P5.25, owner decision O5-13): custody rides a nearby link
    /// under the existing custody gates, as local as LAN from a local
    /// source (no WAN custody needed), and only while the nearby carrier's
    /// gate is open too: with either gate closed nothing changes. Both
    /// sides, every combination.
    #[test]
    fn nearby_custody_follows_the_custody_and_nearby_gates() {
        let route = OutboxRoute {
            carrier: OutboxCarrier::Nearby,
            dial: crate::outbox::nearby_dial_for(&[0x6b; 32]),
        };
        for live in [false, true] {
            for wan in [false, true] {
                for nearby in [false, true] {
                    let g = CustodyGates { live, wan };
                    let c = CarrierGates {
                        lan: false,
                        internet: false,
                        p2p: false,
                        nearby,
                        onion: false,
                    };
                    let want = live && nearby;
                    for source in [None, Some("203.0.113.5".parse().unwrap())] {
                        assert_eq!(
                            custody_link_allowed(g, c, OutboxCarrier::Nearby, source),
                            want,
                            "{g:?} nearby={nearby} {source:?}"
                        );
                    }
                    assert_eq!(custody_route_allowed(g, c, &route), want, "{g:?} {c:?}");
                    assert_eq!(custody_servable_now(g, c), want, "{g:?} {c:?}");
                    // The nearby gate opens no other carrier.
                    for carrier in [
                        OutboxCarrier::Lan,
                        OutboxCarrier::Internet,
                        OutboxCarrier::P2p,
                    ] {
                        assert!(!custody_link_allowed(g, c, carrier, None), "{carrier:?}");
                    }
                }
            }
        }
        // As this process reads them: the nearby carrier follows its own
        // gate (closed without RAVEN_LAB_NEARBY) and a running engine.
        let _engine = crate::nearby_gate::nearby_running_untouched();
        assert_eq!(
            carrier_gates_now().nearby,
            crate::nearby_gate::nearby_usable_now()
        );
        if !crate::nearby_live_enabled() {
            assert!(!custody_route_allowed(
                CustodyGates {
                    live: true,
                    wan: true
                },
                carrier_gates_now(),
                &route
            ));
        }
    }

    /// Review nearby-2: the nearby carrier counts for custody only while
    /// this process runs a nearby engine, whatever its gate says. A
    /// custody-on node with `raven lan off`, WAN custody held and nearby
    /// never enabled (no engine) announces no offer, even with the nearby
    /// lab gate open (`RAVEN_LAB_TEST_A=1 RAVEN_LAB_NEARBY=1`: the case
    /// this pins); with an engine running it may.
    #[test]
    fn nearby_carrier_counts_for_custody_only_while_an_engine_runs() {
        let _lan_off = crate::lan_gate::lan_user_off_for_test(true);
        set_custody_gates_for_this_thread(Some(CustodyGates {
            live: true,
            wan: false,
        }));
        {
            let _idle = crate::nearby_gate::nearby_running_for_test(false);
            let c = carrier_gates_now();
            assert!(!c.lan && !c.nearby, "{c:?}");
            assert_eq!(
                offer_flags(true, false),
                None,
                "LAN off, WAN custody held, no nearby engine"
            );
        }
        {
            let _running = crate::nearby_gate::nearby_running_for_test(true);
            let gate = crate::nearby_live_enabled();
            assert_eq!(carrier_gates_now().nearby, gate);
            assert_eq!(offer_flags(true, false), gate.then_some(0));
        }
        set_custody_gates_for_this_thread(None);
    }

    /// Phase 3 P3.2: `raven lan off` closes the LAN carrier for custody too
    /// (both ends read [`carrier_gates_now`]); the other carriers keep theirs.
    #[test]
    fn carrier_gates_now_closes_lan_while_the_user_turned_it_off() {
        {
            let _off = crate::lan_gate::lan_user_off_for_test(true);
            let off = carrier_gates_now();
            assert!(!off.lan);
            assert_eq!(
                (off.internet, off.p2p),
                (
                    crate::internet_direct_live_enabled(),
                    crate::p2p_live_enabled()
                )
            );
            let local: IpAddr = "192.168.1.9".parse().unwrap();
            let wan = CustodyGates {
                live: true,
                wan: true,
            };
            assert!(!custody_link_allowed(
                wan,
                off,
                OutboxCarrier::Lan,
                Some(local)
            ));
        }
        let _untouched = crate::lan_gate::lan_user_switch_untouched();
        assert!(carrier_gates_now().lan);
    }
}
